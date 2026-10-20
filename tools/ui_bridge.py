"""Стенд для проверки интерфейса с настоящим ядром, без окна pywebview.

Отдаёт app/ui по HTTP и пробрасывает вызовы window.pywebview.api.* в app.api.Api
через POST /api/<метод>. Страницу можно открыть в обычном браузере или снять
скриншот headless Edge. Ничего не запускает в системе: winws не стартует (нет
прав), Telegram-прокси слушает только 127.0.0.1 на случайном порту.

    python tools/ui_bridge.py --port 8765 [--pretend-admin]
"""
from __future__ import annotations

import argparse
import hmac
import json
import logging
import os
import secrets
import shutil
import socket
import sys
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

TOKEN_HEADER = "X-Lazeyka-Bridge"
SHIM_TEMPLATE = """(function () {
  const call = (name) => (...args) => fetch('/api/' + name, {method: 'POST', body: JSON.stringify(args),
    headers: {'__HEADER__': __TOKEN__}}).then(r => r.json());
  // Как у pywebview: на объекте api — настоящие функции, по одной на публичный метод.
  const api = {};
  for (const name of __METHODS__) api[name] = call(name);
  window.pywebview = { api };
  window.__bridge = true;
  setTimeout(() => window.dispatchEvent(new Event('pywebviewready')), 0);
})();
"""
SHIM_TAG = b'<script src="/__bridge.js"></script>'


def request_allowed(method: str, headers, port: int, token: str) -> bool:
    """Стенд слушает 127.0.0.1, но браузер пускает к нему любую открытую страницу: POST с чужого сайта или
    DNS rebinding (evil.example → 127.0.0.1) вызывали бы методы настоящего ядра. Пропускаем только своё:
    Host — 127.0.0.1 или localhost с нашим портом, Origin (если есть) — тот же адрес, запрос не со стороннего
    сайта (Sec-Fetch-Site: так чужая страница не подключит /__bridge.js с токеном), у POST — токен из shim
    в своём заголовке (его не поставит ни форма, ни запрос без разрешения CORS)."""
    hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
    if (headers.get("Host") or "").strip().lower() not in hosts:
        return False
    origin = headers.get("Origin")
    if origin is not None and origin.strip().lower() not in {f"http://{h}" for h in hosts}:
        return False
    site = (headers.get("Sec-Fetch-Site") or "").strip().lower()
    if site and site not in ("same-origin", "none"):
        return False
    if method == "POST":
        return hmac.compare_digest((headers.get(TOKEN_HEADER) or "").encode(), token.encode())
    return True


def shim(methods: list[str], token: str) -> bytes:
    return (SHIM_TEMPLATE.replace("__METHODS__", json.dumps(methods)).replace("__HEADER__", TOKEN_HEADER)
            .replace("__TOKEN__", json.dumps(token)).encode("utf-8"))


def _remove_own_data(path: str) -> None:
    """Временная папка данных стенда — после выхода ядра; журнал закрываем первым, иначе Windows её не отдаст."""
    logging.shutdown()
    try:
        shutil.rmtree(path)
    except OSError as exc:
        print(f"Временная папка стенда {path} удалена не целиком: {exc}", file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--pretend-admin", action="store_true",
                        help="показать интерфейс так, будто права есть (кнопки запуска zapret всё равно не сработают)")
    args = parser.parse_args()

    # Своя временная папка данных, если другую не задали явно; при выходе стенд её убирает.
    own_data = None
    if not os.environ.get("LAZEYKA_DATA"):
        own_data = tempfile.mkdtemp(prefix="lazeyka-bridge-")
        os.environ["LAZEYKA_DATA"] = own_data
    # Стенд не запускает ядро своего VPN и не трогает системный прокси (app/vpnclient/guard.py).
    os.environ["LAZEYKA_NO_CORE"] = "1"
    from app import paths, winutil
    from app import log as applog
    applog.setup(paths.logs_dir(allow_create_data=True))
    if args.pretend_admin:
        winutil.is_admin = lambda: True  # только отображение; winws без настоящих прав не запустится
    from app.api import Api
    from app.core import Core

    core = Core()
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        free = s.getsockname()[1]
    core.settings.update(lambda d: d["tg"].__setitem__("port", free))
    if args.pretend_admin:
        from app.zapret import pack
        pack.ensure_bundled()
        core.zapret.is_admin = True
        core.zapret.start = lambda: (_ for _ in ()).throw(RuntimeError("стенд: запуск winws отключён"))
    core.startup()
    api = Api(core)
    ui = paths.ui_dir()
    token = secrets.token_urlsafe(24)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):  # тише
            pass

        def _refused(self) -> bool:
            if request_allowed(self.command, self.headers, args.port, token):
                return False
            self.send_error(403)
            return True

        def do_GET(self):
            if self._refused():
                return
            rel = self.path.split("?", 1)[0].lstrip("/") or "index.html"
            if rel == "__bridge.js":
                methods = sorted(n for n in dir(api) if not n.startswith("_") and callable(getattr(api, n)))
                body = shim(methods, token)
                self.send_response(200)
                self.send_header("Content-Type", "application/javascript; charset=utf-8")
                self.end_headers()
                self.wfile.write(body)
                return
            target = (ui / rel).resolve()
            if ui.resolve() not in target.parents and target != ui.resolve():
                self.send_error(403)
                return
            if not target.is_file():
                self.send_error(404)
                return
            data = target.read_bytes()
            if rel == "index.html":
                data = data.replace(b'<script src="js/core.js"></script>',
                                    SHIM_TAG + b'<script src="js/core.js"></script>', 1)
            ctype = {".html": "text/html", ".css": "text/css", ".js": "application/javascript",
                     ".svg": "image/svg+xml", ".png": "image/png"}.get(target.suffix, "application/octet-stream")
            self.send_response(200)
            self.send_header("Content-Type", ctype + "; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            if self._refused():
                return
            name = self.path.rsplit("/", 1)[-1]
            length = int(self.headers.get("Content-Length") or 0)
            try:
                call_args = json.loads(self.rfile.read(length) or b"[]")
                fn = getattr(api, name, None)
                if name.startswith("_") or not callable(fn):
                    result = {"ok": False, "error": f"нет метода {name}"}
                else:
                    result = fn(*call_args)
            except Exception as exc:  # noqa: BLE001
                result = {"ok": False, "error": repr(exc)}
            body = json.dumps(result, ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"http://127.0.0.1:{args.port}/index.html", flush=True)
    try:
        server.serve_forever()
    finally:
        try:
            core.shutdown()
        finally:
            if own_data is not None:
                _remove_own_data(own_data)


if __name__ == "__main__":
    main()
