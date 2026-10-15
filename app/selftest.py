"""Самопроверка сборки: `Lazeyka.exe --selftest отчёт.json`.

Ничего не меняет в системе и не запускает winws: проверяет, что в сборку
попали все библиотеки и ресурсы, встроенный пакет цел, стратегии разбираются,
а ядро Telegram-прокси поднимает порт на 127.0.0.1.
"""
from __future__ import annotations

import importlib
import json
import socket
import sys
import tempfile
import time
import traceback
import zipfile
from pathlib import Path


def _check(results: list, name: str, fn) -> None:
    started = time.perf_counter()
    try:
        detail = fn()
        results.append({"name": name, "ok": True, "detail": detail,
                        "ms": round((time.perf_counter() - started) * 1000)})
    except Exception as exc:  # noqa: BLE001
        results.append({"name": name, "ok": False, "detail": f"{exc!r}",
                        "trace": traceback.format_exc(limit=4),
                        "ms": round((time.perf_counter() - started) * 1000)})


def run(report_path: str) -> int:
    from . import __version__, paths
    results: list[dict] = []

    def imports():
        mods = ["webview", "clr", "pystray", "PIL.Image", "psutil", "cryptography.hazmat.primitives.ciphers",
                "httpx", "h2.connection", "certifi", "bottle"]
        for name in mods:
            importlib.import_module(name)
        return ", ".join(mods)

    def certifi_bundle():
        from .vendor.tgws_proxy.utils import create_ssl_context
        create_ssl_context()
        bundle = Path(getattr(sys, "_MEIPASS", "")) / "certifi" / "cacert.pem"
        if getattr(sys, "frozen", False) and not bundle.is_file():
            raise FileNotFoundError(bundle)
        return str(bundle)

    def ui_files():
        missing = [n for n in ("index.html", "app.css", "app.js", "logo.svg") if not (paths.ui_dir() / n).is_file()]
        if missing:
            raise FileNotFoundError(", ".join(missing))
        return str(paths.ui_dir())

    def bundled_pack():
        from .zapret import pack, strategies
        manifest = pack.bundled_manifest()
        if manifest is None:
            raise FileNotFoundError("bundled.json")
        digest = pack.sha256_file(manifest["zip"])
        if digest != manifest["sha256"]:
            raise ValueError("контрольная сумма встроенного пакета не совпала")
        with tempfile.TemporaryDirectory() as tmp:
            with zipfile.ZipFile(manifest["zip"]) as zf:
                zf.extractall(tmp)
            root = next(p for p in Path(tmp).iterdir() if p.is_dir())
            found, errors = strategies.discover(root)
            if errors or not found:
                raise ValueError(f"стратегии: {len(found)}, ошибки: {errors[:2]}")
            for s in found:
                s.args(root)
            from .zapret import vpnfilter
            error = vpnfilter.compile_check(root / "bin" / "WinDivert.dll",
                                            vpnfilter.wrap("tcp and tcp.DstPort == 443", [1], ["93.184.216.34"]))
            if error:
                raise ValueError(f"фильтр для работы рядом с VPN не компилируется: {error}")
        return f"{manifest['version']}, стратегий: {len(found)}, фильтр для VPN компилируется"

    def proxy_core():
        from .settings import Settings
        from .tgproxy.manager import TgProxyManager
        with tempfile.TemporaryDirectory() as tmp:
            settings = Settings(Path(tmp) / "s.json")
            with socket.socket() as s:
                s.bind(("127.0.0.1", 0))
                port = s.getsockname()[1]
            settings.update(lambda d: d["tg"].update({"port": port, "pool_size": 0, "cfproxy": False}))
            mgr = TgProxyManager(settings, lambda *_: None)
            mgr.load_core()
            mgr.start()
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=3):
                    pass
            finally:
                mgr.stop()
            return f"ядро {mgr.core.version}, порт {port} открывался"

    def helpers():
        from . import helpdesk, winutil
        from .zapret import tester
        curl = Path(winutil.system32("curl.exe"))
        if not curl.is_file():
            raise FileNotFoundError(curl)
        if helpdesk.normalize_domain("https://www.Example.com/x") != "example.com":
            raise ValueError("адрес сайта разбирается неверно")
        secret = "0123456789abcdef" * 2
        if secret in helpdesk.build_report({"tg_settings": {"secret": secret}}, []):
            raise ValueError("ключ прокси попал в отчёт")
        return f"{curl}, кандидатов для «Найти и включить»: {len(tester.DEFAULT_CANDIDATES)}"

    def network():
        from . import vpn
        snap = vpn.scan()
        if not snap.adapters:
            raise ValueError("не найдено ни одного сетевого адаптера")
        return f"адаптеров {len(snap.adapters)}, туннелей VPN {len(snap.tunnels)}"

    def icon():
        from . import icons
        img = icons.draw(32, "on")
        return f"{img.size[0]}×{img.size[1]}"

    _check(results, "Библиотеки", imports)
    _check(results, "Сертификаты", certifi_bundle)
    _check(results, "Файлы интерфейса", ui_files)
    _check(results, "Встроенный пакет zapret", bundled_pack)
    _check(results, "Ядро Telegram-прокси", proxy_core)
    _check(results, "Помощь и проверки", helpers)
    _check(results, "Сеть и VPN", network)
    _check(results, "Значок", icon)

    report = {"version": __version__, "frozen": bool(getattr(sys, "frozen", False)),
              "ok": all(r["ok"] for r in results), "checks": results}
    Path(report_path).write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0 if report["ok"] else 1
