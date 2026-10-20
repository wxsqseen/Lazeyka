"""Самопроверка сборки: `Lazeyka.exe --selftest отчёт.json`.

Ничего не меняет в системе и не запускает winws: проверяет, что в сборку
попали все библиотеки и ресурсы, встроенный пакет цел, стратегии разбираются,
а ядро Telegram-прокси поднимает порт на 127.0.0.1. Свой VPN — без запуска ядра и без сети:
разбор ссылок и JSON Xray, генерация конфига, закреплённые версии, хеши и адреса загрузки ядер
(самих ядер в exe нет — их скачивает Лазейка при запуске).
"""
from __future__ import annotations

import importlib
import importlib.util
import json
import re
import socket
import sys
import tempfile
import time
import traceback
import zipfile
from pathlib import Path


# Закреплённые ядра своего VPN (план 3.1): самопроверка сверяет с ними engines.CORES — случайная правка
# хеша или адреса в коде не уйдёт в сборку незамеченной.
PINNED_CORES = {
    "sing-box": {"asset": "sing-box-1.14.3-windows-amd64.zip", "size": 32_853_953,
                 "sha256": "d8b86ef58936dba9230ec6a57ffa4243933f3c14ef4809828b6c553440ed1518",
                 "url": "https://github.com/SagerNet/sing-box/releases/download/v1.14.3/"
                        "sing-box-1.14.3-windows-amd64.zip"},
    "xray": {"asset": "Xray-windows-64.zip", "size": 20_913_304,
             "sha256": "d004c39288ce9ada487c6f398c7c545f7d749e44bdfdd59dbc9f865afba4e1ad",
             "url": "https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-windows-64.zip"},
}

# Тестовые данные: адреса из диапазонов для документации, ключи — не настоящие.
SAMPLE_UUID = "00000000-0000-4000-8000-00000000c0de"
SAMPLE_PBK = "Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw"
SAMPLE_LINK = (f"vless://{SAMPLE_UUID}@203.0.113.10:443?type=tcp&security=reality&sni=www.example.com"
               f"&fp=chrome&pbk={SAMPLE_PBK}&sid=6ba85179e30d4fc2&flow=xtls-rprx-vision#Selftest")
SAMPLE_XRAY = {"outbounds": [{
    "tag": "proxy", "protocol": "vless",
    "settings": {"vnext": [{"address": "203.0.113.11", "port": 443,
                            "users": [{"id": SAMPLE_UUID, "encryption": "none", "flow": "xtls-rprx-vision"}]}]},
    "streamSettings": {"network": "tcp", "security": "reality",
                       "realitySettings": {"serverName": "www.example.com", "publicKey": SAMPLE_PBK,
                                           "shortId": "6ba85179e30d4fc2", "fingerprint": "chrome"}},
}, {"tag": "direct", "protocol": "freedom"}]}


# Все модули своего VPN: менеджер подгружает их по имени, и PyInstaller сам их не видит. Список
# сверяется с файлами пакета в тестах — новый модуль не забудется.
VPNCLIENT_MODULES = ("backup", "clash", "config", "deeplink", "diagnose", "engines", "guard", "killswitch",
                     "links", "manager", "model", "process", "qr", "routeprofile", "routing", "rules", "store",
                     "subscription", "sysproxy", "xrayjson")


def check_vpnclient_modules() -> str:
    """Каждый модуль своего VPN импортируется (в собранном exe — значит, он туда попал)."""
    broken = []
    for name in VPNCLIENT_MODULES:
        try:
            importlib.import_module(f"app.vpnclient.{name}")
        except Exception as exc:  # noqa: BLE001 — в отчёт: какой модуль и почему
            broken.append(f"{name} ({type(exc).__name__}: {exc})")
    if broken:
        raise ImportError("не импортируются модули своего VPN: " + "; ".join(broken))
    return f"модулей: {len(VPNCLIENT_MODULES)}, все импортируются"


def _has_module(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


def check_vpnclient_parsing() -> str:
    """Разбор ссылки и JSON Xray, сборка и проверка конфига sing-box — без запуска ядра.
    Модуль, которого нет в сборке, пропускается (в собранном exe это ошибка)."""
    frozen = bool(getattr(sys, "frozen", False))
    done: list[str] = []
    missing = [m for m in ("links", "xrayjson", "config") if not _has_module(f"app.vpnclient.{m}")]
    if missing and frozen:
        raise ImportError("в сборке нет модулей своего VPN: " + ", ".join(missing))
    server = None
    if "links" not in missing:
        from .vpnclient import links
        server = links.parse_link(SAMPLE_LINK)
        if (server.proto, server.port, server.security) != ("vless", 443, "reality"):
            raise ValueError(f"ссылка VLESS разобрана неверно: {server.proto}/{server.port}/{server.security}")
        done.append("ссылка VLESS+REALITY")
    if "xrayjson" not in missing:
        from .vpnclient import xrayjson
        parsed = xrayjson.parse(SAMPLE_XRAY)
        if not parsed.servers:
            raise ValueError("JSON Xray: сервер не найден")
        done.append("JSON Xray")
        server = server or parsed.servers[0]
    if "config" not in missing and server is not None:
        from .vpnclient import config, model
        if not server.id:
            server.id = server.key()
        with tempfile.TemporaryDirectory() as tmp:
            plan = model.RunPlan(
                mode="proxy", servers=[server], selected=server.id, addresses={server.id: "203.0.113.10"},
                engines={server.id: "sing-box"},
                ports=model.Ports(proxy=20808, internal=20809, clash=20810),
                secrets=model.Secrets(clash="selftest-secret-0000", internal_user="selftest",
                                      internal_pass="selftest-pass-0000"),
                lazeyka_exe=sys.executable, work_dir=Path(tmp))
            errors = config.validate(config.build_singbox(plan))
        if errors:
            raise ValueError("конфиг sing-box не прошёл проверку: " + "; ".join(errors[:3]))
        done.append("конфиг sing-box")
    if not frozen or not missing:
        done.append(_check_subscription_and_store())
    if missing:
        done.append("нет модулей: " + ", ".join(missing))
    return ", ".join(done) or "нечего проверять"


def _check_subscription_and_store() -> str:
    """Путь «Добавить подписку»: подписка base64 → серверы → профиль сохранён и читается заново
    (во временной папке, без сети) — то, что сломалось в exe 1.2.0."""
    import base64
    from .vpnclient import model, store, subscription
    decoded = subscription.decode(base64.b64encode(SAMPLE_LINK.encode("utf-8")), {})
    if not decoded.servers:
        raise ValueError("подписка: серверы не разобраны")
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "vpnclient" / "profiles.json"
        profiles = store.ProfileStore(path)
        sub = profiles.add_subscription(model.Subscription(id="s-selftest", name="Проверка", url="https://example.com/sub"))
        profiles.apply_decoded(sub.id, decoded)
        if len(store.ProfileStore(path).servers()) != len(decoded.servers):
            raise ValueError("профили своего VPN не сохранились")
    return "подписка и профили"


_SHA256 = re.compile(r"[0-9a-f]{64}")


def check_core_pins(frozen: bool) -> str:
    """Закреплённые ядра своего VPN — без сети: имя, размер и SHA-256 архива те же, что в плане (PINNED_CORES),
    exe тоже с SHA-256, адрес загрузки — релиз самого проекта на GitHub, версия годится в путь, текст
    GPL-3.0 (кладётся рядом с sing-box при установке) попал в сборку."""
    try:
        from .vpnclient import engines
    except ImportError:
        if frozen:
            raise
        return "модуля ядер нет (запуск из исходников)"
    found = []
    for name, plan in PINNED_CORES.items():
        s = engines.CORES.get(name)
        if s is None:
            raise ValueError(f"нет закреплённого ядра {name}")
        if (s.asset, s.zip_size, s.zip_sha256) != (plan["asset"], plan["size"], plan["sha256"]):
            raise ValueError(f"{name}: закреплённый архив не совпал с планом")
        if not (_SHA256.fullmatch(s.zip_sha256) and _SHA256.fullmatch(s.exe_sha256)):
            raise ValueError(f"{name}: хеш не похож на SHA-256")
        url = s.release_url()
        if url != plan["url"] or not url.startswith(f"https://github.com/{s.repo}/releases/download/v{s.version}/"):
            raise ValueError(f"{name}: адрес загрузки {url} — не релиз {s.repo}")
        engines.version_dir(name, s.version)
        found.append(f"{name} {s.version}")
    gpl = engines.gpl_text_path()
    if not gpl.is_file():
        raise FileNotFoundError(f"нет текста GPL-3.0: {gpl}")
    return "закреплены " + ", ".join(found) + "; адреса — релизы GitHub; текст GPL-3.0 на месте"


def check_webp() -> str:
    """QR своего VPN принимается и из .webp (vpnclient/qr.py): Pillow в сборке обязан её открыть.
    Импорта библиотеки для этого мало — в 1.2.2 расширение _webp было исключено из exe."""
    import io
    from PIL import Image
    buffer = io.BytesIO()
    Image.new("RGB", (8, 8), (255, 255, 255)).save(buffer, format="WEBP")
    buffer.seek(0)
    with Image.open(buffer) as image:
        image.load()
        if image.format != "WEBP" or image.size != (8, 8):
            raise ValueError(f"WebP прочитан неверно: {image.format} {image.size}")
    return "WebP записывается и читается"


# Оглавление папки licenses (build/third_party.py): «Название версия — лицензия: папка/файл, папка/файл».
_LICENSE_LINE = re.compile(r"^.+ — .+: (?P<files>[^:]+)$")


def check_licenses(root: Path, frozen: bool) -> str:
    """Тексты лицензий сторонних компонентов (папка licenses сборки): оглавление на месте, и каждый
    названный в нём файл — тоже. Из исходников папки нет: её собирает сборка."""
    index = root / "README.txt"
    if not frozen and not index.is_file():
        return "запуск из исходников: папку licenses собирает сборка"
    lines = [m for m in map(_LICENSE_LINE.match, index.read_text(encoding="utf-8").splitlines()) if m]
    files = [name.strip() for m in lines for name in m.group("files").split(",")]
    missing = [name for name in files if not (root / name).is_file()]
    if not lines or missing:
        raise FileNotFoundError(f"в {root} нет текстов лицензий: {missing[:5] or 'оглавление пустое'}")
    return f"компонентов: {len(lines)}, текстов лицензий: {len(files)}"


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
                "httpx", "h2.connection", "certifi", "bottle", "qrcode", "zxingcpp"]
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
        from .filehash import sha256_file
        from .zapret import pack, strategies
        manifest = pack.bundled_manifest()
        if manifest is None:
            raise FileNotFoundError("bundled.json")
        digest = sha256_file(manifest["zip"])
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

    def vpnclient_parsing():
        return check_vpnclient_parsing()

    def vpnclient_modules():
        return check_vpnclient_modules()

    def vpnclient_cores():
        return check_core_pins(frozen=bool(getattr(sys, "frozen", False)))

    def licenses():
        return check_licenses(paths.resource_dir() / "licenses", frozen=bool(getattr(sys, "frozen", False)))

    def window_engine():
        # То же, что main() до создания окна: загрузка движка окна pywebview и замок навигации. Движок при
        # загрузке ищет свои библиотеки (WebView2, папки runtimes всех архитектур) — без них exe падает на старте.
        from . import webview_guard
        webview_guard.install()
        return "движок edgechromium загружается, замок навигации поставлен"

    _check(results, "Библиотеки", imports)
    _check(results, "Сертификаты", certifi_bundle)
    _check(results, "Файлы интерфейса", ui_files)
    _check(results, "Встроенный пакет zapret", bundled_pack)
    _check(results, "Ядро Telegram-прокси", proxy_core)
    _check(results, "Помощь и проверки", helpers)
    _check(results, "Сеть и VPN", network)
    _check(results, "Значок", icon)
    _check(results, "Картинки WebP (QR)", check_webp)
    _check(results, "Свой VPN: модули", vpnclient_modules)
    _check(results, "Свой VPN: разбор и конфиг", vpnclient_parsing)
    _check(results, "Свой VPN: закреплённые ядра", vpnclient_cores)
    _check(results, "Лицензии сторонних компонентов", licenses)
    _check(results, "Окно WebView2", window_engine)

    report = {"version": __version__, "frozen": bool(getattr(sys, "frozen", False)),
              "ok": all(r["ok"] for r in results), "checks": results}
    Path(report_path).write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0 if report["ok"] else 1
