# -*- mode: python ; coding: utf-8 -*-
# Сборка: powershell -ExecutionPolicy Bypass -File build\build.ps1
import os
import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_dynamic_libs, collect_submodules

sys.path.insert(0, SPECPATH)
import third_party  # noqa: E402 — build/third_party.py: лицензии того, что попало в exe

ROOT = os.path.abspath(os.path.join(SPECPATH, os.pardir))


def p(*parts):
    return os.path.join(ROOT, *parts)


# Раскладка в сборке повторяет дерево проекта: <_MEIPASS>/app/ui, <_MEIPASS>/vendor/zapret, ...
datas = [
    (p("app", "ui"), "app/ui"),
    (p("assets"), "assets"),
    (p("vendor", "zapret"), "vendor/zapret"),
    (p("app", "vendor", "tgws_proxy", "LICENSE"), "app/vendor/tgws_proxy"),
    (p("app", "vendor", "tgws_proxy", "UPSTREAM.md"), "app/vendor/tgws_proxy"),
    (p("LICENSE"), "."),
    (p("THIRD_PARTY.md"), "."),
]
# Свой VPN: ядер в exe нет — Лазейка скачивает их с GitHub при запуске (решение владельца 2026-10-18;
# vendor/cores — только кэш для статических проверок в тестах). В сборку — тексты лицензий: GPL-3.0
# кладётся рядом с установленным sing-box.
if os.path.isdir(p("app", "vpnclient", "licenses")):
    datas.append((p("app", "vpnclient", "licenses"), "app/vpnclient/licenses"))
# Хуки pywebview и pythonnet справляются сами; это — страховка.
datas += collect_data_files("webview", subdir="js")
datas += collect_data_files("webview", subdir="lib")
datas += collect_data_files("pythonnet")
datas += collect_data_files("certifi")
binaries = collect_dynamic_libs("clr_loader")

hiddenimports = [
    "pystray._win32",
    "anyio._backends._asyncio",
    # Ядро tg-ws-proxy загружается через importlib по вычисляемому имени — его модули
    # статический анализ не видит.
    *collect_submodules("app.vendor.tgws_proxy"),
    # Менеджер своего VPN подгружает модули пакета по имени (importlib) — статический анализ
    # видит не все: в 1.2.0 из exe выпали store и subscription.
    *collect_submodules("app.vpnclient"),
    # Стандартные модули, которые может импортировать обновлённое ядро прокси.
    "secrets", "hmac", "ipaddress", "zlib", "gzip", "uuid", "statistics", "selectors",
    "concurrent.futures", "http.client", "email.utils", "dataclasses", "enum", "heapq", "bisect",
    # QR: zxingcpp — пакет-обёртка над расширением; qrcode выбирает фабрику картинок по имени.
    # Тесты qrcode (qrcode.tests) в exe не нужны: они тянут pytest и unittest.
    "zxingcpp", "zxingcpp.zxingcpp",
    *collect_submodules("qrcode", filter=lambda name: not name.startswith("qrcode.tests")),
    # QR из картинки .webp (vpnclient/qr.py её принимает): модуль формата Pillow и его расширение.
    "PIL.WebPImagePlugin", "PIL._webp",
]

a = Analysis(
    [p("app", "__main__.py")],
    pathex=[ROOT],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    # httpx._main — консольная утилита httpx (тянет pygments, rich, click); без неё httpx работает сам.
    excludes=["setuptools", "distutils", "_distutils_hack", "tkinter", "pytest", "_pytest", "unittest.mock",
              "httpx._main", "pygments", "PIL._avif", "PIL._imagingtk", "PIL.ImageTk"],
)
# Сборка — только для 64-битной Windows: Android-часть pywebview и библиотеки под x86/arm64 не нужны.
_FOREIGN = ("pywebview-android.jar", "\\win-arm64\\", "\\win-x86\\", "webbrowserinterop.x86.dll",
            "\\ffi\\dlls\\x86\\", "\\ffi\\dlls\\arm64\\")


def _ours(entry):
    name = entry[0].replace("/", "\\").lower()
    return not any(mark in name for mark in _FOREIGN)


a.datas = [entry for entry in a.datas if _ours(entry)]
a.binaries = [entry for entry in a.binaries if _ours(entry)]
# Тексты лицензий всего стороннего, что попало в exe, — папкой licenses/ (build/third_party.py).
a.datas += third_party.license_datas(a.scripts + a.pure + a.binaries + a.datas, project_root=Path(ROOT),
                                     third_party_md=Path(p("THIRD_PARTY.md")), work_dir=Path(workpath))
pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, a.binaries, a.datas, [],
    name="Lazeyka",
    console=False,
    upx=False,
    icon=[p("assets", "icon.ico")],
    version=p("build", "version_info.txt"),
    uac_admin=False,      # права запрашивает само приложение: без них работает ограниченный режим
    uac_uiaccess=False,
    disable_windowed_traceback=False,
    runtime_tmpdir=None,
)
