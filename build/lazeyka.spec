# -*- mode: python ; coding: utf-8 -*-
# Сборка: powershell -ExecutionPolicy Bypass -File build\build.ps1
import os

from PyInstaller.utils.hooks import collect_data_files, collect_dynamic_libs, collect_submodules

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
    "zxingcpp", "zxingcpp.zxingcpp", *collect_submodules("qrcode"),
]

a = Analysis(
    [p("app", "__main__.py")],
    pathex=[ROOT],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    excludes=["setuptools", "distutils", "_distutils_hack", "tkinter", "pytest", "unittest.mock",
              "PIL._avif", "PIL._webp", "PIL._imagingtk", "PIL.ImageTk"],
)
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
