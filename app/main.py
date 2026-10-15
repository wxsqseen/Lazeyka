"""Точка входа: один экземпляр, права администратора, окно и значок в трее."""
from __future__ import annotations

import argparse
import ctypes
import logging
import os
import sys
import threading
from ctypes import wintypes

from . import APP_ID, APP_NAME, paths, winutil
from . import log as applog

log = logging.getLogger("lazeyka.main")

DARK_BG = "#111214"
LIGHT_BG = "#F4F4F2"
WEBVIEW2_URL = "https://developer.microsoft.com/microsoft-edge/webview2/"

_user32 = ctypes.WinDLL("user32", use_last_error=True)
_user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
_user32.PostMessageW.restype = wintypes.BOOL
_user32.IsIconic.argtypes = [wintypes.HWND]
_user32.IsIconic.restype = wintypes.BOOL
_user32.SetWindowPos.argtypes = [wintypes.HWND, wintypes.HWND, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                                 ctypes.c_int, wintypes.UINT]
_user32.SetWindowPos.restype = wintypes.BOOL
WM_CANCELMODE = 0x001F


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog=APP_ID, add_help=False)
    parser.add_argument("--autostart", action="store_true", help="запуск при входе в Windows (свёрнуто)")
    parser.add_argument("--replace", action="store_true", help="дождаться завершения прежнего экземпляра")
    parser.add_argument("--no-elevate", action="store_true", help="не запрашивать права администратора")
    parser.add_argument("--hidden", action="store_true", help="сразу свернуть в трей")
    parser.add_argument("--selftest", metavar="REPORT", help="проверить сборку и записать отчёт в JSON")
    args, _unknown = parser.parse_known_args(argv)
    return args


def _system_dark() -> bool:
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                            r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize") as key:
            return winreg.QueryValueEx(key, "AppsUseLightTheme")[0] == 0
    except OSError:
        return True


def _is_dark(theme: str) -> bool:
    return theme == "dark" or (theme == "system" and _system_dark())


def _title_bar(hwnd: int, dark: bool) -> None:
    """Цвет заголовка окна. pywebview сам красит его под тему Windows; это нужно,
    только если в настройках выбрана тема, отличная от системной."""
    try:
        value = ctypes.c_int(1 if dark else 0)
        dwm = ctypes.WinDLL("dwmapi")
        for attr in (20, 19):  # DWMWA_USE_IMMERSIVE_DARK_MODE: новые и старые сборки Windows 10
            if dwm.DwmSetWindowAttribute(ctypes.c_void_p(hwnd), attr, ctypes.byref(value),
                                         ctypes.sizeof(value)) == 0:
                break
        # SWP_NOSIZE | SWP_NOMOVE | SWP_NOZORDER | SWP_FRAMECHANGED — перерисовать рамку сейчас
        _user32.SetWindowPos(hwnd, None, 0, 0, 0, 0, 0x0001 | 0x0002 | 0x0004 | 0x0020)
    except Exception:  # noqa: BLE001
        log.debug("Цвет заголовка не применён", exc_info=True)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    if args.selftest:
        from .selftest import run as run_selftest
        return run_selftest(args.selftest)
    admin = winutil.is_admin()
    security_notes: list[str] = []
    security_error: Exception | None = None
    if admin:
        from .security import secure_data_root
        try:
            security_notes = secure_data_root()  # до любого чтения или запуска из папки данных
        except OSError as exc:
            security_error = exc
    log_file = applog.setup(paths.logs_dir(allow_create_data=admin and security_error is None))
    for note in security_notes:
        log.warning("Папка данных: %s", note)
    if security_error is not None:
        log.error("Папку данных не удалось защитить: %s", security_error)
        winutil.message_box(f"Папку данных {paths.DATA} не удалось защитить:\n{security_error}\n\n"
                            "Лазейка не будет запускать из неё обход. Удалите папку вручную и запустите снова.",
                            APP_NAME, error=True)
        return 1

    instance = winutil.SingleInstance(APP_ID)
    if instance.already_running:
        if args.replace:
            if not instance.wait_for_previous(20):
                log.error("Прежний экземпляр не завершился")
                return 1
        else:
            instance.signal_existing()
            return 0

    if not admin and not args.no_elevate:
        passthrough = [a for a in sys.argv[1:] if a not in ("--replace",)]
        result = winutil.relaunch_as_admin(paths.launch_command() + passthrough + ["--replace"])
        if result == "launched":
            return 0
        log.warning("Работаю без прав администратора (%s)", result)

    import webview  # тяжёлый импорт — только после проверок выше

    from . import webview_guard
    from .api import Api
    from .core import Core
    from .tray import Tray

    webview_guard.install()  # окно может открыть только наш интерфейс
    core = Core(autostarted=args.autostart, log_dir=log_file.parent)
    log.info("Журнал: %s", log_file)
    core.startup()

    theme = core.settings.get("ui", "theme")
    first_run = core.settings.get("first_run")
    hidden = not first_run and (args.autostart or args.hidden or core.settings.get("ui", "start_minimized"))

    window = webview.create_window(
        APP_NAME, url=str(paths.ui_dir() / "index.html"), js_api=Api(core),
        width=1120, height=740, min_size=(920, 620), hidden=hidden,
        background_color=DARK_BG if _is_dark(theme) else LIGHT_BG, text_select=True,
    )
    tray = Tray(core)
    quitting = threading.Event()
    hwnd_box: dict[str, int] = {}

    core.ui_visible = not hidden

    def went_to_tray() -> None:
        core.ui_visible = False
        if not core.settings.get("ui", "tray_hint_shown"):
            core.settings.update(lambda d: d["ui"].__setitem__("tray_hint_shown", True))
            tray.notify("Лазейка продолжает работать в трее. Открыть окно — щелчок по значку, "
                        "выйти — правой кнопкой → «Выход».")

    def show() -> None:
        core.ui_visible = True
        try:
            window.show()
            hwnd = hwnd_box.get("hwnd")
            if hwnd and _user32.IsIconic(hwnd):
                window.restore()
        except Exception:  # noqa: BLE001
            log.debug("Окно не показано", exc_info=True)

    def hide() -> None:
        window.hide()
        went_to_tray()

    def stop_tray() -> None:
        menu = getattr(tray.icon, "_menu_hwnd", None)
        if menu:
            _user32.PostMessageW(menu, WM_CANCELMODE, 0, 0)  # иначе stop() при открытом меню зависает
        tray.stop()

    def quit_app() -> None:
        if quitting.is_set():
            return
        quitting.set()
        log.info("Выход по запросу пользователя")

        def finish() -> None:
            core.shutdown()
            stop_tray()
            instance.close()
            try:
                window.destroy()
            except Exception:  # noqa: BLE001
                pass

        threading.Thread(target=finish, name="quit", daemon=True).start()

    def on_form_closing(sender, event_args) -> None:
        # Здесь нельзя вызывать evaluate_js: это взаимоблокировка с потоком окна.
        if quitting.is_set() or str(event_args.CloseReason) != "UserClosing":
            return  # выход из системы, завершение Windows или наш собственный destroy()
        event_args.Cancel = True
        if core.settings.get("ui", "close_to_tray"):
            sender.Hide()
            went_to_tray()
        else:
            quit_app()

    def on_before_show() -> None:
        # pywebview передаёт окно, только если параметр назван ровно `window`; берём из замыкания.
        form = window.native
        hwnd_box["hwnd"] = form.Handle.ToInt64()
        form.FormClosing += on_form_closing
        current = core.settings.get("ui", "theme")
        if current != "system":
            _title_bar(hwnd_box["hwnd"], current == "dark")

    def on_loaded() -> None:
        renderer = getattr(webview, "renderer", None)
        if renderer and renderer != "edgechromium":
            log.error("WebView2 не найден, движок окна: %s", renderer)
            winutil.message_box("Для окна Лазейки нужен компонент Microsoft Edge WebView2 Runtime. "
                                "Сейчас откроется страница загрузки — установите его и запустите "
                                "Лазейку снова. Обход и Telegram-прокси продолжают работать.",
                                APP_NAME, error=True)
            winutil.open_unelevated(WEBVIEW2_URL)

    def on_theme(theme_value: str) -> None:
        hwnd = hwnd_box.get("hwnd")
        if hwnd:
            _title_bar(hwnd, _is_dark(theme_value))

    window.events.before_show += on_before_show
    window.events.loaded += on_loaded

    selfcheck = os.environ.get("LAZEYKA_UI_SELFCHECK")
    if selfcheck and not admin:  # с правами не включаем: это запись файла по пути из окружения
        def run_ui_selfcheck() -> None:
            import json
            import time
            time.sleep(4)
            probe = ("JSON.stringify({api: !!(window.pywebview && window.pywebview.api && "
                     "typeof window.pywebview.api.get_state === 'function'), "
                     "methods: window.pywebview && window.pywebview.api ? Object.keys(window.pywebview.api).length : 0, "
                     "nav: Array.from(document.querySelectorAll('nav a, nav button')).map(e => e.textContent.trim()).filter(Boolean), "
                     "nodes: document.querySelectorAll('#app *').length, url: location.href})")
            report: dict = {}

            def measure() -> dict:
                for _ in range(20):
                    raw = window.evaluate_js(probe)
                    if raw:
                        return json.loads(raw)
                    time.sleep(0.5)
                return {"error": "страница не ответила"}

            try:
                report["before"] = measure()
                # blob-страницу того же источника Chromium открыть разрешает — отменить её
                # должен именно замок навигации (webview_guard), а не браузер.
                window.evaluate_js("location.href = URL.createObjectURL("
                                   "new Blob(['<h1>чужая страница</h1>'], {type: 'text/html'}))")
                time.sleep(1.5)
                report["after_navigation_attempt"] = measure()
            except Exception as exc:  # noqa: BLE001
                report["error"] = repr(exc)
            with open(selfcheck, "w", encoding="utf-8") as f:
                json.dump(report, f, ensure_ascii=False, indent=2)
            quit_app()

        window.events.loaded += lambda: threading.Thread(target=run_ui_selfcheck, daemon=True).start()

    core.on_show = show
    core.on_hide = hide
    core.on_quit = quit_app
    core.on_theme = on_theme
    core.on_status_change = tray.refresh
    core.on_toast = tray.notify
    instance.listen(show)
    tray.start()
    tray.refresh()

    icon_path = paths.resource_dir() / "assets" / "icon.ico"
    webview.start(gui="edgechromium", private_mode=True, debug=False,
                  icon=str(icon_path) if icon_path.is_file() else None)
    if not quitting.is_set():
        quitting.set()
        core.shutdown()
        stop_tray()
    log.info("%s завершён", APP_NAME)
    return 0


if __name__ == "__main__":
    sys.exit(main())
