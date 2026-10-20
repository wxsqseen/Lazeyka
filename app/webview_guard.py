"""Замок навигации для окна WebView2.

pywebview внедряет объект API в любую страницу, которую загрузило окно, и не
проверяет, откуда пришёл вызов. Приложение работает с правами администратора,
поэтому чужая страница в окне (перетащенная ссылка, переход по ссылке) получила
бы доступ к его методам. Здесь:

- окну разрешено открывать только адрес нашего интерфейса (первая навигация —
  на встроенный сервер 127.0.0.1); всё остальное отменяется, а веб-ссылки
  открываются в обычном браузере пользователя без наших прав;
- запросы новых окон (target=_blank) идут туда же, а не в webbrowser.open,
  который запустил бы браузер с правами администратора;
- перетаскивание файлов и ссылок в окно выключено.
"""
from __future__ import annotations

import logging
from urllib.parse import urlsplit

from . import winutil

log = logging.getLogger("lazeyka.webview")

_installed = False


def _origin(uri: str) -> str | None:
    parts = urlsplit(uri)
    if parts.scheme != "http" or parts.hostname != "127.0.0.1" or not parts.port:
        return None
    return f"http://127.0.0.1:{parts.port}"


def _open_outside(uri: str) -> None:
    if uri.startswith(("https://", "http://")) and len(uri) <= 2000:
        winutil.open_unelevated(uri)


ALLOW = "allow"          # пропустить
REFUSE = "refuse"        # отменить
OUTSIDE = "outside"      # отменить и открыть в обычном браузере пользователя


def navigation_decision(uri: str, allowed: str | None) -> tuple[str, str | None]:
    """Что делать с навигацией окна — и адрес интерфейса, закреплённый после неё.

    Первая навигация закрепляет встроенный сервер 127.0.0.1, другой адрес — отказ. Дальше разрешены только
    этот адрес и пути под ним, посторонний отменяется и уходит в браузер. about:blank pywebview открывает
    сам — пропускаем, ничего не закрепляя."""
    if uri == "about:blank":
        return ALLOW, allowed
    if allowed is None:
        origin = _origin(uri)
        return (REFUSE, None) if origin is None else (ALLOW, origin)
    if uri == allowed or uri.startswith(allowed + "/"):
        return ALLOW, allowed
    return OUTSIDE, allowed


def install() -> None:
    """Подменяет обработчики EdgeChrome до создания окна."""
    global _installed
    if _installed:
        return
    from webview.platforms import edgechromium

    cls = edgechromium.EdgeChrome
    original_nav = cls.on_navigation_start
    original_ready = cls.on_webview_ready

    def on_navigation_start(self, sender, args):
        uri = str(args.Uri)
        decision, self._lazeyka_origin = navigation_decision(uri, getattr(self, "_lazeyka_origin", None))
        if decision == ALLOW:
            return original_nav(self, sender, args)
        args.Cancel = True
        if decision == REFUSE:
            log.error("Первая навигация окна не на встроенный сервер: %s — отменена", uri[:200])
        else:
            log.warning("Окно пыталось открыть посторонний адрес — отменено: %s", uri[:200])
            _open_outside(uri)
        return None

    def on_new_window_request(self, sender, args):
        args.Handled = True
        _open_outside(str(args.Uri))

    def on_webview_ready(self, sender, args):
        result = original_ready(self, sender, args)
        try:
            sender.AllowExternalDrop = False
        except Exception:  # noqa: BLE001
            log.warning("Не удалось выключить перетаскивание в окно", exc_info=True)
        return result

    cls.on_navigation_start = on_navigation_start
    cls.on_new_window_request = on_new_window_request
    cls.on_webview_ready = on_webview_ready
    _installed = True
    log.debug("Замок навигации WebView2 установлен")
