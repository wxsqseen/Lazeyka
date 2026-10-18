"""Журнал: файл с ротацией и кольцевой буфер для страницы «Журнал».

Секреты своего VPN (ключи, пароли, ссылки серверов, адреса подписок) вычищаются фильтром на
самих обработчиках: они могут прийти не только из вывода ядра, но и через notify(),
log.exception и repr исключений. Владельцы секретов регистрируют их через add_secrets().
"""
from __future__ import annotations

import collections
import logging
import logging.handlers
import re
import threading
import time
import urllib.parse
from pathlib import Path
from typing import Iterable

PROXY_LOGGER = "tg-mtproto-proxy"
ZAPRET_LOGGER = "lazeyka.zapret"
WINWS_LOGGER = "lazeyka.zapret.winws"
VPNCLIENT_LOGGER = "lazeyka.vpnclient"   # свой VPN; «lazeyka.vpn» — совместимость с VPN, это «app»

_LEVELS = {
    logging.DEBUG: "debug",
    logging.INFO: "info",
    logging.WARNING: "warn",
    logging.ERROR: "error",
    logging.CRITICAL: "error",
}


def source_of(logger_name: str) -> str:
    # Сначала свой VPN: префикс «lazeyka.vpn» занят модулем совместимости.
    if logger_name == VPNCLIENT_LOGGER or logger_name.startswith(VPNCLIENT_LOGGER + "."):
        return "vpn"
    if logger_name == PROXY_LOGGER or logger_name.startswith(PROXY_LOGGER + ".") \
            or logger_name.startswith("lazeyka.tg"):
        return "tg"
    if logger_name.startswith(ZAPRET_LOGGER):
        return "zapret"
    return "app"


# ------------------------------------------------------------ секреты

MIN_SECRET = 6          # короче — слишком часто совпадает с обычным текстом журнала
MASK = "<секрет>"
_secrets: collections.Counter = collections.Counter()
_secrets_lock = threading.Lock()
_pattern: re.Pattern | None = None


def _token_like(text: str) -> bool:
    """Кусок адреса похож на токен, а не на слово вроде «subscribe»."""
    return len(text) >= 16 or (len(text) >= 10 and any(c.isdigit() for c in text)
                               and any(c.isalpha() for c in text))


def _variants(secret: str) -> set[str]:
    """Сам секрет, его percent-кодировка и у адресов — путь с запросом и токен из пути."""
    out = {secret, urllib.parse.quote(secret, safe="")}
    if "://" in secret:
        try:
            parts = urllib.parse.urlsplit(secret)
        except ValueError:
            parts = None
        if parts is not None:
            if parts.path.strip("/"):
                out.add(parts.path + (f"?{parts.query}" if parts.query else ""))
            last = parts.path.rstrip("/").rsplit("/", 1)[-1]
            if _token_like(last):
                out.add(last)
            if parts.query:
                out.add(parts.query)
    return {v for v in out if len(v) >= MIN_SECRET}


def _rebuild() -> None:
    global _pattern
    items = sorted(_secrets, key=len, reverse=True)
    _pattern = re.compile("|".join(re.escape(s) for s in items)) if items else None


def add_secrets(values: Iterable[str | None]) -> None:
    """Запомнить строки, которых не должно быть в журнале (повторный вызов — счётчик ссылок)."""
    with _secrets_lock:
        for value in values:
            if isinstance(value, str):
                for v in _variants(value.strip()):
                    _secrets[v] += 1
        _rebuild()


def remove_secrets(values: Iterable[str | None]) -> None:
    with _secrets_lock:
        for value in values:
            if isinstance(value, str):
                for v in _variants(value.strip()):
                    if _secrets[v] <= 1:
                        _secrets.pop(v, None)
                    else:
                        _secrets[v] -= 1
        _rebuild()


def scrub(text: str) -> str:
    """Текст без зарегистрированных секретов."""
    pattern = _pattern
    if pattern is None or not text:
        return text
    return pattern.sub(MASK, text)


class SecretFilter(logging.Filter):
    """Вычищает секреты из сообщения, трассировки и стека записи — до любого обработчика."""

    def filter(self, record: logging.LogRecord) -> bool:
        if _pattern is None:
            return True
        try:
            message = record.getMessage()
        except Exception:  # noqa: BLE001 — журнал не должен падать из-за кривого сообщения
            message = str(record.msg)
        clean = scrub(message)
        if clean != message:
            record.msg, record.args = clean, ()
        if record.exc_info and record.exc_info[1] is not None and not record.exc_text:
            record.exc_text = logging.Formatter().formatException(record.exc_info)
        if record.exc_text:
            record.exc_text = scrub(record.exc_text)
        if record.stack_info:
            record.stack_info = scrub(record.stack_info)
        return True


secret_filter = SecretFilter()


class RingBuffer(logging.Handler):
    """Хранит последние строки журнала для интерфейса."""

    def __init__(self, capacity: int = 5000):
        super().__init__(level=logging.DEBUG)
        self._lines: collections.deque = collections.deque(maxlen=capacity)
        self._next_id = 1
        self._lock_lines = threading.Lock()

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = record.getMessage()
            if record.exc_info and record.exc_info[1] is not None:
                msg = f"{msg}: {record.exc_info[1]!r}"
        except Exception:  # noqa: BLE001 — журнал не должен падать из-за кривого сообщения
            msg = str(record.msg)
        msg = scrub(msg)   # repr исключения фильтр не видит — чистим и здесь
        with self._lock_lines:
            self._lines.append({
                "id": self._next_id,
                "t": record.created,
                "src": source_of(record.name),
                "lvl": _LEVELS.get(record.levelno, "info"),
                "msg": msg,
            })
            self._next_id += 1

    def since(self, after_id: int, source: str = "all", limit: int = 1000) -> dict:
        with self._lock_lines:
            lines = [ln for ln in self._lines
                     if ln["id"] > after_id and (source == "all" or ln["src"] == source)]
            last_id = self._next_id - 1
        return {"lines": lines[-limit:], "last_id": last_id}


ring = RingBuffer()
ring.addFilter(secret_filter)


class _ProxyCensor(logging.Filter):
    """Прячет домены CF-прокси в журнале так же, как это делает tg-ws-proxy."""

    def __init__(self):
        super().__init__()
        self._impl = None

    def set_impl(self, impl: logging.Filter | None) -> None:
        self._impl = impl

    def filter(self, record: logging.LogRecord) -> bool:
        if self._impl is not None:
            try:
                return self._impl.filter(record)
            except Exception:  # noqa: BLE001
                return True
        return True


proxy_censor = _ProxyCensor()


def setup(log_dir: Path, verbose: bool = False) -> Path:
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "lazeyka.log"
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    for handler in list(root.handlers):
        root.removeHandler(handler)

    fmt = logging.Formatter("%(asctime)s  %(levelname)-7s %(name)s: %(message)s", "%Y-%m-%d %H:%M:%S")
    fh = logging.handlers.RotatingFileHandler(log_file, maxBytes=2 * 1024 * 1024, backupCount=2,
                                              encoding="utf-8")
    fh.setFormatter(fmt)
    fh.setLevel(logging.DEBUG if verbose else logging.INFO)
    fh.addFilter(secret_filter)
    root.addHandler(fh)
    ring.setLevel(logging.DEBUG if verbose else logging.INFO)
    ring.addFilter(secret_filter)
    root.addHandler(ring)

    logging.getLogger(PROXY_LOGGER).addFilter(proxy_censor)
    for noisy in ("asyncio", "httpx", "httpcore", "hpack", "h2", "PIL", "urllib3", "pywebview"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    logging.Formatter.converter = time.localtime
    return log_file


def set_verbose(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    ring.setLevel(level)
    for handler in logging.getLogger().handlers:
        if isinstance(handler, logging.handlers.RotatingFileHandler):
            handler.setLevel(level)
