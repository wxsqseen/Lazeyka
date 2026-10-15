"""Журнал: файл с ротацией и кольцевой буфер для страницы «Журнал»."""
from __future__ import annotations

import collections
import logging
import logging.handlers
import threading
import time
from pathlib import Path

PROXY_LOGGER = "tg-mtproto-proxy"
ZAPRET_LOGGER = "lazeyka.zapret"
WINWS_LOGGER = "lazeyka.zapret.winws"

_LEVELS = {
    logging.DEBUG: "debug",
    logging.INFO: "info",
    logging.WARNING: "warn",
    logging.ERROR: "error",
    logging.CRITICAL: "error",
}


def source_of(logger_name: str) -> str:
    if logger_name == PROXY_LOGGER or logger_name.startswith(PROXY_LOGGER + ".") \
            or logger_name.startswith("lazeyka.tg"):
        return "tg"
    if logger_name.startswith(ZAPRET_LOGGER):
        return "zapret"
    return "app"


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
    root.addHandler(fh)
    ring.setLevel(logging.DEBUG if verbose else logging.INFO)
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
