"""Клиент clash API sing-box и сэмплер трафика в своём потоке.

API слушает только 127.0.0.1, секрет — новый на каждый запуск (Bearer). Запросы — напрямую
(ProxyHandler({})): системный прокси в режиме «системный прокси» указывает на само ядро. Формы
ответов sing-box 1.14.3 — docs/vpnclient-plan.md, 5.7 и отчёт спайка (раздел 6).
"""
from __future__ import annotations

import collections
import json
import logging
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from ..errors import UserError

log = logging.getLogger("lazeyka.vpnclient.clash")

TICK_TIMEOUT = 0.5           # тикер и страница не ждут ядро дольше
MAX_DELAY_TIMEOUT = 32767    # timeout задержки в sing-box — int16, больше — «Body invalid»
GROUP_BATCH = 10             # /group/…/delay проверяет членов группы по 10 параллельно
RESPONSE_LIMIT = 16 * 1024 * 1024
HISTORY_POINTS = 120         # две минуты точек скорости для графика
CONNECTIONS_EVERY = 5.0      # тяжёлый снимок соединений — не чаще
STREAM_READ_TIMEOUT = 2.5    # строка /traffic приходит раз в секунду; дольше — поток оборвался
RETRY_PAUSE = 1.0


class ClashError(UserError):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


def _quote(name: str) -> str:
    return urllib.parse.quote(name, safe="")


class ClashClient:
    def __init__(self, port: int, secret: str, *, host: str = "127.0.0.1", timeout: float = TICK_TIMEOUT):
        self.port = port
        self.base = f"http://{host}:{port}"
        self.timeout = timeout
        self._secret = secret
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def __repr__(self) -> str:   # секрет — только в заголовке запроса
        return f"ClashClient({self.base})"

    def _request(self, method: str, path: str, *, query: dict[str, Any] | None = None,
                 body: dict | None = None) -> urllib.request.Request:
        url = self.base + path + ("?" + urllib.parse.urlencode(query) if query else "")
        headers = {"Authorization": f"Bearer {self._secret}"}
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        return urllib.request.Request(url, data=data, method=method, headers=headers)

    def _call(self, method: str, path: str, *, query: dict[str, Any] | None = None, body: dict | None = None,
              timeout: float | None = None, expect: tuple[int, ...] = (200,)) -> Any:
        req = self._request(method, path, query=query, body=body)
        try:
            with self._opener.open(req, timeout=timeout or self.timeout) as resp:
                status = resp.status
                raw = resp.read(RESPONSE_LIMIT + 1)
        except urllib.error.HTTPError as exc:
            raise ClashError(_api_message(exc), exc.code) from exc
        except (urllib.error.URLError, OSError, ValueError) as exc:
            reason = getattr(exc, "reason", exc)
            raise ClashError(f"ядро не отвечает на {method} {path}: {reason}") from exc
        if status not in expect:
            raise ClashError(f"ядро ответило {status} на {method} {path}", status)
        if len(raw) > RESPONSE_LIMIT:
            raise ClashError(f"слишком большой ответ ядра на {path}")
        if not raw:
            return None
        try:
            return json.loads(raw.decode("utf-8"))
        except ValueError as exc:
            raise ClashError(f"непонятный ответ ядра на {path}") from exc

    # ---------------------------------------------------------------- запросы

    def version(self, timeout: float | None = None) -> str:
        data = self._call("GET", "/version", timeout=timeout)
        if not isinstance(data, dict) or not isinstance(data.get("version"), str):
            raise ClashError("ядро не сообщило версию")
        return data["version"]

    def connections(self, timeout: float | None = None) -> dict:
        data = self._call("GET", "/connections", timeout=timeout)
        return data if isinstance(data, dict) else {}

    def proxies(self) -> dict[str, dict]:
        data = self._call("GET", "/proxies")
        proxies = data.get("proxies") if isinstance(data, dict) else None
        return proxies if isinstance(proxies, dict) else {}

    def proxy(self, name: str) -> dict:
        data = self._call("GET", f"/proxies/{_quote(name)}")
        return data if isinstance(data, dict) else {}

    def select(self, selector: str, name: str) -> None:
        """Переключить селектор без перезапуска ядра."""
        try:
            self._call("PUT", f"/proxies/{_quote(selector)}", body={"name": name}, expect=(204, 200))
        except ClashError as exc:
            raise ClashError(f"переключение «{selector}» на «{name}» не удалось: {exc}", exc.status) from exc

    def close_connections(self) -> None:
        """Закрыть все соединения (после сна: старые уже мертвы)."""
        self._call("DELETE", "/connections", expect=(204, 200))

    def delay(self, name: str, url: str, timeout_ms: int) -> int:
        """Реальная задержка через выход name: HEAD к url через новое соединение, мс."""
        _check_delay_args(url, timeout_ms)
        try:
            data = self._call("GET", f"/proxies/{_quote(name)}/delay", query={"url": url, "timeout": timeout_ms},
                              timeout=timeout_ms / 1000 + 2)
        except ClashError as exc:
            raise _delay_error(exc, timeout_ms) from exc
        ms = data.get("delay") if isinstance(data, dict) else None
        if not isinstance(ms, int) or isinstance(ms, bool) or ms <= 0:
            raise ClashError("нет ответа через сервер", 503)
        return ms

    def group_delay(self, group: str, url: str, timeout_ms: int, *, members: int = GROUP_BATCH) -> dict[str, int]:
        """Задержки всех членов группы одним запросом; не ответившие в результат не попадают."""
        _check_delay_args(url, timeout_ms)
        batches = max(1, -(-members // GROUP_BATCH))
        try:
            data = self._call("GET", f"/group/{_quote(group)}/delay", query={"url": url, "timeout": timeout_ms},
                              timeout=batches * timeout_ms / 1000 + 2)
        except ClashError as exc:
            raise _delay_error(exc, timeout_ms) from exc
        if not isinstance(data, dict):
            return {}
        return {str(k): v for k, v in data.items() if isinstance(v, int) and not isinstance(v, bool) and v > 0}

    def open_traffic(self, timeout: float = STREAM_READ_TIMEOUT):
        """Поток /traffic: по строке {"up","down"} в секунду — приращения байт, не итоги."""
        try:
            return self._opener.open(self._request("GET", "/traffic"), timeout=timeout)
        except urllib.error.HTTPError as exc:
            raise ClashError(_api_message(exc), exc.code) from exc
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise ClashError(f"ядро не отдаёт трафик: {getattr(exc, 'reason', exc)}") from exc


def _api_message(exc: urllib.error.HTTPError) -> str:
    try:
        data = json.loads(exc.read(4096).decode("utf-8"))
        message = data.get("message") if isinstance(data, dict) else None
    except (OSError, ValueError):
        message = None
    return f"{exc.code} {message or exc.reason}"


def _check_delay_args(url: str, timeout_ms: int) -> None:
    # http:// ядро молча заменяет своим адресом проверки — такой замер ничего бы не значил
    if not isinstance(url, str) or not url.startswith("https://"):
        raise ClashError("адрес проверки задержки должен начинаться с https://")
    if not isinstance(timeout_ms, int) or isinstance(timeout_ms, bool) or not 0 < timeout_ms <= MAX_DELAY_TIMEOUT:
        raise ClashError(f"тайм-аут проверки задержки — от 1 до {MAX_DELAY_TIMEOUT} мс")


def _delay_error(exc: ClashError, timeout_ms: int) -> ClashError:
    if exc.status == 504:
        return ClashError(f"нет ответа за {timeout_ms / 1000:g} с", 504)
    if exc.status == 503:
        return ClashError("сервер не ответил: ошибка соединения", 503)
    if exc.status == 404:
        return ClashError("сервера нет в работающей конфигурации", 404)
    return exc


# ------------------------------------------------------------ сэмплер

class TrafficSampler:
    """Свой поток: /traffic — скорость и итоги, /connections раз в 5 с — число соединений и точные итоги,
    текущий член групп «Самый быстрый». Тикер и страница берут только snapshot() — кэш."""

    def __init__(self, client: ClashClient, *, groups: tuple[str, ...] = (), clock=time.time):
        self.client = client
        self.groups = tuple(groups)
        self._clock = clock
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._up = 0
        self._down = 0
        self._up_rate = 0.0
        self._down_rate = 0.0
        self._connections = 0
        self._history: collections.deque = collections.deque(maxlen=HISTORY_POINTS)
        self._now: dict[str, str] = {}
        self._polled = 0.0

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="vpnclient-traffic", daemon=True)
        self._thread.start()

    def stop(self, wait: float = 0.0) -> None:
        """Остановить поток. Обычно ядро к этому моменту уже остановлено, и поток сразу видит конец
        /traffic; иначе выйдет по тайм-ауту чтения. Ответ из другого потока не закрываем: http.client
        к этому не готов. wait > 0 — дождаться потока."""
        self._stop.set()
        if wait > 0 and self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join(wait)

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def snapshot(self) -> dict:
        with self._lock:
            return {"stats": {"up": self._up, "down": self._down, "up_rate": self._up_rate,
                              "down_rate": self._down_rate, "connections": self._connections},
                    "history": [list(p) for p in self._history], "now": dict(self._now)}

    def totals(self) -> tuple[int, int]:
        with self._lock:
            return self._up, self._down

    # ---------------------------------------------------------------- поток

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self._poll_if_due(force=True)
                self._stream()
            except (ClashError, OSError, ValueError) as exc:
                if self._stop.is_set():
                    break
                log.debug("Статистика ядра: %s", exc)
                with self._lock:
                    self._up_rate = self._down_rate = 0.0
            self._stop.wait(RETRY_PAUSE)

    def _stream(self) -> None:
        resp = self.client.open_traffic()
        try:
            while not self._stop.is_set():
                raw = resp.readline()
                if not raw:
                    raise ClashError("поток /traffic закрылся")
                self._on_line(raw)
                self._poll_if_due()
        finally:
            resp.close()

    def _on_line(self, raw: bytes) -> None:
        data = json.loads(raw.decode("utf-8"))
        up = data.get("up") if isinstance(data, dict) else None
        down = data.get("down") if isinstance(data, dict) else None
        if not isinstance(up, int) or not isinstance(down, int):
            return
        with self._lock:
            self._up += up
            self._down += down
            self._up_rate, self._down_rate = float(up), float(down)
            self._history.append((int(self._clock()), self._up_rate, self._down_rate))

    def _poll_if_due(self, force: bool = False) -> None:
        if not force and time.monotonic() - self._polled < CONNECTIONS_EVERY:
            return
        self._polled = time.monotonic()
        snap = self.client.connections()
        now = {}
        for group in self.groups:
            try:
                current = self.client.proxy(group).get("now")
            except ClashError as exc:
                log.debug("Группа %s: %s", group, exc)
                continue
            if isinstance(current, str):
                now[group] = current
        with self._lock:
            conns = snap.get("connections")
            self._connections = len(conns) if isinstance(conns, list) else 0
            for key, attr in (("uploadTotal", "_up"), ("downloadTotal", "_down")):
                value = snap.get(key)
                if isinstance(value, int) and value >= getattr(self, attr):
                    setattr(self, attr, value)
            self._now.update(now)
