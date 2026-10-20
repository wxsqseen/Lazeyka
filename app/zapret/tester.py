"""Подбор стратегии и быстрая проверка доступности.

Повторяет утилиту `utils/test zapret.ps1` из пакета: по очереди запускает
стратегии и проверяет цели из `utils/targets.txt` через curl.exe (HTTP/1.1,
TLS 1.2, TLS 1.3) и ping. Лучшая — с наибольшим числом успешных проверок,
при равенстве — с большим числом ответивших ping.
"""
from __future__ import annotations

import ctypes
import json
import logging
import os
import re
import socket
import tempfile
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Callable

from .. import paths, winutil
from ..errors import UserError
from . import lists, netcfg
from .runner import RunnerError, WinwsProcess, foreign_winws

if TYPE_CHECKING:
    from .manager import ZapretManager

log = logging.getLogger("lazeyka.zapret.test")

DPI_SUITE_URL = "https://hyperion-cs.github.io/dpi-checkers/ru/tcp-16-20/suite.v2.json"
CURL_MODES = {
    "http": ["--http1.1"],
    "tls12": ["--tlsv1.2", "--tls-max", "1.2"],
    "tls13": ["--tlsv1.3", "--tls-max", "1.3"],
}
_DNS_RE = re.compile(r"Could not resolve host|Couldn't resolve host", re.I)
_SSL_RE = re.compile(r"certificate|SSL certificate problem|self[- ]?signed|certificate verify failed|"
                     r"unable to get local issuer certificate", re.I)
# «Не поддерживается» — только то, чего не умеют curl или Windows (TLS 1.3 до Windows 11, ключ старого
# curl). Сброс рукопожатия (код 35, «schannel: failed to receive handshake») — это провал: так режет DPI.
_UNSUP_RE = re.compile(r"does not support|doesn't support|not supported|unsupported protocol|"
                       r"Unrecognized option|Unknown option|unsupported option|unsupported feature|not built-in",
                       re.I)
CURL_FAILED_INIT, CURL_NOT_BUILT_IN, CURL_COULDNT_RESOLVE = 2, 4, 6

DEFAULT_TARGETS = [
    ("Discord Main", "https://discord.com"), ("Discord Gateway", "https://gateway.discord.gg"),
    ("Discord CDN", "https://cdn.discordapp.com"), ("Discord Updates", "https://updates.discord.com"),
    ("YouTube Web", "https://www.youtube.com"), ("YouTube Short", "https://youtu.be"),
    ("YouTube Image", "https://i.ytimg.com"), ("YouTube Video Redirect", "https://redirector.googlevideo.com"),
    ("Google Main", "https://www.google.com"), ("Google Gstatic", "https://www.gstatic.com"),
    ("Cloudflare Web", "https://www.cloudflare.com"), ("Cloudflare CDN", "https://cdnjs.cloudflare.com"),
    ("Cloudflare DNS 1.1.1.1", "PING:1.1.1.1"), ("Cloudflare DNS 1.0.0.1", "PING:1.0.0.1"),
    ("Google DNS 8.8.8.8", "PING:8.8.8.8"), ("Google DNS 8.8.4.4", "PING:8.8.4.4"),
]

QUICK_TARGETS = {
    "discord": ("Discord", ["https://discord.com", "https://gateway.discord.gg", "https://cdn.discordapp.com"]),
    "youtube": ("YouTube", ["https://www.youtube.com", "https://i.ytimg.com",
                            "https://redirector.googlevideo.com"]),
}
# Открываются и без обхода: если ни один — нет интернета. Разные компании, один адрес — без DNS,
# чтобы блокировка одного сайта, корпоративный фильтр или DNS-блокировщик не выглядели как «нет связи».
CONTROL_URLS = ("https://ya.ru", "http://www.msftconnecttest.com/connecttest.txt",
                "https://1.1.1.1/cdn-cgi/trace")
CONTROL_TIMEOUT = 4

# Порядок проб, если подбор ещё ни разу не запускался: самые ходовые стратегии пакета.
DEFAULT_CANDIDATES = ["general", "general (ALT)", "general (ALT2)", "general (FAKE TLS AUTO)",
                      "general (SIMPLE FAKE)", "general (ALT5)"]
MAX_CANDIDATES = 6


@dataclass
class Target:
    name: str
    url: str | None
    ping_host: str | None


def _pretty(key: str) -> str:
    for brand in ("YouTube", "Discord", "Google", "Cloudflare"):
        if key.startswith(brand):
            rest = re.sub(r"(?<=[a-z])(?=[A-Z])", " ", key[len(brand):]).strip()
            return f"{brand} {rest}".strip()
    return re.sub(r"(?<=[a-z])(?=[A-Z])", " ", key)


def load_targets(pack_dir: Path | None) -> list[Target]:
    raw: list[tuple[str, str]] = []
    if pack_dir is not None:
        try:
            for line in (pack_dir / "utils" / "targets.txt").read_text(encoding="utf-8").splitlines():
                m = re.match(r'^\s*(\w+)\s*=\s*"(.+)"\s*$', line)
                if m:
                    raw.append((_pretty(m.group(1)), m.group(2)))
        except OSError:
            pass
    if not raw:
        raw = list(DEFAULT_TARGETS)
    targets = []
    for name, value in raw:
        if value.upper().startswith("PING:"):
            targets.append(Target(name, None, value[5:].strip()))
        else:
            host = re.sub(r"^https?://", "", value).split("/")[0]
            targets.append(Target(name, value, host))
    return targets


def curl_exe() -> str:
    return winutil.system32("curl.exe")


def curl_check(url: str, mode: str, timeout: int = 4, cancel: threading.Event | None = None,
               bind: str | None = None) -> str:
    """bind — IPv4 прямого подключения: при включённом VPN проверяем путь мимо туннеля,
    тот самый, по которому пойдёт сайт, если VPN пропускает его мимо себя."""
    # -q первым и --noproxy: ни .curlrc, ни HTTPS_PROXY не должны незаметно увести проверку в прокси.
    args = [curl_exe(), "-q", "--noproxy", "*", "-I", "-s", "-m", str(timeout), "--connect-timeout",
            str(min(2, timeout)), "-o", "NUL", "-w", "%{http_code}", "--show-error", *CURL_MODES[mode]]
    if bind:
        args += ["-4", "--interface", bind, *_resolve_args(url)]
    args.append(url)
    if cancel is not None and cancel.is_set():
        return "fail"
    res = winutil.run(args, timeout=timeout + 6)
    return classify_curl(res.code, res.err)


def classify_curl(code: int, err: str) -> str:
    """Исход curl: ok | dns (адрес не нашёлся) | ssl (подменён сертификат) | unsup | fail. dns и ssl
    в оценке стратегии — тоже неудачи; unsup не считается вовсе."""
    if code == 0:
        return "ok"
    if code == CURL_COULDNT_RESOLVE or _DNS_RE.search(err):
        return "dns"
    if _SSL_RE.search(err):
        return "ssl"
    if code in (CURL_FAILED_INIT, CURL_NOT_BUILT_IN) or _UNSUP_RE.search(err):
        return "unsup"
    return "fail"


_resolved: dict[str, tuple[float, list[str]]] = {}


def _resolve_args(url: str) -> list[str]:
    """Если DNS отдаёт адреса-заглушки VPN-программы, мимо туннеля по ним не уйти:
    берём настоящий адрес через DNS по HTTPS и подставляем его curl'у. Системный DNS
    спрашиваем каждый раз (ответ всё равно в кэше Windows): VPN могли переключить на fake-ip."""
    parts = urllib.parse.urlsplit(url)
    host = (parts.hostname or "").lower()
    if not host:
        return []
    try:
        system = {info[4][0] for info in socket.getaddrinfo(host, 443, socket.AF_INET)}
    except OSError:
        system = set()
    from ..helpdesk import is_fake_ip
    if system and not any(is_fake_ip(ip) for ip in system):
        return []
    now = time.monotonic()
    cached = _resolved.get(host)
    if cached is None or now - cached[0] > 300 or not cached[1]:
        from ..helpdesk import doh_resolve
        cached = (now, doh_resolve(host) or [])
        _resolved[host] = cached
    port = parts.port or (80 if url.startswith("http://") else 443)
    return ["--resolve", f"{host}:{port}:{cached[1][0]}"] if cached[1] else []


# ------------------------------------------------------------ ping через ICMP API

class _IP_OPTION_INFORMATION(ctypes.Structure):
    _fields_ = [("Ttl", ctypes.c_ubyte), ("Tos", ctypes.c_ubyte), ("Flags", ctypes.c_ubyte),
                ("OptionsSize", ctypes.c_ubyte), ("OptionsData", ctypes.c_void_p)]


class _ICMP_ECHO_REPLY(ctypes.Structure):
    _fields_ = [("Address", wintypes.ULONG), ("Status", wintypes.ULONG), ("RoundTripTime", wintypes.ULONG),
                ("DataSize", wintypes.USHORT), ("Reserved", wintypes.USHORT), ("Data", ctypes.c_void_p),
                ("Options", _IP_OPTION_INFORMATION)]


# По полному пути: голое имя процесс с правами сначала ищет в папке exe, а iphlpapi.dll — не из KnownDLLs.
_iphlpapi = ctypes.WinDLL(winutil.system32("iphlpapi.dll"))
_iphlpapi.IcmpCreateFile.restype = wintypes.HANDLE
_iphlpapi.IcmpCloseHandle.argtypes = [wintypes.HANDLE]
_iphlpapi.IcmpSendEcho.argtypes = [wintypes.HANDLE, wintypes.ULONG, ctypes.c_void_p, wintypes.WORD,
                                   ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD]
_iphlpapi.IcmpSendEcho.restype = wintypes.DWORD
_iphlpapi.IcmpSendEcho2Ex.argtypes = [wintypes.HANDLE, wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                      wintypes.ULONG, wintypes.ULONG, ctypes.c_void_p, wintypes.WORD,
                                      ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD]
_iphlpapi.IcmpSendEcho2Ex.restype = wintypes.DWORD


def ping(host: str, timeout_ms: int = 1000, source: str | None = None) -> int | None:
    try:
        ip = socket.gethostbyname(host)
    except OSError:
        return None
    addr = int.from_bytes(socket.inet_aton(ip), "little")
    handle = _iphlpapi.IcmpCreateFile()
    if not handle or handle == wintypes.HANDLE(-1).value:
        return None
    try:
        data = b"lazeyka-ping"
        reply_size = ctypes.sizeof(_ICMP_ECHO_REPLY) + len(data) + 8
        reply = ctypes.create_string_buffer(reply_size)
        if source:
            src = int.from_bytes(socket.inet_aton(source), "little")
            count = _iphlpapi.IcmpSendEcho2Ex(handle, None, None, None, src, addr, data, len(data), None,
                                              reply, reply_size, timeout_ms)
        else:
            count = _iphlpapi.IcmpSendEcho(handle, addr, data, len(data), None, reply, reply_size, timeout_ms)
        if count == 0:
            return None
        echo = _ICMP_ECHO_REPLY.from_buffer(reply)
        return int(echo.RoundTripTime) if echo.Status == 0 else None
    finally:
        _iphlpapi.IcmpCloseHandle(handle)


# ------------------------------------------------------------ проверки

def check_targets(targets: list[Target], cancel: threading.Event, timeout: int = 4,
                  bind: str | None = None) -> list[dict]:
    jobs: list[tuple[int, str, Callable[[], object]]] = []
    for i, t in enumerate(targets):
        if t.url:
            for mode in CURL_MODES:
                jobs.append((i, mode, lambda url=t.url, mode=mode: curl_check(url, mode, timeout, cancel, bind)))
        if t.ping_host:
            jobs.append((i, "ping", lambda host=t.ping_host: ping(host, source=bind)))
    results = [{"name": t.name, "url": t.url or f"ping {t.ping_host}",
                "http": None, "tls12": None, "tls13": None, "ping": None} for t in targets]
    with ThreadPoolExecutor(max_workers=16) as pool:
        futures = [(i, mode, pool.submit(fn)) for i, mode, fn in jobs]
        for i, mode, fut in futures:
            try:
                results[i][mode] = fut.result(timeout=timeout + 15)
            except Exception:  # noqa: BLE001
                results[i][mode] = "fail" if mode != "ping" else None
    return results


def summarize(strategy_id: str, label: str, targets: list[dict]) -> dict:
    ok = fail = unsup = 0
    ping_ok = ping_total = 0
    for t in targets:
        for mode in CURL_MODES:
            v = t.get(mode)
            if v == "ok":
                ok += 1
            elif v == "unsup":
                unsup += 1
            elif v in ("fail", "ssl", "dns"):
                fail += 1
        ping_total += 1  # ping проверяется у каждой цели, как в test zapret.ps1
        if t.get("ping") is not None:
            ping_ok += 1
    checked = ok + fail
    return {"id": strategy_id, "label": label, "ok": ok, "fail": fail, "unsup": unsup,
            "ping_ok": ping_ok, "ping_total": ping_total,
            "score": round(ok / checked, 3) if checked else 0.0, "started": True, "targets": targets}


def pick_best(results: list[dict]) -> str | None:
    best = None
    for r in results:
        if not r.get("started"):
            continue
        key = (r["ok"], r["ping_ok"])
        if best is None or key > best[0]:
            best = (key, r["id"])
    return best[1] if best and best[0][0] > 0 else None


def control_ok(cancel: threading.Event | None = None, bind: str | None = None) -> bool:
    """Есть ли интернет вообще: открылся хоть один проверочный адрес (CONTROL_URLS). Ответил первый —
    остальных не ждём."""
    pool = ThreadPoolExecutor(max_workers=len(CONTROL_URLS))
    futures = [pool.submit(curl_check, url, "http", CONTROL_TIMEOUT, cancel, bind) for url in CONTROL_URLS]
    try:
        for fut in as_completed(futures):
            try:
                if fut.result() == "ok":
                    return True
            except Exception:  # noqa: BLE001 — один адрес не проверился: решают остальные
                log.debug("Проверочный адрес не проверен", exc_info=True)
        return False
    finally:
        pool.shutdown(wait=False, cancel_futures=True)


def quick_check(cancel: threading.Event | None = None, bind: str | None = None) -> list[dict]:
    """Discord и YouTube «открываются». Для YouTube обязателен домен видео googlevideo.com:
    сайт может открываться, а видео — нет, замедляют именно его."""
    cancel = cancel or threading.Event()
    out = []
    with ThreadPoolExecutor(max_workers=8) as pool:
        plan = {key: [(url, pool.submit(_quick_one, url, cancel, bind)) for url in urls]
                for key, (_label, urls) in QUICK_TARGETS.items()}
        for key, futures in plan.items():
            label = QUICK_TARGETS[key][0]
            states = {url: f.result() == "ok" for url, f in futures}
            good = sum(states.values())
            ok = good * 3 >= len(states) * 2
            detail = f"{good}/{len(states)}"
            video = next((u for u in states if "googlevideo.com" in u), None)
            if video is not None:
                ok = ok and states[video]
                detail += ", видео ✓" if states[video] else ", видео ✗"
            out.append({"id": key, "label": label, "ok": ok, "detail": detail})
    return out


def _quick_one(url: str, cancel: threading.Event, bind: str | None = None) -> str:
    return curl_check(url, "http", timeout=5, cancel=cancel, bind=bind)


# ------------------------------------------------------------ DPI 16–20 КБ

def fetch_dpi_suite() -> list[dict]:
    from ..updates.github import http_get_json
    data = http_get_json(DPI_SUITE_URL, timeout=10)
    suite = []
    for entry in data if isinstance(data, list) else []:
        host = str(entry.get("host", "")).strip()
        if re.fullmatch(r"[A-Za-z0-9.\-]+(:\d+)?(/\S*)?", host):
            suite.append({"id": str(entry.get("id", host)), "provider": str(entry.get("provider", "")),
                          "country": str(entry.get("country", "")), "host": host})
    return suite


def dpi_check(host: str, payload: Path, mode: str, timeout: int = 5, bind: str | None = None) -> str:
    url = f"https://{host}"
    args = [curl_exe(), "-q", "--noproxy", "*", "--range", "0-65535", "-m", str(timeout), "--connect-timeout", "3",
            "-w", "%{http_code} %{size_upload} %{size_download} %{time_total}", "-o", "NUL",
            "-X", "POST", "--data-binary", f"@{payload}", "-s", *CURL_MODES[mode]]
    if bind:
        args += ["-4", "--interface", bind, *_resolve_args(url)]
    args.append(url)
    res = winutil.run(args, timeout=timeout + 8)
    m = re.match(r"^(\d{3})\s+(\d+)\s+(\d+)\s+([\d.]+)$", res.out.strip())
    if m is None:
        return "unsup" if classify_curl(res.code, res.out + res.err) == "unsup" else "fail"
    up, down, total = int(m.group(2)), int(m.group(3)), float(m.group(4))
    if up > 0 and down == 0 and total >= timeout and res.code != 0:
        return "blocked"
    return "ok" if res.code == 0 else "fail"


def check_dpi(suite: list[dict], cancel: threading.Event, bind: str | None = None) -> list[dict]:
    fd, name = tempfile.mkstemp(prefix="lazeyka-dpi-", suffix=".bin")
    with os.fdopen(fd, "wb") as f:
        f.write(os.urandom(65536))
    payload = Path(name)
    try:
        results = [{"name": f"{e['country']} {e['provider']} {e['id']}".strip(), "url": e["host"],
                    "http": None, "tls12": None, "tls13": None, "ping": None, "blocked": 0} for e in suite]
        with ThreadPoolExecutor(max_workers=12) as pool:
            futures = []
            for i, e in enumerate(suite):
                for mode in CURL_MODES:
                    futures.append((i, mode, pool.submit(dpi_check, e["host"], payload, mode, 5, bind)))
            for i, mode, fut in futures:
                if cancel.is_set():
                    break
                try:
                    status = fut.result(timeout=30)
                except Exception:  # noqa: BLE001
                    status = "fail"
                if status == "blocked":
                    results[i]["blocked"] += 1
                    status = "fail"
                results[i][mode] = status
        return results
    finally:
        try:
            payload.unlink()
        except OSError:
            pass


# ------------------------------------------------------------ подбор

class NoDirectPath(UserError):
    """Работает туннель VPN в интернет, а прямого подключения мимо него нет: проверка без привязки ушла бы
    в VPN, и подбор признал бы рабочей любую стратегию."""

    def __init__(self) -> None:
        super().__init__("Работает VPN, а прямого подключения мимо него не видно — проверка обхода шла бы "
                         "через VPN и ничего бы не показала. Выключите VPN на время проверки.")


class StrategyTester:
    def __init__(self, zapret: "ZapretManager", notify: Callable[[str, str], None]):
        self.zapret = zapret
        self.notify = notify
        self.cancel_event = threading.Event()
        self.state: dict = self._empty("standard")
        self.check_state: dict = {"running": False, "at": None, "results": None}
        self._thread: threading.Thread | None = None
        self._start_lock = threading.Lock()
        self.fix_state: dict = self._empty_fix()
        self._fix_thread: threading.Thread | None = None
        # Адрес прямого подключения, если работает VPN в интернет: проверки идут мимо туннеля.
        # NoDirectPath — туннель есть, а прямого пути нет.
        self.source: Callable[[], str | None] = lambda: None

    def _bind(self, strict: bool = False) -> str | None:
        """strict — для подбора: без прямого пути при VPN оценивать стратегии нельзя (NoDirectPath).
        Быстрая проверка в этом случае идёт как есть — без привязки и без пометки «напрямую»."""
        try:
            return self.source()
        except NoDirectPath:
            if strict:
                raise
            return None
        except Exception:  # noqa: BLE001
            log.debug("Адрес прямого подключения не получен", exc_info=True)
            return None

    @staticmethod
    def _empty(kind: str) -> dict:
        # cancelled — подбор остановил человек: это не ошибка, error при этом пуст.
        return {"running": False, "kind": kind, "total": 0, "done": 0, "current": None, "best": None,
                "error": None, "cancelled": False, "finished_at": None, "results": []}

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def start(self, kind: str, ids: list[str] | None) -> None:
        with self._start_lock:
            if self.running or self.fix_running:
                raise UserError("Подбор уже идёт")
            if kind not in ("standard", "dpi"):
                raise UserError("Неизвестный вид проверки")
            if not self.zapret.is_admin or self.zapret.pack is None:
                raise UserError(self.zapret.unavailable_reason or "Обход недоступен")
            available = [s for s in self.zapret.strategies if s.usable]
            chosen = [s for s in available if ids is None or s.id in ids]
            if not chosen:
                raise UserError("Не выбрано ни одной стратегии")
            self.cancel_event.clear()
            self.state = self._empty(kind) | {"running": True, "total": len(chosen)}
            self._thread = threading.Thread(target=self._run, args=(kind, chosen), name="strategy-test",
                                            daemon=True)
            self._thread.start()

    def cancel(self) -> None:
        self.cancel_event.set()

    def join(self, timeout: float) -> None:
        """Даёт подбору вернуть обход и IPSet в исходное состояние перед выходом из приложения."""
        for thread in (self._thread, self._fix_thread):
            if thread and thread.is_alive():
                thread.join(timeout)

    def _run(self, kind: str, chosen: list) -> None:
        from .manager import SERVICE_NAME

        z = self.zapret
        mode = z.mode
        was_running = False
        paused = False
        lists_dir = z.pack.path / "lists" if z.pack else None
        original_ipset = lists.detect_ipset_mode(lists_dir) if lists_dir else None
        ipset_switched = False
        results: list[dict] = []
        try:
            # Всё, что может не получиться, — до того, как остановить обход пользователя.
            current = z.process   # одно чтение: параллельный stop() обнуляет поле
            own = {current.pid} if current and current.pid else set()
            service = winutil.service_query(SERVICE_NAME)
            if service and service.pid:
                own.add(service.pid)
            if foreign_winws(own):
                raise UserError("Запущен посторонний winws.exe — устраните конфликт и повторите")
            if kind == "dpi":
                suite = fetch_dpi_suite()
                if not suite:
                    raise UserError("Не удалось загрузить список проверок DPI")
            else:
                targets = load_targets(z.pack.path if z.pack else None)
            bind = self._bind(strict=True)
            self.state["direct"] = bool(bind)

            with z.lock:
                # Обход выключен страховкой связи посреди её проверки — он работал: подбор вернёт его сам.
                running = z.running()
                was_running, z.guard_paused = running or z.guard_paused, False
                z.mark_test(original_ipset, service_was_running=(mode == "service" and was_running))
                z.paused_for_test = paused = True
                if running:
                    z.stop(remember=False)
            z.prepare_pack()
            if z.settings.get("zapret", "tcp_timestamps"):
                netcfg.ensure_tcp_timestamps()
            if kind == "dpi" and original_ipset != "any":
                lists.set_ipset_mode(lists_dir, "any")
                ipset_switched = True

            for strategy in chosen:
                if self.cancel_event.is_set():
                    break
                self.state["current"] = strategy.id
                log.info("Подбор: проверяю «%s»", strategy.label)
                proc = WinwsProcess(z.winws_exe, z.runtime_args(strategy, record=False), label=f"тест {strategy.label}")
                try:
                    proc.start(ready_timeout=5)
                    time.sleep(0.5)
                    if kind == "dpi":
                        target_results = check_dpi(suite, self.cancel_event, bind)
                    else:
                        target_results = check_targets(targets, self.cancel_event, bind=bind)
                    row = summarize(strategy.id, strategy.label, target_results)
                    if kind == "dpi":
                        row["blocked"] = sum(t.get("blocked", 0) for t in target_results)
                except RunnerError as exc:
                    row = {"id": strategy.id, "label": strategy.label, "ok": 0, "fail": 0, "unsup": 0,
                           "ping_ok": 0, "ping_total": 0, "score": 0.0, "started": False,
                           "error": str(exc), "targets": []}
                finally:
                    proc.stop()
                results.append(row)
                self.state["results"] = sorted(results, key=lambda r: (-r["ok"], -r["ping_ok"]))
                self.state["done"] = len(results)
                self.state["best"] = pick_best(results)
            cancelled = self.cancel_event.is_set()
            if cancelled:
                self.state["cancelled"] = True   # остановил человек — не ошибка
            _save_report(kind, results, self.state["best"])
            best = self.state["best"]
            started = [r for r in results if r.get("started")]
            if cancelled:
                # Итог пишет страница: «Подбор остановлен: проверено N из M». «Завершён» было бы неправдой.
                log.info("Подбор остановлен: проверено %d из %d", len(results), len(chosen))
            elif len(started) >= 3 and len({r["ok"] for r in started}) == 1 and started[0]["ok"] > 0:
                why = ("сайты открываются и без обхода" if bind else
                       "включён VPN (трафик идёт мимо провайдера) или сайты открываются и без обхода")
                self.notify("info", f"Все стратегии показали одинаковый результат. Так бывает, если {why} — "
                                    "тогда подбор ничего не различает.")
            elif best:
                label = next((s.label for s in chosen if s.id == best), best)
                self.notify("success", f"Подбор завершён: лучшая стратегия — «{label}».")
            elif results:
                self.notify("warn", "Ни одна стратегия не открыла проверочные сайты. Запустите диагностику.")
        except UserError as exc:
            log.warning("Подбор стратегии не начат или прерван: %s", exc)
            self.state["error"] = str(exc)
            self.notify("error", f"Подбор: {exc}")
        except Exception as exc:  # noqa: BLE001
            log.exception("Подбор стратегии прерван")
            self.state["error"] = str(exc)
            self.notify("error", f"Подбор прерван: {exc}")
        finally:
            if ipset_switched and lists_dir is not None:
                try:
                    lists.set_ipset_mode(lists_dir, original_ipset)
                except (OSError, ValueError) as exc:
                    log.error("Режим IPSet не восстановлен: %s", exc)
            self.state["current"] = None
            self.state["running"] = False
            self.state["finished_at"] = time.time()
            if paused:
                self._end_pause()
            if was_running:
                self._resume(mode, "Обход не перезапустился после подбора")

    def _end_pause(self) -> None:
        """Снять паузу подбора. Метка прерванного подбора не удалилась — не повод не вернуть обход."""
        z = self.zapret
        z.paused_for_test = False
        try:
            z.unmark_test()
        except OSError as exc:
            log.warning("Метка подбора не удалена: %s", exc)

    def _resume(self, mode: str, failure: str) -> None:
        """Вернуть обход, который работал до подбора. Не вышло — плашка «обход лежит» с «Включить снова»:
        подбор запускает и сторож, человек может и не смотреть."""
        z = self.zapret
        try:
            if mode == "service":
                z.resume_service()
            else:
                z.start()
        except Exception as exc:  # noqa: BLE001
            self._report_down(f"{failure}: {exc}")

    def run_quick_check(self) -> None:
        if self.check_state["running"]:
            return
        self.check_state = {"running": True, "at": None, "results": self.check_state.get("results")}

        def work() -> None:
            bind = self._bind()
            try:
                results = quick_check(bind=bind)
            except Exception as exc:  # noqa: BLE001
                log.exception("Быстрая проверка упала")
                results = [{"id": "error", "label": "Проверка", "ok": False, "detail": str(exc)}]
            self.check_state = {"running": False, "at": time.time(), "results": results, "direct": bool(bind)}

        threading.Thread(target=work, name="quick-check", daemon=True).start()

    # ------------------------------------------------------------ «Найти и включить»

    @staticmethod
    def _empty_fix() -> dict:
        return {"running": False, "stage": None, "message": None, "current": None, "tried": [],
                "found": None, "previous": None, "results": None, "finished_at": None, "direct": False}

    @property
    def fix_running(self) -> bool:
        return bool(self._fix_thread and self._fix_thread.is_alive())

    def _last_results(self) -> tuple[list[dict], float | None]:
        """Строки последнего стандартного подбора — этого запуска или из сохранённого отчёта."""
        results, finished = self.state.get("results") or [], self.state.get("finished_at")
        if not results or self.state.get("kind") != "standard":
            report = load_last_report()
            if report:
                results, finished = report["results"], report["at"]
        return results, finished

    def best_known(self) -> tuple[str | None, dict[str, float], float | None]:
        """Лучшая стратегия и оценки по последнему стандартному подбору (в том числе прошлых запусков)."""
        results, finished = self._last_results()
        scores = {r["id"]: float(r.get("score") or 0) for r in results if r.get("started")}
        return pick_best(results), scores, finished

    def candidates(self, exclude: str | None) -> list:
        """Порядок проб — как у pick_best: больше успешных проверок, при равенстве — больше ответов ping.
        По доле (score) нельзя: одна удача при остальных «не поддерживается» дала бы 1.0."""
        usable = {s.id: s for s in self.zapret.strategies if s.usable}
        results, _at = self._last_results()
        leaders = [r for r in results if r.get("started") and (r.get("ok") or 0) > 0 and r.get("id")]
        ranked = [r["id"] for r in sorted(leaders, key=lambda r: (-(r.get("ok") or 0), -(r.get("ping_ok") or 0)))]
        order = ranked + [sid for sid in DEFAULT_CANDIDATES if sid not in ranked]
        picked = [usable[sid] for sid in order if sid in usable and sid != exclude]
        return picked[:MAX_CANDIDATES]

    def start_fix(self) -> None:
        with self._start_lock:
            if self.running or self.fix_running:
                raise UserError("Подбор уже идёт")
            if not self.zapret.is_admin or self.zapret.pack is None:
                raise UserError(self.zapret.unavailable_reason or "Обход недоступен")
            self.cancel_event.clear()
            self.fix_state = self._empty_fix() | {
                "running": True, "stage": "check", "previous": self.zapret.settings.get("zapret", "strategy"),
                "message": "Проверяем, открываются ли Discord и YouTube…"}
            self._fix_thread = threading.Thread(target=self._fix, name="zapret-fix", daemon=True)
            self._fix_thread.start()

    def _set_fix(self, **changes) -> None:
        self.fix_state = dict(self.fix_state) | changes

    def _fix(self) -> None:
        z = self.zapret
        previous = self.fix_state["previous"]
        try:
            try:
                bind = self._bind(strict=True)
            except NoDirectPath as exc:
                self._finish_fix("failed", str(exc))
                return
            if not z.running():
                self._set_fix(message="Включаем обход…")
                z.start()
                time.sleep(2)
            self._set_fix(direct=bool(bind))
            results = quick_check(self.cancel_event, bind)
            self._set_fix(results=results)
            if all(r["ok"] for r in results):
                label = _label(z, previous)
                self._finish_fix("done", f"Всё открывается на «{label}» — менять ничего не нужно.", found=previous)
                return
            if not control_ok(self.cancel_event, bind):
                if bind and control_ok(self.cancel_event):
                    self._finish_fix("failed", "VPN не пускает соединения мимо себя (защита от утечек). Проверить "
                                               "обход можно, только выключив VPN или эту защиту в нём.")
                else:
                    self._finish_fix("failed", "Похоже, нет интернета: не открывается ни один проверочный сайт. "
                                               "Проверьте подключение.")
                return
            found = self._quick_pick(previous, bind)
            if found is None:
                self._finish_fix("failed", "Остановлено." if self.cancel_event.is_set() else
                                 "Среди лучших стратегий подходящей не нашлось. Запустите полный подбор — "
                                 "он проверит все стратегии.")
                return
            # Победитель есть, обход выключен и ждёт его. Отмена после этой точки победителя уже включает:
            # иначе человек остался бы без обхода.
            self._set_fix(stage="apply", current=None, message=f"Включаем «{_label(z, found)}»…")
            try:
                z.set_strategy(found)
                if not z.running():
                    z.start()
            except Exception as exc:  # noqa: BLE001
                log.warning("Стратегия «%s» прошла пробу, но не включилась: %s", found, exc)
                back = self._restore_previous(previous)
                self._finish_fix("failed", f"«{_label(z, found)}» прошла пробу, но не включилась: {exc}. " + (
                    f"Вернули «{_label(z, previous)}»." if back else "Прежняя стратегия тоже не включилась."))
                return
            time.sleep(2)
            self._set_fix(stage="verify", message="Проверяем ещё раз…")
            results = quick_check(self.cancel_event, bind)
            self._set_fix(results=results)
            if all(r["ok"] for r in results):
                self._finish_fix("done", f"Включили «{_label(z, found)}»: Discord и YouTube открываются.", found=found)
                self.notify("success", f"Обход починен: включена стратегия «{_label(z, found)}».")
            else:
                self._finish_fix("failed", f"«{_label(z, found)}» прошла пробу, но проверка после включения не "
                                           "прошла. Попробуйте полный подбор.", found=found)
        except Exception as exc:  # noqa: BLE001
            log.exception("«Найти и включить» не удалось")
            self._finish_fix("failed", f"Не получилось: {exc}")

    def _finish_fix(self, stage: str, message: str, found: str | None = None) -> None:
        self._set_fix(running=False, stage=stage, message=message, found=found, current=None,
                      finished_at=time.time())

    def _restore_previous(self, previous: str | None) -> bool:
        """Победитель пробы не включился — вернуть прежнюю стратегию и включить обход. Не вышло — плашка."""
        z = self.zapret
        try:
            if previous and z.settings.get("zapret", "strategy") != previous:
                z.set_strategy(previous)
            if not z.running():
                z.start()
        except Exception as exc:  # noqa: BLE001
            self._report_down(f"Обход не включился после «Найти и включить»: {exc}")
            return False
        return True

    def _report_down(self, text: str) -> None:
        """Обход лежит не по воле человека: плашка с «Включить снова»; без Core — уведомление."""
        log.warning("%s", text)
        report = getattr(self.zapret, "report_down", None)
        if callable(report):
            report(text)
        else:
            self.notify("error", text)

    def _quick_pick(self, current: str | None, bind: str | None = None) -> str | None:
        """Пробует лидеров прошлого подбора по очереди; первая, с которой всё открылось, — победитель.
        С победителем обход остаётся выключенным — его включит _fix. Без победителя, после отмены или
        ошибки обход возвращается как был."""
        z = self.zapret
        candidates = self.candidates(exclude=current)
        mode = z.mode
        lists_dir = z.pack.path / "lists" if z.pack else None
        was_running = paused = finished = False
        found = None
        try:
            with z.lock:
                running = z.running()
                was_running, z.guard_paused = running or z.guard_paused, False   # см. run()
                z.mark_test(lists.detect_ipset_mode(lists_dir) if lists_dir else None,
                            service_was_running=(mode == "service" and was_running))
                z.paused_for_test = paused = True
                if running:
                    z.stop(remember=False)
            self._set_fix(stage="pick")
            for strategy in candidates:
                if self.cancel_event.is_set():
                    break
                self._set_fix(current=strategy.id, tried=self.fix_state["tried"] + [strategy.id],
                              message=f"Пробуем «{strategy.label}»…")
                proc = WinwsProcess(z.winws_exe, z.runtime_args(strategy, record=False),
                                    label=f"проба {strategy.label}")
                try:
                    proc.start(ready_timeout=5)
                    time.sleep(0.5)
                    if all(r["ok"] for r in quick_check(self.cancel_event, bind)):
                        found = strategy.id
                except RunnerError as exc:
                    log.info("Проба «%s» не запустилась: %s", strategy.label, exc)
                finally:
                    proc.stop()
                if found:
                    break
            finished = True
        finally:
            apply = finished and found is not None and not self.cancel_event.is_set()
            if paused:
                self._end_pause()
            if was_running and not apply:
                self._resume(mode, "Обход не вернулся после пробы стратегий")
        return found if apply else None

    def revert_fix(self) -> str:
        previous = self.fix_state.get("previous")
        if not previous:
            raise UserError("Возвращать нечего")
        if self.fix_running or self.running:
            raise UserError("Дождитесь окончания подбора")
        self.zapret.set_strategy(previous)
        self._set_fix(found=previous, message=f"Вернули «{_label(self.zapret, previous)}».")
        return previous


def _label(z, strategy_id: str | None) -> str:
    for s in z.strategies:
        if s.id == strategy_id:
            return s.label
    return strategy_id or "?"


def load_last_report() -> dict | None:
    """Последний сохранённый стандартный подбор: {results, at}."""
    try:
        reports = sorted(paths.TEST_RESULTS_DIR.glob("test_standard_*.json"))
    except OSError:
        return None
    for path in reversed(reports):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return {"results": data.get("results") or [], "at": path.stat().st_mtime}
        except (OSError, ValueError):
            continue
    return None


def _save_report(kind: str, results: list[dict], best: str | None) -> None:
    try:
        paths.TEST_RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y-%m-%d_%H-%M-%S")
        path = paths.TEST_RESULTS_DIR / f"test_{kind}_{stamp}.json"
        path.write_text(json.dumps({"kind": kind, "best": best, "results": results}, ensure_ascii=False,
                                   indent=1), encoding="utf-8")
    except OSError as exc:
        log.debug("Отчёт подбора не сохранён: %r", exc)
