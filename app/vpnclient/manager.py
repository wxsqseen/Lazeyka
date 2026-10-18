"""Менеджер своего VPN: состояние, запуск и остановка ядер, выбор сервера, режимы, задержки, подписки.

Связывает части пакета (docs/vpnclient-plan.md, 5.3–5.8, 5.11, 13): хранилище профилей, генератор
конфигов, ядра (engines, process), clash API, системный прокси, kill switch. С Core — только через
zapret_view() (снимок обхода, без блокировок), on_change() (флаг «посмотри на own()») и before_core
(перестроить фильтр обхода до старта ядра; зовётся из своей очереди без своих блокировок).

Всё, что меняет работающее ядро — запуск, остановка, переключение селекторов, падение, — идёт одной
очередью ops, строго по одному. start/stop/restart ждут свою задачу (Core зовёт их фоном); set_mode
и быстрые действия страницы (select, latency, import…) только ставят задачу и сразу возвращаются.

Хранилище (store.ProfileStore) менеджер зовёт так: load, subscriptions, subscription(id), servers,
server(id), groups, selected, select(id), latency, set_latency(id, ms, error), speed, set_speed(id, mbps),
add_subscription(sub), update_subscription(id, **поля), remove_subscription(id), apply_decoded(id, decoded),
add_servers(list), remove_server(id), rename_server(id, name|None), export_data, import_data(data).
"""
from __future__ import annotations

import base64
import concurrent.futures
import contextlib
import ctypes
import importlib
import ipaddress
import json
import logging
import os
import queue
import re
import secrets
import shutil
import socket
import ssl
import struct
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from ctypes import wintypes
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Callable

from .. import __version__, log as applog, paths, winutil
from ..errors import UserError
from . import diagnose
from .clash import ClashClient, ClashError, TrafficSampler
from .model import (MODES, PRESETS, PROBE_URL, UA_PRESETS, DnsChoice, Group, Ports, RunPlan, Secrets, Server,
                    Subscription, TunOptions, engine_for)
from .process import CoreProcess, ProcessError
from .sysproxy import SysProxy

log = logging.getLogger("lazeyka.vpnclient.manager")

ADMIN_REASON = "Свой VPN работает только с правами администратора — перезапустите Лазейку с ними."
TUN_NAME = "Lazeyka"
OWN_LABEL = "Лазейка"
DIRECT = "direct"                       # тег прямого выхода в конфиге (член селектора «через обход»)
MAX_CONFIG_SERVERS = 16                 # = vpnfilter.MAX_SERVERS: свои серверы исключаются из перехвата
READY_TIMEOUT = 8.0                     # clash API слушает последним — после всех входов и выходов
PORT_ATTEMPTS = 3                       # порт занят или зарезервирован — повтор с другими портами
RESTART_MIN_UPTIME = 60.0               # перезапуск после падения — только если ядро проработало дольше
RESTARTS_PER_HOUR = 3
RESTART_RETRY = (30.0, 120.0, 300.0)    # автоматический перезапуск не удался — повтор через 30 с, 2, 5 мин, дальше раз в 5 мин
HEALTH_EVERY = 60.0                     # задержка активного сервера
UNVERIFIED_RETRY = 15.0                 # выход не подтверждён — проверяем чаще
HEALTH_FAILS = 2                        # столько провалов подряд — сервер мёртв
BYPASS_HYSTERESIS = 30.0                # селектор «через обход» — не чаще раза в 30 с
TRAFFIC_SAVE_EVERY = 60.0
MEMORY_EVERY = 5.0
SUB_CHECK_EVERY = 60.0
SUB_RETRY = 1800.0                      # подписка не обновилась — повтор через полчаса
DISK_CACHE = 5.0                        # версии ядер и состояние списков для снимка — не чаще
DELAY_TIMEOUT_MS = 5000
DELAY_WORKERS = 8
STOP_WAIT = 15.0
EXIT_URL = "https://1.1.1.1/cdn-cgi/trace"
EXIT_TIMEOUTS = (5.0, 8.0, 8.0)         # проверка выхода: три попытки, первая короче
RECHECK_TIMEOUTS = (5.0, 5.0)           # повторная проверка фоном — короче: за ней в очереди ждут «Выключить» и выбор
SPEED_URL = "https://speed.cloudflare.com/__down?bytes=50000000"
SPEED_SECONDS = 10.0
USER_AGENT = f"Lazeyka/{__version__} (Windows)"
FILE_LIMIT = 5 * 1024 * 1024            # файл импорта (.conf/.json/.txt)
NAME_LIMIT = 64
SUB_MTU = (576, 9000)                   # свой MTU подписки (общий tun_mtu — от 1280: с IPv6 меньше нельзя)
IMAGE_SUFFIXES = (".png", ".jpg", ".jpeg", ".bmp", ".gif", ".webp")

DOH_RESOLVERS = {"cloudflare": "https://1.1.1.1/dns-query", "google": "https://8.8.8.8/dns-query",
                 "quad9": "https://9.9.9.9/dns-query", "adguard": "https://94.140.14.14/dns-query",
                 "yandex": "https://77.88.8.8/dns-query"}
DOH_AUTO = ("cloudflare", "google", "quad9", "yandex")   # «auto»: первый, кто ответил
# Своя /30 для TUN — вне частных сетей (их не заворачиваем в туннель), не 198.18.0.0/15 (Incy и fake-ip)
# и не 172.19.0.0/30 (умолчание sing-box у других клиентов); пересечения с маршрутами проверяются.
TUN_CANDIDATES = ("100.127.255.252/30", "100.127.254.252/30", "100.126.255.252/30", "198.51.100.252/30",
                  "192.0.2.252/30")
TUN_IPV6 = "fdfe:dcba:9876::1/126"
FINGERPRINTS = ("", "chrome", "firefox", "edge", "safari", "360", "qq", "ios", "android", "random", "randomized")
CORE_SETTING = {"sing-box": "singbox_version", "xray": "xray_version"}
CORE_UPDATE_KEY = {"sing-box": "vpncore", "xray": "vpnxray"}   # пункты «Обновлений» (пропущенная версия)
CORE_ALERT = "vpn-core:"                # плашка «ядро не скачалось»: vpn-core:<имя ядра>
FETCH_RETRY = (60.0, 300.0, 900.0, 3600.0)   # ядро не скачалось при запуске — повтор через 1, 5, 15 мин, потом раз в час
FETCH_RECHECK = 600.0                   # ядра на месте — снова посмотреть (вдруг их удалил антивирус)
CORE_UPDATE_FIRST = 120.0               # первая проверка новых версий ядер — через 2 минуты после запуска
CORE_UPDATE_EVERY = 6 * 3600.0
CORE_UPDATE_RETRY = 3600.0              # GitHub не ответил — снова через час
BAD_VERSIONS_LIMIT = 20
# Образцовые серверы для `check` новой версии ядра, если своих нет (адреса — из диапазонов для документации).
SAMPLE_LINKS = {
    "sing-box": "vless://00000000-0000-4000-8000-00000000c0de@203.0.113.10:443?type=tcp&security=reality"
                "&sni=www.example.com&fp=chrome&pbk=Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw"
                "&sid=6ba85179e30d4fc2&flow=xtls-rprx-vision#check",
    "xray": "vless://00000000-0000-4000-8000-00000000c0de@203.0.113.12:443?type=xhttp&security=tls"
            "&sni=www.example.com&path=%2Fx&mode=auto#check-xhttp",
}
PROBE_PRESETS =("v2rayn", "happ", "incy")   # «Проверить расширенный формат»: на эти UA панели отдают JSON Xray
UA_LABELS = {"v2rayn": "как v2rayN", "happ": "как Happ", "incy": "как Incy"}
TIMED_PROTOCOLS = ("vmess",)            # сервер сверяет время клиента (и REALITY — по security)
# Плашки (Core.set_alert) — id с приставкой «vpn-». Плашки сеанса снимаются, когда сеанс кончился.
EXIT_ALERT, SERVER_ALERT, KILLSWITCH_ALERT = "vpn-exit", "vpn-server", "vpn-killswitch"
SESSION_ALERTS = (EXIT_ALERT, SERVER_ALERT, KILLSWITCH_ALERT)
CRASH_ALERT = "vpn-crash"
# Ошибка задержки сервера вне подключения: временное ядро замера kill switch не выпустит в сеть.
KILLSWITCH_DELAY = "не проверить при включённом kill switch: он выпускает в сеть только ядра текущего подключения"
RULES_ALERT, PROFILE_ALERT, STORE_ALERT = "vpn-rules", "vpn-profile", "vpn-store"
# Куда идёт трафик, пока списков нет, — по месту, с которого «через VPN» не исполнить (config._Ends.strict).
RULES_WAIT = {
    None: "пока эти сайты идут по умолчанию",
    "user": "пока через VPN идёт всё, кроме ваших правил «мимо VPN» и переключателей (и «через обход» тоже)",
    "profile": "пока через VPN идёт всё, что не отправили напрямую ваши правила, переключатели и «через обход»",
    "preset": "пока через VPN идёт всё, что не отправили напрямую ваши правила, переключатели и «через обход»",
}


class VpnClientError(UserError):
    def __init__(self, message: str, kind: str = "other"):
        super().__init__(message)
        self.kind = kind


class _Aborted(VpnClientError):
    """Запуск прерван: нажали «Выключить» или Лазейка закрывается."""


@dataclass
class ZapretView:
    """Что менеджер знает об обходе (собирает Core, без блокировок zapret)."""

    running: bool = False
    paused_for_test: bool = False       # идёт подбор: winws перезапускается на каждую пробу
    last_ok: bool | None = None         # итог последней проверки сторожа
    strategy_args: list[str] = field(default_factory=list)
    pack_dir: Path | None = None
    ipset_mode: str | None = None


def _module(name: str):
    """Модуль пакета, который пишут параллельно (store, config, rules…): понятная ошибка, если его нет."""
    try:
        return importlib.import_module(f"{__package__}.{name}")
    except ImportError as exc:
        raise VpnClientError(f"Часть своего VPN ещё не готова ({name}): {exc}") from exc


# ------------------------------------------------------------ сеть: TLS, DoH, порты, подсеть, выход

def tls_context() -> ssl.SSLContext:
    import certifi
    ctx = ssl.create_default_context(cafile=certifi.where())
    ctx.load_default_certs()            # и хранилище Windows: корпоративные корни
    return ctx


def direct_opener() -> urllib.request.OpenerDirector:
    """Напрямую, мимо системного прокси: в режиме прокси он указывает на само ядро."""
    return urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                       urllib.request.HTTPSHandler(context=tls_context()))


def proxy_opener(port: int, user: str, password: str) -> urllib.request.OpenerDirector:
    """Через служебный вход ядра (mixed с логином и паролем) — то есть через выбранный сервер."""
    url = f"http://{urllib.parse.quote(user, safe='')}:{urllib.parse.quote(password, safe='')}@127.0.0.1:{port}"
    return urllib.request.build_opener(urllib.request.ProxyHandler({"http": url, "https": url}),
                                       urllib.request.HTTPSHandler(context=tls_context()))


DNS_TYPES = {"A": 1, "AAAA": 28}


def _dns_query(host: str, qtype: str = "A") -> bytes:
    labels = [part.encode("ascii") for part in host.rstrip(".").split(".")]
    if not labels or any(not 0 < len(part) < 64 for part in labels):
        raise ValueError("имя не годится для DNS")
    qname = b"".join(bytes([len(part)]) + part for part in labels) + b"\x00"
    return struct.pack(">HHHHHH", 0, 0x0100, 1, 0, 0, 0) + qname + struct.pack(">HH", DNS_TYPES[qtype], 1)   # IN


def _skip_name(buf: bytes, pos: int) -> int:
    while True:
        if pos >= len(buf):
            raise ValueError("ответ DNS обрезан")
        length = buf[pos]
        if length == 0:
            return pos + 1
        if length & 0xC0 == 0xC0:                 # сжатое имя — указатель
            return pos + 2
        pos += 1 + length


def parse_dns_answers(data: bytes) -> list[str]:
    """Адреса из ответа DNS (wire format, RFC 1035): IPv4 из записей A, IPv6 из AAAA (RFC 3596)."""
    if len(data) < 12:
        raise ValueError("ответ DNS слишком короткий")
    _, flags, qd, an, _, _ = struct.unpack(">HHHHHH", data[:12])
    if flags & 0x000F:
        return []                                 # NXDOMAIN, SERVFAIL…
    pos = 12
    for _ in range(qd):
        pos = _skip_name(data, pos) + 4
    out = []
    for _ in range(an):
        pos = _skip_name(data, pos)
        if pos + 10 > len(data):
            raise ValueError("ответ DNS обрезан")
        rtype, rclass, _, rdlen = struct.unpack(">HHIH", data[pos:pos + 10])
        pos += 10
        if rtype == 1 and rclass == 1 and rdlen == 4 and pos + 4 <= len(data):
            out.append(socket.inet_ntoa(data[pos:pos + 4]))
        elif rtype == 28 and rclass == 1 and rdlen == 16 and pos + 16 <= len(data):
            out.append(str(ipaddress.IPv6Address(data[pos:pos + 16])))
        pos += rdlen
    return out


def doh_query(host: str, resolver: str, qtype: str = "A", timeout: float = 4.0) -> list[str]:
    """Записи A или AAAA через DNS по HTTPS (RFC 8484, GET): провайдер не подменит адрес сервера."""
    query = base64.urlsafe_b64encode(_dns_query(host, qtype)).rstrip(b"=").decode("ascii")
    request = urllib.request.Request(f"{resolver}?dns={query}",
                                     headers={"Accept": "application/dns-message", "User-Agent": USER_AGENT})
    with direct_opener().open(request, timeout=timeout) as resp:
        return parse_dns_answers(resp.read(65535))


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


class Resolver:
    """Адреса серверов — заранее, через DoH с запасными: Cloudflare → Google → Quad9 → Яндекс."""

    def __init__(self, query: Callable[[str, str], list[str]] = doh_query):
        self._query = query
        self._good: str | None = None             # кто ответил последним — его и спрашиваем первым

    @property
    def working(self) -> str | None:
        return self._good

    def resolve(self, host: str, preferred: str | None = None, *, families: tuple[str, ...] = ("A",)) -> str:
        """Адрес сервера. families — какие записи спрашивать и в каком порядке: ("A",) — только IPv4,
        ("A", "AAAA") — IPv6, если у имени нет IPv4, ("AAAA", "A") — сначала IPv6."""
        if _is_ip(host):
            return host
        order = [u for u in (preferred, self._good, *(DOH_RESOLVERS[n] for n in DOH_AUTO)) if u]
        last: Exception | None = None
        for url in dict.fromkeys(order):
            for family in families:
                try:
                    found = self._query(host, url) if family == "A" else self._query(host, url, family)
                except (OSError, ValueError, urllib.error.URLError) as exc:
                    last = exc
                    break                         # резолвер не отвечает — следующий
                if found:
                    self._good = url
                    return found[0]
        kinds = " и ".join("IPv6" if f == "AAAA" else "IPv4" for f in families)
        raise VpnClientError(f"адрес ({kinds}) не получен ни от одного DNS через HTTPS"
                             + (f" ({last})" if last else ""), "timeout")


def free_port(preferred: int | None = None, *, host: str = "127.0.0.1", avoid: frozenset[int] = frozenset(),
              span: int = 20) -> int:
    """Свободный порт: preferred и следующие за ним или выданный системой. Порты из исключённых диапазонов
    Hyper-V/WSL bind не даёт (WSAEACCES) — такие пропускаются сами."""
    candidates = range(preferred, min(preferred + span, 65536)) if preferred else [0] * span
    for port in candidates:
        if port and port in avoid:
            continue
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            try:
                sock.bind((host, port))
            except OSError:
                continue
            got = sock.getsockname()[1]
        if got not in avoid:
            return got
    raise VpnClientError(f"Не нашлось свободного порта{f' рядом с {preferred}' if preferred else ''}", "port")


def port_open(port: int, host: str = "127.0.0.1", timeout: float = 0.3) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def pick_tun_subnet(taken: list[str], exclude: list[str]) -> ipaddress.IPv4Network:
    """Своя /30 без пересечений: с исключёнными сетями (их нельзя заворачивать в туннель) и с адресами и
    маршрутами адаптеров. Широкие маршруты (0/0, 0/1 у других VPN) занятостью не считаются."""
    busy: list[ipaddress.IPv4Network] = []
    for item, narrow_only in [(x, True) for x in taken] + [(x, False) for x in exclude]:
        try:
            net = ipaddress.ip_network(item, strict=False)
        except ValueError:
            continue
        if net.version == 4 and (not narrow_only or net.prefixlen >= 8):
            busy.append(net)
    for candidate in TUN_CANDIDATES:
        net = ipaddress.ip_network(candidate)
        if not any(net.overlaps(other) for other in busy):
            return net
    raise VpnClientError("Не нашлось свободной подсети для адаптера VPN: все варианты заняты другими сетями",
                         "conflict")


def taken_nets() -> list[str]:
    """Адреса адаптеров и маршруты IPv4 — для выбора подсети TUN."""
    from .. import vpn
    out = []
    for adapter in vpn.list_adapters():
        if adapter.name != TUN_NAME:              # свой осиротевший адаптер занимаем снова
            out += [f"{ip}/32" for ip in adapter.ipv4]
    for dest, plen, _hop, _index in vpn.routes():
        if ":" not in dest and plen >= 8 and not dest.startswith(("127.", "224.", "255.")):
            out.append(f"{dest}/{plen}")
    return out


def physical_interface() -> str | None:
    """Имя физического адаптера с маршрутом в интернет — для sockopt.interface помощника Xray."""
    from .. import vpn
    best = None
    for a in vpn.list_adapters():
        if a.up and a.gateways and a.ipv4 and a.name != TUN_NAME and a.if_type in (6, 71, 23):
            if best is None or a.metric < best.metric:
                best = a
    return best.name if best else None


def ipv6_internet() -> bool:
    """Есть ли у физического адаптера путь в интернет по IPv6: глобальный адрес (не Teredo, не ULA и не
    link-local) и шлюз IPv6. Только таблица адаптеров — без пакетов в сеть; свой TUN не в счёт (его
    маршруты по умолчанию указывают на него самого). Не прочиталась таблица — IPv6 считаем недоступным."""
    from .. import vpn
    try:
        adapters = vpn.list_adapters()
    except OSError:
        return False
    for a in adapters:
        if not a.up or a.name == TUN_NAME or a.if_type not in (6, 71, 23):
            continue
        if any(":" in g for g in a.gateways) and any(_global_v6(ip) for ip in a.ipv6):
            return True
    return False


def _global_v6(text: str) -> bool:
    try:
        return ipaddress.ip_address(text.split("%", 1)[0]).is_global
    except ValueError:
        return False


def adapter_luid(name: str) -> int | None:
    lib = ctypes.WinDLL(winutil.system32("iphlpapi.dll"))
    fn = lib.ConvertInterfaceAliasToLuid
    fn.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_uint64)]
    fn.restype = wintypes.DWORD
    luid = ctypes.c_uint64()
    return luid.value if fn(name, ctypes.byref(luid)) == 0 and luid.value else None


def parse_trace(body: str) -> dict[str, str]:
    return dict(line.split("=", 1) for line in body.splitlines() if "=" in line)


def exit_check(port: int, user: str, password: str, timeout: float) -> dict:
    """Через служебный вход — IP и страна выхода (Cloudflare trace) и Date ответа (для часов)."""
    request = urllib.request.Request(EXIT_URL, headers={"User-Agent": USER_AGENT})
    with proxy_opener(port, user, password).open(request, timeout=timeout) as resp:
        body = resp.read(8192).decode("utf-8", errors="replace")
        date = resp.headers.get("Date")
    trace = parse_trace(body)
    if not trace.get("ip"):
        raise ValueError("в ответе проверки нет адреса")
    loc = trace.get("loc")
    return {"ip": trace["ip"], "country": loc if loc and loc != "XX" else None, "date": date}


def direct_date(timeout: float = 5.0) -> str | None:
    """Date ответа напрямую — сверить часы, когда через сервер ничего не открылось."""
    try:
        with direct_opener().open(urllib.request.Request(EXIT_URL, headers={"User-Agent": USER_AGENT}),
                                  timeout=timeout) as resp:
            return resp.headers.get("Date")
    except (OSError, urllib.error.URLError, ValueError):
        return None


def speed_check(port: int, user: str, password: str, seconds: float = SPEED_SECONDS) -> float:
    """Загрузка через выбранный сервер не дольше seconds: Мбит/с."""
    began = time.monotonic()
    done = 0
    request = urllib.request.Request(SPEED_URL, headers={"User-Agent": USER_AGENT})
    with proxy_opener(port, user, password).open(request, timeout=seconds) as resp:
        while time.monotonic() - began < seconds:
            chunk = resp.read(256 * 1024)
            if not chunk:
                break
            done += len(chunk)
    return round(done * 8 / max(time.monotonic() - began, 0.001) / 1e6, 1)


def process_memory(pid: int) -> int | None:
    import psutil
    try:
        return int(psutil.Process(pid).memory_info().rss)
    except (psutil.Error, OSError):
        return None


def running_apps() -> list[dict]:
    """Программы для «мимо VPN / только через VPN»: по одной на exe, без системных."""
    import psutil
    system = winutil.windows_dir().lower()
    seen: dict[str, dict] = {}
    for proc in psutil.process_iter(["name", "exe"]):
        exe = proc.info.get("exe")
        if not exe or exe.lower().startswith(system):
            continue
        seen.setdefault(exe.lower(), {"name": proc.info.get("name") or Path(exe).name, "path": exe})
    return sorted(seen.values(), key=lambda a: a["name"].lower())


# ------------------------------------------------------------ очередь действий над ядром

class _Worker:
    """Одна очередь: задачи выполняются строго по одной. submit — поставить и забыть (key — не ставить
    вторую такую же, пока первая ждёт); call — поставить и дождаться (из самой очереди — выполнить сразу)."""

    def __init__(self, name: str):
        self._queue: queue.Queue = queue.Queue()
        self._pending: set[str] = set()
        self._busy = 0
        self._cond = threading.Condition()
        self._thread = threading.Thread(target=self._run, name=name, daemon=True)
        self._thread.start()

    def submit(self, fn: Callable[[], Any], key: str | None = None) -> bool:
        def logged() -> None:
            try:
                fn()
            except UserError as exc:
                log.warning("%s", exc)
            except Exception:  # noqa: BLE001 — фоновой задаче некому вернуть ошибку
                log.exception("Задача своего VPN не удалась")

        return self._put(logged, key, None)

    def call(self, fn: Callable[[], Any], timeout: float | None = None) -> Any:
        if threading.current_thread() is self._thread:
            return fn()
        future: concurrent.futures.Future = concurrent.futures.Future()
        self._put(fn, None, future)
        return future.result(timeout)

    def _put(self, fn: Callable[[], Any], key: str | None, future: concurrent.futures.Future | None) -> bool:
        with self._cond:
            if key is not None:
                if key in self._pending:
                    return False
                self._pending.add(key)
            self._busy += 1
        self._queue.put((key, fn, future))
        return True

    def waiting(self, key: str) -> bool:
        """Задача с этим ключом стоит в очереди и ещё не началась."""
        with self._cond:
            return key in self._pending

    def wait_idle(self, timeout: float) -> bool:
        with self._cond:
            return self._cond.wait_for(lambda: self._busy == 0, timeout)

    def _run(self) -> None:
        while True:
            key, fn, future = self._queue.get()
            with self._cond:
                self._pending.discard(key)
            try:
                if future is None:
                    fn()
                elif future.set_running_or_notify_cancel():
                    try:
                        future.set_result(fn())
                    except BaseException as exc:  # noqa: BLE001 — исключение получит тот, кто ждёт
                        future.set_exception(exc)
            finally:
                with self._cond:
                    self._busy -= 1
                    self._cond.notify_all()


# ------------------------------------------------------------ счётчики трафика и закрытые файлы

class TrafficBook:
    """Сегодня и всего (DATA/vpnclient/traffic.json): прибавляем приращения сеанса, пишем раз в минуту."""

    def __init__(self, path: Path, clock: Callable[[], float] = time.time):
        self.path = path
        self._clock = clock
        self._lock = threading.Lock()
        self._data = {"today_up": 0, "today_down": 0, "total_up": 0, "total_down": 0, "day": self._today()}
        self._dirty = False
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            loaded = None
        if isinstance(loaded, dict):
            for key in ("today_up", "today_down", "total_up", "total_down"):
                if isinstance(loaded.get(key), int) and not isinstance(loaded[key], bool) and loaded[key] >= 0:
                    self._data[key] = loaded[key]
            if isinstance(loaded.get("day"), str):
                self._data["day"] = loaded["day"]
        self._rollover()

    def _today(self) -> str:
        return time.strftime("%Y-%m-%d", time.localtime(self._clock()))

    def _rollover(self) -> None:
        today = self._today()
        if self._data["day"] != today:
            self._data.update(day=today, today_up=0, today_down=0)
            self._dirty = True

    def add(self, up: int, down: int) -> None:
        if up <= 0 and down <= 0:
            return
        with self._lock:
            self._rollover()
            for key, value in (("today_up", up), ("total_up", up), ("today_down", down), ("total_down", down)):
                self._data[key] += max(0, value)
            self._dirty = True

    def snapshot(self) -> dict:
        with self._lock:
            self._rollover()
            return dict(self._data)

    def save(self) -> None:
        with self._lock:
            if not self._dirty:
                return
            payload = json.dumps(self._data)
            self._dirty = False
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".json.tmp")
            tmp.write_text(payload, encoding="utf-8")
            os.replace(tmp, self.path)
        except OSError as exc:
            log.debug("Счётчики трафика не сохранены: %s", exc)


class _PrivateJson:
    """JSON в закрытой папке vpnclient/ (логин и пароль локального прокси, профили маршрутизации);
    читается один раз, дальше — из памяти. Папку закрывает secure перед первой записью: она могла
    появиться раньше с правами по наследству."""

    def __init__(self, path: Path, default: dict | list,
                 secure: Callable[[Path], None] | None = None):
        self.path = path
        self._default = default
        self._secure = secure
        self._secured = False
        self._data: Any = None
        self._lock = threading.Lock()

    def load(self) -> Any:
        with self._lock:
            if self._data is None:
                try:
                    data = json.loads(self.path.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    data = None
                self._data = data if isinstance(data, type(self._default)) else type(self._default)()
            return json.loads(json.dumps(self._data))

    def save(self, data: Any) -> None:
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if not self._secured and self._secure is not None:
                try:
                    self._secure(self.path.parent)
                except OSError as exc:              # секрет в открытую папку не пишем
                    raise VpnClientError(f"Не удалось закрыть папку своего VPN от других пользователей: {exc}")                         from exc
            self._secured = True
            tmp = self.path.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
            os.replace(tmp, self.path)
            self._data = json.loads(json.dumps(data))


# ------------------------------------------------------------ сеанс работающего ядра и зависимости

@dataclass
class _Session:
    id: str
    plan: RunPlan
    main: Any                                   # CoreProcess sing-box
    helper: Any | None                          # CoreProcess помощника Xray
    clash: Any                                  # ClashClient
    sampler: Any                                # TrafficSampler
    tags: dict[str, str]                        # тег выхода → id сервера
    versions: dict[str, str]
    config_paths: dict[str, Path]
    started: float = 0.0
    active: str = ""                            # выбранный id (сервер или auto:…)
    tun_net: str | None = None
    proxy_address: str | None = None
    secrets: list[str] = field(default_factory=list)
    last_totals: tuple[int, int] = (0, 0)

    def pids(self) -> set[int]:
        return {p.pid for p in (self.main, self.helper) if p is not None and p.pid}


@dataclass
class Deps:
    """Внешний мир менеджера. None — настоящая реализация; в тестах — подделки."""

    store: Any = None
    modules: dict[str, Any] = field(default_factory=dict)   # подмена модулей пакета: engines, config, links…
    rules: Any = None
    sysproxy: Any = None
    killswitch: Any = None
    process: Callable[..., Any] = CoreProcess
    clash: Callable[..., Any] = ClashClient
    sampler: Callable[..., Any] = TrafficSampler
    resolver: Any = None
    free_port: Callable[..., int] = free_port
    port_open: Callable[[int], bool] = port_open
    taken_nets: Callable[[], list[str]] = taken_nets
    physical_interface: Callable[[], str | None] = physical_interface
    ipv6_internet: Callable[[], bool] = ipv6_internet
    adapter_luid: Callable[[str], int | None] = adapter_luid
    exit_check: Callable[..., dict] = exit_check
    direct_date: Callable[[], str | None] = direct_date
    speed_check: Callable[..., float] = speed_check
    tcp_reach: Callable[..., float | None] = diagnose.tcp_reach
    memory: Callable[[int], int | None] = process_memory
    running_apps: Callable[[], list[dict]] = running_apps
    adapters: Callable[[], list] = diagnose.collect_adapters
    opener: Callable[[str], Any] | None = None      # маршрут загрузок: "direct" | "vpn"
    clock: Callable[[], float] = time.time
    data_dir: Path | None = None                    # vpnclient/ (в тестах — временная)


# ------------------------------------------------------------ менеджер

class VpnClientManager:
    def __init__(self, settings, notify: Callable[..., None], is_admin: bool, *,
                 zapret_view: Callable[[], ZapretView], on_change: Callable[..., None],
                 before_core: Callable[[], None] | None = None, deps: Deps | None = None,
                 alert: Callable[..., None] | None = None):
        self.settings = settings
        self.notify = notify
        self.is_admin = is_admin
        self.zapret_view = zapret_view
        self.on_change = on_change
        self.before_core = before_core
        # Постоянные плашки Core (core.alert): alert(id, level, text, action=, page=), level=None — снять.
        # Без колбэка (тесты, стенд) плашки только пишутся в журнал.
        self.alert = alert
        self.deps = deps or Deps()
        self._lock = threading.RLock()
        self._ops = _Worker("vpnclient-ops")
        self._closing = False
        self._abort = threading.Event()              # «выключить» во время запуска
        self._cancel = threading.Event()             # прервать загрузку ядра при выходе
        self.data_dir = self.deps.data_dir or paths.VPNCLIENT_DIR
        self.run_dir = self.data_dir / "run"
        self._traffic = TrafficBook(self.data_dir / "traffic.json", self.deps.clock)
        self._auth = _PrivateJson(self.data_dir / "local-proxy.json", {}, secure=_secure_dir())
        self._profiles = _PrivateJson(self.data_dir / "routing-profiles.json", [], secure=_secure_dir())
        self._resolver = self.deps.resolver or Resolver()
        self._store = None
        self._unavailable: str | None = None if is_admin else ADMIN_REASON
        # состояние для страницы
        self._status = "stopped"
        self._verified = False
        self._error: str | None = None
        self._error_kind: str | None = None
        self._exit: dict | None = None
        self._session: _Session | None = None
        self._pending: RunPlan | None = None         # план собран, ядро ещё не запущено (для own())
        self._cores = {name: {"state": "idle", "progress": None, "message": None} for name in CORE_SETTING}
        # Ядра в фоне: подкачка при запуске (повтор с паузами) и автообновление; одна задача за раз.
        # Всё, что ставит, проверяет, делает активной или удаляет версию ядра (подкачка, автообновление,
        # кнопки, откат после неудачного старта), идёт под блокировкой этого ядра — целиком, от загрузки
        # до уборки: иначе откат удалил бы версию, которую как раз проверяет check.
        self._core_ops = {name: threading.RLock() for name in CORE_SETTING}
        self._core_job: threading.Thread | None = None
        self._fetch_at = 0.0                          # когда смотреть, все ли ядра на месте
        self._fetch_attempt = 0                       # неудачных подкачек подряд
        self._fetch_retry_at: float | None = None
        self._core_alerted: set[str] = set()          # по каким ядрам висит плашка «не скачалось»
        self._update_at: float | None = None          # следующая проверка новых версий
        self._core_notes: dict[str, str] = {}         # итог автообновления для «Обновлений»
        # Версии ядер, которые взяла попытка запуска, — своя у каждого потока: замер задержек в своём потоке
        # тоже собирает ядра и не должен подменить их запуску (откат при сбое смотрит именно сюда).
        self._attempt = threading.local()
        self._restart_after_start: set[str] = set()   # версию сменили вручную, пока шёл запуск
        self._latency = {"running": False, "done": 0, "total": 0}
        self._speed = {"running": False, "server": None, "mbps": None, "at": None}
        self._import = {"running": False, "message": None, "error": None, "offer": None}
        self._updating: set[str] = set()
        self._sub_retry: dict[str, float] = {}
        self._probes: dict[str, dict] = {}            # «Проверить расширенный формат» по подпискам
        self._gone: dict[str, str] = {}               # имя выбранного до слияния подписки (для уведомления)
        self._last_import: tuple[str, str | None] | None = None   # повтор с другим UA или с HWID (секрет)
        self._deeplink: dict | None = None
        self._deeplink_text: str | None = None
        self._conflict: dict | None = None
        self._memory: dict[str, int | None] = {"sing-box": None, "xray": None}
        self._view_cache: ZapretView | None = None
        self._bypass_applied: str | None = None      # что стоит в селекторе «через обход» сейчас
        self._bypass_at = 0.0
        self._bypass_notes: list[str] = []
        self._restarts: list[float] = []
        self._retry_at: float | None = None          # повтор неудавшегося автоматического перезапуска
        self._retry_attempt = 0
        self._health_fails = 0
        self._health_busy = False                    # проверка здоровья поставлена или идёт
        self._ks_apps: set[str] = set()              # программы, которые пропускает включённый kill switch
        self._next_health = 0.0
        self._next_memory = 0.0
        self._next_save = 0.0
        self._next_subs = 0.0
        self._disk_cache: dict[str, tuple[float, Any]] = {}

    # ================================================================ общие помощники

    @property
    def status(self) -> str:
        return self._status

    def _vc(self) -> dict:
        return self.settings.get("vpnclient")

    def _changed(self) -> None:
        try:
            self.on_change()
        except Exception:  # noqa: BLE001 — сигнал Core не должен ронять менеджер
            log.debug("on_change не сработал", exc_info=True)

    def _set(self, **values: Any) -> None:
        with self._lock:
            for key, value in values.items():
                setattr(self, f"_{key}", value)
        if "status" in values:
            self._alerts_for_status(values["status"])
        self._changed()

    # ---------------------------------------------------------------- постоянные плашки

    def _set_alert(self, alert_id: str, level: str, text: str, action: dict | None = None,
                   page: str | None = "vpnclient") -> None:
        """Поломка, найденная без нажатия человека: плашка в окне вместо уведомления (решение владельца
        2026-10-18). Висит, пока не снимут _clear_alert; повтор с тем же id только обновляет текст."""
        if self.alert is None:
            log.info("Плашка %s: %s", alert_id, applog.scrub(str(text)))
            return
        try:
            self.alert(alert_id, level, applog.scrub(str(text)), action=action, page=page)
        except Exception:  # noqa: BLE001 — плашка не должна ронять менеджер
            log.debug("Плашка не поставлена", exc_info=True)

    def _clear_alert(self, alert_id: str) -> None:
        if self.alert is None:
            return
        try:
            self.alert(alert_id, None)
        except Exception:  # noqa: BLE001
            log.debug("Плашка не снята", exc_info=True)

    def _alerts_for_status(self, status: str) -> None:
        """Плашки сеанса ядра живут, пока он идёт: выключили, перезапускаем или не включился — сняты.
        «Ядро упало» — до нового «работает» или до «выключено» (ставится после смены статуса на error)."""
        if status not in ("running", "stopping"):
            for alert_id in SESSION_ALERTS:
                self._clear_alert(alert_id)
        if status in ("running", "stopped"):
            self._clear_alert(CRASH_ALERT)

    def _cached(self, key: str, compute: Callable[[], Any]) -> Any:
        now = time.monotonic()
        hit = self._disk_cache.get(key)
        if hit is not None and now - hit[0] < DISK_CACHE:
            return hit[1]
        value = compute()
        self._disk_cache[key] = (now, value)
        return value

    @property
    def store(self):
        if self._store is None:
            if self.deps.store is not None:
                self._store = self.deps.store
            else:
                store = self._mod("store").ProfileStore(paths.PROFILES_FILE, secure=_secure_dir())
                if getattr(store, "load_error", None):   # нашлось при запуске, а не по нажатию — плашка
                    self._set_alert(STORE_ALERT, "error", f"Профили своего VPN не прочитаны: {store.load_error}")
                self._store = store
        return self._store

    def _mod(self, name: str):
        """Модуль пакета (или его подмена в тестах)."""
        return self.deps.modules.get(name) or _module(name)

    def _engines(self):
        return self._mod("engines")

    def _config(self):
        return self._mod("config")

    def _routing(self):
        return self._mod("routing")

    def _sysproxy(self) -> SysProxy:
        if self.deps.sysproxy is None:
            self.deps.sysproxy = SysProxy(paths.SYSPROXY_BACKUP_FILE)
        return self.deps.sysproxy

    def _rules(self):
        if self.deps.rules is None:
            self.deps.rules = self._mod("rules").RulesManager(paths.VPNCLIENT_RULES_DIR, opener_for=self.opener_for)
        return self.deps.rules

    def _killswitch(self):
        if self.deps.killswitch is None:
            try:
                self.deps.killswitch = self._mod("killswitch").KillSwitch()
            except VpnClientError as exc:
                log.warning("Kill switch недоступен: %s", exc)
                return None
        return self.deps.killswitch

    def opener_for(self, route: str) -> urllib.request.OpenerDirector:
        """Маршрут загрузок (подписки, файлы правил): "direct" — напрямую, "vpn" — через служебный вход."""
        if self.deps.opener is not None:
            return self.deps.opener(route)
        if route == "vpn":
            session = self._session
            if session is None or self._status != "running":
                raise VpnClientError("Свой VPN выключен — через него не скачать")
            return proxy_opener(session.plan.ports.internal, session.plan.secrets.internal_user,
                                session.plan.secrets.internal_pass)
        return direct_opener()

    # ================================================================ жизненный цикл менеджера

    def init(self) -> None:
        """При запуске Лазейки: секреты профилей — в фильтр журнала, системный прокси после аварии."""
        try:
            self._register_store_secrets()
        except UserError as exc:
            log.warning("Профили своего VPN не загружены: %s", exc)
        try:
            restored = self._sysproxy().recover_after_crash(int(self._vc()["port"]))
        except (UserError, OSError) as exc:
            log.info("Системный прокси после аварии не проверен: %s", exc)
            return
        if restored and restored.get("restored"):
            self.notify("info", "Системный прокси прошлого сеанса Лазейки возвращён в прежнее состояние.")

    def _register_store_secrets(self) -> None:
        values: list[str | None] = []
        for server in self.store.servers():
            values += _server_secrets(server)
        for sub in self.store.subscriptions():
            values += [sub.url, sub.hwid, *sub.fallback_urls]
        values.append(self._auth.load().get("password"))
        applog.add_secrets(values)

    def shutdown(self) -> None:
        """Выход из Лазейки: системный прокси — первым, затем ядра. Запуск в очереди может как раз
        включать прокси: close() запрещает новые включения, начатое доработает под блокировкой
        SysProxy, и второе восстановление после остановки ядер вернёт и его."""
        self._closing = True
        self._abort.set()
        self._cancel.set()
        try:
            self._sysproxy().close()
        except Exception:  # noqa: BLE001 — выход не должен споткнуться о прокси
            log.debug("Системный прокси не закрыт для включений", exc_info=True)
        self._restore_proxy()
        future: concurrent.futures.Future = concurrent.futures.Future()

        def job() -> None:
            try:
                future.set_result(self._stop_session(remember=False))
            except BaseException as exc:  # noqa: BLE001
                future.set_exception(exc)

        self._ops.submit(job)
        try:
            future.result(STOP_WAIT)
        except concurrent.futures.TimeoutError:
            log.warning("Ядро не остановилось вовремя — завершаю процессы")
            session = self._session
            for proc in (session.main, session.helper) if session else ():
                if proc is not None:
                    proc.stop(soft=0)
        except Exception:  # noqa: BLE001
            log.exception("Свой VPN не остановился при выходе")
        self._restore_proxy()
        self._traffic.save()

    def wait_idle(self, timeout: float = 10.0) -> bool:
        """Дождаться, пока очередь действий опустеет (тесты и выход)."""
        return self._ops.wait_idle(timeout)

    # ================================================================ тикер

    def tick(self) -> None:
        """Раз в секунду из тикера Core: только кэш и постановка задач — ничего не ждёт."""
        now = self.deps.clock()
        session = self._session
        if session is not None and self._status == "running":
            self._count_traffic(session)
            if now >= self._next_memory:
                self._next_memory = now + MEMORY_EVERY
                self._memory = {"sing-box": self.deps.memory(session.main.pid) if session.main.pid else None,
                                "xray": self.deps.memory(session.helper.pid)
                                if session.helper is not None and session.helper.pid else None}
            # Ключ очереди снимается уже на старте задачи — без флага за идущей проверкой встала бы вторая.
            if now >= self._next_health and not self._health_busy:
                self._next_health = now + (HEALTH_EVERY if self._verified else UNVERIFIED_RETRY)
                self._health_busy = True          # снимает сама _health, когда кончится
                self._ops.submit(self._health, key="health")
            wanted = self._bypass_wanted()
            if wanted is not None and wanted != self._bypass_applied and now - self._bypass_at >= BYPASS_HYSTERESIS:
                self._ops.submit(self._apply_bypass, key="bypass")
        elif session is None and self._retry_at is not None and now >= self._retry_at:
            self._ops.submit(self._retry_start, key="retry")
        if now >= self._next_save:
            self._next_save = now + TRAFFIC_SAVE_EVERY
            self._traffic.save()
        if now >= self._next_subs and self.is_admin:
            self._next_subs = now + SUB_CHECK_EVERY
            self._auto_update_subs(now)
        self._cores_tick(now)

    def _count_traffic(self, session: _Session) -> None:
        up, down = session.sampler.totals()
        last_up, last_down = session.last_totals
        if (up, down) != (last_up, last_down):
            self._traffic.add(max(0, up - last_up), max(0, down - last_down))
            session.last_totals = (up, down)

    # ================================================================ снимок для страницы

    def snapshot(self) -> dict:
        vc = self._vc()
        with self._lock:
            status, verified = self._status, self._verified
            error, error_kind, exit_info = self._error, self._error_kind, self._exit
            session = self._session
            cores = {k: dict(v) for k, v in self._cores.items()}
            latency, speed, imp = dict(self._latency), dict(self._speed), dict(self._import)
            updating = set(self._updating)
            deeplink, conflict, memory = self._deeplink, self._conflict, dict(self._memory)
        sampled = session.sampler.snapshot() if session is not None else None
        store_error = None
        try:
            store = self.store
            servers, subs, groups = store.servers(), store.subscriptions(), store.groups()
            selected_id, latencies, speeds = store.selected(), store.latency(), _store_speeds(store)
        except UserError as exc:
            store_error = str(exc)
            servers, subs, groups, selected_id, latencies, speeds = [], [], [], None, {}, {}
        noises = bool(vc.get("noises"))
        unavailable = self._unavailable or store_error
        idle_stats = {"up": 0, "down": 0, "up_rate": 0.0, "down_rate": 0.0, "connections": 0}
        return {
            "available": unavailable is None, "unavailable_reason": unavailable,
            "cores": self._cores_snapshot(cores, servers, noises),
            "status": status, "verified": verified, "error": error, "error_kind": error_kind,
            "mode": vc["mode"], "started_at": session.started if session else None,
            "listen": session.proxy_address if session and session.plan.mode in ("proxy", "local") else None,
            "exit": dict(exit_info) if exit_info else None,
            "selected": self._selected_snapshot(selected_id, servers, groups, subs, session, sampled, noises),
            "stats": sampled["stats"] if sampled else idle_stats,
            "history": sampled["history"] if sampled else [],
            "subscriptions": [self._sub_public(s, servers, updating) for s in subs],
            "groups": [{"id": g.id, "sub": g.sub, "name": _shown(g.name), "members": list(g.members)}
                       for g in groups],
            "servers": [dict(_public(s, noises), latency=_latency_entry(latencies.get(s.id)),
                             speed=_speed_entry(speeds.get(s.id))) for s in servers],
            "latency": latency, "speed": speed, "import": imp,
            "routing": self._routing_snapshot(vc),
            "routing_profiles": self._cached("profiles", lambda: [self._profile_public(p)
                                                                  for p in self._profiles.load()]),
            "settings": self._settings_snapshot(vc),
            "traffic": self._traffic.snapshot(),
            "memory": memory if session else {"sing-box": None, "xray": None},
            "deeplink_request": dict(deeplink) if deeplink else None,
            "conflict": dict(conflict) if conflict else None,
        }

    def _sub_public(self, sub: Subscription, servers: list[Server], updating: set[str]) -> dict:
        info = sub.public(servers=sum(1 for x in servers if x.sub == sub.id), updating=sub.id in updating,
                          probe=self._probes.get(sub.id))
        for key in ("name", "announce", "description"):
            info[key] = _shown(info.get(key))
        for key in ("support_url", "web_page_url"):
            url = info.get(key)
            if isinstance(url, str) and applog.scrub(url) != url:
                # В адресе секрет подписки (часто это она сама): странице — только пометка,
                # открывает open_link по id подписки.
                info[key] = "hidden"
        return info

    def _cores_snapshot(self, states: dict, servers: list[Server], noises: bool) -> dict:
        vc = self._vc()

        def disk() -> dict:
            try:
                engines = self._engines()
            except VpnClientError:
                return {}
            out = {}
            for name in CORE_SETTING:
                try:
                    version = engines.installed(name, vc.get(CORE_SETTING[name])) or engines.installed(name)
                    out[name] = (version, engines.origin(name, version) == "auto")
                except (UserError, OSError):
                    out[name] = (None, False)
            return out

        found = self._cached("cores", disk)
        needed = {"sing-box": True, "xray": any(engine_for(s, force_xray=noises)[0] == "xray" for s in servers)}
        session = self._session
        with self._lock:
            retry_at, notes = self._fetch_retry_at, dict(self._core_notes)
        out = {}
        for name, state in states.items():
            version, auto = found.get(name, (None, False))
            # in_use — версия работающего ядра: новая активная начнёт работать со следующего подключения.
            out[name] = {"installed": version is not None, "version": version,
                         "in_use": _running_versions(session).get(name) if session is not None else None,
                         "auto_updated": auto, "needed": needed[name], **state,
                         "retry_at": retry_at if version is None else None, "note": notes.get(name)}
        return out

    def _selected_snapshot(self, selected: str | None, servers: list[Server], groups: list[Group],
                           subs: list[Subscription], session: _Session | None, sampled: dict | None,
                           noises: bool) -> dict | None:
        if not selected:
            return None
        by_id = {s.id: s for s in servers}
        if selected.startswith("auto:"):
            group = self._group(selected[5:], groups, subs, servers)
            if group is None:
                return None
            actual = None
            if session is not None and sampled is not None:
                current = sampled["now"].get(self._tag(selected))
                server = by_id.get(session.tags.get(current, "")) if current else None
                if server is not None:
                    actual = {"id": server.id, "name": _shown(server.display_name()), "country": server.country}
            shown = by_id.get(actual["id"]) if actual else next((by_id[m] for m in group.members if m in by_id), None)
            base = _public(shown, noises) if shown else {}
            return {"id": selected, "kind": "auto", "name": _shown(group.name), "country": None,
                    "proto": base.get("proto"), "transport": base.get("transport"),
                    "security": base.get("security"), "engine": base.get("engine"), "actual": actual}
        server = by_id.get(selected)
        if server is None:
            return None
        info = _public(server, noises)
        return {"id": server.id, "kind": "server", "name": info["name"], "country": server.country,
                "proto": info["proto"], "transport": info["transport"], "security": info["security"],
                "engine": info["engine"], "actual": None}

    def _routing_snapshot(self, vc: dict) -> dict:
        state, note = self._bypass_view(vc)

        def rules_status() -> dict:
            try:
                return dict(self._rules().status())
            except (UserError, AttributeError, OSError):
                return {}

        rules = self._cached("rules", rules_status)
        rules = {"state": rules.get("state", "idle"), "updated_at": rules.get("updated_at"),
                 "stale": bool(rules.get("stale")), "items": list(rules.get("items") or []),
                 "error": rules.get("error")}
        return {"preset": vc["preset"], "via_zapret": vc["via_zapret"], "bypass": state, "bypass_note": note,
                "games_direct": vc["games_direct"], "torrents_direct": vc["torrents_direct"],
                "ip_check_direct": vc["ip_check_direct"], "direct_apps": list(vc["direct_apps"]),
                "proxy_apps": list(vc["proxy_apps"]), "direct_sites": list(vc["direct_sites"]),
                "proxy_sites": list(vc["proxy_sites"]), "rules": rules}

    def _settings_snapshot(self, vc: dict) -> dict:
        auth = self._auth.load()
        out = {"port": vc["port"], "local_auth": vc["local_auth"], "local_user": auth.get("user") or "",
               "local_password_set": bool(auth.get("password"))}
        out.update({key: vc[key] for key in SETTINGS_KEYS if key not in out})
        return out

    # ================================================================ своё для Core

    def own(self):
        """Снимок своего VPN для «Совместимости с VPN»: серверы — уже на этапе сборки плана, чтобы
        фильтр обхода перестроился до старта ядра."""
        from .. import vpn
        with self._lock:
            session, pending = self._session, self._pending
        plan = session.plan if session is not None else pending
        if plan is None:
            return None
        tun = plan.tun if plan.mode == "tun" else None
        values = dict(pids=session.pids() if session is not None else set(),
                      adapter_name=tun.interface_name if tun else None,
                      tun_net=str(ipaddress.ip_interface(tun.address4).network) if tun else None,
                      servers=sorted(set(plan.addresses.values()))[:MAX_CONFIG_SERVERS],
                      proxy=session.proxy_address if session is not None and plan.mode == "proxy" else None,
                      label=OWN_LABEL)
        own_cls = getattr(vpn, "OwnVpn", None)
        if own_cls is None:
            from types import SimpleNamespace
            return SimpleNamespace(**values)
        return own_cls(**values)

    def set_bypass(self, view: ZapretView | None = None) -> None:
        """Состояние обхода сменилось (Core): селектор «через обход» поменяет тикер — с гистерезисом.
        Сменились стратегия или списки — на работающем ядре пересобрать правила «через обход»."""
        self._view_cache = view if view is not None else self._view(fresh=True)
        if self._session is not None:
            self._ops.submit(self._refresh_bypass, key="bypass-rules")

    def _refresh_bypass(self) -> None:
        """Файлы доменов и адресов «через обход» — локальные rule-set: sing-box перечитывает их сам,
        перезапуск не нужен (неизменённые файлы routing не трогает). Поменялось устройство профилей
        (сети, порты, какие файлы) — в конфиге другие правила маршрута: перезапуск с новым конфигом,
        kill switch при этом не снимается."""
        session = self._session
        if session is None or self._status != "running" or self._closing:
            return
        vc, view, plan = self._vc(), self._view(), session.plan
        wanted = bool(vc["via_zapret"]) and bool(view.strategy_args) and view.pack_dir is not None
        profiles: list = []
        voice: list[str] = []
        if wanted:
            try:
                result = self._routing().bypass_from_strategy(
                    view.strategy_args, pack_dir=view.pack_dir, ipset_mode=view.ipset_mode or "loaded",
                    out_dir=self.run_dir)
            except (UserError, OSError, ValueError) as exc:
                log.warning("Правила «через обход» не пересобраны: %s", exc)
                return
            profiles, voice = list(result.profiles), list(result.voice_ports)
            self._bypass_notes = list(result.notes)
        before = (plan.bypass, plan.voice_ports) if plan.via_zapret else ([], [])
        if _bypass_shape(profiles, voice) == _bypass_shape(*before):
            if wanted:
                plan.bypass, plan.voice_ports = profiles, voice
            return
        log.info("Профили «через обход» изменились — перезапускаю свой VPN с новыми правилами")
        try:
            self._restart_job()
        except UserError as exc:
            log.warning("Свой VPN не перезапустился с новыми правилами обхода: %s", exc)

    def on_resume(self) -> None:
        """Выход из сна: без перезапуска — закрыть мёртвые соединения и заново проверить выход."""
        if self._session is None:
            return
        if self._vc()["on_sleep"] == "disconnect":
            self._ops.submit(lambda: self._stop_session(remember=False), key="sleep")
        else:
            self._ops.submit(self._after_sleep, key="sleep")

    def on_network_change(self) -> None:
        """Сменилась сеть: помощнику Xray — новый физический адаптер, выход — проверить снова."""
        if self._session is not None:
            self._ops.submit(self._after_network_change, key="network")

    # ================================================================ запуск

    def preflight(self) -> dict:
        """То, что видит только менеджер: режим прокси под чужой учётной записью UAC."""
        conflict = None
        if self._vc()["mode"] == "proxy":
            reason = self._sysproxy().available()
            if reason:
                conflict = {"kind": "uac_user", "label": OWN_LABEL, "text": reason}
        with self._lock:
            self._conflict = conflict
        return {"ok": True, "ask": conflict is not None, "conflict": conflict}

    def start(self, quiet: bool = False) -> dict:
        """Включить и дождаться «Подключено» (или ошибки). Core зовёт фоном; quiet — окно о чужом VPN
        человек уже видел (менеджер сам ни о чём не спрашивает)."""
        self._ensure_available()
        self._abort.clear()
        return self._ops.call(lambda: self._start(reason="user"))

    def stop(self, remember: bool = True) -> dict:
        self._abort.set()                         # запуск, который ещё идёт, остановится на ближайшем шаге
        return self._ops.call(lambda: self._stop_session(remember=remember))

    def restart(self) -> dict:
        self._ensure_available()
        self._abort.clear()
        return self._ops.call(lambda: self._restart_job(user=True))

    def set_mode(self, mode: str) -> dict:
        """Режим сохраняется сразу, поэтому ответ правдив: недоступный режим — ошибка, {} — режим уже другой
        (на нём и включится VPN следующим действием). Работающий VPN переподключается в очереди ядра, ход —
        в статусе. Без сеанса kill switch, оставшийся после падения, снимается, если режим не «Весь трафик»:
        вне TUN он держал бы интернет закрытым без всякого VPN."""
        if mode not in MODES:
            raise VpnClientError(f"Неизвестный режим: {mode}")
        if mode == "proxy":
            reason = self._sysproxy().available()
            if reason:
                raise VpnClientError(reason)
        running = self._session is not None
        if running:
            self._ensure_available()
        self.settings.update(lambda d: d["vpnclient"].__setitem__("mode", mode))
        if running:
            self._abort.clear()
            self._ops.submit(self._restart_job, key="restart")
        elif mode != "tun":
            self._ops.submit(self._toggle_killswitch, key="killswitch")
        self._changed()
        return {}

    def _ensure_available(self) -> None:
        if self._closing:
            raise VpnClientError("Лазейка завершает работу")
        if self._unavailable:
            raise VpnClientError(self._unavailable)

    def _check_abort(self) -> None:
        if self._abort.is_set() or self._closing:
            raise _Aborted("Включение отменено")

    def _start(self, reason: str) -> dict:
        if self._session is not None:
            return {"verified": self._verified, "exit": self._exit}
        self._set(status="starting", error=None, error_kind=None, verified=False, exit=None)
        try:
            result = self._launch_or_rollback()
        except _Aborted:
            self._set(status="stopped", pending=None)
            log.info("Включение своего VPN отменено")
            return {"verified": False, "exit": None}
        except BaseException as exc:
            kind, text = self._failure(exc)
            self._set(status="error", error=text, error_kind=kind, pending=None)
            log.warning("Свой VPN не включился (%s): %s", kind, text)
            if isinstance(exc, UserError):
                raise VpnClientError(text, kind) from exc
            raise
        if reason == "user":
            self.settings.update(lambda d: d["vpnclient"].__setitem__("was_running", True))
        return result

    def _failure(self, exc: BaseException) -> tuple[str, str]:
        if isinstance(exc, ProcessError):
            kind, text = diagnose.classify(exc.tail) if exc.tail else ("core", str(exc))
        elif isinstance(exc, ClashError):
            kind, text = "core", f"Ядро запустилось, но не отвечает: {exc}"
        elif type(exc).__name__ == "EngineError":
            kind, text = "core", str(exc)
        elif type(exc).__name__ == "ConfigError":
            kind, text = "unsupported", str(exc)   # у сервера параметры, из которых конфиг не собрать
        else:
            kind, text = getattr(exc, "kind", None) or "other", str(exc) or repr(exc)
        return kind, applog.scrub(text)

    def _launch_all(self) -> dict:
        # Kill switch уже держит интернет (перезапуск, падение, повтор) — неудачный запуск его не снимает:
        # VPN по-прежнему «включён», а трафик не должен уйти напрямую.
        keep_killswitch = bool(getattr(self.deps.killswitch, "active", False))
        vc = self._vc()
        pick = self._selection(vc)
        versions = self._ensure_cores(pick["engines"])
        avoid: set[int] = set()
        session = None
        for attempt in range(PORT_ATTEMPTS):
            self._check_abort()
            plan, config_paths = self._plan_and_configs(vc, pick, versions, avoid)
            with self._lock:
                self._pending = plan
            self._changed()
            if self.before_core is not None:
                try:
                    self.before_core()            # фильтр обхода — до старта ядра: адреса серверов известны
                except Exception:  # noqa: BLE001 — обход перестроится по тикеру Core
                    log.exception("Фильтр обхода не перестроен до старта ядра")
            self._check_abort()
            try:
                session = self._launch(plan, versions, config_paths)
                break
            except ProcessError as exc:
                if diagnose.classify(exc.tail)[0] != "port" or attempt == PORT_ATTEMPTS - 1:
                    raise
                avoid |= _ports_of(plan)
                log.info("Порт занят — повторяю запуск с другими портами (попытка %d)", attempt + 2)
        assert session is not None
        with self._lock:
            self._session, self._pending = session, None
            self._bypass_applied = plan.bypass_state if plan.via_zapret and plan.bypass else None
            self._bypass_at = self.deps.clock()
            self._health_fails = 0
            self._next_health = self.deps.clock() + HEALTH_EVERY
        try:
            self._check_abort()
            self._after_launch(session)
        except BaseException:
            self._teardown(session, keep_killswitch=keep_killswitch)
            raise
        self._retry_at, self._retry_attempt = None, 0
        self._set(status="running")
        log.info("Свой VPN работает (%s, серверов в конфиге: %d)", plan.mode, len(plan.servers))
        self._verify_exit(session, announce=True)
        return {"verified": self._verified, "exit": self._exit}

    def _plan_and_configs(self, vc: dict, pick: dict, versions: dict[str, str], avoid: set[int]
                          ) -> tuple[RunPlan, dict[str, Path]]:
        """План и проверенные конфиги. Не собрался конфиг со всей подпиской (у соседнего сервера битые
        параметры) — включаем только выбранное: переключение на соседей тогда будет с перезапуском."""
        plan = self._build_plan(vc, pick, versions, avoid)
        try:
            return plan, self._write_configs(plan, versions)
        except UserError as exc:
            narrow = _narrow(pick)
            if narrow is None:
                raise
            log.warning("Конфиг со всеми серверами подписки не собрался (%s) — включаю только выбранное", exc)
        plan = self._build_plan(vc, narrow, versions, avoid)
        return plan, self._write_configs(plan, versions)

    # ---------------------------------------------------------------- выбор серверов

    def _selection(self, vc: dict) -> dict:
        """Что войдёт в конфиг: выбранный сервер (или группа) и остальные серверы его подписки — тогда
        переключение внутри подписки идёт без перезапуска (до 16: их адреса исключаются из обхода)."""
        store = self.store
        noises = bool(vc.get("noises"))
        all_servers = store.servers()
        groups, subs = store.groups(), store.subscriptions()
        supported = [s for s in all_servers if engine_for(s, force_xray=noises)[0]]
        selected = store.selected()
        if not selected:
            if not supported:
                raise VpnClientError("Добавьте подписку или ссылку на сервер — включать пока нечего")
            selected = supported[0].id
            store.select(selected)
        if selected.startswith("auto:"):
            group = self._group(selected[5:], groups, subs, all_servers)
            if group is None:
                raise VpnClientError("Выбранная группа «Самый быстрый» пропала — выберите сервер")
            members = [s for s in supported if s.id in group.members][:MAX_CONFIG_SERVERS]
            if not members:
                raise VpnClientError(f"В группе «{group.name}» нет серверов, которые Лазейка умеет открывать",
                                     "unsupported")
            sub_id, primary = group.sub, members
            plan_groups = [replace(group, members=[s.id for s in members])]
        else:
            first = next((s for s in all_servers if s.id == selected), None)
            if first is None:
                raise VpnClientError("Выбранный сервер пропал из подписки — выберите другой")
            engine, why = engine_for(first, force_xray=noises)
            if engine is None:
                raise VpnClientError(f"Сервер «{first.display_name()}» не поддерживается: {why}", "unsupported")
            sub_id, primary, plan_groups = first.sub, [first], []
        chosen = {s.id for s in primary}
        servers = (primary + [s for s in supported if s.sub == sub_id and s.id not in chosen])[:MAX_CONFIG_SERVERS]
        ids = {s.id for s in servers}
        for g in groups:
            if g.sub == sub_id and g.id not in {x.id for x in plan_groups} and set(g.members) & ids:
                plan_groups.append(replace(g, members=[m for m in g.members if m in ids]))
        return {"selected": selected, "servers": servers, "groups": plan_groups, "first": primary[0],
                "primary": primary,
                "engines": {s.id: engine_for(s, force_xray=noises)[0] for s in servers},
                "sub": next((s for s in subs if s.id == sub_id), None)}

    @staticmethod
    def _group(group_id: str, groups: list[Group], subs: list[Subscription], servers: list[Server]) -> Group | None:
        """Группа провайдера или «вся подписка» (auto:<id подписки>)."""
        found = next((g for g in groups if g.id == group_id), None)
        if found is not None:
            return found
        sub = next((s for s in subs if s.id == group_id), None)
        if sub is None:
            return None
        return Group(id=sub.id, sub=sub.id, name=f"{sub.name}: самый быстрый",
                     members=[s.id for s in servers if s.sub == sub.id])

    # ---------------------------------------------------------------- ядра

    def _ensure_cores(self, engines_by_server: dict[str, str | None]) -> dict[str, str]:
        """Установленные и сверенные версии нужных ядер. Обычно их уже скачала подкачка при запуске
        Лазейки; идёт она сейчас — ждём (ход виден на странице), не вышла — ставим сами (это и есть нажатие
        человека). Помощник Xray — только если в конфиге есть серверы для него."""
        need = ["sing-box"] + (["xray"] if "xray" in engines_by_server.values() else [])
        return {name: self._installed_or_install(name) for name in need}

    def _installed_or_install(self, name: str) -> str:
        """Активная версия уже стоит — берём её, даже если рядом ставится новая (автообновление не держит
        запуск). Нет ни одной — ждём идущую подкачку, а не вышла она — ставим сами. Версия попытки
        записывается до сверки exe: изменённый exe пробной версии — тоже повод откатиться."""
        engines = self._engines()
        version = self._active_core(name)
        if version is None:
            with self._core_lock(name, abortable=True):   # проверка и установка — одним шагом с подкачкой
                version = self._active_core(name)
                if version is None:
                    version = self._install_core(name)
                    self._fetch_succeeded(name)         # плашка «не скачалось» снимается сразу
        self._attempted()[name] = version
        engines.verify(name, version)
        return version

    def _attempted(self) -> dict[str, str]:
        """Версии ядер, которые взяла попытка запуска в этом потоке."""
        found = getattr(self._attempt, "versions", None)
        if found is None:
            found = self._attempt.versions = {}
        return found

    def _active_core(self, name: str) -> str | None:
        """Активная версия на диске: из настроек, иначе самая новая из установленных и не забракованных."""
        engines = self._engines()
        wanted = self._vc().get(CORE_SETTING[name])
        return (engines.installed(name, wanted) if wanted else None) or self._fallback_core(name)

    def _fallback_core(self, name: str) -> str | None:
        bad = set(self._vc().get("core_bad_versions") or [])
        return next((v for v in self._engines().versions(name) if f"{name}:{v}" not in bad), None)

    @contextlib.contextmanager
    def _core_lock(self, name: str, *, abortable: bool = False):
        """Установка, проверка, смена активной версии и уборка одного ядра — по одной. Ждущий запуск
        прерывается кнопкой «Выключить»; выход Лазейки прерывает любое ожидание."""
        lock = self._core_ops[name]
        while not lock.acquire(timeout=0.25):
            if self._closing:
                raise _Aborted("Лазейка завершает работу")
            if abortable and self._status == "starting" and self._abort.is_set():
                raise _Aborted("Включение отменено")
        try:
            yield
        finally:
            lock.release()

    def _install_core(self, name: str, *, source: Any = None, activate: bool = True, origin: str = "github",
                      background: bool = False) -> str:
        """Скачать и поставить ядро (source — Release новой версии, None — закреплённая); ход — в состоянии
        ядра. background — автообновление: неудача не переводит ядро в «ошибку установки» — работает
        прежняя версия, итог пишется в заметку."""
        engines = self._engines()

        def progress(state: str, fraction: float | None) -> None:
            with self._lock:
                self._cores[name] = {"state": state, "progress": fraction, "message": None}

        with self._lock:
            if self._cores[name]["state"] not in ("idle", "error"):
                raise VpnClientError(f"{engines.spec(name).title} уже устанавливается")
            self._cores[name] = {"state": "downloading", "progress": None, "message": None}
        self._changed()
        if not activate:
            self._pin_active(name)
        try:
            try:
                version = engines.install(name, progress=progress, source=source, cancel=self._cancel,
                                          origin=origin)
            except BaseException as exc:
                with self._lock:
                    self._cores[name] = {"state": "idle" if background else "error", "progress": None,
                                         "message": None if background else applog.scrub(str(exc))}
                raise
            with self._lock:
                self._cores[name] = {"state": "idle", "progress": None, "message": None}
            if activate:
                self._activate_core(name, version)
        finally:
            self._disk_cache.pop("cores", None)
            self._changed()
        return version

    def _pin_active(self, name: str) -> None:
        """Перед установкой версии рядом: записать активную в настройки. Иначе запасное «самая новая на
        диске» показало бы на только что скачанную и ещё не проверенную."""
        engines = self._engines()
        key = CORE_SETTING[name]
        wanted = self._vc().get(key)
        if wanted and engines.installed(name, wanted):
            return
        current = self._fallback_core(name)
        if current:
            self.settings.update(lambda d: d["vpnclient"].__setitem__(key, current))

    def _activate_core(self, name: str, version: str, *, trial: bool = False) -> None:
        """Сделать версию активной — с неё начнётся следующее подключение — и убрать лишние: остаются она,
        прежняя, последняя надёжная (core_good — на неё откат) и та, на которой ядро работает сейчас.
        trial — новая версия ещё ни разу не запускалась: упадёт при старте — откат на надёжную; сама она
        надёжной станет после первого успешного запуска. Без trial версию выбрали сознательно (подкачка,
        откат) — она и есть надёжная. Зовётся под _core_lock(name)."""
        engines = self._engines()
        previous = self._active_core(name)
        key = f"{name}:{version}"
        good = version if not trial else (self._good(name) or (previous if previous != version else None))

        def mutate(d: dict) -> None:
            vc = d["vpnclient"]
            vc[CORE_SETTING[name]] = version
            vc["core_trial"] = [x for x in vc["core_trial"] if not x.startswith(f"{name}:")] + (
                [key] if trial and previous and previous != version else [])
            vc["core_bad_versions"] = [x for x in vc["core_bad_versions"] if x != key]
            vc["core_good"] = [x for x in vc["core_good"] if not x.startswith(f"{name}:")] + (
                [f"{name}:{good}"] if good else [])

        self.settings.update(mutate)
        self._disk_cache.pop("cores", None)
        keep = {v for v in (version, previous, good) if v}
        session = self._session
        if session is not None and session.versions.get(name):
            keep.add(session.versions[name])
        try:
            engines.prune(name, keep)
        except OSError as exc:
            log.debug("Старые версии %s не удалены: %s", name, exc)

    def _good(self, name: str) -> str | None:
        """Последняя версия ядра, которой можно доверять: запускалась или выбрана сознательно."""
        return next((x.split(":", 1)[1] for x in self._vc().get("core_good") or [] if x.startswith(f"{name}:")),
                    None)

    def core_install(self, name: str, release: Any = None) -> str:
        """«Обновления», страница VPN и плашка «Скачать ещё раз»: поставить ядро. release — новая версия:
        ставится рядом, проходит check нашего конфига и только потом становится активной (прежняя — для
        отката). Без release — закреплённая версия: первая установка или повтор подкачки."""
        self._ensure_available()
        engines = self._engines()
        spec = engines.spec(name)
        with self._core_lock(name):
            if release is None:
                current = self._active_core(name)
                if current is not None and self._verifies(name, current):
                    self._fetch_succeeded(name)
                    return f"{spec.title} {current} уже установлено"
                version = spec.version
                if engines.installed(name, version) is None or not self._verifies(name, version):
                    try:
                        self._install_core(name, activate=False)
                    except UserError as exc:
                        self._fetch_failed({name: str(exc)}, reschedule=False)   # плашка — с новой причиной
                        raise
            else:
                version = self._install_core(name, source=release, activate=False)
                try:
                    self._check_with_new_core(name, version)
                except engines.EngineError as exc:
                    self._reject(name, version, str(exc))
                    raise
                except UserError:
                    self._drop_version(name, version)         # не проверить — не оставляем непроверенное
                    raise
            self._activate_core(name, version, trial=release is not None)
        self._fetch_succeeded(name)
        self._restart_on_new_core(name, version)
        return f"{spec.title} {version} установлено"

    def core_rollback(self, name: str) -> str:
        """«Откатить» на «Обновлениях»: прежняя установленная версия, иначе закреплённая (скачается).
        Текущая помечается неподходящей — автообновление не поставит её снова."""
        self._ensure_available()
        engines = self._engines()
        spec = engines.spec(name)
        with self._core_lock(name):                 # идёт установка или проверка этого ядра — дождаться её
            current = self._active_core(name)
            if current is None:
                raise VpnClientError("Нет более ранней версии для отката")
            bad = set(self._vc().get("core_bad_versions") or [])
            older = [v for v in engines.versions(name) if f"{name}:{v}" not in bad
                     and engines.version_key(v) < engines.version_key(current)]
            target = older[0] if older else spec.version
            if engines.version_key(target) >= engines.version_key(current):
                raise VpnClientError("Нет более ранней версии для отката")
            if engines.installed(name, target) is None:
                self._install_core(name, activate=False)
            self._mark_bad(name, current, "откат вручную")
            self._activate_core(name, target)
        self._note(name, None)
        self._restart_on_new_core(name, target)
        return f"{spec.title}: возвращена версия {target}"

    def _verifies(self, name: str, version: str) -> bool:
        try:
            self._engines().verify(name, version)
            return True
        except (UserError, OSError):
            return False

    def _restart_on_new_core(self, name: str, version: str) -> None:
        """Ручная установка или откат: работающий VPN переходит на эту версию сразу (если это ядро в
        сеансе действительно запущено)."""
        with self._lock:                            # сеанс появляется под этой же блокировкой (_launch_all)
            session = self._session
            if session is None and self._status == "starting":
                self._restart_after_start.add(name)   # запуск ещё идёт и мог взять прежнюю версию
        running = _running_versions(session) if session is not None else {}
        if name in running and running[name] != version:
            self._ops.submit(self._restart_job, key="restart")
        self._changed()

    def _check_with_new_core(self, name: str, version: str) -> None:
        """Конфиг текущих серверов и настроек человека должен пройти `check` новой версией, иначе она не
        становится активной (EngineError). Нет в плане серверов этого ядра (адрес не получен) или конфиг
        из них не собрать — проверяем образцовый: без фактического `check` указанного ядра успеха нет.
        У каждой проверки свой каталог: параллельные проверки двух ядер не стирают файлы друг друга."""
        vc = self._vc()
        engines = self._engines()
        versions = {n: self._active_core(n) or "" for n in CORE_SETTING}
        versions[name] = version
        check_dir = self.run_dir / f"check-{name}-{secrets.token_hex(4)}"
        problem: Exception | None = None
        try:
            for pick in self._check_picks(vc, name):
                try:
                    plan = self._build_plan(vc, pick, versions, set(), routing_dir=check_dir, quiet=True)
                    if not plan.servers or (name == "xray" and "xray" not in plan.engines.values()):
                        continue                    # серверы этого ядра без адреса — проверим образцовый
                    if name in self._write_configs(plan, versions, directory=check_dir, only=name):
                        return
                except engines.EngineError:
                    raise
                except UserError as exc:
                    problem = exc
                    log.info("Конфиг для проверки %s %s не собрался (%s) — беру образцовый", name, version, exc)
        finally:
            shutil.rmtree(check_dir, ignore_errors=True)
        raise VpnClientError(f"Конфиг для проверки новой версии не собрался: {problem or 'нет серверов для ядра'}")

    def _check_picks(self, vc: dict, name: str):
        """Что проверять новой версией: текущие серверы человека (если среди них есть серверы этого ядра),
        затем образцовые."""
        try:
            pick = self._selection(vc)
        except UserError:
            pick = None
        if pick is not None and (name != "xray" or "xray" in pick["engines"].values()):
            yield pick
        links = self._mod("links")
        servers = [links.parse_link(SAMPLE_LINKS["sing-box"])]
        if name == "xray":
            servers.append(links.parse_link(SAMPLE_LINKS["xray"]))
        for server in servers:
            server.id = server.id or server.key()
        yield {"selected": servers[0].id, "servers": servers, "groups": [], "first": servers[0],
               "primary": servers[:1], "engines": {s.id: engine_for(s)[0] for s in servers}, "sub": None}

    # ---------------------------------------------------------------- ядра в фоне: подкачка и автообновление

    def wait_cores(self, timeout: float = 10.0) -> bool:
        """Дождаться фоновой задачи ядер (тесты)."""
        job = self._core_job
        if job is None:
            return True
        job.join(timeout)
        return not job.is_alive()

    def _cores_tick(self, now: float) -> None:
        """Из tick: все ли ядра на месте (нет — подкачка с GitHub, повторы с паузами) и не вышла ли новая
        версия (автообновление). Сама работа — в своём потоке, по одной задаче; без прав — ничего."""
        if not self.is_admin or self._closing:
            return
        job = self._core_job
        if job is not None and job.is_alive():
            return
        try:
            engines = self._engines()
        except VpnClientError:
            return
        if not engines.background_allowed():
            return
        if now >= self._fetch_at:
            self._fetch_at = now + FETCH_RECHECK
            missing = [name for name in CORE_SETTING if self._active_core(name) is None]
            if missing:
                self._spawn_core_job("vpnclient-core-fetch", lambda: self._fetch_job(missing))
                return
            self._fetch_succeeded()
        if self._update_at is None:
            self._update_at = now + CORE_UPDATE_FIRST
        if now >= self._update_at and self._vc().get("core_auto_update", True):
            self._update_at = now + CORE_UPDATE_EVERY
            self._spawn_core_job("vpnclient-core-update", self._update_job)

    def core_update_soon(self) -> None:
        """«Обновления» нашли новую версию ядра: проверить автообновлением сейчас, а не через 6 часов."""
        self._update_at = 0.0

    def _spawn_core_job(self, title: str, fn: Callable[[], None]) -> None:
        def run() -> None:
            try:
                fn()
            except Exception:  # noqa: BLE001 — фоновая задача не роняет тикер
                log.exception("Фоновая задача ядер своего VPN не удалась")

        job = threading.Thread(target=run, name=title, daemon=True)
        self._core_job = job
        job.start()

    def _fetch_job(self, names: list[str]) -> None:
        """Подкачка при запуске: закреплённые версии (хеши в коде) напрямую с GitHub, запасной маршрут —
        через системный прокси. Не вышло — плашка (без уведомлений) и повтор через 1, 5, 15 минут, дальше
        раз в час. Плашка каждого ядра, которое встало, снимается сразу — даже если другое не скачалось."""
        failed: dict[str, str] = {}
        for name in names:
            try:
                with self._core_lock(name):       # ставит человек кнопкой — дождаться его
                    if self._active_core(name) is None:
                        self._install_core(name)
            except UserError as exc:
                if self._closing or self._cancel.is_set():
                    return
                failed[name] = applog.scrub(str(exc))
                log.warning("%s не скачалось: %s", name, failed[name])
            except Exception:  # noqa: BLE001
                log.exception("%s не скачалось", name)
                failed[name] = "внутренняя ошибка — подробности в журнале"
        if not failed:
            self._fetch_succeeded()
            return
        for name in names:
            if name not in failed:
                self._clear_core_alert(name)
        self._fetch_failed(failed)

    def _fetch_failed(self, failed: dict[str, str], *, reschedule: bool = True) -> None:
        with self._lock:
            if reschedule:
                self._fetch_attempt += 1
                self._fetch_at = self.deps.clock() + FETCH_RETRY[min(self._fetch_attempt, len(FETCH_RETRY)) - 1]
                self._fetch_retry_at = self._fetch_at
            retry_at = self._fetch_retry_at
        when = f" Повторю в {time.strftime('%H:%M', time.localtime(retry_at))}." if retry_at else ""
        for name, reason in failed.items():
            what = "Ядро VPN не скачалось" if name == "sing-box" else "Помощник Xray не скачался"
            self._core_alert(name, f"{what}: {applog.scrub(reason).rstrip('.')}.{when}")
        self._changed()

    def _fetch_succeeded(self, name: str | None = None) -> None:
        """Ядро на месте — снять его плашку. name=None — на месте все: сбросить и паузы повторов.
        Поставил человек одно — остальные подкачать сразу, не дожидаясь паузы."""
        with self._lock:
            alerted = set(self._core_alerted) if name is None else {name} & self._core_alerted
            if name is None:
                self._fetch_attempt, self._fetch_retry_at = 0, None
            else:
                self._fetch_at = 0.0
        for item in alerted:
            self._clear_core_alert(item)

    def _core_alert(self, name: str, text: str) -> None:
        """Постоянная плашка «не скачалось» с кнопкой — без уведомлений (решение владельца 2026-10-18).
        Тому, кто свой VPN не настраивал (или чьим серверам помощник Xray не нужен), плашка на главной
        ни к чему: ход и причина видны в строке состояния на странице VPN."""
        with self._lock:
            self._core_alerted.add(name)
        if not self._core_matters(name):
            log.info("%s не скачалось, плашку не показываю: ядро пока не нужно ни одному серверу", name)
            return
        self._set_alert(f"{CORE_ALERT}{name}", "error", text,
                        action={"label": "Скачать ещё раз", "call": "vpnclient_core_install", "args": [name]})

    def _core_matters(self, name: str) -> bool:
        try:
            servers = self.store.servers()
        except UserError:
            return True
        if name == "xray":
            return any(engine_for(s)[0] == "xray" for s in servers)
        return bool(servers)

    def _clear_core_alert(self, name: str) -> None:
        with self._lock:
            self._core_alerted.discard(name)
        self._clear_alert(f"{CORE_ALERT}{name}")

    def _update_job(self) -> None:
        """Автообновление: на GitHub версия новее активной (любая серия; черновики и пре-релизы — нет) →
        скачать, сверить digest, распаковать рядом, `version` и `check` текущего конфига новым ядром. Прошло —
        активна со следующего подключения (работающий VPN не трогаем), прежняя — для отката; не прошло —
        версия помечается неподходящей и больше не скачивается."""
        engines = self._engines()
        for name in CORE_SETTING:
            if self._closing or not self._vc().get("core_auto_update", True):
                return
            current = self._active_core(name)
            if current is None:
                continue                            # не стоит — это дело подкачки
            try:
                release = engines.latest_release(name)
            except UserError as exc:
                log.info("Новые версии %s не проверены: %s", name, exc)
                self._update_at = self.deps.clock() + CORE_UPDATE_RETRY
                continue
            if release is None or engines.version_key(release.version) <= engines.version_key(current):
                continue
            if self._is_bad(name, release.version) or self._skipped(name, release.version):
                continue
            self._auto_update(name, release, current)

    def _auto_update(self, name: str, release: Any, current: str) -> None:
        """Загрузка, check, активация и уборка — целиком под блокировкой ядра: ручной откат ждёт конца и не
        удаляет версию, которую как раз проверяют."""
        with self._core_lock(name):
            if self._active_core(name) != current:
                return                              # пока ждали, активную сменил человек — решит он
            self._auto_update_locked(name, release, current)

    def _auto_update_locked(self, name: str, release: Any, current: str) -> None:
        engines = self._engines()
        new = release.version
        try:
            self._install_core(name, source=release, activate=False, origin="auto", background=True)
        except getattr(engines, "ReleaseRejected", ()) as exc:
            self._reject(name, new, str(exc))
            self._note(name, f"Версия {new} не подошла: {applog.scrub(str(exc))} Осталась {current}.")
            return
        except UserError as exc:
            if not self._closing:
                log.info("%s %s не скачалось автообновлением: %s", name, new, exc)
                self._note(name, f"Версия {new} пока не скачалась ({applog.scrub(str(exc))}) — попробую позже.")
            return
        try:
            self._check_with_new_core(name, new)
        except engines.EngineError as exc:
            self._reject(name, new, str(exc))
            self._note(name, f"Версия {new} не приняла ваши настройки: {applog.scrub(str(exc))} Осталась {current}.")
            return
        except UserError as exc:
            log.warning("%s %s не проверено (%s) — не ставлю, попробую позже", name, new, exc)
            self._drop_version(name, new)
            return
        self._activate_core(name, new, trial=True)
        session = self._session
        later = session is not None and _running_versions(session).get(name) not in (None, new)
        self._note(name, f"Обновлено автоматически до {new}" + (" — заработает при следующем подключении."
                                                                if later else "."))
        log.info("%s обновлено автоматически: %s → %s%s", name, current, new,
                 " (работающий VPN не перезапускаю)" if later else "")

    def _note(self, name: str, text: str | None) -> None:
        with self._lock:
            if text:
                self._core_notes[name] = text
            else:
                self._core_notes.pop(name, None)
        self._changed()

    def _is_bad(self, name: str, version: str) -> bool:
        return f"{name}:{version}" in (self._vc().get("core_bad_versions") or [])

    def _skipped(self, name: str, version: str) -> bool:
        """«Пропустить версию» на «Обновлениях» — и для автообновления."""
        return (self.settings.get("updates", "skipped") or {}).get(CORE_UPDATE_KEY[name]) == version

    def _mark_bad(self, name: str, version: str, why: str) -> None:
        key = f"{name}:{version}"
        log.warning("%s %s больше не ставится: %s", name, version, applog.scrub(why))

        def mutate(d: dict) -> None:
            vc = d["vpnclient"]
            vc["core_bad_versions"] = ([x for x in vc["core_bad_versions"] if x != key] + [key])[-BAD_VERSIONS_LIMIT:]
            vc["core_trial"] = [x for x in vc["core_trial"] if x != key]

        self.settings.update(mutate)

    def _reject(self, name: str, version: str, why: str) -> None:
        """Новая версия не подошла: пометить и убрать с диска (активная и прежняя остаются)."""
        self._mark_bad(name, version, why)
        self._drop_version(name, version)

    def _drop_version(self, name: str, version: str) -> None:
        engines = self._engines()
        if version in (self._active_core(name), self._good(name)):
            return
        try:
            engines.prune(name, set(engines.versions(name)) - {version})
        except OSError as exc:
            log.debug("%s %s не удалено: %s", name, version, exc)
        self._disk_cache.pop("cores", None)

    # ---------------------------------------------------------------- откат версии, которая не запустилась

    def _launch_or_rollback(self) -> dict:
        """Запуск. Новая версия ядра (ещё ни разу не запускалась) упала при сверке exe, старте или готовности —
        откат на последнюю надёжную (core_good), версия помечается неподходящей, запуск повторяется. Упала и
        надёжная — дело не в версии: новая возвращается (уже не «на пробу»), ошибка — прежней."""
        engines = self._engines()
        failures = (ProcessError, ClashError, engines.EngineError)
        self._attempt.versions = {}
        with self._lock:
            self._pending = None
        try:
            result = self._launch_all()
        except failures as exc:
            if isinstance(exc, ProcessError) and exc.tail and diagnose.classify(exc.tail)[0] == "port":
                raise
            trial = self._trial_cores(self._involved())
            if not trial:
                raise
            for name, (new, target) in trial.items():
                log.warning("%s %s не запустилось (%s) — возвращаю %s", name, new, applog.scrub(str(exc)), target)
                with self._core_lock(name, abortable=True):
                    self._mark_bad(name, new, f"не запустилось: {exc}")
                    self._activate_core(name, target)
            self._set(status="starting", error=None, error_kind=None, pending=None)
            self._attempt.versions = {}
            try:
                result = self._launch_all()
            except failures:
                for name, (new, _target) in trial.items():
                    with self._core_lock(name, abortable=True):
                        self.settings.update(lambda d, key=f"{name}:{new}": d["vpnclient"].__setitem__(
                            "core_bad_versions", [x for x in d["vpnclient"]["core_bad_versions"] if x != key]))
                        self._activate_core(name, new)
                raise
            for name, (new, target) in trial.items():
                self._note(name, f"Версия {new} не запустилась — вернула {target}; {new} больше не ставится.")
        self._trial_passed()
        self._restart_if_switched()
        return result

    def _restart_if_switched(self) -> None:
        """Пока шёл запуск, человек сменил версию ядра (откат, установка), а запуск взял прежнюю — сразу
        переподключиться на выбранную. Автообновление сюда не попадает: оно ждёт следующего подключения."""
        with self._lock:
            wanted, self._restart_after_start = self._restart_after_start, set()
            session = self._session
        running = _running_versions(session) if session is not None else {}
        if any(name in running and running[name] != self._active_core(name) for name in wanted):
            self._ops.submit(self._restart_job, key="restart")

    def _involved(self) -> dict[str, str]:
        """Версии ядер упавшей попытки. Помощник Xray — только если план успел собраться с ним: без его
        серверов в плане он бы и не запускался."""
        used = dict(self._attempted())
        plan = self._pending
        if plan is not None and "xray" not in plan.engines.values():
            used.pop("xray", None)
        return used

    def _trial_cores(self, used: dict[str, str]) -> dict[str, tuple[str, str]]:
        """Ядра попытки, чья версия ещё на пробе, и куда откатиться: {имя: (новая, куда)}. Куда — последняя
        надёжная, если она на диске; иначе ближайшая старшая незабракованная."""
        engines = self._engines()
        vc = self._vc()
        trial, bad = set(vc.get("core_trial") or []), set(vc.get("core_bad_versions") or [])
        out = {}
        for name, version in used.items():
            if f"{name}:{version}" not in trial:
                continue
            good = self._good(name)
            if good and good != version and f"{name}:{good}" not in bad and engines.installed(name, good):
                out[name] = (version, good)
                continue
            older = [v for v in engines.versions(name) if f"{name}:{v}" not in bad
                     and engines.version_key(v) < engines.version_key(version)]
            if older:
                out[name] = (version, older[0])
        return out

    def _trial_passed(self) -> None:
        """Ядра запустились — их версии больше не на пробе и становятся надёжными. Только те, что в сеансе
        действительно работают: помощник Xray без своих серверов не запускался — его версия ещё на пробе."""
        session = self._session
        if session is None:
            return
        running = _running_versions(session)
        used = {f"{n}:{v}" for n, v in running.items()}
        vc = self._vc()
        if not (used & set(vc.get("core_trial") or [])) and used <= set(vc.get("core_good") or []):
            return

        def mutate(d: dict) -> None:
            v = d["vpnclient"]
            v["core_trial"] = [x for x in v["core_trial"] if x not in used]
            v["core_good"] = [x for x in v["core_good"] if x.split(":", 1)[0] not in running] + sorted(used)

        self.settings.update(mutate)

    # ---------------------------------------------------------------- план

    def _build_plan(self, vc: dict, pick: dict, versions: dict[str, str], avoid: set[int], *,
                    mode: str | None = None, routing_dir: Path | None = None, quiet: bool = False) -> RunPlan:
        """RunPlan для генератора: адреса серверов (DoH), порты, секреты, TUN, маршруты, «через обход»."""
        sub: Subscription | None = pick["sub"]
        dns = self._dns_choice(vc, sub)
        addresses: dict[str, str] = {}
        servers = []
        # Адрес выбранного сервера обязателен; у группы «Самый быстрый» — хотя бы одного участника.
        required = None if pick["selected"].startswith("auto:") or quiet else pick["first"].id
        failure: Exception | None = None
        families = _address_families(vc, self.deps.ipv6_internet)
        for server in pick["servers"]:
            try:
                addresses[server.id] = self._resolver.resolve(server.host, dns.direct, families=families)
                servers.append(server)
            except UserError as exc:
                if server.id == required:
                    raise VpnClientError(f"Не удалось узнать адрес сервера «{server.display_name()}»: {exc}",
                                         "timeout") from exc
                failure = exc
                log.info("Сервер «%s» без адреса — в конфиг не войдёт", server.display_name())
        if not servers and not quiet:
            raise VpnClientError(f"Не удалось узнать адреса серверов: {failure}", "timeout")
        working = getattr(self._resolver, "working", None)
        if vc["dns_direct"] == "auto" and working:
            dns.direct = working
        engines = {s.id: pick["engines"][s.id] for s in servers}
        groups = [replace(g, members=[m for m in g.members if m in engines]) for g in pick["groups"]]
        plan = RunPlan(mode=mode or vc["mode"], servers=servers, selected=pick["selected"], groups=groups,
                       addresses=addresses, engines=engines, dns=dns)
        self._fill_ports(plan, vc, avoid)
        self._fill_routing(plan, vc, routing_dir or self.run_dir, quiet)
        auth = self._auth.load() if vc["local_auth"] or vc["allow_lan"] else {}
        plan.secrets = Secrets(clash=secrets.token_urlsafe(24), internal_user=f"lz{secrets.token_hex(4)}",
                               internal_pass=secrets.token_urlsafe(18), helper_user=f"lzh{secrets.token_hex(4)}",
                               helper_pass=secrets.token_urlsafe(18), local_user=auth.get("user"),
                               local_pass=auth.get("password"))
        if plan.mode == "tun":
            net = pick_tun_subnet(self.deps.taken_nets(), list(vc["exclude_nets"]))
            plan.tun = TunOptions(address4=f"{next(net.hosts())}/{net.prefixlen}",
                                  address6=TUN_IPV6 if vc["ipv6"] else None,
                                  mtu=int(sub.mtu if sub and sub.mtu else vc["tun_mtu"]),
                                  exclude=list(vc["exclude_nets"]), interface_name=TUN_NAME)
        plan.proxy_listen = "0.0.0.0" if vc["allow_lan"] else "127.0.0.1"
        plan.socks_udp = bool(vc["socks_udp"])
        plan.proxy_override = list(vc["proxy_override"])
        plan.tls_fragment, plan.mux, plan.noises = bool(vc["tls_fragment"]), bool(vc["mux"]), bool(vc["noises"])
        plan.fingerprint = vc["fingerprint"] or None
        # Правило «Лазейка — напрямую» ищет процесс по пути: в разработке это настоящий интерпретатор,
        # а не пускач python.exe из venv.
        plan.lazeyka_exe = str(paths.exe_path() if paths.IS_FROZEN
                               else Path(getattr(sys, "_base_executable", sys.executable)).resolve())
        if "xray" in engines.values() and versions.get("xray"):
            core = self._engines()
            plan.xray_exe = str(core.version_dir("xray", versions["xray"]) / core.spec("xray").exe)
            plan.physical_interface = self.deps.physical_interface()
        plan.log_level = "info" if vc["verbose"] else "error"
        plan.work_dir = self.run_dir
        group = next((g for g in groups if f"auto:{g.id}" == plan.selected), None)
        plan.probe_url = group.probe_url if group else PROBE_URL
        return plan

    @staticmethod
    def _dns_choice(vc: dict, sub: Subscription | None) -> DnsChoice:
        def url(value: str | None) -> str:
            if not value or value == "auto":
                return DOH_RESOLVERS["cloudflare"]
            return DOH_RESOLVERS.get(value, value)

        own = sub.dns if sub and sub.dns and sub.dns != "auto" else None    # свой DNS подписки важнее общего
        return DnsChoice(remote=url(own or vc["dns_remote"]), direct=url(vc["dns_direct"]),
                         ru=DOH_RESOLVERS["yandex"], fakeip=bool(vc["fakeip"]), strategy=vc["ip_strategy"])

    def _fill_ports(self, plan: RunPlan, vc: dict, avoid: set[int]) -> None:
        taken = set(avoid)

        def auto() -> int:
            port = self.deps.free_port(None, avoid=frozenset(taken))
            taken.add(port)
            return port

        proxy = self.deps.free_port(int(vc["port"]), host="0.0.0.0" if vc["allow_lan"] else "127.0.0.1",
                                    avoid=frozenset(taken))
        taken.add(proxy)
        plan.ports = Ports(proxy=proxy, internal=auto(), clash=auto(),
                           helper={sid: auto() for sid, engine in plan.engines.items() if engine == "xray"})

    def _fill_routing(self, plan: RunPlan, vc: dict, out_dir: Path, quiet: bool) -> None:
        routing = self._routing()
        plan.preset = vc["preset"]
        plan.games_direct, plan.torrents_direct = bool(vc["games_direct"]), bool(vc["torrents_direct"])
        plan.ip_check_direct = bool(vc["ip_check_direct"])
        plan.direct_apps, plan.proxy_apps = list(vc["direct_apps"]), list(vc["proxy_apps"])
        plan.direct_sites, plan.proxy_sites = list(vc["direct_sites"]), list(vc["proxy_sites"])
        plan.torrent_apps = list(getattr(routing, "TORRENT_APPS", ()))
        plan.additions = list(getattr(routing, "ADDITIONS", ())) if plan.preset == "except_ru" else []
        profile = self._active_profile_rules()
        if profile is not None:
            plan.profile_rules = profile[0]
        wanted = self._wanted_rule_sets(vc, profile[1] if profile is not None else [])
        if wanted:
            self._attach_rules(plan, wanted, quiet)
        view = self._view(fresh=True)
        plan.via_zapret = bool(vc["via_zapret"]) and bool(view.strategy_args) and view.pack_dir is not None
        if plan.via_zapret:
            out_dir.mkdir(parents=True, exist_ok=True)
            result = routing.bypass_from_strategy(view.strategy_args, pack_dir=view.pack_dir,
                                                  ipset_mode=view.ipset_mode or "loaded", out_dir=out_dir)
            plan.bypass, plan.voice_ports = list(result.profiles), list(result.voice_ports)
            plan.bypass_state = "direct" if _bypass_ok(view) else "proxy"
            if not quiet:
                self._bypass_notes = list(result.notes)

    def _wanted_rule_sets(self, vc: dict, profile_sets: list[str]) -> list[str]:
        """Файлы правил, нужные маршрутам: пресет (и «Загрузки игр»), профиль маршрутизации и свои списки
        сайтов — geosite:youtube «только через VPN» без своего файла не действовал бы вовсе."""
        routing = self._routing()
        wanted = list(routing.preset_rule_sets(vc["preset"], games=bool(vc["games_direct"]))) + list(profile_sets)
        wanted += routing.site_rule_sets(list(vc["proxy_sites"]) + list(vc["direct_sites"]))
        return list(dict.fromkeys(wanted))

    def _attach_rules(self, plan: RunPlan, wanted: list[str], quiet: bool) -> None:
        """Локальные .srs маршрутов; чего нет — скачать фоном (пока не скачаны, эти правила пропущены, а
        без списков «через VPN» генератор не пускает напрямую ничего, кроме явных правил человека)."""
        try:
            rules = self._rules()
            plan.rules_files = dict(rules.paths(wanted))
            missing = list(rules.missing(wanted))
        except UserError as exc:
            log.warning("Файлы правил недоступны: %s", exc)
            return
        if missing and not quiet:
            routing = self._routing()
            strict = routing.strict_level(
                routing.vpn_required(plan.proxy_sites, plan.profile_rules, plan.preset), plan.rules_files)
            # Плашка до конца загрузки: удача её снимет, неудача заменит на «не скачались».
            self._set_alert(RULES_ALERT, "info", f"Списки для маршрутов ещё не скачаны — {RULES_WAIT[strict]}. "
                                                 "Лазейка скачивает их и применит сама.")
            threading.Thread(target=self._rules_worker, args=(rules, missing, True, strict),
                             name="vpnclient-rules", daemon=True).start()

    def _view(self, fresh: bool = False) -> ZapretView:
        if fresh or self._view_cache is None:
            try:
                self._view_cache = self.zapret_view() or ZapretView()
            except Exception:  # noqa: BLE001 — без сведений об обходе «через обход» просто не строится
                log.exception("Состояние обхода не получено")
                self._view_cache = ZapretView()
        return self._view_cache

    # ---------------------------------------------------------------- конфиги и процессы

    def _write_configs(self, plan: RunPlan, versions: dict[str, str], *, directory: Path | None = None,
                       only: str | None = None) -> dict[str, Path]:
        """Конфиги собираются заново → validate → `check` ядром (FATAL — ошибка, WARN — в журнал)."""
        config, engines = self._config(), self._engines()
        directory = directory or self.run_dir
        secure = _secure_dir()
        if secure is not None:
            secure(self.data_dir)
        directory.mkdir(parents=True, exist_ok=True)
        rendered = {"sing-box": config.build_singbox(plan),
                    "xray": config.build_xray(plan) if "xray" in plan.engines.values() else None}
        problems = list(config.validate(rendered["sing-box"]))
        if problems:
            raise VpnClientError("Генератор собрал неверную конфигурацию: " + "; ".join(problems[:3]), "core")
        out = {}
        for name, cfg in rendered.items():
            if cfg is not None:
                out[name] = directory / f"{name}.json"
                _write_json(out[name], cfg)
        for name, path in out.items():
            if only is None or name == only:
                for warning in engines.check(name, path, version=versions.get(name)):
                    log.warning("%s: предупреждение проверки (генератору нужна миграция): %s", name, warning)
        return out

    def _launch(self, plan: RunPlan, versions: dict[str, str], config_paths: dict[str, Path]) -> _Session:
        engines, config = self._engines(), self._config()
        sid = secrets.token_hex(4)
        helper = None
        if "xray" in config_paths:
            helper = self._start_helper(sid, plan, engines.verify("xray", versions["xray"]), config_paths["xray"])
        main = self.deps.process("sing-box", engines.verify("sing-box", versions["sing-box"]),
                                 ["run", "--disable-color", "-D", str(self.run_dir), "-c",
                                  str(config_paths["sing-box"])], cwd=self.run_dir,
                                 on_exit=lambda code, tail: self._on_exit(sid, "sing-box", code, tail))
        clash = self.deps.clash(plan.ports.clash, plan.secrets.clash)
        session_secrets = [plan.secrets.clash, plan.secrets.internal_pass, plan.secrets.helper_pass]
        applog.add_secrets(session_secrets)
        try:
            main.start(lambda: bool(clash.version()), READY_TIMEOUT)
        except BaseException:
            applog.remove_secrets(session_secrets)
            if helper is not None:
                helper.stop()
            raise
        groups = tuple(config.group_tag(g.id) for g in plan.groups)
        session = _Session(id=sid, plan=plan, main=main, helper=helper, clash=clash,
                           sampler=self.deps.sampler(clash, groups=groups),
                           tags={config.tag(s.id): s.id for s in plan.servers}, versions=dict(versions),
                           config_paths=config_paths, started=self.deps.clock(), active=plan.selected,
                           secrets=session_secrets)
        if plan.tun is not None:
            session.tun_net = str(ipaddress.ip_interface(plan.tun.address4).network)
        if plan.mode in ("proxy", "local"):
            session.proxy_address = f"{plan.proxy_listen}:{plan.ports.proxy}"
        return session

    def _start_helper(self, sid: str, plan: RunPlan, exe: Path, config_path: Path):
        helper = self.deps.process("xray", exe, ["run", "-c", str(config_path)], cwd=self.run_dir,
                                   on_exit=lambda code, tail: self._on_exit(sid, "xray", code, tail))
        ports = list(plan.ports.helper.values())
        helper.start(lambda: all(self.deps.port_open(p) for p in ports), READY_TIMEOUT)
        return helper

    def _after_launch(self, session: _Session) -> None:
        """Явные селекторы (выбор не берём из прошлого запуска), системный прокси, kill switch, сэмплер."""
        config = self._config()
        plan = session.plan
        session.clash.select(config.SELECTOR_PROXY, self._tag(plan.selected))
        if plan.via_zapret and plan.bypass:
            session.clash.select(config.SELECTOR_BYPASS, getattr(config, "DIRECT", DIRECT)
                                 if plan.bypass_state == "direct" else config.SELECTOR_PROXY)
        if plan.mode == "proxy":
            self._sysproxy().apply("127.0.0.1", plan.ports.proxy, plan.proxy_override)
        if plan.mode == "tun" and self._vc()["kill_switch"]:
            self._enable_killswitch(session)      # после перезапуска — те же фильтры с новым TUN, атомарно
        else:
            self._disable_killswitch()
        session.sampler.start()

    def _enable_killswitch(self, session: _Session) -> None:
        ks = self._killswitch()
        if ks is None or session.plan.tun is None:
            return
        apps = [str(session.main.exe)] + ([str(session.helper.exe)] if session.helper is not None else [])
        apps += [session.plan.lazeyka_exe, winutil.system32("curl.exe")]
        try:
            ks.enable(tun_luid=self.deps.adapter_luid(TUN_NAME), allow_apps=apps,
                      allow_nets=list(session.plan.tun.exclude))
        except UserError as exc:   # при каждом включении VPN — плашка, пока не включится
            self._set_alert(KILLSWITCH_ALERT, "warn", f"Kill switch не включился: {exc}")
            return
        # Неудачное включение оставляет прежние фильтры (замена атомарна) — и прежний список программ.
        self._ks_apps = {os.path.normcase(app) for app in apps}
        self._clear_alert(KILLSWITCH_ALERT)

    def _blocked_cores(self, versions: dict[str, str]) -> set[str]:
        """Ядра временного замера, которые включённый kill switch не выпустит в сеть: их exe нет среди
        разрешённых программ (там — ядра подключения, с которым он включался)."""
        if not getattr(self.deps.killswitch, "active", False):
            return set()
        engines = self._engines()
        return {name for name, version in versions.items()
                if os.path.normcase(str(engines.version_dir(name, version) / engines.spec(name).exe))
                not in self._ks_apps}

    def _disable_killswitch(self) -> None:
        ks = self.deps.killswitch
        if ks is not None and getattr(ks, "active", False):
            try:
                ks.disable()
            except UserError as exc:
                log.warning("Kill switch не снят: %s", exc)

    def _tag(self, item_id: str) -> str:
        """Тег в конфиге: сервер — config.tag(id), «Самый быстрый» — config.group_tag(id группы)."""
        config = self._config()
        if item_id.startswith("auto:"):
            return config.group_tag(item_id[len("auto:"):])
        return config.tag(item_id)

    # ---------------------------------------------------------------- проверка выхода

    def _verify_exit(self, session: _Session, announce: bool = False,
                     timeouts: tuple[float, ...] = EXIT_TIMEOUTS) -> bool:
        """«Подключено» — только после ответа через сервер: IP и страна выхода. На мёртвом сервере проверка
        с разбором причины идёт полминуты, а очередь одна: перед каждой попыткой и перед разбором смотрим,
        не ждёт ли человек (_yielding) — тогда уступаем, ничего не меняя в состоянии."""
        plan = session.plan
        last: Exception | None = None
        for timeout in timeouts:
            if self._session is not session or self._yielding(session):
                return False
            try:
                info = self.deps.exit_check(plan.ports.internal, plan.secrets.internal_user,
                                            plan.secrets.internal_pass, timeout)
            except (OSError, ValueError, urllib.error.URLError) as exc:
                last = exc
                continue
            if not self._verified and not announce:
                log.info("Свой VPN снова подключён: выход через сервер работает")
            self._set(verified=True, exit={"ip": info["ip"], "country": info.get("country"),
                                           "at": self.deps.clock()}, error=None, error_kind=None,
                      next_health=self.deps.clock() + HEALTH_EVERY)
            self._clear_alert(EXIT_ALERT)        # снова работает — плашка уходит сама, без уведомления
            return True
        if self._session is not session or self._yielding(session):
            return False
        kind, text = self._explain_no_exit(session)
        log.warning("Проверка выхода через сервер не прошла (%s): %s; %s", kind, text, last)
        self._set(verified=False, error=text, error_kind=kind, next_health=self.deps.clock() + UNVERIFIED_RETRY)
        # Проверка повторяется сама каждые UNVERIFIED_RETRY секунд — плашка вместо уведомлений.
        self._set_alert(EXIT_ALERT, "warn", f"Ядро включено, но через сервер ничего не открывается: {text}",
                        action={"label": "Переподключить", "call": "vpnclient_restart", "args": []})
        return False

    def _yielding(self, session: _Session) -> bool:
        """Долгой проверке пора уступить очередь: нажали «Выключить», Лазейка закрывается или ждёт выбор
        другого сервера (выход он проверит сам; выбор того же _switch пропускает — его не ждём)."""
        if self._abort.is_set() or self._closing:
            return True
        return self._ops.waiting("select") and self.store.selected() != session.active

    def _explain_no_exit(self, session: _Session) -> tuple[str, str]:
        server = self._active_server(session)
        reach, timed = None, False
        if server is not None:
            reach = self.deps.tcp_reach(session.plan.addresses.get(server.id) or server.host, server.port, 3.0)
            timed = server.proto in TIMED_PROTOCOLS or server.security == "reality"
        skew = diagnose.clock_skew(self.deps.direct_date()) if timed else None
        tail = list(session.main.tail) + (list(session.helper.tail) if session.helper is not None else [])
        kind, text = diagnose.explain_no_exit(tail, reach_ms=reach, skew=skew, timed_sensitive=timed)
        return kind, applog.scrub(text)

    def _active_server(self, session: _Session) -> Server | None:
        active = session.active
        if active.startswith("auto:"):
            current = session.sampler.snapshot()["now"].get(self._tag(active))
            active = session.tags.get(current or "", "")
        found = next((s for s in session.plan.servers if s.id == active), None)
        return found or (session.plan.servers[0] if session.plan.servers else None)

    # ================================================================ остановка и падение

    def _stop_session(self, remember: bool) -> dict:
        session = self._session
        self._retry_at, self._retry_attempt = None, 0     # выключили — неудавшийся перезапуск не повторяем
        if remember:
            self.settings.update(lambda d: d["vpnclient"].__setitem__("was_running", False))
        if session is None:
            self._disable_killswitch()            # после падения kill switch держал интернет закрытым
            self._restore_proxy()                 # прошлое восстановление могло вернуть не все подключения
            if self._status != "stopped":
                self._set(status="stopped", error=None, error_kind=None, verified=False, exit=None)
            return {}
        self._set(status="stopping")
        self._teardown(session)
        self._set(status="stopped", verified=False, exit=None, error=None, error_kind=None)
        log.info("Свой VPN выключен")
        return {}

    def _teardown(self, session: _Session, keep_killswitch: bool = False) -> None:
        """Системный прокси — первым, затем kill switch (кроме падения: он держит интернет закрытым до
        переподключения), ядра (мягко, ≤ 2 с каждое) и сэмплер."""
        self._count_traffic(session)
        if session.plan.mode == "proxy":
            self._restore_proxy()
        if not keep_killswitch:
            self._disable_killswitch()
        for proc in (session.main, session.helper):
            if proc is not None:
                proc.stop()
        session.sampler.stop()
        applog.remove_secrets(session.secrets)
        with self._lock:
            if self._session is session:
                self._session = None
            self._memory = {"sing-box": None, "xray": None}
        self._traffic.save()
        self._changed()

    def _restore_proxy(self) -> None:
        try:
            self._sysproxy().restore()
        except (UserError, OSError) as exc:
            log.warning("Системный прокси не возвращён: %s", exc)

    def _on_exit(self, session_id: str, name: str, code: int, tail: list[str]) -> None:
        """Сторож процесса: ядро завершилось само. Разбор — в очереди, не в потоке сторожа."""
        self._ops.submit(lambda: self._crashed(session_id, name, code, tail))

    def _crashed(self, session_id: str, name: str, code: int, tail: list[str]) -> None:
        session = self._session
        if session is None or session.id != session_id:
            return                              # уже остановлено или перезапущено
        kind, text = diagnose.classify(tail)
        text = applog.scrub(text)
        log.warning("%s упал (код %s, %s): %s", name, code, kind, text)
        now = self.deps.clock()
        self._restarts = [t for t in self._restarts if now - t < 3600]
        may_restart = (now - session.started > RESTART_MIN_UPTIME and len(self._restarts) < RESTARTS_PER_HOUR
                       and not self._closing)
        if name == "xray" and session.main.alive() and may_restart:
            self._restarts.append(now)
            self._restart_helper(session)
            return
        self._teardown(session, keep_killswitch=True)   # прокси на мёртвый порт возвращается здесь же
        if may_restart:
            self._restarts.append(now)
            # Плашка, пока перезапуск идёт: снимется сама на «работает» (_alerts_for_status).
            self._set_alert(CRASH_ALERT, "warn", f"Ядро VPN остановилось ({text}) — перезапускаю.", page=None)
            self._abort.clear()
            try:
                self._start(reason="crash")
                return
            except UserError as exc:
                kind, text = getattr(exc, "kind", kind), str(exc)
        self._set(status="error", error=text, error_kind=kind, verified=False, exit=None)
        self._down_alert(f"Свой VPN остановился: {text}")

    def _restart_helper(self, session: _Session) -> None:
        """Перезапуск одного помощника Xray: TUN и sing-box остаются (смена сети, падение помощника)."""
        if session.helper is None:
            return
        session.helper.stop()
        session.plan.physical_interface = self.deps.physical_interface()
        path = session.config_paths["xray"]
        _write_json(path, self._config().build_xray(session.plan))
        try:
            session.helper = self._start_helper(session.id, session.plan,
                                                self._engines().verify("xray", session.versions["xray"]), path)
        except (ProcessError, UserError) as exc:
            kind, text = self._failure(exc)
            self._set(error=f"Помощник Xray не перезапустился: {text}", error_kind=kind)
            return
        self._changed()

    def _restart_job(self, user: bool = False) -> dict:
        """Перезапуск с новым конфигом. Kill switch не снимаем, как после падения: между старым и новым
        туннелем трафик не должен уйти напрямую, а новый запуск заменит его фильтры атомарно.

        user — «Переподключить»: ошибку человек получит ответом. Остальные перезапуски автоматические
        (правила, маршруты провайдера, сеть, настройки, сервер вне конфига, новое ядро): их неудачу некому
        показать, а выключал VPN не человек — плашка как у падения и повтор с паузами (_restart_failed).
        План и конфиги собираются уже после разборки: прежнее ядро держит порты и подсеть TUN, и новый план
        рядом с ним взял бы другие (системный прокси — на другом порту)."""
        session = self._session
        if session is not None:
            self._set(status="stopping")
            self._teardown(session, keep_killswitch=True)
        try:
            return self._start(reason="restart")
        except Exception:
            self._restart_failed(auto=not user)
            raise

    def _restart_failed(self, auto: bool) -> None:
        """Перезапуск не удался, а kill switch по-прежнему держит интернет закрытым — так и сказать.
        Автоматический — ещё плашка и новый запуск через 30 с, 2 и 5 минут, дальше раз в 5 минут, пока он
        не удастся или человек не нажмёт «Выключить» (_stop_session снимает повтор)."""
        text = self._error or "ядро не запустилось"
        if getattr(self.deps.killswitch, "active", False):
            self._set(error=f"{text} Kill switch держит интернет закрытым — выключите VPN, чтобы открыть.")
        if not auto or self._closing or self._abort.is_set():
            return
        pause = RESTART_RETRY[min(self._retry_attempt, len(RESTART_RETRY) - 1)]
        self._retry_attempt += 1
        self._retry_at = self.deps.clock() + pause
        when = f"{int(pause)} с" if pause < 60 else f"{int(pause // 60)} мин"
        self._down_alert(f"Свой VPN не перезапустился: {text.rstrip('.')}. Повторю через {when}.")

    def _retry_start(self) -> None:
        """Тикер: пора повторить неудавшийся автоматический перезапуск (если VPN с тех пор не выключили и не
        включили)."""
        if self._retry_at is None or self._session is not None or self._closing or self._abort.is_set():
            return
        self._retry_at = None
        log.info("Повторяю запуск своего VPN после неудачного перезапуска (попытка %d)", self._retry_attempt + 1)
        self._restart_job()

    def _down_alert(self, text: str) -> None:
        """Свой VPN остановился сам (упал, не перезапустился) — плашка до «работает» или «выключено». Ошибку
        страница VPN показывает сама — плашка там нужна, только если kill switch держит интернет закрытым:
        тогда главное действие — выключить VPN."""
        closed = getattr(self.deps.killswitch, "active", False)
        self._set_alert(CRASH_ALERT, "error", text + (
            " Kill switch держит интернет закрытым — выключите VPN, чтобы открыть." if closed else ""),
            action=({"label": "Выключить VPN", "call": "vpnclient_stop", "args": []} if closed else
                    {"label": "Включить снова", "call": "vpnclient_start", "args": []}),
            page="vpnclient" if closed else None)

    # ================================================================ сон, сеть, здоровье, обход

    def _after_sleep(self) -> None:
        session = self._session
        if session is None:
            return
        try:
            session.clash.close_connections()
        except ClashError as exc:
            log.info("Соединения после сна не закрыты: %s", exc)
        self._verify_exit(session)

    def _after_network_change(self) -> None:
        session = self._session
        if session is None:
            return
        if any(":" in ip for ip in session.plan.addresses.values()) and not self.deps.ipv6_internet():
            # В новой сети IPv6 нет, а в конфиге закреплён IPv6-адрес сервера — перезапуск спросит A заново.
            log.info("В сети больше нет IPv6, а адрес сервера в конфиге — IPv6: перезапускаю VPN")
            self._restart_job()
            return
        if session.helper is not None:
            self._restart_helper(session)
        self._verify_exit(session)

    def _health(self) -> None:
        """Раз в минуту — задержка активного сервера; два провала подряд — переход на самый быстрый.
        Пока проверка поставлена или идёт, тикер новую не ставит (_health_busy)."""
        try:
            self._check_health()
        finally:
            self._health_busy = False

    def _check_health(self) -> None:
        session = self._session
        if session is None or self._status != "running":
            return
        if not self._verified:
            self._verify_exit(session, timeouts=RECHECK_TIMEOUTS)
            return
        if session.active.startswith("auto:"):
            return                              # urltest сам выбирает живой сервер
        try:
            session.clash.delay(self._tag(session.active), session.plan.probe_url, DELAY_TIMEOUT_MS)
            self._health_fails = 0
            self._clear_alert(SERVER_ALERT)      # сервер снова отвечает
            return
        except ClashError as exc:
            self._health_fails += 1
            log.info("Сервер не ответил на проверку здоровья (%d): %s", self._health_fails, exc)
        if self._health_fails >= HEALTH_FAILS:
            self._health_fails = 0
            self._switch_to_fastest(session)

    def _switch_to_fastest(self, session: _Session) -> None:
        config = self._config()
        try:
            delays = session.clash.group_delay(config.SELECTOR_PROXY, session.plan.probe_url, DELAY_TIMEOUT_MS,
                                               members=len(session.plan.servers))
        except ClashError as exc:
            log.info("Быстрый сервер не найден: %s", exc)
            delays = {}
        current = self._tag(session.active)
        alive = sorted((ms, tag) for tag, ms in delays.items() if tag in session.tags and tag != current)
        dead = next((s.display_name() for s in session.plan.servers if s.id == session.active), "сервер")
        if not alive:   # проверка здоровья повторяется раз в минуту — плашка вместо уведомлений
            self._set_alert(SERVER_ALERT, "warn", f"Сервер «{dead}» не отвечает, а другого живого сервера в "
                                                  "подписке нет.")
            return
        tag = alive[0][1]
        target = session.tags[tag]
        name = next((s.display_name() for s in session.plan.servers if s.id == target), target)
        try:
            session.clash.select(config.SELECTOR_PROXY, tag)
        except ClashError as exc:
            log.warning("Переключение на «%s» не удалось: %s", name, exc)
            return
        session.active = target
        try:
            self.store.select(target)
        except UserError as exc:
            log.debug("Выбор не сохранён: %s", exc)
        self._clear_alert(SERVER_ALERT)
        # Не поломка, а отчёт о том, что Лазейка сама сменила выбор человека: уведомление, но «info» —
        # без уведомления Windows.
        self.notify("info", f"Сервер «{dead}» перестал отвечать — переключила на самый быстрый: «{name}».")
        self._changed()

    def _bypass_wanted(self) -> str | None:
        session = self._session
        if session is None or not (session.plan.via_zapret and session.plan.bypass):
            return None
        view = self._view()
        if view.paused_for_test:
            return self._bypass_applied          # подбор стратегии: winws перезапускается на каждую пробу
        return "direct" if _bypass_ok(view) else "proxy"

    def _apply_bypass(self) -> None:
        session = self._session
        wanted = self._bypass_wanted()
        now = self.deps.clock()
        if session is None or wanted is None or wanted == self._bypass_applied:
            return
        if now - self._bypass_at < BYPASS_HYSTERESIS:
            return                              # тикер напомнит, когда гистерезис пройдёт
        config = self._config()
        try:
            session.clash.select(config.SELECTOR_BYPASS, getattr(config, "DIRECT", DIRECT) if wanted == "direct"
                                 else config.SELECTOR_PROXY)
        except ClashError as exc:
            log.warning("Селектор «через обход» не переключён: %s", exc)
            return
        with self._lock:
            self._bypass_applied, self._bypass_at = wanted, now
        log.info("Discord и YouTube теперь идут %s", "через обход" if wanted == "direct" else "через VPN")
        self._changed()

    def _bypass_view(self, vc: dict) -> tuple[str, str | None]:
        if not vc["via_zapret"]:
            return "proxy", None
        view = self._view()
        if not view.strategy_args or view.pack_dir is None:
            return "proxy", "Обход недоступен — Discord и YouTube идут через VPN."
        state = self._bypass_applied if self._session is not None and self._bypass_applied else (
            "direct" if _bypass_ok(view) else "proxy")
        if view.paused_for_test:
            return state, "Идёт подбор стратегии обхода — маршрут Discord и YouTube пока не меняется."
        if state == "direct":
            return state, "Discord и YouTube идут через обход: он работает и последняя проверка прошла."
        if not view.running:
            return state, "Обход выключен — Discord и YouTube идут через VPN."
        if view.last_ok is False:
            return state, "Последняя проверка обхода не прошла — Discord и YouTube идут через VPN."
        return state, "Discord и YouTube идут через VPN."

    # ================================================================ выбор сервера

    def select(self, item_id: str) -> dict:
        """Сервер или auto:<группа|подписка>. Есть в работающем конфиге — PUT /proxies/proxy без
        перезапуска; нет — перезапуск с новым конфигом."""
        store = self.store
        if item_id.startswith("auto:"):
            if self._group(item_id[5:], store.groups(), store.subscriptions(), store.servers()) is None:
                raise VpnClientError("Такой группы нет")
        else:
            server = store.server(item_id)
            if server is None:
                raise VpnClientError("Такого сервера нет")
            engine, why = engine_for(server, force_xray=bool(self._vc().get("noises")))
            if engine is None:
                raise VpnClientError(f"Сервер не поддерживается: {why}", "unsupported")
        store.select(item_id)
        self._changed()
        if self._session is not None:
            self._ops.submit(self._switch, key="select")   # задача возьмёт выбор, последний к её началу
        return {}

    def _switch(self) -> None:
        session = self._session
        item_id = self.store.selected()
        if session is None or not item_id or item_id == session.active:
            return
        in_config = item_id in {s.id for s in session.plan.servers} or any(
            f"auto:{g.id}" == item_id for g in session.plan.groups)
        if not in_config:
            self._restart_job()
            return
        try:
            session.clash.select(self._config().SELECTOR_PROXY, self._tag(item_id))
        except ClashError as exc:
            log.warning("Переключение без перезапуска не удалось (%s) — перезапускаю", exc)
            self._restart_job()
            return
        session.active = item_id
        self._health_fails = 0
        self._changed()
        self._verify_exit(session)

    # ================================================================ задержка и скорость

    def latency(self, ids: list[str] | None = None) -> dict:
        noises = bool(self._vc().get("noises"))
        wanted = set(ids or [])
        servers = [s for s in self.store.servers() if (not wanted or s.id in wanted)
                   and engine_for(s, force_xray=noises)[0]]
        if not servers:
            raise VpnClientError("Нет серверов, у которых можно проверить задержку")
        with self._lock:
            if self._latency["running"]:
                raise VpnClientError("Задержка уже проверяется")
            self._latency = {"running": True, "done": 0, "total": len(servers)}
        threading.Thread(target=self._measure, args=(servers,), name="vpnclient-latency", daemon=True).start()
        self._changed()
        return {}

    def _measure(self, servers: list[Server]) -> None:
        try:
            session = self._session
            in_config = {s.id for s in session.plan.servers} if session is not None else set()
            live = [s for s in servers if s.id in in_config]
            rest = [s for s in servers if s.id not in in_config]
            if live:
                self._delays_via(session.clash, live, members=len(session.plan.servers) + len(session.plan.groups))
            if rest:
                self._delays_temporary(rest)
        except Exception as exc:  # noqa: BLE001 — итог показываем у серверов и уведомлением
            log.warning("Проверка задержки не удалась: %s", exc)
            self.notify("warn", f"Задержку проверить не удалось: {applog.scrub(str(exc))}")
        finally:
            try:
                self.store.save()
            except (UserError, OSError) as exc:
                log.warning("Задержки не сохранены: %s", exc)
            with self._lock:
                self._latency = dict(self._latency, running=False)
            self._changed()

    def _delays_via(self, clash, servers: list[Server], members: int) -> None:
        """Задержки: одним GET /group/proxy/delay (все члены селектора параллельно), не вышло — по одному.
        members — сколько всего членов у селектора proxy (от этого зависит, сколько ждать ответа)."""
        config = self._config()
        if len(servers) > 1:
            try:
                found = clash.group_delay(config.SELECTOR_PROXY, PROBE_URL, DELAY_TIMEOUT_MS, members=members)
            except ClashError as exc:
                log.info("Задержка группой не получилась (%s) — меряю по одному", exc)
            else:
                for server in servers:
                    ms = found.get(config.tag(server.id))
                    self._latency_done(server.id, ms, None if ms else f"нет ответа за {DELAY_TIMEOUT_MS // 1000} с")
                return

        def one(server: Server) -> None:
            try:
                ms, error = clash.delay(config.tag(server.id), PROBE_URL, DELAY_TIMEOUT_MS), None
            except ClashError as exc:
                ms, error = None, str(exc)
            self._latency_done(server.id, ms, error)

        with concurrent.futures.ThreadPoolExecutor(DELAY_WORKERS) as pool:
            list(pool.map(one, servers))

    def _latency_done(self, server_id: str, ms: int | None, error: str | None) -> None:
        try:
            self.store.set_latency(server_id, ms, error, save=False)   # файл — один раз в конце проверки
        except UserError as exc:
            log.debug("Задержка не сохранена: %s", exc)
        with self._lock:
            self._latency["done"] = self._latency.get("done", 0) + 1

    def _delays_temporary(self, servers: list[Server]) -> None:
        """Сервера нет в работающем конфиге (или ядро выключено): временный экземпляр — только выходы и API
        (+ помощник для своих серверов). В систему он ничего не добавляет: ни TUN, ни прокси."""
        vc = self._vc()
        noises = bool(vc.get("noises"))
        engines_by_id = {s.id: engine_for(s, force_xray=noises)[0] for s in servers}
        versions = self._ensure_cores(engines_by_id)
        session = self._session
        if session is not None and getattr(self.deps.killswitch, "active", False):
            # Kill switch выпускает в сеть только exe ядер подключения — замер на их версиях (новая версия
            # после автообновления начнёт работать со следующего подключения).
            versions.update({n: v for n, v in _running_versions(session).items() if n in versions})
        blocked = self._blocked_cores(versions)
        if blocked:
            # Такому ядру kill switch не даст соединиться: «нет ответа» у сервера было бы неправдой.
            skipped = {s.id for s in servers if "sing-box" in blocked or engines_by_id[s.id] in blocked}
            for server_id in skipped:
                self._latency_done(server_id, None, KILLSWITCH_DELAY)
            servers = [s for s in servers if s.id not in skipped]
        config = self._config()
        probe_dir = self.run_dir / "delay"
        for chunk in _chunks(servers, MAX_CONFIG_SERVERS):
            pick = {"selected": chunk[0].id, "servers": chunk, "groups": [], "first": chunk[0], "sub": None,
                    "engines": {s.id: engines_by_id[s.id] for s in chunk}}
            plan = self._build_plan(vc, pick, versions, set(), mode="local", routing_dir=probe_dir, quiet=True)
            for server in chunk:
                if server.id not in plan.engines:     # адрес не получен — мерить нечего
                    self._latency_done(server.id, None, "адрес сервера не получен через DNS")
            plan = self._buildable(plan)
            if not plan.servers:
                continue
            probe_dir.mkdir(parents=True, exist_ok=True)
            main_cfg, helper_cfg = probe_dir / "sing-box.json", probe_dir / "xray.json"
            _write_json(main_cfg, config.build_delay(plan))
            temp_secrets = [plan.secrets.clash, plan.secrets.helper_pass]
            applog.add_secrets(temp_secrets)
            helper = main = None
            try:
                if "xray" in plan.engines.values():
                    _write_json(helper_cfg, config.build_xray(plan))
                    helper = self.deps.process("xray", self._engines().verify("xray", versions["xray"]),
                                               ["run", "-c", str(helper_cfg)], cwd=probe_dir)
                    ports = list(plan.ports.helper.values())
                    helper.start(lambda: all(self.deps.port_open(p) for p in ports), READY_TIMEOUT)
                main = self.deps.process("sing-box", self._engines().verify("sing-box", versions["sing-box"]),
                                         ["run", "--disable-color", "-D", str(probe_dir), "-c", str(main_cfg)],
                                         cwd=probe_dir)
                clash = self.deps.clash(plan.ports.clash, plan.secrets.clash)
                main.start(lambda: bool(clash.version()), READY_TIMEOUT)
                self._delays_via(clash, list(plan.servers), members=len(plan.servers))
            finally:
                for proc in (main, helper):
                    if proc is not None:
                        proc.stop()
                applog.remove_secrets(temp_secrets)
                for path in probe_dir.glob("*.json"):
                    path.unlink(missing_ok=True)

    def _buildable(self, plan: RunPlan) -> RunPlan:
        """План временного экземпляра без серверов, из которых конфиг не собрать (у них — ошибка задержки)."""
        config = self._config()
        try:
            config.build_delay(plan)
            if "xray" in plan.engines.values():
                config.build_xray(plan)
            return plan
        except UserError:
            pass
        good = []
        for server in plan.servers:
            single = replace(plan, servers=[server], selected=server.id,
                             engines={server.id: plan.engines[server.id]})
            try:
                config.build_delay(single)
                if single.engines[server.id] == "xray":
                    config.build_xray(single)
                good.append(server)
            except UserError as exc:
                self._latency_done(server.id, None, applog.scrub(str(exc)))
        ids = {s.id for s in good}
        return replace(plan, servers=good, engines={k: v for k, v in plan.engines.items() if k in ids},
                       selected=good[0].id if good else plan.selected)

    def speedtest(self, server_id: str | None = None) -> dict:
        session = self._session
        if session is None or self._status != "running":
            raise VpnClientError("Включите VPN: скорость меряется через подключение")
        target = server_id
        if target is None:
            server = self._active_server(session)
            target = server.id if server else None
        if target is None or target not in {s.id for s in session.plan.servers}:
            raise VpnClientError("Сервер не входит в текущее подключение — выберите его и повторите")
        with self._lock:
            if self._speed["running"]:
                raise VpnClientError("Скорость уже меряется")
            self._speed = {"running": True, "server": target, "mbps": None, "at": None}
        threading.Thread(target=self._measure_speed, args=(session, target), name="vpnclient-speed",
                         daemon=True).start()
        self._changed()
        return {}

    def _measure_speed(self, session: _Session, target: str) -> None:
        """Через служебный вход; чужой сервер подключения — на время теста в селектор и обратно."""
        config = self._config()
        current = self._active_server(session)
        switched = current is None or current.id != target
        mbps = None
        try:
            if switched:
                session.clash.select(config.SELECTOR_PROXY, config.tag(target))
            plan = session.plan
            mbps = self.deps.speed_check(plan.ports.internal, plan.secrets.internal_user,
                                         plan.secrets.internal_pass, SPEED_SECONDS)
            self.store.set_speed(target, mbps)
        except (ClashError, OSError, ValueError, urllib.error.URLError, UserError) as exc:
            self.notify("warn", f"Скорость не измерена: {applog.scrub(str(exc))}")
        finally:
            if switched:
                try:
                    session.clash.select(config.SELECTOR_PROXY, self._tag(session.active))
                except ClashError as exc:
                    log.warning("Прежний сервер после теста скорости не вернулся: %s", exc)
            with self._lock:
                self._speed = {"running": False, "server": target, "mbps": mbps,
                               "at": self.deps.clock() if mbps is not None else None}
            self._changed()

    # ================================================================ подписки и импорт

    def import_text(self, text: str | None, ua_preset: str | None = None, hwid: bool = False) -> dict:
        """Ссылки, подписка, base64, обёртки — фоном, ход в snapshot()["import"]. text None — повторить
        прошлое добавление с другим User-Agent или с HWID (так предлагает страница после отказа)."""
        text = (text or "").strip()
        if ua_preset is not None and ua_preset not in UA_PRESETS:
            raise VpnClientError("Неизвестный User-Agent")
        with self._lock:
            if not text and self._last_import is not None:
                text, ua_preset = self._last_import[0], ua_preset or self._last_import[1]
            if not text:
                raise VpnClientError("Вставьте ссылку, подписку или текст со ссылками")
            if self._import["running"]:
                raise VpnClientError("Предыдущее добавление ещё идёт")
            self._import = {"running": True, "message": None, "error": None, "offer": None}
            self._last_import = (text, ua_preset)
        threading.Thread(target=self._import_worker, args=(text, ua_preset, bool(hwid)), name="vpnclient-import",
                         daemon=True).start()
        self._changed()
        return {}

    def _import_worker(self, text: str, ua_preset: str | None, hwid: bool = False) -> None:
        result: dict = {"running": False, "message": None, "error": None, "offer": None}
        try:
            target = self._mod("links").unwrap(text).strip()      # deeplink-обёртка — один уровень
            if "\n" not in target and re.match(r"^https?://\S+$", target, re.I):
                result.update(self._import_subscription(target, ua_preset, hwid))
            else:
                result.update(self._import_body(target))
        except UserError as exc:
            result["error"] = applog.scrub(str(exc))
        except Exception as exc:  # noqa: BLE001
            log.exception("Импорт не удался")
            result["error"] = f"Не удалось добавить: {applog.scrub(repr(exc))}"
        with self._lock:
            self._import = result
        self._changed()

    def _import_body(self, text: str) -> dict:
        """Текст из поля импорта — тем же разбором, что тело подписки: ссылки по строкам, base64, JSON
        Xray и SIP008, .conf WireGuard. Серверы-заглушки провайдера — только сообщением."""
        decoded = self._mod("subscription").decode(text.encode("utf-8"), {})
        notices = "; ".join(getattr(decoded, "notices", None) or [])
        if not decoded.servers:
            if notices:
                raise VpnClientError(f"Провайдер сообщает: {notices}")
            first = decoded.errors[0][1] if decoded.errors else None
            raise VpnClientError(str(first) if first else "Ссылок на серверы не найдено")
        applog.add_secrets([v for s in decoded.servers for v in _server_secrets(s)])
        added = _report_count(self.store.add_servers(decoded.servers), "added", len(decoded.servers))
        parts = [f"Добавлено серверов: {added}"]
        if decoded.errors:
            parts.append(f"не разобрано строк: {len(decoded.errors)}")
        if decoded.groups:
            parts.append("группы «Самый быстрый» бывают только у подписки — добавьте её адрес")
        if notices:
            parts.append(f"провайдер сообщает: {notices}")
        return {"message": "; ".join(parts)}

    def _import_subscription(self, url: str, ua_preset: str | None, hwid: bool = False) -> dict:
        applog.add_secrets([url])
        subscription = self._mod("subscription")
        existing = next((s for s in self.store.subscriptions() if s.url == url), None)
        if existing is not None:
            changes: dict[str, Any] = {}
            if ua_preset and ua_preset != existing.ua_preset:
                changes["ua_preset"] = ua_preset
            if hwid and not existing.hwid:
                changes["hwid"] = subscription.new_hwid()
                applog.add_secrets([changes["hwid"]])
            if changes:
                self.store.update_subscription(existing.id, **changes)
            return self._update_sub(existing.id, announce=False)
        device = subscription.new_hwid() if hwid else None
        applog.add_secrets([device])
        sub = Subscription(id=f"s-{secrets.token_hex(3)}", name=_host_name(url), url=url,
                           ua_preset=ua_preset or "lazeyka", hwid=device, added_at=self.deps.clock(),
                           update_hours=int(self._vc()["sub_update_hours"]))
        self.store.add_subscription(sub)
        outcome = self._update_sub(sub.id, announce=False)
        if outcome.get("error"):
            outcome["message"] = "Подписка добавлена, но серверы пока не получены"
        return outcome

    def sub_update(self, sub_id: str | None = None) -> dict:
        targets = [s for s in self.store.subscriptions() if sub_id is None or s.id == sub_id]
        if sub_id is not None and not targets:
            raise VpnClientError("Такой подписки нет")
        for sub in targets:
            self._spawn_update(sub.id, announce=True)
        return {}

    def _spawn_update(self, sub_id: str, announce: bool) -> None:
        with self._lock:
            if sub_id in self._updating:
                return
            self._updating.add(sub_id)
        threading.Thread(target=self._update_sub, args=(sub_id, announce), name="vpnclient-sub",
                         daemon=True).start()
        self._changed()

    def _update_sub(self, sub_id: str, announce: bool | str) -> dict:
        """Загрузить и разобрать подписку: напрямую, при сбое сети — через свой VPN. Ошибка список не стирает.

        announce: True — по кнопке (итог уведомлением), "auto" — по расписанию (поломка плашкой
        «vpn-sub:<id>», удачное обновление её снимает), False — молча (импорт, свойства подписки)."""
        auto, announce = announce == "auto", announce is True
        subscription = self._mod("subscription")
        with self._lock:
            self._updating.add(sub_id)
        self._changed()
        outcome: dict = {"message": None, "error": None, "offer": None}
        try:
            sub = self.store.subscription(sub_id)
            if sub is None:
                return {"error": "Подписка удалена"}
            fetched, decoded, error = self._download(sub)
            offer = subscription.offer(fetched, decoded, error)
            outcome["offer"] = dict(offer, sub=sub.id) if offer else None
            if error is not None or decoded is None:
                text = applog.scrub(str(error) if error else "подписка не разобрана")
                self.store.update_subscription(sub.id, error=text)
                with self._lock:
                    self._sub_retry[sub.id] = self.deps.clock() + SUB_RETRY
                outcome["error"] = text
                if auto:
                    self._set_alert(f"vpn-sub:{sub.id}", "warn", f"Подписка «{sub.name}» не обновилась: {text}",
                                    action={"label": "Обновить", "call": "vpnclient_sub_update", "args": [sub.id]})
                elif announce:
                    self.notify("warn", f"Подписка «{sub.name}» не обновилась: {text}")
                return outcome
            applog.add_secrets([v for s in decoded.servers for v in _server_secrets(s)]
                               + [decoded.meta.new_url, *decoded.meta.fallback_urls])
            selected = self.store.selected()
            self._gone = {selected: self._label(selected)} if selected else {}
            report = self.store.apply_decoded(sub.id, decoded)
            if self._store_provider_profile(sub, decoded) and self._uses_sub(sub.id):
                self._ops.submit(self._restart_job, key="restart")   # включённые маршруты провайдера сменились
            self._selection_after_merge(sub, report)
            added, removed = _report_count(report, "added", 0), _report_count(report, "removed", 0)
            name = (self.store.subscription(sub.id) or sub).name
            notes = [f"Подписка «{name}»: серверов {len(decoded.servers)}"]
            notices = "; ".join(getattr(decoded, "notices", None) or [])
            if notices:                         # имена-заглушки («Подписка истекла» и т. п.) — подключаться некуда
                notes.append(f"провайдер сообщает: {notices}")
                if announce:
                    self.notify("info", f"Подписка «{name}»: провайдер сообщает: {notices}")
            warning = getattr(fetched, "warning", None)
            if warning:
                notes.append(warning)
                if announce:
                    self.notify("warn", f"Подписка «{name}»: {warning}")
            outcome["message"] = "; ".join(notes)
            problems = notes[1:]                # «провайдер сообщает…», «загружено по http://»
            if auto and problems:
                self._set_alert(f"vpn-sub:{sub.id}", "warn", f"Подписка «{name}»: " + "; ".join(problems))
            else:
                self._clear_alert(f"vpn-sub:{sub.id}")   # обновилась (по кнопке проблемы ушли уведомлением)
            if (announce or auto) and (added or removed):
                self.notify("success", f"Подписка обновлена: +{added} / −{removed}")
            if self._vc()["latency_on_update"] and decoded.servers:
                try:
                    self.latency([s.id for s in self.store.servers() if s.sub == sub.id])
                except UserError as exc:
                    log.debug("Задержка после обновления не проверена: %s", exc)
            return outcome
        except UserError as exc:
            outcome["error"] = applog.scrub(str(exc))
            return outcome
        except Exception as exc:  # noqa: BLE001 — фоновое обновление: ошибку видно в карточке подписки
            log.exception("Подписка не обновилась")
            outcome["error"] = applog.scrub(f"Подписка не обновилась: {exc!r}")
            return outcome
        finally:
            with self._lock:
                self._updating.discard(sub_id)
            self._changed()

    def _selection_after_merge(self, sub: Subscription, report: Any) -> None:
        """Выбранный сервер исчез из подписки (5.8): выключены — выбрать предложенный хранилищем; включены —
        конфиг пока работает, предложить переключиться (а упадёт соединение — переключит здоровье)."""
        change = getattr(report, "selection", None)
        if not change or change[1] is not None:
            return
        suggested = getattr(report, "suggested", None)
        label = self._label(suggested) if suggested else None
        gone = self._gone.get(change[0], "Выбранный сервер")
        if self._session is None:
            if suggested:
                self.store.select(suggested)
                self.notify("info", f"«{gone}» пропал из подписки «{sub.name}», выбран «{label}».")
            return
        if suggested:
            self.notify("warn", f"«{gone}» пропал из подписки «{sub.name}». Подключение пока работает — "
                                f"переключиться на «{label}»?",
                        action={"label": "Переключиться", "call": "vpnclient_select", "args": [suggested]})

    def _label(self, item_id: str) -> str:
        if item_id.startswith("auto:"):
            store = self.store
            group = self._group(item_id[len("auto:"):], store.groups(), store.subscriptions(), store.servers())
            return group.name if group else item_id
        server = self.store.server(item_id)
        return server.display_name() if server else item_id

    def _download(self, sub: Subscription, ua_preset: str | None = None) -> tuple[Any, Any, Any]:
        """(fetched, decoded, error): напрямую, при сбое сети — через свой VPN. ua_preset — проба с чужим
        UA без изменения сохранённой подписки."""
        subscription = self._mod("subscription")
        trial = replace(sub, ua_preset=ua_preset) if ua_preset else sub
        fetched = decoded = error = None
        routes = ["direct"] + (["vpn"] if self._session is not None and self._status == "running" else [])
        for route in routes:
            try:
                fetched = subscription.fetch(sub.url, user_agent=subscription.user_agent(trial, __version__),
                                             hwid=sub.hwid, opener=self.opener_for(route))
                decoded = subscription.decode(fetched.body, fetched.headers, sub_id=sub.id)
                return fetched, decoded, None
            except subscription.SubscriptionError as exc:
                error = exc
                if exc.kind not in ("network", "timeout", "tls"):
                    break                       # провайдер ответил — другим маршрутом не лучше
        return fetched, decoded, error

    def sub_probe(self, sub_id: str) -> dict:
        """«Проверить расширенный формат»: подписка с UA «как v2rayN» (затем «как Happ», «как Incy»), ничего не
        сохраняя. Пришли группы «Самый быстрый» или серверов больше — предложение сменить UA подписки
        (в import.offer и в probe у подписки); иначе — сообщение, что формат тот же."""
        sub = self.store.subscription(sub_id)
        if sub is None:
            raise VpnClientError("Такой подписки нет")
        with self._lock:
            if (self._probes.get(sub_id) or {}).get("running"):
                raise VpnClientError("Проверка формата уже идёт")
            self._probes[sub_id] = {"running": True, "ua_preset": None, "text": None}
        self._changed()
        have = sum(1 for s in self.store.servers() if s.sub == sub_id)
        found, failure = None, None
        try:
            for preset in PROBE_PRESETS:
                if preset == sub.ua_preset:
                    continue
                _fetched, decoded, error = self._download(sub, preset)
                if error is not None or decoded is None:
                    failure = failure or error
                    continue
                if (decoded.format == "xray-json" and decoded.groups) or len(decoded.servers) > have:
                    found = (preset, decoded)
                    break
        except Exception as exc:  # noqa: BLE001 — итог проверки показываем у подписки
            with self._lock:
                self._probes[sub_id] = {"running": False, "ua_preset": None,
                                        "text": applog.scrub(f"Проверить не удалось: {exc}")}
            self._changed()
            raise
        if found is None:
            text = ("Расширенного формата нет — провайдер отдаёт ссылки" if failure is None or have
                    else applog.scrub(f"Проверить не удалось: {failure}"))
            with self._lock:
                self._probes[sub_id] = {"running": False, "ua_preset": None, "text": text}
            self._changed()
            return {"ok": True, "message": text}
        preset, decoded = found
        what = ("JSON с группами" if decoded.format == "xray-json" and decoded.groups
                else f"серверов больше: {len(decoded.servers)}")
        text = (f"Провайдер отдаёт расширенный формат ({what}) приложению «{UA_LABELS[preset]}». "
                "Переключить подписку?")
        # «switch» — формат уже найден (кнопка «Переключить на …»); «extended» — только совет проверить
        offer = {"kind": "switch", "text": text, "options": [preset], "sub": sub_id}
        with self._lock:
            self._probes[sub_id] = {"running": False, "ua_preset": preset, "text": text}
            self._import = dict(self._import, running=False, offer=offer)
        self._changed()
        return dict(offer)

    def _auto_update_subs(self, now: float) -> None:
        try:
            subs = self.store.subscriptions()
        except UserError:
            return
        default_hours = int(self._vc()["sub_update_hours"])
        for sub in subs:
            last = sub.updated_at or sub.added_at or 0
            if sub.url and now - last >= (sub.update_hours or default_hours) * 3600 \
                    and now >= self._sub_retry.get(sub.id, 0):
                self._spawn_update(sub.id, announce="auto")   # по расписанию: поломка — плашкой

    def sub_remove(self, sub_id: str) -> dict:
        if self.store.subscription(sub_id) is None:
            raise VpnClientError("Такой подписки нет")
        session = self._session
        in_use = session is not None and any(s.sub == sub_id for s in session.plan.servers)
        self.store.remove_subscription(sub_id)
        self._profiles.save([p for p in self._profiles.load() if p.get("id") != f"r-{sub_id}"])
        self._disk_cache.pop("profiles", None)
        self._clear_alert(f"vpn-sub:{sub_id}")   # подписки нет — и её плашки тоже
        if in_use:
            self._ops.submit(lambda: self._stop_session(remember=False))
            self.notify("info", "Подписка удалена — свой VPN выключен: его серверы были из неё.")
        self._changed()
        return {}

    def sub_set(self, sub_id: str, values: dict) -> dict:
        """Свойства подписки: name, ua_preset, ua, hwid, update_hours, dns, mtu, provider_routes."""
        sub = self.store.subscription(sub_id)
        if sub is None:
            raise VpnClientError("Такой подписки нет")
        changes, errors = self._sub_changes(sub, values or {})
        if errors:
            return {"ok": False, "error": "Проверьте поля", "errors": errors}
        if changes.get("hwid"):
            applog.add_secrets([changes["hwid"]])
        self.store.update_subscription(sub_id, **changes)
        if "provider_routes" in changes:
            known = any(p.get("id") == f"r-{sub_id}" for p in self._profiles.load())
            self._sync_provider_profile(sub_id, changes["provider_routes"])
            if changes["provider_routes"] and not known:
                self._spawn_update(sub_id, announce=False)   # маршруты придут с подпиской — и перезапуск
        with self._lock:
            self._probes.pop(sub_id, None)        # проверка формата была для прежних свойств
            offer = self._import.get("offer")
            if isinstance(offer, dict) and offer.get("sub") == sub_id:
                self._import = dict(self._import, offer=None)   # и предложение по ней — тоже
        session = self._session
        if session is not None and {"dns", "mtu", "provider_routes"} & set(changes) and any(
                s.sub == sub_id for s in session.plan.servers):
            self._ops.submit(self._restart_job, key="restart")
        self._changed()
        return {}

    def _sync_provider_profile(self, sub_id: str, active: bool) -> None:
        """Переключатель «маршруты провайдера» у подписки и её профиль маршрутов — одно и то же."""
        profiles = self._profiles.load()
        for p in profiles:
            if p.get("id") == f"r-{sub_id}":
                p["active"] = active
            elif active:
                p["active"] = False                 # активен один профиль маршрутов
        self._profiles.save(profiles)
        self._disk_cache.pop("profiles", None)

    def _sub_changes(self, sub: Subscription, values: dict) -> tuple[dict[str, Any], dict[str, str]]:
        errors: dict[str, str] = {}
        changes: dict[str, Any] = {}
        if "name" in values:
            name = str(values["name"] or "").strip()
            if not name or len(name) > NAME_LIMIT:
                errors["name"] = f"Название — от 1 до {NAME_LIMIT} символов"
            else:
                changes["name"] = name
        if "ua_preset" in values:
            if values["ua_preset"] not in UA_PRESETS:
                errors["ua_preset"] = "Неизвестный User-Agent"
            else:
                changes["ua_preset"] = values["ua_preset"]
        # Свой UA проверяется, только если итоговый пресет — «Свой»: у других поле выключено, и окно шлёт ua: null.
        custom = changes.get("ua_preset", sub.ua_preset) == "custom"
        if custom and ("ua" in values or changes.get("ua_preset") == "custom"):
            try:
                changes["user_agent"] = self._mod("subscription").check_user_agent(
                    str(values.get("ua") or sub.user_agent or ""))
            except UserError as exc:
                errors["ua"] = str(exc)
        if "hwid" in values:
            changes["hwid"] = (sub.hwid or self._mod("subscription").new_hwid()) if values["hwid"] else None
        if "update_hours" in values:
            hours = values["update_hours"]
            if isinstance(hours, bool) or not isinstance(hours, int) or not 1 <= hours <= 72:
                errors["update_hours"] = "Интервал обновления — от 1 до 72 часов"
            else:
                changes["update_hours"] = hours
        if "dns" in values:                     # как dns_remote: auto | имя из списка | https://…; пусто — как везде
            value = values["dns"] or None
            problem, normalized = _dns(value) if value is not None else (None, None)
            if problem:
                errors["dns"] = "Свой DNS подписки — из списка или адрес https://…/dns-query"
            else:
                changes["dns"] = normalized
        if "mtu" in values:
            mtu = values["mtu"]
            if mtu is not None and (isinstance(mtu, bool) or not isinstance(mtu, int)
                                    or not SUB_MTU[0] <= mtu <= SUB_MTU[1]):
                errors["mtu"] = f"MTU подписки — пусто или от {SUB_MTU[0]} до {SUB_MTU[1]}"
            else:
                changes["mtu"] = mtu
        if "provider_routes" in values:
            changes["provider_routes"] = bool(values["provider_routes"])
        return changes, errors

    def server_remove(self, server_id: str) -> dict:
        if self.store.server(server_id) is None:
            raise VpnClientError("Такого сервера нет")
        self.store.remove_server(server_id)
        self._changed()
        return {}

    def server_rename(self, server_id: str, name: str) -> dict:
        if self.store.server(server_id) is None:
            raise VpnClientError("Такого сервера нет")
        clean = (name or "").strip()
        if len(clean) > NAME_LIMIT:
            return {"ok": False, "error": f"Имя — не длиннее {NAME_LIMIT} символов",
                    "errors": {"name": f"Не длиннее {NAME_LIMIT} символов"}}
        self.store.rename_server(server_id, clean or None)
        self._changed()
        return {}

    def open_link(self, sub_id: str, kind: str) -> str:
        """Ссылка провайдера («Поддержка», «Страница подписки») для открытия в браузере — в том числе та,
        которую странице не отдаём, потому что в ней секрет подписки."""
        sub = self.store.subscription(sub_id)
        if sub is None:
            raise VpnClientError("Такой подписки нет")
        url = {"support": sub.support_url, "page": sub.web_page_url}.get(kind)
        if not isinstance(url, str) or not url.startswith("https://"):
            raise VpnClientError("У подписки нет такой ссылки")
        return url

    def copy_link(self, item_id: str) -> str:
        """Ссылка сервера или адрес подписки — Core положит в буфер обмена (только по явной кнопке)."""
        return self._secret_text(item_id)

    def _secret_text(self, item_id: str) -> str:
        server = self.store.server(item_id)
        if server is not None:
            return server.raw or self._mod("links").to_link(server)
        sub = self.store.subscription(item_id)
        if sub is not None and sub.url:
            return sub.url
        raise VpnClientError("Сервера или подписки с таким id нет")

    # ================================================================ файлы, QR, резервная копия

    def import_file(self, path: str) -> dict:
        file = Path(path)
        try:
            size = file.stat().st_size
        except OSError as exc:
            raise VpnClientError(f"Файл не открывается: {exc}") from exc
        if size > FILE_LIMIT:
            raise VpnClientError("Файл слишком большой (больше 5 МБ)")
        if file.suffix.lower() in IMAGE_SUFFIXES:
            return self.import_qr("file", str(file))
        text = file.read_bytes().decode("utf-8-sig", errors="replace")
        if file.suffix.lower() == ".conf":
            servers = self._mod("links").parse_wireguard_conf(text, file.stem)
            applog.add_secrets([v for s in servers for v in _server_secrets(s)])
            added = _report_count(self.store.add_servers(servers), "added", len(servers))
            self._changed()
            return {"message": f"Добавлено серверов WireGuard: {added}"}
        return self.import_text(text)

    def import_qr(self, source: str, path: str | None = None) -> dict:
        qr = self._mod("qr")
        texts = qr.decode_screen() if source == "screen" else qr.decode_file(path or "")
        texts = [t.strip() for t in texts if t and t.strip()]
        if not texts:
            raise VpnClientError("QR-код не найден")
        return self.import_text("\n".join(texts))

    def qr(self, item_id: str) -> str:
        """data URL картинки QR со ссылкой — для телефона или ТВ (по явной кнопке: в QR секрет)."""
        return self._mod("qr").png_data_url(self._secret_text(item_id))

    def backup_export(self, password: str, path: str) -> dict:
        backup = self._mod("backup")
        data = {"profiles": self.store.export_data(), "settings": {k: v for k, v in self._vc().items()
                                                                   if k in SAVE_KEYS},
                "routing_profiles": self._profiles.load(), "local_proxy": self._auth.load()}
        target = Path(path)
        tmp = target.with_name(target.name + ".tmp")
        tmp.write_bytes(backup.export_bytes(data, password))
        os.replace(tmp, target)
        return {"message": "Резервная копия сохранена"}

    def backup_import(self, password: str, path: str) -> dict:
        backup = self._mod("backup")
        try:
            blob = Path(path).read_bytes()
        except OSError as exc:
            raise VpnClientError(f"Файл не открывается: {exc}") from exc
        data = backup.import_bytes(blob, password)
        report = self.store.import_data(data.get("profiles") or {})
        local = data.get("local_proxy")
        if isinstance(local, dict) and local.get("password") and not _check_local_auth("local_password",
                                                                                     local["password"]):
            self._auth.save({"user": str(local.get("user") or ""), "password": local["password"]})
        known = {p.get("id") for p in self._profiles.load()}
        extra = [p for p in data.get("routing_profiles") or [] if isinstance(p, dict) and p.get("id") not in known]
        if extra:
            self._profiles.save(self._profiles.load() + extra)
            self._disk_cache.pop("profiles", None)
        values = {k: v for k, v in (data.get("settings") or {}).items() if k in SAVE_KEYS}
        result = self.save_settings(values)
        rejected = set(result.get("errors") or ())
        if rejected:                            # остальные настройки — всё равно восстановить
            self.save_settings({k: v for k, v in values.items() if k not in rejected})
        self._register_store_secrets()
        self._changed()
        message = f"Восстановлено: серверов +{_report_count(report, 'added', 0)}"
        if rejected:
            message += f"; не подошли настройки: {', '.join(sorted(rejected))}"
        return {"message": message}

    # ================================================================ профили маршрутизации

    def profile_import(self, text: str) -> dict:
        """Профиль маршрутов (Happ/Incy) — сначала показ правил, применяется после profile_set(id, True)."""
        routeprofile = self._mod("routeprofile")
        profile = routeprofile.parse_happ(text)
        entry = {"id": f"r-{secrets.token_hex(3)}", "name": getattr(profile, "name", None) or "Профиль маршрутов",
                 "source": "link", "active": False, "text": text.strip()}
        self._profiles.save(self._profiles.load() + [entry])
        self._disk_cache.pop("profiles", None)
        self._changed()
        return {"message": f"Профиль «{entry['name']}» добавлен выключенным — посмотрите правила и включите его",
                "profile": self._profile_public(entry, details=True)}

    def profile_set(self, profile_id: str, active: bool) -> dict:
        profiles = self._profiles.load()
        if not any(p.get("id") == profile_id for p in profiles):
            raise VpnClientError("Такого профиля нет")
        for p in profiles:
            if p.get("id") == profile_id:
                p["active"] = bool(active)
            elif active:
                p["active"] = False             # активен один профиль
        self._profiles.save(profiles)
        self._disk_cache.pop("profiles", None)
        for p in profiles:                      # профиль подписки — это её переключатель «маршруты провайдера»
            sub_id = p.get("sub")
            if p.get("source") == "subscription" and sub_id and self.store.subscription(sub_id) is not None:
                self.store.update_subscription(sub_id, provider_routes=bool(p.get("active")))
        if self._session is not None:
            self._ops.submit(self._restart_job, key="restart")
        self._changed()
        return {}

    def profile_remove(self, profile_id: str) -> dict:
        profiles = self._profiles.load()
        kept = [p for p in profiles if p.get("id") != profile_id]
        if len(kept) == len(profiles):
            raise VpnClientError("Такого профиля нет")
        self._profiles.save(kept)
        self._disk_cache.pop("profiles", None)
        if any(p.get("active") for p in profiles if p.get("id") == profile_id) and self._session is not None:
            self._ops.submit(self._restart_job, key="restart")
        self._changed()
        return {}

    def _profile_public(self, entry: dict, details: bool = False) -> dict:
        """Для страницы: {id, name, source, active, summary: {direct, proxy, block} — числа правил};
        details — ещё и сами строки (окно подтверждения перед включением)."""
        full: dict = {}
        try:
            routeprofile = self._mod("routeprofile")
            full = dict(routeprofile.summary(self._parse_profile(routeprofile, entry)))
        except (UserError, ValueError, TypeError, AttributeError) as exc:
            log.debug("Профиль маршрутов не разобран: %s", exc)
        counts = {k: len(v) if isinstance(v, (list, tuple)) else int(v or 0)
                  for k, v in ((k, full.get(k)) for k in ("direct", "proxy", "block"))}
        out = {"id": entry.get("id"), "name": entry.get("name"), "source": entry.get("source", "link"),
               "active": bool(entry.get("active")), "summary": counts}
        if details:
            out["rules"] = {k: list(full.get(k) or []) for k in ("direct", "proxy", "block")}
            out["warnings"] = list(full.get("warnings") or [])
        return out

    @staticmethod
    def _parse_profile(routeprofile, entry: dict):
        if entry.get("source") == "subscription" and isinstance(entry.get("routing"), dict):
            return routeprofile.from_xray_routing(entry["routing"], entry.get("name") or "")
        return routeprofile.parse_happ(entry.get("text") or "")

    def _active_profile_rules(self) -> tuple[list[dict], list[str]] | None:
        active = next((p for p in self._profiles.load() if p.get("active")), None)
        if active is None:
            self._clear_alert(PROFILE_ALERT)
            return None
        try:
            routeprofile = self._mod("routeprofile")
            rules, sets = routeprofile.to_rules(self._parse_profile(routeprofile, active))
        except (UserError, ValueError, TypeError) as exc:   # при каждом запуске — плашка, пока не применится
            self._set_alert(PROFILE_ALERT, "warn", f"Профиль маршрутов «{active.get('name')}» не применён: {exc}")
            return None
        self._clear_alert(PROFILE_ALERT)
        return list(rules), list(sets)

    def _store_provider_profile(self, sub: Subscription, decoded) -> bool:
        """Маршруты провайдера (JSON Xray или заголовок routing) — профилем; включён, только если человек
        включил «маршруты провайдера» у подписки. True — изменились правила включённого профиля."""
        text = getattr(decoded.meta, "routing", None)
        routing = getattr(decoded, "routing", None)
        if not text and not routing:
            return False
        profiles = self._profiles.load()
        pid = f"r-{sub.id}"
        current = next((p for p in profiles if p.get("id") == pid), None)
        entry = {"id": pid, "name": f"Маршруты «{sub.name}»", "source": "subscription", "sub": sub.id,
                 "active": bool(sub.provider_routes), "text": text or "",
                 "routing": routing if isinstance(routing, dict) else None}
        if current == entry:
            return False
        self._profiles.save([p for p in profiles if p.get("id") != pid] + [entry])
        self._disk_cache.pop("profiles", None)
        return entry["active"]

    def _uses_sub(self, sub_id: str) -> bool:
        session = self._session
        return session is not None and any(s.sub == sub_id for s in session.plan.servers)

    # ================================================================ настройки

    def save_settings(self, values: dict) -> dict:
        errors: dict[str, str] = {}
        clean: dict[str, Any] = {}
        credentials: dict[str, str] = {}
        for key, value in (values or {}).items():
            if key in ("local_user", "local_password"):
                if value in ("", None):
                    continue                    # пусто — «не менять»: форма шлёт их, только когда меняют
                problem = _check_local_auth(key, value)
                if problem:
                    errors[key] = problem
                else:
                    credentials["user" if key == "local_user" else "password"] = value
                continue
            check = _VALIDATORS.get(key)
            if check is None:
                continue                        # чужие ключи (mode — через set_mode) не трогаем
            problem, normalized = check(value)
            if problem:
                errors[key] = problem
            else:
                clean[key] = normalized
        before = self._vc()
        stored = self._auth.load()
        auth_update = {k: v for k, v in credentials.items() if stored.get(k) != v}   # тот же логин — не изменение
        auth = {**stored, **auth_update}
        wants_auth = clean.get("local_auth", before["local_auth"]) or clean.get("allow_lan", before["allow_lan"])
        if wants_auth and not auth.get("user"):
            errors.setdefault("local_user", "Для входа по паролю задайте логин")
        if wants_auth and not auth.get("password"):
            errors.setdefault("local_password", "Для входа по паролю задайте пароль")
        if errors:
            return {"ok": False, "error": "Проверьте поля", "errors": errors}
        if auth_update:
            self._auth.save(auth)
            applog.add_secrets([auth.get("password")])
        self.settings.update(lambda d: d["vpnclient"].update(clean))
        changed = {k for k, v in clean.items() if before.get(k) != v}
        if auth_update and wants_auth:
            changed.add("local_auth")           # без входа по паролю логин в конфиг не попадает
        if "deeplink" in changed:
            self._apply_deeplink(bool(clean["deeplink"]))
        if "preset" in changed and clean["preset"] != "all":
            try:
                self.rules_update()
            except UserError as exc:
                log.warning("Списки для маршрутов не скачиваются: %s", exc)
        if self._session is not None and changed & RESTART_KEYS:
            self._ops.submit(self._restart_job, key="restart")
        elif "kill_switch" in changed:
            # И без сеанса: после падения или неудачного перезапуска фильтры держат интернет закрытым.
            self._ops.submit(self._toggle_killswitch, key="killswitch")
        self._changed()
        return {}

    def _apply_deeplink(self, on: bool) -> None:
        try:
            deeplink = self._mod("deeplink")
            if on:
                deeplink.register(str(paths.exe_path()))
            else:
                deeplink.unregister()
        except UserError as exc:
            self.notify("warn", f"Ссылки lazeyka:// не {'включены' if on else 'выключены'}: {exc}")

    def _toggle_killswitch(self) -> None:
        session = self._session
        if session is not None and self._vc()["kill_switch"] and session.plan.mode == "tun":
            self._enable_killswitch(session)
        else:
            self._disable_killswitch()
            self._clear_alert(KILLSWITCH_ALERT)   # kill switch выключили — «не включился» больше не важно

    # ================================================================ прочее для API

    def rules_update(self) -> dict:
        rules = self._rules()
        vc = self._vc()
        profile = self._active_profile_rules()
        ids = self._wanted_rule_sets(vc, profile[1] if profile is not None else [])
        threading.Thread(target=self._rules_worker, args=(rules, ids), name="vpnclient-rules", daemon=True).start()
        return {}

    def _rules_worker(self, rules, ids: list[str], auto: bool = False, strict: str | None = None) -> None:
        """auto — скачивание при включении VPN (не по кнопке): неудача плашкой, а не уведомлением; strict —
        не хватало списков «через VPN» (routing.strict_level: что генератор пустил через VPN, RULES_WAIT).
        Скачались списки, которых нет в работающем конфиге, — включённый VPN перезапускается с ними."""
        try:
            results = rules.update(ids, force=True) or {}
        except UserError as exc:
            self._rules_failed(str(exc).rstrip("."), auto, strict)
        except Exception:  # noqa: BLE001
            log.exception("Списки маршрутов не обновились")
        else:
            # Сбой источника update не бросает — он в результатах (и в rules.json).
            failed = [i for i, state in results.items() if state in ("failed", "unknown")]
            if failed:
                self._rules_failed(f"не скачаны {', '.join(failed)}", auto, strict)
            else:
                self._clear_alert(RULES_ALERT)
            self._ops.submit(lambda: self._restart_for_rules(rules, list(ids)), key="rules-restart")
        self._disk_cache.pop("rules", None)
        self._changed()

    def _rules_failed(self, why: str, auto: bool, strict: str | None) -> None:
        if not auto:
            self.notify("warn", f"Списки маршрутов не обновились: {why}")
            return
        wait = RULES_WAIT[strict]
        self._set_alert(RULES_ALERT, "warn", f"Списки для маршрутов не скачались: {why}. {wait[0].upper()}{wait[1:]}.",
                        action={"label": "Скачать ещё раз", "call": "vpnclient_rules_update", "args": []})

    def _restart_for_rules(self, rules, ids: list[str]) -> None:
        """Из очереди ядра (после запуска, который ещё шёл): перезапуск, только если VPN включён и в его
        конфиге нет какого-то из уже скачанных списков. Выключенный VPN не включаем."""
        session = self._session
        if session is None:
            return
        try:
            have = rules.paths(ids)
        except UserError:
            return
        fresh = [i for i in have if i not in session.plan.rules_files]
        if fresh:
            log.info("Скачались списки маршрутов (%s) — перезапускаю VPN с ними", ", ".join(fresh))
            self._restart_job()

    def running_apps(self) -> list[dict]:
        return self.deps.running_apps()

    def deeplink_offer(self, text: str) -> None:
        """Строка из ссылки lazeyka:// (второй экземпляр передал её работающему): спросить человека.
        Сама строка — секрет и на страницу не уходит; там — только что это и откуда."""
        clean = (text or "").strip()
        if not clean:
            return
        applog.add_secrets([clean])
        if re.match(r"^https?://", clean, re.I):
            host = urllib.parse.urlsplit(clean).hostname
            kind = "subscription"
            text = f"Подписка с адреса {host} (полный адрес скрыт)" if host else "Подписка (адрес скрыт)"
        else:
            kind = "links"
            text = f"Ссылок на серверы: {sum(1 for line in clean.splitlines() if '://' in line)}"
        with self._lock:
            self._deeplink = {"token": secrets.token_urlsafe(12), "kind": kind, "summary": text}
            self._deeplink_text = clean
        self._changed()

    def deeplink_confirm(self, token: str, accept: bool) -> dict:
        with self._lock:
            request, text = self._deeplink, self._deeplink_text
            if request is None or text is None or not secrets.compare_digest(str(token), request["token"]):
                raise VpnClientError("Запрос на добавление устарел")
            self._deeplink = self._deeplink_text = None
        self._changed()
        return self.import_text(text) if accept else {}

    def help_items(self) -> list[dict]:
        """Проверки панели «Свой VPN не подключается»: мёртвый системный прокси, DNS-остаток чужого VPN,
        осиротевший адаптер Lazeyka."""
        proxy = self._sysproxy()
        try:
            state = proxy.current()
        except (UserError, OSError) as exc:
            log.info("Системный прокси не прочитан: %s", exc)
            state = []
        try:
            adapters = self.deps.adapters()
        except OSError as exc:
            log.info("Адаптеры не прочитаны: %s", exc)
            adapters = []
        return diagnose.help_items(proxy_state=state, owned_address=proxy.owned_address(), adapters=adapters,
                                   own_running=self._session is not None, listening=diagnose.port_listening)

    def fix_proxy(self) -> dict:
        """Кнопка «Помощи»: свой прокси после аварии — вернуть прежний, чужой мёртвый — выключить."""
        proxy = self._sysproxy()
        if proxy.owned_address() and self._session is None:
            return {"message": "Системный прокси возвращён", **proxy.restore()}
        dead = [i for i in diagnose.help_items(proxy_state=proxy.current(), owned_address=None, adapters=[],
                                               own_running=True, listening=diagnose.port_listening)
                if i["id"] == "vpnclient_dead_proxy"]
        fixed = sum(proxy.turn_off(item["address"]) for item in dead)
        return {"message": "Мёртвый прокси выключен" if fixed else "Мёртвого прокси не нашлось"}


# ------------------------------------------------------------ настройки: проверка значений

SETTINGS_KEYS = ("port", "local_auth", "socks_udp", "allow_lan", "dns_remote", "dns_direct", "fakeip", "ip_strategy",
                 "ipv6", "tun_mtu", "exclude_nets", "proxy_override", "kill_switch", "on_sleep", "tls_fragment", "mux",
                 "noises", "fingerprint", "latency_on_update", "sort", "deeplink", "sub_update_hours", "verbose",
                 "core_auto_update")
ROUTING_KEYS =("preset", "via_zapret", "games_direct", "torrents_direct", "ip_check_direct", "direct_apps",
                "proxy_apps", "direct_sites", "proxy_sites")
SAVE_KEYS = SETTINGS_KEYS + ROUTING_KEYS
# Без перезапуска ядра меняются только эти; остальное входит в конфиг.
_LIVE_KEYS = {"sort", "latency_on_update", "sub_update_hours", "deeplink", "on_sleep", "kill_switch",
              "core_auto_update"}
RESTART_KEYS = (set(SAVE_KEYS) - _LIVE_KEYS) | {"local_auth"}
_LOGIN = re.compile(r"[A-Za-z0-9._-]{1,64}")
_EXE = re.compile(r"(?:[A-Za-z]:\\(?:[^<>\"|?*\\]+\\)*)?[^\\/:<>\"|?*]+\.exe", re.I)
LIST_LIMIT = 500


def _bool(value) -> tuple[str | None, Any]:
    return (None, value) if isinstance(value, bool) else ("Нужно «да» или «нет»", None)


def _choice(options: tuple[str, ...], text: str):
    return lambda value: (None, value) if value in options else (text, None)


def _int_range(low: int, high: int, text: str):
    def check(value):
        if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
            return text, None
        return None, value
    return check


def _dns(value) -> tuple[str | None, Any]:
    if value == "auto" or value in DOH_RESOLVERS:
        return None, value
    if isinstance(value, str) and len(value) <= 200:
        parts = urllib.parse.urlsplit(value.strip())
        if parts.scheme == "https" and parts.hostname:
            return None, value.strip()
    return "DNS — из списка или адрес https://…/dns-query", None


def _str_list(item_ok: Callable[[str], bool], text: str, limit: int = LIST_LIMIT):
    def check(value):
        if not isinstance(value, list) or len(value) > limit or not all(isinstance(x, str) for x in value):
            return f"{text} (не больше {limit} строк)", None
        items = list(dict.fromkeys(x.strip() for x in value if x.strip()))
        bad = next((x for x in items if not item_ok(x)), None)
        if bad is not None:
            return f"{text}: «{bad[:60]}»", None
        return None, items
    return check


def _is_net(text: str) -> bool:
    try:
        ipaddress.ip_network(text, strict=False)
        return True
    except ValueError:
        return False


def _is_site(text: str) -> bool:
    try:
        return _module("routing").site_match(text) is not None
    except VpnClientError:
        return bool(re.fullmatch(r"[\w.*:/-]{1,253}", text))


_VALIDATORS: dict[str, Callable[[Any], tuple[str | None, Any]]] = {
    "preset": _choice(PRESETS, "Неизвестный набор маршрутов"),
    "via_zapret": _bool, "games_direct": _bool, "torrents_direct": _bool, "ip_check_direct": _bool,
    "direct_apps": _str_list(lambda x: bool(_EXE.fullmatch(x)) and len(x) <= 260, "Нужен файл программы .exe"),
    "proxy_apps": _str_list(lambda x: bool(_EXE.fullmatch(x)) and len(x) <= 260, "Нужен файл программы .exe"),
    "direct_sites": _str_list(_is_site, "Не похоже на сайт или сеть"),
    "proxy_sites": _str_list(_is_site, "Не похоже на сайт или сеть"),
    "port": _int_range(1024, 65535, "Порт — от 1024 до 65535"),
    "local_auth": _bool, "socks_udp": _bool, "allow_lan": _bool, "fakeip": _bool, "ipv6": _bool,
    "kill_switch": _bool, "tls_fragment": _bool, "mux": _bool, "noises": _bool, "latency_on_update": _bool,
    "deeplink": _bool, "verbose": _bool, "core_auto_update": _bool,
    "dns_remote": _dns, "dns_direct": _dns,
    "ip_strategy": _choice(("ipv4_only", "prefer_ipv4", "prefer_ipv6"), "Неизвестный режим IPv4/IPv6"),
    "tun_mtu": _int_range(1280, 9000, "MTU — от 1280 до 9000"),
    "exclude_nets": _str_list(_is_net, "Нужна сеть вида 192.168.0.0/16", 100),
    "proxy_override": _str_list(lambda x: ";" not in x and len(x) <= 200, "Исключение без «;»", 100),
    "on_sleep": _choice(("reconnect", "disconnect"), "Неизвестное действие после сна"),
    "fingerprint": _choice(FINGERPRINTS, "Неизвестный отпечаток TLS"),
    "sort": _choice(("none", "latency", "name"), "Неизвестная сортировка"),
    "sub_update_hours": _int_range(1, 72, "Интервал обновления — от 1 до 72 часов"),
}


def _check_local_auth(key: str, value) -> str | None:
    if not isinstance(value, str):
        return "Нужна строка"
    if key == "local_user":
        return None if _LOGIN.fullmatch(value) else "Логин — латиница и цифры, без пробелов и двоеточия"
    if not 1 <= len(value) <= 128 or any(not 0x20 < ord(ch) < 0x7F for ch in value) or ":" in value:
        return "Пароль — от 1 до 128 латинских символов, без пробелов и двоеточия"
    return None


# ------------------------------------------------------------ мелочи

def _bypass_ok(view: ZapretView) -> bool:
    """Обход годится для Discord и YouTube: работает (или идёт подбор) и последняя проверка не провалена."""
    return (view.running or view.paused_for_test) and view.last_ok is not False


def _address_families(vc: dict, ipv6_internet: Callable[[], bool]) -> tuple[str, ...]:
    """Какие адреса сервера спрашивать заранее: «только IPv4» без IPv6 — A; иначе ещё AAAA (сервер
    только с IPv6 не выпадает из конфига). «Сначала IPv6» — AAAA первым, только если у ПК есть IPv6 в
    интернет: в конфиг попадает один адрес сервера, и без рабочего IPv6 закреплённый AAAA не открылся
    бы ни при подключении, ни при переподключениях, хотя A работает."""
    strategy = vc.get("ip_strategy")
    if strategy == "prefer_ipv6" and ipv6_internet():
        return ("AAAA", "A")
    if strategy in ("prefer_ipv4", "prefer_ipv6") or vc.get("ipv6"):
        return ("A", "AAAA")
    return ("A",)


def _narrow(pick: dict) -> dict | None:
    """Только выбранный сервер или участники выбранной группы — без соседей по подписке."""
    primary = pick.get("primary") or [pick["first"]]
    if len(pick["servers"]) <= len(primary):
        return None
    ids = {s.id for s in primary}
    return dict(pick, servers=list(primary), engines={k: v for k, v in pick["engines"].items() if k in ids},
                groups=[g for g in pick["groups"] if f"auto:{g.id}" == pick["selected"]])


def _ports_of(plan: RunPlan) -> set[int]:
    return {plan.ports.proxy, plan.ports.internal, plan.ports.clash, *plan.ports.helper.values()}


def _running_versions(session: _Session) -> dict[str, str]:
    """Версии ядер, которые в сеансе действительно запущены: в session.versions помощник Xray есть, даже
    если его серверы остались без адреса и процесс не стартовал."""
    out = {}
    if session.versions.get("sing-box"):
        out["sing-box"] = session.versions["sing-box"]
    if session.helper is not None and session.versions.get("xray"):
        out["xray"] = session.versions["xray"]
    return out


def _server_secrets(server: Server) -> list[str | None]:
    tls, hy2, wg = server.tls or {}, server.hy2 or {}, server.wg or {}
    out = [server.uuid, server.password, server.raw, tls.get("pbk"), tls.get("sid"), hy2.get("obfs_password"),
           wg.get("private_key"), wg.get("preshared_key")]
    if server.xray_outbound:
        out.append(json.dumps(server.xray_outbound, ensure_ascii=False))
    return out


def _bypass_shape(profiles: list, voice: list[str]) -> tuple:
    """Что из профилей «через обход» попадает в правила конфига (содержимое файлов — нет)."""
    return (tuple((p.network, tuple(p.ports), str(p.domains_file or ""), str(p.ips_file or ""),
                   bool(p.reject_quic), tuple(p.l7)) for p in profiles), tuple(voice))


def _shown(text: Any) -> Any:
    """Имя или текст провайдера для страницы: UUID или токен в имени после «#» тоже секрет."""
    return applog.scrub(text) if isinstance(text, str) else text


def _public(server: Server, noises: bool) -> dict:
    info = server.public()
    info["name"], info["description"] = _shown(info.get("name")), _shown(info.get("description"))
    if noises:
        engine, reason = engine_for(server, force_xray=True)
        info.update(engine=engine, supported=engine is not None, reason=reason)
    return info


def _latency_entry(value: Any) -> dict:
    if isinstance(value, dict):
        return {"ms": value.get("ms"), "at": value.get("at"), "error": value.get("error")}
    return {"ms": None, "at": None, "error": None}


def _speed_entry(value: Any) -> dict | None:
    if isinstance(value, dict) and value.get("mbps") is not None:
        return {"mbps": value.get("mbps"), "at": value.get("at")}
    return None


def _store_speeds(store) -> dict:
    speeds = getattr(store, "speed", None)
    if not callable(speeds):
        return {}
    try:
        return dict(speeds() or {})
    except (TypeError, UserError):
        return {}


def _report_count(report: Any, name: str, default: int) -> int:
    value = getattr(report, name, None)
    if value is None and isinstance(report, dict):
        value = report.get(name)
    if isinstance(value, (list, tuple, set)):
        return len(value)
    return value if isinstance(value, int) and not isinstance(value, bool) else default


def _host_name(url: str) -> str:
    return (urllib.parse.urlsplit(url).hostname or "Подписка")[:NAME_LIMIT]


def _chunks(items: list, size: int) -> list[list]:
    return [items[i:i + size] for i in range(0, len(items), size)]


def _write_json(path: Path, data: Any) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, path)


def _secure_dir() -> Callable[[Path], None] | None:
    from .. import security
    return getattr(security, "secure_private_dir", None)
