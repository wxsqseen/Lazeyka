"""Почему свой VPN не работает: причина по выводу ядер и проверки панели «Помощь».

Тексты — для человека: что случилось и что сделать. Разбор опирается на префиксы ошибок sing-box 1.14
(`decode config at`, `initialize outbound[i]`, `start service: start inbound/…`, `finish-start clash
server`) и Xray (`Failed to start`, `[Error]`), тексты ОС — английские даже на русской Windows.
Вид ошибки (kind) — тот же, что `error_kind` в состоянии страницы.
"""
from __future__ import annotations

import email.utils
import ipaddress
import re
import socket
import time
from dataclasses import dataclass, field
from typing import Callable

KINDS = ("port", "admin", "conflict", "timeout", "tls", "auth", "clock", "unsupported", "core", "other")
CLOCK_TOLERANCE = 90.0               # с: VMess AEAD допускает 120 с, REALITY — настройка сервера
FAKE_IP_NET = ipaddress.ip_network("198.18.0.0/15")
OWN_ADAPTER = "Lazeyka"
LINE_LIMIT = 200
SCAN_LINES = 40                      # сколько последних строк смотреть

_ADDR = re.compile(r"listen (?:tcp|udp)[46]? (?:\[[^\]]+\]|[\d.]+):(\d+)")
_FATAL_LINE = re.compile(r"\b(PANIC|FATAL)\[\d+\]|^Failed to start")       # причина остановки ядра
# ошибки соединений: sing-box — ERROR, Xray пишет их предупреждениями «failed to …»
_ERROR_LINE = re.compile(r"\bERROR\[\d+\]|\[Error\]|\[Warning\].*failed")


@dataclass(frozen=True)
class _Rule:
    pattern: re.Pattern
    kind: str
    text: str                        # {port}, {line} подставляются
    also: re.Pattern | None = None   # второе условие (та же строка)


def _rx(text: str) -> re.Pattern:
    return re.compile(text, re.I)


_BUSY = _rx(r"Only one usage of each socket address|address already in use|WSAEADDRINUSE|\b10048\b")
_RESERVED = _rx(r"forbidden by its access permissions|WSAEACCES|\b10013\b")

# Порядок важен: сначала самые точные признаки.
_RULES = (
    _Rule(_rx(r"finish-start clash server"), "port",
          "Служебный порт ядра {port} занят или зарезервирован Windows — Лазейка выберет другой.",
          also=_rx(_BUSY.pattern + "|" + _RESERVED.pattern)),
    _Rule(_RESERVED, "port", "Порт {port} зарезервирован Windows (Hyper-V, WSL или Docker) — нужен другой порт."),
    _Rule(_BUSY, "port", "Порт {port} уже занят другой программой — освободите его или выберите другой порт."),
    _Rule(_rx(r"inbound/tun|configure tun|create tun|wintun"), "admin",
          "Для режима «Весь трафик» нужны права администратора — перезапустите Лазейку с ними.",
          also=_rx(r"access is denied|access denied|requires elevation|administrator|0x80070005")),
    _Rule(_rx(r"inbound/tun|configure tun|create tun|wintun"), "conflict",
          "Адаптер VPN не создался: мешает другой VPN или его адаптер. Выключите другие VPN-программы "
          "или включите режим «Системный прокси». ({line})"),
    _Rule(_rx(r"allowInsecure"), "unsupported",
          "Xray не принимает отключённую проверку сертификата (allowInsecure) — у сервера нужен "
          "pinnedPeerCertSha256 или другой сервер."),
    _Rule(_rx(r"uTLS is required by reality|decode public_key|public_key|short_id|invalid short id"), "tls",
          "Неверные параметры REALITY у сервера (ключ pbk или sid) — обновите подписку или проверьте ссылку."),
    _Rule(_rx(r"unknown transport|unknown outbound type|unknown network|not supported|unsupported"), "unsupported",
          "Ядро не поддерживает настройки этого сервера ({line})."),
    _Rule(_rx(r"bad key length|invalid password|password is required|invalid uuid|invalid user id"), "auth",
          "Ключ сервера в ссылке неверный — обновите подписку или проверьте ссылку."),
    _Rule(_rx(r"decode config at|unknown field|cannot unmarshal|deprecated|ENABLE_DEPRECATED|"
              r"failed to load config|infra/conf|parse rule"), "core",
          "Ядро не приняло конфигурацию — это ошибка Лазейки, сообщите о ней. ({line})"),
    _Rule(_rx(r"initialize outbound\[\d+\]"), "core", "Сервер не подходит ядру: {line}"),
    _Rule(_rx(r"time ?skew|timestamp|clock|VMessAEAD.*time"), "clock",
          "Часы компьютера сбиты — включите синхронизацию времени в параметрах Windows."),
    _Rule(_rx(r"invalid user|authentication failed|auth(entication)? fail|unauthorized|user not found|"
              r"bad request|invalid request"), "auth",
          "Сервер отклонил ключ — возможно, закончилась подписка или ключ сменился. Обновите подписку."),
    _Rule(_rx(r"reality verification|processed invalid connection|REALITY|tls: |x509:|certificate|"
              r"handshake failure|remote error"), "tls",
          "Сервер отклонил защищённое соединение (TLS/REALITY) — проверьте sni, pbk и sid или обновите подписку."),
    _Rule(_rx(r"i/o timeout|context deadline exceeded|timed out|timeout|failed to find an available destination"),
          "timeout", "Сервер не отвечает — он выключен, недоступен из вашей сети или его блокируют."),
    _Rule(_rx(r"connection refused|actively refused|No connection could be made"), "timeout",
          "Сервер не принимает соединения: порт закрыт или сервер выключен."),
)


def _short(line: str) -> str:
    line = re.sub(r"^\S+ \S+ \S+ (?=(PANIC|FATAL|ERROR|WARN|INFO)\[)", "", line.strip())   # время sing-box
    line = re.sub(r"^(PANIC|FATAL|ERROR|WARN|INFO|DEBUG)\[\d+\]\s*", "", line)
    return line if len(line) <= LINE_LIMIT else line[:LINE_LIMIT - 1] + "…"


def classify(tail: list[str]) -> tuple[str, str]:
    """(kind, текст) по хвосту вывода ядра: фатальные строки (почему остановилось), иначе ошибки
    соединений, иначе весь хвост. Правила — от самых точных; из строк — более поздние."""
    lines = [ln for ln in tail if ln and ln.strip()]
    if not lines:
        return "other", "Ядро завершилось, ничего не сообщив."
    fatal = [ln for ln in lines if _FATAL_LINE.search(ln)]
    errors = fatal or [ln for ln in lines if _ERROR_LINE.search(ln)]
    candidates = list(reversed((errors or lines)[-SCAN_LINES:]))
    for rule in _RULES:
        for line in candidates:
            if rule.pattern.search(line) and (rule.also is None or rule.also.search(line)):
                port = _ADDR.search(line)
                return rule.kind, rule.text.format(port=port.group(1) if port else "", line=_short(line))
    return ("core" if errors else "other"), f"Ядро сообщило об ошибке: {_short(candidates[0])}"


def explain_no_exit(tail: list[str], *, reach_ms: float | None, skew: float | None,
                    timed_sensitive: bool) -> tuple[str, str]:
    """Ядро работает, а проверка выхода через сервер не прошла: что сказать человеку.

    reach_ms — TCP до сервера напрямую (None — не прошёл); skew — расхождение часов с ответом проверки;
    timed_sensitive — протокол сервера проверяет время (VMess, REALITY)."""
    if timed_sensitive and skew is not None and abs(skew) > CLOCK_TOLERANCE:
        minutes = max(1, round(abs(skew) / 60))
        return "clock", (f"Часы компьютера расходятся с точным временем на {minutes} мин — сервер такие "
                         "подключения отклоняет. Включите синхронизацию времени в параметрах Windows.")
    if reach_ms is None:
        return "timeout", ("Сервер не отвечает даже напрямую (TCP до его порта не проходит): он выключен, "
                           "недоступен из вашей сети или его блокируют. Выберите другой сервер.")
    kind, text = classify(tail)
    if kind in ("other", "core"):
        return "other", ("Сервер доступен, но через него ничего не открывается — проверьте, не закончилась ли "
                         "подписка, или выберите другой сервер.")
    return kind, text


def clock_skew(date_header: str | None, now: float | None = None) -> float | None:
    """На сколько секунд наши часы впереди времени из заголовка Date ответа (None — не разобрать)."""
    if not date_header:
        return None
    try:
        server = email.utils.parsedate_to_datetime(date_header)
    except (TypeError, ValueError):
        return None
    if server is None or server.tzinfo is None:
        return None
    return (time.time() if now is None else now) - server.timestamp()


def tcp_reach(host: str, port: int, timeout: float = 3.0) -> float | None:
    """Время установки TCP-соединения в мс напрямую до сервера; None — не удалось."""
    began = time.monotonic()
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return round((time.monotonic() - began) * 1000, 1)
    except (OSError, ValueError):
        return None


# ------------------------------------------------------------ «Помощь»: чужие и свои следы

@dataclass
class AdapterInfo:
    name: str
    up: bool
    ipv4: list[str] = field(default_factory=list)
    dns: list[str] = field(default_factory=list)       # статические DNS-серверы адаптера


def _in_fake_net(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in FAKE_IP_NET
    except ValueError:
        return False


def _loopback_address(server: str) -> tuple[str, int] | None:
    first = next((p.split("=", 1)[-1].strip() for p in server.split(";") if p.strip()), "")
    host, _, port = first.rpartition(":")
    host = host.strip("[]").lower()
    try:
        loopback = host == "localhost" or ipaddress.ip_address(host).is_loopback
    except ValueError:
        return None
    if not loopback or not port.isdigit():
        return None
    return host, int(port)


def help_items(*, proxy_state: list[dict], owned_address: str | None, adapters: list[AdapterInfo],
               own_running: bool, listening: Callable[[str, int], bool]) -> list[dict]:
    """Находки для панели «Свой VPN не подключается»: [{id, level, title, text, fix}]."""
    items: list[dict] = []
    dead = {}
    for conn in proxy_state:
        if not (conn.get("flags", 0) & 0x2):        # PROXY_TYPE_PROXY
            continue
        addr = _loopback_address(str(conn.get("server") or ""))
        if addr and not listening(*addr):
            dead[f"{addr[0]}:{addr[1]}"] = conn.get("name")
    for address in dead:
        ours = owned_address is not None and address.lower() == owned_address.lower()
        items.append({
            "id": "vpnclient_dead_proxy", "level": "error", "fix": "vpnclient_proxy_fix", "address": address,
            "ours": ours, "title": "Системный прокси указывает на выключенную программу",
            "text": (f"В настройках Windows включён прокси {address}, но там никто не отвечает — браузеры "
                     "не откроют сайты. " + ("Это прокси Лазейки после аварийного выхода: верните прежние "
                                             "настройки." if ours else
                                             "Его оставила другая VPN-программа после аварии: выключите его."))})
    fake_vpn_up = any(a.up and any(_in_fake_net(ip) for ip in a.ipv4) for a in adapters)
    for a in adapters:
        stale = [ip for ip in a.dns if _in_fake_net(ip)]
        if a.up and stale and not fake_vpn_up:
            items.append({
                "id": "vpnclient_fake_dns", "level": "error", "fix": "vpnclient_open_adapters",
                "title": f"DNS адаптера «{a.name}» — остаток другого VPN",
                "text": (f"У адаптера «{a.name}» DNS-сервер {stale[0]}: так его настраивают VPN-программы "
                         "(например, Incy), а после аварии не возвращают. Сайты по именам не откроются. "
                         "В свойствах адаптера → IP версии 4 выберите «Получить адрес DNS-сервера "
                         "автоматически».")})
    if not own_running and any(a.name == OWN_ADAPTER for a in adapters):
        items.append({
            "id": "vpnclient_orphan_adapter", "level": "warn", "fix": None,
            "title": "Остался адаптер Lazeyka",
            "text": ("Адаптер своего VPN остался после аварийного выхода. Он не мешает интернету; при "
                     "следующем включении VPN Лазейка займёт его снова.")})
    return items


def port_listening(host: str, port: int, timeout: float = 0.5) -> bool:
    return tcp_reach(host, port, timeout) is not None


def collect_adapters() -> list[AdapterInfo]:
    """Адаптеры с адресами и статическими DNS (реестр Tcpip\\Parameters\\Interfaces)."""
    import winreg
    from .. import vpn
    out = []
    for a in vpn.list_adapters():
        dns: list[str] = []
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                rf"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{a.guid}") as key:
                value = str(winreg.QueryValueEx(key, "NameServer")[0])
                dns = [x for x in re.split(r"[,\s]+", value) if x]
        except OSError:
            pass
        out.append(AdapterInfo(name=a.name, up=a.up, ipv4=list(a.ipv4), dns=dns))
    return out
