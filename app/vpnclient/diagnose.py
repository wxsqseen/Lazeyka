"""Почему свой VPN не работает: причина по выводу ядер, чья это сторона и проверки панели «Помощь».

Тексты — для человека: что случилось и что сделать. Разбор опирается на префиксы ошибок sing-box 1.14
(`decode config at`, `initialize outbound[i]`, `start service: start inbound/…`, `finish-start clash
server`) и Xray (`Failed to start`, `[Error]`), тексты ОС — английские даже на русской Windows.
Вид ошибки (kind) — тот же, что `error_kind` в состоянии страницы.

Причина «нет ответа» (explain) — чистая функция на фактах (Facts), которые менеджер собирает только по
факту отказа: прямые пробы TCP и TLS до сервера, контрольный сайт, DNS, задержки соседей по подписке,
срок и трафик подписки, часы. Ответ — Reason: чья сторона (you | isp | provider | lazeyka | unknown),
код, почему и что сделать.
"""
from __future__ import annotations

import email.utils
import errno
import ipaddress
import re
import socket
import ssl
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
    reason: str | None = None        # вид причины для explain (stop_kind), если он точнее вида ошибки страницы


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
    # Свой VPN запускает ядро только с правами администратора (manager.ADMIN_REASON): отказ в доступе к
    # адаптеру — не нехватка прав, а чужая программа, антивирус или политика. Страница предлагает то же, что
    # при чужом VPN (вид conflict: режим «Системный прокси»), а причина — своя (_LOCAL["admin"]).
    _Rule(_rx(r"inbound/tun|configure tun|create tun|wintun"), "conflict",
          "Windows отказала в доступе к адаптеру VPN, хотя права администратора у Лазейки есть: адаптер держит "
          "другая VPN-программа или драйвер Wintun блокирует антивирус. Выключите другие VPN-программы или "
          "включите режим «Системный прокси». ({line})",
          also=_rx(r"access is denied|access denied|requires elevation|administrator|0x80070005"), reason="admin"),
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


def _match(tail: list[str]) -> tuple[_Rule | None, str | None, bool]:
    """(правило, строка, были ли ошибки) по хвосту вывода ядра: фатальные строки (почему остановилось), иначе
    ошибки соединений, иначе весь хвост. Правила — от самых точных; из строк — более поздние."""
    lines = [ln for ln in tail if ln and ln.strip()]
    if not lines:
        return None, None, False
    fatal = [ln for ln in lines if _FATAL_LINE.search(ln)]
    errors = fatal or [ln for ln in lines if _ERROR_LINE.search(ln)]
    candidates = list(reversed((errors or lines)[-SCAN_LINES:]))
    for rule in _RULES:
        for line in candidates:
            if rule.pattern.search(line) and (rule.also is None or rule.also.search(line)):
                return rule, line, bool(errors)
    return None, candidates[0], bool(errors)


def classify(tail: list[str]) -> tuple[str, str]:
    """(kind, текст) по хвосту вывода ядра (_match): вид ошибки для страницы и что случилось."""
    rule, line, errors = _match(tail)
    if line is None:
        return "other", "Ядро завершилось, ничего не сообщив."
    if rule is None:
        return ("core" if errors else "other"), f"Ядро сообщило об ошибке: {_short(line)}"
    port = _ADDR.search(line)
    return rule.kind, rule.text.format(port=port.group(1) if port else "", line=_short(line))


def stop_kind(tail: list[str]) -> str:
    """Вид причины остановки ядра для explain(Facts(kind=…, fatal=True)): обычно — вид ошибки (classify), а
    у отказа в доступе к адаптеру при правах администратора — admin: страница предлагает то же, что при
    чужом VPN, а причина у него своя."""
    rule, _line, errors = _match(tail)
    if rule is not None:
        return rule.reason or rule.kind
    return "core" if errors else "other"


RUNTIME_HINTS = ("tls", "auth", "clock")


def runtime_hint(tail: list[str]) -> str | None:
    """Что работающее ядро сказало о соединениях с сервером: tls | auth | clock — или None, если молчит или
    говорит о другом (остальные виды при работающем ядре о сервере ничего не говорят)."""
    kind = classify(tail)[0]
    return kind if kind in RUNTIME_HINTS else None


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


@dataclass(frozen=True)
class TcpProbe:
    """Прямая проба TCP до сервера. outcome: ok | refused | timeout | reset | unreachable | error."""

    outcome: str
    ms: float | None = None


# WSAENETUNREACH, WSAEHOSTUNREACH — у Windows свои номера, у POSIX — errno.
_UNREACHABLE = {errno.ENETUNREACH, errno.EHOSTUNREACH, 10051, 10065}


def tcp_probe(host: str, port: int, timeout: float = 3.0) -> TcpProbe:
    """Установить TCP-соединение напрямую (мимо ядра) и сказать, как оно кончилось."""
    began = time.monotonic()
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return TcpProbe("ok", round((time.monotonic() - began) * 1000, 1))
    except ConnectionRefusedError:
        return TcpProbe("refused")
    except (ConnectionResetError, ConnectionAbortedError):
        return TcpProbe("reset")
    except TimeoutError:                             # socket.timeout — его синоним с Python 3.10
        return TcpProbe("timeout")
    except OSError as exc:
        return TcpProbe("unreachable" if exc.errno in _UNREACHABLE else "error")
    except ValueError:
        return TcpProbe("error")


def tcp_reach(host: str, port: int, timeout: float = 3.0) -> float | None:
    """Время установки TCP-соединения в мс напрямую до сервера; None — не удалось."""
    return tcp_probe(host, port, timeout).ms


def tls_probe(host: str, port: int, sni: str | None, timeout: float = 4.0) -> str:
    """Рукопожатие TLS напрямую с именем сервера (SNI) из подписки, без проверки сертификата: ok — прошло
    (у REALITY его доводит до конца сайт-маска); alert — сервер ответил отказом или не по TLS (путь
    свободен); reset — оборвали посреди рукопожатия; timeout — повисло; error — не соединиться вовсе."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, int(port)), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=sni or None):
                return "ok"
    except (ssl.SSLEOFError, ssl.SSLZeroReturnError, ConnectionResetError, ConnectionAbortedError):
        return "reset"
    except TimeoutError:
        return "timeout"
    except ssl.SSLError:
        return "alert"
    except (OSError, ValueError):
        return "error"


# ------------------------------------------------------------ чья сторона: причина «нет ответа»

SIDES = ("you", "isp", "provider", "lazeyka", "unknown")
SIDE_LABELS = {"you": "у вас", "isp": "у интернет-провайдера", "provider": "у VPN-провайдера",
               "lazeyka": "в Лазейке", "unknown": "не ясно"}
UDP_PROTOCOLS = ("hysteria2", "tuic", "wireguard")
UDP_NETWORKS = ("kcp", "quic")                  # mKCP и QUIC-транспорт тоже идут по UDP
REPORT_ADVICE = ("Подробности — в журнале. Скопируйте «Отчёт для помощи» на странице «Помощь» и отправьте его "
                 "разработчикам Лазейки.")


@dataclass(frozen=True)
class Reason:
    side: str                        # SIDES
    code: str
    text: str                        # почему — одной-двумя фразами
    advice: str                      # что сделать

    def public(self) -> dict:
        return {"side": self.side, "code": self.code, "text": self.text, "advice": self.advice}


def public_reason(value) -> dict | None:
    """Причина из хранилища для страницы: только знакомой формы (файл профилей мог править кто угодно)."""
    if not isinstance(value, dict) or value.get("side") not in SIDES:
        return None
    if not all(isinstance(value.get(key), str) and value.get(key) for key in ("code", "text", "advice")):
        return None
    return {key: value[key] for key in ("side", "code", "text", "advice")}


@dataclass
class Facts:
    """Что известно об отказе. None — не проверяли (а не «нет»): по непроверенному причину не назначаем."""

    kind: str | None = None          # classify(хвост ядра) или вид сбоя запуска (KINDS, + helper, killswitch)
    fatal: bool = False              # ядро остановилось (запуск, падение), а не «сервер не ответил»
    udp: bool = False                # протокол на UDP: прямой пробы нет, судим по соседям
    timed: bool = False              # протокол сверяет время клиента (VMess, REALITY)
    online: bool | None = None       # контрольный сайт напрямую открылся
    skew: float | None = None        # на сколько секунд наши часы впереди точного времени
    # адрес не получен — что сказал DNS через HTTPS (manager.Resolver.failure): nxdomain | nodata | no_ipv4 |
    # servfail | unreachable | found
    dns: str | None = None
    system_dns: bool | None = None   # DNS сети знает имя сервера
    tcp: str | None = None           # TcpProbe.outcome
    handshake: str | None = None     # tls_probe(): у серверов с TLS и REALITY
    peers_ok: int = 0                # соседи по подписке ответили (свежая задержка)
    peers_udp_ok: int = 0            # из них на UDP
    peers_failed: int = 0            # соседи по подписке не ответили
    tcp_ok_anywhere: bool = False    # хоть один сервер на TCP (любой подписки) ответил
    expired: bool = False            # срок подписки прошёл
    traffic_out: bool = False        # трафик подписки кончился
    device_limit: bool = False       # провайдер сообщил: лимит устройств (x-hwid-max-devices-reached)
    fragment: bool = False           # фрагментация ClientHello уже включена


def uses_udp(proto: str, network: str | None) -> bool:
    return proto in UDP_PROTOCOLS or (network or "") in UDP_NETWORKS


def account_facts(userinfo: dict | None, now: float) -> dict:
    """Срок и трафик подписки (userinfo: upload, download, total, expire в секундах; 0 — без предела)."""
    info = userinfo or {}
    try:
        expire = float(info.get("expire") or 0)
        total = int(info.get("total") or 0)
        used = int(info.get("upload") or 0) + int(info.get("download") or 0)
    except (TypeError, ValueError):
        return {"expired": False, "traffic_out": False}
    return {"expired": 0 < expire <= now, "traffic_out": total > 0 and used >= total}


def _clock(skew: float | None) -> Reason:
    if skew is None:
        text = "Часы компьютера сбиты — сервер такие подключения отклоняет."
    else:
        text = (f"Часы компьютера расходятся с точным временем на {max(1, round(abs(skew) / 60))} мин — сервер "
                "такие подключения отклоняет.")
    return Reason("you", "clock", text, "В параметрах Windows включите «Устанавливать время автоматически» и "
                                        "нажмите «Синхронизировать».")


# Отказы, причина которых ясна без сети: ядро само назвало, что не так.
_LOCAL = {
    "port": Reason("you", "port_busy", "Порт занят другой программой или зарезервирован Windows (Hyper-V, WSL, "
                                       "Docker).",
                   "Смените порт в «Подробнее» или закройте программу, которая его держит."),
    # Без прав свой VPN не запускается вовсе (Core._require_admin, manager.ADMIN_REASON): «доступ запрещён» у
    # адаптера бывает, когда права уже есть, — перезапуск с ними не поможет.
    "admin": Reason("you", "admin", "Windows не дала создать адаптер своего VPN («доступ запрещён»), хотя права "
                                    "администратора у Лазейки есть: драйвер Wintun или адаптер занят другой "
                                    "VPN-программой, его блокирует антивирус или запрещает политика компьютера "
                                    "(так бывает на рабочих ПК).",
                    "Закройте другие VPN-программы (и их значки в трее) и включите VPN снова; не помогло — "
                    "перезагрузите компьютер. Если стоит антивирус, разрешите в нём Лазейку и sing-box.exe. Без "
                    "адаптера работает режим «Системный прокси»."),
    "conflict": Reason("you", "conflict", "Мешает другой VPN: его адаптер или маршруты не дают поднять свой.",
                       "Выключите другой VPN или включите режим «Системный прокси»."),
    "unsupported": Reason("lazeyka", "unsupported", "Лазейка не умеет такие настройки сервера.",
                          "Выберите другой сервер. Если этот работает в других приложениях, скопируйте «Отчёт для "
                          "помощи» на странице «Помощь» и отправьте его разработчикам Лазейки."),
    "killswitch": Reason("lazeyka", "killswitch", "Kill switch выпускает в сеть только ядра текущего подключения — "
                                                  "этот сервер сейчас не проверить.",
                         "Проверьте задержку, когда VPN выключен, или выберите этот сервер — он проверится "
                         "через подключение."),
    "helper": Reason("lazeyka", "helper_failed", "Помощник Xray не запустился или упал — это ошибка Лазейки.",
                     REPORT_ADVICE),
    "core": Reason("lazeyka", "core_failed", "Ядро VPN не приняло настройки или завершилось с ошибкой — это "
                                             "ошибка Лазейки.", REPORT_ADVICE),
}
_BAD_PARAMS = Reason("provider", "bad_params", "Параметры сервера в подписке испорчены (ключ REALITY или пароль) — "
                                               "ядро их не принимает.",
                     "Обновите подписку. Не поможет — напишите в поддержку VPN-провайдера.")
_NO_INTERNET = Reason("you", "no_internet", "Интернета нет: даже напрямую не открываются контрольные сайты.",
                      "Проверьте кабель или Wi-Fi и роутер. Когда интернет появится, проверьте снова.")
_EXPIRED = Reason("provider", "sub_expired", "Срок подписки закончился — серверы больше не пускают.",
                  "Продлите подписку у VPN-провайдера и обновите её в Лазейке.")
_TRAFFIC_OUT = Reason("provider", "traffic_out", "Трафик по подписке закончился — серверы больше не пускают.",
                      "Докупите трафик или дождитесь его сброса у провайдера, затем обновите подписку.")
_DEVICE_LIMIT = Reason("provider", "device_limit", "Провайдер сообщает, что достигнут лимит устройств подписки.",
                       "Отвяжите лишние устройства в личном кабинете или боте провайдера и обновите подписку.")
_DNS_MISSING = Reason("provider", "dns_missing", "DNS не знает имени этого сервера: домен удалён или в подписке "
                                                 "опечатка.",
                      "Обновите подписку. Не поможет — напишите в поддержку VPN-провайдера.")
_DNS_BLOCKED = Reason("isp", "dns_blocked", "Защищённый DNS не отвечает, хотя интернет есть: похоже, его блокирует "
                                            "интернет-провайдер. Без него Лазейка не узнаёт адрес сервера.",
                      "В «Подробнее» выберите другой «DNS напрямую» (например, Яндекс) или подключитесь через "
                      "другую сеть.")
_DNS_DOWN = Reason("you", "dns_down", "Адрес сервера не узнать: не отвечает ни DNS вашей сети, ни защищённый DNS.",
                   "Перезагрузите роутер. В «Помощи» проверьте, не остался ли DNS от другого VPN.")
_DNS_NO_ADDRESS = Reason("provider", "dns_missing", "DNS знает имя этого сервера, но адреса у него нет: сервер "
                                                    "убрали или провайдер ошибся в настройках.",
                          "Обновите подписку. Не поможет — напишите в поддержку VPN-провайдера.")
_IPV6_ONLY = Reason("you", "ipv6_only", "У сервера нет адреса IPv4 — похоже, он доступен только по IPv6, а в "
                                        "«Подробнее» выбрано «Только IPv4».",
                    "В «Подробнее» в «IPv4 и IPv6» выберите «Сначала IPv4»: Лазейка спросит и адрес IPv6 (нужен "
                    "IPv6 у вашего интернета). Не поможет — выберите другой сервер.")
_DNS_ERROR = Reason("unknown", "dns_error", "DNS через HTTPS ответил ошибкой и адреса не назвал: сбой у DNS этого "
                                            "имени (на стороне VPN-провайдера) или у самих DNS-серверов.",
                    "Включите VPN чуть позже ещё раз. Повторится — выберите другой сервер или напишите в "
                    "поддержку VPN-провайдера.")
_DNS_RETRY = Reason("unknown", "dns_retry", "Адрес сервера не получен, а почему — DNS не сообщил.",
                    "Включите VPN ещё раз. Повторится — проверьте DNS на странице «Помощь».")
_UDP_BLOCKED = Reason("isp", "udp_blocked", "Сервер на UDP (Hysteria2, TUIC, WireGuard, mKCP) не отвечает, а серверы "
                                            "на TCP отвечают — похоже, интернет-провайдер режет UDP.",
                      "Выберите сервер на TCP (VLESS, Trojan) или подключитесь через другую сеть.")
_UDP_SILENT = Reason("unknown", "udp_silent", "Сервер на UDP не отвечает. Напрямую это не проверить: он выключен, "
                                              "или интернет-провайдер режет UDP.",
                     "Проверьте задержку всех серверов: если на TCP отвечают, а на UDP — нет, режет провайдер.")
_PORT_CLOSED = Reason("provider", "port_closed", "Сервер на связи, но его порт закрыт: сервер выключен или "
                                                 "провайдер сменил порт.",
                      "Обновите подписку. Не поможет — выберите другой сервер.")
_SERVER_DOWN = Reason("provider", "server_down", "Этот сервер не отвечает, а другие серверы подписки работают: он "
                                                 "выключен или перегружен.",
                      "Выберите другой сервер или «Самый быстрый».")
_ALL_DOWN = Reason("unknown", "all_down", "Не отвечает ни один из проверенных серверов подписки, хотя интернет "
                                          "есть. Либо интернет-провайдер блокирует их адреса, либо сбой у "
                                          "VPN-провайдера.",
                   "Проверьте через другую сеть, например мобильный интернет с телефона: заработает — блокирует "
                   "интернет-провайдер, нет — напишите в поддержку VPN-провайдера.")
_TCP_TIMEOUT = Reason("unknown", "tcp_timeout", "Сервер не отвечает, хотя интернет есть: он выключен, или "
                                                "интернет-провайдер блокирует его адрес.",
                      "Проверьте задержку всех серверов подписки или подключитесь через другую сеть — так станет "
                      "ясно, чья сторона.")
_KEYS_OUTDATED = Reason("provider", "keys_outdated", "До сервера всё доходит, но он не принимает ключи из подписки "
                                                     "(REALITY или TLS) — похоже, они устарели.",
                        "Обновите подписку. Не поможет — напишите в поддержку VPN-провайдера.")
_AUTH_REJECTED = Reason("provider", "auth_rejected", "Сервер не принял ключ: его сменили, подписка закончилась или "
                                                     "устройств больше, чем разрешено.",
                        "Обновите подписку и проверьте срок и устройства в личном кабинете провайдера.")
_NO_EXIT = Reason("provider", "no_exit", "Сервер на связи, но в интернет через него не выйти: сбой на сервере или "
                                         "ключ больше не действует.",
                  "Обновите подписку и выберите другой сервер. Не поможет — напишите в поддержку VPN-провайдера.")
_UNKNOWN = Reason("unknown", "unknown", "Сервер не ответил, а причину определить не удалось.",
                  "Проверьте задержку ещё раз или выберите другой сервер.")


def _dpi(f: Facts) -> Reason:
    if f.tcp == "reset":
        what = "Соединение с сервером сбрасывают сразу"
    else:
        how = "зависает" if f.handshake == "timeout" else "обрывается"
        what = f"Соединение с сервером есть, но защищённое рукопожатие {how}"
    advice = ("Фрагментация уже включена — выберите сервер с другим транспортом (XHTTP, gRPC) или другой сервер."
              if f.fragment else
              "Включите «Фрагментацию ClientHello» в «Подробнее» или выберите сервер с другим транспортом (XHTTP, "
              "gRPC).")
    return Reason("isp", "dpi", f"{what} — похоже, так соединения режет DPI интернет-провайдера.", advice)


def _dns(f: Facts) -> Reason:
    if f.dns == "nxdomain":
        return _DNS_MISSING
    if f.dns == "nodata":
        return _DNS_NO_ADDRESS
    if f.dns == "no_ipv4":
        return _IPV6_ONLY
    if f.dns == "servfail":
        return _DNS_ERROR
    if f.dns == "unreachable":
        return _DNS_BLOCKED if f.system_dns else _DNS_DOWN
    return _DNS_RETRY


def _silent(f: Facts) -> Reason:
    """Сервер не ответил на TCP (или пробы не было): соседи по подписке решают, сервер это или сеть."""
    if f.peers_ok:
        return _SERVER_DOWN
    if f.peers_failed:
        return _ALL_DOWN
    return _TCP_TIMEOUT


def _stopped(kind: str | None) -> Reason:
    """Ядро остановилось (не запустилось или упало): по его последним словам. tls и auth при запуске —
    это разбор параметров сервера (initialize outbound), а не ответ сервера."""
    if kind in ("tls", "auth"):
        return _BAD_PARAMS
    if kind == "clock":
        return _clock(None)
    return _LOCAL.get(kind or "") or _LOCAL["core"]


def explain(f: Facts) -> Reason:
    """Причина отказа по фактам — от того, что ясно без сети, к тому, что видно только по пробам."""
    if f.fatal:
        return _stopped(f.kind)
    if f.kind in ("killswitch", "unsupported"):
        return _LOCAL[f.kind]                    # сервер и не проверялся: что мешает — известно заранее
    if f.online is False:
        return _NO_INTERNET
    if f.expired:
        return _EXPIRED
    if f.traffic_out:
        return _TRAFFIC_OUT
    if f.device_limit:
        return _DEVICE_LIMIT
    if (f.timed and f.skew is not None and abs(f.skew) > CLOCK_TOLERANCE) or f.kind == "clock":
        return _clock(f.skew if f.skew is not None and abs(f.skew) > CLOCK_TOLERANCE else None)
    if f.dns is not None:
        return _dns(f)
    if f.udp:
        if f.peers_udp_ok:
            return _SERVER_DOWN
        return _UDP_BLOCKED if f.tcp_ok_anywhere else _UDP_SILENT
    if f.tcp == "refused":
        return _PORT_CLOSED
    if f.tcp in ("timeout", "unreachable") or (f.tcp is None and (f.peers_ok or f.peers_failed)):
        return _silent(f)
    if f.tcp == "reset" or f.handshake in ("reset", "timeout"):
        return _dpi(f)
    if f.kind == "tls":
        return _KEYS_OUTDATED
    if f.kind == "auth":
        return _AUTH_REJECTED
    if f.tcp == "ok":
        return _NO_EXIT
    return _UNKNOWN


def alert_text(reason: Reason) -> str:
    """Причина для плашки: почему, чья сторона, что сделать — одной строкой."""
    return f"{reason.text} Чья сторона: {SIDE_LABELS.get(reason.side, SIDE_LABELS['unknown'])}. {reason.advice}"


# error_kind страницы (заголовок и подсказка ошибки) для причины; не названные — «сервер не отвечает».
_ERROR_KINDS = {
    "port_busy": "port", "admin": "admin", "conflict": "conflict", "unsupported": "unsupported", "killswitch": "other",
    "helper_failed": "core", "core_failed": "core", "clock": "clock", "dpi": "tls", "keys_outdated": "tls",
    "bad_params": "auth", "auth_rejected": "auth", "sub_expired": "auth", "traffic_out": "auth",
    "device_limit": "auth", "no_exit": "other", "unknown": "other", "ipv6_only": "other",
}


def error_kind(reason: Reason) -> str:
    return _ERROR_KINDS.get(reason.code, "timeout")


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
            "text": ("Адаптер своего VPN остался после аварийного выхода. Интернету он не мешает. Если VPN не "
                     "включается или адаптер лишний, удалите его в «Диспетчере устройств», раздел «Сетевые "
                     "адаптеры».")})
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
