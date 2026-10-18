"""Подписки: загрузка, User-Agent, тело и заголовки ответа, подсказки провайдеру не в ущерб.

Загрузка — только https:// (http:// — с предупреждением), без смены схемы и без переходов на этот
компьютер и в локальную сеть, тело ≤ 5 МБ ПОСЛЕ распаковки gzip/deflate, тайм-аут 20 с. Маршрут
(напрямую или через служебный вход) выбирает менеджер: он передаёт готовый OpenerDirector.
Тело разбирается в детерминированном порядке (план 5.8): utf-8-sig → HTML → WireGuard .conf → JSON
(SIP008, Xray; sing-box и Clash YAML — понятный отказ) → мягкий base64 → построчно.
Адрес подписки — секрет: в тексты ошибок и журнал не попадает.
"""
from __future__ import annotations

import base64
import http.client
import ipaddress
import json
import re
import secrets
import socket
import ssl
import time
import urllib.error
import urllib.request
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping
from urllib.parse import unquote, urljoin, urlsplit, urlunsplit

from ..errors import UserError
from . import links, xrayjson
from .links import LinkError
from .model import UA_PRESETS, Group, Server, Subscription

MAX_BODY = 5 * 1024 * 1024
TIMEOUT = 20.0
MAX_REDIRECTS = 5
MAX_URL = 8192
MAX_UA = 256
MAX_TITLE = 100
MAX_DESCRIPTION = 500
MAX_ANNOUNCE = 200                    # как у Incy и Happ
MAX_SIP008 = 5000
MIN_HOURS, MAX_HOURS = 1, 72
_ERROR_BODY = 64 * 1024               # сколько тела ответа с ошибкой читать (для подсказок)
_COMPRESSED_SLACK = 64 * 1024         # сжатое тело не бывает заметно больше распакованного
_CHUNK = 64 * 1024
_MS_EXPIRE = 32_000_000_000           # expire больше — это миллисекунды (так считает Incy)
_REDIRECTS = (301, 302, 303, 307, 308)
UA_OPTIONS = ("v2rayn", "happ", "incy")

# Нейтральные сведения об устройстве: провайдеру нужен только сам HWID, модель и версия ему ни к чему.
HWID_DEVICE = {"X-Device-OS": "Windows", "X-Ver-OS": "10", "X-Device-Model": "PC"}

HTTP_WARNING = "Подписка загружена без шифрования (http://): провайдер или сеть могли её подменить"
HTML_TEXT = ("Пришла веб-страница, а не подписка: проверьте, что ссылка — именно подписка, "
             "или выберите другой User-Agent")
CLASH_TEXT = "Формат Clash (YAML) пока не поддерживается — выберите User-Agent «как v2rayN»"
SINGBOX_TEXT = "Формат sing-box (JSON) пока не поддерживается — выберите User-Agent «как v2rayN»"
EXTENDED_TEXT = ("Подписка пришла списком ссылок. Проверить расширенный формат — с группами «Самый быстрый» "
                 "и описаниями серверов?")
HWID_OFFER_TEXT = ("Провайдер выдаёт подписку только с идентификатором устройства (HWID). "
                   "Включить HWID для этой подписки?")
HWID_LIMIT_TEXT = "Провайдер сообщает: достигнут лимит устройств для этой подписки"


class SubscriptionError(UserError):
    """kind: http_status | html | empty | too_big | timeout | tls | scheme | network | format | ua | hwid.

    status — код HTTP; reason — уточнение (network: drop/dns/refused/other; format: clash/sing-box/
    json/encoding/compression/wireguard/amneziawg); fetched — ответ с ошибкой (для offer)."""

    def __init__(self, kind: str, text: str, *, status: int | None = None, reason: str | None = None,
                 fetched: Fetched | None = None):
        self.kind = kind
        self.status = status
        self.reason = reason
        self.fetched = fetched
        super().__init__(text)


@dataclass
class Fetched:
    status: int
    headers: dict[str, str] = field(repr=False)        # имена в нижнем регистре
    body: bytes = field(repr=False)                    # уже распакованное
    url: str = field(repr=False)                       # итоговый адрес после переходов — секрет
    user_agent: str = ""
    hwid: bool = False                                 # отправлялся ли X-HWID
    warning: str | None = None                         # загружено по http://


@dataclass
class SubMeta:
    title: str | None = None
    description: str | None = None
    update_hours: int | None = None                    # profile-update-interval, 1–72 ч
    userinfo: dict[str, int] = field(default_factory=dict)   # upload, download, total, expire (с)
    refill_at: float | None = None
    support_url: str | None = None
    web_page_url: str | None = None
    announce: str | None = None
    announce_url: str | None = None
    new_url: str | None = field(default=None, repr=False)          # адрес подписки — секрет
    new_domain: str | None = None
    fallback_urls: list[str] = field(default_factory=list, repr=False)
    hwid: dict[str, bool] = field(default_factory=dict)            # active, not_supported, limit, max_devices
    hwid_text: str | None = None
    routing: str | None = field(default=None, repr=False)         # заголовок routing — разбирает «Конфиг»


@dataclass
class Decoded:
    format: str                                        # model.SUB_FORMATS
    servers: list[Server] = field(default_factory=list)
    groups: list[Group] = field(default_factory=list)
    errors: list[tuple[int, LinkError]] = field(default_factory=list)   # (строка или номер записи, ошибка)
    meta: SubMeta = field(default_factory=SubMeta)
    routing: dict[str, Any] | None = field(default=None, repr=False)   # маршруты провайдера из JSON Xray
    route_lines: list[str] = field(default_factory=list)               # «://routing/…» из тела
    warnings: list[str] = field(default_factory=list)                  # что не разобрано в JSON Xray
    notices: list[str] = field(default_factory=list)                   # имена серверов-заглушек
    base64: bool = False                                                # тело пришло в base64


# ------------------------------------------------------------ User-Agent и HWID

def check_user_agent(text: str) -> str:
    """Свой UA: печатный ASCII без CR/LF, не длиннее 256 — иначе это была бы инъекция заголовка."""
    value = (text or "").strip()
    if not value or len(value) > MAX_UA or any(not 0x20 <= ord(ch) <= 0x7E for ch in value):
        raise SubscriptionError("ua", f"User-Agent: только латиница (ASCII), без переводов строк, не длиннее {MAX_UA} "
                                      "символов")
    return value


def user_agent(sub: Subscription, app_version: str) -> str:
    """UA подписки по пресету: честный Lazeyka/<версия> (Windows), «как v2rayN/Happ/Incy» или свой."""
    preset = sub.ua_preset if sub.ua_preset in UA_PRESETS else "lazeyka"
    if preset == "custom":
        return check_user_agent(sub.user_agent or "")
    return UA_PRESETS[preset] or f"Lazeyka/{app_version} (Windows)"


def new_hwid() -> str:
    """Случайный идентификатор подписки вместо настоящего HWID (Remnawave ждёт 10–64 символа [A-Za-z0-9=-])."""
    return secrets.token_hex(16)


def _hwid_headers(hwid: str) -> dict[str, str]:
    if not re.fullmatch(r"[A-Za-z0-9=_-]{8,128}", hwid or ""):
        raise SubscriptionError("hwid", "Идентификатор устройства (HWID) подписки повреждён — выключите HWID "
                                        "у подписки и включите заново")
    return {"X-HWID": hwid, **HWID_DEVICE}


# ------------------------------------------------------------ адрес и загрузка

_LOCAL_SUFFIXES = (".localhost", ".local", ".home.arpa", ".internal", ".lan")
_NUMERIC_HOST = re.compile(r"(?:0x[0-9a-f]+|\d+)(?:\.(?:0x[0-9a-f]+|\d+)){0,3}")


def _ip_of(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        if not _NUMERIC_HOST.fullmatch(host):
            return None
        try:                                   # «2130706433», «127.1», «0x7f.1» — тоже 127.0.0.1 для Windows
            ip = ipaddress.IPv4Address(socket.inet_aton(host))
        except OSError:
            return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return ip.ipv4_mapped
    return ip


def _is_local(host: str) -> bool:
    if host == "localhost" or host.endswith(_LOCAL_SUFFIXES):
        return True
    ip = _ip_of(host)
    if ip is not None:
        return not ip.is_global
    return "." not in host                     # одно слово («router») — имя из локальной сети


def check_url(url: str, *, allow_local: bool = False) -> str:
    """Адрес подписки для загрузки: https/http, нормальный хост (IDN → punycode), без фрагмента.
    allow_local — только для тестов с сервером на 127.0.0.1."""
    text = (url or "").strip()
    if not text or len(text) > MAX_URL or re.search(r"[\s\x00-\x1f\x7f]", text):
        raise SubscriptionError("scheme", "Адрес подписки пустой, слишком длинный или с пробелами")
    parts = urlsplit(text)
    scheme = parts.scheme.lower()
    if scheme not in ("https", "http"):
        raise SubscriptionError("scheme", "Подписка загружается только по https://")
    try:
        port = parts.port
        host = links.normalize_host(parts.hostname or "")
    except (ValueError, LinkError):
        raise SubscriptionError("scheme", "В адресе подписки неверный сервер или порт") from None
    if not allow_local and _is_local(host):
        raise SubscriptionError("scheme", "Адрес подписки ведёт на этот компьютер или в локальную сеть — "
                                          "туда Лазейка подписки не загружает")
    userinfo = parts.netloc.rpartition("@")[0]
    netloc = (f"{userinfo}@" if userinfo else "") + (f"[{host}]" if ":" in host else host)
    if port is not None:
        netloc += f":{port}"
    return urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))


class _StopRedirects(dict):
    """redirect_dict, на котором стандартный HTTPRedirectHandler останавливается на первом переходе
    (len ≥ max_redirections) и отдаёт HTTPError 3xx: переходы fetch проверяет и делает сам — какой бы
    opener ни дал менеджер."""

    def __len__(self) -> int:
        return 1 << 30


def _request(url: str, headers: dict[str, str]) -> urllib.request.Request:
    parts = urlsplit(url)
    userinfo, _, hostport = parts.netloc.rpartition("@")
    request_headers = dict(headers)
    if userinfo:                               # https://логин:пароль@… — Basic-авторизация, как у v2rayN
        user, _, password = userinfo.partition(":")
        pair = f"{unquote(user)}:{unquote(password)}".encode("utf-8")
        request_headers["Authorization"] = "Basic " + base64.b64encode(pair).decode("ascii")
        url = urlunsplit((parts.scheme, hostport, parts.path, parts.query, ""))
    request = urllib.request.Request(url, headers=request_headers, method="GET")
    request.redirect_dict = _StopRedirects()
    return request


def _next_url(current: str, location: str | None, allow_local: bool) -> str:
    if not location or not location.strip():
        raise SubscriptionError("network", "Сервер подписки прислал перенаправление без адреса", reason="other")
    try:
        target = check_url(urljoin(current, location.strip()), allow_local=allow_local)
    except SubscriptionError as exc:
        raise SubscriptionError("scheme", f"Сервер подписки перенаправил на недопустимый адрес: {exc}") from None
    if urlsplit(current).scheme == "https" and urlsplit(target).scheme == "http":
        raise SubscriptionError("scheme", "Сервер подписки перенаправил на незащищённый http:// — переход отклонён")
    return target


def _fix_latin1(value: str) -> str:
    """http.client читает заголовки как latin-1; UTF-8 провайдера возвращаем как было."""
    try:
        return value.encode("latin-1").decode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError):
        return value


def _headers(message: Any) -> dict[str, str]:
    result: dict[str, str] = {}
    for key, value in (message.items() if message is not None else []):
        name = str(key).strip().lower()
        if name and name not in result:
            result[name] = _fix_latin1(str(value)).strip()
    return result


def _too_big(limit: int) -> SubscriptionError:
    size = f"{limit // (1024 * 1024)} МБ" if limit >= 1024 * 1024 else f"{max(limit // 1024, 1)} КБ"
    return SubscriptionError("too_big", f"Подписка больше {size} — так много серверов не бывает, загрузка остановлена")


class _Body:
    """Тело с лимитом ПОСЛЕ распаковки: gzip-бомба упирается в лимит, а не в память."""

    def __init__(self, encoding: str, limit: int):
        self.limit = limit
        self.out = bytearray()
        self.raw = 0
        self.decompressor: Any = None
        self.deflate = False
        name = (encoding or "").strip().lower()
        if name in ("gzip", "x-gzip"):
            self.decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
        elif name == "deflate":
            self.deflate = True                # zlib или «сырой» deflate — видно по первым байтам
        elif name not in ("", "identity"):
            raise SubscriptionError("format", f"Сервер подписки прислал сжатие «{name[:20]}», которое Лазейка "
                                              "не понимает", reason="compression")

    def _too_big(self) -> SubscriptionError:
        return _too_big(self.limit)

    def feed(self, chunk: bytes) -> None:
        self.raw += len(chunk)
        if self.raw > self.limit + _COMPRESSED_SLACK:
            raise self._too_big()
        if self.deflate and self.decompressor is None:
            zlib_header = len(chunk) >= 2 and chunk[0] & 0x0F == 8 and ((chunk[0] << 8) | chunk[1]) % 31 == 0
            self.decompressor = zlib.decompressobj(zlib.MAX_WBITS if zlib_header else -zlib.MAX_WBITS)
        if self.decompressor is None:
            self.out += chunk
        else:
            try:
                self.out += self.decompressor.decompress(chunk, self.limit + 1 - len(self.out))
            except zlib.error:
                raise SubscriptionError("format", "Сжатый ответ сервера подписки повреждён",
                                        reason="compression") from None
            if self.decompressor.unconsumed_tail:
                raise self._too_big()
        if len(self.out) > self.limit:
            raise self._too_big()

    def finish(self) -> bytes:
        if self.decompressor is not None:
            try:
                self.out += self.decompressor.flush()
            except zlib.error:
                raise SubscriptionError("format", "Сжатый ответ сервера подписки повреждён",
                                        reason="compression") from None
            if len(self.out) > self.limit:
                raise self._too_big()
        return bytes(self.out)


def _read(response: Any, limit: int, deadline: float | None) -> bytes:
    length = (response.headers.get("Content-Length") or "").strip() if response.headers else ""
    if length.isdigit() and int(length) > limit + _COMPRESSED_SLACK:
        raise _too_big(limit)
    body = _Body(response.headers.get("Content-Encoding", "") if response.headers else "", limit)
    read = getattr(response, "read1", None) or response.read
    while True:
        if deadline is not None and time.monotonic() > deadline:
            raise SubscriptionError("timeout", "Сервер подписки отдаёт ответ слишком медленно")
        chunk = read(_CHUNK)
        if not chunk:
            return body.finish()
        body.feed(chunk)


def _read_quietly(response: Any) -> bytes:
    """Начало тела ответа с ошибкой — только для подсказок; что не прочиталось, не важно."""
    try:
        return _read(response, _ERROR_BODY, None)
    except (SubscriptionError, OSError, http.client.HTTPException, ValueError):
        return b""


def _status_text(code: int) -> str:
    if code in (401, 403):
        return f"Провайдер отказал в доступе к подписке (код {code})"
    if code in (404, 410):
        return f"Подписка не найдена (код {code}) — возможно, её удалили или ссылка устарела"
    if code == 451:
        return "Провайдер не отдаёт подписку этому приложению (код 451)"
    if code == 429:
        return "Провайдер просит подождать: слишком много запросов (код 429)"
    if code >= 500:
        return f"Сервер подписки неисправен (код {code}) — попробуйте позже"
    return f"Сервер подписки ответил кодом {code}"


_CERT_HINTS = {9: "часы компьютера сбиты или сертификат ещё не действует",
               10: "сертификат просрочен или часы компьютера сбиты",
               62: "сертификат выдан другому сайту — возможна подмена",
               18: "нет доверия к издателю — возможна подмена", 19: "нет доверия к издателю — возможна подмена",
               20: "нет доверия к издателю — возможна подмена", 21: "нет доверия к издателю — возможна подмена"}


def _transport_error(exc: BaseException) -> SubscriptionError:
    """Ошибка связи → SubscriptionError по тому, что известно об исключении (без адреса подписки)."""
    reason: Any = exc.reason if isinstance(exc, urllib.error.URLError) else exc
    if isinstance(reason, TimeoutError):
        return SubscriptionError("timeout", "Сервер подписки не ответил вовремя")
    if isinstance(reason, ssl.SSLCertVerificationError):
        hint = _CERT_HINTS.get(getattr(reason, "verify_code", 0), "сертификат не прошёл проверку")
        return SubscriptionError("tls", f"Сертификат сервера подписки не принят: {hint}")
    if isinstance(reason, ssl.SSLError):
        return SubscriptionError("tls", f"Не удалось установить защищённое соединение с сервером подписки "
                                        f"({getattr(reason, 'reason', None) or type(reason).__name__})")
    if isinstance(reason, socket.gaierror):
        return SubscriptionError("network", "Не удалось найти сервер подписки по имени (DNS)", reason="dns")
    if isinstance(reason, ConnectionRefusedError):
        return SubscriptionError("network", "Сервер подписки не принимает соединения", reason="refused")
    if isinstance(reason, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError,
                           http.client.RemoteDisconnected, http.client.IncompleteRead)):
        return SubscriptionError("network", "Сервер подписки оборвал соединение", reason="drop")
    if isinstance(reason, http.client.HTTPException):
        return SubscriptionError("network", "Сервер подписки прислал повреждённый ответ", reason="drop")
    if isinstance(reason, OSError):
        detail = reason.strerror or type(reason).__name__
        return SubscriptionError("network", f"Нет связи с сервером подписки ({detail})", reason="other")
    return SubscriptionError("network", "Нет связи с сервером подписки", reason="other")


def fetch(url: str, *, user_agent: str, hwid: str | None = None, opener: urllib.request.OpenerDirector,
          timeout: float = TIMEOUT, limit: int = MAX_BODY, allow_local: bool = False) -> Fetched:
    """Скачать подписку. Ответ не 2xx — SubscriptionError("http_status") с .fetched для offer()."""
    current = check_url(url, allow_local=allow_local)
    headers = {"User-Agent": check_user_agent(user_agent), "Accept": "*/*", "Accept-Encoding": "gzip, deflate"}
    if hwid:
        headers.update(_hwid_headers(hwid))
    deadline = time.monotonic() + timeout
    for _ in range(MAX_REDIRECTS + 1):
        request = _request(current, headers)
        try:
            response = opener.open(request, timeout=timeout)
        except urllib.error.HTTPError as exc:
            try:
                if exc.code in _REDIRECTS:
                    current = _next_url(current, exc.headers.get("Location") if exc.headers else None, allow_local)
                    continue
                fetched = Fetched(exc.code, _headers(exc.headers), _read_quietly(exc), current,
                                  user_agent=headers["User-Agent"], hwid=bool(hwid))
            finally:
                exc.close()
            raise SubscriptionError("http_status", _status_text(exc.code), status=exc.code, fetched=fetched) from None
        except (urllib.error.URLError, OSError, http.client.HTTPException, ValueError) as exc:
            raise _transport_error(exc) from None
        try:
            with response:
                final = response.geturl() or current
                if final != request.full_url:      # opener сам прошёл по переходу — проверяем итог
                    current = _next_url(current, final, allow_local)
                status = int(getattr(response, "status", None) or response.getcode() or 200)
                body = _read(response, limit, deadline)
                response_headers = _headers(response.headers)
        except SubscriptionError:
            raise
        except (OSError, http.client.HTTPException, ValueError) as exc:
            raise _transport_error(exc) from None
        warning = HTTP_WARNING if urlsplit(current).scheme == "http" else None
        return Fetched(status, response_headers, body, current, user_agent=headers["User-Agent"], hwid=bool(hwid),
                       warning=warning)
    raise SubscriptionError("network", "Слишком много перенаправлений у сервера подписки", reason="other")


# ------------------------------------------------------------ тело

_YAML = re.compile(r"^(?:proxies|proxy-groups|proxy-providers|mixed-port)\s*:", re.M)
_HTML_MARKERS = ("<html", "<!doctype html", "<head", "<body")


def looks_like_html(text: str) -> bool:
    head = text[:1024].lstrip().lower()
    return head.startswith("<") and any(marker in head for marker in _HTML_MARKERS)


def _value(item: Mapping[str, Any], key: str) -> str:
    value = item.get(key)
    return "" if value is None or isinstance(value, (dict, list, bool)) else str(value).strip()


def _sip008(items: list[Any]) -> Decoded:
    decoded = Decoded("sip008")
    seen: set[str] = set()
    for number, item in enumerate(items[:MAX_SIP008], start=1):
        if not isinstance(item, dict):
            decoded.errors.append((number, LinkError("bad_value", "запись SIP008")))
            continue
        try:
            host = links.normalize_host(_value(item, "server"))
            port = links.check_port(item.get("server_port"))
            plugin_name = _value(item, "plugin")
            plugin = links.parse_plugin(f"{plugin_name};{_value(item, 'plugin_opts')}") if plugin_name else None
            password = item.get("password")
            server = links.make_shadowsocks(host, port, _value(item, "method"),
                                            "" if password is None else str(password), plugin)
        except LinkError as exc:
            decoded.errors.append((number, exc))
            continue
        server.name, server.source = _value(item, "remarks"), "sip008"
        links.finish(server)
        if server.id in seen:
            decoded.errors.append((number, LinkError("duplicate")))
            continue
        seen.add(server.id)
        decoded.servers.append(server)
    return decoded


def _decode_json(obj: Any, sub_id: str | None) -> Decoded:
    if isinstance(obj, dict) and _value(obj, "type").lower() == "amneziawg":
        raise SubscriptionError("format", links.AMNEZIA_TEXT, reason="amneziawg")
    if isinstance(obj, dict) and isinstance(obj.get("servers"), list) and "outbounds" not in obj:
        return _sip008(obj["servers"])
    if isinstance(obj, list) and obj and all(isinstance(x, dict) and "server_port" in x for x in obj):
        return _sip008(obj)                    # голый массив SIP008 (так принимает и v2rayN)
    configs = obj if isinstance(obj, list) else [obj]
    outbounds = [ob for config in configs if isinstance(config, dict)
                 for ob in (config.get("outbounds") or []) if isinstance(ob, dict)]
    if any("protocol" in ob for ob in outbounds):
        imported = xrayjson.parse(obj, sub=sub_id)
        return Decoded("xray-json", servers=imported.servers, groups=imported.groups, routing=imported.routing,
                       warnings=imported.warnings)
    if any("type" in ob for ob in outbounds):
        raise SubscriptionError("format", SINGBOX_TEXT, reason="sing-box")
    raise SubscriptionError("format", "Непонятный JSON: это не подписка", reason="json")


def _base64_text(text: str) -> str | None:
    try:
        inner = links.b64decode_text(text).lstrip("\ufeff")
    except ValueError:
        return None
    if not inner.strip() or any(not (ch.isprintable() or ch in "\r\n\t") for ch in inner):
        return None
    return inner


def _decode_text(text: str, sub_id: str | None, *, nested: bool) -> tuple[Decoded, dict[str, str]]:
    """(разобранное тело, строки «#ключ: значение»)."""
    stripped = text.strip().lstrip("\ufeff").strip()
    if looks_like_html(stripped):
        raise SubscriptionError("html", HTML_TEXT)
    if links.looks_like_conf(stripped):
        try:
            return Decoded("links", servers=links.parse_wireguard_conf(stripped)), {}
        except LinkError as exc:
            raise SubscriptionError("format", str(exc),
                                    reason="amneziawg" if exc.code == "amneziawg" else "wireguard") from None
    if stripped[:1] in ("{", "["):
        try:
            obj = json.loads(stripped)
        except ValueError:
            raise SubscriptionError("format", "Подписка похожа на JSON, но он повреждён", reason="json") from None
        return _decode_json(obj, sub_id), {}
    if _YAML.search(stripped):
        raise SubscriptionError("format", CLASH_TEXT, reason="clash")
    if "://" not in stripped and not nested:
        inner = _base64_text(stripped)
        if inner is not None:
            decoded, meta = _decode_text(inner, sub_id, nested=True)
            decoded.base64 = True
            return decoded, meta
    parsed = links.parse_text(stripped, decode_base64=False)   # base64 здесь уже снят (или его не было)
    return Decoded("links", servers=parsed.servers, errors=parsed.errors, route_lines=parsed.route_lines), parsed.meta


def _is_stub(server: Server) -> bool:
    """Заглушка провайдера: «серверы» на 0.0.0.0, 127.x, ::1 или с портом ≤ 1 — это текст, а не сервер."""
    host = server.host
    return host in ("0.0.0.0", "::", "::1", "localhost") or host.startswith("127.") or server.port <= 1


def _split_stubs(decoded: Decoded) -> None:
    stubs = [s for s in decoded.servers if _is_stub(s)]
    if not stubs:
        return
    decoded.notices = [s.name or f"{s.host}:{s.port}" for s in stubs]
    stub_ids = {s.id for s in stubs}
    decoded.servers = [s for s in decoded.servers if s.id not in stub_ids]
    for group in decoded.groups:
        group.members = [m for m in group.members if m not in stub_ids]
        if group.fallback in stub_ids:
            group.fallback = None
    decoded.groups = [g for g in decoded.groups if g.members]


def decode(body: bytes, headers: Mapping[str, str] | None = None, *, sub_id: str | None = None) -> Decoded:
    """Тело и заголовки подписки (или текст из поля импорта) → Decoded. Целиком негодное тело —
    SubscriptionError (empty, html, format, too_big); незнакомые строки — в errors, не в отказ."""
    if not body or not body.strip():
        raise SubscriptionError("empty", "Провайдер прислал пустой ответ — серверов нет")
    if len(body) > MAX_BODY:
        raise _too_big(MAX_BODY)
    try:
        text = body.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise SubscriptionError("format", "Подписка не в кодировке UTF-8", reason="encoding") from None
    if not text.strip():
        raise SubscriptionError("empty", "Провайдер прислал пустой ответ — серверов нет")
    decoded, body_meta = _decode_text(text, sub_id, nested=False)
    decoded.meta = sub_meta(headers or {}, body_meta)
    _split_stubs(decoded)
    for server in decoded.servers:
        server.sub = sub_id
    return decoded


# ------------------------------------------------------------ заголовки

# Что провайдер может передать и строкой «#ключ: значение» в теле (заголовок важнее, как у Incy и Happ).
_BODY_KEYS = frozenset({"profile-title", "subscription-name", "profile-description", "profile-update-interval",
                        "subscription-userinfo", "subscription-refill-date", "support-url", "profile-web-page-url",
                        "homepage", "announce", "announce-url", "new-url", "new-domain", "fallback-url", "routing"})
_HWID_FLAGS = (("x-hwid-active", "active"), ("x-hwid-not-supported", "not_supported"),
               ("x-hwid-limit", "limit"), ("x-hwid-max-devices-reached", "max_devices"))


def _lower(headers: Mapping[str, str] | None) -> dict[str, str]:
    return {str(k).strip().lower(): str(v) for k, v in (headers or {}).items()}


def _decoded_value(value: str | None) -> str | None:
    """«base64:…» → текст (UTF-8); битый base64 — None, а не мусор."""
    if not value:
        return None
    if value[:7].lower() == "base64:":
        try:
            return links.b64decode_text(value[7:])
        except ValueError:
            return None
    return value


def _multiline(text: str | None, limit: int) -> str | None:
    if not text:
        return None
    cleaned = re.sub(r"[\x00-\x09\x0b-\x1f\x7f]", " ", text.replace("\r\n", "\n").replace("\r", "\n")).strip()
    if len(cleaned) > limit:
        cleaned = cleaned[:limit - 1].rstrip() + "…"
    return cleaned or None


def _https(value: str | None) -> str | None:
    """Только https и без мусора: ссылки провайдера открываются в браузере по кнопке."""
    text = (value or "").strip()
    if not text or len(text) > MAX_URL or re.search(r"[\s\x00-\x1f\x7f]", text):
        return None
    parts = urlsplit(text)
    return text if parts.scheme.lower() == "https" and parts.hostname else None


def _hours(value: str | None) -> int | None:
    text = (value or "").strip()
    if not text.isdigit():
        return None
    hours = int(text)
    return hours if MIN_HOURS <= hours <= MAX_HOURS else None


def _userinfo(value: str | None) -> dict[str, int]:
    result: dict[str, int] = {}
    for part in (value or "").split(";"):
        key, _, number = part.partition("=")
        key, number = key.strip().lower(), number.strip()
        if key in ("upload", "download", "total", "expire") and re.fullmatch(r"\d+(?:\.\d+)?", number):
            amount = int(number) if number.isdigit() else int(float(number))
            if key == "expire" and amount > _MS_EXPIRE:
                amount //= 1000
            result[key] = amount
    return result


def _timestamp(value: str | None) -> float | None:
    text = (value or "").strip()
    if not text:
        return None
    if text.isdigit():
        number = int(text)
        return float(number // 1000 if number > _MS_EXPIRE else number)
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.timestamp()


def _disposition_name(value: str | None) -> str | None:
    """Имя файла из content-disposition — запасное название подписки (без .txt/.yaml/.json)."""
    if not value:
        return None
    match = re.search(r"filename\*\s*=\s*(?:utf-8)?'[^']*'([^;]+)", value, re.I)
    if match:
        name = unquote(match.group(1).strip().strip('"'))
    else:
        match = re.search(r'filename\s*=\s*"([^"]*)"', value, re.I) or re.search(r"filename\s*=\s*([^;]+)", value, re.I)
        name = match.group(1).strip() if match else ""
    name = re.sub(r"\.(?:txt|ya?ml|json|conf)$", "", links.clean_text(name, MAX_TITLE), flags=re.I).strip()
    return name or None


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in ("1", "true", "yes", "on")


def hwid_flags(headers: Mapping[str, str] | None) -> dict[str, bool]:
    lower = _lower(headers)
    return {key: True for header, key in _HWID_FLAGS if _truthy(lower.get(header))}


def _hwid_text(flags: Mapping[str, bool]) -> str | None:
    if flags.get("max_devices"):
        return HWID_LIMIT_TEXT
    if flags.get("not_supported"):
        return "Провайдер выдаёт подписку только с идентификатором устройства (HWID)"
    if flags.get("limit") or flags.get("active"):
        return "Провайдер ограничивает подписку по числу устройств (HWID)"
    return None


def sub_meta(headers: Mapping[str, str], body: Mapping[str, str] | None = None) -> SubMeta:
    """SubMeta из заголовков; строки «#ключ: значение» тела — запасной источник. x-hwid-* — только заголовки."""
    lower = _lower(headers)
    from_body = {k: v for k, v in (body or {}).items() if k in _BODY_KEYS}

    def get(name: str) -> str | None:
        value = lower.get(name)
        if value is None or not value.strip():
            value = from_body.get(name)
        return value.strip() if value and value.strip() else None

    meta = SubMeta()
    title = _decoded_value(get("profile-title") or get("subscription-name"))
    if title:
        first, _, rest = title.replace("\r\n", "\n").partition("\n")   # Incy: первая строка — имя, дальше — описание
        meta.title = links.clean_text(first, MAX_TITLE) or None
        meta.description = _multiline(rest, MAX_DESCRIPTION)
    meta.title = meta.title or _disposition_name(lower.get("content-disposition"))
    meta.description = _multiline(_decoded_value(get("profile-description")), MAX_DESCRIPTION) or meta.description
    meta.update_hours = _hours(get("profile-update-interval"))
    meta.userinfo = _userinfo(get("subscription-userinfo"))
    meta.refill_at = _timestamp(get("subscription-refill-date"))
    meta.support_url = _https(get("support-url"))
    meta.web_page_url = _https(get("profile-web-page-url")) or _https(get("homepage"))
    meta.announce = _multiline(_decoded_value(get("announce")), MAX_ANNOUNCE)
    meta.announce_url = _https(get("announce-url"))
    meta.new_url = _https(get("new-url"))
    try:
        meta.new_domain = links.normalize_host(get("new-domain") or "") if get("new-domain") else None
    except LinkError:
        meta.new_domain = None
    fallback = _https(get("fallback-url"))
    meta.fallback_urls = [fallback] if fallback else []
    meta.hwid = hwid_flags(lower)
    meta.hwid_text = _hwid_text(meta.hwid)
    meta.routing = get("routing")
    return meta


# ------------------------------------------------------------ подсказки

def _ua_options(fetched: Fetched | None) -> list[str]:
    used = fetched.user_agent if fetched else ""
    return [preset for preset in UA_OPTIONS if UA_PRESETS.get(preset) != used]


def _ua_offer(fetched: Fetched | None, why: str) -> dict[str, Any] | None:
    options = _ua_options(fetched)
    if not options:
        return None
    return {"kind": "ua", "text": f"Провайдер не отдал подписку этому приложению ({why}). "
                                  "Попробовать как v2rayN, Happ или Incy?", "options": options}


def offer(fetched: Fetched | None, decoded: Decoded | None, error: SubscriptionError | None = None
          ) -> dict[str, Any] | None:
    """Что предложить человеку после загрузки: {kind: ua|hwid|html|stub|extended, text, options} или None.
    Чужой UA сами не подставляем — только предлагаем (провайдер считает устройства по UA)."""
    if fetched is None and error is not None:
        fetched = error.fetched
    flags = hwid_flags(fetched.headers if fetched else None)
    nothing = error is not None or decoded is None or not decoded.servers
    if flags.get("max_devices"):
        return {"kind": "hwid", "text": HWID_LIMIT_TEXT, "options": []}
    if nothing and (flags.get("not_supported") or flags.get("limit") or flags.get("active")):
        if fetched is not None and not fetched.hwid:
            return {"kind": "hwid", "text": HWID_OFFER_TEXT, "options": ["hwid"]}
        return None
    if error is not None:
        if error.kind == "html":
            return {"kind": "html", "text": HTML_TEXT, "options": _ua_options(fetched)}
        if error.kind == "http_status" and error.status in (403, 404, 451):
            return _ua_offer(fetched, f"код {error.status}")
        if error.kind == "empty":
            return _ua_offer(fetched, "пустой ответ")
        if error.kind == "network" and error.reason == "drop":
            return _ua_offer(fetched, "обрыв соединения")
        if error.kind == "format" and error.reason in ("clash", "sing-box"):
            return _ua_offer(fetched, "формат для другого приложения")
        return None
    if decoded is None:
        return None
    if not decoded.servers and decoded.notices:
        return {"kind": "stub", "text": "; ".join(decoded.notices)[:MAX_DESCRIPTION], "options": []}
    if not decoded.servers:
        return _ua_offer(fetched, "в ответе нет серверов")
    if (decoded.format == "links" and decoded.base64 and fetched is not None
            and fetched.user_agent.startswith("Lazeyka/")):
        return {"kind": "extended", "text": EXTENDED_TEXT, "options": list(UA_OPTIONS)}
    return None
