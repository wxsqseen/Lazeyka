"""Ссылки серверов: vless, vmess, ss, trojan, hysteria2, tuic, socks, wireguard и файлы WireGuard .conf.

Разбор ничего не знает о ядрах: что и каким ядром открыть, решает model.engine_for. Правила —
docs/vpnclient-plan.md, 5.8: query разбирается вручную (parse_qs превращает «+» в пробел и делит по
всем «=»), значения декодируются ровно один раз, base64 мягкий (url-safe алфавит, без паддинга,
с переносами), IPv6 — только в [], IDN — в punycode. Отказ — LinkError с кодом и фактическим
значением; секреты (UUID, пароли, ключи, сама ссылка) в текст ошибки не попадают.
"""
from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote, unquote

from ..errors import UserError
from .model import Server, split_flag

try:
    import idna as _idna      # IDNA 2008 (зависимость httpx); без него — встроенный кодек IDNA 2003
except ImportError:            # pragma: no cover
    _idna = None

MAX_LINK = 64 * 1024           # ссылка с pqv (ML-DSA) длиннее 2,6 КБ, а extra у XHTTP бывает ещё больше
MAX_NAME = 200
_VALUE_IN_TEXT = 120           # сколько фактического значения показывать в ошибке

ENCRYPTED_TEXT = ("Зашифрованная ссылка для Happ/Incy — Лазейка не расшифровывает чужие ссылки, "
                  "возьмите у провайдера обычную ссылку https://…")
AMNEZIA_TEXT = "AmneziaWG пока не поддерживается: нужен клиент AmneziaWG"
_LEGACY_XTLS_TEXT = "Устаревший XTLS удалён из ядер — нужен сервер с TLS или REALITY и xtls-rprx-vision"

_TEXTS = {
    "empty": "Пустая строка",
    "too_long": "Слишком длинная строка: {value} символов",
    "not_a_link": "Это не ссылка на сервер",
    "unknown_scheme": "Незнакомая ссылка {value}://",
    "unsupported_scheme": "{value} пока не поддерживается",
    "unsupported_format": "Формат ссылки «{value}» пока не поддерживается",
    "subscription_url": "Это адрес подписки, а не сервер",
    "encrypted_link": ENCRYPTED_TEXT,
    "app_command": "Это команда другого приложения ({value}), а не подписка или сервер",
    "route_profile": "Это профиль маршрутизации другого приложения, а не подписка или сервер",
    "bad_wrapper": "В ссылке {value}:// нет адреса подписки или сервера",
    "nested_wrapper": "Ссылка-обёртка внутри другой обёртки",
    "no_host": "Нет адреса сервера",
    "bad_host": "Неверный адрес сервера: {value}",
    "ipv6_without_brackets": "IPv6-адрес нужно писать в квадратных скобках: {value}",
    "no_port": "Не указан порт",
    "bad_port": "Неверный порт: {value}",
    "no_uuid": "Нет идентификатора пользователя (UUID)",
    "no_password": "Нет пароля",
    "no_key": "Нет ключа WireGuard: {value}",
    "bad_base64": "Не удалось раскодировать base64 в ссылке {value}",
    "bad_json": "Внутри ссылки {value} повреждённый JSON",
    "bad_value": "Неверное значение {value}",
    "unsupported_transport": "Транспорт {value} не поддерживается",
    "unsupported_security": "Защита {value} не поддерживается",
    "unsupported_flow": "Неизвестный flow: {value}",
    "reality_without_pbk": "REALITY без открытого ключа (pbk)",
    "unsupported_method": "Шифр Shadowsocks {value} не поддерживается",
    "unsupported_obfs": "Обфускация {value} не поддерживается",
    "amneziawg": AMNEZIA_TEXT,
    "bad_conf": "Неверный файл WireGuard: {value}",
    "duplicate": "Такой сервер уже есть выше",
}


class LinkError(UserError):
    """Ссылка не разобрана. code — для программы и тестов, value — фактическое значение (не секрет)."""

    def __init__(self, code: str, value: object = None, *, text: str | None = None):
        self.code = code
        self.value = None if value is None else str(value)
        if text is None:
            shown = "" if self.value is None else self.value[:_VALUE_IN_TEXT]
            text = _TEXTS.get(code, code).format(value=shown)
        super().__init__(text)


@dataclass
class ParseResult:
    servers: list[Server] = field(default_factory=list)
    errors: list[tuple[int, LinkError]] = field(default_factory=list)   # (номер строки с 1, ошибка)
    meta: dict[str, str] = field(default_factory=dict, repr=False)      # «#ключ: значение» (бывает #new-url с токеном)
    route_lines: list[str] = field(default_factory=list)                # «…://routing/…», «happ://routing/…»


# ------------------------------------------------------------ общие помощники (и для xrayjson, subscription)

_URLSAFE = str.maketrans("-_", "+/")
_SPACES = re.compile(r"\s+")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_HOSTNAME = re.compile(r"(?=.{1,253}$)[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?"
                       r"(?:\.[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)*")
_PORT = re.compile(r"\d{1,5}", re.ASCII)
# В текст ошибки — только то, что похоже на порт или IPv6: в кривой ссылке без «@» на месте порта
# оказывается пароль («socks://user:pass»), а его показывать нельзя.
_PORT_LIKE = re.compile(r"[\d,\- ]{1,64}", re.ASCII)
_IPV6_LIKE = re.compile(r"[0-9A-Fa-f:.]{2,64}", re.ASCII)


def b64decode_soft(text: str) -> bytes:
    """Мягкий base64: оба алфавита, без паддинга, с переносами и пробелами. ValueError — это не base64."""
    data = _SPACES.sub("", text).translate(_URLSAFE).rstrip("=")
    if not data or len(data) % 4 == 1:
        raise ValueError("не base64")
    try:
        return base64.b64decode(data + "=" * (-len(data) % 4), validate=True)
    except binascii.Error as exc:
        raise ValueError("не base64") from exc


def b64decode_text(text: str) -> str:
    """base64 → UTF-8 текст; ValueError — не base64 или не UTF-8."""
    try:
        return b64decode_soft(text).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("не UTF-8") from exc


def clean_text(value: object, limit: int = MAX_NAME) -> str:
    """Строка для показа: без управляющих символов, обрезанная."""
    return _CONTROL.sub(" ", str(value or "")).strip()[:limit]


def _to_ascii(host: str) -> str:
    if host.isascii():
        return host
    try:
        if _idna is not None:
            return _idna.encode(host, uts46=True).decode("ascii")
        return host.encode("idna").decode("ascii")
    except (UnicodeError, ValueError) as exc:
        raise LinkError("bad_host", host) from exc


def normalize_host(raw: str, *, ipv6: bool = False) -> str:
    """Хост без [], в нижнем регистре, IDN — в punycode; IPv6 проверяется как адрес."""
    host = unquote(str(raw or "")).strip()
    if host.startswith("[") and host.endswith("]"):
        host, ipv6 = host[1:-1], True
    if not host:
        raise LinkError("no_host")
    if ipv6 or ":" in host:
        try:
            ipaddress.IPv6Address(host)
        except ValueError as exc:
            raise LinkError("bad_host", host) from exc
        return host.lower()
    host = _to_ascii(host).lower().rstrip(".")
    if not _HOSTNAME.fullmatch(host):
        raise LinkError("bad_host", host)
    return host


def check_port(raw: object) -> int:
    if isinstance(raw, bool):
        raise LinkError("bad_port", raw)
    text = str(raw).strip() if raw is not None else ""
    if not _PORT.fullmatch(text) or not 1 <= int(text) <= 65535:
        raise LinkError("bad_port", text if _PORT_LIKE.fullmatch(text) else "не число")
    return int(text)


def finish(server: Server) -> Server:
    """Имя без флага, страна по флагу, id = key()."""
    server.country, server.name = split_flag(clean_text(server.name))
    server.id = server.key()
    return server


def csv(value: object) -> list[str]:
    if isinstance(value, (list, tuple)):
        items = [str(v) for v in value]
    else:
        items = str(value or "").split(",")
    return [item.strip() for item in items if item and item.strip()]


def _truthy(value: object) -> bool:
    return str(value).strip().lower() in ("1", "true", "yes", "on") if value is not None else False


def _json_object(text: str, name: str) -> dict[str, Any]:
    try:
        value = json.loads(text)
    except ValueError as exc:
        raise LinkError("bad_value", name) from exc
    if not isinstance(value, dict):
        raise LinkError("bad_value", name)
    return value


# ------------------------------------------------------------ ссылка по частям

_SCHEME = re.compile(r"([A-Za-z][A-Za-z0-9+.\-]*)://")


@dataclass
class _Parts:
    scheme: str
    userinfo: str | None           # как в ссылке, без декодирования
    hostport: str
    query: str
    fragment: str


def _split(text: str) -> _Parts:
    """Делит ссылку вручную: urlsplit не понимает мультипорт Hysteria2 и молча вырезает \\t\\r\\n."""
    match = _SCHEME.match(text)
    rest = text[match.end():]
    rest, _, fragment = rest.partition("#")
    main, _, query = rest.partition("?")
    at = main.rfind("@")                       # пароль trojan может содержать «@»: делим по последнему
    userinfo = main[:at] if at >= 0 else None
    hostport = (main[at + 1:] if at >= 0 else main).partition("/")[0]
    return _Parts(match.group(1).lower(), userinfo, hostport, query, fragment)


def _query(query: str) -> tuple[dict[str, str], list[str]]:
    """Ключи без учёта регистра; при повторе — первое значение и предупреждение (как v2rayN)."""
    params: dict[str, str] = {}
    warnings: list[str] = []
    for item in query.split("&"):
        key, _, value = item.partition("=")      # значение — после первого «=»: ech=AAj+DQ…==
        key = unquote(key).strip().lower()[:40]
        if not key:
            continue
        if key in params:
            warning = f"duplicate:{key}"
            if warning not in warnings:
                warnings.append(warning)
            continue
        params[key] = unquote(value)
    return params, warnings


def _host_port(hostport: str) -> tuple[str, str]:
    """(хост, строка порта): порт ещё не проверен — у Hysteria2 это может быть список."""
    text = hostport.strip()
    if text.startswith("["):
        end = text.find("]")
        if end < 0:
            raise LinkError("bad_host", text)
        rest = text[end + 1:]
        if rest and not rest.startswith(":"):
            raise LinkError("bad_host", text)
        return normalize_host(text[1:end], ipv6=True), rest[1:]
    if text.count(":") > 1:
        if _IPV6_LIKE.fullmatch(text):
            raise LinkError("ipv6_without_brackets", text)
        raise LinkError("ipv6_without_brackets", text="В адресе сервера несколько «:» — IPv6 пишется в [скобках]")
    host, _, port = text.partition(":")
    return normalize_host(host), port


def _port(raw: str, default: int | None) -> int:
    if raw.strip():
        return check_port(raw)
    if default is None:
        raise LinkError("no_port")
    return default


def _name(fragment: str) -> tuple[str, str | None]:
    """(имя, описание): Incy дописывает описание сервера как «#Имя?serverDescription=<base64>»."""
    text = unquote(fragment)
    head, sep, tail = text.partition("?serverDescription=")
    if not sep:
        return text, None
    try:
        return head, clean_text(b64decode_text(tail)) or None
    except ValueError:
        return head, None


# ------------------------------------------------------------ транспорт и TLS

NETWORK_ALIASES = {
    "": "tcp", "tcp": "tcp", "raw": "tcp", "ws": "ws", "websocket": "ws", "grpc": "grpc", "gun": "grpc",
    "httpupgrade": "httpupgrade", "xhttp": "xhttp", "splithttp": "xhttp", "h2": "http", "http": "http",
    "kcp": "kcp", "mkcp": "kcp", "quic": "quic",
}
_LINK_NETWORK = {"http": "h2"}                  # как транспорт называется в ссылке, если не как у нас
_FLOWS = ("", "xtls-rprx-vision", "xtls-rprx-vision-udp443")
_LEGACY_FLOWS = ("xtls-rprx-direct", "xtls-rprx-splice", "xtls-rprx-origin", "xtls-rprx-direct-udp443",
                 "xtls-rprx-splice-udp443", "xtls-rprx-origin-udp443")
_GRPC_MODES = ("gun", "multi", "guna")


def network_of(value: object) -> str:
    key = str(value or "").strip().lower()
    if key not in NETWORK_ALIASES:
        raise LinkError("unsupported_transport", key)
    return NETWORK_ALIASES[key]


def security_of(value: object, default: str) -> str:
    key = str(value or "").strip().lower() or default
    if key == "xtls":
        raise LinkError("unsupported_security", key, text=_LEGACY_XTLS_TEXT)
    if key not in ("none", "tls", "reality"):
        raise LinkError("unsupported_security", key)
    return key


def check_flow(value: object) -> str:
    flow = str(value or "").strip().lower()
    if flow in _LEGACY_FLOWS:
        raise LinkError("unsupported_flow", flow, text=f"Устаревший XTLS ({flow}) удалён из ядер — "
                                                       "нужен сервер с xtls-rprx-vision")
    if flow not in _FLOWS:
        raise LinkError("unsupported_flow", flow)
    return flow


def _int_param(params: dict[str, str], key: str, warnings: list[str]) -> int | None:
    value = params.get(key, "").strip()
    if not value:
        return None
    if not value.isdigit():
        warnings.append(f"bad_value:{key}")
        return None
    return int(value)


def _transport(network: str, params: dict[str, str], warnings: list[str]) -> dict[str, Any]:
    transport: dict[str, Any] = {}
    host = params.get("host", "").strip()
    path = params.get("path", "")
    if network == "tcp":
        # headerType=none (и host/path без HTTP-маскировки) для tcp смысла не несут
        if params.get("headertype", "").strip().lower() == "http":
            transport["header_type"] = "http"
            if csv(host):
                transport["host"] = csv(host)
            if path:
                transport["path"] = path
    elif network in ("ws", "httpupgrade", "http", "xhttp"):
        if path:
            transport["path"] = path               # ?ed=2048 остаётся в path: его разбирает генератор
        if host:
            transport["host"] = host
        if network == "xhttp":
            mode = params.get("mode", "").strip().lower()
            if mode:
                transport["xhttp_mode"] = mode
            if params.get("extra", "").strip():
                transport["xhttp_extra"] = _json_object(params["extra"], "extra")
    elif network == "grpc":
        if params.get("servicename"):
            transport["service_name"] = params["servicename"]
        transport["grpc_mode"] = params.get("mode", "").strip().lower() or "gun"
        if params.get("authority", "").strip():
            transport["authority"] = params["authority"].strip()
    elif network == "kcp":
        header = params.get("headertype", "").strip().lower()
        if header and header != "none":
            transport["header_type"] = header
        if params.get("seed"):
            transport["kcp_seed"] = params["seed"]
        for key in ("mtu", "tti"):
            value = _int_param(params, key, warnings)
            if value is not None:
                transport[f"kcp_{key}"] = value
    if params.get("fm", "").strip():               # finalmask Xray: понимает только помощник
        transport["finalmask"] = _json_object(params["fm"], "fm")
    return transport


def _tls(params: dict[str, str], security: str) -> dict[str, Any]:
    if security == "none":
        return {}
    tls: dict[str, Any] = {}
    sni = (params.get("sni") or params.get("peer") or "").strip()   # peer — старое имя sni у trojan
    if sni:
        tls["sni"] = sni
    if csv(params.get("alpn")):
        tls["alpn"] = csv(params.get("alpn"))
    fingerprint = params.get("fp", "").strip().lower()
    if fingerprint:
        tls["fingerprint"] = fingerprint
    if any(_truthy(params.get(key)) for key in ("allowinsecure", "insecure", "allow_insecure")):
        tls["insecure"] = True
    if params.get("ech", "").strip():
        tls["ech"] = params["ech"].strip()
    for key in ("pcs", "vcn"):
        if csv(params.get(key)):
            tls[key] = csv(params.get(key))
    if security == "reality":
        pbk = params.get("pbk", "").strip()
        if not pbk:
            raise LinkError("reality_without_pbk")
        tls["pbk"] = pbk.translate(str.maketrans("+/", "-_")).rstrip("=")   # ядра ждут base64url без паддинга
        if "sid" in params:
            tls["sid"] = params["sid"].strip()      # пустой shortId допустим
        for key in ("spx", "pqv"):
            if params.get(key):
                tls[key] = params[key]
    return tls


# ------------------------------------------------------------ протоколы

def _vless(parts: _Parts) -> Server:
    params, warnings = _query(parts.query)
    uuid = unquote(parts.userinfo or "").strip()
    if not uuid:
        raise LinkError("no_uuid")
    host, port_raw = _host_port(parts.hostport)
    flow = check_flow(params.get("flow"))
    security = security_of(params.get("security"), "none")
    network = network_of(params.get("type"))
    encryption = params.get("encryption", "").strip() or "none"
    if encryption.lower() == "none":
        encryption = "none"
    return Server("vless", host, _port(port_raw, None), uuid=uuid, flow=flow, encryption=encryption,
                  network=network, transport=_transport(network, params, warnings), security=security,
                  tls=_tls(params, security), warnings=warnings)


def _trojan(parts: _Parts) -> Server:
    params, warnings = _query(parts.query)
    password = unquote(parts.userinfo or "")
    if not password:
        raise LinkError("no_password")
    host, port_raw = _host_port(parts.hostport)
    security = security_of(params.get("security"), "tls")
    network = network_of(params.get("type"))
    return Server("trojan", host, _port(port_raw, 443), password=password, network=network,
                  transport=_transport(network, params, warnings), security=security,
                  tls=_tls(params, security), warnings=warnings)


def _vmess716(parts: _Parts) -> Server:
    params, warnings = _query(parts.query)
    uuid = unquote(parts.userinfo or "").strip()
    if not uuid:
        raise LinkError("no_uuid")
    host, port_raw = _host_port(parts.hostport)
    security = security_of(params.get("security"), "none")
    network = network_of(params.get("type"))
    cipher = params.get("encryption", "").strip().lower() or "auto"
    return Server("vmess", host, _port(port_raw, None), uuid=uuid, cipher=cipher, network=network,
                  transport=_transport(network, params, warnings), security=security,
                  tls=_tls(params, security), warnings=warnings)


def _vmess_json(data: dict[str, Any]) -> Server:
    """vmess:// v2rayN «ver 2»: числа строкой или числом, ключи без учёта регистра."""
    d = {str(k).lower(): v for k, v in data.items()}

    def text(key: str) -> str:
        value = d.get(key)
        return "" if value is None or isinstance(value, (dict, list)) else str(value).strip()

    host = normalize_host(text("add"))
    if d.get("port") in (None, ""):
        raise LinkError("no_port")
    port = check_port(d.get("port"))
    uuid = text("id")
    if not uuid:
        raise LinkError("no_uuid")
    aid = text("aid") or "0"
    if not aid.isdigit():
        raise LinkError("bad_value", "aid")
    network = network_of(text("net"))
    kind = text("type").lower()
    host_field, path = text("host"), text("path")
    warnings = ["legacy_vmess_alterid"] if int(aid) > 0 else []
    params: dict[str, str] = {"host": host_field, "path": path}
    if network == "tcp" and kind == "http":
        params["headertype"] = "http"
    elif network == "kcp":
        params.update(headertype=kind, seed=path, path="")
    elif network == "grpc":
        params.update(servicename=path, mode=kind if kind in _GRPC_MODES else "gun", authority=host_field)
    elif network == "xhttp":
        extra = d.get("extra")
        params.update(mode="" if kind in ("", "none") else kind,
                      extra=json.dumps(extra) if isinstance(extra, dict) else text("extra"))
    security = security_of(text("tls"), "none")
    tls_params = {key: text(key) for key in ("sni", "fp", "ech", "pcs", "vcn", "pbk", "sid", "spx", "pqv")
                  if key in d}
    alpn = d.get("alpn")
    tls_params["alpn"] = ",".join(str(a) for a in alpn) if isinstance(alpn, list) else text("alpn")
    tls_params["insecure"] = "1" if _truthy(d.get("insecure")) or _truthy(d.get("allowinsecure")) else ""
    return Server("vmess", host, port, name=text("ps"), uuid=uuid, cipher=text("scy").lower() or "auto",
                  alter_id=int(aid), network=network, transport=_transport(network, params, warnings),
                  security=security, tls=_tls(tls_params, security), warnings=warnings)


_SHADOWROCKET_VMESS = re.compile(r"^[\w-]+:[^@]+@[^@]+:\d+$")


def _vmess(text: str, parts: _Parts) -> Server:
    body = text[len(parts.scheme) + 3:]
    payload = body.partition("#")[0]
    if "@" in payload.partition("?")[0]:
        if ":" in unquote(parts.userinfo or ""):
            raise LinkError("unsupported_format", "VMess v2fly")
        return _vmess716(parts)
    if "?" in payload:
        raise LinkError("unsupported_format", "VMess Shadowrocket")
    try:
        decoded = b64decode_text(payload)
    except ValueError as exc:
        raise LinkError("bad_base64", "vmess") from exc
    try:
        data = json.loads(decoded)
    except ValueError as exc:
        if _SHADOWROCKET_VMESS.match(decoded.strip()):
            raise LinkError("unsupported_format", "VMess Shadowrocket") from exc
        raise LinkError("bad_json", "vmess") from exc
    if not isinstance(data, dict):
        raise LinkError("bad_json", "vmess")
    return _vmess_json(data)


SS_METHODS = frozenset({
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305",
    "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "chacha20-poly1305",
    "xchacha20-ietf-poly1305", "xchacha20-poly1305", "none", "plain",
    "aes-128-ctr", "aes-192-ctr", "aes-256-ctr", "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
    "rc4-md5", "chacha20-ietf", "chacha20", "xchacha20",
})


def _split_unescaped(text: str, sep: str) -> list[str]:
    """Деление по sep, кроме экранированного «\\» (формат SIP003 plugin)."""
    parts, current, i = [], [], 0
    while i < len(text):
        if text[i] == "\\" and i + 1 < len(text):
            current.append(text[i:i + 2])
            i += 2
            continue
        if text[i] == sep:
            parts.append("".join(current))
            current = []
        else:
            current.append(text[i])
        i += 1
    parts.append("".join(current))
    return parts


def _unescape(text: str) -> str:
    return re.sub(r"\\(.)", r"\1", text)


def parse_plugin(value: str | None) -> dict[str, Any] | None:
    """«obfs-local;obfs=http;obfs-host=x» → {"name": "obfs-local", "opts": {...}}; флаг без «=» — True."""
    items = _split_unescaped((value or "").strip(), ";")
    name = _unescape(items[0]).strip()
    if not name or name.lower() == "none":
        return None
    if name == "simple-obfs":                  # опечатка из примера SIP002, клиенты понимают её как obfs-local
        name = "obfs-local"
    opts: dict[str, Any] = {}
    for item in items[1:]:
        pieces = _split_unescaped(item, "=")
        key = _unescape(pieces[0]).strip()
        if key:
            opts[key] = _unescape("=".join(pieces[1:])) if len(pieces) > 1 else True
    return {"name": name, "opts": opts}


def make_shadowsocks(host: str, port: int, method: str, password: str,
                     plugin: dict[str, Any] | None = None) -> Server:
    method = method.strip().lower()
    if method not in SS_METHODS:
        raise LinkError("unsupported_method", method)
    if not password and method not in ("none", "plain"):
        raise LinkError("no_password")
    return Server("shadowsocks", host, port, password=password, method=method, plugin=plugin)


def _ss_credentials(text: str) -> tuple[str, str]:
    """userinfo SIP002: base64(method:password) или method:password в percent-encoding (2022)."""
    decoded = unquote(text)
    if ":" not in decoded:
        try:
            decoded = b64decode_text(decoded)
        except ValueError as exc:
            raise LinkError("bad_base64", "ss") from exc
    method, sep, password = decoded.partition(":")      # в пароле 2022 бывает «:» (iPSK:uPSK)
    if not sep:
        raise LinkError("bad_value", "method:password")
    return method, password


def _shadowsocks(text: str, parts: _Parts) -> Server:
    before_fragment = text[len(parts.scheme) + 3:].partition("#")[0]
    main, _, query = before_fragment.partition("?")
    params, warnings = _query(query)
    if "@" in main:
        at = main.rfind("@")
        method, password = _ss_credentials(main[:at])
        hostport = main[at + 1:].partition("/")[0]
    else:
        # Старый формат: base64(method:password@host:port); пароль может содержать «@» и «:».
        try:
            decoded = b64decode_text(main.rstrip("/"))
        except ValueError as exc:
            raise LinkError("bad_base64", "ss") from exc
        credentials, at, hostport = decoded.rpartition("@")
        method, sep, password = credentials.partition(":")
        if not at or not sep:
            raise LinkError("bad_value", "method:password@host:port")
    host, port_raw = _host_port(hostport)
    server = make_shadowsocks(host, _port(port_raw, None), method, password, parse_plugin(params.get("plugin")))
    server.warnings = warnings
    return server


def _hy2_ports(spec: str) -> tuple[int, str | None]:
    """«443,20000-30000» → (443, "443,20000-30000"); одиночный порт — (порт, None)."""
    compact = spec.replace(" ", "")
    tokens = compact.split(",")
    try:
        for token in tokens:
            low, dash, high = token.partition("-")
            if dash and check_port(low) > check_port(high):
                raise LinkError("bad_port", spec)
            check_port(low)
    except LinkError:
        raise LinkError("bad_port", spec if _PORT_LIKE.fullmatch(spec) else "не число") from None
    first = int(tokens[0].partition("-")[0])
    return first, (compact if ("," in compact or "-" in compact) else None)


def _hysteria2(parts: _Parts) -> Server:
    params, warnings = _query(parts.query)
    password = unquote(parts.userinfo) if parts.userinfo else None
    host, port_raw = _host_port(parts.hostport)
    port, ports = _hy2_ports(port_raw) if port_raw.strip() else (443, None)
    hopping = (params.get("mport") or params.get("ports") or "").strip()
    if not ports and hopping:
        ports = _hy2_ports(hopping)[1] or hopping
    hy2: dict[str, Any] = {}
    if ports:
        hy2["ports"] = ports
    obfs = params.get("obfs", "").strip().lower()
    if obfs and obfs != "none":
        if obfs not in ("salamander", "gecko"):
            raise LinkError("unsupported_obfs", obfs)
        hy2["obfs"] = obfs
        if params.get("obfs-password"):
            hy2["obfs_password"] = params["obfs-password"]
    if params.get("pinsha256", "").strip():
        hy2["pin_sha256"] = params["pinsha256"].strip()
    for keys, target in ((("up", "upmbps"), "up_mbps"), (("down", "downmbps"), "down_mbps")):
        raw = next((params[k] for k in keys if params.get(k, "").strip()), "")
        value = re.sub(r"(?i)\s*mbps$", "", raw.strip())
        if value.isdigit():
            hy2[target] = int(value)
        elif value:
            warnings.append(f"bad_value:{target}")
    return Server("hysteria2", host, port, password=password or None, security="tls", tls=_tls(params, "tls"),
                  hy2=hy2, warnings=warnings)


def _tuic(parts: _Parts) -> Server:
    params, warnings = _query(parts.query)
    uuid_raw, sep, password_raw = (parts.userinfo or "").partition(":")
    uuid, password = unquote(uuid_raw).strip(), unquote(password_raw) if sep else ""
    if not uuid:
        raise LinkError("no_uuid")
    if not password:
        raise LinkError("no_password")
    host, port_raw = _host_port(parts.hostport)
    tuic: dict[str, Any] = {}
    congestion = (params.get("congestion_control") or params.get("congestion") or "").strip().lower()
    if congestion:
        tuic["congestion_control"] = congestion
    relay = params.get("udp_relay_mode", "").strip().lower()
    if relay:
        tuic["udp_relay_mode"] = relay
    return Server("tuic", host, _port(port_raw, None), uuid=uuid, password=password, security="tls",
                  tls=_tls(params, "tls"), tuic=tuic, warnings=warnings)


def _socks(parts: _Parts) -> Server:
    username = password = None
    if parts.userinfo:
        credentials = unquote(parts.userinfo)
        if ":" not in credentials:
            try:
                decoded = b64decode_text(credentials)
            except ValueError:
                decoded = ""
            if ":" in decoded and decoded.isprintable():
                credentials = decoded
        user, sep, secret = credentials.partition(":")
        username, password = user or None, (secret if sep and secret else None)
    host, port_raw = _host_port(parts.hostport)
    return Server("socks", host, _port(port_raw, 1080), username=username, password=password)


def _wg_key(value: str | None, name: str, *, required: bool = True) -> str | None:
    """Ключ WireGuard: base64 (оба алфавита) или hex, 32 байта → стандартный base64."""
    text = (value or "").strip()
    if not text:
        if required:
            raise LinkError("no_key", name)
        return None
    if re.fullmatch(r"[0-9a-fA-F]{64}", text):
        return base64.b64encode(bytes.fromhex(text)).decode("ascii")
    try:
        raw = b64decode_soft(text)
    except ValueError as exc:
        raise LinkError("bad_value", name) from exc
    if len(raw) != 32:
        raise LinkError("bad_value", name)
    canonical = base64.b64encode(raw).decode("ascii")
    return text if text == canonical else canonical


def _wg_address(items: list[str]) -> list[str]:
    result = []
    for item in items:
        try:
            iface = ipaddress.ip_interface(item)
        except ValueError as exc:
            raise LinkError("bad_value", "address") from exc
        result.append(item if "/" in item else f"{iface.ip}/{iface.max_prefixlen}")
    return result


def _wg_reserved(value: str) -> list[int]:
    text = value.strip()
    try:
        numbers = [int(x) for x in text.split(",")] if "," in text or text.isdigit() else list(b64decode_soft(text))
    except ValueError as exc:
        raise LinkError("bad_value", "reserved") from exc
    if len(numbers) != 3 or not all(0 <= n <= 255 for n in numbers):
        raise LinkError("bad_value", "reserved")
    return numbers


def _wg_fields(*, private_key: str | None, public_key: str | None, preshared: str | None,
               address: list[str], mtu: str | None, reserved: str | None, dns: list[str],
               keepalive: str | None, warnings: list[str]) -> dict[str, Any]:
    wg: dict[str, Any] = {"private_key": _wg_key(private_key, "PrivateKey"),
                          "peer_public_key": _wg_key(public_key, "PublicKey")}
    psk = _wg_key(preshared, "PresharedKey", required=False)
    if psk:
        wg["preshared_key"] = psk
    if address:
        wg["local_address"] = _wg_address(address)
    for key, raw in (("mtu", mtu), ("persistent_keepalive", keepalive)):
        if raw and raw.strip():
            if raw.strip().isdigit():
                wg[key] = int(raw.strip())
            else:
                warnings.append(f"bad_value:{key}")
    if reserved and reserved.strip():
        wg["reserved"] = _wg_reserved(reserved)
    if dns:
        wg["dns"] = dns
    return wg


# Параметры обфускации AmneziaWG (1.x–3.x). Нулевые Jc/S* и H1–H4 = 1–4 — это обычный WireGuard.
_AWG_NEUTRAL = {"jc": "0", "jmin": "0", "jmax": "0", "s1": "0", "s2": "0", "s3": "0", "s4": "0",
                "h1": "1", "h2": "2", "h3": "3", "h4": "4"}
_AWG_ONLY = frozenset({"i1", "i2", "i3", "i4", "i5", "headerprotectionkey", "contentpaddingaddition",
                       "rekeyaftertime", "rekeytimeout", "rejectaftertime", "keepalivetimeout",
                       "maxhandshakeattempts", "randomtrailers", "disablecookies"})


def _amnezia_params(values: dict[str, str]) -> list[str]:
    found = [k for k in values if k in _AWG_NEUTRAL or k in _AWG_ONLY]
    if all(k in _AWG_NEUTRAL and values[k].strip() == _AWG_NEUTRAL[k] for k in found):
        return []
    return found


def _wireguard(parts: _Parts) -> Server:
    params, warnings = _query(parts.query)
    awg = _amnezia_params(params)
    if awg:
        raise LinkError("amneziawg", ", ".join(awg))
    host, port_raw = _host_port(parts.hostport)
    wg = _wg_fields(private_key=unquote(parts.userinfo or ""),
                    public_key=params.get("publickey") or params.get("public_key"),
                    preshared=params.get("presharedkey") or params.get("preshared_key"),
                    address=csv(params.get("address") or params.get("ip")), mtu=params.get("mtu"),
                    reserved=params.get("reserved"), dns=csv(params.get("dns")),
                    keepalive=params.get("keepalive"), warnings=warnings)
    return Server("wireguard", host, _port(port_raw, None), wg=wg, warnings=warnings)


# ------------------------------------------------------------ схемы

_PARSERS = {
    "vless": lambda text, parts: _vless(parts),
    "vmess": _vmess,
    "ss": _shadowsocks,
    "trojan": lambda text, parts: _trojan(parts),
    "hysteria2": lambda text, parts: _hysteria2(parts),
    "hy2": lambda text, parts: _hysteria2(parts),
    "tuic": lambda text, parts: _tuic(parts),
    "socks": lambda text, parts: _socks(parts),
    "socks5": lambda text, parts: _socks(parts),
    "wireguard": lambda text, parts: _wireguard(parts),
    "wg": lambda text, parts: _wireguard(parts),
}

# Схемы, которые узнаём, но не открываем: человеческое название для ответа.
UNSUPPORTED_SCHEMES = {
    "anytls": "AnyTLS", "naive": "NaiveProxy", "naive+https": "NaiveProxy", "naive+quic": "NaiveProxy",
    "ssr": "ShadowsocksR", "trojan-go": "Trojan-Go", "socks4": "SOCKS4", "socks4a": "SOCKS4",
    "hysteria": "Hysteria v1", "hysteria2+realm": "Hysteria2 Realms", "hysteria2+realm+http": "Hysteria2 Realms",
    "amneziawg": "AmneziaWG", "awg": "AmneziaWG", "juicity": "Juicity", "shadowtls": "ShadowTLS",
    "ssh": "SSH", "brook": "Brook", "mieru": "Mieru", "tg": "MTProto-прокси Telegram",
    "throne": "ссылки Throne",
}

# Обёртки с адресом в параметре url= (Hiddify принимает эту форму у любой из схем).
_QUERY_WRAPPERS = frozenset({"sing-box", "hiddify", "v2rayng", "v2rayn", "v2ray", "clash", "clashmeta", "clashx",
                             "flclash", "flclashx", "koala-clash", "prizrak-box", "stash", "mihomo", "sn",
                             "karing", "v2box"})
# Обёртки с адресом в пути: остаток строки берётся как есть.
_PATH_WRAPPERS = ("hiddify://import/", "happ://add/", "incy://add/", "incy://import/", "streisand://import/",
                  "shadowrocket://add/", "lazeyka://import/")
_IMPORT_WRAPPERS = ("incy://import/", "lazeyka://import/")      # внутри бывает base64 ссылок или .conf
_APP_COMMANDS = frozenset({"connect", "open", "disconnect", "close", "toggle", "status"})
_ROUTE_HOSTS = frozenset({"routing", "autorouting", "onadd"})
_ENCODED_SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*%3A", re.I)
# Схемы, которые бывают только обёртками: без адреса внутри — понятный отказ, а не «незнакомая ссылка».
_WRAPPER_SCHEMES = frozenset({"happ", "incy", "hiddify", "streisand", "shadowrocket", "lazeyka", "sing-box", "sn"})
_WRAPPER_KEYS = frozenset({"name", "remarks", "title", "tag"})


def _query_url(text: str, scheme: str) -> str:
    """url= из обёртки: декодируется ровно один раз, «+» остаётся плюсом. Шаблоны страниц подписки
    вставляют адрес как есть — тогда его собственные «&k=v» (кроме имени обёртки) — часть адреса."""
    query = text.partition("#")[0].partition("?")[2]
    items = query.split("&")
    for index, item in enumerate(items):
        key, _, value = item.partition("=")
        if unquote(key).strip().lower() != "url":
            continue
        if "://" in value:
            for extra in items[index + 1:]:
                if extra.partition("=")[0].strip().lower() in _WRAPPER_KEYS:
                    break
                value += "&" + extra
        value = unquote(value).strip()
        if value:
            return value
    raise LinkError("bad_wrapper", scheme)


def _strip_name(value: str) -> str:
    """Адрес подписки из обёртки — без «#имя»; у ссылки сервера «#» — её собственное имя."""
    if value.lower().startswith(("http://", "https://")):
        return value.partition("#")[0]
    return value


def _decode_import(value: str) -> str:
    """incy://import/<данные>: адрес, ссылка, несколько адресов, .conf или base64 от них."""
    if "://" in value or "[interface]" in value.lower():
        return value
    try:
        decoded = b64decode_text(value).strip()
    except ValueError:
        return value
    if "://" in decoded or "[interface]" in decoded.lower():
        return decoded
    return value


def unwrap(text: str) -> str:
    """Снять один уровень deeplink-обёртки. Не обёртка — текст как есть.

    LinkError: зашифрованные ссылки Happ/Incy, команды приложений и профили маршрутизации."""
    stripped = (text or "").strip()
    if not stripped or "\n" in stripped or "\r" in stripped:
        return text
    lower = stripped.lower()
    if lower.startswith(("://routing", "://autorouting", "://onadd")):
        raise LinkError("route_profile")
    match = _SCHEME.match(stripped)
    if not match:
        return text
    scheme = match.group(1).lower()
    target = lower[match.end():].partition("/")[0].partition("?")[0].partition("#")[0]
    if scheme in ("happ", "incy"):
        if target.startswith("crypt"):
            raise LinkError("encrypted_link")
        if target in _APP_COMMANDS:
            raise LinkError("app_command", f"{scheme}://{target}")
        if target in _ROUTE_HOSTS:
            raise LinkError("route_profile")
    for prefix in _PATH_WRAPPERS:
        if lower.startswith(prefix):
            value = stripped[len(prefix):].strip()
            if _ENCODED_SCHEME.match(value):
                value = unquote(value)
            if prefix in _IMPORT_WRAPPERS:
                value = _decode_import(value)
            if not value:
                raise LinkError("bad_wrapper", scheme)
            return _strip_name(value)
    if scheme in _QUERY_WRAPPERS and ("?" in stripped and "url=" in lower):
        return _strip_name(_query_url(stripped, scheme))
    if scheme in _WRAPPER_SCHEMES:
        raise LinkError("bad_wrapper", scheme)
    return text


def _is_wrapper(scheme: str, text: str) -> bool:
    lower = text.lower()
    return scheme in _WRAPPER_SCHEMES or (scheme in _QUERY_WRAPPERS and "url=" in lower)


def _parse_plain(text: str) -> Server:
    match = _SCHEME.match(text)
    if not match:
        raise LinkError("not_a_link")
    scheme = match.group(1).lower()
    if scheme in UNSUPPORTED_SCHEMES:
        name = UNSUPPORTED_SCHEMES[scheme]
        raise LinkError("unsupported_scheme", name, text=AMNEZIA_TEXT if name == "AmneziaWG" else None)
    if scheme in ("http", "https"):
        # Как у Incy: http(s)://логин:пароль@хост:порт без пути — HTTP-прокси, остальное — адрес подписки.
        main, query_sep, _ = text[match.end():].partition("#")[0].partition("?")
        at = main.rfind("@")
        if at >= 0 and not main[at + 1:].partition("/")[2].strip("/") and not query_sep:
            raise LinkError("unsupported_scheme", "HTTP-прокси")
        raise LinkError("subscription_url")
    if scheme == "v2rayn":
        raise LinkError("unsupported_scheme", "внутренний формат v2rayN")
    parser = _PARSERS.get(scheme)
    if parser is None:
        if _is_wrapper(scheme, text):
            raise LinkError("nested_wrapper")
        raise LinkError("unknown_scheme", scheme[:20])
    parts = _split(text)
    server = parser(text, parts)
    if not server.name:
        server.name, server.description = _name(parts.fragment)
    server.raw = text
    return finish(server)


def parse_link(text: str) -> Server:
    """Ссылка сервера → Server (id = key(), raw = ссылка, имя без флага, страна по флагу).
    Обёртка (incy://add/vless://…) снимается один раз."""
    link = re.sub(r"[\r\n]+", "", (text or "").strip().lstrip("\ufeff"))
    if not link:
        raise LinkError("empty")
    if len(link) > MAX_LINK:
        raise LinkError("too_long", len(link))
    match = _SCHEME.match(link)
    if match and _is_wrapper(match.group(1).lower(), link):
        inner = unwrap(link).strip()
        if inner == link:
            raise LinkError("bad_wrapper", match.group(1).lower())
        return _parse_plain(inner)
    return _parse_plain(link)


# ------------------------------------------------------------ текст: подписка или поле импорта

_LINES = re.compile(r"\r\n|\r|\n")
_CONF_HEADER = re.compile(r"^\s*\[\s*interface\s*\]\s*$", re.I | re.M)
_META_LINE = re.compile(r"#\s*([A-Za-z][A-Za-z0-9_-]{0,63})\s*:\s?(.*)")
ROUTE_LINE = re.compile(r"(?:[A-Za-z][A-Za-z0-9+.\-]*)?://(?:(?:auto)?routing(?:/|$)|onadd/)", re.I)


def looks_like_conf(text: str) -> bool:
    """Текст — файл WireGuard/AmneziaWG: раздел [Interface] и PrivateKey."""
    return bool(_CONF_HEADER.search(text)) and "privatekey" in text.lower()


def parse_text(text: str, *, decode_base64: bool = True) -> ParseResult:
    """Построчно: пустые строки и комментарии пропускаются, «#ключ: значение» — в meta, строки профиля
    маршрутов — в route_lines, точные дубли — молча, незнакомое — в errors (не отказ всего текста).

    Для поля импорта: файл WireGuard .conf разбирается целиком, текст без «://» — как base64 от ссылок
    (один уровень; decode_base64=False — когда base64 уже снят, как в subscription.decode)."""
    body = (text or "").strip().lstrip("\ufeff").strip()
    if looks_like_conf(body):
        try:
            return ParseResult(servers=parse_wireguard_conf(body))
        except LinkError as exc:
            return ParseResult(errors=[(1, exc)])
    if decode_base64 and body and "://" not in body:
        try:
            decoded = b64decode_text(body)
        except ValueError:
            decoded = ""
        if "://" in decoded or looks_like_conf(decoded):
            return parse_text(decoded, decode_base64=False)
    result = ParseResult()
    seen_lines: set[str] = set()
    seen_ids: set[str] = set()
    for number, raw in enumerate(_LINES.split(text or ""), start=1):
        line = raw.strip().lstrip("\ufeff").strip()
        if not line or line in seen_lines:
            continue
        seen_lines.add(line)
        if line.startswith("#"):
            meta = _META_LINE.fullmatch(line)
            if meta:
                result.meta.setdefault(meta.group(1).lower(), meta.group(2).strip())
            continue
        if ROUTE_LINE.match(line):
            result.route_lines.append(line)
            continue
        try:
            server = parse_link(line)
        except LinkError as exc:
            result.errors.append((number, exc))
            continue
        if server.id in seen_ids:
            result.errors.append((number, LinkError("duplicate")))
            continue
        seen_ids.add(server.id)
        result.servers.append(server)
    return result


# ------------------------------------------------------------ WireGuard .conf

_SECTION = re.compile(r"\[\s*([A-Za-z]+)\s*\]")
_CONF_NAME = re.compile(r"#\s*Name\s*=\s*(.+)", re.I)


def _conf_sections(text: str) -> tuple[list[tuple[str, dict[str, list[str]]]], str]:
    """[(раздел в нижнем регистре, {ключ: [значения]})] и имя из комментария «# Name = …»."""
    sections: list[tuple[str, dict[str, list[str]]]] = []
    comment_name = ""
    for raw in _LINES.split(text or ""):
        line = raw.strip().lstrip("\ufeff")
        if not line:
            continue
        if line.startswith(("#", ";")):
            match = _CONF_NAME.fullmatch(line)
            if match and not comment_name:
                comment_name = match.group(1).strip()
            continue
        section = _SECTION.fullmatch(line)
        if section:
            sections.append((section.group(1).lower(), {}))
            continue
        key, sep, value = line.partition("=")
        if not sep or not sections:
            raise LinkError("bad_conf", "строка вне раздела или без «=»")
        value = value.split("#", 1)[0].strip()          # wg-quick отбрасывает «#…» до конца строки
        sections[-1][1].setdefault(key.strip().lower(), []).append(value)
    return sections, comment_name


def parse_wireguard_conf(text: str, name: str = "") -> list[Server]:
    """Файл WireGuard ([Interface] + [Peer]) → серверы, по одному на [Peer] с Endpoint."""
    sections, comment_name = _conf_sections(text)
    interfaces = [values for title, values in sections if title == "interface"]
    devices = [values for title, values in sections if title == "device"]
    peers = [values for title, values in sections if title == "peer"]
    if not interfaces:
        raise LinkError("bad_conf", "нет раздела [Interface]")
    interface = interfaces[0]
    flat = {k: v[0] for k, v in interface.items()}
    awg = sorted({key for device in devices for key in device}) or _amnezia_params(flat)
    if awg:
        raise LinkError("amneziawg", ", ".join(awg))
    if not peers:
        raise LinkError("bad_conf", "нет раздела [Peer]")
    address = [item for value in interface.get("address", []) for item in csv(value)]
    dns = [item for value in interface.get("dns", []) for item in csv(value)]
    servers = []
    for index, peer in enumerate(peers, start=1):
        endpoint = (peer.get("endpoint") or [""])[0]
        if not endpoint:
            raise LinkError("bad_conf", "у [Peer] нет Endpoint")
        host, port_raw = _host_port(endpoint)
        warnings: list[str] = []
        wg = _wg_fields(private_key=flat.get("privatekey"), public_key=(peer.get("publickey") or [None])[0],
                        preshared=(peer.get("presharedkey") or [None])[0], address=address,
                        mtu=flat.get("mtu"), reserved=None, dns=dns,
                        keepalive=(peer.get("persistentkeepalive") or [None])[0], warnings=warnings)
        title = name.strip() or comment_name or host
        if len(peers) > 1:
            title = f"{title} · {index}"
        server = Server("wireguard", host, _port(port_raw, None), name=title, wg=wg, source="wireguard-conf",
                        warnings=warnings)
        servers.append(finish(server))
    return servers


# ------------------------------------------------------------ сервер → ссылка

def _q(value: object) -> str:
    return quote(str(value), safe="")


def _link_host(host: str) -> str:
    return f"[{host}]" if ":" in host else host


def _flag_name(server: Server) -> str:
    name = server.name or ""
    country = (server.country or "").upper()
    if len(country) == 2 and country.isascii() and country.isalpha():
        flag = "".join(chr(0x1F1E6 + ord(ch) - ord("A")) for ch in country)
        return f"{flag} {name}".strip()
    return name


def _std_params(server: Server) -> list[tuple[str, str]]:
    """Параметры vless/trojan по стандарту XTLS 716 (и диалекту v2rayN)."""
    params: list[tuple[str, str]] = []
    t, tls = server.transport or {}, server.tls or {}
    if server.proto == "vless":
        params.append(("encryption", server.encryption or "none"))
        if server.flow:
            params.append(("flow", server.flow))
    params.append(("security", server.security))
    if server.security != "none":
        for key, name in (("sni", "sni"), ("fingerprint", "fp")):
            if tls.get(key):
                params.append((name, tls[key]))
        if tls.get("alpn"):
            params.append(("alpn", ",".join(tls["alpn"])))
        if server.security == "reality":
            params.append(("pbk", tls.get("pbk", "")))
            if "sid" in tls:
                params.append(("sid", tls["sid"]))
            for key in ("spx", "pqv"):
                if tls.get(key):
                    params.append((key, tls[key]))
        if tls.get("ech"):
            params.append(("ech", tls["ech"]))
        for key in ("pcs", "vcn"):
            if tls.get(key):
                params.append((key, ",".join(tls[key])))
        if tls.get("insecure"):
            params.append(("allowInsecure", "1"))
    params.append(("type", _LINK_NETWORK.get(server.network, server.network)))
    if server.network == "tcp" and t.get("header_type") == "http":
        params.append(("headerType", "http"))
        if t.get("host"):
            params.append(("host", ",".join(t["host"]) if isinstance(t["host"], list) else str(t["host"])))
        if t.get("path"):
            params.append(("path", t["path"]))
    elif server.network in ("ws", "httpupgrade", "http", "xhttp"):
        for key in ("host", "path"):
            if t.get(key):
                params.append((key, t[key]))
        if t.get("xhttp_mode"):
            params.append(("mode", t["xhttp_mode"]))
        if t.get("xhttp_extra"):
            params.append(("extra", json.dumps(t["xhttp_extra"], separators=(",", ":"), ensure_ascii=False)))
    elif server.network == "grpc":
        for key, name in (("service_name", "serviceName"), ("grpc_mode", "mode"), ("authority", "authority")):
            if t.get(key):
                params.append((name, t[key]))
    elif server.network == "kcp":
        for key, name in (("header_type", "headerType"), ("kcp_seed", "seed"), ("kcp_mtu", "mtu"), ("kcp_tti", "tti")):
            if t.get(key) not in (None, ""):
                params.append((name, str(t[key])))
    if t.get("finalmask"):
        params.append(("fm", json.dumps(t["finalmask"], separators=(",", ":"), ensure_ascii=False)))
    return params


def _join(params: list[tuple[str, object]]) -> str:
    return "&".join(f"{key}={_q(value)}" for key, value in params)


def _vmess_link(server: Server) -> str:
    t, tls = server.transport or {}, server.tls or {}
    network = server.network
    kind, host, path = "none", t.get("host", ""), t.get("path", "")
    if network == "tcp" and t.get("header_type") == "http":
        kind = "http"
        host = ",".join(t["host"]) if isinstance(t.get("host"), list) else (host or "")
    elif network == "kcp":
        kind, path = t.get("header_type") or "none", t.get("kcp_seed", "")
    elif network == "grpc":
        kind, host, path = t.get("grpc_mode") or "gun", t.get("authority", ""), t.get("service_name", "")
    elif network == "xhttp":
        kind = t.get("xhttp_mode", "")
    data: dict[str, Any] = {
        "v": "2", "ps": _flag_name(server), "add": server.host, "port": str(server.port), "id": server.uuid or "",
        "aid": str(server.alter_id), "scy": server.cipher or "auto",
        "net": _LINK_NETWORK.get(network, network), "type": kind, "host": host or "", "path": path or "",
        "tls": "" if server.security == "none" else server.security,
        "sni": tls.get("sni", ""), "alpn": ",".join(tls.get("alpn") or []), "fp": tls.get("fingerprint", ""),
    }
    for key in ("pbk", "sid", "spx", "pqv", "ech"):
        if key in tls:
            data[key] = tls[key]
    for key in ("pcs", "vcn"):
        if tls.get(key):
            data[key] = ",".join(tls[key])
    if tls.get("insecure"):
        data["insecure"] = "1"
    if t.get("xhttp_extra"):
        data["extra"] = json.dumps(t["xhttp_extra"], separators=(",", ":"), ensure_ascii=False)
    blob = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return "vmess://" + base64.b64encode(blob).decode("ascii")


def _plugin_text(plugin: dict[str, Any]) -> str:
    def esc(value: object) -> str:
        return re.sub(r"([\\;=:])", r"\\\1", str(value))
    items = [esc(plugin.get("name", ""))]
    for key, value in (plugin.get("opts") or {}).items():
        items.append(esc(key) if value is True else f"{esc(key)}={esc(value)}")
    return ";".join(items)


def to_link(server: Server) -> str:
    """Ссылка сервера для «Скопировать ссылку» и QR: исходная, если есть, иначе собранная из полей."""
    if server.raw:
        return server.raw
    host = _link_host(server.host)
    name = "#" + _q(_flag_name(server)) if _flag_name(server) else ""
    tls = server.tls or {}
    proto = server.proto
    if proto == "vless":
        return f"vless://{_q(server.uuid or '')}@{host}:{server.port}?{_join(_std_params(server))}{name}"
    if proto == "trojan":
        return f"trojan://{_q(server.password or '')}@{host}:{server.port}?{_join(_std_params(server))}{name}"
    if proto == "vmess":
        return _vmess_link(server)
    if proto == "shadowsocks":
        method, password = server.method or "", server.password or ""
        if method.startswith("2022-"):          # SIP002: для 2022 base64 запрещён — только percent-encoding
            userinfo = f"{_q(method)}:{_q(password)}"
        else:
            userinfo = base64.urlsafe_b64encode(f"{method}:{password}".encode("utf-8")).decode("ascii").rstrip("=")
        plugin = f"/?plugin={_q(_plugin_text(server.plugin))}" if server.plugin else ""
        return f"ss://{userinfo}@{host}:{server.port}{plugin}{name}"
    if proto == "hysteria2":
        hy2 = server.hy2 or {}
        ports = str(hy2.get("ports") or "")
        params: list[tuple[str, object]] = []
        if ports and not re.match(rf"{server.port}(?:[,-]|$)", ports):
            params.append(("mport", ports))
            ports = ""
        for key, value in (("sni", tls.get("sni")), ("alpn", ",".join(tls.get("alpn") or [])),
                           ("fp", tls.get("fingerprint")), ("insecure", "1" if tls.get("insecure") else ""),
                           ("obfs", hy2.get("obfs")), ("obfs-password", hy2.get("obfs_password")),
                           ("pinSHA256", hy2.get("pin_sha256")), ("up", hy2.get("up_mbps")),
                           ("down", hy2.get("down_mbps"))):
            if value not in (None, ""):
                params.append((key, value))
        auth = f"{_q(server.password)}@" if server.password else ""
        return f"hysteria2://{auth}{host}:{ports or server.port}/?{_join(params)}{name}"
    if proto == "tuic":
        tuic = server.tuic or {}
        params = [(k, v) for k, v in (("congestion_control", tuic.get("congestion_control")),
                                      ("udp_relay_mode", tuic.get("udp_relay_mode")),
                                      ("alpn", ",".join(tls.get("alpn") or [])), ("sni", tls.get("sni")),
                                      ("allow_insecure", "1" if tls.get("insecure") else "")) if v]
        return f"tuic://{_q(server.uuid or '')}:{_q(server.password or '')}@{host}:{server.port}?{_join(params)}{name}"
    if proto == "socks":
        auth = ""
        if server.username or server.password:
            pair = f"{server.username or ''}:{server.password or ''}".encode("utf-8")
            auth = base64.urlsafe_b64encode(pair).decode("ascii").rstrip("=") + "@"
        return f"socks://{auth}{host}:{server.port}{name}"
    if proto == "wireguard":
        wg = server.wg or {}
        params = [(k, v) for k, v in (("publickey", wg.get("peer_public_key")), ("presharedkey", wg.get("preshared_key")),
                                      ("address", ",".join(wg.get("local_address") or [])), ("mtu", wg.get("mtu")),
                                      ("reserved", ",".join(str(n) for n in wg.get("reserved") or [])),
                                      ("dns", ",".join(wg.get("dns") or []))) if v not in (None, "")]
        return f"wireguard://{_q(wg.get('private_key') or '')}@{host}:{server.port}?{_join(params)}{name}"
    raise LinkError("unsupported_scheme", proto)
