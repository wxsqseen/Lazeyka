"""Конфиги ядер своего VPN: sing-box 1.14.3 (основное ядро) и помощник Xray 26.3.27.

build_singbox(plan) — рабочий конфиг (TUN, системный или локальный прокси), build_delay(plan) —
временный экземпляр для замера задержки, build_xray(plan) — помощник для серверов, которых
sing-box не умеет (model.engine_for): каждый такой сервер в sing-box — выход socks на
127.0.0.1:<порт помощника>, за ним — своя пара inbound/outbound в Xray.

Генератор чистый: всё нужное менеджер собрал в RunPlan заранее (адреса серверов уже
резолвлены, порты и секреты выбраны), в сеть и систему он не ходит. `sing-box check` не ловит
ссылки на несуществующие теги и недопустимые перечисления — это делает validate(); там же
таблица полей, которые ломают конфиг сейчас или в 1.15–1.17 (план 5.5).
"""
from __future__ import annotations

import base64
import copy
import ipaddress
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator
from urllib.parse import urlsplit

from ..errors import UserError
from . import routing
from .model import ENGINES, MODES, RunPlan, Server, engine_for, streamed

SELECTOR_PROXY = "proxy"
SELECTOR_BYPASS = "bypass"
DIRECT = "direct"
TUN_IN = "tun-in"
PROXY_IN = "mixed-in"
INTERNAL_IN = "internal-in"
DNS_REMOTE = "dns-remote"
DNS_DIRECT = "dns-direct"
DNS_BYPASS = "dns-bypass"        # домены «через обход»: DNS идёт тем же путём, что их трафик
DNS_RU = "dns-ru"
DNS_FAKEIP = "dns-fakeip"
DNS_BOOTSTRAP = "dns-bootstrap"

HELPER_HOST = "127.0.0.1"
MAX_GROUP = 16                       # участников «Самого быстрого» (столько же серверов исключает фильтр zapret)
URLTEST_TOLERANCE = 50
SNIFFERS = ["http", "tls", "quic", "dns", "bittorrent"]
LOCAL_SUFFIXES = ["localhost", "local", "lan", "home.arpa"]
FAKEIP_V4 = "198.18.0.0/15"
FAKEIP_V6 = "fc00::/18"
BOOTSTRAP_DOH = "https://1.1.1.1/dns-query"
API_ORIGIN = "http://127.0.0.1"      # CORS: страницы браузера ответы API не прочитают

# DoH по IP, чей сертификат не содержит IP-адреса, — нужен server_name.
_DOH_SNI = {"77.88.8.8": "common.dot.dns.yandex.net", "77.88.8.1": "common.dot.dns.yandex.net"}
# DoH по имени, адрес которого известен заранее (резолвить его некому — это и есть резолвер).
_DOH_IP = {"cloudflare-dns.com": "1.1.1.1", "one.one.one.one": "1.1.1.1", "dns.google": "8.8.8.8",
           "dns.quad9.net": "9.9.9.9", "common.dot.dns.yandex.net": "77.88.8.8"}

SB_MUX = {"enabled": True, "protocol": "h2mux", "max_connections": 4, "min_streams": 4}
XRAY_MUX = {"enabled": True, "concurrency": 8, "xudpConcurrency": 16, "xudpProxyUDP443": "reject"}
XRAY_NOISES = [{"type": "rand", "packet": "10-20", "delay": "10-16"}]
XRAY_FRAGMENT = {"packets": "tlshello", "length": "100-200", "interval": "10-20"}

SB_FINGERPRINTS = frozenset({"chrome", "firefox", "edge", "safari", "360", "qq", "ios", "android", "random",
                             "randomized"})
_SS_METHODS = {"chacha20-poly1305": "chacha20-ietf-poly1305", "xchacha20-poly1305": "xchacha20-ietf-poly1305",
               "plain": "none"}
_VMESS_CIPHERS = frozenset({"auto", "none", "zero", "aes-128-gcm", "chacha20-poly1305", "aes-128-ctr"})
_SS_PLUGINS = {"obfs-local": "obfs-local", "simple-obfs": "obfs-local", "obfs": "obfs-local",
               "v2ray-plugin": "v2ray-plugin"}
_KCP_HEADERS = {"srtp": "header-srtp", "utp": "header-utp", "wechat-video": "header-wechat",
                "wechat": "header-wechat", "dtls": "header-dtls", "wireguard": "header-wireguard",
                "dns": "header-dns"}
_KCP_FIELDS = {"kcp_mtu": "mtu", "kcp_tti": "tti", "kcp_uplink": "uplinkCapacity",
               "kcp_downlink": "downlinkCapacity", "kcp_congestion": "congestion"}
_XRAY_NETWORKS = {"tcp": "raw", "ws": "ws", "grpc": "grpc", "httpupgrade": "httpupgrade", "xhttp": "xhttp",
                  "kcp": "kcp"}


class ConfigError(UserError):
    """План нельзя превратить в конфиг (текст — для человека, без секретов)."""


def tag(server_id: str) -> str:
    """Тег выхода сервера в sing-box (и имя в clash API: PUT /proxies/proxy {"name": tag})."""
    return f"srv-{server_id}"


def group_tag(group_id: str) -> str:
    """Тег urltest-группы «Самый быстрый»."""
    return f"grp-{group_id}"


def selected_tag(plan: RunPlan) -> str:
    """Что выбрать в селекторе proxy: сервер или группа (plan.selected = id или "auto:<группа>")."""
    if plan.selected.startswith("auto:"):
        return group_tag(plan.selected[len("auto:"):])
    return tag(plan.selected)


# ------------------------------------------------------------ общие помощники

def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address((host or "").strip("[]"))
        return True
    except ValueError:
        return False


def _sid(server: Server) -> str:
    return server.id or server.key()


def _addr(plan: RunPlan, server: Server) -> str:
    return plan.addresses.get(_sid(server)) or server.host


def _name(server: Server) -> str:
    return server.display_name()


def _as_list(value: Any) -> list[str]:
    if value is None or value == "":
        return []
    if isinstance(value, (list, tuple)):
        return [str(v).strip() for v in value if str(v).strip()]
    return [v.strip() for v in str(value).split(",") if v.strip()]


def _num(value: Any) -> int | None:
    """Число из поля ссылки: 30, "30", "30s", "100 Mbps" → 30/100; None — числа нет."""
    m = re.match(r"\s*(\d+)", str(value)) if value not in (None, "", True, False) else None
    return int(m.group(1)) if m else None


def _to(outbound: str) -> dict[str, str]:
    return {"action": "route", "outbound": outbound}


def _dns_to(server: str) -> dict[str, str]:
    return {"action": "route", "server": server}


def _port_fields(ports: Iterable[str]) -> dict[str, list]:
    """Порты как у winws («443», «50000-50100») → port / port_range sing-box."""
    single: list[int] = []
    ranges: list[str] = []
    for item in ports:
        lo, _, hi = str(item).partition("-")
        if hi and hi != lo:
            ranges.append(f"{int(lo)}:{int(hi)}")
        else:
            single.append(int(lo))
    out: dict[str, list] = {}
    if single:
        out["port"] = single
    if ranges:
        out["port_range"] = ranges
    return out


_RE_SPECIAL = frozenset("\\.+*?()|[]{}^$")


def _re_escape(text: str) -> str:
    """Экранирование для RE2 (Go): только служебные символы."""
    return "".join("\\" + ch if ch in _RE_SPECIAL else ch for ch in text)


def process_patterns(items: Iterable[str | None]) -> list[str]:
    """Программы человека → process_path_regex без учёта регистра (Windows не различает регистр
    путей, а process_name/process_path в sing-box сравниваются точно). Путь — целиком, имя exe —
    в любой папке."""
    out: list[str] = []
    for item in items:
        text = (item or "").strip().strip('"')
        if not text:
            continue
        if "\\" in text or "/" in text:
            pattern = "(?i)^" + _re_escape(text.replace("/", "\\")) + "$"
        else:
            pattern = "(?i)(^|\\\\)" + _re_escape(text) + "$"
        if pattern not in out:
            out.append(pattern)
    return out


def _b64url(value: str | None) -> str:
    return (value or "").strip().replace("+", "-").replace("/", "_").rstrip("=")


def sb_fingerprint(fp: str | None) -> str | None:
    """uTLS-отпечаток sing-box по отпечатку ссылки (у Xray имён больше). None — без uTLS."""
    f = (fp or "").strip().lower()
    if not f:
        return "chrome"                  # как у Xray: пустой отпечаток — chrome
    if f in SB_FINGERPRINTS:
        return f
    if f in ("unsafe", "hellogolang", "golang", "none"):
        return None
    if f.startswith("randomized") or f.startswith("hellorandomized"):
        return "randomized"
    for family in ("chrome", "firefox", "edge", "safari", "ios", "android", "360", "qq"):
        if f.startswith("hello" + family):
            return family
    return "chrome"


# ------------------------------------------------------------ серверы плана

def _servers(plan: RunPlan) -> list[tuple[Server, str]]:
    """(сервер, ядро) всех серверов плана, которые можно открыть; дубли по id — один раз."""
    out: list[tuple[Server, str]] = []
    seen: set[str] = set()
    for server in plan.servers:
        sid = _sid(server)
        if sid in seen:
            continue
        engine = plan.engines.get(sid) or engine_for(server)[0]
        if engine not in ENGINES:
            continue
        seen.add(sid)
        out.append((server, engine))
    if not out:
        raise ConfigError("В плане нет ни одного сервера, который можно открыть")
    return out


def _unsupported_reason(plan: RunPlan, server_id: str) -> str | None:
    for server in plan.servers:
        if _sid(server) == server_id:
            return engine_for(server)[1] or "сервер не поддерживается"
    return None


def _groups(plan: RunPlan, available: list[str]) -> list[dict[str, Any]]:
    out = []
    for group in plan.groups:
        members = [tag(m) for m in dict.fromkeys(group.members) if tag(m) in available][:MAX_GROUP]
        if not members:
            continue
        url = group.probe_url if (group.probe_url or "").startswith("https://") else plan.probe_url
        out.append({"type": "urltest", "tag": group_tag(group.id), "outbounds": members, "url": url,
                    "interval": f"{max(30, int(group.interval or 300))}s", "tolerance": URLTEST_TOLERANCE,
                    "interrupt_exist_connections": True})
    return out


def _proxy_selector(plan: RunPlan, server_tags: list[str], groups: list[dict[str, Any]]) -> dict[str, Any]:
    members = [g["tag"] for g in groups] + server_tags
    default = selected_tag(plan)
    if default not in members:
        if plan.selected.startswith("auto:"):
            raise ConfigError("Выбранная группа «Самый быстрый» не найдена в плане или в ней нет доступных серверов")
        reason = _unsupported_reason(plan, plan.selected)
        if reason:
            raise ConfigError(f"Выбранный сервер не открыть: {reason}")
        raise ConfigError("Выбранного сервера нет среди серверов плана")
    return {"type": "selector", "tag": SELECTOR_PROXY, "outbounds": members, "default": default,
            "interrupt_exist_connections": True}


# ------------------------------------------------------------ выходы sing-box

def _host_header(server: Server) -> str | None:
    """Host для ws/httpupgrade/http так, как его выбрал бы Xray при адресе-домене (host >
    serverName > адрес): адрес в конфиге уже IP, подставлять его в Host нельзя."""
    t = server.transport or {}
    host = t.get("host")
    if isinstance(host, (list, tuple)):
        host = host[0] if host else None
    if host:
        return str(host)
    if server.security in ("tls", "reality") and (server.tls or {}).get("sni"):
        return str(server.tls["sni"])
    return None if _is_ip(server.host) else server.host


def _strip_ed(path: str) -> tuple[str, int]:
    """«/ws?ed=2048» → («/ws», 2048): ранние данные Xray передаёт в пути, sing-box — полем."""
    parts = urlsplit(path or "/")
    if not parts.query:
        return path or "/", 0
    kept, ed = [], 0
    for item in parts.query.split("&"):
        key, _, value = item.partition("=")
        if key == "ed" and value.isdigit():
            ed = int(value)
            continue
        kept.append(item)
    clean = (parts.path or "/") + ("?" + "&".join(kept) if kept else "")
    return clean, ed


def _headers(server: Server) -> dict[str, str]:
    headers = (server.transport or {}).get("headers") or {}
    if not isinstance(headers, dict):
        return {}
    return {str(k): str(v) for k, v in headers.items() if str(k).lower() != "host"}


def _sb_transport(server: Server) -> dict[str, Any] | None:
    t = server.transport or {}
    net = server.network
    host = _host_header(server)
    if net == "tcp":
        if t.get("header_type") != "http":
            return None
        out: dict[str, Any] = {"type": "http", "method": "GET"}     # как HTTP-маскировка RAW у Xray
        hosts = _as_list(t.get("host")) or ([host] if host else [])
        if hosts:
            out["host"] = hosts
        out["path"] = (_as_list(t.get("path")) or ["/"])[0]
        if _headers(server):
            out["headers"] = _headers(server)
        return out
    if net == "ws":
        path, ed = _strip_ed(str(t.get("path") or "/"))
        ed = _num(t.get("early_data")) or ed
        out = {"type": "ws", "path": path}
        headers = _headers(server)
        if host:
            headers = {"Host": host, **headers}
        if headers:
            out["headers"] = headers
        if ed:
            out["max_early_data"] = ed
            out["early_data_header_name"] = "Sec-WebSocket-Protocol"   # так ранние данные шлёт Xray
        return out
    if net == "httpupgrade":
        path, _ = _strip_ed(str(t.get("path") or "/"))
        out = {"type": "httpupgrade", "path": path}
        if host:
            out["host"] = host
        if _headers(server):
            out["headers"] = _headers(server)
        return out
    if net == "grpc":
        return {"type": "grpc", "service_name": str(t.get("service_name") or "")}
    if net == "http":
        out = {"type": "http", "path": str(t.get("path") or "/")}
        hosts = _as_list(t.get("host"))
        if hosts:
            out["host"] = hosts
        return out
    raise ConfigError(f"Сервер «{_name(server)}»: транспорт {net} ядро sing-box не поддерживает")


def _sb_ech(value: Any) -> dict[str, Any]:
    """ECH из ссылки: base64 ECHConfigList → PEM; запрос через DNS («имя+https://…» у Xray) —
    ядро само возьмёт конфиг из записи HTTPS (для «имени» — query_server_name)."""
    out: dict[str, Any] = {"enabled": True}
    text = str(value).strip() if value not in (None, True) else ""
    if "://" in text:
        head = text.split("://", 1)[0]
        if "+" in head:
            out["query_server_name"] = head.split("+", 1)[0]
        return out
    if text and re.fullmatch(r"[A-Za-z0-9+/=_-]+", text):
        raw = text.replace("-", "+").replace("_", "/").rstrip("=")
        raw += "=" * (-len(raw) % 4)
        try:
            base64.b64decode(raw, validate=True)
        except ValueError:
            return out
        out["config"] = ["-----BEGIN ECH CONFIGS-----", *[raw[i:i + 64] for i in range(0, len(raw), 64)],
                         "-----END ECH CONFIGS-----"]
    return out


def _sb_tls(plan: RunPlan, server: Server, *, quic: bool) -> dict[str, Any] | None:
    if not quic and server.security not in ("tls", "reality"):
        return None
    t = server.tls or {}
    out: dict[str, Any] = {"enabled": True}
    sni = t.get("sni") or ("" if _is_ip(server.host) else server.host)
    if sni:
        out["server_name"] = str(sni)
    alpn = _as_list(t.get("alpn"))
    if server.network in ("ws", "httpupgrade") and not quic:
        alpn = []                        # ws и httpupgrade — только HTTP/1.1, ядро само ставит http/1.1
    if not alpn and quic:
        alpn = ["h3"]
    if alpn:
        out["alpn"] = alpn
    if t.get("insecure"):
        out["insecure"] = True
    reality = server.security == "reality" and not quic
    if not quic:
        fp = sb_fingerprint(t.get("fingerprint") or plan.fingerprint)   # отпечаток сервера важнее общего
        if reality and fp is None:
            fp = "chrome"                # REALITY без uTLS не работает
        if fp:
            out["utls"] = {"enabled": True, "fingerprint": fp}
        # Своя фрагментация или провайдера (dialerProxy с fragment), если сервер всё же у sing-box.
        if (plan.tls_fragment or server.fragment) and not reality:
            out["fragment"] = True       # REALITY фрагментацию ядра не применяет
    if reality:
        pbk = _b64url(t.get("pbk"))
        if not pbk:
            raise ConfigError(f"Сервер «{_name(server)}»: нет публичного ключа REALITY (pbk)")
        out["reality"] = {"enabled": True, "public_key": pbk, "short_id": str(t.get("sid") or "")}
    elif t.get("ech"):
        out["ech"] = _sb_ech(t.get("ech"))
    return out


def _with_stream(plan: RunPlan, ob: dict[str, Any], server: Server) -> dict[str, Any]:
    tls = _sb_tls(plan, server, quic=False)
    if tls:
        ob["tls"] = tls
    transport = _sb_transport(server)
    if transport:
        ob["transport"] = transport
    vision = (server.flow or "").startswith("xtls-rprx-vision")
    if plan.mux and not vision and server.network not in ("grpc", "http"):    # у gRPC и HTTP/2 мультиплекс свой
        ob["multiplex"] = dict(SB_MUX)
    return ob


def _need(server: Server, value: Any, what: str) -> Any:
    if value in (None, ""):
        raise ConfigError(f"Сервер «{_name(server)}»: нет {what}")
    return value


def _sb_vless(plan: RunPlan, server: Server, t: str) -> dict[str, Any]:
    if server.encryption not in ("", "none"):
        raise ConfigError(f"Сервер «{_name(server)}»: шифрование VLESS (ML-KEM) открывает только помощник Xray")
    ob = {"type": "vless", "tag": t, "server": _addr(plan, server), "server_port": server.port,
          "uuid": _need(server, server.uuid, "идентификатора пользователя")}
    if server.flow:
        if not server.flow.startswith("xtls-rprx-vision"):
            raise ConfigError(f"Сервер «{_name(server)}»: flow {server.flow} ядро sing-box не поддерживает")
        ob["flow"] = "xtls-rprx-vision"
    return _with_stream(plan, ob, server)


def _sb_vmess(plan: RunPlan, server: Server, t: str) -> dict[str, Any]:
    cipher = server.cipher if server.cipher in _VMESS_CIPHERS else "auto"
    ob = {"type": "vmess", "tag": t, "server": _addr(plan, server), "server_port": server.port,
          "uuid": _need(server, server.uuid, "идентификатора пользователя"), "security": cipher,
          "alter_id": int(server.alter_id or 0)}
    return _with_stream(plan, ob, server)


def _sb_trojan(plan: RunPlan, server: Server, t: str) -> dict[str, Any]:
    ob = {"type": "trojan", "tag": t, "server": _addr(plan, server), "server_port": server.port,
          "password": _need(server, server.password, "пароля")}
    return _with_stream(plan, ob, server)


def _plugin_opts(opts: Any) -> str:
    if isinstance(opts, str):
        return opts
    parts = []
    for key, value in (opts or {}).items():
        if value is True:
            parts.append(str(key))
        elif value not in (False, None, ""):
            parts.append(f"{key}={value}")
    return ";".join(parts)


def _no_stream(server: Server) -> None:
    """Shadowsocks и SOCKS в sing-box — без транспорта и TLS: молча выдать голый протокол нельзя."""
    if streamed(server):
        raise ConfigError(f"Сервер «{_name(server)}»: {server.proto} через {server.network}/{server.security} "
                          "открывает только помощник Xray")


def _sb_shadowsocks(plan: RunPlan, server: Server, t: str) -> dict[str, Any]:
    _no_stream(server)
    method = _need(server, server.method, "метода шифрования").lower()
    ob: dict[str, Any] = {"type": "shadowsocks", "tag": t, "server": _addr(plan, server), "server_port": server.port,
                          "method": _SS_METHODS.get(method, method),
                          "password": _need(server, server.password, "пароля")}
    if server.plugin:
        name = _SS_PLUGINS.get(str(server.plugin.get("name") or "").lower())
        if name is None:
            raise ConfigError(f"Сервер «{_name(server)}»: плагин {server.plugin.get('name')} не поддерживается")
        ob["plugin"] = name
        opts = _plugin_opts(server.plugin.get("opts"))
        if opts:
            ob["plugin_opts"] = opts
    elif plan.mux:
        ob["multiplex"] = dict(SB_MUX)
    return ob


def hop_ports(spec: str) -> list[str]:
    """Порты Hysteria2 из ссылки («443,20000-30000») → server_ports sing-box («443:443», «20000:30000»)."""
    out = []
    for item in _as_list(spec):
        lo, _, hi = item.partition("-")
        if not lo.isdigit() or (hi and not hi.isdigit()):
            raise ValueError(f"порты Hysteria2: {item}")
        out.append(f"{int(lo)}:{int(hi or lo)}")
    return out


def hop_interval(value: Any) -> tuple[int | None, int | None]:
    """Интервал прыжков Hysteria2 («30», «10-30», 30) → (от, до) в секундах; (None, None) — не задан."""
    m = re.fullmatch(r"\s*(\d+)\s*(?:s\s*)?(?:-\s*(\d+)\s*s?\s*)?", str(value)) \
        if value not in (None, "", True, False) else None
    if not m:
        return None, None
    low = int(m.group(1))
    high = int(m.group(2)) if m.group(2) else low
    return min(low, high), max(low, high)


def _sb_hysteria2(plan: RunPlan, server: Server, t: str) -> dict[str, Any]:
    hy = server.hy2 or {}
    ob: dict[str, Any] = {"type": "hysteria2", "tag": t, "server": _addr(plan, server)}
    if hy.get("ports"):
        try:
            ob["server_ports"] = hop_ports(str(hy["ports"]))     # вместе с server_port нельзя
        except ValueError as exc:
            raise ConfigError(f"Сервер «{_name(server)}»: {exc}") from exc
        low, high = hop_interval(hy.get("hop_interval"))
        if low:
            ob["hop_interval"] = f"{low}s"
        if high and high != low:
            ob["hop_interval_max"] = f"{high}s"      # интервал «10-30» — случайный в этих пределах
    else:
        ob["server_port"] = server.port
    if server.password:
        ob["password"] = server.password
    for key in ("up_mbps", "down_mbps"):
        if _num(hy.get(key)):
            ob[key] = _num(hy[key])
    if hy.get("obfs"):
        ob["obfs"] = {"type": str(hy["obfs"]), "password": str(hy.get("obfs_password") or "")}
    ob["tls"] = _sb_tls(plan, server, quic=True)
    return ob


def _sb_tuic(plan: RunPlan, server: Server, t: str) -> dict[str, Any]:
    tu = server.tuic or {}
    ob: dict[str, Any] = {"type": "tuic", "tag": t, "server": _addr(plan, server), "server_port": server.port,
                          "uuid": _need(server, server.uuid, "идентификатора пользователя")}
    if server.password:
        ob["password"] = server.password
    if tu.get("congestion_control"):
        ob["congestion_control"] = str(tu["congestion_control"])
    if tu.get("udp_relay_mode"):
        ob["udp_relay_mode"] = str(tu["udp_relay_mode"])
    ob["tls"] = _sb_tls(plan, server, quic=True)
    return ob


def _sb_socks(plan: RunPlan, server: Server, t: str) -> dict[str, Any]:
    _no_stream(server)
    ob: dict[str, Any] = {"type": "socks", "tag": t, "server": _addr(plan, server), "server_port": server.port,
                          "version": "5"}
    if server.username:
        ob["username"] = server.username
    if server.password:
        ob["password"] = server.password
    return ob


def _prefix(address: str) -> str:
    text = str(address).strip()
    if "/" in text:
        return text
    return f"{text}/128" if ":" in text else f"{text}/32"


def _sb_wireguard(plan: RunPlan, server: Server, t: str) -> dict[str, Any]:
    wg = server.wg or {}
    addresses = [_prefix(a) for a in _as_list(wg.get("local_address"))]
    if not addresses:
        raise ConfigError(f"Сервер «{_name(server)}»: у WireGuard нет адреса интерфейса")
    peer: dict[str, Any] = {"address": _addr(plan, server), "port": server.port,
                            "public_key": _need(server, wg.get("peer_public_key"), "публичного ключа сервера"),
                            "allowed_ips": ["0.0.0.0/0", "::/0"]}
    if wg.get("preshared_key"):
        peer["pre_shared_key"] = wg["preshared_key"]
    if wg.get("reserved"):
        peer["reserved"] = [n for n in (_num(x) for x in _as_list(wg["reserved"])) if n is not None]
    keepalive = _num(wg.get("persistent_keepalive") or wg.get("keepalive"))
    if keepalive:
        peer["persistent_keepalive_interval"] = keepalive
    ep: dict[str, Any] = {"type": "wireguard", "tag": t, "address": addresses,
                          "private_key": _need(server, wg.get("private_key"), "закрытого ключа"), "peers": [peer]}
    if _num(wg.get("mtu")):
        ep["mtu"] = _num(wg["mtu"])
    return ep


_SB_BUILDERS = {"vless": _sb_vless, "vmess": _sb_vmess, "trojan": _sb_trojan, "shadowsocks": _sb_shadowsocks,
                "hysteria2": _sb_hysteria2, "tuic": _sb_tuic, "socks": _sb_socks, "wireguard": _sb_wireguard}


def _sb_outbound(plan: RunPlan, server: Server, engine: str) -> dict[str, Any]:
    sid = _sid(server)
    if engine == "xray":
        port = plan.ports.helper.get(sid)
        if not port:
            raise ConfigError(f"Сервер «{_name(server)}»: не выбран порт помощника Xray")
        return {"type": "socks", "tag": tag(sid), "server": HELPER_HOST, "server_port": int(port), "version": "5",
                "username": plan.secrets.helper_user, "password": plan.secrets.helper_pass}
    builder = _SB_BUILDERS.get(server.proto)
    if builder is None:
        raise ConfigError(f"Сервер «{_name(server)}»: протокол {server.proto} не поддерживается")
    return builder(plan, server, tag(sid))


def _server_outbounds(plan: RunPlan, servers: list[tuple[Server, str]]
                      ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    outbounds, endpoints, tags = [], [], []
    for server, engine in servers:
        ob = _sb_outbound(plan, server, engine)
        (endpoints if ob["type"] == "wireguard" else outbounds).append(ob)
        tags.append(ob["tag"])
    return outbounds, endpoints, tags


# ------------------------------------------------------------ DNS

def _doh(url: str, tag_: str, *, detour: str | None = None) -> tuple[dict[str, Any], bool]:
    """DoH-сервер нового формата (1.12+). Второе значение — нужен ли запасной резолвер для имени."""
    parts = urlsplit((url or "").strip())
    host = parts.hostname or ""
    if parts.scheme != "https" or not host:
        raise ConfigError(f"DNS-резолвер должен быть адресом https://…, получено: {url!r}")
    out: dict[str, Any] = {"type": "https", "tag": tag_}
    bootstrap = False
    if _is_ip(host):
        out["server"] = host
        sni = _DOH_SNI.get(host)
    elif host in _DOH_IP:
        out["server"] = _DOH_IP[host]
        sni = host
    else:
        out["server"] = host
        sni = None
        if detour is None:
            out["domain_resolver"] = DNS_BOOTSTRAP
            bootstrap = True
    out["server_port"] = parts.port or 443
    out["path"] = parts.path or "/dns-query"
    if sni:
        out["tls"] = {"server_name": sni}
    if detour:
        out["detour"] = detour
    return out, bootstrap


def _domain_parts(group: routing.SiteGroup, available: set[str]) -> list[dict[str, Any]]:
    """Доменная часть списка сайтов для DNS-правил. Поля и rule-set — разными правилами: rule-set не из
    одного простого правила sing-box сочетает с полями правила через И, а не через ИЛИ."""
    out: list[dict[str, Any]] = []
    fields = {k: list(v) for k, v in group.fields.items() if k != "ip_cidr"}
    if fields:
        out.append(fields)
    sets = [s for s in group.rule_sets if s in available and routing.rule_set_kind(s) == "domain"]
    if sets:
        out.append({"rule_set": sets})
    for set_id in group.negated_sets:            # geosite:!X — все имена, кроме набора
        if set_id in available and routing.rule_set_kind(set_id) == "domain":
            out.append({"rule_set": [set_id], "invert": True})
    return out


def _dns_rules_from_route(rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """DNS для доменов профиля маршрутизации: прямые — dns-direct, через VPN — dns-remote."""
    out = []
    for rule in rules:
        if rule.get("type") == "logical" or rule.get("action") != "route":
            continue
        if any(k in rule for k in ("port", "port_range", "network", "protocol", "ip_cidr", "ip_is_private")):
            continue
        server = DNS_DIRECT if rule.get("outbound") == DIRECT else DNS_REMOTE
        part = {k: rule[k] for k in ("domain", "domain_suffix", "domain_keyword", "domain_regex") if k in rule}
        sets = [s for s in _as_list(rule.get("rule_set")) if routing.rule_set_kind(s) == "domain"]
        if part and sets:
            continue                     # поля и rule-set в одном правиле — смысл И, в DNS не переносим
        if rule.get("invert"):
            if sets and not part and len(sets) == len(_as_list(rule.get("rule_set"))):
                out.append({"rule_set": sets, "invert": True, **_dns_to(server)})
            continue                     # «не IP-набор» и «не эти имена» в DNS не переносим
        if part:
            out.append({**part, **_dns_to(server)})
        elif sets:
            out.append({"rule_set": sets, **_dns_to(server)})
    return out


def _app_dns(apps: list[str], server: str) -> list[dict[str, Any]]:
    """DNS программы — тем же путём, что её трафик. Срабатывает, когда программа резолвит имена сама;
    запрос через службу DNS Windows (svchost.exe) ядро программе приписать не может — тогда имя идёт
    по правилам сайтов, а соединение программы всё равно уходит по её правилу."""
    patterns = process_patterns(apps)
    return [{"process_path_regex": patterns, **_dns_to(server)}] if patterns else []


def _dns(plan: RunPlan, servers: list[tuple[Server, str]], available: set[str],
         profile_rules: list[dict[str, Any]], ends: _Ends) -> dict[str, Any]:
    tun = plan.mode == "tun"
    remote, need_a = _doh(plan.dns.remote, DNS_REMOTE, detour=SELECTOR_PROXY)
    direct, need_b = _doh(plan.dns.direct, DNS_DIRECT)
    dns_servers = [remote, direct]
    rules: list[dict[str, Any]] = []
    hosts = sorted({s.host for s, _ in servers if s.host and not _is_ip(s.host)})
    if hosts:                            # иначе помощник в TUN резолвил бы свой сервер через dns-remote
        rules.append({"domain": hosts, **_dns_to(DNS_DIRECT)})
    # Свои правила — в том же порядке, что маршруты: «через VPN» (программы, сайты), затем «мимо VPN».
    for apps, sites, server in ((plan.proxy_apps, plan.proxy_sites, DNS_REMOTE),
                                (plan.direct_apps, plan.direct_sites, DNS_DIRECT)):
        rules += _app_dns(apps, server)
        rules.extend({**part, **_dns_to(server)} for part in _domain_parts(routing.site_group(sites), available))
    if plan.via_zapret and ends.bypass:
        sets = list(dict.fromkeys(Path(p.domains_file).stem for p in plan.bypass if p.domains_file))
        if sets:
            # Тот же DoH, что dns-direct, но через селектор bypass: пока обход работает — напрямую,
            # выключен или сломался — через сервер вместе с трафиком этих сайтов.
            dns_servers.append(_doh(plan.dns.direct, DNS_BYPASS, detour=SELECTOR_BYPASS)[0])
            rules.append({"rule_set": sets, **_dns_to(DNS_BYPASS)})
    if plan.games_direct and routing.GAMES_DOWNLOAD in available:
        rules.append({"rule_set": [routing.GAMES_DOWNLOAD], **_dns_to(DNS_DIRECT)})
    if plan.ip_check_direct:
        rules.append({"domain_suffix": list(routing.IP_CHECK_SITES), **_dns_to(DNS_DIRECT)})
    rules.extend(_dns_rules_from_route(profile_rules))
    fakeip = tun and plan.dns.fakeip
    if ends.preset == "except_ru":
        ru: list[dict[str, Any]] = []
        if routing.RU_DOMAINS in available:
            ru.append({"rule_set": [routing.RU_DOMAINS], **_dns_to(DNS_RU)})
        additions = [d for d in (routing.normalize_domain(a) for a in plan.additions) if d]
        if additions:
            ru.append({"domain_suffix": additions, **_dns_to(DNS_RU)})
        if ru:
            dns_servers.append(_doh(plan.dns.ru, DNS_RU)[0])
            rules.extend(ru)
    elif ends.preset == "blocked":
        sets = [s for s in routing.BLOCKED_DOMAINS if s in available]
        if sets:
            if fakeip:
                rules.append({"rule_set": sets, "query_type": ["A", "AAAA"], **_dns_to(DNS_FAKEIP)})
            rules.append({"rule_set": sets, **_dns_to(DNS_REMOTE)})
    if fakeip:
        dns_servers.append({"type": "fakeip", "tag": DNS_FAKEIP, "inet4_range": FAKEIP_V4, "inet6_range": FAKEIP_V6})
        if ends.final != DIRECT:         # остальное идёт напрямую — ему нужны настоящие адреса
            rules.append({"query_type": ["A", "AAAA"], **_dns_to(DNS_FAKEIP)})
    if need_a or need_b or any(s.get("domain_resolver") == DNS_BOOTSTRAP for s in dns_servers):
        dns_servers.append(_doh(BOOTSTRAP_DOH, DNS_BOOTSTRAP)[0])
    return {"servers": dns_servers, "rules": rules,
            "final": DNS_DIRECT if ends.final == DIRECT else DNS_REMOTE, "strategy": plan.dns.strategy}


# ------------------------------------------------------------ маршруты

@dataclass
class _Ends:
    """Чем кончается маршрут: route.final, пресет, чьи правила действуют, и строгий режим.

    strict — с какого места «через VPN» не исполнить (routing.strict_level): нет файла своего списка
    «только через VPN» (user) — не действуют «через обход», прямые правила профиля и пресета; нет файла
    правила профиля «через VPN» (profile) — прямые правила профиля и пресета; нет ни одного списка пресета
    «Только заблокированное» (preset) — его «остальное напрямую». Во всех случаях final — proxy; явные
    правила человека «мимо VPN» и переключатели остаются."""

    final: str                  # proxy | direct
    preset: str | None          # None — пресет заменил выход по умолчанию профиля или строгий режим
    strict: str | None = None   # None | user | profile | preset

    @property
    def bypass(self) -> bool:
        """Действует ли «через обход»."""
        return self.strict != "user"

    @property
    def profile_direct(self) -> bool:
        """Действуют ли прямые правила профиля маршрутизации."""
        return self.strict not in ("user", "profile")


def missing_vpn_sets(plan: RunPlan, available: Iterable[str]) -> list[str]:
    """Наборы «через VPN» плана (свои списки, правила профиля, пресет «Только заблокированное»),
    которых нет среди available: при них конфиг строится в строгом режиме (_Ends.strict)."""
    return routing.missing_vpn_sets(routing.vpn_required(plan.proxy_sites, plan.profile_rules, plan.preset),
                                    available)


def _ends(plan: RunPlan, available: set[str], profile_final: str | None) -> _Ends:
    strict = routing.strict_level(routing.vpn_required(plan.proxy_sites, plan.profile_rules, plan.preset),
                                  available)
    if strict:
        return _Ends(SELECTOR_PROXY, None, strict)
    if profile_final:
        return _Ends(profile_final, None)
    return _Ends(DIRECT if plan.preset == "blocked" else SELECTOR_PROXY, plan.preset)


def _split_profile(rules: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], str | None]:
    """(правила профиля до его «всего остального», выход «всего остального» или None)."""
    for i, rule in enumerate(rules):
        if routing.catch_all(rule):
            return rules[:i], rule["outbound"]
    return rules, None


def _site_rules(entries: list[str], outbound: str, available: set[str]) -> list[dict[str, Any]]:
    group = routing.site_group(entries)
    out: list[dict[str, Any]] = []
    if group.fields:
        out.append({**{k: list(v) for k, v in group.fields.items()}, **_to(outbound)})
    sets = [s for s in group.rule_sets if s in available]
    if sets:
        out.append({"rule_set": sets, **_to(outbound)})
    for set_id in group.negated_sets:            # geoip:!ru — всё, что не в наборе
        if set_id in available:
            out.append({"rule_set": [set_id], "invert": True, **_to(outbound)})
    if group.private is not None:
        out.append({**routing.private_match(group.private), **_to(outbound)})
    return out


def _app_rules(apps: list[str], outbound: str) -> list[dict[str, Any]]:
    patterns = process_patterns(apps)
    return [{"process_path_regex": patterns, **_to(outbound)}] if patterns else []


def _guarded(match: dict[str, Any], exclude: str | None, action: dict[str, Any]) -> dict[str, Any]:
    """Правило обхода без адресов --ipset-exclude профиля: к ним winws не прикасается."""
    if not exclude:
        return {**match, **action}
    return {"type": "logical", "mode": "and", "rules": [match, {"rule_set": [exclude], "invert": True}], **action}


def _bypass_rules(plan: RunPlan) -> list[dict[str, Any]]:
    """«Через обход»: для каждого (сеть, порты) профиля winws — rule-set → селектор bypass (с
    --filter-l7 — только эти протоколы, их распознаёт sniff); голос Discord — по процессу и UDP-портам
    голоса; домены только TCP-профилей — reject udp/443 (клиент сразу уходит на TCP, где работает
    winws). Отказы — после всех правил обхода: домен, который winws обрабатывает и по UDP, раньше
    уйдёт в bypass. Адреса --ipset-exclude профиля исключаются из всех его правил."""
    rules: list[dict[str, Any]] = []
    rejects: list[dict[str, Any]] = []
    to_bypass = _to(SELECTOR_BYPASS)
    for prof in plan.bypass:
        ports = _port_fields(prof.ports)
        base = {"network": [prof.network], **ports}
        exclude = Path(prof.exclude_file).stem if prof.exclude_file else None
        protocols = list(dict.fromkeys(routing.L7_SNIFF[x] for x in prof.l7 if x in routing.L7_SNIFF))
        lists = [Path(path).stem for path in (prof.domains_file, prof.ips_file) if path]
        for set_id in lists:
            if not prof.l7:
                rules.append(_guarded({**base, "rule_set": [set_id]}, exclude, to_bypass))
                continue
            if protocols:
                rules.append(_guarded({**base, "protocol": protocols, "rule_set": [set_id]}, exclude, to_bypass))
            if "discord" in prof.l7:
                rules.append(_guarded({"process_name": list(routing.DISCORD_APPS), **base, "rule_set": [set_id]},
                                      exclude, to_bypass))
        if not lists and prof.network == "udp" and "discord" in prof.l7:
            rules.append(_guarded({"process_name": list(routing.DISCORD_APPS), "network": ["udp"],
                                   **_port_fields(plan.voice_ports or prof.ports)}, exclude, to_bypass))
        if not lists and prof.network == "udp" and "stun" in prof.l7:
            rules.append(_guarded({"protocol": ["stun"], **base}, exclude, to_bypass))
        if prof.reject_quic and prof.domains_file:
            rejects.append(_guarded({"network": ["udp"], "port": [443], "rule_set": [Path(prof.domains_file).stem]},
                                    exclude, {"action": "reject"}))
    return _unique(rules + rejects)


def _unique(rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen, out = set(), []
    for rule in rules:
        key = json.dumps(rule, sort_keys=True)
        if key not in seen:
            seen.add(key)
            out.append(rule)
    return out


_MATCH_KEYS = frozenset({
    "domain", "domain_suffix", "domain_keyword", "domain_regex", "ip_cidr", "ip_is_private", "rule_set",
    "protocol", "process_name", "process_path", "process_path_regex", "source_ip_cidr", "inbound",
    "port", "port_range", "network", "type"})


def filter_rule_sets(rules: list[dict[str, Any]], available: set[str]) -> list[dict[str, Any]]:
    """Правила профиля маршрутизации без недоступных rule-set: сбой загрузки одного списка не ломает
    конфиг. Правило, у которого не осталось условий, кроме портов и сети, выбрасывается — иначе оно
    стало бы шире задуманного."""
    out = []
    for rule in rules:
        kept = _filter_rule(rule, available)
        if kept is not None:
            out.append(kept)
    return out


def _filter_rule(rule: dict[str, Any], available: set[str]) -> dict[str, Any] | None:
    rule = copy.deepcopy(rule)
    if rule.get("type") == "logical":
        subs = [_filter_rule(r, available) for r in rule.get("rules", [])]
        if rule.get("mode") == "and" and any(s is None for s in subs):
            return None
        subs = [s for s in subs if s is not None]
        if not subs:
            return None
        rule["rules"] = subs
        return rule
    if "rule_set" in rule:
        wanted = _as_list(rule["rule_set"])
        sets = [s for s in wanted if s in available]
        if sets:
            rule["rule_set"] = sets
        else:
            del rule["rule_set"]
            strong = _MATCH_KEYS - {"port", "port_range", "network", "type", "inbound"}
            if not any(k in rule for k in strong):
                return None
    return rule


def _preset_rules(plan: RunPlan, preset: str | None, available: set[str]) -> list[dict[str, Any]]:
    if preset == "except_ru":
        out = []
        sets = [s for s in routing.preset_rule_sets("except_ru", games=False) if s in available]
        if sets:
            out.append({"rule_set": sets, **_to(DIRECT)})
        additions = [d for d in (routing.normalize_domain(a) for a in plan.additions) if d]
        if additions:
            out.append({"domain_suffix": additions, **_to(DIRECT)})
        return out
    if preset == "blocked":
        sets = [s for s in routing.preset_rule_sets("blocked", games=False) if s in available]
        return [{"rule_set": sets, **_to(SELECTOR_PROXY)}] if sets else []
    return []


def _route_rules(plan: RunPlan, servers: list[tuple[Server, str]], available: set[str],
                 profile_rules: list[dict[str, Any]], ends: _Ends, *, proxy_inbound: bool) -> list[dict[str, Any]]:
    """Порядок — план 5.5: sniff → hijack-dns (TUN) → служебный вход → частные сети → Лазейка и
    помощник (TUN) → свои правила человека → «через обход» → переключатели → профиль маршрутизации →
    пресет (дальше route.final)."""
    tun = plan.mode == "tun"
    sniffers = list(SNIFFERS)
    if plan.via_zapret and any("stun" in p.l7 for p in plan.bypass):
        sniffers.append("stun")
    rules: list[dict[str, Any]] = [{"action": "sniff", "sniffer": sniffers}]
    if tun:
        rules.append({"protocol": ["dns"], "action": "hijack-dns"})
    rules.append({"inbound": [INTERNAL_IN], **_to(SELECTOR_PROXY)})
    if proxy_inbound and not plan.socks_udp:
        rules.append({"inbound": [PROXY_IN], "network": ["udp"], "action": "reject"})
    rules.append({"ip_is_private": True, **_to(DIRECT)})
    rules.append({"domain_suffix": list(LOCAL_SUFFIXES), **_to(DIRECT)})
    if tun:
        own = [plan.lazeyka_exe]
        if any(engine == "xray" for _, engine in servers):
            own.append(plan.xray_exe)
        patterns = process_patterns(own)
        if patterns:
            rules.append({"inbound": [TUN_IN], "process_path_regex": patterns, **_to(DIRECT)})
    rules += _app_rules(plan.proxy_apps, SELECTOR_PROXY) + _site_rules(plan.proxy_sites, SELECTOR_PROXY, available)
    rules += _app_rules(plan.direct_apps, DIRECT) + _site_rules(plan.direct_sites, DIRECT, available)
    if plan.via_zapret and ends.bypass:
        rules += _bypass_rules(plan)
    if plan.games_direct and routing.GAMES_DOWNLOAD in available:
        rules.append({"rule_set": [routing.GAMES_DOWNLOAD], **_to(DIRECT)})
    if plan.torrents_direct:
        rules.append({"protocol": ["bittorrent"], **_to(DIRECT)})
        rules += _app_rules(list(routing.TORRENT_APPS) + list(plan.torrent_apps), DIRECT)
    if plan.ip_check_direct:
        rules.append({"domain_suffix": list(routing.IP_CHECK_SITES), **_to(DIRECT)})
    rules += profile_rules
    rules += _preset_rules(plan, ends.preset, available)
    return rules


def _rule_set_files(plan: RunPlan) -> dict[str, tuple[Path, str]]:
    files: dict[str, tuple[Path, str]] = {}
    for set_id, path in plan.rules_files.items():
        p = Path(path)
        files[set_id] = (p, "source" if p.suffix.lower() == ".json" else "binary")
    if plan.via_zapret:
        for prof in plan.bypass:
            for path in (prof.domains_file, prof.ips_file, prof.exclude_file):
                if path:
                    files[Path(path).stem] = (Path(path), "source")
    return files


def _rule_set_decls(files: dict[str, tuple[Path, str]], used: Iterable[str]) -> list[dict[str, Any]]:
    """Объявления только тех rule-set, на которые ссылаются правила (ядро грузит каждый объявленный).
    Ссылку без файла не объявляем — её покажет validate()."""
    out = []
    for set_id in dict.fromkeys(used):
        if set_id in files:
            path, fmt = files[set_id]
            out.append({"type": "local", "tag": set_id, "format": fmt, "path": str(path)})
    return out


# ------------------------------------------------------------ сборка

def _check_plan(plan: RunPlan) -> None:
    if plan.mode not in MODES:
        raise ConfigError(f"Неизвестный режим: {plan.mode}")
    if plan.mode == "tun" and plan.tun is None:
        raise ConfigError("Для режима TUN не выбрана подсеть адаптера")
    if plan.preset not in routing.PRESET_RULE_SETS:
        raise ConfigError(f"Неизвестный пресет маршрутов: {plan.preset}")
    if plan.dns.strategy not in _STRATEGIES:
        raise ConfigError(f"Неизвестная стратегия DNS: {plan.dns.strategy}")
    if not plan.ports.clash or not plan.secrets.clash:
        raise ConfigError("Не выбраны порт и секрет API ядра")


def _log(plan: RunPlan) -> dict[str, Any]:
    level = {"warning": "warn"}.get(plan.log_level, plan.log_level)
    if level not in _LOG_LEVELS:
        raise ConfigError(f"Неизвестный уровень журнала: {plan.log_level}")
    return {"level": level, "timestamp": True}


def _clash(plan: RunPlan) -> dict[str, Any]:
    return {"external_controller": f"127.0.0.1:{plan.ports.clash}", "secret": plan.secrets.clash,
            "access_control_allow_origin": [API_ORIGIN]}


def _inbounds(plan: RunPlan) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if plan.mode == "tun":
        assert plan.tun is not None
        t = plan.tun
        tun_in: dict[str, Any] = {"type": "tun", "tag": TUN_IN, "interface_name": t.interface_name,
                                  "address": [t.address4] + ([t.address6] if t.address6 else []), "mtu": int(t.mtu),
                                  "auto_route": True, "strict_route": True, "dns_mode": "hijack"}
        exclude = without_networks(t.exclude, [FAKEIP_V4, FAKEIP_V6]) if plan.dns.fakeip else list(t.exclude)
        if exclude:
            tun_in["route_exclude_address"] = exclude
        out.append(tun_in)
    if _has_proxy_inbound(plan):
        mixed: dict[str, Any] = {"type": "mixed", "tag": PROXY_IN, "listen": plan.proxy_listen,
                                 "listen_port": int(plan.ports.proxy)}
        if plan.secrets.local_user and plan.secrets.local_pass:
            mixed["users"] = [{"username": plan.secrets.local_user, "password": plan.secrets.local_pass}]
        elif _loopback(plan.proxy_listen) is not True:
            # Без пароля это открытый прокси для всей локальной сети — через сервер человека.
            raise ConfigError("Вход для устройств из сети — только с логином и паролем, а их в плане нет")
        out.append(mixed)
    if not plan.ports.internal or not plan.secrets.internal_user or not plan.secrets.internal_pass:
        raise ConfigError("Не выбраны порт и учётная запись служебного входа")
    out.append({"type": "mixed", "tag": INTERNAL_IN, "listen": "127.0.0.1", "listen_port": int(plan.ports.internal),
                "users": [{"username": plan.secrets.internal_user, "password": plan.secrets.internal_pass}]})
    return out


def without_networks(nets: Iterable[str], cut: Iterable[str]) -> list[str]:
    """Подсети nets без подсетей cut: пулы Fake-IP вычитаются из исключений TUN — иначе синтетические
    адреса (fc00::/18 внутри fc00::/7) шли бы мимо туннеля и соединения с ними рвались."""
    pools = [ipaddress.ip_network(c, strict=False) for c in cut]
    out: list[str] = []
    for text in nets:
        try:
            parts = [ipaddress.ip_network(str(text).strip(), strict=False)]
        except ValueError:
            out.append(str(text))        # не подсеть — как было (validate и ядро скажут своё)
            continue
        for pool in pools:
            left = []
            for part in parts:
                if part.version != pool.version or not part.overlaps(pool):
                    left.append(part)
                elif part.prefixlen < pool.prefixlen:      # пул внутри — вырезаем его
                    left.extend(part.address_exclude(pool))
                # иначе подсеть целиком внутри пула — её не исключаем вовсе
            parts = left
        out.extend(str(p) for p in sorted(parts))
    return out


def _has_proxy_inbound(plan: RunPlan) -> bool:
    """Системный и локальный прокси — всегда; в TUN — только для раздачи в локальную сеть."""
    if plan.mode in ("proxy", "local"):
        return True
    return _loopback(plan.proxy_listen) is False


def _loopback(listen: str) -> bool | None:
    """Вход слушает только этот компьютер (127.0.0.1, ::1); None — это не адрес."""
    try:
        return ipaddress.ip_address(listen).is_loopback
    except ValueError:
        return None


def build_singbox(plan: RunPlan) -> dict[str, Any]:
    """Рабочий конфиг sing-box 1.14.3 по плану менеджера."""
    _check_plan(plan)
    servers = _servers(plan)
    server_obs, endpoints, server_tags = _server_outbounds(plan, servers)
    groups = _groups(plan, server_tags)
    outbounds = [_proxy_selector(plan, server_tags, groups), *groups,
                 {"type": "selector", "tag": SELECTOR_BYPASS, "outbounds": [DIRECT, SELECTOR_PROXY],
                  "default": plan.bypass_state if plan.bypass_state in (DIRECT, SELECTOR_PROXY) else SELECTOR_PROXY,
                  "interrupt_exist_connections": True},
                 *server_obs, {"type": "direct", "tag": DIRECT}]
    files = _rule_set_files(plan)
    available = set(files)
    profile_rules, profile_final = _split_profile(filter_rule_sets(list(plan.profile_rules), available))
    ends = _ends(plan, available, profile_final)
    if not ends.profile_direct:
        profile_rules = [r for r in profile_rules if r.get("outbound") != DIRECT]
    rules = _route_rules(plan, servers, available, profile_rules, ends, proxy_inbound=_has_proxy_inbound(plan))
    dns = _dns(plan, servers, available, profile_rules, ends)
    cfg: dict[str, Any] = {
        "log": _log(plan),
        "dns": dns,
        "inbounds": _inbounds(plan),
        "outbounds": outbounds,
        "route": {
            "rules": rules,
            "rule_set": _rule_set_decls(files, [*routing.rule_set_tags(rules), *routing.rule_set_tags(dns["rules"])]),
            "final": ends.final,
            "auto_detect_interface": True,
            "default_domain_resolver": {"server": DNS_DIRECT, "strategy": plan.dns.strategy},
        },
        "experimental": {"clash_api": _clash(plan)},
    }
    if endpoints:
        cfg["endpoints"] = endpoints
    if not cfg["route"]["rule_set"]:
        del cfg["route"]["rule_set"]
    return cfg


def build_delay(plan: RunPlan) -> dict[str, Any]:
    """Временный экземпляр для задержки при выключенном ядре: только выходы и API (без входов и
    TUN). Все серверы — в селекторе proxy: GET /group/proxy/delay меряет их параллельно."""
    if not plan.ports.clash or not plan.secrets.clash:
        raise ConfigError("Не выбраны порт и секрет API ядра")
    if plan.dns.strategy not in _STRATEGIES:
        raise ConfigError(f"Неизвестная стратегия DNS: {plan.dns.strategy}")
    servers = _servers(plan)
    server_obs, endpoints, server_tags = _server_outbounds(plan, servers)
    direct_dns, bootstrap = _doh(plan.dns.direct, DNS_DIRECT)
    dns_servers = [direct_dns] + ([_doh(BOOTSTRAP_DOH, DNS_BOOTSTRAP)[0]] if bootstrap else [])
    cfg: dict[str, Any] = {
        "log": _log(plan),
        "dns": {"servers": dns_servers, "strategy": plan.dns.strategy},
        "outbounds": [{"type": "selector", "tag": SELECTOR_PROXY, "outbounds": server_tags,
                       "default": server_tags[0], "interrupt_exist_connections": True},
                      *server_obs, {"type": "direct", "tag": DIRECT}],
        "route": {"final": SELECTOR_PROXY, "auto_detect_interface": True,
                  "default_domain_resolver": {"server": DNS_DIRECT, "strategy": plan.dns.strategy}},
        "experimental": {"clash_api": _clash(plan)},
    }
    if endpoints:
        cfg["endpoints"] = endpoints
    return cfg


# ------------------------------------------------------------ помощник Xray

def _xray_tls(plan: RunPlan, server: Server, *, quic: bool) -> tuple[str, dict[str, Any]] | None:
    t = server.tls or {}
    if server.security == "reality" and not quic:
        settings: dict[str, Any] = {"serverName": str(t.get("sni") or ""),
                                    "fingerprint": str(t.get("fingerprint") or plan.fingerprint or "chrome"),
                                    "password": _need(server, _b64url(t.get("pbk")), "публичного ключа REALITY (pbk)"),
                                    "shortId": str(t.get("sid") or "")}
        if t.get("spx"):
            settings["spiderX"] = str(t["spx"])
        if t.get("pqv"):
            settings["mldsa65Verify"] = str(t["pqv"])
        return "realitySettings", settings
    if server.security != "tls" and not quic:
        return None
    if t.get("insecure") and not t.get("pcs"):
        raise ConfigError(f"Сервер «{_name(server)}»: Xray 26 не принимает отключённую проверку сертификата")
    settings = {}
    sni = t.get("sni") or ("" if _is_ip(server.host) else server.host)
    if sni:
        settings["serverName"] = str(sni)
    alpn = _as_list(t.get("alpn")) or (["h3"] if quic else [])
    if alpn:
        settings["alpn"] = alpn
    fp = t.get("fingerprint") or plan.fingerprint
    if fp and not quic:
        settings["fingerprint"] = str(fp)
    pins = _as_list(t.get("pcs"))
    if quic and (server.hy2 or {}).get("pin_sha256"):
        pins = pins or _as_list(server.hy2["pin_sha256"])
    if pins:
        settings["pinnedPeerCertSha256"] = ",".join(pins)
    if _as_list(t.get("vcn")):
        settings["verifyPeerCertByName"] = ",".join(_as_list(t.get("vcn")))
    if t.get("ech") and t.get("ech") is not True:
        settings["echConfigList"] = str(t["ech"])
    return "tlsSettings", settings


def _kcp_masks(server: Server) -> list[dict[str, Any]]:
    """Старые header/seed mKCP → finalmask (Xray 26 убрал их из kcpSettings). Первый слой —
    внутренний: шифрование (seed) или прежняя XOR-маскировка, снаружи — заголовок."""
    t = server.transport or {}
    seed = t.get("kcp_seed") or t.get("seed")
    masks: list[dict[str, Any]] = [{"type": "mkcp-aes128gcm", "settings": {"password": str(seed)}} if seed
                                   else {"type": "mkcp-original"}]
    header = str(t.get("header_type") or "none").lower()
    if header not in ("", "none"):
        name = _KCP_HEADERS.get(header)
        if name is None:
            raise ConfigError(f"Сервер «{_name(server)}»: маскировка mKCP {header} не поддерживается")
        mask: dict[str, Any] = {"type": name}
        if name == "header-dns" and t.get("host"):
            mask["settings"] = {"domain": str(_as_list(t.get("host"))[0])}
        masks.append(mask)
    return masks


def _xray_stream(plan: RunPlan, server: Server) -> dict[str, Any]:
    t = server.transport or {}
    host = _host_header(server)
    if server.proto == "hysteria2":
        hy = server.hy2 or {}
        stream: dict[str, Any] = {"network": "hysteria",
                                  "hysteriaSettings": {"version": 2, "auth": str(server.password or "")}}
        masks = []
        if hy.get("obfs"):
            masks.append({"type": "salamander", "settings": {"password": str(hy.get("obfs_password") or "")}})
        quic: dict[str, Any] = {}
        if hy.get("ports"):
            low, high = hop_interval(hy.get("hop_interval"))
            low, high = max(5, low or 30), max(5, high or 30)     # Xray: не меньше 5 секунд
            quic["udpHop"] = {"ports": ",".join(_as_list(hy["ports"])),
                              "interval": str(low) if low == high else f"{low}-{high}"}
        if _num(hy.get("up_mbps")):
            quic["brutalUp"] = f"{_num(hy['up_mbps'])} mbps"
        if _num(hy.get("down_mbps")):
            quic["brutalDown"] = f"{_num(hy['down_mbps'])} mbps"
        if masks or quic:
            stream["finalmask"] = {**({"udp": masks} if masks else {}), **({"quicParams": quic} if quic else {})}
        key, settings = _xray_tls(plan, server, quic=True) or ("tlsSettings", {})
        stream["security"] = "tls"
        stream[key] = settings
        return _link_finalmask(server, stream)
    net = _XRAY_NETWORKS.get(server.network)
    if net is None:
        raise ConfigError(f"Сервер «{_name(server)}»: транспорт {server.network} помощник Xray 26 не поддерживает")
    stream = {"network": net}
    if net == "raw" and t.get("header_type") == "http":
        hosts = _as_list(t.get("host")) or ([host] if host else [])
        request: dict[str, Any] = {"version": "1.1", "method": "GET", "path": _as_list(t.get("path")) or ["/"]}
        if hosts:
            request["headers"] = {"Host": hosts}
        stream["rawSettings"] = {"header": {"type": "http", "request": request}}
    elif net == "ws":
        ws: dict[str, Any] = {"path": str(t.get("path") or "/")}
        if host:
            ws["host"] = host
        if _headers(server):
            ws["headers"] = _headers(server)
        stream["wsSettings"] = ws
    elif net == "httpupgrade":
        hu: dict[str, Any] = {"path": str(t.get("path") or "/")}
        if host:
            hu["host"] = host
        if _headers(server):
            hu["headers"] = _headers(server)
        stream["httpupgradeSettings"] = hu
    elif net == "grpc":
        grpc: dict[str, Any] = {"serviceName": str(t.get("service_name") or ""),
                                "multiMode": t.get("grpc_mode") == "multi"}
        if t.get("authority"):
            grpc["authority"] = str(t["authority"])
        stream["grpcSettings"] = grpc
    elif net == "xhttp":
        xh: dict[str, Any] = {"path": str(t.get("path") or "/"), "mode": str(t.get("xhttp_mode") or "auto")}
        if host:
            xh["host"] = host
        extra = t.get("xhttp_extra")
        if isinstance(extra, str) and extra.strip():
            try:
                extra = json.loads(extra)
            except ValueError as exc:
                raise ConfigError(f"Сервер «{_name(server)}»: параметр extra XHTTP — не JSON") from exc
        if isinstance(extra, dict) and extra:
            xh["extra"] = extra
        stream["xhttpSettings"] = xh
    elif net == "kcp":
        stream["kcpSettings"] = {dst: t[src] for src, dst in _KCP_FIELDS.items() if t.get(src) is not None}
        stream["finalmask"] = {"udp": _kcp_masks(server)}
    sec = _xray_tls(plan, server, quic=False)
    if sec:
        stream["security"] = "reality" if sec[0] == "realitySettings" else "tls"
        stream[sec[0]] = sec[1]
    return _link_finalmask(server, stream)


def _link_finalmask(server: Server, stream: dict[str, Any]) -> dict[str, Any]:
    """finalmask из ссылки (параметр fm, стандарт XTLS 716) — как задал провайдер, вместо собранного
    из старых полей: заголовки mKCP, salamander и прыжки портов он уже содержит."""
    mask = (server.transport or {}).get("finalmask")
    if isinstance(mask, str) and mask.strip():
        try:
            mask = json.loads(mask)
        except ValueError as exc:
            raise ConfigError(f"Сервер «{_name(server)}»: параметр fm (finalmask) — не JSON") from exc
    if isinstance(mask, dict) and mask:
        stream["finalmask"] = copy.deepcopy(mask)
    return stream


def _mlkem_ok(value: str) -> bool:
    """Строка encryption VLESS для Xray: «mlkem768x25519plus.<режим>.<rtt>[.отступы].<ключи base64url>».
    Без ключа Xray 26.3.27 падает с паникой при чтении конфига — такую строку не пропускаем."""
    parts = value.split(".")
    if len(parts) < 4 or parts[0] != "mlkem768x25519plus" or parts[1] not in ("native", "xorpub", "random") \
            or parts[2] not in ("1rtt", "0rtt"):
        return False
    keys = 0
    for part in parts[3:]:
        if len(part) < 20:
            continue                     # отступы
        try:
            raw = base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))
        except ValueError:
            return False
        if len(raw) not in (32, 1184):
            return False
        keys += 1
    return keys > 0


def _xray_build(plan: RunPlan, server: Server, addr: str, out_tag: str) -> dict[str, Any]:
    proto = server.proto
    if proto == "vless":
        encryption = server.encryption or "none"
        if encryption != "none" and not _mlkem_ok(encryption):
            raise ConfigError(f"Сервер «{_name(server)}»: параметр encryption (ML-KEM) повреждён — нет ключа сервера")
        settings: dict[str, Any] = {"address": addr, "port": server.port,
                                    "id": _need(server, server.uuid, "идентификатора пользователя"),
                                    "encryption": encryption}
        if server.flow:
            settings["flow"] = server.flow
    elif proto == "vmess":
        if server.alter_id:
            raise ConfigError(f"Сервер «{_name(server)}»: устаревший VMess (alterId) помощник Xray не открывает")
        settings = {"address": addr, "port": server.port,
                    "id": _need(server, server.uuid, "идентификатора пользователя"),
                    "security": server.cipher if server.cipher in _VMESS_CIPHERS else "auto"}
    elif proto == "trojan":
        settings = {"address": addr, "port": server.port, "password": _need(server, server.password, "пароля")}
    elif proto == "shadowsocks":
        if server.plugin:
            raise ConfigError(f"Сервер «{_name(server)}»: плагины Shadowsocks помощник Xray не поддерживает")
        settings = {"address": addr, "port": server.port, "method": _need(server, server.method, "метода шифрования"),
                    "password": _need(server, server.password, "пароля")}
    elif proto == "hysteria2":
        settings = {"version": 2, "address": addr, "port": server.port}
    else:
        raise ConfigError(f"Сервер «{_name(server)}»: протокол {proto} помощник Xray не открывает")
    return {"tag": out_tag, "protocol": "hysteria" if proto == "hysteria2" else proto, "settings": settings,
            "streamSettings": _xray_stream(plan, server)}


def _key(d: dict[str, Any], name: str) -> str:
    """Ключ name без учёта регистра: Xray читает JSON через encoding/json, а он регистр не различает,
    и провайдер мог написать streamsettings. Нет такого ключа — name."""
    low = name.lower()
    return next((k for k in d if isinstance(k, str) and k.lower() == low), name)


def _sub(d: dict[str, Any], name: str, *, create: bool = False) -> dict[str, Any] | None:
    key = _key(d, name)
    value = d.get(key)
    if isinstance(value, dict):
        return value
    if create:
        d[key] = {}
        return d[key]
    return None


def _xray_as_is(server: Server, addr: str, out_tag: str) -> dict[str, Any]:
    """Outbound провайдера «как есть»: свой тег, адрес — резолвленный IP, имя сервера — в SNI и Host
    (раньше их давал адрес-домен), цепочки провайдера (proxySettings, dialerProxy) — снимаются."""
    ob = copy.deepcopy(server.xray_outbound or {})
    ob[_key(ob, "tag")] = out_tag
    ob.pop(_key(ob, "proxySettings"), None)
    settings = _sub(ob, "settings") or {}
    for name in ("vnext", "servers"):
        items = settings.get(_key(settings, name))
        if isinstance(items, list) and items and isinstance(items[0], dict):
            items[0][_key(items[0], "address")] = addr
    if _key(settings, "address") in settings:
        settings[_key(settings, "address")] = addr
    stream = _sub(ob, "streamSettings")
    if stream is not None:
        sockopt = _sub(stream, "sockopt")
        if sockopt is not None:
            sockopt.pop(_key(sockopt, "dialerProxy"), None)
        domain = None if _is_ip(server.host) else server.host
        security = str(stream.get(_key(stream, "security")) or "").lower()
        if domain and security == "tls":
            tls = _sub(stream, "tlsSettings", create=True)
            if not tls.get(_key(tls, "serverName")):
                tls[_key(tls, "serverName")] = domain
        if domain and security in ("", "none"):
            for name in ("wsSettings", "httpupgradeSettings", "xhttpSettings", "splithttpSettings"):
                part = _sub(stream, name)
                if part is not None and not part.get(_key(part, "host")):
                    part[_key(part, "host")] = domain
    return ob


def _xray_dialer(plan: RunPlan, server: Server, sid: str) -> dict[str, Any] | None:
    """freedom для dialerProxy: фрагментация ClientHello (провайдера или своя) и UDP-шумы."""
    fragment = server.fragment
    if not fragment and plan.tls_fragment and server.security in ("tls", "reality"):
        fragment = XRAY_FRAGMENT
    settings: dict[str, Any] = {}
    if fragment:
        settings["fragment"] = {k: fragment[k] for k in ("packets", "length", "interval", "maxSplit") if k in fragment}
    if plan.noises:
        settings["noises"] = copy.deepcopy(XRAY_NOISES)
    if not settings:
        return None
    dial: dict[str, Any] = {"tag": f"dial-{sid}", "protocol": "freedom", "settings": settings}
    if plan.physical_interface:
        dial["streamSettings"] = {"sockopt": {"interface": plan.physical_interface}}
    return dial


def build_xray(plan: RunPlan) -> dict[str, Any] | None:
    """Конфиг помощника Xray 26.3.27: на каждый сервер engine=xray — вход socks 127.0.0.1:<порт>
    с учётной записью помощника → свой выход. Без api, stats и журнала соединений. None — помощник
    не нужен."""
    targets = [server for server, engine in _servers(plan) if engine == "xray"]
    if not targets:
        return None
    if not plan.secrets.helper_user or not plan.secrets.helper_pass:
        raise ConfigError("Не выбрана учётная запись помощника Xray")
    inbounds: list[dict[str, Any]] = []
    outbounds: list[dict[str, Any]] = [{"tag": "block", "protocol": "blackhole"}]   # первый выход — по умолчанию
    rules: list[dict[str, Any]] = []
    for server in targets:
        sid = _sid(server)
        port = plan.ports.helper.get(sid)
        if not port:
            raise ConfigError(f"Сервер «{_name(server)}»: не выбран порт помощника Xray")
        in_tag, out_tag = f"in-{sid}", f"out-{sid}"
        inbounds.append({"tag": in_tag, "listen": HELPER_HOST, "port": int(port), "protocol": "socks",
                         "settings": {"auth": "password", "udp": True, "ip": HELPER_HOST,
                                      "accounts": [{"user": plan.secrets.helper_user,
                                                    "pass": plan.secrets.helper_pass}]}})
        addr = _addr(plan, server)
        ob = _xray_as_is(server, addr, out_tag) if server.xray_outbound else _xray_build(plan, server, addr, out_tag)
        dial = _xray_dialer(plan, server, sid)
        if dial or plan.physical_interface:
            sockopt = _sub(_sub(ob, "streamSettings", create=True), "sockopt", create=True)
            if dial:
                sockopt[_key(sockopt, "dialerProxy")] = dial["tag"]
            if plan.physical_interface:
                sockopt[_key(sockopt, "interface")] = plan.physical_interface
        vision = (server.flow or "").startswith("xtls-rprx-vision")
        if plan.mux and not vision and _key(ob, "mux") not in ob \
                and server.network in ("tcp", "ws", "httpupgrade", "kcp") and server.proto != "hysteria2":
            ob["mux"] = dict(XRAY_MUX)
        outbounds.append(ob)
        if dial:
            outbounds.append(dial)
        rules.append({"type": "field", "inboundTag": [in_tag], "outboundTag": out_tag})
    return {"log": {"loglevel": "warning", "access": "none"}, "inbounds": inbounds, "outbounds": outbounds,
            "routing": {"domainStrategy": "AsIs", "rules": rules}}


# ------------------------------------------------------------ проверка конфига sing-box

_LOG_LEVELS = frozenset({"trace", "debug", "info", "warn", "error", "fatal", "panic"})
_STRATEGIES = frozenset({"prefer_ipv4", "prefer_ipv6", "ipv4_only", "ipv6_only"})
_SNIFFERS = frozenset({"http", "tls", "quic", "stun", "dns", "bittorrent", "dtls", "ssh", "rdp", "ntp"})
_STACKS = frozenset({"system", "gvisor", "mixed"})
_DNS_MODES = frozenset({"disabled", "native", "hijack"})
_RULE_NETWORKS = frozenset({"tcp", "udp", "icmp"})
_ACTIONS = frozenset({"route", "route-options", "reject", "hijack-dns", "sniff", "resolve", "bypass"})
_DNS_ACTIONS = frozenset({"route", "reject", "predefined", "evaluate", "respond"})
_DNS_TYPES = frozenset({"local", "hosts", "tcp", "udp", "tls", "quic", "https", "h3", "dhcp", "mdns", "fakeip",
                        "tailscale", "openconnect", "openvpn", "resolved"})
_TRANSPORTS = frozenset({"http", "ws", "quic", "grpc", "httpupgrade"})
_MUX_PROTOCOLS = frozenset({"smux", "yamux", "h2mux"})
_GROUP_TYPES = frozenset({"selector", "urltest"})
_DURATION = re.compile(r"(\d+(\.\d+)?(ns|us|µs|ms|s|m|h))+")

# Что генератору нельзя (план 5.5): (где, поле, почему). «type=X» — значение поля type,
# «!поле» — поле обязано быть. validate() сверяет конфиг с таблицей, тест — каждую строку таблицы.
FORBIDDEN: tuple[tuple[str, str, str], ...] = (
    ("route.rule", "geosite", "geosite удалён в sing-box 1.12 — только rule-set"),
    ("route.rule", "geoip", "geoip удалён в sing-box 1.12 — только rule-set"),
    ("route.rule", "source_geoip", "source_geoip удалён в sing-box 1.12 — только rule-set"),
    ("route.rule", "rule_set_ipcidr_match_source", "поле переименовано в 1.10 и удалено"),
    ("dns.rule", "geosite", "geosite удалён в sing-box 1.12 — только rule-set"),
    ("dns.rule", "geoip", "geoip удалён в sing-box 1.12 — только rule-set"),
    ("dns.rule", "source_geoip", "source_geoip удалён в sing-box 1.12"),
    ("dns.rule", "outbound", "DNS-правило outbound устарело в 1.12 — domain_resolver"),
    ("dns.rule", "strategy", "DNS-действие strategy устарело в 1.14 (удаление в 1.16) — dns.strategy"),
    ("dns.rule", "rule_set_ip_cidr_accept_empty", "устарело в 1.14 (удаление в 1.16)"),
    ("dns.rule", "rule_set_ipcidr_match_source", "поле переименовано в 1.10 и удалено"),
    ("dns.rule", "ip_cidr", "адресные поля DNS-правил без match_response устарели в 1.14 — IP только в route.rules"),
    ("dns.rule", "ip_is_private", "адресные поля DNS-правил без match_response устарели в 1.14"),
    ("dns.rule", "ip_accept_any", "адресные поля DNS-правил без match_response устарели в 1.14"),
    ("dns.server", "!type", "старый формат DNS-серверов удалён в sing-box 1.14 — нужен type"),
    ("dns.server", "address", "старый формат DNS-серверов удалён в sing-box 1.14"),
    ("dns.server", "address_resolver", "старый формат DNS-серверов удалён в sing-box 1.14 — domain_resolver"),
    ("dns.server", "address_strategy", "старый формат DNS-серверов удалён в sing-box 1.14"),
    ("dns.server@tun", "type=local", "DNS-сервер local в TUN даёт петлю через службу DNS Windows"),
    ("dns", "independent_cache", "устарело в 1.14 (удаление в 1.16)"),
    ("inbound", "sniff", "поля sniff у inbound удалены в 1.13 — действие sniff в правилах"),
    ("inbound", "sniff_override_destination", "поля sniff у inbound удалены в 1.13"),
    ("inbound", "sniff_timeout", "поля sniff у inbound удалены в 1.13"),
    ("inbound", "domain_strategy", "domain_strategy у inbound удалён в 1.13"),
    ("inbound", "udp_disable_domain_unmapping", "поле inbound удалено в 1.13 — route-options"),
    ("inbound.tun", "inet4_address", "удалено в 1.12 — address"),
    ("inbound.tun", "inet6_address", "удалено в 1.12 — address"),
    ("inbound.tun", "inet4_route_address", "удалено в 1.12 — route_address"),
    ("inbound.tun", "inet6_route_address", "удалено в 1.12 — route_address"),
    ("inbound.tun", "inet4_route_exclude_address", "удалено в 1.12 — route_exclude_address"),
    ("inbound.tun", "inet6_route_exclude_address", "удалено в 1.12 — route_exclude_address"),
    ("inbound.tun", "gso", "удалено в 1.12"),
    ("inbound.tun", "stack", "устарело в 1.15 (удаление в 1.17) — не задаём"),
    ("outbound", "type=block", "выход block удалён в 1.13 — действие reject"),
    ("outbound", "type=dns", "выход dns удалён в 1.13 — действие hijack-dns"),
    ("outbound", "type=wireguard", "выход wireguard удалён в 1.13 — endpoint"),
    ("outbound", "domain_strategy", "устарело в 1.12, в 1.14 — FATAL; domain_resolver"),
    ("outbound", "override_address", "удалено в 1.13 — route-options"),
    ("outbound", "override_port", "удалено в 1.13 — route-options"),
    ("tls", "acme", "устарело в 1.14"),
    ("tls.ech", "pq_signature_schemes_enabled", "удалено в 1.13"),
    ("tls.ech", "dynamic_record_sizing_disabled", "удалено в 1.13"),
    ("rule_set", "type=remote", "только локальные файлы: remote rule-set Лазейка не использует"),
    ("rule_set", "download_detour", "устарело в 1.14 (удаление в 1.16)"),
    ("experimental", "cache_file", "cache_file не используем: состояние селекторов задаёт Лазейка"),
    ("clash_api", "store_mode", "устарело с 1.8"),
    ("clash_api", "store_selected", "устарело с 1.8"),
    ("clash_api", "store_fakeip", "устарело с 1.8"),
    ("clash_api", "cache_file", "устарело с 1.8"),
    ("clash_api", "cache_id", "устарело с 1.8"),
    ("cache_file", "store_rdrc", "устарело в 1.14 (удаление в 1.16)"),
)
_ADDRESS_FIELDS = frozenset({"ip_cidr", "ip_is_private", "ip_accept_any"})


def _walk(rules: Any) -> Iterator[dict[str, Any]]:
    for rule in rules if isinstance(rules, list) else []:
        if not isinstance(rule, dict):
            continue
        yield rule
        if rule.get("type") == "logical":
            yield from _walk(rule.get("rules"))


def _objects(cfg: dict[str, Any], scope: str) -> list[dict[str, Any]]:
    dns = cfg.get("dns") if isinstance(cfg.get("dns"), dict) else {}
    route = cfg.get("route") if isinstance(cfg.get("route"), dict) else {}
    exp = cfg.get("experimental") if isinstance(cfg.get("experimental"), dict) else {}
    inbounds = [x for x in cfg.get("inbounds") or [] if isinstance(x, dict)]
    outbounds = [x for x in (cfg.get("outbounds") or []) + (cfg.get("endpoints") or []) if isinstance(x, dict)]
    tls = [o["tls"] for o in outbounds if isinstance(o.get("tls"), dict)]
    if scope == "route.rule":
        return list(_walk(route.get("rules")))
    if scope == "dns.rule":
        return list(_walk(dns.get("rules")))
    if scope == "dns.server":
        return [x for x in dns.get("servers") or [] if isinstance(x, dict)]
    if scope == "dns.server@tun":
        return _objects(cfg, "dns.server") if any(i.get("type") == "tun" for i in inbounds) else []
    if scope == "dns":
        return [dns] if dns else []
    if scope == "inbound":
        return inbounds
    if scope == "inbound.tun":
        return [i for i in inbounds if i.get("type") == "tun"]
    if scope == "outbound":
        return [x for x in cfg.get("outbounds") or [] if isinstance(x, dict)]
    if scope == "tls":
        return tls
    if scope == "tls.ech":
        return [t["ech"] for t in tls if isinstance(t.get("ech"), dict)]
    if scope == "rule_set":
        return [x for x in route.get("rule_set") or [] if isinstance(x, dict)]
    if scope == "experimental":
        return [exp] if exp else []
    if scope in ("clash_api", "cache_file"):
        return [exp[scope]] if isinstance(exp.get(scope), dict) else []
    raise ValueError(f"неизвестная область таблицы FORBIDDEN: {scope}")


def _check_forbidden(cfg: dict[str, Any], errors: list[str]) -> None:
    for scope, key, reason in FORBIDDEN:
        for obj in _objects(cfg, scope):
            if key.startswith("type="):
                hit = obj.get("type") == key[len("type="):]
            elif key.startswith("!"):
                hit = key[1:] not in obj
            else:
                hit = key in obj and not (scope == "dns.rule" and key in _ADDRESS_FIELDS and obj.get("match_response"))
            if hit:
                where = obj.get("tag") or obj.get("type") or scope
                errors.append(f"{scope} ({where}): «{key}» — {reason}")


def _tags(items: Any, kind: str, errors: list[str]) -> list[str]:
    out = []
    for item in items or []:
        t = item.get("tag") if isinstance(item, dict) else None
        if not t:
            errors.append(f"{kind}: элемент без тега")
            continue
        if t in out:
            errors.append(f"{kind}: тег «{t}» повторяется")
        out.append(t)
    return out


def _resolver_server(value: Any) -> str | None:
    if isinstance(value, str):
        return value or None
    if isinstance(value, dict):
        return value.get("server")
    return None


def _check_tags(cfg: dict[str, Any], errors: list[str]) -> None:
    dns = cfg.get("dns") or {}
    route = cfg.get("route") or {}
    outs = _tags((cfg.get("outbounds") or []) + (cfg.get("endpoints") or []), "outbounds/endpoints", errors)
    ins = _tags(cfg.get("inbounds"), "inbounds", errors)
    dns_tags = _tags(dns.get("servers"), "dns.servers", errors)
    sets = _tags(route.get("rule_set"), "route.rule_set", errors)
    set_kinds = {s.get("tag"): routing.rule_set_kind(s.get("tag") or "") for s in route.get("rule_set") or []
                 if isinstance(s, dict)}
    for ob in cfg.get("outbounds") or []:
        if ob.get("type") in _GROUP_TYPES:
            members = ob.get("outbounds") or []
            if not members:
                errors.append(f"{ob['type']} «{ob.get('tag')}»: нет участников")
            for m in members:
                if m not in outs:
                    errors.append(f"{ob['type']} «{ob.get('tag')}»: нет выхода «{m}»")
            if ob.get("default") and ob["default"] not in members:
                errors.append(f"selector «{ob.get('tag')}»: default «{ob['default']}» не среди участников")
        if ob.get("detour") and ob["detour"] not in outs:
            errors.append(f"выход «{ob.get('tag')}»: detour на несуществующий выход «{ob['detour']}»")
        server = _resolver_server(ob.get("domain_resolver"))
        if server and server not in dns_tags:
            errors.append(f"выход «{ob.get('tag')}»: domain_resolver на несуществующий DNS-сервер «{server}»")
    if route.get("final") and route["final"] not in outs:
        errors.append(f"route.final: нет выхода «{route['final']}»")
    resolver = _resolver_server(route.get("default_domain_resolver"))
    if resolver and resolver not in dns_tags:
        errors.append(f"route.default_domain_resolver: нет DNS-сервера «{resolver}»")
    for rule in _walk(route.get("rules")):
        for t in _as_list(rule.get("inbound")):
            if t not in ins:
                errors.append(f"route.rules: нет входа «{t}»")
        for t in _as_list(rule.get("rule_set")):
            if t not in sets:
                errors.append(f"route.rules: нет rule-set «{t}»")
    for rule in route.get("rules") or []:            # действие — только у правил верхнего уровня
        action = rule.get("action", "route")
        if (action == "route" or (action == "bypass" and "outbound" in rule)) and rule.get("outbound") not in outs:
            errors.append(f"route.rules: нет выхода «{rule.get('outbound')}»")
    for server in dns.get("servers") or []:
        if server.get("detour") and server["detour"] not in outs:
            errors.append(f"DNS-сервер «{server.get('tag')}»: detour на несуществующий выход «{server['detour']}»")
        res = _resolver_server(server.get("domain_resolver"))
        if res and res not in dns_tags:
            errors.append(f"DNS-сервер «{server.get('tag')}»: domain_resolver на несуществующий «{res}»")
    if dns.get("final") and dns["final"] not in dns_tags:
        errors.append(f"dns.final: нет DNS-сервера «{dns['final']}»")
    for rule in _walk(dns.get("rules")):
        for t in _as_list(rule.get("rule_set")):
            if t not in sets:
                errors.append(f"dns.rules: нет rule-set «{t}»")
            elif set_kinds.get(t) == "ip":
                errors.append(f"dns.rules: IP-набор «{t}» в DNS-правиле — только в route.rules")
    for rule in dns.get("rules") or []:
        if rule.get("action", "route") in ("route", "evaluate") and rule.get("server") not in dns_tags:
            errors.append(f"dns.rules: нет DNS-сервера «{rule.get('server')}»")


def _bad(errors: list[str], where: str, value: Any, allowed: Iterable[str]) -> None:
    errors.append(f"{where}: недопустимое значение «{value}» (можно: {', '.join(sorted(allowed))})")


def _check_enums(cfg: dict[str, Any], errors: list[str]) -> None:
    log = cfg.get("log") or {}
    if log.get("level") is not None and log["level"] not in _LOG_LEVELS:
        _bad(errors, "log.level", log["level"], _LOG_LEVELS)
    dns = cfg.get("dns") or {}
    route = cfg.get("route") or {}
    for where, value in (("dns.strategy", dns.get("strategy")),
                         ("route.default_domain_resolver.strategy",
                          (route.get("default_domain_resolver") or {}).get("strategy")
                          if isinstance(route.get("default_domain_resolver"), dict) else None)):
        if value is not None and value not in _STRATEGIES:
            _bad(errors, where, value, _STRATEGIES)
    for server in dns.get("servers") or []:
        if "type" in server and server["type"] not in _DNS_TYPES:
            _bad(errors, f"DNS-сервер «{server.get('tag')}».type", server["type"], _DNS_TYPES)
    for inbound in cfg.get("inbounds") or []:
        if inbound.get("type") == "tun":
            if "stack" in inbound and inbound["stack"] not in _STACKS:
                _bad(errors, "tun.stack", inbound["stack"], _STACKS)
            if "dns_mode" in inbound and inbound["dns_mode"] not in _DNS_MODES:
                _bad(errors, "tun.dns_mode", inbound["dns_mode"], _DNS_MODES)
    for rule in _walk(route.get("rules")):
        if rule.get("type") == "logical" and rule.get("mode") not in ("and", "or"):
            _bad(errors, "route.rules.mode", rule.get("mode"), ("and", "or"))
        if "action" in rule and rule["action"] not in _ACTIONS:
            _bad(errors, "route.rules.action", rule["action"], _ACTIONS)
        for sniffer in _as_list(rule.get("sniffer")):
            if sniffer not in _SNIFFERS:
                _bad(errors, "route.rules.sniffer", sniffer, _SNIFFERS)
        for proto in _as_list(rule.get("protocol")):
            if proto not in _SNIFFERS:
                _bad(errors, "route.rules.protocol", proto, _SNIFFERS)
        for net in _as_list(rule.get("network")):
            if net not in _RULE_NETWORKS:
                _bad(errors, "route.rules.network", net, _RULE_NETWORKS)
    for rule in _walk(dns.get("rules")):
        if "action" in rule and rule["action"] not in _DNS_ACTIONS:
            _bad(errors, "dns.rules.action", rule["action"], _DNS_ACTIONS)
    for ob in (cfg.get("outbounds") or []) + (cfg.get("endpoints") or []):
        name = f"выход «{ob.get('tag')}»"
        for net in _as_list(ob.get("network")) if ob.get("type") not in _GROUP_TYPES else []:
            if net not in ("tcp", "udp"):
                _bad(errors, f"{name}.network", net, ("tcp", "udp"))
        tls = ob.get("tls") if isinstance(ob.get("tls"), dict) else {}
        utls = tls.get("utls") if isinstance(tls.get("utls"), dict) else {}
        if utls.get("fingerprint") and utls["fingerprint"] not in SB_FINGERPRINTS:
            _bad(errors, f"{name}.tls.utls.fingerprint", utls["fingerprint"], SB_FINGERPRINTS)
        transport = ob.get("transport") if isinstance(ob.get("transport"), dict) else {}
        if transport and transport.get("type") not in _TRANSPORTS:
            _bad(errors, f"{name}.transport.type", transport.get("type"), _TRANSPORTS)
        mux = ob.get("multiplex") if isinstance(ob.get("multiplex"), dict) else {}
        if mux.get("protocol") and mux["protocol"] not in _MUX_PROTOCOLS:
            _bad(errors, f"{name}.multiplex.protocol", mux["protocol"], _MUX_PROTOCOLS)
        if ob.get("type") == "vless" and ob.get("flow") not in (None, "", "xtls-rprx-vision"):
            _bad(errors, f"{name}.flow", ob.get("flow"), ("xtls-rprx-vision",))
        if ob.get("type") == "hysteria2" and isinstance(ob.get("obfs"), dict) \
                and ob["obfs"].get("type") not in ("salamander", "gecko"):
            _bad(errors, f"{name}.obfs.type", ob["obfs"].get("type"), ("salamander", "gecko"))
        if ob.get("type") == "hysteria2" and "server_ports" in ob and "server_port" in ob:
            errors.append(f"{name}: server_port вместе с server_ports — по документации они конфликтуют")
        for key in ("interval", "hop_interval", "hop_interval_max"):
            if key in ob and not _DURATION.fullmatch(str(ob[key])):
                errors.append(f"{name}.{key}: «{ob[key]}» — не длительность Go (например, 300s)")


def validate(cfg: dict[str, Any]) -> list[str]:
    """Ошибки конфига sing-box, которых `sing-box check` не ловит: связность тегов, перечисления,
    запрещённые поля (FORBIDDEN). Пустой список — конфиг в порядке."""
    errors: list[str] = []
    if not isinstance(cfg, dict):
        return ["конфиг — не объект JSON"]
    _check_forbidden(cfg, errors)
    _check_tags(cfg, errors)
    _check_enums(cfg, errors)
    return errors
