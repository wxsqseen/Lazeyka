"""JSON-конфиги Xray из подписки (Remnawave, 3x-ui, Marzban и др.) → серверы и группы.

Тело — массив полных конфигов или один объект. Серверы — outbounds vless/vmess/trojan/shadowsocks/
hysteria (version 2) и socks в формах vnext/servers[] и плоской; freedom/blackhole/dns/loopback —
служебные. Балансировщик, на который ссылается правило balancerTag, становится группой «Самый
быстрый»; один хост в нескольких группах — один сервер по key(). Outbound провайдера целиком
кладётся в Server.xray_outbound — для помощника Xray. Маршруты провайдера отдаются как есть вместе с
тегами и протоколами outbounds (их переводит routeprofile), inbounds/dns/log/stats/policy/api не читаются.
План — 5.8.
"""
from __future__ import annotations

import copy
import hashlib
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from .links import (AMNEZIA_TEXT, LinkError, check_flow, check_port, clean_text, csv, finish, make_shadowsocks,
                    network_of, normalize_host, security_of)
from .model import PROBE_URL, Group, Server, split_flag

MAX_CONFIGS = 500
MAX_OUTBOUNDS = 200
MIN_INTERVAL = 30                      # секунд: чаще проверять задержку бессмысленно и шумно
DEFAULT_INTERVAL = 300
SERVICE_PROTOCOLS = frozenset({"freedom", "blackhole", "dns", "loopback"})
STRATEGIES = ("leastPing", "leastLoad", "random", "roundRobin")


@dataclass
class XrayImport:
    servers: list[Server] = field(default_factory=list)
    groups: list[Group] = field(default_factory=list)
    # {"routing": routing провайдера как есть, "outbounds": [{tag, protocol}]} — форма полного конфига,
    # которую читает routeprofile.from_xray_routing; секретов outbounds в ней нет.
    routing: dict[str, Any] | None = field(default=None, repr=False)
    warnings: list[str] = field(default_factory=list)


def _ci(value: Any) -> dict[str, Any]:
    """Словарь с ключами в нижнем регистре: Xray (Go) читает JSON без учёта регистра."""
    return {str(k).lower(): v for k, v in value.items()} if isinstance(value, dict) else {}


def _first(value: Any) -> dict[str, Any]:
    return _ci(value[0]) if isinstance(value, list) and value else {}


def _text(value: Any) -> str:
    return "" if value is None or isinstance(value, (dict, list, bool)) else str(value).strip()


# ------------------------------------------------------------ outbound → Server

def _endpoint(settings: dict[str, Any], list_key: str) -> tuple[dict[str, Any], bool]:
    """Запись сервера: settings.vnext[0] / settings.servers[0] или плоская форма Xray 26.
    Второе значение — записей больше одной (берётся первая)."""
    entries = settings.get(list_key)
    if isinstance(entries, list) and entries:
        return _first(entries), len(entries) > 1
    return settings, False


def _address(entry: dict[str, Any]) -> tuple[str, int]:
    return normalize_host(_text(entry.get("address"))), check_port(entry.get("port"))


def _tls_settings(stream: dict[str, Any], security: str) -> dict[str, Any]:
    tls: dict[str, Any] = {}
    if security == "tls":
        s = _ci(stream.get("tlssettings"))
        if _text(s.get("servername")):
            tls["sni"] = _text(s.get("servername"))
        if csv(s.get("alpn")):
            tls["alpn"] = csv(s.get("alpn"))
        if _text(s.get("fingerprint")):
            tls["fingerprint"] = _text(s.get("fingerprint")).lower()
        if s.get("allowinsecure") is True:
            tls["insecure"] = True
        if _text(s.get("echconfiglist")):
            tls["ech"] = _text(s.get("echconfiglist"))
        for key, name in (("pinnedpeercertsha256", "pcs"), ("verifypeercertbyname", "vcn")):
            if csv(s.get(key)):
                tls[name] = csv(s.get(key))
    elif security == "reality":
        s = _ci(stream.get("realitysettings"))
        pbk = _text(s.get("password")) or _text(s.get("publickey"))
        if not pbk:
            raise LinkError("reality_without_pbk")
        tls["pbk"] = pbk.translate(str.maketrans("+/", "-_")).rstrip("=")
        if _text(s.get("servername")):
            tls["sni"] = _text(s.get("servername"))
        if _text(s.get("fingerprint")):
            tls["fingerprint"] = _text(s.get("fingerprint")).lower()
        if "shortid" in s:
            tls["sid"] = _text(s.get("shortid"))
        for key, name in (("spiderx", "spx"), ("mldsa65verify", "pqv")):
            if _text(s.get(key)):
                tls[name] = _text(s.get(key))
    return tls


def _transport(network: str, stream: dict[str, Any]) -> dict[str, Any]:
    transport: dict[str, Any] = {}
    if network == "tcp":
        header = _ci(_ci(stream.get("rawsettings") or stream.get("tcpsettings")).get("header"))
        if _text(header.get("type")).lower() == "http":
            request = _ci(header.get("request"))
            transport["header_type"] = "http"
            hosts = csv(_ci(request.get("headers")).get("host"))
            if hosts:
                transport["host"] = hosts
            paths = csv(request.get("path"))
            if paths:
                transport["path"] = paths[0]
    elif network in ("ws", "httpupgrade", "xhttp", "http"):
        key = {"ws": "wssettings", "httpupgrade": "httpupgradesettings", "http": "httpsettings"}.get(network)
        s = _ci(stream.get(key)) if key else _ci(stream.get("xhttpsettings") or stream.get("splithttpsettings"))
        headers = {str(k): str(v) for k, v in (s.get("headers") or {}).items()} if isinstance(s.get("headers"), dict) else {}
        host = _text(s.get("host")) or (csv(s.get("host"))[:1] or [""])[0]
        host = host or next((v for k, v in headers.items() if k.lower() == "host"), "")
        headers = {k: v for k, v in headers.items() if k.lower() != "host"}
        if _text(s.get("path")):
            transport["path"] = _text(s.get("path"))
        if host:
            transport["host"] = host
        if headers:
            transport["headers"] = headers
        if network == "xhttp":
            if _text(s.get("mode")):
                transport["xhttp_mode"] = _text(s.get("mode")).lower()
            raw = (stream.get("xhttpsettings") or stream.get("splithttpsettings") or {})
            extra = dict(raw.get("extra") or {}) if isinstance(raw.get("extra"), dict) else {}
            extra.update({k: v for k, v in raw.items() if k.lower() not in ("host", "path", "mode", "extra", "headers")})
            if extra:
                transport["xhttp_extra"] = extra
    elif network == "grpc":
        s = _ci(stream.get("grpcsettings"))
        if _text(s.get("servicename")):
            transport["service_name"] = _text(s.get("servicename"))
        transport["grpc_mode"] = "multi" if s.get("multimode") is True else "gun"
        if _text(s.get("authority")):
            transport["authority"] = _text(s.get("authority"))
    elif network == "kcp":
        s = _ci(stream.get("kcpsettings"))
        header = _text(_ci(s.get("header")).get("type")).lower()
        if header and header != "none":
            transport["header_type"] = header
        if _text(s.get("seed")):
            transport["kcp_seed"] = _text(s.get("seed"))
        for key in ("mtu", "tti"):
            if isinstance(s.get(key), int) and not isinstance(s.get(key), bool):
                transport[f"kcp_{key}"] = s[key]
    return transport


def _hysteria(settings: dict[str, Any], stream: dict[str, Any]) -> Server:
    hysteria = _ci(stream.get("hysteriasettings"))
    version = settings.get("version", hysteria.get("version"))
    if _text(version) != "2":
        raise LinkError("unsupported_scheme", "Hysteria v1")
    entry, _ = _endpoint(settings, "servers")
    host, port = _address(entry)
    hy2, rest = _hysteria_mask(stream.get("finalmask"))
    tls = _tls_settings(stream, "tls")
    server = Server("hysteria2", host, port, password=_text(hysteria.get("auth")) or None, security="tls",
                    tls=tls, hy2=hy2)
    if rest:
        # Маски и параметры QUIC, которых нет в полях hy2, — только у помощника: finalmask целиком.
        server.transport["finalmask"] = copy.deepcopy(stream["finalmask"])
    return server


_HY2_QUIC = frozenset({"udphop", "brutalup", "brutaldown", "congestion"})
_MBPS = re.compile(r"(\d+)\s*(?:m|mb|mbps)", re.I)


def _hysteria_mask(finalmask: Any) -> tuple[dict[str, Any], bool]:
    """finalmask Hysteria2 → поля Server.hy2 (salamander, прыжки портов с интервалом, brutal) и
    признак «есть что-то ещё»: другие маски UDP, свои окна QUIC и т. п. — тогда сервер открывает помощник."""
    mask_ci = _ci(finalmask)
    hy2: dict[str, Any] = {}
    rest = any(k not in ("udp", "quicparams") for k in mask_ci)
    for mask in mask_ci.get("udp") or []:
        mask = _ci(mask)
        if _text(mask.get("type")).lower() == "salamander" and "obfs" not in hy2:
            hy2["obfs"] = "salamander"
            password = _text(_ci(mask.get("settings")).get("password"))
            if password:
                hy2["obfs_password"] = password
        else:
            rest = True
    quic = _ci(mask_ci.get("quicparams"))
    rest = rest or any(k not in _HY2_QUIC for k in quic)
    if _text(quic.get("congestion")).lower() not in ("", "bbr", "brutal"):
        rest = True                  # reno, force-brutal — у sing-box таких нет
    hop = _ci(quic.get("udphop"))
    rest = rest or any(k not in ("ports", "interval") for k in hop)
    ports = hop.get("ports")
    if isinstance(ports, list):
        ports = ",".join(str(p) for p in ports)
    if _text(ports):
        hy2["ports"] = _text(ports).replace(" ", "")
    interval = _text(hop.get("interval")).replace(" ", "")
    if interval:
        if re.fullmatch(r"\d+(?:-\d+)?", interval):
            hy2["hop_interval"] = interval
        else:
            rest = True
    for key, name in (("brutalup", "up_mbps"), ("brutaldown", "down_mbps")):
        value = _text(quic.get(key))
        if not value:
            continue
        m = _MBPS.fullmatch(value)
        if m:
            hy2[name] = int(m.group(1))
        else:
            rest = True              # другие единицы — как есть у помощника
    return hy2, rest


def _server(outbound: dict[str, Any], warnings: list[str], label: str) -> Server:
    """Outbound провайдера → Server (без имени и id). LinkError — outbound не годится."""
    ob = _ci(outbound)
    proto = _text(ob.get("protocol")).lower()
    settings = _ci(ob.get("settings"))
    stream = _ci(ob.get("streamsettings"))
    if proto == "hysteria":
        return _hysteria(settings, stream)
    if proto in ("vless", "vmess"):
        entry, many = _endpoint(settings, "vnext")
        user = _first(entry.get("users")) or entry          # плоская форма: id прямо в settings
        if many:
            warnings.append(f"{label}: в vnext несколько серверов — взят первый")
        host, port = _address(entry)
        uuid = _text(user.get("id"))
        if not uuid:
            raise LinkError("no_uuid")
        server = Server(proto, host, port, uuid=uuid)
        if proto == "vless":
            server.flow = check_flow(user.get("flow"))
            server.encryption = _text(user.get("encryption")) or "none"
        else:
            server.cipher = _text(user.get("security")).lower() or "auto"
            aid = user.get("alterid") or 0
            server.alter_id = int(aid) if str(aid).isdigit() else 0
            if server.alter_id > 0:
                server.warnings.append("legacy_vmess_alterid")
    elif proto in ("trojan", "shadowsocks"):
        entry, many = _endpoint(settings, "servers")
        if many:
            warnings.append(f"{label}: в servers несколько серверов — взят первый")
        host, port = _address(entry)
        password = _text(entry.get("password"))
        if proto == "trojan":
            if not password:
                raise LinkError("no_password")
            server = Server("trojan", host, port, password=password)
        else:
            server = make_shadowsocks(host, port, _text(entry.get("method")), password)
    elif proto == "socks":
        entry, _ = _endpoint(settings, "servers")
        host, port = _address(entry)
        user = _first(entry.get("users")) or entry
        server = Server("socks", host, port, username=_text(user.get("user")) or None,
                        password=_text(user.get("pass")) or None)
    else:
        raise LinkError("unsupported_scheme", f"outbound {proto or 'без protocol'}")
    network = network_of(stream.get("network") or "tcp")
    security = security_of(stream.get("security"), "none")
    server.network = network
    server.transport = _transport(network, stream)
    if isinstance(stream.get("finalmask"), dict):
        server.transport["finalmask"] = copy.deepcopy(stream["finalmask"])
    server.security = security
    server.tls = _tls_settings(stream, security)
    return server


# ------------------------------------------------------------ конфиг → серверы и группы

_AUTO_TAG = re.compile(r"(?:proxy|bal-\d+-.+)(?:-\d+)?")


def _technical_tags(tags: list[str]) -> set[str]:
    """Теги, в которых нет имени: proxy, proxy-2 (Remnawave), bal-1-vless (3x-ui), свой префикс с номерами."""
    bases = Counter(re.sub(r"-\d+$", "", tag) for tag in tags)
    return {tag for tag in tags
            if not tag or _AUTO_TAG.fullmatch(tag)
            or (bases[re.sub(r"-\d+$", "", tag)] > 1 and re.fullmatch(r"[A-Za-z0-9_.]+(?:-\d+)?", tag))}


def _duration(value: Any) -> float | None:
    """Длительность Go («1m», «30s», «1h30m») или число секунд."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    text = _text(value).lower()
    units = {"ns": 1e-9, "us": 1e-6, "µs": 1e-6, "ms": 1e-3, "s": 1.0, "m": 60.0, "h": 3600.0}
    parts = re.findall(r"(\d+(?:\.\d+)?)(ns|us|µs|ms|s|m|h)", text)
    if not parts or "".join(n + u for n, u in parts) != text:
        return None
    return sum(float(n) * units[u] for n, u in parts)


def _probe(cfg: dict[str, Any], warnings: list[str], label: str) -> tuple[str, int]:
    """(URL проверки, интервал) из observatory/burstObservatory — только подсказки, с поправками."""
    burst = _ci(_ci(cfg.get("burstobservatory")).get("pingconfig"))
    obs = _ci(cfg.get("observatory"))
    url = _text(burst.get("destination")) or _text(obs.get("probeurl"))
    interval = _duration(burst.get("interval") if "interval" in burst else obs.get("probeinterval"))
    if url and not url.lower().startswith("https://"):
        warnings.append(f"{label}: адрес проверки не https — используется {PROBE_URL}")
        url = ""
    seconds = DEFAULT_INTERVAL if interval is None else max(MIN_INTERVAL, int(interval))
    return url or PROBE_URL, seconds


def _group_id(sub: str | None, remarks: str, tag: str) -> str:
    digest = hashlib.sha256(f"{sub or ''}\n{remarks}\n{tag}".encode("utf-8")).hexdigest()
    return "g-" + digest[:12]


def _referenced_balancers(routing: dict[str, Any]) -> list[dict[str, Any]]:
    balancers = {}
    for item in routing.get("balancers") or []:
        b = _ci(item)
        if _text(b.get("tag")):
            balancers.setdefault(_text(b["tag"]), b)
    used: list[dict[str, Any]] = []
    for rule in routing.get("rules") or []:
        tag = _text(_ci(rule).get("balancertag"))
        if tag in balancers and balancers[tag] not in used:
            used.append(balancers[tag])
    return used


class _Collector:
    """Серверы всех конфигов с одним сервером на key() и именами получше из одиночных конфигов."""

    def __init__(self, sub: str | None, result: XrayImport):
        self.sub = sub
        self.result = result
        self.by_id: dict[str, Server] = {}
        self.auto_named: set[str] = set()

    def add(self, server: Server, name: str, *, auto: bool, description: str | None) -> str:
        server.name = name
        server.source = "xray-json"
        server.sub = self.sub
        server.description = (clean_text(description) or None) if description else None
        finish(server)
        existing = self.by_id.get(server.id)
        if existing is None:
            self.by_id[server.id] = server
            self.result.servers.append(server)
            if auto:
                self.auto_named.add(server.id)
        elif server.id in self.auto_named and not auto and server.name:
            existing.name, existing.country = server.name, server.country
            existing.description = existing.description or server.description
            self.auto_named.discard(server.id)
        return server.id


def _dialer_of(outbound: dict[str, Any]) -> str:
    return _text(_ci(_ci(_ci(outbound).get("streamsettings")).get("sockopt")).get("dialerproxy"))


def _proxies(outbounds: list[dict[str, Any]], label: str, warnings: list[str]) -> list[tuple[str, Server]]:
    """Серверы конфига (тег, Server) в порядке outbounds: служебные и выходы цепочек — мимо,
    dialerProxy на freedom с fragment — в Server.fragment, цепочка на другой прокси — отказ."""
    by_tag: dict[str, dict[str, Any]] = {}
    for ob in outbounds:
        by_tag.setdefault(_text(_ci(ob).get("tag")), ob)
    # Выход цепочки (на него ссылается dialerProxy другого сервера) отдельным сервером не считается.
    hops = {_dialer_of(ob) for ob in outbounds} | {_text(_ci(_ci(ob).get("proxysettings")).get("tag")) for ob in outbounds}
    proxies: list[tuple[str, Server]] = []
    for ob in outbounds:
        ci = _ci(ob)
        proto = _text(ci.get("protocol")).lower()
        tag = _text(ci.get("tag"))
        if proto in SERVICE_PROTOCOLS or (tag and tag in hops):
            continue
        try:
            server = _server(ob, warnings, label)
        except LinkError as exc:
            warnings.append(f"{label}: сервер {tag or proto} пропущен — {exc}")
            continue
        dialer = _dialer_of(ob)
        target = _ci(by_tag.get(dialer)) if dialer else {}
        if _text(_ci(ci.get("proxysettings")).get("tag")) or (target and _text(target.get("protocol")).lower() != "freedom"):
            warnings.append(f"{label}: цепочки серверов пока не поддерживаются — {tag or proto} пропущен")
            continue
        if dialer and not target:
            warnings.append(f"{label}: dialerProxy «{dialer}» не найден — {tag or proto} без него")
        if target:
            freedom = _ci(target.get("settings"))
            fragment = _ci(freedom.get("fragment"))
            if fragment:
                server.fragment = {k: fragment[k] for k in ("packets", "length", "interval") if k in fragment}
            if freedom.get("noises"):
                warnings.append(f"{label}: UDP-шумы провайдера не переносятся")
        server.xray_outbound = copy.deepcopy(ob)
        proxies.append((tag, server))
    return proxies


def _config(config: dict[str, Any], index: int, collector: _Collector, warnings: list[str]) -> None:
    cfg = _ci(config)
    raw_remarks = _text(cfg.get("remarks"))
    label = f"«{clean_text(raw_remarks)}»" if raw_remarks else f"конфиг {index}"
    outbounds = [ob for ob in cfg.get("outbounds") or [] if isinstance(ob, dict)]
    if len(outbounds) > MAX_OUTBOUNDS:
        warnings.append(f"{label}: больше {MAX_OUTBOUNDS} outbounds — лишние пропущены")
        outbounds = outbounds[:MAX_OUTBOUNDS]
    proxies = _proxies(outbounds, label, warnings)
    if not proxies:
        warnings.append(f"{label}: нет ни одного сервера")
        return
    title = clean_text(raw_remarks)                      # с флагом: страна участников — из remarks группы
    remarks = split_flag(title)[1] if title else ""
    description = _text(_ci(cfg.get("meta")).get("serverdescription")) or None
    technical = _technical_tags([tag for tag, _ in proxies])
    routing = _ci(cfg.get("routing"))
    balancers = _referenced_balancers(routing)
    if not balancers:
        tag, server = proxies[0]
        name = raw_remarks or ("" if tag in technical else tag)
        collector.add(server, name, auto=False, description=description)
        if len(proxies) > 1:
            warnings.append(f"{label}: ещё {len(proxies) - 1} серв. используются только правилами провайдера — "
                            "взят первый")
        return
    members_all: list[str] = []
    for balancer in balancers:
        selectors = csv(balancer.get("selector"))
        members = [(tag, server) for tag, server in proxies if any(tag.startswith(s) for s in selectors)]
        if not members:
            warnings.append(f"{label}: балансировщик «{_text(balancer.get('tag'))}» без серверов")
            continue
        ids = []
        fallback_tag = _text(balancer.get("fallbacktag"))
        fallback = None
        for number, (tag, server) in enumerate(members, start=1):
            auto = tag in technical
            name = (f"{title} · {number}" if title else "") if auto else tag
            member_id = collector.add(copy.deepcopy(server), name, auto=auto, description=None)
            ids.append(member_id)
            if tag == fallback_tag:
                fallback = member_id
        members_all.extend(tag for tag, _ in members)
        strategy = _text(_ci(balancer.get("strategy")).get("type")) or "random"
        probe_url, interval = _probe(cfg, warnings, label)
        tag = _text(balancer.get("tag"))
        name = remarks or tag
        if len(balancers) > 1:
            name = f"{name} · {tag}"
        collector.result.groups.append(Group(
            id=_group_id(collector.sub, raw_remarks, tag), sub=collector.sub, name=name,
            members=list(dict.fromkeys(ids)), strategy=strategy if strategy in STRATEGIES else "leastPing",
            probe_url=probe_url, interval=interval, fallback=fallback))
    others = [tag for tag, _ in proxies if tag not in members_all]
    if others:
        warnings.append(f"{label}: {len(others)} серв. вне балансировщика используются только правилами провайдера")


def parse(obj: Any, *, sub: str | None = None) -> XrayImport:
    """Массив полных конфигов Xray или один конфиг → XrayImport. Ничего не бросает: что не разобрано —
    в warnings (тексты без секретов)."""
    result = XrayImport()
    configs = obj if isinstance(obj, list) else [obj]
    if len(configs) > MAX_CONFIGS:
        result.warnings.append(f"больше {MAX_CONFIGS} конфигов — лишние пропущены")
        configs = configs[:MAX_CONFIGS]
    collector = _Collector(sub, result)
    for index, config in enumerate(configs, start=1):
        cfg = _ci(config)
        if not isinstance(config, dict):
            result.warnings.append(f"конфиг {index}: не объект — пропущен")
            continue
        if _text(cfg.get("type")).lower() == "amneziawg":
            result.warnings.append(f"конфиг {index}: {AMNEZIA_TEXT}")
            continue
        if not isinstance(cfg.get("outbounds"), list):
            result.warnings.append(f"конфиг {index}: нет outbounds — пропущен")
            continue
        _config(config, index, collector, result.warnings)
        routing = cfg.get("routing")
        if result.routing is None and isinstance(routing, dict) and routing.get("rules"):
            result.routing = {"routing": copy.deepcopy(routing), "outbounds": _outbound_kinds(cfg.get("outbounds"))}
    return result


def _outbound_kinds(outbounds: Any) -> list[dict[str, str]]:
    """Теги и протоколы outbounds в исходном порядке — без адресов и секретов. По ним routeprofile
    узнаёт действие правила (freedom — напрямую, blackhole — блок, прокси — через VPN), а по первому —
    выход по умолчанию: Xray шлёт туда всё, что не попало в правила."""
    out = []
    for ob in (outbounds if isinstance(outbounds, list) else [])[:MAX_OUTBOUNDS]:
        if isinstance(ob, dict):
            ci = _ci(ob)
            out.append({"tag": _text(ci.get("tag")), "protocol": _text(ci.get("protocol")).lower()})
    return out
