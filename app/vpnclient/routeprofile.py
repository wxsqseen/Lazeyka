"""Профили маршрутизации Happ/Incy и маршруты провайдера из JSON Xray → правила sing-box.

Формат Happ (A/happ/routing.md): JSON с ключами Name, GlobalProxy, RemoteDns/DomesticDns
(или RemoteDNSType/…Domain/…IP), Geoipurl, Geositeurl, DnsHosts, DirectSites, DirectIp,
ProxySites, ProxyIp, BlockSites, BlockIp, DomainStrategy. Приходит как base64 JSON, JSON или
ссылка happ://routing/add|onadd/{base64}, incy://routing/…, строка «://routing/…» в подписке.
Списки в синтаксисе Xray: domain:/full:/regexp:/keyword:, geosite:/geoip: — их Лазейка берёт
из rule-set SagerNet (sing-geosite / sing-geoip), файлы .dat провайдера не нужны.

Профиль только описывает правила; применяет их менеджер после подтверждения человека
(summary() — что пойдёт напрямую, через VPN и что будет заблокировано).
"""
from __future__ import annotations

import base64
import binascii
import copy
import json
import re
from dataclasses import asdict, dataclass, field, fields
from typing import Any
from urllib.parse import unquote

from ..errors import UserError
from . import routing

ACTIONS = ("direct", "proxy", "block")
_ROUTE = {"direct": {"action": "route", "outbound": "direct"},
          "proxy": {"action": "route", "outbound": "proxy"},
          "block": {"action": "reject"}}
_LINK = re.compile(r"^(?:[a-z][a-z0-9+.-]*)?://(?:(auto)?routing/(?:(add|onadd|off)(?:/|(?=\?)|$))?|(onadd)/)(.*)$",
                   re.I | re.S)
_SKIP_KEYS = ("inboundTag", "user", "source", "sourceIP", "sourcePort", "localIP", "localPort", "attrs",
              "process", "vlessRoute", "sourceport")
_PROTOCOLS = {"http", "tls", "quic", "bittorrent"}


class RouteProfileError(UserError):
    """Не профиль маршрутизации. kind: bad | url (профиль по адресу — его надо скачать) | off."""

    def __init__(self, message: str, kind: str = "bad", url: str | None = None, auto: bool = False):
        super().__init__(message)
        self.kind = kind
        self.url = url
        self.auto = auto                 # autorouting: профиль по адресу обновляется сам


@dataclass
class RouteProfile:
    name: str
    source: str = "happ"                                   # happ | incy | xray
    global_proxy: bool = True                              # остальное: True — через VPN, False — напрямую
    rules: list[dict[str, Any]] = field(default_factory=list)   # [{action, domains, ips, ports, network, protocols}]
    dns_remote: str | None = None
    dns_domestic: str | None = None
    dns_hosts: dict[str, str] = field(default_factory=dict)
    domain_strategy: str = "AsIs"
    updated: str | None = None
    source_url: str | None = None                          # автообновляемый профиль (incy://autorouting/…)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return copy.deepcopy(asdict(self))

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RouteProfile":
        known = {f.name for f in fields(cls)}
        return cls(**{k: copy.deepcopy(v) for k, v in data.items() if k in known})


# ------------------------------------------------------------ разбор

def _b64decode(text: str) -> bytes:
    raw = re.sub(r"\s+", "", unquote(text))
    raw = raw.replace("-", "+").replace("_", "/")
    raw += "=" * (-len(raw) % 4)
    return base64.b64decode(raw, validate=True)


def _json_from(text: str) -> Any:
    text = text.strip()
    if text.startswith("{"):
        return json.loads(text)
    try:
        decoded = _b64decode(text).decode("utf-8-sig")
    except (binascii.Error, ValueError, UnicodeDecodeError) as exc:
        raise RouteProfileError("Профиль маршрутизации не читается: не JSON и не base64") from exc
    return json.loads(decoded)


def _payload(rest: str) -> str:
    rest = rest.strip()
    if rest.startswith("?"):
        for item in rest[1:].split("&"):
            key, _, value = item.partition("=")
            if key == "data":
                return unquote(value)
        return ""
    return rest


def parse_happ(text: str) -> RouteProfile:
    """Профиль Happ/Incy из ссылки, base64 или JSON. RouteProfileError — не профиль; kind=url —
    профиль лежит по адресу (скачать и передать тело сюда же), kind=off — команда «выключить»."""
    text = (text or "").strip()
    if not text:
        raise RouteProfileError("Пустой профиль маршрутизации")
    source = "incy" if text.lower().startswith("incy:") else "happ"
    m = _LINK.match(text)
    if m:
        auto, verb, _short, rest = m.groups()
        if (verb or "").lower() == "off":
            raise RouteProfileError("Ссылка выключает маршрутизацию другого приложения — это не профиль", kind="off")
        payload = _payload(rest)
        if re.match(r"^https?://", payload, re.I):
            # Скачивать профиль по адресу Лазейка не умеет (docs/vpnclient-plan.md, 4a): честно просим сам профиль.
            raise RouteProfileError("Профиль маршрутизации лежит по адресу в интернете — такие Лазейка не "
                                    "скачивает: нужен сам профиль (JSON или ссылка с ним)", kind="url",
                                    url=payload, auto=bool(auto))
        text = payload
    try:
        data = _json_from(text)
    except ValueError as exc:
        raise RouteProfileError("Профиль маршрутизации не читается: это не JSON") from exc
    if not isinstance(data, dict):
        raise RouteProfileError("Профиль маршрутизации — не объект JSON")
    return _from_happ(data, source)


def _get(data: dict[str, Any], *names: str) -> Any:
    lower = {str(k).lower(): v for k, v in data.items()}
    for name in names:
        if name.lower() in lower:
            return lower[name.lower()]
    return None


def _strings(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [v.strip() for v in value.replace("\n", ",").split(",") if v.strip()]
    if isinstance(value, (list, tuple)):
        return [str(v).strip() for v in value if str(v).strip()]
    return []


def _truthy(value: Any, default: bool) -> bool:
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("true", "1", "yes", "on")


def _dns(data: dict[str, Any], prefix: str) -> str | None:
    plain = _get(data, f"{prefix}Dns")
    if isinstance(plain, str) and plain.strip():
        return plain.strip()
    domain = _get(data, f"{prefix}DNSDomain")
    ip = _get(data, f"{prefix}DNSIP")
    for value in (domain, ip):
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _from_happ(data: dict[str, Any], source: str) -> RouteProfile:
    name = _get(data, "Name")
    profile = RouteProfile(name=str(name).strip() if name else "Профиль маршрутизации", source=source)
    profile.global_proxy = _truthy(_get(data, "GlobalProxy"), True)
    profile.dns_remote = _dns(data, "Remote")
    profile.dns_domestic = _dns(data, "Domestic")
    hosts = _get(data, "DnsHosts")
    if isinstance(hosts, dict):
        profile.dns_hosts = {str(k): str(v) for k, v in hosts.items()}
        if profile.dns_hosts:
            profile.warnings.append("DnsHosts (свои адреса имён) Лазейка не применяет")
    strategy = _get(data, "DomainStrategy")
    if isinstance(strategy, str) and strategy:
        profile.domain_strategy = strategy
    updated = _get(data, "LastUpdated")
    profile.updated = str(updated) if updated not in (None, "") else None
    # Блокировки — первыми, затем «через VPN» (исключения внутри прямых категорий), затем прямые.
    for action, sites_key, ip_key in (("block", "BlockSites", "BlockIp"), ("proxy", "ProxySites", "ProxyIp"),
                                      ("direct", "DirectSites", "DirectIp")):
        sites = _strings(_get(data, sites_key))
        ips = _strings(_get(data, ip_key))
        if sites:
            profile.rules.append({"action": action, "domains": sites})
        if ips:
            profile.rules.append({"action": action, "ips": ips})
    return profile


def _action_of(outbound: Any) -> str:
    proto = str(outbound.get("protocol") or "").lower() if isinstance(outbound, dict) else ""
    return {"freedom": "direct", "blackhole": "block", "dns": "skip"}.get(proto, "proxy")


def _tag_actions(outbounds: list[Any]) -> dict[str, str]:
    return {str(ob["tag"]): _action_of(ob) for ob in outbounds if isinstance(ob, dict) and ob.get("tag")}


def _guess_action(tag: str) -> str:
    """Действие по имени тега — только для профилей, сохранённых без outbounds (прежние выпуски)."""
    t = tag.lower()
    if any(w in t for w in ("block", "blackhole", "reject", "deny", "ads")):
        return "block"
    if any(w in t for w in ("direct", "freedom", "bypass")):
        return "direct"
    return "proxy"


def from_xray_routing(routing: dict[str, Any], name: str, *, outbounds: list[dict[str, Any]] | None = None
                      ) -> RouteProfile:
    """Правила routing провайдера (JSON Xray) → профиль. Принимает routing или форму полного конфига
    {"routing", "outbounds"}. Выход правила — по протоколу outbound с этим тегом (freedom — напрямую,
    blackhole — блок, остальное — через VPN); тега нет среди outbounds — как у Xray, выход по
    умолчанию (первый outbound); outbounds неизвестны совсем — по имени тега. balancerTag — через VPN.
    Правила с inboundTag, user, source и т. п. относятся к входам провайдера и не переносятся."""
    data = routing if isinstance(routing, dict) else {}
    if "rules" not in data and isinstance(data.get("routing"), dict):
        outbounds = outbounds if outbounds is not None else data.get("outbounds")
        data = data["routing"]
    known = isinstance(outbounds, list) and bool(outbounds)
    actions = _tag_actions(outbounds) if known else {}
    default = _action_of(outbounds[0]) if known else "proxy"
    default = "proxy" if default == "skip" else default
    profile = RouteProfile(name=name or "Маршруты провайдера", source="xray")
    profile.domain_strategy = str(data.get("domainStrategy") or "AsIs")
    profile.global_proxy = default != "direct"
    for rule in data.get("rules") or []:
        if not isinstance(rule, dict):
            continue
        skipped = [k for k in _SKIP_KEYS if rule.get(k)]
        if skipped:
            profile.warnings.append(f"Правило с {', '.join(skipped)} пропущено: оно о входах провайдера")
            continue
        if rule.get("balancerTag"):
            action = "proxy"
        elif rule.get("outboundTag"):
            tag = str(rule["outboundTag"])
            action = actions.get(tag, default) if known else _guess_action(tag)
        else:
            continue
        if action == "skip":
            continue
        entry: dict[str, Any] = {"action": action}
        domains = _strings(rule.get("domain") or rule.get("domains"))
        ips = _strings(rule.get("ip"))
        if domains:
            entry["domains"] = domains
        if ips:
            entry["ips"] = ips
        if rule.get("port") not in (None, ""):
            entry["ports"] = str(rule["port"])
        if rule.get("network"):
            entry["network"] = str(rule["network"])
        protocols = [p.lower() for p in _strings(rule.get("protocol")) if p.lower() in _PROTOCOLS]
        if protocols:
            entry["protocols"] = protocols
        if len(entry) > 1:
            profile.rules.append(entry)
    return profile


# ------------------------------------------------------------ перевод в правила sing-box

def _port_fields(spec: str) -> dict[str, list]:
    single: list[int] = []
    ranges: list[str] = []
    for item in _strings(spec):
        lo, _, hi = item.partition("-")
        if not lo.strip().isdigit() or (hi and not hi.strip().isdigit()):
            continue
        if hi and int(hi) != int(lo):
            ranges.append(f"{int(lo)}:{int(hi)}")
        else:
            single.append(int(lo))
    out: dict[str, list] = {}
    if single:
        out["port"] = single
    if ranges:
        out["port_range"] = ranges
    return out


def _extras(entry: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if entry.get("ports"):
        out.update(_port_fields(str(entry["ports"])))
    if entry.get("network"):
        nets = [n for n in _strings(str(entry["network"]).replace(" ", ",")) if n in ("tcp", "udp")]
        if nets:
            out["network"] = nets
    if entry.get("protocols"):
        out["protocol"] = list(entry["protocols"])
    return out


def _matchers(entries: list[str], profile_warnings: list[str], ids: list[str]) -> list[dict[str, Any]]:
    """Список доменов или IP → подправила sing-box (между ними — ИЛИ)."""
    group = routing.site_group(entries)
    for bad in group.bad:
        profile_warnings.append(f"Не понято и пропущено: {bad}")
    out: list[dict[str, Any]] = []
    if group.fields:
        out.append({k: list(v) for k, v in group.fields.items()})
    if group.rule_sets:
        out.append({"rule_set": list(group.rule_sets)})
        ids.extend(s for s in group.rule_sets if s not in ids)
    for set_id in group.negated_sets:
        out.append({"rule_set": [set_id], "invert": True})
        if set_id not in ids:
            ids.append(set_id)
    if group.private is not None:
        out.append(routing.private_match(group.private))
    return out


def _or(parts: list[dict[str, Any]]) -> dict[str, Any]:
    return parts[0] if len(parts) == 1 else {"type": "logical", "mode": "or", "rules": parts}


def to_rules(profile: RouteProfile) -> tuple[list[dict[str, Any]], list[str]]:
    """(правила sing-box, нужные rule-set id). geosite:X → "geosite-X", geoip:X → "geoip-X" (их
    скачивает rules.py из sing-geosite / sing-geoip SagerNet). Домены и IP одного правила Xray
    должны совпасть оба (И), разные строки списка — любая (ИЛИ)."""
    rules: list[dict[str, Any]] = []
    ids: list[str] = []
    warnings: list[str] = []
    for entry in profile.rules:
        action = entry.get("action")
        if action not in ACTIONS:
            continue
        domains = _matchers(_strings(entry.get("domains")), warnings, ids)
        ips = _matchers(_strings(entry.get("ips")), warnings, ids)
        extras = _extras(entry)
        if entry.get("domains") and not domains or entry.get("ips") and not ips:
            continue                     # всё в правиле непонятно — расширять его до «всего» нельзя
        if domains and ips:
            parts = [_or(domains), _or(ips)] + ([extras] if extras else [])
            rules.append({"type": "logical", "mode": "and", "rules": parts, **_ROUTE[action]})
            continue
        matchers = domains or ips
        if not matchers:
            if extras:
                rules.append({**extras, **_ROUTE[action]})
            continue
        for matcher in matchers:
            if extras and (matcher.get("invert") or matcher.get("type") == "logical"):
                rules.append({"type": "logical", "mode": "and", "rules": [matcher, extras], **_ROUTE[action]})
            else:
                rules.append({**matcher, **extras, **_ROUTE[action]})
    # Выход по умолчанию профиля (GlobalProxy) — последним правилом: всё, что не попало в правила
    # профиля, идёт так, как решил профиль, а не по пресету Лазейки (генератор делает его route.final).
    rules.append({"network": ["tcp", "udp"], **_ROUTE["proxy" if profile.global_proxy else "direct"]})
    profile.warnings.extend(w for w in dict.fromkeys(warnings) if w not in profile.warnings)
    return rules, ids


def summary(profile: RouteProfile) -> dict[str, Any]:
    """Что покажет окно подтверждения: строки профиля по действиям, как их написал провайдер."""
    to_rules(profile)                    # заодно собирает предупреждения о непонятых строках
    out: dict[str, Any] = {"name": profile.name, "global_proxy": profile.global_proxy,
                           "direct": [], "proxy": [], "block": [], "warnings": list(profile.warnings)}
    for entry in profile.rules:
        action = entry.get("action")
        if action not in ACTIONS:
            continue
        items = _strings(entry.get("domains")) + _strings(entry.get("ips"))
        extras = []
        if entry.get("ports"):
            extras.append(f"порты {entry['ports']}")
        if entry.get("network"):
            extras.append(str(entry["network"]))
        if entry.get("protocols"):
            extras.append(", ".join(entry["protocols"]))
        suffix = f" ({'; '.join(extras)})" if extras else ""
        if items:
            out[action].extend(item + suffix for item in items)
        elif extras:
            out[action].append("; ".join(extras))
    return out
