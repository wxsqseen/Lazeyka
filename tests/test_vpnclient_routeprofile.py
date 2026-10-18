"""Свой VPN: профили маршрутизации Happ/Incy и маршруты провайдера (JSON Xray) → правила sing-box."""
import base64
import json

import pytest

from app.vpnclient import config, routeprofile
from app.vpnclient.routeprofile import RouteProfile, RouteProfileError, from_xray_routing, parse_happ, summary, to_rules

# Пример из документации Happ (заголовок routing подписки).
HAPP_DOC = ("happ://routing/onadd/ewogICAgIk5hbWUiOiAidGVzdCIsCiAgICAiR2xvYmFsUHJveHkiOiAidHJ1ZSIsCiAgICAiUmVtb3RlRG5z"
            "IjogIiIsCiAgICAiRG9tZXN0aWNEbnMiOiAiIiwKICAgICJHZW9pcHVybCI6ICIiLAogICAgIkdlb3NpdGV1cmwiOiAiIiwKICAgICJEbnNI"
            "b3N0cyI6IHt9LAogICAgIkRpcmVjdFNpdGVzIjogW10sCiAgICAiRGlyZWN0SXAiOiBbXSwKICAgICJQcm94eVNpdGVzIjogW10sCiAgICAi"
            "UHJveHlJcCI6IFtdLAogICAgIkJsb2NrU2l0ZXMiOiBbXSwKICAgICJCbG9ja0lwIjogW10sCiAgICAiRG9tYWluU3RyYXRlZ3kiOiAiQXNJ"
            "cyIKfQ==")
PROFILE = {
    "Name": "RU", "GlobalProxy": "false", "RemoteDNSType": "DoH", "RemoteDNSDomain": "https://cloudflare-dns.com/dns-query",
    "DomesticDNSIP": "77.88.8.8", "DnsHosts": {"lkfl2.nalog.ru": "213.24.64.175"},
    "DirectSites": ["geosite:category-ru", "domain:habr.com", "full:x.example.org", "keyword:yandex",
                    "regexp:^.*\\.su$", "ext:custom.dat:tag", "vk.com"],
    "DirectIp": ["geoip:ru", "geoip:private", "10.0.0.0/8"],
    "ProxySites": ["geosite:youtube"], "ProxyIp": ["geoip:!ru"],
    "BlockSites": ["geosite:category-ads-all"], "BlockIp": [],
    "DomainStrategy": "IPIfNonMatch", "LastUpdated": "1760000000",
}


ALL_PROXY = {"network": ["tcp", "udp"], "action": "route", "outbound": "proxy"}     # GlobalProxy: true


def b64(data: dict, *, urlsafe: bool = False, pad: bool = True) -> str:
    raw = json.dumps(data, ensure_ascii=False).encode("utf-8")
    text = (base64.urlsafe_b64encode(raw) if urlsafe else base64.b64encode(raw)).decode()
    return text if pad else text.rstrip("=")


@pytest.mark.parametrize("text", [
    b64(PROFILE), json.dumps(PROFILE), "happ://routing/add/" + b64(PROFILE), "happ://routing/onadd/" + b64(PROFILE),
    "incy://routing/onadd/" + b64(PROFILE, urlsafe=True, pad=False), "incy://routing/add?data=" + b64(PROFILE),
    "INCY://ROUTING/ONADD/" + b64(PROFILE), "incy://routing/" + b64(PROFILE), "://routing/onadd/" + b64(PROFILE),
    "incy://autorouting/onadd/" + b64(PROFILE),
], ids=["base64", "json", "happ-add", "happ-onadd", "incy-urlsafe", "incy-data", "upper", "incy-short", "bare",
        "incy-auto-inline"])
def test_parse_forms(text):
    p = parse_happ(text)
    assert p.name == "RU" and p.global_proxy is False
    assert p.dns_remote == "https://cloudflare-dns.com/dns-query" and p.dns_domestic == "77.88.8.8"
    assert p.domain_strategy == "IPIfNonMatch" and p.updated == "1760000000"
    assert [r["action"] for r in p.rules] == ["block", "proxy", "proxy", "direct", "direct"]
    assert p.dns_hosts == {"lkfl2.nalog.ru": "213.24.64.175"} and any("DnsHosts" in w for w in p.warnings)


def test_happ_documentation_example():
    p = parse_happ(HAPP_DOC)
    assert (p.name, p.global_proxy, p.rules, p.domain_strategy) == ("test", True, [], "AsIs")
    assert to_rules(p) == ([ALL_PROXY], [])                           # GlobalProxy: true — остальное через VPN


@pytest.mark.parametrize("text,kind,url,auto", [
    ("incy://routing/onadd/https://example.com/p.json", "url", "https://example.com/p.json", False),
    ("incy://autorouting/onadd/https://example.com/p.json", "url", "https://example.com/p.json", True),
    ("incy://onadd/https://example.com/p.json", "url", "https://example.com/p.json", False),
    ("happ://routing/off", "off", None, False),
    ("not a profile at all!", "bad", None, False),
    (json.dumps([1, 2]), "bad", None, False),
    ("", "bad", None, False),
])
def test_parse_refusals(text, kind, url, auto):
    with pytest.raises(RouteProfileError) as exc:
        parse_happ(text)
    assert (exc.value.kind, exc.value.url, exc.value.auto) == (kind, url, auto)
    if kind == "url":
        assert routeprofile.profile_url(text) == url


def test_to_rules_happ():
    rules, ids = to_rules(parse_happ(json.dumps(PROFILE)))
    assert rules == [
        {"rule_set": ["geosite-category-ads-all"], "action": "reject"},
        {"rule_set": ["geosite-youtube"], "action": "route", "outbound": "proxy"},
        {"rule_set": ["geoip-ru"], "invert": True, "action": "route", "outbound": "proxy"},
        {"domain_suffix": ["habr.com", "vk.com"], "domain": ["x.example.org"], "domain_keyword": ["yandex"],
         "domain_regex": ["^.*\\.su$"], "action": "route", "outbound": "direct"},
        {"rule_set": ["geosite-category-ru"], "action": "route", "outbound": "direct"},
        {"ip_cidr": ["10.0.0.0/8"], "action": "route", "outbound": "direct"},
        {"rule_set": ["geoip-ru"], "action": "route", "outbound": "direct"},
        {"ip_is_private": True, "action": "route", "outbound": "direct"},
        {"network": ["tcp", "udp"], "action": "route", "outbound": "direct"},       # GlobalProxy: false
    ]
    assert ids == ["geosite-category-ads-all", "geosite-youtube", "geoip-ru", "geosite-category-ru"]


def test_bad_entries_are_reported_not_widened():
    p = RouteProfile(name="x", rules=[{"action": "block", "domains": ["ext:only.dat:tag"]},
                                      {"action": "direct", "domains": ["ok.example", "bad domain"]}])
    rules, _ = to_rules(p)
    assert rules == [{"domain_suffix": ["ok.example"], "action": "route", "outbound": "direct"}, ALL_PROXY]
    assert {"Не понято и пропущено: ext:only.dat:tag", "Не понято и пропущено: bad domain"} <= set(p.warnings)
    to_rules(p)
    assert len(p.warnings) == len(set(p.warnings))                    # повторный вызов не плодит строки


PROVIDER = {
    "routing": {"domainStrategy": "IPIfNonMatch", "rules": [
        {"type": "field", "inboundTag": ["dns-in"], "outboundTag": "dns-out"},
        {"type": "field", "domain": ["geosite:category-ru", "domain:ru"], "outboundTag": "direct"},
        {"type": "field", "ip": ["geoip:ru", "geoip:private"], "outboundTag": "direct"},
        {"type": "field", "protocol": ["bittorrent"], "outboundTag": "direct"},
        {"type": "field", "domain": ["geosite:category-ads-all"], "outboundTag": "block"},
        {"type": "field", "domain": ["example.com"], "ip": ["1.2.3.4"], "port": "443", "network": "tcp",
         "outboundTag": "proxy"},
        {"type": "field", "port": "0-65535", "balancerTag": "auto"},
    ]},
    "outbounds": [{"tag": "proxy", "protocol": "vless"}, {"tag": "direct", "protocol": "freedom"},
                  {"tag": "block", "protocol": "blackhole"}, {"tag": "dns-out", "protocol": "dns"}],
}


def test_from_xray_routing():
    p = from_xray_routing(PROVIDER, "Провайдер")
    assert p.source == "xray" and p.global_proxy is True and p.domain_strategy == "IPIfNonMatch"
    assert any("inboundTag" in w for w in p.warnings)
    rules, ids = to_rules(p)
    assert rules == [
        {"domain_suffix": ["ru"], "action": "route", "outbound": "direct"},
        {"rule_set": ["geosite-category-ru"], "action": "route", "outbound": "direct"},
        {"rule_set": ["geoip-ru"], "action": "route", "outbound": "direct"},
        {"ip_is_private": True, "action": "route", "outbound": "direct"},
        {"protocol": ["bittorrent"], "action": "route", "outbound": "direct"},
        {"rule_set": ["geosite-category-ads-all"], "action": "reject"},
        {"type": "logical", "mode": "and", "rules": [{"domain_suffix": ["example.com"]}, {"ip_cidr": ["1.2.3.4/32"]},
                                                     {"port": [443], "network": ["tcp"]}],
         "action": "route", "outbound": "proxy"},
        {"port_range": ["0:65535"], "action": "route", "outbound": "proxy"},
        ALL_PROXY,
    ]
    assert ids == ["geosite-category-ru", "geoip-ru", "geosite-category-ads-all"]


def test_from_xray_routing_by_tag_names_and_default_outbound():
    routing_only = {"rules": [{"type": "field", "domain": ["a.example"], "outboundTag": "out-direct"},
                              {"type": "field", "domain": ["b.example"], "outboundTag": "blocked"},
                              {"type": "field", "domain": ["c.example"], "outboundTag": "vless-nl"}]}
    p = from_xray_routing(routing_only, "x")
    assert [r["action"] for r in p.rules] == ["direct", "block", "proxy"]
    direct_first = from_xray_routing(routing_only, "x", outbounds=[{"tag": "d", "protocol": "freedom"}])
    assert direct_first.global_proxy is False


def test_rules_fit_into_config():
    """Правила профиля проходят генератор и validate(); GlobalProxy: false — выход по умолчанию direct."""
    from tests.test_vpnclient_config import RULES_DIR, make_plan, server
    rules, ids = to_rules(parse_happ(json.dumps(PROFILE)))
    plan = make_plan([server("vless_reality_vision")], profile_rules=rules,
                     rules_files={i: RULES_DIR / f"{i}.srs" for i in ids if i != "geosite-category-ads-all"})
    cfg = config.build_singbox(plan)
    assert config.validate(cfg) == []
    assert not any("geosite-category-ads-all" in json.dumps(r) for r in cfg["route"]["rules"])   # набора нет
    assert {"rule_set": ["geosite-category-ru"], "action": "route", "server": "dns-direct"} in cfg["dns"]["rules"]
    assert (cfg["route"]["final"], cfg["dns"]["final"]) == ("direct", "dns-direct")
    assert not any(r.get("network") == ["tcp", "udp"] for r in cfg["route"]["rules"])   # «всё остальное» — final


def test_summary_and_roundtrip():
    p = parse_happ(json.dumps(PROFILE))
    s = summary(p)
    assert s["name"] == "RU" and s["global_proxy"] is False
    assert s["block"] == ["geosite:category-ads-all"]
    assert s["proxy"] == ["geosite:youtube", "geoip:!ru"]
    assert s["direct"][:2] == ["geosite:category-ru", "domain:habr.com"] and "10.0.0.0/8" in s["direct"]
    assert any("ext:custom.dat:tag" in w for w in s["warnings"])
    x = summary(from_xray_routing(PROVIDER, "p"))
    assert "example.com (порты 443; tcp)" in x["proxy"] and "bittorrent" in x["direct"]
    assert RouteProfile.from_dict(p.to_dict()) == p


def test_global_proxy_becomes_the_last_rule_both_ways():
    rules, _ = to_rules(RouteProfile(name="x", global_proxy=True, rules=[{"action": "direct", "domains": ["a.ru"]}]))
    assert rules == [{"domain_suffix": ["a.ru"], "action": "route", "outbound": "direct"}, ALL_PROXY]
    rules, _ = to_rules(RouteProfile(name="x", global_proxy=False))
    assert rules == [{"network": ["tcp", "udp"], "action": "route", "outbound": "direct"}]


def test_not_private_is_inverted_not_an_empty_rule():
    """geoip:!private: «ip_is_private: false» ядро считает «условия нет» — правило совпало бы со всем трафиком."""
    rules, _ = to_rules(RouteProfile(name="x", rules=[{"action": "direct", "ips": ["geoip:!private"]}]))
    assert rules[0] == {"ip_is_private": True, "invert": True, "action": "route", "outbound": "direct"}


def test_provider_rule_action_comes_from_outbound_protocol_not_tag_name():
    """VLESS-выход с тегом «bypass» — это сервер, а не «напрямую»; тег, которого нет среди outbounds, Xray
    отправляет в выход по умолчанию (первый outbound)."""
    from app.vpnclient import xrayjson
    config_ = {"remarks": "P", "outbounds": [
        {"tag": "main", "protocol": "vless", "settings": {"address": "a.example.com", "port": 443, "id": "u"}},
        {"tag": "bypass", "protocol": "vless", "settings": {"address": "b.example.com", "port": 443, "id": "u"}},
        {"tag": "out-direct", "protocol": "blackhole"}],
        "routing": {"rules": [{"domain": ["domain:example.org"], "outboundTag": "bypass"},
                              {"domain": ["domain:ads.example"], "outboundTag": "out-direct"},
                              {"domain": ["domain:lost.example"], "outboundTag": "nowhere"}]}}
    imported = xrayjson.parse([config_])
    assert "secret" not in json.dumps(imported.routing) and "a.example.com" not in json.dumps(imported.routing)
    p = from_xray_routing(imported.routing, "P")
    assert [(r["domains"], r["action"]) for r in p.rules] == [
        (["domain:example.org"], "proxy"), (["domain:ads.example"], "block"), (["domain:lost.example"], "proxy")]
    assert p.global_proxy is True
    first_direct = dict(imported.routing,
                        outbounds=[{"tag": "d", "protocol": "freedom"}, *imported.routing["outbounds"]])
    p = from_xray_routing(first_direct, "P")
    assert p.global_proxy is False and p.rules[-1]["action"] == "direct"   # «nowhere» — в выход по умолчанию
    # профиль, сохранённый прежним выпуском без outbounds, — по имени тега, как раньше
    legacy = from_xray_routing(imported.routing["routing"], "P")
    assert [r["action"] for r in legacy.rules] == ["direct", "direct", "proxy"]
