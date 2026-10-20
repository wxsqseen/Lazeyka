"""Свой VPN: генератор конфигов sing-box и помощника Xray, validate() и таблица запрещённых полей."""
import copy
import json
import os
import re
from pathlib import Path

import pytest

from app.vpnclient import config, routeprofile, routing
from app.vpnclient.config import ConfigError, build_delay, build_singbox, build_xray, tag, validate
from app.vpnclient.model import (BypassProfile, DnsChoice, Group, Ports, RunPlan, Secrets, Server, TunOptions,
                                 engine_for)

DATA = Path(__file__).resolve().parent / "data" / "vpnclient"
SNAPSHOTS = DATA / "snapshots"
CASES = json.loads((DATA / "servers.json").read_text(encoding="utf-8"))["cases"]
BY_CASE = {c["case"]: c for c in CASES}
# Ключ X25519 нужной длины: эталонный «AAAA» — заглушка, на ней Xray 26.3.27 падает с паникой.
MLKEM = "mlkem768x25519plus.native.0rtt.AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"
RULES_DIR = Path(r"C:\lz\rules")
RUN_DIR = Path(r"C:\lz\run")
SB_TYPE = {"vless": "vless", "vmess": "vmess", "trojan": "trojan", "shadowsocks": "shadowsocks",
           "hysteria2": "hysteria2", "tuic": "tuic", "socks": "socks", "wireguard": "wireguard"}


def server(case: str, **changes) -> Server:
    s = Server.from_dict(BY_CASE[case]["server"])
    for key, value in changes.items():
        setattr(s, key, value)
    if changes:
        s.id = s.key()                   # как у хранилища: id = key()
    return s


def supported_servers() -> list[Server]:
    out = []
    for c in CASES:
        if c["engine"] is None:
            continue
        out.append(server(c["case"], encryption=MLKEM) if c["case"] == "vless_mlkem" else server(c["case"]))
    return out


def make_plan(servers: list[Server], mode: str = "tun", **overrides) -> RunPlan:
    """План, каким его собрал бы менеджер: адреса резолвлены, порты и секреты выбраны."""
    plan = RunPlan(
        mode=mode, servers=servers, selected=servers[0].id,
        addresses={s.id: f"198.51.100.{i + 1}" for i, s in enumerate(servers)},
        engines={s.id: engine_for(s)[0] for s in servers if engine_for(s)[0]},
        ports=Ports(proxy=20808, internal=20900, clash=20901,
                    helper={s.id: 21000 + i for i, s in enumerate(servers)}),
        secrets=Secrets(clash="clash-secret-1", internal_user="int-user", internal_pass="int-pass",
                        helper_user="help-user", helper_pass="help-pass"),
        tun=TunOptions(address4="172.31.255.253/30", exclude=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]),
        lazeyka_exe=r"C:\Program Files\Lazeyka\Lazeyka.exe",
        xray_exe=r"C:\ProgramData\Lazeyka\components\xray\26.3.27\xray.exe", physical_interface="Ethernet",
        work_dir=RUN_DIR)
    for key, value in overrides.items():
        setattr(plan, key, value)
    return plan


def bypass_profiles() -> list[BypassProfile]:
    """Профили «через обход», как их даёт general.bat zapret 1.10.3 (IPSet «по списку»)."""
    return [
        BypassProfile("udp", ["443"], domains_file=RUN_DIR / "bypass-0.json"),
        BypassProfile("udp", ["19294-19344", "50000-50100"], l7=["discord", "stun"]),
        BypassProfile("tcp", ["2053", "2083", "2087", "2096", "8443"], domains_file=RUN_DIR / "bypass-2.json"),
        BypassProfile("tcp", ["443"], domains_file=RUN_DIR / "bypass-3.json", reject_quic=True),
        BypassProfile("tcp", ["80", "443"], domains_file=RUN_DIR / "bypass-4.json", reject_quic=True),
        BypassProfile("udp", ["443"], ips_file=RUN_DIR / "bypass-5-ip.json"),
    ]


def all_rule_files() -> dict[str, Path]:
    ids = ["geosite-category-ru", "geoip-ru", "geosite-category-game-platforms-download", "refilter-domains",
           "russia-inside", "geoip-ru-blocked", "geosite-youtube", "geosite-category-ads-all"]
    return {i: RULES_DIR / f"{i}.srs" for i in ids}


def full_plan(mode: str = "tun", preset: str = "all", **overrides) -> RunPlan:
    servers = supported_servers()
    ids = [s.id for s in servers]
    profile = routeprofile.parse_happ(json.dumps({
        "Name": "Тест", "DirectSites": ["geosite:category-ru"], "ProxySites": ["geosite:youtube"],
        "BlockSites": ["geosite:category-ads-all"], "DirectIp": ["geoip:ru"]}))
    plan = make_plan(
        servers, mode, selected="auto:g-all",
        groups=[Group(id="g-all", sub=None, name="Все", members=ids), Group(id="g-two", sub=None, name="Два",
                                                                         members=ids[:2])],
        preset=preset, via_zapret=True, bypass_state="direct", bypass=bypass_profiles(),
        voice_ports=["19294-19344", "50000-50100"], games_direct=True, torrents_direct=True, ip_check_direct=True,
        direct_apps=["steam.exe"], proxy_apps=["Telegram.exe"], direct_sites=["example.org"],
        proxy_sites=["blocked.example"], rules_files=all_rule_files(), additions=list(routing.ADDITIONS),
        profile_rules=routeprofile.to_rules(profile)[0],
        dns=DnsChoice(remote="https://1.1.1.1/dns-query", direct="https://8.8.8.8/dns-query",
                      ru="https://77.88.8.8/dns-query", fakeip=True))
    for key, value in overrides.items():
        setattr(plan, key, value)
    return plan


def outbound(cfg: dict, server_id: str) -> dict:
    t = tag(server_id)
    for ob in cfg.get("outbounds", []) + cfg.get("endpoints", []):
        if ob["tag"] == t:
            return ob
    raise AssertionError(f"нет выхода {t}")


def rule_index(rules: list, predicate) -> int:
    for i, rule in enumerate(rules):
        if predicate(rule):
            return i
    raise AssertionError("правило не найдено")


# ------------------------------------------------------------ эталонные серверы

@pytest.mark.parametrize("mode", ["tun", "proxy", "local"])
@pytest.mark.parametrize("case", CASES, ids=[c["case"] for c in CASES])
def test_reference_server_config(case, mode):
    s = server(case["case"], encryption=MLKEM) if case["case"] == "vless_mlkem" else server(case["case"])
    plan = make_plan([s], mode)
    if case["engine"] is None:
        with pytest.raises(ConfigError):
            build_singbox(plan)
        return
    cfg = build_singbox(plan)
    assert validate(cfg) == []
    ob = outbound(cfg, s.id)
    if case["engine"] == "xray":
        assert ob == {"type": "socks", "tag": tag(s.id), "server": "127.0.0.1", "server_port": 21000, "version": "5",
                      "username": "help-user", "password": "help-pass"}
        helper = build_xray(plan)
        assert helper["inbounds"][0]["port"] == 21000
    else:
        assert ob["type"] == SB_TYPE[s.proto]
        address = ob["peers"][0]["address"] if ob["type"] == "wireguard" else ob["server"]
        assert address == "198.51.100.1"                       # адрес — заранее резолвленный IP
        if "tls" in ob:
            want = (s.tls or {}).get("sni") or (None if ":" in s.host or s.host[0].isdigit() else s.host)
            assert ob["tls"].get("server_name") == want      # SNI — исходный хост
        assert build_xray(plan) is None
    if not s.host[0].isdigit() and ":" not in s.host:
        assert cfg["dns"]["rules"][0] == {"domain": [s.host], "action": "route", "server": "dns-direct"}


def test_reality_vision():
    cfg = build_singbox(make_plan([server("vless_reality_vision")], mux=True))
    ob = outbound(cfg, server("vless_reality_vision").id)
    assert ob["flow"] == "xtls-rprx-vision"
    assert ob["tls"]["utls"] == {"enabled": True, "fingerprint": "chrome"}
    assert ob["tls"]["reality"] == {"enabled": True, "public_key": "ae4k-ShjTC9gh3NHRS_pjKyBGyPS5qpgAK8sA4FIizQ",
                                    "short_id": "6ba85179e30d4fc2"}
    assert ob["tls"]["server_name"] == "www.example.org"
    assert "multiplex" not in ob                                # mux с Vision недоступен


def test_ws_early_data_and_host():
    s = server("vless_tls_ws")
    ob = outbound(build_singbox(make_plan([s])), s.id)
    assert ob["transport"] == {"type": "ws", "path": "/ws", "headers": {"Host": "cdn.example.com"},
                               "max_early_data": 2048, "early_data_header_name": "Sec-WebSocket-Protocol"}
    assert "alpn" not in ob["tls"]                              # ws — только HTTP/1.1
    s2 = server("vless_tls_ws", transport={"path": "/ws?foo=1&ed=4096", "host": "cdn.example.com"})
    assert outbound(build_singbox(make_plan([s2])), s2.id)["transport"]["path"] == "/ws?foo=1"


def test_transports():
    hu = outbound(build_singbox(make_plan([server("vless_httpupgrade")])), server("vless_httpupgrade").id)
    assert hu["transport"] == {"type": "httpupgrade", "path": "/up", "host": "example.com"}
    th = outbound(build_singbox(make_plan([server("vless_tcp_http")])), server("vless_tcp_http").id)
    assert th["transport"] == {"type": "http", "method": "GET", "host": ["a.example.com", "b.example.com"],
                               "path": "/x"}
    h2 = outbound(build_singbox(make_plan([server("vless_h2")])), server("vless_h2").id)
    assert h2["transport"] == {"type": "http", "path": "/h2", "host": ["example.com"]}
    assert h2["tls"]["server_name"] == "example.com"
    grpc = outbound(build_singbox(make_plan([server("trojan_grpc_default_port")])),
                    server("trojan_grpc_default_port").id)
    assert grpc["transport"] == {"type": "grpc", "service_name": "tr-grpc"}
    v6 = outbound(build_singbox(make_plan([server("vless_tls_ipv6")])), server("vless_tls_ipv6").id)
    assert "server_name" not in v6["tls"]                       # у IP-адреса SNI нет


def test_protocol_fields():
    vm = outbound(build_singbox(make_plan([server("vmess_legacy_aid")])), server("vmess_legacy_aid").id)
    assert (vm["alter_id"], vm["security"]) == (64, "auto")
    ss = outbound(build_singbox(make_plan([server("ss_legacy_b64")])), server("ss_legacy_b64").id)
    assert (ss["method"], ss["password"]) == ("chacha20-ietf-poly1305", "test/!@#:")
    plug = outbound(build_singbox(make_plan([server("ss_v2ray_plugin")])), server("ss_v2ray_plugin").id)
    assert (plug["plugin"], plug["plugin_opts"]) == ("v2ray-plugin", "tls;host=cdn.example.com;path=/ss")
    hy = outbound(build_singbox(make_plan([server("hysteria2_salamander_hop")])), server("hysteria2_salamander_hop").id)
    assert hy["server_ports"] == ["443:443", "20000:30000"] and "server_port" not in hy
    assert hy["obfs"] == {"type": "salamander", "password": "obfspw"}
    assert hy["tls"] == {"enabled": True, "server_name": "hy.example.com", "alpn": ["h3"]}
    hy2 = outbound(build_singbox(make_plan([server("hy2_insecure")])), server("hy2_insecure").id)
    assert hy2["server_port"] == 8443 and hy2["tls"]["insecure"] is True and "utls" not in hy2["tls"]
    tuic = outbound(build_singbox(make_plan([server("tuic")])), server("tuic").id)
    assert (tuic["congestion_control"], tuic["udp_relay_mode"], tuic["tls"]["alpn"]) == ("bbr", "native", ["h3"])
    tr = outbound(build_singbox(make_plan([server("trojan_ws_insecure")])), server("trojan_ws_insecure").id)
    assert tr["tls"]["insecure"] is True and tr["transport"]["headers"] == {"Host": "cdn.example.org"}
    socks = outbound(build_singbox(make_plan([server("socks")])), server("socks").id)
    assert (socks["username"], socks["password"], socks["version"]) == ("user", "pass", "5")


def test_wireguard_is_endpoint():
    s = server("wireguard")
    cfg = build_singbox(make_plan([s]))
    assert all(o["type"] != "wireguard" for o in cfg["outbounds"])
    ep = cfg["endpoints"][0]
    assert ep["address"] == ["10.0.0.2/32", "fd00::2/128"] and ep["mtu"] == 1420
    assert ep["peers"][0]["address"] == "198.51.100.1" and ep["peers"][0]["reserved"] == [1, 2, 3]
    assert tag(s.id) in next(o for o in cfg["outbounds"] if o["tag"] == "proxy")["outbounds"]


# ------------------------------------------------------------ режимы, входы, общие разделы

def test_tun_inbound_and_common_sections():
    plan = make_plan([server("vless_reality_vision")], tun=TunOptions(
        address4="172.31.255.253/30", address6="fdfe:dcba:9876::1/126", mtu=1400, exclude=["10.0.0.0/8"]))
    cfg = build_singbox(plan)
    tun = cfg["inbounds"][0]
    assert tun == {"type": "tun", "tag": "tun-in", "interface_name": "Lazeyka",
                   "address": ["172.31.255.253/30", "fdfe:dcba:9876::1/126"], "mtu": 1400, "auto_route": True,
                   "strict_route": True, "dns_mode": "hijack", "route_exclude_address": ["10.0.0.0/8"]}
    assert "stack" not in tun
    assert cfg["route"]["auto_detect_interface"] is True
    assert cfg["experimental"] == {"clash_api": {"external_controller": "127.0.0.1:20901", "secret": "clash-secret-1",
                                                 "access_control_allow_origin": ["http://127.0.0.1"]}}
    assert cfg["log"] == {"level": "error", "timestamp": True}
    internal = next(i for i in cfg["inbounds"] if i["tag"] == "internal-in")
    assert internal["users"] == [{"username": "int-user", "password": "int-pass"}]
    assert not any(i["tag"] == "mixed-in" for i in cfg["inbounds"])     # в TUN системный прокси не нужен


def test_proxy_and_local_inbounds():
    s = server("vless_reality_vision")
    cfg = build_singbox(make_plan([s], "proxy"))
    assert [i["type"] for i in cfg["inbounds"]] == ["mixed", "mixed"]
    mixed = cfg["inbounds"][0]
    assert mixed == {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 20808}
    local = build_singbox(make_plan([s], "local", secrets=Secrets(
        clash="c", internal_user="iu", internal_pass="ip", local_user="lu", local_pass="lp"), socks_udp=False))
    assert local["inbounds"][0]["users"] == [{"username": "lu", "password": "lp"}]
    assert {"inbound": ["mixed-in"], "network": ["udp"], "action": "reject"} in local["route"]["rules"]
    with_password = Secrets(clash="c", internal_user="iu", internal_pass="ip", local_user="lu", local_pass="lp")
    lan = build_singbox(make_plan([s], "tun", proxy_listen="0.0.0.0", secrets=with_password))
    inbound = next(i for i in lan["inbounds"] if i["tag"] == "mixed-in")
    assert inbound["listen"] == "0.0.0.0" and inbound["users"] == [{"username": "lu", "password": "lp"}]


@pytest.mark.parametrize("mode", ["tun", "proxy", "local"])
def test_lan_inbound_without_password_is_refused(mode):
    """Вход для устройств из сети без логина и пароля — открытый прокси через сервер человека для всей
    локальной сети: генератор такой конфиг не собирает, даже если план попросил."""
    with pytest.raises(ConfigError, match="только с логином и паролем"):
        build_singbox(make_plan([server("vless_reality_vision")], mode, proxy_listen="0.0.0.0"))


def test_log_level_and_dns_strategy():
    plan = make_plan([server("vless_reality_vision")], log_level="warning",
                     dns=DnsChoice(strategy="prefer_ipv6"))
    cfg = build_singbox(plan)
    assert cfg["log"]["level"] == "warn"
    assert cfg["dns"]["strategy"] == "prefer_ipv6"
    assert cfg["route"]["default_domain_resolver"] == {"server": "dns-direct", "strategy": "prefer_ipv6"}
    with pytest.raises(ConfigError):
        build_singbox(make_plan([server("vless_reality_vision")], log_level="loud"))


# ------------------------------------------------------------ порядок правил (план 5.5)

def test_rule_order_tun():
    cfg = build_singbox(full_plan("tun", "except_ru"))
    assert validate(cfg) == []
    rules = cfg["route"]["rules"]
    assert rules[0]["action"] == "sniff" and rules[1] == {"protocol": ["dns"], "action": "hijack-dns"}
    internal = rule_index(rules, lambda r: r.get("inbound") == ["internal-in"])
    private = rule_index(rules, lambda r: r.get("ip_is_private") is True and r.get("outbound") == "direct")
    own = rule_index(rules, lambda r: r.get("inbound") == ["tun-in"] and "process_path_regex" in r)
    user_proxy = rule_index(rules, lambda r: r.get("domain_suffix") == ["blocked.example"])
    user_direct = rule_index(rules, lambda r: r.get("domain_suffix") == ["example.org"])
    first_bypass = rule_index(rules, lambda r: r.get("outbound") == "bypass")
    last_reject = max(i for i, r in enumerate(rules) if r.get("action") == "reject" and "rule_set" in r
                      and r["rule_set"][0].startswith("bypass-"))
    games = rule_index(rules, lambda r: r.get("rule_set") == [routing.GAMES_DOWNLOAD])
    profile = rule_index(rules, lambda r: r.get("rule_set") == ["geosite-category-ads-all"])
    assert internal < private < own < user_proxy < user_direct < first_bypass < last_reject < games < profile
    # выход по умолчанию профиля (GlobalProxy) заменяет пресет: его правил нет, «всё остальное» — final
    assert not any(r.get("rule_set") == ["geosite-category-ru", "geoip-ru"] for r in rules)
    without_profile = build_singbox(full_plan("tun", "except_ru", profile_rules=[]))["route"]["rules"]
    preset = rule_index(without_profile, lambda r: r.get("rule_set") == ["geosite-category-ru", "geoip-ru"])
    assert rule_index(without_profile, lambda r: r.get("rule_set") == [routing.GAMES_DOWNLOAD]) < preset
    assert rules[internal]["outbound"] == "proxy"
    # служебный вход — раньше любых правил по процессам
    assert internal < min(i for i, r in enumerate(rules) if "process_path_regex" in r or "process_name" in r)
    own_rule = rules[own]
    assert own_rule["outbound"] == "direct" and len(own_rule["process_path_regex"]) == 2
    assert cfg["route"]["final"] == "proxy"


@pytest.mark.parametrize("mode", ["proxy", "local"])
def test_lazeyka_process_rule_only_in_tun(mode):
    cfg = build_singbox(full_plan(mode))
    assert validate(cfg) == []
    rules = cfg["route"]["rules"]
    assert not any(r.get("inbound") == ["tun-in"] for r in rules)
    assert not any("Lazeyka" in json.dumps(r) for r in rules)
    assert {"protocol": ["dns"], "action": "hijack-dns"} not in rules


def test_bypass_rules():
    cfg = build_singbox(full_plan())
    rules = cfg["route"]["rules"]
    bypass = next(o for o in cfg["outbounds"] if o["tag"] == "bypass")
    assert bypass == {"type": "selector", "tag": "bypass", "outbounds": ["direct", "proxy"], "default": "direct",
                      "interrupt_exist_connections": True}
    voice = next(r for r in rules if "process_name" in r)
    assert voice == {"process_name": list(routing.DISCORD_APPS), "network": ["udp"],
                     "port_range": ["19294:19344", "50000:50100"], "action": "route", "outbound": "bypass"}
    assert {"protocol": ["stun"], "network": ["udp"], "port_range": ["19294:19344", "50000:50100"],
            "action": "route", "outbound": "bypass"} in rules
    assert "stun" in rules[0]["sniffer"]
    assert {"network": ["udp"], "port": [443], "rule_set": ["bypass-0"], "action": "route",
            "outbound": "bypass"} in rules
    rejects = [r for r in rules if r.get("action") == "reject" and str(r.get("rule_set", [""])[0]).startswith("bypass")]
    assert [r["rule_set"] for r in rejects] == [["bypass-3"], ["bypass-4"]]
    assert all(r["network"] == ["udp"] and r["port"] == [443] for r in rejects)
    decl = {d["tag"]: d for d in cfg["route"]["rule_set"]}
    assert decl["bypass-0"] == {"type": "local", "tag": "bypass-0", "format": "source",
                                "path": str(RUN_DIR / "bypass-0.json")}
    assert decl["geosite-category-ru"]["format"] == "binary"
    dns_bypass = next(r for r in cfg["dns"]["rules"] if "bypass-0" in r.get("rule_set", []))
    assert dns_bypass["server"] == "dns-bypass" and "bypass-5-ip" not in dns_bypass["rule_set"]
    # DNS этих сайтов идёт тем же путём, что их трафик: через селектор bypass (обход сломался —
    # через сервер), сам DoH — тот же, что у dns-direct.
    server = next(x for x in cfg["dns"]["servers"] if x["tag"] == "dns-bypass")
    direct = next(x for x in cfg["dns"]["servers"] if x["tag"] == "dns-direct")
    assert server["detour"] == "bypass" and server["server"] == direct["server"]


def test_without_bypass_no_bypass_rules():
    cfg = build_singbox(full_plan(via_zapret=False))
    assert validate(cfg) == []
    assert not any(r.get("outbound") == "bypass" for r in cfg["route"]["rules"])
    assert not any(d["tag"].startswith("bypass-") for d in cfg["route"]["rule_set"])
    assert any(o["tag"] == "bypass" for o in cfg["outbounds"])   # селектор есть всегда: PUT не упадёт


def test_selectors_and_groups():
    plan = full_plan()
    cfg = build_singbox(plan)
    proxy = next(o for o in cfg["outbounds"] if o["tag"] == "proxy")
    assert proxy["default"] == "grp-g-all" and proxy["interrupt_exist_connections"] is True
    assert proxy["outbounds"][:2] == ["grp-g-all", "grp-g-two"]
    group = next(o for o in cfg["outbounds"] if o["tag"] == "grp-g-all")
    assert group["type"] == "urltest" and len(group["outbounds"]) == config.MAX_GROUP
    assert (group["interval"], group["tolerance"], group["url"]) == ("300s", 50, "https://www.gstatic.com/generate_204")
    assert group["interrupt_exist_connections"] is True
    plan.selected = plan.servers[3].id
    assert next(o for o in build_singbox(plan)["outbounds"] if o["tag"] == "proxy")["default"] == tag(plan.servers[3].id)


@pytest.mark.parametrize("preset,final,dns_final", [("all", "proxy", "dns-remote"), ("except_ru", "proxy", "dns-remote"),
                                                    ("blocked", "direct", "dns-direct")])
def test_presets_and_dns(preset, final, dns_final):
    cfg = build_singbox(full_plan("tun", preset, profile_rules=[]))     # профиль заменил бы пресет
    assert validate(cfg) == []
    assert cfg["route"]["final"] == final and cfg["dns"]["final"] == dns_final
    tags = [s["tag"] for s in cfg["dns"]["servers"]]
    assert ("dns-ru" in tags) == (preset == "except_ru")
    remote = next(s for s in cfg["dns"]["servers"] if s["tag"] == "dns-remote")
    assert remote["detour"] == "proxy" and remote["type"] == "https"
    yandex = next((s for s in cfg["dns"]["servers"] if s["tag"] == "dns-ru"), None)
    if yandex:
        assert yandex["tls"] == {"server_name": "common.dot.dns.yandex.net"}
    if preset == "blocked":
        assert {"rule_set": ["refilter-domains", "russia-inside", "geoip-ru-blocked"], "action": "route",
                "outbound": "proxy"} in cfg["route"]["rules"]
        assert {"rule_set": ["refilter-domains", "russia-inside"], "action": "route",
                "server": "dns-remote"} in cfg["dns"]["rules"]
    if preset == "except_ru":
        assert {"domain_suffix": list(routing.ADDITIONS), "action": "route", "outbound": "direct"} in cfg["route"]["rules"]


def test_fakeip_only_in_tun():
    tun = build_singbox(full_plan("tun"))
    assert any(s["type"] == "fakeip" for s in tun["dns"]["servers"])
    assert tun["dns"]["rules"][-1] == {"query_type": ["A", "AAAA"], "action": "route", "server": "dns-fakeip"}
    proxy = build_singbox(full_plan("proxy"))
    assert not any(s["type"] == "fakeip" for s in proxy["dns"]["servers"])


def test_missing_rule_sets_do_not_break_preset():
    plan = full_plan("tun", "except_ru", rules_files={"geoip-ru": RULES_DIR / "geoip-ru.srs"},
                     profile_rules=[r for r in full_plan().profile_rules if "geosite-youtube" not in json.dumps(r)])
    cfg = build_singbox(plan)
    assert validate(cfg) == []
    used = {d["tag"] for d in cfg["route"]["rule_set"]}
    assert "geosite-category-ru" not in used and "geoip-ru" in used
    assert {"rule_set": ["geoip-ru"], "action": "route", "outbound": "direct"} in cfg["route"]["rules"]
    # правило профиля, у которого не осталось наборов, выброшено целиком, а не расширено до «всего»
    assert not any(r.get("action") == "reject" and "rule_set" not in r and "network" not in r
                   for r in cfg["route"]["rules"])


def test_filter_rule_sets():
    rules = [{"rule_set": ["a", "b"], "action": "route", "outbound": "direct"},
             {"rule_set": ["b"], "port": [443], "action": "reject"},
             {"rule_set": ["b"], "domain_suffix": ["x.org"], "action": "route", "outbound": "proxy"},
             {"type": "logical", "mode": "and", "rules": [{"rule_set": ["b"]}, {"port": [80]}], "action": "reject"},
             {"type": "logical", "mode": "or", "rules": [{"rule_set": ["b"]}, {"domain": ["y.org"]}],
              "action": "reject"}]
    out = config.filter_rule_sets(rules, {"a"})
    assert out == [{"rule_set": ["a"], "action": "route", "outbound": "direct"},
                   {"domain_suffix": ["x.org"], "action": "route", "outbound": "proxy"},
                   {"type": "logical", "mode": "or", "rules": [{"domain": ["y.org"]}], "action": "reject"}]


def test_user_rules_apps_and_sites():
    plan = make_plan([server("vless_reality_vision")], direct_apps=[r"D:\Games\Game.exe", "steam.exe"],
                     proxy_sites=["geosite:netflix", "full:exact.example", "203.0.113.0/24"])
    rules = build_singbox(plan)["route"]["rules"]
    apps = next(r for r in rules if r.get("outbound") == "direct" and "process_path_regex" in r
                and r.get("inbound") is None)
    assert apps["process_path_regex"] == [r"(?i)^D:\\Games\\Game\.exe$", r"(?i)(^|\\)steam\.exe$"]
    assert {"domain": ["exact.example"], "ip_cidr": ["203.0.113.0/24"], "action": "route", "outbound": "proxy"} in rules
    assert not any("geosite-netflix" in json.dumps(r) for r in rules)     # набора нет — правила нет


def test_process_patterns_case_insensitive():
    (path_re, name_re) = config.process_patterns([r"C:\Program Files\Lazeyka\Lazeyka.exe", "Discord.exe"])
    assert re.search(path_re, r"c:\program files\lazeyka\LAZEYKA.EXE")
    assert not re.search(path_re, r"C:\Program Files\Lazeyka\Lazeyka.exe.bak")
    assert re.search(name_re, r"C:\Users\u\AppData\Local\Discord\app-1.0\discord.exe")
    assert not re.search(name_re, r"C:\x\NotDiscord.exe")


def _without_fp(case: str) -> Server:
    tls = {k: v for k, v in server(case).tls.items() if k != "fingerprint"}
    return server(case, tls=tls)


def test_options_mux_fingerprint_fragment():
    reality, ws = server("vless_reality_vision"), server("vless_tls_ws")
    cfg = build_singbox(make_plan([reality, ws], mux=True, fingerprint="randomizednoalpn", tls_fragment=True))
    r_ob, ws_ob = outbound(cfg, reality.id), outbound(cfg, ws.id)
    assert "multiplex" not in r_ob and ws_ob["multiplex"]["enabled"] is True
    # Отпечаток из ссылки (fp=chrome, fp=firefox) важнее общего — так обещает «Подробнее».
    assert r_ob["tls"]["utls"]["fingerprint"] == "chrome" and ws_ob["tls"]["utls"]["fingerprint"] == "firefox"
    assert ws_ob["tls"]["fragment"] is True and "fragment" not in r_ob["tls"]   # REALITY фрагментацию не применяет
    plain_reality, plain_ws = _without_fp("vless_reality_vision"), _without_fp("vless_tls_ws")
    cfg = build_singbox(make_plan([plain_reality, plain_ws], fingerprint="randomizednoalpn"))
    assert (outbound(cfg, plain_reality.id)["tls"]["utls"]["fingerprint"] == "randomized"
            == outbound(cfg, plain_ws.id)["tls"]["utls"]["fingerprint"]), "общий — серверам без своего"
    unsafe = build_singbox(make_plan([plain_reality, plain_ws], fingerprint="unsafe"))
    assert "utls" not in outbound(unsafe, plain_ws.id)["tls"]
    assert outbound(unsafe, plain_reality.id)["tls"]["utls"]["fingerprint"] == "chrome"   # REALITY без uTLS не работает


def test_helper_fingerprint_from_link_wins():
    own, plain = server("vless_xhttp_reality"), _without_fp("vless_xhttp_reality")
    for s, expected in ((own, "chrome"), (plain, "firefox")):
        x = build_xray(make_plan([s], fingerprint="firefox"))
        ob = next(o for o in x["outbounds"] if o.get("tag") == f"out-{s.id}")
        assert ob["streamSettings"]["realitySettings"]["fingerprint"] == expected


def test_ech():
    s = server("vless_tls_ws", tls={"sni": "cdn.example.com", "ech": "AEX+/QBBAQAgACDCCCCCCCCCCCCCCC_-"})
    ech = outbound(build_singbox(make_plan([s])), s.id)["tls"]["ech"]
    assert ech["enabled"] is True and ech["config"][0] == "-----BEGIN ECH CONFIGS-----"
    s2 = server("vless_tls_ws", tls={"sni": "cdn.example.com", "ech": "cloudflare-ech.com+https://1.1.1.1/dns-query"})
    assert outbound(build_singbox(make_plan([s2])), s2.id)["tls"]["ech"] == {"enabled": True,
                                                                             "query_server_name": "cloudflare-ech.com"}


def test_doh_by_name():
    plan = make_plan([server("vless_reality_vision")], dns=DnsChoice(remote="https://dns.google/dns-query",
                                                                      direct="https://doh.example.net/q"))
    cfg = build_singbox(plan)
    assert validate(cfg) == []
    remote = next(s for s in cfg["dns"]["servers"] if s["tag"] == "dns-remote")
    assert (remote["server"], remote["tls"]) == ("8.8.8.8", {"server_name": "dns.google"})
    direct = next(s for s in cfg["dns"]["servers"] if s["tag"] == "dns-direct")
    assert (direct["server"], direct["path"], direct["domain_resolver"]) == ("doh.example.net", "/q", "dns-bootstrap")
    assert any(s["tag"] == "dns-bootstrap" and s["server"] == "1.1.1.1" for s in cfg["dns"]["servers"])
    with pytest.raises(ConfigError):
        build_singbox(make_plan([server("vless_reality_vision")], dns=DnsChoice(remote="udp://1.1.1.1")))


# ------------------------------------------------------------ ошибки плана

def test_config_errors_without_secrets():
    s = server("vless_reality_vision")
    with pytest.raises(ConfigError, match="нет ни одного"):
        build_singbox(make_plan([server("vless_quic")]))
    with pytest.raises(ConfigError, match="QUIC"):
        build_singbox(make_plan([s, server("vless_quic")], selected=server("vless_quic").id))
    with pytest.raises(ConfigError, match="TUN"):
        build_singbox(make_plan([s], tun=None))
    with pytest.raises(ConfigError, match="группа"):
        build_singbox(make_plan([s], selected="auto:nope"))
    xh = server("vless_xhttp_reality")
    plan = make_plan([xh], ports=Ports(internal=1, clash=2))
    with pytest.raises(ConfigError, match="порт помощника") as exc:
        build_singbox(plan)
    assert "11111111-2222" not in str(exc.value)
    broken = server("vless_reality_vision", tls={"sni": "x.example"})
    with pytest.raises(ConfigError, match="pbk"):
        build_singbox(make_plan([broken]))
    with pytest.raises(ConfigError, match="секрет"):
        build_singbox(make_plan([s], secrets=Secrets()))
    with pytest.raises(ConfigError, match="ML-KEM") as exc:          # строка ML-KEM без ключа
        build_xray(make_plan([server("vless_mlkem", encryption="mlkem768x25519plus.native.0rtt.AAAA")]))
    assert "mlkem768" not in str(exc.value)
    assert build_xray(make_plan([server("vless_mlkem")])) is not None  # в эталоне — настоящий ключ


# ------------------------------------------------------------ задержка

def test_delay_instance():
    plan = make_plan(supported_servers(), "tun")
    cfg = build_delay(plan)
    assert validate(cfg) == []
    assert "inbounds" not in cfg and "rules" not in cfg["route"]
    proxy = cfg["outbounds"][0]
    assert proxy["tag"] == "proxy" and len(proxy["outbounds"]) == len(plan.servers)
    assert cfg["experimental"]["clash_api"]["external_controller"] == "127.0.0.1:20901"
    assert [s["tag"] for s in cfg["dns"]["servers"]] == ["dns-direct"]


# ------------------------------------------------------------ помощник Xray

def test_xray_helper_pairs():
    servers = [server("vless_xhttp_reality"), server("vless_kcp"), server("vless_grpc_multi"),
               server("vmess_grpc_multi"), server("vless_mlkem", encryption=MLKEM), server("vless_reality_vision")]
    plan = make_plan(servers)
    x = build_xray(plan)
    assert set(x) == {"log", "inbounds", "outbounds", "routing"}         # без api, stats, policy, metrics
    assert x["log"] == {"loglevel": "warning", "access": "none"}
    assert x["outbounds"][0] == {"tag": "block", "protocol": "blackhole"}
    helper_ids = [s.id for s in servers if engine_for(s)[0] == "xray"]
    assert len(x["inbounds"]) == len(helper_ids) == 5
    for s in servers[:5]:
        inbound = next(i for i in x["inbounds"] if i["tag"] == f"in-{s.id}")
        assert inbound["listen"] == "127.0.0.1" and inbound["port"] == plan.ports.helper[s.id]
        assert inbound["settings"]["accounts"] == [{"user": "help-user", "pass": "help-pass"}]
        assert {"type": "field", "inboundTag": [f"in-{s.id}"], "outboundTag": f"out-{s.id}"} in x["routing"]["rules"]
        ob = next(o for o in x["outbounds"] if o["tag"] == f"out-{s.id}")
        assert ob["settings"]["address"] == plan.addresses[s.id]
        assert ob["streamSettings"]["sockopt"] == {"interface": "Ethernet"}
    obs = {o["tag"]: o for o in x["outbounds"]}
    kcp = obs[f"out-{servers[1].id}"]["streamSettings"]
    assert kcp["finalmask"] == {"udp": [{"type": "mkcp-aes128gcm", "settings": {"password": "s33d"}},
                                        {"type": "header-wechat"}]}
    assert "header" not in kcp["kcpSettings"] and "seed" not in kcp["kcpSettings"]
    grpc = obs[f"out-{servers[2].id}"]["streamSettings"]
    assert grpc["grpcSettings"] == {"serviceName": "my/svc", "multiMode": True, "authority": "grpc.example.com"}
    xh = obs[f"out-{servers[0].id}"]["streamSettings"]
    assert xh["xhttpSettings"]["extra"] == {"xPaddingBytes": "100-1000", "noGRPCHeader": False}
    assert xh["security"] == "reality" and xh["realitySettings"]["password"].startswith("ae4k")
    assert obs[f"out-{servers[4].id}"]["settings"]["encryption"] == MLKEM


def test_xray_as_is_outbound_and_masking():
    provider = {"tag": "proxy-1", "protocol": "vless",
                "settings": {"vnext": [{"address": "xh.example.com", "port": 443,
                                        "users": [{"id": "11111111-2222-4333-8444-555555555555", "encryption": "none"}]}]},
                "streamSettings": {"network": "xhttp", "security": "tls", "tlsSettings": {"fingerprint": "chrome"},
                                   "xhttpSettings": {"path": "/x", "mode": "auto"},
                                   "sockopt": {"dialerProxy": "frag-out", "tcpKeepAliveInterval": 15}}}
    s = Server("vless", "xh.example.com", 443, name="xh", uuid="11111111-2222-4333-8444-555555555555",
               network="xhttp", security="tls", tls={"sni": "xh.example.com"}, source="xray-json",
               xray_outbound=copy.deepcopy(provider), fragment={"packets": "tlshello", "length": "50-100",
                                                                "interval": "5"})
    s.id = s.key()
    plan = make_plan([s], noises=True)
    x = build_xray(plan)
    ob = next(o for o in x["outbounds"] if o["tag"] == f"out-{s.id}")
    assert ob["settings"]["vnext"][0]["address"] == "198.51.100.1"
    assert ob["streamSettings"]["tlsSettings"]["serverName"] == "xh.example.com"
    assert ob["streamSettings"]["sockopt"] == {"tcpKeepAliveInterval": 15, "dialerProxy": f"dial-{s.id}",
                                               "interface": "Ethernet"}
    dial = next(o for o in x["outbounds"] if o["tag"] == f"dial-{s.id}")
    assert dial["protocol"] == "freedom"
    assert dial["settings"]["fragment"] == {"packets": "tlshello", "length": "50-100", "interval": "5"}
    assert dial["settings"]["noises"] == config.XRAY_NOISES
    assert s.xray_outbound == provider                               # исходник провайдера не тронут


def test_xray_as_is_keys_in_any_case():
    provider = {"Tag": "p", "Protocol": "trojan",
                "Settings": {"Servers": [{"Address": "tr.example.com", "Port": 443, "Password": "secret"}]},
                "StreamSettings": {"Network": "ws", "Security": "none", "WSSettings": {"Path": "/w"},
                                   "Sockopt": {"DialerProxy": "chain"}}}
    s = Server("trojan", "tr.example.com", 443, name="t", password="secret", network="ws", source="xray-json",
               xray_outbound=provider)
    s.id = s.key()
    plan = make_plan([s])
    plan.engines = {s.id: "xray"}
    ob = next(o for o in build_xray(plan)["outbounds"] if o.get("Tag") == f"out-{s.id}")
    assert set(ob) == {"Tag", "Protocol", "Settings", "StreamSettings"}          # без дублей в другом регистре
    assert ob["Settings"]["Servers"][0]["Address"] == "198.51.100.1"
    assert ob["StreamSettings"]["Sockopt"] == {"interface": "Ethernet"}          # цепочка провайдера снята
    assert ob["StreamSettings"]["WSSettings"]["host"] == "tr.example.com"


def test_xray_options():
    s = server("vless_kcp")
    x = build_xray(make_plan([s], mux=True, tls_fragment=True))
    ob = next(o for o in x["outbounds"] if o["tag"] == f"out-{s.id}")
    assert ob["mux"] == config.XRAY_MUX
    assert not any(o["protocol"] == "freedom" for o in x["outbounds"])   # без TLS фрагментировать нечего
    tls = server("vless_grpc_multi")
    x = build_xray(make_plan([tls], tls_fragment=True, physical_interface=None))
    dial = next(o for o in x["outbounds"] if o["protocol"] == "freedom")
    assert dial["settings"] == {"fragment": config.XRAY_FRAGMENT}
    ob = next(o for o in x["outbounds"] if o["tag"] == f"out-{tls.id}")
    assert ob["streamSettings"]["sockopt"] == {"dialerProxy": dial["tag"]}


def test_xray_masks_and_forced_protocols():
    plain = server("vless_kcp", transport={"header_type": "none"})
    dns = server("vless_kcp", transport={"header_type": "dns", "host": "q.example.com", "kcp_mtu": 1350})
    x = build_xray(make_plan([plain, dns]))
    obs = {o["tag"]: o for o in x["outbounds"]}
    assert obs[f"out-{plain.id}"]["streamSettings"]["finalmask"] == {"udp": [{"type": "mkcp-original"}]}
    assert obs[f"out-{dns.id}"]["streamSettings"]["finalmask"]["udp"][1] == {"type": "header-dns",
                                                                         "settings": {"domain": "q.example.com"}}
    assert obs[f"out-{dns.id}"]["streamSettings"]["kcpSettings"] == {"mtu": 1350}
    hy = server("hysteria2_salamander_hop")
    plan = make_plan([hy], noises=True)
    plan.engines = {hy.id: "xray"}                                  # UDP-шумы — через помощник
    ob = next(o for o in build_xray(plan)["outbounds"] if o["tag"] == f"out-{hy.id}")
    assert ob["protocol"] == "hysteria" and ob["settings"] == {"version": 2, "address": "198.51.100.1", "port": 443}
    stream = ob["streamSettings"]
    assert stream["hysteriaSettings"] == {"version": 2, "auth": "pw"}
    assert stream["finalmask"] == {"udp": [{"type": "salamander", "settings": {"password": "obfspw"}}],
                                   "quicParams": {"udpHop": {"ports": "443,20000-30000", "interval": "30"}}}
    assert stream["tlsSettings"] == {"serverName": "hy.example.com", "alpn": ["h3"]}
    h2 = server("vless_h2")
    plan = make_plan([h2])
    plan.engines = {h2.id: "xray"}
    with pytest.raises(ConfigError, match="http"):
        build_xray(plan)                                            # HTTP/2 в Xray 26 удалён


def test_link_finalmask_goes_to_helper_as_is():
    mask = {"tcp": [{"type": "fragment", "settings": {"packets": "tlshello", "length": "100-200"}}]}
    s = server("vless_tls_ws", transport={"path": "/ws", "host": "cdn.example.com", "finalmask": mask})
    assert engine_for(s)[0] == "xray"
    ob = next(o for o in build_xray(make_plan([s]))["outbounds"] if o["tag"] == f"out-{s.id}")
    assert ob["streamSettings"]["finalmask"] == mask
    kcp = server("vless_kcp", transport={"header_type": "wechat-video", "finalmask": {"udp": [{"type": "noise"}]}})
    ob = next(o for o in build_xray(make_plan([kcp]))["outbounds"] if o["tag"] == f"out-{kcp.id}")
    assert ob["streamSettings"]["finalmask"] == {"udp": [{"type": "noise"}]}


def test_wireguard_keepalive_from_link():
    s = server("wireguard", wg={**BY_CASE["wireguard"]["server"]["wg"], "persistent_keepalive": 25})
    assert outbound(build_singbox(make_plan([s])), s.id)["peers"][0]["persistent_keepalive_interval"] == 25


def test_gecko_and_obfs_plugin():
    gecko = server("hysteria2_salamander_hop", hy2={"obfs": "gecko", "obfs_password": "g"})
    ob = outbound(build_singbox(make_plan([gecko])), gecko.id)
    assert ob["obfs"] == {"type": "gecko", "password": "g"} and ob["server_port"] == 443
    obfs = server("ss_v2ray_plugin", plugin={"name": "simple-obfs", "opts": {"obfs": "http", "obfs-host": "a.example"}})
    ob = outbound(build_singbox(make_plan([obfs])), obfs.id)
    assert (ob["plugin"], ob["plugin_opts"]) == ("obfs-local", "obfs=http;obfs-host=a.example")
    bad = server("ss_v2ray_plugin", plugin={"name": "kcptun", "opts": {}})
    with pytest.raises(ConfigError, match="kcptun"):
        build_singbox(make_plan([bad]))


def test_xray_tags_link():
    x = build_xray(full_plan(noises=True, tls_fragment=True))
    tags = [o["tag"] for o in x["outbounds"]]
    assert len(tags) == len(set(tags))
    for o in x["outbounds"]:
        proxy = (o.get("streamSettings") or {}).get("sockopt", {}).get("dialerProxy")
        assert proxy is None or proxy in tags
    for rule in x["routing"]["rules"]:
        assert rule["outboundTag"] in tags and rule["inboundTag"][0] in [i["tag"] for i in x["inbounds"]]


# ------------------------------------------------------------ validate()

def _valid() -> dict:
    return build_singbox(full_plan())


@pytest.mark.parametrize("mutate,needle", [
    (lambda c: c["outbounds"][0]["outbounds"].append("ghost"), "ghost"),
    (lambda c: c["route"].__setitem__("final", "ghost"), "route.final"),
    (lambda c: c["route"]["rules"].append({"rule_set": ["ghost-set"], "action": "route", "outbound": "direct"}),
     "ghost-set"),
    (lambda c: c["route"]["rules"].append({"domain": ["x.org"], "action": "route", "outbound": "ghost"}), "ghost"),
    (lambda c: c["dns"]["rules"].append({"domain": ["x.org"], "action": "route", "server": "dns-ghost"}), "dns-ghost"),
    (lambda c: c["route"].__setitem__("default_domain_resolver", {"server": "dns-ghost"}), "dns-ghost"),
    (lambda c: c["dns"]["servers"][0].__setitem__("detour", "ghost"), "ghost"),
    (lambda c: c["route"]["rules"].append({"inbound": ["ghost-in"], "action": "route", "outbound": "direct"}),
     "ghost-in"),
    (lambda c: c["dns"]["rules"].append({"rule_set": ["geoip-ru"], "action": "route", "server": "dns-direct"}),
     "IP-набор"),
    (lambda c: c["route"]["rules"][0]["sniffer"].append("quic2"), "quic2"),
    (lambda c: c["route"]["rules"].append({"network": ["sctp"], "action": "route", "outbound": "direct"}), "sctp"),
    (lambda c: c["inbounds"][0].__setitem__("dns_mode", "magic"), "magic"),
    (lambda c: c["outbounds"].append({"type": "direct", "tag": "direct"}), "повторяется"),
    (lambda c: c["log"].__setitem__("level", "loud"), "loud"),
    (lambda c: next(o for o in c["outbounds"] if o["type"] == "urltest").__setitem__("interval", "5"), "длительность"),
])
def test_validate_catches_broken_links_and_enums(mutate, needle):
    cfg = _valid()
    assert validate(cfg) == []
    mutate(cfg)
    errors = validate(cfg)
    assert errors and any(needle in e for e in errors), errors


def _inject(cfg: dict, scope: str, key: str) -> None:
    value: object = "x"
    if key.startswith("type="):
        key, value = "type", key[len("type="):]
    tun = next(i for i in cfg["inbounds"] if i["type"] == "tun")
    if key.startswith("!"):
        del cfg["dns"]["servers"][0][key[1:]]
        return
    if scope == "route.rule":
        cfg["route"]["rules"].append({key: value, "action": "route", "outbound": "direct"})
    elif scope == "dns.rule":
        cfg["dns"]["rules"].append({key: value, "action": "route", "server": "dns-direct"})
    elif scope in ("dns.server", "dns.server@tun"):
        cfg["dns"]["servers"].append({"type": "udp", "tag": "dns-x", "server": "1.1.1.1", key: value})
    elif scope == "dns":
        cfg["dns"][key] = True
    elif scope == "inbound":
        cfg["inbounds"][-1][key] = True
    elif scope == "inbound.tun":
        tun[key] = "system" if key == "stack" else value
    elif scope == "outbound":
        cfg["outbounds"].append({"type": "direct", "tag": "out-x", key: value})
    elif scope == "tls":
        next(o for o in cfg["outbounds"] if "tls" in o)["tls"][key] = {}
    elif scope == "tls.ech":
        next(o for o in cfg["outbounds"] if "tls" in o)["tls"]["ech"] = {"enabled": True, key: True}
    elif scope == "rule_set":
        cfg["route"]["rule_set"].append({"type": "local", "tag": "rs-x", "format": "binary", "path": "x.srs", key: value})
    elif scope == "experimental":
        cfg["experimental"][key] = {"enabled": True}
    elif scope == "clash_api":
        cfg["experimental"]["clash_api"][key] = True
    elif scope == "cache_file":
        cfg["experimental"]["cache_file"] = {"enabled": True, key: True}
    else:
        raise AssertionError(scope)


@pytest.mark.parametrize("scope,key,reason", config.FORBIDDEN, ids=[f"{s}:{k}" for s, k, _ in config.FORBIDDEN])
def test_forbidden_table_is_enforced(scope, key, reason):
    cfg = _valid()
    assert validate(cfg) == []
    _inject(cfg, scope, key)
    errors = validate(cfg)
    assert any(key in e and reason in e for e in errors), errors


def test_dns_address_field_allowed_with_match_response():
    cfg = _valid()
    cfg["dns"]["rules"].append({"ip_cidr": ["1.1.1.0/24"], "match_response": True, "action": "route",
                                "server": "dns-direct"})
    assert not any("ip_cidr" in e for e in validate(cfg))


# ------------------------------------------------------------ снимки ключевых конфигов

def _xray_plan() -> RunPlan:
    provider = {"tag": "p", "protocol": "vless",
                "settings": {"vnext": [{"address": "xh.example.com", "port": 443,
                                        "users": [{"id": "11111111-2222-4333-8444-555555555555", "encryption": "none"}]}]},
                "streamSettings": {"network": "xhttp", "security": "reality",
                                   "realitySettings": {"serverName": "www.example.org", "fingerprint": "chrome",
                                                       "password": "ae4k-ShjTC9gh3NHRS_pjKyBGyPS5qpgAK8sA4FIizQ",
                                                       "shortId": ""},
                                   "xhttpSettings": {"path": "/x", "mode": "auto"}}}
    as_is = Server("vless", "xh.example.com", 443, name="as-is", uuid="11111111-2222-4333-8444-555555555555",
                   network="xhttp", security="reality", tls={"sni": "www.example.org", "pbk": "x"},
                   source="xray-json", xray_outbound=provider, fragment={"packets": "tlshello", "length": "100-200",
                                                                         "interval": "10-20"})
    as_is.id = as_is.key()
    return make_plan([server("vless_xhttp_reality"), server("vless_kcp"), server("vmess_grpc_multi"), as_is],
                     noises=True)


SNAPSHOT_CASES = {
    # профиль маршрутизации заменил бы пресет своим выходом по умолчанию — пресеты снимаются без него
    "singbox-tun-except_ru": lambda: build_singbox(full_plan("tun", "except_ru", profile_rules=[])),
    "singbox-proxy-blocked": lambda: build_singbox(full_plan("proxy", "blocked", proxy_listen="127.0.0.1",
                                                             socks_udp=False, mux=True, profile_rules=[])),
    "singbox-tun-profile": lambda: build_singbox(full_plan("tun", "blocked")),
    "singbox-delay": lambda: build_delay(make_plan(supported_servers()[:6])),
    "xray-helper": lambda: build_xray(_xray_plan()),
}


@pytest.mark.parametrize("name", sorted(SNAPSHOT_CASES))
def test_snapshot(name):
    cfg = SNAPSHOT_CASES[name]()
    path = SNAPSHOTS / f"{name}.json"
    text = json.dumps(cfg, ensure_ascii=False, indent=1) + "\n"
    if os.environ.get("LAZEYKA_UPDATE_SNAPSHOTS") == "1":
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(text.encode("utf-8"))
    assert path.is_file(), f"нет снимка {path.name}: LAZEYKA_UPDATE_SNAPSHOTS=1 создаст его"
    assert json.loads(path.read_text(encoding="utf-8")) == cfg


# ------------------------------------------------------------ выход по умолчанию и «через VPN» без списков

def test_profile_global_proxy_replaces_preset_default():
    """GlobalProxy профиля решает, куда идёт всё остальное: «true» при пресете «Только заблокированное» —
    через VPN, а не напрямую по пресету; «false» — напрямую, и DNS остального тоже."""
    on = routeprofile.parse_happ(json.dumps({"Name": "P", "GlobalProxy": "true", "DirectSites": ["domain:ru"]}))
    plan = make_plan([server("vless_reality_vision")], preset="blocked", rules_files=all_rule_files(),
                     profile_rules=routeprofile.to_rules(on)[0])
    cfg = build_singbox(plan)
    assert validate(cfg) == []
    assert (cfg["route"]["final"], cfg["dns"]["final"]) == ("proxy", "dns-remote")
    assert {"domain_suffix": ["ru"], "action": "route", "outbound": "direct"} in cfg["route"]["rules"]
    assert not any("refilter-domains" in json.dumps(r) for r in cfg["route"]["rules"] + cfg["dns"]["rules"])
    assert not any(r.get("network") == ["tcp", "udp"] for r in cfg["route"]["rules"])     # «всё остальное» — final
    off = routeprofile.parse_happ(json.dumps({"Name": "P", "GlobalProxy": "false", "ProxySites": ["domain:x.org"]}))
    plan.preset, plan.profile_rules = "all", routeprofile.to_rules(off)[0]
    cfg = build_singbox(plan)
    assert (cfg["route"]["final"], cfg["dns"]["final"]) == ("direct", "dns-direct")


def test_vpn_list_without_its_file_does_not_allow_direct():
    """geosite:youtube «только через VPN», а файла ещё нет: правило не исполнить — пока напрямую идут только
    явные правила человека. Иначе YouTube из обхода (или по пресету) ушёл бы мимо сервера."""
    files = {k: v for k, v in all_rule_files().items() if k != "geosite-youtube"}
    plan = full_plan("tun", "blocked", proxy_sites=["geosite:youtube"], profile_rules=[], rules_files=files)
    assert config.missing_vpn_sets(plan, files) == ["geosite-youtube"]
    cfg = build_singbox(plan)
    assert validate(cfg) == []
    rules = cfg["route"]["rules"]
    assert (cfg["route"]["final"], cfg["dns"]["final"]) == ("proxy", "dns-remote")
    assert not any(r.get("outbound") == "bypass" for r in rules)
    assert not any(s["tag"] == "dns-bypass" for s in cfg["dns"]["servers"])
    assert {"domain_suffix": ["example.org"], "action": "route", "outbound": "direct"} in rules     # своё «мимо VPN»
    assert {"rule_set": [routing.GAMES_DOWNLOAD], "action": "route", "outbound": "direct"} in rules  # переключатель
    assert cfg["dns"]["rules"][-1] == {"query_type": ["A", "AAAA"], "action": "route", "server": "dns-fakeip"}
    # файл есть — правило «через VPN» стоит раньше обхода, обход на месте
    ok = build_singbox(full_plan("tun", "blocked", proxy_sites=["geosite:youtube"], profile_rules=[]))
    rules = ok["route"]["rules"]
    youtube = rule_index(rules, lambda r: r.get("rule_set") == ["geosite-youtube"] and r.get("outbound") == "proxy")
    assert youtube < rule_index(rules, lambda r: r.get("outbound") == "bypass") and ok["route"]["final"] == "direct"


def test_profile_vpn_rule_without_file_and_empty_blocked_preset_are_strict():
    """Профиль и пресет стоят после «через обход»: без их списка «через VPN» обход остаётся (он был бы важнее
    и с файлом), а прямые правила профиля, пресет и «остальное напрямую» — нет."""
    profile = routeprofile.to_rules(routeprofile.parse_happ(json.dumps({
        "Name": "P", "GlobalProxy": "false", "ProxySites": ["geosite:youtube"],
        "DirectSites": ["geosite:category-ru"]})))[0]
    files = {k: v for k, v in all_rule_files().items() if k != "geosite-youtube"}
    cfg = build_singbox(full_plan("tun", "except_ru", profile_rules=profile, rules_files=files))
    assert validate(cfg) == []
    assert (cfg["route"]["final"], cfg["dns"]["final"]) == ("proxy", "dns-remote")   # не «direct» профиля
    assert not any(r.get("outbound") == "direct" and "geosite-category-ru" in json.dumps(r)
                   for r in cfg["route"]["rules"])
    assert not any(r.get("server") in ("dns-direct", "dns-ru") and "geosite-category-ru" in json.dumps(r)
                   for r in cfg["dns"]["rules"])
    assert any(r.get("outbound") == "bypass" for r in cfg["route"]["rules"])
    # пресет «Только заблокированное» без единого своего списка — через VPN; без одного из трёх — как был
    empty = build_singbox(full_plan("tun", "blocked", profile_rules=[], rules_files={}))
    assert empty["route"]["final"] == "proxy" and any(r.get("outbound") == "bypass" for r in empty["route"]["rules"])
    one = {"russia-inside": RULES_DIR / "russia-inside.srs"}
    s = server("vless_reality_vision")
    assert build_singbox(make_plan([s], preset="blocked", rules_files=one))["route"]["final"] == "direct"


def test_negated_sets_and_not_private_in_user_lists():
    plan = make_plan([server("vless_reality_vision")], proxy_sites=["geoip:!ru", "geosite:!category-ru"],
                     direct_sites=["geoip:!private"], rules_files=all_rule_files())
    cfg = build_singbox(plan)
    assert validate(cfg) == []
    rules = cfg["route"]["rules"]
    assert {"rule_set": ["geoip-ru"], "invert": True, "action": "route", "outbound": "proxy"} in rules
    assert {"rule_set": ["geosite-category-ru"], "invert": True, "action": "route", "outbound": "proxy"} in rules
    # «не частные сети» — через invert: «ip_is_private: false» ядро считает пустым условием, то есть «всё»
    assert {"ip_is_private": True, "invert": True, "action": "route", "outbound": "direct"} in rules
    assert not any(r.get("ip_is_private") is False for r in rules)
    dns = cfg["dns"]["rules"]
    assert {"rule_set": ["geosite-category-ru"], "invert": True, "action": "route", "server": "dns-remote"} in dns
    assert not any("geoip-ru" in r.get("rule_set", []) for r in dns)       # IP-набор — только в route


def test_bypass_keeps_filter_l7_and_ipset_exclude():
    plan = make_plan([server("vless_reality_vision")], via_zapret=True, bypass=[
        BypassProfile("udp", ["443"], ips_file=RUN_DIR / "bypass-5-ip.json", l7=["quic"]),
        BypassProfile("tcp", ["80", "443"], domains_file=RUN_DIR / "bypass-4.json", reject_quic=True,
                      exclude_file=RUN_DIR / "bypass-4-exclude-ip.json"),
        BypassProfile("udp", ["443"], domains_file=RUN_DIR / "bypass-7.json", l7=["wireguard"])])
    cfg = build_singbox(plan)
    assert validate(cfg) == []
    rules = cfg["route"]["rules"]
    assert {"network": ["udp"], "port": [443], "protocol": ["quic"], "rule_set": ["bypass-5-ip"],
            "action": "route", "outbound": "bypass"} in rules               # winws трогает только QUIC
    assert not any(r.get("rule_set") == ["bypass-5-ip"] and "protocol" not in r for r in rules)
    unexcluded = {"rule_set": ["bypass-4-exclude-ip"], "invert": True}
    assert {"type": "logical", "mode": "and",
            "rules": [{"network": ["tcp"], "port": [80, 443], "rule_set": ["bypass-4"]}, unexcluded],
            "action": "route", "outbound": "bypass"} in rules
    reject = next(r for r in rules if r.get("action") == "reject" and "bypass-4" in json.dumps(r))
    assert reject["type"] == "logical" and reject["rules"][1] == unexcluded
    assert not any("bypass-7" in json.dumps(r) for r in rules)             # wireguard sniff не распознаёт
    decl = {d["tag"]: d for d in cfg["route"]["rule_set"]}
    assert decl["bypass-4-exclude-ip"] == {"type": "local", "tag": "bypass-4-exclude-ip", "format": "source",
                                           "path": str(RUN_DIR / "bypass-4-exclude-ip.json")}
    assert not any("exclude" in json.dumps(r) for r in cfg["dns"]["rules"])   # IP-набор — не в DNS


def test_dns_of_apps_follows_their_route():
    cfg = build_singbox(full_plan("tun", profile_rules=[]))
    assert validate(cfg) == []
    dns = cfg["dns"]["rules"]
    vpn_app = rule_index(dns, lambda r: r.get("process_path_regex") == config.process_patterns(["Telegram.exe"]))
    direct_app = rule_index(dns, lambda r: r.get("process_path_regex") == config.process_patterns(["steam.exe"]))
    bypass = rule_index(dns, lambda r: r.get("server") == "dns-bypass")
    assert (dns[vpn_app]["server"], dns[direct_app]["server"]) == ("dns-remote", "dns-direct")
    assert vpn_app < direct_app < bypass                     # раньше обхода: домен из hostlist — через VPN


def test_tun_exclusions_leave_fakeip_pools_in_the_tunnel():
    import ipaddress
    tun = TunOptions(address4="172.31.255.253/30", address6="fdfe:dcba:9876::1/126",
                     exclude=["10.0.0.0/8", "198.18.0.0/16", "fc00::/7", "fe80::/10"])
    s = server("vless_reality_vision")
    on = build_singbox(make_plan([s], tun=tun, dns=DnsChoice(fakeip=True, strategy="prefer_ipv4")))
    assert validate(on) == []
    excluded = on["inbounds"][0]["route_exclude_address"]
    for pool in (config.FAKEIP_V4, config.FAKEIP_V6):
        assert not any(ipaddress.ip_network(n).overlaps(ipaddress.ip_network(pool)) for n in excluded), pool
    assert {"10.0.0.0/8", "fe80::/10", "fd00::/8", "fc01::/16", "fc00:4000::/18"} <= set(excluded)
    assert "198.18.0.0/16" not in excluded                  # целиком внутри пула — не исключается вовсе
    off = build_singbox(make_plan([s], tun=tun))
    assert off["inbounds"][0]["route_exclude_address"] == tun.exclude


def test_shadowsocks_and_socks_never_lose_transport():
    ss = Server("shadowsocks", "ss.example.com", 443, name="ss-ws", method="aes-128-gcm", password="pw",
                network="ws", security="tls", transport={"path": "/ss", "host": "cdn.example.com"},
                tls={"sni": "cdn.example.com"})
    ss.id = ss.key()
    plan = make_plan([ss])
    assert plan.engines == {ss.id: "xray"}
    assert outbound(build_singbox(plan), ss.id)["server"] == "127.0.0.1"   # в sing-box — вход помощника
    stream = build_xray(plan)["outbounds"][1]["streamSettings"]
    assert (stream["network"], stream["security"], stream["wsSettings"]["path"]) == ("ws", "tls", "/ss")
    plan.engines = {ss.id: "sing-box"}                        # мимо engine_for — отказ, а не голый Shadowsocks
    with pytest.raises(ConfigError, match="помощник Xray"):
        build_singbox(plan)
    socks = Server("socks", "k.example.com", 443, name="socks-tls", security="tls")
    socks.id = socks.key()
    with pytest.raises(ConfigError):
        build_singbox(make_plan([socks], engines={socks.id: "sing-box"}))


def test_provider_fragment_reaches_singbox_when_xray_cannot_open_the_server():
    fragment = {"packets": "tlshello", "length": "10-20", "interval": "10-20"}
    s = server("trojan_ws_insecure", fragment=fragment)
    assert engine_for(s)[0] == "sing-box"                    # allowInsecure — Xray 26 не откроет
    assert outbound(build_singbox(make_plan([s])), s.id)["tls"]["fragment"] is True
    plain = server("trojan_tls", fragment=fragment)
    plan = make_plan([plain])
    assert plan.engines == {plain.id: "xray"}
    dial = next(o for o in build_xray(plan)["outbounds"] if o["tag"] == f"dial-{plain.id}")
    assert dial["settings"]["fragment"] == fragment


def test_hysteria2_hop_interval_range():
    s = server("hysteria2_salamander_hop")
    s.hy2 = dict(s.hy2, hop_interval="10-40")
    ob = outbound(build_singbox(make_plan([s])), s.id)
    assert (ob["hop_interval"], ob["hop_interval_max"]) == ("10s", "40s")
    s.hy2["hop_interval"] = "25"
    ob = outbound(build_singbox(make_plan([s])), s.id)
    assert ob["hop_interval"] == "25s" and "hop_interval_max" not in ob
    assert config.hop_interval("30-10") == (10, 30) and config.hop_interval(None) == (None, None)
    plan = make_plan([s], noises=True)
    plan.engines = {s.id: "xray"}
    s.hy2["hop_interval"] = "3-40"
    hop = build_xray(plan)["outbounds"][1]["streamSettings"]["finalmask"]["quicParams"]["udpHop"]
    assert hop["interval"] == "5-40"                         # Xray: не меньше 5 секунд
