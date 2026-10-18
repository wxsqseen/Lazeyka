"""Свой VPN: JSON-конфиги Xray от панелей (Remnawave, 3x-ui, Marzban) → серверы и группы."""
import copy
import json
from pathlib import Path

import pytest

from app.vpnclient import xrayjson
from app.vpnclient.model import PROBE_URL, engine_for

DATA = Path(__file__).resolve().parent / "data" / "vpnclient"
SECRETS = ("11111111-2222-4333-8444-555555555555", "hy-secret-auth", "obfs-secret", "trojan-secret",
           "ss-secret", "chain-secret", "c3NzZWNyZXQ=")


def _load(name: str):
    return json.loads((DATA / f"{name}.json").read_text(encoding="utf-8"))


def _by_name(result):
    return {s.name: s for s in result.servers}


def _no_secrets(result):
    blob = json.dumps(result.warnings, ensure_ascii=False) + repr(result)
    assert all(secret not in blob for secret in SECRETS)


def test_remnawave_array_with_balancer_group():
    raw = _load("xray_remnawave")
    result = xrayjson.parse(raw, sub="s-1")
    servers = _by_name(result)
    assert list(servers) == ["Амстердам", "Франкфурт", "Хельсинки", "Умная локация · 2", "Умная локация · 3"]
    ams = servers["Амстердам"]
    assert (ams.country, ams.description, ams.proto, ams.flow, ams.security) == (
        "NL", "Основной канал", "vless", "xtls-rprx-vision", "reality")
    assert ams.tls == {"pbk": "ae4k-ShjTC9gh3NHRS_pjKyBGyPS5qpgAK8sA4FIizQ", "sni": "www.example.org",
                       "fingerprint": "chrome", "sid": "6ba85179e30d4fc2", "spx": "/"}
    assert ams.xray_outbound == raw[0]["outbounds"][0]               # outbound провайдера — как есть
    fra = servers["Франкфурт"]
    assert (fra.network, engine_for(fra)[0]) == ("xhttp", "xray")
    assert fra.transport == {"path": "/xh", "host": "cdn.example.com", "xhttp_mode": "packet-up",
                             "xhttp_extra": {"xPaddingBytes": "100-1000", "noGRPCHeader": False}}
    hy = servers["Хельсинки"]
    assert (hy.proto, hy.port, hy.password, hy.security) == ("hysteria2", 443, "hy-secret-auth", "tls")
    assert hy.hy2 == {"obfs": "salamander", "obfs_password": "obfs-secret", "ports": "20000-30000"}
    assert hy.tls == {"sni": "hy.example.net", "alpn": ["h3"]}
    trojan = servers["Умная локация · 3"]
    assert (trojan.proto, trojan.network, trojan.transport) == ("trojan", "ws", {"path": "/tr", "host": "cdn.example.org"})
    for server in result.servers:
        assert server.id == server.key() and server.sub == "s-1" and server.source == "xray-json" and not server.raw
    [group] = result.groups
    assert (group.name, group.sub, group.strategy, group.probe_url, group.interval) == (
        "Умная локация", "s-1", "leastPing", "https://www.gstatic.com/generate_204", 60)
    assert group.members == [ams.id, servers["Умная локация · 2"].id, trojan.id]
    assert group.fallback == ams.id                                     # «Амстердам» — один сервер на двоих
    assert result.routing["routing"] == raw[0]["routing"] and result.warnings == []
    assert result.routing["outbounds"] == [{"tag": "proxy", "protocol": "vless"},          # без адресов и секретов
                                           {"tag": "direct", "protocol": "freedom"},
                                           {"tag": "block", "protocol": "blackhole"}]
    _no_secrets(result)


def test_3xui_single_object_flat_settings_and_burst_observatory():
    result = xrayjson.parse(_load("xray_3xui"), sub="s-2")
    vless, vmess, ss = result.servers
    assert (vless.host, vless.uuid, vless.flow, vless.tls["sid"]) == (
        "a.example.com", "44444444-5555-4666-8777-888888888888", "xtls-rprx-vision", "aa")
    assert (vmess.cipher, vmess.network, vmess.transport) == ("auto", "grpc", {"service_name": "vm-grpc",
                                                                                "grpc_mode": "multi"})
    assert engine_for(vmess)[0] == "xray"
    assert (ss.method, ss.password) == ("2022-blake3-aes-128-gcm", "c3NzZWNyZXQ=:dXNlcnNlY3JldA==")
    assert [s.name for s in result.servers] == ["Балансировщик · 1", "Балансировщик · 2", "Балансировщик · 3"]
    [group] = result.groups
    assert (group.strategy, group.probe_url, group.interval, group.fallback) == (
        "leastLoad", "https://www.google.com/generate_204", 60, vmess.id)
    _no_secrets(result)


def test_marzban_dialer_fragment_chain_and_old_hysteria():
    result = xrayjson.parse(_load("xray_marzban"))
    servers = _by_name(result)
    assert list(servers) == ["Marzban VLESS", "VMess TCP-HTTP", "Shadowsocks"]       # цепочка и Hysteria v1 — мимо
    vless = servers["Marzban VLESS"]
    assert vless.fragment == {"packets": "tlshello", "length": "10-20", "interval": "10-20"}
    assert vless.transport == {"path": "/ws?ed=2048", "host": "cdn.example.com", "headers": {"User-Agent": "Mozilla/5.0"}}
    assert vless.tls == {"sni": "cdn.example.com", "alpn": ["h2", "http/1.1"], "fingerprint": "chrome"}
    assert servers["VMess TCP-HTTP"].transport == {"header_type": "http", "host": ["a.example.net", "b.example.net"],
                                                   "path": "/x"}
    assert servers["Shadowsocks"].method == "chacha20-ietf-poly1305"
    text = "\n".join(result.warnings)
    assert "UDP-шумы" in text and "цепочки серверов пока не поддерживаются" in text and "Hysteria v1" in text
    assert not any(s.host == "entry.example.org" for s in result.servers)   # выход цепочки отдельно не берётся
    assert result.routing is None and result.groups == []
    _no_secrets(result)


def _config(*outbounds, **extra):
    return dict({"remarks": "Тест", "outbounds": list(outbounds)}, **extra)


def _vless(tag="proxy", host="t.example.com", uuid="99999999-2222-4333-8444-555555555555"):
    return {"tag": tag, "protocol": "vless",
            "settings": {"vnext": [{"address": host, "port": 443, "users": [{"id": uuid, "encryption": "none"}]}]},
            "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": {"serverName": host}}}


def test_several_proxies_without_balancer_take_the_first_with_warning():
    result = xrayjson.parse(_config(_vless(), _vless("proxy-2", "u.example.com"), {"tag": "direct", "protocol": "freedom"}))
    assert [s.host for s in result.servers] == ["t.example.com"] and result.servers[0].name == "Тест"
    assert "используются только правилами провайдера" in result.warnings[0]


def test_observatory_hints_are_clamped_and_https_only():
    routing = {"rules": [{"balancerTag": "b"}], "balancers": [{"tag": "b", "selector": ["proxy"]}]}
    fast = xrayjson.parse(_config(_vless(), _vless("proxy-2", "u.example.com"), routing=routing,
                                  observatory={"probeURL": "http://example.com/204", "probeInterval": "5s"}))
    [group] = fast.groups
    assert (group.probe_url, group.interval, group.strategy) == (PROBE_URL, xrayjson.MIN_INTERVAL, "random")
    assert any("не https" in w for w in fast.warnings)
    odd = xrayjson.parse(_config(_vless(), routing=routing, observatory={"probeInterval": "сутки"}))
    assert odd.groups[0].interval == xrayjson.DEFAULT_INTERVAL


def test_two_balancers_in_one_config_and_stable_group_ids():
    routing = {"rules": [{"balancerTag": "eu"}, {"balancerTag": "us"}],
               "balancers": [{"tag": "eu", "selector": ["eu"]}, {"tag": "us", "selector": ["us"]}]}
    config = _config(_vless("eu-1", "eu1.example.com"), _vless("eu-2", "eu2.example.com"), _vless("us", "us.example.com"),
                     routing=routing)
    first = xrayjson.parse(copy.deepcopy(config), sub="s-1")
    assert [g.name for g in first.groups] == ["Тест · eu", "Тест · us"]
    assert [len(g.members) for g in first.groups] == [2, 1]
    assert [s.name for s in first.servers] == ["Тест · 1", "Тест · 2", "us"]       # свой тег «us» — это имя
    assert [g.id for g in xrayjson.parse(copy.deepcopy(config), sub="s-1").groups] == [g.id for g in first.groups]
    assert [g.id for g in xrayjson.parse(copy.deepcopy(config), sub="s-2").groups] != [g.id for g in first.groups]


def test_keys_are_read_without_case_like_xray_does():
    outbound = {"Tag": "proxy", "Protocol": "trojan",
                "Settings": {"Servers": [{"Address": "c.example.com", "Port": 443, "Password": "pw"}]},
                "StreamSettings": {"Network": "WS", "Security": "TLS", "WsSettings": {"Path": "/c"}}}
    [server] = xrayjson.parse({"Remarks": "Регистр", "Outbounds": [outbound]}).servers
    assert (server.name, server.network, server.security, server.transport) == ("Регистр", "ws", "tls", {"path": "/c"})


def test_junk_never_raises():
    result = xrayjson.parse([42, {"remarks": "без outbounds"}, {"type": "amneziawg", "servers": []},
                             _config({"tag": "proxy", "protocol": "http", "settings": {}}),
                             _config({"tag": "proxy", "protocol": "vless", "settings": {}}),
                             _config({"tag": "proxy", "protocol": "vless", "settings": {"address": "x.example.com",
                                                                                       "port": 99999, "id": "u"}})])
    assert result.servers == [] and result.groups == []
    text = "\n".join(result.warnings)
    for fragment in ("не объект", "нет outbounds", "AmneziaWG", "outbound http", "Нет адреса сервера", "99999"):
        assert fragment in text
    assert xrayjson.parse("not a config").servers == []


@pytest.mark.parametrize("stream, field_, expected", [
    ({"network": "kcp", "kcpSettings": {"mtu": 1350, "tti": 20, "header": {"type": "srtp"}, "seed": "s"}},
     "transport", {"header_type": "srtp", "kcp_seed": "s", "kcp_mtu": 1350, "kcp_tti": 20}),
    ({"network": "httpupgrade", "httpupgradeSettings": {"path": "/u", "host": "h.example.com"}},
     "transport", {"path": "/u", "host": "h.example.com"}),
    ({"network": "tcp", "security": "tls", "tlsSettings": {"allowInsecure": True, "pinnedPeerCertSha256": "AA,BB",
                                                           "echConfigList": "ECH"}},
     "tls", {"insecure": True, "pcs": ["AA", "BB"], "ech": "ECH"}),
    ({"network": "tcp", "finalmask": {"tcp": [{"type": "fragment"}]}}, "transport", {"finalmask": {"tcp": [{"type": "fragment"}]}}),
])
def test_stream_settings(stream, field_, expected):
    outbound = _vless()
    outbound["streamSettings"] = stream
    [server] = xrayjson.parse(_config(outbound)).servers
    assert getattr(server, field_) == expected


def _hysteria(finalmask):
    return {"tag": "hy", "protocol": "hysteria",
            "settings": {"version": 2, "address": "hy.example.net", "port": 443},
            "streamSettings": {"network": "hysteria", "security": "tls",
                               "tlsSettings": {"serverName": "hy.example.net"},
                               "hysteriaSettings": {"version": 2, "auth": "hy-secret-auth"}, "finalmask": finalmask}}


def test_hysteria2_finalmask_beyond_salamander_goes_to_helper_as_is():
    """Salamander, прыжки портов с интервалом и brutal — поля hy2 (sing-box их умеет); любые другие маски
    и параметры QUIC — finalmask целиком, сервер открывает помощник Xray."""
    plain = {"udp": [{"type": "salamander", "settings": {"password": "obfs-secret"}}],
             "quicParams": {"udpHop": {"ports": "20000-30000", "interval": "10-30"}, "brutalUp": "100 mbps",
                            "brutalDown": "200mbps"}}
    [hy] = xrayjson.parse(_config(_hysteria(plain))).servers
    assert hy.hy2 == {"obfs": "salamander", "obfs_password": "obfs-secret", "ports": "20000-30000",
                      "hop_interval": "10-30", "up_mbps": 100, "down_mbps": 200}
    assert "finalmask" not in hy.transport and engine_for(hy)[0] == "sing-box"
    for extra in ({"udp": [*plain["udp"], {"type": "noise", "settings": {"noise": [{"rand": "10-20"}]}}]},
                  {"quicParams": {**plain["quicParams"], "maxIdleTimeout": 30}},
                  {"quicParams": {**plain["quicParams"], "congestion": "force-brutal"}},
                  {"quicParams": {**plain["quicParams"], "brutalUp": "1 gbps"}}):
        mask = {**plain, **extra}
        [hy] = xrayjson.parse(_config(_hysteria(mask))).servers
        assert hy.transport["finalmask"] == mask, extra
        assert engine_for(hy)[0] == "xray" and hy.xray_outbound["streamSettings"]["finalmask"] == mask
