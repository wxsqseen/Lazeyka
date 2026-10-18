"""Свой VPN: ссылки серверов, обёртки deeplink, текст подписки и файлы WireGuard."""
import base64
import json
from pathlib import Path

import pytest

from app.vpnclient import links
from app.vpnclient.links import LinkError, parse_link, parse_text, parse_wireguard_conf, to_link, unwrap
from app.vpnclient.model import Server, engine_for

DATA = Path(__file__).resolve().parent / "data" / "vpnclient"
CASES = json.loads((DATA / "servers.json").read_text(encoding="utf-8"))["cases"]
BY_CASE = {c["case"]: c for c in CASES}
U1 = "11111111-2222-4333-8444-555555555555"
VLESS = f"vless://{U1}@example.com:443?security=tls&sni=example.com#%F0%9F%87%B3%F0%9F%87%B1%20Amsterdam"
KEY_A = base64.b64encode(bytes(range(32))).decode()
KEY_B = base64.b64encode(bytes(range(32, 64))).decode()
KEY_C = base64.b64encode(bytes(range(64, 96))).decode()


def _error(text: str) -> LinkError:
    with pytest.raises(LinkError) as info:
        parse_link(text)
    return info.value


def _reference(case: str, **changes) -> dict:
    return dict(BY_CASE[case]["server"], **changes)


# ------------------------------------------------------------ эталонные серверы

@pytest.mark.parametrize("case", CASES, ids=[c["case"] for c in CASES])
def test_reference_link_gives_reference_server(case):
    server = parse_link(case["link"])
    assert server.to_dict() == Server.from_dict(case["server"]).to_dict()
    assert server.id == server.key() and server.raw == case["link"]
    assert engine_for(server)[0] == case["engine"]


@pytest.mark.parametrize("case", CASES, ids=[c["case"] for c in CASES])
def test_built_link_parses_back_to_the_same_server(case):
    server = Server.from_dict(case["server"])
    server.raw = ""                                   # как у сервера из JSON Xray: ссылки нет, собираем
    again = parse_link(to_link(server))
    assert dict(again.to_dict(), raw="") == dict(case["server"], raw="")


def test_to_link_returns_the_original_link():
    assert to_link(parse_link(CASES[0]["link"])) == CASES[0]["link"]


# ------------------------------------------------------------ векторы draft_s5

def test_scheme_host_and_keys_are_case_insensitive():                      # L07
    server = parse_link(f"VLESS://{U1}@Example.COM:443?Security=tls&SNI=Example.COM#upper")
    assert (server.proto, server.host, server.security, server.tls["sni"]) == ("vless", "example.com", "tls",
                                                                              "Example.COM")


def test_empty_flow_is_allowed():                                         # L08
    assert parse_link(f"vless://{U1}@example.com:443?security=tls&flow=#emptyflow").flow == ""


def test_legacy_xtls_is_refused_not_silently_dropped():                   # L09
    error = _error(f"vless://{U1}@example.com:443?security=xtls&flow=xtls-rprx-direct#legacy")
    assert (error.code, error.value) == ("unsupported_flow", "xtls-rprx-direct")
    assert "xtls-rprx-vision" in str(error)
    error = _error(f"vless://{U1}@example.com:443?security=xtls#legacy")
    assert (error.code, error.value) == ("unsupported_security", "xtls")


def test_plus_stays_plus_in_query_and_name():                            # L12
    server = parse_link(f"vless://{U1}@example.com:443?security=tls&type=ws&path=/a+b#Fast+1")
    assert server.transport == {"path": "/a+b"} and server.name == "Fast+1"


def test_repeated_key_takes_first_value_with_warning():                  # L16
    server = parse_link(f"vless://{U1}@example.com:443?security=tls&security=reality&sni=a.example.com#dup")
    assert server.security == "tls" and server.warnings == ["duplicate:security"]


def test_value_is_split_only_by_first_equals_sign():                     # L18
    server = parse_link(f"vless://{U1}@example.com:443?security=tls&sni=example.com&allowInsecure=1"
                        f"&ech=AAj+DQAEAAAAAA==#ech-raw")
    assert server.tls == {"sni": "example.com", "insecure": True, "ech": "AAj+DQAEAAAAAA=="}


def test_non_uuid_id_is_kept_as_is():                                    # L20
    assert parse_link("vless://my-short-id@example.com:443?security=tls#non-uuid-id").uuid == "my-short-id"


def test_vmess_base64url_without_padding():                              # M02
    link = ("vmess://eyJ2IjoiMiIsInBzIjoi8J-HqfCfh6ogREUgdm1lc3MiLCJhZGQiOiJleGFtcGxlLm5ldCIsInBvcnQiOiI0NDMiLCJpZCI6Ij"
            "IyMjIyMjIyLTMzMzMtNDQ0NC04NTU1LTY2NjY2NjY2NjY2NiIsImFpZCI6IjAiLCJzY3kiOiJhdXRvIiwibmV0Ijoid3MiLCJ0eXBlIjoibm9u"
            "ZSIsImhvc3QiOiJjZG4uZXhhbXBsZS5uZXQiLCJwYXRoIjoiL3ZtP2VkPTIwNDgiLCJ0bHMiOiJ0bHMiLCJzbmkiOiJjZG4uZXhhbXBsZS5uZX"
            "QiLCJhbHBuIjoiaDIsaHR0cC8xLjEiLCJmcCI6ImNocm9tZSJ9")
    assert parse_link(link).to_dict() == _reference("vmess_ws_tls", raw=link)


def test_vmess_with_line_breaks_inside_base64():                         # M03
    link = ("vmess://eyJ2IjoyLCJwcyI6ImdycGMiLCJhZGQiOiIxOTguNTEuMTAwLjciLCJwb3J0Ijo4NDQzLCJpZCI6\n"
            "IjMzMzMzMzMzLTQ0NDQtNDU1NS04NjY2LTc3Nzc3Nzc3Nzc3NyIsImFpZCI6MCwic2N5Ijoibm9u\n"
            "ZSIsIm5ldCI6ImdycGMiLCJ0eXBlIjoibXVsdGkiLCJob3N0IjoiIiwicGF0aCI6InZtLWdycGMi\n"
            "LCJ0bHMiOiJ0bHMiLCJzbmkiOiJncnBjLmV4YW1wbGUub3JnIiwiZnAiOiIifQ")
    server = parse_link(link)
    assert server.to_dict() == _reference("vmess_grpc_multi", raw=link.replace("\n", ""))


def test_vmess_tcp_http_and_h2():                                         # M05, M07
    tcp_http = parse_link("vmess://eyJ2IjoiMiIsInBzIjoidGNwLWh0dHAiLCJhZGQiOiJleGFtcGxlLmNvbSIsInBvcnQiOiI4MCIsImlkIjoiN"
                          "DQ0NDQ0NDQtNTU1NS00NjY2LTg3NzctODg4ODg4ODg4ODg4IiwiYWlkIjoiMCIsIm5ldCI6InRjcCIsInR5cGUiOiJodHRwI"
                          "iwiaG9zdCI6ImEuZXhhbXBsZS5jb20sYi5leGFtcGxlLmNvbSIsInBhdGgiOiIveCIsInRscyI6Im5vbmUifQ==")
    assert tcp_http.transport == {"header_type": "http", "host": ["a.example.com", "b.example.com"], "path": "/x"}
    assert tcp_http.security == "none"
    h2 = parse_link("vmess://eyJ2IjoiMiIsInBzIjoiaDIiLCJhZGQiOiJleGFtcGxlLmNvbSIsInBvcnQiOiI0NDMiLCJpZCI6IjQ0NDQ0NDQ0LTU1"
                    "NTUtNDY2Ni04Nzc3LTg4ODg4ODg4ODg4OCIsImFpZCI6IjAiLCJuZXQiOiJoMiIsInR5cGUiOiJub25lIiwiaG9zdCI6ImV4YW1wbG"
                    "UuY29tIiwicGF0aCI6Ii9oMiIsInRscyI6InRscyJ9")
    assert (h2.network, h2.transport, h2.security) == ("http", {"host": "example.com", "path": "/h2"}, "tls")


def test_shadowsocks_variants():                                          # S03, S05, S06, S08
    s03 = parse_link("ss://cmM0LW1kNTpwYXNzd2Q@192.168.100.1:8888/?plugin=obfs-local%3Bobfs%3Dhttp#Example2")
    assert (s03.method, s03.password, s03.plugin) == ("rc4-md5", "passwd", {"name": "obfs-local", "opts": {"obfs": "http"}})
    s05 = parse_link("ss://2022-blake3-aes-128-gcm:3a8c2f8NQtWVsStTEmv%2F9A%3D%3D%3ArzV6p0d4KcA3UsqnrzP%2FBw%3D%3D"
                     "@example.com:8388#multi-user")
    assert s05.password == "3a8c2f8NQtWVsStTEmv/9A==:rzV6p0d4KcA3UsqnrzP/Bw=="
    s06 = parse_link("ss://YWVzLTEyOC1nY206cGFzczEyMw==@1.2.3.4:8388/?plugin=obfs-local;obfs=http;obfs-host=example.com#ss")
    assert s06.password == "pass123" and s06.plugin["opts"] == {"obfs": "http", "obfs-host": "example.com"}
    s08 = parse_link("ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYTpzc0B3MHJk@203.0.113.10:8388#std-b64")
    assert (s08.method, s08.password) == ("chacha20-ietf-poly1305", "pa:ss@w0rd")


def test_simple_obfs_plugin_name_is_understood_as_obfs_local():
    server = parse_link("ss://YWVzLTEyOC1nY206dGVzdA@example.com:8388/?plugin=simple-obfs%3Bobfs%3Dtls#x")
    assert server.plugin == {"name": "obfs-local", "opts": {"obfs": "tls"}}


def test_hysteria2_defaults_and_options():                                # U02 и мультипорт
    server = parse_link("hy2://pw@example.com#hy2b")
    assert (server.port, server.password, server.security, server.hy2) == (443, "pw", "tls", {})
    hop = parse_link("hysteria2://pw@example.com:443?mport=5000-6000&obfs=gecko&obfs-password=o&pinSHA256=ab%3Acd"
                     "&up=100%20mbps&down=200#hop")
    assert hop.port == 443
    assert hop.hy2 == {"ports": "5000-6000", "obfs": "gecko", "obfs_password": "o", "pin_sha256": "ab:cd",
                       "up_mbps": 100, "down_mbps": 200}
    again = parse_link(to_link(Server.from_dict(dict(hop.to_dict(), raw=""))))
    assert again.hy2 == hop.hy2 and again.port == 443


@pytest.mark.parametrize("link, code, value", [
    (f"vless://{U1}@example.com?security=tls#noport", "no_port", None),                          # L13
    (f"vless://{U1}@example.com:70000#bigport", "bad_port", "70000"),                            # L14
    (f"vless://{U1}@example.com:abc#port", "bad_port", "не число"),
    (f"vless://{U1}@2001:db8::1:443#v6nobrackets", "ipv6_without_brackets", "2001:db8::1:443"),  # L15
    (f"vless://{U1}@example.com:443?security=reality&sni=www.example.org#x", "reality_without_pbk", None),  # L19
    (f"vless://{U1}@example.com:443?security=tls&type=foo#x", "unsupported_transport", "foo"),
    (f"vless://{U1}@example.com:443?security=foo#x", "unsupported_security", "foo"),
    (f"vless://{U1}@example.com:443?flow=xtls-rprx-unknown#x", "unsupported_flow", "xtls-rprx-unknown"),
    (f"vless://{U1}@example.com:443?type=xhttp&extra=%7Bnot-json#x", "bad_value", "extra"),
    ("vless://@example.com:443#x", "no_uuid", None),
    (f"vless://{U1}@:443#x", "no_host", None),
    (f"vless://{U1}@exa mple.com:443#x", "bad_host", "exa mple.com"),
    ("trojan://@example.com:443#x", "no_password", None),
    ("ss://Zm9vOmJhcg@example.com:8388#x", "unsupported_method", "foo"),
    ("ss://YWVzLTEyOC1nY206dGVzdA@example.com#x", "no_port", None),
    ("hysteria2://pw@example.com:443,abc#x", "bad_port", "не число"),
    ("hysteria2://pw@example.com:443,20-10#x", "bad_port", "443,20-10"),
    ("hysteria2://pw@example.com:443?obfs=foo#x", "unsupported_obfs", "foo"),
    (f"tuic://{U1}@example.com:443#x", "no_password", None),
    (f"wireguard://{KEY_A}@203.0.113.40:51820?address=10.0.0.2#x", "no_key", "PublicKey"),
    (f"wireguard://{KEY_A}@203.0.113.40:51820?publickey={KEY_B}&reserved=1,2#x", "bad_value", "reserved"),
    (f"wireguard://short@203.0.113.40:51820?publickey={KEY_B}#x", "bad_value", "PrivateKey"),
    (f"wireguard://{KEY_A}@203.0.113.40:51820?publickey={KEY_B}&jc=4&jmin=40#x", "amneziawg", "jc, jmin"),
    ("vmess://bm90IGpzb24", "bad_json", "vmess"),
    ("vmess://!!!", "bad_base64", "vmess"),
    ("vmess://YXV0bzo1ZGM5NGYzYS1lY2YwLTQyZDgtYWUyNy03MjJhNjhhNjQ1NmNAZXhhbXBsZS5jb206NDQz", "unsupported_format",
     "VMess Shadowrocket"),
    ("vmess://YXV0bzo1ZGM5NGYzYUBleGFtcGxlLmNvbTo0NDM?remarks=x&obfs=websocket", "unsupported_format",
     "VMess Shadowrocket"),
    ("vmess://ws+tls:5dc94f3a-0@example.com:443/?path=%2Fx#v2fly", "unsupported_format", "VMess v2fly"),
    ("trojan-go://password1234@example.com/?sni=example.net&type=ws&host=example.org&path=%2Fgo#tgo",   # T04
     "unsupported_scheme", "Trojan-Go"),
    ("ssr://ZXhhbXBsZS5jb206NDQzOm9yaWdpbjphZXMtMjU2LWNmYjpwbGFpbjpjR0Z6Y3cv", "unsupported_scheme", "ShadowsocksR"),
    ("anytls://pw@example.com:443?sni=example.com&insecure=1#anytls", "unsupported_scheme", "AnyTLS"),     # U09
    ("naive+https://user:pw@example.com:443#n", "unsupported_scheme", "NaiveProxy"),
    ("socks4://203.0.113.9:1080#s4", "unsupported_scheme", "SOCKS4"),
    ("hysteria://example.com:443?auth=x#h1", "unsupported_scheme", "Hysteria v1"),
    ("http://user:pass@203.0.113.9:8080#p", "unsupported_scheme", "HTTP-прокси"),
    ("v2rayn://vless/eyJ4IjoxfQ", "unsupported_scheme", "внутренний формат v2rayN"),
    ("https://sub.example.com/api/v1/client/subscribe?token=abc", "subscription_url", None),            # U06
    ("http://sub.example.com/sub/abc", "subscription_url", None),
    ("happ://crypt4/AAAABBBB", "encrypted_link", None),                                                  # U08
    ("incy://add/happ://add/https://sub.example.com/x", "nested_wrapper", None),
    ("foo bar", "not_a_link", None),
    ("mystery://x", "unknown_scheme", "mystery"),
    ("   ", "empty", None),
])
def test_refusal_has_code_and_actual_value(link, code, value):
    error = _error(link)
    assert error.code == code
    if value is not None:
        assert error.value == value
    assert str(error) and not str(error).startswith(code)     # человеческий текст, а не код


def test_amneziawg_scheme_says_which_client_is_needed():
    error = _error("amneziawg://W0ludGVyZmFjZV0#Germany")
    assert (error.code, error.value, str(error)) == ("unsupported_scheme", "AmneziaWG", links.AMNEZIA_TEXT)


def test_too_long_line_is_refused():
    assert _error("vless://" + "a" * links.MAX_LINK).code == "too_long"


def test_errors_and_warnings_carry_no_secrets():
    for link in (f"vless://{U1}@example.com:70000", "trojan://super-secret@exa mple.com:443",
                 f"vless://{U1}@example.com:443?security=reality", "ss://bWV0aG9kOnN1cGVyLXNlY3JldA@x.example.com:1",
                 "socks://user:super-secret", "socks://user:super-secret:x", "hy2://host.example.com:super-secret"):
        error = _error(link)
        for secret in (U1, "super-secret", link):
            assert secret not in str(error) and secret not in repr(error)


# ------------------------------------------------------------ прочее разбора

def test_idn_host_becomes_punycode_and_ipv6_loses_brackets():
    assert parse_link(f"vless://{U1}@пример.рф:443?security=tls#idn").host == "xn--e1afmkfd.xn--p1ai"
    assert parse_link("trojan://pw@[2001:DB8::2]:443#v6").host == "2001:db8::2"


def test_flag_becomes_country_and_incy_description_is_read():
    description = base64.b64encode("Быстрый канал".encode()).decode()
    server = parse_link(f"vless://{U1}@example.com:443?security=tls#%F0%9F%87%A9%F0%9F%87%AA%20Berlin"
                        f"?serverDescription={description}")
    assert (server.country, server.name, server.description) == ("DE", "Berlin", "Быстрый канал")


def test_socks_forms():
    plain = parse_link("socks5://user:p%40ss@203.0.113.30#s")
    assert (plain.username, plain.password, plain.port) == ("user", "p@ss", 1080)
    anonymous = parse_link("socks://203.0.113.30:1081#anon")
    assert (anonymous.username, anonymous.password, anonymous.port) == (None, None, 1081)


def test_wireguard_link_normalizes_address_and_hex_key():
    hex_key = bytes(range(32)).hex()
    server = parse_link(f"wg://{hex_key}@203.0.113.40:51820?publickey={KEY_B}&address=10.0.0.2,fd00::2"
                        f"&reserved=AQID&dns=1.1.1.1#wg")
    assert server.wg == {"private_key": KEY_A, "peer_public_key": KEY_B, "local_address": ["10.0.0.2/32", "fd00::2/128"],
                         "reserved": [1, 2, 3], "dns": ["1.1.1.1"]}


def test_tls_options_and_reality_key_normalization():
    server = parse_link(f"vless://{U1}@example.com:443?security=reality&sni=a.example.org&pbk=ab%2Bcd%2Fef%3D"
                        f"&sid=01&pqv=PQ&type=grpc&serviceName=s&authority=auth.example.org#r")
    assert server.tls == {"sni": "a.example.org", "pbk": "ab-cd_ef", "sid": "01", "pqv": "PQ"}
    assert server.transport == {"service_name": "s", "grpc_mode": "gun", "authority": "auth.example.org"}
    tls = parse_link(f"trojan://pw@example.com:443?pcs=AA%3ABB,CC&vcn=a.example.com&peer=p.example.com&fp=Chrome#t").tls
    assert tls == {"sni": "p.example.com", "fingerprint": "chrome", "pcs": ["AA:BB", "CC"], "vcn": ["a.example.com"]}


# ------------------------------------------------------------ обёртки deeplink

@pytest.mark.parametrize("wrapped, expected", [
    ("sing-box://import-remote-profile?url=https%3A%2F%2Fsub.example.com%2Fs%2Fabc%2B1#My%20VPN",
     "https://sub.example.com/s/abc+1"),
    ("sing-box://import-remote-profile?url=https%253A%252F%252Fsub.example.com%252Fx",       # декодируется ровно раз
     "https%3A%2F%2Fsub.example.com%2Fx"),
    ("hiddify://install-config?url=https%3A%2F%2Fsub.example.com%2Fh", "https://sub.example.com/h"),
    ("hiddify://import/https://sub.example.com/h2#Name", "https://sub.example.com/h2"),
    ("v2rayng://install-config?name=user&url=https://sub.example.com/api?token=abc&flag=1",
     "https://sub.example.com/api?token=abc&flag=1"),
    ("v2rayng://install-sub?url=https%3A%2F%2Fsub.example.com%2Fv&name=x", "https://sub.example.com/v"),
    ("clash://install-config?url=https%3A%2F%2Fsub.example.com%2Fc", "https://sub.example.com/c"),
    ("flclashx://install-config?url=https://sub.example.com/f", "https://sub.example.com/f"),
    ("sn://subscription?url=https%3A%2F%2Fsub.example.com%2Fn&name=n", "https://sub.example.com/n"),
    ("happ://add/https://sub.example.com/a+b", "https://sub.example.com/a+b"),
    ("incy://add/https://sub.example.com/i", "https://sub.example.com/i"),
    ("incy://import/https://sub.example.com/imp", "https://sub.example.com/imp"),
    ("streisand://import/https://sub.example.com/st", "https://sub.example.com/st"),
    ("shadowrocket://add/https://sub.example.com/sr#user", "https://sub.example.com/sr"),
    ("lazeyka://import/https%3A%2F%2Fsub.example.com%2Fl", "https://sub.example.com/l"),
    ("incy://add/" + VLESS, VLESS),
])
def test_unwrap_takes_off_one_level(wrapped, expected):
    assert unwrap(wrapped) == expected


def test_unwrap_import_with_base64_inside():
    body = f"{VLESS}\ntrojan://pw@example.org:443#B"
    blob = base64.urlsafe_b64encode(body.encode()).decode().rstrip("=")
    assert unwrap(f"incy://import/{blob}") == body
    conf = f"[Interface]\nPrivateKey = {KEY_A}\n[Peer]\nPublicKey = {KEY_B}\nEndpoint = wg.example.com:51820"
    assert unwrap("lazeyka://import/" + base64.b64encode(conf.encode()).decode()) == conf


@pytest.mark.parametrize("text", ["https://sub.example.com/x", VLESS, f"{VLESS}\n{VLESS}", "просто текст"])
def test_unwrap_leaves_other_text_alone(text):
    assert unwrap(text) == text


@pytest.mark.parametrize("text, code", [
    ("happ://crypt/xxx", "encrypted_link"), ("happ://crypt4/AAAA", "encrypted_link"),
    ("happ://crypt5/BBBB", "encrypted_link"), ("happ://crypto0abc", "encrypted_link"),
    ("incy://crypt1/FZEVXuV39UEX1yHB3nkrgdPdrJ3syVxc", "encrypted_link"),
    ("incy://connect", "app_command"), ("incy://toggle", "app_command"), ("happ://disconnect", "app_command"),
    ("happ://routing/add/eyJOYW1lIjoidCJ9", "route_profile"), ("happ://routing/off", "route_profile"),
    ("incy://autorouting/onadd/https://example.com/r.json", "route_profile"),
    ("incy://onadd/https://example.com/r.json", "route_profile"), ("://routing/onadd/eyJOYW1lIjoidCJ9", "route_profile"),
    ("happ://add/", "bad_wrapper"), ("sing-box://import-remote-profile", "bad_wrapper"),
])
def test_unwrap_refuses_closed_and_command_links(text, code):
    with pytest.raises(LinkError) as info:
        unwrap(text)
    assert info.value.code == code
    if code == "encrypted_link":
        assert str(info.value) == links.ENCRYPTED_TEXT


def test_parse_link_unwraps_server_and_reports_subscription_inside():
    server = parse_link("incy://add/" + VLESS)
    assert (server.raw, server.name, server.country) == (VLESS, "Amsterdam", "NL")
    assert _error("happ://add/https://sub.example.com/x").code == "subscription_url"
    assert _error("incy://crypt1/AAAA").code == "encrypted_link"


# ------------------------------------------------------------ текст

def test_parse_text_skips_comments_and_reports_junk_by_line():            # B03
    text = ("\ufeff# комментарий\r\n\r\n  vless://11111111-2222-4333-8444-555555555555@example.com:443?security=tls#A  "
            "\r\ntrojan://secret@example.org:443#B\r\nfoo bar\r\n")
    result = parse_text(text)
    assert [s.name for s in result.servers] == ["A", "B"]
    assert [(line, error.code) for line, error in result.errors] == [(5, "not_a_link")]


def test_parse_text_meta_route_lines_and_duplicates():
    text = "\n".join([
        "#profile-title: Мой VPN", "#Announce: base64:0J/RgNC+0LTQu9C40YLQtSDQtNC+IDAxLjEx",
        "#profile-title: второе значение не перетирает первое",
        VLESS, VLESS,                                                 # точный дубль — молча
        VLESS.replace("Amsterdam", "Copy"),                           # тот же сервер под другим именем
        "://routing/onadd/eyJOYW1lIjoiUlUifQ==", "happ://routing/add/eyJOYW1lIjoiUlUifQ==",
        "incy://autorouting/onadd/https://example.com/profile.json",
        "https://sub.example.com/other",
    ])
    result = parse_text(text)
    assert result.meta == {"profile-title": "Мой VPN", "announce": "base64:0J/RgNC+0LTQu9C40YLQtSDQtNC+IDAxLjEx"}
    assert [s.name for s in result.servers] == ["Amsterdam"]
    assert result.route_lines == ["://routing/onadd/eyJOYW1lIjoiUlUifQ==", "happ://routing/add/eyJOYW1lIjoiUlUifQ==",
                                  "incy://autorouting/onadd/https://example.com/profile.json"]
    assert [(line, error.code) for line, error in result.errors] == [(6, "duplicate"), (10, "subscription_url")]


def test_parse_text_understands_base64_and_conf_from_import_field():
    lines = f"{VLESS}\r\ntrojan://pw@example.org:443#B"
    assert [s.name for s in parse_text(base64.b64encode(lines.encode()).decode()).servers] == ["Amsterdam", "B"]
    assert parse_text(base64.b64encode(lines.encode()).decode(), decode_base64=False).errors[0][1].code == "not_a_link"
    conf = f"[Interface]\nPrivateKey = {KEY_A}\n[Peer]\nPublicKey = {KEY_B}\nEndpoint = wg.example.com:51820"
    via_link = parse_text(unwrap("incy://import/" + base64.b64encode(conf.encode()).decode()))
    assert [s.proto for s in via_link.servers] == ["wireguard"] and via_link.servers[0].host == "wg.example.com"
    broken = parse_text(conf.replace("Endpoint = wg.example.com:51820", ""))
    assert broken.servers == [] and broken.errors[0][1].code == "bad_conf"


# ------------------------------------------------------------ WireGuard .conf

CONF = f"""# Name = 🇩🇪 Германия
[Interface]
PrivateKey = {KEY_A}
Address = 10.8.0.2/32
Address = fd00::2/128
DNS = 1.1.1.1, 1.0.0.1
MTU = 1380

[Peer]
PublicKey = {KEY_B}
PresharedKey = {KEY_C}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = [2001:db8::40]:51820   # сервер
PersistentKeepalive = 25
"""


def test_wireguard_conf():
    [server] = parse_wireguard_conf(CONF)
    assert (server.proto, server.host, server.port, server.name, server.country) == (
        "wireguard", "2001:db8::40", 51820, "Германия", "DE")
    assert server.wg == {"private_key": KEY_A, "peer_public_key": KEY_B, "preshared_key": KEY_C,
                         "local_address": ["10.8.0.2/32", "fd00::2/128"], "mtu": 1380, "persistent_keepalive": 25,
                         "dns": ["1.1.1.1", "1.0.0.1"]}
    assert server.source == "wireguard-conf" and server.id == server.key() and engine_for(server)[0] == "sing-box"


def test_wireguard_conf_name_and_several_peers():
    conf = CONF + f"\n[Peer]\nPublicKey = {KEY_C}\nEndpoint = wg2.example.com:51821\n"
    first, second = parse_wireguard_conf(conf, "Мой WG")
    assert (first.name, second.name, second.host, second.port) == ("Мой WG · 1", "Мой WG · 2", "wg2.example.com", 51821)


def test_amneziawg_conf_is_refused_with_explanation():
    conf = CONF.replace("MTU = 1380", "MTU = 1380\nJc = 4\nJmin = 40\nJmax = 70\nS1 = 86\nH1 = 1234567890")
    with pytest.raises(LinkError) as info:
        parse_wireguard_conf(conf)
    assert info.value.code == "amneziawg" and str(info.value) == links.AMNEZIA_TEXT
    with pytest.raises(LinkError):
        parse_wireguard_conf("[Device]\nJc = 4\n" + CONF.split("\n", 1)[1])


def test_amneziawg_with_neutral_values_is_plain_wireguard():
    conf = CONF.replace("MTU = 1380", "MTU = 1380\nJc = 0\nJmin = 0\nJmax = 0\nS1 = 0\nS2 = 0\nH1 = 1\nH2 = 2\nH3 = 3\nH4 = 4")
    assert parse_wireguard_conf(conf)[0].proto == "wireguard"


@pytest.mark.parametrize("conf, code", [
    (f"[Peer]\nPublicKey = {KEY_B}\nEndpoint = a.example.com:1", "bad_conf"),
    (f"[Interface]\nPrivateKey = {KEY_A}\n", "bad_conf"),
    (f"[Interface]\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = {KEY_B}\nEndpoint = a.example.com:1", "no_key"),
    (f"[Interface]\nPrivateKey = {KEY_A}\n[Peer]\nPublicKey = {KEY_B}\n", "bad_conf"),
    ("PrivateKey = x\n", "bad_conf"),
])
def test_broken_wireguard_conf(conf, code):
    with pytest.raises(LinkError) as info:
        parse_wireguard_conf(conf)
    assert info.value.code == code
