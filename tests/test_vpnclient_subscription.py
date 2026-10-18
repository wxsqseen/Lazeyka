"""Свой VPN: загрузка подписки (локальный HTTP-сервер теста), тело, заголовки, User-Agent и подсказки."""
import base64
import gzip
import http.server
import json
import socket
import sys
import threading
import urllib.request
import zlib
from pathlib import Path

import pytest

from app.vpnclient import subscription as sb
from app.vpnclient.links import AMNEZIA_TEXT
from app.vpnclient.model import UA_PRESETS, Subscription
from app.vpnclient.subscription import Decoded, Fetched, SubscriptionError, check_url, decode, fetch, offer, sub_meta

DATA = Path(__file__).resolve().parent / "data" / "vpnclient"
UA = "Lazeyka/1.2.0 (Windows)"
U1 = "11111111-2222-4333-8444-555555555555"
VLESS = f"vless://{U1}@example.com:443?security=tls#A"
TROJAN = "trojan://secret@example.org:443#B"
B01 = ("dmxlc3M6Ly8xMTExMTExMS0yMjIyLTQzMzMtODQ0NC01NTU1NTU1NTU1NTVAZXhhbXBsZS5jb206NDQzP3NlY3VyaXR5PXRscyZ0eXBlPXdzJnBh"
       "dGg9JTJGd3Mj8J+HqfCfh6og0JPQtdGA0LzQsNC90LjRjw0KdHJvamFuOi8vc2VjcmV0QGV4YW1wbGUub3JnOjQ0MyPwn4ez8J+HsSBOTA0Kc3M6Ly"
       "9ZV1Z6TFRFeU9DMW5ZMjA2ZEdWemRBQDE5Mi4xNjguMTAwLjE6ODg4OCNFeGFtcGxlMQ0K")
B02 = ("dmxlc3M6Ly8xMTExMTExMS0yMjIyLTQzMzMtODQ0NC01NTU1NTU1NTU1NTVAZXhhbXBsZS5jb206\n"
       "NDQzP3NlY3VyaXR5PXRscyZ0eXBlPXdzJnBhdGg9JTJGd3Mj8J-HqfCfh6og0JPQtdGA0LzQsNC9\n"
       "0LjRjw0KdHJvamFuOi8vc2VjcmV0QGV4YW1wbGUub3JnOjQ0MyPwn4ez8J-HsSBOTA0Kc3M6Ly9Z\n"
       "V1Z6TFRFeU9DMW5ZMjA2ZEdWemRBQDE5Mi4xNjguMTAwLjE6ODg4OCNFeGFtcGxlMQ0K")
KEY_A = base64.b64encode(bytes(range(32))).decode()
KEY_B = base64.b64encode(bytes(range(32, 64))).decode()
CONF = f"[Interface]\nPrivateKey = {KEY_A}\nAddress = 10.8.0.2/32\n[Peer]\nPublicKey = {KEY_B}\nEndpoint = wg.example.com:51820\n"


def _b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode()


def _error(call, *args, **kwargs) -> SubscriptionError:
    with pytest.raises(SubscriptionError) as info:
        call(*args, **kwargs)
    return info.value


# ------------------------------------------------------------ тело

@pytest.mark.parametrize("body", [B01, B02])
def test_base64_bodies(body):                                              # B01, B02
    decoded = decode(body.encode(), {})
    assert decoded.format == "links" and decoded.base64
    assert [(s.name, s.country) for s in decoded.servers] == [("Германия", "DE"), ("NL", "NL"), ("Example1", None)]


def test_plain_body_with_bom_comments_and_junk():                         # B03
    body = f"\ufeff# комментарий\r\n\r\n  {VLESS}  \r\n{TROJAN}\r\nfoo bar\r\n".encode("utf-8")
    decoded = decode(body, {}, sub_id="s-1")
    assert [s.name for s in decoded.servers] == ["A", "B"] and not decoded.base64
    assert [(line, error.code) for line, error in decoded.errors] == [(5, "not_a_link")]
    assert all(s.sub == "s-1" for s in decoded.servers)


@pytest.mark.parametrize("body, kind, reason", [
    (b"<!DOCTYPE html><html><head><title>Sub</title></head><body></body></html>", "html", None),          # B04
    (b"mixed-port: 7890\nproxies:\n  - name: a\n    type: vless\n", "format", "clash"),                     # B07
    (json.dumps({"outbounds": [{"type": "vless", "tag": "a", "server": "x.example.com"}]}).encode(), "format", "sing-box"),
    (b"{oops", "format", "json"),
    (b'{"some": "json"}', "format", "json"),
    (json.dumps({"type": "amneziawg", "version": 1, "servers": []}).encode(), "format", "amneziawg"),
    (CONF.replace("Address", "Jc = 4\nAddress").encode(), "format", "amneziawg"),
    (b"\xff\xfe\x00broken", "format", "encoding"),
    (b"", "empty", None),
    (b"  \r\n ", "empty", None),
    ("\ufeff".encode("utf-8"), "empty", None),
])
def test_whole_body_refusals(body, kind, reason):
    error = _error(decode, body, {})
    assert (error.kind, error.reason) == (kind, reason)
    if reason == "amneziawg":
        assert str(error) == AMNEZIA_TEXT


def test_too_big_body_is_refused(monkeypatch):
    monkeypatch.setattr(sb, "MAX_BODY", 10)
    assert _error(decode, b"x" * 11, {}).kind == "too_big"


def test_sip008():                                                         # B05
    body = json.dumps({"version": 1, "servers": [
        {"id": "27b8a625-4f4b-4428-9f0f-8a2317db7c79", "remarks": "SIP008-1", "server": "example.com",
         "server_port": 8388, "password": "example", "method": "chacha20-ietf-poly1305"},
        {"remarks": "obfs", "server": "198.51.100.1", "server_port": 8389, "password": "p", "method": "aes-128-gcm",
         "plugin": "obfs-local", "plugin_opts": "obfs=http;obfs-host=cdn.example.com"},
        {"remarks": "битый", "server": "example.com", "server_port": 0, "password": "p", "method": "aes-128-gcm"},
    ]}).encode()
    decoded = decode(body, {})
    assert decoded.format == "sip008"
    assert [(s.name, s.source, s.method) for s in decoded.servers] == [
        ("SIP008-1", "sip008", "chacha20-ietf-poly1305"), ("obfs", "sip008", "aes-128-gcm")]
    assert decoded.servers[1].plugin == {"name": "obfs-local", "opts": {"obfs": "http", "obfs-host": "cdn.example.com"}}
    assert [(n, e.code) for n, e in decoded.errors] == [(3, "bad_port")]


def test_xray_json_bodies():                                               # B06 и панели
    b06 = decode(b'[{"remarks":"JSON-1","outbounds":[{"protocol":"vless","tag":"proxy"},'
                 b'{"protocol":"freedom","tag":"direct"}]}]', {})
    assert b06.format == "xray-json" and b06.servers == [] and b06.warnings
    decoded = decode((DATA / "xray_remnawave.json").read_bytes(), {}, sub_id="s-9")
    assert decoded.format == "xray-json" and len(decoded.servers) == 5 and len(decoded.groups) == 1
    assert all(s.sub == "s-9" for s in decoded.servers) and decoded.groups[0].sub == "s-9"
    assert decoded.routing["routing"]["rules"][0]["outboundTag"] == "direct"
    assert {"tag": "direct", "protocol": "freedom"} in decoded.routing["outbounds"]


def test_wireguard_conf_body_plain_and_base64():
    plain = decode(CONF.encode(), {})
    wrapped = decode(_b64(CONF).encode(), {})
    assert [s.proto for s in plain.servers] == ["wireguard"] and plain.servers[0].host == "wg.example.com"
    assert wrapped.base64 and wrapped.servers[0].id == plain.servers[0].id


def test_base64_body_carries_meta_and_route_lines():
    body = _b64(f"#profile-title: Внутри\n#support-url: https://t.me/support\n{VLESS}\n"
                "://routing/onadd/eyJOYW1lIjoiUlUifQ==\n")
    decoded = decode(body.encode(), {"Profile-Title": "Из заголовка", "routing": "happ://routing/onadd/eyJ9"})
    assert decoded.base64 and [s.name for s in decoded.servers] == ["A"]
    assert decoded.meta.title == "Из заголовка"                       # заголовок важнее строки тела
    assert decoded.meta.support_url == "https://t.me/support"          # а это — только из тела
    assert decoded.route_lines == ["://routing/onadd/eyJOYW1lIjoiUlUifQ=="]
    assert decoded.meta.routing == "happ://routing/onadd/eyJ9"


def test_stub_servers_become_provider_notices():
    stubs = "\n".join([f"vless://{U1}@0.0.0.0:1?security=none#⛔ Подписка истекла",
                       f"vless://{U1}@127.0.0.1:443?security=none#Продлите в боте"])
    only = decode(stubs.encode(), {})
    assert only.servers == [] and only.notices == ["⛔ Подписка истекла", "Продлите в боте"]
    assert offer(None, only) == {"kind": "stub", "text": "⛔ Подписка истекла; Продлите в боте", "options": []}
    mixed = decode(f"{stubs}\n{VLESS}".encode(), {})
    assert [s.name for s in mixed.servers] == ["A"] and len(mixed.notices) == 2
    xray_stub = decode(json.dumps({"remarks": "Срок истёк", "outbounds": [
        {"tag": "proxy", "protocol": "socks", "settings": {"servers": [{"address": "127.0.0.1", "port": 1080}]}}]}).encode(),
        {})
    assert xray_stub.servers == [] and xray_stub.notices == ["Срок истёк"]


# ------------------------------------------------------------ заголовки

def test_headers_h01_to_h04():
    meta = sub_meta({
        "subscription-userinfo": "upload=455727941; download=6174315083; total=1073741824000; expire=1671815872",   # H01
        "profile-title": "base64:8J+agCDQnNC+0Y8g0L/QvtC00L/QuNGB0LrQsA==",                                         # H02
        "profile-update-interval": "12",                                                                            # H03
        "announce": "base64:0J/RgNC+0LTQu9C40YLQtSDQtNC+IDAxLjEx",                                                  # H04
    })
    assert meta.userinfo == {"upload": 455727941, "download": 6174315083, "total": 1073741824000, "expire": 1671815872}
    assert (meta.title, meta.update_hours, meta.announce) == ("🚀 Моя подписка", 12, "Продлите до 01.11")


def test_userinfo_expire_in_milliseconds_and_hidden_block():
    assert sub_meta({"subscription-userinfo": "upload=0;download=1;total=2;expire=1762992000000"}).userinfo == {
        "upload": 0, "download": 1, "total": 2, "expire": 1762992000}
    assert sub_meta({"subscription-userinfo": "upload=0; download=5; total=0; expire=0"}).userinfo["expire"] == 0
    assert sub_meta({"subscription-userinfo": "0"}).userinfo == {}


@pytest.mark.parametrize("value, hours", [("1", 1), ("72", 72), ("0", None), ("73", None), ("168", None),
                                          ("abc", None), ("", None)])
def test_update_interval_range(value, hours):
    assert sub_meta({"profile-update-interval": value}).update_hours == hours


def test_title_description_and_disposition():
    meta = sub_meta({"profile-title": "base64:" + _b64("Мой VPN\nБыстрые серверы в Европе")})
    assert (meta.title, meta.description) == ("Мой VPN", "Быстрые серверы в Европе")
    assert sub_meta({"profile-title": "X", "profile-description": "base64:" + _b64("Описание")}).description == "Описание"
    assert sub_meta({"content-disposition": "attachment; filename*=UTF-8''%D0%9C%D0%BE%D0%B9.txt"}).title == "Мой"
    assert sub_meta({"content-disposition": "attachment; filename=user123"}).title == "user123"
    assert sub_meta({"content-disposition": 'attachment; filename="sub.yaml"'}).title == "sub"
    assert sub_meta({"profile-title": "base64:!!!"}).title is None


def test_announce_is_cut_to_200_characters():
    meta = sub_meta({"announce": "а" * 300})
    assert len(meta.announce) == 200 and meta.announce.endswith("…")


def test_links_from_provider_are_https_only():
    meta = sub_meta({"support-url": "http://t.me/x", "homepage": "https://example.com/home",
                     "announce-url": "javascript:alert(1)", "new-url": "http://new.example.com/s",
                     "fallback-url": "https://mirror.example.com/s/token", "new-domain": "New.Example.com"})
    assert (meta.support_url, meta.web_page_url, meta.announce_url, meta.new_url) == (
        None, "https://example.com/home", None, None)
    assert meta.fallback_urls == ["https://mirror.example.com/s/token"] and meta.new_domain == "new.example.com"
    assert "mirror.example.com" not in repr(meta)                      # адреса подписки — секрет
    assert sub_meta({"new-url": "https://new.example.com/s", "new-domain": "bad domain"}).new_domain is None


def test_hwid_headers_are_explained():
    meta = sub_meta({"X-Hwid-Not-Supported": "true", "x-hwid-limit": "true"})
    assert meta.hwid == {"not_supported": True, "limit": True} and "HWID" in meta.hwid_text
    assert sub_meta({"x-hwid-max-devices-reached": "true"}).hwid_text == sb.HWID_LIMIT_TEXT
    assert sub_meta({"x-hwid-not-supported": "true"}, {"x-hwid-active": "true"}).hwid == {"not_supported": True}


# ------------------------------------------------------------ User-Agent

def test_user_agent_presets():
    sub = Subscription(id="s-1", name="x")
    assert sb.user_agent(sub, "1.2.0") == UA
    for preset in ("v2rayn", "happ", "incy"):
        sub.ua_preset = preset
        assert sb.user_agent(sub, "1.2.0") == UA_PRESETS[preset]
    sub.ua_preset, sub.user_agent = "custom", "MyClient/1.0"
    assert sb.user_agent(sub, "1.2.0") == "MyClient/1.0"
    sub.ua_preset = "неизвестный"
    assert sb.user_agent(sub, "1.2.0") == UA


@pytest.mark.parametrize("value", ["", "a\r\nX-Evil: 1", "Клиент/1.0", "a" * 257, "tab\there"])
def test_custom_user_agent_is_validated(value):
    sub = Subscription(id="s-1", name="x", ua_preset="custom", user_agent=value)
    assert _error(sb.user_agent, sub, "1.2.0").kind == "ua"


def test_hwid_is_random_and_fits_panels():
    first, second = sb.new_hwid(), sb.new_hwid()
    assert first != second and len(first) == 32 and first.isalnum()


# ------------------------------------------------------------ адрес

@pytest.mark.parametrize("url", [
    "", "ftp://sub.example.com/x", "file:///C:/Windows/win.ini", "javascript:alert(1)", "https://sub.example.com/a b",
    "https://sub.example.com/x\ny", "https://localhost/x", "https://127.0.0.1/x", "https://10.1.2.3/x",
    "https://192.168.1.1/x", "https://[::1]/x", "https://[::ffff:127.0.0.1]/x", "http://2130706433/x",
    "http://0x7f.1/x", "https://router/x", "https://nas.local/x", "https://sub.example.com:99999/x",
])
def test_check_url_refuses(url):
    assert _error(check_url, url).kind == "scheme"


def test_check_url_normalizes():
    assert check_url("https://Sub.Example.com/s?token=1#frag") == "https://sub.example.com/s?token=1"
    assert check_url("https://пример.рф/sub") == "https://xn--e1afmkfd.xn--p1ai/sub"
    assert check_url("https://sub.example.com") == "https://sub.example.com/"
    assert check_url("http://127.0.0.1:8080/x", allow_local=True) == "http://127.0.0.1:8080/x"


def test_redirect_target_rules():
    assert sb._next_url("https://a.example.com/x", "/y?z=1", False) == "https://a.example.com/y?z=1"
    assert _error(sb._next_url, "https://a.example.com/x", "http://b.example.com/y", False).kind == "scheme"
    assert _error(sb._next_url, "https://a.example.com/x", "https://192.168.1.1/admin", False).kind == "scheme"
    assert sb._next_url("http://a.example.com/x", "https://a.example.com/x", False) == "https://a.example.com/x"


# ------------------------------------------------------------ загрузка с локального сервера

class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 — имя задаёт http.server
        self.server.requests.append((self.path, {k.lower(): v for k, v in self.headers.items()}))
        route = self.server.routes.get(self.path.split("?")[0])
        if route is None:
            self.send_error(404)
            return
        route(self)

    def log_message(self, *args):
        pass


def _reply(status=200, body=b"", headers=None, length=True):
    def handler(h):
        h.send_response(status)
        for key, value in (headers or {}).items():
            h.send_header(key, value)
        if length:
            h.send_header("Content-Length", str(len(body)))
        h.end_headers()
        h.wfile.write(body)
    return handler


class _Server(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        if isinstance(sys.exc_info()[1], ConnectionError):
            return                     # клиент сам закрыл соединение (лимит, тайм-аут) — так и задумано
        super().handle_error(request, client_address)


@pytest.fixture
def web():
    server = _Server(("127.0.0.1", 0), _Handler)
    server.routes, server.requests = {}, []
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()


def _url(web, path: str) -> str:
    return f"http://127.0.0.1:{web.server_address[1]}{path}"


def _get(web, path: str, **kwargs) -> Fetched:
    kwargs.setdefault("user_agent", UA)
    return fetch(_url(web, path), opener=urllib.request.build_opener(urllib.request.ProxyHandler({})),
                 allow_local=True, **kwargs)


def test_fetch_returns_body_headers_and_sends_honest_headers(web):
    title = "Мой VPN".encode("utf-8").decode("latin-1")              # UTF-8 в заголовке, как шлют панели
    web.routes["/sub/TOKEN"] = _reply(body=B01.encode(), headers={"Profile-Title": title, "Subscription-Userinfo": "total=1"})
    fetched = _get(web, "/sub/TOKEN")
    assert (fetched.status, fetched.body, fetched.url, fetched.user_agent, fetched.hwid) == (
        200, B01.encode(), _url(web, "/sub/TOKEN"), UA, False)
    assert fetched.headers["profile-title"] == "Мой VPN" and fetched.headers["subscription-userinfo"] == "total=1"
    assert fetched.warning == sb.HTTP_WARNING
    sent = web.requests[0][1]
    assert sent["user-agent"] == UA and sent["accept"] == "*/*" and "gzip" in sent["accept-encoding"]
    assert "x-hwid" not in sent
    assert offer(fetched, decode(fetched.body, fetched.headers))["kind"] == "extended"


def test_fetch_sends_hwid_only_when_asked(web):
    web.routes["/s"] = _reply(body=VLESS.encode())
    hwid = sb.new_hwid()
    assert _get(web, "/s", hwid=hwid).hwid
    sent = web.requests[0][1]
    assert (sent["x-hwid"], sent["x-device-os"], sent["x-ver-os"], sent["x-device-model"]) == (hwid, "Windows", "10", "PC")
    assert _error(_get, web, "/s", hwid="плохой id").kind == "hwid"


def test_fetch_basic_auth_from_address(web):
    web.routes["/auth"] = _reply(body=VLESS.encode())
    port = web.server_address[1]
    fetch(f"http://user:p%40ss@127.0.0.1:{port}/auth", user_agent=UA,
          opener=urllib.request.build_opener(urllib.request.ProxyHandler({})), allow_local=True)
    path, sent = web.requests[0]
    assert path == "/auth" and sent["authorization"] == "Basic " + base64.b64encode(b"user:p@ss").decode()


@pytest.mark.parametrize("encoding, pack", [
    ("gzip", gzip.compress),
    ("deflate", zlib.compress),
    ("deflate", lambda data: zlib.compress(data)[2:-4]),               # «сырой» deflate без заголовка zlib
])
def test_fetch_decompresses(web, encoding, pack):
    web.routes["/z"] = _reply(body=pack(B01.encode()), headers={"Content-Encoding": encoding})
    assert _get(web, "/z").body == B01.encode()


def test_fetch_limits_size_after_decompression(web):
    limit = 64 * 1024
    web.routes["/bomb"] = _reply(body=gzip.compress(b"\0" * (limit * 40)), headers={"Content-Encoding": "gzip"})
    web.routes["/declared"] = _reply(body=b"x" * (limit * 3))
    web.routes["/stream"] = _reply(body=b"x" * (limit * 3), length=False)
    web.routes["/br"] = _reply(body=b"x", headers={"Content-Encoding": "br"})
    for path in ("/bomb", "/declared", "/stream"):
        assert _error(_get, web, path, limit=limit).kind == "too_big"
    assert _error(_get, web, "/br").reason == "compression"


def test_fetch_timeout(web):
    release = threading.Event()

    def slow(h):
        release.wait(10)
        _reply(body=b"late")(h)
    web.routes["/slow"] = slow
    try:
        assert _error(_get, web, "/slow", timeout=0.3).kind == "timeout"
    finally:
        release.set()


def test_fetch_http_errors_carry_response_for_offer(web):
    web.routes["/sub/SECRET-TOKEN-123"] = _reply(403, b"forbidden")
    web.routes["/hwid"] = _reply(404, headers={"X-Hwid-Limit": "true"})
    web.routes["/broken"] = _reply(502)
    error = _error(_get, web, "/sub/SECRET-TOKEN-123")
    assert (error.kind, error.status, error.fetched.status, error.fetched.body) == ("http_status", 403, 403, b"forbidden")
    assert "SECRET-TOKEN-123" not in str(error) and "SECRET-TOKEN-123" not in repr(error)
    assert offer(None, None, error) == {"kind": "ua", "text": offer(None, None, error)["text"],
                                        "options": ["v2rayn", "happ", "incy"]}
    assert offer(None, None, _error(_get, web, "/hwid")) == {"kind": "hwid", "text": sb.HWID_OFFER_TEXT,
                                                             "options": ["hwid"]}
    assert offer(None, None, _error(_get, web, "/broken")) is None


def test_fetch_empty_body_with_hwid_headers(web):
    web.routes["/e"] = _reply(headers={"x-hwid-not-supported": "true", "x-hwid-limit": "true"})
    fetched = _get(web, "/e")
    error = _error(decode, fetched.body, fetched.headers)
    assert error.kind == "empty"
    assert offer(fetched, None, error)["kind"] == "hwid"
    web.routes["/plain-empty"] = _reply()
    empty = _get(web, "/plain-empty")
    assert offer(empty, None, _error(decode, empty.body, empty.headers))["kind"] == "ua"


def test_fetch_follows_and_checks_redirects(web):
    web.routes["/start"] = _reply(302, headers={"Location": "/final"})
    web.routes["/final"] = _reply(body=VLESS.encode())
    web.routes["/to-file"] = _reply(302, headers={"Location": "file:///C:/Windows/win.ini"})
    web.routes["/to-ftp"] = _reply(301, headers={"Location": "ftp://example.com/x"})
    web.routes["/loop"] = _reply(302, headers={"Location": "/loop"})
    web.routes["/nowhere"] = _reply(302)
    fetched = _get(web, "/start")
    assert fetched.url == _url(web, "/final") and [p for p, _ in web.requests] == ["/start", "/final"]
    for path in ("/to-file", "/to-ftp"):
        assert _error(_get, web, path).kind == "scheme"
    loop = _error(_get, web, "/loop")
    assert loop.kind == "network" and "перенаправлений" in str(loop)
    assert _error(_get, web, "/nowhere").kind == "network"


def test_fetch_connection_dropped_and_refused():
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()

    def drop():
        conn, _ = listener.accept()
        conn.recv(65536)
        conn.close()
    thread = threading.Thread(target=drop, daemon=True)
    thread.start()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    port = listener.getsockname()[1]
    try:
        dropped = _error(fetch, f"http://127.0.0.1:{port}/x", user_agent=UA, opener=opener, allow_local=True, timeout=5)
    finally:
        thread.join(5)
        listener.close()
    assert (dropped.kind, dropped.reason) == ("network", "drop")
    assert offer(None, None, dropped)["kind"] == "ua"
    refused = _error(fetch, f"http://127.0.0.1:{port}/x", user_agent=UA, opener=opener, allow_local=True, timeout=5)
    assert (refused.kind, refused.reason) == ("network", "refused")
    assert offer(None, None, refused) is None


def test_fetch_refuses_local_address_without_test_flag():
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    assert _error(fetch, "http://127.0.0.1:1/x", user_agent=UA, opener=opener).kind == "scheme"


# ------------------------------------------------------------ подсказки

def _fetched(user_agent: str = UA, **kwargs) -> Fetched:
    return Fetched(200, kwargs.pop("headers", {}), b"", "https://sub.example.com/s", user_agent=user_agent, **kwargs)


def test_extended_offer_only_for_base64_links_with_own_user_agent():
    base64_links = decode(B01.encode(), {})
    assert offer(_fetched(), base64_links)["kind"] == "extended"
    assert offer(_fetched(UA_PRESETS["v2rayn"]), base64_links) is None
    assert offer(_fetched(), decode(VLESS.encode(), {})) is None
    assert offer(_fetched(), decode((DATA / "xray_3xui.json").read_bytes(), {})) is None


def test_ua_offer_skips_the_user_agent_already_used():
    error = SubscriptionError("http_status", "x", status=451, fetched=_fetched(UA_PRESETS["happ"]))
    assert offer(None, None, error)["options"] == ["v2rayn", "incy"]


@pytest.mark.parametrize("error, kind", [
    (SubscriptionError("format", sb.CLASH_TEXT, reason="clash"), "ua"),
    (SubscriptionError("format", "x", reason="json"), None),
    (SubscriptionError("network", "x", reason="dns"), None),
    (SubscriptionError("html", sb.HTML_TEXT), "html"),
    (SubscriptionError("http_status", "x", status=500), None),
    (SubscriptionError("timeout", "x"), None),
])
def test_offer_by_error(error, kind):
    result = offer(_fetched(), None, error)
    assert (result or {}).get("kind") == kind


def test_hwid_offers():
    limit = _fetched(headers={"x-hwid-max-devices-reached": "true"})
    assert offer(limit, None, SubscriptionError("empty", "x")) == {"kind": "hwid", "text": sb.HWID_LIMIT_TEXT,
                                                                    "options": []}
    already = _fetched(headers={"x-hwid-not-supported": "true"}, hwid=True)
    assert offer(already, None, SubscriptionError("empty", "x")) is None
    working = _fetched(headers={"x-hwid-active": "true"})
    assert offer(working, Decoded("links", servers=decode(VLESS.encode(), {}).servers)) is None
    assert offer(_fetched(), Decoded("links")) ["kind"] == "ua"
