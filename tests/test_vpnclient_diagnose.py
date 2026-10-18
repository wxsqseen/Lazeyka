"""Свой VPN: причины ошибок по выводу ядер и проверки «Помощи»."""
import email.utils
import socket

import pytest

from app.vpnclient import diagnose
from app.vpnclient.diagnose import AdapterInfo

BUSY = ("FATAL[0000] start service: start inbound/mixed[mixed-in]: listen tcp 127.0.0.1:20808: bind: Only one "
        "usage of each socket address (protocol/network address/port) is normally permitted.")
API_BUSY = ("FATAL[0000] start service: finish-start clash server: external controller listen error: listen tcp "
            "127.0.0.1:19090: bind: Only one usage of each socket address (protocol/network address/port) is "
            "normally permitted.")
RESERVED = ("FATAL[0000] start service: start inbound/mixed[mixed-in]: listen tcp 127.0.0.1:50123: bind: An attempt "
            "was made to access a socket in a way forbidden by its access permissions.")


@pytest.mark.parametrize("line, kind, fragment", [
    (BUSY, "port", "Порт 20808 уже занят"),
    (API_BUSY, "port", "Служебный порт ядра 19090"),
    (RESERVED, "port", "Порт 50123 зарезервирован"),
    ("FATAL[0000] start service: start inbound/tun[tun-in]: configure tun interface: Access is denied.",
     "admin", "права администратора"),
    ("FATAL[0000] start service: start inbound/tun[tun-in]: create tun: Cannot create a file when that file "
     "already exists.", "conflict", "мешает другой VPN"),
    ("FATAL[0000] decode config at C:\\x\\sing-box.json: route.bogus_field: json: unknown field \"bogus_field\"",
     "core", "ошибка Лазейки"),
    ("FATAL[0000] initialize outbound[3]: decode public_key: illegal base64 data at input byte 8", "tls", "REALITY"),
    ("FATAL[0000] initialize outbound[3]: uTLS is required by reality client", "tls", "REALITY"),
    ("FATAL[0000] initialize outbound[6]: bad key length, required 16, got 5", "auth", "Ключ сервера"),
    ("FATAL[0000] initialize outbound[4]: unknown transport type: xhttp", "unsupported", "не поддерживает"),
    ("Failed to start: main: failed to load config files: [xray.json] > infra/conf: failed to build outbound "
     "config with tag x > allowInsecure is not allowed", "unsupported", "allowInsecure"),
    ("ERROR[0012] [3355392573 5.0s] inbound/mixed[internal-in]: process connection from 127.0.0.1:55331: "
     "open outbound connection: dial tcp 203.0.113.5:443: i/o timeout", "timeout", "не отвечает"),
    ("ERROR[0013] outbound/vless[srv]: reality verification failed", "tls", "TLS/REALITY"),
    ("2026/10/17 07:00:00 [Warning] [1234] app/proxyman/outbound: failed to process outbound traffic > "
     "proxy/vless/outbound: failed to find an available destination", "timeout", "не отвечает"),
    ("ERROR[0001] connection: dial tcp 203.0.113.5:443: connectex: No connection could be made because the "
     "target machine actively refused it.", "timeout", "не принимает"),
])
def test_classify(line, kind, fragment):
    got_kind, text = diagnose.classify(["INFO[0000] sing-box started", line])
    assert got_kind == kind and fragment in text, text


def test_fatal_line_wins_over_connection_errors():
    tail = ["ERROR[0005] dial tcp 203.0.113.5:443: i/o timeout", BUSY]
    assert diagnose.classify(tail)[0] == "port"


def test_unknown_and_empty():
    assert diagnose.classify([])[0] == "other"
    kind, text = diagnose.classify(["FATAL[0000] something completely new"])
    assert kind == "core" and "something completely new" in text and "FATAL[" not in text


def test_explain_no_exit():
    assert diagnose.explain_no_exit([], reach_ms=None, skew=None, timed_sensitive=False)[0] == "timeout"
    kind, text = diagnose.explain_no_exit([], reach_ms=40.0, skew=600.0, timed_sensitive=True)
    assert kind == "clock" and "10 мин" in text
    assert diagnose.explain_no_exit([], reach_ms=40.0, skew=600.0, timed_sensitive=False)[0] == "other"
    tls = ["ERROR[0013] outbound/vless[srv]: reality verification failed"]
    assert diagnose.explain_no_exit(tls, reach_ms=40.0, skew=1.0, timed_sensitive=True)[0] == "tls"


def test_clock_skew():
    now = 1_760_000_000.0
    header = email.utils.formatdate(now - 300, usegmt=True)
    assert diagnose.clock_skew(header, now=now) == pytest.approx(300, abs=1)
    assert diagnose.clock_skew("не дата", now=now) is None
    assert diagnose.clock_skew(None) is None


def test_tcp_reach_local():
    with socket.socket() as srv:
        srv.bind(("127.0.0.1", 0))
        srv.listen()
        port = srv.getsockname()[1]
        assert diagnose.tcp_reach("127.0.0.1", port, 2) is not None
    assert diagnose.tcp_reach("127.0.0.1", port, 0.5) is None


def _no_listener(host, port):
    return False


def test_help_dead_proxy_ours_and_foreign():
    state = [{"name": None, "flags": 0x3, "server": "127.0.0.1:20808"},
             {"name": "VPN", "flags": 0x3, "server": "http=127.0.0.1:10809;https=127.0.0.1:10809"},
             {"name": "Офис", "flags": 0x3, "server": "10.0.0.1:3128"}]
    items = diagnose.help_items(proxy_state=state, owned_address="127.0.0.1:20808", adapters=[],
                                own_running=False, listening=_no_listener)
    texts = [i["text"] for i in items if i["id"] == "vpnclient_dead_proxy"]
    assert len(texts) == 2
    assert "прокси Лазейки" in texts[0] and "другая VPN-программа" in texts[1]
    alive = diagnose.help_items(proxy_state=state, owned_address=None, adapters=[], own_running=True,
                                listening=lambda h, p: True)
    assert alive == []


def test_help_fake_dns_left_by_other_vpn():
    eth = AdapterInfo("Ethernet", True, ["192.168.1.10"], ["198.18.0.2"])
    items = diagnose.help_items(proxy_state=[], owned_address=None, adapters=[eth], own_running=False,
                                listening=_no_listener)
    assert [i["id"] for i in items] == ["vpnclient_fake_dns"] and "198.18.0.2" in items[0]["text"]
    incy_up = AdapterInfo("wwan99", True, ["198.18.0.1"], [])
    assert diagnose.help_items(proxy_state=[], owned_address=None, adapters=[eth, incy_up], own_running=False,
                               listening=_no_listener) == []


def test_help_orphan_own_adapter():
    own = AdapterInfo("Lazeyka", False, [], [])
    items = diagnose.help_items(proxy_state=[], owned_address=None, adapters=[own], own_running=False,
                                listening=_no_listener)
    assert [i["id"] for i in items] == ["vpnclient_orphan_adapter"]
    assert diagnose.help_items(proxy_state=[], owned_address=None, adapters=[own], own_running=True,
                               listening=_no_listener) == []


def test_collect_adapters_read_only_smoke():
    adapters = diagnose.collect_adapters()
    assert all(isinstance(a.name, str) and isinstance(a.dns, list) for a in adapters)
