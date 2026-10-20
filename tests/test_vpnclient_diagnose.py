"""Свой VPN: причины ошибок по выводу ядер, чья сторона у «нет ответа» и проверки «Помощи»."""
import email.utils
import socket
import ssl
import struct
import threading
from pathlib import Path

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
     "conflict", "хотя права администратора у Лазейки есть"),
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


def test_tun_access_denied_has_its_own_honest_reason():
    """«Доступ запрещён» у адаптера бывает, когда права администратора уже есть (без них свой VPN не
    запускается вовсе): страница — как при чужом VPN (вид conflict: режим «Системный прокси»), а причина —
    своя, без совета перезапуститься с правами, которые и так есть."""
    tail = ["INFO[0000] sing-box started",
            "FATAL[0000] start service: start inbound/tun[tun-in]: configure tun interface: Access is denied."]
    assert diagnose.classify(tail)[0] == "conflict" and diagnose.stop_kind(tail) == "admin"
    reason = diagnose.explain(diagnose.Facts(kind=diagnose.stop_kind(tail), fatal=True))
    assert (reason.side, reason.code) == ("you", "admin")
    assert "права администратора у Лазейки есть" in reason.text and "антивирус" in reason.text
    assert "Перезапустите Лазейку с правами" not in reason.advice and "«Системный прокси»" in reason.advice
    other = ["FATAL[0000] start service: start inbound/tun[tun-in]: create tun: Cannot create a file when that "
             "file already exists."]
    assert diagnose.stop_kind(other) == diagnose.classify(other)[0] == "conflict"
    assert diagnose.stop_kind([]) == "other" and diagnose.stop_kind(["FATAL[0000] something new"]) == "core"


def test_fatal_line_wins_over_connection_errors():
    tail = ["ERROR[0005] dial tcp 203.0.113.5:443: i/o timeout", BUSY]
    assert diagnose.classify(tail)[0] == "port"


def test_unknown_and_empty():
    assert diagnose.classify([])[0] == "other"
    kind, text = diagnose.classify(["FATAL[0000] something completely new"])
    assert kind == "core" and "something completely new" in text and "FATAL[" not in text


def test_runtime_hint_keeps_only_what_speaks_about_the_server():
    assert diagnose.runtime_hint(["ERROR[0013] outbound/vless[srv]: reality verification failed"]) == "tls"
    assert diagnose.runtime_hint(["ERROR[0001] invalid user: authentication failed"]) == "auth"
    assert diagnose.runtime_hint(["INFO[0000] started"]) is None
    assert diagnose.runtime_hint([]) is None
    assert diagnose.runtime_hint(["ERROR[0005] dial tcp 203.0.113.5:443: i/o timeout"]) is None, \
        "тайм-аут в журнале — не причина: её назовут прямые пробы"


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


def test_tcp_probe_tells_refused_from_ok():
    with socket.socket() as srv:
        srv.bind(("127.0.0.1", 0))
        srv.listen()
        port = srv.getsockname()[1]
        probe = diagnose.tcp_probe("127.0.0.1", port, 2)
        assert probe.outcome == "ok" and probe.ms is not None
    # Windows повторяет SYN после отказа: «закрыто» приходит через ~2 с — тайм-аут пробы с запасом.
    assert diagnose.tcp_probe("127.0.0.1", port, 4) == diagnose.TcpProbe("refused")
    assert diagnose.tcp_probe("127.0.0.1", "порт", 1).outcome == "error"


# ------------------------------------------------------------ прямое рукопожатие TLS (локальные серверы)

def _self_signed(tmp_path):
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "www.example.com")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1)).sign(key, hashes.SHA256()))
    cert_path, key_path = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    return cert_path, key_path


def _serve_once(handler):
    """Локальный сервер на одно соединение: handler(conn) решает, как ответить на рукопожатие."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen()
    done = threading.Event()

    def run():
        try:
            conn, _ = srv.accept()
            with conn:
                handler(conn)
        except OSError:
            pass
        finally:
            done.set()
            srv.close()

    threading.Thread(target=run, daemon=True).start()
    return srv.getsockname()[1], done


def test_tls_probe_ok_with_real_handshake(tmp_path):
    cert, key = _self_signed(tmp_path)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)

    def handshake(conn):
        with ctx.wrap_socket(conn, server_side=True):
            pass

    port, done = _serve_once(handshake)
    assert diagnose.tls_probe("127.0.0.1", port, "www.example.com", 3) == "ok"
    assert done.wait(5)


def test_tls_probe_reset_mid_handshake():
    def reset(conn):
        conn.recv(1024)                                   # ClientHello дошёл — и соединение оборвали
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))

    port, done = _serve_once(reset)
    assert diagnose.tls_probe("127.0.0.1", port, "www.example.com", 3) == "reset"
    assert done.wait(5)


def _recv_exactly(conn, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            raise ConnectionError(f"клиент закрыл соединение: получено {len(data)} байт из {size}")
        data += chunk
    return data


def _read_client_hello(conn) -> bytes:
    """Запись TLS целиком: 5 байт заголовка и тело по длине из него. ClientHello OpenSSL 3.5 — около 1,5 КБ;
    недочитанный хвост при закрытии сокета Windows превращает в RST, и клиент видел бы обрыв вместо ответа."""
    head = _recv_exactly(conn, 5)
    return head + _recv_exactly(conn, int.from_bytes(head[3:5], "big"))


def test_tls_probe_hangs_and_answers_not_tls():
    release = threading.Event()
    port, done = _serve_once(lambda conn: (_read_client_hello(conn), release.wait(5)))
    assert diagnose.tls_probe("127.0.0.1", port, "www.example.com", 0.5) == "timeout"
    release.set()
    assert done.wait(5)
    port, done = _serve_once(lambda conn: (_read_client_hello(conn),
                                           conn.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")))
    assert diagnose.tls_probe("127.0.0.1", port, None, 3) == "alert", "ответил не по TLS — путь свободен"
    assert done.wait(5)


def test_tls_probe_without_listener():
    with socket.socket() as srv:
        srv.bind(("127.0.0.1", 0))
        port = srv.getsockname()[1]
    assert diagnose.tls_probe("127.0.0.1", port, "www.example.com", 4) == "error"


# ------------------------------------------------------------ чья сторона: причина по фактам

F = diagnose.Facts


@pytest.mark.parametrize("facts, side, code", [
    # у вас
    (F(online=False, tcp="timeout", peers_failed=3), "you", "no_internet"),
    (F(online=True, dns="unreachable", system_dns=False), "you", "dns_down"),
    (F(online=True, timed=True, skew=600.0, tcp="ok", handshake="ok"), "you", "clock"),
    (F(online=True, kind="clock", tcp="ok"), "you", "clock"),
    (F(kind="conflict", fatal=True), "you", "conflict"),
    (F(kind="admin", fatal=True), "you", "admin"),
    (F(kind="port", fatal=True), "you", "port_busy"),
    # у интернет-провайдера
    (F(online=True, dns="unreachable", system_dns=True), "isp", "dns_blocked"),
    (F(online=True, tcp="ok", handshake="reset"), "isp", "dpi"),
    (F(online=True, tcp="ok", handshake="timeout"), "isp", "dpi"),
    (F(online=True, tcp="reset"), "isp", "dpi"),
    (F(online=True, udp=True, tcp_ok_anywhere=True, peers_failed=1), "isp", "udp_blocked"),
    # у VPN-провайдера
    (F(online=True, dns="nxdomain"), "provider", "dns_missing"),
    (F(online=True, dns="nodata"), "provider", "dns_missing"),
    (F(online=True, dns="no_ipv4"), "you", "ipv6_only"),
    (F(online=True, dns="servfail"), "unknown", "dns_error"),
    (F(online=True, tcp="refused"), "provider", "port_closed"),
    (F(online=True, tcp="timeout", peers_ok=2, peers_failed=1), "provider", "server_down"),
    (F(online=True, tcp=None, peers_ok=1), "provider", "server_down"),
    (F(online=True, udp=True, peers_ok=1, peers_udp_ok=1, tcp_ok_anywhere=True), "provider", "server_down"),
    (F(online=True, tcp="ok", handshake="ok", kind="tls"), "provider", "keys_outdated"),
    (F(online=True, tcp="ok", kind="auth"), "provider", "auth_rejected"),
    (F(online=True, tcp="ok", handshake="alert"), "provider", "no_exit"),
    (F(online=True, expired=True, tcp="timeout"), "provider", "sub_expired"),
    (F(online=True, traffic_out=True, tcp="ok"), "provider", "traffic_out"),
    (F(online=True, device_limit=True, tcp="ok", kind="tls"), "provider", "device_limit"),
    (F(kind="tls", fatal=True), "provider", "bad_params"),
    (F(kind="auth", fatal=True), "provider", "bad_params"),
    # в Лазейке
    (F(kind="core", fatal=True), "lazeyka", "core_failed"),
    (F(kind="other", fatal=True), "lazeyka", "core_failed"),
    (F(kind="helper", fatal=True), "lazeyka", "helper_failed"),
    (F(kind="unsupported", fatal=True), "lazeyka", "unsupported"),
    (F(kind="unsupported", online=True), "lazeyka", "unsupported"),
    (F(kind="killswitch"), "lazeyka", "killswitch"),
    # не ясно — честно обе версии
    (F(online=True, tcp="timeout", peers_failed=4), "unknown", "all_down"),
    (F(online=True, tcp="unreachable"), "unknown", "tcp_timeout"),
    (F(online=True, udp=True), "unknown", "udp_silent"),
    (F(online=True, dns="found"), "unknown", "dns_retry"),
    (F(), "unknown", "unknown"),
])
def test_explain(facts, side, code):
    reason = diagnose.explain(facts)
    assert (reason.side, reason.code) == (side, code), reason
    assert reason.side in diagnose.SIDES and reason.text and reason.advice


def test_explain_order_what_wins():
    assert diagnose.explain(F(kind="port", fatal=True, online=False)).code == "port_busy", \
        "ядро само назвало причину — сеть ни при чём"
    assert diagnose.explain(F(online=False, expired=True, dns="nxdomain")).code == "no_internet"
    assert diagnose.explain(F(online=True, expired=True, tcp="refused")).code == "sub_expired"
    assert diagnose.explain(F(online=None, tcp="refused")).code == "port_closed", "не проверили — не «нет»"
    assert diagnose.explain(F(online=True, timed=False, skew=600.0, tcp="ok", handshake="ok")).code == "no_exit", \
        "часы не мешают протоколу, который время не сверяет"
    assert diagnose.explain(F(online=True, timed=True, skew=30.0, tcp="ok", handshake="ok")).code == "no_exit"


def test_explain_texts_follow_facts():
    assert "10 мин" in diagnose.explain(F(online=True, timed=True, skew=-600.0)).text
    assert "обрывается" in diagnose.explain(F(online=True, tcp="ok", handshake="reset")).text
    assert "сбрасывают сразу" in diagnose.explain(F(online=True, tcp="reset")).text
    hang = diagnose.explain(F(online=True, tcp="ok", handshake="timeout"))
    assert "зависает" in hang.text and "Фрагментацию ClientHello" in hang.advice
    assert "уже включена" in diagnose.explain(F(online=True, tcp="ok", handshake="reset", fragment=True)).advice
    both = diagnose.explain(F(online=True, tcp="timeout", peers_failed=2))
    assert "интернет-провайдер" in both.text and "VPN-провайдера" in both.text and "мобильный" in both.advice


def test_account_facts():
    now = 1_760_000_000.0
    assert diagnose.account_facts({"expire": now - 1}, now) == {"expired": True, "traffic_out": False}
    assert diagnose.account_facts({"expire": 0, "total": 0, "download": 10}, now) == {"expired": False,
                                                                                      "traffic_out": False}
    assert diagnose.account_facts({"total": 100, "upload": 40, "download": 60}, now)["traffic_out"] is True
    assert diagnose.account_facts({"expire": "сломано"}, now) == {"expired": False, "traffic_out": False}
    assert diagnose.account_facts(None, now) == {"expired": False, "traffic_out": False}


def test_udp_protocols():
    assert diagnose.uses_udp("hysteria2", "tcp") and diagnose.uses_udp("tuic", None)
    assert diagnose.uses_udp("wireguard", "tcp") and diagnose.uses_udp("vless", "kcp")
    assert not diagnose.uses_udp("vless", "xhttp") and not diagnose.uses_udp("trojan", "grpc")


def test_public_reason_and_alert_text():
    reason = diagnose.explain(F(online=True, tcp="refused"))
    assert diagnose.public_reason(reason.public()) == reason.public()
    assert diagnose.public_reason({"side": "чужая", "code": "x", "text": "t", "advice": "a"}) is None
    assert diagnose.public_reason({"side": "isp", "code": "", "text": "t", "advice": "a"}) is None
    assert diagnose.public_reason("строка") is None
    assert "Чья сторона: у VPN-провайдера." in diagnose.alert_text(reason)


def test_error_kind_of_reason():
    assert diagnose.error_kind(diagnose.explain(F(online=True, tcp="ok", handshake="reset"))) == "tls"
    assert diagnose.error_kind(diagnose.explain(F(online=True, timed=True, skew=600.0))) == "clock"
    assert diagnose.error_kind(diagnose.explain(F(online=False))) == "timeout"
    assert diagnose.error_kind(diagnose.explain(F(online=True, expired=True))) == "auth"
    assert diagnose.error_kind(diagnose.explain(F(online=True, tcp="ok", handshake="ok"))) == "other"


def _all_codes():
    found = {v.code for v in vars(diagnose).values() if isinstance(v, diagnose.Reason)}
    found |= {r.code for r in diagnose._LOCAL.values()}
    return found | {diagnose.explain(F(online=True, tcp="reset")).code, diagnose.explain(F(kind="clock")).code}


def test_every_reason_has_a_short_label_on_the_page():
    """Страница подписывает причину коротко по коду (texts.js, VPNC_REASONS): новый код без подписи —
    в списке серверов осталась бы длинная фраза вместо метки."""
    texts = (Path(__file__).resolve().parent.parent / "app" / "ui" / "js" / "texts.js").read_text(encoding="utf-8")
    block = texts.split("const VPNC_REASONS = {", 1)[1].split("};", 1)[0]
    missing = sorted(code for code in _all_codes() if f"{code}:" not in block)
    assert not missing, missing
    assert len(_all_codes()) >= 25


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
    # Лазейка такой адаптер сама не убирает и не занимает — текст этого не обещает.
    assert "займёт" not in items[0]["text"] and "Диспетчере устройств" in items[0]["text"]
    assert diagnose.help_items(proxy_state=[], owned_address=None, adapters=[own], own_running=True,
                               listening=_no_listener) == []


def test_collect_adapters_read_only_smoke():
    adapters = diagnose.collect_adapters()
    assert all(isinstance(a.name, str) and isinstance(a.dns, list) for a in adapters)
