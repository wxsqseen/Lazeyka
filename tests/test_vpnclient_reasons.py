"""Свой VPN: чья сторона у «нет ответа». Менеджер собирает факты на подделках (контрольный сайт, пробы TCP и
TLS, DNS, соседи по подписке, срок подписки, часы, журнал ядра) и кладёт причину в состояние и плашки."""
import email.utils
import time

import pytest

from app.errors import UserError
from app.vpnclient import manager as mgr
from app.vpnclient.model import Server, Subscription
from tests.fakes.vpn_world import FakeStore, FakeSubscription, basic_store, make_manager, server, wait_for


@pytest.fixture
def world(tmp_path):
    manager, w = make_manager(tmp_path, basic_store())
    w.engines.allowed = False                      # без фоновых задач ядер: тест сам двигает часы
    yield w
    manager.shutdown()


def _named(world, name):
    return next(s for s in world.store.servers() if s.name == name)


def _addr(world, name):
    return world.resolver.address(_named(world, name).host)


def _fresh(world, name, ms=40, error=None):
    """Свежая задержка соседа — как после недавней проверки."""
    world.store._latency[_named(world, name).id] = {"ms": ms, "at": world.clock_value, "error": error}


def _silent(world, *names):
    world.delays.update({f"t-{_named(world, n).id}": "нет ответа" for n in names})


def _measure(m, ids=None):
    m.latency(ids)
    assert wait_for(lambda: not m.snapshot()["latency"]["running"])


def _reason(world, name):
    reason = (world.store.latency().get(_named(world, name).id) or {}).get("reason")
    return (reason["side"], reason["code"]) if reason else None


def _diagnosis(m):
    found = m.snapshot()["diagnosis"]
    return (found["side"], found["code"]) if found else None


# ------------------------------------------------------------ подключено, а через сервер ничего не открывается

def test_no_exit_server_down_when_neighbours_answer(world):
    m = world.manager
    world.exit_ok = False
    world.tcp[_addr(world, "Amsterdam")] = "timeout"
    _fresh(world, "Berlin")
    m.start()
    snap = m.snapshot()
    assert _diagnosis(m) == ("provider", "server_down")
    assert snap["error"] == snap["diagnosis"]["text"] and snap["error_kind"] == "timeout"
    assert "Чья сторона: у VPN-провайдера." in world.alerts["vpn-exit"]["text"]
    assert ("tcp", _addr(world, "Amsterdam")) in world.probes, "проба — по адресу сервера из плана"


def test_no_exit_without_internet_is_on_your_side(world):
    m = world.manager
    world.exit_ok, world.online = False, False
    m.start()
    assert _diagnosis(m) == ("you", "no_internet")
    assert "Чья сторона: у вас." in world.alerts["vpn-exit"]["text"]


def test_no_exit_handshake_reset_is_dpi_and_advice_follows_fragment(world):
    m = world.manager
    world.exit_ok = False
    world.handshakes[_addr(world, "Amsterdam")] = "reset"
    m.start()
    snap = m.snapshot()
    assert _diagnosis(m) == ("isp", "dpi") and snap["error_kind"] == "tls"
    assert "Фрагментацию ClientHello" in snap["diagnosis"]["advice"]
    world.settings.update(lambda d: d["vpnclient"].__setitem__("tls_fragment", True))
    world.advance(mgr.DIAGNOSIS_REUSE + 1)
    m.tick()
    assert m.wait_idle(10)
    assert "уже включена" in m.snapshot()["diagnosis"]["advice"]


def test_no_exit_keys_outdated_from_core_log(world):
    m = world.manager
    m.start()
    world.exit_ok = False
    m._session.main.tail.append("ERROR[0013] outbound/vless[srv]: reality verification failed")
    m.on_network_change()                          # перепроверка выхода
    assert m.wait_idle(10)
    assert _diagnosis(m) == ("provider", "keys_outdated")
    assert m.snapshot()["error_kind"] == "tls"


def test_no_exit_clock_skew_for_reality(world):
    m = world.manager
    world.exit_ok = False
    m.deps.direct_date = lambda: email.utils.formatdate(time.time() - 600, usegmt=True)
    m.start()
    snap = m.snapshot()
    assert _diagnosis(m) == ("you", "clock") and "10 мин" in snap["diagnosis"]["text"]
    assert snap["error_kind"] == "clock"


def test_no_exit_expired_subscription(world):
    m = world.manager
    world.exit_ok = False
    world.store.update_subscription("s-1", userinfo={"expire": int(world.clock_value) - 60})
    m.start()
    assert _diagnosis(m) == ("provider", "sub_expired")


def test_device_limit_from_subscription_headers(world):
    m = world.manager
    fake = FakeSubscription()
    m.deps.modules["subscription"] = fake
    keep = [s for s in world.store.servers() if s.sub == "s-1"]
    fake.fetch = lambda url, *, user_agent, hwid=None, opener=None, **_kw: fake.real.Fetched(
        200, {"X-HWID-Max-Devices-Reached": "true"}, b"", url, user_agent=user_agent, hwid=False)
    fake.decode = lambda body, headers=None, **_kw: fake.real.Decoded(format="links", servers=keep)
    m._update_sub("s-1", False)
    world.exit_ok = False
    m.start()
    assert _diagnosis(m) == ("provider", "device_limit")


def test_no_exit_reason_is_reused_for_a_minute(world):
    m = world.manager
    world.exit_ok = False
    m.start()
    probes = len(world.probes)
    assert probes
    world.advance(mgr.UNVERIFIED_RETRY)
    m.tick()
    assert m.wait_idle(10)
    assert len(world.probes) == probes, "повтор через 15 с — прежняя причина, без новых проб"
    world.advance(mgr.DIAGNOSIS_REUSE)
    m.tick()
    assert m.wait_idle(10)
    assert len(world.probes) > probes, "через минуту сервер пробуется снова"


def test_dead_server_alert_names_the_side(world):
    m = world.manager
    m.start()
    _silent(world, "Amsterdam", "Berlin", "Helsinki")
    world.tcp[_addr(world, "Amsterdam")] = "timeout"
    for _ in range(mgr.HEALTH_FAILS):
        world.advance(mgr.HEALTH_EVERY + 1)
        m.tick()
        assert m.wait_idle(10)
    text = world.alerts["vpn-server"]["text"]
    assert "другого живого сервера в подписке нет" in text
    assert "Не отвечает ни один из проверенных серверов подписки" in text and "Чья сторона: не ясно." in text


# ------------------------------------------------------------ не включилось

def test_resolver_remembers_how_it_failed():
    def nothing(host, url, qtype="A"):
        return []                                            # NODATA: имя есть, записей этого типа нет

    def rcode(code):
        def query(host, url, qtype="A"):
            raise mgr.DnsRcodeError(code)
        return query

    def down(host, url, qtype="A"):
        raise OSError("нет связи")

    def v6_only(host, url, qtype="A"):
        return ["2001:db8::7"] if qtype == "AAAA" else []

    for query, families, expected in ((nothing, ("A",), "no_ipv4"), (nothing, ("A", "AAAA"), "nodata"),
                                      (rcode(3), ("A",), "nxdomain"), (rcode(2), ("A",), "servfail"),
                                      (rcode(5), ("A",), "servfail"), (down, ("A",), "unreachable")):
        resolver = mgr.Resolver(query)
        with pytest.raises(mgr.VpnClientError):
            resolver.resolve("gone.example.com", families=families)
        assert resolver.failure("gone.example.com") == expected, (query.__name__, families)
    # Один резолвер говорит «нет такого имени», другой знает имя — значит, имя есть.
    answers = iter([mgr.DnsRcodeError(3), []] * 4)

    def mixed(host, url, qtype="A"):
        answer = next(answers)
        if isinstance(answer, Exception):
            raise answer
        return answer

    resolver = mgr.Resolver(mixed)
    with pytest.raises(mgr.VpnClientError, match="знает это имя"):
        resolver.resolve("gone.example.com")
    assert resolver.failure("gone.example.com") == "no_ipv4"
    assert mgr.Resolver(v6_only).resolve("v6.example.com", families=("A", "AAAA")) == "2001:db8::7"
    resolver = mgr.Resolver(lambda host, url, qtype="A": ["203.0.113.7"])
    resolver._failures["gone.example.com"] = "unreachable"
    assert resolver.resolve("gone.example.com") == "203.0.113.7"
    assert resolver.failure("gone.example.com") is None, "адрес нашёлся — прежняя неудача забыта"


def _answers(table: dict[str, object]):
    """Резолвер по семействам: значение — список адресов или исключение; asked — что спрашивали у кого."""
    asked: list[tuple[str, str]] = []

    def query(host, url, qtype="A"):
        asked.append((url, qtype))
        answer = table[qtype]
        if isinstance(answer, Exception):
            raise answer
        return list(answer)

    return query, asked


def test_servfail_on_aaaa_still_asks_a_at_the_same_resolver():
    """«Сначала IPv6»: SERVFAIL (или REFUSED) на AAAA об имени ничего не говорит — тот же резолвер спрашивают
    и про A. Раньше A не спрашивали вовсе, и подключение падало с ошибкой DNS, хотя IPv4 есть."""
    for rcode in (2, 5):
        query, asked = _answers({"AAAA": mgr.DnsRcodeError(rcode), "A": ["203.0.113.7"]})
        resolver = mgr.Resolver(query)
        assert resolver.resolve("vpn.example.com", families=("AAAA", "A")) == "203.0.113.7"
        assert [qtype for _url, qtype in asked] == ["AAAA", "A"] and len({url for url, _ in asked}) == 1
        assert resolver.failure("vpn.example.com") is None


def test_nxdomain_does_not_ask_the_other_family():
    query, asked = _answers({"AAAA": mgr.DnsRcodeError(3), "A": ["203.0.113.7"]})
    resolver = mgr.Resolver(query)
    with pytest.raises(mgr.VpnClientError, match="NXDOMAIN"):
        resolver.resolve("gone.example.com", families=("AAAA", "A"))
    assert {qtype for _url, qtype in asked} == {"AAAA"}, "имени нет — про A не спрашиваем"
    assert resolver.failure("gone.example.com") == "nxdomain"


@pytest.mark.parametrize("aaaa, a, expected", [
    (mgr.DnsRcodeError(2), [], "servfail"),        # про IPv6 ничего не известно — «адресов нет» было бы неправдой
    ([], mgr.DnsRcodeError(2), "servfail"),
    ([], [], "nodata"),
    (mgr.DnsRcodeError(2), mgr.DnsRcodeError(5), "servfail"),
    (OSError("нет связи"), OSError("нет связи"), "unreachable"),
])
def test_failure_by_family_stays_true(aaaa, a, expected):
    query, _asked = _answers({"AAAA": aaaa, "A": a})
    resolver = mgr.Resolver(query)
    with pytest.raises(mgr.VpnClientError):
        resolver.resolve("vpn.example.com", families=("AAAA", "A"))
    assert resolver.failure("vpn.example.com") == expected


@pytest.mark.parametrize("kind, system_dns, online, expected", [
    ("nxdomain", True, True, ("provider", "dns_missing")),
    ("nodata", True, True, ("provider", "dns_missing")),
    ("no_ipv4", True, True, ("you", "ipv6_only")),
    ("servfail", True, True, ("unknown", "dns_error")),
    ("unreachable", True, True, ("isp", "dns_blocked")),
    ("unreachable", False, True, ("you", "dns_down")),
    ("unreachable", True, False, ("you", "no_internet")),
])
def test_start_without_server_address(world, kind, system_dns, online, expected):
    m = world.manager
    host = _named(world, "Amsterdam").host
    world.resolver.fail.add(host)
    world.resolver.fail_kind[host] = kind
    world.system_dns, world.online = system_dns, online
    with pytest.raises(mgr.VpnClientError, match="Не удалось узнать адрес"):
        m.start()
    assert m.snapshot()["status"] == "error" and _diagnosis(m) == expected
    assert host not in str(m.snapshot()), "имя сервера в состояние не попадает"


@pytest.mark.parametrize("line, expected", [
    ("FATAL[0000] start service: start inbound/tun[tun-in]: create tun: Cannot create a file when that file "
     "already exists.", ("you", "conflict")),
    ("FATAL[0000] start service: start inbound/tun[tun-in]: configure tun interface: Access is denied.",
     ("you", "admin")),                     # права у Лазейки есть — запретили Windows, антивирус или чужой VPN
    ("FATAL[0000] initialize outbound[3]: decode public_key: illegal base64 data at input byte 8",
     ("provider", "bad_params")),
    ("FATAL[0000] decode config at C:\\x\\sing-box.json: route.bogus: json: unknown field \"bogus\"",
     ("lazeyka", "core_failed")),
])
def test_start_core_failure_names_the_side(world, line, expected):
    m = world.manager
    world.start_failures = [line]
    with pytest.raises(mgr.VpnClientError):
        m.start()
    assert _diagnosis(m) == expected


def test_own_refusals_have_no_reason(tmp_path):
    m, w = make_manager(tmp_path, FakeStore())
    with pytest.raises(mgr.VpnClientError, match="включать пока нечего"):
        m.start()
    snap = m.snapshot()
    assert snap["status"] == "error" and snap["diagnosis"] is None, "текст отказа сам говорит, что делать"
    m.shutdown()


def test_stop_and_restart_clear_the_reason(world):
    m = world.manager
    world.exit_ok = False
    m.start()
    assert m.snapshot()["diagnosis"] is not None
    m.stop()
    assert m.snapshot()["diagnosis"] is None


# ------------------------------------------------------------ ядро упало

def test_crash_of_core_is_lazeyka(world):
    m = world.manager
    m.start()
    m._session.main.crash()                        # сразу после запуска — без автоматического перезапуска
    assert m.wait_idle(10)
    assert m.snapshot()["status"] == "error" and _diagnosis(m) == ("lazeyka", "core_failed")


def test_crash_of_helper_is_lazeyka(tmp_path):
    store = basic_store(xhttp=True)
    store.select(next(s.id for s in store.servers() if s.name == "Helsinki"))
    m, w = make_manager(tmp_path, store)
    w.engines.allowed = False
    m.start()
    m._session.helper.crash(line="Failed to start: something went wrong")
    assert m.wait_idle(10)
    assert _diagnosis(m) == ("lazeyka", "helper_failed")
    m.shutdown()


# ------------------------------------------------------------ проверка задержки

def test_latency_reasons_on_running_core(world):
    m = world.manager
    m.start()
    _silent(world, "Berlin", "Helsinki")
    world.tcp[_addr(world, "Berlin")] = "refused"
    world.handshakes[_addr(world, "Helsinki")] = "reset"
    _measure(m)
    assert _reason(world, "Berlin") == ("provider", "port_closed")
    assert _reason(world, "Helsinki") == ("isp", "dpi")
    assert _reason(world, "Amsterdam") is None and _reason(world, "Other") is None
    shown = {s["name"]: s["latency"] for s in m.snapshot()["servers"]}
    assert shown["Berlin"]["reason"]["code"] == "port_closed" and shown["Berlin"]["error"]
    assert shown["Amsterdam"]["reason"] is None
    assert world.store.calls.count(("save",)) >= 1


def test_latency_whole_subscription_silent_is_honest_about_both_sides(world):
    m = world.manager
    names = ("Amsterdam", "Berlin", "Helsinki", "Other")
    _silent(world, *names)
    for name in names:
        world.tcp[_addr(world, name)] = "timeout"
    _measure(m)
    for name in ("Amsterdam", "Berlin", "Helsinki"):
        assert _reason(world, name) == ("unknown", "all_down"), name
    assert _reason(world, "Other") == ("unknown", "tcp_timeout"), "одинокий сервер своей подписки — сравнить не с кем"


def test_latency_probes_are_limited(world, monkeypatch):
    monkeypatch.setattr(mgr, "PROBE_LIMIT", 2)
    m = world.manager
    names = ("Amsterdam", "Berlin", "Helsinki")
    _silent(world, *names)
    for name in names:
        world.tcp[_addr(world, name)] = "timeout"
    _measure(m, [_named(world, n).id for n in names])
    assert len([p for p in world.probes if p[0] == "tcp"]) == 2
    assert all(_reason(world, n) == ("unknown", "all_down") for n in names), "без пробы — по соседям"


def test_latency_without_internet_makes_no_probes(world):
    m = world.manager
    world.online = False
    _silent(world, "Amsterdam", "Berlin")
    _measure(m)
    assert world.probes == []
    assert _reason(world, "Amsterdam") == ("you", "no_internet") and _reason(world, "Berlin") == ("you", "no_internet")
    assert _reason(world, "Helsinki") is None


def _udp_world(tmp_path, *, udp_peer_ok):
    store = basic_store()
    for name in ("Hy", "Tu"):
        s = Server("hysteria2", f"{name.lower()}.example.com", 443, name=name, password="p" + name, security="tls",
                   tls={"sni": "www.example.com"}, sub="s-1")
        s.id = s.key()
        store._servers[s.id] = s
    m, w = make_manager(tmp_path, store)
    w.engines.allowed = False
    _silent(w, "Hy") if udp_peer_ok else _silent(w, "Hy", "Tu")
    return m, w


def test_latency_core_names_rejected_key_of_silent_server(tmp_path):
    """Сервер Hysteria2 отказывает в ключе лишь через ~10 с — дольше замера: clash API говорит «ошибка в проверке
    задержки», и раньше страница писала «UDP-сервер молчит · не ясно». Теперь Лазейка спрашивает ядро замера
    отдельным запросом через его вход разбора, и журнал ядра называет отказ."""
    m, w = _udp_world(tmp_path, udp_peer_ok=True)
    hy = _named(w, "Hy")
    tag = w.config.tag(hy.id)
    w.core_says[tag] = (f"ERROR [1 10.5s] connection: open connection to www.gstatic.com:443 using "
                        f"outbound/hysteria2[{tag}]: authentication failed, status code: 404")
    _measure(m, [hy.id])
    assert ("ask", tag) in w.probes
    assert _reason(w, "Hy") == ("provider", "auth_rejected")
    m.shutdown()


# Журнал Xray 26.3.27 уровня info при вопросе ядру (сняты с настоящего ядра: отказ в ключе Hysteria2 сервером
# sing-box и чужой сертификат у VLESS gRPC; соединения перемешаны, тегов в строках отказа нет).
XRAY_TAIL = [
    "2026/11/10 06:47:23.750685 [Warning] common/errors: The feature gRPC transport (with unnecessary costs, etc.) "
    "is deprecated, not recommended for using and might be removed.",
    "2026/11/10 06:47:24.573924 [Info] [3307873727] proxy/socks: TCP Connect request to tcp:www.gstatic.com:443",
    "2026/11/10 06:47:24.573924 [Info] [3307873727] app/dispatcher: taking detour [out-grpc] for "
    "[tcp:www.gstatic.com:443]",
    "2026/11/10 06:47:24.573924 [Info] [3203454497] app/dispatcher: taking detour [out-kcp] for "
    "[tcp:www.gstatic.com:443]",
    "2026/11/10 06:47:24.573924 [Info] [3203454497] proxy/vless/outbound: tunneling request to "
    "tcp:www.gstatic.com:443 via 127.0.0.1:61223",
    "2026/11/10 06:47:24.573924 [Info] [3419092343] app/dispatcher: taking detour [out-hy] for "
    "[tcp:www.gstatic.com:443]",
    "2026/11/10 06:47:24.589031 [Info] [3419092343] app/proxyman/outbound: app/proxyman/outbound: failed to process "
    "outbound traffic > proxy/hysteria: failed to find an available destination > transport/internet/hysteria: "
    "auth failed",
    "2026/11/10 06:47:24.793559 [Info] [3307873727] transport/internet/grpc: creating connection to "
    "tcp:127.0.0.1:59158",
    "2026/11/10 06:47:26.594281 [Info] [3307873727] app/proxyman/outbound: app/proxyman/outbound: failed to process "
    "outbound traffic > proxy/vless/outbound: failed to find an available destination > common/retry: "
    "[transport/internet/grpc: failed to dial gRPC > transport/internet/grpc: Cannot dial gRPC > rpc error: code = "
    "Unavailable desc = connection error: desc = \"transport: failed to write client preface: tls: failed to verify "
    "certificate: x509: certificate signed by unknown authority\"] > common/retry: all retry attempts failed",
]


def test_xray_log_names_reason_by_connection():
    """В строках отказа Xray нет тега выхода: выход соединения — по «taking detour», отказ — тем же номером.
    Молчащий сервер (mKCP) отказа не пишет — причину назовут прямые пробы."""
    assert mgr.xray_lines(XRAY_TAIL, "out-kcp") == []
    grpc = mgr.xray_lines(XRAY_TAIL, "out-grpc")
    assert len(grpc) == 1 and "[3307873727]" in grpc[0] and "x509" in grpc[0]
    proc = type("Proc", (), {"tail": XRAY_TAIL})()
    assert mgr.core_hints(proc, ["out-hy", "out-grpc", "out-kcp"], time.monotonic(), mgr.xray_lines) \
        == {"out-hy": "auth", "out-grpc": "tls"}


@pytest.mark.parametrize("says, want", [
    ("proxy/hysteria: failed to find an available destination > transport/internet/hysteria: auth failed",
     ("provider", "auth_rejected")),
    ("proxy/hysteria: failed to find an available destination > tls: failed to verify certificate: x509: "
     "certificate signed by unknown authority", ("provider", "keys_outdated")),
])
def test_latency_xray_server_reason_from_helper_log(tmp_path, says, want):
    """Сервер помощника Xray (Hysteria2 с закреплённым сертификатом): вопрос — тем же входом разбора через sing-box,
    причина — из журнала помощника замера, который для этого пишет уровнем info."""
    m, w = _udp_world(tmp_path, udp_peer_ok=True)
    hy = _named(w, "Hy")
    hy.hy2 = {"pin_sha256": "ab" * 32}
    tag = w.config.tag(hy.id)
    w.xray_says[tag] = says
    _measure(m, [hy.id])
    assert ("ask", tag) in w.probes
    assert w.config.xray_kw == {"loglevel": "info"}
    assert _reason(w, "Hy") == want
    m.shutdown()


def test_latency_progress_names_reasons_phase(tmp_path):
    """Задержки сняты, а причина у молчащих ещё выясняется (до ~20 с) — окно пишет «Уточняем причину у N…», а не
    «Проверяем N из N…», будто зависло."""
    m, w = _udp_world(tmp_path, udp_peer_ok=True)
    seen = []
    ask = m.deps.ask_core

    def spy(*args):
        seen.append(dict(m.snapshot()["latency"]))
        ask(*args)

    m.deps.ask_core = spy
    _measure(m)
    assert seen and all(s["why"] == 1 and s["done"] == s["total"] for s in seen)
    assert m.snapshot()["latency"]["why"] == 0
    m.shutdown()


@pytest.mark.parametrize("quic, control, want", [
    ("answer", True, ("unknown", "udp_handshake")),
    ("silent", True, ("unknown", "udp_server_silent")),
    ("silent", False, ("isp", "udp_blocked")),
    ("closed", True, ("provider", "port_closed")),
])
def test_latency_udp_server_probed_directly(tmp_path, quic, control, want):
    """Сервер на QUIC молчит, а ядро причины не назвало: прямая проба QUIC (у Hysteria2 с salamander — с паролем
    обфускации) и, если сервер молчит, эталон QUIC — проходит ли UDP вообще."""
    m, w = _udp_world(tmp_path, udp_peer_ok=False)
    hy = _named(w, "Hy")
    hy.hy2 = {"obfs": "salamander", "obfs_password": "obfs-pw"}
    w.quic[_addr(w, "Hy")] = quic
    w.quic_control = control
    _measure(m, [hy.id])
    assert ("quic", _addr(w, "Hy"), "obfs-pw") in w.probes
    assert _reason(w, "Hy") == want
    m.shutdown()


def test_latency_udp_blocked_when_tcp_answers(tmp_path):
    m, w = _udp_world(tmp_path, udp_peer_ok=False)
    _measure(m)
    assert _reason(w, "Hy") == ("isp", "udp_blocked") and _reason(w, "Tu") == ("isp", "udp_blocked")
    assert ("tcp", _addr(w, "Hy")) not in w.probes, "у протоколов на UDP прямой пробы TCP нет"
    m.shutdown()


def test_latency_udp_server_down_when_other_udp_answers(tmp_path):
    m, w = _udp_world(tmp_path, udp_peer_ok=True)
    _measure(m)
    assert _reason(w, "Hy") == ("provider", "server_down")
    m.shutdown()


def test_latency_dns_missing_for_server_without_address(world):
    m = world.manager
    other = _named(world, "Other")
    world.resolver.fail.add(other.host)
    world.resolver.fail_kind[other.host] = "nxdomain"
    _measure(m)
    assert world.store.latency()[other.id]["error"] == "адрес сервера не получен через DNS"
    assert _reason(world, "Other") == ("provider", "dns_missing")


def test_latency_unbuildable_server_is_lazeyka_and_not_a_silent_peer(world):
    m = world.manager
    broken = _named(world, "Berlin")
    real_build = world.config.build_delay

    def build_delay(plan):
        if any(s.id == broken.id for s in plan.servers):
            raise UserError("у сервера битый pbk")
        return real_build(plan)

    world.config.build_delay = build_delay
    _silent(world, "Amsterdam")
    world.tcp[_addr(world, "Amsterdam")] = "timeout"
    _measure(m, [_named(world, n).id for n in ("Amsterdam", "Berlin")])
    assert _reason(world, "Berlin") == ("lazeyka", "unsupported")
    assert _reason(world, "Amsterdam") == ("unknown", "tcp_timeout"), \
        "Berlin не мерили — его «ошибка» не значит, что молчит вся подписка"
    assert ("tcp", _addr(world, "Berlin")) not in world.probes


def test_latency_kill_switch_is_not_a_silent_server(tmp_path):
    a, b = server("Amsterdam"), server("Berlin")
    helper_only = server("Xhttp", sub="s-2", network="xhttp")
    subs = [Subscription(id="s-1", name="A", url="https://a.example/x1TOKEN", added_at=1.76e9, updated_at=1.76e9),
            Subscription(id="s-2", name="B", url="https://b.example/x2TOKEN", added_at=1.76e9, updated_at=1.76e9)]
    m, w = make_manager(tmp_path, FakeStore([a, b, helper_only], subs, [], selected=a.id))
    w.engines.allowed = False
    w.settings.update(lambda d: d["vpnclient"].__setitem__("kill_switch", True))
    m.start()
    _measure(m, [helper_only.id])
    assert _reason(w, "Xhttp") == ("lazeyka", "killswitch")
    assert w.probes == [], "не мерили — не пробуем"
    m.shutdown()


def test_reason_failure_keeps_latency(world, caplog):
    m = world.manager

    def broken():
        raise RuntimeError("сломалось")

    m.deps.online = broken
    _silent(world, "Berlin")
    _measure(m)
    entry = world.store.latency()[_named(world, "Berlin").id]
    assert entry["error"] and "reason" not in entry
    assert not any("Задержку проверить не удалось" in text for _level, text in world.notices)
    assert "Причины «нет ответа» не определены" in caplog.text


def test_snapshot_shows_reason_only_with_error(world):
    m = world.manager
    berlin = _named(world, "Berlin")
    good = {"side": "isp", "code": "dpi", "text": "т", "advice": "с"}
    world.store._latency[berlin.id] = {"ms": 50, "at": 1.0, "error": None, "reason": good}
    assert next(s for s in m.snapshot()["servers"] if s["name"] == "Berlin")["latency"]["reason"] is None
    world.store._latency[berlin.id] = {"ms": None, "at": 1.0, "error": "нет ответа", "reason": {"side": "чужая"}}
    assert next(s for s in m.snapshot()["servers"] if s["name"] == "Berlin")["latency"]["reason"] is None
    world.store._latency[berlin.id] = {"ms": None, "at": 1.0, "error": "нет ответа", "reason": good}
    assert next(s for s in m.snapshot()["servers"] if s["name"] == "Berlin")["latency"]["reason"] == good
