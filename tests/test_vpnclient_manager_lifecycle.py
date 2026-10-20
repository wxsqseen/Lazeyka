"""Свой VPN: изменения во время включения и выключения, повторы после падения, выход и плашки после смены
сервера, подписки, ссылки lazeyka:// и маршруты загрузок — на подделках (ядро не запускается, систему не
трогаем)."""
import base64
import json
import threading
import urllib.request

import pytest

from app import __version__
from app import vpn
from app.vpnclient import engines as real_engines
from app.vpnclient import manager as mgr
from app.vpnclient.model import Group, Subscription
from app.vpnclient.process import ProcessError
from tests.fakes.vpn_world import FakeProcess, FakeSubscription, basic_store, make_manager, server, wait_for

LINK_A = ("vless://22222222-3333-4444-8555-666666666666@203.0.113.77:443?security=reality&sni=www.example.com"
          "&pbk=wMTJ9bV1x6qRdnQk2eBcUJbQ8Wl0Jp0r3o0t5s6Y7m4&sid=ab&fp=chrome&type=tcp#A")
LINK_B = ("vless://33333333-4444-4555-8666-777777777777@203.0.113.78:443?security=reality&sni=www.example.com"
          "&pbk=wMTJ9bV1x6qRdnQk2eBcUJbQ8Wl0Jp0r3o0t5s6Y7m4&sid=ab&fp=chrome&type=tcp#B")


@pytest.fixture
def world(tmp_path):
    manager, w = make_manager(tmp_path, basic_store())
    yield w
    manager.shutdown()


def _start_while_core_downloads(world):
    """Ядра нет на диске, подкачка «идёт»: включение ждёт её в статусе starting."""
    gate = threading.Event()
    world.engines.versions["sing-box"].clear()
    world.engines.install_gate = gate
    thread = threading.Thread(target=world.manager.start, daemon=True)
    thread.start()
    assert wait_for(lambda: world.manager.status == "starting")
    return gate, thread


def _finish(world, gate, thread):
    gate.set()
    thread.join(10)
    assert world.manager.wait_idle(10)


def _subscription(world):
    fake = FakeSubscription()
    world.manager.deps.modules["subscription"] = fake
    return fake


def _lazeyka_ua(world, fake, sub_id="s-1"):
    return fake.real.user_agent(world.store.subscription(sub_id), __version__)


# ------------------------------------------------------------ выключение и смена режима

def test_mode_change_while_stopping_does_not_turn_vpn_back_on(world, monkeypatch):
    m = world.manager
    m.start()
    gate = threading.Event()
    original = FakeProcess.stop

    def slow_stop(self, soft=2.0):
        if self.name == "sing-box":
            gate.wait(10)
        return original(self, soft)

    monkeypatch.setattr(FakeProcess, "stop", slow_stop)
    stopper = threading.Thread(target=m.stop, daemon=True)
    stopper.start()
    assert wait_for(lambda: m.status == "stopping")
    m.set_mode("local")                                     # «Выключить», а потом — другой режим
    gate.set()
    stopper.join(10)
    assert m.wait_idle(10)
    assert m.status == "stopped" and m._session is None, "VPN не включается сам после «Выключить»"
    assert world.settings.get("vpnclient", "mode") == "local"


def test_automatic_restart_without_session_starts_nothing(world):
    m = world.manager
    m.start()
    m.stop()
    m._restart_job()                                        # переподключение дождалось очереди уже после «Выключить»
    assert m.status == "stopped" and m._session is None
    assert m.restart()["verified"] is True, "«Переподключить» включает и выключенный"


# ------------------------------------------------------------ изменения, пока идёт включение

def test_select_while_starting_switches_after_start(world):
    m = world.manager
    first = world.store.selected()
    other = next(s.id for s in world.store.servers() if s.sub == "s-1" and s.id != first)
    gate, thread = _start_while_core_downloads(world)
    m.select(other)
    _finish(world, gate, thread)
    assert m.status == "running" and m._session.active == other
    assert m.snapshot()["selected"]["id"] == other


def test_mode_change_while_starting_reconnects_in_the_new_mode(world):
    m = world.manager
    gate, thread = _start_while_core_downloads(world)
    m.set_mode("proxy")
    _finish(world, gate, thread)
    assert m.status == "running" and m._session.plan.mode == "proxy"
    assert m.snapshot()["mode"] == "proxy" and m.snapshot()["listen"]


def test_settings_change_while_starting_reconnects_with_them(world):
    m = world.manager
    gate, thread = _start_while_core_downloads(world)
    assert m.save_settings({"tls_fragment": True}) == {}
    _finish(world, gate, thread)
    assert m.status == "running" and m._session.plan.tls_fragment is True


def test_subscription_mtu_change_while_starting_reconnects(world):
    m = world.manager
    gate, thread = _start_while_core_downloads(world)
    assert m.sub_set("s-1", {"mtu": 1400}) == {}
    _finish(world, gate, thread)
    assert m.status == "running" and m._session.plan.tun.mtu == 1400


def test_removing_subscription_while_starting_stops_and_forgets(world):
    m = world.manager
    gate, thread = _start_while_core_downloads(world)
    m.sub_remove("s-1")
    _finish(world, gate, thread)
    assert m.status == "stopped" and m._session is None
    assert world.settings.get("vpnclient", "was_running") is False


def test_removing_subscription_in_use_forgets_was_running(world):
    """Удалили подписку, на которой работал VPN: при следующем запуске Лазейки он не включится сам на первом
    сервере другой подписки."""
    m = world.manager
    m.start()
    assert world.settings.get("vpnclient", "was_running") is True
    m.sub_remove("s-1")
    assert m.wait_idle(10)
    assert m.status == "stopped" and world.settings.get("vpnclient", "was_running") is False


def _quiet(fn):
    try:
        fn()
    except mgr.VpnClientError:
        pass                                    # отказ включения — тоже ответ; проверяем состояние


def _failing_start_with_leftover_killswitch(world):
    """Kill switch остался после падения (сеанса нет, интернет закрыт), а включение ждёт ядро и не удастся."""
    world.settings.update(lambda d: d["vpnclient"].update(mode="tun", kill_switch=True))
    world.killswitch.active = True
    gate = threading.Event()
    world.engines.versions["sing-box"].clear()
    world.engines.install_gate = gate
    world.engines.install_errors = [real_engines.EngineError("не скачалось")]
    starter = threading.Thread(target=lambda: _quiet(world.manager.start), daemon=True)
    starter.start()
    assert wait_for(lambda: world.manager.status == "starting")
    return gate, starter


def test_proxy_mode_during_failed_start_drops_leftover_killswitch(world):
    """Контракт vpnclient_set_mode: без сеанса и не в tun kill switch, оставшийся после падения, снимается —
    и тогда, когда режим сменили посреди включения, а включение не удалось."""
    m = world.manager
    gate, starter = _failing_start_with_leftover_killswitch(world)
    m.set_mode("proxy")
    gate.set()
    starter.join(10)
    assert m.wait_idle(10)
    assert m._session is None and m.status == "error"
    assert not world.killswitch.active, "режим прокси, VPN не включился — интернет не должен остаться закрытым"


def test_mode_returned_to_tun_keeps_killswitch_after_failed_start(world):
    """Вернули «Весь трафик» раньше, чем очередь дошла до проверки: kill switch держит интернет, как положено."""
    m = world.manager
    gate, starter = _failing_start_with_leftover_killswitch(world)
    m.set_mode("proxy")
    m.set_mode("tun")
    gate.set()
    starter.join(10)
    assert m.wait_idle(10)
    assert m._session is None and world.killswitch.active


# ------------------------------------------------------------ свой прокси с «Пускать устройства из сети»

def test_own_proxy_with_lan_is_recognized_as_own(world):
    m = world.manager
    world.settings.update(lambda d: d["vpnclient"].update(mode="proxy", allow_lan=True))
    m._auth.save({"user": "u1", "password": "p1"})
    m.start()
    own = m.own()
    assert m._session.plan.proxy_listen == "0.0.0.0", "ядро слушает и сеть"
    assert own.proxy == world.sysproxy.applied == f"127.0.0.1:{m._session.plan.ports.proxy}"
    assert vpn.same_proxy(world.sysproxy.applied, own.proxy), "свой прокси — не чужой VPN"
    assert m.snapshot()["listen"] == own.proxy


@pytest.mark.parametrize("mode", ["tun", "proxy"])
def test_lan_without_password_listens_only_on_this_pc(world, mode):
    """«Пускать устройства из сети», а логина и пароля нет (local-proxy.json пропал): без пароля в сеть не
    пускаем никогда — вход только для этого компьютера и постоянная плашка; задали пароль — сеть открылась."""
    m = world.manager
    world.settings.update(lambda d: d["vpnclient"].update(mode=mode, allow_lan=True))
    m.start()
    plan = m._session.plan
    assert plan.proxy_listen == "127.0.0.1" and not (plan.secrets.local_user or plan.secrets.local_pass)
    alert = world.alerts["vpn-local-auth"]
    assert "Пароль для устройств из сети пропал" in alert["text"] and alert["page"] == "vpnclient"
    assert m.save_settings({"local_user": "u1", "local_password": "p1"}) == {}
    assert m.wait_idle(10) and m.status == "running"
    plan = m._session.plan
    assert plan.proxy_listen == "0.0.0.0" and (plan.secrets.local_user, plan.secrets.local_pass) == ("u1", "p1")
    assert "vpn-local-auth" not in world.alerts


def test_local_password_lost_in_proxy_mode_shows_alert_for_the_session(world):
    """Вход по паролю для программ этого компьютера, а пароля нет: прокси работает без него (только этот
    компьютер) — и плашка об этом. Выключили VPN — плашка сеанса снята."""
    m = world.manager
    world.settings.update(lambda d: d["vpnclient"].update(mode="proxy", local_auth=True))
    m.start()
    assert m._session.plan.proxy_listen == "127.0.0.1"
    assert "без него" in world.alerts["vpn-local-auth"]["text"]
    m.stop()
    assert "vpn-local-auth" not in world.alerts


# ------------------------------------------------------------ маршрут «через своё ядро» для файлов правил

def test_core_route_goes_through_own_core(tmp_path):
    manager, w = make_manager(tmp_path, basic_store(), opener=None)
    try:
        assert manager.opener_for("core") is None, "ядро выключено — маршрута нет, а не «напрямую»"
        manager.start()
        opener = manager.opener_for("core")
        proxies = [h.proxies for h in opener.handlers if isinstance(h, urllib.request.ProxyHandler)]
        port = manager._session.plan.ports.internal
        assert len(proxies) == 1 and all(f"@127.0.0.1:{port}" in url for url in proxies[0].values())
        with pytest.raises(mgr.VpnClientError, match="Неизвестный маршрут"):
            manager.opener_for("other")
    finally:
        manager.shutdown()


# ------------------------------------------------------------ подписка обновилась, а конфиг прежний

def test_outdated_config_reconnects_when_server_goes_silent(world):
    m = world.manager
    fake = _subscription(world)
    m.start()
    session = m._session
    active = session.active
    fresh = []
    for s in world.store.servers():
        if s.sub != "s-1":
            continue
        copy = server(s.name)
        if s.id == active:
            copy.tls = dict(copy.tls, pbk="NEW-KEY")              # провайдер сменил ключ REALITY: id тот же
        fresh.append(copy)
    fake.answers[_lazeyka_ua(world, fake)] = fake.real.Decoded(format="links", servers=fresh)
    assert m._update_sub("s-1", announce=False)["error"] is None
    assert m._session is session and session.outdated, "туннель, пока работает, не рвём"
    world.delays[world.config.tag(active)] = None             # прежний ключ больше не пускает
    m._check_health()
    m._check_health()
    assert m.wait_idle(10)
    assert m._session is not session and not m._session.outdated
    plan_server = next(s for s in m._session.plan.servers if s.id == active)
    assert plan_server.tls["pbk"] == "NEW-KEY", "переподключение — с параметрами из подписки"


def _remove_active_from_subscription(world, fake, *, extra=()):
    """Провайдер убрал из подписки активный сервер (Amsterdam), остальные — как были (и extra в придачу)."""
    m = world.manager
    active = m._session.active
    rest = [server(s.name) for s in world.store.servers() if s.sub == "s-1" and s.id != active] + list(extra)
    fake.answers[_lazeyka_ua(world, fake)] = fake.real.Decoded(format="links", servers=rest)
    assert m._update_sub("s-1", announce=False)["error"] is None
    assert m._session.outdated and world.store.server(active) is None
    return active


def test_removed_active_server_switches_to_live_neighbour(world):
    """Убранный сервер замолчал (его и убрали потому, что выключили): VPN переходит на живого соседа по
    работающему конфигу, без перезапуска, — а не перезапускается с выбором, которого в подписке больше нет
    (раньше: «Выбранный сервер пропал из подписки» и повторы раз в 5 минут, с kill switch — без интернета)."""
    m = world.manager
    fake = _subscription(world)
    m.start()
    session = m._session
    active = _remove_active_from_subscription(world, fake)
    world.delays[world.config.tag(active)] = None
    m._check_health()
    m._check_health()
    assert m.wait_idle(10)
    assert m.status == "running" and m._session is session, "переход — внутри работающего конфига"
    assert session.active != active and world.store.selected() == session.active
    assert world.store.server(session.active) is not None, "выбран сервер, который в подписке остался"
    assert any("перестал отвечать" in text for _, text in world.notices)


def test_removed_server_without_live_neighbour_reconnects_with_replacement(world):
    """Живых соседей в старом конфиге нет — перезапуск с новыми параметрами, и выбор сам заменяется на
    «Самый быстрый» подписки (подделка хранилища не предлагает замену) — с уведомлением."""
    m = world.manager
    fake = _subscription(world)
    m.start()
    session = m._session
    active = _remove_active_from_subscription(world, fake)
    for s in session.plan.servers:
        world.delays[world.config.tag(s.id)] = None                # молчит весь старый конфиг
    m._check_health()
    m._check_health()
    assert m.wait_idle(10)
    assert m.status == "running" and m._session is not session and not m._session.outdated
    assert world.store.selected() == "auto:s-1" and m._session.active == "auto:s-1"
    assert any("С «Amsterdam» свой VPN больше не включить: этого сервера в подписке больше нет" in text
               and "переподключаемся" in text for _, text in world.notices)
    assert m._retry_at is None and "vpn-crash" not in world.alerts


def test_lost_selection_is_replaced_by_store_suggestion(tmp_path):
    """Настоящее хранилище предлагает замену при слиянии (первый сервер или группа исчезнувшего): перезапуск
    после замолчавшего сервера берёт её."""
    from app.vpnclient.store import ProfileStore
    store = ProfileStore(tmp_path / "profiles.json")
    store.add_subscription(Subscription(id="s-1", name="Мой VPN", url="https://sub.example.com/T1",
                                        added_at=mgr.time.time(), updated_at=mgr.time.time()))
    m, w = make_manager(tmp_path, store)
    try:
        fake = _subscription(w)
        ua = _lazeyka_ua(w, fake)
        fake.answers[ua] = fake.real.Decoded(format="links", servers=[server("Amsterdam", sub=None),
                                                                      server("Berlin", sub=None)])
        assert m._update_sub("s-1", announce=False)["error"] is None
        amsterdam = next(s for s in store.servers() if s.name == "Amsterdam")
        store.select(amsterdam.id)
        m.start()
        session = m._session
        fake.answers[ua] = fake.real.Decoded(format="links", servers=[server("Berlin", sub=None)])
        assert m._update_sub("s-1", announce=False)["error"] is None
        berlin = store.servers()[0]
        assert store.selected() == amsterdam.id, "подключение пока работает — выбор не трогаем"
        for s in session.plan.servers:
            w.delays[w.config.tag(s.id)] = None
        m._check_health()
        m._check_health()
        assert m.wait_idle(10)
        assert m.status == "running" and store.selected() == berlin.id and m._session.active == berlin.id
    finally:
        m.shutdown()


def test_lost_selection_without_replacement_is_not_retried_in_a_loop(world):
    """Заменить нечем (в подписке остался сервер, которого не открыть): с тем же выбором перезапуск не
    удастся никогда — без повторов раз в 5 минут, плашка просит выбрать сервер."""
    m = world.manager
    fake = _subscription(world)
    m.start()
    quic = server("Quic", network="quic")                       # QUIC-транспорт не открыть ни одним ядром
    fake.answers[_lazeyka_ua(world, fake)] = fake.real.Decoded(format="links", servers=[quic])
    assert m._update_sub("s-1", announce=False)["error"] is None
    assert m._session.outdated
    world.delays[world.config.tag(m._session.active)] = None
    m._check_health()
    m._check_health()
    assert m.wait_idle(10)
    assert m.status == "error" and m._retry_at is None, "детерминированный отказ не повторяется"
    alert = world.alerts["vpn-crash"]
    assert "пропал из подписки" in alert["text"] and "Повторим" not in alert["text"]
    assert alert["action"] == {"label": "Выбрать сервер", "page": "vpnclient"}


def test_config_that_cannot_be_built_is_not_retried_in_a_loop(world, monkeypatch):
    """Конфиг для выбранного сервера не собрать даже без соседей (ConfigError, вид unsupported): с теми же
    параметрами автоматический перезапуск не удастся никогда — без «Повторим», плашка просит выбрать сервер."""
    from app.vpnclient.config import ConfigError
    m = world.manager
    m.start()

    def broken(plan):
        raise ConfigError("у сервера параметры, из которых конфиг не собрать")

    monkeypatch.setattr(world.config, "build_singbox", broken)
    with pytest.raises(mgr.VpnClientError):
        m._restart_job()
    assert m.status == "error" and m._retry_at is None
    assert world.alerts["vpn-crash"]["action"] == {"label": "Выбрать сервер", "page": "vpnclient"}


def test_unchanged_subscription_does_not_mark_session_outdated(world):
    m = world.manager
    fake = _subscription(world)
    m.start()
    same = [server(s.name) for s in world.store.servers() if s.sub == "s-1"]
    fake.answers[_lazeyka_ua(world, fake)] = fake.real.Decoded(format="links", servers=same)
    m._update_sub("s-1", announce=False)
    assert not m._session.outdated


# ------------------------------------------------------------ ссылки lazeyka://

def test_deeplink_with_wrapped_subscription(world):
    m = world.manager
    m.deeplink_offer("lazeyka://import/https://sub.example.org/secret-token-123456")
    request = m.snapshot()["deeplink_request"]
    assert request["kind"] == "subscription" and "sub.example.org" in request["summary"]
    assert "secret-token-123456" not in json.dumps(m.snapshot())


def test_deeplink_with_base64_counts_servers_and_imports_them(world):
    m = world.manager
    packed = base64.urlsafe_b64encode(f"{LINK_A}\n{LINK_B}".encode()).decode().rstrip("=")
    m.deeplink_offer(f"lazeyka://import/{packed}")
    request = m.snapshot()["deeplink_request"]
    assert request["kind"] == "links" and request["summary"] == "Ссылок на серверы: 2"
    before = len(world.store.servers())
    m.deeplink_confirm(request["token"], True)
    assert wait_for(lambda: not m.snapshot()["import"]["running"])
    assert len(world.store.servers()) == before + 2, m.snapshot()["import"]


@pytest.mark.parametrize("link", ["lazeyka://connect", "https://sub.example.org/x", "lazeyka://import/"])
def test_deeplink_that_is_not_import_is_refused(world, link):
    m = world.manager
    m.deeplink_offer(link)
    assert m.snapshot()["deeplink_request"] is None
    assert world.notices and world.notices[-1][0] == "warn" and "lazeyka://" in world.notices[-1][1]


def test_deeplink_without_servers_is_refused(world):
    m = world.manager
    m.deeplink_offer("lazeyka://import/" + base64.b64encode(b"just some text").decode())
    assert m.snapshot()["deeplink_request"] is None and world.notices[-1][0] == "warn"


# ------------------------------------------------------------ падение и повторы

def test_failed_restart_after_crash_is_retried(world):
    m = world.manager
    world.settings.update(lambda d: d["vpnclient"].__setitem__("kill_switch", True))
    m.start()
    world.advance(120)
    main = next(p for p in world.processes if p.name == "sing-box" and p.alive())
    world.resolver.fail = {s.host for s in world.store.servers()}   # сеть ещё не поднялась после сбоя
    main.crash()
    assert m.wait_idle(10)
    assert m.status == "error" and m._retry_at is not None and world.killswitch.active
    assert "Повторим через 30 с" in world.alerts["vpn-crash"]["text"]
    world.resolver.fail = set()
    world.advance(31)
    m.tick()
    assert m.wait_idle(10) and m.status == "running"
    assert "vpn-crash" not in world.alerts


def test_crash_restart_failure_of_any_kind_is_retried(world, monkeypatch):
    """Не только UserError: OSError при перезапуске не оставляет плашку «перезапускаем» навсегда."""
    m = world.manager
    m.start()
    world.advance(120)
    main = next(p for p in world.processes if p.name == "sing-box" and p.alive())
    monkeypatch.setattr(m, "_plan_and_configs", lambda *a, **k: (_ for _ in ()).throw(OSError(28, "No space")))
    main.crash()
    assert m.wait_idle(10)
    assert m.status == "error" and m._retry_at is not None
    assert world.alerts["vpn-crash"]["level"] == "error" and "перезапускаем" not in world.alerts["vpn-crash"]["text"]


# ------------------------------------------------------------ группа без адресов, сверка exe, помощник

def test_group_without_any_resolved_member_is_a_dns_failure(tmp_path):
    store = basic_store()
    dublin = server("Dublin")                                 # сосед по подписке, не участник группы
    store._servers[dublin.id] = dublin
    store.select("auto:g-smart")
    m, w = make_manager(tmp_path, store)
    try:
        w.resolver.fail = {s.host for s in store.servers() if s.id in store.groups()[0].members}
        with pytest.raises(mgr.VpnClientError, match="ни одного сервера группы «Умная локация»"):
            m.start()
        snap = m.snapshot()
        assert snap["error_kind"] != "unsupported" and snap["diagnosis"]["side"] != "lazeyka"
        assert snap["diagnosis"]["code"] in ("dns_blocked", "dns_down", "dns_retry")
    finally:
        m.shutdown()


def test_changed_core_exe_does_not_leave_helper_running(tmp_path):
    store = basic_store(xhttp=True)
    store.select(next(s.id for s in store.servers() if s.network == "xhttp"))
    m, w = make_manager(tmp_path, store)
    try:
        real_verify, calls = w.engines.verify, []

        def verify(name, version=None):
            calls.append(name)
            if name == "sing-box" and calls.count("sing-box") > 1:   # exe подменили между сверками
                raise w.engines.EngineError("Ядро VPN (sing-box): файл sing-box.exe изменён")
            return real_verify(name, version)

        w.engines.verify = verify
        with pytest.raises(mgr.VpnClientError, match="изменён"):
            m.start()
        assert not any(p.name == "xray" and p.alive() for p in w.processes), "помощник без ядра не остаётся"
        assert not [p for p in w.processes if p.name == "xray"], "сверка — до старта помощника"
    finally:
        m.shutdown()


def test_helper_restart_failure_is_rechecked_and_cleared(tmp_path, monkeypatch):
    m, w = make_manager(tmp_path, basic_store(xhttp=True))
    try:
        m.start()
        original = FakeProcess.start

        def start(self, ready, timeout):
            if self.name == "xray":
                raise ProcessError("xray завершился при запуске (код 1)", code=1, tail=["Failed to start: x"])
            return original(self, ready, timeout)

        monkeypatch.setattr(FakeProcess, "start", start)
        m._restart_helper(m._session)
        snap = m.snapshot()
        assert snap["error"] and "Помощник Xray не перезапустился" in snap["error"]
        assert not snap["verified"], "«Подключено» рядом с ошибкой не показываем"
        m._check_health()                                      # перепроверка выхода снимает ошибку
        snap = m.snapshot()
        assert snap["verified"] and snap["error"] is None
    finally:
        m.shutdown()


# ------------------------------------------------------------ смена сервера: выход и плашки

def test_switch_to_fastest_rechecks_exit(world):
    m = world.manager
    m.start()
    active = m._session.active
    world.delays[world.config.tag(active)] = None
    m._exit = {"ip": "198.51.100.1", "country": "DE", "at": 1.0}          # выход прежнего сервера
    m._check_health()
    m._check_health()
    assert m._session.active != active
    assert m.snapshot()["exit"]["ip"] == "203.0.113.5", "выход перепроверен через новый сервер"


def test_server_alert_goes_away_after_choosing_fastest(world):
    m = world.manager
    m.start()
    for s in m._session.plan.servers:
        world.delays[world.config.tag(s.id)] = None
    m._check_health()
    m._check_health()
    assert "vpn-server" in world.alerts
    world.delays.clear()
    m.select("auto:g-smart")
    assert m.wait_idle(10) and m._session.active == "auto:g-smart"
    assert "vpn-server" not in world.alerts


def test_rules_alert_goes_away_when_preset_needs_no_lists(world):
    m = world.manager
    m._rules_failed("не скачаны geoip-ru", True, None)
    assert "vpn-rules" in world.alerts
    m.save_settings({"preset": "all"})
    m.start()
    assert m.wait_idle(10) and "vpn-rules" not in world.alerts


def test_restart_failure_text_keeps_sentences_apart(world):
    m = world.manager
    world.settings.update(lambda d: d["vpnclient"].__setitem__("kill_switch", True))
    m.start()
    m._error = "ядро не ответило"
    m._restart_failed(auto=False)
    assert m._error == "ядро не ответило. Kill switch держит интернет закрытым — выключите VPN, чтобы открыть."


# ------------------------------------------------------------ MTU с IPv6, помощник в режиме прокси, плашка ядра

def test_subscription_mtu_below_ipv6_minimum_is_raised_with_ipv6(world):
    m = world.manager
    world.store.update_subscription("s-1", mtu=1000)
    m.start()
    assert m._session.plan.tun.mtu == 1000, "без IPv6 — как задано у подписки"
    m.stop()
    world.settings.update(lambda d: d["vpnclient"].__setitem__("ipv6", True))
    m.start()
    assert m._session.plan.tun.mtu == mgr.IPV6_MIN_MTU


def test_network_change_in_proxy_mode_keeps_helper(tmp_path):
    store = basic_store(xhttp=True)
    store.select(next(s.id for s in store.servers() if s.network == "xhttp"))
    m, w = make_manager(tmp_path, store)
    try:
        w.settings.update(lambda d: d["vpnclient"].__setitem__("mode", "proxy"))
        m.start()
        m.on_network_change()
        assert m.wait_idle(5)
        assert [p.name for p in w.processes].count("xray") == 1, "без привязки к адаптеру перезапуск не нужен"
    finally:
        m.shutdown()


def test_core_alert_for_helper_counts_udp_noises(world):
    m = world.manager
    m._core_alert("xray", "Помощник Xray не скачался: нет связи.")
    assert "vpn-core:xray" not in world.alerts, "помощник пока никому не нужен"
    world.settings.update(lambda d: d["vpnclient"].__setitem__("noises", True))
    m._core_alert("xray", "Помощник Xray не скачался: нет связи.")
    assert "vpn-core:xray" in world.alerts, "с UDP-шумами он нужен всем серверам"


# ------------------------------------------------------------ подписки: адрес, итог, запасные адреса, маршруты

def test_same_subscription_address_in_other_spelling_updates_it(world):
    fake = _subscription(world)
    fake.answers[_lazeyka_ua(world, fake)] = fake.real.Decoded(
        format="links", servers=[server(s.name) for s in world.store.servers() if s.sub == "s-1"])
    outcome = world.manager._import_subscription("https://SUB.example.com/abc123TOKEN/", None)
    assert outcome["error"] is None and len(world.store.subscriptions()) == 2
    assert world.store.subscription("s-1").updated_at == 1.0, "обновилась та же подписка"


def test_update_summary_is_notified_only_by_button(world):
    m = world.manager
    fake = _subscription(world)
    servers = [server(s.name) for s in world.store.servers() if s.sub == "s-1"] + [server("Oslo")]
    fake.answers[_lazeyka_ua(world, fake)] = fake.real.Decoded(format="links", servers=servers)
    m._update_sub("s-1", announce="auto")
    assert not [text for _level, text in world.notices if text.startswith("Подписка обновлена")]
    servers.append(server("Rome"))
    m._update_sub("s-1", announce=True)
    assert [text for _level, text in world.notices if text.startswith("Подписка обновлена")] == \
        ["Подписка обновлена: +1 / −0"]


def test_fallback_address_is_used_when_main_is_unreachable(world):
    m = world.manager
    fake = _subscription(world)
    world.store.update_subscription("s-1", fallback_urls=["https://backup.example.net/abc123TOKEN"])
    asked = []
    ok = fake.real.Decoded(format="links", servers=[server(s.name) for s in world.store.servers() if s.sub == "s-1"])

    def fetch(url, *, user_agent, hwid=None, opener=None, **_kw):
        asked.append((url, opener))
        if "backup" not in url:
            raise fake.SubscriptionError("network", "Нет связи с адресом подписки", reason="drop")
        return fake.real.Fetched(200, {}, b"", url)

    fake.fetch = fetch
    fake.decode = lambda body, headers=None, *, sub_id=None, keep_local=False: ok
    assert m._update_sub("s-1", announce=False)["error"] is None
    assert [url for url, _ in asked] == ["https://sub.example.com/abc123TOKEN",
                                        "https://backup.example.net/abc123TOKEN"]
    assert world.store.subscription("s-1").fallback_urls == ["https://backup.example.net/abc123TOKEN"]


def test_fallback_is_not_tried_when_main_answered(world):
    m = world.manager
    fake = _subscription(world)
    world.store.update_subscription("s-1", fallback_urls=["https://backup.example.net/abc123TOKEN"])
    asked = []

    def fetch(url, *, user_agent, hwid=None, opener=None, **_kw):
        asked.append(url)
        raise fake.SubscriptionError("http_status", "Провайдер ответил 404", status=404)

    fake.fetch = fetch
    assert "404" in m._update_sub("s-1", announce=False)["error"]
    assert asked == ["https://sub.example.com/abc123TOKEN"], "адрес ответил — запасной не нужен"


def test_route_line_in_subscription_becomes_provider_profile(world):
    m = world.manager
    fake = _subscription(world)
    profile = {"Name": "Россия", "GlobalProxy": "true", "DirectSites": ["geosite:category-ru"]}
    line = "happ://routing/add/" + base64.b64encode(json.dumps(profile).encode()).decode()
    servers = [server(s.name) for s in world.store.servers() if s.sub == "s-1"]
    fake.answers[_lazeyka_ua(world, fake)] = fake.real.Decoded(format="links", servers=servers, route_lines=[line])
    m._update_sub("s-1", announce=False)
    stored = next(p for p in m._profiles.load() if p["id"] == "r-s-1")
    assert stored["text"] == line and stored["active"] is False, "включается только по согласию"
    public = next(p for p in m.snapshot()["routing_profiles"] if p["id"] == "r-s-1")
    assert public["summary"]["direct"] >= 1


def test_removing_other_subscription_while_starting_keeps_starting(world):
    """План ещё не собран (ядро скачивается) — чья подписка, решает выбор: чужую удалить можно."""
    m = world.manager
    gate, thread = _start_while_core_downloads(world)
    assert m._selected_sub() == "s-1"
    m.sub_remove("s-2")
    _finish(world, gate, thread)
    assert m.status == "running"
    world.store._groups.append(Group(id="g-x", sub="s-1", name="X", members=[]))
    world.store.select("auto:g-x")
    assert m._selected_sub() == "s-1"
    world.store._subs["s-3"] = Subscription(id="s-3", name="Третья", url="https://three.example.com/t")
    world.store.select("auto:s-3")
    assert m._selected_sub() == "s-3", "группа «вся подписка»"


def test_import_summary_counts_updated_servers(world):
    from app.vpnclient.store import MergeReport
    world.store.add_servers = lambda servers: MergeReport(added=["x"], updated=["y"])
    assert world.manager._add_servers([], "Добавлено серверов") == "Добавлено серверов: 1, обновлено: 1"
    world.store.add_servers = lambda servers: MergeReport(added=["x", "z"])
    assert world.manager._add_servers([], "Добавлено серверов") == "Добавлено серверов: 2"
