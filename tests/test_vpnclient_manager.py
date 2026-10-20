"""Свой VPN: машина состояний менеджера на подделках (ядро не запускается, систему не трогаем)."""
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from app import log as applog
from app.vpnclient import engines as real_engines
from app.vpnclient import manager as mgr
from app.vpnclient.manager import ZapretView
from app.vpnclient.model import Group
from tests.fakes.vpn_world import (FakeStore, FakeSubscription, PORT_BUSY, basic_store, make_manager, server,
                                  wait_for)

MOCK = Path(__file__).resolve().parent.parent / "app" / "ui" / "mock-vpnclient-state.json"


@pytest.fixture
def world(tmp_path):
    manager, w = make_manager(tmp_path, basic_store())
    yield w
    manager.shutdown()


def _main_processes(world):
    return [p for p in world.processes if p.name == "sing-box"]


# ------------------------------------------------------------ запуск по порядку 5.3.3

def test_start_order_filter_before_core_selectors_and_exit(world):
    m = world.manager
    result = m.start()
    assert m.status == "running" and result["verified"] is True
    # (б) фильтр обхода перестраивается до старта ядра, и own() уже знает адреса серверов
    own, alive = world.before_core_calls[0]
    assert alive == 0 and own.servers and own.adapter_name == "Lazeyka"
    # (д) явные селекторы: proxy — выбранный сервер, bypass — direct (обход работает)
    client = world.clients[-1]
    selected = world.store.selected()
    assert client.selects == [("proxy", f"t-{selected}"), ("bypass", "direct")]
    # (е) выход через сервер
    snap = m.snapshot()
    assert snap["status"] == "running" and snap["verified"] and snap["exit"]["country"] == "NL"
    assert world.settings.get("vpnclient", "was_running") is True


def test_config_contains_neighbours_of_the_subscription(world):
    world.manager.start()
    plan = world.config.plans[-1]
    ids = [s.id for s in plan.servers]
    store = world.store
    assert ids[0] == store.selected()
    assert {s.id for s in store.servers() if s.sub == "s-1"} == set(ids), "только серверы своей подписки"
    assert plan.addresses and all(ip.startswith("203.0.113.") for ip in plan.addresses.values())
    assert plan.tun.interface_name == "Lazeyka" and plan.tun.address4 == "100.127.255.253/30"
    assert plan.bypass and plan.bypass_state == "direct" and plan.voice_ports == ["50000-50100"]
    assert len({plan.ports.proxy, plan.ports.internal, plan.ports.clash}) == 3


def test_own_snapshot_while_running(world):
    m = world.manager
    assert m.own() is None
    m.start()
    own = m.own()
    assert own.adapter_name == "Lazeyka" and own.tun_net == "100.127.255.252/30"
    assert own.pids == {p.pid for p in world.processes if p.alive()}
    assert own.proxy is None and len(own.servers) == 3
    m.stop()
    assert m.own() is None and m.status == "stopped"


def test_port_reserved_retries_with_other_ports(world):
    world.start_failures = [PORT_BUSY.format(port=30001)]
    m = world.manager
    m.start()
    assert m.status == "running"
    first, second = world.config.plans[0], world.config.plans[1]
    assert {first.ports.internal, first.ports.clash}.isdisjoint({second.ports.internal, second.ports.clash})
    assert len(_main_processes(world)) == 2


def test_non_port_failure_is_reported_with_kind(world):
    world.start_failures = ["FATAL[0000] start service: start inbound/tun[tun-in]: configure tun interface: "
                            "Access is denied."]
    # Лазейка уже с правами (без них свой VPN не включается вовсе): отказ в доступе — не нехватка прав.
    with pytest.raises(mgr.VpnClientError, match="Windows отказала в доступе к адаптеру VPN"):
        world.manager.start()
    snap = world.manager.snapshot()
    assert snap["status"] == "error" and snap["error_kind"] == "conflict"
    assert "права администратора у Лазейки есть" in snap["error"]
    assert world.manager.own() is None, "план без запуска не держит серверы в own()"


def test_unsupported_selected_server_is_refused(tmp_path):
    bad = server("Quic", network="quic")
    store = basic_store()
    store._servers[bad.id] = bad
    store.select(bad.id)
    m, w = make_manager(tmp_path, store)
    with pytest.raises(mgr.VpnClientError, match="не поддерживается"):
        m.start()
    assert w.processes == []
    m.shutdown()


def test_without_admin_start_is_refused(tmp_path):
    m, w = make_manager(tmp_path, basic_store(), is_admin=False)
    with pytest.raises(mgr.VpnClientError, match="права"):
        m.start()
    snap = m.snapshot()
    assert snap["available"] is False and "прав" in snap["unavailable_reason"]
    m.shutdown()


def test_xhttp_server_starts_xray_helper_first(tmp_path):
    store = basic_store(xhttp=True)
    helsinki = next(s for s in store.servers() if s.name == "Helsinki")
    store.select(helsinki.id)
    m, w = make_manager(tmp_path, store)
    m.start()
    starts = [e for e in w.events if e[0] == "start"]
    assert starts == [("start", "xray"), ("start", "sing-box")]
    plan = w.config.plans[-1]
    assert list(plan.ports.helper) == [helsinki.id] and plan.physical_interface == "Ethernet"
    assert plan.xray_exe and plan.xray_exe.endswith("xray.exe")
    assert m.own().pids == {p.pid for p in w.processes}
    m.shutdown()


def test_missing_core_is_installed_on_first_start(tmp_path):
    m, w = make_manager(tmp_path, basic_store())
    w.engines.versions["sing-box"] = set()
    m.start()
    assert ("sing-box", "1.14.3") in w.engines.installs
    assert w.settings.get("vpnclient", "singbox_version") == "1.14.3"
    assert m.snapshot()["cores"]["sing-box"]["state"] == "idle"
    m.shutdown()


# ------------------------------------------------------------ остановка, режим прокси, kill switch

def test_proxy_mode_restores_system_proxy_first(tmp_path):
    m, w = make_manager(tmp_path, basic_store())
    w.settings.update(lambda d: d["vpnclient"].__setitem__("mode", "proxy"))
    m.start()
    assert w.sysproxy.applied == "127.0.0.1:20808"
    assert m.snapshot()["listen"] == "127.0.0.1:20808" and m.own().proxy == "127.0.0.1:20808"
    assert w.config.plans[-1].tun is None
    m.stop()
    stop_events = [e for e in w.events if e[0] in ("proxy-restore", "stop")]
    assert stop_events[0][0] == "proxy-restore", "прокси возвращается раньше остановки ядра"
    assert w.settings.get("vpnclient", "was_running") is False
    m.shutdown()


def test_kill_switch_follows_vpn(tmp_path):
    m, w = make_manager(tmp_path, basic_store())
    w.settings.update(lambda d: d["vpnclient"].__setitem__("kill_switch", True))
    m.start()
    luid, apps, nets = w.killswitch.enabled_with
    assert w.killswitch.active and luid == 42
    assert any(a.endswith("sing-box.exe") for a in apps) and "10.0.0.0/8" in nets
    m.stop()
    assert not w.killswitch.active
    m.shutdown()


def test_shutdown_stops_everything(world):
    world.manager.start()
    world.manager.shutdown()
    assert all(not p.alive() for p in world.processes)
    assert world.manager.status == "stopped"


# ------------------------------------------------------------ падение и автоперезапуск

def test_crash_after_long_run_restarts(world):
    m = world.manager
    m.start()
    world.advance(120)
    _main_processes(world)[-1].crash()
    assert m.wait_idle(10)
    assert m.status == "running" and len(_main_processes(world)) == 2
    # Перезапуск после падения — плашка, пока он идёт (без уведомления); на «работает» она снята.
    assert not any("перезапускаем" in text for _, text in world.notices)
    assert "vpn-crash" not in world.alerts


def test_early_crash_is_an_error_without_restart(world):
    m = world.manager
    m.start()
    world.advance(5)
    _main_processes(world)[-1].crash(line="FATAL[0003] start service: finish-start clash server: external "
                                          "controller listen error: listen tcp 127.0.0.1:30002: bind: Only "
                                          "one usage of each socket address")
    assert m.wait_idle(10)
    snap = m.snapshot()
    assert snap["status"] == "error" and snap["error_kind"] == "port"
    assert len(_main_processes(world)) == 1
    crash = world.alerts["vpn-crash"]
    assert crash["level"] == "error" and crash["action"]["call"] == "vpnclient_start" and crash["page"] is None
    assert not any(level == "error" for level, _ in world.notices), "упало само — плашка, не уведомление"
    m.stop()
    assert "vpn-crash" not in world.alerts, "выключили — плашка «остановился» снята"


def test_restarts_are_limited_per_hour(world):
    m = world.manager
    m.start()
    for _ in range(3):
        world.advance(120)
        _main_processes(world)[-1].crash()
        assert m.wait_idle(10) and m.status == "running"
    world.advance(120)
    _main_processes(world)[-1].crash()
    assert m.wait_idle(10)
    assert m.status == "error" and len(_main_processes(world)) == 4


def test_proxy_restored_right_after_crash(tmp_path):
    m, w = make_manager(tmp_path, basic_store())
    w.settings.update(lambda d: d["vpnclient"].__setitem__("mode", "proxy"))
    m.start()
    w.advance(5)
    _main_processes(w)[-1].crash()
    assert m.wait_idle(10)
    assert w.sysproxy.applied is None and ("proxy-restore", "127.0.0.1:20808") in w.events
    m.shutdown()


def test_stale_crash_report_is_ignored(world):
    m = world.manager
    m.start()
    old = _main_processes(world)[-1]
    m.restart()
    assert m.status == "running"
    old.on_exit(3, ["FATAL[0001] old"])     # сторож прежнего процесса сообщил поздно
    assert m.wait_idle(10)
    assert m.status == "running" and len(_main_processes(world)) == 2


# ------------------------------------------------------------ смена сервера без перезапуска

def test_select_inside_config_switches_without_restart(world):
    m = world.manager
    m.start()
    berlin = next(s for s in world.store.servers() if s.name == "Berlin")
    m.select(berlin.id)
    assert m.wait_idle(10)
    assert len(_main_processes(world)) == 1
    assert world.clients[-1].selects[-1] == ("proxy", f"t-{berlin.id}")
    assert m.snapshot()["selected"]["name"] == "Berlin"


def test_select_group_auto_inside_config(world):
    m = world.manager
    m.start()
    m.select("auto:g-smart")
    assert m.wait_idle(10)
    assert world.clients[-1].selects[-1] == ("proxy", "t-auto:g-smart") and len(_main_processes(world)) == 1
    snap = m.snapshot()["selected"]
    assert snap["kind"] == "auto" and snap["name"] == "Умная локация"


def test_select_from_other_subscription_restarts(world):
    m = world.manager
    m.start()
    other = next(s for s in world.store.servers() if s.sub == "s-2")
    m.select(other.id)
    assert m.wait_idle(10)
    assert len(_main_processes(world)) == 2 and m.status == "running"
    assert [s.id for s in world.config.plans[-1].servers] == [other.id]


def test_select_unknown_is_refused(world):
    with pytest.raises(mgr.VpnClientError):
        world.manager.select("nope")
    with pytest.raises(mgr.VpnClientError):
        world.manager.select("auto:nope")


# ------------------------------------------------------------ «через обход»: гистерезис и подбор

def test_bypass_selector_with_hysteresis(world):
    m = world.manager
    m.start()
    client = world.clients[-1]
    world.view = ZapretView(running=False, strategy_args=["--wf-tcp=443"], pack_dir=Path("C:/pack"))
    m.set_bypass(world.view)
    m.tick()
    assert m.wait_idle(5)
    assert client.selects[-1] == ("bypass", "direct"), "в первые 30 с селектор не дёргаем"
    world.advance(31)
    m.tick()
    assert m.wait_idle(5)
    assert client.selects[-1] == ("bypass", "proxy")
    assert m.snapshot()["routing"]["bypass"] == "proxy"
    # обход вернулся — снова не раньше чем через 30 с
    world.view = ZapretView(running=True, last_ok=True, strategy_args=["--wf-tcp=443"], pack_dir=Path("C:/pack"))
    m.set_bypass(world.view)
    world.advance(10)
    m.tick()
    assert m.wait_idle(5) and client.selects[-1] == ("bypass", "proxy")
    world.advance(25)
    m.tick()
    assert m.wait_idle(5) and client.selects[-1] == ("bypass", "direct")


def test_bypass_untouched_while_strategy_test_runs(world):
    m = world.manager
    m.start()
    client = world.clients[-1]
    world.view = ZapretView(running=False, paused_for_test=True, strategy_args=["--wf-tcp=443"],
                            pack_dir=Path("C:/pack"))
    m.set_bypass(world.view)
    world.advance(60)
    m.tick()
    assert m.wait_idle(5)
    assert [s for s in client.selects if s[0] == "bypass"] == [("bypass", "direct")]
    assert "подбор" in m.snapshot()["routing"]["bypass_note"]


def test_failed_check_routes_bypass_through_vpn_from_start(tmp_path):
    m, w = make_manager(tmp_path, basic_store())
    w.view = ZapretView(running=True, last_ok=False, strategy_args=["--wf-tcp=443"], pack_dir=Path("C:/pack"))
    m.start()
    assert w.clients[-1].selects[-1] == ("bypass", "proxy")
    assert "проверка обхода не прошла" in m.snapshot()["routing"]["bypass_note"]
    m.shutdown()


# ------------------------------------------------------------ сон, сеть, здоровье

def test_resume_closes_connections_without_restart(world):
    m = world.manager
    m.start()
    m.on_resume()
    assert m.wait_idle(5)
    assert world.clients[-1].closed == 1 and len(_main_processes(world)) == 1 and m.status == "running"


def test_resume_can_disconnect(world):
    m = world.manager
    m.start()
    world.settings.update(lambda d: d["vpnclient"].__setitem__("on_sleep", "disconnect"))
    m.on_resume()
    assert m.wait_idle(5)
    assert m.status == "stopped" and world.settings.get("vpnclient", "was_running") is True


def test_network_change_restarts_only_xray_helper(tmp_path):
    store = basic_store(xhttp=True)
    store.select(next(s for s in store.servers() if s.name == "Helsinki").id)
    m, w = make_manager(tmp_path, store)
    m.start()
    m.on_network_change()
    assert m.wait_idle(5)
    names = [p.name for p in w.processes]
    assert names.count("xray") == 2 and names.count("sing-box") == 1
    m.shutdown()


def test_exit_check_failure_explains_and_recovers(world):
    m = world.manager
    world.exit_ok = False
    selected = world.store.server(world.store.selected())
    world.tcp[world.resolver.address(selected.host)] = "timeout"
    m.start()
    snap = m.snapshot()
    assert snap["status"] == "running" and snap["verified"] is False and snap["error_kind"] == "timeout"
    assert snap["diagnosis"]["code"] == "tcp_timeout" and snap["error"] == snap["diagnosis"]["text"]
    exit_alert = world.alerts["vpn-exit"]
    assert exit_alert["level"] == "warn" and exit_alert["page"] == "vpnclient"
    assert "ничего не открывается" in exit_alert["text"] and exit_alert["action"]["call"] == "vpnclient_restart"
    assert "Чья сторона: не ясно" in exit_alert["text"]
    world.advance(16)
    m.tick()                                      # повтор проверки: плашка та же, уведомлений нет
    assert m.wait_idle(10)
    assert "vpn-exit" in world.alerts and world.notices == []
    world.exit_ok = True
    world.advance(16)
    m.tick()
    assert m.wait_idle(10)
    snap = m.snapshot()
    assert snap["verified"] is True and snap["error"] is None and snap["diagnosis"] is None
    assert "vpn-exit" not in world.alerts and world.notices == [], "заработало — плашка ушла сама, без уведомления"


def test_health_switches_to_fastest_after_two_failures(world):
    m = world.manager
    m.start()
    store = world.store
    amsterdam = store.selected()
    berlin = next(s for s in store.servers() if s.name == "Berlin")
    world.delays = {f"t-{amsterdam}": "timeout", f"t-{berlin.id}": 40}
    for _ in range(2):
        world.advance(61)
        m.tick()
        assert m.wait_idle(5)
    assert world.clients[-1].selects[-1] == ("proxy", f"t-{berlin.id}")
    assert store.selected() == berlin.id
    # Лазейка сама сменила выбор человека — сообщает, но «info» (без уведомления Windows)
    assert any(level == "info" and "Berlin" in text for level, text in world.notices)
    assert "vpn-server" not in world.alerts


# ------------------------------------------------------------ задержка, скорость, трафик, память

def test_latency_via_running_core(world):
    m = world.manager
    m.start()
    m.latency(None)
    assert wait_for(lambda: not m.snapshot()["latency"]["running"])
    latencies = world.store.latency()
    in_config = {s.id for s in world.config.plans[-1].servers}
    assert in_config <= set(latencies) and all(latencies[i]["ms"] == 50 for i in in_config)


def test_latency_when_stopped_uses_temporary_instance(world):
    m = world.manager
    m.latency(None)
    assert wait_for(lambda: not m.snapshot()["latency"]["running"])
    assert len(world.store.latency()) == 4
    assert all(not p.alive() for p in world.processes), "временный экземпляр остановлен"
    assert m.status == "stopped" and m.own() is None


def test_speedtest_and_memory_and_traffic(world):
    m = world.manager
    m.start()
    m.speedtest(None)
    assert wait_for(lambda: not m.snapshot()["speed"]["running"])
    assert m.snapshot()["speed"]["mbps"] == 87.4
    session = m._session
    session.sampler.up, session.sampler.down = 1000, 5000
    world.advance(6)
    m.tick()
    snap = m.snapshot()
    assert snap["memory"]["sing-box"] == _main_processes(world)[-1].pid * 1000
    assert snap["traffic"]["today_up"] == 1000 and snap["traffic"]["total_down"] == 5000


def test_speedtest_needs_running_vpn(world):
    with pytest.raises(mgr.VpnClientError, match="Включите VPN"):
        world.manager.speedtest(None)


# ------------------------------------------------------------ снимок для страницы

def _keys(value):
    if isinstance(value, dict):
        return {k: _keys(v) for k, v in value.items()}
    if isinstance(value, list) and value and isinstance(value[0], dict):
        return [_keys(value[0])]
    return None


def test_snapshot_keys_match_mock(world):
    mock = json.loads(MOCK.read_text(encoding="utf-8"))
    m = world.manager
    m.start()
    m.latency(None)
    assert wait_for(lambda: not m.snapshot()["latency"]["running"])
    amsterdam = world.store.selected()
    m.select("auto:g-smart")
    assert m.wait_idle(5)
    m._session.sampler.now = {"t-auto:g-smart": f"t-{amsterdam}"}   # urltest выбрал Амстердам
    snap = m.snapshot()
    assert snap["selected"]["actual"]["name"] == "Amsterdam"
    assert set(snap) == set(mock)
    for key in ("cores", "stats", "latency", "speed", "import", "routing", "settings", "traffic", "memory",
                "exit", "selected"):
        assert _keys(snap[key]) == _keys(mock[key]), key
    assert _keys(snap["servers"][0]) == _keys(mock["servers"][0])
    assert _keys(snap["subscriptions"][0]) == _keys(mock["subscriptions"][0])
    assert _keys(snap["groups"][0]) == _keys(mock["groups"][0])
    json.dumps(snap)


def test_snapshot_lists_servers_of_running_config(world):
    """config_servers — серверы работающего конфига как они есть (session.plan.servers), а не правило
    _selection, которое страница повторяла сама: сервер без адреса в конфиг не вошёл, после переключения
    внутри подписки состав не меняется. Без сеанса — null."""
    m = world.manager
    assert m.snapshot()["config_servers"] is None
    helsinki = next(s for s in world.store.servers() if s.name == "Helsinki")
    world.resolver.fail.add(helsinki.host)                   # адрес не получен — в конфиг не войдёт
    m.start()
    expected = [s.id for s in m._session.plan.servers]
    assert m.snapshot()["config_servers"] == expected and helsinki.id not in expected
    m.select(expected[1])
    assert m.wait_idle(5) and m.snapshot()["config_servers"] == expected, "переключение — без перезапуска"
    m.stop()
    assert m.snapshot()["config_servers"] is None


def test_snapshot_has_no_secrets(world):
    m = world.manager
    m.start()
    blob = json.dumps(m.snapshot(), ensure_ascii=False)
    for s in world.store.servers():
        assert s.uuid not in blob and s.tls["pbk"] not in blob and s.host not in blob
    assert "abc123TOKEN" not in blob
    session = m._session
    assert session.plan.secrets.clash not in blob and session.plan.secrets.internal_pass not in blob


def test_snapshot_without_store_module_is_unavailable(tmp_path, monkeypatch):
    m, w = make_manager(tmp_path, basic_store())
    m.deps.store = None
    m._store = None
    monkeypatch.setattr(mgr, "_module", lambda name: (_ for _ in ()).throw(mgr.VpnClientError(f"нет {name}")))
    snap = m.snapshot()
    assert snap["available"] is False and "store" in snap["unavailable_reason"]
    m.shutdown()


# ------------------------------------------------------------ установка ядра с «Обновлений»

def test_core_update_is_checked_before_activation(world):
    m = world.manager
    rel = real_engines.Release(version="1.14.4", url="https://example.invalid/x.zip", zip_sha256="0" * 64)
    world.engines.check_error = "decode config at x: unknown field"
    with pytest.raises(real_engines.EngineError):
        m.core_install("sing-box", release=rel)
    assert world.settings.get("vpnclient", "singbox_version") == "1.14.3", "непрошедшая проверку версия не активна"
    assert "sing-box:1.14.4" in world.settings.get("vpnclient", "core_bad_versions")
    world.engines.check_error = None
    assert "1.14.4" in m.core_install("sing-box", release=rel)
    assert world.settings.get("vpnclient", "singbox_version") == "1.14.4"
    assert ("sing-box", "1.14.4") in world.engines.checks


def test_core_rollback_to_previous_and_mark_current_bad(world):
    world.settings.update(lambda d: d["vpnclient"].__setitem__("singbox_version", "1.14.4"))
    world.engines.versions["sing-box"].add("1.14.4")
    assert "1.14.3" in world.manager.core_rollback("sing-box")
    assert world.settings.get("vpnclient", "singbox_version") == "1.14.3"
    assert "sing-box:1.14.4" in world.settings.get("vpnclient", "core_bad_versions"), \
        "автообновление не вернёт версию, от которой откатились"
    with pytest.raises(mgr.VpnClientError, match="Нет более ранней"):
        world.manager.core_rollback("sing-box")


# ------------------------------------------------------------ настройки и прочие действия

def test_save_settings_validates_and_restarts(world):
    m = world.manager
    result = m.save_settings({"port": 80, "dns_direct": "ftp://x", "exclude_nets": ["not-a-net"]})
    assert result["ok"] is False and set(result["errors"]) == {"port", "dns_direct", "exclude_nets"}
    m.start()
    assert m.save_settings({"tun_mtu": 1400, "sort": "name"}) == {}
    assert m.wait_idle(10)
    assert world.settings.get("vpnclient", "tun_mtu") == 1400
    assert len(_main_processes(world)) == 2, "MTU входит в конфиг — перезапуск"
    assert m.save_settings({"sort": "latency"}) == {}
    assert m.wait_idle(5) and len(_main_processes(world)) == 2


def test_local_auth_requires_credentials_and_keeps_password_private(world):
    m = world.manager
    assert m.save_settings({"local_auth": True})["errors"]["local_user"]
    assert m.save_settings({"local_auth": True, "local_user": "me", "local_password": "Secret-pass-1"}) == {}
    snap = m.snapshot()["settings"]
    assert snap["local_user"] == "me" and snap["local_password_set"] is True
    assert "Secret-pass-1" not in json.dumps(m.snapshot())
    m.start()
    assert world.config.plans[-1].secrets.local_pass == "Secret-pass-1"


# Поля формы «Подробнее» (vpnclient-more.js): прежняя форма слала их все, пустой пароль — нет.
SETTINGS_FORM_KEYS = ("port", "local_auth", "local_user", "socks_udp", "allow_lan", "dns_remote", "dns_direct",
                      "fakeip", "ip_strategy", "ipv6", "tun_mtu", "exclude_nets", "proxy_override", "kill_switch",
                      "on_sleep", "tls_fragment", "mux", "noises", "fingerprint", "latency_on_update",
                      "sub_update_hours", "verbose", "deeplink", "core_auto_update")


def _settings_form(m, **changes):
    snap = m.snapshot()["settings"]
    return {**{key: snap[key] for key in SETTINGS_FORM_KEYS}, **changes}


def test_settings_form_saves_with_empty_login_when_password_is_off(world):
    m = world.manager
    form = _settings_form(m, tun_mtu=1400)
    assert form["local_user"] == "" and form["local_auth"] is False
    assert m.save_settings(form) == {}
    assert world.settings.get("vpnclient", "tun_mtu") == 1400


def test_same_login_is_not_a_change_and_new_password_restarts(world):
    m = world.manager
    assert m.save_settings({"local_auth": True, "local_user": "bob", "local_password": "Secret-1"}) == {}
    m.start()
    form = _settings_form(m)
    assert m.save_settings(dict(form, latency_on_update=not form["latency_on_update"])) == {}
    assert m.wait_idle(5) and len(_main_processes(world)) == 1, "живой ключ и тот же логин — без перезапуска"
    assert m.save_settings(_settings_form(m, local_password="Secret-2")) == {}
    assert m.wait_idle(10) and len(_main_processes(world)) == 2, "новый пароль входит в конфиг"
    assert world.config.plans[-1].secrets.local_pass == "Secret-2"


def test_missing_password_is_reported_at_its_own_field(world):
    result = world.manager.save_settings({"allow_lan": True, "local_user": "bob"})
    assert set(result["errors"]) == {"local_password"}, "устройствам из сети нужен вход по паролю"
    assert world.manager.save_settings({"local_user": "bad user"})["errors"]["local_user"]


def test_deeplink_request_hides_text(world):
    m = world.manager
    m.deeplink_offer("lazeyka://import/https://sub.example.com/secret-token-123456")
    request = m.snapshot()["deeplink_request"]
    assert set(request) == {"token", "kind", "summary"}
    assert request["kind"] == "subscription" and "sub.example.com" in request["summary"]
    assert "secret-token-123456" not in json.dumps(m.snapshot())
    with pytest.raises(mgr.VpnClientError):
        m.deeplink_confirm("wrong", True)
    assert m.deeplink_confirm(request["token"], False) == {}
    assert m.snapshot()["deeplink_request"] is None


def test_import_links_adds_servers(world):
    m = world.manager
    link = ("vless://22222222-3333-4444-8555-666666666666@203.0.113.77:443?security=reality&sni=www.example.com"
            "&pbk=wMTJ9bV1x6qRdnQk2eBcUJbQ8Wl0Jp0r3o0t5s6Y7m4&sid=ab&fp=chrome&type=tcp#New")
    m.import_text(link)
    assert wait_for(lambda: not m.snapshot()["import"]["running"])
    imp = m.snapshot()["import"]
    assert imp["error"] is None and "1" in imp["message"]
    assert any(s.name == "New" for s in world.store.servers())


def test_copy_link_returns_secret_for_explicit_button(world):
    s = world.store.servers()[0]
    s.raw = "vless://secret@host:443"
    assert world.manager.copy_link(s.id) == "vless://secret@host:443"
    assert world.manager.copy_link("s-1") == "https://sub.example.com/abc123TOKEN"


def test_sub_set_validates(world):
    m = world.manager
    result = m.sub_set("s-1", {"update_hours": 100, "ua_preset": "nope"})
    assert set(result["errors"]) == {"update_hours", "ua_preset"}
    assert m.sub_set("s-1", {"name": "Новое имя", "hwid": True}) == {}
    sub = world.store.subscription("s-1")
    assert sub.name == "Новое имя" and sub.hwid


def test_sub_set_accepts_dialog_payload_and_checks_ua_only_for_custom(world):
    """Ровно то, что шлёт окно «Свойства подписки»: у пресета не «Свой» поле UA выключено."""
    m = world.manager
    values = {"name": "Мой VPN 2", "ua_preset": "incy", "ua": None, "hwid": False, "update_hours": 12,
              "dns": None, "mtu": None, "provider_routes": False}
    assert m.sub_set("s-1", values) == {}
    sub = world.store.subscription("s-1")
    assert (sub.name, sub.ua_preset, sub.update_hours) == ("Мой VPN 2", "incy", 12)
    assert m.sub_set("s-1", dict(values, ua="")) == {}, "пустая строка у выключенного поля — не ошибка"
    assert set(m.sub_set("s-1", dict(values, ua_preset="custom", ua=""))["errors"]) == {"ua"}
    assert set(m.sub_set("s-1", dict(values, ua_preset="custom", ua=None))["errors"]) == {"ua"}
    assert m.sub_set("s-1", dict(values, ua_preset="custom", ua="MyClient/1.0")) == {}
    assert world.store.subscription("s-1").user_agent == "MyClient/1.0"
    assert m.sub_set("s-1", {"ua": "Bad\nAgent"})["errors"]["ua"], "пресет «Свой» сохранён — UA проверяется"


def test_remove_subscription_in_use_stops_vpn(world):
    m = world.manager
    m.start()
    m.sub_remove("s-1")
    assert m.wait_idle(5)
    assert m.status == "stopped"


def test_set_mode_restarts_running_core(world):
    m = world.manager
    m.start()
    assert m.set_mode("proxy") == {}
    assert world.settings.get("vpnclient", "mode") == "proxy", "режим сохранён до ответа"
    assert m.wait_idle(10)
    assert m.status == "running" and world.config.plans[-1].mode == "proxy"
    with pytest.raises(mgr.VpnClientError):
        m.set_mode("bogus")


def test_set_mode_refuses_unavailable_proxy_before_start(world):
    """Окно «Уже работает другой VPN» → «Включить как системный прокси»: set_mode отвечает сразу. Отказ —
    режим прежний (и страница не включает VPN); согласие — следующий запуск уже в режиме прокси."""
    m = world.manager
    world.sysproxy.unavailable = "Лазейка запущена от имени другой учётной записи"
    with pytest.raises(mgr.VpnClientError, match="другой учётной записи"):
        m.set_mode("proxy")
    assert world.settings.get("vpnclient", "mode") == "tun" and world.processes == []
    world.sysproxy.unavailable = None
    assert m.set_mode("proxy") == {}
    m.start()
    assert world.config.plans[-1].mode == "proxy" and world.sysproxy.applied


def _crashed_with_kill_switch(world):
    world.settings.update(lambda d: d["vpnclient"].__setitem__("kill_switch", True))
    world.manager.start()
    world.advance(5)                              # раннее падение — без перезапуска
    _main_processes(world)[-1].crash()
    assert world.manager.wait_idle(10)
    assert world.manager.status == "error" and world.killswitch.active


def test_kill_switch_off_in_settings_opens_internet_after_crash(world):
    _crashed_with_kill_switch(world)
    assert world.manager.save_settings({"kill_switch": False}) == {}
    assert world.manager.wait_idle(5)
    assert not world.killswitch.active, "сеанса нет, но фильтры сняты"


def test_set_mode_without_session_drops_kill_switch_outside_tun(world):
    _crashed_with_kill_switch(world)
    assert world.manager.set_mode("tun") == {}
    assert world.manager.wait_idle(5) and world.killswitch.active, "в TUN интернет закрыт до переподключения"
    assert world.manager.set_mode("local") == {}
    assert world.manager.wait_idle(5) and not world.killswitch.active


def test_preflight_reports_other_uac_user(world):
    world.settings.update(lambda d: d["vpnclient"].__setitem__("mode", "proxy"))
    world.sysproxy.unavailable = "другой учётной записи"
    result = world.manager.preflight()
    assert result["ask"] and result["conflict"]["kind"] == "uac_user"
    assert world.manager.snapshot()["conflict"]["kind"] == "uac_user"


# ------------------------------------------------------------ чистые помощники

def test_pick_tun_subnet_avoids_overlaps():
    assert str(mgr.pick_tun_subnet([], [])) == "100.127.255.252/30"
    tailscale = ["100.64.0.0/10"]
    assert str(mgr.pick_tun_subnet(tailscale, [])) == "198.51.100.252/30"
    assert str(mgr.pick_tun_subnet(["0.0.0.0/0", "0.0.0.0/1"], [])) == "100.127.255.252/30"
    with pytest.raises(mgr.VpnClientError):
        mgr.pick_tun_subnet(["100.64.0.0/10", "198.51.100.0/24", "192.0.2.0/24"], [])


def test_dns_wire_format_roundtrip():
    query = mgr._dns_query("example.com")
    assert query[12:25] == b"\x07example\x03com\x00"
    answer = bytes.fromhex("000081800001000200000000076578616d706c6503636f6d0000010001"
                           "c00c000100010000003c0004cb007105c00c000500010000003c0002c00c")
    assert mgr.parse_dns_answers(answer) == ["203.0.113.5"]
    assert mgr.parse_dns_answers(bytes.fromhex("000081800000000000000000")) == [], "NODATA: имя есть, адресов нет"
    for flags, rcode in (("8183", 3), ("8182", 2), ("8185", 5)):     # NXDOMAIN, SERVFAIL, REFUSED
        with pytest.raises(mgr.DnsRcodeError) as failure:
            mgr.parse_dns_answers(bytes.fromhex(f"0000{flags}0001000000000000"))
        assert failure.value.rcode == rcode


def test_resolver_falls_back_in_order():
    asked = []

    def query(host, url):
        asked.append(url)
        if "1.1.1.1" in url:
            raise OSError("заблокирован")
        return ["198.51.100.7"]

    resolver = mgr.Resolver(query)
    assert resolver.resolve("vpn.example.com") == "198.51.100.7"
    assert asked == ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"]
    assert resolver.working == "https://8.8.8.8/dns-query"
    assert resolver.resolve("203.0.113.9") == "203.0.113.9"


def test_free_port_skips_busy():
    import socket
    with socket.socket() as busy:
        busy.bind(("127.0.0.1", 0))
        busy.listen()
        port = busy.getsockname()[1]
        assert mgr.free_port(port) != port
    assert mgr.free_port(None) > 0


def test_trace_parsing():
    assert mgr.parse_trace("fl=1\nip=203.0.113.5\nloc=NL\n")["loc"] == "NL"


def test_traffic_book_rolls_over_by_day(tmp_path):
    now = [1_760_000_000.0]
    book = mgr.TrafficBook(tmp_path / "traffic.json", clock=lambda: now[0])
    book.add(100, 200)
    book.save()
    now[0] += 86400
    again = mgr.TrafficBook(tmp_path / "traffic.json", clock=lambda: now[0])
    snap = again.snapshot()
    assert (snap["today_up"], snap["total_up"], snap["total_down"]) == (0, 100, 200)


# ------------------------------------------------------------ подписки: проба формата, повтор с HWID, свойства

def _with_subscription(world):
    fake = FakeSubscription()
    world.manager.deps.modules["subscription"] = fake
    return fake


def test_sub_probe_offers_extended_format_without_changing_subscription(world):
    fake = _with_subscription(world)
    rich = fake.real.Decoded(format="xray-json", servers=[server("X1"), server("X2")],
                             groups=[Group(id="g-x", sub="s-1", name="Авто", members=[])])
    fake.answers["v2rayN/7.15.0"] = rich
    offer = world.manager.sub_probe("s-1")
    assert offer["kind"] == "switch" and offer["options"] == ["v2rayn"] and offer["sub"] == "s-1"
    assert "JSON с группами" in offer["text"] and "как v2rayN" in offer["text"]
    assert [ua for ua, _route, _hwid in fake.calls] == ["v2rayN/7.15.0"]
    assert world.store.subscription("s-1").ua_preset == "lazeyka", "сохранённая подписка не меняется"
    snap = world.manager.snapshot()
    assert snap["import"]["offer"]["kind"] == "switch"
    probe = next(s for s in snap["subscriptions"] if s["id"] == "s-1")["probe"]
    assert probe == {"running": False, "ua_preset": "v2rayn", "text": offer["text"]}
    assert world.manager.sub_set("s-2", {"name": "Второй!"}) == {}
    assert world.manager.snapshot()["import"]["offer"]["sub"] == "s-1", "предложение другой подписки остаётся"
    world.manager.sub_set("s-1", {"ua_preset": "v2rayn"})
    snap = world.manager.snapshot()
    assert next(s for s in snap["subscriptions"] if s["id"] == "s-1")["probe"] is None
    assert snap["import"]["offer"] is None, "по предложению уже действуют — «Переключить» не повторится"


def test_sub_probe_reports_same_format(world):
    _with_subscription(world)
    result = world.manager.sub_probe("s-1")
    assert result == {"ok": True, "message": "Расширенного формата нет — провайдер отдаёт ссылки"}
    with pytest.raises(mgr.VpnClientError):
        world.manager.sub_probe("nope")


def test_import_retry_with_hwid_reuses_last_text(world):
    fake = _with_subscription(world)
    fake.answers["Lazeyka/" + mgr.__version__ + " (Windows)"] = fake.SubscriptionError(
        "http_status", "Подписка недоступна (403)", status=403)
    m = world.manager
    m.import_text("https://new.example.com/sub/TOKEN-777")
    assert wait_for(lambda: not m.snapshot()["import"]["running"])
    first = m.snapshot()["import"]
    assert first["error"] and first["offer"]["kind"] == "ua" and first["offer"]["sub"]
    m.import_text(None, None, True)         # «Отправить HWID и повторить»: текст ядро помнит само
    assert wait_for(lambda: not m.snapshot()["import"]["running"])
    _ua, _route, hwid = fake.calls[-1]
    assert hwid and len([s for s in world.store.subscriptions() if s.url.endswith("TOKEN-777")]) == 1
    assert "TOKEN-777" not in json.dumps(m.snapshot())


def test_first_failed_import_hides_subscription_address(world):
    """Адрес новой подписки — секрет с первой попытки: ошибка загрузки, повторившая его, адрес не показывает."""
    fake = _with_subscription(world)
    url = "https://fresh.example.com/sub/Fr3shTok3n-2026"
    fake.answers["Lazeyka/" + mgr.__version__ + " (Windows)"] = fake.SubscriptionError(
        "network", f"Не удалось загрузить {url}: соединение сброшено")
    m = world.manager
    m.import_text(url)
    assert wait_for(lambda: not m.snapshot()["import"]["running"])
    error = m.snapshot()["import"]["error"]
    stored = next(s for s in world.store.subscriptions() if s.url == url).error
    assert error and applog.MASK in error and "Fr3shTok3n" not in error
    assert applog.MASK in stored and "Fr3shTok3n" not in stored


def test_sub_set_dns_and_mtu(world):
    m = world.manager
    bad = m.sub_set("s-1", {"dns": "ftp://x", "mtu": 100})
    assert set(bad["errors"]) == {"dns", "mtu"}
    assert m.sub_set("s-1", {"dns": "auto", "mtu": 600}) == {}
    assert world.store.subscription("s-1").mtu == 600
    assert mgr.VpnClientManager._dns_choice(world.settings.get("vpnclient"),
                                            world.store.subscription("s-1")).remote == "https://1.1.1.1/dns-query"
    assert m.sub_set("s-1", {"dns": "google"}) == {}
    assert mgr.VpnClientManager._dns_choice(world.settings.get("vpnclient"),
                                            world.store.subscription("s-1")).remote == "https://8.8.8.8/dns-query"
    assert m.sub_set("s-1", {"dns": "https://dns.example.com/dns-query", "mtu": 1400, "provider_routes": True}) == {}
    sub = world.store.subscription("s-1")
    assert (sub.dns, sub.mtu, sub.provider_routes) == ("https://dns.example.com/dns-query", 1400, True)
    m.start()
    plan = world.config.plans[-1]
    assert plan.dns.remote == "https://dns.example.com/dns-query" and plan.tun.mtu == 1400


def test_sub_set_same_dns_mtu_routes_is_not_a_change(world):
    """Окно свойств шлёт dns, mtu и маршруты провайдера и при переименовании: прежние значения — не изменение,
    работающий VPN не перезапускается."""
    m = world.manager
    assert m.sub_set("s-1", {"dns": "google", "mtu": 1400}) == {}
    m.start()
    assert m.wait_idle(10)
    starts = len(_main_processes(world))
    sub = world.store.subscription("s-1")
    assert m.sub_set("s-1", {"name": "Новое имя", "dns": "google", "mtu": 1400,
                             "provider_routes": sub.provider_routes}) == {}
    assert m.wait_idle(10)
    assert world.store.subscription("s-1").name == "Новое имя"
    assert len(_main_processes(world)) == starts, "переименование не перезапускает VPN"
    assert m.sub_set("s-1", {"mtu": 1380}) == {}
    assert m.wait_idle(10) and len(_main_processes(world)) > starts, "новый MTU — перезапуск"
    m.shutdown()


def test_kill_switch_stays_closed_after_crash_until_stop(tmp_path):
    m, w = make_manager(tmp_path, basic_store())
    w.settings.update(lambda d: d["vpnclient"].__setitem__("kill_switch", True))
    m.start()
    w.advance(5)                                  # раннее падение — без перезапуска
    _main_processes(w)[-1].crash()
    assert m.wait_idle(10)
    assert m.status == "error" and w.killswitch.active, "упало ядро — интернет закрыт до переподключения"
    crash = w.alerts["vpn-crash"]
    assert "Kill switch" in crash["text"] and crash["action"]["call"] == "vpnclient_stop"
    assert crash["page"] == "vpnclient", "главное действие — выключить VPN, видно и на его странице"
    m.stop()
    assert not w.killswitch.active and m.status == "stopped" and "vpn-crash" not in w.alerts
    m.shutdown()


def test_stop_during_start_ends_quietly(world):
    m = world.manager
    m._abort.set()
    result = m._ops.call(lambda: m._start(reason="user"))     # как если бы «Выключить» нажали в процессе
    assert result == {"verified": False, "exit": None} and m.status == "stopped"
    assert world.processes == []


def test_group_starts_when_one_member_has_no_address(world):
    m = world.manager
    store = world.store
    amsterdam = next(s for s in store.servers() if s.name == "Amsterdam")
    world.resolver.fail.add(amsterdam.host)
    store.select("auto:g-smart")
    m.start()
    plan = world.config.plans[-1]
    assert amsterdam.id not in plan.engines and plan.servers and m.status == "running"
    world.resolver.fail.update(s.host for s in store.servers())
    m.stop()
    with pytest.raises(mgr.VpnClientError, match="адреса серверов"):
        m.start()


# ------------------------------------------------------------ поле импорта, заглушки, пакетная задержка

DATA = Path(__file__).resolve().parent / "data" / "vpnclient"


def test_pasted_xray_json_is_imported(world):
    m = world.manager
    m.import_text((DATA / "xray_remnawave.json").read_text(encoding="utf-8"))
    assert wait_for(lambda: not m.snapshot()["import"]["running"])
    imp = m.snapshot()["import"]
    assert imp["error"] is None and imp["message"].startswith("Добавлено серверов:")
    assert any(s.name.endswith("Амстердам") or s.name == "Амстердам" for s in world.store.servers())


def test_provider_stub_names_are_a_message(world):
    fake = _with_subscription(world)
    decoded = fake.real.Decoded(format="links", notices=["Подписка истекла — продлите на example.com"])
    fake.decode = lambda body, headers=None, *, sub_id=None, keep_local=False: decoded
    m = world.manager
    m.import_text("vless://x")
    assert wait_for(lambda: not m.snapshot()["import"]["running"])
    assert m.snapshot()["import"]["error"] == "Провайдер сообщает: Подписка истекла — продлите на example.com"


def test_latency_batch_saves_store_once(world):
    m = world.manager
    m.start()
    world.store.calls.clear()
    m.latency(None)
    assert wait_for(lambda: not m.snapshot()["latency"]["running"])
    batch = [c for c in world.store.calls if c[0] == "set_latency"]
    assert batch and all(save is False for _, _, save in batch)
    assert world.store.calls.count(("save",)) == 1


def test_vanished_selection_with_real_store(tmp_path):
    from app.vpnclient.store import ProfileStore
    from app.vpnclient.model import Subscription
    store = ProfileStore(tmp_path / "profiles.json")
    store.add_subscription(Subscription(id="s-1", name="Мой VPN", url="https://sub.example.com/T1"))
    m, w = make_manager(tmp_path, store)
    fake = _with_subscription(w)
    fake.decode = lambda body, headers=None, *, sub_id=None: fake.real.Decoded(format="links", servers=[
        server("Amsterdam", sub=None), server("Berlin", sub=None)])
    m.sub_update("s-1")
    assert wait_for(lambda: len(store.servers()) == 2 and not m.snapshot()["subscriptions"][0]["updating"])
    amsterdam = next(s for s in store.servers() if s.name == "Amsterdam")
    store.select(amsterdam.id)
    fake.decode = lambda body, headers=None, *, sub_id=None: fake.real.Decoded(format="links", servers=[
        server("Berlin", sub=None)])
    m.sub_update("s-1")
    assert wait_for(lambda: len(store.servers()) == 1 and not m.snapshot()["subscriptions"][0]["updating"])
    berlin = store.servers()[0]
    assert store.selected() == berlin.id
    assert any("Amsterdam» пропал из подписки" in text and "выбран «Berlin»" in text for _, text in w.notices)
    m.shutdown()


# ------------------------------------------------------------ связка с настоящим генератором конфигов

def _reference_store() -> "FakeStore":
    from app.vpnclient.model import Server, Subscription
    from tests.fakes.vpn_world import FakeStore
    cases = json.loads((DATA / "servers.json").read_text(encoding="utf-8"))["cases"]
    servers = []
    for case in cases:
        s = Server.from_dict(case["server"])
        s.sub = "s-ref"
        s.id = s.key()
        servers.append(s)
    broken = Server("vless", "broken.example.com", 443, name="broken", uuid="33333333-2222-4333-8444-555555555555",
                    security="reality", tls={"sni": "www.example.com"}, sub="s-ref")   # нет pbk — не собрать
    broken.id = broken.key()
    servers.insert(1, broken)                    # сосед выбранного: войдёт в конфиг (до 16 серверов подписки)
    sub = Subscription(id="s-ref", name="Эталон", url="https://sub.example.com/REF", added_at=mgr.time.time(),
                       updated_at=mgr.time.time())
    return FakeStore(servers, [sub], [], selected=servers[0].id)


@pytest.mark.parametrize("mode", ["tun", "proxy"])
def test_plan_is_accepted_by_real_config_generator(tmp_path, mode):
    from app.vpnclient import config, routing
    store = _reference_store()
    m, w = make_manager(tmp_path, store)
    m.deps.modules.update(config=config, routing=routing)
    w.settings.update(lambda d: d["vpnclient"].update(mode=mode, via_zapret=False))
    xhttp = next(s for s in store.servers() if s.network == "xhttp")
    store.select(xhttp.id)                       # выбранный — через помощник Xray: и sing-box, и xray-конфиг
    m.start()
    assert m.status == "running"
    sb = json.loads((tmp_path / "vpnclient" / "run" / "sing-box.json").read_text(encoding="utf-8"))
    xr = json.loads((tmp_path / "vpnclient" / "run" / "xray.json").read_text(encoding="utf-8"))
    assert config.validate(sb) == []
    assert w.clients[-1].selects[0] == ("proxy", config.tag(xhttp.id))
    assert any(ob.get("tag") == config.tag(xhttp.id) and ob.get("type") == "socks" for ob in sb["outbounds"])
    assert xr["inbounds"] and all(i["listen"] == "127.0.0.1" for i in xr["inbounds"])
    tun = [i for i in sb["inbounds"] if i["type"] == "tun"]
    assert bool(tun) == (mode == "tun")
    m.shutdown()


def test_broken_neighbour_does_not_block_start(tmp_path):
    from app.vpnclient import config, routing
    store = _reference_store()
    m, w = make_manager(tmp_path, store)
    m.deps.modules.update(config=config, routing=routing)
    w.settings.update(lambda d: d["vpnclient"].__setitem__("via_zapret", False))
    m.start()                                    # выбран обычный VLESS+REALITY, рядом в подписке — без pbk
    plan = w.config.plans[-1] if w.config.plans else None
    assert m.status == "running" and plan is None, "работал настоящий генератор"
    sb = json.loads((tmp_path / "vpnclient" / "run" / "sing-box.json").read_text(encoding="utf-8"))
    tags = {ob["tag"] for ob in sb["outbounds"]}
    server_tags = {config.tag(s.id) for s in store.servers()} & tags
    assert server_tags == {config.tag(store.selected())}, "соседи не собрались — включено только выбранное"
    m.shutdown()


def test_latency_marks_unbuildable_servers(tmp_path):
    from app.vpnclient import config, routing
    store = _reference_store()
    m, w = make_manager(tmp_path, store)
    m.deps.modules.update(config=config, routing=routing)
    w.delays = {config.tag(s.id): 50 for s in store.servers()}     # ответы временного экземпляра
    m.latency(None)
    assert wait_for(lambda: not m.snapshot()["latency"]["running"])
    assert w.group_delays >= 1, "все серверы — одним запросом группы"
    latencies = store.latency()
    broken = next(s for s in store.servers() if s.name == "broken")
    assert latencies[broken.id]["ms"] is None and "pbk" in latencies[broken.id]["error"]
    assert sum(1 for v in latencies.values() if v["ms"] == 50) >= 20
    assert m.snapshot()["latency"]["done"] == m.snapshot()["latency"]["total"]
    m.shutdown()


def test_provider_routes_toggle_and_profile_are_one_switch(world):
    m = world.manager
    sub = world.store.subscription("s-1")
    decoded = SimpleNamespace(meta=SimpleNamespace(routing="happ://routing/onadd/e30="), routing=None)
    m._store_provider_profile(sub, decoded)
    assert m.sub_set("s-1", {"provider_routes": True}) == {}
    profile = next(p for p in m.snapshot()["routing_profiles"] if p["id"] == "r-s-1")
    assert profile["active"] is True and profile["source"] == "subscription"
    m.profile_set("r-s-1", False)
    assert world.store.subscription("s-1").provider_routes is False


def test_provider_profile_saved_by_1_2_does_not_reconnect_vpn(world):
    """Выпуск 1.2 называл профиль «Маршруты «…»», 1.3 — «…: маршруты провайдера». Правила те же — первое
    обновление подписки после перехода не переподключает работающий VPN, а имя обновляется молча."""
    m = world.manager
    sub = world.store.subscription("s-1")
    sub.provider_routes = True
    text = "happ://routing/onadd/eyJOYW1lIjoiUCJ9"
    m._profiles.save([{"id": "r-s-1", "name": "Маршруты «Мой VPN»", "source": "subscription", "sub": "s-1",
                       "active": True, "text": text, "routing": None}])
    decoded = SimpleNamespace(meta=SimpleNamespace(routing=text), routing=None, route_lines=[])
    assert m._store_provider_profile(sub, decoded) is False, "правила те же — переподключать незачем"
    assert m._profiles.load()[0]["name"] == "Мой VPN: маршруты провайдера"
    decoded.meta.routing = "happ://routing/onadd/eyJOYW1lIjoiUSJ9"
    assert m._store_provider_profile(sub, decoded) is True, "правила другие — переподключение с ними"


def test_backup_roundtrip_restores_what_fits(tmp_path):
    m, w = make_manager(tmp_path / "a", basic_store())
    m.save_settings({"local_auth": True, "local_user": "me", "local_password": "Pass-123", "tun_mtu": 1400})
    target = tmp_path / "vpn.lzbackup"
    assert "сохранена" in m.backup_export("пароль-копии", str(target))["message"]
    other, w2 = make_manager(tmp_path / "b", FakeStore())
    result = other.backup_import("пароль-копии", str(target))
    assert "Восстановлено: серверов +4" in result["message"]
    assert w2.settings.get("vpnclient", "tun_mtu") == 1400 and w2.settings.get("vpnclient", "local_auth") is True
    assert other.snapshot()["settings"]["local_user"] == "me"
    with pytest.raises(Exception):
        other.backup_import("неверный", str(target))
    m.shutdown()
    other.shutdown()


def test_provider_routes_from_xray_json_follow_the_switch(world):
    m = world.manager
    routing = {"rules": [{"type": "field", "domain": ["geosite:category-ru"], "outboundTag": "direct"}]}
    fake = _with_subscription(world)
    fake.decode = lambda body, headers=None, *, sub_id=None: fake.real.Decoded(
        format="xray-json", servers=[server("Amsterdam", sub=None)], routing=routing)
    m.start()
    starts = len(_main_processes(world))
    assert m.sub_set("s-1", {"provider_routes": True}) == {}   # профиля ещё нет — подписка скачается заново
    assert wait_for(lambda: any(p["id"] == "r-s-1" for p in m.snapshot()["routing_profiles"]))
    assert m.wait_idle(10) and wait_for(lambda: not m.snapshot()["subscriptions"][0]["updating"])
    assert m.wait_idle(10)
    profile = next(p for p in m.snapshot()["routing_profiles"] if p["id"] == "r-s-1")
    assert profile["active"] is True and profile["summary"]["direct"] == 1
    plan = world.config.plans[-1]
    assert plan.profile_rules and "geosite-category-ru" in str(plan.profile_rules)
    assert len(_main_processes(world)) > starts, "маршруты провайдера применились перезапуском"
    m.sub_set("s-1", {"provider_routes": False})
    assert m.wait_idle(10)
    assert not world.config.plans[-1].profile_rules


# ------------------------------------------------------------ адреса серверов IPv6, списки своих правил

def test_dns_wire_format_aaaa():
    assert mgr._dns_query("example.com", "AAAA")[-4:] == b"\x00\x1c\x00\x01"           # AAAA, IN
    answer = bytes.fromhex("000081800001000100000000076578616d706c6503636f6d00001c0001"
                           "c00c001c00010000003c0010" "20010db8000000000000000000000001")
    assert mgr.parse_dns_answers(answer) == ["2001:db8::1"]


def test_resolver_asks_aaaa_when_ipv6_is_allowed():
    asked = []

    def query(host, url, qtype="A"):
        asked.append(qtype)
        return ["2001:db8::7"] if qtype == "AAAA" else []

    resolver = mgr.Resolver(query)
    with pytest.raises(mgr.VpnClientError, match="IPv4"):
        resolver.resolve("v6only.example.com")                     # «только IPv4»: сервер без A не годится
    asked.clear()
    assert resolver.resolve("v6only.example.com", families=("A", "AAAA")) == "2001:db8::7"
    assert asked == ["A", "AAAA"]
    asked.clear()
    assert resolver.resolve("v6only.example.com", families=("AAAA", "A")) == "2001:db8::7" and asked == ["AAAA"]
    with_v6, without_v6 = (lambda: True), (lambda: False)
    assert mgr._address_families({"ip_strategy": "ipv4_only", "ipv6": False}, with_v6) == ("A",)
    assert mgr._address_families({"ip_strategy": "ipv4_only", "ipv6": True}, with_v6) == ("A", "AAAA")
    assert mgr._address_families({"ip_strategy": "prefer_ipv4", "ipv6": False}, with_v6) == ("A", "AAAA")
    assert mgr._address_families({"ip_strategy": "prefer_ipv6", "ipv6": True}, with_v6) == ("AAAA", "A")
    # «сначала IPv6» без IPv6 у ПК: закреплённый AAAA не открылся бы — сначала A
    assert mgr._address_families({"ip_strategy": "prefer_ipv6", "ipv6": True}, without_v6) == ("A", "AAAA")


def test_plan_asks_server_addresses_by_ip_settings(world):
    world.settings.update(lambda d: d["vpnclient"].update({"ipv6": True, "ip_strategy": "prefer_ipv6"}))
    world.manager.deps.ipv6_internet = lambda: True
    world.manager.start()
    assert world.resolver.families and set(world.resolver.families) == {("AAAA", "A")}


def _rules_world(world, gate):
    """Файлы правил в памяти: update ждёт gate и «скачивает» всё, что просили."""
    have, updated = {}, []

    def update(ids, force=False):
        assert gate.wait(10)
        have.update({i: Path(f"C:/lz/rules/{i}.srs") for i in ids})
        updated.append(list(ids))
        return {i: "updated" for i in ids}

    world.manager.deps.rules = SimpleNamespace(paths=lambda ids: {i: have[i] for i in ids if i in have},
                                               missing=lambda ids: [i for i in ids if i not in have],
                                               status=lambda: {}, update=update)
    world.settings.update(lambda d: d["vpnclient"].__setitem__("proxy_sites", ["geosite:youtube", "a.example"]))
    return have, updated


def test_vpn_list_is_downloaded_and_applied_by_one_restart(world):
    """geosite:youtube из своего списка «только через VPN» — нужный файл; пока его нет, плашка честно говорит,
    что всё идёт через VPN; скачался — включённый VPN перезапускается с ним один раз."""
    import threading
    gate = threading.Event()
    _, updated = _rules_world(world, gate)
    m = world.manager
    m.start()
    starts = len(_main_processes(world))
    assert mgr.RULES_WAIT["user"] in world.alerts["vpn-rules"]["text"]
    assert "geosite-youtube" not in world.config.plans[-1].rules_files
    gate.set()
    assert wait_for(lambda: len(_main_processes(world)) == starts + 1), "скачался — перезапуск с ним"
    assert m.wait_idle(10) and updated == [["geosite-youtube"]]
    assert "geosite-youtube" in world.config.plans[-1].rules_files and "vpn-rules" not in world.alerts
    assert len(_main_processes(world)) == starts + 1 and m.status == "running"


def test_downloaded_lists_do_not_start_a_stopped_vpn(world):
    import threading
    gate = threading.Event()
    _, updated = _rules_world(world, gate)
    m = world.manager
    m.start()
    m.stop()
    starts = len(_main_processes(world))
    gate.set()
    assert wait_for(lambda: updated) and m.wait_idle(10)
    assert m.status == "stopped" and len(_main_processes(world)) == starts


def test_failed_list_download_is_an_alert_not_a_silent_success(world):
    m = world.manager
    world.settings.update(lambda d: d["vpnclient"].__setitem__("proxy_sites", ["geosite:youtube"]))
    m.deps.rules = SimpleNamespace(paths=lambda ids: {}, missing=lambda ids: list(ids), status=lambda: {},
                                   update=lambda ids, force=False: {i: "failed" for i in ids})
    m.start()
    assert wait_for(lambda: (world.alerts.get("vpn-rules") or {}).get("level") == "warn")
    alert = world.alerts["vpn-rules"]
    assert "geosite-youtube" in alert["text"] and mgr.RULES_WAIT["user"][1:] in alert["text"]
    assert alert["action"]["call"] == "vpnclient_rules_update"


def test_ipv6_internet_needs_a_global_address_and_a_direct_default_route(monkeypatch):
    """IPv6 есть, если он есть у прямого выхода в интернет (тот же выбор, что для привязки помощника Xray):
    маршрут ::/0 через прямой адаптер и глобальный адрес. Свой TUN и Radmin не в счёт."""
    from app import vpn

    def adapter(index=1, name="Ethernet", if_type=6, ipv6=("2a00:1450:4010::12",)):
        return vpn.Adapter(index=index, guid="{%d}" % index, name=name, description=name, if_type=if_type, up=True,
                           ipv4=["192.168.1.5"], ipv6=list(ipv6), gateways=["192.168.1.1", "fe80::1"])

    drivers = {"{1}": (r"PCI\VEN_10EC", vpn.NCF_PHYSICAL), "{2}": (r"PCI\VEN_8086", vpn.NCF_PHYSICAL),
               "{3}": ("wintun", vpn.NCF_VIRTUAL), "{4}": (r"{B06D84D1}\RvNetMP60", vpn.NCF_VIRTUAL)}
    v4 = [("0.0.0.0", 0, "192.168.1.1", 1, 0)]
    v6 = [("::", 0, "fe80::1", 1, 0)]
    for adapters, table, expected in (
            ([adapter()], v4 + v6, True),
            ([adapter(ipv6=("fe80::5%12", "fd12::5"))], v4 + v6, False),          # link-local и ULA — не интернет
            ([adapter(ipv6=("2001:0:53aa:64c::5",))], v4 + v6, False),              # Teredo
            ([adapter()], v4, False),                                               # маршрута ::/0 нет
            ([adapter(), adapter(3, mgr.TUN_NAME, 53)], v4 + [("::", 0, "", 3, 0)], False),  # ::/0 — в свой TUN
            ([adapter(4, "Radmin VPN", ipv6=("2a00:1450:4010::12",))], [("::", 0, "fe80::1", 4, 0)], False),
            ([adapter(ipv6=()), adapter(2, "Wi-Fi", 71)], v4 + [("::", 0, "fe80::1", 2, 0)], True)):
        monkeypatch.setattr(vpn, "list_adapters", lambda adapters=adapters: adapters)
        monkeypatch.setattr(vpn, "_driver_info", lambda: drivers)
        monkeypatch.setattr(vpn, "routes", lambda table=table: list(table))
        assert mgr.ipv6_internet() is expected, adapters

    def broken():
        raise OSError(87, "GetAdaptersAddresses")
    monkeypatch.setattr(vpn, "list_adapters", broken)
    assert mgr.ipv6_internet() is False


def test_prefer_ipv6_without_ipv6_pins_ipv4_and_network_change_reresolves(world):
    """«Сначала IPv6»: есть IPv6 у ПК — в конфиге AAAA; сеть сменилась и IPv6 пропал — перезапуск с A
    (в конфиге один адрес сервера, иначе VPN так и не подключился бы)."""
    m = world.manager
    world.settings.update(lambda d: d["vpnclient"].update({"ipv6": True, "ip_strategy": "prefer_ipv6"}))
    v6 = {"on": True}
    m.deps.ipv6_internet = lambda: v6["on"]
    world.resolver.resolve = lambda host, preferred=None, *, families=("A",):         "2001:db8::5" if families[0] == "AAAA" else "203.0.113.5"
    m.start()
    assert set(world.config.plans[-1].addresses.values()) == {"2001:db8::5"}
    starts = len(_main_processes(world))
    v6["on"] = False
    m.on_network_change()
    assert wait_for(lambda: len(_main_processes(world)) == starts + 1), "IPv6 пропал — перезапуск"
    assert m.wait_idle(10) and m.status == "running"
    assert set(world.config.plans[-1].addresses.values()) == {"203.0.113.5"}
    m.on_network_change()                                        # IPv4 в конфиге — перезапуск не нужен
    assert m.wait_idle(10) and len(_main_processes(world)) == starts + 1
