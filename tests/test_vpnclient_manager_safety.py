"""Свой VPN: страховки менеджера по ревью — kill switch при перезапуске, системный прокси при выходе
и падении помощника, правила «через обход» на работающем ядре, секреты в именах и ссылках провайдера,
неудачный автоматический перезапуск, очередь за проверкой выхода, kill switch и замер задержки."""
import threading
from types import SimpleNamespace

import pytest

from app import log as applog
from app.vpnclient import diagnose
from app.vpnclient import manager as mgr
from app.vpnclient.model import BypassProfile, Subscription
from tests.fakes.vpn_world import FakeStore, basic_store, make_manager, server, wait_for


def _main(world):
    return [p for p in world.processes if p.name == "sing-box"]


# ------------------------------------------------------------ kill switch при перезапуске

def test_restart_keeps_kill_switch(tmp_path):
    m, w = make_manager(tmp_path, basic_store())
    w.settings.update(lambda d: d["vpnclient"].__setitem__("kill_switch", True))
    m.start()
    disabled = []
    real_disable = w.killswitch.disable
    w.killswitch.disable = lambda: (disabled.append(True), real_disable())
    m.restart()
    assert m.wait_idle(10) and m.status == "running" and len(_main(w)) == 2
    assert not disabled and w.killswitch.active, "между старым и новым туннелем интернет не открывается"
    assert w.killswitch.enabled_with[0] == 42                 # фильтры заменены под новый запуск
    m.stop()
    assert disabled and not w.killswitch.active
    m.shutdown()


def test_failed_restart_keeps_kill_switch_and_says_so(tmp_path):
    m, w = make_manager(tmp_path, basic_store())
    w.settings.update(lambda d: d["vpnclient"].__setitem__("kill_switch", True))
    m.start()
    w.start_failures.append("FATAL[0000] start service: initialize outbound: broken")
    try:
        m.restart()
    except Exception:  # noqa: BLE001 — ошибка запуска — тоже ответ; проверяем состояние
        pass
    assert m.wait_idle(10)
    snap = m.snapshot()
    assert snap["status"] == "error" and w.killswitch.active
    assert "Kill switch держит интернет закрытым" in snap["error"]
    m.stop()
    assert not w.killswitch.active and m.status == "stopped"
    m.shutdown()


def _ks_world(tmp_path):
    m, w = make_manager(tmp_path, basic_store())
    w.settings.update(lambda d: d["vpnclient"].__setitem__("kill_switch", True))
    asked = []
    luid = {"value": 42}
    m.deps.tun_luid = lambda address: (asked.append(address), luid["value"])[1]
    return m, w, asked, luid


def test_kill_switch_finds_own_tun_by_its_address(tmp_path):
    """LUID своего TUN — по адресу своей /30: имя «Lazeyka» мог занять осиротевший адаптер."""
    m, w, asked, _luid = _ks_world(tmp_path)
    m.start()
    assert asked == ["100.127.255.253"] and w.killswitch.enabled_with[0] == 42
    m.shutdown()


def test_kill_switch_without_own_tun_is_not_enabled(tmp_path):
    """Свой TUN не нашёлся — фильтры не ставятся (они закрыли бы и сам VPN), VPN работает, плашка."""
    m, w, _asked, luid = _ks_world(tmp_path)
    luid["value"] = None
    m.start()
    snap = m.snapshot()
    assert snap["status"] == "running" and snap["verified"] and not w.killswitch.active
    assert "адаптер своего VPN не найден" in w.alerts["vpn-killswitch"]["text"]
    assert "Kill switch: " not in w.alerts["vpn-killswitch"]["text"], "без повтора «Kill switch» в тексте"
    m.shutdown()


def test_failed_reenable_on_restart_drops_stale_filters(tmp_path):
    """Перезапуск: под новый TUN фильтры не встали — прежние (с LUID прежнего TUN) сняты, иначе они
    закрыли бы интернет и новому сеансу, а страница показывала бы «Подключено»."""
    m, w, _asked, luid = _ks_world(tmp_path)
    m.start()
    assert w.killswitch.active
    luid["value"] = None
    m.restart()
    assert m.status == "running" and not w.killswitch.active and "vpn-killswitch" in w.alerts
    luid["value"] = 43
    m.restart()
    assert m.status == "running" and w.killswitch.active and w.killswitch.enabled_with[0] == 43
    assert "vpn-killswitch" not in w.alerts
    m.shutdown()


def test_new_lan_networks_reuse_own_tun_and_keep_filters(tmp_path):
    """Включили Radmin после VPN: фильтры того же TUN переставляются с тем же LUID — адаптер заново не ищется,
    и миг, когда таблица адаптеров его не отдала, не снимает защиту от утечек."""
    m, w, asked, luid = _ks_world(tmp_path)
    m.start()
    assert w.killswitch.active and asked == ["100.127.255.253"]
    luid["value"] = None                                   # таблица адаптеров своего TUN сейчас не отдаёт
    m.deps.lan_networks = lambda: [(7, ["26.0.0.0/8"])]
    m._after_network_change()
    assert w.killswitch.active and w.killswitch.enabled_with[0] == 42 and w.killswitch.lan == [(7, ["26.0.0.0/8"])]
    assert asked == ["100.127.255.253"] and "vpn-killswitch" not in w.alerts
    m.shutdown()


def test_failed_refresh_for_new_lan_keeps_previous_filters(tmp_path):
    """Перестановка под новые локальные сети не удалась (WFP не ответила): прежние фильтры того же TUN
    остаются — VPN не работает без защиты, а плашка говорит, что не открыты только новые сети. Проверка
    здоровья повторяет перестановку."""
    from app.vpnclient.killswitch import KillSwitchError
    m, w, _asked, _luid = _ks_world(tmp_path)
    m.start()
    disabled = []
    real_enable, real_disable = w.killswitch.enable, w.killswitch.disable
    w.killswitch.disable = lambda: (disabled.append(True), real_disable())

    def refused(**kw):
        raise KillSwitchError("Kill switch: не удалось применить фильтры (0x80320009)")

    w.killswitch.enable = refused
    m.deps.lan_networks = lambda: [(7, ["26.0.0.0/8"])]
    m._after_network_change()
    assert w.killswitch.active and not disabled and w.killswitch.lan == []
    text = w.alerts["vpn-killswitch"]["text"]
    assert "не открыл новые локальные сети" in text and "Защита от утечек работает" in text
    assert "Kill switch: " not in text
    w.killswitch.enable = real_enable
    m._check_health()
    assert w.killswitch.lan == [(7, ["26.0.0.0/8"])] and "vpn-killswitch" not in w.alerts
    m.shutdown()


def test_stale_filters_that_stay_fail_the_restart(tmp_path):
    """Прежние фильтры не снялись — запуск не удался: интернет закрыт, и страница говорит об этом."""
    from app.vpnclient.killswitch import KillSwitchError
    m, w, _asked, luid = _ks_world(tmp_path)
    m.start()
    luid["value"] = None

    def stuck():
        raise KillSwitchError("Kill switch: не удалось снять фильтры — служба базовой фильтрации Windows недоступна")

    w.killswitch.disable = stuck
    with pytest.raises(mgr.VpnClientError):
        m.restart()
    snap = m.snapshot()
    assert snap["status"] == "error" and w.killswitch.active
    assert "Kill switch держит интернет закрытым" in snap["error"]
    m.shutdown()


def test_tun_luid_needs_exactly_one_live_adapter_with_own_address():
    def adapter(name, index, ipv4, up=True):
        return SimpleNamespace(name=name, index=index, ipv4=ipv4, up=up)

    own = "100.127.255.253"
    luid_of = lambda index: 1000 + index  # noqa: E731
    orphan = adapter("Lazeyka", 7, [own], up=False)             # осиротевший адаптер прошлого сеанса
    fresh = adapter("Lazeyka 2", 9, [own])
    assert mgr.tun_luid(own, 0, lambda: [orphan, fresh, adapter("Ethernet", 3, ["192.168.1.5"])], luid_of) == 1009
    assert mgr.tun_luid(own, 0, lambda: [fresh, adapter("Другой", 11, [own])], luid_of) is None, "не понять, какой свой"
    assert mgr.tun_luid(own, 0, lambda: [orphan], luid_of) is None

    def broken():
        raise OSError(1, "GetAdaptersAddresses")

    assert mgr.tun_luid(own, 0, broken, luid_of) is None
    calls = []

    def appears():                                            # адрес появился не сразу после старта ядра
        calls.append(1)
        return [fresh] if len(calls) > 1 else []

    assert mgr.tun_luid(own, 5, appears, luid_of) == 1009 and len(calls) == 2


# ------------------------------------------------------------ системный прокси

def test_helper_crash_keeps_system_proxy(tmp_path):
    """Упал только помощник Xray: sing-box с портом прокси жив — прокси не снимаем (раньше снимали
    и не возвращали, а VPN показывался работающим)."""
    m, w = make_manager(tmp_path, basic_store(xhttp=True))
    w.settings.update(lambda d: d["vpnclient"].__setitem__("mode", "proxy"))
    m.select(next(s.id for s in w.store.servers() if s.network == "xhttp"))
    m.start()
    assert w.sysproxy.applied == "127.0.0.1:20808"
    w.advance(120)
    helper = [p for p in w.processes if p.name == "xray"][-1]
    helper.crash()
    assert m.wait_idle(10)
    assert m.status == "running" and w.sysproxy.applied == "127.0.0.1:20808"
    assert len([p for p in w.processes if p.name == "xray"]) == 2 and len(_main(w)) == 1
    m.shutdown()
    assert w.sysproxy.applied is None


def test_shutdown_closes_proxy_and_restores_after_stop(tmp_path):
    m, w = make_manager(tmp_path, basic_store())
    w.settings.update(lambda d: d["vpnclient"].__setitem__("mode", "proxy"))
    w.sysproxy.close = lambda: w.events.append(("proxy-close", None))
    m.start()
    m.shutdown()
    kinds = [e[0] for e in w.events if e[0].startswith("proxy-")]
    assert kinds[:2] == ["proxy-apply", "proxy-close"], "новые включения запрещены до восстановления"
    assert kinds.count("proxy-restore") >= 2              # второе — после остановки ядра
    assert w.sysproxy.applied is None


def test_stop_retries_restore_when_nothing_runs(tmp_path):
    m, w = make_manager(tmp_path, basic_store())
    m.stop()
    assert ("proxy-restore", None) in w.events            # прошлое восстановление могло вернуть не всё
    m.shutdown()


# ------------------------------------------------------------ «через обход» на работающем ядре

def test_list_change_rewrites_rules_without_restart(tmp_path):
    m, w = make_manager(tmp_path, basic_store())
    m.start()
    calls = w.routing.calls
    m.set_bypass(w.view)
    assert m.wait_idle(10)
    assert w.routing.calls == calls + 1 and len(_main(w)) == 1   # файлы переписаны, ядро перечитает
    m.shutdown()


def test_profile_change_restarts_with_kill_switch(tmp_path):
    m, w = make_manager(tmp_path, basic_store())
    w.settings.update(lambda d: d["vpnclient"].__setitem__("kill_switch", True))
    m.start()
    disabled = []
    w.killswitch.disable = lambda: disabled.append(True)
    w.routing.bypass_from_strategy = lambda *a, **kw: SimpleNamespace(
        profiles=[BypassProfile(network="tcp", ports=["443", "2053"])], voice_ports=["50000-50100"], notes=[])
    m.set_bypass(w.view)
    assert m.wait_idle(10)
    assert len(_main(w)) == 2 and m.status == "running" and not disabled
    assert w.config.plans[-1].bypass[0].ports == ["443", "2053"]
    m.shutdown()


def test_bypass_gone_restarts_without_rules(tmp_path):
    m, w = make_manager(tmp_path, basic_store())
    m.start()
    assert w.config.plans[-1].via_zapret
    w.view.strategy_args = []                            # стратегия не разобралась или пакета нет
    m.set_bypass(w.view)
    assert m.wait_idle(10)
    assert len(_main(w)) == 2 and not w.config.plans[-1].via_zapret
    m.shutdown()


# ------------------------------------------------------------ секреты в именах и ссылках провайдера

def test_secrets_in_names_and_links_are_not_shown(tmp_path):
    uuid = "9f8e7d6c-5b4a-4321-8765-0123456789ab"
    srv = server("Amsterdam", uuid=uuid)
    srv.name = f"Амстердам {srv.uuid}"
    sub_url = "https://panel.example.com/sub/Zq8xT0kenSecret42"
    sub = Subscription(id="s-1", name="Мой VPN", url=sub_url, web_page_url=sub_url,
                       support_url="https://t.me/example_support", added_at=1.0, updated_at=1.0)
    m, w = make_manager(tmp_path, FakeStore([srv], [sub], selected=srv.id))
    try:
        m.init()                                          # секреты профилей — в фильтр журнала
        snap = m.snapshot()
        info = snap["subscriptions"][0]
        assert info["web_page_url"] == "hidden" and info["support_url"] == "https://t.me/example_support"
        shown = snap["servers"][0]["name"]
        assert srv.uuid not in shown and "Амстердам" in shown
        assert m.open_link("s-1", "page") == sub_url and m.open_link("s-1", "support").startswith("https://t.me/")
    finally:
        applog.remove_secrets(mgr._server_secrets(srv) + [sub_url])
        m.shutdown()


# ------------------------------------------------------------ неудачный автоматический перезапуск

def _quiet_world(tmp_path, store=None, *, kill_switch=False):
    """Мир без фоновых задач ядер: тест двигает часы и зовёт tick сам."""
    m, w = make_manager(tmp_path, store or basic_store())
    w.engines.allowed = False
    if kill_switch:
        w.settings.update(lambda d: d["vpnclient"].__setitem__("kill_switch", True))
    return m, w


def _tick_after(m, w, seconds):
    w.advance(seconds)
    m.tick()
    assert m.wait_idle(10)


def test_failed_auto_restart_alerts_and_retries_with_pauses(tmp_path):
    m, w = _quiet_world(tmp_path)
    m.start()
    w.notices.clear()
    # Стратегия обхода сменилась — нужен перезапуск, а DoH в этот момент не ответил.
    w.routing.bypass_from_strategy = lambda *a, **k: SimpleNamespace(
        profiles=[BypassProfile(network="udp", ports=["50000-50100"])], voice_ports=[], notes=[])
    w.resolver.fail.update(s.host for s in w.store.servers())
    m.set_bypass(w.view)
    assert m.wait_idle(10) and m.status == "error"
    crash = w.alerts["vpn-crash"]
    assert "не перезапустился" in crash["text"] and "Повторим через 30 с" in crash["text"]
    assert crash["action"]["call"] == "vpnclient_start" and w.notices == [], "плашка, а не уведомление"
    _tick_after(m, w, 29)
    assert m.status == "error" and len(_main(w)) == 1, "раньше паузы не повторяет"
    _tick_after(m, w, 1)                                  # повтор тоже не удался — следующий через 2 минуты
    assert m.status == "error" and "Повторим через 2 мин" in w.alerts["vpn-crash"]["text"]
    w.resolver.fail.clear()
    _tick_after(m, w, 119)
    assert m.status == "error" and len(_main(w)) == 1
    _tick_after(m, w, 1)
    assert m.status == "running" and len(_main(w)) == 2
    assert "vpn-crash" not in w.alerts, "заработало — плашка снята"
    assert w.config.plans[-1].bypass[0].network == "udp"
    m.shutdown()


def test_failed_auto_restart_with_kill_switch_waits_for_stop(tmp_path):
    m, w = _quiet_world(tmp_path, kill_switch=True)
    m.start()
    other = next(s for s in w.store.servers() if s.sub == "s-2")
    w.resolver.fail.add(other.host)
    m.select(other.id)                                    # сервера нет в конфиге — перезапуск фоном
    assert m.wait_idle(10) and m.status == "error"
    assert w.killswitch.active, "VPN не выключали — интернет закрыт и между попытками"
    crash = w.alerts["vpn-crash"]
    assert "Kill switch держит интернет закрытым" in crash["text"] and "Повторим" in crash["text"]
    assert crash["action"]["call"] == "vpnclient_stop" and crash["page"] == "vpnclient"
    m.stop()
    assert not w.killswitch.active and m.status == "stopped" and "vpn-crash" not in w.alerts
    started = len(w.processes)
    _tick_after(m, w, 600)
    assert m.status == "stopped" and len(w.processes) == started, "выключили — повтора нет"
    m.shutdown()


def test_restart_by_button_reports_error_without_retry(tmp_path):
    m, w = _quiet_world(tmp_path)
    m.start()
    w.resolver.fail.update(s.host for s in w.store.servers())
    with pytest.raises(mgr.VpnClientError):
        m.restart()
    assert m.status == "error" and "vpn-crash" not in w.alerts, "ошибку человек получил ответом"
    w.resolver.fail.clear()
    _tick_after(m, w, 600)
    assert m.status == "error" and len(_main(w)) == 1
    m.shutdown()


# ------------------------------------------------------------ kill switch, когда сбой — после старта ядра

def test_restart_failing_after_launch_keeps_kill_switch(tmp_path):
    m, w = _quiet_world(tmp_path, kill_switch=True)
    m.start()
    w.select_error = "ядро не отвечает на PUT /proxies/proxy: timed out"
    with pytest.raises(mgr.VpnClientError):
        m.restart()
    assert m.status == "error" and w.killswitch.active, "селектор не переключился — интернет всё равно закрыт"
    assert "Kill switch держит интернет закрытым" in m.snapshot()["error"]
    w.select_error = None
    m.start()
    assert m.status == "running"
    w.advance(120)
    w.select_error = "ядро не отвечает на PUT /proxies/proxy: timed out"
    _main(w)[-1].crash()                                  # перезапуск после падения — тот же сбой
    assert m.wait_idle(10)
    assert m.status == "error" and w.killswitch.active
    assert w.alerts["vpn-crash"]["action"]["call"] == "vpnclient_stop"
    m.stop()
    assert not w.killswitch.active
    m.shutdown()


def test_first_start_failing_after_kill_switch_drops_it(tmp_path):
    m, w = _quiet_world(tmp_path, kill_switch=True)

    class BrokenSampler:
        def __init__(self, client, *, groups=()):
            pass

        def start(self):
            assert w.killswitch.active                    # фильтры уже стояли
            raise RuntimeError("сэмплер не запустился")

        def stop(self, wait=0.0):
            pass

        def totals(self):
            return 0, 0

    m.deps.sampler = BrokenSampler
    with pytest.raises(RuntimeError):
        m.start()
    assert m.status == "error" and not w.killswitch.active, "VPN не включился — интернет не закрываем"
    m.shutdown()


# ------------------------------------------------------------ очередь за проверкой выхода мёртвого сервера

def _stuck_exit_check(m, w, stuck_at):
    """Сервер умер: попытки проверки выхода до stuck_at не проходят, попытка stuck_at висит, пока тест её
    не отпустит; следующие — отвечают."""
    w.exit_ok = False
    m.start()
    assert m.status == "running" and not m.snapshot()["verified"]
    calls, reach = [], []
    entered, release = threading.Event(), threading.Event()

    def exit_check(port, user, password, timeout):
        calls.append(timeout)
        if len(calls) > stuck_at:
            return {"ip": "203.0.113.5", "country": "NL", "date": None}
        if len(calls) == stuck_at:
            entered.set()
            release.wait(10)
        raise OSError("timed out")

    m.deps.exit_check = exit_check
    m.deps.tcp_probe = lambda *a: reach.append(a) or diagnose.TcpProbe("ok", 12.0)
    # Причина прошлой неудачи годится DIAGNOSIS_REUSE — дальше разбор снова пробует сервер напрямую.
    w.advance(max(mgr.UNVERIFIED_RETRY, mgr.DIAGNOSIS_REUSE))
    m.tick()                                              # проверка здоровья: выход ещё не подтверждён
    assert entered.wait(5)
    return calls, reach, release


def test_stop_does_not_wait_for_exit_checks(tmp_path):
    m, w = _quiet_world(tmp_path)
    last = len(mgr.RECHECK_TIMEOUTS)
    calls, reach, release = _stuck_exit_check(m, w, stuck_at=last)   # висит последняя — дальше разбор причины
    assert calls == list(mgr.RECHECK_TIMEOUTS), "фоновая проверка — с короткими тайм-аутами"
    w.advance(mgr.UNVERIFIED_RETRY)
    m.tick()
    assert not m._ops.waiting("health"), "пока идёт проверка, вторая за ней не встаёт"
    stopper = threading.Thread(target=m.stop)
    stopper.start()
    assert wait_for(m._abort.is_set)
    release.set()
    stopper.join(10)
    assert not stopper.is_alive() and m.status == "stopped"
    assert len(calls) == last and reach == [], "после «Выключить» ни новых попыток, ни разбора причины"
    m.shutdown()


def test_select_does_not_wait_for_exit_check(tmp_path):
    m, w = _quiet_world(tmp_path)
    calls, reach, release = _stuck_exit_check(m, w, stuck_at=1)
    berlin = next(s for s in w.store.servers() if s.name == "Berlin")
    m.select(berlin.id)                                   # в конфиге — без перезапуска
    release.set()
    assert m.wait_idle(10)
    assert w.clients[-1].selects[-1] == ("proxy", f"t-{berlin.id}")
    assert len(calls) == 2 and reach == [], "проверка уступила выбору; выход проверил уже он"
    assert m.snapshot()["verified"] and len(_main(w)) == 1
    m.shutdown()


def test_select_of_same_server_does_not_cut_exit_check(tmp_path):
    m, w = _quiet_world(tmp_path)
    calls, reach, release = _stuck_exit_check(m, w, stuck_at=1)
    m.select(w.store.selected())                          # тот же сервер — _switch ничего не проверит
    release.set()
    assert m.wait_idle(10)
    assert len(calls) == 2 and m.snapshot()["verified"], "проверка дошла до конца сама"
    m.shutdown()


# ------------------------------------------------------------ kill switch и временное ядро замера задержки

def test_latency_outside_config_with_kill_switch(tmp_path):
    a, b = server("Amsterdam"), server("Berlin")
    other = server("Other", sub="s-2")                    # вне конфига, хватает sing-box
    helper_only = server("Xhttp", sub="s-2", network="xhttp")   # нужен помощник Xray, в подключении его нет
    subs = [Subscription(id="s-1", name="A", url="https://a.example/x1TOKEN", added_at=1.76e9, updated_at=1.76e9),
            Subscription(id="s-2", name="B", url="https://b.example/x2TOKEN", added_at=1.76e9, updated_at=1.76e9)]
    m, w = _quiet_world(tmp_path, FakeStore([a, b, other, helper_only], subs, [], selected=a.id), kill_switch=True)
    m.start()
    allowed = set(w.killswitch.enabled_with[1])
    w.engines.versions["sing-box"].add("1.15.0")         # автообновление: новая — со следующего подключения
    with m._core_lock("sing-box"):
        m._activate_core("sing-box", "1.15.0", trial=True)
    before = len(w.processes)
    m.latency([other.id, helper_only.id])
    assert wait_for(lambda: not m.snapshot()["latency"]["running"])
    temp = w.processes[before:]
    assert [p.name for p in temp] == ["sing-box"] and str(temp[0].exe) in allowed, \
        "замер — на ядре, которое kill switch пропускает"
    latency = w.store.latency()
    assert latency[other.id]["ms"] == 50
    assert latency[helper_only.id]["ms"] is None and "kill switch" in latency[helper_only.id]["error"]
    m.stop()
    m.latency([helper_only.id])                           # kill switch снят — меряется как обычно
    assert wait_for(lambda: not m.snapshot()["latency"]["running"])
    assert w.store.latency()[helper_only.id]["ms"] == 50
    m.shutdown()


# ------------------------------------------------------------ помощник Xray и чужой VPN

def test_helper_binds_to_physical_adapter_only_in_tun(tmp_path):
    """В режимах прокси своего TUN нет: помощник идёт по маршрутам Windows, как sing-box, — при чужом
    VPN трафик серверов через помощника не уходит мимо него."""
    for mode, expected in (("tun", "Ethernet"), ("proxy", None), ("local", None)):
        m, w = make_manager(tmp_path / mode, basic_store(xhttp=True))
        w.settings.update(lambda d, mode=mode: d["vpnclient"].__setitem__("mode", mode))
        m.select(next(s.id for s in w.store.servers() if s.network == "xhttp"))
        m.start()
        assert w.config.plans[-1].physical_interface == expected, mode
        m.shutdown()


# ------------------------------------------------------------ очередь действий при выходе

def test_worker_close_finishes_queued_and_ends_thread():
    worker = mgr._Worker("vpnclient-ops-test")
    gate, done = threading.Event(), []
    worker.submit(lambda: (gate.wait(5), done.append("first")))
    worker.submit(lambda: done.append("second"))
    worker.close()
    assert worker.submit(lambda: done.append("late")) is False, "после close() задачи не принимаются"
    with pytest.raises(mgr.VpnClientError, match="завершает работу"):
        worker.call(lambda: "late")
    gate.set()
    worker._thread.join(5)
    assert not worker._thread.is_alive() and done == ["first", "second"], "поставленное до close() доработало"


def test_shutdown_ends_ops_thread_and_repeats_quietly(tmp_path):
    m, _w = make_manager(tmp_path, basic_store())
    m.start()
    m.shutdown()
    m._ops._thread.join(5)
    assert not m._ops._thread.is_alive(), "поток очереди не переживает выход"
    m.shutdown()                                          # второй выход ничего не ждёт и не падает
    assert m.status == "stopped"
