"""Постоянные плашки (решение владельца 2026-10-18): о поломках, найденных без нажатия человека, —
только плашка в окне, без уведомлений. Жизненный цикл, сторож, обход, свой VPN и значок в трее.
Ядро VPN не запускается, сеть и система не трогаются."""
import time
from types import SimpleNamespace

import pytest

from app import log as applog
from app.errors import UserError
from tests.fakes.vpn_world import FakeSubscription, basic_store, make_manager, wait_for
from tests.test_vpnclient_core import FakeManager, make_core


def _alert(core, alert_id):
    return next((n for n in core.notices() if n["id"] == alert_id), None)


def _transient(core):
    return [n for n in core.notices() if not n["persistent"]]


# ------------------------------------------------------------ жизненный цикл

def test_alert_lifecycle_set_dismiss_clear_reappear(tmp_path):
    core = make_core(tmp_path, None)
    toasts = []
    core.ui_visible, core.on_toast = False, toasts.append          # окно скрыто: notify дал бы уведомление Windows
    core.set_alert("demo", "warn", "Discord перестал открываться", page="zapret",
                   action={"label": "Найти и включить", "call": "zapret_fix", "args": []})
    alert = _alert(core, "demo")
    assert alert == {"id": "demo", "level": "warn", "text": "Discord перестал открываться",
                     "action": {"label": "Найти и включить", "call": "zapret_fix", "args": []},
                     "page": "zapret", "dismissible": True, "persistent": True}
    assert toasts == [] and _transient(core) == [], "плашка — не уведомление и не уведомление Windows"

    assert core.dismiss_notice("demo") == {"ok": True}
    assert _alert(core, "demo") is None
    core.set_alert("demo", "warn", "Discord и YouTube перестали открываться")   # проблема всё ещё есть
    assert _alert(core, "demo") is None, "скрытая крестиком не возвращается, пока проблема не прошла"
    assert core.has_alert("demo")

    core.clear_alert("demo")
    assert not core.has_alert("demo") and _alert(core, "demo") is None
    core.set_alert("demo", "warn", "Discord перестал открываться снова")
    assert _alert(core, "demo")["text"] == "Discord перестал открываться снова", "проблема вернулась — и плашка"


def test_alert_text_is_scrubbed_and_levels_ordered(tmp_path):
    core = make_core(tmp_path, None)
    applog.add_secrets(["TOKEN-SECRET-42"])
    core.set_alert("a-info", "info", "Справка")
    core.set_alert("a-error", "error", "Подписка https://x.example/TOKEN-SECRET-42 не загрузилась")
    core.set_alert("a-warn", "warn", "Предупреждение")
    core.notify("info", "временное")
    ids = [n["id"] for n in core.notices()]
    assert ids[:3] == ["a-error", "a-warn", "a-info"], "серьёзные первыми, временные — после плашек"
    assert "TOKEN-SECRET-42" not in _alert(core, "a-error")["text"]
    transient = _transient(core)
    assert len(transient) == 1 and transient[0]["page"] is None and transient[0]["persistent"] is False


def test_alert_callback_for_managers(tmp_path):
    core = make_core(tmp_path, None)
    core.alert("vpn-exit", "warn", "Через сервер ничего не открывается", page="vpnclient")
    assert _alert(core, "vpn-exit")["page"] == "vpnclient"
    core.alert("vpn-exit", None)
    assert not core.has_alert("vpn-exit")


def test_fixed_persistent_notices_are_marked(tmp_path):
    core = make_core(tmp_path, None)
    core.is_admin = False
    admin = _alert(core, "admin")
    assert admin["persistent"] is True and admin["page"] is None


# ------------------------------------------------------------ сторож обхода

@pytest.fixture
def watchdog_core(tmp_path, monkeypatch):
    core = make_core(tmp_path, None)
    core.zapret.status = "running"
    core._wd_fails, core._wd_next, core._wd_busy = 0, 0.0, False
    sites = {"discord": False, "youtube": True}
    monkeypatch.setattr("app.zapret.tester.control_ok", lambda *a, **k: True)
    monkeypatch.setattr("app.zapret.tester.quick_check", lambda *a, **k: [
        {"id": "discord", "label": "Discord", "ok": sites["discord"], "detail": ""},
        {"id": "youtube", "label": "YouTube", "ok": sites["youtube"], "detail": ""}])
    core.sites = sites
    return core


def test_watchdog_ask_sets_alert_without_notify(watchdog_core):
    core = watchdog_core
    core._watchdog_check("ask")
    assert _alert(core, "watchdog") is None, "один сбой — ещё не поломка"
    core._watchdog_check("ask")
    alert = _alert(core, "watchdog")
    assert alert["level"] == "warn" and alert["page"] == "zapret"
    assert alert["text"] == "Discord перестал открываться. Найти рабочую стратегию?"
    assert alert["action"] == {"label": "Найти и включить", "call": "zapret_fix", "args": []}
    assert _transient(core) == [], "сторож больше не шлёт уведомлений"
    # Через 10 минут то же самое — плашка та же, уведомлений по-прежнему нет.
    core._watchdog_check("ask")
    core._watchdog_check("ask")
    assert [n["id"] for n in core.notices()] == ["watchdog"]
    core.sites.update(discord=True)
    core._watchdog_check("ask")
    assert _alert(core, "watchdog") is None, "удачная проверка снимает плашку"


def test_watchdog_plural_text(watchdog_core):
    core = watchdog_core
    core.sites.update(youtube=False)
    core._watchdog_check("ask")
    core._watchdog_check("ask")
    assert _alert(core, "watchdog")["text"].startswith("Discord и YouTube перестали открываться.")


def test_watchdog_auto_shows_progress_then_result(watchdog_core):
    core = watchdog_core
    fixes = []
    core.tester.start_fix = lambda: fixes.append(1)
    core._watchdog_check("auto")
    core._watchdog_check("auto")
    assert fixes == [1]
    alert = _alert(core, "watchdog")
    assert alert["text"] == "Discord перестал открываться — подбираю рабочую стратегию." and alert["action"] is None
    assert _transient(core) == []
    # Подбор не нашёл стратегию — «подбираю…» меняется на итог с кнопкой.
    core.tester.fix_state = {"finished_at": time.time(), "stage": "failed",
                             "message": "Среди лучших стратегий подходящей не нашлось."}
    core._reconcile_alerts()
    alert = _alert(core, "watchdog")
    assert "подобрать стратегию не вышло" in alert["text"] and alert["action"]["call"] == "zapret_fix"
    # Человек нажал «Найти и включить», нашлось — плашка снята.
    core.tester.fix_state = {"finished_at": time.time() + 1, "stage": "done", "message": "Включили «ALT5»"}
    core._reconcile_alerts()
    assert _alert(core, "watchdog") is None


def test_old_fix_does_not_clear_new_watchdog_alert(watchdog_core):
    core = watchdog_core
    core.tester.fix_state = {"finished_at": time.time() - 3600, "stage": "done", "message": "Включили «ALT5»"}
    core._watchdog_check("ask")
    core._watchdog_check("ask")
    core._reconcile_alerts()
    assert core.has_alert("watchdog"), "«Найти и включить» час назад — не про эту поломку"


def test_manual_check_clears_watchdog_alert(watchdog_core):
    core = watchdog_core
    core._watchdog_check("ask")
    core._watchdog_check("ask")
    assert core.has_alert("watchdog")
    core._check_fp = core._zapret_fingerprint()
    core.tester.check_state = {"running": False, "at": time.time() + 1, "direct": False,
                               "results": [{"id": "discord", "label": "Discord", "ok": True},
                                           {"id": "youtube", "label": "YouTube", "ok": True}]}
    core._reconcile_alerts()
    assert not core.has_alert("watchdog"), "«Проверить» по кнопке тоже считается удачной проверкой"


def test_watchdog_alert_goes_when_zapret_stopped(watchdog_core):
    core = watchdog_core
    core._watchdog_check("ask")
    core._watchdog_check("ask")
    core.set_alert("zapret-guard", "error", "пропал интернет")
    core.zapret.status = "stopped"
    core._reconcile_alerts()
    assert not core.has_alert("watchdog") and not core.has_alert("zapret-guard")


def test_guard_alert_clears_when_internet_back_even_without_watchdog(tmp_path, monkeypatch):
    core = make_core(tmp_path, None)
    core.zapret.status = "running"
    core.settings.update(lambda d: d["zapret"].__setitem__("watchdog", "off"))
    online = {"value": False}
    probes = []
    monkeypatch.setattr("app.zapret.tester.control_ok", lambda *a, **k: probes.append(1) or online["value"])
    core.set_alert("zapret-guard", "error", "После включения обхода не открывается даже проверочный сайт")
    core._reconcile_alerts()
    assert wait_for(lambda: probes and not core._guard_busy)
    assert core.has_alert("zapret-guard"), "связи нет — плашка висит"
    core._reconcile_alerts()
    assert len(probes) == 1, "перепроверка не чаще раза в минуту"
    online["value"] = True
    core._guard_next = 0.0                                          # минута прошла
    core._reconcile_alerts()
    assert wait_for(lambda: not core.has_alert("zapret-guard")), "связь вернулась — плашка снята без сторожа"


def test_manual_check_clears_guard_alert(tmp_path):
    core = make_core(tmp_path, None)
    core.zapret.status = "running"
    core._guard_next = time.monotonic() + 3600                      # фоновая перепроверка ещё не скоро
    core.set_alert("zapret-guard", "error", "пропал интернет")
    core._check_fp = core._zapret_fingerprint()
    core.tester.check_state = {"running": False, "at": time.time() + 1, "direct": False,
                               "results": [{"id": "discord", "label": "Discord", "ok": False},
                                           {"id": "youtube", "label": "YouTube", "ok": True}]}
    core._reconcile_alerts()
    assert not core.has_alert("zapret-guard"), "хоть что-то открылось по «Проверить» — интернет есть"


def _reapply_kills_winws(core):
    from app.zapret.manager import ZapretError

    def reapply():
        core.zapret.status, core.zapret.error = "error", "winws не запустился"
        raise ZapretError("winws не запустился")
    core.zapret.reapply_for_network = reapply


def test_auto_reapply_that_kills_bypass_raises_zapret_down(tmp_path):
    core = make_core(tmp_path, None)
    core.zapret.status = "running"
    core.settings.update(lambda d: d["zapret"].__setitem__("was_running", True))
    _reapply_kills_winws(core)
    core._reapply_zapret("vpn-reapply", "Обход не перезапустился под новую сеть")
    core._reconcile_alerts()                                        # следующий тик: «обход выключен»
    down = _alert(core, "zapret-down")
    assert down and down["level"] == "error" and "winws не запустился" in down["text"]
    assert down["action"] == {"label": "Включить снова", "call": "zapret_start", "args": []}
    assert _alert(core, "zapret-filter") is None, "одна поломка — одна плашка"
    core.zapret.status = "running"                                  # «Включить снова» помогло
    core._reconcile_alerts()
    assert _alert(core, "zapret-down") is None


def test_before_core_reapply_that_kills_bypass_raises_zapret_down(tmp_path):
    core = make_core(tmp_path, None)
    core.zapret.status = "running"
    core._vpn_scan = lambda: SimpleNamespace(foreign_active=False, own_active=True)
    core._filter_stale = lambda snap: True
    _reapply_kills_winws(core)
    core._vpnclient_before_core()
    core._reconcile_alerts()
    assert _alert(core, "zapret-down")["action"]["call"] == "zapret_start"
    assert _alert(core, "zapret-filter") is None


def test_reapply_failure_with_bypass_alive_stays_filter_alert(tmp_path):
    from app.zapret.manager import ZapretError
    core = make_core(tmp_path, None)
    core.zapret.status = "running"

    def reapply():                                                  # служба не остановилась — работает по-старому
        raise ZapretError("Служба обхода не остановилась за 10 секунд — перенастройка отменена")
    core.zapret.reapply_for_network = reapply
    core._reapply_zapret("vpn-reapply", "Обход не перезапустился под новую сеть")
    core._reconcile_alerts()
    assert _alert(core, "zapret-filter")["page"] == "zapret"
    assert _alert(core, "zapret-down") is None


def test_zapret_down_cleared_when_person_turned_bypass_off(tmp_path):
    core = make_core(tmp_path, None)
    core.zapret.status = "stopped"                                  # выключил сам, пока шла перестройка
    core.set_alert("zapret-down", "error", "Обход не перезапустился под новую сеть и сейчас не работает")
    core._reconcile_alerts()
    assert _alert(core, "zapret-down") is None
    core.settings.update(lambda d: d["zapret"].__setitem__("was_running", True))
    core.set_alert("zapret-down", "error", "Обход не включился при запуске Лазейки")
    core._reconcile_alerts()
    assert _alert(core, "zapret-down"), "обход должен работать, а не работает — плашка висит"


def test_watchdog_quiet_when_traffic_goes_via_own_vpn(watchdog_core):
    core = watchdog_core
    core.set_alert("watchdog", "warn", "Discord перестал открываться")
    core.vpn_snapshot = SimpleNamespace(foreign_active=False, own_active=True, internet=False)
    core.settings.update(lambda d: d["vpnclient"].__setitem__("via_zapret", False))
    core._watchdog_check("ask")
    assert not core.has_alert("watchdog"), "сторожить нечего — и плашке незачем висеть"


# ------------------------------------------------------------ обход, Telegram, свой VPN: снятие по состоянию

def test_down_alerts_clear_when_running_again(tmp_path):
    vc = FakeManager()
    core = make_core(tmp_path, vc)
    core.zapret.status = "error"                                    # winws упал (так ставит плашку менеджер)
    core.set_alert("zapret-down", "error", "Обход остановился")
    core.set_alert("tg-down", "error", "Telegram-прокси не включился")
    core.set_alert("vpnclient-autostart", "error", "Свой VPN не включился")
    core._reconcile_alerts()
    assert {n["id"] for n in core.notices() if n["persistent"]} >= {"zapret-down", "tg-down", "vpnclient-autostart"}
    core.zapret.status, core.tg.status, vc.status = "running", "running", "running"
    core._reconcile_alerts()
    assert not any(core.has_alert(a) for a in ("zapret-down", "tg-down", "vpnclient-autostart"))


def test_user_actions_clear_down_alerts(tmp_path):
    vc = FakeManager()
    core = make_core(tmp_path, vc)
    core.zapret.start = core.zapret.stop = lambda *a, **k: None
    core._arm_connectivity_guard = lambda: None
    core._vpn_note_on_start = lambda: None
    core.tg.start = core.tg.stop = lambda *a, **k: None
    core.set_alert("zapret-down", "error", "Обход остановился")
    core.zapret_start()
    assert not core.has_alert("zapret-down")
    core.set_alert("zapret-down", "error", "Обход остановился")
    core.zapret_stop()
    assert not core.has_alert("zapret-down")
    core.set_alert("tg-down", "error", "Telegram-прокси не включился")
    core.tg_start()
    assert not core.has_alert("tg-down")
    core.set_alert("vpnclient-autostart", "error", "Свой VPN не включился")
    core.vpnclient_stop()
    assert not core.has_alert("vpnclient-autostart")


def test_autostart_failures_are_alerts(tmp_path, monkeypatch):
    from app.tgproxy.manager import TgError
    from app.zapret.manager import ZapretError
    core = make_core(tmp_path, None)

    def mutate(d):
        d["first_run"] = False
        d["startup"].update({"tg": True, "zapret": True, "vpnclient": False})
        d["tg"]["was_running"] = d["zapret"]["was_running"] = True
    core.settings.update(mutate)
    core.tg.start = lambda: (_ for _ in ()).throw(TgError("порт 1443 занят"))
    core.zapret.start = lambda: (_ for _ in ()).throw(ZapretError("winws не запустился"))
    core._status_changed = lambda force=False: None
    core._autostart_components()
    assert _transient(core) == []
    tg, zapret = _alert(core, "tg-down"), _alert(core, "zapret-down")
    assert "порт 1443 занят" in tg["text"] and tg["action"]["call"] == "tg_start"
    assert "winws не запустился" in zapret["text"] and zapret["action"]["call"] == "zapret_start"


def test_compat_off_is_alert_until_vpn_gone(tmp_path):
    core = make_core(tmp_path, None)
    core.zapret.status = "running"
    core.settings.update(lambda d: d["vpn"].__setitem__("compat", False))
    snap = SimpleNamespace(foreign_active=True, foreign_label="Incy")
    core._announce_vpn(snap)
    alert = _alert(core, "compat-off")
    assert "Incy" in alert["text"] and alert["action"]["call"] == "vpn_set_compat" and alert["page"] == "zapret"
    assert _transient(core) == []
    core.vpn_snapshot = snap
    core._reconcile_alerts()
    assert core.has_alert("compat-off")
    core.vpn_snapshot = SimpleNamespace(foreign_active=False)
    core._reconcile_alerts()
    assert not core.has_alert("compat-off")


def test_background_task_started_by_lazeyka_reports_with_alert(tmp_path):
    core = make_core(tmp_path, None)
    task = core._alerting("tg-down", "Telegram-прокси не перезапустился после смены сети",
                          lambda: (_ for _ in ()).throw(UserError("порт занят")), action={"label": "x", "page": "telegram"})
    task()
    assert _alert(core, "tg-down")["text"] == "Telegram-прокси не перезапустился после смены сети: порт занят"
    assert _transient(core) == []
    core._alerting("tg-down", "—", lambda: None)()
    assert not core.has_alert("tg-down"), "удача снимает плашку"


def test_zapret_crash_is_alert_via_hook(tmp_path):
    from app.settings import Settings
    from app.zapret.manager import ZapretManager
    notes, alerts = [], {}
    z = ZapretManager(Settings(tmp_path / "s.json"), lambda level, text: notes.append(text), True)
    z.alert = lambda alert_id, level, text=None, action=None, page=None: alerts.__setitem__(
        alert_id, (level, text, action, page))
    proc = SimpleNamespace(started_at=time.time())          # упал сразу — без перезапуска
    z.process = proc
    z._on_crash(proc, 1, ["error"])
    level, text, action, page = alerts["zapret-down"]
    assert level == "error" and text.startswith("Обход остановился") and action["call"] == "zapret_start"
    assert page is None, "на странице обхода ошибку и так видно"
    assert notes == []


def test_zapret_without_core_hook_still_notifies(tmp_path):
    from app.settings import Settings
    from app.zapret.manager import ZapretManager
    notes = []
    z = ZapretManager(Settings(tmp_path / "s.json"), lambda level, text: notes.append((level, text)), True)
    proc = SimpleNamespace(started_at=time.time())
    z.process = proc
    z._on_crash(proc, 1, ["error"])
    assert notes and notes[0][0] == "error"


# ------------------------------------------------------------ значок в трее

def _tray(core):
    from app.tray import Tray
    tray = Tray.__new__(Tray)
    tray.core = core
    return tray


def test_tray_colour_and_tooltip_follow_alerts(tmp_path):
    core = make_core(tmp_path, None)
    core.zapret.status, core.tg.status = "running", "running"
    tray = _tray(core)
    assert tray._status() == "on" and "Проблема" not in tray._tooltip()
    core.set_alert("watchdog", "warn", "Discord перестал открываться. Найти рабочую стратегию?")
    assert tray._status() == "partial"
    tip = tray._tooltip()
    assert tip.splitlines()[1].startswith("Проблема: Discord перестал открываться") and len(tip) <= 127
    core.set_alert("vpn-crash", "error", "Свой VPN остановился")
    assert tray._status() == "error"
    assert tray._tooltip().splitlines()[1] == "Проблема: Свой VPN остановился (+1)"
    core.set_alert("vpn-rules", "info", "Списки скачиваются")       # info цвет не меняет
    core.clear_alert("vpn-crash")
    core.dismiss_notice("watchdog")                                  # скрытую человек уже видел
    assert tray._status() == "on"


def test_tray_refreshes_when_alert_appears(tmp_path):
    core = make_core(tmp_path, None)
    refreshed = []
    core.on_status_change = lambda: refreshed.append(1)
    core._status_changed()
    core._status_changed()
    assert refreshed == [1]
    core.set_alert("zapret-down", "error", "Обход остановился")
    core._status_changed()
    assert refreshed == [1, 1], "новая плашка — значок перерисовывается тикером"


# ------------------------------------------------------------ свой VPN: плашки менеджера

@pytest.fixture
def world(tmp_path):
    manager, w = make_manager(tmp_path, basic_store())
    yield w
    manager.shutdown()


def test_dead_server_without_alternative_is_alert(world):
    m = world.manager
    m.start()
    dead = {tag: "timeout" for tag in world.config.last_tags}       # молчат все серверы подписки
    world.delays = dict(dead)
    for _ in range(2):
        world.advance(61)
        m.tick()
        assert m.wait_idle(5)
    alert = world.alerts["vpn-server"]
    assert alert["level"] == "warn" and "не отвечает" in alert["text"] and alert["page"] == "vpnclient"
    assert world.notices == []
    world.delays = {}
    world.advance(61)
    m.tick()
    assert m.wait_idle(5)
    assert "vpn-server" not in world.alerts, "сервер снова ответил — плашка снята"
    world.delays = dict(dead)
    for _ in range(2):
        world.advance(61)
        m.tick()
        assert m.wait_idle(5)
    assert "vpn-server" in world.alerts
    m.stop()
    assert "vpn-server" not in world.alerts, "VPN выключен — плашки сеанса сняты"


def test_kill_switch_failure_is_alert(tmp_path):
    m, w = make_manager(tmp_path, basic_store())
    w.settings.update(lambda d: d["vpnclient"].__setitem__("kill_switch", True))

    def refuse(**_kw):
        raise UserError("служба BFE не отвечает")
    w.killswitch.enable = refuse
    m.start()
    alert = w.alerts["vpn-killswitch"]
    assert "служба BFE не отвечает" in alert["text"] and w.notices == []
    m.stop()
    assert "vpn-killswitch" not in w.alerts
    m.shutdown()


def _sub_world(world, answer=None):
    fake = FakeSubscription()
    world.manager.deps.modules["subscription"] = fake
    ua = "Lazeyka/" + __import__("app").__version__ + " (Windows)"
    if answer is not None:
        fake.answers[ua] = answer
    return fake, ua


def test_scheduled_subscription_failure_is_alert_per_subscription(world):
    fake, ua = _sub_world(world)
    fake.answers[ua] = fake.SubscriptionError("network", "Сервер подписки не отвечает")
    m = world.manager
    m._update_sub("s-1", "auto")
    alert = world.alerts["vpn-sub:s-1"]
    assert "«Мой VPN» не обновилась" in alert["text"] and alert["action"]["args"] == ["s-1"]
    assert world.notices == [], "по расписанию — плашка, без уведомления"
    m._update_sub("s-2", "auto")
    assert {"vpn-sub:s-1", "vpn-sub:s-2"} <= set(world.alerts), "по плашке на подписку"
    # По кнопке — ответ уведомлением, плашка остаётся до удачного обновления.
    m._update_sub("s-1", True)
    assert any("не обновилась" in text for _, text in world.notices) and "vpn-sub:s-1" in world.alerts
    fake.answers.pop(ua)
    m._update_sub("s-1", "auto")
    assert "vpn-sub:s-1" not in world.alerts, "обновилась — плашка снята"
    m.sub_remove("s-2")
    assert "vpn-sub:s-2" not in world.alerts, "подписку удалили — и её плашку"


def test_scheduled_update_goes_through_alert_path(world):
    m = world.manager
    spawned = []
    m._spawn_update = lambda sub_id, announce: spawned.append((sub_id, announce))
    world.advance(10 * 24 * 3600)
    m._auto_update_subs(world.clock())
    assert spawned and all(announce == "auto" for _, announce in spawned)


def test_scheduled_update_with_provider_notice_is_alert(world):
    fake, ua = _sub_world(world)
    fake.answers[ua] = fake.real.Decoded(format="links", notices=["Подписка истекла"])
    world.manager._update_sub("s-1", "auto")
    assert "провайдер сообщает: Подписка истекла" in world.alerts["vpn-sub:s-1"]["text"]
    assert not any("провайдер сообщает" in text for _, text in world.notices)


def test_route_lists_alert_while_downloading_then_cleared(world):
    m = world.manager
    world.routing.preset_rule_sets = lambda preset, games: ["geosite-ru"]
    updated = []
    m.deps.rules = SimpleNamespace(paths=lambda ids: {}, missing=lambda ids: list(ids), status=lambda: {},
                                   update=lambda ids, force=False: updated.append(list(ids)))
    m.start()
    assert wait_for(lambda: updated)
    assert wait_for(lambda: "vpn-rules" not in world.alerts), "скачались — плашка снята"
    assert not any("Списки" in text for _, text in world.notices)


def test_route_lists_failure_is_alert_with_retry(world):
    m = world.manager
    world.routing.preset_rule_sets = lambda preset, games: ["geosite-ru"]

    def fail(ids, force=False):
        raise UserError("GitHub не отвечает")
    m.deps.rules = SimpleNamespace(paths=lambda ids: {}, missing=lambda ids: list(ids), status=lambda: {},
                                   update=fail)
    m.start()
    assert wait_for(lambda: (world.alerts.get("vpn-rules") or {}).get("level") == "warn")
    alert = world.alerts["vpn-rules"]
    assert "GitHub не отвечает" in alert["text"] and alert["action"]["call"] == "vpnclient_rules_update"
    assert not any("Списки" in text for _, text in world.notices)
    m._rules_worker(m.deps.rules, ["geosite-ru"])                  # по кнопке — ответ уведомлением
    assert any("Списки маршрутов не обновились" in text for _, text in world.notices)


def test_broken_route_profile_is_alert(world):
    m = world.manager
    m._profiles.save([{"id": "p-1", "name": "Мой профиль", "source": "link", "text": "?", "active": True}])

    def broken(_profile):
        raise ValueError("нет ни одного правила")
    m.deps.modules["routeprofile"] = SimpleNamespace(parse_happ=lambda text: text, to_rules=broken)
    m.start()
    assert "Мой профиль" in world.alerts["vpn-profile"]["text"] and world.notices == []
    m.stop()
    m._profiles.save([])
    m.start()
    assert "vpn-profile" not in world.alerts, "профиля нет — и плашки"
