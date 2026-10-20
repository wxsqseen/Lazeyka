"""Страховка связи (app/zapret/guard.py): после любого запуска winws Лазейкой — не пропал ли интернет.
Жалоба: «если не работает запрет, у него полностью вырубается интернет». winws и сеть — подделки."""
import threading
import time
from types import SimpleNamespace

import pytest

from app.settings import Settings
from app.zapret import guard as guard_mod
from app.zapret.guard import ConnectivityGuard
from tests.fakes.vpn_world import wait_for


class _Zapret:
    """Ровно то, чем пользуется страховка: статус, режим, пауза подбора, start/stop и настройки."""

    def __init__(self, settings, world):
        self.settings = settings
        self.world = world
        self.status = "running"
        self.mode = "app"
        self.paused_for_test = False
        self.guard_paused = False
        self.lock = threading.RLock()
        self.calls: list[str] = []
        self.guard: ConnectivityGuard | None = None
        self.fail_start = self.fail_stop = None

    def start(self):
        self.calls.append("start")
        if self.fail_start:
            raise self.fail_start
        online = self.guard.probe() if self.guard else None   # как ZapretManager.start: до winws
        self.status = "running"
        self.settings.update(lambda d: d["zapret"].__setitem__("was_running", True))
        if self.guard:
            self.guard.started(online)

    def stop(self, remember=True, hold=None):
        self.calls.append(f"stop(remember={remember})" if hold is None else f"stop(remember={remember}, hold={hold})")
        if self.fail_stop:
            raise self.fail_stop
        self.status = "stopped"
        if remember:
            self.settings.update(lambda d: d["zapret"].__setitem__("was_running", False))


class _World:
    """Связь: с обходом (bypass) и без него (plain) — список ответов по очереди или постоянное значение."""

    def __init__(self, z_ref):
        self.z = z_ref
        self.with_bypass: list[bool] | bool = False
        self.without: list[bool] | bool = True
        self.probes = 0

    def online(self) -> bool:
        self.probes += 1
        source = self.with_bypass if self.z().status == "running" else self.without
        if isinstance(source, list):
            return source.pop(0) if source else False
        return source


@pytest.fixture
def rig(tmp_path):
    settings = Settings(tmp_path / "s.json")
    settings.update(lambda d: d["zapret"].__setitem__("was_running", True))
    holder = {}
    world = _World(lambda: holder["z"])
    z = holder["z"] = _Zapret(settings, world)
    alerts: dict[str, tuple] = {}

    def alert(alert_id, level, text=None, action=None, page=None):
        if level is None:
            alerts.pop(alert_id, None)
        else:
            alerts[alert_id] = (level, text, action, page)
    busy = {"value": False}
    g = ConnectivityGuard(z, online=world.online, alert=alert, busy=lambda: busy["value"],
                          hint=lambda: "Скорее всего, стратегия не подходит вашему провайдеру.", pause=0)
    z.guard = g
    yield g, z, world, alerts, busy
    g.close()                     # ожидание связи (поток zapret-guard-link) не переживает тест


def _judge(g):
    """Проверка сразу в этом потоке — как поток страховки после запуска winws."""
    with g._lock:
        g._gen += 1
        gen = g._gen
    g.run(gen)


def test_bypass_that_kills_internet_is_turned_off_after_confirmation(rig):
    g, z, world, alerts, _ = rig
    world.with_bypass, world.without = False, True
    _judge(g)
    # A/B/A: без связи → выключить → связь есть → включить снова → опять нет → выключить.
    assert z.calls == ["stop(remember=False)", "start", "stop(remember=False, hold=True)"]
    assert z.status == "stopped" and not z.guard_paused, "итог: подбор не должен считать обход работавшим"
    level, text, action, page = alerts["zapret-guard-off"]
    assert level == "error" and "с ним пропадал интернет" in text and "стратегия не подходит" in text
    assert action["call"] == "zapret_start" and page == "zapret"
    assert z.settings.get("zapret", "was_running") is True, "не запоминать: ошибись страховка — обход вернётся"


def test_wifi_up_late_is_not_blamed_on_bypass(rig):
    """Вход в Windows: обход запущен, Wi-Fi поднялся через 15 секунд. Связь появилась, пока обход был
    выключен, — но со вторым запуском обхода она есть: обвинять не в чем."""
    g, z, world, alerts, _ = rig
    world.with_bypass = [False, False, False, True]
    world.without = True
    _judge(g)
    assert z.calls == ["stop(remember=False)", "start"] and z.status == "running"
    assert alerts == {}


def test_single_lucky_probe_without_bypass_is_not_enough(rig):
    """Без обхода связь мелькнула один раз и пропала — это сеть, а не обход."""
    g, z, world, alerts, _ = rig
    world.without = [True, False, False, False]
    _judge(g)
    assert z.calls == ["stop(remember=False)", "start"] and z.status == "running"
    assert alerts["zapret-guard"][0] == "warn" and "Интернета нет и без обхода" in alerts["zapret-guard"][1]
    assert "zapret-guard-off" not in alerts


def test_offline_alert_only_after_bypass_really_back(rig):
    g, z, world, alerts, _ = rig
    world.without = False
    z.fail_start = RuntimeError("winws не запустился")
    _judge(g)
    assert "zapret-guard" not in alerts, "«Обход снова включён» — неправда, если он не включился"
    level, text, action, _page = alerts["zapret-down"]
    assert level == "error" and "winws не запустился" in text and action["call"] == "zapret_start"


def test_no_internet_before_start_defers_until_network_changes(rig):
    g, z, world, alerts, _ = rig
    g.started(False)                       # связи не было ещё до winws — судить не по чему
    assert world.probes == 0 and g._pending
    world.with_bypass, world.without = False, True
    g.network_changed()                    # Wi-Fi подключился
    assert wait_for(lambda: "zapret-guard-off" in alerts), "после смены сети обход проверен"
    assert not g._pending


def test_offline_restore_waits_for_network_to_recheck(rig):
    g, z, world, alerts, _ = rig
    world.without = False
    _judge(g)
    assert g._pending, "сеть вернётся с новым адресом — проверить обход тогда"


def test_person_turning_bypass_off_during_check_is_respected(rig):
    g, z, world, alerts, _ = rig

    def online():
        if z.status == "running":
            return False
        z.settings.update(lambda d: d["zapret"].__setitem__("was_running", False))   # нажали «Выключить»
        return True
    g.online = online
    _judge(g)
    assert z.calls == ["stop(remember=False)"], "выключенный человеком обход страховка не включает"
    assert alerts == {}


def test_new_start_cancels_previous_check(rig):
    g, z, world, alerts, _ = rig
    calls = {"n": 0}

    def online():
        calls["n"] += 1
        with g._lock:
            g._gen += 1                   # пока шла проверка, человек сменил стратегию — новый запуск
        return False
    g.online = online
    _judge(g)
    assert z.calls == [] and alerts == {}, "прежняя проверка о новом winws ничего не знает"


def test_stop_failure_is_reported_with_button(rig):
    g, z, world, alerts, _ = rig
    z.fail_stop = RuntimeError("Служба обхода не остановилась за 10 секунд — обход ещё работает")
    _judge(g)
    level, text, action, _ = alerts["zapret-guard"]
    assert level == "error" and "не остановилась" in text and action["call"] == "zapret_stop"


def test_guard_own_restart_does_not_arm_new_check(rig):
    g, z, world, alerts, _ = rig
    world.with_bypass, world.without = False, True
    started = []
    real = g.started
    g.started = lambda online: started.append(online) or real(online)
    _judge(g)
    assert started == [None], "свой перезапуск: без проверки связи до запуска и без новой проверки"
    assert g._gen == 1


def test_waits_for_strategy_test_before_acting(rig, monkeypatch):
    """Подбор сам останавливает и запускает обход: страховка не вмешивается, пока он идёт."""
    g, z, world, alerts, busy = rig
    monkeypatch.setattr(guard_mod, "BUSY_POLL", 0.01)
    busy["value"] = True
    world.with_bypass = [False, False, False, True]   # к концу подбора связь с обходом есть
    done = threading.Event()
    threading.Thread(target=lambda: (_judge(g), done.set()), daemon=True).start()
    assert wait_for(lambda: world.probes >= 3)
    assert z.calls == [], "пока идёт подбор — ни выключений, ни включений"
    busy["value"] = False
    assert done.wait(5)
    assert z.calls == [] and alerts == {}


def test_does_nothing_while_bypass_not_running(rig):
    g, z, world, alerts, _ = rig
    z.status = "starting"
    _judge(g)
    assert world.probes == 0 and z.calls == []


def test_probe_reports_online_and_survives_errors(rig):
    g, z, world, alerts, _ = rig
    world.without = True
    z.status = "stopped"
    assert g.probe() is True
    g.online = lambda: (_ for _ in ()).throw(OSError("curl не запустился"))
    assert g.probe() is None


def test_started_runs_check_in_background(rig):
    g, z, world, alerts, _ = rig
    world.with_bypass, world.without = False, True
    g.started(True)
    assert wait_for(lambda: "zapret-guard-off" in alerts)
    assert threading.current_thread().name != "zapret-guard"
    assert wait_for(lambda: not any(t.name == "zapret-guard" for t in threading.enumerate()))


def test_check_starts_as_soon_as_winws_is_ready_not_by_clock(rig):
    """guard_race.py: winws готовился 3,5 с — прежняя проверка по таймеру видела «запускается» и уходила.
    Теперь проверка начинается от события «winws запущен», сколько бы ни длился запуск."""
    g, z, world, alerts, _ = rig
    world.with_bypass, world.without = False, True

    def slow_start():
        z.calls.append("start")
        z.status = "starting"
        time.sleep(0.3)                      # netsh, осмотр адаптеров, --wf-save, ожидание готовности
        z.status = "running"
        g.started(True)
    z.start = slow_start
    threading.Thread(target=z.start, daemon=True).start()
    assert wait_for(lambda: "zapret-guard-off" in alerts)


def test_exit_stops_check_and_never_turns_bypass_back_on(rig):
    g, z, world, alerts, _ = rig
    world.with_bypass = False

    def without_bypass():
        g.close()                              # Лазейка выходит, пока страховка проверяла связь без обхода
        return True
    g.online = lambda: False if z.status == "running" else without_bypass()
    _judge(g)
    assert z.calls == ["stop(remember=False)"], "на выходе обход обратно не включается"
    g.started(True)
    assert not any(t.name == "zapret-guard" for t in threading.enumerate())


def test_mid_check_stop_is_marked_for_strategy_test(rig):
    """Пока страховка держит обход выключенным, подбор и выход Лазейки знают: он работал (guard_paused)."""
    g, z, world, alerts, _ = rig
    seen = []

    def online():
        if z.status == "running":
            return False
        seen.append(z.guard_paused)
        return True
    g.online = online
    _judge(g)
    assert seen and all(seen), "без обхода — помечен как выключенный страховкой"
    assert z.calls[-1] == "stop(remember=False, hold=True)" and not z.guard_paused


class _SpyLock:
    """RLock обхода, который замечает, что страховка ждёт его (перестройка под сеть держит блокировку)."""

    def __init__(self):
        self._lock = threading.RLock()
        self.waiting = threading.Event()

    def __enter__(self):
        if threading.current_thread() is not threading.main_thread():
            self.waiting.set()
        self._lock.acquire()
        return self

    def __exit__(self, *exc):
        self._lock.release()


def test_check_and_stop_are_atomic_with_bypass_lock(rig):
    """Страховка прежнего запуска решила «выключить», а перестройка под сеть в этот миг держит блокировку обхода
    и запускает новый winws. Решение принимается под блокировкой: свежий winws страховка не трогает."""
    g, z, world, alerts, _ = rig
    z.lock = _SpyLock()
    world.with_bypass, world.without = False, True
    with g._lock:
        g._gen += 1
        gen = g._gen
    z.lock.__enter__()                                  # перестройка под сеть идёт
    worker = threading.Thread(target=g.run, args=(gen,), daemon=True)
    worker.start()
    assert z.lock.waiting.wait(5), "страховка дошла до выключения"
    with g._lock:
        g._gen += 1                                     # перестройка запустила новый winws: started()
    z.lock.__exit__(None, None, None)
    worker.join(5)
    assert z.calls == [] and z.status == "running" and alerts == {}


def test_offline_start_is_checked_when_network_never_changes(rig, monkeypatch):
    """Вход в Windows: обход запущен, когда связи ещё не было, а адрес у адаптера уже был — смены сети не будет.
    Связь так и не появилась — через LINK_FIRST та же схема A/B/A: обход, рвущий интернет, выключен."""
    g, z, world, alerts, _ = rig
    monkeypatch.setattr(guard_mod, "LINK_POLL", 0.01)
    monkeypatch.setattr(guard_mod, "LINK_FIRST", 0.05)
    world.with_bypass, world.without = False, True
    g.started(False)
    assert wait_for(lambda: "zapret-guard-off" in alerts), "обход проверен без смены сети"
    assert not g._pending


def test_offline_start_is_left_alone_once_link_appears(rig, monkeypatch):
    g, z, world, alerts, _ = rig
    monkeypatch.setattr(guard_mod, "LINK_POLL", 0.01)
    monkeypatch.setattr(guard_mod, "LINK_FIRST", 60.0)
    world.with_bypass = [False, True]                   # Wi-Fi поднялся — с обходом связь есть
    g.started(False)
    assert wait_for(lambda: not g._pending), "связь появилась при работающем обходе — проверять нечего"
    assert z.calls == [] and alerts == {}


def test_offline_restore_keeps_watching_for_link(rig, monkeypatch):
    """Без обхода связи тоже не было: обход включён обратно, и страховка ждёт связи (или смены сети) снова."""
    g, z, world, alerts, _ = rig
    monkeypatch.setattr(guard_mod, "LINK_POLL", 0.01)
    monkeypatch.setattr(guard_mod, "LINK_AGAIN", 60.0)
    world.without = False
    _judge(g)
    assert g._pending
    world.with_bypass = True                            # сеть вернулась, обход её не рвёт
    assert wait_for(lambda: not g._pending)
    assert z.status == "running"


def test_exit_wakes_link_watch(rig, monkeypatch):
    g, z, world, alerts, _ = rig
    monkeypatch.setattr(guard_mod, "LINK_POLL", 30.0)
    before = set(threading.enumerate())
    g.started(False)
    assert wait_for(lambda: [t for t in threading.enumerate() if t.name == "zapret-guard-link" and t not in before])
    mine = [t for t in threading.enumerate() if t.name == "zapret-guard-link" and t not in before]
    g.close()
    assert wait_for(lambda: not any(t.is_alive() for t in mine)), "выход будит ожидание, а не ждёт LINK_POLL"
    assert world.probes == 0


def test_service_mode_verdict_takes_service_off_windows_autostart(tmp_path, monkeypatch):
    """Режим службы: с обходом пропадал интернет — служба больше не стартует вместе с Windows (без Лазейки её
    некому проверить); was_running не меняется — «Включить снова» вернёт автозапуск. Проверка посреди
    схемы A/B/A автозапуск не трогает."""
    from app.zapret import manager as zm
    settings = Settings(tmp_path / "settings.json")
    settings.update(lambda d: d["zapret"].update(mode="service", was_running=True))
    z = zm.ZapretManager(settings, lambda *a, **k: None, is_admin=True)
    calls: list = []
    state = {"svc": "running"}
    monkeypatch.setattr(zm.winutil, "service_stop", lambda name, wait=10.0: calls.append("stop") or
                        state.__setitem__("svc", "stopped") or True)
    monkeypatch.setattr(zm.winutil, "service_set_start", lambda name, auto: calls.append(("set_start", auto)))
    monkeypatch.setattr(zm.winutil, "service_query",
                        lambda name, with_config=False: SimpleNamespace(state=state["svc"], pid=1))

    def fake_start():                                   # как _service_apply(start=True)
        calls.append("start")
        state["svc"] = "running"
        z.status = "running"
    z.start = fake_start
    z.status = "running"
    book: dict = {}
    g = ConnectivityGuard(z, online=lambda: z.status != "running",
                          alert=lambda alert_id, level, text=None, action=None, page=None:
                          book.__setitem__(alert_id, text), pause=0)
    _judge(g)
    assert "zapret-guard-off" in book
    assert calls == ["stop", "start", "stop", ("set_start", False)], calls
    assert settings.get("zapret", "was_running") is True and not z.guard_paused
