"""Свой VPN: ядра в фоне — подкачка при запуске (повторы с паузами, плашка) и автообновление (check новой
версией, неподходящие версии, без перезапуска работающего VPN, откат после неудачного старта).

Всё на подделках tests/fakes/vpn_world.py: ядро не запускается, сети нет, часы — у теста."""
import threading

import pytest

from app.vpnclient import engines as real_engines
from app.vpnclient import manager as mgr
from tests.fakes.vpn_world import FakeStore, basic_store, make_manager, wait_for

NEW = real_engines.Release(version="1.15.0", url="https://github.com/SagerNet/sing-box/releases/download/v1.15.0/"
                                                 "sing-box-1.15.0-windows-amd64.zip", zip_sha256="ab" * 32)
NEW_XRAY = real_engines.Release(version="27.1.0", url="https://github.com/XTLS/Xray-core/releases/download/v27.1.0/"
                                                      "Xray-windows-64.zip", zip_sha256="cd" * 32)
OFFLINE = real_engines.EngineError("Нет связи с GitHub: timed out; через системный прокси — Нет связи с GitHub: "
                                   "getaddrinfo failed")


@pytest.fixture
def world(tmp_path):
    manager, w = make_manager(tmp_path, basic_store())
    yield w
    manager.shutdown()


def _tick(world, advance: float = 0.0):
    world.advance(advance)
    world.manager.tick()
    assert world.manager.wait_cores(10)


def _vc(world, key):
    return world.settings.get("vpnclient", key)


def _auto_update(world):
    """Запуск Лазейки (первый тик задаёт расписание) и первая проверка новых версий через 2 минуты."""
    _tick(world)
    _tick(world, mgr.CORE_UPDATE_FIRST)


def _no_core_notices(world):
    return not [text for _level, text in world.notices if "скача" in text or "Ядро VPN" in text]


# ------------------------------------------------------------ подкачка при запуске

def test_installed_cores_are_left_alone(world):
    _tick(world)
    assert world.engines.installs == [] and world.alerts == {}


def test_missing_cores_are_fetched_in_background_at_startup(world):
    for name in ("sing-box", "xray"):
        world.engines.versions[name].clear()
    _tick(world)
    assert world.engines.installs == [("sing-box", "1.14.3"), ("xray", "26.3.27")]
    assert world.engines.origins[("sing-box", "1.14.3")] == "github"
    assert _vc(world, "singbox_version") == "1.14.3" and _vc(world, "xray_version") == "26.3.27"
    cores = world.manager.snapshot()["cores"]
    assert cores["sing-box"]["installed"] and cores["sing-box"]["state"] == "idle" and cores["sing-box"]["retry_at"] is None
    assert world.alerts == {} and _no_core_notices(world)


def test_without_admin_rights_nothing_is_fetched(tmp_path):
    m, w = make_manager(tmp_path, basic_store(), is_admin=False)
    w.engines.versions["sing-box"].clear()
    m.tick()
    assert m.wait_cores(5) and w.engines.installs == [] and w.alerts == {}
    m.shutdown()


def test_stand_and_tests_never_fetch(world):
    world.engines.allowed = False          # настоящий engines: LAZEYKA_NO_CORE=1
    world.engines.versions["sing-box"].clear()
    _tick(world)
    assert world.engines.installs == []


def test_failed_fetch_retries_with_pauses_and_keeps_an_alert(world):
    world.engines.versions["sing-box"].clear()
    world.engines.install_errors = [OFFLINE] * 5
    _tick(world)
    alert = world.alerts["vpn-core:sing-box"]
    assert alert["level"] == "error" and alert["page"] == "vpnclient"
    assert alert["text"].startswith("Ядро VPN не скачалось: Нет связи с GitHub") and "Повторим в" in alert["text"]
    assert alert["action"] == {"label": "Скачать ещё раз", "call": "vpnclient_core_install", "args": ["sing-box"]}
    assert _no_core_notices(world), "о фоновой неудаче — только плашка, без уведомлений"
    core = world.manager.snapshot()["cores"]["sing-box"]
    assert core["state"] == "error" and "Нет связи" in core["message"]
    assert core["retry_at"] == world.clock() + 60

    for pause in (60, 300, 900, 3600):
        left = len(world.engines.install_errors)
        _tick(world, pause - 1)
        assert len(world.engines.install_errors) == left, f"до конца паузы {pause} с не повторяем"
        _tick(world, 1)
        assert len(world.engines.install_errors) == left - 1, f"после паузы {pause} с — повтор"
    assert world.manager.snapshot()["cores"]["sing-box"]["retry_at"] == world.clock() + 3600, "дальше — раз в час"

    _tick(world, 3600)                   # сеть появилась
    assert ("sing-box", "1.14.3") in world.engines.installs
    assert "vpn-core:sing-box" not in world.alerts
    core = world.manager.snapshot()["cores"]["sing-box"]
    assert core["installed"] and core["state"] == "idle" and core["retry_at"] is None


def test_no_alert_while_vpn_is_not_set_up(tmp_path):
    """Своим VPN не пользуются (серверов нет): плашка на главной ни к чему — ход виден на странице VPN."""
    manager, world = make_manager(tmp_path, FakeStore())
    try:
        for name in ("sing-box", "xray"):
            world.engines.versions[name].clear()
        world.engines.install_errors = [OFFLINE, OFFLINE]
        _tick(world)
        assert world.alerts == {}
        assert manager.snapshot()["cores"]["sing-box"]["state"] == "error"
    finally:
        manager.shutdown()


def test_retry_button_installs_and_clears_the_alert(tmp_path):
    manager, world = make_manager(tmp_path, basic_store(xhttp=True))   # серверу с XHTTP нужен помощник
    try:
        _retry_button_flow(world)
    finally:
        manager.shutdown()


def _retry_button_flow(world):
    for name in ("sing-box", "xray"):
        world.engines.versions[name].clear()
    world.engines.install_errors = [OFFLINE, OFFLINE, real_engines.EngineError("GitHub ответил ошибкой 502")]
    _tick(world)
    assert {"vpn-core:sing-box", "vpn-core:xray"} <= set(world.alerts)
    with pytest.raises(real_engines.EngineError):
        world.manager.core_install("sing-box")      # нажали «Скачать ещё раз» — снова не вышло
    assert "ошибкой 502" in world.alerts["vpn-core:sing-box"]["text"], "плашка — с новой причиной"
    assert "1.14.3" in world.manager.core_install("sing-box")
    assert "vpn-core:sing-box" not in world.alerts and "vpn-core:xray" in world.alerts
    _tick(world, 1)                                 # остальное — сразу, не дожидаясь паузы
    assert ("xray", "26.3.27") in world.engines.installs and world.alerts == {}


def test_power_button_during_fetch_waits_instead_of_failing(world):
    world.engines.versions["sing-box"].clear()
    gate = world.engines.install_gate = threading.Event()
    world.manager.tick()
    assert wait_for(lambda: world.manager.snapshot()["cores"]["sing-box"]["state"] == "downloading")
    results, errors = [], []

    def press():
        try:
            results.append(world.manager.start())
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    thread = threading.Thread(target=press)
    thread.start()
    assert wait_for(lambda: world.manager.snapshot()["status"] == "starting")
    snap = world.manager.snapshot()
    assert snap["cores"]["sing-box"]["state"] == "downloading" and snap["cores"]["sing-box"]["progress"] == 0.5
    gate.set()
    thread.join(10)
    assert errors == [] and world.manager.status == "running"
    assert world.engines.installs == [("sing-box", "1.14.3")], "одна установка, без «уже устанавливается»"


# ------------------------------------------------------------ автообновление

def test_newer_version_is_installed_checked_and_activated(world):
    world.engines.latest["sing-box"] = NEW
    _tick(world)
    assert world.engines.installs == [], "первая проверка — не сразу после запуска"
    _tick(world, mgr.CORE_UPDATE_FIRST - 1)
    assert world.engines.installs == []
    _tick(world, 1)
    assert ("sing-box", "1.15.0") in world.engines.installs
    assert world.engines.origins[("sing-box", "1.15.0")] == "auto"
    assert ("sing-box", "1.15.0") in world.engines.checks, "check текущего конфига новым ядром"
    assert _vc(world, "singbox_version") == "1.15.0"
    assert world.engines.versions("sing-box") == ["1.15.0", "1.14.3"], "прежняя — для отката"
    assert _vc(world, "core_trial") == ["sing-box:1.15.0"]
    core = world.manager.snapshot()["cores"]["sing-box"]
    assert core["version"] == "1.15.0" and core["auto_updated"] is True and core["state"] == "idle"
    assert core["note"] == "Обновлено автоматически до 1.15.0."
    assert world.alerts == {} and _no_core_notices(world)
    installs = len(world.engines.installs)
    _tick(world, mgr.CORE_UPDATE_EVERY)
    assert len(world.engines.installs) == installs, "уже стоит — второй раз не качаем"


def test_power_button_does_not_wait_for_an_update_download(world):
    """Активная версия стоит — «Включить» берёт её, пока рядом качается новая."""
    m = world.manager
    world.engines.latest["sing-box"] = NEW
    gate = world.engines.install_gate = threading.Event()
    _tick(world)
    world.advance(mgr.CORE_UPDATE_FIRST)
    m.tick()
    assert wait_for(lambda: m.snapshot()["cores"]["sing-box"]["state"] == "downloading")
    snap = m.snapshot()
    assert snap["cores"]["sing-box"]["installed"] is True, "обновление ставится рядом с работающей версией"
    m.start()
    assert m.status == "running" and m._session.versions["sing-box"] == "1.14.3"
    gate.set()
    assert m.wait_cores(10)
    assert _vc(world, "singbox_version") == "1.15.0" and m._session.versions["sing-box"] == "1.14.3"


def test_check_fatal_keeps_old_version_and_remembers_the_bad_one(world):
    world.engines.latest["sing-box"] = NEW
    world.engines.check_errors["1.15.0"] = "Ядро VPN (sing-box) не принял конфигурацию: unknown field \"bogus\""
    _auto_update(world)
    assert _vc(world, "singbox_version") == "1.14.3" and world.manager._active_core("sing-box") == "1.14.3"
    assert "sing-box:1.15.0" in _vc(world, "core_bad_versions")
    assert "1.15.0" not in world.engines.versions["sing-box"], "непрошедшая версия убрана с диска"
    note = world.manager.snapshot()["cores"]["sing-box"]["note"]
    assert "1.15.0 не приняла ваши настройки" in note and "Осталась 1.14.3" in note
    assert world.alerts == {}, "ядро работает — плашка не нужна"
    installs = len(world.engines.installs)
    _tick(world, mgr.CORE_UPDATE_EVERY)
    assert len(world.engines.installs) == installs, "плохую версию по кругу не качаем"


def test_broken_release_is_remembered_too(world):
    world.engines.latest["sing-box"] = NEW
    world.engines.install_errors = [real_engines.ReleaseRejected("Ядро VPN (sing-box): в архиве версия 1.14.9, "
                                                                 "ожидалась 1.15.0")]
    _auto_update(world)
    assert "sing-box:1.15.0" in _vc(world, "core_bad_versions")
    assert world.manager.snapshot()["cores"]["sing-box"]["state"] == "idle"


def test_offline_update_is_retried_later_without_marking(world):
    world.engines.latest["sing-box"] = OFFLINE
    _auto_update(world)
    assert world.engines.installs == [] and _vc(world, "core_bad_versions") == []
    world.engines.latest["sing-box"] = NEW
    world.engines.install_errors = [OFFLINE]
    _tick(world, mgr.CORE_UPDATE_RETRY)
    assert _vc(world, "core_bad_versions") == [] and "попробую позже" in \
        world.manager.snapshot()["cores"]["sing-box"]["note"]
    _tick(world, mgr.CORE_UPDATE_EVERY)
    assert _vc(world, "singbox_version") == "1.15.0"


def test_running_vpn_is_not_restarted_by_auto_update(world):
    m = world.manager
    m.start()
    starts = [p for p in world.processes if p.name == "sing-box"]
    world.engines.latest["sing-box"] = NEW
    _auto_update(world)
    assert m.wait_idle(5)
    assert [p for p in world.processes if p.name == "sing-box"] == starts and starts[0].alive()
    assert _vc(world, "singbox_version") == "1.15.0" and m._session.versions["sing-box"] == "1.14.3"
    core = m.snapshot()["cores"]["sing-box"]
    assert core["version"] == "1.15.0" and core["in_use"] == "1.14.3"
    assert "при следующем подключении" in core["note"]
    m.stop()
    m.start()
    assert m._session.versions["sing-box"] == "1.15.0"
    assert _vc(world, "core_trial") == [], "запустилась — больше не на пробе"


def test_new_version_that_fails_to_start_is_rolled_back(world):
    m = world.manager
    world.engines.latest["sing-box"] = NEW
    _auto_update(world)
    world.start_failures = ["FATAL[0000] start service: initialize outbound[2]: unknown transport type: xyz"]
    m.start()
    assert m.status == "running" and m._session.versions["sing-box"] == "1.14.3"
    assert _vc(world, "singbox_version") == "1.14.3"
    assert "sing-box:1.15.0" in _vc(world, "core_bad_versions") and _vc(world, "core_trial") == []
    assert "не запустилась — вернула 1.14.3" in m.snapshot()["cores"]["sing-box"]["note"]
    installs = len(world.engines.installs)
    _tick(world, mgr.CORE_UPDATE_EVERY)
    assert len(world.engines.installs) == installs, "откаченную версию снова не ставим"


def test_when_old_version_fails_too_the_new_one_is_not_blamed(world):
    m = world.manager
    world.engines.latest["sing-box"] = NEW
    _auto_update(world)
    failure = "FATAL[0000] start service: start inbound/tun[tun-in]: configure tun interface: Access is denied."
    world.start_failures = [failure, failure]
    with pytest.raises(mgr.VpnClientError):
        m.start()
    assert m.status == "error"
    assert _vc(world, "singbox_version") == "1.15.0" and "sing-box:1.15.0" not in _vc(world, "core_bad_versions")
    assert _vc(world, "core_trial") == []


def test_port_conflict_is_not_a_reason_to_roll_back(world):
    world.engines.latest["sing-box"] = NEW
    _auto_update(world)
    from tests.fakes.vpn_world import PORT_BUSY
    world.start_failures = [PORT_BUSY.format(port=30001)]
    world.manager.start()
    assert world.manager._session.versions["sing-box"] == "1.15.0"
    assert _vc(world, "core_bad_versions") == []


def test_auto_update_can_be_switched_off_and_respects_skipped(world):
    m = world.manager
    world.engines.latest["sing-box"] = NEW
    assert m.save_settings({"core_auto_update": False}) == {}
    assert m.snapshot()["settings"]["core_auto_update"] is False
    _auto_update(world)
    assert world.engines.installs == []
    world.settings.update(lambda d: d["updates"]["skipped"].__setitem__("vpncore", "1.15.0"))
    m.save_settings({"core_auto_update": True})
    _tick(world, 1)
    assert world.engines.installs == [], "«Пропустить версию» действует и на автообновление"
    world.settings.update(lambda d: d["updates"].__setitem__("skipped", {}))
    m.core_update_soon()
    _tick(world, 1)
    assert _vc(world, "singbox_version") == "1.15.0"


def test_without_servers_the_sample_config_is_checked(tmp_path):
    m, w = make_manager(tmp_path, FakeStore())
    w.engines.latest["sing-box"] = NEW
    _auto_update(w)
    assert ("sing-box", "1.15.0") in w.engines.checks and _vc(w, "singbox_version") == "1.15.0"
    assert [s.host for s in w.config.plans[-1].servers] == ["203.0.113.10"]
    m.shutdown()


def test_xray_update_is_checked_with_a_helper_server(world):
    world.engines.latest["xray"] = NEW_XRAY
    _auto_update(world)
    assert ("xray", "27.1.0") in world.engines.checks and _vc(world, "xray_version") == "27.1.0"
    plan = world.config.plans[-1]
    assert "xray" in plan.engines.values() and any(s.network == "xhttp" for s in plan.servers)


# ------------------------------------------------------------ ревью: гонки и откат (каждый тест краснел до правки)

NEWER = real_engines.Release(version="1.15.1", url="https://github.com/SagerNet/sing-box/releases/download/v1.15.1/"
                                                   "sing-box-1.15.1-windows-amd64.zip", zip_sha256="ef" * 32)
START_FAIL = "FATAL[0000] start service: initialize outbound[2]: unknown transport type: xyz"
HELSINKI = "helsinki.example.com"          # сервер XHTTP из basic_store(xhttp=True)


@pytest.fixture
def xworld(tmp_path):
    """Подписка с сервером XHTTP: помощник Xray нужен."""
    manager, w = make_manager(tmp_path, basic_store(xhttp=True))
    yield w
    manager.shutdown()


def test_two_updates_in_a_row_keep_the_last_good_version(world):
    """1: A работает → поставилась B → потом C, VPN всё это время выключен. A не удаляется, пока замена не
    запустилась, и откат идёт на неё, а не на непроверенную B."""
    m = world.manager
    world.engines.latest["sing-box"] = NEW
    _auto_update(world)
    world.engines.latest["sing-box"] = NEWER
    _tick(world, mgr.CORE_UPDATE_EVERY)
    assert _vc(world, "singbox_version") == "1.15.1"
    assert "1.14.3" in world.engines.versions["sing-box"], "последняя рабочая — на диске до успешного испытания"
    world.start_failures = [START_FAIL]
    m.start()
    assert m._session.versions["sing-box"] == "1.14.3"
    assert "sing-box:1.15.1" in _vc(world, "core_bad_versions")
    assert _vc(world, "core_good") == ["sing-box:1.14.3"]


def test_latency_measurement_does_not_hide_the_trial_helper(xworld):
    """2: замер задержек в своём потоке тоже собирает ядра — версии запуска от этого не теряются."""
    m = xworld.manager
    xworld.engines.latest["xray"] = NEW_XRAY
    _auto_update(xworld)
    assert _vc(xworld, "core_trial") == ["xray:27.1.0"]
    real_before = m.before_core

    def before_core():
        probe = threading.Thread(target=lambda: m._ensure_cores({"x": "sing-box"}))   # как _delays_temporary
        probe.start()
        probe.join(5)
        real_before()

    m.before_core = before_core
    xworld.start_failures = [START_FAIL]
    m.start()
    assert m._session.versions["xray"] == "26.3.27"
    assert "xray:27.1.0" in _vc(xworld, "core_bad_versions")


def test_manual_rollback_waits_for_the_update_check(world):
    """3: «Откатить», пока новая версия проходит check: откат ждёт конца установки — и не удаляет
    проверяемую версию из-под проверки."""
    import time
    m = world.manager
    world.engines.latest["sing-box"] = NEW
    _auto_update(world)
    gate = world.engines.check_gates["1.15.1"] = threading.Event()
    world.engines.latest["sing-box"] = NEWER
    world.advance(mgr.CORE_UPDATE_EVERY)
    m.tick()
    assert wait_for(lambda: "1.15.1" in world.engines.versions["sing-box"])
    done = []
    rollback = threading.Thread(target=lambda: done.append(m.core_rollback("sing-box")))
    rollback.start()
    time.sleep(0.3)                          # отрицательное утверждение: за это время откат не прошёл
    assert done == [] and "1.15.1" in world.engines.versions["sing-box"]
    gate.set()
    rollback.join(10)
    assert m.wait_cores(10) and done
    assert ("sing-box", "1.15.1") in world.engines.checks
    assert _vc(world, "singbox_version") == "1.15.0", "откат — от поставленной C к прежней B"


def test_parallel_checks_do_not_delete_each_others_configs(xworld):
    """4: check sing-box и check Xray одновременно — у каждого свой каталог, чужие файлы целы."""
    m = xworld.manager
    entered, gate, seen = threading.Event(), threading.Event(), {}

    def hook(name, path, version):
        if name == "sing-box":
            entered.set()
            gate.wait(10)
        seen[name] = (path.parent, path.is_file())

    xworld.engines.check_hook = hook
    first = threading.Thread(target=lambda: m._check_with_new_core("sing-box", "1.14.3"))
    first.start()
    assert entered.wait(10)
    m._check_with_new_core("xray", "26.3.27")
    gate.set()
    first.join(10)
    assert seen["sing-box"][1] and seen["xray"][1], "конфиг на месте в момент проверки"
    assert seen["sing-box"][0] != seen["xray"][0]
    assert not seen["sing-box"][0].exists() and not seen["xray"][0].exists(), "каталоги проверок убраны"


def test_xray_update_is_really_checked_when_its_servers_lost_dns(xworld):
    """5: адрес сервера XHTTP не получен — проверочный план без помощника; новая Xray всё равно проходит
    check (на образцовом конфиге), а не становится активной без него."""
    xworld.resolver.fail = {HELSINKI}
    xworld.engines.latest["xray"] = NEW_XRAY
    _auto_update(xworld)
    assert ("xray", "27.1.0") in xworld.engines.checks
    assert _vc(xworld, "xray_version") == "27.1.0"


def test_helper_trial_is_kept_when_the_helper_did_not_run(xworld):
    """6: помощник в этом сеансе не запускался (его сервер без адреса) — его новая версия ещё на пробе."""
    m = xworld.manager
    xworld.engines.latest["xray"] = NEW_XRAY
    _auto_update(xworld)
    xworld.resolver.fail = {HELSINKI}
    m.start()
    assert m._session.helper is None
    assert _vc(xworld, "core_trial") == ["xray:27.1.0"]
    assert m.snapshot()["cores"]["xray"]["in_use"] is None


def test_trial_version_with_a_broken_exe_is_rolled_back(world):
    """7: exe пробной версии изменён или пропал — verify падает до запуска, откат всё равно происходит."""
    world.engines.latest["sing-box"] = NEW
    _auto_update(world)
    world.engines.verify_errors.add("1.15.0")
    world.manager.start()
    assert world.manager._session.versions["sing-box"] == "1.14.3"
    assert "sing-box:1.15.0" in _vc(world, "core_bad_versions")


def test_fallback_never_picks_a_rejected_version(world):
    """8: после отката B→A пропал каталог A — запасной выбор не берёт забракованную B, а подкачка
    возвращает закреплённую."""
    m = world.manager
    world.settings.update(lambda d: d["vpnclient"].__setitem__("singbox_version", "1.15.0"))
    world.engines.versions["sing-box"].add("1.15.0")
    m.core_rollback("sing-box")
    world.engines.versions["sing-box"].discard("1.14.3")
    assert m._active_core("sing-box") is None
    _tick(world)
    assert world.engines.installs[-1] == ("sing-box", "1.14.3") and m._active_core("sing-box") == "1.14.3"


def test_partial_fetch_clears_the_alert_of_the_core_that_came(xworld):
    """10: sing-box скачался, Xray — нет: плашка sing-box уходит сразу, плашка Xray остаётся."""
    for name in ("sing-box", "xray"):
        xworld.engines.versions[name].clear()
    xworld.engines.install_errors = [OFFLINE, OFFLINE, None, OFFLINE]
    _tick(xworld)
    assert {"vpn-core:sing-box", "vpn-core:xray"} <= set(xworld.alerts)
    _tick(xworld, 60)
    assert ("sing-box", "1.14.3") in xworld.engines.installs
    assert "vpn-core:sing-box" not in xworld.alerts and "vpn-core:xray" in xworld.alerts


def test_rollback_during_a_start_restarts_on_the_target_version(world):
    """Ревью жизненного цикла, 7: «Откатить», пока запуск ещё идёт и уже взял забракованную версию, —
    после запуска VPN переподключается на версию отката, а не остаётся на забракованной."""
    m = world.manager
    world.engines.latest["sing-box"] = NEW
    _auto_update(world)
    real_before, done = m.before_core, []

    def before_core():
        if not done:                         # запуск уже выбрал 1.15.0 — человек нажал «Откатить»
            pressed = threading.Thread(target=lambda: done.append(m.core_rollback("sing-box")))
            pressed.start()
            pressed.join(5)
        real_before()

    m.before_core = before_core
    m.start()
    assert done and _vc(world, "singbox_version") == "1.14.3"
    assert wait_for(lambda: m.wait_idle(1) and m._session is not None
                    and m._session.versions["sing-box"] == "1.14.3")


def test_power_button_and_fetch_install_the_core_once(world):
    """Ревью жизненного цикла, 8: «Включить» ставит ядро, тут же стартует подкачка — она ждёт, а не
    падает с «уже устанавливается», и второй раз не качает."""
    m = world.manager
    world.engines.versions["sing-box"].clear()
    gate = world.engines.install_gate = threading.Event()
    results = []
    press = threading.Thread(target=lambda: results.append(m.start()))
    press.start()
    assert wait_for(lambda: m.snapshot()["cores"]["sing-box"]["state"] == "downloading")
    m.tick()                                 # подкачка видит: ядра нет — и встаёт в очередь за запуском
    gate.set()
    press.join(10)
    assert m.wait_cores(10) and results and m.status == "running"
    assert world.engines.installs == [("sing-box", "1.14.3")] and world.alerts == {}


def test_core_installed_by_the_power_button_clears_the_alert(xworld):
    """Ревью жизненного цикла, 9: подкачка не вышла (плашка), потом ядро поставил сам «Включить» —
    плашка снимается сразу, а не через час на следующей подкачке."""
    m = xworld.manager
    xworld.engines.versions["sing-box"].clear()
    xworld.engines.install_errors = [OFFLINE]
    _tick(xworld)
    assert "vpn-core:sing-box" in xworld.alerts
    m.start()
    assert m.status == "running" and "vpn-core:sing-box" not in xworld.alerts
