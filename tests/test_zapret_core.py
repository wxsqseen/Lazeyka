"""Core и обход: сторож (auto не повторяет неудачный подбор), свежесть итога для своего VPN, проверка без
прямого пути, объявление о VPN по двум осмотрам, «Мои сайты», страховка для службы и смены сети.
Подделки обхода и сети, ядро VPN не запускается."""
import time
from types import SimpleNamespace

import pytest

from app.zapret.tester import NoDirectPath
from tests.test_vpnclient_core import make_core


def _alert(core, alert_id):
    return next((n for n in core.notices() if n["id"] == alert_id), None)


@pytest.fixture
def wd(tmp_path, monkeypatch):
    """Сторож с подделкой сети: YouTube не открывается, интернет есть."""
    core = make_core(tmp_path, None)
    core.zapret.status = "running"
    core._wd_fails, core._wd_next, core._wd_busy = 0, 0.0, False
    core._net_fp = frozenset({("Ethernet", "192.168.1.10")})
    sites = {"discord": True, "youtube": False}
    online = {"value": True}
    monkeypatch.setattr("app.zapret.tester.control_ok", lambda *a, **k: online["value"])
    monkeypatch.setattr("app.zapret.tester.quick_check", lambda *a, **k: [
        {"id": "discord", "label": "Discord", "ok": sites["discord"], "detail": ""},
        {"id": "youtube", "label": "YouTube", "ok": sites["youtube"], "detail": ""}])
    fixes = []

    def start_fix():
        fixes.append(time.time())
        core.tester.fix_state = {"stage": "failed", "message": "Среди лучших стратегий подходящей не нашлось.",
                                 "finished_at": time.time() + 1, "results": None}
    core.tester.start_fix = start_fix
    return SimpleNamespace(core=core, sites=sites, online=online, fixes=fixes)


def _cycle(core, mode="auto"):
    core._watchdog_check(mode)      # первый сбой — повтор через минуту
    core._watchdog_check(mode)      # второй — подбор
    core._reconcile_alerts()


# ------------------------------------------------------------ сторож в режиме auto

def test_auto_watchdog_does_not_repeat_failed_pick_forever(wd):
    """watchdog_loop.py: три десятиминутных цикла — три подбора по 40–60 с обрывов. Теперь — один."""
    core = wd.core
    for _ in range(3):
        _cycle(core)
    assert len(wd.fixes) == 1
    alert = _alert(core, "watchdog")
    assert "подобрать стратегию не вышло" in alert["text"] and alert["action"]["call"] == "zapret_fix"


def test_auto_watchdog_tries_again_after_something_changed(wd):
    core = wd.core
    _cycle(core)
    core.settings.update(lambda d: d["zapret"].__setitem__("strategy", "general (ALT2)"))   # человек сменил
    _cycle(core)
    assert len(wd.fixes) == 2
    core._net_fp = frozenset({("Wi-Fi", "10.0.0.7")})                                     # другая сеть
    _cycle(core)
    assert len(wd.fixes) == 3


def test_auto_watchdog_tries_again_after_problem_went_away(wd):
    core = wd.core
    _cycle(core)
    wd.sites["youtube"] = True
    core._watchdog_check("auto")              # всё открылось — плашка снята
    assert _alert(core, "watchdog") is None
    wd.sites["youtube"] = False
    _cycle(core)
    assert len(wd.fixes) == 2, "новая поломка — новая попытка"


# ------------------------------------------------------------ итог проверки для своего VPN

def test_error_only_check_does_not_clear_watchdog_alert(wd):
    core = wd.core
    _cycle(core, "ask")
    core._check_fp = core._zapret_fingerprint()
    core.tester.check_state = {"running": False, "at": time.time() + 1, "direct": False,
                               "results": [{"id": "error", "label": "Проверка", "ok": False, "detail": "curl"}]}
    core._reconcile_alerts()
    assert core.has_alert("watchdog"), "упавшая проверка — не удачная проверка"


def test_bypass_result_for_own_vpn_is_fresh_only(wd):
    core = wd.core
    core._watchdog_check("ask")
    assert core._bypass_ok() is False and core._zapret_view().last_ok is False
    core.settings.update(lambda d: d["zapret"].__setitem__("strategy", "general (ALT2)"))
    assert core._bypass_ok() is None, "стратегия сменилась — прежний провал не про неё"
    core.settings.update(lambda d: d["zapret"].__setitem__("strategy", "general"))
    assert core._bypass_ok() is False
    core._net_fp = frozenset({("Wi-Fi", "10.0.0.7")})
    assert core._bypass_ok() is None, "сеть сменилась — тоже"


def test_no_internet_makes_watchdog_result_unknown(wd):
    core = wd.core
    core._watchdog_check("ask")
    assert core.watchdog_state["last_ok"] is False
    wd.online["value"] = False
    core._watchdog_check("ask")
    assert core.watchdog_state["last_ok"] is None


def test_successful_fix_is_a_fresh_check(wd):
    core = wd.core
    _cycle(core, "ask")
    results = [{"id": "discord", "label": "Discord", "ok": True}, {"id": "youtube", "label": "YouTube", "ok": True}]
    core.tester.fix_state = {"stage": "done", "finished_at": time.time() + 5, "results": results, "direct": False}
    core._reconcile_alerts()
    assert core._bypass_ok() is True and not core.has_alert("watchdog")


def test_bypass_state_handed_to_own_vpn_is_retried_after_failure(tmp_path):
    from tests.test_vpnclient_core import FakeManager
    vc = FakeManager()
    core = make_core(tmp_path, vc)
    core.zapret.status = "stopped"
    calls = []

    def set_bypass(view):
        calls.append(view)
        if len(calls) == 1:
            raise RuntimeError("менеджер занят")
    vc.set_bypass = set_bypass
    core._zapret_view = lambda: "view"
    core._sync_bypass()
    core._sync_bypass()
    assert calls == ["view", "view"], "не передалось — следующий тик передаёт снова"
    core._sync_bypass()
    assert len(calls) == 2, "передалось — повторять незачем"


# ------------------------------------------------------------ VPN без пути мимо себя

def test_tunnel_without_direct_path_is_not_checked_through_vpn(wd):
    core = wd.core
    core.vpn_snapshot = SimpleNamespace(internet=[object()], source_ip=lambda: None, foreign_active=False,
                                        own_active=False)
    with pytest.raises(NoDirectPath):
        core._direct_source()
    core.set_alert("watchdog", "warn", "YouTube перестал открываться")
    core._watchdog_check("ask")
    assert core.watchdog_state["vpn"] is True and core.watchdog_state["last_ok"] is None
    assert not core.has_alert("watchdog")


# ------------------------------------------------------------ объявление о VPN

def test_vpn_is_confirmed_by_two_scans_in_a_row(tmp_path):
    core = make_core(tmp_path, None)
    core._vpn_was_active = None
    assert core._confirmed_vpn(False) is False            # первый осмотр — как есть
    core._vpn_was_active = False
    assert core._confirmed_vpn(True) is False, "Radmin на секунду «в интернет» — ещё не VPN"
    core._vpn_was_active = False
    assert core._confirmed_vpn(False) is False
    assert core._confirmed_vpn(True) is False
    assert core._confirmed_vpn(True) is True


# ------------------------------------------------------------ «Мои сайты» и настройки во время подбора

def test_add_site_keeps_comments_of_the_list(tmp_path):
    core = make_core(tmp_path, None)
    saved = {"text": "# Мои сайты для работы\r\nwork.example.com\r\n# игры\r\ngame.example.com\r\n"}
    core.zapret.lists_get = lambda: [{"id": "list-general-user.txt", "text": saved["text"]}]
    core.zapret.lists_save = lambda list_id, text: saved.__setitem__("text", text)
    result = core.lists_add_site("https://New.Example.org/page")
    assert result["ok"] and saved["text"] == ("# Мои сайты для работы\nwork.example.com\n# игры\n"
                                              "game.example.com\nnew.example.org\n")


def test_add_site_replaces_placeholder(tmp_path):
    from app.zapret import lists
    core = make_core(tmp_path, None)
    saved = {"text": f"# Never leave this file empty\r\n{lists.PLACEHOLDER_DOMAIN}\r\n"}
    core.zapret.lists_get = lambda: [{"id": "list-general-user.txt", "text": saved["text"]}]
    core.zapret.lists_save = lambda list_id, text: saved.__setitem__("text", text)
    core.lists_add_site("site.ru")
    assert saved["text"] == "# Never leave this file empty\nsite.ru\n"


def test_strategy_change_is_refused_right_away_during_test(tmp_path):
    core = make_core(tmp_path, None)
    core.zapret.paused_for_test = True
    core.zapret.strategy = lambda sid: None
    result = core.zapret_set_strategy("general (ALT)")
    assert result["ok"] is False and "Идёт подбор" in result["error"]


# ------------------------------------------------------------ страховка: служба и смена сети

def test_running_service_is_guarded_when_lazeyka_starts(tmp_path):
    core = make_core(tmp_path, None)
    core.zapret.mode = "service"
    core.zapret.running = lambda: True
    armed = []
    core.guard = SimpleNamespace(started=armed.append)
    core._guard_running_service()
    assert armed == [None] and core.zapret.status == "running"
    core.zapret.mode = "app"
    core._guard_running_service()
    assert armed == [None]


def test_network_change_lets_guard_check_bypass_started_offline(tmp_path, monkeypatch):
    core = make_core(tmp_path, None)
    calls = []
    core.guard = SimpleNamespace(network_changed=lambda: calls.append(1))
    core._own_exclusions = lambda: (set(), set())
    core._vpn_watch = lambda announce: None
    core.tg.status = "stopped"
    addresses = {"Wi-Fi": [SimpleNamespace(family=2, address="192.168.1.5")]}
    monkeypatch.setattr("psutil.net_if_addrs", lambda: addresses)
    core._net_fp = None
    core._check_network()
    assert calls == []
    addresses["Wi-Fi"] = [SimpleNamespace(family=2, address="10.0.0.7")]
    core._check_network()
    assert calls == [1]


def test_fingerprint_reads_process_once(tmp_path):
    core = make_core(tmp_path, None)
    reads = {"n": 0}
    proc = SimpleNamespace(started_at=123.0)

    class Vanishing(type(core.zapret)):
        @property
        def process(self):
            reads["n"] += 1
            return proc if reads["n"] % 2 else None

        @process.setter
        def process(self, value):
            pass
    zapret = Vanishing()
    zapret.settings = core.settings
    core.zapret = zapret
    assert core._zapret_fingerprint()[-1] == 123.0
