"""Версия 1.1: «Найти и включить», согласование с Telegram, помощь, честные проверки."""
import threading
from types import SimpleNamespace

import pytest

from app import helpdesk
from app.settings import Settings
from app.zapret import tester


# ------------------------------------------------------------ «Найти и включить»

class _Strategy:
    def __init__(self, sid):
        self.id = sid
        self.label = sid
        self.usable = True


class _FakeZapret:
    """Ровно то, чем пользуется подборщик: без winws и без системы."""

    def __init__(self, settings, working: str | None, pack_path):
        self.settings = settings
        self.is_admin = True
        self.pack = SimpleNamespace(path=pack_path)
        self.unavailable_reason = None
        self.mode = "app"
        self.lock = threading.RLock()
        self.paused_for_test = False
        self.strategies = [_Strategy(s) for s in ("general", "general (ALT)", "general (ALT2)", "general (ALT5)")]
        self.working = working          # с какой стратегией «всё открывается»
        self.active: str | None = None  # что сейчас «запущено»
        self.marks = 0
        self.winws_exe = "winws.exe"

    def running(self):
        return self.active is not None

    def start(self):
        self.active = self.settings.get("zapret", "strategy")

    def stop(self, remember=True):
        self.active = None

    def set_strategy(self, sid):
        self.settings.update(lambda d: d["zapret"].__setitem__("strategy", sid))
        if self.active:
            self.active = sid

    def mark_test(self, *_a, **_k):
        self.marks += 1

    def unmark_test(self):
        self.marks -= 1

    def build_args(self, strategy):
        return [strategy.id]

    def runtime_args(self, strategy, record=True):
        return self.build_args(strategy)


@pytest.fixture
def fake(tmp_path, monkeypatch):
    settings = Settings(tmp_path / "s.json")
    settings.update(lambda d: d["zapret"].__setitem__("strategy", "general"))
    z = _FakeZapret(settings, working="general (ALT2)", pack_path=tmp_path)

    class FakeProc:
        def __init__(self, exe, args, label):
            self.sid = args[0]

        def start(self, ready_timeout=5):
            z.active = self.sid

        def stop(self):
            z.active = None

    monkeypatch.setattr(tester, "WinwsProcess", FakeProc)
    z.binds = []
    z.direct_ok = True

    def control_ok(cancel=None, bind=None):
        z.binds.append(bind)
        return z.direct_ok or bind is None

    monkeypatch.setattr(tester, "control_ok", control_ok)
    monkeypatch.setattr(tester, "quick_check", lambda cancel=None, bind=None: [
        {"id": "discord", "label": "Discord", "ok": z.active == z.working, "detail": ""},
        {"id": "youtube", "label": "YouTube", "ok": z.active == z.working, "detail": ""}])
    monkeypatch.setattr(tester.time, "sleep", lambda s: None)
    monkeypatch.setattr(tester, "load_last_report", lambda: None)  # не читать отчёты с этой машины
    notes = []
    t = tester.StrategyTester(z, lambda lvl, text: notes.append((lvl, text)))
    t.state = {"kind": "standard", "finished_at": 1.0, "results": []}
    return z, t, notes


def _wait(t):
    t.join(5)  # time.sleep подменён фикстурой — ждём поток, а не часы
    assert not t.fix_running, "подбор не закончился"


def test_fix_finds_working_strategy_and_keeps_it(fake):
    z, t, notes = fake
    t.start_fix()
    _wait(t)
    st = t.fix_state
    assert st["stage"] == "done" and st["found"] == "general (ALT2)" and st["previous"] == "general"
    assert z.settings.get("zapret", "strategy") == "general (ALT2)"
    assert z.active == "general (ALT2)" and z.marks == 0 and not z.paused_for_test
    assert st["tried"][-1] == "general (ALT2)"          # остановились на первой удачной
    assert any(level == "success" for level, _ in notes)


def test_fix_does_nothing_when_everything_works(fake):
    z, t, _ = fake
    z.working = "general"
    t.start_fix()
    _wait(t)
    assert t.fix_state["stage"] == "done" and t.fix_state["tried"] == []
    assert z.settings.get("zapret", "strategy") == "general"


def test_fix_reports_failure_and_restores_previous(fake):
    z, t, _ = fake
    z.working = "nothing"
    t.start_fix()
    _wait(t)
    assert t.fix_state["stage"] == "failed" and t.fix_state["found"] is None
    assert z.settings.get("zapret", "strategy") == "general"
    assert z.active == "general"                          # обход вернулся как был


def test_revert_returns_previous(fake):
    z, t, _ = fake
    t.start_fix()
    _wait(t)
    t.revert_fix()
    assert z.settings.get("zapret", "strategy") == "general"


def test_fix_checks_past_vpn_and_explains_kill_switch(fake):
    z, t, _ = fake
    z.working = "nothing"
    z.direct_ok = False                 # VPN не пускает соединения мимо себя
    t.source = lambda: "192.0.2.10"
    t.start_fix()
    _wait(t)
    st = t.fix_state
    assert st["stage"] == "failed" and st["direct"] is True
    assert "VPN не пускает" in st["message"]
    assert z.binds[:2] == ["192.0.2.10", None]   # сначала мимо VPN, потом — есть ли интернет вообще
    assert z.settings.get("zapret", "strategy") == "general"


def test_second_fix_is_refused(fake):
    from app.errors import UserError
    z, t, _ = fake
    gate = threading.Event()
    t._fix = lambda: gate.wait(5)
    t.start_fix()
    with pytest.raises(UserError):
        t.start_fix()
    with pytest.raises(UserError):
        t.start("standard", None)
    gate.set()
    t.join(5)


# ------------------------------------------------------------ согласование с Telegram

def _core_like(tmp_path):
    from app.core import Core
    core = Core.__new__(Core)
    core.settings = Settings(tmp_path / "c.json")
    return core


def test_tg_extra_lists(tmp_path):
    core = _core_like(tmp_path)
    assert core._tg_extra_lists() == {"list-general-user.txt": [], "list-exclude-user.txt": ["co.uk"]}
    core.settings.update(lambda d: d["tg"].update({"worker_enabled": True, "worker_domains": ["a.b.workers.dev"]}))
    extra = core._tg_extra_lists()
    assert "a.b.workers.dev" in extra["list-general-user.txt"] and "workers.dev" in extra["list-general-user.txt"]
    core.settings.update(lambda d: d["tg"].update({"cf_domains_enabled": True, "cf_domains": ["my.example.com"]}))
    extra = core._tg_extra_lists()
    assert "my.example.com" in extra["list-general-user.txt"] and extra["list-exclude-user.txt"] == []
    core.settings.update(lambda d: d["tg"].__setitem__("zapret_sync", False))
    assert core._tg_extra_lists() == {}


# ------------------------------------------------------------ помощь

@pytest.mark.parametrize("raw, expected", [
    ("https://www.Example.com/path?q=1", "example.com"),
    ("discord.com", "discord.com"),
    ("http://sub.site.ru:8080/x", "sub.site.ru"),
    ("not a domain", None),
    ("", None),
])
def test_normalize_domain(raw, expected):
    assert helpdesk.normalize_domain(raw) == expected


def test_report_hides_secret_and_user_path():
    secret = "0123456789abcdef0123456789abcdef"
    state = {"app": {"admin": True}, "zapret": {"status": "running", "error": r"C:\Users\Ivan\x failed"},
             "tg": {"status": "running", "link": f"tg://proxy?secret=dd{secret}"}, "tg_settings": {"secret": secret},
             "diag": {"items": []}}
    text = helpdesk.build_report(state, [{"lvl": "warn", "t": 0, "msg": f"ключ {secret}"}])
    assert secret not in text and "Ivan" not in text
    assert "<ключ>" in text


def test_bogus_addresses():
    assert helpdesk._bogus("0.0.0.0") and helpdesk._bogus("127.0.0.1") and helpdesk._bogus("10.1.2.3")
    assert not helpdesk._bogus("162.159.135.232")


def test_dns_check_understands_vpn_fake_ip(monkeypatch):
    """Xray и mihomo отвечают на DNS адресами 198.18.x.x — это не подмена провайдером."""
    monkeypatch.setattr(helpdesk, "system_resolve", lambda name: ["198.18.0.7"])
    monkeypatch.setattr(helpdesk, "doh_resolve", lambda name: ["162.159.135.232"])
    monkeypatch.setattr(helpdesk, "_provider_ms", lambda ip: 20)
    result = helpdesk.check_dns(doh_enabled=False)
    assert result["spoofed"] == [] and len(result["vpn_dns"]) == len(helpdesk.DNS_PROBE_DOMAINS)
    assert "VPN-программа" in result["message"]
