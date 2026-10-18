"""Core и свой VPN: обёртки раздела 6, порядок выключения, автозапуск, тикер, журнал, настройки.
Менеджер VPN — подделка с интерфейсом раздела 13 плана; ядро не запускается."""
import itertools
import json
import logging
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from app import log as applog
from app import paths, vpn, winutil
from app.errors import UserError
from app.settings import Settings

MOCK = Path(__file__).resolve().parent.parent / "app" / "ui" / "mock-vpnclient-state.json"

# Методы страницы из раздела 6 плана.
API_METHODS = (
    "vpnclient_import", "vpnclient_sub_update", "vpnclient_sub_remove", "vpnclient_sub_set",
    "vpnclient_server_remove", "vpnclient_server_rename", "vpnclient_copy_link", "vpnclient_select",
    "vpnclient_preflight", "vpnclient_start", "vpnclient_stop", "vpnclient_restart", "vpnclient_set_mode",
    "vpnclient_latency", "vpnclient_save_settings", "vpnclient_core_install", "vpnclient_rules_update",
    "vpnclient_running_apps", "vpnclient_import_file", "vpnclient_import_qr", "vpnclient_qr",
    "vpnclient_backup_export", "vpnclient_backup_import", "vpnclient_profile_import", "vpnclient_profile_set",
    "vpnclient_profile_remove", "vpnclient_speedtest", "vpnclient_deeplink_confirm",
)


def mock_state() -> dict:
    return json.loads(MOCK.read_text(encoding="utf-8"))


class FakeManager:
    """VpnClientManager по разделу 13: записывает вызовы, снимок — эталон страницы."""

    def __init__(self, journal: list | None = None):
        self.calls: list[tuple] = []
        self.journal = journal if journal is not None else self.calls
        self.status = "stopped"
        self.own_value = None
        self.snap = mock_state()

    def __getattr__(self, name):
        # Любое действие из раздела 6: import_text, sub_update, select, latency…
        if name.startswith("_"):
            raise AttributeError(name)

        def action(*args, **kwargs):
            self.calls.append((name, args, kwargs))
            return None
        return action

    def snapshot(self):
        return self.snap

    def own(self):
        return self.own_value

    def shutdown(self):
        self.journal.append(("vpnclient.shutdown",))

    def start(self, quiet=False):
        self.journal.append(("vpnclient.start", quiet))

    def copy_link(self, server_id):
        self.calls.append(("copy_link", (server_id,), {}))
        return "vless://secret-uuid@203.0.113.10:443#x"

    def running_apps(self):
        return [{"name": "Discord", "path": r"C:\Apps\Discord.exe"}]

    def qr(self, item_id):
        return "data:image/png;base64,AAAA"


class FakeZapret:
    def __init__(self):
        self.available, self.unavailable_reason = True, None
        self.status, self.error, self.mode = "stopped", None, "app"
        self.strategies, self.process, self.pack = [], None, None
        self.paused_for_test = False
        self.vpn_applied = {"mode": "plain"}
        self.settings = None
        self.av_removal_seen = False

    def ipset_info(self):
        return {"mode": "none", "count": 0}

    def service_info(self):
        return {"installed": False, "running": False, "strategy": None}


def make_core(tmp_path, vpnclient=None):
    """Core без системы: подделки обхода, прокси и подбора, настоящие настройки и «Обновления»."""
    from app.core import Core
    from app.updates.manager import UpdateManager
    core = Core.__new__(Core)
    core.settings = Settings(tmp_path / "s.json")
    core.is_admin = True
    core.autostarted = False
    core._lock = threading.RLock()
    core._notices, core._notice_ids, core._dismissed = [], itertools.count(1), set()
    core.ui_visible, core.on_toast, core._last_toast = True, None, 0.0
    core.on_status_change = None
    core._last_tray_key = None
    core.zapret = FakeZapret()
    core.zapret.settings = core.settings
    core.tg = SimpleNamespace(status="stopped", snapshot=lambda: {"status": "stopped"})
    core.tester = SimpleNamespace(state={}, fix_state={}, check_state={}, running=False, fix_running=False)
    core.updates = UpdateManager(core.settings, core.zapret, SimpleNamespace(core=None), core.notify, True)
    core.diag_state, core.dns_state, core.defender_state = {}, {}, {}
    core.watchdog_state = {"last_at": None, "last_ok": None, "failing": [], "vpn": False}
    core._conflicts, core._original_tgws, core.busy = [], False, None
    core._check_fp, core._best_id, core._scores, core._best_at = None, None, {}, None
    core.vpn_snapshot, core.vpn_routes, core._vpn_scan_at = None, None, 0.0
    core.vpnclient = vpnclient
    core.vpnclient_error = None if vpnclient is not None else "Модуль своего VPN не загрузился: тест"
    core.updates.vpnclient = vpnclient
    core.background = lambda name, fn, on_error: fn()
    return core


# ------------------------------------------------------------ обёртки

def test_every_section6_method_is_in_api_and_core():
    from app.api import Api
    from app.core import Core
    for name in API_METHODS:
        assert callable(getattr(Api, name, None)), name
        assert callable(getattr(Core, name, None)), name


def test_wrappers_call_manager(tmp_path, monkeypatch):
    monkeypatch.setattr("app.core.Core._vpn_scan", lambda self: None)
    vc = FakeManager()
    core = make_core(tmp_path, vc)
    assert core.vpnclient_select("auto:g-1") == {"ok": True}
    assert core.vpnclient_import("vless://x", "incy")["ok"]
    assert core.vpnclient_latency(None)["ok"] and core.vpnclient_speedtest(None)["ok"]
    assert core.vpnclient_start(quiet=True)["ok"]
    names = [c[0] for c in vc.calls]
    assert names[:4] == ["select", "import_text", "latency", "speedtest"]
    assert ("vpnclient.start", True) in vc.calls
    assert core.vpnclient_running_apps() == {"ok": True, "apps": [{"name": "Discord", "path": r"C:\Apps\Discord.exe"}]}
    assert core.vpnclient_qr("s-1") == {"ok": True, "png": "data:image/png;base64,AAAA"}
    assert core.vpnclient_set_mode("vpn")["ok"] is False


def test_copy_link_goes_to_clipboard_not_to_page(tmp_path, monkeypatch):
    copied = []
    monkeypatch.setattr(winutil, "set_clipboard", lambda text: copied.append(text) or True)
    core = make_core(tmp_path, FakeManager())
    reply = core.vpnclient_copy_link("s1")
    assert reply == {"ok": True} and copied == ["vless://secret-uuid@203.0.113.10:443#x"]


def test_set_mode_answers_with_the_outcome_not_in_background(tmp_path):
    """Окно «Уже работает другой VPN» → «Включить как системный прокси» включает VPN следом: ответ
    vpnclient_set_mode — уже итог смены режима, иначе отказ прокси ушёл бы в фон, а VPN включился бы в TUN."""
    from app.api import Api
    from app.vpnclient.manager import VpnClientError
    vc = FakeManager()

    def set_mode(mode):
        if mode == "proxy":
            raise VpnClientError("Режим «Системный прокси» недоступен: другая учётная запись")
        vc.calls.append(("set_mode", (mode,), {}))
        return {}
    vc.set_mode = set_mode
    core = make_core(tmp_path, vc)
    core.background = lambda name, fn, on_error: pytest.fail(f"смена режима ушла в фон: {name}")
    reply = Api(core).vpnclient_set_mode("proxy")
    assert reply["ok"] is False and "недоступен" in reply["error"]
    assert Api(core).vpnclient_set_mode("local") == {"ok": True}
    assert ("set_mode", ("local",), {}) in vc.calls


def test_manager_fail_dict_in_background_is_an_error(tmp_path):
    vc = FakeManager()
    vc.restart = lambda: {"ok": False, "error": "порт занят"}
    core = make_core(tmp_path, vc)
    seen = []

    def background(name, fn, on_error):
        try:
            fn()
        except UserError as exc:
            seen.append(f"{on_error}: {exc}")
    core.background = background
    core.vpnclient_restart()
    assert seen == ["Свой VPN не перезапустился: порт занят"]


def test_without_manager_api_explains(tmp_path):
    from app.api import Api
    core = make_core(tmp_path, None)
    reply = Api(core).vpnclient_start()
    assert reply["ok"] is False and "не загрузился" in reply["error"]
    assert Api(core).vpnclient_latency("все")["ok"] is False          # проверка типов
    assert Api(core).vpnclient_import("   ")["ok"] is False
    state = core.state()["vpnclient"]
    assert state["available"] is False and "не загрузился" in state["unavailable_reason"]


def test_core_install_shares_busy_with_updates(tmp_path, monkeypatch):
    from app.updates.manager import UpdateError
    gate, started = threading.Event(), threading.Event()
    vc = FakeManager()

    def core_install(name, release=None):
        started.set()
        gate.wait(5)
        return f"{name} установлено"
    vc.core_install = core_install
    core = make_core(tmp_path, vc)
    assert core.vpnclient_core_install("sing-box") == {"ok": True}
    assert started.wait(5)
    with pytest.raises(UpdateError, match="Уже выполняется"):
        core.updates.install_async("vpncore")               # та же задача со страницы «Обновления»
    gate.set()
    for _ in range(100):
        if "vpncore" not in core.updates._busy:
            break
        time.sleep(0.02)
    assert core.updates.progress["vpncore"]["state"] == "done"
    assert core.vpnclient_core_install("v2ray")["ok"] is False


# ------------------------------------------------------------ жизненный цикл

def test_shutdown_returns_system_proxy_first(tmp_path):
    journal: list = []
    core = make_core(tmp_path, FakeManager(journal))
    core._stop = threading.Event()
    core.tester = SimpleNamespace(cancel=lambda: journal.append(("tester.cancel",)),
                                  join=lambda t: journal.append(("tester.join",)))
    core.tg = SimpleNamespace(stop=lambda remember: journal.append(("tg.stop",)))
    core.zapret.stop = lambda remember: journal.append(("zapret.stop",))
    core.shutdown()
    assert [j[0] for j in journal] == ["vpnclient.shutdown", "tester.cancel", "tester.join", "tg.stop",
                                       "zapret.stop"]


def test_shutdown_survives_manager_failure(tmp_path):
    vc = FakeManager()
    vc.shutdown = lambda: (_ for _ in ()).throw(RuntimeError("ядро не ответило"))
    core = make_core(tmp_path, vc)
    core._stop = threading.Event()
    stopped = []
    core.tester = SimpleNamespace(cancel=lambda: None, join=lambda t: None)
    core.tg = SimpleNamespace(stop=lambda remember: stopped.append("tg"))
    core.zapret.stop = lambda remember: stopped.append("zapret")
    core.shutdown()
    assert stopped == ["tg", "zapret"]


def _autostart_core(tmp_path, monkeypatch, first=False, on_start=True, was_running=True, foreign=False):
    journal: list = []
    vc = FakeManager(journal)
    core = make_core(tmp_path, vc)

    def mutate(d):
        d["first_run"] = first
        d["startup"].update({"vpnclient": on_start, "tg": False})
        d["zapret"]["was_running"] = True
        d["vpnclient"]["was_running"] = was_running
    core.settings.update(mutate)
    core.zapret.start = lambda: journal.append(("zapret.start",))
    core._arm_connectivity_guard = lambda: None
    core._status_changed = lambda force=False: None
    snap = SimpleNamespace(foreign_internet=[1] if foreign else [], foreign_label="Incy", proxy=None)
    monkeypatch.setattr("app.core.Core._vpn_scan", lambda self: snap)
    notes: list = []
    core.notify = lambda level, text, action=None: notes.append((level, text))
    return core, journal, notes


def test_autostart_vpn_after_zapret(tmp_path, monkeypatch):
    core, journal, _ = _autostart_core(tmp_path, monkeypatch)
    core._autostart_components()
    assert journal == [("zapret.start",), ("vpnclient.start", True)]


@pytest.mark.parametrize("kwargs", [{"first": True}, {"on_start": False}, {"was_running": False}])
def test_no_autostart(tmp_path, monkeypatch, kwargs):
    core, journal, _ = _autostart_core(tmp_path, monkeypatch, **kwargs)
    core._autostart_components()
    assert ("vpnclient.start", True) not in journal


def test_autostart_skips_next_to_incy(tmp_path, monkeypatch):
    core, journal, notes = _autostart_core(tmp_path, monkeypatch, foreign=True)
    core._autostart_components()
    assert ("vpnclient.start", True) not in journal
    # Не включился сам — плашка (с переходом на страницу VPN), а не уведомление.
    assert notes == []
    alert = next(n for n in core.notices() if n["id"] == "vpnclient-autostart")
    assert alert["level"] == "warn" and "Incy" in alert["text"] and alert["persistent"] is True
    assert alert["action"] == {"label": "Открыть VPN", "page": "vpnclient"}


def test_resume_does_not_restart_vpn(tmp_path):
    vc = FakeManager()
    core = make_core(tmp_path, vc)
    core._last_wall = time.time() - 120
    core._wd_next = 0.0
    core._check_resume()
    names = [c[0] for c in vc.calls]
    assert names == ["on_resume"]


def test_ticker_parts_call_manager(tmp_path, monkeypatch):
    vc = FakeManager()
    core = make_core(tmp_path, vc)
    core._vpnclient_tick()
    vc.tick = lambda: (_ for _ in ()).throw(RuntimeError("сбой"))
    core._vpnclient_tick()                      # ошибка своего VPN тикер не роняет
    assert ("tick", (), {}) in vc.calls


def test_sync_bypass_on_changes_only(tmp_path):
    vc = FakeManager()
    core = make_core(tmp_path, vc)
    core._zapret_view = lambda: SimpleNamespace(running=core.zapret.status == "running",
                                                paused_for_test=core.zapret.paused_for_test,
                                                last_ok=core.watchdog_state["last_ok"])
    sent = []
    vc.set_bypass = lambda view: sent.append((view.running, view.paused_for_test, view.last_ok))
    core._sync_bypass()
    core._sync_bypass()
    core.zapret.status = "starting"
    core._sync_bypass()                         # переходное состояние не передаём
    core.zapret.status = "running"
    core._sync_bypass()
    core.zapret.paused_for_test = True          # подбор: селектор не трогать
    core._sync_bypass()
    core.zapret.paused_for_test = False
    core.watchdog_state["last_ok"] = False      # проверка провалилась
    core._sync_bypass()
    assert sent == [(False, False, None), (True, False, None), (True, True, None), (True, False, False)]


def test_background_shows_user_error_text(tmp_path):
    from app.core import Core
    core = make_core(tmp_path, None)
    del core.background                          # настоящий Core.background
    done = threading.Event()
    notes = []
    core.notify = lambda level, text, action=None: (notes.append(text), done.set())
    core._status_changed = lambda force=False: None
    Core.background(core, "x", lambda: (_ for _ in ()).throw(UserError("сервер не отвечает")), "Свой VPN не включился")
    assert done.wait(5)
    assert notes == ["Свой VPN не включился: сервер не отвечает"]


# ------------------------------------------------------------ журнал, настройки, состояние

def test_log_source_vpn():
    assert applog.source_of("lazeyka.vpnclient") == "vpn"
    assert applog.source_of("lazeyka.vpnclient.process") == "vpn"
    assert applog.source_of("lazeyka.vpn") == "app"                 # совместимость с VPN
    assert applog.source_of("lazeyka.vpnfilter") == "app"


def test_logs_accept_vpn_source(tmp_path):
    core = make_core(tmp_path, None)
    root = logging.getLogger()
    root.addHandler(applog.ring)
    try:
        logging.getLogger("lazeyka.vpnclient.engines").warning("проверка источника vpn")
        logging.getLogger("lazeyka.vpn").warning("проверка источника app")
    finally:
        root.removeHandler(applog.ring)
    lines = core.logs(0, "vpn")["lines"]
    assert lines and all(ln["src"] == "vpn" for ln in lines)
    assert any("источника vpn" in ln["msg"] for ln in lines)
    assert not any("источника app" in ln["msg"] for ln in lines)


def test_save_settings_vpn_on_start_and_scale(tmp_path):
    core = make_core(tmp_path, None)
    assert core.save_settings({"vpnclient_on_start": True, "ui_scale": 1.25})["ok"]
    assert core.settings.get("startup", "vpnclient") is True and core.settings.get("ui", "scale") == 1.25
    for bad in (2.0, 0.5, True, "1.2"):
        assert core.save_settings({"ui_scale": bad})["ok"] is False
    assert core.settings.get("ui", "scale") == 1.25
    s = core.state()["settings"]
    assert s["vpnclient_on_start"] is True and s["ui_scale"] == 1.25


def test_state_has_vpnclient_and_core_updates(tmp_path):
    core = make_core(tmp_path, FakeManager())
    state = core.state()
    assert state["vpnclient"]["status"] == "running"
    assert state["vpn"]["own"] == {"active": False, "mode": None}
    items = {i["id"]: i for i in state["updates"]["items"]}
    assert items["vpncore"]["title"] == "Ядро VPN (sing-box)" and items["vpnxray"]["title"] == "Помощник Xray"
    assert set(items["vpncore"]) == set(items["zapret"])           # той же формы


def test_defender_targets_include_cores(tmp_path, monkeypatch):
    sb = tmp_path / "components" / "sing-box"
    xr = tmp_path / "components" / "xray"
    for folder, exe in ((sb / "1.14.3", "sing-box.exe"), (xr / "26.3.27", "xray.exe"), (sb / "1.14.3.staging", "sing-box.exe")):
        folder.mkdir(parents=True)
        (folder / exe).write_bytes(b"MZ")
    monkeypatch.setattr(paths, "SINGBOX_COMPONENTS_DIR", sb)
    monkeypatch.setattr(paths, "XRAY_COMPONENTS_DIR", xr)
    core = make_core(tmp_path, None)
    _paths, procs, _roots = core._defender_targets()
    assert str(sb / "1.14.3" / "sing-box.exe") in procs and str(xr / "26.3.27" / "xray.exe") in procs
    assert not any("staging" in p for p in procs)


def test_status_changed_reacts_to_vpn(tmp_path):
    vc = FakeManager()
    core = make_core(tmp_path, vc)
    refreshed = []
    core.on_status_change = lambda: refreshed.append(1)
    core._status_changed()
    core._status_changed()
    vc.status = "running"
    core._status_changed()
    core._status_changed(force=True)
    assert len(refreshed) == 3


def test_own_vpn_snapshot_feeds_scan(tmp_path, monkeypatch):
    vc = FakeManager()
    vc.own_value = vpn.OwnVpn(pids={1}, adapter_name="Lazeyka", tun_net="172.31.255.252/30", servers=["198.51.100.7"])
    core = make_core(tmp_path, vc)
    got = {}
    monkeypatch.setattr(vpn, "scan", lambda overrides=None, own=None: got.setdefault("own", own) and None)
    core._vpn_scan()
    assert got["own"] is vc.own_value
    nets, names = core._own_exclusions()
    assert nets == {"172.31.255.252/30"} and names == {"Lazeyka"}


# ------------------------------------------------------------ самопроверка сборки

def test_selftest_vpnclient_checks_without_core():
    from app import selftest
    from app.vpnclient import engines
    detail = selftest.check_vpnclient_parsing()           # разбор и конфиг — без запуска ядра
    assert "ссылка VLESS+REALITY" in detail and "подписка и профили" in detail
    cores = selftest.pinned_cores()
    assert cores["sing-box"]["sha256"] == engines.CORES["sing-box"].zip_sha256
    assert cores["xray"]["url"].startswith("https://github.com/XTLS/Xray-core/releases/download/v26.3.27/")
    assert selftest.PINNED_CORES["sing-box"]["sha256"] == engines.CORES["sing-box"].zip_sha256   # план = код
    detail = selftest.check_core_pins(frozen=True)        # без сети и без zip: их в сборке больше нет
    assert "sing-box 1.14.3" in detail and "xray 26.3.27" in detail and "GPL-3.0" in detail


def test_selftest_lists_every_vpnclient_module():
    """Менеджер подгружает модули по имени — exe 1.2.0 вышел без store и subscription. Самопроверка
    сборки импортирует каждый модуль из списка, а список обязан совпадать с файлами пакета."""
    from app import selftest
    package = Path(selftest.__file__).parent / "vpnclient"
    on_disk = {f.stem for f in package.glob("*.py") if f.stem != "__init__"}
    assert set(selftest.VPNCLIENT_MODULES) == on_disk
    assert "все импортируются" in selftest.check_vpnclient_modules()


def test_spec_bundles_every_vpnclient_module():
    spec = (Path(__file__).resolve().parents[1] / "build" / "lazeyka.spec").read_text(encoding="utf-8")
    assert 'collect_submodules("app.vpnclient")' in spec


def test_selftest_core_pins_catch_a_changed_hash_or_address(monkeypatch):
    import dataclasses
    from app import selftest
    from app.vpnclient import engines
    real = engines.CORES["xray"]
    monkeypatch.setitem(engines.CORES, "xray", dataclasses.replace(real, zip_sha256="0" * 64))
    with pytest.raises(ValueError, match="не совпал с планом"):
        selftest.check_core_pins(frozen=True)
    monkeypatch.setitem(engines.CORES, "xray", dataclasses.replace(real, repo="evil/Xray-core"))
    with pytest.raises(ValueError, match="адрес загрузки"):
        selftest.check_core_pins(frozen=True)
    monkeypatch.setitem(engines.CORES, "xray", real)
    monkeypatch.setattr(engines, "gpl_text_path", lambda: paths.DATA / "нет-такого" / "gpl-3.0.txt")
    with pytest.raises(FileNotFoundError, match="GPL"):
        selftest.check_core_pins(frozen=True)


# ------------------------------------------------------------ ссылки, помощь, конфликт на странице

def test_deeplink_and_sub_probe(tmp_path):
    vc = FakeManager()
    core = make_core(tmp_path, vc)
    core.vpnclient_deeplink("https://panel.example.com/sub/x")
    assert ("deeplink_offer", ("https://panel.example.com/sub/x",), {}) in vc.calls
    assert core.vpnclient_sub_probe("s-1") == {"ok": True}
    bare = make_core(tmp_path, SimpleNamespace(status="stopped"))
    assert bare.vpnclient_sub_probe("s-1")["ok"] is False      # менеджер этого не умеет — честный отказ


def test_help_items_and_proxy_fix(tmp_path):
    vc = FakeManager()
    vc.help_items = lambda: [{"id": "vpnclient_dead_proxy", "level": "error", "title": "Мёртвый прокси"}]
    vc.fix_proxy = lambda: {"message": "Прокси выключен"}
    core = make_core(tmp_path, vc)
    assert core.vpnclient_help() == {"ok": True, "items": vc.help_items()}
    assert core.vpnclient_proxy_fix() == {"ok": True, "message": "Прокси выключен"}


def test_report_lists_vpn_traces(tmp_path, monkeypatch):
    vc = FakeManager()
    vc.help_items = lambda: [{"id": "vpnclient_fake_dns", "level": "error", "title": "DNS адаптера «Ethernet» — остаток другого VPN"},
                             {"id": "ok", "level": "ok", "title": "всё хорошо"}]
    core = make_core(tmp_path, vc)
    monkeypatch.setattr(winutil, "set_clipboard", lambda text: True)
    text = core.help_report()["text"]
    assert "остаток другого VPN" in text and "всё хорошо" not in text


def test_foreign_conflict_shows_on_vpn_page(tmp_path):
    a = vpn.Adapter(index=5, guid="{2E219888-9139-4199-EA45-CB771D7DAD1D}", name="wwan99", description="Wintun",
                    if_type=53, up=True, ipv4=["172.19.0.1"])
    a.kind, a.role = "tunnel", "internet"
    core = make_core(tmp_path, FakeManager())
    core.vpn_snapshot = vpn.Snapshot(adapters=[a], servers=[], apps=["Incy"], at=0.0)
    conflict = core.state()["vpnclient"]["conflict"]
    assert conflict["kind"] == "tunnel" and conflict["label"] == "Incy"
    core.settings.update(lambda d: d["vpnclient"].__setitem__("mode", "proxy"))
    assert core.state()["vpnclient"]["conflict"] is None


def test_real_manager_gets_core_hooks(tmp_path, monkeypatch):
    """Настоящий VpnClientManager создаётся Core с zapret_view, on_change и before_core."""
    import importlib.util
    if importlib.util.find_spec("app.vpnclient.manager") is None:
        pytest.skip("app/vpnclient/manager.py ещё не написан")
    core = make_core(tmp_path, None)
    core.zapret.pack = None
    manager = core._create_vpnclient()
    assert manager is not None, core.vpnclient_error
    assert manager.before_core == core._vpnclient_before_core and manager.on_change == core._vpnclient_changed
    view = manager.zapret_view()
    assert view.running is False and view.strategy_args == [] and view.pack_dir is None
    manager.on_change()
    assert core._vc_dirty is True
