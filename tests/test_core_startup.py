"""Core: автозапуск компонентов по отдельности, тикер по разделам, сон по часам Windows, отложенные
проверки, «Подключить Telegram», падение прокси, перезапуск после самообновления, плашки обновлений.
Ничего настоящего не запускается."""
import threading
import time
from types import SimpleNamespace

import pytest

from app import paths, winutil
from app.errors import UserError
from tests.test_vpnclient_core import FakeManager, make_core


def _alert(core, alert_id):
    return next((n for n in core.notices() if n["id"] == alert_id), None)


def _core(tmp_path, vc=None):
    core = make_core(tmp_path, vc)
    core._stop = threading.Event()
    core._status_changed = lambda force=False: None
    return core


# ------------------------------------------------------------ автозапуск

def test_autostart_survives_unexpected_tg_failure(tmp_path):
    """Ядро прокси не загрузилось (ModuleNotFoundError) — плашка, а обход и свой VPN всё равно включаются."""
    vc = FakeManager()
    core = _core(tmp_path, vc)

    def mutate(d):
        d["first_run"] = False
        d["startup"].update({"tg": True, "zapret": True, "vpnclient": True})
        d["tg"]["was_running"] = d["zapret"]["was_running"] = d["vpnclient"]["was_running"] = True
    core.settings.update(mutate)
    started = []
    core.tg.start = lambda: (_ for _ in ()).throw(ModuleNotFoundError("No module named 'cryptography'"))
    core.zapret.start = lambda: started.append("zapret")
    core._arm_connectivity_guard = lambda: None
    core._vpn_scan = lambda: None
    core._autostart_components()
    assert started == ["zapret"] and ("vpnclient.start", True) in vc.calls
    assert "cryptography" in _alert(core, "tg-down")["text"]


def test_autostart_survives_unexpected_zapret_failure(tmp_path):
    vc = FakeManager()
    core = _core(tmp_path, vc)

    def mutate(d):
        d["first_run"] = False
        d["startup"].update({"tg": False, "zapret": True, "vpnclient": True})
        d["zapret"]["was_running"] = d["vpnclient"]["was_running"] = True
    core.settings.update(mutate)
    core.zapret.start = lambda: (_ for _ in ()).throw(OSError("WinError 5"))
    core._vpn_scan = lambda: None
    core._autostart_components()
    assert "WinError 5" in _alert(core, "zapret-down")["text"] and ("vpnclient.start", True) in vc.calls


# ------------------------------------------------------------ тикер

def test_ticker_section_failure_does_not_skip_the_rest(tmp_path):
    core = _core(tmp_path)
    done = []
    core._check_resume = lambda: done.append("сон")
    core.tg = SimpleNamespace(sample=lambda: (_ for _ in ()).throw(AttributeError("bytes_up")), status="stopped")
    core.zapret.refresh_status = lambda: done.append("обход")
    for name in ("_vpnclient_tick", "_watchdog_tick", "_sync_bypass", "_watch_own_vpn"):
        setattr(core, name, lambda name=name: done.append(name))
    core._reconcile_alerts = lambda: done.append("плашки")
    core._tick_once(2)
    assert done == ["сон", "обход", "_vpnclient_tick", "_watchdog_tick", "_sync_bypass", "_watch_own_vpn", "плашки"]


# ------------------------------------------------------------ сон

def test_clock_jump_or_stalled_ticker_is_not_sleep(tmp_path, monkeypatch):
    """Перевод часов и подвисший на 40 с тикер не перезапускают прокси и обход: сна не было."""
    core = _core(tmp_path)
    woke = []
    core._after_sleep = lambda: woke.append(True)
    core._sleep_mark = (1000.0, 1000.0)
    monkeypatch.setattr(winutil, "sleep_clock", lambda: (1040.0, 1040.0))
    core._check_resume()
    assert woke == []
    monkeypatch.setattr(winutil, "sleep_clock", lambda: (1140.0, 1045.0))   # 95 с без хода «без сна»
    core._check_resume()
    assert woke == [True]


def test_sleep_clock_is_consistent():
    tick, unbiased = winutil.sleep_clock()
    assert tick > 0 and 0 < unbiased <= tick + 1


# ------------------------------------------------------------ отложенные проверки

def test_delayed_checks_are_daemon_and_skip_after_quit(tmp_path):
    core = _core(tmp_path)
    ran = []
    core._stop.set()
    core._later(0.01, lambda: ran.append(True))
    time.sleep(0.2)          # отрицательное утверждение: лишнего вызова не случилось
    assert ran == []
    timers = [t for t in threading.enumerate() if isinstance(t, threading.Timer)]
    assert all(t.daemon for t in timers)


# ------------------------------------------------------------ «Подключить Telegram»

def test_connect_telegram_waits_for_start_and_refuses_dead_proxy(tmp_path, monkeypatch):
    core = _core(tmp_path)
    opened = []
    monkeypatch.setattr(winutil, "open_unelevated", lambda link: opened.append(link) or True)
    started = threading.Event()

    def start():
        time.sleep(0.2)
        core.tg.status = "running"
        started.set()

    core.tg = SimpleNamespace(status="stopped", error=None, start=start, link=lambda: "tg://proxy?server=127.0.0.1")
    core.background = lambda name, fn, on_error: threading.Thread(target=fn, daemon=True)
    job = core._tg_start_job = core.background("tg-start", start, "")
    job.start()
    assert core.tg_open_in_telegram() == {"ok": True}
    assert started.is_set() and opened == ["tg://proxy?server=127.0.0.1"], "ссылка — только когда прокси слушает"
    core.tg.status, core.tg.error = "error", "Порт 1443 уже занят"
    reply = core.tg_open_in_telegram()
    assert reply["ok"] is False and "Порт 1443 уже занят" in reply["error"] and len(opened) == 1


# ------------------------------------------------------------ падение прокси

def test_proxy_crash_restarts_once_then_reports(tmp_path, monkeypatch):
    core = _core(tmp_path)
    monkeypatch.setattr("app.core.TG_REVIVE_PAUSE", 0.0)
    revived = threading.Event()
    core.tg = SimpleNamespace(status="error", start=lambda: (setattr(core.tg, "status", "running"), revived.set()))
    core._tg_crashed("Прокси остановился сам: порт закрылся")
    assert _alert(core, "tg-down")["level"] == "warn" and "перезапускаем" in _alert(core, "tg-down")["text"]
    assert revived.wait(5)
    core.tg.status = "error"
    core._tg_crashed("Прокси остановился сам: порт закрылся")       # снова, меньше чем через минуту
    alert = _alert(core, "tg-down")
    assert alert["level"] == "error" and alert["action"]["call"] == "tg_start"


def test_proxy_revive_failure_is_error_alert(tmp_path, monkeypatch):
    core = _core(tmp_path)
    monkeypatch.setattr("app.core.TG_REVIVE_PAUSE", 0.0)
    failed = threading.Event()

    def start():
        failed.set()
        raise UserError("порт занят")

    core.tg = SimpleNamespace(status="error", start=start)
    core._tg_crashed("Прокси остановился сам")
    assert failed.wait(5)
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and _alert(core, "tg-down")["level"] != "error":
        time.sleep(0.01)
    assert "не перезапустился: порт занят" in _alert(core, "tg-down")["text"]


# ------------------------------------------------------------ перезапуск после самообновления

def test_app_restart_launches_new_exe_with_replace_and_quits(tmp_path, monkeypatch):
    core = _core(tmp_path)
    exe = tmp_path / "Lazeyka.exe"
    monkeypatch.setattr(paths, "IS_FROZEN", True)
    monkeypatch.setattr(paths, "exe_path", lambda: exe)
    launched, quit_calls = [], []
    monkeypatch.setattr("app.core.subprocess.Popen", lambda cmd, **kw: launched.append(cmd))
    core.on_quit = lambda: quit_calls.append(True)
    assert core.app_restart() == {"ok": True}
    assert launched == [[str(exe), "--replace"]] and quit_calls == [True]
    monkeypatch.setattr(paths, "IS_FROZEN", False)
    assert core.app_restart()["ok"] is False


# ------------------------------------------------------------ плашки обновлений

def test_update_notice_counts_what_the_badge_counts(tmp_path, monkeypatch):
    """Ядро VPN при автообновлении в счётчик не входит — и в id плашки тоже: иначе плашка, скрытая
    крестиком, возвращалась бы после каждого автообновления ядра."""
    from app.vpnclient import engines
    monkeypatch.setattr(engines, "installed", lambda name, version=None: "1.14.3" if name == "sing-box" else None)
    core = _core(tmp_path, FakeManager())
    core.zapret.pack = SimpleNamespace(version="1.10.3")
    core.updates.releases["zapret"] = {"version": "1.10.4"}
    core.updates.releases["vpncore"] = {"version": "1.15.0"}
    notice = next(n for n in core.notices() if n["id"].startswith("update:"))
    assert notice["id"] == "update:zapret:1.10.4"
    assert notice["text"] == "Доступно обновление. Скачается, только если вы нажмёте «Установить»."
    core.updates.releases["vpncore"] = {"version": "1.15.1"}
    assert any(n["id"] == "update:zapret:1.10.4" for n in core.notices())


def test_restart_notice_after_self_update(tmp_path):
    core = _core(tmp_path)
    core.updates._app_restart = "Лазейка 1.3.0 установлена — перезапустите её, чтобы заработала новая версия."
    notice = _alert(core, "app-restart")
    assert notice["action"] == {"label": "Перезапустить", "call": "app_restart", "args": []}


def test_broken_settings_file_is_alert(tmp_path):
    core = _core(tmp_path)
    core.settings.recovered = "Файл настроек был повреждён — восстановлены настройки из резервной копии."
    core._startup_alerts = [("data-untrusted", "warn", "Папке данных нельзя было доверять")]
    core.tg = SimpleNamespace(load_core=lambda: None)
    for name in ("_first_launch_import", "_autostart_components", "_ticker", "_startup_path_alerts"):
        setattr(core, name, lambda: None)
    core.first_launch = False
    core.zapret.init = lambda: None
    core.vpnclient = None
    core.settings.update(lambda d: d["updates"].__setitem__("check", False))
    core.startup()
    assert _alert(core, "settings-broken")["level"] == "warn"
    assert _alert(core, "data-untrusted")["text"] == "Папке данных нельзя было доверять"


def test_unsaved_settings_say_why(tmp_path):
    """Запись отключена до перезапуска (файл настроек не прочитался): ответ на нажатие — об этом, а не
    «нет прав на запись»."""
    core = _core(tmp_path)
    core.settings._block_writes()
    reply = core.save_settings({"close_to_tray": False})
    assert reply["ok"] is False and "не прочитался при запуске" in reply["error"]
    assert "нет прав" not in reply["error"]


def test_discord_cache_is_not_cleared_for_another_account(tmp_path, monkeypatch):
    core = _core(tmp_path)
    monkeypatch.setattr(winutil, "other_account", lambda: True)
    monkeypatch.setattr("app.core.diagnostics.clear_discord_cache", lambda: pytest.fail("чистить чужой кэш нельзя"))
    reply = core.discord_clear_cache()
    assert reply["ok"] is False and "другой учётной записи" in reply["error"]
