"""Обновления: обрыв связи, частичная проверка, перезапуск после самообновления, откат, копия для
автозапуска, восстановление после неудачной установки. Сеть, winws и Telegram-прокси не запускаются."""
import http.client
import socket
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from app import __version__, autostart, paths
from app.settings import Settings
from app.updates import github
from app.updates import manager as um
from app.updates.manager import UpdateError, UpdateManager, settle_app_files
from app.zapret import pack

APP_URL = "https://github.com/wxsqseen/Lazeyka/releases/download/v99.0.0/Lazeyka.exe"


class _Tg:
    core = None
    status = "stopped"


class _Zapret:
    pack = None

    def running(self):
        return False


@pytest.fixture(autouse=True)
def _no_vpn_cores(monkeypatch):
    """Ядер своего VPN нет: проверка обновлений не спрашивает про них GitHub."""
    from app.vpnclient import engines
    monkeypatch.setattr(engines, "installed", lambda name, version=None: None)
    monkeypatch.setattr(engines, "versions", lambda name: [])


def _mgr(tmp_path, zapret=None, tg=None, notes=None):
    notify = (lambda level, text: notes.append((level, text))) if notes is not None else (lambda *a: None)
    return UpdateManager(Settings(tmp_path / "s.json"), zapret or _Zapret(), tg or _Tg(), notify, is_admin=True)


def _frozen_exe(tmp_path, monkeypatch, content=b"OLD", name="Lazeyka.exe"):
    exe = tmp_path / name
    exe.parent.mkdir(parents=True, exist_ok=True)
    exe.write_bytes(content)
    monkeypatch.setattr(paths, "IS_FROZEN", True)
    monkeypatch.setattr(paths, "exe_path", lambda: exe)
    return exe


def _fake_download(content=b"NEW"):
    def download(url, dest, sha, *, progress=None, cancel=None, **kw):
        Path(dest).write_bytes(content)
        return "ab" * 32
    return download


def _app_release(version="99.0.0"):
    return {"version": version, "assets": [{"name": "Lazeyka.exe", "url": APP_URL, "sha256": "ab" * 32}]}


def _wait(predicate, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


# ------------------------------------------------------------ обрыв связи с GitHub

def _broken_server(payload: bytes):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)

    def serve():
        conn, _ = sock.accept()
        conn.recv(65536)
        conn.sendall(payload)
        conn.close()
        sock.close()

    threading.Thread(target=serve, daemon=True).start()
    return f"http://127.0.0.1:{sock.getsockname()[1]}/x"


CHUNKED_CUT = (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: application/json\r\n\r\n"
               b"100\r\n[{\"tag_name\": \"v1")


def test_truncated_chunked_answer_is_github_error():
    """IncompleteRead (обрыв chunked-ответа) — не исключение мимо обработчиков, а понятная ошибка связи."""
    with pytest.raises(github.GitHubError, match="ответ пришёл не целиком"):
        github.http_get(_broken_server(CHUNKED_CUT), timeout=5)
    with pytest.raises(github.GitHubError, match="Обрыв связи"):
        github.http_get(_broken_server(b"garbage-not-http\r\n\r\n"), timeout=5)


def test_truncated_download_removes_file(tmp_path):
    target = tmp_path / "f.bin"
    with pytest.raises(github.GitHubError, match="не целиком"):
        github.download(_broken_server(CHUNKED_CUT), target, None, timeout=5)
    assert not target.exists()


def test_write_error_is_not_called_network_error(tmp_path):
    """Нет места или прав — «не удалось записать файл», а не «ошибка связи с GitHub», и без второго маршрута."""
    missing = tmp_path / "нет-такой-папки" / "f.bin"
    with pytest.raises(github.LocalFileError, match="Не удалось записать файл f.bin"):
        github.download("http://127.0.0.1:9/", missing, None, timeout=1)
    assert issubclass(github.LocalFileError, github.IntegrityError), "via_routes не повторяет через прокси"


def test_check_never_stays_checking_forever(tmp_path, monkeypatch):
    """Необработанное исключение проверки не оставляет «Проверяем…» навсегда."""
    notes = []
    monkeypatch.setattr(github, "latest_release", lambda repo, **kw: (_ for _ in ()).throw(RuntimeError("сбой")))
    m = _mgr(tmp_path, notes=notes)
    m.check_async(quiet=False)
    assert _wait(lambda: not m.checking)
    assert "сбой" in m.error and notes and notes[-1][0] == "error"
    monkeypatch.setattr(github, "latest_release",
                        lambda repo, **kw: (_ for _ in ()).throw(http.client.IncompleteRead(b"")))
    m.check_async(quiet=True)
    assert _wait(lambda: not m.checking), "следующая проверка тоже запускается и заканчивается"


# ------------------------------------------------------------ частичная проверка

def test_partial_check_failure_is_shown_per_item(tmp_path, monkeypatch):
    """Не проверился один источник — ошибка у него и общая строка, а «Всё актуально» не говорится."""
    notes = []

    def latest(repo, **kw):
        if repo == "Flowseal/tg-ws-proxy":
            raise github.GitHubError("Нет связи с GitHub: timed out")
        return {"version": "0.0.1", "tag": "v0.0.1", "assets": []}

    monkeypatch.setattr(github, "latest_release", latest)
    m = _mgr(tmp_path, notes=notes)
    m.checking = True
    m._check(quiet=False)
    assert m.check_errors == {"tgws": "Нет связи с GitHub: timed out"}
    assert "«Ядро Telegram-прокси»" in m.error and "timed out" in m.error
    items = {i["id"]: i for i in m.snapshot()["items"]}
    assert items["tgws"]["check_error"] and not items["tgws"]["checked"]
    assert items["zapret"]["checked"] and items["zapret"]["check_error"] is None
    assert notes == [("warn", m.error)], "по кнопке — предупреждение, а не «Всё актуально»"


def test_full_check_success_says_all_fine_and_clears_errors(tmp_path, monkeypatch):
    notes = []
    monkeypatch.setattr(github, "latest_release", lambda repo, **kw: {"version": "0.0.1", "tag": "v", "assets": []})
    m = _mgr(tmp_path, notes=notes, zapret=SimpleNamespace(pack=SimpleNamespace(version="1.10.3")),
             tg=SimpleNamespace(core=SimpleNamespace(version="1.11.2", origin="bundled"), status="stopped"))
    m.check_errors = {"tgws": "старое"}
    m._check(quiet=False)
    assert m.error is None and m.check_errors == {}
    assert notes == [("success", "Всё актуально — обновлений нет.")]


# ------------------------------------------------------------ самообновление

def test_installed_app_waits_for_restart_and_is_not_offered_again(tmp_path, monkeypatch):
    """После установки до перезапуска обновление не «доступно», плашка и бейдж не висят, повторной
    установки нет — иначе копией для отката стала бы новая версия."""
    _frozen_exe(tmp_path, monkeypatch)
    monkeypatch.setattr(github, "download", _fake_download())
    m = _mgr(tmp_path)
    m.releases["app"] = _app_release()
    assert m.pending_keys() == ["app"]
    m._install_app()
    assert m.is_available("app") is False and m.pending_keys() == [] and m.available_count() == 0
    assert "перезапустите" in m.app_restart_text()
    item = next(i for i in m.snapshot()["items"] if i["id"] == "app")
    assert item["restart"] is True and item["available"] is False
    with pytest.raises(UpdateError, match="перезапустите"):
        m.install_async("app")


def test_install_app_refuses_older_or_foreign_file(tmp_path, monkeypatch):
    _frozen_exe(tmp_path, monkeypatch)
    monkeypatch.setattr(github, "download", _fake_download())
    m = _mgr(tmp_path)
    m.releases["app"] = _app_release(version=__version__)
    with pytest.raises(UpdateError, match="не новее"):
        m._install_app()
    rel = _app_release()
    rel["assets"][0]["url"] = "https://evil.example.com/Lazeyka.exe"
    m.releases["app"] = rel
    with pytest.raises(UpdateError, match="не в релизах"):
        m._install_app()


def test_zapret_archive_must_come_from_its_releases(tmp_path):
    m = _mgr(tmp_path)
    m.releases["zapret"] = {"version": "1.10.4", "assets": [
        {"name": "zapret-discord-youtube-1.10.4.zip", "url": "https://evil.example.com/z-1.10.4.zip",
         "sha256": "ab" * 32}]}
    with pytest.raises(UpdateError, match="не в релизах"):
        m._install_zapret()


def test_backup_is_recorded_before_exe_is_moved(tmp_path, monkeypatch):
    """Настройки не сохранились — обновление не начинается: иначе уборка при следующем запуске удалила
    бы незаписанную копию прежней версии."""
    exe = _frozen_exe(tmp_path, monkeypatch)
    monkeypatch.setattr(github, "download", _fake_download())
    m = _mgr(tmp_path)
    m.releases["app"] = _app_release()
    monkeypatch.setattr(m.settings, "save", lambda: False)
    with pytest.raises(UpdateError, match="обновление не начато"):
        m._install_app()
    assert exe.read_bytes() == b"OLD" and not list(tmp_path.glob("*.old"))
    assert m.settings.get("updates", "app_backup") is None


def test_self_update_refreshes_autostart_copy(tmp_path, monkeypatch):
    """Обновилась Лазейка из «Загрузок» — копия для автозапуска в Program Files тоже новая, с version.txt."""
    _frozen_exe(tmp_path / "Downloads", monkeypatch)
    copy = autostart.installed_exe()
    copy.parent.mkdir(parents=True)
    copy.write_bytes(b"OLD-COPY")
    autostart.write_version(__version__)
    monkeypatch.setattr(github, "download", _fake_download(b"NEW"))
    m = _mgr(tmp_path)
    m.releases["app"] = _app_release()
    m._install_app()
    assert copy.read_bytes() == b"NEW" and autostart.installed_version() == "99.0.0"


def test_autostart_copy_is_inside_the_block_exit_waits_for(tmp_path, monkeypatch):
    """Копия для автозапуска при обновлении и откате пишется внутри блока замены файлов: выход посреди неё
    оставил бы недописанный exe в Program Files."""
    exe = _frozen_exe(tmp_path / "Downloads", monkeypatch)
    monkeypatch.setattr(github, "download", _fake_download(b"NEW"))
    m = _mgr(tmp_path)
    m.releases["app"] = _app_release()
    inside = []
    monkeypatch.setattr(autostart, "update_copy",
                        lambda source, version, downgrade=False: inside.append(m._critical.locked()) or True)
    m._install_app()
    backup = tmp_path / "backups" / "Lazeyka-previous.exe"
    backup.parent.mkdir()
    backup.write_bytes(b"PREV")
    m.settings.update(lambda d: d["updates"].update({"app_backup": str(backup), "app_backup_for": str(exe),
                                                      "app_backup_version": "1.2.1"}))
    m._rollback_app()
    assert inside == [True, True]


def test_self_update_of_program_files_copy_writes_version(tmp_path, monkeypatch):
    """Обновилась сама копия в Program Files — version.txt о новой версии: старый exe из «Загрузок»
    не затрёт её при следующем запуске."""
    copy = autostart.installed_exe()
    _frozen_exe(copy.parent, monkeypatch, name=copy.name)
    autostart.write_version(__version__)
    monkeypatch.setattr(github, "download", _fake_download(b"NEW"))
    m = _mgr(tmp_path)
    m.releases["app"] = _app_release()
    m._install_app()
    assert copy.read_bytes() == b"NEW" and autostart.installed_version() == "99.0.0"


def test_backup_of_another_exe_is_not_offered(tmp_path, monkeypatch):
    """Копия для отката другой Лазейки (Program Files и «Загрузки» делят папку данных) — не наша."""
    _frozen_exe(tmp_path / "pf", monkeypatch)
    other = tmp_path / "dl" / "Lazeyka.exe.old"
    other.parent.mkdir()
    other.write_bytes(b"PREV")
    m = _mgr(tmp_path)
    m.settings.update(lambda d: d["updates"].update({"app_backup": str(other),
                                                      "app_backup_for": str(tmp_path / "dl" / "Lazeyka.exe")}))
    assert m.app_backup() is None
    assert next(i for i in m.snapshot()["items"] if i["id"] == "app")["can_rollback"] is False
    with pytest.raises(UpdateError, match="Нет сохранённой"):
        m._rollback_app()
    settle_app_files(m.settings)
    assert other.read_bytes() == b"PREV", "уборка чужую копию не трогает"


def test_app_rollback_restores_version_and_autostart_copy(tmp_path, monkeypatch):
    exe = _frozen_exe(tmp_path / "dl", monkeypatch, b"NEW")
    backup = tmp_path / "backups" / "Lazeyka-previous.exe"
    backup.parent.mkdir()
    backup.write_bytes(b"PREV")
    copy = autostart.installed_exe()
    copy.parent.mkdir(parents=True)
    copy.write_bytes(b"NEW")
    autostart.write_version("1.9.0")
    m = _mgr(tmp_path)
    m.settings.update(lambda d: d["updates"].update({"app_backup": str(backup), "app_backup_for": str(exe),
                                                      "app_backup_version": "1.2.1"}))
    message = m._rollback_app()
    assert exe.read_bytes() == b"PREV" and "1.2.1" in message
    assert copy.read_bytes() == b"PREV" and autostart.installed_version() == "1.2.1", "откат — и для автозапуска"
    assert "перезапустите" in m.app_restart_text()


def test_settle_finds_backup_after_portable_folder_moved(tmp_path, monkeypatch):
    """Переносную папку переместили до перезапуска: копия прежней версии находится рядом с exe по имени,
    а не удаляется как незаписанный .old."""
    exe = _frozen_exe(tmp_path / "new-place", monkeypatch, b"cur")
    monkeypatch.setattr(paths, "BACKUPS_DIR", tmp_path / "data" / "backups")
    moved = exe.with_name("Lazeyka.exe.old")
    moved.write_bytes(b"backup")
    settings = Settings(tmp_path / "s.json")
    old_place = tmp_path / "old-place"
    settings.update(lambda d: d["updates"].update({"app_backup": str(old_place / "Lazeyka.exe.old"),
                                                    "app_backup_for": str(old_place / "Lazeyka.exe"),
                                                    "app_backup_version": "1.2.1"}))
    monkeypatch.setattr(paths, "is_portable", lambda: True)
    settle_app_files(settings)
    target = paths.BACKUPS_DIR / um.APP_BACKUP_NAME
    assert target.read_bytes() == b"backup" and settings.get("updates", "app_backup") == str(target)
    assert settings.get("updates", "app_backup_for") == str(exe)


def test_settle_never_breaks_startup_on_locked_tmp(tmp_path, monkeypatch):
    """Защищённый хвост .tmp и запрет копирования — копия остаётся рядом с exe, запуск идёт дальше."""
    exe = _frozen_exe(tmp_path, monkeypatch, b"cur")
    monkeypatch.setattr(paths, "BACKUPS_DIR", tmp_path / "backups")
    old = exe.with_name("Lazeyka.exe.old")
    old.write_bytes(b"backup")
    settings = Settings(tmp_path / "s.json")
    settings.update(lambda d: d["updates"].__setitem__("app_backup", str(old)))
    real_unlink = Path.unlink

    def guarded_unlink(self, missing_ok=False):
        if self.name.endswith(".tmp"):
            raise PermissionError("отказано")
        return real_unlink(self, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", guarded_unlink)
    monkeypatch.setattr(um.shutil, "copy2", lambda *a, **k: (_ for _ in ()).throw(PermissionError("нет прав")))
    settle_app_files(settings)
    assert old.read_bytes() == b"backup"


# ------------------------------------------------------------ откат и итоги задач

def test_rollback_is_its_own_state_not_an_install(tmp_path, monkeypatch):
    notes = []
    m = _mgr(tmp_path, notes=notes)
    gate = threading.Event()
    monkeypatch.setattr(m, "_rollback_zapret", lambda: (gate.wait(5), "Стратегии zapret возвращены к версии 1.10.3")[1])
    m.rollback_async("zapret")
    assert m.progress["zapret"]["state"] == "rolling_back", "сразу видно, что идёт откат"
    assert notes == [], "итог — только когда задача закончилась"
    gate.set()
    assert _wait(lambda: m.progress["zapret"]["state"] == "rolled_back")
    assert notes == [("success", "Стратегии zapret возвращены к версии 1.10.3")]


def test_failed_job_names_the_component(tmp_path, monkeypatch):
    notes = []
    m = _mgr(tmp_path, notes=notes)
    monkeypatch.setattr(m, "_rollback_zapret", lambda: (_ for _ in ()).throw(UpdateError("Нет предыдущей версии")))
    m.rollback_async("zapret")
    assert _wait(lambda: notes)
    assert notes == [("error", "«Стратегии zapret»: откат не удался — Нет предыдущей версии")]


def test_tgws_rollback_on_bundled_core_is_refused(tmp_path):
    tg = SimpleNamespace(core=SimpleNamespace(origin="bundled", version="1.11.2"), status="running")
    m = _mgr(tmp_path, tg=tg)
    with pytest.raises(UpdateError, match="встроенное"):
        m._rollback_tgws()


def test_core_install_message_agrees_in_gender(tmp_path, monkeypatch):
    from app.vpnclient import engines
    monkeypatch.setattr(engines, "installed", lambda name, version=None: "26.3.27" if name == "xray" else "1.14.3")
    m = _mgr(tmp_path)
    m.vpnclient = SimpleNamespace(core_install=lambda name, release=None: None)
    assert m._install_core("vpnxray", update=False) == "Помощник Xray 26.3.27 установлен"
    assert m._install_core("vpncore", update=False) == "Ядро VPN (sing-box) 1.14.3 установлено"


# ------------------------------------------------------------ zapret: неудачный старт нового пакета

class _SwitchingZapret:
    def __init__(self, current, fail_on):
        self.pack, self.fail_on, self.was_on = current, fail_on, True
        self.calls = []

    def running(self):
        return self.was_on

    def switch_pack(self, info):
        self.calls.append(("switch", info.version))
        self.was_on = False
        self.pack = info
        if info.version == self.fail_on:
            raise RuntimeError("winws не запустился")
        self.was_on = True

    def start(self):
        self.calls.append(("start", self.pack.version))
        self.was_on = True


def test_zapret_update_that_does_not_start_brings_back_previous(tmp_path):
    old = pack.PackInfo("1.10.3", "bundled", "", None, 0.0, "x")
    new = pack.PackInfo("1.10.4", "github", "", None, 0.0, "y")
    zapret = _SwitchingZapret(new, fail_on="1.10.4")     # новый пакет уже активен, winws на нём не встал
    zapret.was_on = False
    m = _mgr(tmp_path, zapret=zapret)
    error = m._restore_zapret(old, True, new, RuntimeError("winws не запустился"))
    assert zapret.calls == [("switch", "1.10.3")] and zapret.pack.version == "1.10.3"
    assert "вернул прежнюю версию 1.10.3" in str(error)
    zapret.was_on = False                         # прежний пакет активирован, но обход не поднялся сам
    zapret.switch_pack = lambda info: setattr(zapret, "pack", info)
    zapret.pack = new
    m._restore_zapret(old, True, new, RuntimeError("x"))
    assert ("start", "1.10.3") in zapret.calls, "обход работал до обновления — работает и после отката"


def test_zapret_install_path_restores_on_switch_failure(tmp_path, monkeypatch):
    old = pack.PackInfo("1.10.3", "bundled", "", None, 0.0, "x")
    new = pack.PackInfo("1.10.4", "github", "", None, 0.0, "y")
    zapret = _SwitchingZapret(old, fail_on="1.10.4")
    m = _mgr(tmp_path, zapret=zapret)
    m.releases["zapret"] = {"version": "1.10.4", "assets": [
        {"name": "zapret-discord-youtube-1.10.4.zip", "sha256": "ab" * 32,
         "url": "https://github.com/Flowseal/zapret-discord-youtube/releases/download/1.10.4/z-1.10.4.zip"}]}
    monkeypatch.setattr(github, "download", _fake_download(b"zip"))
    monkeypatch.setattr(pack, "install_zip", lambda *a, **k: new)
    monkeypatch.setattr(pack, "cleanup", lambda keep: pytest.fail("неудачная установка ничего не убирает"))
    with pytest.raises(UpdateError, match="вернул прежнюю версию 1.10.3"):
        m._install_zapret()
    assert zapret.pack.version == "1.10.3"


# ------------------------------------------------------------ ядро Telegram-прокси

@pytest.mark.parametrize("bad", ["proxy/..\\..\\..\\escaped.py", "proxy/../x.py", "proxy/C:/x.py", "proxy//x.py",
                                 "proxy/./x.py", "other/x.py"])
def test_tgws_paths_cannot_escape_package(tmp_path, bad):
    with pytest.raises(UpdateError, match="Небезопасный путь"):
        um.tgws_target(tmp_path / "pkg", bad)


def test_tgws_target_inside_package(tmp_path):
    assert um.tgws_target(tmp_path / "pkg", "proxy/sub/mod.py") == tmp_path / "pkg" / "sub" / "mod.py"


def test_tgws_install_rejects_backslash_entry_before_writing(tmp_path, monkeypatch):
    m = _mgr(tmp_path)
    m.releases["tgws"] = {"tag": "v9.9.9", "version": "9.9.9"}
    data = b"x = 1\n"
    monkeypatch.setattr(github, "tree", lambda repo, tag, **kw: [
        {"type": "blob", "path": "proxy/tg_ws_proxy.py", "sha": github.git_blob_sha1(data)},
        {"type": "blob", "path": "proxy/..\\..\\..\\escaped.py", "sha": github.git_blob_sha1(data)}])
    monkeypatch.setattr(github, "raw_file", lambda repo, tag, path, **kw: data)
    with pytest.raises(UpdateError, match="Небезопасный путь"):
        m._install_tgws()
    assert not list(paths.DATA.rglob("escaped.py")) and not list(tmp_path.rglob("escaped.py"))


class _FakeTgManager:
    """Менеджер прокси: ядро и состояние, без настоящего запуска."""

    def __init__(self, core, status, failing_versions=()):
        self.core, self.status, self.failing = core, status, set(failing_versions)
        self.calls = []

    def switch_core(self, core, *, fallback=True):
        self.calls.append(("switch", core.version, fallback))
        was = self.status in ("running", "starting")
        self.core = core
        if was:
            self.start()

    def start(self, *, fallback=True):
        self.calls.append(("start", self.core.version))
        if self.core.version in self.failing:
            self.status = "error"
            raise RuntimeError("ядро упало")
        self.status = "running"


def _core(version, origin="updated"):
    return SimpleNamespace(version=version, origin=origin)


def test_tgws_failed_core_returns_previous_downloaded_core_and_restarts(tmp_path):
    """Не встроенное, а то, что работало до обновления, — и прокси снова включён."""
    previous = _core("1.11.3")
    tg = _FakeTgManager(previous, "running", failing_versions={"1.11.4"})
    m = _mgr(tmp_path, tg=tg)
    m.settings.update(lambda d: d["tg"].__setitem__("core", "1.11.3"))
    final = paths.TGWS_COMPONENTS_DIR / "1.11.4"
    final.mkdir(parents=True, exist_ok=True)
    with pytest.raises(UpdateError, match="работает прежнее 1.11.3"):
        m._switch_tgws(_core("1.11.4"), final)
    assert tg.core is previous and tg.status == "running"
    assert m.settings.get("tg", "core") == "1.11.3" and not final.exists()


def test_tgws_new_core_is_tried_when_proxy_is_off(tmp_path, monkeypatch):
    """Прокси выключен — новое ядро пробуется на свободном порту; не поднялось — установка не состоялась,
    при следующем включении работает прежнее ядро."""
    previous = _core("1.11.2", origin="bundled")
    tg = _FakeTgManager(previous, "stopped")
    m = _mgr(tmp_path, tg=tg)
    tried = []
    monkeypatch.setattr(UpdateManager, "_trial_start",
                        staticmethod(lambda core: tried.append(core.version) or (_ for _ in ()).throw(
                            RuntimeError("не слушает порт"))))
    final = paths.TGWS_COMPONENTS_DIR / "1.11.5"
    final.mkdir(parents=True, exist_ok=True)
    with pytest.raises(UpdateError, match="не слушает порт"):
        m._switch_tgws(_core("1.11.5"), final)
    assert tried == ["1.11.5"] and tg.core is previous and tg.status == "stopped"
    assert m.settings.get("tg", "core") == "bundled"


def test_tgws_success_keeps_new_core(tmp_path, monkeypatch):
    tg = _FakeTgManager(_core("1.11.2", origin="bundled"), "stopped")
    m = _mgr(tmp_path, tg=tg)
    monkeypatch.setattr(UpdateManager, "_trial_start", staticmethod(lambda core: None))
    final = paths.TGWS_COMPONENTS_DIR / "1.11.6"
    final.mkdir(parents=True, exist_ok=True)
    m._switch_tgws(_core("1.11.6"), final)
    assert tg.core.version == "1.11.6" and m.settings.get("tg", "core") == "1.11.6"
    assert ("switch", "1.11.6", False) in tg.calls, "при установке встроенное втихую не подставляется"


# ------------------------------------------------------------ выход во время установки

def test_shutdown_waits_for_file_replacement_and_cancels_downloads(tmp_path):
    m = _mgr(tmp_path)
    inside, release, done = threading.Event(), threading.Event(), []

    def replacing():
        with m.replacing():
            inside.set()
            release.wait(5)
            done.append("заменено")

    worker = threading.Thread(target=replacing)
    worker.start()
    assert inside.wait(5)
    stopper = threading.Thread(target=m.shutdown, args=(5.0,))
    stopper.start()
    time.sleep(0.2)
    assert stopper.is_alive(), "выход ждёт конца замены файлов"
    release.set()
    stopper.join(5)
    worker.join(5)
    assert done == ["заменено"] and not stopper.is_alive()
    with pytest.raises(UpdateError, match="закрывается"):
        with m.replacing():
            pass
    with pytest.raises(UpdateError, match="закрывается"):
        m.install_async("zapret")


def test_cancelled_download_stops(tmp_path):
    cancel = threading.Event()
    cancel.set()
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)

    def serve():
        conn, _ = server.accept()
        conn.recv(65536)
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndata")
        conn.close()
        server.close()

    threading.Thread(target=serve, daemon=True).start()
    target = tmp_path / "f.bin"
    with pytest.raises(github.GitHubError, match="отменена"):
        github.download(f"http://127.0.0.1:{server.getsockname()[1]}/", target, None, timeout=5, cancel=cancel)
    assert not target.exists()
