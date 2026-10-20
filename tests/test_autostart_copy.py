"""Копия для автозапуска в Program Files (в тестах — временная папка, см. conftest): version.txt,
обновление и откат, отказ в переносном режиме и под чужой учётной записью, задание от 1.2, выход посреди
копирования. Планировщик не трогается: schtasks подменён."""
import contextlib
import threading
import time
from types import SimpleNamespace

import pytest

from app import __version__, autostart, paths, winutil


def _frozen(monkeypatch, exe):
    monkeypatch.setattr(paths, "IS_FROZEN", True)
    monkeypatch.setattr(paths, "exe_path", lambda: exe)


def test_running_copy_keeps_version_file_current(monkeypatch):
    """Запущена сама копия (в том числе после самообновления) — version.txt о ней: иначе старый exe из
    «Загрузок» счёл бы её старее и затёр."""
    copy = autostart.installed_exe()
    copy.parent.mkdir(parents=True)
    copy.write_bytes(b"exe")
    autostart.write_version("1.0.0")
    _frozen(monkeypatch, copy)
    assert autostart.install_copy() == [str(copy)]
    assert autostart.installed_version() == __version__


def test_update_copy_places_file_and_respects_newer(tmp_path):
    source = tmp_path / "new.exe"
    source.write_bytes(b"NEW")
    assert autostart.update_copy(source, "99.0.0") is False, "копии нет — автозапуск не включали"
    copy = autostart.installed_exe()
    copy.parent.mkdir(parents=True)
    copy.write_bytes(b"OLD")
    autostart.write_version("1.0.0")
    assert autostart.update_copy(source, "99.0.0") is True
    assert copy.read_bytes() == b"NEW" and autostart.installed_version() == "99.0.0"
    older = tmp_path / "old.exe"
    older.write_bytes(b"OLDER")
    assert autostart.update_copy(older, "1.0.0") is False and copy.read_bytes() == b"NEW"
    assert autostart.update_copy(older, "1.0.0", downgrade=True) is True and copy.read_bytes() == b"OLDER"
    assert not list(copy.parent.glob("*.new")), "временной копии не осталось"


@pytest.mark.parametrize("portable, other, text", [(True, False, "переносном режиме"),
                                                   (False, True, "другой учётной записи")])
def test_enable_refuses_with_reason(monkeypatch, portable, other, text):
    monkeypatch.setattr(paths, "is_portable", lambda: portable)
    monkeypatch.setattr(winutil, "other_account", lambda: other)
    monkeypatch.setattr(autostart, "_schtasks", lambda *a: pytest.fail("Планировщик не трогается"))
    with pytest.raises(autostart.AutostartError, match=text):
        autostart.enable()
    assert text in autostart.refusal()


def test_sync_does_nothing_in_portable_mode(monkeypatch, tmp_path):
    _frozen(monkeypatch, tmp_path / "Lazeyka.exe")
    monkeypatch.setattr(paths, "is_portable", lambda: True)
    monkeypatch.setattr(autostart, "install_copy", lambda guard=None: pytest.fail("копия в Program Files не нужна"))
    autostart.sync()


# ------------------------------------------------------------ задание, оставшееся от 1.2 в переносном режиме

class _Tasks:
    """Подделка schtasks: какие задания есть и что с ними делали."""

    def __init__(self, *names):
        self.names = set(names)
        self.deleted = []

    def __call__(self, *args):
        verb, name = args[0], args[2]
        if verb == "/Delete":
            self.names.discard(name)
            self.deleted.append(name)
            return winutil.RunResult(0, "", "")
        return winutil.RunResult(0 if name in self.names else 1, "", "")


def _program_files_copy(monkeypatch, tmp_path, settings_text):
    copy = autostart.installed_exe()
    copy.parent.mkdir(parents=True)
    copy.write_bytes(b"exe")
    _frozen(monkeypatch, copy)
    monkeypatch.setattr(paths, "is_portable", lambda: False)
    settings_file = tmp_path / "ProgramData" / "settings.json"
    settings_file.parent.mkdir()
    if settings_text is not None:
        settings_file.write_text(settings_text, encoding="utf-8")
    monkeypatch.setattr(paths, "SETTINGS_FILE", settings_file)
    return copy


@pytest.mark.parametrize("settings_text, stray", [
    (None, True),                                         # переносная 1.2 — в ProgramData настроек нет
    ('{"startup": {"autostart": false}}', True),
    ('{"startup": {"autostart": true}}', False),          # обычная установка с автозапуском
    ("{обрыв", False),                                    # не прочитались — не решаем
])
def test_copy_started_by_someone_elses_task_steps_aside(monkeypatch, tmp_path, settings_text, stray):
    """1.2 в переносном режиме ставила задание на копию в Program Files: после входа в Windows открывалась
    «чужая» Лазейка с данными ProgramData, а переносная лишь показывала её окно. Копия, у которой в
    настройках автозапуск выключен, снимает задание и не запускается."""
    _program_files_copy(monkeypatch, tmp_path, settings_text)
    assert autostart.stray_launch() is stray


def test_stray_check_is_only_for_the_program_files_copy(monkeypatch, tmp_path):
    _program_files_copy(monkeypatch, tmp_path, None)
    monkeypatch.setattr(paths, "is_portable", lambda: True)
    assert autostart.stray_launch() is False, "переносная сама решает по своей плашке"
    monkeypatch.setattr(paths, "is_portable", lambda: False)
    _frozen(monkeypatch, tmp_path / "Downloads" / "Lazeyka.exe")
    assert autostart.stray_launch() is False, "exe из «Загрузок» задание не запускает"


def test_stray_task_is_retired(monkeypatch):
    tasks = _Tasks(autostart.TASK_NAME)
    monkeypatch.setattr(autostart, "_schtasks", tasks)
    autostart.retire_stray_task()
    assert tasks.deleted == [autostart.TASK_NAME] and not tasks.names


def test_stray_task_that_cannot_be_retired_does_not_crash(monkeypatch):
    def refuse(*args):
        return winutil.RunResult(1 if args[0] == "/Delete" else 0, "", "Отказано в доступе")

    monkeypatch.setattr(autostart, "_schtasks", refuse)
    autostart.retire_stray_task()


# ------------------------------------------------------------ копирование и выход

def test_copy_runs_inside_guard_under_a_name_the_cleanup_knows(monkeypatch, tmp_path):
    """Временная копия называлась Lazeyka.<hex>.new и писалась вне блока, которого ждёт выход: выход
    посреди копирования оставлял ~40 МБ в Program Files навсегда."""
    source = tmp_path / "new.exe"
    source.write_bytes(b"NEW")
    target = autostart.installed_exe()
    events = []

    @contextlib.contextmanager
    def guard():
        events.append("вход")
        yield
        events.append("выход")

    real_copy = autostart.shutil.copyfile

    def copy(src, dst):
        events.append("копия")
        real_copy(src, dst)
        assert dst in autostart.staging_leftovers(), "уборка нашла бы недописанную копию"

    monkeypatch.setattr(autostart.shutil, "copyfile", copy)
    autostart._place(source, target, "9.9.9", guard)
    assert events == ["вход", "копия", "выход"] and target.read_bytes() == b"NEW"
    assert autostart.staging_leftovers() == []


def test_exit_waits_for_autostart_copy(monkeypatch, tmp_path):
    from app.settings import Settings
    from app.updates.manager import UpdateManager
    m = UpdateManager(Settings(tmp_path / "s.json"), SimpleNamespace(pack=None), SimpleNamespace(core=None),
                      lambda *a: None, is_admin=True)
    source = tmp_path / "new.exe"
    source.write_bytes(b"NEW")
    copying, release = threading.Event(), threading.Event()
    real_copy = autostart.shutil.copyfile

    def slow_copy(src, dst):
        copying.set()
        release.wait(5)
        return real_copy(src, dst)

    monkeypatch.setattr(autostart.shutil, "copyfile", slow_copy)
    worker = threading.Thread(target=autostart._place, args=(source, autostart.installed_exe(), "9.9.9", m.replacing))
    worker.start()
    assert copying.wait(5)
    stopper = threading.Thread(target=m.shutdown, args=(5.0,))
    stopper.start()
    time.sleep(0.2)
    assert stopper.is_alive(), "выход ждёт конца копирования"
    release.set()
    stopper.join(5)
    worker.join(5)
    assert not stopper.is_alive() and autostart.installed_exe().read_bytes() == b"NEW"
    assert autostart.staging_leftovers() == []


def test_startup_cleanup_removes_unfinished_autostart_copies(monkeypatch, tmp_path):
    """Уборка при запуске знает оба имени временной копии (до 1.3.1 — Lazeyka.<hex>.new) и смотрит в
    Program Files, даже когда запущен exe из «Загрузок»; .old копии (её откат) не трогает."""
    from app.settings import Settings
    from app.updates.manager import settle_app_files
    folder = autostart.installed_exe().parent
    folder.mkdir(parents=True)
    leftovers = [folder / ".Lazeyka-1a2b3c4d.new", folder / "Lazeyka.1a2b3c4d.new"]
    for path in leftovers:
        path.write_bytes(b"half")
    kept = folder / "Lazeyka.exe.old"
    kept.write_bytes(b"rollback")
    downloads = tmp_path / "Downloads" / "Lazeyka.exe"
    downloads.parent.mkdir()
    downloads.write_bytes(b"exe")
    _frozen(monkeypatch, downloads)
    settle_app_files(Settings(tmp_path / "s.json"))
    assert not any(p.exists() for p in leftovers) and kept.read_bytes() == b"rollback"
