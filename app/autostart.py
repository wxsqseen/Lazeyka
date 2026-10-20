"""Автозапуск через Планировщик заданий.

Ключ Run в реестре не подходит: приложению с правами администратора Windows
при входе показала бы запрос UAC (или вовсе не запустила бы его). Задание с
наивысшими правами стартует сразу, без запроса.

Такое задание запускает exe с правами администратора без вопросов, поэтому
оно указывает только на копию в Program Files: туда может писать лишь
администратор. Запуск exe из «Загрузок» или с рабочего стола позволил бы любой
программе подменить файл и получить права при следующем входе в Windows.
"""
from __future__ import annotations

import getpass
import logging
import os
import shutil
import subprocess
import uuid
from contextlib import nullcontext
from pathlib import Path
from typing import Callable, ContextManager
from xml.sax.saxutils import escape

from . import APP_ID, __version__, paths, winutil
from .settings import read_saved

log = logging.getLogger("lazeyka.autostart")

LEGACY_TASK_NAME = APP_ID
AUTOSTART_ARG = "--autostart"
VERSION_FILE = "version.txt"

# Почему автозапуск не включается — текст для человека (ответ на нажатие и плашка при запуске).
PORTABLE_REFUSAL = ("В переносном режиме автозапуск не работает: Windows запускала бы копию из Program Files, а "
                    "она хранит настройки не в папке LazeykaData рядом с exe, а в ProgramData — после входа "
                    "в Windows открылась бы «чистая» Лазейка. Запускайте Лазейку вручную или поставьте её "
                    "в обычном режиме (без папки LazeykaData рядом с exe).")
OTHER_ACCOUNT_REFUSAL = ("Лазейка запущена от имени другой учётной записи Windows (так бывает, когда при запуске "
                         "вводят пароль администратора). Автозапуск сработал бы при входе той учётной записи, "
                         "а не вашей, поэтому он не включён.")


class AutostartError(RuntimeError):
    pass


def refusal() -> str | None:
    """Почему автозапуск здесь включать нельзя; None — можно."""
    if paths.is_portable():
        return PORTABLE_REFUSAL
    if winutil.other_account():
        return OTHER_ACCOUNT_REFUSAL
    return None


def _current_user() -> str:
    domain = os.environ.get("USERDOMAIN")
    user = os.environ.get("USERNAME") or getpass.getuser()
    return f"{domain}\\{user}" if domain else user


def _task_name() -> str:
    """Своё задание у каждого пользователя Windows: иначе второй затёр бы автозапуск первого."""
    user = os.environ.get("USERNAME") or getpass.getuser()
    safe = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in user)[:40] or "user"
    return f"{APP_ID}-{safe}"


TASK_NAME = _task_name()


def installed_exe() -> Path:
    base = winutil.known_folder(winutil.FOLDERID_PROGRAM_FILES)
    return Path(base) / APP_ID / f"{APP_ID}.exe"


def installed_version() -> str | None:
    try:
        return (installed_exe().parent / VERSION_FILE).read_text(encoding="ascii").strip() or None
    except OSError:
        return None


def write_version(version: str) -> None:
    """version.txt рядом с копией: по нему старый exe из «Загрузок» не затрёт более новую копию."""
    (installed_exe().parent / VERSION_FILE).write_text(version, encoding="ascii")


def _same_path(a: Path | str, b: Path | str) -> bool:
    return os.path.normcase(os.path.abspath(a)) == os.path.normcase(os.path.abspath(b))


def staging_leftovers() -> list[Path]:
    """Временные копии в Program Files, оставшиеся от прерванного копирования (выход Windows посреди него);
    второе имя — у копий до 1.3.1. Убирает их уборка при запуске (updates.manager.settle_app_files)."""
    folder = installed_exe().parent
    try:
        return [*folder.glob(f".{APP_ID}-*.new"), *folder.glob(f"{APP_ID}.*.new")]
    except OSError as exc:
        log.debug("Временные копии для автозапуска не найдены: %r", exc)
        return []


def _place(source: Path, target: Path, version: str, guard: Callable[[], ContextManager] = nullcontext) -> None:
    """Копия рядом с целью и замена одним переименованием: задание не застанет exe наполовину. Имя
    временной копии — как у самообновления, её подбирает та же уборка. guard — блок замены файлов
    (UpdateManager.replacing): выход Лазейки дожидается конца копирования, иначе недописанные ~40 МБ
    остались бы в Program Files."""
    target.parent.mkdir(parents=True, exist_ok=True)
    staging = target.with_name(f".{target.stem}-{uuid.uuid4().hex[:8]}.new")
    with guard():
        try:
            shutil.copyfile(source, staging)
            os.replace(staging, target)
        finally:
            staging.unlink(missing_ok=True)
        write_version(version)
    log.info("Копия для автозапуска — версия %s: %s", version, target)


def install_copy(guard: Callable[[], ContextManager] = nullcontext) -> list[str]:
    """Кладёт копию текущей сборки в Program Files и возвращает команду запуска. guard — как у _place.

    Более новую копию старой не затираем: если пользователь запустил старый exe
    из «Загрузок», автозапуск продолжит запускать новую версию.
    """
    if not paths.IS_FROZEN:
        return paths.launch_command()  # запуск из исходников — для разработки
    from .filehash import sha256_file
    from .zapret.pack import version_key

    source = paths.exe_path()
    target = installed_exe()
    have = installed_version()
    if _same_path(source, target):
        # Запущена сама копия (в том числе после самообновления): version.txt — о ней.
        if have != __version__:
            write_version(__version__)
        return [str(target)]
    if target.exists() and have and version_key(have) > version_key(__version__):
        log.info("В Program Files лежит более новая Лазейка %s — оставляю её", have)
        return [str(target)]
    if not target.exists() or sha256_file(source) != sha256_file(target):
        _place(source, target, __version__, guard)
    elif have != __version__:
        write_version(__version__)
    return [str(target)]


def update_copy(source: Path, version: str, *, downgrade: bool = False) -> bool:
    """Самообновление и откат: копия для автозапуска получает тот же (уже проверенный) exe, иначе при
    входе в Windows запускалась бы прежняя версия. Копии нет — нечего обновлять. Более новую копию
    без downgrade (откат) не трогаем. Возвращает, обновлена ли копия. Вызывается уже внутри блока
    замены файлов (UpdateManager.replacing): выход дожидается и этой копии."""
    from .zapret.pack import version_key
    target = installed_exe()
    if not target.exists():
        return False
    have = installed_version()
    if have and not downgrade and version_key(have) > version_key(version):
        log.info("В Program Files лежит более новая Лазейка %s — оставляю её", have)
        return False
    _place(Path(source), target, version)
    return True


def _task_xml(command: list[str]) -> str:
    exe = command[0]
    args = subprocess.list2cmdline(command[1:] + [AUTOSTART_ARG])
    user = escape(_current_user())
    workdir = Path(exe).parent if paths.IS_FROZEN else paths.resource_dir()
    return f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Запуск «Лазейки» при входе в Windows</Description>
    <URI>\\{TASK_NAME}</URI>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>{user}</UserId>
      <Delay>PT5S</Delay>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{user}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{escape(exe)}</Command>
      <Arguments>{escape(args)}</Arguments>
      <WorkingDirectory>{escape(str(workdir))}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"""


def _schtasks(*args: str) -> winutil.RunResult:
    return winutil.run([winutil.system32("schtasks.exe"), *args], timeout=20)


def is_enabled() -> bool:
    return _schtasks("/Query", "/TN", TASK_NAME).code == 0


def _legacy_task_is_mine() -> bool:
    """Общее задание «Lazeyka» из первой версии — переносим, если оно этого пользователя."""
    res = _schtasks("/Query", "/TN", LEGACY_TASK_NAME, "/XML")
    if res.code != 0:
        return False
    return f"<UserId>{_current_user()}</UserId>".lower() in res.out.lower()


def _remove_legacy_task() -> None:
    if _legacy_task_is_mine():
        _schtasks("/Delete", "/TN", LEGACY_TASK_NAME, "/F")
        log.info("Старое общее задание автозапуска заменено личным")


def registered_command() -> str | None:
    res = _schtasks("/Query", "/TN", TASK_NAME, "/XML")
    if res.code != 0:
        return None
    start = res.out.find("<Command>")
    end = res.out.find("</Command>")
    return res.out[start + 9:end].strip() if start >= 0 and end > start else None


def enable(guard: Callable[[], ContextManager] = nullcontext) -> Path:
    """Копия в Program Files (guard — как у _place) и задание на неё. Возвращает, что запускает задание."""
    problem = refusal()
    if problem:
        raise AutostartError(problem)
    command = install_copy(guard)
    xml = _task_xml(command)
    # XML кладём в защищённую папку данных: из %TEMP% его можно было бы подменить
    # между записью и чтением планировщиком.
    paths.TMP_DIR.mkdir(parents=True, exist_ok=True)
    staging = paths.TMP_DIR / f"task-{uuid.uuid4().hex[:8]}.xml"
    try:
        staging.write_bytes(xml.encode("utf-16"))
        res = _schtasks("/Create", "/TN", TASK_NAME, "/XML", str(staging), "/F")
    finally:
        staging.unlink(missing_ok=True)
    if res.code != 0:
        raise RuntimeError(f"Планировщик заданий отказал: {(res.err or res.out).strip()}")
    _remove_legacy_task()
    log.info("Автозапуск включён: %s", command[0])
    return Path(command[0])


def disable() -> None:
    _remove_legacy_task()
    if not is_enabled():
        return
    res = _schtasks("/Delete", "/TN", TASK_NAME, "/F")
    if res.code != 0:
        raise RuntimeError(f"Не удалось удалить задание: {(res.err or res.out).strip()}")
    log.info("Автозапуск выключен")


def stray_launch() -> bool:
    """Задание автозапуска запустило копию из Program Files, а в её папке данных (ProgramData) автозапуск не
    включали. Так бывает после 1.2: в переносном режиме она ставила задание на эту копию, и после входа в
    Windows открывалась «чужая» Лазейка с данными ProgramData, а переносная, запущенная следом, лишь
    показывала её окно. Снимать задание из переносной Лазейки нельзя: его могла поставить и обычная
    установка этого же пользователя. Поэтому решает сама копия, по своим настройкам: автозапуск в них
    выключен (или настроек нет вовсе) — задание не её. Настройки не прочитались — не решаем ничего."""
    if not paths.IS_FROZEN or paths.is_portable() or not _same_path(paths.exe_path(), installed_exe()):
        return False
    saved = read_saved(paths.SETTINGS_FILE)
    return saved is not None and not saved["startup"]["autostart"]


def retire_stray_task() -> None:
    """Снять задание, которое запустило копию зря (stray_launch). Копия после этого выходит: переносная
    Лазейка запустится, как прежде, а её плашка о переносном режиме предложит выключить автозапуск и там."""
    try:
        disable()
    except RuntimeError as exc:
        log.warning("Задание автозапуска, запустившее Лазейку зря, не снято: %s", exc)
        return
    log.info("Задание автозапуска запустило копию из Program Files, а в её настройках автозапуск выключен — "
             "задание снято, копия закрывается")


def sync(guard: Callable[[], ContextManager] = nullcontext) -> None:
    """При запуске: копия в Program Files соответствует текущей сборке, задание — копии. В переносном
    режиме и под чужой учёткой не делает ничего (почему — refusal(), Core покажет плашку). guard — как
    у _place."""
    if not paths.IS_FROZEN or refusal():
        return
    command = install_copy(guard)
    if (registered_command() or "").lower() != command[0].lower() or _legacy_task_is_mine():
        enable(guard)
