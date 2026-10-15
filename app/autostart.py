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
import hashlib
import logging
import os
import shutil
import subprocess
import uuid
from pathlib import Path
from xml.sax.saxutils import escape

from . import APP_ID, __version__, paths, winutil

log = logging.getLogger("lazeyka.autostart")

LEGACY_TASK_NAME = APP_ID
AUTOSTART_ARG = "--autostart"
VERSION_FILE = "version.txt"


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


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def installed_version() -> str | None:
    try:
        return (installed_exe().parent / VERSION_FILE).read_text(encoding="ascii").strip() or None
    except OSError:
        return None


def install_copy() -> list[str]:
    """Кладёт копию текущей сборки в Program Files и возвращает команду запуска.

    Более новую копию старой не затираем: если пользователь запустил старый exe
    из «Загрузок», автозапуск продолжит запускать новую версию.
    """
    if not paths.IS_FROZEN:
        return paths.launch_command()  # запуск из исходников — для разработки
    from .zapret.pack import version_key

    source = paths.exe_path()
    target = installed_exe()
    if source == target:
        return [str(target)]
    have = installed_version()
    if target.exists() and have and version_key(have) > version_key(__version__):
        log.info("В Program Files лежит более новая Лазейка %s — оставляю её", have)
        return [str(target)]
    if not target.exists() or _sha256(source) != _sha256(target):
        target.parent.mkdir(parents=True, exist_ok=True)
        staging = target.with_name(f"{target.stem}.{uuid.uuid4().hex[:8]}.new")
        shutil.copyfile(source, staging)
        os.replace(staging, target)
        (target.parent / VERSION_FILE).write_text(__version__, encoding="ascii")
        log.info("Копия для автозапуска обновлена до %s: %s", __version__, target)
    return [str(target)]


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


def enable() -> Path:
    command = install_copy()
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


def sync() -> None:
    """При запуске: копия в Program Files соответствует текущей сборке, задание — копии."""
    if not paths.IS_FROZEN:
        return
    command = install_copy()
    if (registered_command() or "").lower() != command[0].lower() or _legacy_task_is_mine():
        enable()
