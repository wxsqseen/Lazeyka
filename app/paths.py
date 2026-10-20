"""Где приложение хранит свои файлы.

Всё состояние лежит в одном корне. По умолчанию это ``%ProgramData%\\Lazeyka``:
путь без кириллицы и пробелов (winws и WinDivert к этому чувствительны), а писать
туда может только администратор. Последнее важно: приложение запускает оттуда
winws.exe с правами администратора, и папка, доступная на запись обычным
процессам, превратилась бы в способ повысить права.

Портативный режим включается папкой ``LazeykaData`` рядом с exe.
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

from . import APP_ID

PORTABLE_DIR_NAME = "LazeykaData"

IS_FROZEN = bool(getattr(sys, "frozen", False))


def exe_path() -> Path:
    """Путь, который нужно запускать, чтобы стартовало это приложение."""
    if IS_FROZEN:
        return Path(sys.executable).resolve()
    return Path(sys.argv[0]).resolve()


def launch_command() -> list[str]:
    """Команда запуска текущей сборки (для автозапуска и перезапуска)."""
    if IS_FROZEN:
        return [str(exe_path())]
    return [sys.executable, "-m", "app"]


def resource_dir() -> Path:
    """Каталог с ресурсами сборки (ui, встроенный пакет zapret)."""
    if IS_FROZEN:
        return Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))
    return Path(__file__).resolve().parent.parent


def ui_dir() -> Path:
    # В сборке PyInstaller раскладка та же: <_MEIPASS>/app/ui и <_MEIPASS>/vendor/zapret.
    return resource_dir() / "app" / "ui"


def bundled_zapret_dir() -> Path:
    return resource_dir() / "vendor" / "zapret"


def _portable_root() -> Path | None:
    candidate = exe_path().parent / PORTABLE_DIR_NAME
    return candidate if candidate.is_dir() else None


def data_root() -> Path:
    # LAZEYKA_DATA — только для тестов из исходников: в сборке переменную окружения
    # мог бы подставить кто угодно и подменить папку, откуда запускается winws.
    override = os.environ.get("LAZEYKA_DATA")
    if override and not IS_FROZEN:
        return Path(override)
    portable = _portable_root()
    if portable is not None:
        return portable
    from .winutil import FOLDERID_PROGRAM_DATA, known_folder
    try:
        base = known_folder(FOLDERID_PROGRAM_DATA)
    except OSError:
        base = r"C:\ProgramData"
    return Path(base) / APP_ID


def test_data_override() -> bool:
    return bool(os.environ.get("LAZEYKA_DATA")) and not IS_FROZEN


def is_portable() -> bool:
    """Переносной режим: данные в папке ``LazeykaData`` рядом с exe. Её родителем может
    владеть обычный пользователь, поэтому исключать такую папку из антивируса небезопасно."""
    return _portable_root() is not None


DATA = data_root()
SETTINGS_FILE = DATA / "settings.json"
ZAPRET_DIR = DATA / "zapret"
PACKS_DIR = ZAPRET_DIR / "packs"
USER_LISTS_DIR = ZAPRET_DIR / "user"
COMPONENTS_DIR = DATA / "components"
TGWS_COMPONENTS_DIR = COMPONENTS_DIR / "tgws"
BACKUPS_DIR = DATA / "backups"
TMP_DIR = DATA / "tmp"
TEST_RESULTS_DIR = DATA / "test-results"
# Свой VPN: ключи и подписки — в папке, закрытой на чтение для обычных пользователей
# (security.secure_private_dir); ядра — в components/<ядро>/<версия>.
VPNCLIENT_DIR = DATA / "vpnclient"
VPNCLIENT_RULES_DIR = VPNCLIENT_DIR / "rules"
PROFILES_FILE = VPNCLIENT_DIR / "profiles.json"
# Резервная копия системного прокси — вне закрытой папки: секретов в ней нет, а вернуть
# прокси после аварии нужно уметь и без прав администратора.
SYSPROXY_BACKUP_FILE = DATA / "sysproxy-backup.json"
SINGBOX_COMPONENTS_DIR = COMPONENTS_DIR / "sing-box"
XRAY_COMPONENTS_DIR = COMPONENTS_DIR / "xray"


def _writable(directory: Path) -> bool:
    try:
        directory.mkdir(parents=True, exist_ok=True)
        probe = directory / f".probe-{os.getpid()}"
        probe.write_bytes(b"")
        probe.unlink()
        return True
    except OSError:
        return False


def logs_dir(allow_create_data: bool) -> Path:
    """Журналы пишем в DATA, а без прав администратора — во временную папку.

    Без прав DATA не создаём: иначе её владельцем стал бы обычный пользователь.
    """
    primary = DATA / "logs"
    if (allow_create_data or DATA.is_dir()) and _writable(primary):
        return primary
    fallback = Path(tempfile.gettempdir()) / f"{APP_ID}-logs"
    fallback.mkdir(parents=True, exist_ok=True)
    return fallback


def has_non_ascii(path: Path) -> bool:
    return any(ord(ch) > 127 for ch in str(path))
