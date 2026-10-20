"""Защита папки данных.

Из папки данных winws.exe запускается с правами администратора. По умолчанию
подпапки ProgramData разрешают обычным программам добавлять туда файлы — значит,
любая программа без прав могла бы подложить DLL рядом с winws.exe. Поэтому:

- без прав администратора папка данных не создаётся вовсе;
- с правами — владелец «Администраторы» и защищённый (без наследования) список
  доступа ровно из трёх записей: SYSTEM и администраторы — полный доступ,
  пользователи — чтение и запуск;
- если папкой владел не администратор, на ней нет нашей метки или права на неё (на
  папки внутри, на программы и код) на деле разрешают запись не только администраторам,
  её содержимое не доверено: права выставляются заново, всё содержимое уезжает в сторону
  (``<папка>-untrusted-<время>``, закрыта для пользователей — там ключи своего VPN), а назад
  переносятся только данные человека (настройки, профили, свои списки). Программы и код
  ставятся заново: подменить их могли как раз в это время. Пустую папку (её по README
  создаёт сам человек для переносного режима) откладывать незачем — ей просто ставятся права;
- перенос — как транзакция: ничего не удаляется, метка доверия ставится только после возврата
  данных, а незаконченный перенос (сбой, занятый файл) узнаётся по метке в отложенной папке и
  доделывается при следующем запуске;
- на диске без прав доступа (FAT32, exFAT) папку не защитить вовсе — отказ с объяснением.
"""
from __future__ import annotations

import ctypes
import fnmatch
import json
import logging
import os
import re
import shutil
import stat
import time
import uuid
from ctypes import wintypes
from dataclasses import dataclass, field
from pathlib import Path

from . import paths

log = logging.getLogger("lazeyka.security")

ADMINS = "S-1-5-32-544"
SYSTEM = "S-1-5-18"
MARKER = ".secured-v1"
# В отложенной папке: данные человека из неё ещё не вернулись назад — следующий запуск вернёт их.
PENDING_MARKER = ".restore-pending-v1"
ASIDE_SUFFIX = "-untrusted-"
# Владелец — администраторы; DACL защищён от наследования (P) и наследуется вниз (OICI).
SDDL = "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"
# Папка с секретами (ключи и подписки своего VPN): то же, но без чтения для пользователей.
PRIVATE_SDDL = "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

_advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_advapi32.GetNamedSecurityInfoW.argtypes = [
    wintypes.LPCWSTR, ctypes.c_int, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p),
    ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
    ctypes.POINTER(ctypes.c_void_p)]
_advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
_advapi32.SetNamedSecurityInfoW.argtypes = [
    wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
    ctypes.c_void_p]
_advapi32.SetNamedSecurityInfoW.restype = wintypes.DWORD
_advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
_advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
_advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
    wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.ULONG)]
_advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
_advapi32.GetSecurityDescriptorOwner.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p),
                                                 ctypes.POINTER(wintypes.BOOL)]
_advapi32.GetSecurityDescriptorOwner.restype = wintypes.BOOL
_advapi32.GetSecurityDescriptorDacl.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.BOOL),
                                                ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.BOOL)]
_advapi32.GetSecurityDescriptorDacl.restype = wintypes.BOOL
_advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
    ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(wintypes.LPWSTR), ctypes.POINTER(wintypes.ULONG)]
_advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = wintypes.BOOL
_kernel32.LocalFree.argtypes = [ctypes.c_void_p]
_kernel32.LocalFree.restype = ctypes.c_void_p
_kernel32.GetVolumePathNameW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
_kernel32.GetVolumePathNameW.restype = wintypes.BOOL
_kernel32.GetVolumeInformationW.argtypes = [
    wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
    ctypes.POINTER(wintypes.DWORD), wintypes.LPWSTR, wintypes.DWORD]
_kernel32.GetVolumeInformationW.restype = wintypes.BOOL

SE_FILE_OBJECT = 1
SDDL_REVISION_1 = 1
OWNER_SECURITY_INFORMATION = 0x1
DACL_SECURITY_INFORMATION = 0x4
PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
FILE_PERSISTENT_ACLS = 0x8

# Кому можно писать в папку данных. Остальным — только чтение и запуск.
TRUSTED_SIDS = frozenset({"SY", "BA", SYSTEM, ADMINS})
# Права, которые позволили бы подменить файл или папку: запись и дозапись, расширенные атрибуты,
# удаление (в том числе вложенного), смена прав и владельца, общие «запись»/«всё», MAXIMUM_ALLOWED.
WRITE_RIGHTS = (0x2 | 0x4 | 0x10 | 0x40 | 0x100 | 0x10000 | 0x40000 | 0x80000
                | 0x02000000 | 0x10000000 | 0x40000000)
# Буквенные права SDDL для файлов (docs.microsoft.com, «Access Rights» в SDDL).
_SDDL_RIGHTS = {
    "GA": 0x10000000, "GR": 0x80000000, "GW": 0x40000000, "GX": 0x20000000,
    "FA": 0x1F01FF, "FR": 0x120089, "FW": 0x120116, "FX": 0x1200A0,
    "RC": 0x20000, "SD": 0x10000, "WD": 0x40000, "WO": 0x80000,
    "CC": 0x1, "DC": 0x2, "LC": 0x4, "SW": 0x8, "RP": 0x10, "WP": 0x20, "DT": 0x40, "LO": 0x80, "CR": 0x100,
}
_DACL = re.compile(r"^D:([A-Z]*)((?:\([^()]*\))*)$")
# Что в папке данных исполняется с правами администратора: программы, драйвер, код ядра прокси.
CODE_SUFFIXES = (".exe", ".dll", ".sys", ".pyd", ".py")
# Данные человека, которые переносятся из недоверенной папки (это не код: их разбирают с проверкой), и как
# они называются в плашке. Остальное — программы, код, скачанные списки и журналы — ставится или копится
# заново. Резервная копия настроек нужна, когда запись прервалась между переименованиями (Settings._load).
USER_DATA = {
    "settings.json": "настройки",
    "settings.json.bak": "настройки",
    "vpnclient/profiles.json": "серверы и подписки своего VPN",
    "vpnclient/local-proxy.json": "логин и пароль локального прокси",
    "vpnclient/routing-profiles.json": "профили маршрутов",
    "vpnclient/traffic.json": "счётчик трафика",
    "sysproxy-backup.json": "резервная копия системного прокси",
    "zapret/test-in-progress.json": "метка прерванного подбора",
    "zapret/user/*.txt": "свои списки",
    "backups/hosts-*.bak": "копии файла hosts",
}
SETTINGS_DATA = ("settings.json", "settings.json.bak")   # переносятся без путей к программам
USER_DATA_LIMIT = 16 * 1024 * 1024
# Что можно оставить в недоверенной папке, не откладывая её: журналы запуска без прав администратора.
LOGS_DIR = "logs"


class DataFolderError(OSError):
    """Папку данных нельзя защитить или очистить — текст для человека."""


def owner_sid(path: Path) -> str | None:
    owner = ctypes.c_void_p()
    descriptor = ctypes.c_void_p()
    err = _advapi32.GetNamedSecurityInfoW(str(path), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION,
                                          ctypes.byref(owner), None, None, None, ctypes.byref(descriptor))
    if err != 0:
        return None
    try:
        text = wintypes.LPWSTR()
        if not _advapi32.ConvertSidToStringSidW(owner, ctypes.byref(text)):
            return None
        try:
            return text.value
        finally:
            _kernel32.LocalFree(text)
    finally:
        _kernel32.LocalFree(descriptor)


def is_link(path: Path) -> bool:
    try:
        return bool(os.lstat(path).st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)
    except OSError:
        return False


def _remove(path: Path) -> None:
    if is_link(path):
        # Ссылку удаляем саму по себе: rmdir для junction/ссылки на папку, unlink — на файл.
        try:
            os.rmdir(path)
        except OSError:
            os.unlink(path)
    elif path.is_dir():
        shutil.rmtree(path)
    else:
        path.unlink()


def _apply_protected_acl(path: Path, sddl: str = SDDL) -> None:
    descriptor = ctypes.c_void_p()
    if not _advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(descriptor), None):
        raise OSError(ctypes.get_last_error(), "ConvertStringSecurityDescriptorToSecurityDescriptorW")
    try:
        owner = ctypes.c_void_p()
        dacl = ctypes.c_void_p()
        defaulted = wintypes.BOOL()
        present = wintypes.BOOL()
        if not _advapi32.GetSecurityDescriptorOwner(descriptor, ctypes.byref(owner), ctypes.byref(defaulted)):
            raise OSError(ctypes.get_last_error(), "GetSecurityDescriptorOwner")
        if not _advapi32.GetSecurityDescriptorDacl(descriptor, ctypes.byref(present), ctypes.byref(dacl),
                                                   ctypes.byref(defaulted)):
            raise OSError(ctypes.get_last_error(), "GetSecurityDescriptorDacl")
        err = _advapi32.SetNamedSecurityInfoW(
            str(path), SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            owner, None, dacl, None)
        if err != 0:
            raise OSError(err, f"SetNamedSecurityInfoW {path}")
    finally:
        _kernel32.LocalFree(descriptor)


def secure_private_dir(path: Path) -> None:
    """Папка с секретами внутри папки данных (vpnclient/): полный доступ — SYSTEM и
    администраторам, обычные пользователи её не читают. Ядра VPN — дочерние процессы Лазейки
    с теми же правами — свои конфиги читают. Создаёт папку, если её нет; права на уже лежащие
    в ней файлы Windows переносит сама (наследование).

    В тестах (LAZEYKA_DATA) не делает ничего: там нет прав менять владельца."""
    if paths.test_data_override():
        return
    path = Path(path)
    if is_link(path):
        _remove(path)   # ссылка увела бы ключи в чужую папку
    path.mkdir(parents=True, exist_ok=True)
    _apply_protected_acl(path, PRIVATE_SDDL)


def dacl_sddl(path: Path) -> str | None:
    """Список доступа (DACL) файла или папки строкой SDDL; None — не прочитать."""
    dacl = ctypes.c_void_p()
    descriptor = ctypes.c_void_p()
    err = _advapi32.GetNamedSecurityInfoW(str(path), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
                                          None, None, ctypes.byref(dacl), None, ctypes.byref(descriptor))
    if err != 0:
        return None
    try:
        text = wintypes.LPWSTR()
        if not _advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, ctypes.byref(text), None):
            return None
        try:
            return text.value
        finally:
            _kernel32.LocalFree(text)
    finally:
        _kernel32.LocalFree(descriptor)


def _rights_mask(rights: str) -> int | None:
    if rights.lower().startswith("0x"):
        try:
            return int(rights, 16)
        except ValueError:
            return None
    if len(rights) % 2:
        return None
    mask = 0
    for index in range(0, len(rights), 2):
        bit = _SDDL_RIGHTS.get(rights[index:index + 2])
        if bit is None:
            return None            # незнакомое право — не угадываем, считаем опасным
        mask |= bit
    return mask


def dacl_problem(sddl: str, protected: bool = False) -> str | None:
    """Что не так со списком доступа: запись разрешена кому-то кроме SYSTEM и администраторов, права
    наследуются от родителя (protected=True — для корня папки данных) или список не разобрать."""
    match = _DACL.match(sddl or "")
    if match is None:
        return "список доступа не разобрать"
    flags, aces = match.groups()
    if protected and "P" not in flags:
        return "права наследуются от родительской папки"
    for ace in re.findall(r"\(([^()]*)\)", aces):
        fields = ace.split(";")
        if len(fields) < 6:
            return "список доступа не разобрать"
        ace_type, _flags, rights, sid = fields[0], fields[1], fields[2], fields[5]
        if ace_type in ("D", "OD") or sid in TRUSTED_SIDS:
            continue
        mask = _rights_mask(rights)
        if mask is None or mask & WRITE_RIGHTS:
            return f"менять содержимое может не только администратор ({sid})"
    return None


def acl_problem(path: Path, protected: bool = False) -> str | None:
    sddl = dacl_sddl(path)
    return "права не прочитать" if sddl is None else dacl_problem(sddl, protected)


def keeps_acls(path: Path) -> bool | None:
    """Хранит ли файловая система права доступа (NTFS — да, FAT32 и exFAT — нет); None — не узнать."""
    probe = Path(path)
    while not probe.exists() and probe.parent != probe:
        probe = probe.parent
    volume = ctypes.create_unicode_buffer(520)
    if not _kernel32.GetVolumePathNameW(str(probe), volume, len(volume)):
        return None
    flags = wintypes.DWORD()
    if not _kernel32.GetVolumeInformationW(volume.value, None, 0, None, None, ctypes.byref(flags), None, 0):
        return None
    return bool(flags.value & FILE_PERSISTENT_ACLS)


def _trusted_tree_problem(root: Path) -> str | None:
    """Папки и код внутри: никаких ссылок, запись — только администраторам."""
    for current, dirs, files in os.walk(root, topdown=True, followlinks=False):
        here = Path(current)
        for name in list(dirs):
            child = here / name
            if is_link(child):
                return f"{child.relative_to(root)} — ссылка на другую папку"
            problem = acl_problem(child)
            if problem:
                return f"{child.relative_to(root)}: {problem}"
        for name in files:
            if name.lower().endswith(CODE_SUFFIXES):
                child = here / name
                problem = "ссылка на другой файл" if is_link(child) else acl_problem(child)
                if problem:
                    return f"{child.relative_to(root)}: {problem}"
    return None


def untrusted_reason(root: Path) -> str | None:
    """Почему содержимому папки данных нельзя доверять; None — можно."""
    if owner_sid(root) not in (ADMINS, SYSTEM):
        return "владелец не администратор"
    marker = root / MARKER
    if not marker.is_file() or is_link(marker):
        return "нет метки защищённой папки"
    problem = acl_problem(root, protected=True)
    if problem:
        return problem
    return _trusted_tree_problem(root)


@dataclass
class SetAside:
    """Итог разбора недоверенной папки данных."""
    folders: list[Path] = field(default_factory=list)   # куда отложено прежнее содержимое, старые первыми
    restored: list[str] = field(default_factory=list)   # что вернулось назад (относительные пути)
    service_stopped: bool = False   # служба обхода остановлена перед разбором — Core запустит её снова


def _plain_file(base: Path, path: Path) -> bool:
    """Обычный файл внутри base, и по пути к нему нет ссылок: папка-ссылка увела бы чтение (и запись) в
    чужую папку, а ссылка на сам файл, в том числе жёсткая, отдала бы чужое содержимое. Не больше
    USER_DATA_LIMIT."""
    current = base
    for part in path.relative_to(base).parts[:-1]:
        current = current / part
        if is_link(current):
            return False
    try:
        info = os.lstat(path)
    except OSError:
        return False
    return (stat.S_ISREG(info.st_mode) and not info.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT
            and info.st_nlink == 1 and info.st_size <= USER_DATA_LIMIT)


def _user_data_files(source: Path) -> list[Path]:
    found: list[Path] = []
    for rel in USER_DATA:
        found.extend(source.glob(rel) if "*" in rel else [source / rel])
    return [f for f in found if _plain_file(source, f)]


def restored_titles(restored: list[str]) -> list[str]:
    """Что вернулось назад — словами из USER_DATA, без повторов."""
    titles: list[str] = []
    for pattern, title in USER_DATA.items():
        if title not in titles and any(fnmatch.fnmatchcase(rel, pattern) for rel in restored):
            titles.append(title)
    return titles


def _settings_without_paths(data: bytes) -> bytes | None:
    """settings.json из недоверенной папки: пути к программам (копия прежней Лазейки для «Откатить»,
    скачанное ядро прокси) из неё не берём — их могли подменить. Не JSON — не переносим вовсе."""
    try:
        raw = json.loads(data.decode("utf-8-sig"))   # с BOM — как читает Settings
    except ValueError:                               # UnicodeError — тоже ValueError
        return None
    if not isinstance(raw, dict):
        return None
    if isinstance(raw.get("updates"), dict):
        for key in ("app_backup", "app_backup_for", "app_backup_version"):
            raw["updates"][key] = None
    if isinstance(raw.get("tg"), dict):
        raw["tg"]["core"] = "bundled"
    return json.dumps(raw, ensure_ascii=False, indent=2).encode("utf-8")


def _checked(rel: str, data: bytes) -> bytes | None:
    """Содержимое файла данных человека, каким его можно вернуть; None — не возвращать: JSON, который не
    разбирается, — не данные, а мусор или подмена."""
    if rel in SETTINGS_DATA:
        return _settings_without_paths(data)
    if rel.endswith(".json"):
        try:
            json.loads(data.decode("utf-8-sig"))
        except ValueError:
            return None
    return data


def _write_restored(root: Path, rel: str, data: bytes) -> None:
    """Записать файл в корень. Через временный файл и замену: файл-ссылку, оставшийся в корне после
    отказа, замена убирает, а не пишет сквозь неё. Папка-ссылка по пути — отказ: запись ушла бы в чужую."""
    if rel.startswith("vpnclient/"):
        secure_private_dir(root / "vpnclient")      # ключи и подписки — не для чтения пользователям
    current = root
    for part in Path(rel).parts[:-1]:
        current = current / part
        if is_link(current):
            raise OSError(f"{current} — ссылка на другую папку")
    target = root / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    staging = target.with_name(f"{target.name}.{uuid.uuid4().hex[:8]}.tmp")
    try:
        staging.write_bytes(data)
        os.replace(staging, target)
    finally:
        staging.unlink(missing_ok=True)


def restore_user_data(asides: list[Path], root: Path) -> tuple[list[str], list[str]]:
    """Вернуть в корень данные человека из отложенных папок — по порядку, более новые поверх.
    Возвращает (что вернулось — относительные пути; что не записалось — с причиной). Незаписанный файл
    не останавливает остальные."""
    restored: list[str] = []
    failed: list[str] = []
    for aside in asides:
        for source in _user_data_files(aside):
            rel = source.relative_to(aside).as_posix()
            try:
                data = _checked(rel, source.read_bytes())
                if data is None:
                    continue
                _write_restored(root, rel, data)
            except OSError as exc:
                failed.append(f"{rel} ({exc})")
                continue
            if rel not in restored:
                restored.append(rel)
    return restored, failed


def _move_aside(source: Path, target: Path, root: Path, stuck: list[str]) -> None:
    """source — в target переименованием. Папка целиком не переехала (что-то внутри занято) — по частям.
    Ничего не удаляется: что не переехало, остаётся на месте и попадает в stuck (путь и причина)."""
    try:
        os.rename(source, target)
        return
    except OSError as exc:
        if is_link(source) or not source.is_dir():
            stuck.append(f"{source.relative_to(root)} ({exc.strerror or exc})")
            return
    try:
        target.mkdir()
        children = list(source.iterdir())
    except OSError as exc:
        stuck.append(f"{source.relative_to(root)} ({exc.strerror or exc})")
        return
    before = len(stuck)
    for child in children:
        _move_aside(child, target / child.name, root, stuck)
    try:
        os.rmdir(source)                 # опустела; не пуста — в ней то, что уже попало в stuck
    except OSError as exc:
        if len(stuck) == before:
            stuck.append(f"{source.relative_to(root)} ({exc.strerror or exc})")


def _set_aside(root: Path, aside: Path) -> list[str]:
    """Всё содержимое корня — в отложенную папку (на том же диске: переименованием). Возвращает, что
    перенести не удалось (путь и причина)."""
    stuck: list[str] = []
    for child in list(root.iterdir()):
        target = aside / child.name
        if os.path.lexists(target):      # имя метки PENDING_MARKER: в корне такому файлу взяться неоткуда
            target = aside / f"{child.name}-{uuid.uuid4().hex[:4]}"
        _move_aside(child, target, root, stuck)
    return stuck


def _new_aside(root: Path, apply_acl) -> Path:
    """Отложенная папка рядом с корнем — сразу с меткой «перенос не закончен»."""
    aside = root.parent / f"{root.name}{ASIDE_SUFFIX}{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:4]}"
    aside.mkdir()
    apply_acl(aside, PRIVATE_SDDL)       # там ключи своего VPN — пользователям не читать
    if any(aside.iterdir()):
        raise DataFolderError(f"В новую папку {aside} кто-то успел положить файлы — запустите Лазейку снова")
    (aside / PENDING_MARKER).write_text("ok", encoding="ascii")
    return aside


def _trusted_aside(aside: Path) -> bool:
    """Отложенную папку создала Лазейка: владелец — администраторы, и запись только у них. Метку
    незаконченного переноса в такую не подложить (в ProgramData папки может создавать любой)."""
    return owner_sid(aside) in (ADMINS, SYSTEM) and acl_problem(aside, protected=True) is None


def _unfinished_asides(root: Path) -> list[Path]:
    """Отложенные папки этого корня, перенос из которых не закончен (сбой, отказ из-за занятого файла),
    старые первыми — по времени метки: в имени время только до секунды."""
    name = re.compile(re.escape(root.name + ASIDE_SUFFIX) + r"\d{8}-\d{6}-[0-9a-f]{4}", re.IGNORECASE)
    try:
        candidates = [p for p in root.parent.iterdir() if name.fullmatch(p.name)]
    except OSError:
        return []
    found: list[tuple[int, Path]] = []
    for aside in candidates:
        marker = aside / PENDING_MARKER
        if (not is_link(aside) and aside.is_dir() and marker.is_file() and not is_link(marker)
                and _trusted_aside(aside)):
            found.append((marker.stat().st_mtime_ns, aside))
    return [aside for _, aside in sorted(found)]


def _nothing_to_set_aside(root: Path) -> bool:
    """В корне нет ничего, кроме журналов запуска без прав (обычные файлы, не код и без ссылок). Такую
    папку — например пустую LazeykaData, которую по README создаёт сам человек, — откладывать незачем."""
    entries = list(root.iterdir())
    if not entries:
        return True
    logs = entries[0]
    if len(entries) > 1 or logs.name != LOGS_DIR or is_link(logs) or not logs.is_dir():
        return False
    return all(_plain_file(logs, f) and not f.name.lower().endswith(CODE_SUFFIXES) for f in logs.iterdir())


def _refusal(root: Path, result: SetAside, stuck: list[str], failed: list[str]) -> str:
    """Текст отказа: что именно не перенеслось и где теперь прежнее содержимое."""
    where = ", ".join(str(folder) for folder in result.folders)
    if stuck:
        more = f" (и ещё {len(stuck) - 1})" if len(stuck) > 1 else ""
        text = (f"Папку данных {root} не удалось разобрать: не переносится {stuck[0]}{more}. Обычно так "
                "бывает, когда файл занят работающей программой.")
    else:
        text = f"Данные человека не вернулись в {root}: {', '.join(failed)}."
    titles = restored_titles(result.restored)
    back = f" На место уже вернули: {', '.join(titles)}." if titles else ""
    return (f"{text} Что удалось перенести, отложено в {where}.{back} Закройте программу, которая может "
            "держать файл (или перезагрузите компьютер), и запустите Лазейку снова — перенос доделается сам.")


def rebuild(root: Path, reason: str, apply_acl=None) -> tuple[list[str], SetAside | None]:
    """Недоверенная папка данных: права заново, содержимое — в сторону, данные человека — назад.
    Возвращает (заметки для журнала, итог; None — откладывать было нечего: пустая папка).

    Перенос — как транзакция. Отложенная папка сразу получает метку «перенос не закончен», а корень —
    метку доверия, только когда данные человека вернулись. Что-то в корне не переносится (занятый файл)
    или не записалось назад — отказ запуска, но данные человека возвращаются в корень и тогда, а
    следующий запуск возвращает их из всех незаконченных отложенных папок (более новые — поверх) и
    доделывает перенос. Ничего не удаляется."""
    apply_acl = apply_acl or _apply_protected_acl
    apply_acl(root)                      # сначала отнять запись у чужих, потом разбирать
    result = SetAside(folders=_unfinished_asides(root))
    notes = [f"Перенос в {folder} не был закончен — данные человека вернутся и из неё" for folder in result.folders]
    if _nothing_to_set_aside(root):
        if (root / LOGS_DIR).is_dir():
            apply_acl(root / LOGS_DIR)   # владелец журналов — не человек: иначе он вернул бы себе запись
        if not result.folders:
            (root / MARKER).write_text("ok", encoding="ascii")
            notes.append(f"Папке {root} нельзя было доверять ({reason}), но в ней ничего нет (разве что "
                         "журналы) — откладывать нечего")
            return notes, None
        notes.append(f"Папке {root} нельзя было доверять ({reason}), но новых файлов в ней нет — откладывать нечего")
        fresh = None
    else:
        fresh = _new_aside(root, apply_acl)
        result.folders.append(fresh)
        notes.append(f"Содержимому {root} нельзя было доверять ({reason}): оно перенесено в {fresh}")
    stuck: list[str] = []
    try:
        if fresh is not None:
            stuck = _set_aside(root, fresh)
            apply_acl(fresh, PRIVATE_SDDL)   # перенесённое — с теми же правами
    finally:
        # И при отказе: данные человека — на месте, а не только в отложенной папке.
        result.restored, failed = restore_user_data(result.folders, root)
    if stuck or failed:
        raise DataFolderError(_refusal(root, result, stuck, failed))
    for folder in result.folders:
        (folder / PENDING_MARKER).unlink(missing_ok=True)
    (root / MARKER).write_text("ok", encoding="ascii")
    notes.append(("Назад перенесено: " + ", ".join(result.restored)) if result.restored
                 else "Данных человека в отложенном не нашлось — назад переносить нечего")
    return notes, result


def untrusted_alert(result: SetAside) -> str:
    """Плашка data-untrusted — по тому, что на деле вернулось назад."""
    where = ", ".join(str(folder) for folder in result.folders)
    titles = restored_titles(result.restored)
    back = (f"Назад перенесли: {', '.join(titles)}." if titles
            else "Настроек, профилей и своих списков в нём не нашлось — переносить назад было нечего.")
    which = "эту папку" if len(result.folders) == 1 else "эти папки"
    return (f"Папке данных нельзя было доверять (почему — в журнале), и её прежнее содержимое отложено в "
            f"{where}. {back} Программы поставим заново. Проверьте и удалите {which}.")


def stop_own_service(root: Path) -> tuple[list[str], bool]:
    """Служба обхода Лазейки, чей winws лежит в недоверенной папке, запускает от SYSTEM код, который могли
    подменить, и держит его файлы занятыми — папку под ней не разобрать. Останавливаем только её и
    только тогда: чужие службы и службу Лазейки с другой папкой данных не трогаем. Тип запуска не меняем —
    пакет поставится заново, и обход перенастроит службу на него и запустит снова (Core). Возвращает
    (заметки для журнала, остановлена ли)."""
    from . import winutil
    from .zapret.manager import SERVICE_NAME
    from .zapret.strategies import split_args
    info = winutil.service_query(SERVICE_NAME, with_config=True)
    if info is None or info.state == "stopped" or not info.binary:
        return [], False
    args = split_args(info.binary)
    inside = os.path.normcase(os.path.abspath(root)) + os.sep
    if not args or not os.path.normcase(os.path.abspath(args[0])).startswith(inside):
        return [], False
    try:
        stopped = winutil.service_stop(SERVICE_NAME)
    except winutil.ServiceError as exc:
        return [f"служба {SERVICE_NAME} запускает winws из недоверенной папки, но не остановлена: {exc}"], False
    if not stopped:
        return [f"служба {SERVICE_NAME} запускает winws из недоверенной папки и не остановилась за 10 секунд"], False
    return [f"служба {SERVICE_NAME} запускала winws из недоверенной папки — остановлена до переустановки "
            "пакета"], True


def secure_data_root(notes: list[str]) -> SetAside | None:
    """Вызывается только с правами администратора, до любого чтения или запуска из папки данных
    (и под межпроцессной блокировкой папки — winutil.DataLock).

    notes — заметки для журнала (он ещё не настроен): дописываются и тогда, когда защитить не вышло.
    Возвращает итог разбора недоверенной папки или None."""
    if paths.test_data_override():
        return None
    root = paths.DATA
    if keeps_acls(root) is False:
        raise DataFolderError(
            f"Папка данных {root} — на диске без прав доступа (FAT32 или exFAT). Там её не закрыть от записи "
            "обычными программами, а из неё обход запускается с правами администратора. Перенесите Лазейку "
            "на диск NTFS или уберите папку LazeykaData рядом с exe — тогда данные будут храниться в ProgramData.")
    if is_link(root):
        notes.append(f"{root} — ссылка на другую папку; убираем ссылку и создаём папку заново")
        _remove(root)
    if not root.exists():
        root.mkdir(parents=True)
        _apply_protected_acl(root)
        (root / MARKER).write_text("ok", encoding="ascii")
        notes.append(f"Права на {root} выставлены: запись только у администраторов")
        return None
    reason = untrusted_reason(root)
    if reason is None:
        return None
    service_notes, service_stopped = stop_own_service(root)
    notes.extend(service_notes)
    more, result = rebuild(root, reason)
    result.service_stopped = service_stopped
    notes.extend(more)
    notes.append(f"Права на {root} выставлены заново: запись только у администраторов")
    return result
