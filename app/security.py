"""Защита папки данных.

Из папки данных winws.exe запускается с правами администратора. По умолчанию
подпапки ProgramData разрешают обычным программам добавлять туда файлы — значит,
любая программа без прав могла бы подложить DLL рядом с winws.exe. Поэтому:

- без прав администратора папка данных не создаётся вовсе;
- с правами — владелец «Администраторы» и защищённый (без наследования) список
  доступа ровно из трёх записей: SYSTEM и администраторы — полный доступ,
  пользователи — чтение и запуск;
- если папкой владел не администратор или на ней нет нашей метки, её содержимое
  не доверено и удаляется целиком (ссылки и junction удаляются как ссылки,
  без перехода по ним), после чего права выставляются заново.
"""
from __future__ import annotations

import ctypes
import logging
import os
import shutil
import stat
import uuid
from ctypes import wintypes
from pathlib import Path

from . import paths

log = logging.getLogger("lazeyka.security")

ADMINS = "S-1-5-32-544"
SYSTEM = "S-1-5-18"
MARKER = ".secured-v1"
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
_kernel32.LocalFree.argtypes = [ctypes.c_void_p]
_kernel32.LocalFree.restype = ctypes.c_void_p

SE_FILE_OBJECT = 1
OWNER_SECURITY_INFORMATION = 0x1
DACL_SECURITY_INFORMATION = 0x4
PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000


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


def secure_data_root() -> list[str]:
    """Вызывается только с правами администратора, до любого чтения или запуска из папки данных.

    Возвращает заметки для журнала: журнал ещё не настроен в момент вызова.
    """
    notes: list[str] = []
    if paths.test_data_override():
        return notes
    root = paths.DATA
    if is_link(root):
        notes.append(f"{root} — ссылка на другую папку; удаляю её и создаю папку заново")
        _remove(root)
    if root.exists():
        trusted_owner = owner_sid(root) in (ADMINS, SYSTEM)
        marker = root / MARKER
        if trusted_owner and marker.is_file() and not is_link(marker):
            return notes
        reason = "владелец не администратор" if not trusted_owner else "нет метки защищённой папки"
        notes.append(f"Содержимому {root} нельзя доверять ({reason}) — очищаю и выставляю права заново")
        _apply_protected_acl(root)  # сначала отнять запись у чужих, потом чистить
        for child in list(root.iterdir()):
            try:
                _remove(child)
            except OSError:
                # Права на саму папку позволяют убрать из неё любой элемент, даже если
                # его собственные права запрещают удаление: переносим его наружу.
                quarantine = root.parent / f"{root.name}-quarantine-{uuid.uuid4().hex[:8]}"
                try:
                    os.rename(child, quarantine)
                    notes.append(f"{child} не удалялся — перенесён в {quarantine}")
                except OSError as exc:
                    raise OSError(f"Папку данных не удалось очистить: {child}: {exc}") from exc
    else:
        root.mkdir(parents=True)
    _apply_protected_acl(root)
    (root / MARKER).write_text("ok", encoding="ascii")
    notes.append(f"Права на {root} выставлены: запись только у администраторов")
    return notes
