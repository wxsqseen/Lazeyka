"""Ссылки только для импорта; канал текущего пользователя не выполняет команд."""
from __future__ import annotations

import ctypes
import logging
import math
import ntpath
import threading
import time
import winreg
from ctypes import wintypes
from typing import Callable
from urllib.parse import unquote

from ..errors import UserError
from . import guard

log = logging.getLogger("lazeyka.vpnclient.deeplink")
SCHEME = "lazeyka"
PIPE_NAME = r"\\.\pipe\Lazeyka.Links"
MAX_BYTES = 64 * 1024
_KEY = r"Software\Classes\lazeyka"
_ACTION = "регистрация ссылок lazeyka://"


def parse(url: str) -> str | None:
    if not isinstance(url, str) or not url.startswith("lazeyka://import/"):
        return None
    try:
        if len(url) > MAX_BYTES or len(url.encode("utf-8")) > MAX_BYTES:
            return None
        text = unquote(url[len("lazeyka://import/"):], encoding="utf-8", errors="strict")
        # Не применяем unquote_plus и не декодируем вложенную ссылку повторно.
        return text if text and "\x00" not in text else None
    except UnicodeError:
        return None


def register(exe: str) -> None:
    guard.ensure_allowed(_ACTION)
    if not isinstance(exe, str) or not ntpath.isabs(exe) or any(c in exe for c in '\x00\r\n"'):
        raise UserError("Для регистрации ссылок нужен полный путь к Лазейке")
    try:
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, _KEY) as key:
            winreg.SetValueEx(key, "", 0, winreg.REG_SZ, "URL:Лазейка")
            winreg.SetValueEx(key, "URL Protocol", 0, winreg.REG_SZ, "")
        for suffix, value in (("DefaultIcon", f'"{exe}",0'),
                              (r"shell\open\command", f'"{exe}" "%1"')):
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, _KEY + "\\" + suffix) as key:
                winreg.SetValueEx(key, "", 0, winreg.REG_SZ, value)
    except OSError as exc:
        raise UserError("Не удалось зарегистрировать ссылки lazeyka://") from exc


def unregister() -> None:
    guard.ensure_allowed(_ACTION)
    try:
        # Только свой известный ключ, снизу вверх; чужие ветки не обходим.
        for suffix in (r"\shell\open\command", r"\shell\open", r"\shell", r"\DefaultIcon", ""):
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, _KEY + suffix)
            except FileNotFoundError:
                pass
    except OSError as exc:
        raise UserError("Не удалось убрать обработчик ссылок lazeyka://") from exc


def registered() -> bool:
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _KEY) as key:
            protocol, kind = winreg.QueryValueEx(key, "URL Protocol")
            if protocol != "" or kind != winreg.REG_SZ:
                return False
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _KEY + r"\shell\open\command") as key:
            command, kind = winreg.QueryValueEx(key, "")
            return kind == winreg.REG_SZ and bool(command) and command.endswith('" "%1"')
    except OSError:
        return False


class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("nLength", wintypes.DWORD), ("lpSecurityDescriptor", ctypes.c_void_p),
                ("bInheritHandle", wintypes.BOOL)]


class _SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]


class _TOKEN_USER(ctypes.Structure):
    _fields_ = [("User", _SID_AND_ATTRIBUTES)]


class _OVERLAPPED(ctypes.Structure):
    # Союз Offset/OffsetHigh и Pointer занимает 8 байт; для канала смещение равно нулю.
    _fields_ = [("Internal", ctypes.c_size_t), ("InternalHigh", ctypes.c_size_t),
                ("Offset", wintypes.DWORD), ("OffsetHigh", wintypes.DWORD),
                ("hEvent", wintypes.HANDLE)]


class _PipeApi:
    def __init__(self) -> None:
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        handle, dword, pointer = wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p
        pdword, overlapped = ctypes.POINTER(dword), ctypes.POINTER(_OVERLAPPED)
        definitions = {
            "CreateNamedPipeW": ([wintypes.LPCWSTR, dword, dword, dword, dword, dword, dword,
                                  ctypes.POINTER(SECURITY_ATTRIBUTES)], handle),
            "ConnectNamedPipe": ([handle, overlapped], wintypes.BOOL),
            "DisconnectNamedPipe": ([handle], wintypes.BOOL),
            "CreateFileW": ([wintypes.LPCWSTR, dword, dword, pointer, dword, dword, handle], handle),
            "ReadFile": ([handle, pointer, dword, pdword, overlapped], wintypes.BOOL),
            "WriteFile": ([handle, pointer, dword, pdword, overlapped], wintypes.BOOL),
            "CreateEventW": ([pointer, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR], handle),
            "WaitForSingleObject": ([handle, dword], dword),
            "GetOverlappedResult": ([handle, overlapped, pdword, wintypes.BOOL], wintypes.BOOL),
            "CancelIoEx": ([handle, overlapped], wintypes.BOOL),
            "CloseHandle": ([handle], wintypes.BOOL),
            "GetCurrentProcess": ([], handle),
            "LocalFree": ([pointer], pointer),
        }
        for name, (args, result) in definitions.items():
            func = getattr(self.kernel, name)
            func.argtypes, func.restype = args, result
        definitions = {
            "OpenProcessToken": ([handle, dword, ctypes.POINTER(handle)], wintypes.BOOL),
            "GetTokenInformation": ([handle, ctypes.c_int, pointer, dword, pdword], wintypes.BOOL),
            "ConvertSidToStringSidW": ([pointer, ctypes.POINTER(wintypes.LPWSTR)], wintypes.BOOL),
            "ConvertStringSecurityDescriptorToSecurityDescriptorW": (
                [wintypes.LPCWSTR, dword, ctypes.POINTER(pointer), pdword], wintypes.BOOL),
        }
        for name, (args, result) in definitions.items():
            func = getattr(self.advapi, name)
            func.argtypes, func.restype = args, result

    def user_sid(self) -> str:
        token = wintypes.HANDLE()
        if not self.advapi.OpenProcessToken(self.kernel.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            needed = wintypes.DWORD()
            self.advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))  # TokenUser
            if not needed.value:
                raise ctypes.WinError(ctypes.get_last_error())
            buffer = ctypes.create_string_buffer(needed.value)
            if not self.advapi.GetTokenInformation(token, 1, buffer, needed, ctypes.byref(needed)):
                raise ctypes.WinError(ctypes.get_last_error())
            user = ctypes.cast(buffer, ctypes.POINTER(_TOKEN_USER)).contents
            sid = wintypes.LPWSTR()
            if not self.advapi.ConvertSidToStringSidW(user.User.Sid, ctypes.byref(sid)):
                raise ctypes.WinError(ctypes.get_last_error())
            try:
                return sid.value
            finally:
                self.kernel.LocalFree(sid)
        finally:
            self.kernel.CloseHandle(token)

    def create(self, name: str) -> int:
        descriptor = ctypes.c_void_p()
        sddl = f"D:(A;;GRGW;;;{self.user_sid()})S:(ML;;NW;;;ME)"
        if not self.advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl, 1, ctypes.byref(descriptor), None):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            attrs = SECURITY_ATTRIBUTES(ctypes.sizeof(SECURITY_ATTRIBUTES), descriptor, False)
            # INBOUND | OVERLAPPED | FIRST_PIPE_INSTANCE; MESSAGE | READMODE_MESSAGE | REJECT_REMOTE.
            handle = self.kernel.CreateNamedPipeW(name, 0x40080001, 0x0E, 1,
                                                  MAX_BYTES + 1, MAX_BYTES + 1, 0, ctypes.byref(attrs))
            if handle == ctypes.c_void_p(-1).value:
                raise ctypes.WinError(ctypes.get_last_error())
            return handle
        finally:
            self.kernel.LocalFree(descriptor)

    def io(self, handle: int, operation: str, buffer=None, *, stop: threading.Event | None = None,
           deadline: float | None = None) -> int:
        """Одна операция; отмена обязательно завершена до освобождения OVERLAPPED и буфера."""
        event = self.kernel.CreateEventW(None, True, False, None)
        if not event:
            raise ctypes.WinError(ctypes.get_last_error())
        overlapped = _OVERLAPPED(hEvent=event)
        count = wintypes.DWORD()
        pending = False
        try:
            if operation == "connect":
                ok = self.kernel.ConnectNamedPipe(handle, ctypes.byref(overlapped))
            else:
                func = self.kernel.ReadFile if operation == "read" else self.kernel.WriteFile
                ok = func(handle, buffer, len(buffer), ctypes.byref(count), ctypes.byref(overlapped))
            if not ok:
                error = ctypes.get_last_error()
                if operation == "connect" and error == 535:  # ERROR_PIPE_CONNECTED
                    return 0
                if error != 997:  # ERROR_IO_PENDING
                    raise ctypes.WinError(error)
                pending = True
                while True:
                    if stop is not None and stop.is_set():
                        raise InterruptedError("Канал остановлен")
                    remaining = None if deadline is None else deadline - time.monotonic()
                    if remaining is not None and remaining <= 0:
                        raise TimeoutError("Канал не ответил")
                    wait_ms = 50 if remaining is None else max(1, min(50, math.ceil(remaining * 1000)))
                    result = self.kernel.WaitForSingleObject(event, wait_ms)
                    if result == 0:
                        break
                    if result != 258:  # WAIT_TIMEOUT
                        raise ctypes.WinError(ctypes.get_last_error())
            if not self.kernel.GetOverlappedResult(handle, ctypes.byref(overlapped), ctypes.byref(count), False):
                raise ctypes.WinError(ctypes.get_last_error())
            pending = False
            return count.value
        finally:
            if pending:
                self.kernel.CancelIoEx(handle, ctypes.byref(overlapped))
                self.kernel.GetOverlappedResult(handle, ctypes.byref(overlapped), ctypes.byref(count), True)
            self.kernel.CloseHandle(event)


def _pipe_name(name: str) -> str:
    if not isinstance(name, str) or not name.startswith("\\\\.\\pipe\\") or "\x00" in name:
        raise ValueError("Нужен локальный именованный канал")
    return name


class LinkServer:
    def __init__(self, *, pipe_name: str = PIPE_NAME) -> None:
        self.pipe_name = _pipe_name(pipe_name)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

    def start(self, on_text: Callable[[str], None]) -> None:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            api = _PipeApi()
            try:
                handle = api.create(self.pipe_name)
            except OSError as exc:
                raise UserError("Не удалось открыть канал ссылок Лазейки") from exc
            self._stop.clear()

            def receive() -> None:
                try:
                    while not self._stop.is_set():
                        try:
                            api.io(handle, "connect", stop=self._stop)
                            buffer = ctypes.create_string_buffer(MAX_BYTES + 1)
                            size = api.io(handle, "read", buffer, stop=self._stop,
                                          deadline=time.monotonic() + 2.0)
                            if not 0 < size <= MAX_BYTES:
                                continue
                            text = buffer.raw[:size].decode("utf-8")
                            if "\x00" in text:
                                continue
                            if not self._stop.is_set():
                                try:
                                    on_text(text)
                                except Exception:  # noqa: BLE001
                                    # Исключение обработчика может содержать секретную ссылку.
                                    log.warning("Не удалось передать ссылку в окно импорта")
                        except (OSError, UnicodeError):
                            pass  # отключение, таймаут, слишком длинное или повреждённое сообщение
                        finally:
                            api.kernel.DisconnectNamedPipe(handle)
                finally:
                    api.kernel.CloseHandle(handle)

            self._thread = threading.Thread(target=receive, name="vpn-links", daemon=True)
            try:
                self._thread.start()
            except Exception:
                api.kernel.CloseHandle(handle)
                self._thread = None
                raise

    def stop(self) -> None:
        with self._lock:
            self._stop.set()
            thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=3.0)


def send_to_running(text: str, timeout: float = 2.0, *, pipe_name: str = PIPE_NAME) -> bool:
    if not isinstance(text, str) or not text or "\x00" in text or not math.isfinite(timeout) or timeout < 0:
        return False
    name = _pipe_name(pipe_name)
    try:
        payload = text.encode("utf-8")
    except UnicodeError:
        return False
    if len(payload) > MAX_BYTES:
        return False
    api = _PipeApi()
    deadline = time.monotonic() + timeout
    while True:
        # SQOS_PRESENT | SECURITY_IDENTIFICATION: сервер не может выдать себя за клиента.
        handle = api.kernel.CreateFileW(name, 0x40000000, 0, None, 3, 0x40110000, None)
        if handle != ctypes.c_void_p(-1).value:
            break
        error = ctypes.get_last_error()
        remaining = deadline - time.monotonic()
        if error not in (2, 231) or remaining <= 0:  # канал ещё не появился или занят
            return False
        time.sleep(min(0.02, remaining))
    try:
        buffer = ctypes.create_string_buffer(payload, len(payload))
        return api.io(handle, "write", buffer, deadline=deadline) == len(payload)
    except OSError:
        return False
    finally:
        api.kernel.CloseHandle(handle)
