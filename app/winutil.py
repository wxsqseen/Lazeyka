"""Тонкие обёртки над WinAPI через ctypes."""
from __future__ import annotations

import ctypes
import json
import logging
import os
import re
import subprocess
import sys
import threading
import time
from ctypes import wintypes
from dataclasses import dataclass
from typing import Callable

log = logging.getLogger("lazeyka.win")

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
shell32 = ctypes.WinDLL("shell32", use_last_error=True)
user32 = ctypes.WinDLL("user32", use_last_error=True)

CREATE_NO_WINDOW = 0x08000000
CREATE_NEW_PROCESS_GROUP = 0x00000200

ERROR_ALREADY_EXISTS = 183
ERROR_ACCESS_DENIED = 5
ERROR_CANCELLED = 1223


# ---------------------------------------------------------------- права и UAC

def is_admin() -> bool:
    try:
        return bool(shell32.IsUserAnAdmin())
    except OSError:
        return False


class SHELLEXECUTEINFOW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("fMask", wintypes.ULONG),
        ("hwnd", wintypes.HWND),
        ("lpVerb", wintypes.LPCWSTR),
        ("lpFile", wintypes.LPCWSTR),
        ("lpParameters", wintypes.LPCWSTR),
        ("lpDirectory", wintypes.LPCWSTR),
        ("nShow", ctypes.c_int),
        ("hInstApp", wintypes.HINSTANCE),
        ("lpIDList", ctypes.c_void_p),
        ("lpClass", wintypes.LPCWSTR),
        ("hkeyClass", wintypes.HKEY),
        ("dwHotKey", wintypes.DWORD),
        ("hIconOrMonitor", wintypes.HANDLE),
        ("hProcess", wintypes.HANDLE),
    ]


shell32.ShellExecuteExW.argtypes = [ctypes.POINTER(SHELLEXECUTEINFOW)]
shell32.ShellExecuteExW.restype = wintypes.BOOL


def relaunch_as_admin(command: list[str]) -> str:
    """Запускает команду с повышением прав. Возвращает launched | cancelled | failed."""
    info = SHELLEXECUTEINFOW()
    info.cbSize = ctypes.sizeof(info)
    info.fMask = 0x00000400  # SEE_MASK_FLAG_NO_UI — ошибки вернём сами
    info.lpVerb = "runas"
    info.lpFile = command[0]
    info.lpParameters = subprocess.list2cmdline(command[1:]) if len(command) > 1 else None
    info.lpDirectory = os.path.dirname(command[0]) or None
    info.nShow = 1
    if shell32.ShellExecuteExW(ctypes.byref(info)):
        return "launched"
    err = ctypes.get_last_error()
    if err == ERROR_CANCELLED:
        return "cancelled"
    log.warning("Не удалось перезапуститься с правами администратора: WinError %d", err)
    return "failed"


# ------------------------------------------------------------ один экземпляр

class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("nLength", wintypes.DWORD),
        ("lpSecurityDescriptor", ctypes.c_void_p),
        ("bInheritHandle", wintypes.BOOL),
    ]


kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
kernel32.CreateMutexW.restype = wintypes.HANDLE
kernel32.CreateEventW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR]
kernel32.CreateEventW.restype = wintypes.HANDLE
kernel32.OpenEventW.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR]
kernel32.OpenEventW.restype = wintypes.HANDLE
kernel32.SetEvent.argtypes = [wintypes.HANDLE]
kernel32.SetEvent.restype = wintypes.BOOL
kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
kernel32.WaitForSingleObject.restype = wintypes.DWORD
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL
kernel32.LocalFree.argtypes = [ctypes.c_void_p]
kernel32.LocalFree.restype = ctypes.c_void_p
advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
    wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.ULONG)]
advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL

EVENT_MODIFY_STATE = 0x0002
WAIT_OBJECT_0 = 0


class SingleInstance:
    """Мьютекс «уже запущено» и событие «покажи окно».

    Событие создаётся с низкой меткой целостности: обычный процесс должен суметь
    разбудить уже работающий экземпляр с правами администратора.
    """

    def __init__(self, name: str):
        self.name = name
        self._mutex = None
        self.already_running = False
        self._event = None
        self._stop = False
        self._try_acquire()

    def _try_acquire(self) -> None:
        if self._mutex:
            kernel32.CloseHandle(self._mutex)
        self._mutex = kernel32.CreateMutexW(None, False, f"Local\\{self.name}.Instance")
        err = ctypes.get_last_error()
        self.already_running = (not self._mutex and err == ERROR_ACCESS_DENIED) or err == ERROR_ALREADY_EXISTS

    def wait_for_previous(self, timeout: float) -> bool:
        """Ждёт, пока прежний экземпляр завершится (перезапуск с правами администратора)."""
        deadline = time.monotonic() + timeout
        while self.already_running and time.monotonic() < deadline:
            time.sleep(0.25)
            self._try_acquire()
        return not self.already_running

    def signal_existing(self) -> bool:
        handle = kernel32.OpenEventW(EVENT_MODIFY_STATE, False, f"Local\\{self.name}.Show")
        if not handle:
            return False
        try:
            return bool(kernel32.SetEvent(handle))
        finally:
            kernel32.CloseHandle(handle)

    def listen(self, on_show: Callable[[], None]) -> None:
        sd = ctypes.c_void_p()
        sddl = "D:(A;;0x1F0003;;;WD)S:(ML;;NW;;;LW)"
        attrs = None
        if advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(sd), None):
            attrs = SECURITY_ATTRIBUTES(ctypes.sizeof(SECURITY_ATTRIBUTES), sd, False)
        self._event = kernel32.CreateEventW(ctypes.byref(attrs) if attrs else None, False, False,
                                            f"Local\\{self.name}.Show")
        if sd:
            kernel32.LocalFree(sd)
        if not self._event:
            log.warning("Событие показа окна не создано: WinError %d", ctypes.get_last_error())
            return

        def loop() -> None:
            while not self._stop:
                if kernel32.WaitForSingleObject(self._event, 500) == WAIT_OBJECT_0 and not self._stop:
                    try:
                        on_show()
                    except Exception:  # noqa: BLE001
                        log.exception("Ошибка при показе окна по сигналу второго экземпляра")

        threading.Thread(target=loop, name="instance-listener", daemon=True).start()

    def close(self) -> None:
        self._stop = True


# ------------------------------------------------- job: дочерние процессы

class IO_COUNTERS(ctypes.Structure):
    _fields_ = [(n, ctypes.c_ulonglong) for n in (
        "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
        "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]


class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_int64),
        ("PerJobUserTimeLimit", ctypes.c_int64),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
        ("IoInfo", IO_COUNTERS),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
kernel32.CreateJobObjectW.restype = wintypes.HANDLE
kernel32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
kernel32.SetInformationJobObject.restype = wintypes.BOOL
kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
kernel32.AssignProcessToJobObject.restype = wintypes.BOOL

_job_handle = None


def kill_with_app(process_handle: int) -> bool:
    """Привязывает процесс к job с KILL_ON_JOB_CLOSE: он умрёт вместе с приложением."""
    global _job_handle
    if _job_handle is None:
        job = kernel32.CreateJobObjectW(None, None)
        if not job:
            return False
        info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        info.BasicLimitInformation.LimitFlags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not kernel32.SetInformationJobObject(job, 9, ctypes.byref(info), ctypes.sizeof(info)):
            kernel32.CloseHandle(job)
            return False
        _job_handle = job
    return bool(kernel32.AssignProcessToJobObject(_job_handle, wintypes.HANDLE(process_handle)))


# ------------------------------------------------------------ процессы

def oem_decode(data: bytes) -> str:
    if not data:
        return ""
    for enc in (f"cp{kernel32.GetOEMCP()}", "utf-8"):
        try:
            return data.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("utf-8", errors="replace")


@dataclass
class RunResult:
    code: int
    out: str
    err: str


def run(cmd: list[str], timeout: float = 30.0, cwd: str | None = None) -> RunResult:
    """Запускает консольную утилиту без окна и возвращает вывод."""
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout, cwd=cwd,
                              creationflags=CREATE_NO_WINDOW, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired as exc:
        return RunResult(-1, oem_decode(exc.stdout or b""), "timeout")
    except OSError as exc:
        return RunResult(-1, "", str(exc))
    return RunResult(proc.returncode, oem_decode(proc.stdout), oem_decode(proc.stderr))


# Пути к системным папкам берём у Windows, а не из переменных окружения: их обычный
# пользователь может переопределить у себя (HKCU\Environment), и процесс с правами
# администратора запустил бы подставленную программу.

kernel32.GetSystemDirectoryW.argtypes = [wintypes.LPWSTR, wintypes.UINT]
kernel32.GetSystemDirectoryW.restype = wintypes.UINT
kernel32.GetSystemWindowsDirectoryW.argtypes = [wintypes.LPWSTR, wintypes.UINT]
kernel32.GetSystemWindowsDirectoryW.restype = wintypes.UINT


def system_dir() -> str:
    buf = ctypes.create_unicode_buffer(520)
    if not kernel32.GetSystemDirectoryW(buf, len(buf)):
        raise OSError(ctypes.get_last_error(), "GetSystemDirectoryW")
    return buf.value


def windows_dir() -> str:
    buf = ctypes.create_unicode_buffer(520)
    if not kernel32.GetSystemWindowsDirectoryW(buf, len(buf)):
        raise OSError(ctypes.get_last_error(), "GetSystemWindowsDirectoryW")
    return buf.value


class _GUID(ctypes.Structure):
    _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD), ("Data3", wintypes.WORD),
                ("Data4", ctypes.c_ubyte * 8)]


FOLDERID_PROGRAM_DATA = "{62AB5D82-FDC1-4DC3-A9DD-070D1D495D97}"
FOLDERID_PROGRAM_FILES = "{905e63b6-c1bf-494e-b29c-65b732d3d21a}"

shell32.SHGetKnownFolderPath.argtypes = [ctypes.POINTER(_GUID), wintypes.DWORD, wintypes.HANDLE,
                                         ctypes.POINTER(ctypes.c_wchar_p)]
shell32.SHGetKnownFolderPath.restype = ctypes.c_long
_ole32 = ctypes.WinDLL("ole32")
_ole32.CoTaskMemFree.argtypes = [ctypes.c_void_p]


def known_folder(folder_id: str) -> str:
    import uuid
    guid = _GUID.from_buffer_copy(uuid.UUID(folder_id).bytes_le)
    out = ctypes.c_wchar_p()
    hr = shell32.SHGetKnownFolderPath(ctypes.byref(guid), 0, None, ctypes.byref(out))
    if hr != 0:
        raise OSError(hr, f"SHGetKnownFolderPath {folder_id}")
    try:
        return out.value
    finally:
        _ole32.CoTaskMemFree(out)


def system32(name: str) -> str:
    return os.path.join(system_dir(), name)


# ------------------------------------------------------------ Microsoft Defender
#
# Драйвер WinDivert, без которого не работает winws, многие антивирусы (и встроенный
# Defender) помечают как RiskTool/HackTool — это ложное срабатывание, то же самое бывает
# у оригинального zapret. Из-за него Defender может удалять файлы Лазейки при каждом входе.
# Здесь — честная мера против ложного срабатывания: по явной просьбе человека добавить в
# доверенные КОНКРЕТНЫЕ файлы Лазейки (папку в Program Files, папку данных, два exe и драйвер).
# Это не отключение антивируса и не маскировка: Defender продолжает проверять всё остальное.


def _powershell() -> str:
    return os.path.join(system_dir(), "WindowsPowerShell", "v1.0", "powershell.exe")


def _run_ps(script: str, timeout: float = 25.0) -> RunResult:
    return run([_powershell(), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                "-Command", script], timeout=timeout)


def _ps_literal(value: str) -> str:
    """Строка-литерал PowerShell: одинарные кавычки, внутренние удваиваются."""
    return "'" + str(value).replace("'", "''") + "'"


def defender_present() -> bool:
    """Установлен ли вообще Microsoft Defender (модуль management есть не везде)."""
    return os.path.isfile(_powershell()) and _run_ps(
        "if (Get-Command Get-MpPreference -ErrorAction SilentlyContinue) { 'yes' }").out.strip() == "yes"


def defender_active() -> bool:
    """Включена ли антивирусная защита Defender в реальном времени (иначе исключения ни к чему)."""
    out = _run_ps("try { $s = Get-MpComputerStatus; "
                  "if ($s.AntivirusEnabled -or $s.RealTimeProtectionEnabled) { 'on' } else { 'off' } } "
                  "catch { 'err' }").out.strip()
    return out == "on"


def defender_exclusions() -> tuple[set[str], set[str]]:
    """Текущие исключения Defender: (пути, процессы). Пустые множества, если спросить не вышло."""
    res = _run_ps("try { $p = Get-MpPreference; "
                  "[pscustomobject]@{ paths = @($p.ExclusionPath); procs = @($p.ExclusionProcess) } "
                  "| ConvertTo-Json -Compress } catch { '' }")
    try:
        data = json.loads(res.out) if res.out.strip() else {}
    except ValueError:
        return set(), set()

    def norm(value) -> set[str]:
        if value is None:
            return set()
        items = value if isinstance(value, list) else [value]
        return {str(x).rstrip("\\").lower() for x in items if x}

    return norm(data.get("paths")), norm(data.get("procs"))


def _under(path: str, roots: tuple[str, ...]) -> bool:
    try:
        resolved = os.path.normcase(os.path.realpath(path))
    except OSError:
        return False
    return any(resolved == os.path.normcase(os.path.realpath(r))
               or resolved.startswith(os.path.normcase(os.path.realpath(r)) + os.sep) for r in roots)


def defender_add_exclusions(paths: list[str], processes: list[str], allowed_roots: tuple[str, ...]) -> RunResult:
    """Добавляет исключения Defender. Пути обязаны лежать внутри allowed_roots (папки Лазейки) —
    чтобы случайно не исключить что-то широкое. Требует прав администратора."""
    safe_paths = [p for p in paths if _under(p, allowed_roots)]
    safe_procs = [p for p in processes if _under(p, allowed_roots)]
    rejected = [p for p in (*paths, *processes) if p not in safe_paths and p not in safe_procs]
    if rejected:
        log.warning("Пропущены исключения Defender вне папок Лазейки: %s", rejected)
    if not safe_paths and not safe_procs:
        return RunResult(1, "", "нет путей внутри папок Лазейки")
    cmds = [f"Add-MpPreference -ExclusionPath {_ps_literal(p)}" for p in safe_paths]
    cmds += [f"Add-MpPreference -ExclusionProcess {_ps_literal(p)}" for p in safe_procs]
    script = "try { " + "; ".join(cmds) + "; 'ok' } catch { Write-Error $_.Exception.Message; exit 1 }"
    return _run_ps(script)


# ------------------------------------------------------------ запуск без наших прав

class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR), ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR), ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD), ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD), ("dwFillAttribute", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD), ("lpReserved2", ctypes.c_void_p),
        ("hStdInput", wintypes.HANDLE), ("hStdOutput", wintypes.HANDLE), ("hStdError", wintypes.HANDLE),
    ]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
                ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD)]


class LUID(ctypes.Structure):
    _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]


class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]


class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [("PrivilegeCount", wintypes.DWORD), ("Privileges", LUID_AND_ATTRIBUTES * 1)]


TOKEN_ASSIGN_PRIMARY = 0x0001
TOKEN_DUPLICATE = 0x0002
TOKEN_QUERY = 0x0008
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_ADJUST_DEFAULT = 0x0080
TOKEN_ADJUST_SESSIONID = 0x0100
PROCESS_QUERY_INFORMATION = 0x0400
SECURITY_IMPERSONATION = 2
TOKEN_PRIMARY = 1
SE_PRIVILEGE_ENABLED = 0x0002

user32.GetShellWindow.restype = wintypes.HWND
user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
user32.GetWindowThreadProcessId.restype = wintypes.DWORD
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.GetCurrentProcess.restype = wintypes.HANDLE
advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
advapi32.OpenProcessToken.restype = wintypes.BOOL
advapi32.DuplicateTokenEx.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, ctypes.c_int,
                                      ctypes.c_int, ctypes.POINTER(wintypes.HANDLE)]
advapi32.DuplicateTokenEx.restype = wintypes.BOOL
advapi32.CreateProcessWithTokenW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPWSTR,
                                             wintypes.DWORD, ctypes.c_void_p, wintypes.LPCWSTR,
                                             ctypes.POINTER(STARTUPINFOW), ctypes.POINTER(PROCESS_INFORMATION)]
advapi32.CreateProcessWithTokenW.restype = wintypes.BOOL
advapi32.LookupPrivilegeValueW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.POINTER(LUID)]
advapi32.LookupPrivilegeValueW.restype = wintypes.BOOL
advapi32.AdjustTokenPrivileges.argtypes = [wintypes.HANDLE, wintypes.BOOL, ctypes.POINTER(TOKEN_PRIVILEGES),
                                           wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p]
advapi32.AdjustTokenPrivileges.restype = wintypes.BOOL


def _enable_privilege(name: str) -> None:
    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                                     ctypes.byref(token)):
        return
    try:
        luid = LUID()
        if not advapi32.LookupPrivilegeValueW(None, name, ctypes.byref(luid)):
            return
        tp = TOKEN_PRIVILEGES(1, (LUID_AND_ATTRIBUTES * 1)(LUID_AND_ATTRIBUTES(luid, SE_PRIVILEGE_ENABLED)))
        advapi32.AdjustTokenPrivileges(token, False, ctypes.byref(tp), 0, None, None)
    finally:
        kernel32.CloseHandle(token)


def run_as_desktop_user(app: str, command_line: str, cwd: str | None = None) -> bool:
    """Запускает процесс с токеном оболочки Windows (explorer.exe), то есть без наших прав.

    Так устроен образец RunAsDesktopUser из Windows SDK: берётся токен процесса,
    владеющего рабочим столом, и через CreateProcessWithTokenW запускается новый
    процесс от имени того, кто сидит за компьютером, с обычными правами.
    """
    hwnd = user32.GetShellWindow()
    if not hwnd:
        log.debug("Нет окна оболочки — некому передать запуск")
        return False
    pid = wintypes.DWORD()
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    if not pid.value:
        return False
    _enable_privilege("SeIncreaseQuotaPrivilege")
    _enable_privilege("SeImpersonatePrivilege")
    process = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, pid.value)
    if not process:
        log.debug("OpenProcess(оболочка) не удался: WinError %d", ctypes.get_last_error())
        return False
    shell_token = wintypes.HANDLE()
    primary = wintypes.HANDLE()
    try:
        if not advapi32.OpenProcessToken(process, TOKEN_DUPLICATE, ctypes.byref(shell_token)):
            log.debug("OpenProcessToken(оболочка) не удался: WinError %d", ctypes.get_last_error())
            return False
        access = TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID
        if not advapi32.DuplicateTokenEx(shell_token, access, None, SECURITY_IMPERSONATION, TOKEN_PRIMARY,
                                         ctypes.byref(primary)):
            log.debug("DuplicateTokenEx не удался: WinError %d", ctypes.get_last_error())
            return False
        si = STARTUPINFOW()
        si.cb = ctypes.sizeof(si)
        pi = PROCESS_INFORMATION()
        buf = ctypes.create_unicode_buffer(command_line)
        if not advapi32.CreateProcessWithTokenW(primary, 0, app, buf, 0, None, cwd or windows_dir(),
                                                ctypes.byref(si), ctypes.byref(pi)):
            log.debug("CreateProcessWithTokenW не удался: WinError %d", ctypes.get_last_error())
            return False
        kernel32.CloseHandle(pi.hThread)
        kernel32.CloseHandle(pi.hProcess)
        return True
    finally:
        for handle in (primary, shell_token):
            if handle:
                kernel32.CloseHandle(handle)
        kernel32.CloseHandle(process)


_URL = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]+:")


def open_unelevated(target: str) -> bool:
    """Открывает ссылку (https://, tg://) или папку от имени обычного пользователя.

    Браузер, Telegram и Проводник не должны получать права администратора. Без наших
    прав запуск идёт напрямую. Возвращает False, если открыть не удалось.
    """
    if not is_admin():
        try:
            os.startfile(target)  # noqa: S606 — ShellExecute с правами пользователя
            return True
        except OSError as exc:
            log.warning("Не удалось открыть %s: %s", target[:100], exc)
            return False
    if _URL.match(target):
        # Ссылку разбирает штатный обработчик протокола — так же, как при щелчке по ней.
        app = system32("rundll32.exe")
        command = f'"{app}" url.dll,FileProtocolHandler {target}'
    else:
        app = os.path.join(windows_dir(), "explorer.exe")
        command = f'"{app}" "{target}"'
    if run_as_desktop_user(app, command):
        return True
    # Без службы «Вторичный вход в систему» токен оболочки не применить. Тогда для веб-ссылок,
    # параметров Windows и папок — новый explorer.exe: он передаёт запрос уже работающей оболочке.
    # Ссылки других протоколов (tg://) он не понимает и открыл бы «Документы», поэтому для них — отказ.
    if not _URL.match(target) or target.lower().startswith(("https://", "http://", "ms-settings:")):
        explorer = os.path.join(windows_dir(), "explorer.exe")
        try:
            subprocess.Popen([explorer, target], creationflags=CREATE_NO_WINDOW, close_fds=True)
            return True
        except OSError as exc:
            log.warning("explorer.exe не открыл %s: %s", target[:100], exc)
    log.warning("Не удалось открыть %s от имени пользователя", target[:100])
    return False


# ------------------------------------------------------------ буфер обмена

user32.OpenClipboard.argtypes = [wintypes.HWND]
user32.OpenClipboard.restype = wintypes.BOOL
user32.EmptyClipboard.restype = wintypes.BOOL
user32.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]
user32.SetClipboardData.restype = wintypes.HANDLE
user32.CloseClipboard.restype = wintypes.BOOL
kernel32.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
kernel32.GlobalAlloc.restype = wintypes.HGLOBAL
kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]
kernel32.GlobalLock.restype = ctypes.c_void_p
kernel32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
kernel32.GlobalUnlock.restype = wintypes.BOOL
kernel32.GlobalFree.argtypes = [wintypes.HGLOBAL]
kernel32.GlobalFree.restype = wintypes.HGLOBAL


def set_clipboard(text: str) -> bool:
    data = ctypes.create_unicode_buffer(text)
    size = ctypes.sizeof(data)
    for _ in range(10):
        if user32.OpenClipboard(None):
            break
        threading.Event().wait(0.05)
    else:
        return False
    try:
        user32.EmptyClipboard()
        handle = kernel32.GlobalAlloc(0x0002, size)  # GMEM_MOVEABLE
        if not handle:
            return False
        ptr = kernel32.GlobalLock(handle)
        if not ptr:
            kernel32.GlobalFree(handle)
            return False
        ctypes.memmove(ptr, data, size)
        kernel32.GlobalUnlock(handle)
        if not user32.SetClipboardData(13, handle):  # CF_UNICODETEXT
            kernel32.GlobalFree(handle)
            return False
        return True
    finally:
        user32.CloseClipboard()


def message_box(text: str, title: str, error: bool = False) -> None:
    user32.MessageBoxW(None, text, title, 0x10 if error else 0x40)


# ------------------------------------------------------------ DNS

def flush_dns() -> bool:
    try:
        dnsapi = ctypes.WinDLL("dnsapi")
        return bool(dnsapi.DnsFlushResolverCache())
    except (OSError, AttributeError):
        return False


# ------------------------------------------------------------ службы

SC_MANAGER_CONNECT = 0x0001
SC_MANAGER_CREATE_SERVICE = 0x0002
SC_MANAGER_ENUMERATE_SERVICE = 0x0004
SERVICE_QUERY_CONFIG = 0x0001
SERVICE_CHANGE_CONFIG = 0x0002
SERVICE_QUERY_STATUS = 0x0004
SERVICE_START = 0x0010
SERVICE_STOP = 0x0020
DELETE = 0x00010000
SERVICE_ALL_ACCESS = 0x000F01FF

SERVICE_WIN32_OWN_PROCESS = 0x10
SERVICE_WIN32 = 0x30
SERVICE_DRIVER = 0x0B
SERVICE_AUTO_START = 2
SERVICE_DEMAND_START = 3
SERVICE_ERROR_NORMAL = 1
SERVICE_NO_CHANGE = 0xFFFFFFFF
SERVICE_CONTROL_STOP = 1

ERROR_SERVICE_DOES_NOT_EXIST = 1060
ERROR_SERVICE_NOT_ACTIVE = 1062
ERROR_SERVICE_ALREADY_RUNNING = 1056
ERROR_SERVICE_MARKED_FOR_DELETE = 1072
ERROR_INSUFFICIENT_BUFFER = 122
ERROR_MORE_DATA = 234

STATE_NAMES = {1: "stopped", 2: "start_pending", 3: "stop_pending", 4: "running",
               5: "continue_pending", 6: "pause_pending", 7: "paused"}


class SERVICE_STATUS(ctypes.Structure):
    _fields_ = [(n, wintypes.DWORD) for n in (
        "dwServiceType", "dwCurrentState", "dwControlsAccepted", "dwWin32ExitCode",
        "dwServiceSpecificExitCode", "dwCheckPoint", "dwWaitHint")]


class SERVICE_STATUS_PROCESS(ctypes.Structure):
    _fields_ = [(n, wintypes.DWORD) for n in (
        "dwServiceType", "dwCurrentState", "dwControlsAccepted", "dwWin32ExitCode",
        "dwServiceSpecificExitCode", "dwCheckPoint", "dwWaitHint", "dwProcessId", "dwServiceFlags")]


class ENUM_SERVICE_STATUS_PROCESSW(ctypes.Structure):
    _fields_ = [
        ("lpServiceName", wintypes.LPWSTR),
        ("lpDisplayName", wintypes.LPWSTR),
        ("ServiceStatusProcess", SERVICE_STATUS_PROCESS),
    ]


class QUERY_SERVICE_CONFIGW(ctypes.Structure):
    _fields_ = [
        ("dwServiceType", wintypes.DWORD),
        ("dwStartType", wintypes.DWORD),
        ("dwErrorControl", wintypes.DWORD),
        ("lpBinaryPathName", wintypes.LPWSTR),
        ("lpLoadOrderGroup", wintypes.LPWSTR),
        ("dwTagId", wintypes.DWORD),
        ("lpDependencies", wintypes.LPWSTR),
        ("lpServiceStartName", wintypes.LPWSTR),
        ("lpDisplayName", wintypes.LPWSTR),
    ]


class SERVICE_DESCRIPTIONW(ctypes.Structure):
    _fields_ = [("lpDescription", wintypes.LPWSTR)]


SC_HANDLE = wintypes.HANDLE
advapi32.OpenSCManagerW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
advapi32.OpenSCManagerW.restype = SC_HANDLE
advapi32.OpenServiceW.argtypes = [SC_HANDLE, wintypes.LPCWSTR, wintypes.DWORD]
advapi32.OpenServiceW.restype = SC_HANDLE
advapi32.CloseServiceHandle.argtypes = [SC_HANDLE]
advapi32.CloseServiceHandle.restype = wintypes.BOOL
advapi32.QueryServiceStatusEx.argtypes = [SC_HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
                                          ctypes.POINTER(wintypes.DWORD)]
advapi32.QueryServiceStatusEx.restype = wintypes.BOOL
advapi32.QueryServiceConfigW.argtypes = [SC_HANDLE, ctypes.c_void_p, wintypes.DWORD,
                                         ctypes.POINTER(wintypes.DWORD)]
advapi32.QueryServiceConfigW.restype = wintypes.BOOL
advapi32.CreateServiceW.argtypes = [SC_HANDLE, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
                                    wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.LPCWSTR,
                                    wintypes.LPCWSTR, ctypes.c_void_p, wintypes.LPCWSTR,
                                    wintypes.LPCWSTR, wintypes.LPCWSTR]
advapi32.CreateServiceW.restype = SC_HANDLE
advapi32.ChangeServiceConfigW.argtypes = [SC_HANDLE, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
                                          wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.c_void_p,
                                          wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR,
                                          wintypes.LPCWSTR]
advapi32.ChangeServiceConfigW.restype = wintypes.BOOL
advapi32.ChangeServiceConfig2W.argtypes = [SC_HANDLE, wintypes.DWORD, ctypes.c_void_p]
advapi32.ChangeServiceConfig2W.restype = wintypes.BOOL
advapi32.StartServiceW.argtypes = [SC_HANDLE, wintypes.DWORD, ctypes.c_void_p]
advapi32.StartServiceW.restype = wintypes.BOOL
advapi32.ControlService.argtypes = [SC_HANDLE, wintypes.DWORD, ctypes.POINTER(SERVICE_STATUS)]
advapi32.ControlService.restype = wintypes.BOOL
advapi32.DeleteService.argtypes = [SC_HANDLE]
advapi32.DeleteService.restype = wintypes.BOOL
advapi32.EnumServicesStatusExW.argtypes = [SC_HANDLE, ctypes.c_int, wintypes.DWORD, wintypes.DWORD,
                                           ctypes.c_void_p, wintypes.DWORD,
                                           ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
                                           ctypes.POINTER(wintypes.DWORD), wintypes.LPCWSTR]
advapi32.EnumServicesStatusExW.restype = wintypes.BOOL


class ServiceError(OSError):
    pass


def _err(action: str, name: str) -> ServiceError:
    code = ctypes.get_last_error()
    return ServiceError(code, f"{action} «{name}»: {ctypes.FormatError(code).strip()} (WinError {code})")


class _Scm:
    def __init__(self, access: int):
        self.handle = advapi32.OpenSCManagerW(None, None, access)
        if not self.handle:
            raise _err("Не открыт диспетчер служб для", "SCM")

    def __enter__(self):
        return self.handle

    def __exit__(self, *exc):
        advapi32.CloseServiceHandle(self.handle)


@dataclass
class ServiceInfo:
    name: str
    state: str
    pid: int
    binary: str | None = None
    start_type: int | None = None


def _status(handle) -> SERVICE_STATUS_PROCESS:
    status = SERVICE_STATUS_PROCESS()
    needed = wintypes.DWORD()
    if not advapi32.QueryServiceStatusEx(handle, 0, ctypes.byref(status), ctypes.sizeof(status),
                                         ctypes.byref(needed)):
        raise _err("Не получено состояние службы", "?")
    return status


def service_query(name: str, with_config: bool = False) -> ServiceInfo | None:
    """Состояние службы или None, если её нет."""
    try:
        with _Scm(SC_MANAGER_CONNECT) as scm:
            access = SERVICE_QUERY_STATUS | (SERVICE_QUERY_CONFIG if with_config else 0)
            handle = advapi32.OpenServiceW(scm, name, access)
            if not handle:
                if ctypes.get_last_error() == ERROR_SERVICE_DOES_NOT_EXIST:
                    return None
                raise _err("Не открыта служба", name)
            try:
                st = _status(handle)
                info = ServiceInfo(name, STATE_NAMES.get(st.dwCurrentState, "unknown"), st.dwProcessId)
                if with_config:
                    needed = wintypes.DWORD()
                    advapi32.QueryServiceConfigW(handle, None, 0, ctypes.byref(needed))
                    buf = ctypes.create_string_buffer(max(needed.value, ctypes.sizeof(QUERY_SERVICE_CONFIGW)))
                    if advapi32.QueryServiceConfigW(handle, buf, len(buf), ctypes.byref(needed)):
                        cfg = ctypes.cast(buf, ctypes.POINTER(QUERY_SERVICE_CONFIGW)).contents
                        info.binary = cfg.lpBinaryPathName
                        info.start_type = cfg.dwStartType
                return info
            finally:
                advapi32.CloseServiceHandle(handle)
    except ServiceError as exc:
        log.debug("service_query(%s): %s", name, exc)
        return None


def service_list(drivers: bool = False) -> list[tuple[str, str, str]]:
    """Список служб: (имя, отображаемое имя, состояние)."""
    result: list[tuple[str, str, str]] = []
    try:
        with _Scm(SC_MANAGER_ENUMERATE_SERVICE) as scm:
            kind = SERVICE_DRIVER if drivers else SERVICE_WIN32
            needed = wintypes.DWORD()
            count = wintypes.DWORD()
            resume = wintypes.DWORD(0)
            size = 64 * 1024
            while True:
                buf = ctypes.create_string_buffer(size)
                ok = advapi32.EnumServicesStatusExW(scm, 0, kind, 3, buf, size, ctypes.byref(needed),
                                                    ctypes.byref(count), ctypes.byref(resume), None)
                err = ctypes.get_last_error()
                entries = ctypes.cast(buf, ctypes.POINTER(ENUM_SERVICE_STATUS_PROCESSW))
                for i in range(count.value):
                    e = entries[i]
                    result.append((e.lpServiceName or "", e.lpDisplayName or "",
                                   STATE_NAMES.get(e.ServiceStatusProcess.dwCurrentState, "unknown")))
                if ok:
                    break
                if err != ERROR_MORE_DATA:
                    break
                size = max(size, needed.value + 1024)
    except ServiceError as exc:
        log.debug("service_list: %s", exc)
    return result


def service_create_or_update(name: str, display: str, binary: str, description: str,
                             auto_start: bool = True, depends_on: tuple[str, ...] = (),
                             restart_on_failure: bool = False) -> None:
    start = SERVICE_AUTO_START if auto_start else SERVICE_DEMAND_START
    # Список зависимостей — строки через \0 с двумя \0 в конце.
    deps = ctypes.create_unicode_buffer("\0".join(depends_on) + "\0") if depends_on else None
    with _Scm(SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE) as scm:
        handle = advapi32.OpenServiceW(scm, name, SERVICE_ALL_ACCESS)
        if handle:
            try:
                if not advapi32.ChangeServiceConfigW(handle, SERVICE_WIN32_OWN_PROCESS, start,
                                                     SERVICE_ERROR_NORMAL, binary, None, None, deps,
                                                     None, None, display):
                    raise _err("Не изменена служба", name)
                _set_description(handle, description)
                if restart_on_failure:
                    _set_restart_on_failure(handle)
            finally:
                advapi32.CloseServiceHandle(handle)
            return
        if ctypes.get_last_error() != ERROR_SERVICE_DOES_NOT_EXIST:
            raise _err("Не открыта служба", name)
        handle = advapi32.CreateServiceW(scm, name, display, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                                         start, SERVICE_ERROR_NORMAL, binary, None, None, deps, None, None)
        if not handle:
            raise _err("Не создана служба", name)
        try:
            _set_description(handle, description)
            if restart_on_failure:
                _set_restart_on_failure(handle)
        finally:
            advapi32.CloseServiceHandle(handle)


class SC_ACTION(ctypes.Structure):
    _fields_ = [("Type", wintypes.DWORD), ("Delay", wintypes.DWORD)]


class SERVICE_FAILURE_ACTIONSW(ctypes.Structure):
    _fields_ = [("dwResetPeriod", wintypes.DWORD), ("lpRebootMsg", wintypes.LPWSTR),
                ("lpCommand", wintypes.LPWSTR), ("cActions", wintypes.DWORD),
                ("lpsaActions", ctypes.POINTER(SC_ACTION))]


def _set_restart_on_failure(handle) -> None:
    """Если служба упадёт, Windows перезапустит её через 5, 15 и 60 секунд; счётчик — сутки."""
    actions = (SC_ACTION * 3)(SC_ACTION(1, 5_000), SC_ACTION(1, 15_000), SC_ACTION(1, 60_000))
    cfg = SERVICE_FAILURE_ACTIONSW(86_400, None, None, 3, actions)
    if not advapi32.ChangeServiceConfig2W(handle, 2, ctypes.byref(cfg)):  # SERVICE_CONFIG_FAILURE_ACTIONS
        log.warning("Не удалось включить перезапуск службы при сбое: WinError %d", ctypes.get_last_error())


def _set_description(handle, text: str) -> None:
    desc = SERVICE_DESCRIPTIONW(text)
    advapi32.ChangeServiceConfig2W(handle, 1, ctypes.byref(desc))


def service_start(name: str) -> None:
    with _Scm(SC_MANAGER_CONNECT) as scm:
        handle = advapi32.OpenServiceW(scm, name, SERVICE_START | SERVICE_QUERY_STATUS)
        if not handle:
            raise _err("Не открыта служба", name)
        try:
            if not advapi32.StartServiceW(handle, 0, None):
                if ctypes.get_last_error() != ERROR_SERVICE_ALREADY_RUNNING:
                    raise _err("Не запущена служба", name)
        finally:
            advapi32.CloseServiceHandle(handle)


def service_stop(name: str, wait: float = 10.0) -> bool:
    """Останавливает службу и ждёт остановки.

    True — служба остановлена (или её нет), False — не остановилась за `wait` секунд.
    """
    with _Scm(SC_MANAGER_CONNECT) as scm:
        handle = advapi32.OpenServiceW(scm, name, SERVICE_STOP | SERVICE_QUERY_STATUS)
        if not handle:
            if ctypes.get_last_error() == ERROR_SERVICE_DOES_NOT_EXIST:
                return True
            raise _err("Не открыта служба", name)
        try:
            status = SERVICE_STATUS()
            if not advapi32.ControlService(handle, SERVICE_CONTROL_STOP, ctypes.byref(status)):
                err = ctypes.get_last_error()
                if err != ERROR_SERVICE_NOT_ACTIVE:
                    raise _err("Не остановлена служба", name)
            deadline = time.monotonic() + wait
            while time.monotonic() < deadline:
                if _status(handle).dwCurrentState == 1:
                    return True
                time.sleep(0.2)
            return _status(handle).dwCurrentState == 1
        finally:
            advapi32.CloseServiceHandle(handle)


def service_delete(name: str) -> bool:
    """Останавливает и удаляет службу. False — службы не было."""
    try:
        service_stop(name)
    except ServiceError as exc:
        log.debug("Остановка %s перед удалением: %s", name, exc)
    with _Scm(SC_MANAGER_CONNECT) as scm:
        handle = advapi32.OpenServiceW(scm, name, DELETE | SERVICE_QUERY_STATUS)
        if not handle:
            if ctypes.get_last_error() == ERROR_SERVICE_DOES_NOT_EXIST:
                return False
            raise _err("Не открыта служба", name)
        try:
            if not advapi32.DeleteService(handle):
                if ctypes.get_last_error() != ERROR_SERVICE_MARKED_FOR_DELETE:
                    raise _err("Не удалена служба", name)
            return True
        finally:
            advapi32.CloseServiceHandle(handle)
