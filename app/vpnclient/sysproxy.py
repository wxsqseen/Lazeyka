"""Системный прокси Windows (WinINet) для режима «Системный прокси» своего VPN.

Настройки — per-connection: у локальной сети (LAN) и у каждого подключения RAS (PPPoE, L2TP провайдера)
свои. Перед изменением все поля всех подключений сохраняются в DATA/sysproxy-backup.json (вне закрытой
папки: секретов там нет, а вернуть прокси после аварии нужно уметь и без прав). Возвращаем только то,
что всё ещё указывает на наш адрес: прокси, который с тех пор поменял человек или другая программа,
не трогаем. Все вызовы WinAPI — через внедряемый бэкенд (в тестах подделка).
"""
from __future__ import annotations

import ctypes
import json
import logging
import os
import threading
import time
from ctypes import wintypes
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Protocol

from .. import winutil
from ..errors import UserError
from . import guard

log = logging.getLogger("lazeyka.vpnclient.sysproxy")

INTERNET_OPTION_REFRESH = 37
INTERNET_OPTION_SETTINGS_CHANGED = 39
INTERNET_OPTION_PER_CONNECTION_OPTION = 75
INTERNET_PER_CONN_FLAGS = 1
INTERNET_PER_CONN_PROXY_SERVER = 2
INTERNET_PER_CONN_PROXY_BYPASS = 3
INTERNET_PER_CONN_AUTOCONFIG_URL = 4
INTERNET_PER_CONN_FLAGS_UI = 10      # для чтения: флаги, как их показывает окно настроек (Windows 7+)
PROXY_TYPE_DIRECT = 0x1
PROXY_TYPE_PROXY = 0x2
PROXY_TYPE_AUTO_PROXY_URL = 0x4
PROXY_TYPE_AUTO_DETECT = 0x8
ERROR_BUFFER_TOO_SMALL = 603
BACKUP_SCHEMA = 1

Connection = str | None              # None — локальная сеть (LAN), иначе имя подключения RAS


class SysProxyError(UserError):
    pass


@dataclass
class ProxySettings:
    flags: int = PROXY_TYPE_DIRECT
    server: str = ""
    bypass: str = ""
    autoconfig_url: str = ""

    def points_to(self, address: str) -> bool:
        """Прокси включён и указывает на address (у нас — один сервер на все протоколы)."""
        if not self.flags & PROXY_TYPE_PROXY:
            return False
        servers = [part.split("=", 1)[-1].strip() for part in self.server.split(";") if part.strip()]
        return bool(servers) and all(s.lower() == address.lower() for s in servers)

    @classmethod
    def from_dict(cls, data: dict) -> "ProxySettings":
        flags = data.get("flags")
        return cls(flags=flags if isinstance(flags, int) else PROXY_TYPE_DIRECT,
                   server=str(data.get("server") or ""), bypass=str(data.get("bypass") or ""),
                   autoconfig_url=str(data.get("autoconfig_url") or ""))


class Backend(Protocol):
    def connections(self) -> list[Connection]: ...
    def query(self, connection: Connection) -> ProxySettings: ...
    def apply(self, connection: Connection, settings: ProxySettings) -> None: ...
    def refresh(self) -> None: ...


# ------------------------------------------------------------ настоящий WinINet

class _VALUE(ctypes.Union):
    # pszValue — указатель: строки от InternetQueryOptionW освобождаются GlobalFree
    _fields_ = [("dwValue", wintypes.DWORD), ("pszValue", ctypes.c_void_p), ("ftValue", wintypes.FILETIME)]


class INTERNET_PER_CONN_OPTIONW(ctypes.Structure):
    _fields_ = [("dwOption", wintypes.DWORD), ("Value", _VALUE)]


class INTERNET_PER_CONN_OPTION_LISTW(ctypes.Structure):
    _fields_ = [("dwSize", wintypes.DWORD), ("pszConnection", wintypes.LPWSTR), ("dwOptionCount", wintypes.DWORD),
                ("dwOptionError", wintypes.DWORD), ("pOptions", ctypes.POINTER(INTERNET_PER_CONN_OPTIONW))]


class RASENTRYNAMEW(ctypes.Structure):
    _fields_ = [("dwSize", wintypes.DWORD), ("szEntryName", wintypes.WCHAR * 257), ("dwFlags", wintypes.DWORD),
                ("szPhonebookPath", wintypes.WCHAR * 261)]


class WinInet:
    """InternetQueryOptionW/InternetSetOptionW и список подключений RAS."""

    def __init__(self) -> None:
        self._inet = ctypes.WinDLL(winutil.system32("wininet.dll"), use_last_error=True)
        for name in ("InternetQueryOptionW", "InternetSetOptionW"):
            fn = getattr(self._inet, name)
            fn.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p,
                           ctypes.POINTER(wintypes.DWORD) if name == "InternetQueryOptionW" else wintypes.DWORD]
            fn.restype = wintypes.BOOL
        self._kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self._kernel.GlobalFree.argtypes = [ctypes.c_void_p]
        self._kernel.GlobalFree.restype = ctypes.c_void_p

    def connections(self) -> list[Connection]:
        return [None, *self._ras_entries()]

    def _ras_entries(self) -> list[str]:
        try:
            ras = ctypes.WinDLL(winutil.system32("rasapi32.dll"))
        except OSError:
            return []
        fn = ras.RasEnumEntriesW
        fn.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD),
                       ctypes.POINTER(wintypes.DWORD)]
        fn.restype = wintypes.DWORD
        count = 8
        for _ in range(3):
            entries = (RASENTRYNAMEW * count)()
            entries[0].dwSize = ctypes.sizeof(RASENTRYNAMEW)
            size, found = wintypes.DWORD(ctypes.sizeof(entries)), wintypes.DWORD(0)
            ret = fn(None, None, entries, ctypes.byref(size), ctypes.byref(found))
            if ret == ERROR_BUFFER_TOO_SMALL:
                count = size.value // ctypes.sizeof(RASENTRYNAMEW) + 1
                continue
            if ret != 0:
                log.debug("RasEnumEntriesW: ошибка %d", ret)
                return []
            return [entries[i].szEntryName for i in range(found.value) if entries[i].szEntryName]
        return []

    def _option_list(self, connection: Connection, options) -> INTERNET_PER_CONN_OPTION_LISTW:
        lst = INTERNET_PER_CONN_OPTION_LISTW()
        lst.dwSize = ctypes.sizeof(lst)
        lst.pszConnection = connection
        lst.dwOptionCount = len(options)
        lst.pOptions = options
        return lst

    def query(self, connection: Connection) -> ProxySettings:
        for flags_option in (INTERNET_PER_CONN_FLAGS_UI, INTERNET_PER_CONN_FLAGS):
            opts = (INTERNET_PER_CONN_OPTIONW * 4)()
            for i, option in enumerate((flags_option, INTERNET_PER_CONN_PROXY_SERVER,
                                        INTERNET_PER_CONN_PROXY_BYPASS, INTERNET_PER_CONN_AUTOCONFIG_URL)):
                opts[i].dwOption = option
            lst = self._option_list(connection, opts)
            size = wintypes.DWORD(ctypes.sizeof(lst))
            if self._inet.InternetQueryOptionW(None, INTERNET_OPTION_PER_CONNECTION_OPTION, ctypes.byref(lst),
                                               ctypes.byref(size)):
                return ProxySettings(int(opts[0].Value.dwValue), self._take(opts[1]), self._take(opts[2]),
                                     self._take(opts[3]))
        err = ctypes.get_last_error()
        raise SysProxyError(f"Не удалось прочитать настройки прокси «{connection or 'локальная сеть'}» (ошибка {err})")

    def _take(self, opt: INTERNET_PER_CONN_OPTIONW) -> str:
        ptr = opt.Value.pszValue
        if not ptr:
            return ""
        try:
            return ctypes.wstring_at(ptr)
        finally:
            self._kernel.GlobalFree(ptr)

    def apply(self, connection: Connection, settings: ProxySettings) -> None:
        buffers = [ctypes.create_unicode_buffer(v) for v in (settings.server, settings.bypass, settings.autoconfig_url)]
        opts = (INTERNET_PER_CONN_OPTIONW * 4)()
        opts[0].dwOption, opts[0].Value.dwValue = INTERNET_PER_CONN_FLAGS, settings.flags
        for i, (option, buf) in enumerate(zip((INTERNET_PER_CONN_PROXY_SERVER, INTERNET_PER_CONN_PROXY_BYPASS,
                                               INTERNET_PER_CONN_AUTOCONFIG_URL), buffers), start=1):
            opts[i].dwOption = option
            opts[i].Value.pszValue = ctypes.cast(buf, ctypes.c_void_p).value
        lst = self._option_list(connection, opts)
        if not self._inet.InternetSetOptionW(None, INTERNET_OPTION_PER_CONNECTION_OPTION, ctypes.byref(lst),
                                             ctypes.sizeof(lst)):
            err = ctypes.get_last_error()
            raise SysProxyError(f"Не удалось изменить прокси «{connection or 'локальная сеть'}» (ошибка {err})")

    def refresh(self) -> None:
        """Сообщить программам, что настройки поменялись."""
        self._inet.InternetSetOptionW(None, INTERNET_OPTION_SETTINGS_CHANGED, None, 0)
        self._inet.InternetSetOptionW(None, INTERNET_OPTION_REFRESH, None, 0)


# ------------------------------------------------------------ чей это прокси

_TOKEN_QUERY = 0x0008
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_TOKEN_USER_CLASS = 1


class _SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]


def _token_user_sid(process: int) -> str | None:
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
                                           ctypes.POINTER(wintypes.DWORD)]
    advapi.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    token = wintypes.HANDLE()
    if not advapi.OpenProcessToken(process, _TOKEN_QUERY, ctypes.byref(token)):
        return None
    try:
        needed = wintypes.DWORD()
        advapi.GetTokenInformation(token, _TOKEN_USER_CLASS, None, 0, ctypes.byref(needed))
        if not needed.value:
            return None
        buf = ctypes.create_string_buffer(needed.value)
        if not advapi.GetTokenInformation(token, _TOKEN_USER_CLASS, buf, needed, ctypes.byref(needed)):
            return None
        sid = ctypes.cast(buf, ctypes.POINTER(_SID_AND_ATTRIBUTES)).contents.Sid
        text = wintypes.LPWSTR()
        if not advapi.ConvertSidToStringSidW(sid, ctypes.byref(text)):
            return None
        try:
            return text.value
        finally:
            kernel.LocalFree(text)
    finally:
        kernel.CloseHandle(token)


def process_user_sid() -> str | None:
    return _token_user_sid(winutil.kernel32.GetCurrentProcess())


def shell_user_sid() -> str | None:
    """Учётная запись того, кто сидит за компьютером (владелец окна оболочки)."""
    hwnd = winutil.user32.GetShellWindow()
    if not hwnd:
        return None
    pid = wintypes.DWORD()
    winutil.user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    if not pid.value:
        return None
    process = winutil.kernel32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid.value)
    if not process:
        return None
    try:
        return _token_user_sid(process)
    finally:
        winutil.kernel32.CloseHandle(process)


def shell_user_matches() -> bool | None:
    """Совпадает ли учётная запись Лазейки с владельцем рабочего стола; None — не удалось узнать."""
    mine, shell = process_user_sid(), shell_user_sid()
    if not mine or not shell:
        return None
    return mine == shell


# ------------------------------------------------------------ системный прокси Лазейки

class SysProxy:
    """apply/restore/turn_off — под одной блокировкой: выход Лазейки восстанавливает прокси из своего
    потока, пока очередь менеджера может ещё включать его. После close() новых включений нет."""

    def __init__(self, backup_path: Path, *, backend: Backend | None = None,
                 same_user: Callable[[], bool | None] = shell_user_matches):
        self.backup_path = Path(backup_path)
        self._backend = backend
        self._real = backend is None
        self._same_user = same_user
        self._lock = threading.RLock()
        self._closed = False

    def close(self) -> None:
        """Лазейка закрывается: начатое включение доработает, новые — отказ (восстанавливать их будет некому)."""
        with self._lock:
            self._closed = True

    @property
    def backend(self) -> Backend:
        if self._backend is None:
            self._backend = WinInet()
        return self._backend

    def _guard(self, action: str) -> None:
        if self._real:
            guard.ensure_allowed(action)

    def current(self) -> list[dict]:
        """Настройки всех подключений: [{name, flags, server, bypass, autoconfig_url}]."""
        out = []
        for conn in self.backend.connections():
            out.append({"name": conn, **asdict(self.backend.query(conn))})
        return out

    def owned_address(self) -> str | None:
        """Наш адрес, если резервная копия есть (прокси сейчас наш или остался после аварии)."""
        backup = self._load_backup()
        return backup["address"] if backup else None

    def available(self) -> str | None:
        """Причина, по которой режим прокси недоступен, или None. Только причина, без совета: что делать,
        говорит место показа (окно конфликта, плашка — свой совет у каждого; apply — режим «Весь трафик»)."""
        if self._same_user() is False:
            # В окне UAC ввели пароль другого администратора: HKCU Лазейки — чужой, прокси не подействует.
            return "Системный прокси здесь недоступен: Лазейка запущена от другой учётной записи"
        return None

    def apply(self, host: str, port: int, override: list[str]) -> None:
        """Включить прокси host:port на LAN и всех подключениях RAS; резервная копия — до изменений."""
        self._guard("системный прокси")
        reason = self.available()
        if reason:
            raise SysProxyError(f"{reason} (в окне UAC ввели пароль другого администратора). Включите режим "
                                "«Весь трафик» или запустите Лазейку из своей учётной записи.")
        with self._lock:
            if self._closed:
                raise SysProxyError("Лазейка закрывается — системный прокси не включаю")
            self._apply(host, port, override)

    def _apply(self, host: str, port: int, override: list[str]) -> None:
        address = f"{host}:{int(port)}"
        bypass = ";".join(dict.fromkeys(["<local>", *[x.strip() for x in override if x and x.strip()]]))
        previous = self._load_backup()
        saved_before = {c["name"]: c for c in previous["connections"]} if previous else {}
        ours = {address} | ({previous["address"]} if previous else set())
        connections = self.backend.connections()
        originals: dict[Connection, ProxySettings] = {}
        for conn in connections:
            cur = self.backend.query(conn)
            if any(cur.points_to(a) for a in ours):
                # Уже наш (повторное включение, авария): в копии — то, что было до нас; копии нет — «напрямую».
                originals[conn] = ProxySettings.from_dict(saved_before.get(conn, {}))
            else:
                originals[conn] = cur
        self._save_backup(address, originals)
        changed: list[Connection] = []
        try:
            for conn in connections:
                self.backend.apply(conn, ProxySettings(PROXY_TYPE_DIRECT | PROXY_TYPE_PROXY, address, bypass,
                                                       originals[conn].autoconfig_url))
                changed.append(conn)
        except (OSError, SysProxyError) as exc:
            for conn in changed:
                try:
                    self.backend.apply(conn, originals[conn])
                except (OSError, SysProxyError):
                    log.exception("Прокси «%s» не вернулся после ошибки", conn or "LAN")
            self.backend.refresh()
            raise SysProxyError(f"Системный прокси не включился: {exc}") from exc
        self.backend.refresh()
        log.info("Системный прокси → %s (подключений: %d)", address, len(connections))

    def restore(self) -> dict:
        """Вернуть сохранённые настройки там, где прокси всё ещё наш. {restored, skipped, failed}.

        Ошибка одного подключения не прерывает остальные. Если что-то не вернулось, резервная копия
        остаётся: следующая остановка или запуск Лазейки повторят (трогаем только то, что ещё наше)."""
        self._guard("системный прокси")
        with self._lock:
            return self._restore()

    def _restore(self) -> dict:
        backup = self._load_backup()
        if backup is None:
            return {"restored": 0, "skipped": 0, "failed": 0}
        saved = {c["name"]: ProxySettings.from_dict(c) for c in backup["connections"]}
        restored = skipped = 0
        failed: list[str] = []
        try:
            connections = self.backend.connections()
        except (OSError, SysProxyError) as exc:
            raise SysProxyError(f"Список подключений Windows не прочитан: {exc}") from exc
        for conn in connections:
            try:
                if not self.backend.query(conn).points_to(backup["address"]):
                    skipped += 1      # прокси поменяли после нас — не наш, не трогаем
                    continue
                self.backend.apply(conn, saved.get(conn, ProxySettings()))
                restored += 1
            except (OSError, SysProxyError) as exc:
                failed.append(conn or "LAN")
                log.warning("Прокси подключения «%s» не возвращён: %s", conn or "LAN", exc)
        if restored:
            self.backend.refresh()
        if failed:
            log.warning("Системный прокси возвращён не везде (%s) — резервная копия остаётся для повтора",
                        ", ".join(failed))
            return {"restored": restored, "skipped": skipped, "failed": len(failed)}
        try:
            self.backup_path.unlink(missing_ok=True)
        except OSError as exc:
            # Без прав администратора папка данных только для чтения: копия останется, но вреда нет —
            # возвращаем мы только то, что всё ещё указывает на наш адрес.
            log.warning("Резервная копия прокси не удалена: %s", exc)
        log.info("Системный прокси возвращён: %d подключений, не наших — %d", restored, skipped)
        return {"restored": restored, "skipped": skipped, "failed": 0}

    def turn_off(self, address: str) -> int:
        """Снять галочку «прокси» там, где он указывает на address (мёртвый порт чужой программы) —
        только по кнопке «Помощи». Адрес и исключения остаются, как если бы галочку снял человек."""
        self._guard("системный прокси")
        with self._lock:
            changed = 0
            for conn in self.backend.connections():
                cur = self.backend.query(conn)
                if cur.points_to(address):
                    self.backend.apply(conn, ProxySettings((cur.flags & ~PROXY_TYPE_PROXY) | PROXY_TYPE_DIRECT,
                                                           cur.server, cur.bypass, cur.autoconfig_url))
                    changed += 1
            if changed:
                self.backend.refresh()
            return changed

    def recover_after_crash(self, port: int) -> dict | None:
        """При запуске Лазейки: прокси остался от прошлого сеанса (авария) — вернуть прежний."""
        backup = self._load_backup(default_address=f"127.0.0.1:{int(port)}")
        if backup is None:
            return None
        log.info("Найдена резервная копия системного прокси прошлого сеанса — возвращаю прежние настройки")
        return self.restore()

    # ---------------------------------------------------------------- резервная копия

    def _save_backup(self, address: str, originals: dict[Connection, ProxySettings]) -> None:
        data = {"schema": BACKUP_SCHEMA, "address": address, "saved_at": time.time(),
                "connections": [{"name": conn, **asdict(s)} for conn, s in originals.items()]}
        self.backup_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.backup_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(tmp, self.backup_path)

    def _load_backup(self, default_address: str | None = None) -> dict | None:
        try:
            data = json.loads(self.backup_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None
        except (OSError, ValueError) as exc:
            log.warning("Резервная копия прокси не читается: %s", exc)
            return None
        if not isinstance(data, dict) or not isinstance(data.get("connections"), list):
            return None
        address = data.get("address") if isinstance(data.get("address"), str) else default_address
        if not address:
            return None
        conns = [c for c in data["connections"] if isinstance(c, dict) and (c.get("name") is None
                                                                             or isinstance(c.get("name"), str))]
        return {"address": address, "connections": conns}
