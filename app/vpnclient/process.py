"""Процесс ядра (sing-box или помощник Xray): без окна, вывод в журнал, готовность, остановка.

По образцу zapret/runner.WinwsProcess. Ядро получает свою скрытую консоль (CREATE_NO_WINDOW) и свою
группу процессов. Мягкая остановка — CTRL_BREAK этой группе: Go превращает его в os.Interrupt, и ядро
само закрывает TUN и WFP-сессию. У exe Лазейки консоли нет (console=False), а событие доходит только до
процессов той же консоли, поэтому к консоли ядра сначала присоединяемся (AttachConsole).
"""
from __future__ import annotations

import collections
import ctypes
import logging
import re
import subprocess
import sys
import threading
import time
from ctypes import wintypes
from pathlib import Path
from typing import Callable

from .. import log as applog
from .. import paths, winutil
from ..errors import UserError
from . import guard

log = logging.getLogger("lazeyka.vpnclient.process")

CORE_LOGGER = "lazeyka.vpnclient.core"
TAIL_LINES = 200
SOFT_STOP = 2.0             # столько ядру на мягкую остановку, потом TerminateProcess
KILL_WAIT = 5.0
READY_POLL = 0.1
OUTPUT_DRAIN = 2.0          # дождаться, пока читатель допишет хвост вывода упавшего ядра
ERROR_ELEVATION_REQUIRED = 740
ERROR_ACCESS_DENIED = 5     # AttachConsole: процесс уже со своей консолью
CTRL_BREAK_EVENT = 1
DETACHED_PROCESS = 0x00000008

_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
# Уровень строки по префиксу: sing-box «FATAL[0000] …», Xray «2026/10/17 07:00:00 [Warning] …»
_LEVELS = (
    (re.compile(r"\b(PANIC|FATAL|ERROR)\[\d+\]|\[Error\]"), logging.ERROR),
    (re.compile(r"\bWARN\[\d+\]|\[Warning\]"), logging.WARNING),
    (re.compile(r"\b(DEBUG|TRACE)\[\d+\]|\[Debug\]"), logging.DEBUG),
)


class ProcessError(UserError):
    """Ядро не запустилось: текст для журнала, код и хвост вывода — для разбора причины (diagnose)."""

    def __init__(self, message: str, *, code: int | None = None, tail: list[str] | None = None):
        super().__init__(message)
        self.code = code
        self.tail = list(tail or [])


def line_level(line: str) -> int:
    for pattern, level in _LEVELS:
        if pattern.search(line):
            return level
    return logging.INFO


class CoreProcess:
    """Один процесс ядра. on_exit(code, tail) — ядро завершилось само после успешного старта."""

    def __init__(self, name: str, exe: Path, args: list[str], *, cwd: Path, log_name: str = CORE_LOGGER,
                 scrub: Callable[[str], str] = applog.scrub,
                 on_exit: Callable[[int, list[str]], None] | None = None, bind_to_app: bool = True):
        self.name = name
        self.exe = Path(exe)
        self.args = list(args)
        self.cwd = Path(cwd)
        self.scrub = scrub
        self.on_exit = on_exit
        self.bind_to_app = bind_to_app
        self.proc: subprocess.Popen | None = None
        self.started_at: float | None = None
        self._out = logging.getLogger(log_name)
        self._tail: collections.deque[str] = collections.deque(maxlen=TAIL_LINES)
        self._lock = threading.Lock()
        self._started = False       # готовность получена: дальше падение — дело on_exit
        self._stopping = False
        self._exited = threading.Event()
        self._reader: threading.Thread | None = None

    @property
    def pid(self) -> int | None:
        return self.proc.pid if self.proc else None

    @property
    def tail(self) -> list[str]:
        with self._lock:
            return list(self._tail)

    @property
    def returncode(self) -> int | None:
        return self.proc.poll() if self.proc else None

    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    # ---------------------------------------------------------------- запуск

    def start(self, ready: Callable[[], bool], timeout: float) -> None:
        """Запускает ядро и ждёт ready() — условия готовности (порты помощника, ответ clash API)."""
        guard.ensure_allowed("запуск ядра")
        log.info("Запуск %s", self.name)
        log.debug("Командная строка %s: %s", self.name, self.scrub(subprocess.list2cmdline([str(self.exe), *self.args])))
        try:
            self.proc = subprocess.Popen(
                [str(self.exe), *self.args], executable=str(self.exe), cwd=str(self.cwd),
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                creationflags=winutil.CREATE_NO_WINDOW | winutil.CREATE_NEW_PROCESS_GROUP)
        except OSError as exc:
            if getattr(exc, "winerror", None) == ERROR_ELEVATION_REQUIRED:
                raise ProcessError(f"Для запуска {self.name} нужны права администратора") from exc
            raise ProcessError(f"Не удалось запустить {self.name}: {exc}") from exc
        self.started_at = time.time()
        if self.bind_to_app and not winutil.kill_with_app(int(self.proc._handle)):  # noqa: SLF001
            log.debug("%s не привязан к job-объекту", self.name)
        self._reader = threading.Thread(target=self._read_output, name=f"{self.name}-out", daemon=True)
        self._reader.start()
        threading.Thread(target=self._watch, name=f"{self.name}-watch", daemon=True).start()
        self._wait_ready(ready, timeout)

    def _wait_ready(self, ready: Callable[[], bool], timeout: float) -> None:
        deadline = time.monotonic() + timeout
        while True:
            if self._exited.is_set():
                raise self._early_exit()
            if self._probe(ready):
                with self._lock:
                    if not self._exited.is_set():
                        self._started = True
                        log.info("%s готов, pid %d", self.name, self.pid)
                        return
                raise self._early_exit()
            if time.monotonic() >= deadline:
                tail = self.tail
                self.stop(soft=0)
                raise ProcessError(f"{self.name} не ответил за {timeout:.0f} с", tail=tail)
            self._exited.wait(READY_POLL)

    def _probe(self, ready: Callable[[], bool]) -> bool:
        try:
            return bool(ready())
        except Exception:  # noqa: BLE001 — проба готовности не должна ронять запуск: просто «ещё нет»
            log.debug("Проба готовности %s не удалась", self.name, exc_info=True)
            return False

    def _early_exit(self) -> ProcessError:
        code = self.returncode
        tail = self.tail
        last = next((ln for ln in reversed(tail) if ln.strip()), "")
        return ProcessError(f"{self.name} завершился при запуске (код {code})" + (f": {last}" if last else ""),
                            code=code, tail=tail)

    # ---------------------------------------------------------------- вывод и сторож

    def _read_output(self) -> None:
        assert self.proc is not None and self.proc.stdout is not None
        for raw in iter(self.proc.stdout.readline, b""):
            line = self.scrub(_ANSI.sub("", raw.decode("utf-8", errors="replace")).rstrip())
            if not line:
                continue
            with self._lock:
                self._tail.append(line)
            self._out.log(line_level(line), "%s: %s", self.name, line)

    def _watch(self) -> None:
        assert self.proc is not None
        code = self.proc.wait()
        if self._reader is not None:
            self._reader.join(OUTPUT_DRAIN)   # хвост вывода нужен для причины падения
        with self._lock:
            self._exited.set()
            crashed = self._started and not self._stopping
        if not crashed:
            return
        log.warning("%s завершился сам, код %s", self.name, code)
        if self.on_exit is not None:
            try:
                self.on_exit(code, self.tail)
            except Exception:  # noqa: BLE001
                log.exception("Обработчик падения %s не сработал", self.name)

    # ---------------------------------------------------------------- остановка

    def stop(self, soft: float = SOFT_STOP) -> bool:
        """Остановить: CTRL_BREAK и soft секунд на выход, затем TerminateProcess.
        True — ядро вышло само (или уже не работало)."""
        with self._lock:
            self._stopping = True
        proc = self.proc
        if proc is None or proc.poll() is not None:
            self._exited.wait(OUTPUT_DRAIN)
            return True
        log.info("Остановка %s", self.name)
        graceful = False
        if soft > 0 and send_ctrl_break(proc.pid):
            try:
                proc.wait(timeout=soft)
                graceful = True
            except subprocess.TimeoutExpired:
                log.warning("%s не остановился за %.1f с — завершаю принудительно", self.name, soft)
        if not graceful:
            try:
                proc.kill()   # TerminateProcess
                proc.wait(timeout=KILL_WAIT)
            except (OSError, subprocess.TimeoutExpired) as exc:
                log.error("%s не завершился: %r", self.name, exc)
        self._exited.wait(OUTPUT_DRAIN)
        return graceful


# ------------------------------------------------------------ CTRL_BREAK в чужую консоль

_CONSOLE_LOCK = threading.Lock()     # консоль у процесса одна: присоединяемся по очереди
_HANDLER = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.DWORD)


@_HANDLER
def _swallow(_ctrl_type: int) -> bool:
    """Пока Лазейка присоединена к консоли ядра, её события — не для нас (по умолчанию — выход)."""
    return True


class _ConsoleApi:
    def __init__(self) -> None:
        k = ctypes.WinDLL("kernel32", use_last_error=True)
        k.AttachConsole.argtypes = [wintypes.DWORD]
        k.AttachConsole.restype = wintypes.BOOL
        k.FreeConsole.restype = wintypes.BOOL
        k.SetConsoleCtrlHandler.argtypes = [ctypes.c_void_p, wintypes.BOOL]
        k.SetConsoleCtrlHandler.restype = wintypes.BOOL
        k.GenerateConsoleCtrlEvent.argtypes = [wintypes.DWORD, wintypes.DWORD]
        k.GenerateConsoleCtrlEvent.restype = wintypes.BOOL
        self.k = k

    def attach(self, pid: int) -> int:
        """0 — присоединились, иначе код ошибки Windows."""
        return 0 if self.k.AttachConsole(pid) else (ctypes.get_last_error() or -1)

    def free(self) -> None:
        self.k.FreeConsole()

    def ignore_ctrl(self, on: bool) -> None:
        self.k.SetConsoleCtrlHandler(None, on)                                  # CTRL_C — штатно
        self.k.SetConsoleCtrlHandler(ctypes.cast(_swallow, ctypes.c_void_p), on)  # и CTRL_BREAK

    def ctrl_break(self, pid: int) -> bool:
        return bool(self.k.GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pid))


_api: _ConsoleApi | None = None


def _console_api() -> _ConsoleApi:
    global _api
    if _api is None:
        _api = _ConsoleApi()
    return _api


def send_ctrl_break(pid: int, api: _ConsoleApi | None = None) -> bool:
    """CTRL_BREAK группе процессов ядра (создана CREATE_NEW_PROCESS_GROUP, её id = pid ядра)."""
    api = api or _console_api()
    with _CONSOLE_LOCK:
        err = api.attach(pid)
        if err == ERROR_ACCESS_DENIED:
            # У нас своя консоль: так бывает только при запуске из исходников в терминале.
            # Отсоединяться нельзя — пропал бы вывод в терминал, поэтому событие шлёт помощник.
            return _send_via_helper(pid)
        if err:
            log.debug("AttachConsole(%d): ошибка %d", pid, err)
            return False
        api.ignore_ctrl(True)
        try:
            return api.ctrl_break(pid)
        finally:
            api.free()
            api.ignore_ctrl(False)


# Помощник сначала отпускает свою консоль: python.exe из venv — пускач, и настоящий интерпретатор
# получает от него новую консоль даже с DETACHED_PROCESS.
_HELPER = ("import ctypes,sys\n"
           "k=ctypes.WinDLL('kernel32',use_last_error=True)\n"
           "p=int(sys.argv[1])\n"
           "k.FreeConsole()\n"
           "ok=k.AttachConsole(p) and k.SetConsoleCtrlHandler(None,1) and k.GenerateConsoleCtrlEvent(1,p)\n"
           "sys.exit(0 if ok else 1)\n")


def _send_via_helper(pid: int) -> bool:
    if paths.IS_FROZEN:
        return False   # у сборки консоли нет — сюда она не попадает
    try:
        res = subprocess.run([sys.executable, "-I", "-c", _HELPER, str(pid)], timeout=10,
                             stdin=subprocess.DEVNULL, capture_output=True, creationflags=DETACHED_PROCESS)
    except (OSError, subprocess.TimeoutExpired) as exc:
        log.debug("Помощник CTRL_BREAK не сработал: %r", exc)
        return False
    return res.returncode == 0
