"""Процесс winws.exe: запуск без окна, вывод в журнал, ожидание готовности."""
from __future__ import annotations

import collections
import logging
import os
import subprocess
import threading
import time
from pathlib import Path
from typing import Callable

import psutil

from .. import winutil
from ..log import WINWS_LOGGER
from . import strategies
from ..errors import UserError

log = logging.getLogger("lazeyka.zapret.runner")
winws_log = logging.getLogger(WINWS_LOGGER)

READY_MARKER = "capture is started"
ERROR_MARKERS = ("error opening filter", "already running with the same filter", "could not",
                 "cannot access", "failed to")
ERROR_ELEVATION_REQUIRED = 740


class RunnerError(UserError):
    pass


def explain_failure(code: int | None, tail: list[str]) -> str:
    text = "\n".join(tail).lower()
    if "already running with the same filter" in text:
        return "Уже запущен другой winws с тем же фильтром — закройте другой обход (оригинальный zapret, другую копию)."
    if "error opening filter" in text:
        if "access is denied" in text or "отказано" in text:
            return "WinDivert не смог открыть фильтр: доступ запрещён. Нужны права администратора."
        if "secure boot" in text or "signature" in text or "577" in text:
            return ("Драйвер WinDivert не загрузился (подпись или Secure Boot). "
                    "Установите обновления Windows или временно отключите Secure Boot.")
        return "WinDivert не смог открыть фильтр. Запустите диагностику: возможно, мешает другой обход или антивирус."
    if "cannot access" in text and ("hostlist" in text or "ipset" in text):
        return "winws не смог прочитать файл списка. Проверьте пакет стратегий (Обновления → переустановить)."
    if code is not None and code != 0:
        last = next((ln for ln in reversed(tail) if ln.strip()), "")
        return f"winws завершился с кодом {code}" + (f": {last}" if last else "")
    return "winws завершился сразу после запуска"


class WinwsProcess:
    def __init__(self, exe: Path, args: list[str], *, label: str,
                 on_exit: Callable[[int, list[str]], None] | None = None,
                 bind_to_app: bool = True):
        self.exe = exe
        self.args = args
        self.label = label
        self.on_exit = on_exit
        self.bind_to_app = bind_to_app
        self.proc: subprocess.Popen | None = None
        self.started_at: float | None = None
        self.tail: collections.deque[str] = collections.deque(maxlen=200)
        self._ready = threading.Event()
        self._stopping = False

    @property
    def pid(self) -> int | None:
        return self.proc.pid if self.proc else None

    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def start(self, ready_timeout: float = 6.0) -> None:
        cmdline = strategies.command_line(self.exe, self.args)
        log.info("Запуск winws (%s)", self.label)
        log.debug("Командная строка: %s", cmdline)
        try:
            self.proc = subprocess.Popen(
                cmdline, executable=str(self.exe), cwd=str(self.exe.parent),
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                creationflags=winutil.CREATE_NO_WINDOW | winutil.CREATE_NEW_PROCESS_GROUP,
            )
        except OSError as exc:
            if getattr(exc, "winerror", None) == ERROR_ELEVATION_REQUIRED:
                raise RunnerError("Для запуска winws нужны права администратора") from exc
            raise RunnerError(f"Не удалось запустить winws: {exc}") from exc
        self.started_at = time.time()
        if self.bind_to_app and not winutil.kill_with_app(int(self.proc._handle)):  # noqa: SLF001
            log.debug("winws не привязан к job-объекту")
        threading.Thread(target=self._read_output, name="winws-out", daemon=True).start()

        deadline = time.monotonic() + ready_timeout
        alive_since = time.monotonic()
        while time.monotonic() < deadline:
            if self._ready.wait(0.1):
                log.info("winws готов (%s), pid %d", self.label, self.proc.pid)
                break
            if self.proc.poll() is not None:
                self.proc.wait()
                time.sleep(0.2)  # дать читателю дочитать хвост вывода
                raise RunnerError(explain_failure(self.proc.returncode, list(self.tail)))
            # Вывод cygwin-программы в канал буферизуется, поэтому маркер готовности
            # может прийти поздно. Живой процесс плюс загруженный драйвер — тоже готовность.
            if time.monotonic() - alive_since > 1.2 and _windivert_running():
                log.info("winws работает (%s), pid %d", self.label, self.proc.pid)
                break
        else:
            if self.proc.poll() is not None:
                raise RunnerError(explain_failure(self.proc.returncode, list(self.tail)))
            log.info("winws работает (%s), pid %d — маркер готовности не получен", self.label, self.proc.pid)
        threading.Thread(target=self._watch, name="winws-watch", daemon=True).start()

    def _read_output(self) -> None:
        assert self.proc and self.proc.stdout
        for raw in iter(self.proc.stdout.readline, b""):
            line = raw.decode("utf-8", errors="replace").rstrip()
            if not line:
                continue
            self.tail.append(line)
            low = line.lower()
            if READY_MARKER in low:
                self._ready.set()
            level = logging.WARNING if any(m in low for m in ERROR_MARKERS) else logging.INFO
            winws_log.log(level, "%s", line)

    def _watch(self) -> None:
        assert self.proc
        code = self.proc.wait()
        if self._stopping:
            return
        log.warning("winws (%s) завершился сам, код %s", self.label, code)
        if self.on_exit:
            time.sleep(0.2)
            self.on_exit(code, list(self.tail))

    def stop(self, timeout: float = 5.0) -> None:
        self._stopping = True
        if not self.proc or self.proc.poll() is not None:
            return
        log.info("Остановка winws (%s)", self.label)
        try:
            self.proc.terminate()
            self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=timeout)
        except OSError as exc:
            log.warning("winws не остановился: %r", exc)


def _windivert_running() -> bool:
    info = winutil.service_query("WinDivert")
    return info is not None and info.state == "running"


def foreign_winws(exclude: set[int]) -> list[psutil.Process]:
    """Процессы winws.exe, запущенные не нами. Дочерние процессы самой Лазейки (например,
    короткий `winws --wf-save` при сборке фильтра для VPN) чужими не считаются."""
    found = []
    me = os.getpid()
    for proc in psutil.process_iter(["name", "pid", "ppid"]):
        try:
            if ((proc.info["name"] or "").lower() == "winws.exe" and proc.info["pid"] not in exclude
                    and proc.info["ppid"] != me):
                found.append(proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return found


def kill_processes(procs: list[psutil.Process], timeout: float = 5.0) -> None:
    for proc in procs:
        try:
            proc.kill()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    psutil.wait_procs(procs, timeout=timeout)
