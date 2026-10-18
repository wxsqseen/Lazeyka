"""Свой VPN: процесс ядра на поддельном ядре (python-скрипт) — готовность, вывод, падение, остановка."""
import json
import logging
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from app.vpnclient import guard, process

ROOT = Path(__file__).resolve().parent.parent
FAKE = ROOT / "tests" / "fakes" / "fake_core.py"
HARNESS = ROOT / "tests" / "fakes" / "stop_harness.py"


@pytest.fixture(autouse=True)
def _allow_fake_core(monkeypatch):
    # Поддельное ядро — python.exe: страж conftest на имена sing-box.exe/xray.exe остаётся в силе.
    monkeypatch.setattr(guard, "core_blocked", lambda: False)


def _core(*args, on_exit=None, scrub=lambda s: s) -> process.CoreProcess:
    return process.CoreProcess("fake-core", Path(sys.executable), [str(FAKE), *args], cwd=ROOT,
                               scrub=scrub, on_exit=on_exit)


def _ready(core: process.CoreProcess):
    return lambda: any("(ready)" in line for line in core.tail)


def test_start_waits_for_readiness_and_logs_scrubbed_output(caplog):
    caplog.set_level(logging.DEBUG, logger=process.CORE_LOGGER)
    core = _core("--lines", "2", "--secret", "uuid-SECRET-123", scrub=lambda s: s.replace("uuid-SECRET-123", "***"))
    try:
        core.start(_ready(core), timeout=20)
        assert core.alive() and core.pid
        tail = core.tail
        assert any("(ready)" in line for line in tail)
        assert all("uuid-SECRET-123" not in line for line in tail)
        assert all("\x1b[" not in line for line in tail), "цвета ANSI вычищены"
        assert "uuid-SECRET-123" not in caplog.text and "line 0 ***" in caplog.text
    finally:
        core.stop(soft=0)
    assert not core.alive()


def test_exit_during_start_raises_with_tail():
    core = _core("--exit-now", "1")
    with pytest.raises(process.ProcessError) as err:
        core.start(lambda: False, timeout=20)
    assert err.value.code == 1
    assert any("Only one usage of each socket address" in line for line in err.value.tail)


def test_ready_timeout_kills_the_process():
    core = _core()
    began = time.monotonic()
    with pytest.raises(process.ProcessError, match="не ответил"):
        core.start(lambda: False, timeout=1.0)
    assert time.monotonic() - began < 10
    assert not core.alive()


def test_crash_after_start_calls_on_exit_with_tail():
    got = {}
    done = threading.Event()

    def on_exit(code, tail):
        got.update(code=code, tail=tail)
        done.set()

    core = _core("--crash-after", "0.3", on_exit=on_exit)
    core.start(_ready(core), timeout=20)
    assert done.wait(20), "сторож не сообщил о падении"
    assert got["code"] == 3 and any("something broke" in line for line in got["tail"])


def test_stop_is_not_reported_as_crash():
    calls = []
    core = _core(on_exit=lambda code, tail: calls.append(code))
    core.start(_ready(core), timeout=20)
    core.stop(soft=0)
    time.sleep(0.5)   # отрицательное утверждение: лишнего вызова on_exit не должно случиться
    assert calls == []


def test_tail_keeps_last_200_lines():
    core = _core("--lines", "450")
    try:
        core.start(_ready(core), timeout=20)
        tail = core.tail
        assert len(tail) == process.TAIL_LINES and "(ready)" in tail[-1]
    finally:
        core.stop(soft=0)


def test_guard_blocks_start(monkeypatch):
    monkeypatch.setattr(guard, "core_blocked", lambda: True)
    with pytest.raises(guard.CoreBlocked):
        _core().start(lambda: True, timeout=1)


def test_line_levels():
    assert process.line_level("FATAL[0000] decode config at x") == logging.ERROR
    assert process.line_level("+0300 2026-10-17 07:00:00 ERROR[0015] connection: open outbound") == logging.ERROR
    assert process.line_level("WARN[0000] deprecated") == logging.WARNING
    assert process.line_level("2026/10/17 07:00:00 [Warning] core: Xray 26.3.27 started") == logging.WARNING
    assert process.line_level("2026/10/17 07:00:00 [Error] app/proxyman/outbound: failed") == logging.ERROR
    assert process.line_level("INFO[0000] sing-box started") == logging.INFO


class _FakeConsole:
    def __init__(self, attach_error=0):
        self.attach_error = attach_error
        self.calls = []

    def attach(self, pid):
        self.calls.append(("attach", pid))
        return self.attach_error

    def free(self):
        self.calls.append(("free",))

    def ignore_ctrl(self, on):
        self.calls.append(("ignore", on))

    def ctrl_break(self, pid):
        self.calls.append(("break", pid))
        return True


def test_ctrl_break_sequence_without_own_console():
    api = _FakeConsole()
    assert process.send_ctrl_break(4242, api)
    assert api.calls == [("attach", 4242), ("ignore", True), ("break", 4242), ("free",), ("ignore", False)]


def test_ctrl_break_with_own_console_goes_through_helper(monkeypatch):
    api = _FakeConsole(attach_error=process.ERROR_ACCESS_DENIED)
    sent = []
    monkeypatch.setattr(process, "_send_via_helper", lambda pid: sent.append(pid) or True)
    assert process.send_ctrl_break(77, api)
    assert sent == [77] and ("free",) not in api.calls, "свою консоль не отпускаем"


def _harness(tmp_path, mode, *fake_args):
    """Остановка в отдельном процессе: no-console — как Lazeyka.exe, own-console — как запуск из терминала."""
    out = tmp_path / "result.json"
    proc = subprocess.run([sys.executable, str(HARNESS), str(out), mode, *fake_args], cwd=str(ROOT),
                          creationflags=process.DETACHED_PROCESS if mode == "no-console" else subprocess.CREATE_NO_WINDOW,
                          capture_output=True, timeout=60)
    assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")[-2000:]
    return json.loads(out.read_text(encoding="utf-8"))


@pytest.mark.parametrize("mode", ["no-console", "own-console"])
def test_soft_stop_fits_in_two_seconds(tmp_path, mode):
    result = _harness(tmp_path, mode)
    assert result["graceful"] is True, result["tail"][-5:]
    assert result["elapsed"] <= process.SOFT_STOP
    assert result["code"] == 0 and not result["alive"]
    assert any("got CTRL_BREAK" in line for line in result["tail"])
    # без консоли — сами присоединяемся к консоли ядра, со своей — через помощника
    assert result["helper_calls"] == (0 if mode == "no-console" else 1)


def test_terminate_when_core_ignores_ctrl_break(tmp_path):
    result = _harness(tmp_path, "no-console", "--ignore-break")
    assert result["graceful"] is False
    assert process.SOFT_STOP <= result["elapsed"] < process.SOFT_STOP + process.KILL_WAIT
    assert not result["alive"] and result["code"] not in (None, 0)
