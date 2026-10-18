"""Остановка ядра из отдельного процесса — как её видит Lazeyka.exe.

Режим "no-console" отпускает консоль процесса (FreeConsole), как у сборки с console=False: python.exe
из venv — пускач, и настоящий интерпретатор получает консоль даже при запуске с DETACHED_PROCESS.
Режим "own-console" оставляет её — как запуск из исходников в терминале. Здесь CoreProcess поднимает
поддельное ядро и останавливает его; итог — JSON в argv[1].

Запуск: python stop_harness.py <out.json> <no-console|own-console> [аргументы fake_core.py]
"""
import ctypes
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from app.vpnclient import guard, process  # noqa: E402

guard.core_blocked = lambda: False   # поддельное ядро — python.exe, систему не трогает
helper_calls = []
_real_helper = process._send_via_helper
process._send_via_helper = lambda pid: helper_calls.append(pid) or _real_helper(pid)


def main() -> int:
    out, mode, fake_args = Path(sys.argv[1]), sys.argv[2], sys.argv[3:]
    if mode == "no-console":
        ctypes.WinDLL("kernel32").FreeConsole()
    core = process.CoreProcess("fake-core", Path(sys.executable),
                               [str(ROOT / "tests" / "fakes" / "fake_core.py"), *fake_args],
                               cwd=ROOT, bind_to_app=True)
    core.start(lambda: any("(ready)" in line for line in core.tail), timeout=20)
    began = time.monotonic()
    graceful = core.stop(soft=process.SOFT_STOP)
    elapsed = time.monotonic() - began
    out.write_text(json.dumps({"graceful": graceful, "elapsed": elapsed, "code": core.returncode,
                               "tail": core.tail, "alive": core.alive(), "helper_calls": len(helper_calls)}),
                   encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
