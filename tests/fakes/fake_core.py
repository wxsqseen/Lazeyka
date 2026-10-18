"""Поддельное ядро для тестов процесса: печатает строки, ждёт CTRL_BREAK, по флагам падает или не слушается.

Запускается как `python fake_core.py …` — имя не sing-box.exe/xray.exe, страж conftest его пропускает.
"""
import argparse
import signal
import sys
import threading
import time

stop = threading.Event()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lines", type=int, default=3, help="сколько строк вывода до «ready»")
    parser.add_argument("--secret", default="", help="строка, которую ядро «выдаст» в журнал")
    parser.add_argument("--crash-after", type=float, default=0.0, help="упасть с кодом 3 через N с")
    parser.add_argument("--exit-now", type=int, default=None, help="сразу выйти с этим кодом")
    parser.add_argument("--ignore-break", action="store_true", help="не реагировать на CTRL_BREAK")
    args = parser.parse_args()
    sys.stdout.reconfigure(encoding="utf-8")

    if args.exit_now is not None:
        print("FATAL[0000] start service: start inbound/mixed[mixed-in]: listen tcp 127.0.0.1:20808: bind: "
              "Only one usage of each socket address (protocol/network address/port) is normally permitted.",
              flush=True)
        return args.exit_now
    if args.ignore_break:
        signal.signal(signal.SIGBREAK, signal.SIG_IGN)
    else:
        signal.signal(signal.SIGBREAK, lambda *_: stop.set())
    for i in range(args.lines):
        print(f"INFO[{i:04d}] line {i} {args.secret}".rstrip(), flush=True)
    print("\x1b[36mINFO\x1b[0m[0000] sing-box started (ready)", flush=True)
    started = time.monotonic()
    while not stop.wait(0.05):
        if args.crash_after and time.monotonic() - started > args.crash_after:
            print("FATAL[0010] something broke", flush=True)
            return 3
    print("WARN[0011] got CTRL_BREAK, closing", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
