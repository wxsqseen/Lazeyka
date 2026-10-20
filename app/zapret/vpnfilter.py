"""WinDivert-фильтр для режима «Совместимость с VPN».

winws строит фильтр сам из --wf-tcp/--wf-udp; ключ --wf-save сохраняет его в файл и
выходит, не открывая драйвер и не трогая уже работающий winws (проверено по исходникам
zapret v72.9: сохранение идёт до мьютекса и WinDivertOpen). Мы оборачиваем этот фильтр:
перехват только на прямых интерфейсах (ifIdx) и не трогать соединения с серверами VPN.
Результат проверяет компилятор фильтров из WinDivert.dll, и winws запускается с
--wf-raw=@файл. Любая ошибка — повод запустить обход как обычно, а не не запустить вовсе.
"""
from __future__ import annotations

import ctypes
import hashlib
import ipaddress
import json
import logging
import os
from ctypes import wintypes
from pathlib import Path

from .. import winutil

log = logging.getLogger("lazeyka.zapret")

MAX_FILTER = 16000          # буфер фильтра в winws — 16384 байта
MAX_SERVERS = 16            # больше адресов серверов не бывает; длинный фильтр WinDivert не скомпилирует
KEEP_FILTERS = 4     # рабочие фильтры: самый свежий — у работающего обхода или службы Windows
KEEP_PROBES = 30     # фильтры проб подбора — в своей папке, их уборка рабочие не заденет
KEEP_BASES = 40
_WF_PREFIXES = ("--wf-tcp=", "--wf-udp=", "--wf-l3=", "--wf-iface=", "--wf-raw-part=", "--wf-filter-lan=",
                "--wf-raw=", "--wf-save=")


class VpnFilterError(Exception):
    pass


def without_wf(args: list[str], keep_ports: bool) -> list[str]:
    """Аргументы без ключей фильтра WinDivert. keep_ports — оставить то, из чего winws строит
    фильтр сам (для --wf-save)."""
    drop = ("--wf-raw=", "--wf-save=") if keep_ports else _WF_PREFIXES
    return [a for a in args if not a.startswith(drop)]


def with_raw_filter(args: list[str], path: Path) -> list[str]:
    return [*without_wf(args, keep_ports=False), f"--wf-raw=@{path}"]


def wrap(base: str, interfaces: list[int], servers: list[str]) -> str:
    """Фильтр winws, ограниченный прямыми интерфейсами и без серверов VPN."""
    base = base.strip()
    if not base:
        raise VpnFilterError("winws вернул пустой фильтр")
    if not interfaces or any(int(i) <= 0 for i in interfaces):
        raise VpnFilterError("нет прямых сетевых интерфейсов")
    parts = [f"({base})", "(" + " or ".join(f"ifIdx={int(i)}" for i in sorted(set(interfaces))) + ")"]
    by_layer: dict[str, list[str]] = {"ip": [], "ipv6": []}
    for raw in servers[:MAX_SERVERS]:
        ip = ipaddress.ip_address(raw)
        layer = "ip" if ip.version == 4 else "ipv6"
        by_layer[layer] += [f"{layer}.DstAddr != {ip}", f"{layer}.SrcAddr != {ip}"]
    for layer, terms in by_layer.items():
        # В языке WinDivert «!» ставится только перед полем, не перед скобкой. «!ip or …» —
        # чтобы сравнение адресов IPv4 не касалось пакетов IPv6, и наоборот.
        if terms:
            parts.append(f"(!{layer} or (" + " and ".join(terms) + "))")
    return "\nand\n".join(parts) + "\n"


def compile_check(dll: Path, text: str) -> str | None:
    """Ошибка компиляции фильтра или None. Драйвер не нужен: это разбор строки в WinDivert.dll."""
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.LoadLibraryExW.argtypes = [wintypes.LPCWSTR, wintypes.HANDLE, wintypes.DWORD]
    kernel32.LoadLibraryExW.restype = wintypes.HMODULE
    kernel32.GetProcAddress.argtypes = [wintypes.HMODULE, ctypes.c_char_p]
    kernel32.GetProcAddress.restype = ctypes.c_void_p
    kernel32.FreeLibrary.argtypes = [wintypes.HMODULE]
    # LOAD_WITH_ALTERED_SEARCH_PATH: зависимости — рядом с DLL и в System32, не из текущей папки.
    handle = kernel32.LoadLibraryExW(str(dll), None, 0x8)
    if not handle:
        raise VpnFilterError(f"WinDivert.dll не загрузилась (ошибка {ctypes.get_last_error()})")
    try:
        address = kernel32.GetProcAddress(handle, b"WinDivertHelperCompileFilter")
        if not address:
            raise VpnFilterError("в WinDivert.dll нет проверки фильтров")
        proto = ctypes.WINFUNCTYPE(wintypes.BOOL, ctypes.c_char_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint,
                                   ctypes.POINTER(ctypes.c_char_p), ctypes.POINTER(ctypes.c_uint))
        compile_filter = proto(address)
        error, position = ctypes.c_char_p(), ctypes.c_uint(0)
        ok = compile_filter(text.encode("ascii"), 0, None, 0, ctypes.byref(error), ctypes.byref(position))
        if ok:
            return None
        message = (error.value or b"").decode("ascii", "replace")
        return f"{message or 'ошибка'} (символ {position.value})"
    finally:
        kernel32.FreeLibrary(handle)  # иначе DLL пакета заблокирована, и старый пакет не удалить


def _key(*parts) -> str:
    return hashlib.sha256(json.dumps(parts, ensure_ascii=False).encode("utf-8")).hexdigest()[:20]


def _winws_stamp(winws: Path) -> list:
    st = winws.stat()
    return [str(winws), st.st_size, st.st_mtime_ns]


def base_filter(winws: Path, args: list[str], folder: Path) -> str:
    """Фильтр, который winws построил бы сам, — через --wf-save; кэшируется по аргументам."""
    save_args = without_wf(args, keep_ports=True)
    cached = folder / f"base-{_key(_winws_stamp(winws), save_args)}.txt"
    if cached.is_file():
        return cached.read_text(encoding="ascii")
    folder.mkdir(parents=True, exist_ok=True)
    temporary = folder / f"save-{os.getpid()}.tmp"
    if len(str(temporary).encode("utf-8")) >= 255:
        raise VpnFilterError("слишком длинный путь к папке данных для winws")
    temporary.unlink(missing_ok=True)
    res = winutil.run([str(winws), *save_args, f"--wf-save={temporary}"], timeout=30, cwd=str(winws.parent))
    try:
        if res.code != 0 or not temporary.is_file():
            tail = " ".join((res.err or res.out).split())[-300:]
            raise VpnFilterError(f"winws не собрал фильтр (код {res.code}): {tail}")
        text = temporary.read_text(encoding="ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise VpnFilterError("winws сохранил фильтр в неожиданной кодировке") from exc
    finally:
        temporary.unlink(missing_ok=True)
    cached.write_text(text, encoding="ascii")
    _cleanup(folder, "base-*.txt", KEEP_BASES, keep=cached)
    return text


def build(winws: Path, args: list[str], interfaces: list[int], servers: list[str], folder: Path,
          cache: Path | None = None, keep_files: int = KEEP_FILTERS) -> Path:
    """Готовый файл фильтра для --wf-raw=@… (или VpnFilterError). cache — папка исходных
    фильтров winws, общая для рабочего запуска и проб."""
    final = folder / f"vpn-{_key(_winws_stamp(winws), without_wf(args, keep_ports=True), interfaces, servers)}.txt"
    if final.is_file():
        os.utime(final)  # свежий — не попадёт под уборку
        return final
    text = wrap(base_filter(winws, args, cache or folder), interfaces, servers)
    if len(text) > MAX_FILTER:
        raise VpnFilterError(f"фильтр получился длиннее, чем принимает winws ({len(text)} байт)")
    error = compile_check(winws.parent / "WinDivert.dll", text)
    if error:
        raise VpnFilterError(f"WinDivert не принял фильтр: {error}")
    folder.mkdir(parents=True, exist_ok=True)
    tmp = final.with_suffix(".tmp")
    tmp.write_text(text, encoding="ascii")
    os.replace(tmp, final)
    _cleanup(folder, "vpn-*.txt", keep_files, keep=final)
    log.info("Фильтр для работы рядом с VPN: интерфейсы %s, серверов VPN исключено: %d",
             ", ".join(map(str, interfaces)), len(servers))
    return final


def _cleanup(folder: Path, pattern: str, limit: int, keep: Path) -> None:
    try:
        files = sorted((p for p in folder.glob(pattern) if p != keep), key=lambda p: p.stat().st_mtime,
                       reverse=True)
    except OSError:
        return
    for old in files[max(0, limit - 1):]:
        try:
            old.unlink()
        except OSError:
            pass


def guard_servers(servers: list[str], targets: set[str], keep: list[str] | tuple[str, ...] = ()) -> list[str]:
    """Сервер VPN не исключаем, если по этому же адресу сейчас отвечают Discord или YouTube
    (VPN через CDN): иначе вместе с VPN обход перестал бы трогать и сам сайт. Соседний адрес
    той же сети не помеха — исключается ровно адрес сервера. keep — свои серверы Лазейки: их
    исключаем всегда, иначе обход менял бы транспорт своего VPN."""
    mandatory = set()
    for raw in keep:
        try:
            mandatory.add(str(ipaddress.ip_address(raw)))
        except ValueError:
            continue
    out = []
    for raw in servers:
        try:
            ip = str(ipaddress.ip_address(raw))
        except ValueError:
            continue
        if ip in targets and ip not in mandatory:
            log.info("Сервер VPN отвечает по тому же адресу, что Discord или YouTube, — не исключаю его")
            continue
        if ip not in out:
            out.append(ip)
    return out
