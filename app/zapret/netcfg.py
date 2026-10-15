"""Сетевые настройки Windows, которые нужны стратегиям zapret."""
from __future__ import annotations

import logging
from pathlib import Path

from .. import winutil

log = logging.getLogger("lazeyka.zapret.netcfg")

WINDIVERT_SERVICES = ("WinDivert", "WinDivert14")


def tcp_timestamps_enabled() -> bool | None:
    """Включены ли TCP timestamps (RFC 1323). None — не удалось узнать."""
    res = winutil.run([winutil.system32("netsh.exe"), "interface", "tcp", "show", "global"], timeout=15)
    if res.code != 0:
        return None
    for line in res.out.splitlines():
        low = line.lower()
        if "1323" in low or "timestamp" in low or "метк" in low:
            value = low.rsplit(":", 1)[-1].strip()
            if value.startswith(("enabled", "включ", "allowed")):
                return True
            if value.startswith(("disabled", "выключ", "отключ")):
                return False
    return None


def enable_tcp_timestamps() -> bool:
    """Включает TCP timestamps: без них часть стратегий (fooling=ts) не работает."""
    res = winutil.run([winutil.system32("netsh.exe"), "interface", "tcp", "set", "global",
                       "timestamps=enabled"], timeout=15)
    if res.code == 0:
        log.info("TCP timestamps включены")
        return True
    log.warning("Не удалось включить TCP timestamps: %s", (res.out + res.err).strip())
    return False


def ensure_tcp_timestamps() -> None:
    if tcp_timestamps_enabled() is not True:
        enable_tcp_timestamps()


def windivert_states() -> dict[str, str]:
    states = {}
    for name in WINDIVERT_SERVICES:
        info = winutil.service_query(name)
        if info is not None:
            states[name] = info.state
    return states


def windivert_driver_path(name: str = "WinDivert") -> Path | None:
    info = winutil.service_query(name, with_config=True)
    if info is None or not info.binary:
        return None
    return Path(info.binary.strip().strip('"').removeprefix("\\??\\"))


def windivert_from_zapret(name: str = "WinDivert") -> bool:
    """Драйвер загружен из папки zapret (рядом лежит winws.exe)?

    WinDivert используют и другие программы — VPN-клиенты, ускорители игр.
    Их драйвер трогать нельзя: выгрузка сломала бы им сеть.
    """
    path = windivert_driver_path(name)
    return path is not None and (path.parent / "winws.exe").is_file()


def remove_windivert() -> list[str]:
    """Останавливает и удаляет службу WinDivert, но только если она от zapret."""
    removed = []
    for name in WINDIVERT_SERVICES:
        if winutil.service_query(name) is None:
            continue
        if not windivert_from_zapret(name):
            log.info("WinDivert (%s) загружен не из папки zapret (%s) — не трогаю",
                     name, windivert_driver_path(name))
            continue
        try:
            if winutil.service_delete(name):
                removed.append(name)
        except winutil.ServiceError as exc:
            log.warning("WinDivert (%s) не удалён: %s", name, exc)
    return removed
