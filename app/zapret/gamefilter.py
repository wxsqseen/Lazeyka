"""Игровой фильтр: перенос логики :game_switch_status из service.bat."""
from __future__ import annotations

import re

from .strategies import DUMMY_PORT

MODES = ("disabled", "all", "tcp", "udp")
DEFAULT_RANGE = "1024-65535"

_ITEM = re.compile(r"[1-9][0-9]*(?:-[1-9][0-9]*)?")


def validate_range(value: str) -> str | None:
    """Нормализованная строка портов или None, если она некорректна.

    Допустимо: «1024-65535», «1024-1934,1936-65535», «27015».
    """
    text = (value or "").replace(" ", "")
    if not text:
        return None
    for item in text.split(","):
        if not _ITEM.fullmatch(item):
            return None
        parts = item.split("-")
        if any(len(p) > 5 for p in parts):
            return None
        start = int(parts[0])
        end = int(parts[-1])
        if start > 65535 or end > 65535 or start > end:
            return None
    return text


def port_values(mode: str, tcp: str, udp: str) -> tuple[str, str]:
    """Значения %GameFilterTCP% и %GameFilterUDP% для стратегии."""
    tcp_range = validate_range(tcp) or DEFAULT_RANGE
    udp_range = validate_range(udp) or DEFAULT_RANGE
    if mode == "all":
        return tcp_range, udp_range
    if mode == "tcp":
        return tcp_range, DUMMY_PORT
    if mode == "udp":
        return DUMMY_PORT, udp_range
    return DUMMY_PORT, DUMMY_PORT


def legacy_value(mode: str, tcp: str, udp: str) -> str:
    """%GameFilter% старых стратегий: один диапазон на оба протокола."""
    tcp_v, udp_v = port_values(mode, tcp, udp)
    if mode == "udp":
        return udp_v
    return tcp_v
