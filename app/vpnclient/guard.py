"""Стражи «без ядра».

На ПК разработчика рядом работает чужой VPN, а тесты и стенд интерфейса не должны трогать сеть:
при LAZEYKA_NO_CORE=1 нельзя запускать ядро, ставить его, менять системный прокси, включать
kill switch и регистрировать обработчик ссылок. Статические проверки ядра (version, check,
rule-set compile, format, generate) разрешены всегда: они ничего не меняют в системе.
"""
from __future__ import annotations

import os

from ..errors import UserError

STATIC_COMMANDS = frozenset({"version", "check", "format", "rule-set", "generate", "help", "--help", "-h"})


class CoreBlocked(UserError):
    pass


def core_blocked() -> bool:
    return os.environ.get("LAZEYKA_NO_CORE") == "1"


def ensure_allowed(action: str) -> None:
    """Бросает CoreBlocked, если действие трогает сеть или систему, а стенд это запрещает."""
    if core_blocked():
        raise CoreBlocked(f"{action}: отключено (LAZEYKA_NO_CORE=1 — ядро не запускается и систему не трогает)")


def is_static(args: list[str]) -> bool:
    """Команда ядра только читает конфиг или файлы (args — без пути к exe). У Xray проверка
    конфига — `xray run -test -c …`: с флагом -test он не поднимает ни одного входа."""
    if not args:
        return False
    return args[0] in STATIC_COMMANDS or (args[0] == "run" and "-test" in args)
