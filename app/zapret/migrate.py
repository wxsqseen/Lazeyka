"""Перенос настроек из уже установленного оригинального zapret-discord-youtube.

Папку ищем там, где её оставил сам zapret: путь драйвера WinDivert, путь службы
zapret или запущенного winws.exe.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path

import psutil

from .. import winutil
from ..settings import Settings
from . import gamefilter, lists

log = logging.getLogger("lazeyka.zapret.migrate")


def _root_from_binary(binary: str | None) -> Path | None:
    if not binary:
        return None
    text = binary.strip()
    if text.startswith('"'):
        text = text[1:].split('"', 1)[0]
    else:
        text = re.split(r"\s--", text, maxsplit=1)[0].strip()
    text = text.removeprefix("\\??\\")
    path = Path(text)
    if path.parent.name.lower() == "bin":
        root = path.parent.parent
        if (root / "service.bat").is_file() and (root / "lists").is_dir():
            return root
    return None


def find_original() -> Path | None:
    candidates: list[str | None] = []
    for name in ("zapret", "WinDivert"):
        info = winutil.service_query(name, with_config=True)
        if info is not None:
            candidates.append(info.binary)
    for proc in psutil.process_iter(["name", "exe"]):
        try:
            if (proc.info["name"] or "").lower() == "winws.exe":
                candidates.append(proc.info["exe"])
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    for binary in candidates:
        root = _root_from_binary(binary)
        if root is not None:
            return root
    return None


def read_game_filter(root: Path) -> dict | None:
    """Разбор utils\\game_filter.enabled так же, как в service.bat (старый и новый формат)."""
    path = root / "utils" / "game_filter.enabled"
    if not path.is_file():
        return None
    mode, tcp, udp = "disabled", gamefilter.DEFAULT_RANGE, gamefilter.DEFAULT_RANGE
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        key, _, value = line.strip().partition("=")
        key = key.strip().lower()
        value = value.strip()
        if key == "mode" and value:
            mode = value.lower()
        elif key == "all":
            mode = "all"
        elif key == "tcp":
            if value:
                tcp = gamefilter.validate_range(value) or tcp
            else:
                mode = "tcp"
        elif key == "udp":
            if value:
                udp = gamefilter.validate_range(value) or udp
            else:
                mode = "udp"
    if mode not in gamefilter.MODES:
        mode = "disabled"
    return {"mode": mode, "tcp": tcp, "udp": udp}


def import_from(root: Path, settings: Settings, user_dir: Path) -> list[str]:
    """Переносит игровой фильтр, режим IPSet и непустые пользовательские списки."""
    done: list[str] = []
    gf = read_game_filter(root)
    ipset_mode = lists.detect_ipset_mode(root / "lists")

    def mutate(d: dict) -> None:
        if gf:
            d["zapret"]["game_filter"] = gf
        d["zapret"]["ipset_mode"] = ipset_mode

    settings.update(mutate)
    if gf and gf["mode"] != "disabled":
        done.append("игровой фильтр")
    done.append(f"режим IPSet «{ipset_mode}»")

    user_dir.mkdir(parents=True, exist_ok=True)
    for name, (title, _hint, default) in lists.USER_LISTS.items():
        src = root / "lists" / name
        if not src.is_file():
            continue
        text = src.read_text(encoding="utf-8", errors="replace")
        entries = {ln.strip() for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")}
        if entries <= {lists.PLACEHOLDER_DOMAIN, lists.NONE_MARKER}:
            continue  # в файле только заглушки из шаблона — переносить нечего
        lists.save_user_list(user_dir, name, text)
        done.append(f"список «{title}»")
    log.info("Перенесено из %s: %s", root, ", ".join(done))
    return done
