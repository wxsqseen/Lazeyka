"""Файл hosts: записи из zapret-discord-youtube для веб-Telegram и голосового Discord.

В отличие от service.bat (тот открывает Блокнот и просит скопировать руками),
записи добавляются отдельным помеченным блоком, с резервной копией, а
конфликтующие старые строки не удаляются, а комментируются.
"""
from __future__ import annotations

import logging
import os
import shutil
import time
from pathlib import Path

from .. import paths, winutil
from ..updates.github import http_get

log = logging.getLogger("lazeyka.zapret.hosts")

HOSTS_URL = ("https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/"
             "refs/heads/main/.service/hosts")
BEGIN = "# >>> Lazeyka: zapret-discord-youtube hosts"
END = "# <<< Lazeyka"
DISABLED_PREFIX = "# [Lazeyka off] "


def hosts_path() -> Path:
    return Path(winutil.system_dir()) / "drivers" / "etc" / "hosts"


def parse(text: str) -> list[tuple[str, str]]:
    pairs = []
    for line in text.splitlines():
        body = line.split("#", 1)[0].strip()
        if not body:
            continue
        parts = body.split()
        if len(parts) >= 2:
            pairs.extend((parts[0], host.lower()) for host in parts[1:])
    return pairs


def fetch() -> list[tuple[str, str]]:
    text = http_get(HOSTS_URL + f"?t={int(time.time())}", timeout=15, limit=512 * 1024).decode("utf-8", "replace")
    pairs = parse(text)
    if not pairs:
        raise ValueError("Скачанный список hosts пуст")
    return pairs


def _split_block(lines: list[str]) -> tuple[list[str], list[str]]:
    outside, inside, in_block = [], [], False
    for line in lines:
        if line.strip() == BEGIN:
            in_block = True
            continue
        if line.strip() == END:
            in_block = False
            continue
        (inside if in_block else outside).append(line)
    return outside, inside


def plan(current: str, wanted: list[tuple[str, str]]) -> dict:
    lines = current.splitlines()
    outside, _inside = _split_block(lines)
    wanted_hosts = {h for _ip, h in wanted}
    wanted_set = set(wanted)
    active = set(parse("\n".join(lines)))
    missing = [p for p in wanted if p not in active]
    conflicts = []
    for line in outside:
        pairs = parse(line)
        if any(h in wanted_hosts and (ip, h) not in wanted_set for ip, h in pairs):
            conflicts.append(line)
    return {"missing": missing, "conflicts": conflicts, "outside": outside}


def check() -> dict:
    wanted = fetch()
    current = hosts_path().read_text(encoding="utf-8", errors="replace")
    p = plan(current, wanted)
    return {"up_to_date": not p["missing"] and not p["conflicts"], "missing": len(p["missing"]),
            "conflicts": len(p["conflicts"]), "total": len(wanted)}


def apply() -> dict:
    wanted = fetch()
    path = hosts_path()
    current = path.read_text(encoding="utf-8", errors="replace")
    p = plan(current, wanted)
    paths.BACKUPS_DIR.mkdir(parents=True, exist_ok=True)
    backup = paths.BACKUPS_DIR / f"hosts-{time.strftime('%Y%m%d-%H%M%S')}.bak"
    shutil.copyfile(path, backup)
    conflict_set = set(p["conflicts"])
    body = [DISABLED_PREFIX + line if line in conflict_set else line for line in p["outside"]]
    while body and not body[-1].strip():
        body.pop()
    block = [BEGIN] + [f"{ip} {host}" for ip, host in wanted] + [END]
    text = "\r\n".join(body + [""] + block) + "\r\n"
    try:
        path.write_bytes(text.encode("utf-8"))
    except PermissionError as exc:
        raise PermissionError("Windows не дал изменить hosts — возможно, файл защищает антивирус") from exc
    winutil.flush_dns()
    log.info("hosts обновлён: %d записей, %d старых строк отключено, копия %s",
             len(wanted), len(conflict_set), backup)
    return {"added": len(p["missing"]), "disabled": len(conflict_set), "backup": str(backup)}
