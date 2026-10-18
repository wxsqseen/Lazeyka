"""Безопасная распаковка zip: пакеты стратегий zapret и ядра своего VPN.

Пути внутри архива не выходят за пределы целевой папки (zip-slip, буквы дисков, «..»),
суммарный объём ограничен — архив-бомба не заполнит диск. Лимит у каждого потребителя свой:
пакет zapret весит единицы мегабайт, ядро sing-box распаковывается почти в 90 МБ.
"""
from __future__ import annotations

import shutil
import zipfile
from pathlib import Path, PurePosixPath
from typing import Callable

from .errors import UserError

DEFAULT_MAX_UNPACKED = 64 * 1024 * 1024


class ArchiveError(UserError):
    pass


def safe_members(zf: zipfile.ZipFile, max_unpacked: int = DEFAULT_MAX_UNPACKED
                 ) -> list[tuple[zipfile.ZipInfo, PurePosixPath]]:
    members = []
    total = 0
    for info in zf.infolist():
        name = info.filename.replace("\\", "/")
        rel = PurePosixPath(name)
        if rel.is_absolute() or any(part in ("..", "") or ":" in part for part in rel.parts if part != "."):
            raise ArchiveError(f"Небезопасный путь в архиве: {info.filename}")
        total += info.file_size
        if total > max_unpacked:
            raise ArchiveError(f"Архив распаковывается в подозрительно большой объём (больше {max_unpacked // (1024 * 1024)} МБ)")
        members.append((info, rel))
    return members


def extract(zip_path: Path, target: Path, *, max_unpacked: int = DEFAULT_MAX_UNPACKED, strip_single_top: bool = True,
            skip: Callable[[PurePosixPath], bool] | None = None) -> Path:
    """Распаковывает архив в target. strip_single_top — если всё лежит в одной папке верхнего
    уровня, её содержимое кладётся прямо в target. skip(путь) — пропустить файл (например,
    geo-файлы Xray, которые помощнику не нужны)."""
    root = target.resolve()
    with zipfile.ZipFile(zip_path) as zf:
        members = safe_members(zf, max_unpacked)
        tops = {rel.parts[0] for _, rel in members if rel.parts}
        strip = strip_single_top and len(tops) == 1 and all(len(rel.parts) > 1 or info.is_dir() for info, rel in members)
        for info, rel in members:
            parts = rel.parts[1:] if strip else rel.parts
            if not parts:
                continue
            if skip is not None and not info.is_dir() and skip(PurePosixPath(*parts)):
                continue
            dest = target.joinpath(*parts)
            if not dest.resolve().is_relative_to(root):
                raise ArchiveError(f"Небезопасный путь в архиве: {info.filename}")
            if info.is_dir():
                dest.mkdir(parents=True, exist_ok=True)
                continue
            dest.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, open(dest, "wb") as out:
                shutil.copyfileobj(src, out, 1 << 20)
    return target
