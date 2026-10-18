"""Пакеты стратегий zapret (релизы Flowseal/zapret-discord-youtube).

Каждая версия живёт в своей папке ``packs/<версия>``. Новая версия ставится рядом
с работающей, поэтому установка не упирается в занятые winws.exe и драйвером
файлы, а откат — это переключение на предыдущую папку.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path

from .. import archive, paths
from . import strategies
from ..errors import UserError

log = logging.getLogger("lazeyka.zapret.pack")

META_FILE = "lazeyka-pack.json"
REQUIRED_BIN = ("winws.exe", "WinDivert.dll", "WinDivert64.sys", "cygwin1.dll")
MAX_UNPACKED = 64 * 1024 * 1024


class PackError(UserError):
    pass


@dataclass
class PackInfo:
    version: str
    source: str               # bundled | github
    sha256: str
    published_at: str | None
    installed_at: float
    dir: str = ""

    @property
    def path(self) -> Path:
        return Path(self.dir)


def safe_version(version: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", version.strip().lstrip("vV"))[:40]
    if not cleaned or cleaned in (".", ".."):
        raise PackError(f"Некорректная версия пакета: {version!r}")
    return cleaned


def version_key(version: str) -> tuple:
    parts = []
    for chunk in re.split(r"[.\-_]", version.strip().lstrip("vV")):
        m = re.match(r"(\d+)(.*)", chunk)
        if m:
            # 1.10.3 > 1.10.3b: суффикс после числа означает предрелиз
            parts.append((int(m.group(1)), 0 if m.group(2) else 1, m.group(2)))
        else:
            parts.append((-1, 0, chunk))
    return tuple(parts)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def read_meta(pack_dir: Path) -> PackInfo | None:
    try:
        raw = json.loads((pack_dir / META_FILE).read_text(encoding="utf-8"))
        info = PackInfo(
            version=str(raw["version"]), source=str(raw.get("source", "github")),
            sha256=str(raw.get("sha256", "")), published_at=raw.get("published_at"),
            installed_at=float(raw.get("installed_at", 0.0)),
        )
    except (OSError, ValueError, KeyError, TypeError):
        return None
    info.dir = str(pack_dir)
    return info


def installed() -> list[PackInfo]:
    result = []
    if paths.PACKS_DIR.is_dir():
        for child in paths.PACKS_DIR.iterdir():
            if child.is_dir() and not child.name.startswith("."):
                info = read_meta(child)
                if info is not None and validate(child, quick=True) is None:
                    result.append(info)
    return sorted(result, key=lambda i: version_key(i.version))


def find(version: str | None) -> PackInfo | None:
    if not version:
        return None
    for info in installed():
        if info.version == version:
            return info
    return None


def problem_of(version: str | None) -> str | None:
    """Что не так с установленной папкой версии (None — папки нет или она в порядке)."""
    if not version:
        return None
    try:
        folder = paths.PACKS_DIR / safe_version(version)
    except PackError:
        return None
    if not folder.is_dir():
        return None
    return validate(folder, quick=True)


def newest() -> PackInfo | None:
    packs = installed()
    return packs[-1] if packs else None


def validate(pack_dir: Path, quick: bool = False) -> str | None:
    """Текст проблемы или None, если пакет пригоден."""
    for name in REQUIRED_BIN:
        if not (pack_dir / "bin" / name).is_file():
            return f"в пакете нет bin\\{name}"
    if not (pack_dir / "lists").is_dir():
        return "в пакете нет папки lists"
    if quick:
        return None
    found, errors = strategies.discover(pack_dir)
    usable = [s for s in found if s.usable]
    if not usable:
        return "в пакете нет ни одной понятной стратегии" + (f" ({errors[0]})" if errors else "")
    return None


def _extract(zip_path: Path, target: Path) -> Path:
    """Распаковывает архив и возвращает корень пакета (папку с bin и lists)."""
    try:
        return archive.extract(zip_path, target, max_unpacked=MAX_UNPACKED)
    except archive.ArchiveError as exc:
        raise PackError(str(exc)) from exc


def install_zip(zip_path: Path, version: str, *, source: str, expected_sha256: str | None,
                published_at: str | None = None) -> PackInfo:
    """Проверяет архив и ставит его в packs/<версия>. Работающий пакет не трогает.

    Хеш считается и архив распаковывается из приватной копии в защищённой папке:
    иначе исходный файл (например, во временной папке сборки) могли бы подменить
    между проверкой и распаковкой.
    """
    name = safe_version(version)
    paths.TMP_DIR.mkdir(parents=True, exist_ok=True)
    private = paths.TMP_DIR / f"dl-{uuid.uuid4().hex[:8]}.zip"
    staging = paths.TMP_DIR / f"pack-{name}-{uuid.uuid4().hex[:8]}"
    try:
        shutil.copyfile(zip_path, private)
        digest = sha256_file(private)
        if expected_sha256 and digest.lower() != expected_sha256.lower():
            raise PackError("Контрольная сумма архива не совпала с опубликованной — файл повреждён или подменён")
        _extract(private, staging)
        problem = validate(staging)
        if problem:
            raise PackError(f"Пакет {version} не подходит: {problem}")
        info = PackInfo(version=version.strip().lstrip("vV"), source=source, sha256=digest,
                        published_at=published_at, installed_at=time.time())
        meta = asdict(info)
        meta.pop("dir", None)
        (staging / META_FILE).write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")

        paths.PACKS_DIR.mkdir(parents=True, exist_ok=True)
        target = paths.PACKS_DIR / name
        if target.exists():
            trash = paths.TMP_DIR / f"old-{name}-{uuid.uuid4().hex[:8]}"
            try:
                os.replace(target, trash)
            except OSError as exc:
                raise PackError(f"Версия {version} уже установлена и сейчас используется — "
                                f"остановите обход и повторите ({exc})") from exc
            shutil.rmtree(trash, ignore_errors=True)
        os.replace(staging, target)
        info.dir = str(target)
        log.info("Установлен пакет стратегий %s (%s) в %s", info.version, source, target)
        return info
    finally:
        private.unlink(missing_ok=True)
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)


# Встроенный пакет описан здесь, в коде: код лежит внутри exe, а файлы данных сборки
# распаковываются во временную папку, где их мог бы подменить обычный процесс.
BUNDLED_VERSION = "1.10.3"
BUNDLED_SHA256 = "244314ae1c24538a0d751601da8e0c925c843371eec4456eb15f14c4fd6b7058"
BUNDLED_PUBLISHED_AT = "2026-09-20T08:46:37Z"


def bundled_manifest() -> dict | None:
    zip_path = paths.bundled_zapret_dir() / f"zapret-discord-youtube-{BUNDLED_VERSION}.zip"
    if not zip_path.is_file():
        log.error("Встроенный пакет zapret не найден: %s", zip_path)
        return None
    return {"version": BUNDLED_VERSION, "sha256": BUNDLED_SHA256, "zip": zip_path,
            "published_at": BUNDLED_PUBLISHED_AT}


def ensure_bundled() -> tuple[PackInfo | None, bool]:
    """Встроенный пакет: (сведения или None, поставлен ли он только что).

    Ставится, только если среди установленных нет такой же или более новой версии —
    так откат пользователя на старую версию не отменяется при следующем запуске.
    """
    existing = find(BUNDLED_VERSION)
    if existing is not None:
        return existing, False
    latest = newest()
    if latest is not None and version_key(latest.version) >= version_key(BUNDLED_VERSION):
        return None, False
    manifest = bundled_manifest()
    if manifest is None:
        return None, False
    info = install_zip(manifest["zip"], manifest["version"], source="bundled",
                       expected_sha256=manifest["sha256"], published_at=manifest["published_at"])
    return info, True


def cleanup(keep: set[str]) -> None:
    """Удаляет старые версии (кроме keep) и мусор во временной папке.

    Папка сначала переименовывается: если в ней что-то занято (её использует
    служба или winws), она остаётся целой, а не удаляется наполовину.
    """
    for info in installed():
        if info.version in keep:
            continue
        trash = paths.TMP_DIR / f"old-{safe_version(info.version)}-{uuid.uuid4().hex[:8]}"
        try:
            paths.TMP_DIR.mkdir(parents=True, exist_ok=True)
            os.replace(info.path, trash)
        except OSError as exc:
            log.debug("Пакет %s пока не удалить: %r", info.version, exc)
            continue
        shutil.rmtree(trash, ignore_errors=True)
        log.info("Удалён старый пакет стратегий %s", info.version)
    if paths.TMP_DIR.is_dir():
        for child in paths.TMP_DIR.iterdir():
            if child.name.startswith(("pack-", "old-", "dl-")):
                if child.is_dir():
                    shutil.rmtree(child, ignore_errors=True)
                else:
                    try:
                        child.unlink()
                    except OSError:
                        pass
