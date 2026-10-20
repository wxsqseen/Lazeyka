"""Пакеты стратегий zapret (релизы Flowseal/zapret-discord-youtube).

Каждая версия живёт в своей папке ``packs/<версия>``. Новая версия ставится рядом
с работающей, поэтому установка не упирается в занятые winws.exe и драйвером
файлы, а откат — это переключение на предыдущую папку.
"""
from __future__ import annotations

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
from ..filehash import sha256_file
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


# Слова пре-релиза, приписанные к числу без дефиса: «1.3.0rc1», «2.0beta2».
_PRE_WORDS = ("alpha", "beta", "preview", "pre", "rc", "dev")
_VERSION_PART = re.compile(r"^(\d+)([a-z]*)(\d*)$")
_PRE_SPLIT = re.compile(r"[.\-_]|(?<=\D)(?=\d)|(?<=\d)(?=\D)")
_NO_FIX = (0, "", 0)


def version_key(version: str) -> tuple:
    """Ключ сравнения версий zapret, tg-ws-proxy и самой Лазейки.

    - Буква сразу после числа — более позднее исправление той же версии (так нумерует Flowseal):
      1.9.8 < 1.9.8a < 1.9.8b < 1.9.9.
    - Пре-релиз — после дефиса (semver: 1.3.0-beta.1 < 1.3.0-rc.1 < 1.3.0) или словом alpha/beta/rc/pre/dev
      без дефиса (1.3.0rc1 < 1.3.0); окончательный релиз старше любого своего пре-релиза.
    - Хвостовые нули не значат ничего: 1.10 == 1.10.0; «v» в начале и метаданные после «+» не учитываются.
    """
    text = version.strip().lstrip("vV").lower().split("+", 1)[0]
    main, _, pre = text.partition("-")
    parts = re.split(r"[._]", main) if main else []
    numbers: list[tuple[int, str, int]] = []
    for index, chunk in enumerate(parts):
        match = _VERSION_PART.match(chunk)
        if match is None:
            numbers.append((-1, chunk, 0))
            continue
        number, letters, tail = int(match.group(1)), match.group(2), match.group(3)
        if letters.startswith(_PRE_WORDS):
            numbers.append((number, "", 0))
            pre = ".".join(item for item in (letters + tail, *parts[index + 1:], pre) if item)
            break
        numbers.append((number, letters, int(tail or 0)))
    while numbers and numbers[-1] == _NO_FIX:
        numbers.pop()
    if not pre:
        return tuple(numbers), (1, ())
    ids = tuple((0, int(ident), "") if ident.isdigit() else (1, 0, ident)
                for ident in _PRE_SPLIT.split(pre) if ident)
    return tuple(numbers), (0, ids)


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
    remove_stale_tmp()


# Временные файлы установок во временной папке данных: пакеты zapret (pack-, old-, dl-), ядро
# Telegram-прокси (tgws-), новая Лазейка (app-). Свежие не трогаем — их может писать установка,
# идущая параллельно (уборку зовут и после обновления zapret, и при перечитывании пакета).
TMP_PREFIXES = ("pack-", "old-", "dl-", "tgws-", "app-")
STALE_TMP_SECONDS = 3600.0


def remove_stale_tmp(now: float | None = None) -> None:
    """Хвосты прерванных установок (аварийный выход, выключение компьютера) старше часа."""
    if not paths.TMP_DIR.is_dir():
        return
    now = time.time() if now is None else now
    for child in paths.TMP_DIR.iterdir():
        if not child.name.startswith(TMP_PREFIXES):
            continue
        try:
            if now - child.lstat().st_mtime < STALE_TMP_SECONDS:
                continue
            if child.is_dir() and not child.is_symlink():
                shutil.rmtree(child, ignore_errors=True)
            else:
                child.unlink()
        except OSError as exc:
            log.debug("Временный файл %s пока не удалить: %r", child.name, exc)
