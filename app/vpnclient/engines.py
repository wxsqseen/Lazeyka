"""Ядра своего VPN: закреплённые версии, установка с GitHub, сверка exe, `version` и `check`.

sing-box — основное ядро, Xray — помощник для того, чего sing-box не умеет (docs/vpnclient-plan.md, 3.2).
В Lazeyka.exe ядер нет (решение владельца 2026-10-18): официальные zip без изменений скачиваются с GitHub —
при запуске Лазейки закреплённая версия (хеши в коде), автообновлением новая (хеш — digest ассета из API
релизов) — и ставятся в DATA/components/<ядро>/<версия>/. Маршрут — напрямую с закреплёнными адресами
GitHub, запасной — через системный прокси. exe ядер не подписаны, поэтому целостность держится только на
SHA-256: архива — до распаковки, exe — после неё и перед каждым запуском (verify).

Какая версия активна, помнит менеджер (настройки vpnclient.*_version); здесь — только диск и GitHub.
"""
from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import threading
import time
import uuid
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, TypeVar

from .. import archive, paths, winutil
from ..filehash import sha256_file
from ..errors import UserError
from . import guard

log = logging.getLogger("lazeyka.vpnclient.engines")

CORE_MAX_UNPACKED = 128 * 1024 * 1024   # sing-box распаковывается почти в 92 МБ, Xray — в 66 МБ
MARKER = "lazeyka-core.json"            # что и откуда поставлено, хеш exe
OLD_MARK = ".old-"                      # <версия>.old-<случайное>: прежняя установка на время замены
GPL_FILE = "gpl-3.0.txt"                 # LICENSE в zip sing-box — только уведомление, текст GPL кладём сами
VERSION_TIMEOUT = 15.0
CHECK_TIMEOUT = 30.0
DOWNLOAD_LIMIT = 200 * 1024 * 1024
ROUTES = ("direct", "system")           # напрямую с закреплёнными адресами GitHub; запасной — системный прокси
ROUTE_TITLE = {"direct": "напрямую", "system": "через системный прокси"}
_VERSION = re.compile(r"^\d{1,4}(\.\d{1,4}){1,3}$")   # версия — часть пути: ничего, кроме цифр и точек
_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
# sing-box: «FATAL[0000] текст» (перед ним бывает время); Xray: «2026/10/17 07:00:00 [Warning] текст»
_SINGBOX_LINE = re.compile(r"\b(PANIC|FATAL|ERROR|WARN|INFO|DEBUG|TRACE)\[\d+\]\s*(.*)$")
_XRAY_WARNING = re.compile(r"\[Warning\]\s*(.*)$")

Progress = Callable[[str, float | None], None]          # (стадия, доля 0..1 или None)
T = TypeVar("T")


class EngineError(UserError):
    pass


class ReleaseRejected(EngineError):
    """Архив скачан и сверен, но ядро в нём не то или не отвечает: эту версию ставить не нужно."""


@dataclass(frozen=True)
class CoreSpec:
    name: str                 # "sing-box" | "xray"
    title: str                # для «Обновлений» и окон
    version: str              # закреплённая версия: её хеши проверены и записаны в код
    repo: str
    asset: str                # имя zip закреплённой версии в релизе GitHub
    zip_size: int
    zip_sha256: str
    exe: str
    exe_sha256: str
    disk_size: int            # примерно на диске после установки
    license: str              # SPDX
    skip: tuple[str, ...] = ()        # файлы zip, которые не распаковываем
    gpl_text: bool = False            # положить рядом полный текст GPL-3.0
    neuter: bool = False              # «Ядро VPN» — средний род, «Помощник Xray» — мужской

    def agree(self, masculine: str) -> str:
        """Глагол в роде названия: agree("установлен") — «Ядро VPN … установлено», «Помощник Xray … установлен»."""
        return masculine + "о" if self.neuter else masculine

    @property
    def tag(self) -> str:
        return f"v{self.version}"

    def asset_for(self, version: str) -> str:
        """Имя zip той же сборки в релизе другой версии (у Xray версии в имени нет)."""
        return self.asset.replace(self.version, version)

    def release_url(self, version: str | None = None) -> str:
        ver = version or self.version
        return f"https://github.com/{self.repo}/releases/download/v{ver}/{self.asset_for(ver)}"

    def source_url(self, version: str | None = None) -> str:
        return f"https://github.com/{self.repo}/tree/v{version or self.version}"


CORES: dict[str, CoreSpec] = {
    "sing-box": CoreSpec(
        name="sing-box", title="Ядро VPN (sing-box)", version="1.14.3", repo="SagerNet/sing-box",
        asset="sing-box-1.14.3-windows-amd64.zip", zip_size=32_853_953,
        zip_sha256="d8b86ef58936dba9230ec6a57ffa4243933f3c14ef4809828b6c553440ed1518",
        exe="sing-box.exe", exe_sha256="5c19bb3f8c12d4e85b3d47fe63123a7624b314b58dd7a8e32f51004f1c4d2faf",
        disk_size=91_552_885, license="GPL-3.0-or-later", gpl_text=True, neuter=True),
    "xray": CoreSpec(
        name="xray", title="Помощник Xray", version="26.3.27", repo="XTLS/Xray-core",
        asset="Xray-windows-64.zip", zip_size=20_913_304,
        zip_sha256="d004c39288ce9ada487c6f398c7c545f7d749e44bdfdd59dbc9f865afba4e1ad",
        exe="xray.exe", exe_sha256="15c2d007954ac53ba69b80ec91242786b3c0b71d52649165b4ca1d5cc96ef8f1",
        disk_size=36_074_379, license="MPL-2.0",
        # geo-файлы (30 МБ) помощнику не нужны: маршрутизирует sing-box
        skip=("geoip.dat", "geosite.dat")),
}

_VERSION_OUTPUT = {
    "sing-box": re.compile(r"sing-box version (\S+)"),
    "xray": re.compile(r"^Xray (\S+)", re.M),
}


@dataclass(frozen=True)
class Release:
    """Что ставить: закреплённая версия (хеши в коде) или новая версия с GitHub (хеш — digest)."""

    version: str
    url: str
    zip_sha256: str
    exe_sha256: str | None = None     # неизвестен для новых версий: запоминаем при установке
    size: int = 0


def spec(name: str) -> CoreSpec:
    try:
        return CORES[name]
    except KeyError:
        raise EngineError(f"Неизвестное ядро: {name}") from None


def pinned_release(name: str) -> Release:
    s = spec(name)
    return Release(s.version, s.release_url(), s.zip_sha256, s.exe_sha256, s.zip_size)


def background_allowed() -> bool:
    """Можно ли качать и ставить ядра без нажатия человека: стенд и тесты (LAZEYKA_NO_CORE=1) — нельзя."""
    return not guard.core_blocked()


def version_key(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


# ------------------------------------------------------------ где лежит

def core_root(name: str) -> Path:
    return paths.COMPONENTS_DIR / spec(name).name


def version_dir(name: str, version: str) -> Path:
    if not _VERSION.match(version or ""):
        raise EngineError(f"Недопустимая версия ядра: {version!r}")
    return core_root(name) / version


def gpl_text_path() -> Path:
    return paths.resource_dir() / "app" / "vpnclient" / "licenses" / GPL_FILE


def _marker(name: str, version: str) -> dict | None:
    try:
        data = json.loads((version_dir(name, version) / MARKER).read_text(encoding="utf-8"))
    except (OSError, ValueError, EngineError):
        return None
    if not isinstance(data, dict) or data.get("version") != version or not isinstance(data.get("exe_sha256"), str):
        return None
    return data


def origin(name: str, version: str | None) -> str | None:
    """Откуда поставлена версия: "github" (подкачка, кнопка), "auto" (автообновление) или None."""
    marker = _marker(name, version) if version else None
    value = (marker or {}).get("source")
    return value if isinstance(value, str) else None


def _present(name: str, version: str) -> bool:
    """Версия стоит: есть метка установки и сам exe. Метка без exe (exe удалил антивирус) — не стоит:
    подкачка поставит ядро заново, а запуск возьмёт другую версию."""
    return bool(_VERSION.match(version or "")) and _marker(name, version) is not None \
        and (version_dir(name, version) / spec(name).exe).is_file()


def versions(name: str) -> list[str]:
    """Установленные версии (с меткой установки и exe), новые первыми."""
    root = core_root(name)
    if not root.is_dir():
        return []
    _recover_interrupted(name)
    found = [p.name for p in root.iterdir() if p.is_dir() and _present(name, p.name)]
    return sorted(found, key=version_key, reverse=True)


def installed(name: str, version: str | None = None) -> str | None:
    """Версия, которая стоит на диске: заданная или самая новая."""
    if version:
        if not _present(name, version):
            _recover_interrupted(name)
        return version if _present(name, version) else None
    return next(iter(versions(name)), None)


# ------------------------------------------------------------ сверка и запуск статических команд

def verify(name: str, version: str | None = None) -> Path:
    """Путь к exe установленного ядра после сверки SHA-256 — перед каждым запуском."""
    s = spec(name)
    ver = installed(name, version)
    if ver is None:
        raise EngineError(f"{s.title} {version or ''} {s.agree('не установлен')}".replace("  ", " "))
    marker = _marker(name, ver) or {}
    # Для закреплённой версии эталон — код, а не метка на диске.
    expected = s.exe_sha256 if ver == s.version else str(marker.get("exe_sha256", ""))
    exe = version_dir(name, ver) / s.exe
    try:
        actual = sha256_file(exe)
    except OSError as exc:
        raise EngineError(f"{s.title}: файл {s.exe} не читается ({exc}) — переустановите ядро") from exc
    if actual.lower() != expected.lower():
        raise EngineError(f"{s.title}: файл {s.exe} изменён (контрольная сумма не совпала) — переустановите ядро "
                          "на странице «Обновления»")
    return exe


def _run(cmd: list[str], timeout: float, cwd: Path | None = None) -> winutil.RunResult:
    """Статическая команда ядра без окна. Не winutil.run: ядра пишут UTF-8, а не в кодировке OEM."""
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout, cwd=str(cwd) if cwd else None,
                              stdin=subprocess.DEVNULL, creationflags=winutil.CREATE_NO_WINDOW)
    except subprocess.TimeoutExpired:
        return winutil.RunResult(-1, "", f"не ответило за {timeout:.0f} с")
    except OSError as exc:
        return winutil.RunResult(-1, "", str(exc))
    decode = lambda raw: _ANSI.sub("", (raw or b"").decode("utf-8", errors="replace"))  # noqa: E731
    return winutil.RunResult(proc.returncode, decode(proc.stdout), decode(proc.stderr))


def version(name: str, exe: Path | None = None) -> str:
    """Версия из вывода `<exe> version`."""
    s = spec(name)
    exe = exe or verify(name)
    res = _run([str(exe), "version"], VERSION_TIMEOUT, cwd=exe.parent)
    match = _VERSION_OUTPUT[s.name].search(res.out + "\n" + res.err)
    if res.code != 0 or not match:
        detail = (res.err or res.out).strip().splitlines()[-1:] or [f"код {res.code}"]
        raise EngineError(f"{s.title} {s.agree('не сообщил')} версию: {detail[0][:200]}")
    return match.group(1).lstrip("v")


def check(name: str, config_path: Path, *, version: str | None = None) -> list[str]:
    """Статическая проверка конфига ядром. Ошибка — EngineError с текстом ядра; при коде 0 возвращает
    предупреждения (WARN об устаревшем — сигнал «генератору нужна миграция»)."""
    s = spec(name)
    exe = verify(name, version)
    if s.name == "sing-box":
        args = ["check", "--disable-color", "-D", str(config_path.parent), "-c", str(config_path)]
    else:
        args = ["run", "-test", "-c", str(config_path)]
    res = _run([str(exe), *args], CHECK_TIMEOUT, cwd=config_path.parent)
    lines = [ln.strip() for ln in (res.err + "\n" + res.out).splitlines() if ln.strip()]
    if res.code != 0:
        raise EngineError(f"{s.title} {s.agree('не принял')} конфигурацию: {_check_error(s.name, lines, res.code)}")
    return _check_warnings(s.name, lines)


def _check_error(name: str, lines: list[str], code: int) -> str:
    if name == "sing-box":
        for level in ("FATAL", "PANIC", "ERROR"):
            found = [m.group(2) for m in map(_SINGBOX_LINE.match, lines) if m and m.group(1) == level]
            if found:
                return found[-1][:500]
    else:
        failed = [ln for ln in lines if ln.startswith("Failed to start") or "failed to" in ln.lower()]
        if failed:
            return failed[-1][:500]
    return (lines[-1] if lines else f"код возврата {code}")[:500]


def _check_warnings(name: str, lines: list[str]) -> list[str]:
    if name == "sing-box":
        return [m.group(2) for m in map(_SINGBOX_LINE.match, lines) if m and m.group(1) == "WARN"]
    return [m.group(1) for m in map(_XRAY_WARNING.search, lines) if m]


# ------------------------------------------------------------ GitHub: маршруты, релизы, загрузка

def _opener(route: str):
    from ..updates import github
    return github.direct_opener() if route == "direct" else github.system_opener()


def via_routes(what: str, fn: Callable[[Any], T], cancel: threading.Event | None = None) -> T:
    """fn(opener) напрямую, а не вышло — через системный прокси. Файл не тот (хеш, размер) или загрузку
    отменили — второй маршрут не пробуем."""
    from ..updates import github
    failures: list[str] = []
    for route in ROUTES:
        try:
            return fn(_opener(route))
        except github.IntegrityError:
            raise
        except github.GitHubError as exc:
            if cancel is not None and cancel.is_set():
                raise
            failures.append(str(exc).rstrip("."))
            log.info("%s %s не вышло: %s", what, ROUTE_TITLE[route], exc)
    first, second = failures[0], failures[-1]
    raise EngineError(f"{first} (через системный прокси — тоже)" if first == second
                      else f"{first}; через системный прокси — {second}")


def newest(releases: list[dict]) -> dict | None:
    """Самый новый стабильный релиз из списка GitHub: без пре-релизов и меток вида 1.15.0-beta.1."""
    stable = [r for r in releases if isinstance(r, dict) and not r.get("prerelease")
              and _VERSION.match(str(r.get("version") or ""))]
    return max(stable, key=lambda r: version_key(r["version"]), default=None)


def release_for(name: str, rel: dict) -> Release:
    """Release из релиза GitHub: архив той же сборки, хеш — digest GitHub (без него не ставим), адрес — в
    релизах самого проекта. Закреплённая версия — с хешами из кода."""
    s = spec(name)
    ver = str(rel.get("version") or "")
    if not _VERSION.match(ver):
        raise EngineError(f"{s.title}: непонятная версия {ver!r}")
    if ver == s.version:
        return pinned_release(name)
    asset_name = s.asset_for(ver)
    asset = next((a for a in rel.get("assets") or [] if isinstance(a, dict) and a.get("name") == asset_name), None)
    if asset is None:
        raise EngineError(f"В релизе {ver} нет архива {asset_name}")
    if not asset.get("sha256"):
        raise EngineError("У архива нет опубликованной контрольной суммы — ставить его небезопасно")
    url = str(asset.get("url") or "")
    if not url.startswith(f"https://github.com/{s.repo}/releases/download/"):
        raise EngineError("Архив ядра лежит не в релизах его проекта — ставить его небезопасно")
    return Release(version=ver, url=url, zip_sha256=str(asset["sha256"]).lower(), size=int(asset.get("size") or 0))


def latest_release(name: str) -> Release | None:
    """Самый новый стабильный релиз ядра на GitHub — любой серии (1.15, 27.x); None — релизов нет."""
    from ..updates import github
    s = spec(name)
    found = via_routes(f"Список релизов {s.repo}", lambda opener: github.releases(s.repo, pages=1, opener=opener))
    best = newest(found)
    return release_for(name, best) if best else None


def _github_download(url: str, dest: Path, sha256: str, *, cancel: threading.Event | None,
                     progress: Callable[[int, int], None]) -> str:
    from ..updates import github
    return via_routes(f"Загрузка {url}", lambda opener: github.download(
        url, dest, sha256, progress=progress, cancel=cancel, timeout=30.0, limit=DOWNLOAD_LIMIT, opener=opener),
        cancel)


# ------------------------------------------------------------ установка

_install_locks = {name: threading.Lock() for name in CORES}
# Переименования папок версий одного ядра — замена при установке (_finish) и возврат прерванной
# (_recover_interrupted) — по одному: уборка не должна вернуть «прежнюю» папку посреди замены. Держится
# миллисекунды, поэтому уборка её ждёт; установке целиком — своя блокировка выше.
_layout_locks = {name: threading.Lock() for name in CORES}


def install(name: str, *, progress: Progress | None = None, source: Release | None = None,
            cancel: threading.Event | None = None, download: Callable[..., str] | None = None,
            origin: str = "github") -> str:
    """Скачивает с GitHub и ставит ядро; возвращает версию. source — Release новой версии (хеш — digest
    GitHub), без него — закреплённая (хеши в коде). origin — пометка в метке установки: "github"
    (подкачка, кнопка) или "auto" (автообновление). Активной версию делает менеджер (настройки)."""
    s = spec(name)
    guard.ensure_allowed(f"установка ядра {s.name}")
    if source is not None and not isinstance(source, Release):
        raise EngineError(f"Неизвестный источник ядра: {source}")
    lock = _install_locks[s.name]
    if not lock.acquire(blocking=False):
        raise EngineError(f"{s.title} уже устанавливается")
    try:
        return _install(s, progress or (lambda *_: None), source or pinned_release(s.name), cancel, download, origin)
    finally:
        lock.release()


def _install(s: CoreSpec, progress: Progress, release: Release, cancel: threading.Event | None,
             download: Callable[..., str] | None, origin: str) -> str:
    paths.TMP_DIR.mkdir(parents=True, exist_ok=True)
    zip_copy = paths.TMP_DIR / f"{s.name}-{release.version}-{uuid.uuid4().hex[:8]}.zip"
    staging = version_dir(s.name, release.version).with_name(f"{release.version}.staging")
    try:
        progress("downloading", 0.0)
        got = (download or _github_download)(
            release.url, zip_copy, release.zip_sha256, cancel=cancel,
            progress=lambda done, total: progress("downloading", done / total if total else None))
        progress("verifying", None)
        if got.lower() != release.zip_sha256.lower():
            raise EngineError(f"{s.title}: контрольная сумма архива не совпала — файл повреждён или подменён")
        progress("installing", None)
        try:
            _unpack(s, zip_copy, staging)
        except (archive.ArchiveError, zipfile.BadZipFile) as exc:
            raise ReleaseRejected(f"{s.title}: архив не распаковался — {exc}") from exc
        exe_sha = _check_staging(s, release, staging)
        _finish(s, release, staging, exe_sha, origin)
    except OSError as exc:
        raise EngineError(f"{s.title}: установка не удалась — {exc}") from exc
    finally:
        zip_copy.unlink(missing_ok=True)
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)
    log.info("%s %s установлено с GitHub (%s)", s.title, release.version, origin)
    return release.version


def _unpack(s: CoreSpec, zip_path: Path, staging: Path) -> None:
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)
    skip = {name.lower() for name in s.skip}
    archive.extract(zip_path, staging, max_unpacked=CORE_MAX_UNPACKED,
                    skip=(lambda rel: rel.name.lower() in skip) if skip else None)


def _check_staging(s: CoreSpec, release: Release, staging: Path) -> str:
    exe = staging / s.exe
    if not exe.is_file():
        raise ReleaseRejected(f"{s.title}: в архиве нет {s.exe}")
    actual = sha256_file(exe)
    if release.exe_sha256 and actual.lower() != release.exe_sha256.lower():
        raise ReleaseRejected(f"{s.title}: контрольная сумма {s.exe} не совпала с закреплённой")
    try:
        reported = version(s.name, exe)
    except EngineError as exc:
        raise ReleaseRejected(str(exc)) from exc
    if reported != release.version:
        raise ReleaseRejected(f"{s.title}: в архиве версия {reported}, ожидалась {release.version}")
    if s.gpl_text:
        shutil.copyfile(gpl_text_path(), staging / GPL_FILE)
    return actual


def _finish(s: CoreSpec, release: Release, staging: Path, exe_sha: str, origin: str) -> None:
    marker = {"name": s.name, "version": release.version, "exe": s.exe, "exe_sha256": exe_sha,
              "zip_sha256": release.zip_sha256.lower(), "source": origin, "installed_at": time.time()}
    (staging / MARKER).write_text(json.dumps(marker, ensure_ascii=False, indent=2), encoding="utf-8")
    final = version_dir(s.name, release.version)
    with _layout_locks[s.name]:
        old = _swap_in(s, release, staging, final)
    if old is not None:
        shutil.rmtree(old, ignore_errors=True)


def _swap_in(s: CoreSpec, release: Release, staging: Path, final: Path) -> Path | None:
    """Прежняя установка этой версии — в сторону, новая — на её место. Ответ — куда ушла прежняя (удалить)."""
    old = None
    if final.exists():
        old = final.with_name(f"{release.version}{OLD_MARK}{uuid.uuid4().hex[:8]}")
        try:
            os.rename(final, old)
        except OSError as exc:
            raise EngineError(f"{s.title} {release.version} сейчас {s.agree('запущен')} — выключите VPN и "
                              "повторите") from exc
    try:
        os.rename(staging, final)
    except OSError:
        if old is not None:
            # Прежняя установка этой версии — на место: иначе installed() её бы больше не видел.
            try:
                os.rename(old, final)
            except OSError as exc:
                log.error("%s %s: прежняя установка не вернулась на место (%s) — вернётся при следующей "
                          "проверке установленных версий", s.title, release.version, exc)
        raise
    return old


def _recover_interrupted(name: str) -> None:
    """Установка прервалась между двумя переименованиями (_finish): папки версии нет, а прежняя лежит
    рядом как <версия>.old-* — вернуть её на место. Идущей установке не мешаем: её переименования — под той
    же блокировкой, а саму установку уборка не держит (иначе install() ответил бы «уже устанавливается»)."""
    root = core_root(name)
    if not root.is_dir():
        return
    with _layout_locks[spec(name).name]:
        try:
            for entry in sorted(root.iterdir(), key=lambda p: p.name):
                version, mark, _ = entry.name.partition(OLD_MARK)
                if not mark or not entry.is_dir() or not _VERSION.match(version) or (root / version).exists():
                    continue
                try:
                    os.rename(entry, root / version)
                    log.warning("%s %s: прерванная установка — прежняя версия возвращена на место", name, version)
                except OSError as exc:
                    log.warning("%s %s: прежняя версия после прерванной установки не вернулась: %s", name, version,
                                exc)
        except OSError as exc:
            log.warning("Папка ядра %s не прочитана: %s", name, exc)


def prune(name: str, keep: set[str]) -> list[str]:
    """Удаляет версии, кроме keep (активная и прежняя — для отката), и брошенные папки установки (прежнюю
    версию из прерванной установки сначала возвращает на место)."""
    root = core_root(name)
    removed: list[str] = []
    if not root.is_dir():
        return removed
    _recover_interrupted(name)
    for entry in root.iterdir():
        if not entry.is_dir() or entry.name in keep:
            continue
        leftover = ".staging" in entry.name or OLD_MARK in entry.name
        if leftover or _VERSION.match(entry.name):
            shutil.rmtree(entry, ignore_errors=True)
            removed.append(entry.name)
    return removed
