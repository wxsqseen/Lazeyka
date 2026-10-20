"""Файлы правил своего VPN: rule-set .srs sing-box для пресетов и профилей маршрутизации.

Источники — данными (SOURCES): у каждого способ проверки. Файл из ветки репозитория — git-blob
SHA-1 (`sha` из contents API GitHub), ассет релиза — SHA-256 из поля `digest` releases API. Это
сверка с API GitHub по TLS, не подпись. Дальше — заголовок `SRS` и версия формата (не новее
понимаемой ядром), атомарная замена файла и запись в rules.json
(источник, хеш, даты). Сбой одного источника не ломает пресет: остальные файлы обновляются,
прежний файл остаётся (final_rules.md, 2–3).

Маршрут загрузки — колбэком opener_for(route): "direct" — напрямую, "core" — через своё ядро;
None — маршрут сейчас недоступен. Порядок: напрямую → через ядро → зеркало jsDelivr.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable

from ..errors import UserError
from ..updates import github
from . import routing

log = logging.getLogger("lazeyka.vpnclient.rules")

ROUTES = ("direct", "core")
SRS_MAGIC = b"SRS"
MAX_SRS_VERSION = 5                  # sing-box 1.14: C.RuleSetVersionCurrent
CHECK_EVERY = 24 * 3600              # проверка обновлений — не чаще раза в сутки
STALE_AFTER = 30 * 24 * 3600         # старше — мягкое предупреждение
MAX_SIZE = 16 * 1024 * 1024
TIMEOUT = 20.0
META_FILE = "rules.json"
_NAME = re.compile(r"[a-z0-9][a-z0-9._@!-]*")

Opener = Any                          # urllib.request.OpenerDirector или подделка с .open(req, timeout=)


class RulesError(UserError):
    pass


@dataclass(frozen=True)
class Mirror:
    """Где лежит файл. ref — ветка (проверка git-blob); пусто — ассет последнего релиза (digest)."""

    repo: str
    path: str
    ref: str = ""

    @property
    def verify(self) -> str:
        return "git-blob" if self.ref else "digest"

    @property
    def label(self) -> str:
        return f"{self.repo}:{self.ref or 'releases'}/{self.path}"

    def raw_url(self) -> str:
        return f"https://raw.githubusercontent.com/{self.repo}/{self.ref}/{self.path}"

    def jsdelivr_url(self) -> str:
        return f"https://cdn.jsdelivr.net/gh/{self.repo}@{self.ref}/{self.path}"

    def contents_api(self) -> str:
        return f"{github.API}/repos/{self.repo}/contents/{self.path}?ref={self.ref}"


@dataclass(frozen=True)
class Source:
    id: str
    title: str
    kind: str                       # domain | ip
    mirrors: tuple[Mirror, ...]
    license: str = ""


def _sagernet(set_id: str) -> Mirror:
    repo = "SagerNet/sing-geoip" if set_id.startswith("geoip-") else "SagerNet/sing-geosite"
    return Mirror(repo, f"{set_id}.srs", "rule-set")


SOURCES: dict[str, Source] = {s.id: s for s in (
    Source(routing.RU_DOMAINS, "Российские сайты", "domain", (_sagernet(routing.RU_DOMAINS),),
           "GPL-3.0 (данные v2fly, MIT)"),
    Source(routing.RU_IPS, "Российские IP-адреса", "ip",
           (_sagernet(routing.RU_IPS), Mirror("Loyalsoldier/geoip", "srs/ru.srs", "release")),
           "GPL-3.0 / CC-BY-SA-4.0, данные GeoLite2"),
    Source(routing.GAMES_DOWNLOAD, "Загрузки игр", "domain", (_sagernet(routing.GAMES_DOWNLOAD),),
           "GPL-3.0 (данные v2fly, MIT)"),
    Source("refilter-domains", "Заблокированные сайты (re:filter)", "domain",
           (Mirror("1andrevich/Re-filter-lists", "ruleset-domain-refilter_domains.srs"),), "MIT"),
    Source("russia-inside", "Заблокированные сайты (itdoginfo)", "domain",
           (Mirror("itdoginfo/allow-domains", "russia_inside.srs"),), "лицензия не указана"),
    Source(routing.BLOCKED_IPS, "Заблокированные IP-адреса", "ip",
           (Mirror("runetfreedom/russia-v2ray-rules-dat", "sing-box/rule-set-geoip/geoip-ru-blocked.srs", "release"),
            Mirror("1andrevich/Re-filter-lists", "ruleset-ip-refilter_ipsum.srs")), "GPL-3.0 / MIT"),
)}


def source_for(set_id: str) -> Source | None:
    """Источник набора: из SOURCES или geosite-X / geoip-X из rule-set SagerNet (профили маршрутов)."""
    if set_id in SOURCES:
        return SOURCES[set_id]
    for prefix, kind in (("geosite-", "domain"), ("geoip-", "ip")):
        if set_id.startswith(prefix) and _NAME.fullmatch(set_id[len(prefix):]):
            return Source(set_id, set_id, kind, (_sagernet(set_id),), "GPL-3.0")
    return None


def srs_version(data: bytes) -> int | None:
    """Версия формата SRS по заголовку; None — не файл rule-set."""
    if len(data) < 4 or data[:3] != SRS_MAGIC:
        return None
    return data[3]


class RulesManager:
    """Файлы правил в папке dir: <id>.srs и rules.json."""

    def __init__(self, dir: Path, *, opener_for: Callable[[str], Opener | None]):
        self.dir = Path(dir)
        self.opener_for = opener_for
        self._lock = threading.Lock()
        self._updating = False

    # ---------------------------------------------------------------- файлы

    def path(self, set_id: str) -> Path:
        if not _NAME.fullmatch(set_id):
            raise RulesError(f"Недопустимое имя набора правил: {set_id!r}")
        return self.dir / f"{set_id}.srs"

    def _usable(self, path: Path) -> bool:
        try:
            with path.open("rb") as fh:
                version = srs_version(fh.read(4))
        except OSError:
            return False
        return version is not None and version <= MAX_SRS_VERSION

    def paths(self, ids: Iterable[str]) -> dict[str, Path]:
        """Наборы, которые уже есть и годятся ядру: id → путь (для RunPlan.rules_files)."""
        out = {}
        for set_id in dict.fromkeys(ids):
            path = self.path(set_id)
            if self._usable(path):
                out[set_id] = path
        return out

    def missing(self, ids: Iterable[str]) -> list[str]:
        have = self.paths(ids)
        return [i for i in dict.fromkeys(ids) if i not in have]

    # ---------------------------------------------------------------- rules.json

    def _meta(self) -> dict[str, dict[str, Any]]:
        try:
            data = json.loads((self.dir / META_FILE).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        items = data.get("items") if isinstance(data, dict) else None
        return {k: v for k, v in (items or {}).items() if isinstance(v, dict)}

    def _save_meta(self, meta: dict[str, dict[str, Any]]) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        target = self.dir / META_FILE
        tmp = target.with_name(target.name + ".tmp")
        tmp.write_text(json.dumps({"schema": 1, "items": meta}, ensure_ascii=False, indent=1), encoding="utf-8")
        os.replace(tmp, target)

    # ---------------------------------------------------------------- загрузка

    def _fetch(self, urls: list[str], *, as_json: bool = False) -> Any:
        """Первый удачный ответ: адреса по порядку, для каждого — маршруты напрямую → через ядро."""
        last: Exception | None = None
        for url in urls:
            for route in ROUTES:
                opener = self.opener_for(route)
                if opener is None:
                    continue
                try:
                    if as_json:
                        return github.http_get_json(url, timeout=TIMEOUT, opener=opener)
                    return github.http_get(url, timeout=TIMEOUT, limit=MAX_SIZE, opener=opener)
                except github.GitHubError as exc:
                    last = exc
                    log.info("Список правил: %s (%s) — %s", url.split("?")[0], route, exc)
        if last is None:
            raise RulesError("Нет маршрута для загрузки: ни напрямую, ни через своё ядро")
        raise RulesError(str(last))

    def _expected(self, mirror: Mirror) -> tuple[str, list[str]]:
        """(ожидаемый хеш «sha1:…»/«sha256:…», адреса файла) — из API GitHub."""
        if mirror.verify == "git-blob":
            data = self._fetch([mirror.contents_api()], as_json=True)
            sha = data.get("sha") if isinstance(data, dict) else None
            if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{40}", sha):
                raise RulesError(f"GitHub не сообщил хеш файла {mirror.path}")
            return f"sha1:{sha}", [mirror.raw_url(), mirror.jsdelivr_url()]
        release = None
        last: Exception | None = None
        for route in ROUTES:
            opener = self.opener_for(route)
            if opener is None:
                continue
            try:
                release = github.latest_release(mirror.repo, opener=opener)
                break
            except github.GitHubError as exc:
                last = exc
        if release is None:
            raise RulesError(str(last) if last else "Нет маршрута для загрузки: ни напрямую, ни через своё ядро")
        asset = next((a for a in release["assets"] if a["name"] == mirror.path), None)
        if asset is None:
            raise RulesError(f"В последнем релизе {mirror.repo} нет файла {mirror.path}")
        if not asset.get("sha256"):
            raise RulesError(f"У файла {mirror.path} в релизе нет digest — проверить его нечем")
        return f"sha256:{asset['sha256']}", [asset["url"]]

    @staticmethod
    def _actual(expected: str, data: bytes) -> str:
        if expected.startswith("sha1:"):
            return f"sha1:{github.git_blob_sha1(data)}"
        return f"sha256:{hashlib.sha256(data).hexdigest()}"

    def _install(self, set_id: str, data: bytes) -> None:
        """Атомарная замена: новый файл — во временный рядом, затем os.replace."""
        self.dir.mkdir(parents=True, exist_ok=True)
        target = self.path(set_id)
        tmp = target.with_name(target.name + ".tmp")
        tmp.write_bytes(data)
        os.replace(tmp, target)

    def _update_one(self, source: Source, meta: dict[str, dict[str, Any]], force: bool) -> str:
        entry = meta.setdefault(source.id, {})
        now = time.time()
        installed = self._usable(self.path(source.id))
        if not force and installed and now - float(entry.get("checked_at") or 0) < CHECK_EVERY:
            return "fresh"
        errors: list[str] = []
        for mirror in source.mirrors:
            try:
                expected, urls = self._expected(mirror)
                if installed and entry.get("hash") == expected and entry.get("source") == mirror.label:
                    entry.update({"checked_at": now, "error": None})
                    return "same"
                data = self._fetch(urls)
                actual = self._actual(expected, data)
                if actual != expected:
                    raise RulesError(f"хеш {mirror.path} не совпал с GitHub (ожидали {expected}, получили {actual})")
                version = srs_version(data)
                if version is None:
                    raise RulesError(f"{mirror.path} — не файл rule-set sing-box")
                if version > MAX_SRS_VERSION:
                    raise RulesError(f"{mirror.path}: формат SRS версии {version}, ядро понимает до {MAX_SRS_VERSION}")
                self._install(source.id, data)
                entry.update({"source": mirror.label, "hash": expected, "size": len(data), "version": version,
                              "updated_at": now, "checked_at": now, "error": None})
                return "updated"
            except (RulesError, github.GitHubError, OSError) as exc:
                errors.append(f"{mirror.repo}: {exc}")
        entry.update({"checked_at": now, "error": "; ".join(errors)})
        return "failed"

    def update(self, ids: Iterable[str], force: bool = False) -> dict[str, str]:
        """Обновить наборы: id → updated | same | fresh | failed | unknown. Не бросает из-за одного
        источника — ошибка записывается в rules.json и видна в status()."""
        results: dict[str, str] = {}
        with self._lock:
            self._updating = True
            try:
                meta = self._meta()
                for set_id in dict.fromkeys(ids):
                    source = source_for(set_id)
                    if source is None:
                        results[set_id] = "unknown"
                        continue
                    results[set_id] = self._update_one(source, meta, force)
                    if results[set_id] == "failed":
                        log.warning("Список правил %s не обновлён: %s", set_id, meta[set_id].get("error"))
                self._save_meta(meta)
            finally:
                self._updating = False
        return results

    # ---------------------------------------------------------------- состояние для страницы

    def status(self) -> dict[str, Any]:
        """Для vpnclient.routing.rules: состояние, дата самого старого набора, «устарело», наборы."""
        meta = self._meta()
        now = time.time()
        items = []
        for set_id in sorted(meta):
            entry = meta[set_id]
            source = source_for(set_id)
            present = self._usable(self.path(set_id)) if _NAME.fullmatch(set_id) else False
            updated = entry.get("updated_at")
            items.append({
                "id": set_id, "title": source.title if source else set_id,
                "kind": source.kind if source else routing.rule_set_kind(set_id),
                "present": present, "updated_at": updated, "checked_at": entry.get("checked_at"),
                "size": entry.get("size"), "source": entry.get("source"), "error": entry.get("error"),
                "stale": bool(present and updated and now - float(updated) > STALE_AFTER),
            })
        dates = [i["updated_at"] for i in items if i["present"] and i["updated_at"]]
        return {"state": "updating" if self._updating else "idle",
                "updated_at": min(dates) if dates else None,
                "stale": any(i["stale"] for i in items), "items": items}
