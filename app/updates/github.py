"""Минимальный клиент GitHub: релизы, файлы тега, скачивание с проверкой хеша.

Маршрут запросов явный: по умолчанию — напрямую, без системного прокси из реестра (его
выставляет и свой VPN Лазейки, и чужой — запрос молча ушёл бы через него), как проверки
обхода ходят через `curl -q --noproxy *`. Через своё ядро — только переданным opener. Через
системный прокси — тоже только явно (system_opener): запасной маршрут загрузки ядер своего VPN.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import threading
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable

from .. import __version__
from ..vendor.tgws_proxy.utils import build_github_opener, create_ssl_context
from ..errors import UserError

log = logging.getLogger("lazeyka.updates.github")

API = "https://api.github.com"
USER_AGENT = f"Lazeyka/{__version__} (+https://github.com)"
_SHA256 = re.compile(r"^sha256:([0-9a-f]{64})$", re.I)

Opener = urllib.request.OpenerDirector


class GitHubError(UserError):
    pass


class IntegrityError(GitHubError):
    """Файл скачан, но не тот (хеш, размер): другим маршрутом повторять бессмысленно."""


def direct_opener() -> Opener:
    """Напрямую: ProxyHandler({}) отключает системный прокси и переменные HTTPS_PROXY; адреса
    GitHub закреплены так же, как в build_github_opener (провайдер подменяет DNS)."""
    https = [h for h in build_github_opener().handlers if isinstance(h, urllib.request.HTTPSHandler)]
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), *https)


def system_opener() -> Opener:
    """Обычный маршрут Windows: системный прокси (реестр, HTTPS_PROXY) и системный DNS. Запасной —
    у человека может работать другой VPN в режиме прокси, а напрямую GitHub недоступен."""
    return urllib.request.build_opener(urllib.request.ProxyHandler(),
                                       urllib.request.HTTPSHandler(context=create_ssl_context()))


def _request(url: str, accept: str | None = None) -> urllib.request.Request:
    headers = {"User-Agent": USER_AGENT, "Cache-Control": "no-cache"}
    if accept:
        headers["Accept"] = accept
    return urllib.request.Request(url, headers=headers)


def _explain(exc: Exception, url: str) -> GitHubError:
    if isinstance(exc, urllib.error.HTTPError):
        if exc.code == 403 and exc.headers.get("X-RateLimit-Remaining") == "0":
            return GitHubError("GitHub временно ограничил число запросов — попробуйте через час")
        if exc.code == 404:
            return GitHubError("На GitHub не найдено (404)")
        return GitHubError(f"GitHub ответил ошибкой {exc.code}")
    if isinstance(exc, urllib.error.URLError):
        reason = exc.reason
        return GitHubError(f"Нет связи с GitHub: {reason}")
    if isinstance(exc, TimeoutError):
        return GitHubError("GitHub не ответил вовремя")
    return GitHubError(f"Ошибка связи с GitHub: {exc}")


def http_get(url: str, timeout: float = 15.0, accept: str | None = None, limit: int = 32 * 1024 * 1024,
             opener: Opener | None = None) -> bytes:
    """GET с лимитом размера. opener — явный маршрут (например, через своё ядро); по умолчанию напрямую."""
    try:
        with (opener or direct_opener()).open(_request(url, accept), timeout=timeout) as resp:
            data = resp.read(limit + 1)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise _explain(exc, url) from exc
    if len(data) > limit:
        raise GitHubError("Ответ слишком большой")
    return data


def http_get_json(url: str, timeout: float = 15.0, opener: Opener | None = None):
    data = http_get(url, timeout=timeout, accept="application/vnd.github+json", opener=opener)
    try:
        return json.loads(data.decode("utf-8"))
    except ValueError as exc:
        raise GitHubError("GitHub прислал непонятный ответ") from exc


def _release(data: dict, repo: str) -> dict:
    assets = []
    for a in data.get("assets") or []:
        if isinstance(a, dict) and isinstance(a.get("name"), str) and isinstance(a.get("browser_download_url"), str):
            digest = a.get("digest") if isinstance(a.get("digest"), str) else ""
            m = _SHA256.match(digest or "")
            assets.append({"name": a["name"], "url": a["browser_download_url"],
                           "sha256": m.group(1).lower() if m else None, "size": int(a.get("size") or 0)})
    return {
        "tag": data["tag_name"].strip(),
        "version": data["tag_name"].strip().lstrip("vV"),
        "name": str(data.get("name") or data["tag_name"]),
        "notes": str(data.get("body") or "")[:20000],
        "url": str(data.get("html_url") or f"https://github.com/{repo}/releases"),
        "published_at": data.get("published_at"),
        "prerelease": bool(data.get("prerelease")),
        "assets": assets,
    }


def latest_release(repo: str, opener: Opener | None = None) -> dict:
    data = http_get_json(f"{API}/repos/{repo}/releases/latest", opener=opener)
    if not isinstance(data, dict) or not isinstance(data.get("tag_name"), str):
        raise GitHubError("Некорректный ответ о релизе")
    return _release(data, repo)


def releases(repo: str, *, per_page: int = 100, pages: int = 1, opener: Opener | None = None) -> list[dict]:
    """Список релизов, новые первыми, без черновиков (пре-релизы помечены prerelease).

    Нужен ядрам своего VPN: releases/latest не отличает метки вида 1.15.0-beta.1, если релиз не помечен
    пре-релизом, а список позволяет выбрать самую новую стабильную версию самим (engines.newest)."""
    out: list[dict] = []
    for page in range(1, max(1, pages) + 1):
        data = http_get_json(f"{API}/repos/{repo}/releases?per_page={per_page}&page={page}", opener=opener)
        if not isinstance(data, list):
            raise GitHubError("Некорректный ответ о релизах")
        for item in data:
            if isinstance(item, dict) and isinstance(item.get("tag_name"), str) and not item.get("draft"):
                out.append(_release(item, repo))
        if len(data) < per_page:
            break
    return out


def tree(repo: str, ref: str, opener: Opener | None = None) -> list[dict]:
    data = http_get_json(f"{API}/repos/{repo}/git/trees/{urllib.request.quote(ref)}?recursive=1", opener=opener)
    if not isinstance(data, dict) or not isinstance(data.get("tree"), list):
        raise GitHubError("Некорректное дерево файлов")
    if data.get("truncated"):
        raise GitHubError("Дерево файлов на GitHub обрезано")
    return [e for e in data["tree"] if isinstance(e, dict) and isinstance(e.get("path"), str)]


def raw_file(repo: str, ref: str, path: str, limit: int = 2 * 1024 * 1024, opener: Opener | None = None) -> bytes:
    url = f"https://raw.githubusercontent.com/{repo}/{urllib.request.quote(ref)}/{urllib.request.quote(path)}"
    return http_get(url, timeout=20, limit=limit, opener=opener)


def git_blob_sha1(data: bytes) -> str:
    """Хеш, которым git идентифицирует содержимое файла (sha1("blob <len>\\0" + data))."""
    return hashlib.sha1(b"blob %d\x00" % len(data) + data).hexdigest()


def download(url: str, dest: Path, expected_sha256: str | None, *,
             progress: Callable[[int, int], None] | None = None,
             cancel: threading.Event | None = None, timeout: float = 30.0,
             limit: int = 200 * 1024 * 1024, opener: Opener | None = None) -> str:
    """Скачивает файл и возвращает его SHA-256. При несовпадении хеша файл удаляется."""
    sha = hashlib.sha256()
    done = 0
    try:
        with (opener or direct_opener()).open(_request(url), timeout=timeout) as resp, open(dest, "wb") as out:
            total = int(resp.headers.get("Content-Length") or 0)
            while True:
                if cancel is not None and cancel.is_set():
                    raise GitHubError("Загрузка отменена")
                chunk = resp.read(256 * 1024)
                if not chunk:
                    break
                done += len(chunk)
                if done > limit:
                    raise IntegrityError("Файл слишком большой")
                out.write(chunk)
                sha.update(chunk)
                if progress:
                    progress(done, total)
    except GitHubError:
        dest.unlink(missing_ok=True)
        raise
    except (urllib.error.URLError, OSError, ValueError) as exc:
        dest.unlink(missing_ok=True)
        raise _explain(exc, url) from exc
    digest = sha.hexdigest()
    if expected_sha256 and digest.lower() != expected_sha256.lower():
        dest.unlink(missing_ok=True)
        raise IntegrityError("Контрольная сумма скачанного файла не совпала с опубликованной на GitHub")
    return digest
