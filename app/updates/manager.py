"""Обновления компонентов: только сообщаем, ставим — только по нажатию.

- zapret: релизный zip Flowseal/zapret-discord-youtube, SHA-256 обязателен
  (GitHub публикует его для каждого файла релиза).
- tg-ws-proxy: файлы папки proxy/ по тегу релиза. Каждый файл сверяется с
  git-хешем из дерева того же тега, полученного через API.
"""
from __future__ import annotations

import logging
import os
import shutil
import threading
import time
import uuid
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Callable

from .. import APP_REPO, TGWS_REPO, ZAPRET_REPO, __version__, paths
from ..tgproxy import loader
from ..zapret import pack
from . import github
from ..errors import UserError

if TYPE_CHECKING:
    from ..settings import Settings
    from ..tgproxy.manager import TgProxyManager
    from ..zapret.manager import ZapretManager

log = logging.getLogger("lazeyka.updates")

Notify = Callable[[str, str], None]


class UpdateError(UserError):
    pass


class UpdateManager:
    def __init__(self, settings: "Settings", zapret: "ZapretManager", tg: "TgProxyManager",
                 notify: Notify, is_admin: bool):
        self.settings = settings
        self.zapret = zapret
        self.tg = tg
        self.notify = notify
        self.is_admin = is_admin
        self.lock = threading.RLock()
        self.checking = False
        self.error: str | None = None
        self.releases: dict[str, dict | None] = {"zapret": None, "tgws": None, "app": None}
        self.progress: dict[str, dict] = {k: {"state": "idle", "progress": None, "message": None}
                                          for k in self.releases}
        self._busy: set[str] = set()

    # ------------------------------------------------------------ проверка

    def check_async(self, quiet: bool = False) -> None:
        with self.lock:
            if self.checking:
                return
            self.checking = True
        threading.Thread(target=self._check, args=(quiet,), name="update-check", daemon=True).start()

    def _check(self, quiet: bool) -> None:
        errors = []
        sources = [("zapret", ZAPRET_REPO), ("tgws", TGWS_REPO), ("app", APP_REPO)]
        for key, repo in sources:
            try:
                self.releases[key] = github.latest_release(repo)
            except github.GitHubError as exc:
                # У самой Лазейки релиза может ещё не быть — это не ошибка проверки.
                if not (key == "app" and "404" in str(exc)):
                    errors.append(str(exc))
                log.warning("Проверка обновлений %s: %s", repo, exc)
        with self.lock:
            self.checking = False
            self.error = errors[0] if errors and len(errors) == len(sources) else None
        self.settings.update(lambda d: d["updates"].__setitem__("last_check", time.time()))
        count = self.available_count()
        log.info("Проверка обновлений завершена: доступно %d", count)
        if not quiet and not errors and count == 0:
            self.notify("success", "Всё актуально — обновлений нет.")

    def current_version(self, key: str) -> str | None:
        if key == "zapret":
            return self.zapret.pack.version if self.zapret.pack else None
        if key == "app":
            return __version__
        return self.tg.core.version if self.tg.core else None

    def is_available(self, key: str) -> bool:
        rel = self.releases.get(key)
        current = self.current_version(key)
        if not rel:
            return False
        if current is None:
            return True
        return pack.version_key(rel["version"]) > pack.version_key(current)

    def is_skipped(self, key: str) -> bool:
        rel = self.releases.get(key)
        return bool(rel) and self.settings.get("updates", "skipped").get(key) == rel["version"]

    def available_count(self) -> int:
        return sum(1 for k in self.releases if self.is_available(k) and not self.is_skipped(k))

    def skip(self, key: str) -> None:
        rel = self.releases.get(key)
        if not rel:
            raise UpdateError("Сначала проверьте обновления")
        self.settings.update(lambda d: d["updates"]["skipped"].__setitem__(key, rel["version"]))

    # ------------------------------------------------------------ установка

    def _set(self, key: str, state: str, progress: float | None = None, message: str | None = None) -> None:
        self.progress[key] = {"state": state, "progress": progress, "message": message}

    def install_async(self, key: str) -> None:
        jobs = {"zapret": self._install_zapret, "tgws": self._install_tgws, "app": self._install_app}
        self._start_job(key, jobs.get(key))

    def rollback_async(self, key: str) -> None:
        jobs = {"zapret": self._rollback_zapret, "tgws": self._rollback_tgws, "app": self._rollback_app}
        self._start_job(key, jobs.get(key))

    def _start_job(self, key: str, job: Callable[[], str]) -> None:
        if key not in self.releases:
            raise UpdateError("Неизвестный компонент")
        if not self.is_admin:
            raise UpdateError("Устанавливать обновления можно только с правами администратора")
        with self.lock:
            if key in self._busy:
                raise UpdateError("Уже выполняется")
            self._busy.add(key)

        def run() -> None:
            try:
                message = job()
                self._set(key, "done", 1.0, message)
                self.notify("success", message)
            except Exception as exc:  # noqa: BLE001
                log.exception("Обновление %s не удалось", key)
                self._set(key, "error", None, str(exc))
                self.notify("error", f"Не удалось: {exc}")
            finally:
                with self.lock:
                    self._busy.discard(key)

        threading.Thread(target=run, name=f"update-{key}", daemon=True).start()

    def _install_zapret(self) -> str:
        rel = self.releases.get("zapret")
        if not rel:
            raise UpdateError("Сначала проверьте обновления")
        asset = next((a for a in rel["assets"] if a["name"].lower().endswith(".zip")
                      and rel["version"] in a["name"]), None)
        if asset is None:
            raise UpdateError("В релизе нет zip-архива")
        if not asset["sha256"]:
            raise UpdateError("У архива нет опубликованной контрольной суммы — ставить его небезопасно")
        paths.TMP_DIR.mkdir(parents=True, exist_ok=True)
        target = paths.TMP_DIR / f"dl-{uuid.uuid4().hex[:8]}.zip"
        self._set("zapret", "downloading", 0.0, f"Скачиваю {asset['name']}")
        try:
            github.download(asset["url"], target, asset["sha256"],
                            progress=lambda done, total: self._set(
                                "zapret", "downloading", (done / total) if total else None,
                                f"Скачано {done // 1024} КБ"))
            self._set("zapret", "verifying", None, "Проверяю пакет")
            info = pack.install_zip(target, rel["version"], source="github",
                                    expected_sha256=asset["sha256"], published_at=rel.get("published_at"))
        finally:
            target.unlink(missing_ok=True)
        self._set("zapret", "installing", None, "Переключаю стратегии на новую версию")
        previous = self.zapret.pack.version if self.zapret.pack else None
        self.zapret.switch_pack(info)
        keep = {info.version} | ({previous} if previous else set())
        pack.cleanup(keep)
        return f"Стратегии zapret обновлены до {info.version}"

    def _rollback_zapret(self) -> str:
        current = self.zapret.pack.version if self.zapret.pack else None
        older = [p for p in pack.installed() if p.version != current
                 and (current is None or pack.version_key(p.version) < pack.version_key(current))]
        if not older:
            raise UpdateError("Нет предыдущей версии для отката")
        target = older[-1]
        self._set("zapret", "installing", None, f"Возвращаю {target.version}")
        self.zapret.switch_pack(target)
        return f"Стратегии zapret возвращены к версии {target.version}"

    def _install_tgws(self) -> str:
        rel = self.releases.get("tgws")
        if not rel:
            raise UpdateError("Сначала проверьте обновления")
        tag, version = rel["tag"], rel["version"]
        self._set("tgws", "downloading", 0.0, "Получаю список файлов")
        entries = [e for e in github.tree(TGWS_REPO, tag)
                   if e.get("type") == "blob" and e["path"].startswith("proxy/") and e["path"].endswith(".py")]
        if not any(e["path"] == "proxy/tg_ws_proxy.py" for e in entries):
            raise UpdateError("В релизе нет ядра прокси (proxy/tg_ws_proxy.py)")
        staging = paths.TMP_DIR / f"tgws-{uuid.uuid4().hex[:8]}"
        package_dir = staging / "tgws_proxy"
        try:
            for index, entry in enumerate(entries, 1):
                rel_path = PurePosixPath(entry["path"]).relative_to("proxy")
                if ".." in rel_path.parts:
                    raise UpdateError("Небезопасный путь в релизе")
                data = github.raw_file(TGWS_REPO, tag, entry["path"])
                if github.git_blob_sha1(data) != entry.get("sha"):
                    raise UpdateError(f"Файл {entry['path']} не совпал с git-хешем релиза")
                dest = package_dir.joinpath(*rel_path.parts)
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(data)
                self._set("tgws", "downloading", index / len(entries), f"Файл {index} из {len(entries)}")
            self._set("tgws", "verifying", None, "Проверяю ядро")
            final = paths.TGWS_COMPONENTS_DIR / pack.safe_version(version)
            if final.exists():
                if self.tg.core and self.tg.core.origin == "updated" and self.tg.core.version == version:
                    raise UpdateError("Эта версия уже работает")
                shutil.rmtree(final)
            final.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(staging), str(final))
        finally:
            shutil.rmtree(staging, ignore_errors=True)
        try:
            core = loader.load_from_dir(final / "tgws_proxy", version)
        except loader.CoreError as exc:
            shutil.rmtree(final, ignore_errors=True)
            raise UpdateError(f"Новое ядро несовместимо с этой версией Лазейки: {exc}") from exc
        self._set("tgws", "installing", None, "Перезапускаю прокси на новом ядре")
        self.settings.update(lambda d: d["tg"].__setitem__("core", pack.safe_version(version)))
        try:
            self.tg.switch_core(core)
        except Exception as exc:  # noqa: BLE001
            log.error("Новое ядро не запустилось: %s — возвращаю встроенное", exc)
            self.settings.update(lambda d: d["tg"].__setitem__("core", "bundled"))
            self.tg.switch_core(loader.load_bundled())
            raise UpdateError(f"Новое ядро не запустилось ({exc}); возвращено встроенное") from exc
        # Прежние скачанные ядра больше не нужны (откат — к встроенному), чтобы они не копились.
        remove_component_dirs({pack.safe_version(version)})
        return f"Ядро Telegram-прокси обновлено до {core.version}"

    def _rollback_tgws(self) -> str:
        self.settings.update(lambda d: d["tg"].__setitem__("core", "bundled"))
        core = loader.load_bundled()
        self.tg.switch_core(core)
        return f"Возвращено встроенное ядро Telegram-прокси {core.version}"

    # ------------------------------------------------------------ сама Лазейка
    #
    # Скачиваем новый Lazeyka.exe из релиза, сверяем по SHA-256, опубликованному GitHub, и
    # заменяем работающий файл. Работающий exe на Windows удалить нельзя, но можно переименовать:
    # отодвигаем его в <имя>.old, ставим новый на его место, прежний удаляется при следующем
    # запуске. Всё по кнопке и с проверкой целостности; подпись сертификатом — отдельный шаг.

    EXE_ASSET = "lazeyka.exe"

    def _install_app(self) -> str:
        if not paths.IS_FROZEN:
            raise UpdateError("Самообновление работает только в собранном приложении")
        rel = self.releases.get("app")
        if not rel:
            raise UpdateError("Сначала проверьте обновления")
        asset = next((a for a in rel["assets"] if a["name"].lower() == self.EXE_ASSET), None)
        if asset is None:
            raise UpdateError("В релизе нет файла Lazeyka.exe")
        if not asset["sha256"]:
            raise UpdateError("У файла нет опубликованной контрольной суммы — обновляться небезопасно")
        current = Path(paths.exe_path())
        staging = current.with_name(f".{current.stem}-{uuid.uuid4().hex[:8]}.new")
        self._set("app", "downloading", 0.0, f"Скачиваю {asset['name']}")
        try:
            github.download(asset["url"], staging, asset["sha256"],
                            progress=lambda done, total: self._set(
                                "app", "downloading", (done / total) if total else None,
                                f"Скачано {done // 1024} КБ"))
            # download() уже сверил SHA-256 с опубликованным GitHub и удалил бы файл при несовпадении.
            self._set("app", "verifying", None, "Контрольная сумма совпала")
            self._set("app", "installing", None, "Заменяю программу")
            backup = current.with_name(current.name + ".old")
            try:
                backup.unlink(missing_ok=True)
            except OSError:
                backup = current.with_name(f"{current.name}-{uuid.uuid4().hex[:6]}.old")
            os.replace(current, backup)        # сдвигаем работающий exe (Windows это разрешает)
            try:
                os.replace(staging, current)   # ставим новый на его место
            except OSError:
                os.replace(backup, current)    # не удалось — вернём прежний и выйдем
                raise
        finally:
            staging.unlink(missing_ok=True)
        self.settings.update(lambda d: d["updates"].__setitem__("app_backup", str(backup)))
        return (f"Лазейка обновлена до {rel['version']}. Перезапустите её, чтобы запустить новую версию "
                "(прежнюю можно вернуть кнопкой «Откатить»).")

    def _rollback_app(self) -> str:
        backup = self.settings.get("updates", "app_backup")
        if not backup or not Path(backup).is_file():
            raise UpdateError("Нет сохранённой прежней версии")
        current = Path(paths.exe_path())
        aside = current.with_name(f".{current.stem}-{uuid.uuid4().hex[:8]}.old")
        os.replace(current, aside)             # сдвигаем нынешний (запущенный) exe
        try:
            os.replace(backup, current)        # возвращаем прежний
        except OSError:
            os.replace(aside, current)
            raise
        self.settings.update(lambda d: d["updates"].__setitem__("app_backup", None))
        return "Вернулась прежняя версия Лазейки. Перезапустите её."

    # ------------------------------------------------------------ состояние для UI

    def snapshot(self) -> dict:
        items = []
        meta = {
            "zapret": ("Стратегии zapret", ZAPRET_REPO,
                       lambda: len([p for p in pack.installed()
                                    if self.zapret.pack and p.version != self.zapret.pack.version
                                    and pack.version_key(p.version) < pack.version_key(self.zapret.pack.version)]) > 0),
            "tgws": ("Ядро Telegram-прокси", TGWS_REPO,
                     lambda: bool(self.tg.core and self.tg.core.origin == "updated")),
            "app": ("Лазейка", APP_REPO,
                    lambda: bool(self.settings.get("updates", "app_backup")
                                 and Path(self.settings.get("updates", "app_backup")).is_file())),
        }
        for key, (title, repo, can_rollback) in meta.items():
            rel = self.releases.get(key)
            prog = self.progress[key]
            items.append({
                "id": key, "title": title, "subtitle": repo,
                "current": self.current_version(key),
                "latest": rel["version"] if rel else None,
                "available": self.is_available(key),
                "skipped": self.is_skipped(key),
                "published_at": rel.get("published_at") if rel else None,
                "notes": rel.get("notes") if rel else None,
                "url": rel.get("url") if rel else f"https://github.com/{repo}/releases",
                "state": prog["state"], "progress": prog["progress"], "message": prog["message"],
                "can_rollback": _safe_bool(can_rollback),
            })
        return {
            "auto_check": self.settings.get("updates", "check"),
            "checking": self.checking,
            "last_check": self.settings.get("updates", "last_check"),
            "error": self.error,
            "count": self.available_count(),
            "items": items,
        }


def _safe_bool(fn: Callable[[], bool]) -> bool:
    try:
        return bool(fn())
    except Exception:  # noqa: BLE001
        return False


def remove_component_dirs(keep: set[str]) -> None:
    """Удаляет скачанные ядра прокси, кроме нужных."""
    root: Path = paths.TGWS_COMPONENTS_DIR
    if not root.is_dir():
        return
    for child in root.iterdir():
        if child.is_dir() and child.name not in keep:
            shutil.rmtree(child, ignore_errors=True)


def cleanup_stale_exe(keep: str | None = None) -> None:
    """При запуске убирает временные копии exe от самообновления: недокачанные .new и осиротевшие
    .old рядом с exe. Резервную копию для отката (keep — путь из настроек) НЕ трогаем."""
    if not paths.IS_FROZEN:
        return
    exe = Path(paths.exe_path())
    keep_norm = os.path.normcase(os.path.abspath(keep)) if keep else None
    try:
        for sibling in exe.parent.glob(f".{exe.stem}-*.new"):
            sibling.unlink(missing_ok=True)
        for sibling in exe.parent.glob(f"{exe.name}*.old"):
            if os.path.normcase(str(sibling.resolve())) != keep_norm:
                sibling.unlink(missing_ok=True)
    except OSError as err:
        log.debug("Старые копии exe не убраны: %r", err)
