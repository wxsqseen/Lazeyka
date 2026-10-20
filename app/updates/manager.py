"""Обновления компонентов: только сообщаем, ставим — только по нажатию.

- zapret: релизный zip Flowseal/zapret-discord-youtube, SHA-256 обязателен
  (GitHub публикует его для каждого файла релиза).
- tg-ws-proxy: файлы папки proxy/ по тегу релиза. Каждый файл сверяется с
  git-хешем из дерева того же тега, полученного через API.
- сама Лазейка: Lazeyka.exe из релиза, SHA-256 обязателен; новая версия работает после перезапуска.
- ядра своего VPN (sing-box и помощник Xray): самая новая стабильная версия любой серии по
  списку релизов (vpnclient/engines.py). Исключение из «только по нажатию» (решение владельца
  2026-10-18): при включённом vpnclient.core_auto_update их ставит само автообновление менеджера
  VPN, поэтому в счётчик «Доступно обновление» они не входят; кнопка «Установить» остаётся.
  Ставит менеджер VPN, ход установки — в его снимке.

Новая версия, которая не встала (не запустилась), откатывается к прежней сама: zapret — к прежнему
пакету с прежним состоянием обхода, ядро прокси — к прежнему ядру (не обязательно встроенному).
"""
from __future__ import annotations

import contextlib
import logging
import os
import shutil
import threading
import time
import uuid
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Iterator

from .. import APP_REPO, TGWS_REPO, ZAPRET_REPO, __version__, autostart, paths
from ..settings import SettingsSaveError
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


# Пункты «Обновлений» для ядер своего VPN → имя ядра в vpnclient/engines.py
CORE_KEYS = {"vpncore": "sing-box", "vpnxray": "xray"}
_CORE_SETTING = {"sing-box": "singbox_version", "xray": "xray_version"}
_CORE_CACHE_TTL = 5.0     # снимок «Обновлений» строится раз в секунду — диск читаем реже
SOURCES = (("zapret", ZAPRET_REPO), ("tgws", TGWS_REPO), ("app", APP_REPO))
TITLES = {"zapret": "Стратегии zapret", "tgws": "Ядро Telegram-прокси", "app": "Лазейка"}
JOB_JOIN_WAIT = 5.0       # выход: столько ждём каждую задачу обновления (загрузку отменяем сразу)
STOPPING = "Установка прервана: Лазейка закрывается"
CLOSING = "Лазейка закрывается — файлы на диске не меняем"   # replacing(): обновление, откат, копия автозапуска


def _engines():
    """Модуль ядер своего VPN или None, если его нет в этой сборке."""
    try:
        from ..vpnclient import engines
    except ImportError:
        return None
    return engines


def _require_release_url(url: str, repo: str) -> None:
    """Файл для установки — только из релизов самого проекта на GitHub (как у ядер своего VPN)."""
    if not str(url).startswith(f"https://github.com/{repo}/releases/download/"):
        raise UpdateError("Файл лежит не в релизах проекта на GitHub — ставить его небезопасно")


def tgws_target(package_dir: Path, tree_path: str) -> Path:
    """Куда положить файл proxy/… из дерева тега. Путь из чужого репозитория: без «..», дисков,
    абсолютных путей и обратных слешей (PurePosixPath их не разбирает, а Windows — разбирает), части
    сверяются как пришли, до нормализации, — и итог обязан лежать внутри папки пакета."""
    parts = tree_path.split("/")
    if (parts[0] != "proxy" or len(parts) < 2 or "\\" in tree_path or ":" in tree_path or "\x00" in tree_path
            or any(part in ("", ".", "..") for part in parts[1:])):
        raise UpdateError(f"Небезопасный путь в релизе: {tree_path!r}")
    root = package_dir.resolve()
    dest = package_dir.joinpath(*parts[1:])
    if not dest.resolve().is_relative_to(root):
        raise UpdateError(f"Небезопасный путь в релизе: {tree_path!r}")
    return dest


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
        self.releases: dict[str, dict | None] = {"zapret": None, "tgws": None, "app": None,
                                                 "vpncore": None, "vpnxray": None}
        self.progress: dict[str, dict] = {k: {"state": "idle", "progress": None, "message": None}
                                          for k in self.releases}
        self.check_errors: dict[str, str] = {}   # почему пункт не проверился в последний раз
        self.checked: set[str] = set()           # пункты, про которые GitHub ответил в этом сеансе
        self._busy: set[str] = set()
        # Менеджер своего VPN (ставит ядра); Core подставляет после создания. None — модуля нет.
        self.vpnclient: Any = None
        self._core_cache: dict[str, tuple[float, str | None]] = {}
        # exe на диске сменился (обновление или откат), а работает прежний процесс: текст для плашки.
        self._app_restart: str | None = None
        self._cancel = threading.Event()         # выход: прервать загрузки, новых установок не начинать
        self._critical = threading.Lock()        # замена файлов: выход дожидается её конца
        self._jobs: set[threading.Thread] = set()

    # ------------------------------------------------------------ проверка

    def check_async(self, quiet: bool = False) -> None:
        with self.lock:
            if self.checking or self._cancel.is_set():
                return
            self.checking = True
        threading.Thread(target=self._check, args=(quiet,), name="update-check", daemon=True).start()

    def _check(self, quiet: bool) -> None:
        try:
            errors, succeeded = self._check_sources()
            self._after_check(errors, succeeded, quiet)
        except Exception as exc:  # noqa: BLE001 — «Проверяем…» не должно висеть вечно
            log.exception("Проверка обновлений упала")
            with self.lock:
                self.error = f"Проверка обновлений не удалась: {exc}"
            if not quiet:
                self.notify("error", self.error)
        finally:
            with self.lock:
                self.checking = False

    def _check_sources(self) -> tuple[dict[str, str], set[str]]:
        """Спросить GitHub про каждый пункт. Возвращает (ошибки по пунктам, проверенные пункты)."""
        errors: dict[str, str] = {}
        succeeded: set[str] = set()
        for key, repo in SOURCES:
            try:
                self.releases[key] = github.latest_release(repo)
            except github.GitHubError as exc:
                log.warning("Проверка обновлений %s: %s", repo, exc)
                if not (key == "app" and "404" in str(exc)):
                    errors[key] = str(exc)
                    continue
                self.releases[key] = None     # у самой Лазейки релиза может ещё не быть — это не ошибка
            succeeded.add(key)
        for key, name in CORE_KEYS.items():
            # Неустановленное ядро не проверяем: его скачивает подкачка при запуске, а лишние
            # запросы съедают лимит GitHub (60 в час).
            if self.current_version(key) is None:
                self.releases[key] = None
                self.checked.discard(key)
                continue
            try:
                self.releases[key] = self.core_release(name)
                succeeded.add(key)
            except UserError as exc:
                log.warning("Проверка обновлений %s: %s", name, exc)
                errors[key] = str(exc)
        with self.lock:
            self.check_errors = errors
            self.checked |= succeeded
            self.error = self._error_summary(errors, succeeded)
        return errors, succeeded

    def _error_summary(self, errors: dict[str, str], succeeded: set[str]) -> str | None:
        if not errors:
            return None
        first = next(iter(errors.values()))
        if not succeeded:
            return first
        names = ", ".join(f"«{self._title(key)}»" for key in errors)
        return f"Не удалось проверить {names}: {first}"

    def _after_check(self, errors: dict[str, str], succeeded: set[str], quiet: bool) -> None:
        if succeeded:
            self.settings.update(lambda d: d["updates"].__setitem__("last_check", time.time()))
        if self._core_auto() and any(self.is_available(key) for key in CORE_KEYS):
            soon = getattr(self.vpnclient, "core_update_soon", None)
            if soon is not None:
                soon()                  # автообновление поставит сейчас, а не по своему расписанию
        count = self.available_count()
        log.info("Проверка обновлений завершена: доступно %d, не проверено %d", count, len(errors))
        if quiet:
            return
        if errors:
            self.notify("warn" if succeeded else "error", self.error or "Проверка обновлений не удалась")
        elif count == 0:
            self.notify("success", "Всё актуально — обновлений нет.")

    def _title(self, key: str) -> str:
        if key in CORE_KEYS:
            engines = _engines()
            return engines.spec(CORE_KEYS[key]).title if engines else key
        return TITLES.get(key, key)

    @staticmethod
    def core_release(name: str) -> dict | None:
        """Самый новый стабильный релиз ядра — любой серии (1.15, 27.x); черновиков и пре-релизов нет.
        Маршрут — как у загрузки ядер: напрямую, запасной — через системный прокси."""
        engines = _engines()
        if engines is None:
            return None
        spec = engines.spec(name)
        found = engines.via_routes(f"Релизы {spec.repo}",
                                   lambda opener: github.releases(spec.repo, pages=1, opener=opener))
        return engines.newest(found)

    def _core_auto(self) -> bool:
        """Ядра ставит автообновление менеджера VPN (vpnclient.core_auto_update)."""
        return bool(self.vpnclient is not None and self.settings.get("vpnclient").get("core_auto_update", True))

    def _core_bad(self, key: str) -> bool:
        rel = self.releases.get(key)
        bad = self.settings.get("vpnclient").get("core_bad_versions") or []
        return bool(rel) and f"{CORE_KEYS[key]}:{rel['version']}" in bad

    def current_version(self, key: str) -> str | None:
        if key == "zapret":
            return self.zapret.pack.version if self.zapret.pack else None
        if key == "app":
            return __version__
        if key in CORE_KEYS:
            return self._core_version(CORE_KEYS[key])
        return self.tg.core.version if self.tg.core else None

    def _core_version(self, name: str) -> str | None:
        """Активная версия ядра на диске: из настроек менеджера, иначе самая новая установленная и не
        забракованная (как выбирает менеджер VPN)."""
        now = time.monotonic()
        cached = self._core_cache.get(name)
        if cached and now - cached[0] < _CORE_CACHE_TTL:
            return cached[1]
        engines = _engines()
        found = None
        if engines is not None:
            try:
                vc = self.settings.get("vpnclient")
                wanted, bad = vc.get(_CORE_SETTING[name]), set(vc.get("core_bad_versions") or [])
                found = (engines.installed(name, wanted) if wanted else None) or (
                    next((v for v in engines.versions(name) if f"{name}:{v}" not in bad), None) if bad
                    else engines.installed(name))
            except Exception:  # noqa: BLE001 — сломанная папка ядра не должна ронять «Обновления»
                log.debug("Версия ядра %s не прочитана", name, exc_info=True)
        self._core_cache[name] = (now, found)
        return found

    def forget_core_versions(self) -> None:
        """После установки или отката ядра — перечитать диск."""
        self._core_cache.clear()

    def is_available(self, key: str) -> bool:
        rel = self.releases.get(key)
        current = self.current_version(key)
        if not rel:
            return False
        if key == "app" and self._app_restart:
            return False                # новая версия уже на диске — ждёт перезапуска
        if current is None:
            # Неустановленное ядро VPN — не «обновление»: оно ставится при первом включении.
            return key not in CORE_KEYS
        return pack.version_key(rel["version"]) > pack.version_key(current)

    def is_skipped(self, key: str) -> bool:
        rel = self.releases.get(key)
        return bool(rel) and self.settings.get("updates", "skipped").get(key) == rel["version"]

    def pending_keys(self) -> list[str]:
        """Обновления, которые ждут нажатия (для счётчика и плашки). Ядра своего VPN при автообновлении
        ставятся сами, а версия, которая не подошла (check, запуск, откат), — не повод звать человека."""
        return [k for k in self.releases if self.is_available(k) and not self.is_skipped(k)
                and not (k in CORE_KEYS and (self._core_auto() or self._core_bad(k)))]

    def available_count(self) -> int:
        return len(self.pending_keys())

    def app_restart_text(self) -> str | None:
        """exe Лазейки на диске уже другой (обновление или откат): текст «перезапустите»; иначе None."""
        return self._app_restart

    def skip(self, key: str) -> None:
        rel = self.releases.get(key)
        if not rel:
            raise UpdateError("Сначала проверьте обновления")
        self.settings.update(lambda d: d["updates"]["skipped"].__setitem__(key, rel["version"]))

    def _release(self, key: str) -> dict:
        rel = self.releases.get(key)
        if not rel:
            raise UpdateError("Сначала проверьте обновления")
        return rel

    # ------------------------------------------------------------ задачи

    def _set(self, key: str, state: str, progress: float | None = None, message: str | None = None) -> None:
        self.progress[key] = {"state": state, "progress": progress, "message": message}

    def install_async(self, key: str) -> None:
        jobs = {"zapret": self._install_zapret, "tgws": self._install_tgws, "app": self._install_app,
                "vpncore": lambda: self._install_core("vpncore", update=self.is_available("vpncore")),
                "vpnxray": lambda: self._install_core("vpnxray", update=self.is_available("vpnxray"))}
        self._start_job(key, jobs.get(key))

    def install_core_async(self, name: str) -> None:
        """Поставить ядро VPN закреплённой версии (со страницы VPN). Та же задача, что пункт
        «Обновлений»: один _busy на обе кнопки."""
        key = next((k for k, v in CORE_KEYS.items() if v == name), None)
        if key is None:
            raise UpdateError("Неизвестное ядро")
        self._start_job(key, lambda: self._install_core(key, update=False))

    def rollback_async(self, key: str) -> None:
        jobs = {"zapret": self._rollback_zapret, "tgws": self._rollback_tgws, "app": self._rollback_app,
                "vpncore": lambda: self._rollback_core("vpncore"),
                "vpnxray": lambda: self._rollback_core("vpnxray")}
        self._start_job(key, jobs.get(key), rollback=True)

    def _start_job(self, key: str, job: Callable[[], str] | None, *, rollback: bool = False) -> None:
        """Установка (итог — state done) или откат (rolling_back → rolled_back: без этапов и хешей)."""
        if key not in self.releases or job is None:
            raise UpdateError("Неизвестный компонент")
        if not self.is_admin:
            raise UpdateError("Устанавливать обновления можно только с правами администратора")
        if self._cancel.is_set():
            raise UpdateError(STOPPING)
        if key == "app" and self._app_restart and not rollback:
            raise UpdateError(self._app_restart)
        with self.lock:
            if key in self._busy:
                raise UpdateError("Уже выполняется")
            self._busy.add(key)
        if rollback:
            self._set(key, "rolling_back", None, "Возвращаем прежнюю версию")
        title = self._title(key)

        def run() -> None:
            try:
                message = job()
                self._set(key, "rolled_back" if rollback else "done", 1.0, message)
                self.notify("success", message)
            except Exception as exc:  # noqa: BLE001
                log.exception("%s %s не удался", "Откат" if rollback else "Обновление", key)
                self._set(key, "error", None, str(exc))
                self.notify("error", f"«{title}»: {'откат не удался' if rollback else 'обновление не установлено'}"
                                     f" — {exc}")
            finally:
                with self.lock:
                    self._busy.discard(key)
                    self._jobs.discard(threading.current_thread())

        thread = threading.Thread(target=run, name=f"update-{key}", daemon=True)
        with self.lock:
            self._jobs.add(thread)
        thread.start()

    @contextlib.contextmanager
    def replacing(self) -> Iterator[None]:
        """Замена файлов на диске — целиком: выход Лазейки (shutdown) дожидается её конца, а начатую
        после выхода не начинает. Им же Core обёртывает копирование exe для автозапуска."""
        with self._critical:
            if self._cancel.is_set():
                raise UpdateError(CLOSING)
            yield

    def shutdown(self, timeout: float) -> None:
        """Выход: загрузки прерываются, начатая замена файлов доделывается."""
        self._cancel.set()
        deadline = time.monotonic() + timeout
        if self._critical.acquire(timeout=timeout):
            self._critical.release()
        with self.lock:
            jobs = list(self._jobs)
        for thread in jobs:
            thread.join(max(0.0, min(JOB_JOIN_WAIT, deadline - time.monotonic())))

    # ------------------------------------------------------------ zapret

    def _install_zapret(self) -> str:
        rel = self._release("zapret")
        asset = next((a for a in rel["assets"] if a["name"].lower().endswith(".zip")
                      and rel["version"] in a["name"]), None)
        if asset is None:
            raise UpdateError("В релизе нет zip-архива")
        if not asset["sha256"]:
            raise UpdateError("У архива нет опубликованной контрольной суммы — ставить его небезопасно")
        _require_release_url(asset["url"], ZAPRET_REPO)
        paths.TMP_DIR.mkdir(parents=True, exist_ok=True)
        target = paths.TMP_DIR / f"dl-{uuid.uuid4().hex[:8]}.zip"
        self._set("zapret", "downloading", 0.0, f"Скачиваем {asset['name']}")
        try:
            github.download(asset["url"], target, asset["sha256"], cancel=self._cancel,
                            progress=lambda done, total: self._set(
                                "zapret", "downloading", (done / total) if total else None,
                                f"Скачано {done // 1024} КБ"))
            self._set("zapret", "verifying", None, "Проверяем пакет")
            info = pack.install_zip(target, rel["version"], source="github",
                                    expected_sha256=asset["sha256"], published_at=rel.get("published_at"))
        finally:
            target.unlink(missing_ok=True)
        self._set("zapret", "installing", None, "Переключаем стратегии на новую версию")
        previous, was_running = self.zapret.pack, self._zapret_running()
        try:
            self.zapret.switch_pack(info)
        except Exception as exc:  # noqa: BLE001 — новая версия не встала: вернуть прежнюю
            raise self._restore_zapret(previous, was_running, info, exc) from exc
        keep = {info.version} | ({previous.version} if previous else set())
        pack.cleanup(keep)
        return f"Стратегии zapret обновлены до {info.version}"

    def _zapret_running(self) -> bool:
        try:
            return bool(self.zapret.running())
        except Exception:  # noqa: BLE001 — состояние службы не прочиталось: считаем, что обход не работал
            log.debug("Состояние обхода не прочитано", exc_info=True)
            return False

    def _restore_zapret(self, previous: pack.PackInfo | None, was_running: bool, info: pack.PackInfo,
                        exc: Exception) -> UpdateError:
        """Новый пакет не запустился: вернуть прежний и прежнее состояние обхода. Возвращает ошибку
        для человека (её поднимает вызывающий)."""
        current = self.zapret.pack
        if previous is None or (current is not None and current.version == previous.version):
            return UpdateError(f"Стратегии {info.version} не включились: {exc}")
        log.error("Стратегии %s не запустились (%s) — возвращаю %s", info.version, exc, previous.version)
        try:
            self.zapret.switch_pack(previous)
            if was_running and not self.zapret.running():
                self.zapret.start()
        except Exception as back:  # noqa: BLE001
            log.exception("Прежние стратегии не вернулись")
            return UpdateError(f"Стратегии {info.version} не запустились ({exc}), а вернуть {previous.version} "
                               f"тоже не вышло: {back}")
        return UpdateError(f"Стратегии {info.version} не запустились ({exc}) — вернул прежнюю версию "
                           f"{previous.version}")

    def _rollback_zapret(self) -> str:
        current = self.zapret.pack.version if self.zapret.pack else None
        older = [p for p in pack.installed() if p.version != current
                 and (current is None or pack.version_key(p.version) < pack.version_key(current))]
        if not older:
            raise UpdateError("Нет предыдущей версии для отката")
        target = older[-1]
        self._set("zapret", "rolling_back", None, f"Возвращаем {target.version}")
        self.zapret.switch_pack(target)
        return f"Стратегии zapret возвращены к версии {target.version}"

    # ------------------------------------------------------------ ядро Telegram-прокси

    def _install_tgws(self) -> str:
        rel = self._release("tgws")
        tag, version = rel["tag"], rel["version"]
        final = paths.TGWS_COMPONENTS_DIR / pack.safe_version(version)
        if self.tg.core and self.tg.core.origin == "updated" and self.tg.core.version == version:
            raise UpdateError("Эта версия уже работает")
        self._set("tgws", "downloading", 0.0, "Получаем список файлов")
        entries = [e for e in github.tree(TGWS_REPO, tag)
                   if e.get("type") == "blob" and e["path"].startswith("proxy/") and e["path"].endswith(".py")]
        if not any(e["path"] == "proxy/tg_ws_proxy.py" for e in entries):
            raise UpdateError("В релизе нет ядра прокси (proxy/tg_ws_proxy.py)")
        staging = paths.TMP_DIR / f"tgws-{uuid.uuid4().hex[:8]}"
        package_dir = staging / "tgws_proxy"
        try:
            for index, entry in enumerate(entries, 1):
                if self._cancel.is_set():
                    raise UpdateError(STOPPING)
                dest = tgws_target(package_dir, entry["path"])
                data = github.raw_file(TGWS_REPO, tag, entry["path"])
                if github.git_blob_sha1(data) != entry.get("sha"):
                    raise UpdateError(f"Файл {entry['path']} не совпал с git-хешем релиза")
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(data)
                self._set("tgws", "downloading", index / len(entries), f"Файл {index} из {len(entries)}")
            self._set("tgws", "verifying", None, "Проверяем ядро")
            with self.replacing():
                if final.exists():
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
        self._set("tgws", "installing", None, "Перезапускаем прокси на новом ядре")
        self._switch_tgws(core, final)
        # Прежние скачанные ядра больше не нужны (откат — к встроенному), чтобы они не копились.
        remove_component_dirs({pack.safe_version(version)})
        return f"Ядро Telegram-прокси обновлено до {core.version}"

    def _switch_tgws(self, core: loader.ProxyCore, final: Path) -> None:
        """Перейти на новое ядро. Работал прокси — перезапуск на нём; не работал — пробный запуск на
        свободном порту. Не вышло — прежнее ядро (не обязательно встроенное) и прежнее состояние."""
        previous_core, previous_setting = self.tg.core, self.settings.get("tg", "core")
        was_running = self.tg.status in ("running", "starting")
        try:
            if not was_running:
                self._trial_start(core)
            self.settings.update(lambda d: d["tg"].__setitem__("core", final.name))
            self.tg.switch_core(core, fallback=False)
        except Exception as exc:  # noqa: BLE001
            log.error("Новое ядро %s не запустилось: %s — возвращаю прежнее", core.version, exc)
            back = self._restore_tgws(previous_core, previous_setting, was_running)
            shutil.rmtree(final, ignore_errors=True)
            raise UpdateError(f"Новое ядро не запустилось ({exc}); {back}") from exc

    def _restore_tgws(self, previous: loader.ProxyCore | None, setting: str, was_running: bool) -> str:
        try:
            self.settings.update(lambda d: d["tg"].__setitem__("core", setting))
            core = previous or loader.load_bundled()
            self.tg.switch_core(core, fallback=False)
            if was_running and self.tg.status != "running":
                self.tg.start()
        except Exception as exc:  # noqa: BLE001
            log.exception("Прежнее ядро Telegram-прокси не вернулось")
            return f"прежнее ядро тоже не включилось: {exc}"
        kind = "встроенное" if core.origin == "bundled" else "прежнее"
        return f"работает {kind} {core.version}"

    @staticmethod
    def _trial_start(core: loader.ProxyCore) -> None:
        """Прокси выключен: новое ядро пробно поднимается на свободном порту 127.0.0.1 со своими
        временными настройками и сразу выключается. Не поднялось — установка не состоялась."""
        import socket
        from ..settings import Settings
        from ..tgproxy.manager import TgProxyManager
        trial_dir = paths.TMP_DIR / f"tgws-trial-{uuid.uuid4().hex[:8]}"
        try:
            trial_dir.mkdir(parents=True)
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0))
                port = probe.getsockname()[1]
            settings = Settings(trial_dir / "settings.json")
            settings.update(lambda d: d["tg"].update({"host": "127.0.0.1", "port": port, "pool_size": 0,
                                                      "cfproxy": False, "core": "bundled"}))
            trial = TgProxyManager(settings, lambda *_: None)
            trial._install_core(core)                          # noqa: SLF001 — то самое ядро, без загрузки с диска
            try:
                trial.start(fallback=False)
            finally:
                trial.stop(remember=False)
        finally:
            shutil.rmtree(trial_dir, ignore_errors=True)

    def _rollback_tgws(self) -> str:
        if not (self.tg.core and self.tg.core.origin == "updated"):
            raise UpdateError("Уже работает встроенное ядро Telegram-прокси — откатываться не к чему")
        self.settings.update(lambda d: d["tg"].__setitem__("core", "bundled"))
        core = loader.load_bundled()
        self.tg.switch_core(core)
        remove_component_dirs(set())      # скачанное больше не используется
        return f"Возвращено встроенное ядро Telegram-прокси {core.version}"

    # ------------------------------------------------------------ сама Лазейка
    #
    # Скачиваем новый Lazeyka.exe из релиза во временную папку данных (туда пишет только администратор,
    # поэтому сверенный по SHA-256 файл там уже не подменить) и заменяем работающий exe. Работающий exe на
    # Windows удалить нельзя, но можно переименовать: отодвигаем его в скрытый <имя>.old, ставим новый на
    # его место. Куда отодвинут прежний, записывается в настройки ДО замены: иначе уборка при следующем
    # запуске сочла бы копию мусором. При запуске новой версии прежняя переезжает в backups папки данных
    # (settle_app_files) — это копия для «Откатить», рядом с exe ничего не остаётся. Копия для автозапуска
    # в Program Files получает тот же проверенный файл. Если сам exe лежит в папке, куда пишут обычные
    # программы («Загрузки»), его и так может подменить кто угодно — защищать там промежуточный файл
    # бессмысленно; поэтому автозапуск указывает только на копию в Program Files.

    EXE_ASSET = "lazeyka.exe"

    def _install_app(self) -> str:
        if not paths.IS_FROZEN:
            raise UpdateError("Самообновление работает только в собранном приложении")
        rel = self._release("app")
        if pack.version_key(rel["version"]) <= pack.version_key(__version__):
            raise UpdateError(f"Версия {rel['version']} не новее работающей {__version__}")
        asset = next((a for a in rel["assets"] if a["name"].lower() == self.EXE_ASSET), None)
        if asset is None:
            raise UpdateError("В релизе нет файла Lazeyka.exe")
        if not asset["sha256"]:
            raise UpdateError("У файла нет опубликованной контрольной суммы — обновляться небезопасно")
        _require_release_url(asset["url"], APP_REPO)
        current = Path(paths.exe_path())
        paths.TMP_DIR.mkdir(parents=True, exist_ok=True)
        downloaded = paths.TMP_DIR / f"app-{uuid.uuid4().hex[:8]}.exe"
        self._set("app", "downloading", 0.0, f"Скачиваем {asset['name']}")
        try:
            github.download(asset["url"], downloaded, asset["sha256"], cancel=self._cancel,
                            progress=lambda done, total: self._set(
                                "app", "downloading", (done / total) if total else None,
                                f"Скачано {done // 1024} КБ"))
            # download() уже сверил SHA-256 с опубликованным GitHub и удалил бы файл при несовпадении.
            self._set("app", "verifying", None, "Контрольная сумма совпала")
            self._set("app", "installing", None, "Заменяем программу")
            with self.replacing():
                self._replace_exe(current, downloaded)
                # Копия для автозапуска — в том же блоке: выход не оборвёт её на полпути.
                note = self._sync_autostart_copy(downloaded, rel["version"], current, downgrade=False)
        finally:
            downloaded.unlink(missing_ok=True)
        self._app_restart = f"Лазейка {rel['version']} установлена — перезапустите её, чтобы заработала новая версия."
        return (f"Лазейка обновлена до {rel['version']}. Перезапустите её, чтобы запустить новую версию "
                f"(прежнюю можно вернуть кнопкой «Откатить»).{note}")

    def _replace_exe(self, current: Path, source: Path) -> None:
        staging = current.with_name(f".{current.stem}-{uuid.uuid4().hex[:8]}.new")
        backup = current.with_name(current.name + ".old")
        try:
            backup.unlink(missing_ok=True)
        except OSError:
            backup = current.with_name(f"{current.name}-{uuid.uuid4().hex[:6]}.old")
        before = self.settings.get("updates")
        try:
            shutil.copyfile(source, staging)
            try:
                self._record_backup(backup, current, __version__)
            except SettingsSaveError as exc:
                raise UpdateError(f"Не удалось записать, где будет прежняя версия, — обновление не начато "
                                  f"({exc})") from exc
            os.replace(current, backup)        # сдвигаем работающий exe (Windows это разрешает)
            _hide(backup)                      # до перезапуска; потом переедет в backups
            try:
                os.replace(staging, current)   # ставим новый на его место
            except OSError:
                os.replace(backup, current)    # не удалось — вернём прежний и выйдем
                raise
        except Exception:
            self._restore_backup_record(before)
            raise
        finally:
            staging.unlink(missing_ok=True)

    def _record_backup(self, backup: Path | None, owner: Path | None, version: str | None) -> None:
        self.settings.update(lambda d: d["updates"].update({
            "app_backup": str(backup) if backup else None, "app_backup_for": str(owner) if owner else None,
            "app_backup_version": version}), strict=True)

    def _restore_backup_record(self, before: dict) -> None:
        self.settings.update(lambda d: d["updates"].update(
            {key: before.get(key) for key in ("app_backup", "app_backup_for", "app_backup_version")}))

    def _sync_autostart_copy(self, source: Path, version: str, current: Path, *, downgrade: bool) -> str:
        """Копия для автозапуска — того же exe, иначе при входе в Windows запускалась бы прежняя версия.
        Возвращает приписку к итогу (пусто — всё в порядке)."""
        try:
            if _same(current, autostart.installed_exe()):
                autostart.write_version(version)    # обновился сам exe в Program Files
            else:
                autostart.update_copy(source, version, downgrade=downgrade)
        except Exception as exc:  # noqa: BLE001 — сам exe уже заменён; копию поправит следующий запуск
            log.warning("Копия для автозапуска не обновлена: %s", exc)
            return f" Копию для автозапуска обновить не вышло ({exc}) — она обновится при следующем запуске."
        return ""

    def app_backup(self) -> Path | None:
        """Сохранённая прежняя версия именно этого exe (у копии в Program Files и exe в «Загрузках»
        одна папка данных, а откатывать каждый должен свою)."""
        u = self.settings.get("updates")
        path = u.get("app_backup")
        if not path or not Path(path).is_file():
            return None
        owner = u.get("app_backup_for")
        if owner and not _same(owner, paths.exe_path()):
            return None
        return Path(path)

    def _rollback_app(self) -> str:
        if not paths.IS_FROZEN:
            raise UpdateError("Откат Лазейки работает только в собранном приложении")
        backup = self.app_backup()
        if backup is None:
            raise UpdateError("Нет сохранённой прежней версии")
        version = self.settings.get("updates", "app_backup_version")
        current = Path(paths.exe_path())
        # Копия может лежать на другом диске (backups в папке данных): сначала рядом с exe.
        staging = current.with_name(f".{current.stem}-{uuid.uuid4().hex[:8]}.new")
        aside = current.with_name(f".{current.stem}-{uuid.uuid4().hex[:8]}.old")
        self._set("app", "rolling_back", None, "Возвращаем прежнюю версию")
        try:
            with self.replacing():
                shutil.copyfile(backup, staging)
                os.replace(current, aside)         # сдвигаем нынешний (запущенный) exe
                _hide(aside)                       # уберётся при следующем запуске
                try:
                    os.replace(staging, current)   # возвращаем прежний
                except OSError:
                    os.replace(aside, current)
                    raise
                note = self._sync_autostart_copy(backup, version, current, downgrade=True) if version else ""
        finally:
            staging.unlink(missing_ok=True)
        try:
            backup.unlink()                        # прежняя версия снова на месте exe
        except OSError as exc:
            log.debug("Копия прежней версии не удалена: %r", exc)
        self._restore_backup_record({})
        if version == __version__:
            self._app_restart = None               # вернулась та версия, что и работает
            return f"Вернулась версия {version} — она и работает сейчас.{note}"
        label = f"Лазейка {version}" if version else "Прежняя версия Лазейки"
        self._app_restart = f"{label} возвращена — перезапустите её, чтобы она заработала."
        return f"{label} возвращена. Перезапустите Лазейку.{note}"

    # ------------------------------------------------------------ ядра своего VPN
    #
    # Ставит менеджер VPN (он же делает версию активной после `check` нашего конфига и держит
    # прежнюю для отката); здесь — выбор релиза и общий _busy с кнопкой на странице VPN.

    def _vpn_manager(self):
        if self.vpnclient is None or _engines() is None:
            raise UpdateError("Свой VPN недоступен в этой сборке Лазейки")
        return self.vpnclient

    def _core_release(self, name: str, rel: dict):
        """Release новой версии: архив той же сборки, хеш — digest GitHub (без него не ставим)."""
        engines = _engines()
        try:
            return engines.release_for(name, rel)
        except engines.EngineError as exc:
            raise UpdateError(str(exc)) from exc

    def _install_core(self, key: str, update: bool) -> str:
        name = CORE_KEYS[key]
        vc = self._vpn_manager()
        release = None
        if update:
            release = self._core_release(name, self._release(key))
        try:
            message = vc.core_install(name, release=release) if release is not None else vc.core_install(name)
        finally:
            self.forget_core_versions()
        if isinstance(message, str) and message:
            return message
        version = self.current_version(key)
        spec = _engines().spec(name)
        return " ".join(part for part in (spec.title, version, spec.agree("установлен")) if part)

    def _rollback_core(self, key: str) -> str:
        """Откат — к прежней установленной версии (её оставляет автообновление), иначе к закреплённой
        в этой Лазейке. Текущая помечается неподходящей: автообновление не вернёт её."""
        name = CORE_KEYS[key]
        vc = self._vpn_manager()
        if not self._core_can_rollback(key):
            raise UpdateError("Нет более ранней версии для отката")
        try:
            return vc.core_rollback(name)
        finally:
            self.forget_core_versions()

    def _core_can_rollback(self, key: str) -> bool:
        engines = _engines()
        current = self.current_version(key)
        if not (engines and self.vpnclient is not None and current):
            return False
        name = CORE_KEYS[key]
        now = time.monotonic()
        cached = self._core_cache.get(f"older:{name}")
        if cached and now - cached[0] < _CORE_CACHE_TTL:
            older = cached[1]
        else:
            bad = set(self.settings.get("vpnclient").get("core_bad_versions") or [])
            older = ",".join(v for v in engines.versions(name) if f"{name}:{v}" not in bad
                             and engines.version_key(v) < engines.version_key(current)) or None
            self._core_cache[f"older:{name}"] = (now, older)
        return bool(older) or engines.version_key(engines.spec(name).version) < engines.version_key(current)

    # ------------------------------------------------------------ состояние для UI

    def snapshot(self, cores: dict | None = None) -> dict:
        """cores — vpnclient.snapshot()["cores"]: у ядер VPN ход установки берётся оттуда (один
        источник для страницы VPN и «Обновлений»)."""
        items = []
        meta = {
            "zapret": (TITLES["zapret"], ZAPRET_REPO,
                       lambda: len([p for p in pack.installed()
                                    if self.zapret.pack and p.version != self.zapret.pack.version
                                    and pack.version_key(p.version) < pack.version_key(self.zapret.pack.version)]) > 0),
            "tgws": (TITLES["tgws"], TGWS_REPO,
                     lambda: bool(self.tg.core and self.tg.core.origin == "updated")),
            "app": (TITLES["app"], APP_REPO, lambda: paths.IS_FROZEN and self.app_backup() is not None),
        }
        engines = _engines()
        if engines is not None:
            for key, name in CORE_KEYS.items():
                spec = engines.spec(name)
                meta[key] = (spec.title, spec.repo, lambda key=key: self._core_can_rollback(key))
        for key, (title, repo, can_rollback) in meta.items():
            rel = self.releases.get(key)
            prog = self.progress[key]
            if key in CORE_KEYS and isinstance((cores or {}).get(CORE_KEYS[key]), dict):
                core = cores[CORE_KEYS[key]]
                state = core.get("state") or "idle"
                # Итог задачи («готово», «возвращено» или ошибка) показываем, пока менеджер VPN снова не занят.
                if state != "idle" or prog["state"] not in ("done", "error", "rolled_back"):
                    prog = {"state": state, "progress": core.get("progress"),
                            "message": core.get("message") if state != "idle" else _core_note(core)}
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
                "checked": key in self.checked,
                "check_error": self.check_errors.get(key),
                "restart": key == "app" and bool(self._app_restart),
            })
        return {
            "auto_check": self.settings.get("updates", "check"),
            "checking": self.checking,
            "last_check": self.settings.get("updates", "last_check"),
            "error": self.error,
            "count": self.available_count(),
            "items": items,
        }


def _core_note(core: dict) -> str | None:
    """Пояснение к ядру своего VPN без установки в ходе: итог автообновления (поставлено, не подошло) или
    пометка, что активную версию поставило автообновление."""
    note = core.get("note")
    if note:
        return str(note)
    if core.get("auto_updated") and core.get("version"):
        later = core.get("in_use") and core.get("in_use") != core.get("version")
        return f"Версия {core['version']} поставлена автоматически" + (
            f"; сейчас работает {core['in_use']}, новая — со следующего подключения." if later else ".")
    return None


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


APP_BACKUP_NAME = "Lazeyka-previous.exe"     # копия прежней версии для «Откатить» — в backups


def _hide(path: Path) -> None:
    """Скрытый файл: копия рядом с exe не мозолит глаза до перезапуска."""
    if os.name != "nt":
        return
    import ctypes
    try:
        ctypes.windll.kernel32.SetFileAttributesW(str(path), 0x2)   # FILE_ATTRIBUTE_HIDDEN
    except (OSError, AttributeError):
        pass


def _same(a: Path | str, b: Path | str) -> bool:
    return os.path.normcase(os.path.abspath(a)) == os.path.normcase(os.path.abspath(b))


def _unlink_quietly(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError as exc:
        log.debug("Не удалён %s: %r", path, exc)


def _locate_backup(settings: "Settings", exe: Path) -> Path | None:
    """Копия прежней версии, записанная в настройках. Переносную папку могли переместить вместе с
    копией (абсолютный путь устарел) — тогда ищем её по имени рядом с exe и в backups и записываем
    заново. Копию другой Лазейки (Program Files и «Загрузки» делят ProgramData) не трогаем."""
    u = settings.get("updates")
    recorded, owner = u.get("app_backup"), u.get("app_backup_for")
    if not recorded:
        return None
    portable = paths.is_portable()
    if owner and not _same(owner, exe) and not portable:
        return Path(recorded) if Path(recorded).is_file() else None
    if Path(recorded).is_file():
        found = Path(recorded)
    else:
        name = Path(recorded).name
        candidates = [exe.parent / name] + ([paths.BACKUPS_DIR / name] if name == APP_BACKUP_NAME else [])
        found = next((c for c in candidates if c.is_file()), None)
        if found is None:
            settings.update(lambda d: d["updates"].update(
                {"app_backup": None, "app_backup_for": None, "app_backup_version": None}))
            return None
        log.info("Копия прежней версии Лазейки нашлась на новом месте: %s", found)
    if not _same(found, recorded) or (owner and not _same(owner, exe)):
        settings.update(lambda d: d["updates"].update({"app_backup": str(found), "app_backup_for": str(exe)}))
    return found


def _move_to_backups(settings: "Settings", keep: Path) -> Path:
    """Копию из папки exe — в backups папки данных. Записать её новое место — прежде, чем удалять
    старое: не записалось — всё остаётся как было. Возвращает, где копия теперь."""
    target = paths.BACKUPS_DIR / APP_BACKUP_NAME
    tmp = target.with_name(target.name + ".tmp")
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(keep, tmp)
        os.replace(tmp, target)
    except OSError as err:
        log.debug("Прежняя версия осталась рядом с exe: %r", err)
        _unlink_quietly(tmp)
        return keep
    try:
        settings.update(lambda d: d["updates"].__setitem__("app_backup", str(target)), strict=True)
    except SettingsSaveError as err:
        log.warning("Прежняя версия осталась рядом с exe: настройки не сохранились (%s)", err)
        _unlink_quietly(target)
        return keep
    _unlink_quietly(keep)
    log.info("Прежняя версия Лазейки перенесена в %s (для «Откатить»)", target)
    return target


def settle_app_files(settings: "Settings") -> None:
    """При запуске: копия прежней версии из папки exe переезжает в backups папки данных (кнопка
    «Откатить» берёт её оттуда), временные .new и .old рядом с exe — в том числе после отката —
    удаляются. Без прав на папку данных копия остаётся рядом с exe (скрытой). В Program Files, если
    запущен не тот exe, — только недописанные временные копии для автозапуска: .old там — откат самой копии."""
    if not paths.IS_FROZEN:
        return
    exe = Path(paths.exe_path())
    keep = _locate_backup(settings, exe)
    if keep is not None and _same(keep.parent, exe.parent):
        keep = _move_to_backups(settings, keep)
    for leftover in autostart.staging_leftovers():
        _unlink_quietly(leftover)
    try:
        stale = [*exe.parent.glob(f".{exe.stem}-*.new"), *exe.parent.glob(f".{exe.stem}-*.old"),
                 *exe.parent.glob(f"{exe.name}*.old")]
    except OSError as err:
        log.debug("Старые копии exe не найдены: %r", err)
        return
    for sibling in stale:
        if keep is None or not _same(sibling, keep):
            _unlink_quietly(sibling)
