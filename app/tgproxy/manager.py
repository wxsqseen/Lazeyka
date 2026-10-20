"""Локальный MTProto-прокси для Telegram Desktop (ядро tg-ws-proxy)."""
from __future__ import annotations

import asyncio
import base64
import collections
import ipaddress
import logging
import os
import re
import shutil
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Callable

import psutil

from .. import paths
from ..log import PROXY_LOGGER, add_secrets, proxy_censor, remove_secrets
from ..settings import Settings
from . import loader
from ..errors import UserError

log = logging.getLogger("lazeyka.tg")

DC_DEFAULT_IPS = {1: "149.154.175.50", 2: "149.154.167.51", 3: "149.154.175.100",
                  4: "149.154.167.91", 5: "149.154.171.5"}
_DOMAIN = re.compile(r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.IGNORECASE)

Notify = Callable[[str, str], None]

STOP_WAIT = 6.0          # столько ждём, пока поток прокси закроет соединения
START_WAIT = 5.0         # столько ждём, пока ядро начнёт слушать порт
RESTART_PAUSE = 0.3
CORE_ALERT = "tg-core"   # плашка: ядро не загрузилось или скачанное заменено встроенным


class TgError(UserError):
    pass


def explain_bind_error(exc: BaseException, port: int) -> str:
    # asyncio.start_server пересоздаёт OSError: код WinSock остаётся только в errno.
    winerror = getattr(exc, "winerror", None) or getattr(exc, "errno", None)
    if winerror in (10048, 98):
        hint = ""
        if _tgwsproxy_running():
            hint = " Его держит оригинальный TG WS Proxy — закройте его, Лазейка его заменяет."
        return f"Порт {port} уже занят другой программой.{hint} Или выберите другой порт в настройках."
    if winerror == 10013:
        return (f"Доступ к порту {port} запрещён (брандмауэр, антивирус или зарезервированный диапазон). "
                "Выберите порт из диапазона 10000–50000.")
    if winerror in (10049, 10014):
        return "Адрес для прослушивания недоступен — проверьте поле «Адрес» в настройках."
    return f"Прокси не запустился: {exc}"


def _component_dir(version: str):
    """Папка скачанного ядра; None, если имя из настроек выводит за пределы папки компонентов.

    Отсюда загружается Python-код в процесс с правами администратора, поэтому
    значение из settings.json не должно задавать произвольный путь.
    """
    from ..zapret.pack import PackError, safe_version
    try:
        name = safe_version(version)
    except PackError:
        return None
    if name != version:
        return None
    root = paths.TGWS_COMPONENTS_DIR.resolve()
    target = (root / name / "tgws_proxy").resolve()
    return target if target.is_relative_to(root) else None


def _stat(stats, name: str) -> int:
    """Счётчик ядра: чужое ядро может переименовать поле — тогда 0, а не исключение в тикере."""
    try:
        return int(getattr(stats, name, 0) or 0)
    except (TypeError, ValueError):
        return 0


def _stop_domain_refresh(core: loader.ProxyCore | None) -> None:
    """Поток обновления доменов Cloudflare (раз в час) ядро запускает при каждом старте и само не
    останавливает: при выключении и смене ядра он копился бы."""
    refresh = getattr(getattr(core, "config", None), "_refresh_stop", None)
    if isinstance(refresh, threading.Event):
        refresh.set()


TELEGRAM_PROCESSES = {"telegram.exe", "ayugram.exe", "kotatogram.exe", "64gram.exe", "materialgram.exe",
                      "forkgram.exe", "telegramdesktop.exe"}


def _telegram_running() -> bool:
    for proc in psutil.process_iter(["name"]):
        try:
            if (proc.info["name"] or "").lower() in TELEGRAM_PROCESSES:
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return False


def _tgwsproxy_running() -> list[psutil.Process]:
    found = []
    for proc in psutil.process_iter(["name"]):
        try:
            if (proc.info["name"] or "").lower().startswith("tgwsproxy"):
                found.append(proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return found


class TgProxyManager:
    def __init__(self, settings: Settings, notify: Notify):
        self.settings = settings
        self.notify = notify
        # Core подставляет колбэк плашек core.alert(id, level|None, text, page=…); без него — уведомление.
        self.alert: Callable[..., None] | None = None
        # Прокси работал и остановился сам (порт закрылся, ядро упало): Core перезапускает его.
        self.on_crash: Callable[[str], None] | None = None
        self.core: loader.ProxyCore | None = None
        self.core_error: str | None = None
        self.status = "stopped"
        self.error: str | None = None
        self.started_at: float | None = None
        # Включение, выключение, перезапуск и смена ядра — по одному: сон и смена сети могут
        # попросить перезапуск одновременно.
        self.lock = threading.RLock()
        self._thread: threading.Thread | None = None
        self._stop_requested: threading.Event | None = None   # выключение попросили (не падение)
        self._failure: str | None = None    # почему не включился: bind | config | load | core
        self._loop: asyncio.AbstractEventLoop | None = None
        self._stop_event: asyncio.Event | None = None
        self._history: collections.deque = collections.deque(maxlen=120)
        self._last_sample: tuple[float, int, int] | None = None
        self._rates = (0.0, 0.0)
        self.test_state: dict = {"running": False, "at": None, "results": []}
        self.client: dict = {"telegram_running": False, "connected": False, "stale_key": False, "hint": None}
        self._bad_seen: tuple[int, float] = (0, 0.0)

    # ------------------------------------------------------------ ядро

    def load_core(self) -> None:
        bundled = loader.load_bundled()
        core = bundled
        wanted = self.settings.get("tg", "core")
        if wanted and wanted != "bundled":
            core = self._load_downloaded(wanted, bundled) or bundled
        self._install_core(core)

    def _load_downloaded(self, wanted: str, bundled: loader.ProxyCore) -> loader.ProxyCore | None:
        """Скачанное обновлением ядро; None — работать на встроенном (настройка и папка убраны)."""
        from ..zapret.pack import version_key
        package_dir = _component_dir(wanted)
        if package_dir is None:
            log.error("Некорректное имя ядра в настройках: %r — использую встроенное", wanted)
            self._forget_downloaded(None)
            return None
        if version_key(wanted) <= version_key(bundled.version):
            # Новая Лазейка принесла ядро не старше скачанного: скачанный код не исполняем вовсе.
            log.info("Встроенное ядро %s не старше скачанного %s — использую встроенное, скачанное удаляю",
                     bundled.version, wanted)
            self._forget_downloaded(wanted)
            return None
        try:
            return loader.load_from_dir(package_dir, wanted)
        except loader.CoreError as exc:
            self.core_error = str(exc)
            log.error("Скачанное ядро tg-ws-proxy %s не загрузилось: %s", wanted, exc)
            self._forget_downloaded(wanted)
            self._report(CORE_ALERT, "warn",
                         f"Скачанное ядро Telegram-прокси {wanted} не загрузилось ({exc}) — работает встроенное "
                         f"{bundled.version}. Обновление можно поставить снова на странице «Обновления».")
            return None

    def _forget_downloaded(self, version: str | None) -> None:
        """Вернуть в настройки встроенное ядро и убрать папку скачанного — иначе ошибка повторялась бы
        при каждом запуске."""
        self.settings.update(lambda d: d["tg"].__setitem__("core", "bundled"))
        folder = _component_dir(version) if version else None
        if folder is not None:
            shutil.rmtree(folder.parent, ignore_errors=True)

    def _report(self, alert_id: str, level: str, text: str) -> None:
        """Поломка, найденная без нажатия человека, — плашкой (без Core — уведомлением)."""
        if self.alert is not None:
            self.alert(alert_id, level, text, page="telegram")
        else:
            self.notify("error" if level == "error" else "warn", text)

    def _install_core(self, core: loader.ProxyCore) -> None:
        if self.core is not None and self.core is not core:
            _stop_domain_refresh(self.core)
        self.core = core
        # Счётчики нового ядра начинаются с нуля: прежние отсчёты дали бы ложную скорость и «старый ключ».
        self._last_sample, self._rates, self._bad_seen = None, (0.0, 0.0), (0, 0.0)
        censor = getattr(core.utils, "DomainCensorFilter", None)
        proxy_censor.set_impl(censor() if censor else None)
        log.info("Ядро tg-ws-proxy %s (%s)", core.version,
                 "встроенное" if core.origin == "bundled" else "обновлённое")

    def switch_core(self, core: loader.ProxyCore, *, fallback: bool = True) -> None:
        """fallback=False — при установке обновления: неудачное ядро не подменяется встроенным втихую,
        установщик сам вернёт прежнее."""
        with self.lock:
            was = self.status in ("running", "starting")
            if was:
                self.stop(remember=False)
            self._install_core(core)
            if was:
                self.start(fallback=fallback)

    # ------------------------------------------------------------ конфигурация

    def _hide_secret(self, secret: str) -> None:
        """Ключ прокси ядро пишет в журнал при каждом запуске («Secret: …», ссылки с dd… и ee…): он
        регистрируется как секрет, и в файле журнала и на странице «Журнал» вместо него — <секрет>."""
        old = getattr(self, "_hidden_secret", None)
        if old == secret:
            return
        if old:
            remove_secrets([old])
        add_secrets([secret])
        self._hidden_secret = secret

    def apply_config(self) -> None:
        assert self.core is not None
        cfg = self.settings.get("tg")
        mod = self.core.config
        pc = mod.proxy_config
        try:
            dc = mod.parse_dc_ip_list(cfg["dc_ip"])
        except ValueError as exc:
            raise TgError(f"Ошибка в списке DC → IP: {exc}") from exc
        pc.port = int(cfg["port"])
        pc.host = cfg["host"]
        self._hide_secret(cfg["secret"])
        pc.secret = cfg["secret"]
        pc.dc_redirects = dc
        pc.buffer_size = max(4, int(cfg["buf_kb"])) * 1024
        pc.pool_size = max(0, int(cfg["pool_size"]))
        pc.fallback_cfproxy = bool(cfg["cfproxy"])
        pc.cfproxy_h2_media = bool(cfg["h2"])
        cf = mod.coerce_domain_list(cfg["cf_domains"])
        workers = mod.coerce_domain_list(cfg["worker_domains"])
        pc.cfproxy_user_domains = cf if cfg["cf_domains_enabled"] else []
        pc.cfproxy_worker_domains = workers if cfg["worker_enabled"] else []
        pc.disable_secure = bool(cfg["no_secure"])
        for field, value in (("force_test_dc", False), ("fake_tls_domain", ""), ("proxy_protocol", False)):
            if hasattr(pc, field):
                setattr(pc, field, value)
        logging.getLogger(PROXY_LOGGER).setLevel(logging.DEBUG if cfg["verbose"] else logging.INFO)

    # ------------------------------------------------------------ запуск

    def start(self, *, fallback: bool = True) -> None:
        """Включить прокси. Скачанное ядро, которое не стартует по своей вине (не порт и не настройки),
        заменяется встроенным — с плашкой, — и прокси включается на нём (fallback=False — нет)."""
        with self.lock:
            try:
                self._start_once()
            except TgError:
                if not (fallback and self._fall_back_to_bundled()):
                    raise
                self._start_once()

    def _fall_back_to_bundled(self) -> bool:
        core = self.core
        if core is None or core.origin != "updated" or self._failure != "core":
            return False
        reason = self.error
        try:
            bundled = loader.load_bundled()
        except Exception:  # noqa: BLE001 — нет и встроенного: остаётся исходная ошибка
            log.exception("Встроенное ядро Telegram-прокси не загрузилось")
            return False
        log.error("Скачанное ядро tg-ws-proxy %s не запустилось (%s) — перехожу на встроенное %s",
                  core.version, reason, bundled.version)
        self._forget_downloaded(self.settings.get("tg", "core"))
        self._install_core(bundled)
        self._report(CORE_ALERT, "warn", f"Скачанное ядро Telegram-прокси {core.version} не запустилось ({reason}) — "
                                         f"включено встроенное {bundled.version}.")
        return True

    def _start_once(self) -> None:
        thread = self._thread
        if thread is not None and thread.is_alive():
            if self.status in ("running", "starting"):
                return
            # Прежний запуск ещё закрывается (остановка дольше STOP_WAIT или падение ядра).
            thread.join(timeout=STOP_WAIT)
            if thread.is_alive():
                raise TgError("Прежний запуск прокси ещё не закрылся — повторите через несколько секунд")
        if self.core is None:
            try:
                self.load_core()
            except Exception as exc:  # noqa: BLE001 — ядро не загрузилось (нет модуля в сборке и т. п.)
                log.exception("Ядро Telegram-прокси не загрузилось")
                self.status, self.error, self._failure = "error", f"Ядро Telegram-прокси не загрузилось: {exc}", "load"
                raise TgError(self.error) from exc
        self.status, self.error, self._failure = "starting", None, None
        try:
            self.apply_config()
        except TgError as exc:
            self.status, self.error, self._failure = "error", str(exc), "config"
            raise
        ready, stop_requested = threading.Event(), threading.Event()
        thread = threading.Thread(target=self._run_thread, args=(ready, stop_requested), name="tg-proxy",
                                  daemon=True)
        self._thread, self._stop_requested = thread, stop_requested
        thread.start()
        ready.wait(START_WAIT)
        deadline = time.monotonic() + START_WAIT
        while time.monotonic() < deadline:
            if self.core.server_listening() and self.status == "starting":
                self.status = "running"
                self.started_at = time.time()
                log.info("Telegram-прокси слушает %s:%d", self.settings.get("tg", "host"),
                         self.settings.get("tg", "port"))
                self._remember_running(True)
                return
            if self.status == "error" or not thread.is_alive():
                break
            time.sleep(0.05)
        if self.status != "error":
            self.status, self.error = "error", self.error or "Прокси не начал принимать подключения"
            self._failure = self._failure or "core"
        error = self.error
        self._halt(thread, stop_requested)        # не начал слушать — не оставляем поток висеть
        self.status, self.error = "error", error
        raise TgError(error)

    def _run_thread(self, ready: threading.Event, stop_requested: threading.Event) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        stop_event = asyncio.Event()
        self._loop, self._stop_event = loop, stop_event
        ready.set()
        failure: tuple[str, str] | None = None
        try:
            loop.run_until_complete(self.core.main._run(stop_event=stop_event))  # noqa: SLF001
            if not stop_requested.is_set():
                # Ядро вышло само: слушающий сокет умер, а занять порт снова не вышло.
                failure = ("core", "слушающий порт закрылся, а открыть его снова не удалось")
        except OSError as exc:
            failure = ("bind", explain_bind_error(exc, self.settings.get("tg", "port")))
            log.error("%s", failure[1])
        except Exception as exc:  # noqa: BLE001 — ядро чужое, падать приложению нельзя
            failure = ("core", f"Прокси аварийно остановился: {exc!r}")
            log.exception("Telegram-прокси упал")
        finally:
            pending = [t for t in asyncio.all_tasks(loop) if not t.done()]
            for task in pending:
                task.cancel()
            if pending:
                loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            loop.run_until_complete(loop.shutdown_asyncgens())
            loop.close()
            # Только свои поля: новый запуск мог уже поставить свои (остановка дольше STOP_WAIT).
            if self._loop is loop:
                self._loop = None
            if self._stop_event is stop_event:
                self._stop_event = None
        if stop_requested.is_set() or self._thread is not threading.current_thread():
            return
        self._finish_run(failure)

    def _finish_run(self, failure: tuple[str, str] | None) -> None:
        """Поток прокси закончился без просьбы о выключении: не включился или упал на ходу."""
        kind, text = failure or ("core", "ядро остановилось без объяснения причин")
        self._failure = kind
        if self.status != "running":
            self.status, self.error = "error", text
            return
        self.status, self.error, self.started_at = "error", f"Прокси остановился сам: {text}", None
        log.error("%s", self.error)
        if self.on_crash is not None:
            try:
                self.on_crash(self.error)
            except Exception:  # noqa: BLE001
                log.exception("Падение Telegram-прокси не обработано")

    def _halt(self, thread: threading.Thread, stop_requested: threading.Event) -> None:
        """Попросить поток прокси закончиться и подождать его. Не дождались — поток помним: новый
        запуск подождёт его, а не поднимется рядом на тех же глобальных объектах ядра."""
        stop_requested.set()
        loop, stop_event = self._loop, self._stop_event
        if loop and stop_event and not loop.is_closed():
            try:
                loop.call_soon_threadsafe(stop_event.set)
            except RuntimeError:
                pass
        _stop_domain_refresh(self.core)
        thread.join(timeout=STOP_WAIT)
        if thread.is_alive():
            log.warning("Поток прокси не остановился за %.0f с — новый запуск подождёт его", STOP_WAIT)
        elif self._thread is thread:
            self._thread = None

    def stop(self, remember: bool = True) -> None:
        with self.lock:
            thread, stop_requested = self._thread, self._stop_requested
            if thread is not None and stop_requested is not None:
                self._halt(thread, stop_requested)
            else:
                _stop_domain_refresh(self.core)
            self.status, self.error, self.started_at = "stopped", None, None
            if remember:
                self._remember_running(False)
            log.info("Telegram-прокси остановлен")

    def restart(self) -> None:
        with self.lock:
            self.stop(remember=False)
            time.sleep(RESTART_PAUSE)
            self.start()

    def _remember_running(self, value: bool) -> None:
        self.settings.update(lambda d: d["tg"].__setitem__("was_running", value))

    def close_original(self) -> int:
        procs = _tgwsproxy_running()
        for proc in procs:
            try:
                proc.kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        psutil.wait_procs(procs, timeout=5)
        return len(procs)

    def original_running(self) -> bool:
        return bool(_tgwsproxy_running())

    def refresh_client(self) -> None:
        """Подключён ли Telegram на самом деле — по процессам и счётчикам ядра."""
        running = _telegram_running()
        st = self.core.stats if self.core else None
        connected = bool(st is not None and _stat(st, "connections_active") > 0)
        bad = _stat(st, "connections_bad") if st is not None else 0
        now = time.time()
        last_bad, last_bad_at = self._bad_seen
        if bad > last_bad:
            self._bad_seen = (bad, now)
            last_bad_at = now
        stale = (not connected) and now - last_bad_at < 120 and bad > 0
        if self.status != "running":
            hint = None
        elif stale:
            hint = "Telegram подключается со старым ключом — нажмите «Подключить Telegram» ещё раз."
        elif connected:
            hint = None
        elif running:
            hint = "Telegram запущен, но не использует прокси — нажмите «Подключить Telegram»."
        else:
            hint = "Запустите Telegram Desktop и нажмите «Подключить Telegram»."
        self.client = {"telegram_running": running, "connected": connected, "stale_key": stale, "hint": hint}

    # ------------------------------------------------------------ состояние

    def link(self) -> str:
        cfg = self.settings.get("tg")
        host = cfg["host"]
        if host in ("0.0.0.0", ""):   # слушает все адреса — Telegram на этом же компьютере
            host = "127.0.0.1"
        return f"tg://proxy?server={host}&port={cfg['port']}&secret=dd{cfg['secret']}"

    def sample(self) -> None:
        """Раз в секунду: скорость и история для графика."""
        if self.core is None:
            return
        st = self.core.stats
        now = time.monotonic()
        up, down = _stat(st, "bytes_up"), _stat(st, "bytes_down")
        if self._last_sample is not None:
            t0, u0, d0 = self._last_sample
            dt = max(now - t0, 1e-3)
            self._rates = (max(0.0, (up - u0) / dt), max(0.0, (down - d0) / dt))
        self._last_sample = (now, up, down)
        if self.status == "running":
            self._history.append([round(time.time(), 1), round(self._rates[0], 1), round(self._rates[1], 1)])

    def snapshot(self) -> dict:
        cfg = self.settings.get("tg")
        stats = {}
        if self.core is not None:
            st = self.core.stats
            stats = {
                "active": _stat(st, "connections_active"), "total": _stat(st, "connections_total"),
                "ws": _stat(st, "connections_ws"), "cf": _stat(st, "connections_cfproxy"),
                "h2": _stat(st, "connections_h2"), "tcp_fallback": _stat(st, "connections_tcp_fallback"),
                "bad": _stat(st, "connections_bad"), "up": _stat(st, "bytes_up"), "down": _stat(st, "bytes_down"),
                "up_rate": round(self._rates[0], 1), "down_rate": round(self._rates[1], 1),
            }
        return {
            "status": self.status, "error": self.error,
            "host": cfg["host"], "port": cfg["port"], "link": self.link(),
            "version": self.core.version if self.core else None,
            "core": self.core.origin if self.core else "bundled",
            "started_at": self.started_at,
            "stats": stats,
            "history": list(self._history),
            "test": dict(self.test_state),
            "client": dict(self.client),
        }

    # ------------------------------------------------------------ настройки

    def validate(self, values: dict) -> tuple[dict, dict]:
        """Проверяет форму настроек. Возвращает (чистые значения, ошибки по полям).

        Формат DC и доменов знает ядро: не загрузилось — TgError с причиной (а не «внутренняя ошибка»)."""
        core = self._core_for_validation()
        errors: dict[str, str] = {}
        clean: dict = {}
        host = str(values.get("host", "")).strip()
        if valid_listen_host(host):
            clean["host"] = host
        else:
            # IPv6 asyncio слушал бы без IPv4, а ссылка для Telegram ведёт на 127.0.0.1.
            errors["host"] = "Нужен IPv4-адрес, например 127.0.0.1"
        try:
            port = int(values.get("port"))
            if not 1 <= port <= 65535:
                raise ValueError
            clean["port"] = port
        except (TypeError, ValueError):
            errors["port"] = "Порт должен быть числом от 1 до 65535"
        secret = str(values.get("secret", "")).strip().lower()
        if len(secret) != 32 or not re.fullmatch(r"[0-9a-f]{32}", secret):
            errors["secret"] = "Ключ — ровно 32 символа 0–9 и a–f"
        else:
            clean["secret"] = secret
        dc_lines = values.get("dc_ip", [])
        if isinstance(dc_lines, str):
            dc_lines = dc_lines.splitlines()
        dc_lines = [str(x).strip() for x in dc_lines if str(x).strip()]
        try:
            core.config.parse_dc_ip_list(dc_lines)
            clean["dc_ip"] = dc_lines
        except ValueError as exc:
            entry = getattr(exc, "entry", None)
            errors["dc_ip"] = f"Неверная строка «{entry}» — формат номер:IP" if entry else str(exc)
        for key in ("cf_domains", "worker_domains"):
            raw = values.get(key, [])
            items = core.config.coerce_domain_list(raw)
            bad = [d for d in items if not _DOMAIN.match(d)]
            if bad:
                errors[key] = f"Некорректный домен: {bad[0]}"
            else:
                clean[key] = items
        for key, lo, hi in (("pool_size", 0, 32), ("buf_kb", 4, 4096)):
            try:
                value = int(values.get(key))
                if not lo <= value <= hi:
                    raise ValueError
                clean[key] = value
            except (TypeError, ValueError):
                errors[key] = f"Число от {lo} до {hi}"
        for key in ("cfproxy", "h2", "cf_domains_enabled", "worker_enabled", "no_secure", "verbose"):
            clean[key] = bool(values.get(key))
        clean["zapret_sync"] = bool(values.get("zapret_sync", True))
        if clean.get("worker_enabled") and not clean.get("worker_domains"):
            errors["worker_domains"] = "Укажите хотя бы один домен Worker или выключите его"
        if clean.get("cf_domains_enabled") and not clean.get("cf_domains"):
            errors["cf_domains"] = "Укажите свой домен или выключите эту опцию"
        return clean, errors

    def _core_for_validation(self) -> loader.ProxyCore:
        if self.core is None:
            try:
                self.load_core()
            except Exception as exc:  # noqa: BLE001
                log.exception("Ядро Telegram-прокси не загрузилось")
                raise TgError(f"Ядро Telegram-прокси не загрузилось — настройки не проверить: {exc}") from exc
        assert self.core is not None
        return self.core

    def save(self, values: dict) -> dict:
        clean, errors = self.validate(values)
        if errors:
            return errors
        self.settings.update(lambda d: d["tg"].update(clean))
        if self.status in ("running", "starting"):
            threading.Thread(target=self._restart_quietly, name="tg-restart", daemon=True).start()
        return {}

    def regen_secret(self) -> str:
        secret = os.urandom(16).hex()
        self.settings.update(lambda d: d["tg"].__setitem__("secret", secret))
        if self.status in ("running", "starting"):
            threading.Thread(target=self._restart_quietly, name="tg-restart", daemon=True).start()
        return secret

    def _restart_quietly(self) -> None:
        try:
            self.restart()
        except TgError as exc:
            self.notify("error", str(exc))

    # ------------------------------------------------------------ проверка маршрутов

    def run_test(self) -> None:
        if self.test_state["running"]:
            return
        self.test_state = {"running": True, "at": None, "results": []}
        threading.Thread(target=self._test_worker, name="tg-test", daemon=True).start()

    def _test_worker(self) -> None:
        try:
            results = self._routes()
        except TgError as exc:
            results = [{"name": "Проверка", "ok": False, "detail": str(exc)}]
        except Exception as exc:  # noqa: BLE001
            log.exception("Проверка маршрутов упала")
            results = [{"name": "Проверка", "ok": False, "detail": repr(exc)}]
        self.test_state = {"running": False, "at": time.time(), "results": results}

    def _routes(self) -> list[dict]:
        core = self._core_for_validation()
        cfg = self.settings.get("tg")
        mod = core.config
        ctx = core.utils.create_ssl_context()
        ctx_front = core.utils.create_ssl_context(check_hostname=False)
        cases: list[tuple[str, Callable[[], str]]] = []
        try:
            dc_map = mod.parse_dc_ip_list(cfg["dc_ip"])
        except ValueError:
            dc_map = {}
        for dc, ip in sorted(dc_map.items()):
            domain = f"kws{dc}.web.telegram.org"
            cases.append((f"Прямой WebSocket DC{dc} ({ip})",
                          lambda ip=ip, domain=domain: _ws_probe(ip, domain, domain, "/apiws", ctx)))
            cases.append((f"WebSocket DC{dc} с маскировкой SNI",
                          lambda ip=ip, domain=domain: _ws_probe(ip, "sprinthost.ru", domain, "/apiws", ctx_front)))
        if cfg["cfproxy"]:
            if cfg["cf_domains_enabled"] and cfg["cf_domains"]:
                for base in mod.coerce_domain_list(cfg["cf_domains"]):
                    host = f"kws2.{base}"
                    cases.append((f"Cloudflare: {base}",
                                  lambda host=host: _ws_probe(host, host, host, "/apiws", ctx)))
            else:
                pool = list(getattr(mod, "CFPROXY_DEFAULT_DOMAINS", []))[:4]
                for index, base in enumerate(pool, 1):
                    host = f"kws2.{base}"
                    cases.append((f"Cloudflare, встроенный домен №{index}",
                                  lambda host=host: _ws_probe(host, host, host, "/apiws", ctx)))
        if cfg["worker_enabled"]:
            for worker in mod.coerce_domain_list(cfg["worker_domains"]):
                path = f"/apiws?dst={DC_DEFAULT_IPS[2]}&dc=2"
                cases.append((f"Cloudflare Worker: {worker}",
                              lambda worker=worker, path=path: _ws_probe(worker, worker, worker, path, ctx)))
        if not cases:
            return [{"name": "Маршруты", "ok": False, "detail": "Нет ни одного маршрута для проверки"}]
        results = []
        with ThreadPoolExecutor(max_workers=8) as pool_exec:
            futures = [(name, pool_exec.submit(fn)) for name, fn in cases]
            for name, fut in futures:
                try:
                    detail = fut.result(timeout=20)
                    results.append({"name": name, "ok": detail.startswith("101"), "detail": detail})
                except Exception as exc:  # noqa: BLE001
                    results.append({"name": name, "ok": False, "detail": _short(exc)})
        return results


def valid_listen_host(host: object) -> bool:
    """Адрес, который прокси слушает: только IPv4 (0.0.0.0 — все адреса)."""
    try:
        return isinstance(host, str) and ipaddress.ip_address(host.strip()).version == 4
    except ValueError:
        return False


def _short(exc: BaseException) -> str:
    if isinstance(exc, socket.timeout):
        return "нет ответа (таймаут)"
    text = str(exc) or type(exc).__name__
    return text if len(text) <= 90 else text[:87] + "…"


def _ws_probe(connect_host: str, sni: str, host_header: str, path: str, ctx) -> str:
    """Пробное WebSocket-рукопожатие. Возвращает строку статуса ответа."""
    with socket.create_connection((connect_host, 443), timeout=6) as raw:
        with ctx.wrap_socket(raw, server_hostname=sni) as tls:
            key = base64.b64encode(os.urandom(16)).decode()
            tls.sendall((f"GET {path} HTTP/1.1\r\nHost: {host_header}\r\nUpgrade: websocket\r\n"
                         f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
                         f"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: binary\r\n\r\n").encode())
            tls.settimeout(6)
            buf = b""
            while b"\r\n" not in buf and len(buf) < 4096:
                chunk = tls.recv(1024)
                if not chunk:
                    break
                buf += chunk
    first = buf.split(b"\r\n", 1)[0].decode("latin-1", errors="replace")
    parts = first.split(" ", 2)
    if len(parts) >= 2 and parts[1].isdigit():
        return " ".join(parts[1:])
    return first or "пустой ответ"
