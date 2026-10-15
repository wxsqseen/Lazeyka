"""Ядро приложения: связывает zapret, Telegram-прокси, обновления и интерфейс."""
from __future__ import annotations

import itertools
import logging
import re
import threading
import time
from pathlib import Path
from typing import Any, Callable

from . import APP_NAME, __version__, autostart, paths, vpn, winutil
from .log import ring, set_verbose
from .settings import Settings, import_tgwsproxy_config
from .tgproxy.manager import TgError, TgProxyManager
from .updates.manager import UpdateError, UpdateManager
from .zapret import diagnostics, hosts, migrate
from .zapret.manager import ZapretError, ZapretManager
from .zapret.tester import StrategyTester

log = logging.getLogger("lazeyka.core")

Result = dict[str, Any]


def ok(**extra: Any) -> Result:
    return {"ok": True, **extra}


def fail(message: str, **extra: Any) -> Result:
    return {"ok": False, "error": message, **extra}


class Core:
    def __init__(self, autostarted: bool = False, log_dir: Path | None = None):
        self.autostarted = autostarted
        self.is_admin = winutil.is_admin()
        self.log_dir = log_dir or paths.logs_dir(allow_create_data=self.is_admin)
        self.settings = Settings(paths.SETTINGS_FILE, allow_create=self.is_admin)
        self.first_launch = self.settings.created
        self._notices: list[dict] = []
        self._notice_ids = itertools.count(1)
        self._dismissed: set[str] = set()
        self._lock = threading.RLock()
        self.zapret = ZapretManager(self.settings, self.notify, self.is_admin)
        self.tester = StrategyTester(self.zapret, self.notify)
        self.zapret.extra_lists = self._tg_extra_lists
        self.tg = TgProxyManager(self.settings, self.notify)
        self.updates = UpdateManager(self.settings, self.zapret, self.tg, self.notify, self.is_admin)
        self.diag_state: dict = {"running": False, "at": None, "items": []}
        self.busy: str | None = None
        self._conflicts: list[dict] = []
        self._original_tgws = False
        self._stop = threading.Event()
        self.on_show: Callable[[], None] | None = None
        self.on_hide: Callable[[], None] | None = None
        self.on_quit: Callable[[], None] | None = None
        self.on_theme: Callable[[str], None] | None = None
        self.on_status_change: Callable[[], None] | None = None
        self.on_toast: Callable[[str], None] | None = None
        self.ui_visible = True
        self._last_toast = 0.0
        # Сторож обхода, сон и смена сети
        self.watchdog_state: dict = {"last_at": None, "last_ok": None, "failing": [], "vpn": False}
        self._wd_next = 0.0
        self._wd_fails = 0
        self._wd_busy = False
        self._last_wall = time.time()
        self._net_fp: frozenset | None = None
        self._best_id: str | None = None
        self._best_at: float | None = None
        self._scores: dict[str, float] = {}
        self._check_fp: tuple | None = None   # состояние обхода, при котором шла последняя проверка
        self.dns_state: dict = {"running": False, "at": None, "doh_enabled": None, "spoofed": [],
                                "providers": [], "message": None}
        # Defender сносит файлы: проверяем по запросу, кнопку даём только после реального удаления
        self.defender_state: dict = {"checked": False, "running": False, "present": None, "active": None,
                                     "excluded": None, "at": None}
        # VPN рядом с обходом
        self.vpn_snapshot: vpn.Snapshot | None = None
        self.vpn_routes: dict | None = None
        self._vpn_scan_at = 0.0
        self._vpn_was_active: bool | None = None
        self.zapret.vpn_plan = self._vpn_plan
        self.tester.source = self._direct_source
        self._last_tray_key: tuple | None = None

    # ------------------------------------------------------------ уведомления

    def notify(self, level: str, text: str, action: dict | None = None) -> None:
        ttl = 60 if level == "error" or action else 25
        with self._lock:
            self._notices.append({"id": f"n{next(self._notice_ids)}", "level": level, "text": text,
                                  "action": action, "dismissible": True, "expires": time.time() + ttl})
            self._notices = self._notices[-6:]
        log.log(logging.ERROR if level == "error" else logging.INFO, "Уведомление: %s", text)
        self._toast_if_hidden(level, text)

    def _toast_if_hidden(self, level: str, text: str) -> None:
        """Пока окно скрыто, важное приходит уведомлением Windows — не чаще раза в 20 секунд."""
        if self.ui_visible or self.on_toast is None or level not in ("error", "warn", "success"):
            return
        now = time.monotonic()
        if now - self._last_toast < 20:
            return
        self._last_toast = now
        try:
            self.on_toast(text)
        except Exception:  # noqa: BLE001
            log.debug("Уведомление Windows не показано", exc_info=True)

    def _persistent_notices(self) -> list[dict]:
        out = []
        if not self.is_admin:
            out.append({"id": "admin", "level": "warn",
                        "text": "Лазейка запущена без прав администратора: обход для Discord и YouTube "
                                "недоступен, настройки не сохраняются. Telegram-прокси работает.",
                        "action": {"label": "Перезапустить с правами", "call": "relaunch_admin", "args": []},
                        "dismissible": False})
        count = self.updates.available_count()
        if count:
            versions = ",".join(f"{key}:{rel['version']}" for key, rel in self.updates.releases.items()
                                if rel and self.updates.is_available(key) and not self.updates.is_skipped(key))
            out.append({"id": f"update:{versions}", "level": "info",
                        "text": "Доступно обновление" + ("" if count == 1 else f"ий: {count}") +
                                ". Скачается только если вы нажмёте «Установить».",
                        "action": {"label": "Посмотреть", "page": "updates"}, "dismissible": True})
        if self._conflicts:
            first = self._conflicts[0]
            out.append({"id": f"conflict:{first['id']}", "level": "warn", "text": first["text"],
                        "action": {"label": first["fix_label"], "call": "zapret_fix_conflict",
                                   "args": [first["id"]]} if first.get("fix_label") else None,
                        "dismissible": True})
        if self._original_tgws:
            out.append({"id": "tgws-original", "level": "warn",
                        "text": "Запущен оригинальный TG WS Proxy. Лазейка его заменяет — закройте его, "
                                "чтобы не было конфликта портов.",
                        "action": {"label": "Закрыть TG WS Proxy", "call": "tg_close_original", "args": []},
                        "dismissible": True})
        d = self.defender_state
        if (self.is_admin and not paths.is_portable() and self.zapret.av_removal_seen
                and d.get("active") and d.get("excluded") is False):
            out.append({"id": "defender", "level": "warn",
                        "text": "Microsoft Defender удаляет файлы Лазейки — это ложное срабатывание на драйвер "
                                "WinDivert, не вирус. Добавить Лазейку в доверенные Defender, чтобы он её не трогал?",
                        "action": {"label": "Добавить в исключения Defender", "call": "defender_exclude",
                                   "args": []},
                        "dismissible": True})
        return [n for n in out if n["id"] not in self._dismissed]

    def notices(self) -> list[dict]:
        now = time.time()
        with self._lock:
            self._notices = [n for n in self._notices if n["expires"] > now and n["id"] not in self._dismissed]
            transient = [{k: v for k, v in n.items() if k != "expires"} for n in self._notices]
        return self._persistent_notices() + transient

    def dismiss_notice(self, notice_id: str) -> Result:
        with self._lock:
            self._dismissed.add(str(notice_id))
        return ok()

    # ------------------------------------------------------------ запуск

    def startup(self) -> None:
        log.info("%s %s, администратор: %s, данные: %s", APP_NAME, __version__, self.is_admin, paths.DATA)
        if self.first_launch and self.is_admin:
            self._first_launch_import()
        self.zapret.init()
        try:
            self.tg.load_core()
        except Exception as exc:  # noqa: BLE001
            log.exception("Ядро Telegram-прокси не загрузилось")
            self.notify("error", f"Ядро Telegram-прокси не загрузилось: {exc}")
        set_verbose(self.settings.get("tg", "verbose"))
        threading.Thread(target=self._autostart_components, name="autostart-components", daemon=True).start()
        threading.Thread(target=self._ticker, name="ticker", daemon=True).start()
        if self.settings.get("updates", "check"):
            threading.Timer(8.0, lambda: self.updates.check_async(quiet=True)).start()
        if self.is_admin and self.zapret.av_removal_seen:
            # Файлы уже удаляли — выясним про Defender, чтобы предложить исключение.
            threading.Timer(3.0, self.defender_check).start()
        if self.is_admin and self.settings.get("startup", "autostart"):
            try:
                autostart.sync()
            except Exception as exc:  # noqa: BLE001
                log.warning("Задание автозапуска не обновлено: %s", exc)

    def _first_launch_import(self) -> None:
        if import_tgwsproxy_config(self.settings):
            self.notify("success", "Перенесены настройки TG WS Proxy — ссылка в Telegram остаётся прежней.")
        try:
            root = migrate.find_original()
            if root is not None:
                done = migrate.import_from(root, self.settings, paths.USER_LISTS_DIR)
                self.notify("success", f"Найден ваш zapret в {root}. Перенесено: {', '.join(done)}.")
        except Exception as exc:  # noqa: BLE001
            log.warning("Перенос настроек zapret не удался: %r", exc)

    def _autostart_components(self) -> None:
        first = self.settings.get("first_run")
        start = self.settings.get("startup")
        if start["tg"] and (first or self.settings.get("tg", "was_running")):
            try:
                self.tg.start()
            except TgError as exc:
                self.notify("error", str(exc))
        if (self.zapret.available and start["zapret"] and not first
                and self.settings.get("zapret", "was_running")):
            try:
                if self.zapret.mode == "app":
                    self.zapret.start()
                    self._arm_connectivity_guard()  # и при автозапуске: вдруг оборвёт интернет при входе
            except ZapretError as exc:
                self.notify("error", f"Обход не запустился: {exc}")
        self._status_changed()

    def _ticker(self) -> None:
        tick = 0
        while not self._stop.wait(1.0):
            tick += 1
            try:
                self._check_resume()
                self.tg.sample()
                self.zapret.refresh_status()
                if tick % 5 == 1:
                    self._conflicts = self.zapret.conflicts() if self.is_admin else []
                    self._original_tgws = self.tg.original_running()
                    self.tg.refresh_client()
                    self._best_id, self._scores, self._best_at = self.tester.best_known()
                    self._check_network()
                self._watchdog_tick()
                self._status_changed()
            except Exception:  # noqa: BLE001
                log.exception("Ошибка фонового обновления состояния")

    # ------------------------------------------------------------ сон, сеть, сторож

    def _check_resume(self) -> None:
        """Разрыв между тиками больше 30 с — компьютер спал: соединения мертвы, перезапускаем."""
        now = time.time()
        gap = now - self._last_wall
        self._last_wall = now
        if gap < 30:
            return
        log.info("Похоже, компьютер выходил из сна (пауза %.0f с) — перезапускаю обход и прокси", gap)

        def work() -> None:
            if self.tg.status == "running":
                self.tg.restart()
            if self.zapret.mode == "app" and self.zapret.status == "running" and not self.zapret.paused_for_test:
                self.zapret.restart()
            self._wd_next = time.time() + 30   # и перепроверить, когда сеть поднимется

        self.background("resume", work, "Перезапуск после сна не удался")

    def _check_network(self) -> None:
        """Сменилась сеть (другой Wi-Fi, кабель, VPN) — обновить прокси и перепроверить обход."""
        import psutil
        addrs = set()
        for name, items in psutil.net_if_addrs().items():
            for a in items:
                if a.family == 2 and not a.address.startswith(("127.", "169.254.")):
                    addrs.add((name, a.address))
        fp = frozenset(addrs)
        first = self._net_fp is None
        changed = not first and fp != self._net_fp
        if changed:
            log.info("Сеть изменилась — перезапускаю Telegram-прокси и перепроверю обход")
            if self.tg.status == "running":
                self.background("net-change", self.tg.restart, "Перезапуск прокси после смены сети не удался")
            self._wd_next = time.time() + 20
        self._net_fp = fp
        if first or changed or time.monotonic() - self._vpn_scan_at > 30:
            self._vpn_watch(announce=not first)

    def _watchdog_tick(self) -> None:
        mode = self.settings.get("zapret", "watchdog")
        z = self.zapret
        if (mode == "off" or not self.is_admin or z.status != "running" or self._wd_busy
                or self.tester.running or self.tester.fix_running or z.paused_for_test):
            return
        now = time.time()
        if self._wd_next == 0.0:
            self._wd_next = now + 180    # первая проверка — через 3 минуты после запуска
            return
        if now < self._wd_next:
            return
        self._wd_next = now + 600
        self._wd_busy = True
        threading.Thread(target=self._watchdog_check, args=(mode,), name="watchdog", daemon=True).start()

    def _watchdog_check(self, mode: str) -> None:
        from .zapret.tester import control_ok, quick_check
        try:
            bind = self._direct_source()
            watch = {"discord", "youtube"}
            snap = self.vpn_snapshot
            if snap is not None and snap.active:
                # Что идёт через VPN, обход не касается — и тревожить из-за него незачем.
                routes = vpn.probe_routes(snap)
                self.vpn_routes = dict(routes, running=False)
                watch = {i["id"] for i in routes["items"] if i["id"] in watch and i["via"] != "vpn"}
                if not watch:
                    self.watchdog_state.update(last_at=time.time(), last_ok=None, failing=[], vpn=True)
                    self._wd_fails = 0
                    return
            if not control_ok(bind=bind):
                log.info("Сторож: нет интернета — проверку пропускаю")
                return
            fp = self._zapret_fingerprint()
            results = [r for r in quick_check(bind=bind) if r["id"] in watch]
            failing = [r["label"] for r in results if not r["ok"]]
            self.watchdog_state.update(last_at=time.time(), last_ok=not failing, failing=failing, vpn=False)
            self.tester.check_state = {"running": False, "at": time.time(), "results": results,
                                       "direct": bool(bind)}
            self._check_fp = fp
            self._wd_fails = self._wd_fails + 1 if failing else 0
            if self._wd_fails == 1 and failing:
                self._wd_next = time.time() + 60   # перепроверить через минуту: вдруг случайный сбой
            if self._wd_fails < 2:
                return
            self._wd_fails = 0
            what = " и ".join(failing)
            if mode == "auto":
                self.notify("warn", f"{what} перестал открываться — подбираю рабочую стратегию.")
                self.tester.start_fix()
            else:
                self.notify("warn", f"{what} перестал открываться. Найти рабочую стратегию?",
                            action={"label": "Найти и включить", "call": "zapret_fix", "args": []})
        except Exception:  # noqa: BLE001
            log.exception("Сторож не смог проверить доступность")
        finally:
            self._wd_busy = False

    def _best_summary(self) -> dict | None:
        if not self._best_id:
            return None
        label = next((s.label for s in self.zapret.strategies if s.id == self._best_id), self._best_id)
        return {"id": self._best_id, "label": label, "score": self._scores.get(self._best_id),
                "at": self._best_at}

    def _status_changed(self) -> None:
        key = (self.zapret.status, self.tg.status, self.zapret.settings.get("zapret", "strategy"),
               self.updates.available_count())
        if key != self._last_tray_key:
            self._last_tray_key = key
            if self.on_status_change:
                try:
                    self.on_status_change()
                except Exception:  # noqa: BLE001
                    log.exception("Иконка в трее не обновилась")

    def shutdown(self) -> None:
        self._stop.set()
        self.tester.cancel()
        self.tester.join(15)  # подбор сам вернёт обход и IPSet; иначе это сделает следующий запуск
        try:
            self.tg.stop(remember=False)
        except Exception:  # noqa: BLE001
            log.exception("Прокси не остановился")
        if self.zapret.mode == "app":
            try:
                self.zapret.stop(remember=False)
            except Exception:  # noqa: BLE001
                log.exception("Обход не остановился")
        log.info("Лазейка завершает работу")

    # ------------------------------------------------------------ состояние

    def state(self) -> dict:
        s = self.settings.snapshot()
        z = self.zapret
        updates = self.updates.snapshot()
        return {
            "app": {"name": APP_NAME, "version": __version__, "admin": self.is_admin,
                    "first_run": s["first_run"], "data_dir": str(paths.DATA), "busy": self.busy},
            "notices": self.notices(),
            "zapret": {
                "available": z.available,
                "unavailable_reason": z.unavailable_reason,
                "status": z.status, "error": z.error, "mode": s["zapret"]["mode"],
                "strategy": s["zapret"]["strategy"],
                "strategies": [{"id": st.id, "label": st.label} for st in z.strategies if st.usable],
                "started_at": z.process.started_at if z.process else None,
                "pack": {"version": z.pack.version if z.pack else None},
                "game_filter": s["zapret"]["game_filter"],
                "ipset": z.ipset_info(),
                "service": z.service_info(),
                "conflicts": self._conflicts,
                "check": self._fresh_check(),
                "test": dict(self.tester.state),
                "fix": dict(self.tester.fix_state),
                "watchdog": dict(self.watchdog_state, mode=s["zapret"]["watchdog"]),
                "best": self._best_summary(),
                "scores": self._scores,
            },
            "tg": self.tg.snapshot(),
            "updates": updates,
            "settings": {
                "theme": s["ui"]["theme"], "close_to_tray": s["ui"]["close_to_tray"],
                "start_minimized": s["ui"]["start_minimized"], "autostart": s["startup"]["autostart"],
                "zapret_on_start": s["startup"]["zapret"], "tg_on_start": s["startup"]["tg"],
                "check_updates": s["updates"]["check"], "tcp_timestamps": s["zapret"]["tcp_timestamps"],
                "watchdog": s["zapret"]["watchdog"],
            },
            "tg_settings": {k: s["tg"][k] for k in (
                "host", "port", "secret", "dc_ip", "cfproxy", "h2", "cf_domains_enabled", "cf_domains",
                "worker_enabled", "worker_domains", "pool_size", "buf_kb", "no_secure", "verbose",
                "zapret_sync")},
            "diag": dict(self.diag_state),
            "dns": dict(self.dns_state),
            "vpn": self._vpn_state(s),
            "defender": dict(self.defender_state),
        }

    def logs(self, after_id: int, source: str) -> dict:
        if source not in ("all", "app", "zapret", "tg"):
            source = "all"
        return ring.since(int(after_id or 0), source)

    # ------------------------------------------------------------ общее

    def _require_admin(self) -> None:
        if not self.is_admin:
            raise PermissionError("Нужны права администратора — перезапустите Лазейку с ними")

    def background(self, name: str, fn: Callable[[], Any], on_error: str) -> None:
        def run() -> None:
            try:
                fn()
            except (ZapretError, TgError, UpdateError, PermissionError, ValueError, RuntimeError, OSError) as exc:
                self.notify("error", f"{on_error}: {exc}")
            except Exception as exc:  # noqa: BLE001
                log.exception("%s", on_error)
                self.notify("error", f"{on_error}: {exc!r}")
            finally:
                self._status_changed()
        threading.Thread(target=run, name=name, daemon=True).start()

    def finish_onboarding(self, opts: dict) -> Result:
        opts = opts or {}
        check = bool(opts.get("check_updates", True))
        want_autostart = bool(opts.get("autostart", False))

        def mutate(d: dict) -> None:
            d["first_run"] = False
            d["updates"]["check"] = check

        self.settings.update(mutate)
        if want_autostart:
            result = self.save_settings({"autostart": True})
            if not result["ok"]:
                return result
        if check:
            self.updates.check_async(quiet=True)
        return ok()

    def save_settings(self, partial: dict) -> Result:
        partial = partial or {}
        mapping = {
            "theme": ("ui", "theme"), "close_to_tray": ("ui", "close_to_tray"),
            "start_minimized": ("ui", "start_minimized"), "zapret_on_start": ("startup", "zapret"),
            "tg_on_start": ("startup", "tg"), "check_updates": ("updates", "check"),
            "tcp_timestamps": ("zapret", "tcp_timestamps"),
        }
        if "theme" in partial and partial["theme"] not in ("system", "dark", "light"):
            return fail("Неизвестная тема")
        if "watchdog" in partial:
            if partial["watchdog"] not in ("ask", "auto", "off"):
                return fail("Неизвестный режим сторожа")
            self.settings.update(lambda d: d["zapret"].__setitem__("watchdog", partial["watchdog"]))
        if "autostart" in partial:
            try:
                self._require_admin()
                if partial["autostart"]:
                    target = autostart.enable()
                    if paths.IS_FROZEN and target != paths.exe_path():
                        self.notify("info", f"Для автозапуска Лазейка скопирована в {target.parent} — "
                                            "туда может писать только администратор.")
                else:
                    autostart.disable()
            except Exception as exc:  # noqa: BLE001
                return fail(f"Автозапуск не изменён: {exc}")
            self.settings.update(lambda d: d["startup"].__setitem__("autostart", bool(partial["autostart"])))

        def mutate(d: dict) -> None:
            for key, (section, field) in mapping.items():
                if key in partial:
                    d[section][field] = partial[key] if key == "theme" else bool(partial[key])

        self.settings.update(mutate)
        if "theme" in partial and self.on_theme:
            self.on_theme(partial["theme"])
        if not self.settings.writable:
            return fail("Настройки не сохранены: нет прав на запись в " + str(paths.DATA))
        return ok()

    def open_url(self, url: str) -> Result:
        if not isinstance(url, str) or not url.startswith("https://") or len(url) > 2000:
            return fail("Можно открывать только https-ссылки")
        if not winutil.open_unelevated(url):
            winutil.set_clipboard(url)
            return fail("Не удалось открыть браузер — ссылка скопирована в буфер обмена.")
        return ok()

    def open_path(self, kind: str) -> Result:
        target = {"logs": self.log_dir, "data": paths.DATA, "lists": paths.USER_LISTS_DIR}.get(kind)
        if target is None:
            return fail("Неизвестная папка")
        if not Path(target).is_dir():
            return fail("Папка ещё не создана")
        if not winutil.open_unelevated(str(target)):
            return fail(f"Не удалось открыть папку {target}")
        return ok()

    def copy_text(self, text: str) -> Result:
        return ok() if winutil.set_clipboard(str(text)[:100_000]) else fail("Буфер обмена занят другой программой")

    def relaunch_admin(self) -> Result:
        if self.is_admin:
            return ok()
        result = winutil.relaunch_as_admin(paths.launch_command() + ["--replace"])
        if result == "launched":
            threading.Timer(0.3, self.quit).start()
            return ok()
        if result == "cancelled":
            return fail("Запрос прав администратора отклонён")
        return fail("Не удалось перезапуститься с правами администратора")

    def show(self) -> None:
        if self.on_show:
            self.on_show()

    def hide(self) -> Result:
        if self.on_hide:
            self.on_hide()
        return ok()

    def quit(self) -> Result:
        if self.on_quit:
            self.on_quit()
        return ok()

    # ------------------------------------------------------------ zapret

    def zapret_start(self, quiet: bool = False) -> Result:
        """quiet — включили после окна «Работает VPN»: человек уже всё прочитал."""
        self._require_admin()
        self.background("zapret-start", self.zapret.start, "Обход не запустился")
        self._arm_connectivity_guard()
        if not quiet:
            self._vpn_note_on_start()
        return ok()

    def _arm_connectivity_guard(self) -> None:
        """После включения обхода проверяет, не пропал ли интернет вовсе (бывает при жёстком
        конфликте с VPN или антивирусом). Если пропал — предлагает выключить обход, сам ничего
        не переключает: вдруг человек как раз этого и хотел."""
        def guard() -> None:
            from .zapret.tester import control_ok
            time.sleep(2)
            bind = self._direct_source()
            for _ in range(4):
                if self.zapret.mode != "app" or self.zapret.status != "running" or self.zapret.paused_for_test:
                    return
                if control_ok(bind=bind):
                    return  # контрольный сайт открывается — всё в порядке
                time.sleep(2)
            # Прямой путь мёртв. Если без привязки к прямому интерфейсу сайт открывается — это не
            # «пропал интернет», а особенность VPN (kill switch глушит обход мимо туннеля): не пугаем.
            if bind and control_ok():
                return
            via = (" Возможно, конфликт с VPN." if self.vpn_snapshot and self.vpn_snapshot.active else "")
            self.notify("error", "После включения обхода не открывается даже проверочный сайт — похоже, "
                                 f"пропал интернет.{via} Можно выключить обход и вернуть всё как было.",
                        action={"label": "Выключить обход", "call": "zapret_stop", "args": []})

        threading.Timer(1.0, lambda: self.background("zapret-guard", guard, "Проверка связи не удалась")).start()

    def zapret_stop(self) -> Result:
        self._require_admin()
        self.background("zapret-stop", self.zapret.stop, "Обход не остановился")
        return ok()

    def zapret_restart(self) -> Result:
        self._require_admin()
        self.background("zapret-restart", self.zapret.restart, "Обход не перезапустился")
        return ok()

    def zapret_set_strategy(self, strategy_id: str) -> Result:
        self._require_admin()
        self.zapret.strategy(strategy_id)
        self.background("zapret-strategy", lambda: self.zapret.set_strategy(strategy_id),
                        "Стратегия не применена")
        return ok()

    def zapret_set_game_filter(self, mode: str, tcp: str, udp: str) -> Result:
        self._require_admin()
        errors = self.zapret.set_game_filter(str(mode), str(tcp), str(udp))
        return fail("Проверьте порты", errors=errors) if errors else ok()

    def zapret_set_ipset(self, mode: str) -> Result:
        self._require_admin()
        self.zapret.set_ipset(str(mode))
        return ok()

    def zapret_update_ipset(self) -> Result:
        """Скачивает свежий список IP. Синхронно: страница ждёт результата (это секунды)."""
        self._require_admin()
        from .updates.github import http_get
        from .zapret.manager import IPSET_URL
        text = http_get(IPSET_URL, timeout=30, limit=8 * 1024 * 1024).decode("utf-8", "replace")
        count = self.zapret.store_ipset(text)
        return ok(message=f"Список IP обновлён: {count} подсетей.")

    def zapret_set_mode(self, mode: str) -> Result:
        self._require_admin()
        self.background("zapret-mode", lambda: self._set_mode(mode), "Режим работы не изменён")
        return ok()

    def _set_mode(self, mode: str) -> None:
        self.zapret.set_mode(mode)
        self.notify("success", "Обход теперь работает как служба Windows — даже без открытой Лазейки."
                    if mode == "service" else "Обход снова запускается самой Лазейкой.")

    def zapret_check(self) -> Result:
        self._check_fp = self._zapret_fingerprint()
        self.tester.run_quick_check()
        return ok()

    def zapret_fix(self) -> Result:
        self._require_admin()
        self.tester.start_fix()
        return ok()

    def zapret_fix_revert(self) -> Result:
        self._require_admin()
        previous = self.tester.revert_fix()
        return ok(message=f"Вернули стратегию «{previous}».")

    def _tg_extra_lists(self) -> dict[str, list[str]]:
        """Домены для списков zapret, без которых Cloudflare-маршруты Telegram-прокси ломаются.

        Встроенные домены CF-прокси (*.co.uk) zapret портит — их исключаем, как советует
        автор tg-ws-proxy. Свои домены Cloudflare и Worker, наоборот, пропускаем через обход.
        """
        cfg = self.settings.get("tg")
        if not cfg.get("zapret_sync", True):
            return {}
        general: list[str] = []
        exclude: list[str] = []
        if cfg["cfproxy"]:
            if cfg["cf_domains_enabled"] and cfg["cf_domains"]:
                general += list(cfg["cf_domains"])
            else:
                exclude.append("co.uk")
        if cfg["worker_enabled"] and cfg["worker_domains"]:
            general += list(cfg["worker_domains"]) + ["workers.dev", "cloudflare.com", "cloudflare.dev"]
        return {"list-general-user.txt": general, "list-exclude-user.txt": exclude}

    def _zapret_fingerprint(self) -> tuple:
        """Всё, от чего зависит результат проверки доступности."""
        z = self.zapret
        cfg = self.settings.get("zapret")
        gf = cfg["game_filter"]
        return (z.status, cfg["strategy"], gf["mode"], gf["tcp"], gf["udp"], cfg["ipset_mode"],
                z.pack.version if z.pack else None, z.process.started_at if z.process else None)

    def _fresh_check(self) -> dict:
        """Результат проверки, только если с тех пор обход не менялся: старые «✓» не обманывают."""
        check = dict(self.tester.check_state)
        stale = self._check_fp != self._zapret_fingerprint()
        if not check.get("running") and check.get("results") and stale:
            return {"running": False, "at": None, "results": None}
        return check

    def zapret_test_start(self, kind: str, ids: list[str] | None) -> Result:
        self._require_admin()
        if ids is not None and not isinstance(ids, list):
            return fail("Неверный список стратегий")
        self.tester.start(str(kind), ids)
        return ok()

    def zapret_test_cancel(self) -> Result:
        self.tester.cancel()
        return ok()

    def zapret_fix_conflict(self, conflict_id: str) -> Result:
        self._require_admin()
        message = self.zapret.fix_conflict(str(conflict_id))
        self._conflicts = self.zapret.conflicts()
        return ok(message=message)

    def lists_get(self) -> Result:
        return ok(lists=self.zapret.lists_get())

    def lists_save(self, list_id: str, text: str) -> Result:
        self.zapret.lists_save(str(list_id), str(text))
        return ok()

    def fakes_get(self) -> Result:
        return ok(**self.zapret.fakes_get())

    def fakes_set(self, slot: str, name: str | None) -> Result:
        self._require_admin()
        self.zapret.fakes_set(str(slot), name or None)
        return ok()

    def hosts_check(self) -> Result:
        result = hosts.check()
        if result["up_to_date"]:
            text = f"Файл hosts в порядке: все {result['total']} записей на месте."
        else:
            parts = []
            if result["missing"]:
                parts.append(f"не хватает записей: {result['missing']}")
            if result["conflicts"]:
                parts.append(f"старых конфликтующих строк: {result['conflicts']}")
            text = "Файл hosts нужно обновить — " + ", ".join(parts) + "."
        return ok(text=text, **result)

    def hosts_apply(self) -> Result:
        self._require_admin()
        result = hosts.apply()
        return ok(**result)

    # ------------------------------------------------------------ Telegram

    def tg_start(self) -> Result:
        self.background("tg-start", self.tg.start, "Telegram-прокси не запустился")
        return ok()

    def tg_stop(self) -> Result:
        self.background("tg-stop", self.tg.stop, "Telegram-прокси не остановился")
        return ok()

    def tg_restart(self) -> Result:
        self.background("tg-restart", self.tg.restart, "Telegram-прокси не перезапустился")
        return ok()

    def tg_open_in_telegram(self) -> Result:
        link = self.tg.link()
        if not winutil.open_unelevated(link):
            winutil.set_clipboard(link)
            return fail("Не получилось открыть Telegram автоматически. Ссылка скопирована — "
                        "вставьте её в «Избранное» в Telegram и нажмите на неё.")
        if self.tg.status not in ("running", "starting"):
            return ok(warning="Прокси сейчас выключен — включите его, иначе Telegram не подключится.")
        return ok()

    def tg_copy_link(self) -> Result:
        return self.copy_text(self.tg.link())

    def tg_save_settings(self, values: dict) -> Result:
        errors = self.tg.save(values or {})
        if errors:
            return fail("Проверьте поля", errors=errors)
        if self.is_admin:
            self.background("lists-sync", self.zapret.refresh_extra_lists, "Списки обхода не обновлены")
        set_verbose(self.settings.get("tg", "verbose"))
        return ok()

    def tg_regen_secret(self) -> Result:
        return ok(secret=self.tg.regen_secret())

    def tg_test(self) -> Result:
        self.tg.run_test()
        return ok()

    def tg_close_original(self) -> Result:
        count = self.tg.close_original()
        self._original_tgws = False
        if self.tg.status == "error":
            self.background("tg-start", self.tg.start, "Telegram-прокси не запустился")
        return ok(message=f"Закрыто процессов: {count}")

    # ------------------------------------------------------------ диагностика

    def diag_run(self) -> Result:
        if self.diag_state["running"]:
            return ok()
        self.diag_state = {"running": True, "at": None, "items": self.diag_state.get("items", [])}

        def work() -> None:
            items: list[dict] = []
            try:
                items = diagnostics.run_all(self.zapret.pack.path if self.zapret.pack else None,
                                            self.zapret.running())
            finally:
                self.diag_state = {"running": False, "at": time.time(), "items": items}

        self.background("diagnostics", work, "Диагностика не выполнена")
        return ok()

    def diag_fix(self, fix_id: str) -> Result:
        self._require_admin()
        message = diagnostics.apply_fix(str(fix_id))
        self.diag_run()
        return ok(message=message)

    # ------------------------------------------------------------ VPN

    def _vpn_scan(self) -> vpn.Snapshot | None:
        try:
            snap = vpn.scan(self.settings.get("vpn", "overrides"))
        except Exception:  # noqa: BLE001
            log.exception("Сетевые адаптеры не прочитаны")
            return self.vpn_snapshot
        self.vpn_snapshot, self._vpn_scan_at = snap, time.monotonic()
        return snap

    def _vpn_plan(self) -> dict | None:
        """Для обхода: что исключить из перехвата. Вызывается при каждом запуске winws."""
        if not self.settings.get("vpn", "compat"):
            return None
        snap = self._vpn_scan()
        return snap.plan() if snap else None

    def _direct_source(self) -> str | None:
        """Для проверок обхода: адрес прямого подключения, если работает туннель VPN в интернет —
        полный или для части адресов (тогда неизвестно, каких именно). У VPN в режиме системного
        прокси проверки и так идут мимо него: curl запускается с --noproxy."""
        snap = self.vpn_snapshot
        if snap is None or not snap.internet:
            return None
        return snap.source_ip()

    def _vpn_watch(self, announce: bool) -> None:
        """Появился или пропал VPN, сменились интерфейсы — обновить фильтр работающего обхода."""
        snap = self._vpn_scan()
        if snap is None:
            return
        active = snap.active
        if announce and self._vpn_was_active is False and active:
            self._announce_vpn(snap)
        if active != self._vpn_was_active:
            self.vpn_routes = None  # прежняя картина «что куда идёт» больше не верна
        self._vpn_was_active = active
        z = self.zapret
        if (not self.is_admin or z.status != "running" or z.paused_for_test or self.tester.running
                or self.tester.fix_running):
            return
        if self.settings.get("vpn", "compat"):
            stale = vpn.plan_changed(z.vpn_applied, snap.plan(), snap.direct_indices())
        else:
            # Совместимость выключили, пока шёл подбор, — служба вернулась со старым фильтром.
            stale = z.vpn_applied.get("mode") == "vpn"
        if stale:
            self.background("vpn-reapply", z.reapply_for_network, "Обход не перезапустился под новую сеть")

    def _announce_vpn(self, snap: vpn.Snapshot) -> None:
        if self.zapret.status != "running":
            return
        name = snap.label()
        if self.settings.get("vpn", "compat"):
            self.notify("info", f"Подключён VPN ({name}). Обход его не трогает: интерфейс и сервер VPN "
                                "исключены из перехвата.", action={"label": "Что куда идёт", "page": "zapret"})
        else:
            self.notify("warn", f"Подключён VPN ({name}), а совместимость с VPN выключена — обход может "
                                "мешать VPN.", action={"label": "Включить совместимость", "call": "vpn_set_compat",
                                                       "args": [True]})

    def _vpn_note_on_start(self) -> None:
        snap = self.vpn_snapshot
        if snap is None or not snap.active:
            return
        if self.settings.get("vpn", "compat"):
            self.notify("info", f"Обход включён рядом с VPN ({snap.label()}): трафик VPN он не трогает.",
                        action={"label": "Что куда идёт", "page": "zapret"})
        else:
            self._announce_vpn(snap)

    @staticmethod
    def _vpn_known(snap: vpn.Snapshot | None, known: list[str]) -> bool:
        return bool(snap and snap.active and set(snap.signature()) <= set(known))

    def _vpn_state(self, s: dict) -> dict:
        snap = self.vpn_snapshot
        out = vpn.snapshot_dict(snap)
        out.update(compat=s["vpn"]["compat"], ask=s["vpn"]["ask"], overrides=dict(s["vpn"]["overrides"]),
                   known=self._vpn_known(snap, s["vpn"]["known"]), filter=dict(self.zapret.vpn_applied),
                   routes=dict(self.vpn_routes) if self.vpn_routes else None)
        return out

    def vpn_preflight(self, component: str) -> Result:
        """Перед включением обхода или прокси: работает ли VPN и нужно ли спросить человека."""
        snap = self._vpn_scan()
        cfg = self.settings.get("vpn")
        ask = bool(snap and snap.active and cfg["ask"] and not self._vpn_known(snap, cfg["known"]))
        if ask:
            self.vpn_probe()
        return ok(ask=ask, component=str(component), compat=cfg["compat"], vpn=vpn.snapshot_dict(snap))

    def vpn_probe(self) -> Result:
        """В фоне: через что сейчас идут Discord, YouTube и Telegram (состояние — в vpn.routes)."""
        if (self.vpn_routes or {}).get("running"):
            return ok()
        snap = self.vpn_snapshot or self._vpn_scan()
        if snap is None or not snap.active:
            self.vpn_routes = None
            return ok()
        self.vpn_routes = {"running": True, "at": None, "items": (self.vpn_routes or {}).get("items")}

        def work() -> None:
            result: dict = {}
            try:
                result = vpn.probe_routes(snap)
            finally:
                self.vpn_routes = (dict(result, running=False) if result else
                                   {"running": False, "at": time.time(), "items": None, "error": True})

        self.background("vpn-probe", work, "Не удалось проверить, что куда идёт")
        return ok()

    def vpn_answer(self, remember: bool, compat: bool = True) -> Result:
        """Ответ в окне «Работает VPN»: запомнить этот VPN и включить совместимость."""
        snap = self.vpn_snapshot
        compat = bool(compat)
        changed = self.settings.get("vpn", "compat") != compat

        def mutate(d: dict) -> None:
            if remember and snap is not None:
                d["vpn"]["known"] = sorted(set(d["vpn"]["known"]) | set(snap.signature()))[-20:]
            d["vpn"]["compat"] = compat

        self.settings.update(mutate)
        if changed:
            self._vpn_compat_changed()
        return ok()

    def vpn_set_compat(self, on: bool) -> Result:
        self._require_admin()
        self.settings.update(lambda d: d["vpn"].__setitem__("compat", bool(on)))
        self._vpn_compat_changed()
        return ok(message="Обход не будет трогать трафик VPN." if on else
                  "Совместимость с VPN выключена: обход снова перехватывает все подключения.")

    def _vpn_compat_changed(self) -> None:
        z = self.zapret
        if z.status == "running" and not z.paused_for_test:
            self.background("vpn-compat", z.reapply_for_network, "Обход не перезапустился")

    def vpn_set_ask(self, on: bool) -> Result:
        self.settings.update(lambda d: d["vpn"].__setitem__("ask", bool(on)))
        return ok()

    def vpn_forget(self) -> Result:
        self.settings.update(lambda d: d["vpn"].__setitem__("known", []))
        return ok(message="Лазейка снова спросит при включении рядом с VPN.")

    def vpn_set_override(self, adapter_id: str, kind: str | None) -> Result:
        """Поправка человека: этот адаптер — VPN (не трогать) или прямое подключение (обходить)."""
        self._require_admin()
        guid = str(adapter_id or "").lower()
        if not re.fullmatch(r"\{[0-9a-f-]{36}\}", guid):
            return fail("Неизвестный адаптер")
        if kind not in (None, "", "direct", "tunnel"):
            return fail("Неизвестный вариант")

        def mutate(d: dict) -> None:
            overrides = dict(d["vpn"]["overrides"])
            if kind:
                overrides[guid] = kind
            else:
                overrides.pop(guid, None)
            d["vpn"]["overrides"] = overrides

        self.settings.update(mutate)
        snap = self._vpn_scan()
        z = self.zapret
        if (self.settings.get("vpn", "compat") and z.status == "running" and snap is not None
                and vpn.plan_changed(z.vpn_applied, snap.plan(), snap.direct_indices())):
            self.background("vpn-override", z.reapply_for_network, "Обход не перезапустился")
        return ok()

    # ------------------------------------------------------------ помощь

    def dns_check(self) -> Result:
        if self.dns_state.get("running"):
            return ok()
        self.dns_state = dict(self.dns_state, running=True)

        def work() -> None:
            from .helpdesk import check_dns
            result = {}
            try:
                result = check_dns(diagnostics.doh_configured())
            finally:
                self.dns_state = dict(self.dns_state, **result, running=False)

        self.background("dns-check", work, "Проверка DNS не выполнена")
        return ok()

    def dns_open_settings(self) -> Result:
        """Параметры сети Windows: там включается DNS через HTTPS (Лазейка сама сеть не перенастраивает)."""
        if not winutil.open_unelevated("ms-settings:network-status"):
            return fail("Не удалось открыть параметры Windows")
        return ok()

    def help_report(self) -> Result:
        from .helpdesk import build_report
        text = build_report(self.state(), ring.since(0, "all", limit=400)["lines"])
        copied = winutil.set_clipboard(text)
        return ok(text=text, copied=copied)

    def check_site(self, domain: str) -> Result:
        from .helpdesk import check_site
        return check_site(str(domain))

    def lists_add_site(self, domain: str) -> Result:
        from .helpdesk import normalize_domain
        from .zapret import lists as zlists
        name = normalize_domain(str(domain))
        if not name:
            return fail("Некорректный адрес сайта")
        current = next((x["text"] for x in self.zapret.lists_get() if x["id"] == "list-general-user.txt"), "")
        entries = [ln.strip() for ln in current.splitlines() if ln.strip() and not ln.strip().startswith("#")]
        if name in entries:
            return ok(message=f"{name} уже в «Моих сайтах»")
        kept = [e for e in entries if e != zlists.PLACEHOLDER_DOMAIN]
        self.zapret.lists_save("list-general-user.txt", "\n".join(kept + [name]) + "\n")
        return ok(message=f"{name} добавлен в «Мои сайты»")

    def discord_clear_cache(self) -> Result:
        report = diagnostics.clear_discord_cache()
        return ok(message="; ".join(report))

    # ------------------------------------------------------------ Microsoft Defender

    def _defender_targets(self) -> tuple[list[str], list[str], tuple[str, ...]]:
        """Что именно сделать доверенным: только папки и файлы самой Лазейки.

        Папки (ProgramData\\Lazeyka и Program Files\\Lazeyka) создаются с доступом на запись
        лишь администратору, поэтому исключить их из проверки безопасно: подложить туда файл
        обычная программа не сможет. Случайный exe из «Загрузок» в исключения не попадёт —
        winutil проверяет, что путь внутри этих папок."""
        from . import autostart
        roots: list[str] = [str(paths.DATA)]
        install_dir = None
        try:
            install_dir = str(autostart.installed_exe().parent)
            roots.append(install_dir)
        except Exception:  # noqa: BLE001
            log.debug("Папка установки не определена", exc_info=True)
        paths_ex = list(roots)
        procs: list[str] = []
        try:
            procs.append(str(autostart.installed_exe()))
        except Exception:  # noqa: BLE001
            pass
        if paths.IS_FROZEN:
            procs.append(str(paths.exe_path()))
        if self.zapret.pack:
            procs.append(str(self.zapret.winws_exe))
        return paths_ex, procs, tuple(roots)

    def defender_check(self) -> Result:
        """В фоне узнаёт, включён ли Defender и добавлены ли уже файлы Лазейки в его исключения."""
        if self.defender_state.get("running"):
            return ok()
        self.defender_state = dict(self.defender_state, running=True)

        def work() -> None:
            result = {"checked": True, "present": False, "active": False, "excluded": None, "at": time.time()}
            try:
                if winutil.defender_present():
                    result["present"] = True
                    result["active"] = winutil.defender_active()
                    paths_ex, procs, _roots = self._defender_targets()
                    have_paths, have_procs = winutil.defender_exclusions()
                    want_paths = {p.rstrip("\\").lower() for p in paths_ex}
                    result["excluded"] = bool(want_paths) and want_paths <= have_paths
            except Exception:  # noqa: BLE001
                log.exception("Проверка Defender не удалась")
            finally:
                self.defender_state = dict(result, running=False)

        self.background("defender-check", work, "Проверка Defender не выполнена")
        return ok()

    def defender_exclude(self) -> Result:
        """Добавляет файлы Лазейки в доверенные Microsoft Defender (по явной просьбе человека)."""
        self._require_admin()
        if paths.is_portable():
            return fail("В переносном режиме (папка LazeykaData рядом с программой) Лазейка не добавляет "
                        "себя в исключения Defender: эта папка лежит в месте, куда может писать обычный "
                        "пользователь, и исключать её из проверки небезопасно. Установите Лазейку обычным "
                        "способом (в Program Files) или добавьте её папки в исключения Defender вручную.")
        paths_ex, procs, roots = self._defender_targets()
        res = winutil.defender_add_exclusions(paths_ex, procs, roots)
        if res.code != 0:
            detail = (res.err or res.out).strip() or "Defender отклонил запрос"
            return fail(f"Не удалось добавить в исключения Defender: {detail}")
        self.defender_check()
        # Если драйвер уже был удалён — восстановим пакет, чтобы обход заработал без перезапуска.
        if not self.zapret.available or self.zapret.pack is None:
            self.background("zapret-reinit", self.zapret.init, "Пакет не восстановлен")
        self.notify("success", "Лазейка добавлена в исключения Microsoft Defender — он больше не будет "
                               "удалять её файлы. Остальное Defender по-прежнему проверяет.")
        return ok(message="Готово: Лазейка в исключениях Defender.")

    # ------------------------------------------------------------ обновления

    def updates_check(self) -> Result:
        self.updates.check_async(quiet=False)
        return ok()

    def updates_install(self, key: str) -> Result:
        self.updates.install_async(str(key))
        return ok()

    def updates_skip(self, key: str) -> Result:
        self.updates.skip(str(key))
        return ok()

    def updates_rollback(self, key: str) -> Result:
        self.updates.rollback_async(str(key))
        return ok()
