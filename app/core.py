"""Ядро приложения: связывает zapret, Telegram-прокси, свой VPN, обновления и интерфейс."""
from __future__ import annotations

import itertools
import logging
import re
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Callable

from . import APP_NAME, __version__, autostart, paths, vpn, winutil
from .errors import UserError
from .log import ring, scrub, set_verbose
from .settings import Settings, import_tgwsproxy_config
from .tgproxy.manager import TgError, TgProxyManager
from .updates.manager import UpdateManager
from .zapret import diagnostics, hosts, migrate
from .zapret.guard import GUARD_ALERT, GUARD_OFF_ALERT, ConnectivityGuard
from .zapret.manager import TESTING_ERROR, ZapretError, ZapretManager
from .zapret.tester import NoDirectPath, StrategyTester

log = logging.getLogger("lazeyka.core")

Result = dict[str, Any]

VPNCLIENT_MODES = ("tun", "proxy", "local")
UI_SCALE = (0.8, 1.5)
OWN_NET_MEMORY = 600.0     # столько секунд после выключения адрес своего TUN не считается «сменой сети»
_LOG_EVERY = 60.0          # повторяющуюся ошибку своего VPN в тикере пишем в журнал не чаще раза в минуту

# Постоянные плашки (решение владельца 2026-10-18): о поломке, найденной без нажатия человека, —
# только плашка в окне, без уведомлений; исчезает сама, когда всё снова работает.
ALERT_RANK = {"error": 3, "warn": 2, "info": 1, "success": 0}
_ALERT_LOG = {"error": logging.ERROR, "warn": logging.WARNING}
WATCHDOG_ALERT = "watchdog"        # сторож: Discord или YouTube перестали открываться
# GUARD_ALERT, GUARD_OFF_ALERT — плашки страховки связи (zapret/guard.py)
ZAPRET_DOWN = "zapret-down"        # обход упал или не включился сам (снимается, когда снова работает)
VPN_CONFIRM_SCANS = 2              # о подключённом VPN — только если его видно два осмотра подряд
TG_DOWN = "tg-down"                # Telegram-прокси не включился сам (запуск, сон, смена сети)
VC_DOWN = "vpnclient-autostart"    # свой VPN не включился при запуске Лазейки
FILTER_ALERT = "zapret-filter"     # фильтр обхода не перестроился под сеть или свой VPN
COMPAT_ALERT = "compat-off"        # подключён VPN, а совместимость с VPN выключена
VPN_NOTE_WAIT = 90.0               # столько ждём фильтра под VPN, чтобы сказать «обход его не трогает»
GUARD_RECHECK = 60.0               # «пропал интернет» висит — проверочный сайт раз в минуту, без сторожа
UPDATE_CHECK_DELAY = 8.0           # проверка обновлений после запуска — когда всё уже включилось
DEFENDER_CHECK_DELAY = 3.0
SLEEP_GAP = 30.0                   # компьютер спал дольше — соединения мертвы, перезапускаем
TG_REVIVE_PAUSE = 3.0              # прокси упал сам — перезапуск через столько секунд
TG_REVIVE_EVERY = 60.0             # и не чаще: падает снова и снова — плашка «остановился»
TG_START_WAIT = 15.0               # «Подключить Telegram»: столько ждём, пока прокси включится
UPDATES_STOP_WAIT = 10.0           # выход: столько ждём, пока установка обновления доделает замену файлов
ZAPRET_RETRY = {"label": "Включить снова", "call": "zapret_start", "args": []}
TG_RETRY = {"label": "Включить снова", "call": "tg_start", "args": []}


def ok(**extra: Any) -> Result:
    return {"ok": True, **extra}


def fail(message: str, **extra: Any) -> Result:
    return {"ok": False, "error": message, **extra}


def _stopped(what: str) -> str:
    """«Discord перестал открываться», но «Discord и YouTube перестали»."""
    return "перестали открываться" if " и " in what else "перестал открываться"


def _sites_ok(results: list[dict]) -> bool | None:
    """Открываются ли Discord и YouTube по результатам проверки: True/False — по тем из них, что
    проверялись; None — ни одного нет (проверка упала с одной строкой «ошибка»)."""
    sites = [r for r in results if r.get("id") in ("discord", "youtube")]
    if not sites:
        return None
    return all(r.get("ok") for r in sites)


class VpnClientUnavailable(UserError):
    pass


# Настройки своего VPN, которые страница видит в state()["vpnclient"]["settings"] (как в эталоне).
_VC_SETTINGS = ("port", "local_auth", "socks_udp", "allow_lan", "dns_remote", "dns_direct", "fakeip", "ip_strategy",
                "ipv6", "tun_mtu", "exclude_nets", "proxy_override", "kill_switch", "on_sleep", "tls_fragment", "mux",
                "noises", "fingerprint", "latency_on_update", "sort", "deeplink", "sub_update_hours", "verbose",
                "core_auto_update")
_VC_ROUTING = ("preset", "via_zapret", "games_direct", "torrents_direct", "ip_check_direct", "direct_apps",
               "proxy_apps", "direct_sites", "proxy_sites")


def vpnclient_placeholder(settings: dict, reason: str) -> dict:
    """state()["vpnclient"], когда менеджера нет (модуля нет в сборке или он не создался): те же
    ключи, что у app/ui/mock-vpnclient-state.json, — страница рисует «недоступно» с причиной."""
    vc = dict(settings.get("vpnclient") or {})

    def core() -> dict:
        return {"installed": False, "version": None, "in_use": None, "auto_updated": False, "needed": False,
                "state": "idle", "progress": None, "message": None, "retry_at": None, "note": None}

    return {
        "available": False, "unavailable_reason": reason,
        "cores": {"sing-box": core(), "xray": core()},
        "status": "stopped", "verified": False, "error": None, "error_kind": None, "diagnosis": None,
        "mode": vc.get("mode", "tun"), "started_at": None, "listen": None, "config_servers": None,
        "exit": None, "selected": None,
        "stats": {"up": 0, "down": 0, "up_rate": 0.0, "down_rate": 0.0, "connections": 0},
        "history": [], "subscriptions": [], "groups": [], "servers": [],
        "latency": {"running": False, "done": 0, "total": 0},
        "speed": {"running": False, "server": None, "mbps": None, "at": None},
        "import": {"running": False, "message": None, "error": None, "offer": None},
        "routing": {**{k: vc.get(k) for k in _VC_ROUTING}, "bypass": "proxy", "bypass_note": None,
                    "rules": {"state": "idle", "updated_at": None, "stale": False, "items": [], "error": None}},
        "routing_profiles": [],
        # Логин и пароль локального прокси — секрет менеджера: без него — пусто.
        "settings": {**{k: vc.get(k) for k in _VC_SETTINGS}, "local_user": "", "local_password_set": False},
        "traffic": {"today_up": 0, "today_down": 0, "total_up": 0, "total_down": 0,
                    "day": time.strftime("%Y-%m-%d")},
        "memory": {"sing-box": None, "xray": None},
        "deeplink_request": None,
        "conflict": None,
    }


class Core:
    def __init__(self, autostarted: bool = False, log_dir: Path | None = None,
                 startup_alerts: list[tuple[str, str, str]] | None = None, resume_service: bool = False):
        """startup_alerts — (id, level, текст) плашек, найденных до Core (папка данных отложена и т. п.);
        resume_service — служба обхода работала из недоверенной папки и остановлена перед её разбором."""
        self.autostarted = autostarted
        self._startup_alerts = list(startup_alerts or [])
        self._resume_service = resume_service
        self.is_admin = winutil.is_admin()
        self.log_dir = log_dir or paths.logs_dir(allow_create_data=self.is_admin)
        self.settings = Settings(paths.SETTINGS_FILE, allow_create=self.is_admin)
        self.first_launch = self.settings.created
        self._notices: list[dict] = []
        self._notice_ids = itertools.count(1)
        self._dismissed: set[str] = set()
        self._lock = threading.RLock()
        self._alerts_lock = threading.RLock()
        self._alerts: dict[str, dict] = {}          # постоянные плашки по id
        self._wd_fixing: str | None = None          # сторож в режиме auto запустил подбор: что не открывалось
        self._fix_seen: float | None = None         # конец последнего «Найти и включить», уже учтённый плашкой
        self._guard_next, self._guard_busy = 0.0, False   # перепроверка связи под плашкой «пропал интернет»
        self.zapret = ZapretManager(self.settings, self.notify, self.is_admin)
        self.zapret.alert = self.alert
        self.tester = StrategyTester(self.zapret, self.notify)
        self.zapret.extra_lists = self._tg_extra_lists
        self.tg = TgProxyManager(self.settings, self.notify)
        self.tg.alert = self.alert
        self.tg.on_crash = self._tg_crashed
        self._tg_crash_at: float | None = None   # monotonic() — секунды с загрузки Windows, не с нуля
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
        self._sleep_mark: tuple[float, float] | None = None   # winutil.sleep_clock() на прошлом тике
        self._tick_log_at: dict[str, float] = {}              # раздел тикера → когда его ошибку писали в журнал
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
        self._vpn_seen: tuple[bool, int] = (False, 0)   # что видел последний осмотр и сколько осмотров подряд
        self.zapret.vpn_plan = self._vpn_plan
        self.tester.source = self._direct_source
        self._wd_fix_failed: tuple | None = None    # сторож (auto) уже подбирал при этих настройках и сети — зря
        # Страховка связи: после любого запуска winws Лазейкой — не пропал ли из-за него интернет.
        self.guard = ConnectivityGuard(self.zapret, online=self._online, alert=self.alert,
                                       busy=self._tester_busy, hint=lambda: self._vpn_conflict_hint().strip())
        self.zapret.guard_probe = self.guard.probe
        self.zapret.on_started = self.guard.started
        self._last_tray_key: tuple | None = None
        # Свой VPN (app/vpnclient). Везде — getattr(self, "vpnclient", None): тесты собирают Core.__new__.
        self.vpnclient_error: str | None = None
        self._own_key: tuple | None = None          # снимок своего VPN, под который строился фильтр обхода
        self._own_nets: dict[str, float] = {}       # подсети и имена своего TUN → когда видели
        self._handed_plan: dict | None = None       # последний план, отданный обходу
        self._reapply_lock = threading.Lock()       # перестройка фильтра обхода под сеть — одна за раз
        self._vc_dirty = False                      # свой VPN сообщил об изменении — осмотреть сеть
        self._bypass_key: tuple | None = None       # состояние обхода, переданное своему VPN
        self._vc_log_at = 0.0
        self.vpnclient = self._create_vpnclient()
        self.updates.vpnclient = self.vpnclient

    # ------------------------------------------------------------ уведомления

    def notify(self, level: str, text: str, action: dict | None = None) -> None:
        text = scrub(str(text))   # уведомление уходит в get_state(): секретов своего VPN в нём быть не должно
        ttl = 60 if level == "error" or action else 25
        with self._lock:
            self._notices.append({"id": f"n{next(self._notice_ids)}", "level": level, "text": text,
                                  "action": action, "dismissible": True, "persistent": False, "page": None,
                                  "expires": time.time() + ttl})
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
        pending = self.updates.pending_keys()
        if pending:
            # id — по тем же пунктам, что и счётчик: иначе автообновление ядра VPN «воскрешало» бы скрытую плашку.
            versions = ",".join(f"{key}:{self.updates.releases[key]['version']}" for key in pending)
            out.append({"id": f"update:{versions}", "level": "info",
                        "text": ("Доступно обновление" if len(pending) == 1 else f"Доступно обновлений: {len(pending)}") +
                                ". Скачается, только если вы нажмёте «Установить».",
                        "action": {"label": "Посмотреть", "page": "updates"}, "dismissible": True})
        restart = self.updates.app_restart_text()
        if restart:
            out.append({"id": "app-restart", "level": "info", "text": restart,
                        "action": {"label": "Перезапустить", "call": "app_restart", "args": []},
                        "dismissible": True})
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
        fixed = [dict(n, persistent=True, page=n.get("page")) for n in self._persistent_notices()]
        return fixed + self._alert_notices() + transient

    def dismiss_notice(self, notice_id: str) -> Result:
        notice_id = str(notice_id)
        if not self._dismiss_alert(notice_id):
            with self._lock:
                self._dismissed.add(notice_id)
        return ok()

    # ------------------------------------------------------------ постоянные плашки

    def _alert_book(self) -> tuple[Any, dict[str, dict]]:
        """(блокировка, плашки по id). Лениво: тесты собирают Core.__new__."""
        book = getattr(self, "_alerts", None)
        if book is None:
            self._alerts_lock = threading.RLock()
            book = self._alerts = {}
        return self._alerts_lock, book

    def set_alert(self, alert_id: str, level: str, text: str, action: dict | None = None,
                  page: str | None = None) -> None:
        """Плашка о поломке, найденной без нажатия человека: висит, пока проблема есть, и снимается
        clear_alert. Ни уведомления в окне, ни уведомления Windows. Повтор с тем же id обновляет
        текст и не показывает снова плашку, скрытую крестиком, — до clear_alert.

        page — на какой странице показать её ещё и сверху (на главной видны все)."""
        alert_id = str(alert_id)
        level = level if level in ALERT_RANK else "warn"
        text = scrub(str(text))   # плашка уходит в get_state(): секретов своего VPN в ней быть не должно
        lock, book = self._alert_book()
        with lock:
            entry = book.get(alert_id)
            changed = entry is None or (entry["level"], entry["text"]) != (level, text)
            if entry is None:
                entry = book[alert_id] = {"id": alert_id, "since": time.time(), "dismissed": False}
            entry.update(level=level, text=text, action=dict(action) if action else None,
                         page=str(page) if page else None)
        if changed:   # сторож повторяет одно и то же раз в 10 минут — в журнал только перемены
            log.log(_ALERT_LOG.get(level, logging.INFO), "Плашка: %s", text)

    def clear_alert(self, alert_id: str) -> None:
        """Проблема прошла: плашка исчезает, а «скрыто крестиком» забывается — вернётся проблема,
        вернётся и плашка."""
        lock, book = self._alert_book()
        with lock:
            entry = book.pop(str(alert_id), None)
        if entry is not None:
            log.info("Плашка снята: %s", entry["text"])

    def alert(self, alert_id: str, level: str | None, text: str | None = None, action: dict | None = None,
              page: str | None = None) -> None:
        """Колбэк плашек для менеджеров (свой VPN, обход): level=None — снять."""
        if level is None:
            self.clear_alert(alert_id)
        else:
            self.set_alert(alert_id, level, text or "", action, page)

    def has_alert(self, alert_id: str) -> bool:
        lock, book = self._alert_book()
        with lock:
            return str(alert_id) in book

    def _dismiss_alert(self, alert_id: str) -> bool:
        lock, book = self._alert_book()
        with lock:
            entry = book.get(alert_id)
            if entry is None:
                return False
            entry["dismissed"] = True
        return True

    def _alert_notices(self) -> list[dict]:
        """Видимые плашки для notices: серьёзные первыми, при равенстве — давние."""
        lock, book = self._alert_book()
        with lock:
            entries = sorted((dict(e) for e in book.values() if not e["dismissed"]),
                             key=lambda e: (-ALERT_RANK[e["level"]], e["since"]))
        return [{"id": e["id"], "level": e["level"], "text": e["text"], "action": e["action"], "page": e["page"],
                 "dismissible": True, "persistent": True} for e in entries]

    def active_alerts(self) -> list[dict]:
        """Видимые плашки warn и error — цвет и подсказка значка в трее. Скрытая крестиком в счёт не
        идёт: человек её видел и попросил не напоминать."""
        return [n for n in self._alert_notices() if n["level"] in ("warn", "error")]

    def _alerting(self, alert_id: str, on_error: str, fn: Callable[[], Any], *, page: str | None = None,
                  action: dict | None = None, clear: bool = True,
                  fail: Callable[[str], None] | None = None) -> Callable[[], None]:
        """Фоновая задача, которую Лазейка начала сама (сон, смена сети): ошибка — плашкой, а не
        уведомлением; удача снимает плашку (clear=False — снимет кто-то другой, по состоянию).
        fail(подробность) ставит плашку сам — когда от состояния после ошибки зависит, какую."""
        def report(detail: str) -> None:
            if fail is not None:
                fail(detail)
            else:
                self.set_alert(alert_id, "error", f"{on_error}: {detail}", action, page)

        def run() -> None:
            try:
                fn()
            except (UserError, PermissionError, ValueError, RuntimeError, OSError) as exc:
                report(str(exc))
                return
            except Exception as exc:  # noqa: BLE001
                log.exception("%s", on_error)
                report(repr(exc))
                return
            if clear:
                self.clear_alert(alert_id)
        return run

    def _filter_failed(self, on_error: str, detail: str, level: str = "error") -> None:
        """Фильтр обхода не перестроился сам (смена сети, свой VPN). Если обход при этом упал — winws
        не поднялся с новым фильтром, — это уже «обход не работает»: плашка о падении с «Включить
        снова». Плашку о фильтре тикер снял бы как «обход выключен», и обход лежал бы без плашки."""
        z = self.zapret
        if z.status == "error" or (z.status == "stopped" and self.settings.get("zapret", "was_running")):
            self.clear_alert(FILTER_ALERT)
            self.set_alert(ZAPRET_DOWN, "error", f"{on_error} и сейчас не работает: {detail}",
                           action=ZAPRET_RETRY)
        else:
            self.set_alert(FILTER_ALERT, level, f"{on_error}: {detail}", page="zapret")

    def _reconcile_alerts(self) -> None:
        """Тикер: снять плашки, чья поломка прошла, — только чтение состояний, без сети."""
        lock, book = self._alert_book()
        with lock:
            if not book:
                return
        z, tester = self.zapret, self.tester
        busy = bool(z.paused_for_test or getattr(tester, "running", False) or getattr(tester, "fix_running", False))
        down = not busy and z.status in ("stopped", "error")   # обход выключили или он упал — сторожить нечего
        if z.status == "running":
            self.clear_alert(ZAPRET_DOWN)
            self.clear_alert(GUARD_OFF_ALERT)
        elif not busy and z.status == "stopped" and not self.settings.get("zapret", "was_running"):
            self.clear_alert(ZAPRET_DOWN)   # выключил человек — например, пока перестраивался фильтр
        if down or self.settings.get("zapret", "watchdog") == "off":
            self.clear_alert(WATCHDOG_ALERT)
            self._wd_fixing = None
        if down:
            self.clear_alert(GUARD_ALERT)
            self.clear_alert(FILTER_ALERT)
        elif not busy and z.status == "running" and self.has_alert(GUARD_ALERT):
            self._recheck_guard()
        if not busy and z.status == "stopped":
            self.clear_alert("zapret-vpnfilter")
        snap = getattr(self, "vpn_snapshot", None)
        if down or self.settings.get("vpn", "compat") or not (snap is not None and snap.foreign_active):
            self.clear_alert(COMPAT_ALERT)
        if getattr(self.tg, "status", None) == "running":
            self.clear_alert(TG_DOWN)
        if self._vpnclient_status() in ("running", "starting"):
            self.clear_alert(VC_DOWN)
        self._reconcile_fix()
        self._reconcile_check()

    def _reconcile_fix(self) -> None:
        """«Найти и включить» закончился: удача снимает плашку сторожа, неудача подбора, запущенного
        самим сторожем (режим auto), меняет текст «подбираем…» на итог."""
        tester = self.tester
        fix = getattr(tester, "fix_state", None) or {}
        finished = fix.get("finished_at")
        if getattr(tester, "fix_running", False) or not finished or finished == getattr(self, "_fix_seen", None):
            return
        self._fix_seen = finished
        lock, book = self._alert_book()
        with lock:
            since = (book.get(WATCHDOG_ALERT) or {}).get("since")
        what, self._wd_fixing = getattr(self, "_wd_fixing", None), None
        if fix.get("stage") == "done" and fix.get("results"):
            # Проверка «Найти и включить» — свежая проверка обхода: свой VPN узнает, что обход снова работает.
            self.tester.check_state = {"running": False, "at": finished, "results": list(fix["results"]),
                                       "direct": bool(fix.get("direct"))}
            self._check_fp = self._zapret_fingerprint()
        if since is None or finished < since:
            return                  # подбор закончился раньше, чем сторож заметил поломку, — не про неё
        if fix.get("stage") == "done":
            self.clear_alert(WATCHDOG_ALERT)
        elif what and self.has_alert(WATCHDOG_ALERT):
            # Сторож сам не повторяет подбор, пока не сменятся стратегия, фильтры, пакет или сеть.
            self._wd_fix_failed = self._autofix_key()
            reason = str(fix.get("message") or "Подходящей стратегии не нашлось.")
            self.set_alert(WATCHDOG_ALERT, "warn", f"{what} {_stopped(what)}, а подобрать стратегию не вышло. "
                                                   f"{reason}",
                           action={"label": "Найти и включить", "call": "zapret_fix", "args": []}, page="zapret")

    def _recheck_guard(self) -> None:
        """Плашка «пропал интернет» висит, а обход работает — раз в минуту фоном пробуем проверочный
        сайт так же, как страховка при включении. От сторожа не зависит: его могут выключить, а снять
        плашку, когда связь вернулась, всё равно нужно."""
        now = time.monotonic()
        if getattr(self, "_guard_busy", False) or now < getattr(self, "_guard_next", 0.0):
            return
        self._guard_busy, self._guard_next = True, now + GUARD_RECHECK

        def check() -> None:
            try:
                if self._online():
                    self.clear_alert(GUARD_ALERT)
            except Exception:  # noqa: BLE001 — не вышло проверить: плашка остаётся, повтор через минуту
                log.debug("Проверочный сайт не проверен", exc_info=True)
            finally:
                self._guard_busy = False

        threading.Thread(target=check, name="guard-recheck", daemon=True).start()

    def _reconcile_check(self) -> None:
        """Удачная проверка после плашки (сторожа или по кнопке «Проверить»): всё открылось — снять
        плашку сторожа; открылось хоть что-то — интернет есть, снять «пропал интернет»."""
        lock, book = self._alert_book()
        with lock:
            since = {key: (book.get(key) or {}).get("since") for key in (WATCHDOG_ALERT, GUARD_ALERT)}
        if since[WATCHDOG_ALERT] is None and since[GUARD_ALERT] is None:
            return
        check = self._fresh_check()
        results = check.get("results") or []
        if check.get("running") or not results:
            return
        at = check.get("at") or 0
        if since[WATCHDOG_ALERT] is not None and at > since[WATCHDOG_ALERT] and _sites_ok(results):
            self.clear_alert(WATCHDOG_ALERT)
        if since[GUARD_ALERT] is not None and at > since[GUARD_ALERT] and any(r.get("ok") for r in results):
            self.clear_alert(GUARD_ALERT)

    def _bypass_ok(self) -> bool | None:
        """Работает ли обход по последней проверке (сторож, «Проверить», «Найти и включить»), сделанной
        при нынешних стратегии, фильтрах, процессе winws и сети. Устарела, не было или упала — None."""
        check = self._fresh_check()
        if check.get("running"):
            return None
        return _sites_ok(check.get("results") or [])

    def _alerts_key(self) -> tuple:
        return tuple((n["id"], n["level"], n["text"]) for n in self.active_alerts())

    # ------------------------------------------------------------ запуск

    def startup(self) -> None:
        log.info("%s %s, администратор: %s, данные: %s", APP_NAME, __version__, self.is_admin, paths.DATA)
        for alert_id, level, text in getattr(self, "_startup_alerts", []):
            self.set_alert(alert_id, level, text)
        if self.settings.recovered:
            self.set_alert("settings-broken", "warn", self.settings.recovered)
        from .updates.manager import settle_app_files
        try:
            settle_app_files(self.settings)   # прежняя версия — в backups, рядом с exe ничего лишнего
        except Exception:  # noqa: BLE001 — уборка копий exe не должна мешать запуску
            log.exception("Копии прежней версии Лазейки не разобраны")
        try:
            self.tg.load_core()               # до переноса настроек TG WS Proxy: их проверяет ядро
        except Exception as exc:  # noqa: BLE001
            log.exception("Ядро Telegram-прокси не загрузилось")
            self.set_alert("tg-core", "error", f"Ядро Telegram-прокси не загрузилось: {exc}", page="telegram")
        if self.first_launch and self.is_admin:
            self._first_launch_import()
        self.zapret.init()
        vc = getattr(self, "vpnclient", None)
        if vc is not None:
            try:
                vc.init()   # секреты профилей — в фильтр журнала, системный прокси после аварии
            except Exception as exc:  # noqa: BLE001 — обход и Telegram работают и без своего VPN
                log.exception("Свой VPN не подготовлен")
                self.set_alert("vpnclient-init", "error", f"Свой VPN не подготовлен: {exc}", page="vpnclient")
        set_verbose(self.settings.get("tg", "verbose"))
        threading.Thread(target=self._autostart_components, name="autostart-components", daemon=True).start()
        threading.Thread(target=self._ticker, name="ticker", daemon=True).start()
        if self.settings.get("updates", "check"):
            self._later(UPDATE_CHECK_DELAY, lambda: self.updates.check_async(quiet=True))
        if self.is_admin and self.zapret.av_removal_seen:
            # Файлы уже удаляли — выясним про Defender, чтобы предложить исключение.
            self._later(DEFENDER_CHECK_DELAY, self.defender_check)
        self._startup_path_alerts()
        if self.is_admin and self.settings.get("startup", "autostart"):
            problem = autostart.refusal()
            if problem:
                self.set_alert("autostart", "warn", problem,
                               action={"label": "Выключить автозапуск", "call": "save_settings",
                                       "args": [{"autostart": False}]})
            try:
                autostart.sync(guard=self.updates.replacing)   # копию в Program Files выход дожидается
            except Exception as exc:  # noqa: BLE001
                log.warning("Задание автозапуска не обновлено: %s", exc)

    def _later(self, delay: float, fn: Callable[[], Any]) -> None:
        """Отложенный запуск при старте: фоновым потоком (выход его не ждёт) и не после выхода."""
        def run() -> None:
            if not self._stop.is_set():
                fn()
        timer = threading.Timer(delay, run)
        timer.daemon = True
        timer.start()

    def _startup_path_alerts(self) -> None:
        """Переносной режим: путь к папке данных выбирает человек, а кириллицу и пробелы winws не любит."""
        data = paths.DATA
        if paths.is_portable() and (paths.has_non_ascii(data) or " " in str(data)):
            self.set_alert("data-path", "warn",
                           f"В пути к папке данных {data} есть кириллица или пробелы — обход (winws) может не "
                           "запуститься. Перенесите Лазейку в папку с латинским путём без пробелов, например "
                           r"C:\Lazeyka.", page="zapret")

    def _first_launch_import(self) -> None:
        # Под чужой учёткой (при запуске ввели пароль администратора) %APPDATA% — её, а не того, кто за
        # компьютером: чужой конфиг переносить незачем.
        if winutil.other_account():
            log.info("Настройки TG WS Proxy не переносятся: Лазейка запущена от имени другой учётной записи")
        elif import_tgwsproxy_config(self.settings, self._validate_tg):
            self.notify("success", "Перенесены настройки TG WS Proxy — ссылка в Telegram остаётся прежней.")
        try:
            root = migrate.find_original()
            if root is not None:
                done = migrate.import_from(root, self.settings, paths.USER_LISTS_DIR)
                self.notify("success", f"Найден ваш zapret в {root}. Перенесено: {', '.join(done)}.")
        except Exception as exc:  # noqa: BLE001
            log.warning("Перенос настроек zapret не удался: %r", exc)

    def _validate_tg(self, values: dict) -> tuple[dict, dict]:
        try:
            return self.tg.validate(values)
        except TgError as exc:   # ядро не загрузилось: формат DC и доменов проверить нечем
            log.warning("Настройки TG WS Proxy не проверены: %s", exc)
            return {}, {"core": str(exc)}

    def _autostart_components(self) -> None:
        """Каждый компонент — сам по себе: сбой одного (даже непредвиденный) не мешает остальным."""
        first = self.settings.get("first_run")
        start = self.settings.get("startup")
        if start["tg"] and (first or self.settings.get("tg", "was_running")):
            try:
                self.tg.start()
            except Exception as exc:  # noqa: BLE001 — включался сам: плашка, а не уведомление
                if not isinstance(exc, UserError):
                    log.exception("Telegram-прокси не включился при запуске")
                self.set_alert(TG_DOWN, "error", f"Telegram-прокси не включился при запуске Лазейки: {exc}",
                               action=TG_RETRY)
        if (self.zapret.available and start["zapret"] and not first
                and self.settings.get("zapret", "was_running")):
            try:
                if self.zapret.mode == "app":
                    self.zapret.start()   # страховку связи взводит сам запуск (и при входе в Windows)
            except Exception as exc:  # noqa: BLE001
                if not isinstance(exc, (ZapretError, UserError)):
                    log.exception("Обход не включился при запуске")
                self.set_alert(ZAPRET_DOWN, "error", f"Обход не включился при запуске Лазейки: {exc}",
                               action=ZAPRET_RETRY)
        if getattr(self, "_resume_service", False) and self.zapret.available and self.zapret.mode == "service":
            # Служба работала из недоверенной папки и остановлена перед её разбором (security.stop_own_service):
            # пакет поставлен заново — служба запускается снова уже из него, как была до разбора.
            try:
                self.zapret.start()
            except Exception as exc:  # noqa: BLE001
                if not isinstance(exc, (ZapretError, UserError)):
                    log.exception("Служба обхода не запустилась после переустановки пакета")
                self.set_alert(ZAPRET_DOWN, "error", f"Служба обхода не запустилась после переустановки пакета: {exc}",
                               action=ZAPRET_RETRY)
        self._guard_running_service()
        self._autostart_vpnclient(first, start)
        self._status_changed()

    def _guard_running_service(self) -> None:
        """Служба Windows запустила winws вместе с системой, без Лазейки: страховка проверяет связь и её —
        иначе стратегия, рвущая интернет, рвала бы его при каждом старте Windows без присмотра."""
        z, guard = self.zapret, getattr(self, "guard", None)
        if guard is None or not self.is_admin or z.mode != "service":
            return
        try:
            running = z.running()
        except Exception:  # noqa: BLE001 — состояние службы не прочитано: проверять нечего
            log.debug("Состояние службы обхода не прочитано", exc_info=True)
            return
        if running:
            z.status = "running"
            guard.started(None)

    def _autostart_vpnclient(self, first: bool, start: dict) -> None:
        """Свой VPN — после обхода (фильтр zapret уже собран) и не в первый запуск. Рядом с чужим
        VPN сам не включается: два туннеля ломают маршруты — решает человек в окне."""
        vc = getattr(self, "vpnclient", None)
        if (vc is None or first or not start.get("vpnclient")
                or not self.settings.get("vpnclient", "was_running")):
            return
        try:
            conflict = self._own_conflict(self._vpn_scan())
            if conflict is not None:
                self.set_alert(VC_DOWN, "warn", f"Свой VPN не включён при запуске: {conflict['text']}",
                               action={"label": "Открыть VPN", "page": "vpnclient"})
                return
            self._check_vc_result(vc.start(quiet=True))
        except UserError as exc:
            self.set_alert(VC_DOWN, "error", f"Свой VPN не включился при запуске Лазейки: {exc}",
                           action={"label": "Открыть VPN", "page": "vpnclient"})
        except Exception as exc:  # noqa: BLE001
            log.exception("Свой VPN не включился при запуске")
            self.set_alert(VC_DOWN, "error", f"Свой VPN не включился при запуске Лазейки: {exc}",
                           action={"label": "Открыть VPN", "page": "vpnclient"})

    def _ticker(self) -> None:
        tick = 0
        while not self._stop.wait(1.0):
            tick += 1
            self._tick_once(tick)

    def _tick_once(self, tick: int) -> None:
        """Один тик. Каждый раздел — сам по себе: исключение в одном (например, чужое ядро прокси без
        нужного счётчика) не останавливает сторожа, плашки и свой VPN."""
        step = self._tick_step
        step("сон", self._check_resume)
        step("прокси", self.tg.sample)
        step("обход", self.zapret.refresh_status)
        step("свой VPN", self._vpnclient_tick)
        if tick % 5 == 1:
            step("конфликты", self._refresh_conflicts)
            step("TG WS Proxy", self._refresh_original_tgws)
            step("клиент Telegram", self.tg.refresh_client)
            step("подбор", self._refresh_best)
            step("сеть", self._check_network)
        step("сторож", self._watchdog_tick)
        step("маршрут обхода", self._sync_bypass)
        step("сеть своего VPN", self._watch_own_vpn)
        step("плашки", self._reconcile_alerts)
        step("уведомление о VPN", self._vpn_note_tick)
        # Подсказка значка показывает скорость своего VPN — обновляем её и без смены статуса.
        step("значок", lambda: self._status_changed(force=tick % 5 == 0 and self._vpnclient_status() == "running"))

    def _tick_step(self, name: str, fn: Callable[[], Any]) -> None:
        try:
            fn()
        except Exception:  # noqa: BLE001
            # Раз в секунду одно и то же — в журнал не чаще раза в минуту на раздел.
            book = getattr(self, "_tick_log_at", None)
            if book is None:
                book = self._tick_log_at = {}
            now = time.monotonic()
            if now - book.get(name, -_LOG_EVERY) >= _LOG_EVERY:
                book[name] = now
                log.exception("Ошибка фонового обновления состояния (%s)", name)

    def _refresh_conflicts(self) -> None:
        self._conflicts = self.zapret.conflicts() if self.is_admin else []

    def _refresh_original_tgws(self) -> None:
        self._original_tgws = self.tg.original_running()

    def _refresh_best(self) -> None:
        self._best_id, self._scores, self._best_at = self.tester.best_known()

    # ------------------------------------------------------------ свой VPN: связка

    def _create_vpnclient(self):
        """Менеджер своего VPN; None — модуля нет в этой сборке или он не создался (обход и
        Telegram при этом работают, страница VPN показывает причину)."""
        try:
            from .vpnclient.manager import VpnClientManager
        except ImportError as exc:
            self.vpnclient_error = f"Модуль своего VPN не загрузился: {exc}"
            log.warning("Свой VPN недоступен: %r", exc)
            return None
        try:
            return VpnClientManager(self.settings, self.notify, self.is_admin,
                                    zapret_view=self._zapret_view, on_change=self._vpnclient_changed,
                                    before_core=self._vpnclient_before_core, alert=self.alert)
        except Exception as exc:  # noqa: BLE001
            log.exception("Менеджер своего VPN не создан")
            self.vpnclient_error = f"Свой VPN не запустился: {exc}"
            return None

    def _vc(self):
        vc = getattr(self, "vpnclient", None)
        if vc is None:
            raise VpnClientUnavailable(getattr(self, "vpnclient_error", None)
                                       or "Свой VPN недоступен в этой сборке Лазейки")
        return vc

    def _vc_log(self, message: str) -> None:
        """Повторяющаяся ошибка (тикер, снимок раз в секунду) — в журнал не чаще раза в минуту."""
        now = time.monotonic()
        if now - getattr(self, "_vc_log_at", 0.0) >= _LOG_EVERY:
            self._vc_log_at = now
            log.exception(message)

    def _vpnclient_changed(self, *_args: Any, **_kwargs: Any) -> None:
        """Сигнал менеджера VPN (старт, стоп, смена сервера). Только флаг: менеджер может звать
        это под своей блокировкой — осмотр сети и значок сделает тикер."""
        self._vc_dirty = True

    def _vpnclient_before_core(self) -> None:
        """Менеджер собрал план (адреса серверов известны), ядро ещё не запущено: перестроить фильтр
        обхода сейчас и дождаться — иначе обход задел бы первое соединение с сервером (план, 5.3).
        Зовётся из очереди менеджера без его блокировок; идущую фоном перестройку не дублирует."""
        lock = self._reapply_guard()
        if not lock.acquire(timeout=60):
            log.warning("Фильтр обхода перестраивается дольше минуты — свой VPN запускается, не дожидаясь")
            return
        try:
            snap = self._vpn_scan()
            z = self.zapret
            if (snap is None or not self.is_admin or z.status != "running" or z.paused_for_test
                    or self.tester.running or self.tester.fix_running):
                return
            if self._filter_stale(snap):
                z.reapply_for_network()
                self.clear_alert(FILTER_ALERT)
        except UserError as exc:   # часть включения своего VPN, но нашла её Лазейка сама — плашка
            self._filter_failed("Обход не перестроился под свой VPN", str(exc), "warn")
        finally:
            lock.release()

    def _vpnclient_status(self) -> str | None:
        vc = getattr(self, "vpnclient", None)
        return getattr(vc, "status", None) if vc is not None else None

    def _vpnclient_tick(self) -> None:
        vc = getattr(self, "vpnclient", None)
        if vc is None:
            return
        try:
            vc.tick()
        except Exception:  # noqa: BLE001 — сбой своего VPN не останавливает тикер обхода и прокси
            self._vc_log("Ошибка своего VPN в тикере")

    def _own_vpn(self) -> vpn.OwnVpn | None:
        """Снимок своего VPN для «Совместимости с VPN»; запоминает подсеть и имя своего TUN."""
        vc = getattr(self, "vpnclient", None)
        if vc is None:
            return None
        try:
            own = vc.own()
        except Exception:  # noqa: BLE001
            self._vc_log("Свой VPN не сообщил своё состояние")
            return None
        if own is not None:
            memory = getattr(self, "_own_nets", None)
            if memory is None:
                memory = self._own_nets = {}
            now = time.monotonic()
            for item in (own.tun_net, own.adapter_name):
                if item:
                    memory[item] = now
        return own

    def _own_exclusions(self) -> tuple[set[str], set[str]]:
        """(подсети, имена) своего TUN — нынешнего и недавних: адаптер Wintun бывает виден ещё
        несколько секунд после выключения ядра."""
        own = self._own_vpn()
        now = time.monotonic()
        memory = getattr(self, "_own_nets", {}) or {}
        recent = {item for item, at in memory.items() if now - at < OWN_NET_MEMORY}
        for item in [k for k, at in memory.items() if now - at >= OWN_NET_MEMORY]:
            memory.pop(item, None)
        if own is not None:
            recent |= {x for x in (own.tun_net, own.adapter_name) if x}
        nets = {x for x in recent if "/" in x}
        return nets, recent - nets

    def _watch_own_vpn(self) -> None:
        """Свой VPN включился, выключился или сменил сервер — осмотреть сеть фоном и, если нужно,
        один раз перестроить фильтр обхода (без петли: план сравнивается с применённым)."""
        own = self._own_vpn()
        key = None if own is None else (tuple(sorted(own.servers)), own.adapter_name, own.tun_net, own.proxy)
        changed = key != getattr(self, "_own_key", None)
        now = time.monotonic()
        # Сигнал без смены снимка (менеджер сообщает и о мелочах) — осмотр не чаще раза в 5 с.
        if not changed and not (getattr(self, "_vc_dirty", False)
                                and now - getattr(self, "_own_watch_at", 0.0) >= 5.0):
            return
        self._own_key, self._vc_dirty, self._own_watch_at = key, False, now
        on_error = "Обход не перестроился под свой VPN"
        # Удачный осмотр ещё не значит, что фильтр собрался: плашку снимет перестройка.
        self.background("vpn-own", self._alerting(FILTER_ALERT, on_error, lambda: self._vpn_watch(announce=False),
                                                  page="zapret", clear=False), on_error)

    def _zapret_view(self):
        """Что менеджеру своего VPN нужно знать об обходе: «через обход» строится по профилям winws
        активной стратегии, селектор — по тому, работает ли обход и прошла ли его проверка."""
        from .vpnclient.manager import ZapretView
        z = self.zapret
        args: list[str] = []
        pack_dir = z.pack.path if z.pack else None
        ipset_mode = None
        if z.pack is not None:
            try:
                args = z.build_args(z.strategy())
            except Exception:  # noqa: BLE001 — стратегия не разобралась: «через обход» без профилей
                log.debug("Аргументы стратегии для своего VPN не получены", exc_info=True)
            try:
                ipset_mode = z.ipset_info().get("mode")
            except Exception:  # noqa: BLE001
                log.debug("Режим IPSet для своего VPN не получен", exc_info=True)
        # Итог проверки — только свежий: сменились стратегия, winws или сеть — прежний итог не про них.
        return ZapretView(running=z.status == "running", paused_for_test=bool(z.paused_for_test),
                          last_ok=self._bypass_ok(), strategy_args=args,
                          pack_dir=pack_dir, ipset_mode=ipset_mode)

    def _sync_bypass(self, force: bool = False) -> None:
        """Сменились статус обхода, результат сторожа, пауза подбора или стратегия — сообщить
        своему VPN (селектор «через обход»). Переходные «запускается/останавливается» не
        передаём: быстрый перезапуск winws не должен дёргать селектор."""
        vc = getattr(self, "vpnclient", None)
        if vc is None:
            return
        z = self.zapret
        if z.status in ("starting", "stopping") and not force:
            return
        cfg = self.settings.get("zapret")
        gf = cfg["game_filter"]
        key = (z.status, bool(z.paused_for_test), self._bypass_ok(), cfg["strategy"],
               gf["mode"], gf["tcp"], gf["udp"], cfg["ipset_mode"], z.pack.version if z.pack else None)
        if key == getattr(self, "_bypass_key", None) and not force:
            return
        try:
            vc.set_bypass(self._zapret_view())
        except Exception:  # noqa: BLE001 — ключ не запоминаем: следующий тик передаст снова
            self._vc_log("Своему VPN не передано состояние обхода")
            return
        self._bypass_key = key

    @staticmethod
    def _check_vc_result(result: Any) -> Any:
        """Действие менеджера вернуло {ok: false} вместо исключения — это тоже ошибка."""
        if isinstance(result, dict) and result.get("ok") is False:
            raise UserError(str(result.get("error") or "не получилось"))
        return result

    def _vc_background(self, name: str, fn: Callable[[], Any], on_error: str) -> Result:
        self.background(name, lambda: self._check_vc_result(fn()), on_error)
        return ok()

    @staticmethod
    def _vc_result(value: Any, key: str | None = None) -> Result:
        """Ответ менеджера → ответ странице: словарь — как есть, строка — сообщение, список — key."""
        if isinstance(value, dict):
            return value if "ok" in value else ok(**value)
        if value is None or value is True:
            return ok()
        if value is False:
            return fail("Не получилось")
        return ok(**{key or ("message" if isinstance(value, str) else "result"): value})

    def _vpnclient_snapshot(self, s: dict) -> dict:
        vc = getattr(self, "vpnclient", None)
        if vc is None:
            return vpnclient_placeholder(s, getattr(self, "vpnclient_error", None)
                                         or "Свой VPN недоступен в этой сборке Лазейки")
        try:
            snap = vc.snapshot()
        except Exception as exc:  # noqa: BLE001 — страница опрашивает раз в секунду
            self._vc_log("Снимок своего VPN не построен")
            return vpnclient_placeholder(s, f"Свой VPN не ответил: {exc}")
        if isinstance(snap, dict) and not snap.get("conflict"):
            # Чужой VPN видит Core («Совместимость с VPN»): плашка на странице — до нажатия «Включить».
            conflict = self._own_conflict(getattr(self, "vpn_snapshot", None))
            if conflict is not None:
                snap = dict(snap, conflict=conflict)
        return snap

    # ------------------------------------------------------------ сон, сеть, сторож

    def _check_resume(self) -> None:
        """Компьютер спал дольше SLEEP_GAP — соединения мертвы, перезапускаем. Сон меряется часами Windows
        с ним и без него (winutil.sleep_clock): перевод часов и подвисший на полминуты тикер — не сон."""
        now = winutil.sleep_clock()
        mark = getattr(self, "_sleep_mark", None)
        self._sleep_mark = now
        if mark is None:
            return
        slept = (now[0] - mark[0]) - (now[1] - mark[1])
        if slept < SLEEP_GAP:
            return
        log.info("Компьютер выходил из сна (спал %.0f с) — перезапускаю обход и прокси", slept)
        self._after_sleep()

    def _after_sleep(self) -> None:
        vc = getattr(self, "vpnclient", None)

        def work() -> None:
            if vc is not None:
                # Свой VPN не перезапускаем: новый TUN дал бы «смену сети» и перезапуск прокси.
                # Менеджер сбросит соединения и заново проверит выход (или выключит VPN по настройке).
                try:
                    vc.on_resume()
                except Exception:  # noqa: BLE001
                    log.exception("Свой VPN не обработал выход из сна")
            # Перезапуски после сна Лазейка делает сама: неудача — плашка, а не уведомление.
            if self.tg.status == "running":
                self._alerting(TG_DOWN, "Telegram-прокси не перезапустился после сна", self.tg.restart,
                               action=TG_RETRY, clear=False)()
            if self.zapret.mode == "app" and self.zapret.status == "running" and not self.zapret.paused_for_test:
                self._alerting(ZAPRET_DOWN, "Обход не перезапустился после сна", self.zapret.restart,
                               action=ZAPRET_RETRY, clear=False)()
            self._wd_next = time.time() + 30   # и перепроверить, когда сеть поднимется

        self.background("resume", work, "Перезапуск после сна не удался")

    def _check_network(self) -> None:
        """Сменилась сеть (другой Wi-Fi, кабель, VPN) — обновить прокси и перепроверить обход.
        Адрес своего TUN в отпечаток не входит: иначе каждое включение своего VPN было бы «сменой сети»."""
        import psutil
        own_nets, own_names = self._own_exclusions()
        addrs = set()
        for name, items in psutil.net_if_addrs().items():
            if name in own_names:
                continue
            for a in items:
                if (a.family == 2 and not a.address.startswith(("127.", "169.254."))
                        and not any(vpn.in_network(a.address, net) for net in own_nets)):
                    addrs.add((name, a.address))
        fp = frozenset(addrs)
        first = self._net_fp is None
        changed = not first and fp != self._net_fp
        if changed:
            log.info("Сеть изменилась — перезапускаю Telegram-прокси и перепроверю обход")
            if self.tg.status == "running":
                on_error = "Telegram-прокси не перезапустился после смены сети"
                self.background("net-change", self._alerting(TG_DOWN, on_error, self.tg.restart, action=TG_RETRY,
                                                             clear=False), on_error)
            self._wd_next = time.time() + 20
            vc = getattr(self, "vpnclient", None)
            if vc is not None:
                on_error = "Свой VPN не перепроверил подключение после смены сети"
                self.background("vpn-net-change", self._alerting("vpnclient-net", on_error, vc.on_network_change,
                                                                 page="vpnclient"), on_error)
        self._net_fp = fp
        if changed and getattr(self, "guard", None) is not None:
            self.guard.network_changed()   # обход включали без связи — проверить его теперь
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
            try:
                bind = self._direct_source()
            except NoDirectPath:
                # Туннель в интернет есть, а пути мимо него нет: весь трафик — через VPN, обход не участвует.
                self.watchdog_state.update(last_at=time.time(), last_ok=None, failing=[], vpn=True)
                self._wd_fails = 0
                self.clear_alert(WATCHDOG_ALERT)
                return
            watch = {"discord", "youtube"}
            snap = self.vpn_snapshot
            if snap is not None and snap.foreign_active:
                # Что идёт через VPN, обход не касается — и тревожить из-за него незачем.
                routes = vpn.probe_routes(snap)
                self.vpn_routes = dict(routes, running=False)
                watch = {i["id"] for i in routes["items"] if i["id"] in watch and i["via"] != "vpn"}
                if not watch:
                    self.watchdog_state.update(last_at=time.time(), last_ok=None, failing=[], vpn=True)
                    self._wd_fails = 0
                    self.clear_alert(WATCHDOG_ALERT)
                    return
            elif snap is not None and snap.own_active and not self.settings.get("vpnclient", "via_zapret"):
                # Свой VPN ведёт Discord и YouTube через сервер — обход для них сейчас не нужен.
                # С «через обход» проверяем обход напрямую (bind), а не по маршрутам: иначе
                # переключение селектора на сервер выглядело бы как «обход снова в порядке».
                self.watchdog_state.update(last_at=time.time(), last_ok=None, failing=[], vpn=True)
                self._wd_fails = 0
                self.clear_alert(WATCHDOG_ALERT)
                return
            if not control_ok(bind=bind):
                log.info("Сторож: нет интернета — проверку пропускаю")
                # Прежний итог больше не про сейчас: свой VPN не должен опираться на него.
                self.watchdog_state.update(last_at=time.time(), last_ok=None, failing=[])
                return
            self.clear_alert(GUARD_ALERT)       # проверочный сайт открывается — интернет есть
            fp = self._zapret_fingerprint()
            results = [r for r in quick_check(bind=bind) if r["id"] in watch]
            failing = [r["label"] for r in results if not r["ok"]]
            self.watchdog_state.update(last_at=time.time(), last_ok=not failing, failing=failing, vpn=False)
            self.tester.check_state = {"running": False, "at": time.time(), "results": results,
                                       "direct": bool(bind)}
            self._check_fp = fp
            self._wd_fails = self._wd_fails + 1 if failing else 0
            if not failing:
                self.clear_alert(WATCHDOG_ALERT)
            if self._wd_fails == 1 and failing:
                self._wd_next = time.time() + 60   # перепроверить через минуту: вдруг случайный сбой
            if self._wd_fails < 2:
                return
            self._wd_fails = 0
            # Решение владельца: не уведомление раз в 10 минут, а плашка, пока не откроется снова.
            what = " и ".join(failing)
            repeat = (getattr(self, "_wd_fix_failed", None) == self._autofix_key()
                      and self.has_alert(WATCHDOG_ALERT))
            if mode == "auto" and repeat:
                # Подбор при этих настройках и этой сети уже не помог: каждые 10 минут рвать обход новым
                # перебором незачем — плашка с итогом висит, повтор — после перемен или по кнопке.
                log.info("Сторож: %s по-прежнему не открывается, подбор при тех же условиях не повторяю", what)
            elif mode == "auto":
                self.set_alert(WATCHDOG_ALERT, "warn", f"{what} {_stopped(what)} — подбираем рабочую стратегию.",
                               page="zapret")
                self._wd_fixing = what
                self.tester.start_fix()
            else:
                self.set_alert(WATCHDOG_ALERT, "warn", f"{what} {_stopped(what)}. Найти рабочую стратегию?",
                               action={"label": "Найти и включить", "call": "zapret_fix", "args": []},
                               page="zapret")
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

    def _status_changed(self, force: bool = False) -> None:
        key = (self.zapret.status, self.tg.status, self.zapret.settings.get("zapret", "strategy"),
               self.updates.available_count(), self._vpnclient_status(), self._alerts_key())
        if force or key != self._last_tray_key:
            self._last_tray_key = key
            if self.on_status_change:
                try:
                    self.on_status_change()
                except Exception:  # noqa: BLE001
                    log.exception("Иконка в трее не обновилась")

    def shutdown(self) -> None:
        self._stop.set()
        guard = getattr(self, "guard", None)
        if guard is not None:
            guard.close()   # страховка не включит обход обратно посреди выхода
        # Сначала свой VPN: он возвращает системный прокси — даже если дальше что-то зависнет
        # (подбор ждём до 15 с), браузер не останется с прокси на мёртвый порт.
        vc = getattr(self, "vpnclient", None)
        if vc is not None:
            try:
                vc.shutdown()
            except Exception:  # noqa: BLE001
                log.exception("Свой VPN не остановился")
        try:
            # Загрузки обновлений прерываются, а замена файлов (exe, ядро прокси) доделывается: иначе
            # выход между двумя переименованиями оставил бы Лазейку без exe.
            self.updates.shutdown(UPDATES_STOP_WAIT)
        except Exception:  # noqa: BLE001
            log.exception("Обновления не остановились")
        self.tester.cancel()
        self.tester.join(15)  # подбор сам вернёт обход и IPSet; иначе это сделает следующий запуск
        if self.zapret.mode == "service" and self.zapret.guard_paused:
            # Страховка выключила службу посреди проверки, вердикта нет: служба работает и без Лазейки —
            # вернуть её, как было. До перезагрузки Windows её больше никто бы не запустил.
            try:
                self.zapret.resume_service()
            except Exception:  # noqa: BLE001
                log.exception("Служба обхода не возвращена после проверки связи")
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
        process = z.process   # одно чтение: параллельный stop() обнуляет поле
        vc_state = self._vpnclient_snapshot(s)
        updates = self.updates.snapshot(cores=vc_state.get("cores"))
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
                "started_at": process.started_at if process else None,
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
                "vpnclient_on_start": s["startup"]["vpnclient"], "ui_scale": s["ui"]["scale"],
            },
            "tg_settings": {k: s["tg"][k] for k in (
                "host", "port", "secret", "dc_ip", "cfproxy", "h2", "cf_domains_enabled", "cf_domains",
                "worker_enabled", "worker_domains", "pool_size", "buf_kb", "no_secure", "verbose",
                "zapret_sync")},
            "diag": dict(self.diag_state),
            "dns": dict(self.dns_state),
            "vpn": self._vpn_state(s),
            "vpnclient": vc_state,
            "defender": dict(self.defender_state),
        }

    def logs(self, after_id: int, source: str) -> dict:
        if source not in ("all", "app", "zapret", "tg", "vpn"):
            source = "all"
        return ring.since(int(after_id or 0), source)

    # ------------------------------------------------------------ общее

    def _require_admin(self) -> None:
        if not self.is_admin:
            raise PermissionError("Нужны права администратора — перезапустите Лазейку с ними")

    def background(self, name: str, fn: Callable[[], Any], on_error: str) -> threading.Thread:
        def run() -> None:
            try:
                fn()
            except (UserError, PermissionError, ValueError, RuntimeError, OSError) as exc:
                # Ожидаемые ошибки (в том числе своего VPN) — текстом, а не repr.
                self.notify("error", f"{on_error}: {exc}")
            except Exception as exc:  # noqa: BLE001
                log.exception("%s", on_error)
                self.notify("error", f"{on_error}: {exc!r}")
            finally:
                self._status_changed()
        thread = threading.Thread(target=run, name=name, daemon=True)
        thread.start()
        return thread

    def finish_onboarding(self, opts: dict) -> Result:
        opts = opts or {}
        check = bool(opts.get("check_updates", True))
        want_autostart = bool(opts.get("autostart", False))

        def mutate(d: dict) -> None:
            d["first_run"] = False
            d["updates"]["check"] = check

        self.settings.update(mutate)
        if check:
            self.updates.check_async(quiet=True)   # и при отказе автозапуска: остальные настройки сохранены
        if want_autostart:
            result = self.save_settings({"autostart": True})
            if not result["ok"]:
                return result
        return ok()

    def save_settings(self, partial: dict) -> Result:
        partial = partial or {}
        mapping = {
            "theme": ("ui", "theme"), "close_to_tray": ("ui", "close_to_tray"),
            "start_minimized": ("ui", "start_minimized"), "zapret_on_start": ("startup", "zapret"),
            "tg_on_start": ("startup", "tg"), "check_updates": ("updates", "check"),
            "tcp_timestamps": ("zapret", "tcp_timestamps"), "vpnclient_on_start": ("startup", "vpnclient"),
        }
        if "theme" in partial and partial["theme"] not in ("system", "dark", "light"):
            return fail("Неизвестная тема")
        if "ui_scale" in partial:
            scale = partial["ui_scale"]
            if (isinstance(scale, bool) or not isinstance(scale, (int, float))
                    or not UI_SCALE[0] <= float(scale) <= UI_SCALE[1]):
                return fail("Масштаб окна — от 80 до 150 %")
            self.settings.update(lambda d: d["ui"].__setitem__("scale", round(float(scale), 2)))
        if "watchdog" in partial:
            if partial["watchdog"] not in ("ask", "auto", "off"):
                return fail("Неизвестный режим сторожа")
            self.settings.update(lambda d: d["zapret"].__setitem__("watchdog", partial["watchdog"]))
        if "autostart" in partial:
            try:
                self._require_admin()
                if partial["autostart"]:
                    target = autostart.enable(guard=self.updates.replacing)   # копию выход дожидается
                    if paths.IS_FROZEN and target != paths.exe_path():
                        self.notify("info", f"Для автозапуска Лазейка скопирована в {target.parent} — "
                                            "туда может писать только администратор.")
                else:
                    autostart.disable()
            except Exception as exc:  # noqa: BLE001
                return fail(f"Автозапуск не изменён: {exc}")
            self.settings.update(lambda d: d["startup"].__setitem__("autostart", bool(partial["autostart"])))
            if not partial["autostart"]:
                self.clear_alert("autostart")   # кнопка плашки «Выключить автозапуск» сделала своё

        def mutate(d: dict) -> None:
            for key, (section, field) in mapping.items():
                if key in partial:
                    d[section][field] = partial[key] if key == "theme" else bool(partial[key])

        self.settings.update(mutate)
        if "theme" in partial and self.on_theme:
            self.on_theme(partial["theme"])
        if not self.settings.writable:
            return fail("Настройки не сохранены: " + (self.settings.write_blocked
                                                      or f"нет прав на запись в {paths.DATA}"))
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

    def app_restart(self) -> Result:
        """«Перезапустить» после самообновления или отката: новый exe (на месте прежнего) с --replace
        дождётся, пока этот экземпляр выйдет, и запустится сам — с теми же правами."""
        if not paths.IS_FROZEN:
            return fail("Перезапуск после обновления работает только в собранном приложении")
        command = paths.launch_command() + ["--replace"]
        try:
            subprocess.Popen(command, cwd=str(Path(command[0]).parent), close_fds=True,
                             creationflags=winutil.CREATE_NEW_PROCESS_GROUP)
        except OSError as exc:
            return fail(f"Не удалось запустить Лазейку заново: {exc}")
        log.info("Перезапуск: запущена %s, этот экземпляр выходит", command[0])
        self.quit()
        return ok()

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
        """quiet — включили после окна «Работает VPN»: человек уже всё прочитал. Страховку связи взводит
        сам запуск winws (ZapretManager.on_started)."""
        self._require_admin()
        self.clear_alert(ZAPRET_DOWN)   # человек включает сам — неудачу покажет ответ на нажатие
        self.clear_alert(GUARD_OFF_ALERT)
        self.background("zapret-start", self.zapret.start, "Обход не запустился")
        if not quiet:
            self._vpn_note_on_start()
        return ok()

    def _online(self) -> bool:
        """Для страховки связи: открылся ли хоть один проверочный адрес — мимо VPN, а если VPN не пускает
        мимо себя (kill switch глушит прямой путь), то через него: это не «пропал интернет»."""
        from .zapret.tester import control_ok
        bind = self._direct_bind()
        return control_ok(bind=bind) or (bind is not None and control_ok())

    def _direct_bind(self) -> str | None:
        """Адрес прямого подключения или None — и когда VPN нет, и когда пути мимо него нет."""
        try:
            return self._direct_source()
        except NoDirectPath:
            return None

    def _tester_busy(self) -> bool:
        tester = self.tester
        return bool(getattr(tester, "running", False) or getattr(tester, "fix_running", False))

    def zapret_stop(self) -> Result:
        self._require_admin()
        for alert_id in (ZAPRET_DOWN, GUARD_ALERT, GUARD_OFF_ALERT, WATCHDOG_ALERT):   # выключили — тревожить незачем
            self.clear_alert(alert_id)
        self.background("zapret-stop", self.zapret.stop, "Обход не остановился")
        return ok()

    def zapret_restart(self) -> Result:
        self._require_admin()
        self.clear_alert(ZAPRET_DOWN)
        self.clear_alert(GUARD_OFF_ALERT)
        self.background("zapret-restart", self.zapret.restart, "Обход не перезапустился")
        return ok()

    def zapret_set_strategy(self, strategy_id: str) -> Result:
        self._require_admin()
        if self.zapret.paused_for_test:
            return fail(TESTING_ERROR)   # сразу, а не уведомлением из фона
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
        """Всё, от чего зависит результат проверки доступности: настройки, процесс winws и сеть."""
        process = self.zapret.process   # одно чтение: параллельный stop() обнуляет поле
        return (self.zapret.status, *self._autofix_key(), process.started_at if process else None)

    def _autofix_key(self) -> tuple:
        """Условия, при которых подбор что-то решает: стратегия, фильтры, IPSet, пакет и сеть. Пока они те же,
        сторож в режиме auto не повторяет неудачный подбор."""
        z = self.zapret
        cfg = self.settings.get("zapret")
        gf = cfg["game_filter"]
        return (cfg["strategy"], gf["mode"], gf["tcp"], gf["udp"], cfg["ipset_mode"],
                z.pack.version if z.pack else None, getattr(self, "_net_fp", None))

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
        self._sync_bypass(force=True)   # «через обход» своего VPN берёт домены из этих списков
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
        self.clear_alert(TG_DOWN)   # человек включает сам — неудачу покажет ответ на нажатие
        self._tg_start_job = self.background("tg-start", self.tg.start, "Telegram-прокси не запустился")
        return ok()

    def _tg_crashed(self, error: str) -> None:
        """Прокси работал и остановился сам (порт закрылся, ядро упало) — из потока прокси. Как у обхода:
        плашка «перезапускаем» и одна попытка через TG_REVIVE_PAUSE; падает снова чаще раза в минуту или
        не включается — плашка «остановился» с «Включить снова»."""
        now = time.monotonic()
        last = getattr(self, "_tg_crash_at", None)
        recent, self._tg_crash_at = last is not None and now - last < TG_REVIVE_EVERY, now
        if recent or self._stop.is_set():
            self.set_alert(TG_DOWN, "error", f"Telegram-прокси остановился: {error}", action=TG_RETRY)
            return
        self.set_alert(TG_DOWN, "warn", f"Telegram-прокси остановился сам ({error}) — перезапускаем.")

        def revive() -> None:
            if self._stop.wait(TG_REVIVE_PAUSE) or self.tg.status != "error":
                return              # выход или человек уже включил или выключил прокси сам
            try:
                self.tg.start()
            except Exception as exc:  # noqa: BLE001
                if not isinstance(exc, UserError):
                    log.exception("Telegram-прокси не перезапустился после падения")
                self.set_alert(TG_DOWN, "error", f"Telegram-прокси остановился и не перезапустился: {exc}",
                               action=TG_RETRY)
            finally:
                self._status_changed()

        threading.Thread(target=revive, name="tg-revive", daemon=True).start()

    def tg_stop(self) -> Result:
        self.clear_alert(TG_DOWN)
        self.background("tg-stop", self.tg.stop, "Telegram-прокси не остановился")
        return ok()

    def tg_restart(self) -> Result:
        self.clear_alert(TG_DOWN)
        self.background("tg-restart", self.tg.restart, "Telegram-прокси не перезапустился")
        return ok()

    def tg_open_in_telegram(self) -> Result:
        """Ссылку Telegram получает, только когда прокси уже слушает порт: «Подключить Telegram» включает
        прокси и сразу зовёт этот метод — дожидаемся включения, а не отдаём ссылку на пустой адрес."""
        job = getattr(self, "_tg_start_job", None)
        if job is not None and job.is_alive():
            job.join(TG_START_WAIT)
        if self.tg.status != "running":
            reason = f" ({self.tg.error})" if self.tg.status == "error" and self.tg.error else ""
            return fail(f"Прокси не работает{reason} — Telegram через него не подключится. "
                        "Включите прокси и нажмите «Подключить Telegram» снова.")
        link = self.tg.link()
        if not winutil.open_unelevated(link):
            winutil.set_clipboard(link)
            return fail("Не получилось открыть Telegram автоматически. Ссылка скопирована — "
                        "вставьте её в «Избранное» в Telegram и нажмите на неё.")
        return ok()

    def tg_copy_link(self) -> Result:
        return self.copy_text(self.tg.link())

    def tg_save_settings(self, values: dict) -> Result:
        errors = self.tg.save(values or {})
        if errors:
            return fail("Проверьте поля", errors=errors)
        if self.is_admin:
            def sync() -> None:
                self.zapret.refresh_extra_lists()
                self._sync_bypass(force=True)
            self.background("lists-sync", sync, "Списки обхода не обновлены")
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
                                            self.zapret.running(), own=self._own_vpn(),
                                            compat=bool(self.settings.get("vpn", "compat")),
                                            overrides=self.settings.get("vpn", "overrides"))
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
            snap = vpn.scan(self.settings.get("vpn", "overrides"), own=self._own_vpn())
        except Exception:  # noqa: BLE001
            log.exception("Сетевые адаптеры не прочитаны")
            return self.vpn_snapshot
        # Прямой маршрут пропал на время (Wi-Fi, сон) — VPN, который был, остаётся VPN.
        vpn.keep_roles(snap, self.vpn_snapshot)
        self.vpn_snapshot, self._vpn_scan_at = snap, time.monotonic()
        return snap

    def _wanted_plan(self, snap: vpn.Snapshot | None) -> dict | None:
        """Единственная точка решения, что исключить из перехвата обходом (план, 5.6).

        Совместимость включена — интерфейсы и серверы VPN, как раньше, плюс свои серверы (всегда:
        ALT5, игровой фильтр и ipset «все адреса» задели бы соединение с сервером и в режиме
        прокси). Выключена — обход трогает всё, кроме своего VPN: его TUN и серверов (mode «own»)."""
        if snap is None:
            return None
        if self.settings.get("vpn", "compat"):
            return snap.plan()
        return snap.own_plan()

    def _vpn_plan(self) -> dict | None:
        """Для обхода: что исключить из перехвата. Вызывается при каждом запуске winws. own_servers —
        свои серверы (исключаются всегда, даже совпав с адресом Discord); strict — рядом VPN в интернет
        или свой VPN: не собрался фильтр — обход не запускается обычным перехватом, он задел бы VPN."""
        snap = self._vpn_scan()
        plan = self._wanted_plan(snap)
        if plan and snap is not None:
            plan = dict(plan, own_servers=list(snap.own_servers),
                        strict=bool(snap.internet or snap.own_servers))
        self._handed_plan = dict(plan) if plan else None
        return plan

    def _applied_filter(self) -> dict:
        """Фильтр работающего обхода. zapret/manager.py записывает «vpn» и для плана своего VPN —
        режим «own» восстанавливаем по последнему отданному плану."""
        applied = dict(getattr(self.zapret, "vpn_applied", None) or {"mode": "plain"})
        handed = getattr(self, "_handed_plan", None)
        if (applied.get("mode") == "vpn" and handed and handed.get("mode") == "own"
                and sorted(applied.get("interfaces") or []) == sorted(handed.get("interfaces") or [])):
            applied["mode"] = "own"
        return applied

    def _filter_stale(self, snap: vpn.Snapshot) -> bool:
        """Нужно ли перезапустить winws с новым фильтром — без петли перезапусков."""
        applied = self._applied_filter()
        wanted = self._wanted_plan(snap)
        if self.settings.get("vpn", "compat"):
            return vpn.plan_changed(applied, wanted, snap.direct_indices())
        if wanted is not None:
            return vpn.plan_changed(applied, wanted, snap.indices_except_own())
        if applied.get("mode") == "own":
            # Свой VPN выключили: исключение его сервера никому не мешает, пока интерфейсы те же.
            return vpn.plan_changed(applied, None, snap.indices_except_own())
        # Совместимость выключили, пока шёл подбор, — служба вернулась со старым фильтром.
        return applied.get("mode") == "vpn"

    def _reapply_guard(self) -> threading.Lock:
        lock = getattr(self, "_reapply_lock", None)
        if lock is None:
            lock = self._reapply_lock = threading.Lock()
        return lock

    def _reapply_zapret(self, name: str, on_error: str, auto: bool = True) -> None:
        """Перестроить фильтр обхода фоном — одна задача за раз: пока она идёт, повторный осмотр
        видит прежний фильтр и запустил бы второй перезапуск."""
        lock = self._reapply_guard()
        if not lock.acquire(blocking=False):
            return
        started = threading.Event()

        def work() -> None:
            started.set()
            try:
                self.zapret.reapply_for_network()
            finally:
                lock.release()

        try:
            # Сама (смена сети, свой VPN) — ошибка плашкой, удача её снимает; по нажатию — уведомлением.
            auto_work = self._alerting(FILTER_ALERT, on_error, work,
                                       fail=lambda detail: self._filter_failed(on_error, detail))
            self.background(name, auto_work if auto else work, on_error)
        except BaseException:
            if not started.is_set():
                lock.release()
            raise

    def _direct_source(self) -> str | None:
        """Для проверок обхода: адрес прямого подключения, если работает туннель VPN в интернет —
        полный или для части адресов (тогда неизвестно, каких именно). У VPN в режиме системного
        прокси проверки и так идут мимо него: curl запускается с --noproxy. Туннель есть, а прямого
        адреса нет — NoDirectPath: проверка без привязки ушла бы в VPN и показала бы не обход, а VPN."""
        snap = self.vpn_snapshot
        if snap is None or not snap.internet:
            return None
        source = snap.source_ip()
        if source is None:
            raise NoDirectPath()
        return source

    def _vpn_watch(self, announce: bool) -> None:
        """Появился или пропал VPN, сменились интерфейсы — обновить фильтр работающего обхода."""
        snap = self._vpn_scan()
        if snap is None:
            return
        active = self._confirmed_vpn(snap.foreign_active)   # только чужой VPN: свой включил сам человек
        was = getattr(self, "_vpn_was_active", None)
        if announce and was is False and active:
            self._announce_vpn(snap)
        if (active, snap.own_active) != (was, getattr(self, "_own_was_active", None)):
            self.vpn_routes = None  # прежняя картина «что куда идёт» больше не верна
        self._vpn_was_active, self._own_was_active = active, snap.own_active
        z = self.zapret
        if (not self.is_admin or z.status != "running" or z.paused_for_test or self.tester.running
                or self.tester.fix_running):
            return
        if self._filter_stale(snap):
            self._reapply_zapret("vpn-reapply", "Обход не перезапустился под новую сеть")
        self._vpn_note_tick()

    def _confirmed_vpn(self, seen: bool) -> bool:
        """Работает ли чужой VPN — по VPN_CONFIRM_SCANS осмотрам подряд. Один осмотр мог застать пропавший
        на секунду маршрут прямого подключения, и Radmin выглядел бы «VPN в интернет»: объявлять такое и
        включать из-за него плашки незачем. Первый осмотр после запуска принимается сразу."""
        last, streak = getattr(self, "_vpn_seen", (seen, 0))
        streak = streak + 1 if seen == last else 1
        self._vpn_seen = (seen, streak)
        confirmed = getattr(self, "_vpn_was_active", None)
        if confirmed is None or streak >= VPN_CONFIRM_SCANS:
            return seen
        return confirmed

    def _announce_vpn(self, snap: vpn.Snapshot) -> None:
        if self.zapret.status != "running" or not snap.foreign_active:
            return
        name = snap.foreign_label
        if self.settings.get("vpn", "compat"):
            # Что обход VPN не трогает, скажем, когда фильтр под этот VPN соберётся (_vpn_note_tick).
            self._vpn_note = ("connected", time.monotonic())
        else:
            # Плашка висит, пока VPN подключён и совместимость выключена: переподключения VPN не дёргают.
            self.set_alert(COMPAT_ALERT, "warn", f"Подключён VPN ({name}), а совместимость с VPN выключена — "
                                                 "обход может мешать VPN.",
                           action={"label": "Включить совместимость", "call": "vpn_set_compat", "args": [True]},
                           page="zapret")

    def _vpn_note_on_start(self) -> None:
        """Обход включают рядом с чужим VPN: сказать, как они уживаются, — когда обход запустится."""
        snap = self.vpn_snapshot
        if snap is None or not snap.foreign_active:
            return
        self._vpn_note = ("start", time.monotonic())

    def _vpn_note_tick(self) -> None:
        """Отложенное уведомление о чужом VPN рядом с обходом. «Обход его не трогает» — только когда обход
        работает с фильтром, собранным под этот VPN: до этого оно было бы неправдой. Фильтр не собрался —
        об этом говорит плашка zapret-vpnfilter, уведомления нет. Совместимость выключена — плашка compat-off."""
        pending = getattr(self, "_vpn_note", None)
        if pending is None:
            return
        kind, since = pending
        snap, z = self.vpn_snapshot, self.zapret
        if snap is None or not snap.foreign_active or time.monotonic() - since > VPN_NOTE_WAIT:
            self._vpn_note = None
            return
        if (z.status != "running" or z.paused_for_test or self.tester.running or self.tester.fix_running
                or (self.settings.get("vpn", "compat") and self._filter_stale(snap))):
            return   # обход ещё запускается, идёт подбор или фильтр под VPN ещё не перестроен
        self._vpn_note = None
        if not self.settings.get("vpn", "compat"):
            self._announce_vpn(snap)
            return
        text = self._vpn_compat_text(snap, kind)
        if text:
            self.notify("info", text, action={"label": "Что куда идёт", "page": "zapret"})

    def _vpn_compat_text(self, snap: vpn.Snapshot, kind: str) -> str | None:
        """Что именно совместимость сделала с этим VPN — по применённому фильтру, а не по намерению."""
        applied = self._applied_filter()
        if applied.get("mode") == "error":
            return None
        name = snap.foreign_label
        head = f"Подключён VPN ({name})." if kind == "connected" else f"Обход включён рядом с VPN ({name})."
        filtered = applied.get("mode") == "vpn"
        server = filtered and bool(set(applied.get("servers") or []) & set(snap.foreign_servers))
        if snap.foreign_internet:
            if not filtered:
                return None
            if server:
                return f"{head} Обход его не трогает: интерфейс и сервер VPN исключены из перехвата."
            return f"{head} Обход не трогает его туннель: интерфейс VPN исключён из перехвата."
        if server:
            return (f"{head} Он работает как системный прокси; соединение VPN с сервером исключено из перехвата "
                    "обхода.")
        return (f"{head} Он работает как системный прокси: браузер и программы, которые его слушают, идут через "
                "VPN. Сервер VPN определить не удалось, поэтому обход может задевать соединение с ним — если VPN "
                "начнёт рваться, выключите обход или включите в VPN-программе режим TUN.")

    def _vpn_conflict_hint(self) -> str:
        """Совет в плашке «обход выключен: с ним пропадал интернет» — по тому, что известно о VPN сейчас:
        «включите совместимость» — только если она выключена."""
        snap = self.vpn_snapshot
        if snap is None or not snap.foreign_active:
            return " Скорее всего, стратегия не подходит вашему провайдеру — попробуйте другую."
        name = snap.foreign_label
        if not self.settings.get("vpn", "compat"):
            return f" Похоже на конфликт с VPN ({name}) — включите «Совместимость с VPN»."
        if not snap.foreign_internet and not snap.foreign_servers:
            return (f" Похоже на конфликт с VPN ({name}): он работает как системный прокси, и отделить его "
                    "соединение от обхода не удалось — попробуйте другую стратегию или режим TUN в VPN-программе.")
        return (f" Похоже на конфликт с VPN ({name}): совместимость с VPN включена, но не помогла — попробуйте "
                "другую стратегию.")

    @staticmethod
    def _vpn_known(snap: vpn.Snapshot | None, known: list[str]) -> bool:
        return bool(snap and snap.foreign_active and set(snap.signature()) <= set(known))

    def _vpn_state(self, s: dict) -> dict:
        snap = self.vpn_snapshot
        out = vpn.snapshot_dict(snap)
        out.update(compat=s["vpn"]["compat"], ask=s["vpn"]["ask"], overrides=dict(s["vpn"]["overrides"]),
                   known=self._vpn_known(snap, s["vpn"]["known"]), filter=self._applied_filter(),
                   routes=dict(self.vpn_routes) if self.vpn_routes else None)
        return out

    def vpn_preflight(self, component: str) -> Result:
        """Перед включением обхода или прокси: работает ли чужой VPN и нужно ли спросить человека.
        Про свой VPN не спрашиваем: его включил сам человек, и обход его не трогает."""
        snap = self._vpn_scan()
        cfg = self.settings.get("vpn")
        ask = bool(snap and snap.foreign_active and cfg["ask"] and not self._vpn_known(snap, cfg["known"]))
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
                and self._filter_stale(snap)):
            self._reapply_zapret("vpn-override", "Обход не перезапустился", auto=False)
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
        state = self.state()
        vc = getattr(self, "vpnclient", None)
        if vc is not None:
            try:
                state["vpnclient_help"] = list(vc.help_items())   # следы чужих VPN и аварий — в отчёт
            except Exception:  # noqa: BLE001 — отчёт важнее этой части
                log.debug("Проверки своего VPN для отчёта не выполнены", exc_info=True)
        text = build_report(state, ring.since(0, "all", limit=400)["lines"])
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
        lines = current.splitlines()
        if name in (ln.strip() for ln in lines):
            return ok(message=f"{name} уже в «Моих сайтах»")
        # Дописываем в конец: пометки и заголовок, которые человек вёл в списке, остаются как были.
        kept = [ln for ln in lines if ln.strip() != zlists.PLACEHOLDER_DOMAIN]
        while kept and not kept[-1].strip():
            kept.pop()
        self.zapret.lists_save("list-general-user.txt", "\n".join(kept + [name]) + "\n")
        self._sync_bypass(force=True)
        return ok(message=f"{name} добавлен в «Мои сайты»")

    def discord_clear_cache(self) -> Result:
        if winutil.other_account():
            # %APPDATA% — той учётной записи, чей пароль ввели при запуске, а Discord — того, кто за компьютером.
            return fail("Лазейка запущена от имени другой учётной записи Windows (при запуске вводили пароль "
                        "администратора) — кэш вашего Discord ей не виден. Очистите кэш вручную или запустите "
                        "Лазейку из своей учётной записи.")
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
        procs += self._core_exes()
        return paths_ex, procs, tuple(roots)

    @staticmethod
    def _core_exes() -> list[str]:
        """exe установленных ядер своего VPN (components/<ядро>/<версия>/ — внутри папки данных)."""
        out: list[str] = []
        for folder, exe in ((paths.SINGBOX_COMPONENTS_DIR, "sing-box.exe"), (paths.XRAY_COMPONENTS_DIR, "xray.exe")):
            try:
                found = sorted(folder.glob(f"*/{exe}"))
            except OSError:
                continue
            out += [str(p) for p in found if re.fullmatch(r"\d+(\.\d+)+", p.parent.name) and p.is_file()]
        return out

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

    # ------------------------------------------------------------ свой VPN (раздел 6 плана)

    def _own_conflict(self, snap: vpn.Snapshot | None) -> dict | None:
        """Чужой VPN, с которым своему не ужиться: два TUN ломают маршруты друг другу, а в режиме
        прокси Лазейка заменит чужой системный прокси (и вернёт его, когда выключится). Чужой туннель, через
        который идёт интернет, а доказать «VPN в интернет» нечем (OpenVPN снял прямой маршрут и вывел сервер
        маршрутом к /24, vpn.Snapshot.unproven), — тоже повод спросить: неопределённость — не повод молчать."""
        if snap is None:
            return None
        mode = self.settings.get("vpnclient", "mode")
        label = snap.foreign_label
        unproven = getattr(snap, "unproven", None) or []
        if mode == "tun" and (snap.foreign_internet or unproven):
            lead = f"Уже работает {label}"
            if not snap.foreign_internet:
                label = snap.unproven_label()
                lead = f"Интернет сейчас идёт через {label}"
            denied = self._vc_proxy_denied()
            if denied:
                # Оба факта: чужой туннель и недоступный системный прокси — уйти в прокси не предлагаем.
                return {"kind": "tunnel", "label": label, "proxy_denied": denied,
                        "text": f"{lead} — два VPN мешают друг другу: выключите {label}."}
            return {"kind": "tunnel", "label": label,
                    "text": f"{lead} — два VPN мешают друг другу: выключите {label} "
                            "или включите Лазейку как системный прокси."}
        if mode == "proxy" and snap.proxy:
            return {"kind": "proxy", "label": label,
                    "text": f"Лазейка заменит системный прокси {label} и вернёт его, когда выключится."}
        return None

    def _vc_proxy_denied(self) -> str | None:
        """Почему режим «Системный прокси» своего VPN недоступен (чужая учётная запись UAC), или None."""
        check = getattr(getattr(self, "vpnclient", None), "proxy_unavailable", None)
        if not callable(check):
            return None
        try:
            reason = check()
        except Exception:  # noqa: BLE001 — зовётся и из снимка: не знаем — не мешаем
            log.debug("Доступность системного прокси не проверена", exc_info=True)
            return None
        return str(reason) if reason else None

    def vpnclient_preflight(self) -> Result:
        """Перед включением своего VPN: {ok, ask, conflict} — по образцу окна «Работает VPN». Менеджер
        спрашиваем всегда: он помнит свой отказ (uac_user) до следующего preflight — и снимает устаревший."""
        vc = self._vc()
        conflict = self._own_conflict(self._vpn_scan())
        check = getattr(vc, "preflight", None)
        extra = check() if callable(check) else None   # то, что видит только менеджер (чужая учётная запись UAC)
        own = extra.get("conflict") if isinstance(extra, dict) else None
        # Прокси под чужой учётной записью не включится вовсе — это важнее, чем «заменим чужой прокси».
        if own and (conflict is None or conflict.get("kind") == "proxy"):
            conflict = own
        return ok(ask=conflict is not None, conflict=conflict)

    def vpnclient_start(self, quiet: bool = False) -> Result:
        """quiet — включили после окна «Уже работает другой VPN»: человек уже всё прочитал."""
        self._require_admin()
        vc = self._vc()
        self.clear_alert(VC_DOWN)   # человек включает сам — неудачу покажет ответ на нажатие
        return self._vc_background("vpnclient-start", lambda: vc.start(quiet=bool(quiet)), "Свой VPN не включился")

    def vpnclient_stop(self) -> Result:
        vc = self._vc()
        self.clear_alert(VC_DOWN)
        return self._vc_background("vpnclient-stop", vc.stop, "Свой VPN не выключился")

    def vpnclient_restart(self) -> Result:
        self._require_admin()
        vc = self._vc()
        self.clear_alert(VC_DOWN)
        return self._vc_background("vpnclient-restart", vc.restart, "Свой VPN не перезапустился")

    def vpnclient_set_mode(self, mode: str) -> Result:
        if mode not in VPNCLIENT_MODES:
            return fail("Неизвестный режим своего VPN")
        # Не фоном: окно «Уже работает другой VPN» включает VPN следом и должно знать, что режим сменился
        # (режим прокси недоступен под чужой учётной записью UAC). Переподключение менеджер ставит в очередь сам.
        return self._vc_result(self._vc().set_mode(mode))

    def vpnclient_select(self, server_id: str) -> Result:
        """Сервер или auto:<группа|подписка>; на работающем ядре — без перезапуска. Фильтр обхода
        под новый адрес перестроит тикер (снимок own() сменился)."""
        return self._vc_result(self._vc().select(str(server_id)))

    def vpnclient_import(self, text: str | None, ua_preset: str | None = None, hwid: bool = False) -> Result:
        return self._vc_result(self._vc().import_text(text, ua_preset, hwid))

    def vpnclient_sub_update(self, sub_id: str | None = None) -> Result:
        return self._vc_result(self._vc().sub_update(sub_id))

    def vpnclient_sub_remove(self, sub_id: str) -> Result:
        return self._vc_result(self._vc().sub_remove(str(sub_id)))

    def vpnclient_sub_set(self, sub_id: str, values: dict) -> Result:
        return self._vc_result(self._vc().sub_set(str(sub_id), dict(values or {})))

    def vpnclient_server_remove(self, server_id: str) -> Result:
        return self._vc_result(self._vc().server_remove(str(server_id)))

    def vpnclient_server_rename(self, server_id: str, name: str) -> Result:
        return self._vc_result(self._vc().server_rename(str(server_id), str(name)))

    def vpnclient_copy_link(self, server_id: str) -> Result:
        """Ссылка — секрет: в буфер обмена по явной кнопке, странице её не отдаём."""
        value = self._vc().copy_link(str(server_id))
        if isinstance(value, str):
            return ok() if winutil.set_clipboard(value) else fail("Буфер обмена занят другой программой")
        return self._vc_result(value)

    def vpnclient_open_link(self, sub_id: str, kind: str) -> Result:
        """Ссылка провайдера по id подписки: адрес с секретом подписки странице не отдаётся."""
        return self.open_url(self._vc().open_link(str(sub_id), str(kind)))

    def vpnclient_latency(self, ids: list[str] | None = None) -> Result:
        return self._vc_result(self._vc().latency(ids))

    def vpnclient_save_settings(self, values: dict) -> Result:
        return self._vc_result(self._vc().save_settings(dict(values or {})))

    def vpnclient_core_install(self, name: str) -> Result:
        """Скачать ядро с GitHub (кнопка на странице VPN, «Скачать ещё раз» на плашке): та же задача, что
        пункт «Обновлений»."""
        if name not in ("sing-box", "xray"):
            return fail("Неизвестное ядро")
        self._require_admin()
        self._vc()
        self.updates.install_core_async(name)
        return ok()

    def vpnclient_rules_update(self) -> Result:
        return self._vc_result(self._vc().rules_update())

    def vpnclient_running_apps(self) -> Result:
        return self._vc_result(self._vc().running_apps(), key="apps")

    def vpnclient_import_file(self) -> Result:
        vc = self._vc()
        path = self._file_dialog("open", ("Подписки и конфиги (*.conf;*.json;*.txt)",
                                          "Картинки с QR (*.png;*.jpg;*.jpeg;*.bmp;*.webp)", "Все файлы (*.*)"))
        if path is None:
            return ok(cancelled=True)
        return self._vc_result(vc.import_file(path))

    def vpnclient_import_qr(self, source: str) -> Result:
        if source not in ("screen", "file"):
            return fail("Неизвестный источник QR")
        vc = self._vc()
        if source == "screen":
            return self._vc_result(vc.import_qr("screen"))
        path = self._file_dialog("open", ("Картинки с QR (*.png;*.jpg;*.jpeg;*.bmp;*.webp)", "Все файлы (*.*)"))
        if path is None:
            return ok(cancelled=True)
        return self._vc_result(vc.import_qr("file", path))

    def vpnclient_qr(self, item_id: str) -> Result:
        return self._vc_result(self._vc().qr(str(item_id)), key="png")

    def vpnclient_backup_export(self, password: str) -> Result:
        vc = self._vc()
        path = self._file_dialog("save", ("Резервная копия Лазейки (*.lzbackup)",),
                                 save_name=f"lazeyka-vpn-{time.strftime('%Y-%m-%d')}.lzbackup")
        if path is None:
            return ok(cancelled=True)
        return self._vc_result(vc.backup_export(str(password), path))

    def vpnclient_backup_import(self, password: str) -> Result:
        vc = self._vc()
        path = self._file_dialog("open", ("Резервная копия Лазейки (*.lzbackup)", "Все файлы (*.*)"))
        if path is None:
            return ok(cancelled=True)
        return self._vc_result(vc.backup_import(str(password), path))

    def vpnclient_profile_import(self, text: str) -> Result:
        return self._vc_result(self._vc().profile_import(str(text)))

    def vpnclient_profile_set(self, profile_id: str, active: bool) -> Result:
        return self._vc_result(self._vc().profile_set(str(profile_id), bool(active)))

    def vpnclient_profile_remove(self, profile_id: str) -> Result:
        return self._vc_result(self._vc().profile_remove(str(profile_id)))

    def vpnclient_speedtest(self, server_id: str | None = None) -> Result:
        return self._vc_result(self._vc().speedtest(server_id))

    def vpnclient_deeplink_confirm(self, token: str, accept: bool) -> Result:
        return self._vc_result(self._vc().deeplink_confirm(str(token), bool(accept)))

    def vpnclient_deeplink(self, text: str) -> None:
        """Строка из ссылки lazeyka:// (main.py, канал второго экземпляра): менеджер покажет окно
        «Добавить …?» — без подтверждения ничего не добавляется."""
        self._vc().deeplink_offer(str(text))

    def vpnclient_sub_probe(self, sub_id: str) -> Result:
        """«Проверить расширенный формат» подписки (кнопка страницы)."""
        probe = getattr(self._vc(), "sub_probe", None)
        if not callable(probe):
            return fail("Проверка расширенного формата подписки пока не поддерживается")
        return self._vc_result(probe(str(sub_id)))

    def vpnclient_help(self) -> Result:
        """Панель «Свой VPN не подключается»: чужие и свои следы (мёртвый прокси, DNS после Incy…)."""
        return ok(items=list(self._vc().help_items()))

    def vpnclient_proxy_fix(self) -> Result:
        """Кнопка «Помощи»: вернуть свой прокси после аварии или выключить чужой мёртвый."""
        self._require_admin()
        return self._vc_result(self._vc().fix_proxy())

    def vpnclient_open_adapters(self) -> Result:
        """«Сетевые подключения» Windows: DNS адаптера человек правит сам (Лазейка их не переписывает)."""
        if not winutil.open_unelevated("ncpa.cpl"):
            return fail("Не удалось открыть «Сетевые подключения»")
        return ok()

    def _file_dialog(self, kind: str, file_types: tuple[str, ...], save_name: str | None = None) -> str | None:
        """Окно выбора файла pywebview: путь или None (отмена). Ничего не читает — только путь."""
        import webview
        window = webview.windows[0] if getattr(webview, "windows", None) else None
        if window is None:
            raise VpnClientUnavailable("Окно Лазейки ещё не открыто")
        dialog_types = getattr(webview, "FileDialog", None)
        if kind == "save":
            dtype = dialog_types.SAVE if dialog_types else webview.SAVE_DIALOG
            picked = window.create_file_dialog(dtype, save_filename=save_name or "", file_types=file_types)
        else:
            dtype = dialog_types.OPEN if dialog_types else webview.OPEN_DIALOG
            picked = window.create_file_dialog(dtype, allow_multiple=False, file_types=file_types)
        if not picked:
            return None
        return str(picked[0] if isinstance(picked, (list, tuple)) else picked)
