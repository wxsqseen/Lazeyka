"""Управление обходом zapret: пакет, стратегия, winws или служба Windows."""
from __future__ import annotations

import hashlib
import json
import logging
import shutil
import socket
import threading
import time
import winreg
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Callable

from .. import paths, winutil
from ..settings import Settings
from . import gamefilter, lists, netcfg, pack, strategies, vpnfilter
from .runner import RunnerError, WinwsProcess, foreign_winws, kill_processes
from ..errors import UserError

log = logging.getLogger("lazeyka.zapret")

SERVICE_NAME = "LazeykaZapret"
SERVICE_DISPLAY = "Лазейка — zapret"
SERVICE_DESCRIPTION = "Обход блокировок Discord и YouTube (zapret, стратегии Flowseal). Управляется приложением «Лазейка»."
FOREIGN_SERVICES = ("zapret", "GoodbyeDPI", "discordfix_zapret", "winws1", "winws2")
IPSET_URL = ("https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/"
             "refs/heads/main/.service/ipset-service.txt")
FULL_IPSET_FILE = "ipset-all.full.txt"
ACTIVE_FAKES = {"discord": "ACTIVE_DISCORD_UDP.bin", "game": "ACTIVE_GAME_UDP.bin"}
TESTING_ERROR = "Идёт подбор стратегии — дождитесь окончания или остановите его"
SERVICE_STOP_ERROR = "Служба обхода не остановилась за 10 секунд — обход ещё работает"
# Адреса Discord и YouTube: сервер VPN с таким же адресом из перехвата не исключаем (VPN через CDN).
TARGET_HOSTS = ("discord.com", "gateway.discord.gg", "cdn.discordapp.com", "media.discordapp.net",
                "www.youtube.com", "youtube.com", "redirector.googlevideo.com", "i.ytimg.com", "yt3.ggpht.com")
TARGET_TTL = 600.0       # адреса держим 10 минут; пустой ответ не держим вовсе
RESOLVE_TIMEOUT = 3.0    # DNS не ответил за это время — запуск обхода его не ждёт
FILTER_RETRY_DELAY = 30.0   # фильтр совместимости с VPN не собрался — повтор запуска через столько секунд
FILTER_RETRIES = 3

Notify = Callable[[str, str], None]  # (уровень, текст)


class ZapretError(UserError):
    pass


class FilterRefused(ZapretError):
    """Рядом VPN в интернет, а фильтр совместимости не собрался: обычный перехват задел бы VPN."""


_RETRY = {"label": "Включить снова", "call": "zapret_start", "args": []}
SERVICE_ALERT = "zapret-service"   # служба запускает winws из прежнего пакета, перенастроить не вышло


class ZapretManager:
    def __init__(self, settings: Settings, notify: Notify, is_admin: bool):
        self.settings = settings
        self.notify = notify
        self.is_admin = is_admin
        self.lock = threading.RLock()
        self.status = "stopped"
        self.error: str | None = None
        self.pack: pack.PackInfo | None = None
        self.strategies: list[strategies.Strategy] = []
        self.parse_errors: list[str] = []
        self.process: WinwsProcess | None = None
        self.unavailable_reason: str | None = None
        self.paused_for_test = False
        # Обход выключила страховка связи посреди проверки (zapret/guard.py): подбор, начатый в это время,
        # считает его работавшим и вернёт сам; выход Лазейки возвращает службу. Сбрасывают start() и stop().
        self.guard_paused = False
        self._restarts: list[float] = []
        self.av_removal_seen = False   # антивирус удалял файлы пакета (повод предложить исключение)
        # Домены, которые нужно добавить в списки ради других частей Лазейки (Telegram-прокси).
        self.extra_lists: Callable[[], dict[str, list[str]]] | None = None
        # «Совместимость с VPN»: что исключить из перехвата ({interfaces, servers}) или None.
        self.vpn_plan: Callable[[], dict | None] | None = None
        self.vpn_applied: dict = {"mode": "plain"}
        self._vpn_error_shown: str | None = None
        # Постоянная плашка Core (core.alert): поломки, найденные без нажатия человека. Без неё — уведомление.
        self.alert: Callable[..., None] | None = None
        # Страховка связи Core (zapret/guard.py): guard_probe() — есть ли связь, пока новый winws не запущен;
        # on_started(связь_была) — Лазейка запустила winws (сама или службой).
        self.guard_probe: Callable[[], bool | None] | None = None
        self.on_started: Callable[[bool | None], None] | None = None
        self._target_cache: tuple[float, set[str]] = (0.0, set())
        self._filter_retries = 0

    def _alert(self, alert_id: str, level: str | None, text: str = "", action: dict | None = None,
               page: str | None = "zapret") -> None:
        """Плашка вместо уведомления (level=None — снять); без Core — прежнее уведомление."""
        if self.alert is not None:
            self.alert(alert_id, level, text, action=action, page=page)
        elif level is not None:
            self.notify(level, text)

    # ------------------------------------------------------------ подготовка

    def init(self) -> None:
        # Повторный init (пакет восстановлен после Defender) — с чистого листа: прежняя причина
        # недоступности больше не правда.
        self.unavailable_reason = None if self.is_admin else "Для работы обхода нужны права администратора."
        try:
            wanted = self.settings.get("zapret", "pack")
            current = pack.find(wanted)
            # Ожидали конкретную версию, а её нет — файл или вся папка пакета пропали (антивирус).
            if wanted and current is None:
                self.av_removal_seen = True
            broken = pack.problem_of(wanted) if current is None else None
            if broken:
                self.av_removal_seen = True
            if self.is_admin:
                try:
                    bundled, fresh = pack.ensure_bundled()
                except pack.PackError:
                    if broken:
                        self._notify_broken(wanted, broken, None)
                    raise
                # Выбор пользователя (в том числе откат) уважаем; встроенный пакет перебивает
                # его, только если он новее и пришёл вместе с новой версией приложения.
                if bundled is not None and (current is None or (
                        fresh and pack.version_key(bundled.version) > pack.version_key(current.version))):
                    current = bundled
            if current is None:
                current = pack.newest()
            if broken:
                self._notify_broken(wanted, broken, current)
            if current is None:
                self.unavailable_reason = self.unavailable_reason or "Пакет стратегий ещё не установлен."
                return
            self._activate_pack(current)
            if self.is_admin:
                lists.adopt_user_lists(paths.USER_LISTS_DIR, current.path / "lists")
                lists.ensure_user_lists(paths.USER_LISTS_DIR)
                self._recover_interrupted_test()
                self.prepare_pack()  # режим IPSet, списки и фейки — сразу, чтобы окно показывало правду
                if self.mode == "service":
                    self._load_service_filter()
                try:
                    self._align_service()
                except ZapretError as exc:
                    # Служба работает по-старому — обход от этого не недоступен: плашка, а не «недоступно».
                    log.warning("Служба обхода не перенастроена на пакет %s: %s", current.version, exc)
                    self._alert(SERVICE_ALERT, "warn", f"Служба обхода запускает winws из прежнего пакета, а "
                                                       f"перенастроить её на {current.version} не вышло: {exc}")
                self._align_service_start()
                keep = {current.version}
                previous = [p for p in pack.installed() if p.version != current.version
                            and pack.version_key(p.version) < pack.version_key(current.version)]
                if previous:
                    keep.add(previous[-1].version)  # одна прошлая версия — для отката
                service_pack = self._service_pack_version()
                if service_pack:
                    keep.add(service_pack)       # пакет, из которого запускается служба, не трогаем
                pack.cleanup(keep)
        except (pack.PackError, OSError, ZapretError, ValueError) as exc:
            log.exception("Пакет стратегий не подготовлен")
            self.unavailable_reason = f"Пакет стратегий не подготовлен: {exc}"
        except Exception as exc:  # noqa: BLE001 — непредвиденное: Лазейка (прокси, свой VPN) запускается без обхода
            log.exception("Пакет стратегий не подготовлен из-за непредвиденной ошибки")
            self.unavailable_reason = f"Пакет стратегий не подготовлен: {exc!r}"

    def _notify_broken(self, wanted: str, problem: str, current: pack.PackInfo | None) -> None:
        """Пакет повреждён — сказать, что с ним стало на самом деле (встроенный ставится заново, только
        если новее его ничего не установлено)."""
        if current is not None and current.version == wanted:
            what = "Он поставлен заново из встроенной копии."
        elif current is not None:
            what = f"Обход работает на пакете {current.version}, а {wanted} можно переустановить на странице «Обновления»."
        else:
            what = "Переустановите его на странице «Обновления»."
        self.notify("warn", f"Пакет стратегий {wanted} повреждён ({problem}) — похоже, файл удалил антивирус. {what}")

    # ------------------------------------------------------------ подбор: защита от прерывания

    TEST_MARKER = "test-in-progress.json"

    def mark_test(self, ipset_mode: str | None, service_was_running: bool) -> None:
        """Запоминает, что вернуть, если подбор оборвётся вместе с приложением."""
        data = {"pack": self.pack.version if self.pack else None, "ipset_mode": ipset_mode,
                "service_was_running": service_was_running}
        (paths.ZAPRET_DIR / self.TEST_MARKER).write_text(json.dumps(data), encoding="utf-8")

    def unmark_test(self) -> None:
        (paths.ZAPRET_DIR / self.TEST_MARKER).unlink(missing_ok=True)

    def _recover_interrupted_test(self) -> None:
        marker = paths.ZAPRET_DIR / self.TEST_MARKER
        if not marker.is_file():
            return
        try:
            data = json.loads(marker.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = {}
        marker.unlink(missing_ok=True)
        restored = []
        mode = data.get("ipset_mode")
        if self.pack and data.get("pack") == self.pack.version and mode in lists.IPSET_MODES:
            lists_dir = self.pack.path / "lists"
            if lists.detect_ipset_mode(lists_dir) != mode:
                try:
                    lists.set_ipset_mode(lists_dir, mode)
                    restored.append(f"режим IPSet «{mode}»")
                except ValueError as exc:
                    log.warning("Режим IPSet не восстановлен: %s", exc)
        if data.get("service_was_running") and self.mode == "service":
            try:
                self.resume_service()
                restored.append("служба обхода")
            except ZapretError as exc:
                log.warning("Служба не запущена после прерванного подбора: %s", exc)
        log.warning("Прошлый подбор стратегии был прерван; восстановлено: %s", ", ".join(restored) or "нечего")
        if restored:
            self.notify("info", "Прошлый подбор стратегии был прерван — восстановлено: " + ", ".join(restored) + ".")

    # ------------------------------------------------------------ служба и активный пакет

    def _service_pack_version(self) -> str | None:
        info = winutil.service_query(SERVICE_NAME, with_config=True)
        if info is None or not info.binary:
            return None
        binary = info.binary.lower()
        for p in pack.installed():
            if str(p.path).lower() + "\\" in binary:
                return p.version
        return None

    def _align_service(self) -> None:
        """Служба должна запускать winws из активного пакета (после обновления приложения и т. п.)."""
        if self.mode != "service" or self.pack is None:
            return
        info = winutil.service_query(SERVICE_NAME, with_config=True)
        if info is None or not info.binary or str(self.pack.path).lower() + "\\" in info.binary.lower():
            return
        log.info("Служба запускает winws из другого пакета — перенастраиваю на %s", self.pack.version)
        self._service_apply(start=info.state == "running")

    def _align_service_start(self) -> None:
        """До 1.3 служба, выключенная человеком, оставалась в автозапуске Windows и после перезагрузки
        включала обход сама. Выключен и не работает — запуск вручную («Включить» вернёт автозапуск)."""
        if self.mode != "service" or self.settings.get("zapret", "was_running"):
            return
        info = winutil.service_query(SERVICE_NAME, with_config=True)
        if info is None or info.state != "stopped" or info.start_type != winutil.SERVICE_AUTO_START:
            return
        try:
            winutil.service_set_start(SERVICE_NAME, auto=False)
            log.info("Обход выключен, а служба стартовала бы вместе с Windows — теперь она запускается вручную")
        except winutil.ServiceError as exc:
            log.warning("Служба выключенного обхода осталась в автозапуске Windows: %s", exc)

    def _activate_pack(self, info: pack.PackInfo) -> None:
        self.pack = info
        self.strategies, self.parse_errors = strategies.discover(info.path)
        for err in self.parse_errors:
            log.warning("Стратегия пропущена: %s", err)
        ids = {s.id for s in self.strategies if s.usable}
        chosen = self.settings.get("zapret", "strategy")

        def mutate(d: dict) -> None:
            d["zapret"]["pack"] = info.version
            if chosen not in ids and ids:
                d["zapret"]["strategy"] = "general" if "general" in ids else sorted(ids)[0]

        self.settings.update(mutate)
        if chosen not in ids and ids:
            picked = self.settings.get("zapret", "strategy")
            names = {s.id: s.label for s in self.strategies}
            self.notify("warn", f"Стратегии «{strategies.label_for(chosen) if chosen else '—'}» нет в пакете "
                                f"{info.version} — выбрана «{names.get(picked, picked)}».")

    @property
    def available(self) -> bool:
        return self.is_admin and self.pack is not None and self.unavailable_reason is None

    @property
    def mode(self) -> str:
        return self.settings.get("zapret", "mode")

    def strategy(self, strategy_id: str | None = None) -> strategies.Strategy:
        wanted = strategy_id or self.settings.get("zapret", "strategy")
        for s in self.strategies:
            if s.id == wanted:
                if not s.usable:
                    raise ZapretError(f"Стратегия «{s.label}» не поддерживается этой версией приложения")
                return s
        raise ZapretError(f"Стратегия «{wanted}» не найдена")

    def _extra(self) -> dict[str, list[str]]:
        try:
            return self.extra_lists() if self.extra_lists else {}
        except Exception:  # noqa: BLE001
            log.exception("Дополнительные домены для списков не получены")
            return {}

    def refresh_extra_lists(self) -> None:
        """Пересобрать рабочие списки и перезапустить обход, если домены для прокси поменялись."""
        with self.lock:
            if not self.pack or not self.is_admin:
                return
            if self.paused_for_test:
                # Пробы подбора идут при одних и тех же списках; обход после подбора запускается с
                # prepare_pack (и служба — тоже), он и перенесёт новые домены.
                log.info("Списки обхода обновлю после подбора стратегии")
                return
            lists_dir = self.pack.path / "lists"
            before = {n: (lists_dir / n).read_bytes() if (lists_dir / n).exists() else b"" for n in lists.USER_LISTS}
            lists.sync_user_lists(paths.USER_LISTS_DIR, lists_dir, self._extra())
            after = {n: (lists_dir / n).read_bytes() for n in lists.USER_LISTS}
            if before != after:
                log.info("Списки обхода обновлены под настройки Telegram-прокси")
                self._apply_if_running()

    def prepare_pack(self) -> None:
        """Переносит в пакет пользовательские списки, режим IPSet и выбранные фейки."""
        assert self.pack is not None
        lists_dir = self.pack.path / "lists"
        lists.sync_user_lists(paths.USER_LISTS_DIR, lists_dir, self._extra())
        cfg = self.settings.get("zapret")
        if cfg["ipset_custom"]:
            self._apply_custom_ipset(lists_dir)
        mode = cfg["ipset_mode"]
        if mode and lists.detect_ipset_mode(lists_dir) != mode:
            try:
                lists.set_ipset_mode(lists_dir, mode)
            except ValueError as exc:
                log.warning("Режим IPSet %s не применён: %s", mode, exc)
        self._apply_fakes(cfg["fakes"])

    def _apply_custom_ipset(self, lists_dir: Path) -> None:
        """Скачанный человеком список IP — в пакет, если он годен и свежее списка самого пакета."""
        full_user = paths.USER_LISTS_DIR / FULL_IPSET_FILE
        try:
            fresh = full_user.read_text(encoding="utf-8", errors="replace")
            downloaded_at = full_user.stat().st_mtime
        except OSError:
            return
        if not lists.count_entries(fresh):
            log.warning("Скачанный список IP пуст или испорчен — остаётся список из пакета")
            return
        if self._pack_published_after(downloaded_at):
            # Новый пакет вышел позже, чем человек скачивал список: его список свежее.
            log.info("Список IP пакета %s свежее скачанного — беру его", self.pack.version)
            self.settings.update(lambda d: d["zapret"].__setitem__("ipset_custom", False))
            return
        current = lists.read_full_ipset(lists_dir)
        if current is None or current.strip() != lists.normalize_text(fresh).strip():
            lists.store_full_ipset(lists_dir, fresh)

    def _pack_published_after(self, stamp: float) -> bool:
        published = getattr(self.pack, "published_at", None)
        if not published:
            return False
        try:
            return datetime.fromisoformat(str(published).replace("Z", "+00:00")).timestamp() > stamp
        except ValueError:
            return False

    def build_args(self, strategy: strategies.Strategy) -> list[str]:
        assert self.pack is not None
        gf = self.settings.get("zapret", "game_filter")
        tcp, udp = gamefilter.port_values(gf["mode"], gf["tcp"], gf["udp"])
        legacy = gamefilter.legacy_value(gf["mode"], gf["tcp"], gf["udp"])
        return strategy.args(self.pack.path, game_tcp=tcp, game_udp=udp, game_any=legacy)

    def runtime_args(self, strategy: strategies.Strategy, record: bool = True) -> list[str]:
        """Аргументы запуска winws. Рядом с VPN — с фильтром только по прямым интерфейсам и без серверов
        VPN. Не собрался: при одних виртуальных сетях (Radmin, Hamachi) обход запускается как обычно; рядом
        с VPN в интернет (план strict) — не запускается вовсе (FilterRefused): обычный перехват задел бы
        туннель или соединение с сервером, и интернет пропал бы.
        record=False — для проб подбора: они не меняют то, что показывается о работающем обходе."""
        args = self.build_args(strategy)
        plan = None
        if self.vpn_plan is not None:
            try:
                plan = self.vpn_plan()
            except Exception as exc:  # noqa: BLE001
                log.exception("Сетевые адаптеры не прочитаны")
                if self.vpn_applied.get("mode") in ("vpn", "own"):
                    # Только что рядом был VPN — без осмотра адаптеров обычный перехват мог бы его задеть.
                    raise FilterRefused(f"Сетевые адаптеры не прочитаны ({exc}) — обход не запущен, чтобы не "
                                        "задеть VPN") from exc
        if not plan:
            if record:
                self.vpn_applied = {"mode": "plain"}
                self._alert("zapret-vpnfilter", None)   # фильтр под VPN больше не нужен — и плашка о нём
            return args
        own = [str(s) for s in plan.get("own_servers") or []]
        foreign = [s for s in plan["servers"] if str(s) not in own]
        # Свой сервер исключается всегда: совпади его адрес с Discord, обход менял бы транспорт своего VPN.
        targets = self._target_ips() if foreign else set()
        servers = vpnfilter.guard_servers(plan["servers"], targets, keep=own)[:vpnfilter.MAX_SERVERS]
        folder = paths.ZAPRET_DIR / "vpnfilter"
        try:
            path = vpnfilter.build(self.winws_exe, args, plan["interfaces"], servers,
                                   folder if record else folder / "probe", cache=folder / "base",
                                   keep_files=vpnfilter.KEEP_FILTERS if record else vpnfilter.KEEP_PROBES)
        except (vpnfilter.VpnFilterError, OSError, ValueError) as exc:
            log.warning("Фильтр для работы рядом с VPN не собран: %s", exc)
            strict = bool(plan.get("strict"))
            if record:
                self.vpn_applied = {"mode": "error", "error": str(exc), "interfaces": list(plan["interfaces"]),
                                    "servers_seen": list(plan["servers"])}
                if self.alert is not None or self._vpn_error_shown != str(exc):
                    self._vpn_error_shown = str(exc)
                    tail = ("Чтобы не оборвать VPN, обход не запущен." if strict else
                            "Обход работает как обычно и может задевать трафик VPN.")
                    self._alert("zapret-vpnfilter", "warn", f"Совместимость с VPN не включилась ({exc}). {tail}")
            if strict:
                raise FilterRefused(f"Совместимость с VPN не включилась ({exc}) — обход не запущен, чтобы не "
                                    "оборвать VPN") from exc
            return args
        if record:
            self._vpn_error_shown = None
            self._alert("zapret-vpnfilter", None)
            # «own» — совместимость выключена, а фильтр исключает только свой VPN Лазейки.
            self.vpn_applied = {"mode": plan.get("mode", "vpn"), "interfaces": list(plan["interfaces"]),
                                "servers": servers, "servers_seen": list(plan["servers"]), "at": time.time()}
        return vpnfilter.with_raw_filter(args, path)

    SERVICE_FILTER_STATE = "vpn-service.json"

    def _save_service_filter(self) -> None:
        """С каким фильтром настроена служба: иначе после перезапуска Лазейки она считала бы,
        что фильтра нет, и перенастраивала службу без нужды."""
        try:
            (paths.ZAPRET_DIR / self.SERVICE_FILTER_STATE).write_text(json.dumps(self.vpn_applied), encoding="utf-8")
        except OSError as exc:
            log.debug("Состояние фильтра службы не сохранено: %r", exc)

    def _load_service_filter(self) -> None:
        try:
            data = json.loads((paths.ZAPRET_DIR / self.SERVICE_FILTER_STATE).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        if isinstance(data, dict) and data.get("mode") in ("plain", "vpn", "own", "error"):
            self.vpn_applied = data

    def _target_ips(self) -> set[str]:
        """Адреса, по которым сейчас отвечают Discord и YouTube: сервер VPN с таким же адресом
        из перехвата не исключаем (VPN через CDN). Имена — параллельно и не дольше RESOLVE_TIMEOUT:
        запуск обхода идёт под блокировкой и без DNS ждал бы десятки секунд."""
        stamp, found = self._target_cache
        if found and time.monotonic() - stamp < TARGET_TTL:
            return found
        found = set()
        pool = ThreadPoolExecutor(max_workers=len(TARGET_HOSTS))
        futures = [pool.submit(_resolve, host) for host in TARGET_HOSTS]
        try:
            for fut in as_completed(futures, timeout=RESOLVE_TIMEOUT):
                found |= fut.result()
        except TimeoutError:
            log.info("DNS не ответил за %.0f с — адреса Discord и YouTube известны не все", RESOLVE_TIMEOUT)
        finally:
            pool.shutdown(wait=False, cancel_futures=True)
        if found:   # пустой ответ (DNS ещё не поднялся) не держим: следующий запуск спросит снова
            self._target_cache = (time.monotonic(), found)
        return found

    @property
    def winws_exe(self) -> Path:
        assert self.pack is not None
        return self.pack.path / "bin" / "winws.exe"

    # ------------------------------------------------------------ запуск

    def _check_ready(self) -> None:
        if not self.is_admin:
            raise ZapretError("Для запуска обхода нужны права администратора")
        if self.pack is None:
            raise ZapretError(self.unavailable_reason or "Пакет стратегий не установлен")

    def _ensure_not_testing(self) -> None:
        if self.paused_for_test:
            raise ZapretError(TESTING_ERROR)

    def start(self) -> None:
        with self.lock:
            self._check_ready()
            self._ensure_not_testing()
            self.guard_paused = False
            if self.mode == "service":
                self.status, self.error = "starting", None
                self._service_apply(start=True)   # не вышло — статус «ошибка» ставит сама
                self._remember_running(True)
                return
            current = self.process
            if current and current.alive():
                self.status = "running"
                return
            self.status, self.error = "starting", None
            try:
                strategy = self.strategy()
                self._prestart_cleanup()
                self.prepare_pack()
                if self.settings.get("zapret", "tcp_timestamps"):
                    netcfg.ensure_tcp_timestamps()
                holder: dict = {}
                args = self.runtime_args(strategy)
                online = self._probe_online()
                proc = WinwsProcess(self.winws_exe, args, label=strategy.label,
                                    on_exit=lambda code, tail: self._on_crash(holder.get("proc"), code, tail))
                holder["proc"] = proc
                proc.start()
            except (RunnerError, ZapretError, OSError, ValueError) as exc:
                self._start_failed(str(exc), refused=isinstance(exc, FilterRefused))
                raise ZapretError(str(exc)) from exc
            except Exception as exc:
                # Неожиданное — тоже ошибка запуска: «запускается» навсегда не нажать (кнопка ждёт конца).
                self._start_failed(repr(exc))
                raise
            self.process = proc
            self.status = "running"
            self._filter_retries = 0
            self._remember_running(True)
            self._started(online)

    def _start_failed(self, error: str, refused: bool = False) -> None:
        self.status, self.error = "error", error
        self.process = None
        if refused and self._filter_retries < FILTER_RETRIES:
            # Фильтр совместимости не собрался (файл занят, DLL не загрузилась) — бывает на секунды.
            self._filter_retries += 1
            log.info("Повторю запуск обхода через %.0f с (попытка %d из %d)", FILTER_RETRY_DELAY,
                     self._filter_retries, FILTER_RETRIES)
            timer = threading.Timer(FILTER_RETRY_DELAY, self._auto_restart)
            timer.daemon = True
            timer.start()

    def _probe_online(self) -> bool | None:
        """Есть ли связь, пока новый winws ещё не запущен (страховка Core); None — не проверяли."""
        if self.guard_probe is None:
            return None
        try:
            return self.guard_probe()
        except Exception:  # noqa: BLE001 — проверка связи не мешает запуску обхода
            log.debug("Связь перед запуском обхода не проверена", exc_info=True)
            return None

    def _started(self, online: bool | None) -> None:
        """winws запущен Лазейкой — страховке Core пора смотреть, не пропал ли интернет."""
        if self.on_started is None:
            return
        try:
            self.on_started(online)
        except Exception:  # noqa: BLE001
            log.exception("Страховка связи не взведена")

    def stop(self, remember: bool = True, hold: bool | None = None) -> None:
        """remember=False — временно (перезапуск, подбор, страховка связи): включённым обход остаётся
        в настройках, а служба — в автозапуске Windows. hold — снять службу с автозапуска и без запоминания
        (страховка связи: с обходом пропадал интернет, а без Лазейки службу проверить некому)."""
        with self.lock:
            self.guard_paused = False
            if self.mode == "service":
                if self.is_admin:
                    self._stop_service(hold=remember if hold is None else hold)
            else:
                current = self.process
                if current:
                    self.status = "stopping"
                    current.stop()
                    self.process = None
            self.status, self.error = "stopped", None
            if remember:
                self._remember_running(False)

    def _stop_service(self, hold: bool) -> None:
        """hold — выключил человек: служба больше не стартует вместе с Windows (до «Включить»)."""
        try:
            stopped = winutil.service_stop(SERVICE_NAME)
        except winutil.ServiceError as exc:
            raise ZapretError(str(exc)) from exc
        if not stopped:
            raise ZapretError(SERVICE_STOP_ERROR)
        if hold and winutil.service_query(SERVICE_NAME) is not None:
            try:
                winutil.service_set_start(SERVICE_NAME, auto=False)
            except winutil.ServiceError as exc:
                log.warning("Служба обхода остановлена, но запуск вместе с Windows не выключен: %s", exc)

    def restart(self) -> None:
        with self.lock:
            self.stop(remember=False)
            self.start()

    def running(self) -> bool:
        if self.mode == "service":
            info = winutil.service_query(SERVICE_NAME)
            return info is not None and info.state == "running"
        current = self.process
        return bool(current and current.alive())

    def _remember_running(self, value: bool) -> None:
        self.settings.update(lambda d: d["zapret"].__setitem__("was_running", value))

    def _prestart_cleanup(self) -> None:
        current = self.process
        own = {current.pid} if current and current.pid else set()
        own_service = winutil.service_query(SERVICE_NAME)
        if own_service and own_service.state == "running" and self.mode == "app":
            # Осталась служба от режима «служба Windows»: два winws с одним фильтром не уживаются.
            if not winutil.service_stop(SERVICE_NAME):
                raise ZapretError(SERVICE_STOP_ERROR)
        others = foreign_winws(own)
        if others:
            raise ZapretError("Уже работает другой winws.exe (оригинальный zapret или другая программа). "
                              "Остановите его на странице «Обход» → конфликты.")

    def _on_crash(self, proc: WinwsProcess | None, code: int, tail: list[str]) -> None:
        from .runner import explain_failure
        with self.lock:
            if proc is None or self.process is not proc:
                return  # запоздалое сообщение о процессе, который уже заменён новым
            ran_for = time.time() - (proc.started_at or time.time())
            self.process = None
            self.status, self.error = "error", explain_failure(code, tail)
        log.error("Обход остановился: %s", self.error)
        now = time.time()
        self._restarts = [t for t in self._restarts if now - t < 3600]
        # Падение замечено без нажатия человека — плашка на главной (на странице обхода и так видна
        # ошибка), Core снимет её, когда обход снова заработает.
        if ran_for > 60 and len(self._restarts) < 3:
            self._restarts.append(now)
            self._alert("zapret-down", "warn", "winws неожиданно остановился — перезапускаем.", page=None)
            threading.Timer(3.0, self._auto_restart).start()
        else:
            self._alert("zapret-down", "error", f"Обход остановился: {self.error}", action=_RETRY, page=None)

    def _auto_restart(self) -> None:
        try:
            if self.status == "error" and not self.paused_for_test:
                self.start()
        except Exception as exc:  # noqa: BLE001 — поток таймера: ошибку видно только плашкой
            if not isinstance(exc, ZapretError):
                log.exception("Обход не перезапустился сам")
            self._alert("zapret-down", "error", f"Обход остановился, а перезапуск не удался: {exc}", action=_RETRY,
                        page=None)

    # ------------------------------------------------------------ настройки

    # Пока идёт подбор, настройки обхода не меняются: пробы оцениваются при одних и тех же условиях,
    # а служба Windows не перенастраивается у подбора за спиной.

    def set_strategy(self, strategy_id: str) -> None:
        with self.lock:
            self._ensure_not_testing()
            self.strategy(strategy_id)
            self.settings.update(lambda d: d["zapret"].__setitem__("strategy", strategy_id))
            self._apply_if_running()

    def set_game_filter(self, mode: str, tcp: str, udp: str) -> dict[str, str]:
        errors = {}
        if mode not in gamefilter.MODES:
            errors["mode"] = "Неизвестный режим"
        tcp_v = gamefilter.validate_range(tcp)
        udp_v = gamefilter.validate_range(udp)
        if tcp_v is None:
            errors["tcp"] = "Порты через запятую или диапазоны 1–65535, например 1024-65535"
        if udp_v is None:
            errors["udp"] = "Порты через запятую или диапазоны 1–65535, например 1024-65535"
        if errors:
            return errors
        with self.lock:
            self._ensure_not_testing()
            self.settings.update(lambda d: d["zapret"].__setitem__(
                "game_filter", {"mode": mode, "tcp": tcp_v, "udp": udp_v}))
            self._apply_if_running()
        return {}

    def set_ipset(self, mode: str) -> None:
        if mode not in lists.IPSET_MODES:
            raise ZapretError("Неизвестный режим IPSet")
        with self.lock:
            self._check_ready()
            self._ensure_not_testing()
            lists.set_ipset_mode(self.pack.path / "lists", mode)
            self.settings.update(lambda d: d["zapret"].__setitem__("ipset_mode", mode))
            self._apply_if_running()

    def store_ipset(self, text: str) -> int:
        with self.lock:
            self._check_ready()
            self._ensure_not_testing()
            # Сначала в пакет: пустой или испорченный список store_full_ipset отвергает — тогда своя
            # копия не пишется вовсе и при следующем запуске не сломает подготовку пакета.
            lists_dir = self.pack.path / "lists"
            count = lists.store_full_ipset(lists_dir, text)
            paths.USER_LISTS_DIR.mkdir(parents=True, exist_ok=True)
            # Копия — в том же виде, что в пакете: prepare_pack сравнивает их как есть.
            (paths.USER_LISTS_DIR / FULL_IPSET_FILE).write_bytes(
                (lists.read_full_ipset(lists_dir) or lists.normalize_text(text)).encode("utf-8"))
            self.settings.update(lambda d: d["zapret"].__setitem__("ipset_custom", True))
            if lists.detect_ipset_mode(self.pack.path / "lists") == "loaded":
                self._apply_if_running()
            return count

    def reapply_for_network(self) -> bool:
        """Сменился набор сетевых интерфейсов или появился VPN — перезапустить обход с новым
        фильтром. Во время подбора не трогаем: подбор сам вернёт обход с актуальным фильтром."""
        with self.lock:
            if self.paused_for_test or self.status not in ("running", "error"):
                return False
            if self.mode == "service" and not winutil.service_query(SERVICE_NAME):
                return False
            log.info("Сеть изменилась — перезапускаю обход с новым фильтром интерфейсов")
            self._apply_if_running()
            return True

    def _apply_if_running(self) -> None:
        current = self.process
        if self.mode == "service":
            if winutil.service_query(SERVICE_NAME):
                self._service_apply(start=self.running())
        elif current and current.alive():
            self.stop(remember=False)
            self.start()

    def set_mode(self, mode: str) -> None:
        if mode not in ("app", "service"):
            raise ZapretError("Неизвестный режим")
        with self.lock:
            self._check_ready()
            self._ensure_not_testing()
            if mode == self.mode:
                return
            was_running = self.running() or self.settings.get("zapret", "was_running")
            if mode == "service":
                current = self.process
                if current:
                    current.stop()
                    self.process = None
                self.settings.update(lambda d: d["zapret"].__setitem__("mode", "service"))
                self._service_apply(start=was_running)
            else:
                try:
                    # Неостановленная служба после удаления работала бы дальше рядом с winws Лазейки.
                    if not winutil.service_stop(SERVICE_NAME):
                        raise ZapretError(f"{SERVICE_STOP_ERROR}; режим не изменён")
                    winutil.service_delete(SERVICE_NAME)
                except winutil.ServiceError as exc:
                    raise ZapretError(f"Служба не удалена: {exc}") from exc
                self._alert(SERVICE_ALERT, None)
                self.settings.update(lambda d: d["zapret"].__setitem__("mode", "app"))
                self.status = "stopped"
                if was_running:
                    self.start()

    def _service_apply(self, start: bool) -> None:
        """Создаёт или перенастраивает службу под текущие стратегию и пакет. Не вышло — статус «ошибка»
        (не «запускается» навсегда) и ZapretError."""
        try:
            self._service_configure(start)
        except ZapretError as exc:
            self._service_failed(str(exc), start, refused=isinstance(exc, FilterRefused))
            raise
        except (winutil.ServiceError, RunnerError, OSError, ValueError) as exc:
            self._service_failed(str(exc), start)
            raise ZapretError(str(exc)) from exc
        except Exception as exc:
            self._service_failed(repr(exc), start)
            raise

    def _service_failed(self, error: str, start: bool, refused: bool = False) -> None:
        """Запускали — статус «ошибка» (с повтором, если не собрался фильтр совместимости). Только
        перенастраивали остановленную службу — она так и стоит, ошибку увидит тот, кто настраивал."""
        if start:
            self._start_failed(error, refused=refused)
        elif self.status == "starting":
            self.status, self.error = "error", error

    def _service_configure(self, start: bool) -> None:
        self._check_ready()
        strategy = self.strategy()
        self.prepare_pack()
        if self.settings.get("zapret", "tcp_timestamps"):
            netcfg.ensure_tcp_timestamps()
        current = self.process
        if current:
            current.stop()
            self.process = None
        others = foreign_winws(set())
        own = winutil.service_query(SERVICE_NAME)
        own_pid = own.pid if own else 0
        if any(p.pid != own_pid for p in others):
            raise ZapretError("Уже работает другой winws.exe — сначала устраните конфликт.")
        binary = strategies.command_line(self.winws_exe, self.runtime_args(strategy))
        if own and own.state != "stopped" and not winutil.service_stop(SERVICE_NAME):
            raise ZapretError("Служба обхода не остановилась за 10 секунд — перенастройка отменена")
        # Вместе с Windows служба стартует, только пока обход должен работать: выключенный человеком
        # обход после перезагрузки не включается сам.
        auto = start or bool(self.settings.get("zapret", "was_running"))
        winutil.service_create_or_update(SERVICE_NAME, SERVICE_DISPLAY, binary, SERVICE_DESCRIPTION,
                                         auto_start=auto, depends_on=("BFE",), restart_on_failure=True)
        self._save_service_filter()
        self._alert(SERVICE_ALERT, None)
        if start:
            self._start_service()
        else:
            self.status = "stopped"
        log.info("Служба %s настроена на стратегию «%s»%s", SERVICE_NAME, strategy.label,
                 " и запущена" if start else "")

    def _start_service(self) -> None:
        online = self._probe_online()
        winutil.service_start(SERVICE_NAME)
        self.status, self.error = "running", None
        self._filter_retries = 0
        self._started(online)

    def resume_service(self) -> None:
        """Подбор закончился (или был прерван вместе с Лазейкой) — снова запустить службу. Её настройки
        подбор не менял; списки, отложенные на время подбора, переносятся сейчас."""
        with self.lock:
            try:
                self.prepare_pack()
                self._start_service()
            except (winutil.ServiceError, OSError, ValueError) as exc:
                self.status, self.error = "error", str(exc)
                raise ZapretError(str(exc)) from exc

    def report_down(self, text: str) -> None:
        """Обход лежит не по воле человека (подбор не вернул его) — плашка с «Включить снова»."""
        self._alert("zapret-down", "error", text, action=_RETRY, page=None)

    def switch_pack(self, info: pack.PackInfo) -> None:
        """Переключение на только что установленный пакет (из обновлений или отката)."""
        with self.lock:
            self._ensure_not_testing()
            was = self.running()
            if was and self.mode == "app":
                self.stop(remember=False)
            self._activate_pack(info)
            if self.mode == "service" and winutil.service_query(SERVICE_NAME):
                self._service_apply(start=was)
            elif was:
                self.start()

    # ------------------------------------------------------------ состояние

    def refresh_status(self) -> None:
        if self.mode == "service":
            info = winutil.service_query(SERVICE_NAME)  # чтение состояния прав администратора не требует
            if info is None:
                if self.status == "running":
                    self.status = "stopped"
            elif info.state == "running":
                self.status, self.error = "running", None
            elif info.state in ("start_pending",):
                self.status = "starting"
            elif info.state in ("stop_pending",):
                self.status = "stopping"
            elif self.status != "error":
                self.status = "stopped"
        else:
            current = self.process
            if self.status == "running" and not (current and current.alive()):
                self.status = "stopped" if self.error is None else "error"

    def ipset_info(self) -> dict:
        """Режим IPSet и число подсетей; файл на 0,5 МБ перечитывается только при изменении."""
        if not self.pack:
            return {"mode": self.settings.get("zapret", "ipset_mode") or "none", "count": 0}
        lists_dir = self.pack.path / "lists"
        stamp = []
        for name in (lists.IPSET_FILE, lists.IPSET_BACKUP):
            try:
                st = (lists_dir / name).stat()
                stamp.append((st.st_mtime_ns, st.st_size))
            except OSError:
                stamp.append(None)
        key = (str(lists_dir), tuple(stamp))
        cached = getattr(self, "_ipset_cache", None)
        if cached and cached[0] == key:
            return cached[1]
        info = {"mode": lists.detect_ipset_mode(lists_dir),
                "count": lists.count_entries(lists.read_full_ipset(lists_dir))}
        self._ipset_cache = (key, info)
        return info

    def service_info(self) -> dict:
        info = winutil.service_query(SERVICE_NAME)
        return {"installed": info is not None, "running": bool(info and info.state == "running"),
                "strategy": self.settings.get("zapret", "strategy") if info else None}

    def conflicts(self) -> list[dict]:
        found = []
        for name in FOREIGN_SERVICES:
            info = winutil.service_query(name)
            if info is None:
                continue
            if name == "zapret":
                strat = _original_zapret_strategy()
                text = ("Найдена служба zapret из оригинального пакета"
                        + (f" (стратегия «{strat}»)" if strat else "")
                        + ". Она будет мешать — две копии winws не уживаются.")
            else:
                text = f"Найдена служба {name} — другой обход блокировок, он конфликтует с zapret."
            found.append({"id": f"service:{name}", "text": text, "fix_label": "Удалить службу"})
        current = self.process
        own_pids = {current.pid} if current and current.pid else set()
        own = winutil.service_query(SERVICE_NAME)
        if own and own.pid:
            own_pids.add(own.pid)
        # Во время подбора winws запускает сам подборщик — это не посторонний процесс.
        others = [] if self.paused_for_test else foreign_winws(own_pids)
        if others:
            found.append({"id": "process:winws",
                          "text": f"Запущен посторонний winws.exe ({len(others)} шт.) — например, из папки "
                                  "оригинального zapret.",
                          "fix_label": "Остановить"})
        if own and self.mode == "app":
            found.append({"id": "service:own", "text": "Осталась служба Лазейки от режима «служба Windows».",
                          "fix_label": "Удалить службу"})
        return found

    def fix_conflict(self, conflict_id: str) -> str:
        if not self.is_admin:
            raise ZapretError("Нужны права администратора")
        self._ensure_not_testing()
        if conflict_id == "process:winws":
            current = self.process
            own = {current.pid} if current and current.pid else set()
            procs = foreign_winws(own)
            kill_processes(procs)
            return f"Остановлено процессов: {len(procs)}"
        if conflict_id == "service:own":
            winutil.service_delete(SERVICE_NAME)
            return "Служба удалена"
        if conflict_id.startswith("service:"):
            name = conflict_id.split(":", 1)[1]
            if name not in FOREIGN_SERVICES:
                raise ZapretError("Неизвестная служба")
            winutil.service_delete(name)
            if not foreign_winws(set()):
                netcfg.remove_windivert()
            return f"Служба {name} удалена"
        raise ZapretError("Неизвестный конфликт")

    # ------------------------------------------------------------ списки и фейки

    def lists_get(self) -> list[dict]:
        out = []
        if self.is_admin:
            lists.ensure_user_lists(paths.USER_LISTS_DIR)
        for name, (title, hint, _default) in lists.USER_LISTS.items():
            path = paths.USER_LISTS_DIR / name
            text = path.read_text(encoding="utf-8", errors="replace") if path.is_file() else ""
            out.append({"id": name, "title": title, "hint": hint, "text": text, "editable": self.is_admin})
        if self.pack:
            for name, (title, hint) in lists.BUILTIN_LISTS.items():
                path = self.pack.path / "lists" / name
                text = path.read_text(encoding="utf-8", errors="replace") if path.is_file() else ""
                out.append({"id": name, "title": title, "hint": hint, "text": text, "editable": False})
        return out

    def lists_save(self, name: str, text: str) -> None:
        if not self.is_admin:
            raise ZapretError("Изменять списки можно только с правами администратора")
        if len(text) > 2_000_000:
            raise ZapretError("Список слишком большой")
        with self.lock:
            self._ensure_not_testing()
            lists.save_user_list(paths.USER_LISTS_DIR, name, text)
            if self.pack:
                lists.sync_user_lists(paths.USER_LISTS_DIR, self.pack.path / "lists", self._extra())
            self._apply_if_running()

    def fakes_get(self) -> dict:
        if not self.pack:
            return {"files": [], "discord": None, "game": None}
        bin_dir = self.pack.path / "bin"
        files = sorted(p.stem for p in bin_dir.glob("*.bin") if not p.stem.upper().startswith("ACTIVE_"))
        chosen = self.settings.get("zapret", "fakes")
        return {"files": files, "discord": chosen.get("discord"), "game": chosen.get("game")}

    def fakes_set(self, slot: str, name: str | None) -> None:
        if slot not in ACTIVE_FAKES:
            raise ZapretError("Неизвестный тип фейка")
        if name is not None and name not in self.fakes_get()["files"]:
            raise ZapretError("Такого файла нет в пакете")
        with self.lock:
            self._check_ready()
            self._ensure_not_testing()
            self.settings.update(lambda d: d["zapret"]["fakes"].__setitem__(slot, name))
            self._apply_fakes(self.settings.get("zapret", "fakes"))
            self._apply_if_running()

    def _apply_fakes(self, chosen: dict) -> None:
        if not self.pack:
            return
        bin_dir = self.pack.path / "bin"
        for slot, active_name in ACTIVE_FAKES.items():
            active = bin_dir / active_name
            original = bin_dir / (active_name + ".orig")
            if active.is_file() and not original.exists():
                shutil.copyfile(active, original)
            source = bin_dir / f"{chosen.get(slot)}.bin" if chosen.get(slot) else original
            if source.is_file() and _digest(source) != (_digest(active) if active.is_file() else None):
                shutil.copyfile(source, active)


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _resolve(host: str) -> set[str]:
    try:
        return {info[4][0].split("%")[0] for info in socket.getaddrinfo(host, 443)}
    except OSError:
        return set()


def _original_zapret_strategy() -> str | None:
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\zapret") as key:
            value, _ = winreg.QueryValueEx(key, "zapret-discord-youtube")
            return str(value)
    except OSError:
        return None
