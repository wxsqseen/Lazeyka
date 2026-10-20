"""ZapretManager без системы: winws, службы Windows и DNS — подделки. Страховка связи (хуки запуска),
служба (тип запуска, «не остановилась»), статус «запускается» не застревает, повторный init, IPSet,
фильтр совместимости рядом с VPN, настройки во время подбора."""
import threading
import time
from types import SimpleNamespace

import pytest

from app.settings import Settings
from app.zapret import manager as M
from app.zapret import vpnfilter
from app.zapret.strategies import Strategy


class FakeProc:
    """WinwsProcess: start() записывает событие, живёт до stop()."""
    started: list["FakeProc"] = []

    def __init__(self, exe, args, label, on_exit=None):
        self.args, self.label, self.on_exit = args, label, on_exit
        self.pid, self.started_at, self._alive = 4000 + len(FakeProc.started), time.time(), False
        self.events = None

    def start(self, ready_timeout=6.0):
        self._alive = True
        FakeProc.started.append(self)
        if self.events is not None:
            self.events.append(("winws",))

    def alive(self):
        return self._alive

    def stop(self, timeout=5.0):
        self._alive = False


class FakeServices:
    """Службы Windows в памяти: состояние, тип запуска, «не остановилась за 10 секунд»."""

    def __init__(self):
        self.items: dict[str, dict] = {}
        self.stop_ok = True
        self.log: list[tuple] = []

    def query(self, name, with_config=False):
        item = self.items.get(name)
        if item is None:
            return None
        return SimpleNamespace(name=name, state=item["state"], pid=item.get("pid", 0), binary=item.get("binary"),
                               start_type=M.winutil.SERVICE_AUTO_START if item.get("auto")
                               else M.winutil.SERVICE_DEMAND_START)

    def create_or_update(self, name, display, binary, description, auto_start=True, depends_on=(),
                         restart_on_failure=False):
        item = self.items.setdefault(name, {"state": "stopped"})
        item.update(binary=binary, auto=auto_start)
        self.log.append(("create", name, auto_start))

    def start(self, name):
        self.log.append(("start", name))
        self.items[name]["state"] = "running"
        self.items[name]["pid"] = 777

    def stop(self, name, wait=10.0):
        self.log.append(("stop", name))
        if name not in self.items:
            return True
        if not self.stop_ok:
            return False
        self.items[name]["state"] = "stopped"
        return True

    def set_start(self, name, auto):
        self.log.append(("set_start", name, auto))
        self.items[name]["auto"] = auto

    def delete(self, name):
        self.log.append(("delete", name))
        return self.items.pop(name, None) is not None


@pytest.fixture
def zm(tmp_path, monkeypatch):
    settings = Settings(tmp_path / "s.json")
    notes, alerts, events = [], {}, []
    z = M.ZapretManager(settings, lambda level, text: notes.append((level, text)), True)
    for sub in ("bin", "lists", "user", "data"):
        (tmp_path / sub).mkdir()
    z.pack = SimpleNamespace(path=tmp_path, version="1.10.3", published_at=None)
    z.strategies = [Strategy("general", "Стандартная", tmp_path / "general.bat", "--wf-tcp=443"),
                    Strategy("general (ALT)", "ALT", tmp_path / "alt.bat", "--wf-tcp=443 --new")]
    monkeypatch.setattr(z, "prepare_pack", lambda: None)
    monkeypatch.setattr(M.netcfg, "ensure_tcp_timestamps", lambda: None)
    monkeypatch.setattr(M, "foreign_winws", lambda exclude: [])
    monkeypatch.setattr(M.paths, "USER_LISTS_DIR", tmp_path / "user")
    monkeypatch.setattr(M.paths, "ZAPRET_DIR", tmp_path / "data")
    services = FakeServices()
    for name, fn in (("service_query", services.query), ("service_create_or_update", services.create_or_update),
                     ("service_start", services.start), ("service_stop", services.stop),
                     ("service_set_start", services.set_start), ("service_delete", services.delete)):
        monkeypatch.setattr(M.winutil, name, fn)
    FakeProc.started = []

    def proc(*a, **k):
        p = FakeProc(*a, **k)
        p.events = events
        return p
    monkeypatch.setattr(M, "WinwsProcess", proc)
    z.alert = lambda alert_id, level, text=None, action=None, page=None: (
        alerts.pop(alert_id, None) if level is None else alerts.__setitem__(alert_id, (level, text, action)))
    z.guard_probe = lambda: events.append(("probe", z.status, any(p.alive() for p in FakeProc.started))) or True
    z.on_started = lambda online: events.append(("started", z.status, online))
    return SimpleNamespace(z=z, settings=settings, notes=notes, alerts=alerts, events=events, services=services,
                           tmp=tmp_path)


# ------------------------------------------------------------ страховка связи: хуки запуска

def test_start_probes_before_winws_and_arms_guard_after(zm):
    zm.z.start()
    assert zm.events == [("probe", "starting", False), ("winws",), ("started", "running", True)]


def test_every_restart_by_lazeyka_arms_guard(zm):
    """Смена стратегии, игрового фильтра, IPSet, перезапуск и авто-перезапуск — тоже запуски winws."""
    z = zm.z
    z.start()
    z.set_strategy("general (ALT)")
    z.set_game_filter("all", "1024-65535", "1024-65535")
    z.restart()
    starts = [e for e in zm.events if e[0] == "started"]
    assert len(starts) == 4 and all(e[1] == "running" for e in starts)
    current = z.process
    z._on_crash(current, 1, ["error"])                       # упал сразу — без авто-перезапуска
    z.status, z.error = "error", "упал"
    z._auto_restart()
    assert len([e for e in zm.events if e[0] == "started"]) == 5


def test_service_start_probes_before_service_and_arms_after(zm):
    z, services = zm.z, zm.services
    zm.settings.update(lambda d: d["zapret"].__setitem__("mode", "service"))
    z.start()
    assert ("create", M.SERVICE_NAME, True) in services.log, "включён — служба стартует вместе с Windows"
    assert [e[0] for e in zm.events] == ["probe", "started"]
    assert services.log.index(("start", M.SERVICE_NAME)) > services.log.index(("create", M.SERVICE_NAME, True))
    assert zm.events[1] == ("started", "running", True)


def test_resume_service_after_test_arms_guard(zm):
    zm.settings.update(lambda d: d["zapret"].__setitem__("mode", "service"))
    zm.services.items[M.SERVICE_NAME] = {"state": "stopped", "auto": True}
    zm.z.resume_service()
    assert zm.z.status == "running" and [e[0] for e in zm.events] == ["probe", "started"]


# ------------------------------------------------------------ служба Windows

def test_service_turned_off_by_person_does_not_start_with_windows(zm):
    z, services = zm.z, zm.services
    zm.settings.update(lambda d: d["zapret"].__setitem__("mode", "service"))
    z.start()
    z.stop(remember=False)                                    # перезапуск, подбор, страховка — временно
    assert services.items[M.SERVICE_NAME]["auto"] is True
    z.start()
    z.stop()                                                  # выключил человек
    assert ("set_start", M.SERVICE_NAME, False) in services.log
    assert services.items[M.SERVICE_NAME]["auto"] is False and z.status == "stopped"
    z.start()
    assert services.items[M.SERVICE_NAME]["auto"] is True, "включили снова — снова вместе с Windows"


def test_reconfigured_stopped_service_stays_manual(zm):
    zm.settings.update(lambda d: d["zapret"].update(mode="service", was_running=False))
    zm.z._service_apply(start=False)
    assert ("create", M.SERVICE_NAME, False) in zm.services.log


def test_service_left_on_windows_autostart_by_old_version_is_made_manual(zm):
    """До 1.3 выключенная человеком служба оставалась «Автоматически» и после перезагрузки включала обход сама.
    Запуск Лазейки это выправляет; работающую или включённую службу не трогает."""
    z, services = zm.z, zm.services
    zm.settings.update(lambda d: d["zapret"].update(mode="service", was_running=False))
    services.items[M.SERVICE_NAME] = {"state": "stopped", "auto": True}
    z._align_service_start()
    assert services.items[M.SERVICE_NAME]["auto"] is False
    services.log.clear()
    services.items[M.SERVICE_NAME] = {"state": "running", "auto": True}
    z._align_service_start()
    zm.settings.update(lambda d: d["zapret"].__setitem__("was_running", True))
    services.items[M.SERVICE_NAME] = {"state": "stopped", "auto": True}
    z._align_service_start()
    assert services.log == [], "работающую службу и включённый обход не трогаем"


def test_service_that_did_not_stop_is_not_reported_stopped(zm):
    z, services = zm.z, zm.services
    zm.settings.update(lambda d: d["zapret"].__setitem__("mode", "service"))
    z.start()
    services.stop_ok = False
    with pytest.raises(M.ZapretError, match="не остановилась"):
        z.stop()
    assert z.status == "running" and zm.settings.get("zapret", "was_running") is True


def test_switching_to_app_mode_refuses_while_service_runs(zm):
    z, services = zm.z, zm.services
    zm.settings.update(lambda d: d["zapret"].__setitem__("mode", "service"))
    z.start()
    services.stop_ok = False
    with pytest.raises(M.ZapretError, match="не остановилась"):
        z.set_mode("app")
    assert M.SERVICE_NAME in services.items and zm.settings.get("zapret", "mode") == "service"


def test_service_start_with_foreign_winws_ends_in_error_not_starting(zm, monkeypatch):
    """service_stuck.py: служба ещё не создана, рядом оригинальный zapret — кнопка питания не залипает."""
    zm.settings.update(lambda d: d["zapret"].__setitem__("mode", "service"))
    monkeypatch.setattr(M, "foreign_winws", lambda exclude: [SimpleNamespace(pid=4242)])
    with pytest.raises(M.ZapretError, match="другой winws"):
        zm.z.start()
    for _ in range(3):
        zm.z.refresh_status()
    assert zm.z.status == "error" and "другой winws" in zm.z.error


def test_unexpected_start_failure_is_error_status(zm, monkeypatch):
    def broken(*a, **k):
        raise KeyError("нет ключа")
    monkeypatch.setattr(M, "WinwsProcess", broken)
    with pytest.raises(KeyError):
        zm.z.start()
    assert zm.z.status == "error" and zm.z.process is None


def test_leftover_service_that_wont_stop_blocks_app_start(zm):
    zm.services.items[M.SERVICE_NAME] = {"state": "running"}
    zm.services.stop_ok = False
    with pytest.raises(M.ZapretError, match="не остановилась"):
        zm.z.start()
    assert zm.z.status == "error" and not FakeProc.started


# ------------------------------------------------------------ во время подбора

def test_settings_are_frozen_while_strategy_test_runs(zm):
    z = zm.z
    z.paused_for_test = True
    for action in (lambda: z.set_strategy("general (ALT)"), lambda: z.set_game_filter("all", "1-2", "1-2"),
                   lambda: z.set_ipset("any"), lambda: z.store_ipset("1.1.1.0/24\n"),
                   lambda: z.lists_save("list-general-user.txt", "site.ru\n"), lambda: z.fakes_set("discord", None)):
        with pytest.raises(M.ZapretError, match="Идёт подбор"):
            action()
    assert zm.settings.get("zapret", "strategy") == "general"
    z.refresh_extra_lists()   # из настроек Telegram — не ошибка: отложено до запуска после подбора


# ------------------------------------------------------------ повторный init

def _init_world(zm, monkeypatch, *, ensure, newest=None, problem=None, wanted="1.10.3"):
    info = SimpleNamespace(version="1.10.3", path=zm.tmp, published_at=None)
    zm.settings.update(lambda d: d["zapret"].__setitem__("pack", wanted))
    zm.z.pack = None
    monkeypatch.setattr(M.pack, "find", lambda v: None)
    monkeypatch.setattr(M.pack, "problem_of", lambda v: problem)
    monkeypatch.setattr(M.pack, "ensure_bundled", ensure)
    monkeypatch.setattr(M.pack, "newest", lambda: newest)
    monkeypatch.setattr(M.pack, "installed", lambda: [info])
    monkeypatch.setattr(M.pack, "cleanup", lambda keep: None)
    monkeypatch.setattr(M.lists, "adopt_user_lists", lambda *a, **k: None)
    monkeypatch.setattr(M.lists, "ensure_user_lists", lambda *a, **k: None)
    monkeypatch.setattr(zm.z, "_activate_pack", lambda i: setattr(zm.z, "pack", i))
    monkeypatch.setattr(zm.z, "_recover_interrupted_test", lambda: None)
    monkeypatch.setattr(zm.z, "_service_pack_version", lambda: None)
    return info


def test_reinit_after_defender_clears_old_reason(zm, monkeypatch):
    """reinit.py: Defender удалил драйвер, человек добавил исключение — пакет встал, обход доступен сразу."""
    state = {"broken": True}
    info = SimpleNamespace(version="1.10.3", path=zm.tmp, published_at=None)

    def ensure():
        if state["broken"]:
            raise M.pack.PackError("в пакете нет bin\\WinDivert64.sys")
        return info, True
    _init_world(zm, monkeypatch, ensure=ensure)
    zm.z.init()
    assert not zm.z.available and "WinDivert64" in zm.z.unavailable_reason
    state["broken"] = False
    zm.z.init()
    assert zm.z.available and zm.z.unavailable_reason is None


def test_service_alignment_failure_is_alert_not_unavailable(zm, monkeypatch):
    info = SimpleNamespace(version="1.10.3", path=zm.tmp, published_at=None)
    _init_world(zm, monkeypatch, ensure=lambda: (info, False))

    def refuse():
        raise M.ZapretError("Уже работает другой winws.exe — сначала устраните конфликт.")
    monkeypatch.setattr(zm.z, "_align_service", refuse)
    zm.z.init()
    assert zm.z.available, "служба работает по-старому — обход не «недоступен»"
    assert "другой winws" in zm.alerts[M.SERVICE_ALERT][1]


def test_init_survives_value_error(zm, monkeypatch):
    info = SimpleNamespace(version="1.10.3", path=zm.tmp, published_at=None)
    _init_world(zm, monkeypatch, ensure=lambda: (info, False))
    monkeypatch.setattr(zm.z, "prepare_pack", lambda: (_ for _ in ()).throw(ValueError("испорченный список")))
    zm.z.init()                                               # Лазейка запускается, обход — с причиной
    assert "испорченный список" in zm.z.unavailable_reason


def test_broken_pack_notice_tells_what_really_happened(zm, monkeypatch):
    info = SimpleNamespace(version="1.10.3", path=zm.tmp, published_at=None)
    _init_world(zm, monkeypatch, ensure=lambda: (info, True), problem="нет bin\\WinDivert64.sys")
    zm.z.init()
    assert "поставлен заново из встроенной копии" in zm.notes[-1][1]
    newer = SimpleNamespace(version="1.11.0", path=zm.tmp, published_at=None)
    _init_world(zm, monkeypatch, ensure=lambda: (None, False), newest=newer, problem="нет bin\\WinDivert64.sys")
    zm.z.init()
    text = zm.notes[-1][1]
    assert "заново" not in text and "работает на пакете 1.11.0" in text


def test_strategy_replacement_notice_uses_names_from_window(zm, tmp_path, monkeypatch):
    zm.settings.update(lambda d: d["zapret"].__setitem__("strategy", "general (ALT9)"))
    info = SimpleNamespace(version="1.10.4", path=tmp_path, published_at=None)
    monkeypatch.setattr(M.strategies, "discover", lambda path: (list(zm.z.strategies), []))
    zm.z._activate_pack(info)
    text = zm.notes[-1][1]
    assert "«ALT9»" in text and "«Стандартная»" in text and "general" not in text


# ------------------------------------------------------------ IPSet

def test_empty_ipset_download_is_rejected_before_anything_is_written(zm):
    with pytest.raises(ValueError, match="пуст"):
        zm.z.store_ipset("")
    assert not (zm.tmp / "user" / M.FULL_IPSET_FILE).exists()
    assert zm.settings.get("zapret", "ipset_custom") is False
    with pytest.raises(ValueError, match="испорчен"):
        zm.z.store_ipset("<html>Ошибка 404</html>\n")
    assert not (zm.tmp / "user" / M.FULL_IPSET_FILE).exists()


def test_bad_custom_copy_does_not_break_prepare_pack(zm):
    """ipset_empty.py: пустая своя копия при ipset_custom — пакет готовится из своего списка."""
    lists_dir = zm.tmp / "lists"
    (lists_dir / "ipset-all.txt").write_text("1.2.3.0/24\n", encoding="utf-8")
    (zm.tmp / "user" / M.FULL_IPSET_FILE).write_text("", encoding="utf-8")
    zm.settings.update(lambda d: d["zapret"].__setitem__("ipset_custom", True))
    zm.z._apply_custom_ipset(lists_dir)
    assert (lists_dir / "ipset-all.txt").read_text(encoding="utf-8") == "1.2.3.0/24\n"


def test_newer_pack_list_beats_old_download(zm):
    lists_dir = zm.tmp / "lists"
    (lists_dir / "ipset-all.txt").write_bytes(b"9.9.9.0/24\r\n")
    copy = zm.tmp / "user" / M.FULL_IPSET_FILE
    copy.write_bytes(b"1.1.1.0/24\r\n")
    zm.settings.update(lambda d: d["zapret"].__setitem__("ipset_custom", True))
    import os
    os.utime(copy, (1_700_000_000, 1_700_000_000))                      # скачан в 2023 году
    zm.z.pack.published_at = "2026-09-20T08:46:37Z"                     # пакет вышел позже
    zm.z._apply_custom_ipset(lists_dir)
    assert (lists_dir / "ipset-all.txt").read_bytes() == b"9.9.9.0/24\r\n"
    assert zm.settings.get("zapret", "ipset_custom") is False
    zm.settings.update(lambda d: d["zapret"].__setitem__("ipset_custom", True))
    zm.z.pack.published_at = "2020-01-01T00:00:00Z"                     # пакет старше скачанного
    zm.z._apply_custom_ipset(lists_dir)
    assert (lists_dir / "ipset-all.txt").read_bytes() == b"1.1.1.0/24\r\n"


def test_store_ipset_keeps_copy_identical_to_pack(zm):
    zm.z.store_ipset("1.1.1.0/24\n8.8.8.0/24\n")
    lists_dir = zm.tmp / "lists"
    copy = (zm.tmp / "user" / M.FULL_IPSET_FILE).read_text(encoding="utf-8")
    assert copy == M.lists.read_full_ipset(lists_dir) and zm.settings.get("zapret", "ipset_custom") is True


# ------------------------------------------------------------ DNS для фильтра под VPN

def test_target_addresses_do_not_hang_and_empty_is_not_kept(zm, monkeypatch):
    gate = threading.Event()
    monkeypatch.setattr(M, "RESOLVE_TIMEOUT", 0.2)

    def slow(host):
        gate.wait(5)
        return set()
    monkeypatch.setattr(M, "_resolve", slow)
    began = time.monotonic()
    assert zm.z._target_ips() == set()
    assert time.monotonic() - began < 2, "DNS молчит — запуск обхода его не ждёт"
    gate.set()
    monkeypatch.setattr(M, "_resolve", lambda host: {"162.159.135.232"} if host == "discord.com" else set())
    assert zm.z._target_ips() == {"162.159.135.232"}, "пустой ответ не запоминается на 10 минут"


# ------------------------------------------------------------ фильтр совместимости с VPN

def test_filter_failure_next_to_internet_vpn_refuses_plain_start(zm, monkeypatch):
    """Обычный перехват рядом с VPN в интернет задел бы туннель или сервер — и интернет пропал бы."""
    timers = []
    monkeypatch.setattr(M.threading, "Timer", lambda delay, fn: SimpleNamespace(
        daemon=True, start=lambda: timers.append((delay, fn))))
    monkeypatch.setattr(vpnfilter, "build", lambda *a, **k: (_ for _ in ()).throw(
        vpnfilter.VpnFilterError("WinDivert.dll не загрузилась")))
    zm.z.vpn_plan = lambda: {"interfaces": [5], "servers": [], "own_servers": [], "strict": True}
    with pytest.raises(M.ZapretError, match="чтобы не оборвать VPN"):
        zm.z.start()
    assert zm.z.status == "error" and not FakeProc.started
    assert "не запущен" in zm.alerts["zapret-vpnfilter"][1]
    assert timers and timers[0][0] == M.FILTER_RETRY_DELAY, "повтор — сам, через полминуты"
    zm.z.vpn_plan = lambda: {"interfaces": [5], "servers": [], "own_servers": [], "strict": False}
    zm.z.start()                                              # только Radmin/Hamachi — как обычно
    assert zm.z.status == "running" and "как обычно" in zm.alerts["zapret-vpnfilter"][1]


def test_unreadable_adapters_after_vpn_filter_refuse_plain_start(zm):
    zm.z.vpn_applied = {"mode": "vpn", "interfaces": [5]}
    zm.z.vpn_plan = lambda: (_ for _ in ()).throw(OSError("GetAdaptersAddresses: 87"))
    with pytest.raises(M.ZapretError, match="адаптеры не прочитаны"):
        zm.z.start()


def test_own_server_stays_excluded_even_if_discord_shares_it(zm, monkeypatch):
    own, foreign = "203.0.113.10", "198.51.100.20"
    seen = {}

    def build(winws, args, interfaces, servers, folder, cache=None, keep_files=4):
        seen["servers"] = servers
        return zm.tmp / "filter.txt"
    monkeypatch.setattr(vpnfilter, "build", build)
    monkeypatch.setattr(zm.z, "_target_ips", lambda: {own, foreign})
    zm.z.vpn_plan = lambda: {"interfaces": [5], "servers": [own, foreign], "own_servers": [own], "strict": True}
    zm.z.runtime_args(zm.z.strategy())
    assert seen["servers"] == [own], "свой сервер — всегда; чужой с адресом Discord — нет"


def test_guard_servers_keeps_mandatory_and_dedupes():
    assert vpnfilter.guard_servers(["1.1.1.1", "1.1.1.1", "2.2.2.2"], {"1.1.1.1", "2.2.2.2"},
                                   keep=["2.2.2.2"]) == ["2.2.2.2"]


# ------------------------------------------------------------ двойное чтение процесса

class _VanishingProcess(M.ZapretManager):
    """process при каждом втором чтении — None: так выглядит stop() из другого потока между чтениями."""

    @property
    def process(self):
        self._reads = getattr(self, "_reads", 0) + 1
        return getattr(self, "_proc", None) if self._reads % 2 else None

    @process.setter
    def process(self, value):
        self._proc = value


def test_process_is_read_once(zm, tmp_path):
    z = _VanishingProcess(zm.settings, lambda *a: None, True)
    z.pack = zm.z.pack
    z._proc = FakeProc("winws.exe", [], "x")
    z._proc._alive = True
    z.conflicts()
    z._reads = 0
    z.fix_conflict("process:winws")
    z._reads = 0
    z.running()
    z.status = "running"
    z._reads = 0
    z.refresh_status()
