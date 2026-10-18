"""Свой VPN рядом с «Совместимостью с VPN»: желаемый план фильтра обхода, отпечаток сети,
свои процессы, вопрос перед включением и значок в трее. Ядро не запускается: мир подделан."""
import copy
import os
import time
from collections import namedtuple
from types import SimpleNamespace

import pytest

from app import vpn
from app.settings import Settings

ETH, TUN, INCY = 17, 40, 5
OWN_NET = "172.31.255.252/30"
SERVER, SERVER2 = "198.51.100.7", "198.51.100.8"


def _adapter(index, name, if_type=6, ipv4=None, gateways=None, guid=None):
    return vpn.Adapter(index=index, guid=guid or "{%08d-0000-0000-0000-000000000000}" % index, name=name,
                       description=name, if_type=if_type, up=True, ipv4=list(ipv4 or []),
                       gateways=list(gateways or []))


class World:
    """Сеть компьютера: Ethernet, по желанию — свой TUN «Lazeyka» и туннель Incy."""

    def __init__(self):
        self.own_tun = False
        self.incy = False
        self.proxy: str | None = None
        self.apps: list[str] = []

    def adapters(self):
        out = [_adapter(ETH, "Ethernet", ipv4=["192.168.0.10"], gateways=["192.168.0.1"])]
        if self.own_tun:
            out.append(_adapter(TUN, "Lazeyka", 53, ipv4=["172.31.255.253"]))
        if self.incy:
            out.append(_adapter(INCY, "wwan99", 53, ipv4=["172.19.0.1"], guid="{2E219888-9139-4199-EA45-CB771D7DAD1D}"))
        return copy.deepcopy(out)

    def drivers(self):
        return {"{%08d-0000-0000-0000-000000000000}" % ETH: (r"PCI\VEN_10EC", vpn.NCF_PHYSICAL),
                "{%08d-0000-0000-0000-000000000000}" % TUN: ("wintun", vpn.NCF_VIRTUAL),
                "{2e219888-9139-4199-ea45-cb771d7dad1d}": ("wintun", vpn.NCF_VIRTUAL)}

    def best(self, ip):
        if self.incy:
            return INCY
        return TUN if self.own_tun else ETH


@pytest.fixture
def world(monkeypatch):
    w = World()
    monkeypatch.setattr(vpn, "list_adapters", w.adapters)
    monkeypatch.setattr(vpn, "_driver_info", w.drivers)
    monkeypatch.setattr(vpn, "best_interface", w.best)
    monkeypatch.setattr(vpn, "routes", lambda: [])
    monkeypatch.setattr(vpn, "wireguard_endpoints", lambda tunnels: [])
    monkeypatch.setattr(vpn, "system_proxy", lambda: w.proxy)
    monkeypatch.setattr(vpn, "running_apps", lambda skip_pids=None: list(w.apps))
    monkeypatch.setattr(vpn, "own_child_pids", lambda: set())
    monkeypatch.setattr(vpn, "active_core_apps", lambda ips, skip_pids=None: [])
    return w


class FakeVpnClient:
    """Менеджер своего VPN: только то, что связке нужно (own() — готовый снимок)."""

    def __init__(self):
        self.snapshot_own: vpn.OwnVpn | None = None
        self.calls: list[str] = []
        self.status = "stopped"

    def own(self):
        return self.snapshot_own

    def on_resume(self):
        self.calls.append("on_resume")

    def on_network_change(self):
        self.calls.append("on_network_change")


class FakeZapret:
    """Обход, который записывает применённый фильтр так же, как ZapretManager.runtime_args."""

    def __init__(self, record_mode: bool):
        self.status, self.paused_for_test, self.mode = "running", False, "app"
        self.vpn_applied = {"mode": "plain"}
        self.vpn_plan = None
        self.restarts = 0
        self.record_mode = record_mode   # True — как будет после правки zapret/manager.py (mode из плана)

    def reapply_for_network(self):
        self.restarts += 1
        plan = self.vpn_plan()
        if not plan:
            self.vpn_applied = {"mode": "plain"}
        else:
            mode = plan.get("mode", "vpn") if self.record_mode else "vpn"
            self.vpn_applied = {"mode": mode, "interfaces": list(plan["interfaces"]),
                                "servers": list(plan["servers"])[:16], "servers_seen": list(plan["servers"])}
        return True


def _core(tmp_path, world, record_mode=False, compat=True):
    from app.core import Core
    core = Core.__new__(Core)
    core.settings = Settings(tmp_path / "s.json")
    core.settings.update(lambda d: d["vpn"].__setitem__("compat", compat))
    core.is_admin = True
    core.vpn_snapshot, core.vpn_routes, core._vpn_scan_at = None, None, 0.0
    core.background = lambda name, fn, on_error: fn()
    core.notices_sent = []
    core.notify = lambda level, text, action=None: core.notices_sent.append((level, text))
    core.tester = SimpleNamespace(running=False, fix_running=False)
    core.zapret = FakeZapret(record_mode)
    core.zapret.vpn_plan = core._vpn_plan
    core.vpnclient = FakeVpnClient()
    return core


def _own_tun(servers=(SERVER,)):
    return vpn.OwnVpn(pids={4242}, adapter_name="Lazeyka", tun_net=OWN_NET, servers=list(servers))


def _own_proxy(servers=(SERVER,)):
    return vpn.OwnVpn(pids={4242}, servers=list(servers), proxy="127.0.0.1:20808")


def _watch(core, times=4):
    for _ in range(times):
        core._vpn_watch(announce=True)


# ------------------------------------------------------------ снимок со своим VPN

def test_scan_marks_own_tun_and_hides_it_from_foreign(world):
    world.own_tun = True
    snap = vpn.scan({"{%08d-0000-0000-0000-000000000000}" % TUN: "direct"}, own=_own_tun())
    own = next(a for a in snap.adapters if a.index == TUN)
    assert own.own and own.kind == "tunnel" and own.app == "Лазейка"   # поправка человека к своему TUN не применяется
    assert own.role == "internet" and snap.internet == [own]
    assert snap.own_active and not snap.foreign_active and snap.active
    assert snap.signature() == [] and snap.servers == [SERVER]
    d = snap.to_dict()
    assert d["active"] is False and d["own"] == {"active": True, "mode": "tun"} and d["servers"] == []
    assert any(a["own"] for a in d["adapters"])


def test_scan_own_system_proxy_is_not_foreign(world):
    world.proxy = "http://127.0.0.1:20808"
    snap = vpn.scan(None, own=_own_proxy())
    assert snap.proxy is None and not snap.foreign_active and snap.to_dict()["own"]["mode"] == "proxy"
    world.proxy = "http://127.0.0.1:10808"     # прокси Happ — чужой
    assert vpn.scan(None, own=_own_proxy()).proxy == "http://127.0.0.1:10808"


def test_own_servers_go_first_and_are_capped(world):
    world.incy = True
    many = [f"198.51.100.{i}" for i in range(1, 30)]
    snap = vpn.scan(None, own=_own_proxy(many))
    assert snap.servers[:16] == many[:16] and len(snap.own_servers) == 16


# ------------------------------------------------------------ желаемый план

def test_own_servers_are_excluded_always(tmp_path, world):
    core = _core(tmp_path, world, compat=True)
    core.vpnclient.snapshot_own = _own_proxy()
    # Совместимость включена, туннелей нет, свой VPN — системный прокси: план есть ради своего сервера.
    assert core._vpn_plan() == {"interfaces": [ETH], "servers": [SERVER]}
    core.settings.update(lambda d: d["vpn"].__setitem__("compat", False))
    world.own_tun = True
    core.vpnclient.snapshot_own = _own_tun()
    plan = core._vpn_plan()
    assert plan == {"interfaces": [ETH], "servers": [SERVER], "mode": "own"}   # всё, кроме своего TUN
    core.vpnclient.snapshot_own, world.own_tun = None, False
    assert core._vpn_plan() is None            # своего VPN нет — обычный перехват


def test_compat_off_with_foreign_vpn_still_intercepts_it(tmp_path, world):
    world.incy = world.own_tun = True
    core = _core(tmp_path, world, compat=False)
    core.vpnclient.snapshot_own = _own_tun()
    plan = core._vpn_plan()
    assert plan["interfaces"] == [INCY, ETH] and TUN not in plan["interfaces"] and plan["servers"] == [SERVER]


@pytest.mark.parametrize("record_mode", [False, True])
def test_compat_off_one_restart_not_a_loop(tmp_path, world, record_mode):
    """Совместимость выключена, работает свой VPN: один перезапуск winws, а не петля (прежде
    любой mode == «vpn» при выключенной совместимости считался устаревшим)."""
    core = _core(tmp_path, world, record_mode=record_mode, compat=False)
    _watch(core)
    assert core.zapret.restarts == 0
    world.own_tun = True
    core.vpnclient.snapshot_own = _own_tun()
    _watch(core, 6)
    assert core.zapret.restarts == 1
    assert core._applied_filter()["mode"] == "own"
    # Выключили свой VPN — исключение его сервера никому не мешает: перезапуска нет.
    world.own_tun, core.vpnclient.snapshot_own = False, None
    _watch(core, 4)
    assert core.zapret.restarts == 1


def test_compat_off_drops_foreign_filter_once(tmp_path, world):
    """Старое поведение: совместимость выключили — фильтр чужого VPN уходит одним перезапуском."""
    world.incy = True
    core = _core(tmp_path, world, compat=False)
    core.zapret.vpn_applied = {"mode": "vpn", "interfaces": [ETH], "servers": [], "servers_seen": []}
    _watch(core, 4)
    assert core.zapret.restarts == 1 and core.zapret.vpn_applied == {"mode": "plain"}


def test_proxy_mode_restarts(tmp_path, world):
    """Режим прокси: один перезапуск при старте, ноль при стопе и повторном старте, один при новом IP."""
    core = _core(tmp_path, world, compat=True)
    world.proxy, core.vpnclient.snapshot_own = "http://127.0.0.1:20808", _own_proxy()
    _watch(core)
    assert core.zapret.restarts == 1
    world.proxy, core.vpnclient.snapshot_own = None, None       # выключили: прокси вернулся
    _watch(core)
    assert core.zapret.restarts == 1
    world.proxy, core.vpnclient.snapshot_own = "http://127.0.0.1:20808", _own_proxy()
    _watch(core)
    assert core.zapret.restarts == 1
    core.vpnclient.snapshot_own = _own_proxy([SERVER2])          # сервер с другим адресом
    _watch(core)
    assert core.zapret.restarts == 2
    assert core.notices_sent == []                               # про свой VPN не объявляем


def test_tun_mode_with_compat_restarts_once(tmp_path, world):
    core = _core(tmp_path, world, compat=True)
    world.own_tun = True
    core.vpnclient.snapshot_own = _own_tun()
    _watch(core, 5)
    assert core.zapret.restarts == 1
    applied = core.zapret.vpn_applied
    assert applied["interfaces"] == [ETH] and applied["servers_seen"] == [SERVER]


def test_reapply_in_flight_is_not_doubled(tmp_path, world):
    """Пока перестройка фильтра идёт, повторный осмотр видит прежний фильтр — второй перезапуск не нужен."""
    core = _core(tmp_path, world, compat=True)
    queued = []
    core.background = lambda name, fn, on_error: queued.append(fn)
    world.own_tun = True
    core.vpnclient.snapshot_own = _own_tun()
    _watch(core, 3)
    assert len(queued) == 1
    queued[0]()
    _watch(core, 3)
    assert len(queued) == 1 and core.zapret.restarts == 1


def test_plan_changed_treats_own_like_vpn():
    applied = {"mode": "own", "interfaces": [ETH], "servers_seen": [SERVER]}
    assert vpn.plan_changed(applied, None, [ETH]) is False
    assert vpn.plan_changed(applied, None, [ETH, 31]) is True


def test_watch_own_vpn_triggers_scan_on_change(tmp_path, world):
    core = _core(tmp_path, world)
    core._own_key, core._vc_dirty = None, False
    seen = []
    core._vpn_watch = lambda announce: seen.append(announce)
    core._watch_own_vpn()
    assert seen == []
    core.vpnclient.snapshot_own = _own_proxy()
    core._watch_own_vpn()
    core._watch_own_vpn()
    assert seen == [False]                     # один осмотр на одну смену, без объявлений
    core._vpnclient_changed("status")
    core._own_watch_at = 0.0
    core._watch_own_vpn()
    assert seen == [False, False]


# ------------------------------------------------------------ отпечаток сети

def test_check_network_ignores_own_tun(tmp_path, world, monkeypatch):
    import psutil
    Addr = namedtuple("Addr", "family address")
    ifaces = {"Ethernet": [Addr(2, "192.168.0.10")]}
    monkeypatch.setattr(psutil, "net_if_addrs", lambda: ifaces)
    core = _core(tmp_path, world)
    restarts = []
    core.tg = SimpleNamespace(status="running", restart=lambda: restarts.append(1))
    core._net_fp, core._wd_next, core._vpn_scan_at = None, 0.0, time.monotonic()
    core._vpn_watch = lambda announce: None
    core._check_network()
    world.own_tun = True
    core.vpnclient.snapshot_own = _own_tun()
    ifaces["Lazeyka"] = [Addr(2, "172.31.255.253")]
    core._check_network()
    # Ядро выключилось, а адаптер Wintun ещё виден несколько секунд — это тоже не «смена сети».
    core.vpnclient.snapshot_own = None
    core._check_network()
    del ifaces["Lazeyka"]
    core._check_network()
    assert restarts == [] and core.vpnclient.calls == []
    ifaces["Wi-Fi"] = [Addr(2, "10.0.0.5")]     # а вот новая сеть — смена
    core._check_network()
    assert restarts == [1] and core.vpnclient.calls == ["on_network_change"]


# ------------------------------------------------------------ свои процессы

def test_own_processes_are_not_foreign_vpn(monkeypatch):
    import psutil

    class P:
        def __init__(self, pid, ppid, name):
            self.info = {"pid": pid, "ppid": ppid, "name": name}

    me = os.getpid()
    procs = [P(10, me, "sing-box.exe"), P(11, 1, "xray.exe"), P(12, 1, "Incy.exe"), P(13, me, "xray.exe")]
    monkeypatch.setattr(psutil, "process_iter", lambda attrs=None: iter(procs))
    assert vpn.running_apps({11}) == ["Incy"]                  # sing-box и xray — дети Лазейки или из own.pids
    assert vpn.running_apps() == ["Xray", "Incy"]              # без own.pids xray 11 — чужой
    assert vpn.own_child_pids() == {10, 13}


def test_active_core_apps_skip_own(monkeypatch):
    import psutil
    Addr = namedtuple("Addr", "ip port")
    Conn = namedtuple("Conn", "pid laddr status")
    conns = [Conn(10, Addr("192.168.0.10", 50000), psutil.CONN_ESTABLISHED),
             Conn(20, Addr("192.168.0.10", 50001), psutil.CONN_ESTABLISHED)]
    names = {10: "sing-box.exe", 20: "xray.exe"}
    monkeypatch.setattr(psutil, "net_connections", lambda kind="tcp": conns)
    monkeypatch.setattr(psutil, "Process", lambda pid: SimpleNamespace(name=lambda: names[pid]))
    assert vpn.active_core_apps({"192.168.0.10"}, {10}) == ["Xray"]
    assert vpn.active_core_apps({"192.168.0.10"}, {10, 20}) == []


# ------------------------------------------------------------ вопрос перед включением

def test_preflight_silent_about_own_asks_about_incy(tmp_path, world, monkeypatch):
    monkeypatch.setattr(vpn, "probe_routes", lambda s: {"items": [], "full_tunnel": True, "at": 1.0})
    core = _core(tmp_path, world)
    world.own_tun = True
    core.vpnclient.snapshot_own = _own_tun()
    assert core.vpn_preflight("zapret")["ask"] is False
    world.incy, world.apps = True, ["Incy"]
    reply = core.vpn_preflight("zapret")
    assert reply["ask"] is True and reply["vpn"]["label"] == "Incy" and reply["vpn"]["own"]["active"]


def test_announce_is_silent_about_own(tmp_path, world):
    core = _core(tmp_path, world)
    core._vpn_was_active = False
    world.own_tun = True
    core.vpnclient.snapshot_own = _own_tun()
    core._vpn_watch(announce=True)
    assert core.notices_sent == []
    world.incy, world.apps = True, ["Incy"]
    core._vpn_watch(announce=True)
    assert len(core.notices_sent) == 1 and "Incy" in core.notices_sent[0][1]


def test_vpnclient_preflight_conflicts(tmp_path, world):
    core = _core(tmp_path, world)
    assert core.vpnclient_preflight() == {"ok": True, "ask": False, "conflict": None}
    world.incy, world.apps = True, ["Incy"]
    reply = core.vpnclient_preflight()
    assert reply["ask"] and reply["conflict"]["kind"] == "tunnel" and reply["conflict"]["label"] == "Incy"
    assert "системный прокси" in reply["conflict"]["text"]
    core.settings.update(lambda d: d["vpnclient"].__setitem__("mode", "proxy"))
    assert core.vpnclient_preflight()["ask"] is False   # системный прокси поверх чужого TUN — можно
    world.incy, world.apps, world.proxy = False, ["Happ"], "http://127.0.0.1:10808"
    reply = core.vpnclient_preflight()
    assert reply["conflict"]["kind"] == "proxy" and "вернёт" in reply["conflict"]["text"]


# ------------------------------------------------------------ трей

class _TrayVpn:
    def __init__(self, status="stopped", **extra):
        self.status = status
        self.extra = extra

    def snapshot(self):
        servers = [{"id": f"s{i}", "sub": "s-1", "name": f"Сервер номер {i} с очень длинным названием",
                    "country": "NL", "supported": i != 3} for i in range(30)]
        return {"available": True, "status": self.status, "servers": servers,
                "subscriptions": [{"id": "s-1"}], "groups": [],
                "selected": {"id": "s1", "kind": "server", "name": "Амстердам", "actual": None},
                "stats": {"up_rate": 15360.0, "down_rate": 1843200.0}, **self.extra}


def _tray(vc):
    from app.tray import Tray
    tray = Tray.__new__(Tray)
    tray.core = SimpleNamespace(zapret=SimpleNamespace(status="running", available=True),
                                tg=SimpleNamespace(status="running"), vpnclient=vc)
    return tray


@pytest.mark.parametrize("status, icon", [("stopped", "on"), ("running", "on"), ("starting", "partial"),
                                          ("error", "error")])
def test_tray_reacts_to_vpn_status(status, icon):
    assert _tray(_TrayVpn(status))._status() == icon


def test_tray_without_vpn_module_keeps_old_logic():
    tray = _tray(None)
    assert tray._status() == "on" and "VPN" not in tray._tooltip()


def test_tray_tooltip_has_speed_and_fits():
    tray = _tray(_TrayVpn("running"))
    text = tray._tooltip()
    assert len(text) <= 127 and "VPN: Амстердам" in text and "1,8 МБ/с" in text and "15,0 КБ/с" in text
    assert "VPN: выключен" in _tray(_TrayVpn("stopped"))._tooltip()


def test_tray_server_menu():
    tray = _tray(_TrayVpn("running"))
    choices = tray._server_choices(tray._vpn())
    assert choices[0] == ("auto:s-1", "Самый быстрый") and len(choices) == 21
    assert all(sid != "s3" for sid, _ in choices)        # неподдерживаемый не предлагаем


def test_tray_toggle_next_to_incy_opens_window_instead_of_starting():
    shown, notes, started = [], [], []
    tray = _tray(_TrayVpn("stopped"))
    tray.notify = notes.append
    conflict = {"kind": "tunnel", "label": "Incy", "text": "Уже работает Incy — два VPN мешают друг другу"}
    tray.core.vpnclient_preflight = lambda: {"ok": True, "ask": True, "conflict": conflict}
    tray.core.vpnclient_start = lambda quiet=False: started.append(quiet) or {"ok": True}
    tray.core.show = lambda: shown.append(1)
    tray._toggle_vpn()
    assert shown == [1] and started == [] and "Incy" in notes[0]
    tray.core.vpnclient_preflight = lambda: {"ok": True, "ask": False, "conflict": None}
    tray._toggle_vpn()
    assert started == [True]


def test_tray_toggle_reports_errors():
    from app.errors import UserError
    notes = []
    tray = _tray(_TrayVpn("running"))
    tray.notify = notes.append

    def stop():
        raise UserError("ядро не ответило")
    tray.core.vpnclient_stop = stop
    tray._toggle_vpn()
    assert notes == ["ядро не ответило"]


def test_probe_routes_uses_own_proxy_as_vpn_reference(monkeypatch):
    seen = {}

    def curl(url, bind=None, proxy=None, timeout=6):
        seen.setdefault(proxy, []).append(url)
        return "198.51.100.20" if proxy else "203.0.113.50"

    monkeypatch.setattr(vpn, "_curl_seen", curl)
    monkeypatch.setattr(vpn, "_python_seen", lambda *a, **k: "203.0.113.50")
    snap = vpn.Snapshot(adapters=[], servers=[SERVER], apps=[], at=0.0, own=_own_proxy())
    result = vpn.probe_routes(snap)
    assert result["mode"] == "proxy" and "http://127.0.0.1:20808" in seen
    via = {i["id"]: i["via"] for i in result["items"]}
    assert via["other"] == "vpn" and via["telegram"] == "direct"


# ------------------------------------------------------------ фильтр до старта ядра (before_core)

def test_before_core_rebuilds_filter_once(tmp_path, world):
    """План собран, ядро ещё не запущено: фильтр перестраивается сразу и один раз."""
    core = _core(tmp_path, world, compat=True)
    core.vpnclient.snapshot_own = _own_proxy()
    core._vpnclient_before_core()
    assert core.zapret.restarts == 1 and core.zapret.vpn_applied["servers_seen"] == [SERVER]
    core._vpnclient_before_core()
    _watch(core)
    assert core.zapret.restarts == 1


def test_before_core_waits_for_reapply_in_flight(tmp_path, world):
    import threading
    core = _core(tmp_path, world, compat=True)
    queued = []
    core.background = lambda name, fn, on_error: queued.append(fn)
    core.vpnclient.snapshot_own = _own_proxy()
    core._vpn_watch(announce=False)               # фоновая перестройка поставлена, ещё не выполнена
    assert len(queued) == 1
    done = threading.Event()
    waiter = threading.Thread(target=lambda: (core._vpnclient_before_core(), done.set()), daemon=True)
    waiter.start()
    assert not done.wait(0.3)                     # ждёт идущую перестройку, а не запускает вторую
    queued[0]()
    assert done.wait(5)
    assert core.zapret.restarts == 1


def test_before_core_does_nothing_without_running_bypass(tmp_path, world):
    core = _core(tmp_path, world)
    core.zapret.status = "stopped"
    core.vpnclient.snapshot_own = _own_proxy()
    core._vpnclient_before_core()
    assert core.zapret.restarts == 0
