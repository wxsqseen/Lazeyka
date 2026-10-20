"""Прямой выход в интернет и Radmin VPN: жалоба «не работает запрет — Лазейка лезет в Radmin, и интернет
пропадает целиком». Мир подделан настоящими параметрами ПК разработчика: Radmin VPN (RvNetMP60, 26.253.76.57)
с метрикой интерфейса 1, шлюзом 26.0.0.1 и маршрутом 0.0.0.0/0 с метрикой 9256; Ethernet — метрика
интерфейса 35, маршрут по умолчанию с метрикой 0. Сеть, реестр и WFP не трогаются."""
import copy
import socket
from collections import namedtuple
from types import SimpleNamespace

import pytest

from app import vpn
from app.vpnclient import killswitch as ks
from app.vpnclient import manager as mgr
from tests.fakes.vpn_world import basic_store, make_manager

ETH, RADMIN, HYPERV, WINTUN, ZT, WIFI = 17, 14, 19, 5, 23, 18
ETH_IP, RADMIN_IP = "192.168.0.133", "26.253.76.57"
RADMIN_LUID = 0x0006_0000_0100_0000
RADMIN_COMPONENT = r"{B06D84D1-AF78-41EC-A5B9-3CCE676528B2}\RvNetMP60"
SERVER = "45.137.21.9"


def _ethernet(**kw):
    a = dict(index=ETH, guid="{eth}", name="Ethernet", description="Realtek PCIe GbE Family Controller", if_type=6,
             up=True, ipv4=[ETH_IP], gateways=["fe80::be0f:9aff:fe8e:5718", "192.168.0.1"], metric=35, luid=0x60080)
    a.update(kw)
    return vpn.Adapter(**a)


def _radmin(**kw):
    a = dict(index=RADMIN, guid="{rad}", name="Radmin VPN", description="Famatech Radmin VPN Ethernet Adapter",
             if_type=6, up=True, ipv4=[RADMIN_IP], ipv6=["fdfd::1afd:4c39"], gateways=["26.0.0.1"], metric=1,
             luid=RADMIN_LUID)
    a.update(kw)
    return vpn.Adapter(**a)


ETH_ROUTES = [("0.0.0.0", 0, "192.168.0.1", ETH, 0), ("192.168.0.0", 24, "0.0.0.0", ETH, 256),
              ("::", 0, "fe80::be0f:9aff:fe8e:5718", ETH, 0)]
RADMIN_ROUTES = [("0.0.0.0", 0, "26.0.0.1", RADMIN, 9256), ("26.0.0.0", 8, "0.0.0.0", RADMIN, 256),
                 ("26.253.76.57", 32, "0.0.0.0", RADMIN, 256), ("26.255.255.255", 32, "0.0.0.0", RADMIN, 256),
                 ("224.0.0.0", 4, "0.0.0.0", RADMIN, 256), ("255.255.255.255", 32, "0.0.0.0", RADMIN, 256),
                 ("fdfd::", 64, "::", RADMIN, 256), ("fe80::", 64, "::", RADMIN, 256), ("ff00::", 8, "::", RADMIN, 256)]


class World:
    def __init__(self):
        self.adapters = [
            _ethernet(), _radmin(),
            vpn.Adapter(index=HYPERV, guid="{hv}", name="vEthernet (Default Switch)",
                        description="Hyper-V Virtual Ethernet Adapter", if_type=6, up=True, ipv4=["172.25.192.1"],
                        metric=5000),
            vpn.Adapter(index=1, guid="{lo}", name="Loopback Pseudo-Interface 1",
                        description="Software Loopback Interface 1", if_type=24, up=True, ipv4=["127.0.0.1"])]
        self.drivers = {"{eth}": (r"PCI\VEN_10EC&DEV_8168&SUBSYS_7C961462&REV_15", vpn.NCF_PHYSICAL),
                        "{rad}": (RADMIN_COMPONENT, vpn.NCF_VIRTUAL), "{hv}": ("", 0), "{lo}": ("", 0),
                        "{wt}": ("wintun", vpn.NCF_VIRTUAL), "{zt}": ("zttap300", vpn.NCF_VIRTUAL),
                        "{wifi}": (r"PCI\VEN_8086", vpn.NCF_PHYSICAL), "{eex}": ("expressvpn", 0)}
        self.routes = ETH_ROUTES + RADMIN_ROUTES + [("127.0.0.0", 8, "0.0.0.0", 1, 256)]
        self.best = ETH            # куда Windows отправляет проверочные адреса
        self.apps = ["Radmin VPN"]
        self.proxy = None
        self.conns: list = []      # vpn_connections: (программа, удалённый адрес)

    def without_direct_route(self):
        """Wi-Fi переподключается / PPPoE упал / после сна: маршрута по умолчанию у сетевой карты нет."""
        self.adapters[0] = _ethernet(gateways=[])
        self.routes = [r for r in self.routes if not (r[3] == ETH and r[1] == 0)]
        self.best = RADMIN


@pytest.fixture
def world(monkeypatch):
    w = World()
    monkeypatch.setattr(vpn, "list_adapters", lambda: copy.deepcopy(w.adapters))
    monkeypatch.setattr(vpn, "_driver_info", lambda: dict(w.drivers))
    monkeypatch.setattr(vpn, "routes", lambda: list(w.routes))
    monkeypatch.setattr(vpn, "best_interface", lambda ip: w.best)
    monkeypatch.setattr(vpn, "running_apps", lambda skip_pids=None: list(w.apps))
    monkeypatch.setattr(vpn, "system_proxy", lambda: w.proxy)
    monkeypatch.setattr(vpn, "own_child_pids", lambda: set())
    monkeypatch.setattr(vpn, "wireguard_endpoints", lambda tunnels: [])
    monkeypatch.setattr(vpn, "vpn_connections", lambda ips, skip_pids=None: list(w.conns))
    return w


def _named(snap, name):
    return next(a for a in snap.adapters if a.name == name)


def _add_tunnel(world, index=WINTUN, guid="{wt}", name="wwan99", description="Wintun Tunnel", if_type=53,
                ip="198.18.0.1", metric=0):
    world.adapters.append(vpn.Adapter(index=index, guid=guid, name=name, description=description, if_type=if_type,
                                      up=True, ipv4=[ip], gateways=["0.0.0.0"], metric=metric))
    world.routes.append(("0.0.0.0", 0, "0.0.0.0", index, 0))
    world.best = index


# ------------------------------------------------------------ прямой выход: привязка помощника Xray

def test_physical_interface_picks_ethernet_not_radmin(world):
    """Раньше побеждала наименьшая метрика интерфейса (Radmin — 1), и все выходы помощника Xray своего VPN
    уходили в Radmin: свой TUN + сервер через Xray = интернета нет вовсе. Теперь — сумма метрик маршрута
    по умолчанию и интерфейса: Ethernet 0 + 35 против Radmin 9256 + 1, и Radmin не кандидат вовсе."""
    assert mgr.physical_interface() == "Ethernet"
    assert mgr.ipv6_internet() is False            # у Ethernet нет глобального IPv6 — только маршрут
    world.adapters[0] = _ethernet(ipv6=["2a02:2168:1:2::10"])
    assert mgr.ipv6_internet() is True


def test_physical_interface_never_radmin_even_alone_or_marked_direct(world):
    world.without_direct_route()
    assert mgr.physical_interface() is None, "единственный маршрут — через Radmin, но интернета там нет"
    assert mgr.physical_interface({"{rad}": "direct"}) is None, "поправка «прямое» не делает Radmin выходом"


def test_own_tun_is_never_the_exit(world):
    world.adapters.append(vpn.Adapter(index=40, guid="{own}", name=mgr.TUN_NAME, description="sing-box TUN",
                                      if_type=53, up=True, ipv4=["100.127.255.253"]))
    world.routes.append(("0.0.0.0", 0, "0.0.0.0", 40, 0))
    assert mgr.physical_interface({"{own}": "direct"}) == "Ethernet"


def test_route_metric_decides_between_two_network_cards(world):
    """Wi-Fi и кабель: Windows идёт по сумме метрик, а не по метрике интерфейса; карта без маршрута в
    интернет (вторая сеть, только локальная) выходом не бывает."""
    world.adapters.append(vpn.Adapter(index=WIFI, guid="{wifi}", name="Wi-Fi", description="Intel Wi-Fi 6 AX201",
                                      if_type=71, up=True, ipv4=["192.168.1.40"], gateways=["192.168.1.1"], metric=25))
    world.routes = [r for r in world.routes if not (r[3] == ETH and r[1] == 0)]
    world.routes += [("0.0.0.0", 0, "192.168.0.1", ETH, 256), ("0.0.0.0", 0, "192.168.1.1", WIFI, 0)]
    assert mgr.physical_interface() == "Wi-Fi"                     # 0 + 25 < 256 + 35
    world.routes = [r for r in world.routes if not (r[3] == WIFI and r[1] == 0)]
    assert mgr.physical_interface() == "Ethernet"
    world.routes = [r for r in world.routes if not (r[3] == ETH and r[1] == 0)]
    assert mgr.physical_interface() is None                        # у Wi-Fi есть шлюз, но маршрута нет


def test_isp_l2tp_marked_direct_by_human_is_the_exit(world):
    """L2TP провайдера, которого Windows считает VPN: человек пометил его «прямым» — им и ходим в интернет."""
    world.adapters.append(vpn.Adapter(index=30, guid="{l2tp}", name="Мой провайдер", description="WAN Miniport",
                                      if_type=23, up=True, ipv4=["10.20.30.40"], metric=5))
    world.routes = [r for r in world.routes if not (r[3] == ETH and r[1] == 0)] + [("0.0.0.0", 0, "0.0.0.0", 30, 0)]
    vpn_ras = {"Мой провайдер": "vpn"}
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(vpn, "ras_connections", lambda: dict(vpn_ras))
        assert mgr.physical_interface() is None
        assert mgr.physical_interface({"{l2tp}": "direct"}) == "Мой провайдер"


def test_route_table_unreadable_falls_back_to_gateway(world):
    """Таблица маршрутов не прочиталась (пустая): как раньше — прямой адаптер со шлюзом, но не Radmin."""
    world.routes = []
    assert mgr.physical_interface() == "Ethernet"


# ------------------------------------------------------------ роль Radmin в «Совместимости с VPN»

def test_radmin_is_lan_and_not_a_vpn(world):
    world.routes.append(("217.69.167.103", 32, "192.168.0.1", ETH, 0))   # маршрут мимо туннеля — не сервер VPN
    snap = vpn.scan()
    radmin = _named(snap, "Radmin VPN")
    assert (radmin.kind, radmin.role, radmin.app) == ("tunnel", "lan", "Radmin VPN")
    assert not snap.foreign_active and snap.source_ip() == ETH_IP and snap.tunnel_ip() is None
    assert snap.servers == [], "на ПК только с Radmin маршруты /32 — не серверы VPN"
    assert snap.plan() == {"interfaces": [ETH, HYPERV], "servers": []}, "интерфейс Radmin обход не перехватывает"


def test_radmin_stays_lan_when_direct_route_is_gone(world):
    """Маршрут по умолчанию у сетевой карты пропал, а у Radmin он есть: раньше Radmin становился «VPN в
    интернет» — уведомление «Подключён VPN (Radmin VPN)», «Уже работает Radmin VPN» у своего VPN, проверки
    с адреса 26.x. Пропажа прямого маршрута — не VPN."""
    world.without_direct_route()
    snap = vpn.scan()
    radmin = _named(snap, "Radmin VPN")
    assert (radmin.kind, radmin.role, radmin.default_route) == ("tunnel", "lan", False)
    assert not snap.foreign_active and not snap.full_tunnel and snap.to_dict()["label"] is None
    assert snap.tunnel_ip() is None, "эталон «через VPN» для «Что куда идёт» — не Radmin"
    assert snap.source_ip() is None, "проверки «мимо VPN» не привязываются к 26.x"


def test_radmin_marked_direct_does_not_steal_source_ip(world):
    """Человек пометил Radmin «прямым» (раз Лазейка назвала его VPN): проверки мимо VPN всё равно идут с
    Ethernet — у Radmin нет интернета."""
    _add_tunnel(world)
    snap = vpn.scan(overrides={"{rad}": "direct"})
    assert _named(snap, "Radmin VPN").kind == "direct"
    assert snap.source_ip() == ETH_IP
    world.without_direct_route()
    world.best = WINTUN
    assert vpn.scan(overrides={"{rad}": "direct"}).source_ip() is None


def test_radmin_with_physical_flag_is_still_a_tunnel(world):
    """Драйвер VPN с признаком «сетевая карта» (NCF_PHYSICAL) узнаётся по драйверу раньше признака."""
    world.drivers["{rad}"] = (RADMIN_COMPONENT, vpn.NCF_PHYSICAL)
    snap = vpn.scan()
    assert _named(snap, "Radmin VPN").kind == "tunnel" and snap.source_ip() == ETH_IP


def test_own_conflict_does_not_name_radmin(world, tmp_path):
    from tests.test_vpnclient_core import make_core
    world.without_direct_route()
    core = make_core(tmp_path)
    assert core._own_conflict(vpn.scan()) is None


# ------------------------------------------------------------ другой туннель — VPN только с доказательством

def _zerotier(world):
    world.adapters.append(vpn.Adapter(index=ZT, guid="{zt}", name="ZeroTier One", description="ZeroTier Virtual Port",
                                      if_type=6, up=True, ipv4=["10.147.17.5"], gateways=["10.147.17.1"], metric=25))
    world.routes.append(("0.0.0.0", 0, "10.147.17.1", ZT, 9000))


def test_tunnel_beating_direct_route_is_internet(world):
    _add_tunnel(world)
    snap = vpn.scan()
    wintun = _named(snap, "wwan99")
    assert (wintun.role, wintun.default_route) == ("internet", True) and snap.foreign_active and snap.full_tunnel


def test_tunnel_without_direct_route_is_not_proof(world):
    """Через ZeroTier идёт интернет лишь потому, что прямой маршрут пропал: это не «подключился VPN»."""
    _zerotier(world)
    world.without_direct_route()
    world.best = ZT
    snap = vpn.scan()
    zt = _named(snap, "ZeroTier One")
    assert zt.role == "lan" and zt.pending_internet and not snap.foreign_active


def _openvpn_without_default_route(world):
    """OpenVPN (TAP) снял прямой маршрут по умолчанию, а сервер вывел из туннеля маршрутом к /24 — не /32, и
    эндпоинтов WireGuard у него нет: доказать «VPN в интернет» нечем."""
    world.adapters.append(vpn.Adapter(index=31, guid="{tap}", name="Ethernet 3", description="TAP-Windows Adapter V9",
                                      if_type=6, up=True, ipv4=["10.8.0.6"], gateways=["10.8.0.5"], metric=25))
    world.drivers["{tap}"] = ("tap0901", vpn.NCF_VIRTUAL)
    world.routes = [r for r in world.routes if not (r[3] == ETH and r[1] == 0)]
    world.routes += [("0.0.0.0", 0, "10.8.0.5", 31, 0), ("45.137.21.0", 24, "192.168.0.1", ETH, 0)]
    world.best = 31


def test_unproven_foreign_tunnel_still_conflicts_with_own_tun(world, tmp_path):
    """Роль у такого туннеля — lan (фильтр обхода не меняется), но свой VPN в TUN поверх него — те же два
    туннеля: неопределённость — повод спросить, а не молчать. Подпись — программа по драйверу."""
    from tests.test_vpnclient_core import make_core
    _openvpn_without_default_route(world)
    snap = vpn.scan()
    tap = _named(snap, "Ethernet 3")
    assert (tap.role, tap.pending_internet) == ("lan", True) and not snap.foreign_active, "роли — как раньше"
    core = make_core(tmp_path)
    conflict = core._own_conflict(snap)
    assert conflict["kind"] == "tunnel" and conflict["label"] == "OpenVPN"
    assert conflict["text"].startswith("Интернет сейчас идёт через OpenVPN — два VPN мешают друг другу")
    core.settings.update(lambda d: d["vpnclient"].__setitem__("mode", "proxy"))
    assert core._own_conflict(snap) is None, "системному прокси чужой туннель не мешает"


def test_unproven_tunnel_without_named_app_is_called_by_adapter(world, tmp_path):
    from tests.test_vpnclient_core import make_core
    _openvpn_without_default_route(world)
    world.drivers["{tap}"] = ("", vpn.NCF_VIRTUAL)
    world.adapters[-1].description = "Some Virtual Tunnel"
    world.adapters[-1].if_type = vpn.IF_TYPE_PROP_VIRTUAL
    snap = vpn.scan()
    assert _named(snap, "Ethernet 3").pending_internet
    assert make_core(tmp_path)._own_conflict(snap)["label"] == "VPN «Ethernet 3»"


def test_vpn_keeps_its_role_while_wifi_reconnects(world):
    _add_tunnel(world)
    before = vpn.scan()
    assert before.foreign_active
    world.without_direct_route()
    world.best = WINTUN
    gap = vpn.scan()
    assert not gap.foreign_active, "сам по себе снимок доказательства не видит"
    vpn.keep_roles(gap, before)
    assert gap.foreign_active and _named(gap, "wwan99").role == "internet", "VPN не «переподключался»"
    fresh = vpn.scan()
    vpn.keep_roles(fresh, vpn.scan())          # прежний снимок без VPN — новый туннель роль не получает
    assert not fresh.foreign_active
    vpn.keep_roles(None, before)               # снимка нет — нечего и делать


def test_vpn_that_removed_direct_route_is_proven_by_server_route(world):
    """VPN снял прямой маршрут по умолчанию, но вывел свой сервер из туннеля маршрутом /32 — это VPN."""
    _add_tunnel(world)
    world.without_direct_route()
    world.best = WINTUN
    world.adapters[0] = _ethernet()
    world.routes.append((SERVER, 32, "192.168.0.1", ETH, 0))
    snap = vpn.scan()
    assert _named(snap, "wwan99").role == "internet" and snap.servers == [SERVER]


# ------------------------------------------------------------ серверы VPN

def test_many_host_routes_keep_servers_confirmed_by_connections(world):
    """Больше трёх маршрутов /32 — раздельное туннелирование; сервер — тот адрес, с которым соединена
    сама VPN-программа."""
    _add_tunnel(world)
    sites = [f"162.159.{i}.1" for i in range(6)]
    world.routes += [(ip, 32, "192.168.0.1", ETH, 0) for ip in sites + [SERVER]]
    world.apps = ["Incy"]
    assert vpn.scan().servers == []
    world.routes += [("1.2.3.4", 32, "192.168.0.1", ETH, 0)]
    world.conns = [("Incy", SERVER), ("Incy", None)]
    assert vpn.scan().servers == [SERVER]


def test_proxy_vpn_server_is_excluded_from_interception(world):
    """VPN в режиме системного прокси (Happ, v2rayN): соединение ядра с сервером идёт с адреса Ethernet —
    его адрес берётся из соединений ядра, и фильтр его не трогает."""
    world.proxy, world.apps = "http://127.0.0.1:10808", ["Happ"]
    world.conns = [("Happ", SERVER), ("Happ", "127.0.0.1")]
    snap = vpn.scan()
    assert snap.foreign_active and snap.servers == [SERVER] and snap.foreign_servers == [SERVER]
    assert snap.plan() == {"interfaces": [ETH, HYPERV], "servers": [SERVER]}
    world.conns = [("Happ", f"45.137.21.{i}") for i in range(10, 15)]     # правила «напрямую» — не угадываем
    assert vpn.scan().servers == []


def test_vpn_connections_and_owners(monkeypatch):
    import psutil
    Addr = namedtuple("Addr", "ip port")
    Conn = namedtuple("Conn", "pid laddr raddr status type")
    conns = [Conn(10, Addr(ETH_IP, 50000), Addr(SERVER, 443), psutil.CONN_ESTABLISHED, socket.SOCK_STREAM),
             Conn(10, Addr(ETH_IP, 50001), Addr("8.8.8.8", 443), psutil.CONN_TIME_WAIT, socket.SOCK_STREAM),
             Conn(20, Addr(ETH_IP, 4500), None, psutil.CONN_NONE, socket.SOCK_DGRAM),           # UDP на прямом адресе
             Conn(30, Addr("0.0.0.0", 5353), None, psutil.CONN_NONE, socket.SOCK_DGRAM),        # слушает всё
             Conn(40, Addr(ETH_IP, 50002), Addr("1.1.1.1", 443), psutil.CONN_ESTABLISHED, socket.SOCK_STREAM)]
    names = {10: "happ.exe", 20: "expressvpnd.exe", 30: "adguardvpnsvc.exe", 40: "msedge.exe"}
    monkeypatch.setattr(psutil, "net_connections", lambda kind="inet": conns)
    monkeypatch.setattr(psutil, "Process", lambda pid: SimpleNamespace(name=lambda: names[pid]))
    assert vpn.vpn_connections({ETH_IP}) == [("Happ", SERVER), ("ExpressVPN", None)]
    assert vpn.active_core_apps({ETH_IP}) == ["Happ"]
    assert vpn.vpn_connections({ETH_IP}, {10, 20}) == []


def test_idle_vpn_service_without_adapter_is_not_flagged(world):
    """Служба ExpressVPN висит в фоне без подключения — предупреждения «совместимость не поможет» нет;
    держит соединения с прямого адреса — есть."""
    world.apps = ["ExpressVPN"]
    assert vpn.scan().unseparable == []
    world.conns = [("ExpressVPN", "185.12.3.4")]
    snap = vpn.scan()
    assert snap.unseparable == ["ExpressVPN"] and snap.to_dict()["unseparable"] == ["ExpressVPN"]


def test_idle_tunnel_does_not_need_a_filter(world):
    """Отключённый адаптер VPN (без адресов) трафика не несёт — фильтр совместимости ради него не нужен."""
    world.adapters = [a for a in world.adapters if a.name != "Radmin VPN"]
    world.adapters.append(vpn.Adapter(index=21, guid="{tap}", name="Ethernet 2", description="TAP-Windows Adapter V9",
                                      if_type=6, up=False))
    world.drivers["{tap}"] = ("tap0901", vpn.NCF_VIRTUAL)
    snap = vpn.scan()
    assert _named(snap, "Ethernet 2").role == "idle" and snap.plan() is None


# ------------------------------------------------------------ kill switch и сети Radmin

def test_lan_networks_are_radmin_subnets_without_default_route(world):
    _add_tunnel(world)
    assert vpn.lan_networks() == [(RADMIN_LUID, ["26.0.0.0/8", "224.0.0.0/4", "255.255.255.255/32",
                                                 "fdfd::/64", "fe80::/64", "ff00::/8"])]
    world.adapters[1] = _radmin(up=False)
    assert vpn.lan_networks() == []


def test_killswitch_allows_lan_networks_only_through_their_adapter():
    from tests.test_vpnclient_system import FakeWfp
    api = FakeWfp()
    switch = ks.KillSwitch(backend=api)
    switch.enable(tun_luid=0x42, allow_apps=[], allow_nets=[],
                  allow_lan=[(RADMIN_LUID, ["26.253.76.57/8", "fdfd::/64"])])
    lan = [r for r in api.rules.values()
           if {c[0] for c in r["conditions"]} == {bytes(ks.FWPM_CONDITION_IP_LOCAL_INTERFACE),
                                                   bytes(ks.FWPM_CONDITION_IP_REMOTE_ADDRESS)}]
    assert len(lan) == 4 and all(r["action"] == ks.FWP_ACTION_PERMIT for r in lan)
    for rule in lan:
        values = {c[0]: c[3] for c in rule["conditions"]}
        assert values[bytes(ks.FWPM_CONDITION_IP_LOCAL_INTERFACE)] == RADMIN_LUID
        assert values[bytes(ks.FWPM_CONDITION_IP_REMOTE_ADDRESS)] in (
            (0x1A000000, 0xFF000000), (bytes.fromhex("fdfd" + "00" * 14), 64))
    with pytest.raises(ks.KillSwitchError, match="LUID"):
        switch.enable(tun_luid=0x42, allow_apps=[], allow_nets=[], allow_lan=[(0, ["26.0.0.0/8"])])
    with pytest.raises(ks.KillSwitchError, match="локальная сеть"):
        switch.enable(tun_luid=0x42, allow_apps=[], allow_nets=[], allow_lan=[(RADMIN_LUID, ["26.x/8"])])
    switch.disable()


def test_killswitch_backend_dll_by_full_path(monkeypatch):
    from app import winutil
    loaded = []

    class Dll:
        def __init__(self, name, **kw):
            loaded.append(name)

        def __getattr__(self, name):
            fn = SimpleNamespace()
            setattr(self, name, fn)
            return fn

    monkeypatch.setattr(ks.ctypes, "WinDLL", Dll)
    ks._load_backend()
    assert loaded == [winutil.system32("fwpuclnt.dll")]


def test_icmp_dll_by_full_path():
    from app import winutil
    from app.zapret import tester
    assert tester._iphlpapi._name.lower() == winutil.system32("iphlpapi.dll").lower()


def test_manager_kill_switch_gets_lan_networks_and_follows_them(tmp_path):
    lan = {"now": [(RADMIN_LUID, ["26.0.0.0/8"])]}
    m, w = make_manager(tmp_path, basic_store(), lan_networks=lambda: list(lan["now"]))
    w.settings.update(lambda d: d["vpnclient"].__setitem__("kill_switch", True))
    enables = []
    real_enable = w.killswitch.enable
    w.killswitch.enable = lambda **kw: (enables.append(kw), real_enable(**kw))
    m.start()
    assert w.killswitch.active and w.killswitch.lan == [(RADMIN_LUID, ["26.0.0.0/8"])]
    m.on_network_change()
    assert m.wait_idle(5) and len(enables) == 1, "сети те же — фильтры не трогаем"
    lan["now"] = lan["now"] + [(0x77, ["25.0.0.0/8"])]          # включили Hamachi после VPN
    m.on_network_change()
    assert m.wait_idle(5) and len(enables) == 2 and w.killswitch.lan[-1] == (0x77, ["25.0.0.0/8"])
    m.shutdown()


def test_manager_passes_overrides_and_keeps_binding_without_exit(tmp_path):
    store = basic_store(xhttp=True)
    store.select(next(s for s in store.servers() if s.name == "Helsinki").id)
    calls, exits = [], ["Ethernet"]
    m, w = make_manager(tmp_path, store, physical_interface=lambda overrides=None: (calls.append(overrides),
                                                                                   exits[-1])[1])
    w.settings.update(lambda d: d["vpn"]["overrides"].__setitem__("{l2tp}", "direct"))
    m.start()
    assert m._session.plan.physical_interface == "Ethernet" and calls[-1] == {"{l2tp}": "direct"}
    exits.append(None)                     # Wi-Fi переподключается: прямого выхода нет
    m.on_network_change()
    assert m.wait_idle(5) and m._session.plan.physical_interface == "Ethernet", "без привязки — петля в свой TUN"
    exits.append("Wi-Fi")
    m.on_network_change()
    assert m.wait_idle(5) and m._session.plan.physical_interface == "Wi-Fi"
    m.shutdown()


# ------------------------------------------------------------ что говорить человеку

def _core(tmp_path, snap, compat=True):
    from tests.test_vpnclient_core import make_core
    core = make_core(tmp_path)
    core.settings.update(lambda d: d["vpn"].__setitem__("compat", compat))
    core.vpn_snapshot = snap
    core.zapret.status = "running"
    core.notes = []
    core.notify = lambda level, text, action=None: core.notes.append(text)
    return core


def _internet_snapshot(world, servers=True):
    _add_tunnel(world)
    if servers:
        world.routes.append((SERVER, 32, "192.168.0.1", ETH, 0))
    world.apps = ["Incy"]
    return vpn.scan()


def test_vpn_note_waits_for_the_filter(world, tmp_path):
    """«Обход его не трогает: интерфейс и сервер VPN исключены» — только когда фильтр под этот VPN собран."""
    snap = _internet_snapshot(world)
    core = _core(tmp_path, snap)
    core._announce_vpn(snap)
    core._vpn_note_tick()
    assert core.notes == [], "фильтр ещё прежний — говорить рано"
    core.zapret.vpn_applied = {"mode": "vpn", "interfaces": [ETH, HYPERV], "servers": [SERVER],
                               "servers_seen": [SERVER]}
    core._vpn_note_tick()
    assert len(core.notes) == 1 and "интерфейс и сервер VPN исключены" in core.notes[0]
    core._vpn_note_tick()
    assert len(core.notes) == 1


def test_vpn_note_does_not_claim_server_it_did_not_find(world, tmp_path):
    snap = _internet_snapshot(world, servers=False)
    core = _core(tmp_path, snap)
    core._vpn_note_on_start()
    core.zapret.vpn_applied = {"mode": "vpn", "interfaces": [ETH, HYPERV], "servers": [], "servers_seen": []}
    core._vpn_note_tick()
    assert core.notes == ["Обход включён рядом с VPN (Incy). Обход не трогает его туннель: интерфейс VPN исключён "
                          "из перехвата."]


def test_vpn_note_silent_when_filter_failed(world, tmp_path):
    snap = _internet_snapshot(world)
    core = _core(tmp_path, snap)
    core._announce_vpn(snap)
    core.zapret.vpn_applied = {"mode": "error", "error": "WinDivert", "interfaces": [ETH, HYPERV],
                               "servers_seen": [SERVER]}
    core._vpn_note_tick()
    assert core.notes == [] and core._vpn_note is None, "о неудаче говорит плашка zapret-vpnfilter"


def test_vpn_note_for_proxy_vpn(world, tmp_path):
    world.proxy, world.apps = "http://127.0.0.1:10808", ["Happ"]
    core = _core(tmp_path, vpn.scan())
    core._vpn_note_on_start()
    core._vpn_note_tick()
    assert core.notes == [], "фильтр под Radmin ещё не применён"
    core.zapret.vpn_applied = {"mode": "vpn", "interfaces": [ETH, HYPERV], "servers": [], "servers_seen": []}
    core._vpn_note_tick()
    assert len(core.notes) == 1 and "системный прокси" in core.notes[0] and "не удалось" in core.notes[0]
    world.conns = [("Happ", SERVER)]
    core = _core(tmp_path, vpn.scan())
    core._vpn_note_on_start()
    core.zapret.vpn_applied = {"mode": "vpn", "interfaces": [ETH, HYPERV], "servers": [SERVER],
                               "servers_seen": [SERVER]}
    core._vpn_note_tick()
    assert "соединение VPN с сервером исключено" in core.notes[0]


def test_vpn_note_on_start_with_compat_off_is_the_alert(world, tmp_path):
    snap = _internet_snapshot(world)
    core = _core(tmp_path, snap, compat=False)
    core.zapret.status = "starting"
    core._vpn_note_on_start()
    core._vpn_note_tick()
    assert not core.has_alert("compat-off"), "обход ещё запускается"
    core.zapret.status = "running"
    core._vpn_note_tick()
    assert core.has_alert("compat-off") and core.notes == []


def test_guard_hint_matches_compat_state(world, tmp_path):
    """«Включите совместимость» — только если она выключена."""
    snap = _internet_snapshot(world)
    assert "включите «Совместимость с VPN»" in _core(tmp_path, snap, compat=False)._vpn_conflict_hint()
    on = _core(tmp_path, snap)._vpn_conflict_hint()
    assert "включена, но не помогла" in on and "включите «Совместимость" not in on
    world.adapters = [a for a in world.adapters if a.name != "wwan99"]
    world.proxy, world.apps = "http://127.0.0.1:10808", ["Happ"]
    assert "системный прокси" in _core(tmp_path, vpn.scan())._vpn_conflict_hint()
    assert "стратегия" in _core(tmp_path, None)._vpn_conflict_hint()


@pytest.mark.parametrize("compat, expected", [
    (True, "Виртуальные сети (Radmin VPN) обход не трогает."),
    (False, "обход перехватывает, пока «Совместимость с VPN» выключена"),
])
def test_diagnostics_radmin_line_follows_compat(world, compat, expected):
    from app.zapret.diagnostics import vpn_verdict
    level, text = vpn_verdict(vpn.scan(), compat)
    assert expected in text


def test_diagnostics_vpn_line_follows_compat(world):
    from app.zapret.diagnostics import vpn_verdict
    snap = _internet_snapshot(world)
    assert "включена — обход не трогает его туннель" in vpn_verdict(snap, True)[1]
    off = vpn_verdict(snap, False)[1]
    assert "выключена — обход может мешать VPN" in off and "не трогает" not in off
