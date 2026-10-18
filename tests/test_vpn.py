"""Совместимость с VPN: какие интерфейсы — туннели, фильтр WinDivert и вопрос перед включением."""
import ctypes
import ipaddress
import socket
import struct
from ctypes import wintypes
from pathlib import Path

import pytest

from app import vpn
from app.settings import Settings
from app.zapret import vpnfilter as vf


def _adapter(index, name, if_type=6, component="", description="", chars=0, up=True, ipv4=None,
             gateways=None, ras_device=None, guid=None):
    a = vpn.Adapter(index=index, guid=guid or "{%08d-0000-0000-0000-000000000000}" % index, name=name,
                    description=description, if_type=if_type, up=up, ipv4=list(ipv4 or []),
                    gateways=list(gateways or []))
    a.component, a.characteristics, a.ras_device = component, chars, ras_device
    return a


# ------------------------------------------------------------ какие интерфейсы — туннели

@pytest.mark.parametrize("adapter, kind", [
    (_adapter(5, "wwan99", 53, "Wintun", "Wintun Tunnel", chars=vpn.NCF_VIRTUAL), "tunnel"),   # имя под модем
    (_adapter(7, "home", 53, "wireguard", "WireGuard Tunnel"), "tunnel"),
    (_adapter(14, "Radmin VPN", 6, r"{B06D84D1-AF78-41EC-A5B9-3CCE676528B2}\RvNetMP60",
              "Famatech Radmin VPN Ethernet Adapter", chars=vpn.NCF_VIRTUAL), "tunnel"),
    (_adapter(21, "Ethernet 2", 6, "tap0901", "TAP-Windows Adapter V9", chars=vpn.NCF_VIRTUAL), "tunnel"),
    (_adapter(17, "Ethernet", 6, r"PCI\VEN_10EC&DEV_8168", "Realtek PCIe GbE Family Controller",
              chars=vpn.NCF_PHYSICAL), "direct"),
    (_adapter(18, "Беспроводная сеть", 71, r"PCI\VEN_8086", "Intel Wi-Fi 6 AX201", chars=vpn.NCF_PHYSICAL), "direct"),
    (_adapter(19, "vEthernet (Default Switch)", 6, "", "Hyper-V Virtual Ethernet Adapter",
              chars=vpn.NCF_VIRTUAL), "direct"),
    (_adapter(9, "Teredo Tunneling Pseudo-Interface", 131), "tunnel"),
    (_adapter(30, "Ростелеком", 23, ras_device="PPPoE"), "direct"),   # PPPoE провайдера — сам интернет
    (_adapter(31, "Рабочий VPN", 23, ras_device="vpn"), "tunnel"),    # VPN-подключение Windows
    (_adapter(33, "Билайн", 23, ras_device="isp"), "direct"),         # L2TP провайдера — сам интернет
    (_adapter(32, "Неизвестное PPP", 23), "direct"),
    (_adapter(1, "Loopback Pseudo-Interface 1", 24), "skip"),
])
def test_classify(adapter, kind):
    assert vpn.classify(adapter)[0] == kind


def test_override_wins_but_not_for_loopback():
    wintun = _adapter(5, "wwan99", 53, "Wintun")
    assert vpn.classify(wintun, "direct") == ("direct", "задано вручную")
    assert vpn.classify(_adapter(1, "lo", 24), "tunnel")[0] == "skip"


def test_adapter_app_only_when_adapter_tells():
    assert vpn.adapter_app("wireguard", "WireGuard Tunnel") == "WireGuard"
    assert vpn.adapter_app(r"x\RvNetMP60", "Famatech Radmin VPN Ethernet Adapter") == "Radmin VPN"
    assert vpn.adapter_app("Wintun", "Wintun Tunnel") is None      # безымянный Wintun ничего не говорит


# ------------------------------------------------------------ снимок: план, имя, серверы

def _snapshot(apps=("Incy", "Radmin VPN", "Happ", "Cloudflare WARP"), with_vpn=True):
    adapters = [
        _adapter(17, "Ethernet", 6, r"PCI\VEN", chars=vpn.NCF_PHYSICAL, ipv4=["192.168.0.10"],
                 gateways=["192.168.0.1"]),
        _adapter(19, "vEthernet (Default Switch)", 6, "", "Hyper-V Virtual Ethernet Adapter", chars=vpn.NCF_VIRTUAL,
                 ipv4=["172.20.0.1"]),
        _adapter(9, "Teredo", 131),
        _adapter(14, "Radmin VPN", 6, r"x\RvNetMP60", "Famatech Radmin VPN Ethernet Adapter", ipv4=["26.1.2.3"]),
    ]
    if with_vpn:
        adapters.append(_adapter(5, "wwan99", 53, "Wintun", "Wintun Tunnel", ipv4=["172.19.0.1"],
                                 guid="{2E219888-9139-4199-EA45-CB771D7DAD1D}"))
    for a in adapters:
        a.kind, a.reason = vpn.classify(a)
        a.app = vpn.adapter_app(a.component, a.description) if a.kind == "tunnel" else None
        a.role = ("system" if a.if_type == 131 else "internet" if a.index == 5 else "lan") if a.kind == "tunnel" else ""
        a.default_route = a.index == 5
    return vpn.Snapshot(adapters=adapters, servers=["203.0.113.7"] if with_vpn else [], apps=list(apps), at=0.0)


def test_snapshot_plan_and_label():
    snap = _snapshot()
    assert snap.full_tunnel and [a.name for a in snap.internet] == ["wwan99"]
    assert snap.plan() == {"interfaces": [17, 19], "servers": ["203.0.113.7"]}
    # Radmin — локальная сеть, WARP без адаптера: на роль «того самого VPN» не претендуют.
    assert snap.candidates() == ["Incy", "Happ"] and snap.label() == "Incy или Happ"
    assert snap.source_ip() == "192.168.0.10"
    assert snap.signature() == ["Wintun:{2e219888-9139-4199-ea45-cb771d7dad1d}"]


def test_owner_by_connections_beats_background_apps():
    """Incy держит соединения с адреса Ethernet, служба Happ просто висит в фоне."""
    snap = _snapshot()
    snap.owners = ["Incy"]
    assert snap.candidates() == ["Incy"] and snap.label() == "Incy"


def test_active_core_apps(monkeypatch):
    import psutil
    from collections import namedtuple
    Addr = namedtuple("Addr", "ip port")
    Conn = namedtuple("Conn", "pid laddr status")
    conns = [Conn(10, Addr("192.168.0.10", 50000), psutil.CONN_ESTABLISHED),    # incy.exe с Ethernet
             Conn(20, Addr("127.0.0.1", 50001), psutil.CONN_ESTABLISHED),       # happd — только петля
             Conn(30, Addr("192.168.0.10", 50002), psutil.CONN_ESTABLISHED),    # браузер — не VPN
             Conn(40, Addr("192.168.0.10", 50003), psutil.CONN_TIME_WAIT)]
    names = {10: "incy.exe", 20: "happd.exe", 30: "msedge.exe", 40: "hiddify.exe"}

    class P:
        def __init__(self, pid):
            self.pid = pid

        def name(self):
            return names[self.pid]

    monkeypatch.setattr(psutil, "net_connections", lambda kind="tcp": conns)
    monkeypatch.setattr(psutil, "Process", P)
    assert vpn.active_core_apps({"192.168.0.10"}) == ["Incy"]
    assert vpn.active_core_apps(set()) == []


def test_vpn_without_adapter_is_flagged():
    snap = _snapshot(apps=("ExpressVPN",), with_vpn=False)
    assert snap.unseparable == ["ExpressVPN"] and snap.to_dict()["unseparable"] == ["ExpressVPN"]
    assert _snapshot(apps=("Incy",)).unseparable == []


def test_label_without_known_apps_names_adapter():
    assert _snapshot(apps=()).label() == "VPN «wwan99»"


def test_no_vpn_adapters_means_plain_filter():
    snap = _snapshot(with_vpn=False)
    snap.adapters = [a for a in snap.adapters if a.name != "Radmin VPN"]
    assert snap.plan() is None                  # Teredo — системный туннель, не повод что-то менять
    assert not snap.internet and not snap.full_tunnel


def test_server_routes():
    table = [
        ("93.184.216.34", 32, "192.168.0.1", 17),       # сервер VPN — мимо туннеля
        ("2001:4860:4860::8844", 128, "fe80::1", 17),    # сервер по IPv6
        ("203.0.113.8", 32, "192.168.0.1", 17),          # адрес для документации — не публичный
        ("10.8.0.1", 32, "192.168.0.1", 17),             # частный адрес — не сервер
        ("198.51.100.9", 32, "0.0.0.0", 17),             # on-link — не обход туннеля
        ("8.8.4.4", 32, "172.19.0.1", 5),                # через сам туннель
        ("0.0.0.0", 0, "192.168.0.1", 17),
    ]
    assert vpn.server_routes(table, {17, 19}) == ["2001:4860:4860::8844", "93.184.216.34"]


def test_many_bypass_routes_are_split_tunnel_not_servers():
    """Клиенты, которые пускают сайты мимо VPN маршрутами /32, — это не серверы: иначе обход
    перестал бы трогать, например, тот же Discord."""
    table = [(f"162.159.{i}.1", 32, "192.168.0.1", 17) for i in range(10)]
    assert vpn.server_routes(table, {17}) == []


@pytest.mark.parametrize("applied, wanted, restart", [
    ({"mode": "plain"}, {"interfaces": [17], "servers": []}, True),                 # VPN появился
    ({"mode": "vpn", "interfaces": [17], "servers_seen": ["1.2.3.4"]},
     {"interfaces": [17], "servers": ["1.2.3.4"]}, False),                         # ничего не поменялось
    ({"mode": "vpn", "interfaces": [17], "servers_seen": []}, None, False),        # VPN пропал — фильтр верен
    ({"mode": "vpn", "interfaces": [17], "servers_seen": []},
     {"interfaces": [17, 23], "servers": []}, True),                               # новый прямой интерфейс
    ({"mode": "vpn", "interfaces": [17], "servers_seen": ["1.2.3.4"]},
     {"interfaces": [17], "servers": ["5.6.7.8"]}, True),                          # другой сервер VPN
    ({"mode": "error", "interfaces": [17], "servers_seen": []},
     {"interfaces": [17], "servers": []}, False),                                  # не собрался — не по кругу
    ({"mode": "plain"}, None, False),
])
def test_plan_changed(applied, wanted, restart):
    assert vpn.plan_changed(applied, wanted, [17]) is restart


def test_stale_filter_after_vpn_gone_and_new_adapter():
    """VPN отключили, потом воткнули USB-модем: старый фильтр его бы не обходил."""
    applied = {"mode": "vpn", "interfaces": [17], "servers_seen": []}
    assert vpn.plan_changed(applied, None, [17]) is False
    assert vpn.plan_changed(applied, None, [17, 31]) is True


# ------------------------------------------------------------ что куда идёт

VPN4, DIRECT4 = "198.51.100.20", "203.0.113.50"


@pytest.mark.parametrize("seen, vpn_exits, direct_exits, via", [
    (VPN4, [VPN4], [DIRECT4], "vpn"),
    (DIRECT4, [VPN4], [DIRECT4], "direct"),
    (None, [VPN4], [DIRECT4], "blocked"),
    (None, [None], [None], "unknown"),                       # не ответило вообще ничего
    ("2a14:7c0:1002:12f9::1", ["2a14:7c0:1002:12f9::"], [DIRECT4], "vpn"),   # тот же /56 IPv6
    ("192.0.2.77", [VPN4], [DIRECT4], "unknown"),            # незнакомый адрес — не гадаем
    (DIRECT4, [None], [DIRECT4], "direct"),
    (VPN4, [None], [DIRECT4], "unknown"),                    # выход VPN не подтверждён
])
def test_judge(seen, vpn_exits, direct_exits, via):
    assert vpn.judge(seen, vpn_exits, direct_exits) == via


def test_judge_ipv6_leaking_past_ipv4_only_vpn():
    """VPN заворачивает только IPv4, а сайт видит наш собственный IPv6 — это «напрямую»."""
    mine = [ipaddress.ip_network("2a02:2168:1:2::/64")]
    assert vpn.judge("2a02:2168:1:2::abcd", [VPN4], [DIRECT4], mine) == "direct"
    assert vpn.judge("2a14:7c0:1002:12f9::1", [VPN4, "2a14:7c0:1002:12f9::"], [DIRECT4], mine) == "vpn"
    assert vpn.judge("2a14:7c0:1002:12f9::1", [VPN4], [DIRECT4], mine) == "unknown"


def _fake_curl(monkeypatch, seen: dict, python=None):
    monkeypatch.setattr(vpn, "_curl_seen", lambda url, bind=None, proxy=None, timeout=6: seen.get((url, bind, proxy)))
    monkeypatch.setattr(vpn, "_python_seen", lambda *a, **k: python)


def test_probe_routes_full_tunnel(monkeypatch):
    _fake_curl(monkeypatch, {
        (vpn.TRACE_DEFAULT, "192.168.0.10", None): DIRECT4,     # эталон «напрямую» — привязка к Ethernet
        (vpn.TRACE_DEFAULT, "172.19.0.1", None): VPN4,          # эталон «через VPN» — привязка к туннелю
        (vpn.TRACE_DEFAULT_HOST, "172.19.0.1", None): VPN4,
        (vpn.TRACE_DISCORD[0], None, None): DIRECT4,            # Discord VPN пускает мимо себя
        (vpn.TRACE_YOUTUBE, None, None): VPN4,
        (vpn.TRACE_DEFAULT_HOST, None, None): VPN4,
    })
    result = vpn.probe_routes(_snapshot())
    via = {i["id"]: i["via"] for i in result["items"]}
    assert via == {"discord": "direct", "youtube": "vpn", "telegram": "blocked", "other": "vpn"}
    assert result["mode"] == "tunnel" and result["checked_direct"] and result["checked_vpn"]


def test_probe_routes_system_proxy(monkeypatch):
    """VPN в режиме системного прокси: браузер и Discord идут через прокси, Telegram-прокси — нет."""
    proxy = "http://127.0.0.1:10808"
    snap = _snapshot(with_vpn=False)
    snap.proxy = proxy
    _fake_curl(monkeypatch, {
        (vpn.TRACE_DEFAULT, None, None): DIRECT4,
        (vpn.TRACE_DEFAULT, None, proxy): VPN4,
        (vpn.TRACE_DEFAULT_HOST, None, proxy): VPN4,
        (vpn.TRACE_DISCORD[0], None, proxy): VPN4,
        (vpn.TRACE_YOUTUBE, None, proxy): DIRECT4,              # правило «напрямую» в программе
    }, python=DIRECT4)
    assert snap.active and snap.to_dict()["mode"] == "proxy"
    result = vpn.probe_routes(snap)
    via = {i["id"]: i["via"] for i in result["items"]}
    assert via == {"discord": "vpn", "youtube": "direct", "telegram": "direct", "other": "vpn"}
    assert result["mode"] == "proxy"


# ------------------------------------------------------------ фильтр WinDivert

def test_without_wf_and_raw_args():
    args = ["--wf-tcp=80,443", "--wf-udp=443", "--wf-l3=ipv4", "--filter-tcp=443", "--wf-raw=@old.txt",
            "--new", "--wf-save=x.txt"]
    assert vf.without_wf(args, keep_ports=True) == ["--wf-tcp=80,443", "--wf-udp=443", "--wf-l3=ipv4",
                                                    "--filter-tcp=443", "--new"]
    path = Path("C:/data/f.txt")
    assert vf.with_raw_filter(args, path) == ["--filter-tcp=443", "--new", f"--wf-raw=@{path}"]


def test_wrap_refuses_nonsense():
    with pytest.raises(vf.VpnFilterError):
        vf.wrap("   ", [17], [])
    with pytest.raises(vf.VpnFilterError):
        vf.wrap("tcp", [], [])


def test_guard_servers_only_exact_shared_address():
    targets = {"162.159.135.232"}
    assert vf.guard_servers(["162.159.135.232", "162.159.135.9", "203.0.113.7", "bad"], targets) == [
        "162.159.135.9", "203.0.113.7"]


# Короткий фильтр того же вида, что строит winws: исходящие на 443 и ответы SYN-ACK,
# без локальных сетей.
BASE = """!impostor and !loopback and
(
 (
  (outbound and (!tcp or tcp.Syn or tcp.Rst or tcp.Fin or tcp.PayloadLength>0) and ((tcp.DstPort == 443) or (udp.DstPort == 443)))
  or
  (inbound and tcp and (tcp.Ack and tcp.Syn or tcp.Rst or tcp.Fin) and (tcp.SrcPort == 443))
 )
)
and
(
 outbound and ((ip.DstAddr < 192.168.0.0 or ip.DstAddr > 192.168.255.255) or ipv6)
 or
 inbound and ((ip.SrcAddr < 192.168.0.0 or ip.SrcAddr > 192.168.255.255) or ipv6)
)
"""
ME4, ME6, SERVER4, SERVER6 = "192.168.0.10", "2a02:2168:1::10", "203.0.113.7", "2001:db8:77::1"


def _tcp(sport, dport, flags=0x02):
    return struct.pack("!HHIIBBHHH", sport, dport, 1, 0, 5 << 4, flags, 65535, 0, 0)


def _v4(src, dst, l4):
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), 1, 0, 64, 6, 0,
                       socket.inet_aton(src), socket.inet_aton(dst)) + l4


def _v6(src, dst, l4):
    return struct.pack("!IHBB16s16s", 6 << 28, len(l4), 6, 64, socket.inet_pton(socket.AF_INET6, src),
                       socket.inet_pton(socket.AF_INET6, dst)) + l4


def _addr(ifidx, outbound=True, ipv6=False):
    """WINDIVERT_ADDRESS: Timestamp, биты Layer/Event/…/Outbound(17)/IPv6(20), IfIdx, SubIfIdx."""
    bits = (1 << 17 if outbound else 0) | (1 << 20 if ipv6 else 0)
    return struct.pack("<qIIII", 0, bits, 0, ifidx, 0) + bytes(80 - 24)


@pytest.fixture(scope="module")
def windivert(pack_dir):
    dll = pack_dir / "bin" / "WinDivert.dll"
    lib = ctypes.WinDLL(str(dll))
    lib.WinDivertHelperEvalFilter.argtypes = [ctypes.c_char_p, ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p]
    lib.WinDivertHelperEvalFilter.restype = wintypes.BOOL
    yield dll, lib
    ctypes.windll.kernel32.FreeLibrary(ctypes.c_void_p(lib._handle))


def test_wrapped_filter_compiles(windivert):
    dll, _ = windivert
    assert vf.compile_check(dll, BASE) is None
    assert vf.compile_check(dll, vf.wrap(BASE, [17, 19], [SERVER4, SERVER6])) is None
    assert vf.compile_check(dll, "tcp and !(ip.DstAddr == 1.2.3.4)") is not None   # язык WinDivert так не умеет


@pytest.mark.parametrize("name, packet, address, caught", [
    ("Discord через Ethernet", _v4(ME4, "162.159.135.232", _tcp(50000, 443)), _addr(17), True),
    ("Discord через Hyper-V", _v4(ME4, "162.159.135.232", _tcp(50000, 443)), _addr(19), True),
    ("Discord внутри туннеля VPN", _v4("172.19.0.1", "162.159.135.232", _tcp(50000, 443)), _addr(5), False),
    ("сервер VPN", _v4(ME4, SERVER4, _tcp(50001, 443)), _addr(17), False),
    ("ответ сервера VPN", _v4(SERVER4, ME4, _tcp(443, 50001, 0x12)), _addr(17, outbound=False), False),
    ("ответ Discord", _v4("162.159.135.232", ME4, _tcp(443, 50000, 0x12)), _addr(17, outbound=False), True),
    ("IPv6 YouTube через Ethernet", _v6(ME6, "2a00:1450:4010:c05::5d", _tcp(50002, 443)), _addr(17, ipv6=True), True),
    ("IPv6 сервер VPN", _v6(ME6, SERVER6, _tcp(50003, 443)), _addr(17, ipv6=True), False),
    ("IPv6 внутри туннеля", _v6(ME6, "2a00:1450:4010:c05::5d", _tcp(50004, 443)), _addr(5, ipv6=True), False),
])
def test_wrapped_filter_semantics(windivert, name, packet, address, caught):
    _, lib = windivert
    flt = vf.wrap(BASE, [17, 19], [SERVER4, SERVER6]).encode()
    pkt = ctypes.create_string_buffer(packet, len(packet))
    addr = ctypes.create_string_buffer(address, 80)
    assert bool(lib.WinDivertHelperEvalFilter(flt, pkt, len(packet), addr)) is caught, name


def test_build_uses_winws_save_and_caches(tmp_path, monkeypatch, pack_dir):
    """Фильтр собирается из того, что сохранил winws, проверяется и кэшируется по аргументам."""
    import shutil
    from app import winutil
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    shutil.copy(pack_dir / "bin" / "WinDivert.dll", bin_dir)
    winws = bin_dir / "winws.exe"
    winws.write_bytes(b"MZ")
    calls = []

    def fake_run(cmd, timeout=30.0, cwd=None):
        calls.append(cmd)
        target = next(a.split("=", 1)[1] for a in cmd if a.startswith("--wf-save="))
        Path(target).write_text(BASE, encoding="ascii")
        return winutil.RunResult(0, "", "")

    monkeypatch.setattr(vf.winutil, "run", fake_run)
    args = ["--wf-tcp=443", "--filter-tcp=443", "--dpi-desync=fake"]
    first = vf.build(winws, args, [17], [SERVER4], tmp_path / "filters")
    assert first.read_text(encoding="ascii").count("ifIdx=17") == 1
    assert calls[0][1:-1] == args and calls[0][-1].startswith("--wf-save=")
    vf.build(winws, args, [17, 19], [SERVER4], tmp_path / "filters")
    assert len(calls) == 1          # исходный фильтр winws не пересобирается ради другого набора интерфейсов
    assert not list((tmp_path / "filters").glob("*.tmp"))


def test_probe_filters_never_evict_the_working_one(tmp_path, monkeypatch, pack_dir):
    """Подбор строит по фильтру на стратегию; файл, на который ссылается служба, уцелеть обязан."""
    import shutil
    from app import winutil
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    shutil.copy(pack_dir / "bin" / "WinDivert.dll", bin_dir)
    winws = bin_dir / "winws.exe"
    winws.write_bytes(b"MZ")

    def fake_run(cmd, timeout=30.0, cwd=None):
        Path(next(a.split("=", 1)[1] for a in cmd if a.startswith("--wf-save="))).write_text(BASE, encoding="ascii")
        return winutil.RunResult(0, "", "")

    monkeypatch.setattr(vf.winutil, "run", fake_run)
    folder = tmp_path / "vpnfilter"
    working = vf.build(winws, ["--wf-tcp=443", "--filter-tcp=443"], [17], [], folder, cache=folder / "base")
    for i in range(40):
        vf.build(winws, ["--wf-tcp=443", f"--filter-tcp={1000 + i}"], [17], [], folder / "probe",
                 cache=folder / "base", keep_files=vf.KEEP_PROBES)
    assert working.is_file()
    assert len(list((folder / "probe").glob("vpn-*.txt"))) == vf.KEEP_PROBES
    assert len(list((folder / "base").glob("base-*.txt"))) == vf.KEEP_BASES


def test_build_failure_is_reported(tmp_path, monkeypatch):
    from app import winutil
    winws = tmp_path / "winws.exe"
    winws.write_bytes(b"MZ")
    monkeypatch.setattr(vf.winutil, "run", lambda cmd, timeout=30.0, cwd=None: winutil.RunResult(1, "", "bad arg"))
    with pytest.raises(vf.VpnFilterError, match="bad arg"):
        vf.build(winws, ["--wf-tcp=443"], [17], [], tmp_path / "f")


# ------------------------------------------------------------ вопрос перед включением

def _core(tmp_path, monkeypatch, snap):
    from app.core import Core
    core = Core.__new__(Core)
    core.settings = Settings(tmp_path / "c.json")
    core.vpn_snapshot, core.vpn_routes, core._vpn_scan_at = None, None, 0.0
    core.background = lambda name, fn, on_error: fn()
    monkeypatch.setattr(vpn, "scan", lambda overrides=None, own=None: snap)
    monkeypatch.setattr(vpn, "probe_routes", lambda s: {"items": [], "full_tunnel": True, "at": 1.0})

    class Z:
        status, paused_for_test, vpn_applied = "stopped", False, {"mode": "plain"}

    core.zapret = Z()
    return core


def test_preflight_asks_once_per_vpn(tmp_path, monkeypatch):
    core = _core(tmp_path, monkeypatch, _snapshot())
    first = core.vpn_preflight("zapret")
    assert first["ok"] and first["ask"] and first["vpn"]["label"] == "Incy или Happ"
    assert core.vpn_routes and core.vpn_routes["running"] is False      # маршруты уже проверены
    core.vpn_answer(remember=True, compat=True)
    assert core.vpn_preflight("tg")["ask"] is False
    core.vpn_forget()
    assert core.vpn_preflight("tg")["ask"] is True


def test_preflight_silent_without_vpn(tmp_path, monkeypatch):
    core = _core(tmp_path, monkeypatch, _snapshot(with_vpn=False))
    assert core.vpn_preflight("zapret")["ask"] is False


def test_compat_off_means_plain(tmp_path, monkeypatch):
    core = _core(tmp_path, monkeypatch, _snapshot())
    assert core._vpn_plan() == {"interfaces": [17, 19], "servers": ["203.0.113.7"]}
    core.settings.update(lambda d: d["vpn"].__setitem__("compat", False))
    assert core._vpn_plan() is None


def test_isp_l2tp_server_pattern():
    assert vpn.ISP_TUNNEL_SERVERS.search("tp.internet.beeline.ru")
    assert not vpn.ISP_TUNNEL_SERVERS.search("vpn.example.com")
    assert not vpn.ISP_TUNNEL_SERVERS.search("notbeeline.ru")
