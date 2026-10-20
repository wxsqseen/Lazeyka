"""VPN рядом с обходом: какие сетевые интерфейсы — туннели и куда на самом деле идут сайты.

Обход в режиме «Совместимость с VPN» перехватывает пакеты только на прямых интерфейсах
(см. zapret/vpnfilter.py), поэтому трафик внутри туннеля он не трогает. Этот модуль —
только наблюдение: адаптеры (GetAdaptersAddresses), их драйверы (реестр), подключения RAS,
маршруты, системный прокси, адреса серверов VPN и проверка, с какого адреса сайты видят нас
через VPN и напрямую.

Свой VPN Лазейки (app/vpnclient) сюда приходит готовым снимком OwnVpn: его адаптер, процессы
ядер и системный прокси чужими не считаются, а его серверы обход не трогает всегда.
"""
from __future__ import annotations

import configparser
import ctypes
import ipaddress
import logging
import os
import re
import socket
import struct
import time
import winreg
from concurrent.futures import ThreadPoolExecutor
from ctypes import wintypes
from dataclasses import dataclass, field
from pathlib import Path
from typing import NamedTuple

from . import winutil

log = logging.getLogger("lazeyka.vpn")

# ------------------------------------------------------------ WinAPI: адаптеры и маршруты

AF_UNSPEC, AF_INET, AF_INET6 = 0, 2, 23
GAA_FLAG_SKIP_ANYCAST = 0x2
GAA_FLAG_SKIP_MULTICAST = 0x4
GAA_FLAG_SKIP_DNS_SERVER = 0x8
GAA_FLAG_INCLUDE_GATEWAYS = 0x80
ERROR_BUFFER_OVERFLOW = 111
ERROR_NO_DATA = 232
ERROR_BUFFER_TOO_SMALL = 603
IF_OPER_UP = 1

IF_TYPE_PPP = 23
IF_TYPE_LOOPBACK = 24
IF_TYPE_PROP_VIRTUAL = 53
IF_TYPE_WIFI = 71
IF_TYPE_TUNNEL = 131

NCF_VIRTUAL = 0x1
NCF_PHYSICAL = 0x4
NET_CLASS_KEY = r"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"
INTERNET_SETTINGS_KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
RASET_VPN = 2
MAX_SERVER_ROUTES = 3   # больше маршрутов /32 мимо туннеля — это уже раздельное туннелирование, не серверы
# Виртуальные локальные сети для игр: интернета через них нет никогда, даже с маршрутом по умолчанию
# (у Radmin VPN — шлюз 26.0.0.1 и маршрут 0.0.0.0/0 с метрикой 9256: он выигрывает, когда прямой пропал).
LAN_APPS = frozenset({"Radmin VPN", "Hamachi"})
# Сети этих адаптеров kill switch своего VPN не закрывает: это локальные сети, а не интернет.
LAN_NETWORK_APPS = LAN_APPS | {"ZeroTier", "Tailscale"}
LAN_MIN_PREFIX = {4: 8, 6: 16}   # маршрут шире — уже в интернет (0.0.0.0/0, ::/0, 0/1), а не сеть адаптера
LAN_MAX_NETS = 64                # фильтров kill switch на один адаптер — с запасом для сетей Tailscale
# Серверы, через которые провайдеры дают сам интернет по L2TP/PPTP: для Windows это «VPN», но
# обход на таком подключении нужен, как на обычном.
ISP_TUNNEL_SERVERS = re.compile(r"(^|\.)(beeline\.ru|corbina\.net)$", re.I)


class SOCKET_ADDRESS(ctypes.Structure):
    _fields_ = [("lpSockaddr", ctypes.c_void_p), ("iSockaddrLength", ctypes.c_int)]


class IP_ADAPTER_UNICAST_ADDRESS(ctypes.Structure):
    pass


IP_ADAPTER_UNICAST_ADDRESS._fields_ = [
    ("Length", wintypes.ULONG), ("Flags", wintypes.DWORD),
    ("Next", ctypes.POINTER(IP_ADAPTER_UNICAST_ADDRESS)),
    ("Address", SOCKET_ADDRESS),
]


class IP_ADAPTER_GATEWAY_ADDRESS(ctypes.Structure):
    pass


IP_ADAPTER_GATEWAY_ADDRESS._fields_ = [
    ("Length", wintypes.ULONG), ("Reserved", wintypes.DWORD),
    ("Next", ctypes.POINTER(IP_ADAPTER_GATEWAY_ADDRESS)),
    ("Address", SOCKET_ADDRESS),
]


class IP_ADAPTER_ADDRESSES(ctypes.Structure):
    pass


# Раскладка IP_ADAPTER_ADDRESSES_LH из iptypes.h (Windows Vista и новее), 448 байт на x64.
IP_ADAPTER_ADDRESSES._fields_ = [
    ("Length", wintypes.ULONG),
    ("IfIndex", wintypes.DWORD),
    ("Next", ctypes.POINTER(IP_ADAPTER_ADDRESSES)),
    ("AdapterName", ctypes.c_char_p),
    ("FirstUnicastAddress", ctypes.POINTER(IP_ADAPTER_UNICAST_ADDRESS)),
    ("FirstAnycastAddress", ctypes.c_void_p),
    ("FirstMulticastAddress", ctypes.c_void_p),
    ("FirstDnsServerAddress", ctypes.c_void_p),
    ("DnsSuffix", ctypes.c_wchar_p),
    ("Description", ctypes.c_wchar_p),
    ("FriendlyName", ctypes.c_wchar_p),
    ("PhysicalAddress", ctypes.c_ubyte * 8),
    ("PhysicalAddressLength", wintypes.ULONG),
    ("Flags", wintypes.ULONG),
    ("Mtu", wintypes.ULONG),
    ("IfType", wintypes.ULONG),
    ("OperStatus", ctypes.c_int),
    ("Ipv6IfIndex", wintypes.DWORD),
    ("ZoneIndices", wintypes.ULONG * 16),
    ("FirstPrefix", ctypes.c_void_p),
    ("TransmitLinkSpeed", ctypes.c_uint64),
    ("ReceiveLinkSpeed", ctypes.c_uint64),
    ("FirstWinsServerAddress", ctypes.c_void_p),
    ("FirstGatewayAddress", ctypes.POINTER(IP_ADAPTER_GATEWAY_ADDRESS)),
    ("Ipv4Metric", wintypes.ULONG),
    ("Ipv6Metric", wintypes.ULONG),
    ("Luid", ctypes.c_uint64),
    ("Dhcpv4Server", SOCKET_ADDRESS),
    ("CompartmentId", ctypes.c_uint32),
    ("NetworkGuid", ctypes.c_ubyte * 16),
    ("ConnectionType", ctypes.c_int),
    ("TunnelType", ctypes.c_int),
    ("Dhcpv6Server", SOCKET_ADDRESS),
    ("Dhcpv6ClientDuid", ctypes.c_ubyte * 130),
    ("Dhcpv6ClientDuidLength", wintypes.ULONG),
    ("Dhcpv6Iaid", wintypes.ULONG),
    ("FirstDnsSuffix", ctypes.c_void_p),
]


class IP_ADDRESS_PREFIX(ctypes.Structure):
    # SOCKADDR_INET — объединение sockaddr_in/sockaddr_in6 (28 байт, выравнивание 4).
    _fields_ = [("Prefix", ctypes.c_uint32 * 7), ("PrefixLength", ctypes.c_ubyte)]


class MIB_IPFORWARD_ROW2(ctypes.Structure):
    """netioapi.h, 104 байта на x64."""
    _fields_ = [
        ("InterfaceLuid", ctypes.c_uint64),
        ("InterfaceIndex", wintypes.ULONG),
        ("DestinationPrefix", IP_ADDRESS_PREFIX),
        ("NextHop", ctypes.c_uint32 * 7),
        ("SitePrefixLength", ctypes.c_ubyte),
        ("ValidLifetime", wintypes.ULONG),
        ("PreferredLifetime", wintypes.ULONG),
        ("Metric", wintypes.ULONG),
        ("Protocol", ctypes.c_int),
        ("Loopback", ctypes.c_ubyte),
        ("AutoconfigureAddress", ctypes.c_ubyte),
        ("Publish", ctypes.c_ubyte),
        ("Immortal", ctypes.c_ubyte),
        ("Age", wintypes.ULONG),
        ("Origin", ctypes.c_int),
    ]


class RASCONNW(ctypes.Structure):
    """ras.h для Windows 7 и новее, 1392 байта на x64."""
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("hrasconn", wintypes.HANDLE),
        ("szEntryName", wintypes.WCHAR * 257),
        ("szDeviceType", wintypes.WCHAR * 17),
        ("szDeviceName", wintypes.WCHAR * 129),
        ("szPhonebook", wintypes.WCHAR * 260),
        ("dwSubEntry", wintypes.DWORD),
        ("guidEntry", ctypes.c_uint32 * 4),
        ("dwFlags", wintypes.DWORD),
        ("luid", ctypes.c_uint32 * 2),
        ("guidCorrelationId", ctypes.c_uint32 * 4),
    ]


_iphlpapi = None


def _api():
    """iphlpapi.dll из System32 — по полному пути, а не по порядку поиска DLL."""
    global _iphlpapi
    if _iphlpapi is None:
        lib = ctypes.WinDLL(winutil.system32("iphlpapi.dll"), use_last_error=True)
        lib.GetAdaptersAddresses.argtypes = [wintypes.ULONG, wintypes.ULONG, ctypes.c_void_p, ctypes.c_void_p,
                                             ctypes.POINTER(wintypes.ULONG)]
        lib.GetAdaptersAddresses.restype = wintypes.ULONG
        lib.GetIpForwardTable2.argtypes = [ctypes.c_ushort, ctypes.POINTER(ctypes.c_void_p)]
        lib.GetIpForwardTable2.restype = wintypes.DWORD
        lib.FreeMibTable.argtypes = [ctypes.c_void_p]
        lib.FreeMibTable.restype = None
        lib.GetBestInterface.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
        lib.GetBestInterface.restype = wintypes.DWORD
        _iphlpapi = lib
    return _iphlpapi


def _raw_ip(raw: bytes) -> str | None:
    """Адрес из sockaddr_in / sockaddr_in6."""
    if len(raw) < 8:
        return None
    family = struct.unpack_from("<H", raw)[0]
    if family == AF_INET:
        return socket.inet_ntop(socket.AF_INET, raw[4:8])
    if family == AF_INET6 and len(raw) >= 24:
        return socket.inet_ntop(socket.AF_INET6, raw[8:24])
    return None


def _sockaddr_ip(sa: SOCKET_ADDRESS) -> str | None:
    if not sa.lpSockaddr or sa.iSockaddrLength < 8:
        return None
    return _raw_ip(ctypes.string_at(sa.lpSockaddr, sa.iSockaddrLength))


# ------------------------------------------------------------ адаптеры

@dataclass
class Adapter:
    index: int
    guid: str                    # AdapterName — {GUID}, он же NetCfgInstanceId в реестре
    name: str                    # имя в «Сетевых подключениях» (его можно переименовать)
    description: str
    if_type: int
    up: bool
    ipv4: list[str] = field(default_factory=list)
    ipv6: list[str] = field(default_factory=list)
    gateways: list[str] = field(default_factory=list)
    metric: int = 0              # метрика интерфейса IPv4 (Ipv4Metric)
    metric6: int = 0             # метрика интерфейса IPv6
    luid: int = 0
    # Метрика самого выгодного маршрута по умолчанию (0.0.0.0/0, ::/0) через адаптер; None — такого нет.
    # Windows выбирает выход в интернет по сумме метрики маршрута и метрики интерфейса.
    default4_metric: int | None = None
    default6_metric: int | None = None
    component: str = ""          # ComponentId драйвера: Wintun, wireguard, tap0901, PCI\VEN_…
    characteristics: int = 0     # NCF_* из реестра
    ras_device: str | None = None  # для PPP: тип устройства RAS — «vpn», «PPPoE», «modem»…
    default_route: bool = False  # через него Windows сейчас отправляет интернет по умолчанию
    ipv6_index: int = 0          # обычно совпадает с index; WinDivert для IPv6 смотрит на него
    kind: str = "direct"         # direct | tunnel | skip
    role: str = ""               # у туннелей: internet | lan | idle | system
    app: str | None = None       # программа, если её видно по самому адаптеру
    reason: str = ""
    own: bool = False            # TUN своего VPN Лазейки
    # Через туннель идут проверочные адреса, но доказать «VPN в интернет» нечем: прямого маршрута по
    # умолчанию нет (Wi-Fi переподключается, выход из сна). Пока — lan; keep_roles вернёт прежнюю роль.
    pending_internet: bool = False

    @property
    def routable(self) -> bool:
        return self.up and bool(self.ipv4 or [a for a in self.ipv6 if not a.startswith("fe80")])

    @property
    def indices(self) -> set[int]:
        return {i for i in (self.index, self.ipv6_index) if i > 0}


def list_adapters() -> list[Adapter]:
    api = _api()
    flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_INCLUDE_GATEWAYS
    size = wintypes.ULONG(32 * 1024)
    for _ in range(4):
        buf = ctypes.create_string_buffer(size.value)
        ret = api.GetAdaptersAddresses(AF_UNSPEC, flags, None, buf, ctypes.byref(size))
        if ret == ERROR_BUFFER_OVERFLOW:
            continue
        if ret == ERROR_NO_DATA:
            return []
        if ret != 0:
            raise OSError(ret, "GetAdaptersAddresses")
        break
    else:
        raise OSError(ERROR_BUFFER_OVERFLOW, "GetAdaptersAddresses")
    out: list[Adapter] = []
    node = ctypes.cast(buf, ctypes.POINTER(IP_ADAPTER_ADDRESSES))
    while node:
        a = node.contents
        ipv4, ipv6, gateways = [], [], []
        uni = a.FirstUnicastAddress
        while uni:
            ip = _sockaddr_ip(uni.contents.Address)
            if ip:
                (ipv6 if ":" in ip else ipv4).append(ip)
            uni = uni.contents.Next
        gw = a.FirstGatewayAddress
        while gw:
            ip = _sockaddr_ip(gw.contents.Address)
            if ip:
                gateways.append(ip)
            gw = gw.contents.Next
        out.append(Adapter(
            index=int(a.IfIndex or a.Ipv6IfIndex), guid=(a.AdapterName or b"").decode("ascii", "replace"),
            name=a.FriendlyName or "", description=a.Description or "", if_type=int(a.IfType),
            up=a.OperStatus == IF_OPER_UP, ipv4=ipv4, ipv6=ipv6, gateways=gateways, metric=int(a.Ipv4Metric),
            metric6=int(a.Ipv6Metric), luid=int(a.Luid), ipv6_index=int(a.Ipv6IfIndex)))
        node = a.Next
    return out


def _driver_info() -> dict[str, tuple[str, int]]:
    """NetCfgInstanceId → (ComponentId, Characteristics) из ветки класса сетевых адаптеров."""
    out: dict[str, tuple[str, int]] = {}
    try:
        root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, NET_CLASS_KEY)
    except OSError:
        return out
    with root:
        for i in range(2048):
            try:
                sub = winreg.EnumKey(root, i)
            except OSError:
                break
            try:
                with winreg.OpenKey(root, sub) as key:
                    guid = str(winreg.QueryValueEx(key, "NetCfgInstanceId")[0]).lower()
                    component = _reg_str(key, "ComponentId")
                    try:
                        chars = int(winreg.QueryValueEx(key, "Characteristics")[0])
                    except (OSError, ValueError, TypeError):
                        chars = 0
                    out[guid] = (component, chars)
            except OSError:
                continue  # «Properties» и ветки без прав чтения
    return out


def _reg_str(key, name: str) -> str:
    try:
        return str(winreg.QueryValueEx(key, name)[0])
    except OSError:
        return ""


def ras_connections() -> dict[str, str]:
    """Активные подключения RAS: имя → тип устройства («vpn», «PPPoE», «modem»…).

    Телефонные книги бывают и свои, не только стандартные, поэтому спрашиваем саму службу
    удалённого доступа о том, что подключено сейчас. L2TP провайдера (Билайн) для Windows —
    тоже «vpn»; такие подключения узнаём по адресу сервера и называем «isp»."""
    try:
        rasapi = ctypes.WinDLL(winutil.system32("rasapi32.dll"))
    except OSError:
        return {}
    fn = rasapi.RasEnumConnectionsW
    fn.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD)]
    fn.restype = wintypes.DWORD
    count = 16
    for _ in range(3):
        conns = (RASCONNW * count)()
        conns[0].dwSize = ctypes.sizeof(RASCONNW)
        size, found = wintypes.DWORD(ctypes.sizeof(conns)), wintypes.DWORD(0)
        ret = fn(conns, ctypes.byref(size), ctypes.byref(found))
        if ret == ERROR_BUFFER_TOO_SMALL:
            count = size.value // ctypes.sizeof(RASCONNW) + 1
            continue
        if ret != 0:
            log.debug("RasEnumConnectionsW: ошибка %d", ret)
            return {}
        out = {}
        for i in range(found.value):
            device = conns[i].szDeviceType
            if device.lower() == "vpn" and ISP_TUNNEL_SERVERS.search(_phonebook_server(conns[i].szPhonebook,
                                                                                         conns[i].szEntryName)):
                device = "isp"
            out[conns[i].szEntryName] = device
        return out
    return {}


def _phonebook_server(path: str, entry: str) -> str:
    """Адрес сервера подключения из его телефонной книги (PhoneNumber)."""
    parser = configparser.RawConfigParser(strict=False, interpolation=None)
    try:
        with open(path, encoding="utf-8-sig", errors="replace") as fh:
            parser.read_file(fh)
        return parser.get(entry, "PhoneNumber", fallback="").strip()
    except (OSError, configparser.Error):
        return ""


def _phonebook_types() -> dict[str, int]:
    """Запасной путь: тип записи из стандартных телефонных книг (2 — VPN, 5 — PPPoE)."""
    books = []
    for folder_id in ("{62AB5D82-FDC1-4DC3-A9DD-070D1D495D97}",   # ProgramData
                      "{3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}"):  # AppData\Roaming
        try:
            books.append(f"{winutil.known_folder(folder_id)}\\Microsoft\\Network\\Connections\\Pbk\\rasphone.pbk")
        except OSError:
            continue
    out: dict[str, int] = {}
    for path in books:
        parser = configparser.RawConfigParser(strict=False, interpolation=None)
        try:
            with open(path, encoding="utf-8-sig", errors="replace") as fh:
                parser.read_file(fh)
        except (OSError, configparser.Error):
            continue
        for entry in parser.sections():
            try:
                out[entry] = int(parser.get(entry, "Type", fallback="0") or 0)
            except ValueError:
                continue
    return out


def user_hive() -> tuple[int, str]:
    """(корень, префикс) ветки реестра того, кто сидит за компьютером. Лазейку с правами могут запустить
    под другой учётной записью (в окне UAC ввели пароль другого администратора) — тогда её HKCU чужой, и
    VPN в режиме системного прокси, включённый человеком, был бы не виден."""
    try:
        from .vpnclient.sysproxy import process_user_sid, shell_user_sid
    except ImportError:      # сборка без своего VPN
        return winreg.HKEY_CURRENT_USER, ""
    mine, desk = process_user_sid(), shell_user_sid()
    if mine and desk and mine != desk:
        return winreg.HKEY_USERS, desk + "\\"
    return winreg.HKEY_CURRENT_USER, ""


def system_proxy() -> str | None:
    """Системный прокси Windows, если он указывает на этот компьютер: так работают VPN-программы
    в режиме «системный прокси» (Happ, Hiddify, v2rayN и другие) — без туннеля."""
    root, prefix = user_hive()
    try:
        with winreg.OpenKey(root, prefix + INTERNET_SETTINGS_KEY) as key:
            enabled = int(winreg.QueryValueEx(key, "ProxyEnable")[0])
            server = str(winreg.QueryValueEx(key, "ProxyServer")[0]).strip()
    except (OSError, ValueError, TypeError):
        return None
    if not enabled or not server:
        return None
    chosen = server
    if "=" in server:
        parts = dict(p.split("=", 1) for p in server.split(";") if "=" in p)
        chosen = parts.get("https") or parts.get("http") or ""
        if not chosen and parts.get("socks"):
            chosen = "socks5h://" + parts["socks"]
    host = re.sub(r"^[a-z0-9]+://", "", chosen, flags=re.I).rsplit(":", 1)[0].strip("[]").lower()
    try:
        loopback = host == "localhost" or ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = False
    if not loopback:
        return None  # прокси организации или провайдера — это не VPN
    return chosen if "://" in chosen else f"http://{chosen}"


# Драйверы и описания адаптеров VPN. Имя адаптера пользователь может переименовать,
# поэтому смотрим только на драйвер и описание.
_TUNNEL_DRIVER = re.compile(
    r"wintun|wireguard|tap0901|tap-?windows|\btap[-_ ]|tap_|ovpn-dco|openvpn|zttap|zerotier|hamachi|rvnetmp|"
    r"radmin|softether|anyconnect|pangp|globalprotect|fortinet|forticlient|juniper|pulse ?secure|check ?point|"
    r"sonicwall|nordlynx|warp|tailscale|amnezia|outline|kaspersky|adguard|windscribe|surfshark|expressvpn|"
    r"proton|mullvad|\bvpn\b|tunnel", re.I)
# ComponentId драйверов, которые бывают только у VPN: их узнаём раньше признака «сетевая карта»
# (NCF_PHYSICAL) — некоторые VPN ставят его своему адаптеру, чтобы программы считали его настоящим.
_TUNNEL_COMPONENT = re.compile(r"wintun|wireguard|tap0901|ovpn-dco|zttap|rvnetmp|hamachi", re.I)

# Программа по самому адаптеру — когда это видно наверняка.
_ADAPTER_APPS = (
    (r"amneziawg", "AmneziaWG"), (r"amnezia", "AmneziaVPN"), (r"wireguard tunnel|\bwireguard\b", "WireGuard"),
    (r"cloudflare ?warp|\bwarp\b", "Cloudflare WARP"), (r"proton", "Proton VPN"), (r"nordlynx|nordvpn", "NordVPN"),
    (r"mullvad", "Mullvad"), (r"radmin|rvnetmp", "Radmin VPN"), (r"hamachi", "Hamachi"),
    (r"zerotier|zttap", "ZeroTier"), (r"tailscale", "Tailscale"), (r"tap0901|tap-?windows|ovpn-dco|openvpn", "OpenVPN"),
    (r"outline", "Outline"), (r"kaspersky", "Kaspersky VPN"), (r"adguard", "AdGuard VPN"),
    (r"windscribe", "Windscribe"), (r"surfshark", "Surfshark"), (r"expressvpn", "ExpressVPN"),
    (r"anyconnect|cisco", "Cisco AnyConnect"), (r"pangp|globalprotect", "GlobalProtect"),
    (r"fortinet|forticlient", "FortiClient"),
)

# Запущенные VPN-программы — только как подсказка: одновременно их может быть несколько,
# и по процессам не видно, чей именно туннель сейчас поднят.
VPN_PROCESSES = (
    (r"^incy", "Incy"), (r"^happ", "Happ"), (r"^hiddify", "Hiddify"), (r"^v2rayn", "v2rayN"),
    (r"^v2raytun", "v2RayTun"), (r"^neko(box|ray)", "NekoBox"), (r"^throne", "Throne"),
    (r"^(clash|verge|mihomo)", "Clash Verge"), (r"^flclash", "FlClash"), (r"^karing", "Karing"),
    (r"^amnezia", "AmneziaVPN"), (r"^wireguard", "WireGuard"), (r"^openvpn", "OpenVPN"), (r"^outline", "Outline"),
    (r"^warp-svc", "Cloudflare WARP"), (r"^protonvpn", "Proton VPN"), (r"^nordvpn", "NordVPN"),
    (r"^ksde", "Kaspersky VPN"), (r"^adguardvpn", "AdGuard VPN"), (r"^windscribe", "Windscribe"),
    (r"^surfshark", "Surfshark"), (r"^expressvpn", "ExpressVPN"), (r"^mullvad", "Mullvad"),
    (r"^psiphon", "Psiphon"), (r"^lantern", "Lantern"), (r"^tailscale", "Tailscale"), (r"^zerotier", "ZeroTier"),
    (r"^(radmin|rvcontrol)", "Radmin VPN"), (r"^hamachi", "Hamachi"), (r"^sing-box", "sing-box"),
    (r"^xray", "Xray"),
)

# Программы-«ядра» (sing-box, xray, mihomo): поднимают безымянный туннель Wintun или системный
# прокси. Только их и можно подозревать, если сам адаптер о программе не говорит.
CORE_APPS = {"Incy", "Happ", "Hiddify", "v2rayN", "v2RayTun", "NekoBox", "Throne", "Clash Verge", "FlClash",
             "Karing", "sing-box", "Xray", "AmneziaVPN", "Outline", "Psiphon", "Lantern"}


# VPN, которые умеют работать без отдельного адаптера (ExpressVPN — протокол Lightway Turbo с
# NDIS-фильтром, AdGuard VPN — режим без WinTun): их трафик идёт через тот же физический
# интерфейс, и фильтр по интерфейсам отделить его не может.
NO_ADAPTER_APPS = {"ExpressVPN", "AdGuard VPN"}


def adapter_app(component: str, description: str) -> str | None:
    text = f"{component} {description}"
    for pattern, app in _ADAPTER_APPS:
        if re.search(pattern, text, re.I):
            return app
    return None


def is_lan_overlay(a: Adapter) -> bool:
    """Radmin VPN или Hamachi — по драйверу, независимо от поправки человека: интернета через них нет."""
    return adapter_app(a.component, a.description) in LAN_APPS


def classify(a: Adapter, override: str | None = None) -> tuple[str, str]:
    """(kind, reason): direct — перехват обходом нужен, tunnel — VPN, его не трогаем, skip — петля."""
    if a.if_type == IF_TYPE_LOOPBACK:
        return "skip", "петлевой интерфейс"
    if override in ("direct", "tunnel"):
        return override, "задано вручную"
    if a.if_type == IF_TYPE_TUNNEL:
        return "tunnel", "системный туннель IPv6"
    if a.if_type == IF_TYPE_PROP_VIRTUAL:
        return "tunnel", "туннель VPN"
    if a.if_type == IF_TYPE_PPP:
        device = (a.ras_device or "").lower()
        if device == "vpn":
            return "tunnel", "VPN-подключение Windows"
        if device == "isp":
            return "direct", "подключение к провайдеру (L2TP)"
        if device:
            return "direct", "подключение к провайдеру (PPPoE)" if device == "pppoe" else "модем"
        # RAS о подключении не знает — оставляем перехват (обход нужнее), но говорим об этом.
        return "direct", "подключение PPP (тип не определён)"
    if _TUNNEL_COMPONENT.search(a.component):
        return "tunnel", "адаптер VPN"
    if a.characteristics & NCF_PHYSICAL:
        return "direct", "сетевая карта" if a.if_type != IF_TYPE_WIFI else "Wi-Fi"
    if _TUNNEL_DRIVER.search(f"{a.component} {a.description}"):
        return "tunnel", "адаптер VPN"
    if a.characteristics & NCF_VIRTUAL:
        return "direct", "виртуальный адаптер"
    return "direct", "сетевой адаптер"


# ------------------------------------------------------------ маршруты

class Route(NamedTuple):
    dest: str
    plen: int
    hop: str
    index: int
    metric: int = 0      # метрика самого маршрута; Windows прибавляет к ней метрику интерфейса


def routes() -> list[Route]:
    """Маршруты IPv4 и IPv6: назначение, длина префикса, следующий узел, интерфейс, метрика."""
    api = _api()
    table = ctypes.c_void_p()
    if api.GetIpForwardTable2(AF_UNSPEC, ctypes.byref(table)) != 0 or not table.value:
        return []
    try:
        count = ctypes.c_ulong.from_address(table.value).value
        offset = 8  # ULONG NumEntries и выравнивание до 8 перед массивом строк
        rows = (MIB_IPFORWARD_ROW2 * count).from_address(table.value + offset)
        out = []
        for r in rows:
            dest = _raw_ip(bytes(r.DestinationPrefix.Prefix))
            hop = _raw_ip(bytes(r.NextHop))
            if dest is not None:
                out.append(Route(dest, int(r.DestinationPrefix.PrefixLength), hop or "", int(r.InterfaceIndex),
                                 int(r.Metric)))
        return out
    finally:
        api.FreeMibTable(table)


def _route_rows(table) -> list[Route]:
    """Строки таблицы как Route: подделки в тестах отдают и кортежи из четырёх полей, без метрики."""
    return [r if isinstance(r, Route) else Route(*r) for r in table]


def mark_default_routes(adapters: list[Adapter], table) -> None:
    """Записать каждому адаптеру метрику его лучшего маршрута по умолчанию (0.0.0.0/0 и ::/0)."""
    best: dict[tuple[bool, int], int] = {}
    for r in _route_rows(table):
        if r.plen == 0:
            key = (":" in r.dest, r.index)
            best[key] = min(r.metric, best.get(key, r.metric))
    for a in adapters:
        a.default4_metric = best.get((False, a.index))
        a.default6_metric = best.get((True, a.ipv6_index or a.index))


def _exit_address(a: Adapter, v6: bool) -> bool:
    if v6:
        return any(_public(ip) for ip in a.ipv6)
    return any(not ip.startswith("169.254.") for ip in a.ipv4)


def internet_exit(adapters: list[Adapter], family: int = AF_INET) -> Adapter | None:
    """Прямой выход в интернет — куда Windows отправит интернет мимо туннелей.

    Кандидаты — включённые прямые адаптеры (не туннель, не свой TUN, не Radmin и не Hamachi даже с поправкой
    «прямое») с адресом нужного семейства и маршрутом по умолчанию; побеждает наименьшая сумма метрики
    маршрута и метрики интерфейса — так выбирают Windows и sing-box (auto_detect_interface). Одна функция
    для привязки помощника Xray своего VPN, адреса проверок «мимо VPN» и вопроса «есть ли IPv6».
    Таблица маршрутов не прочиталась (ни одного маршрута по умолчанию ни в IPv4, ни в IPv6, даже у
    туннелей) — как раньше, по шлюзу адаптера. Нет кандидата — None: прямого выхода сейчас нет."""
    v6 = family == AF_INET6

    def route_metric(a: Adapter) -> int | None:
        return a.default6_metric if v6 else a.default4_metric

    known = any(a.default4_metric is not None or a.default6_metric is not None for a in adapters)
    best: Adapter | None = None
    best_cost = 0
    for a in adapters:
        if a.kind != "direct" or a.own or not a.up or is_lan_overlay(a) or not _exit_address(a, v6):
            continue
        route = route_metric(a)
        if route is None:
            if known or not any((":" in g) == v6 and not _unspecified(g) for g in a.gateways):
                continue
            route = 0
        cost = route + (a.metric6 if v6 else a.metric)
        if best is None or cost < best_cost:
            best, best_cost = a, cost
    return best


def best_interface(ip: str) -> int | None:
    """Через какой интерфейс Windows отправит пакет на этот IPv4 прямо сейчас."""
    try:
        packed = socket.inet_aton(ip)
    except OSError:
        return None
    index = wintypes.DWORD(0)
    if _api().GetBestInterface(struct.unpack("<I", packed)[0], ctypes.byref(index)) != 0:
        return None
    return int(index.value)


def _public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def _unspecified(ip: str) -> bool:
    try:
        return not ip or ipaddress.ip_address(ip).is_unspecified
    except ValueError:
        return True


def host_routes(table, direct: set[int]) -> list[str]:
    """Публичные адреса с маршрутом /32 или /128 через шлюз прямого интерфейса — мимо туннеля."""
    return sorted({r.dest for r in _route_rows(table)
                   if ((":" in r.dest and r.plen == 128) or (":" not in r.dest and r.plen == 32))
                   and r.index in direct and not _unspecified(r.hop) and r.hop != r.dest and _public(r.dest)})


def server_routes(table, direct: set[int], confirmed: set[str] | frozenset[str] = frozenset()) -> list[str]:
    """Адреса серверов VPN по маршрутам /32 и /128 через шлюз прямого интерфейса — так
    OpenVPN, встроенный VPN Windows, Outline и многие клиенты на xray/sing-box выводят соединение
    с собственным сервером из туннеля. Таких маршрутов больше трёх — значит, это раздельное
    туннелирование (сайты, пущенные мимо VPN), а не серверы: по одному маршруту их не отличить, иначе
    вместе с «серверами» обход перестал бы трогать, например, тот же Discord. Тогда серверы — только те
    адреса, с которыми сама VPN-программа держит соединение (confirmed, vpn_connections)."""
    found = host_routes(table, direct)
    if len(found) > MAX_SERVER_ROUTES:
        sure = [ip for ip in found if ip in confirmed]
        log.info("Маршрутов мимо туннеля много (%d) — это раздельное туннелирование; серверов VPN по соединениям "
                 "программы: %d", len(found), len(sure))
        return sure
    return found


def wireguard_endpoints(tunnels: list[Adapter]) -> list[str]:
    """Серверы туннелей официального WireGuard: он не прокладывает маршрут к серверу, а
    привязывает сокет к интерфейсу, поэтому спрашиваем его самого (wg show all endpoints)."""
    if not any(a.component.lower() == "wireguard" for a in tunnels):
        return []
    try:
        exe = Path(winutil.known_folder("{905E63B6-C1BF-494E-B29C-65B732D3D21A}")) / "WireGuard" / "wg.exe"
    except OSError:
        return []
    if not exe.is_file():
        return []
    res = winutil.run([str(exe), "show", "all", "endpoints"], timeout=5)
    out = []
    for line in res.out.splitlines():
        endpoint = line.split("\t")[-1].strip()
        match = re.match(r"^\[?([0-9a-fA-F:.]+?)\]?:\d+$", endpoint)
        if match and _public(match.group(1)):
            out.append(match.group(1))
    return sorted(set(out))


# Публичные адреса для вопроса «куда пойдёт интернет»: Cloudflare и Google DNS, Яндекс,
# Discord и Telegram — у разделённых туннелей маршруты к ним бывают разными.
ROUTE_PROBES = ("1.1.1.1", "8.8.8.8", "77.88.8.8", "162.159.135.232", "149.154.167.51")


# ------------------------------------------------------------ свой VPN

OWN_LABEL = "Лазейка"
MAX_OWN_SERVERS = 16    # столько же адресов умещает фильтр WinDivert (vpnfilter.MAX_SERVERS)


@dataclass
class OwnVpn:
    """Снимок своего VPN от менеджера: готовые данные, без DNS, HTTP и блокировок.

    pids — процессы ядер; adapter_name и tun_net — свой TUN (режим «весь трафик»); servers — IP
    серверов из работающего конфига; proxy — системный прокси, который выставила сама Лазейка."""

    pids: set[int] = field(default_factory=set)
    adapter_name: str | None = None
    tun_net: str | None = None
    servers: list[str] = field(default_factory=list)
    proxy: str | None = None
    label: str = OWN_LABEL

    @property
    def mode(self) -> str:
        if self.adapter_name or self.tun_net:
            return "tun"
        return "proxy" if self.proxy else "local"

    def owns_address(self, ip: str) -> bool:
        """Адрес из подсети своего TUN."""
        return in_network(ip, self.tun_net)

    def capped_servers(self) -> list[str]:
        """Серверы без повторов — не больше, чем умещает фильтр WinDivert."""
        return list(dict.fromkeys(str(s) for s in self.servers))[:MAX_OWN_SERVERS]


def in_network(ip: str, net: str | None) -> bool:
    if not net:
        return False
    try:
        return ipaddress.ip_address(ip.split("%")[0]) in ipaddress.ip_network(net, strict=False)
    except ValueError:
        return False


def _proxy_key(value: str | None) -> str:
    """«http://127.0.0.1:20808» и «127.0.0.1:20808» — один и тот же прокси."""
    return re.sub(r"^[a-z0-9]+://", "", (value or "").strip(), flags=re.I).rstrip("/").lower()


def same_proxy(a: str | None, b: str | None) -> bool:
    return bool(a and b) and _proxy_key(a) == _proxy_key(b)


# ------------------------------------------------------------ снимок

@dataclass
class Snapshot:
    adapters: list[Adapter]
    servers: list[str]            # серверы чужих VPN и свои (свои — первыми)
    apps: list[str]               # запущенные VPN-программы (подсказка)
    at: float
    proxy: str | None = None      # чужой системный прокси на этом компьютере (VPN в режиме прокси)
    owners: list[str] = field(default_factory=list)  # программы, чьи соединения идут с прямого адреса
    own: OwnVpn | None = None     # свой VPN Лазейки, если работает
    # VPN-программы, которые сейчас сами держат соединения с прямого адреса (vpn_connections). Собирается,
    # только когда нужно: запущен VPN без своего адаптера (NO_ADAPTER_APPS) или VPN в режиме прокси.
    connected: list[str] = field(default_factory=list)

    @property
    def tunnels(self) -> list[Adapter]:
        """Туннели VPN — без системных туннелей IPv6 (Teredo, 6to4). Свой TUN — тоже туннель."""
        return [a for a in self.adapters if a.kind == "tunnel" and a.role != "system"]

    @property
    def internet(self) -> list[Adapter]:
        """Туннели, через которые идёт интернет, — и чужие, и свой."""
        return [a for a in self.adapters if a.kind == "tunnel" and a.role == "internet"]

    @property
    def foreign_internet(self) -> list[Adapter]:
        return [a for a in self.internet if not a.own]

    @property
    def unproven(self) -> list[Adapter]:
        """Чужие туннели, через которые идёт интернет, а «VPN в интернет» не доказан (hold_unproven): прямого
        маршрута нет, сервер из туннеля не выведен ни маршрутом /32, ни эндпоинтом WireGuard. Для фильтра обхода
        они — lan; своему VPN в TUN рядом с ними — тот же риск двух туннелей."""
        return [a for a in self.adapters if a.pending_internet and not a.own]

    def unproven_label(self) -> str:
        """Имя такого туннеля для сообщений: программа, если адаптер её называет, иначе «VPN «<адаптер>»»."""
        names = list(dict.fromkeys(a.app or f"VPN «{a.name}»" for a in self.unproven))
        return " или ".join(names[:3]) or "VPN"

    @property
    def direct(self) -> list[Adapter]:
        return [a for a in self.adapters if a.kind == "direct"]

    @property
    def own_active(self) -> bool:
        return self.own is not None

    @property
    def foreign_active(self) -> bool:
        """Работает чужой VPN в интернет: туннель или прокси на этом компьютере."""
        return bool(self.foreign_internet or self.proxy)

    @property
    def active(self) -> bool:
        """Работает хоть какой-то VPN в интернет — чужой или свой."""
        return self.foreign_active or self.own_active

    @property
    def foreign_label(self) -> str:
        return self.label()

    @property
    def own_servers(self) -> list[str]:
        return self.own.capped_servers() if self.own else []

    @property
    def foreign_servers(self) -> list[str]:
        """Серверы чужих VPN (по маршрутам, WireGuard и соединениям VPN-прокси) — без своих."""
        own = set(self.own_servers)
        return [s for s in self.servers if s not in own]

    @property
    def full_tunnel(self) -> bool:
        """Весь интернет по умолчанию уходит в чужой туннель (маршрут к 1.1.1.1 — через VPN)."""
        return any(a.default_route for a in self.foreign_internet)

    @property
    def unseparable(self) -> list[str]:
        """Работающие VPN без своего адаптера: совместимость для них не работает. Работающие — по
        соединениям с прямого адреса: служба ExpressVPN или AdGuard VPN висит в фоне и без подключения."""
        own = {a.app for a in self.tunnels if a.app}
        return [app for app in self.apps if app in NO_ADAPTER_APPS and app in self.connected and app not in own]

    def direct_indices(self) -> list[int]:
        return sorted({i for a in self.direct for i in a.indices})

    def indices_except_own(self) -> list[int]:
        """Все интерфейсы, кроме своего TUN и петли: так перехватывает обход без совместимости."""
        return sorted({i for a in self.adapters if a.kind != "skip" and not a.own for i in a.indices})

    def source_ip(self) -> str | None:
        """IPv4 прямого выхода в интернет (internet_exit) — для проверок мимо VPN. Radmin сюда не попадает
        и с поправкой «прямое», второй сетевой карте без маршрута в интернет тоже не достаётся."""
        a = internet_exit(self.adapters)
        if a is None:
            return None
        return next((ip for ip in a.ipv4 if not ip.startswith("169.254.")), None)

    def tunnel_ip(self) -> str | None:
        """IPv4 туннеля VPN в интернет — запрос, привязанный к нему, уйдёт в VPN."""
        for a in self.internet:
            for ip in a.ipv4:
                if not ip.startswith("169.254."):
                    return ip
        return None

    def direct_v6(self) -> list:
        """Сети /64 глобальных IPv6-адресов прямых подключений."""
        nets = set()
        for a in self.direct:
            for ip in a.ipv6:
                try:
                    addr = ipaddress.ip_address(ip.split("%")[0])
                except ValueError:
                    continue
                if addr.is_global:
                    nets.add(ipaddress.ip_network(f"{addr}/64", strict=False))
        return sorted(nets, key=str)

    def signature(self) -> list[str]:
        """Чем отличаются активные чужие VPN — чтобы «не спрашивать снова» относилось к ним.
        Свой VPN сюда не входит: о нём не спрашивают."""
        out = [f"{a.component or a.if_type}:{a.guid.lower()}" for a in self.foreign_internet]
        if self.proxy:
            out.append(f"proxy:{self.proxy}")
        return sorted(out)

    def plan(self) -> dict | None:
        """Что исключить из перехвата при включённой совместимости: прямые интерфейсы и все
        серверы VPN (свои — всегда, у VPN в режиме прокси — по его соединениям). None — нечего отделять:
        ни туннелей с адресами (отключённый адаптер VPN трафика не несёт), ни серверов — фильтр не нужен."""
        carrying = [a for a in self.tunnels if a.role in ("internet", "lan")]
        if not carrying and not self.servers:
            return None
        interfaces = self.direct_indices()
        if not interfaces:
            return None
        return {"interfaces": interfaces, "servers": list(self.servers)}

    def own_plan(self) -> dict | None:
        """Совместимость выключена, а работает свой VPN: перехват на всех интерфейсах, кроме
        своего TUN, и без своих серверов (чужие VPN обход трогает, как просили)."""
        if self.own is None:
            return None
        interfaces = self.indices_except_own()
        if not interfaces:
            return None
        return {"interfaces": interfaces, "servers": self.own_servers, "mode": "own"}

    def candidates(self) -> list[str]:
        """Какие программы могут держать чужой VPN в интернет. Если адаптер сам называет
        программу — это она. Иначе — запущенные программы-ядра; чей именно туннель или прокси,
        Windows не говорит, поэтому при нескольких честно перечисляем всех."""
        named = [a.app for a in self.foreign_internet if a.app]
        if named:
            return list(dict.fromkeys(named))
        if self.owners:
            return list(self.owners)
        return [app for app in self.apps if app in CORE_APPS]

    def label(self) -> str:
        """Имя чужого VPN для сообщений."""
        names = self.candidates()
        if names:
            return " или ".join(names[:3])
        adapters = [a.name for a in self.foreign_internet]
        if adapters:
            return f"VPN «{adapters[0]}»"
        return "VPN через системный прокси" if self.proxy else "VPN"

    def to_dict(self) -> dict:
        """active, mode, label — про чужой VPN (с ним и работает совместимость); свой — в own."""
        foreign = self.foreign_active
        return {
            "active": foreign,
            "mode": "tunnel" if self.foreign_internet else "proxy" if self.proxy else None,
            "full_tunnel": self.full_tunnel,
            "proxy": self.proxy,
            "label": self.label() if foreign else None,
            "candidates": self.candidates() if foreign else [],
            "apps": self.apps,
            "servers": self.foreign_servers,
            "source_ip": bool(self.source_ip()),
            "unseparable": self.unseparable,
            "at": self.at,
            "adapters": [{
                "id": a.guid.lower(), "index": a.index, "name": a.name, "description": a.description,
                "kind": a.kind, "role": a.role, "reason": a.reason, "up": a.up, "app": a.app, "own": a.own,
            } for a in self.adapters if a.kind != "skip" and not (a.kind == "tunnel" and a.role == "system")],
            "own": {"active": self.own_active, "mode": self.own.mode if self.own else None},
        }


def running_apps(skip_pids: set[int] | None = None) -> list[str]:
    """Запущенные VPN-программы. Свои процессы не считаются: дочерние процессы Лазейки (ядра
    своего VPN, короткие version/check) и PID из skip_pids — sing-box.exe и xray.exe Лазейки
    иначе выглядели бы чужим VPN."""
    import psutil
    me = os.getpid()
    skip = skip_pids or set()
    found: list[str] = []
    for proc in psutil.process_iter(["name", "pid", "ppid"]):
        info = proc.info
        if info.get("pid") in skip or info.get("ppid") == me:
            continue
        name = (info.get("name") or "").lower()
        for pattern, app in VPN_PROCESSES:
            if re.match(pattern, name) and app not in found:
                found.append(app)
    return found


def own_child_pids() -> set[int]:
    """Процессы, запущенные самой Лазейкой (как runner.foreign_winws отличает свой winws)."""
    import psutil
    me = os.getpid()
    out: set[int] = set()
    try:
        for proc in psutil.process_iter(["pid", "ppid"]):
            if proc.info.get("ppid") == me:
                out.add(proc.info["pid"])
    except (psutil.Error, OSError):
        pass
    return out


def _process_app(pid: int) -> str | None:
    """VPN-программа по имени процесса или None."""
    import psutil
    try:
        name = psutil.Process(pid).name().lower()
    except (psutil.Error, OSError):
        return None
    return next((app for pattern, app in VPN_PROCESSES if re.match(pattern, name)), None)


def vpn_connections(direct_ips: set[str], skip_pids: set[int] | None = None) -> list[tuple[str, str | None]]:
    """(программа, удалённый адрес) — сокеты VPN-программ на адресах прямых подключений: установленные
    TCP и UDP, привязанные к прямому адресу (у UDP удалённого адреса может не быть). Так видно, чья программа
    сама держит связь мимо туннеля — с сервером VPN или по своим правилам «напрямую». skip_pids — свои
    процессы (ядра Лазейки)."""
    import psutil
    if not direct_ips:
        return []
    try:
        conns = psutil.net_connections(kind="inet")
    except (psutil.Error, OSError):
        return []
    skip = skip_pids or set()
    apps: dict[int, str | None] = {}
    out: list[tuple[str, str | None]] = []
    for c in conns:
        if not c.pid or c.pid in skip or not c.laddr or c.laddr.ip.split("%")[0] not in direct_ips:
            continue
        if getattr(c, "type", socket.SOCK_STREAM) == socket.SOCK_STREAM and c.status != psutil.CONN_ESTABLISHED:
            continue
        if c.pid not in apps:
            apps[c.pid] = _process_app(c.pid)
        app = apps[c.pid]
        if app is not None:
            remote = getattr(c, "raddr", None)
            out.append((app, remote.ip.split("%")[0] if remote else None))
    return out


def active_core_apps(direct_ips: set[str], skip_pids: set[int] | None = None) -> list[str]:
    """Чей туннель или прокси сейчас работает. Ядро VPN (Xray, sing-box, mihomo) само открывает
    соединения с адреса физического адаптера — к своему серверу и для правил «напрямую».
    Программа, которая просто висит в фоне (у владельца так висит служба Happ рядом с работающим
    Incy), таких соединений не держит. skip_pids — свои процессы (ядра Лазейки)."""
    return sorted({app for app, _remote in vpn_connections(direct_ips, skip_pids) if app in CORE_APPS})


def proxy_servers(conns: list[tuple[str, str | None]]) -> list[str]:
    """Серверы VPN в режиме системного прокси: ядро (Happ, v2rayN…) соединяется с сервером с прямого
    адреса, и без исключения его соединение попадало бы под перехват. Адресов больше трёх — это уже
    правила «напрямую» в программе, а не сервер: какой из них сервер, не угадываем."""
    found = sorted({remote for app, remote in conns if app in CORE_APPS and remote and _public(remote)})
    if len(found) > MAX_SERVER_ROUTES:
        log.info("У VPN-прокси много прямых соединений (%d) — сервер не определён", len(found))
        return []
    return found


def is_own_adapter(a: Adapter, own: OwnVpn | None) -> bool:
    """Свой TUN: по имени адаптера или по адресу из своей подсети."""
    if own is None:
        return False
    if own.adapter_name and a.name.lower() == own.adapter_name.lower():
        return True
    return bool(own.tun_net) and any(own.owns_address(ip) for ip in a.ipv4)


def classified_adapters(overrides: dict[str, str] | None = None, own: OwnVpn | None = None,
                        table=None) -> list[Adapter]:
    """Адаптеры с драйвером, видом (direct | tunnel | skip) и маршрутами по умолчанию — без ролей
    туннелей, процессов и прокси. table — уже прочитанная таблица маршрутов (иначе читается здесь)."""
    overrides = {k.lower(): v for k, v in (overrides or {}).items()}
    adapters = list_adapters()
    drivers = _driver_info()
    ras: dict[str, str] = {}
    if any(a.if_type == IF_TYPE_PPP for a in adapters):
        ras = ras_connections()
        if not ras:
            ras = {name: ("vpn" if kind == RASET_VPN else "PPPoE") for name, kind in _phonebook_types().items()}
    for a in adapters:
        a.component, a.characteristics = drivers.get(a.guid.lower(), ("", 0))
        if a.if_type == IF_TYPE_PPP:
            a.ras_device = ras.get(a.name)
        if a.if_type != IF_TYPE_LOOPBACK and is_own_adapter(a, own):
            a.own, a.kind, a.reason, a.app = True, "tunnel", "свой VPN Лазейки", own.label
            continue
        a.kind, a.reason = classify(a, overrides.get(a.guid.lower()))
        if a.kind == "tunnel":
            a.app = adapter_app(a.component, a.description)
    mark_default_routes(adapters, routes() if table is None else table)
    return adapters


def direct_exit(overrides: dict[str, str] | None = None, own: OwnVpn | None = None,
                family: int = AF_INET) -> Adapter | None:
    """Прямой выход в интернет прямо сейчас (internet_exit) — для своего VPN: привязка помощника Xray
    (sockopt.interface) и вопрос «есть ли у ПК IPv6». Только чтение таблиц адаптеров и маршрутов."""
    return internet_exit(classified_adapters(overrides, own), family)


def lan_networks() -> list[tuple[int, list[str]]]:
    """(LUID, сети) виртуальных локальных сетей — Radmin VPN, Hamachi, ZeroTier, Tailscale — для kill switch
    своего VPN: это не интернет, и закрывать их незачем. Сети берутся из маршрутов через сам адаптер
    (у Radmin — 26.0.0.0/8 и широковещательные адреса для поиска игр); маршруты в интернет (0.0.0.0/0 у
    Radmin, выход через узел у Tailscale) сюда не входят."""
    table = _route_rows(routes())
    out: list[tuple[int, list[str]]] = []
    for a in classified_adapters(table=table):
        if (a.kind != "tunnel" or not a.up or not a.luid
                or adapter_app(a.component, a.description) not in LAN_NETWORK_APPS):
            continue
        nets = set()
        for r in table:
            if r.index not in a.indices:
                continue
            try:
                net = ipaddress.ip_network(f"{r.dest}/{r.plen}", strict=False)
            except ValueError:
                continue
            if net.is_multicast or net.prefixlen >= LAN_MIN_PREFIX[net.version]:
                nets.add(net)
        collapsed = [str(n) for version in (4, 6)
                     for n in ipaddress.collapse_addresses(sorted(n for n in nets if n.version == version))]
        if len(collapsed) > LAN_MAX_NETS:
            log.info("У адаптера «%s» сетей больше %d — kill switch пропустит первые", a.name, LAN_MAX_NETS)
        if collapsed:
            out.append((a.luid, collapsed[:LAN_MAX_NETS]))
    return out


def assign_roles(adapters: list[Adapter], carrying: dict[int, bool]) -> None:
    """Роли туннелей по тому, куда Windows отправляет проверочные адреса (carrying: интерфейс → идёт ли
    через него 1.1.1.1). Radmin и Hamachi — всегда lan: у Radmin есть маршрут по умолчанию с огромной
    метрикой, и он «несёт интернет», как только пропадает прямой маршрут."""
    for a in adapters:
        if a.kind != "tunnel":
            continue
        if a.if_type == IF_TYPE_TUNNEL and a.reason != "задано вручную":
            a.role = "system"
        elif a.index in carrying and not is_lan_overlay(a):
            a.role = "internet"
            a.default_route = carrying[a.index]
        elif a.routable:
            a.role = "lan"
        else:
            a.role = "idle"


def hold_unproven(adapters: list[Adapter]) -> None:
    """Прямого маршрута в интернет нет, и VPN не выводит из туннеля свой сервер: «VPN в интернет» ничем не
    доказан — через чужой туннель интернет идёт лишь потому, что другого пути нет. Такой туннель — lan
    (пропажа прямого маршрута — не «подключился VPN»); прежнюю роль вернёт keep_roles."""
    for a in adapters:
        if a.kind == "tunnel" and a.role == "internet" and not a.own:
            a.role, a.pending_internet = "lan", True


def keep_roles(snapshot: Snapshot | None, previous: Snapshot | None) -> None:
    """Пока прямого маршрута нет (Wi-Fi переподключается, выход из сна), туннель, который был VPN в
    интернет, им и остаётся: иначе каждое переподключение Wi-Fi выглядело бы как «VPN отключился и
    подключился снова». Новый туннель роль internet без доказательства не получает."""
    if not isinstance(snapshot, Snapshot) or not isinstance(previous, Snapshot):
        return
    was = {a.guid.lower() for a in previous.adapters if a.kind == "tunnel" and a.role == "internet" and not a.own}
    restored = False
    for a in snapshot.adapters:
        if a.pending_internet and a.guid.lower() in was:
            a.role, a.pending_internet, restored = "internet", False, True
    if restored and not snapshot.owners:
        snapshot.owners = list(previous.owners)


def scan(overrides: dict[str, str] | None = None, own: OwnVpn | None = None) -> Snapshot:
    """Адаптеры, их роль и серверы VPN. Быстро (десятки миллисекунд): WinAPI и реестр.

    own — готовый снимок своего VPN от менеджера: его адаптер помечается own (это туннель, поправки
    человека к нему не применяются), его процессы и системный прокси не считаются чужими, а его
    серверы добавляются к серверам VPN первыми.

    Роль internet чужой туннель получает только с доказательством: через него идут проверочные адреса
    и при этом он перебивает существующий прямой маршрут по умолчанию либо VPN выводит свой сервер из
    туннеля (маршрут /32 через прямой шлюз, эндпоинт WireGuard). Radmin и Hamachi — всегда lan."""
    table = _route_rows(routes())
    adapters = classified_adapters(overrides, own, table)
    carrying: dict[int, bool] = {}
    for ip in ROUTE_PROBES:
        index = best_interface(ip)
        if index is not None:
            carrying[index] = carrying.get(index, False) or ip == "1.1.1.1"
    assign_roles(adapters, carrying)
    # Серверы ищем у туннелей с адресами, кроме Radmin и Hamachi: на ПК только с ними маршруты /32 — не их.
    tunnels = [a for a in adapters if a.kind == "tunnel" and not a.own and a.role in ("internet", "lan")
               and not is_lan_overlay(a)]
    direct = {i for a in adapters if a.kind == "direct" for i in a.indices}
    hosts = host_routes(table, direct) if tunnels else []
    endpoints: list[str] = []
    if tunnels:
        try:
            endpoints = wireguard_endpoints(tunnels)
        except OSError:
            endpoints = []
    if internet_exit(adapters) is None and not (hosts or endpoints):
        hold_unproven(adapters)
    skip = set(own.pids) if own else set()
    try:
        apps = running_apps(skip)
    except Exception:  # noqa: BLE001
        apps = []
    proxy = system_proxy()
    if own is not None and same_proxy(proxy, own.proxy):
        proxy = None  # системный прокси выставила сама Лазейка
    direct_ips = {ip for a in adapters if a.kind == "direct" for ip in (*a.ipv4, *a.ipv6)}
    foreign = [a for a in adapters if a.kind == "tunnel" and a.role == "internet" and not a.own]
    mine: set[int] | None = None
    owners: list[str] = []
    if [a for a in foreign if not a.app] or proxy:
        mine = skip | own_child_pids()
        owners = active_core_apps(direct_ips, mine)
    proxy_mode = bool(proxy) and not foreign
    conns: list[tuple[str, str | None]] = []
    if len(hosts) > MAX_SERVER_ROUTES or proxy_mode or any(app in NO_ADAPTER_APPS for app in apps):
        conns = vpn_connections(direct_ips, mine if mine is not None else skip | own_child_pids())
    servers = set(server_routes(table, direct, {remote for _app, remote in conns if remote}) if hosts else [])
    servers |= set(endpoints)
    if proxy_mode:
        servers |= set(proxy_servers(conns))
    own_servers = own.capped_servers() if own else []
    # Свои — первыми: фильтр WinDivert умещает ограниченное число адресов.
    servers_list = own_servers + [s for s in sorted(servers) if s not in own_servers]
    return Snapshot(adapters=adapters, servers=servers_list, apps=apps, at=time.time(), proxy=proxy, owners=owners,
                    own=own, connected=sorted({app for app, _remote in conns}))


def plan_changed(applied: dict | None, wanted: dict | None, direct: list[int] | None = None) -> bool:
    """Нужно ли перезапустить winws с новым фильтром.

    Появился VPN, новый прямой интерфейс, новый сервер VPN — нужен. VPN пропал — фильтр по
    прямым интерфейсам по-прежнему верен, пока сами прямые интерфейсы те же; сменились —
    перезапуск (без туннелей обход вернётся к обычному фильтру). Если фильтр при том же наборе
    уже не собрался, повторять незачем: иначе обход перезапускался бы по кругу. Фильтр своего VPN
    (mode «own») ведёт себя так же: выключили VPN — исключение его сервера никому не мешает.
    """
    applied = applied or {"mode": "plain"}
    if wanted is None:
        return (applied.get("mode") in ("vpn", "own") and direct is not None
                and sorted(applied.get("interfaces") or []) != sorted(direct))
    if applied.get("mode") == "plain":
        return True
    if applied.get("interfaces") != wanted["interfaces"]:
        return True
    return not set(wanted["servers"]) <= set(applied.get("servers_seen") or [])


# ------------------------------------------------------------ куда идут сайты

TRACE_DEFAULT = "https://1.1.1.1/cdn-cgi/trace"
TRACE_DEFAULT_HOST = "https://cloudflare.com/cdn-cgi/trace"
TRACE_DISCORD = ("https://gateway.discord.gg/cdn-cgi/trace", "https://discord.gg/cdn-cgi/trace")
TRACE_YOUTUBE = "https://redirector.googlevideo.com/report_mapping?di=no"
_TRACE_IP = re.compile(r"^ip=([0-9a-fA-F:.]+)\s*$", re.M)
_MAPPING_IP = re.compile(r"^\s*([0-9a-fA-F:.]+)\s+=>", re.M)


def _curl_seen(url: str, bind: str | None = None, proxy: str | None = None, timeout: int = 6) -> str | None:
    """IP, с которого нас видит сайт (Cloudflare trace или report_mapping видеосерверов YouTube).

    -q и --noproxy: ни .curlrc, ни переменные HTTPS_PROXY не должны незаметно увести запрос
    в прокси — маршрут задаём только сами (bind — прямое подключение или туннель, proxy —
    системный прокси VPN-программы)."""
    args = [winutil.system32("curl.exe"), "-q", "-s", "-m", str(timeout), "--connect-timeout", str(min(4, timeout))]
    if proxy:
        args += ["-x", proxy]
    else:
        args += ["--noproxy", "*"]
        if bind:
            args += ["-4" if ":" not in bind else "-6", "--interface", bind]
    res = winutil.run([*args, url], timeout=timeout + 6)
    if res.code != 0:
        return None
    match = _TRACE_IP.search(res.out) or _MAPPING_IP.search(res.out)
    return match.group(1) if match else None


def _python_seen(url: str = TRACE_DEFAULT, timeout: int = 6) -> str | None:
    """То же, но из самого процесса Лазейки и без системного прокси — так ходит
    Telegram-прокси (его ядро открывает обычные сокеты)."""
    import ssl
    import urllib.request
    try:
        ctx = ssl.create_default_context()
        try:
            import certifi
            ctx.load_verify_locations(certifi.where())
        except Exception:  # noqa: BLE001
            pass
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                             urllib.request.HTTPSHandler(context=ctx))
        with opener.open(url, timeout=timeout) as resp:  # noqa: S310 — фиксированный адрес
            text = resp.read(4096).decode("utf-8", "replace")
    except (OSError, ValueError):
        return None
    match = _TRACE_IP.search(text)
    return match.group(1) if match else None


def _same_exit(a: str | None, b: str | None) -> bool:
    if not a or not b:
        return False
    try:
        x, y = ipaddress.ip_address(a), ipaddress.ip_address(b)
    except ValueError:
        return False
    if x.version != y.version:
        return False
    if x.version == 4:
        return x == y
    return ipaddress.ip_network(f"{x}/56", strict=False) == ipaddress.ip_network(f"{y}/56", strict=False)


def judge(seen: str | None, vpn_exits: list[str | None], direct_exits: list[str | None],
          direct_v6: list | None = None) -> str:
    """vpn | direct | blocked | unknown — по адресу, с которого сайт нас видит.

    Выводы — только по подтверждённым эталонам: direct_exits — адрес, который сайты видят у
    запроса, привязанного к прямому подключению; vpn_exits — у запроса через туннель или прокси
    VPN; direct_v6 — сети /64 глобальных IPv6 прямых адаптеров (у IPv6 обычно нет NAT, и сайт
    видит адрес из нашей же сети — так ловится VPN, который заворачивает только IPv4).
    Незнакомый адрес — «не удалось определить», а не догадка."""
    if seen is None:
        # Через VPN сайт открылся бы. Не открылся — значит, идёт напрямую и его режет провайдер
        # (или VPN-программа сама его не пускает); в обоих случаях без обхода никак.
        return "blocked" if any(vpn_exits) or any(direct_exits) else "unknown"
    if any(_same_exit(seen, d) for d in direct_exits):
        return "direct"
    try:
        addr = ipaddress.ip_address(seen)
    except ValueError:
        return "unknown"
    if addr.version == 6 and any(addr in net for net in direct_v6 or []):
        return "direct"
    if any(_same_exit(seen, v) for v in vpn_exits):
        return "vpn"
    return "unknown"


def probe_routes(snapshot: Snapshot) -> dict:
    """Через что сейчас ходят Discord, YouTube, Telegram-прокси и остальные сайты.

    Сравниваем адрес, с которым нас видит сайт, с двумя эталонами: запрос, привязанный к
    прямому подключению, и запрос через туннель (или системный прокси) VPN. Работает для любого
    VPN, в том числе с правилами внутри программы (Incy, Happ, Hiddify, v2rayN…), где таблица
    маршрутов ничего не говорит. Это маршрут проверочного запроса: если в VPN есть правила для
    отдельных программ, у самих программ он может отличаться. Свой VPN: эталон — привязка к своему
    TUN или запрос через системный прокси, который выставила Лазейка."""
    own_proxy = snapshot.own.proxy if snapshot.own is not None and snapshot.own.proxy else None
    if own_proxy and "://" not in own_proxy:
        own_proxy = f"http://{own_proxy}"
    proxy = (snapshot.proxy or own_proxy) if not snapshot.internet else None
    direct_ip = snapshot.source_ip() if snapshot.internet else None
    tunnel_ip = snapshot.tunnel_ip()
    with ThreadPoolExecutor(max_workers=8) as pool:
        # Эталон «напрямую»: при туннеле — привязка к прямому подключению; при прокси или без
        # VPN — обычный запрос мимо прокси.
        f_direct = pool.submit(_curl_seen, TRACE_DEFAULT, direct_ip) if (direct_ip or not snapshot.internet) else None
        # Эталон «через VPN»: привязка к самому туннелю или запрос через системный прокси.
        f_vpn = (pool.submit(_curl_seen, TRACE_DEFAULT, tunnel_ip) if tunnel_ip else
                 pool.submit(_curl_seen, TRACE_DEFAULT, None, proxy) if proxy else None)
        f_vpn_host = (pool.submit(_curl_seen, TRACE_DEFAULT_HOST, tunnel_ip) if tunnel_ip else
                      pool.submit(_curl_seen, TRACE_DEFAULT_HOST, None, proxy) if proxy else None)
        # Как ходят приложения: обычный запрос (при туннеле — по маршрутам Windows), при VPN в
        # режиме прокси — через этот прокси, как браузер и Discord.
        f_discord = pool.submit(lambda: _curl_seen(TRACE_DISCORD[0], None, proxy)
                                or _curl_seen(TRACE_DISCORD[1], None, proxy))
        f_youtube = pool.submit(_curl_seen, TRACE_YOUTUBE, None, proxy)
        f_other = pool.submit(_curl_seen, TRACE_DEFAULT_HOST, None, proxy)
        f_python = pool.submit(_python_seen)
        direct = f_direct.result() if f_direct else None
        vpn_exits = [f.result() if f else None for f in (f_vpn, f_vpn_host)]
        discord, youtube, other, python = (f_discord.result(), f_youtube.result(), f_other.result(),
                                           f_python.result())
    direct_exits, v6 = [direct], snapshot.direct_v6()
    items = [
        {"id": "discord", "label": "Discord", "via": judge(discord, vpn_exits, direct_exits, v6)},
        {"id": "youtube", "label": "YouTube", "via": judge(youtube, vpn_exits, direct_exits, v6)},
        {"id": "telegram", "label": "Telegram-прокси", "via": judge(python, vpn_exits, direct_exits, v6)},
        {"id": "other", "label": "Остальные сайты", "via": judge(other, vpn_exits, direct_exits, v6)},
    ]
    log.info("Маршруты при VPN: %s", ", ".join(f"{i['id']}={i['via']}" for i in items))
    return {"items": items, "full_tunnel": snapshot.full_tunnel, "mode": "proxy" if proxy else "tunnel",
            "checked_direct": bool(direct), "checked_vpn": any(vpn_exits), "at": time.time()}


def snapshot_dict(snapshot: Snapshot | None) -> dict:
    return snapshot.to_dict() if snapshot else {"active": False, "mode": None, "adapters": [], "servers": [],
                                                "apps": [], "candidates": [], "proxy": None, "unseparable": [],
                                                "own": {"active": False, "mode": None}}
