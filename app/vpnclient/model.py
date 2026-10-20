"""Общая модель своего VPN: серверы, группы, подписки и план запуска ядра.

Это контракт между частями пакета: разбор ссылок и подписок, хранилище, генератор конфигов
и менеджер договариваются только этими типами (docs/vpnclient-plan.md, 5.1). Модуль чистый —
без сети, файлов и системы.

Секреты (идентификаторы и пароли пользователя, ключи, исходные ссылки, outbound'ы провайдера)
хранятся в полях с repr=False и не попадают в public(): страница и журнал видят только имя,
протокол, транспорт и страну.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any

PROTOCOLS = ("vless", "vmess", "trojan", "shadowsocks", "hysteria2", "tuic", "socks", "wireguard")
NETWORKS = ("tcp", "ws", "grpc", "httpupgrade", "xhttp", "http", "kcp", "quic")
SECURITIES = ("none", "tls", "reality")
ENGINES = ("sing-box", "xray")
MODES = ("tun", "proxy", "local")
PRESETS = ("all", "except_ru", "blocked")
SOURCES = ("link", "xray-json", "sip008", "wireguard-conf")
SUB_FORMATS = ("links", "xray-json", "sip008")

# Пресеты User-Agent подписки. «lazeyka» — честный UA, подставляет subscription.py
# (Lazeyka/<версия> (Windows)); «custom» — строка из свойств подписки.
UA_PRESETS: dict[str, str | None] = {
    "lazeyka": None,
    "v2rayn": "v2rayN/7.15.0",
    "happ": "Happ/4.7.2",
    "incy": "INCY/3.8.8/Windows",
    "custom": None,
}

PROBE_URL = "https://www.gstatic.com/generate_204"   # только https: http clash API молча подменяет


# ------------------------------------------------------------ страна из имени

_REGIONAL = re.compile("([\U0001F1E6-\U0001F1FF])([\U0001F1E6-\U0001F1FF])")


def split_flag(name: str) -> tuple[str | None, str]:
    """(код страны, имя без флага): флаг страница рисует сама — локальным шрифтом флагов по коду страны."""
    match = _REGIONAL.search(name or "")
    if not match:
        return None, (name or "").strip()
    code = "".join(chr(ord(ch) - 0x1F1E6 + ord("A")) for ch in match.groups())
    clean = (name[:match.start()] + name[match.end():]).strip(" \t-—|·")
    return code, clean or code


# ------------------------------------------------------------ сервер

@dataclass
class Server:
    """Один сервер. Разбор ссылок ничего не знает о ядрах: что открыть каким ядром, решает engine_for."""

    proto: str                                  # PROTOCOLS
    host: str                                   # без [], нижний регистр, IDNA (punycode)
    port: int
    name: str = ""
    uuid: str | None = field(default=None, repr=False)       # vless/vmess/tuic
    password: str | None = field(default=None, repr=False)   # trojan/ss/hysteria2/tuic/socks
    username: str | None = field(default=None, repr=False)   # socks
    method: str | None = None                   # shadowsocks
    cipher: str = "auto"                        # vmess security
    alter_id: int = 0                           # vmess: > 0 — устаревший MD5-VMess
    flow: str = ""                              # vless: "" | xtls-rprx-vision | xtls-rprx-vision-udp443
    encryption: str = "none"                    # vless: none | mlkem768x25519plus…
    network: str = "tcp"                        # NETWORKS
    # path, host (str или список для tcp+http), headers, header_type, service_name, grpc_mode,
    # authority, xhttp_mode, xhttp_extra, early_data, kcp_* — по типу транспорта
    transport: dict[str, Any] = field(default_factory=dict)
    security: str = "none"                      # SECURITIES
    # sni, alpn[], fingerprint, insecure, ech, pcs[], vcn[], pbk, sid, spx, pqv
    tls: dict[str, Any] = field(default_factory=dict, repr=False)
    # ports ("443,20000-30000"), obfs (salamander|gecko), obfs_password, up_mbps, down_mbps, pin_sha256
    hy2: dict[str, Any] = field(default_factory=dict, repr=False)
    # congestion_control, udp_relay_mode, alpn — для tuic
    tuic: dict[str, Any] = field(default_factory=dict)
    # private_key, peer_public_key, preshared_key, local_address[], reserved[], mtu, dns[] — для wireguard
    wg: dict[str, Any] = field(default_factory=dict, repr=False)
    plugin: dict[str, Any] | None = None        # shadowsocks: {"name": "obfs-local", "opts": {...}}
    xray_outbound: dict[str, Any] | None = field(default=None, repr=False)  # outbound провайдера «как есть»
    fragment: dict[str, Any] | None = None      # из dialerProxy freedom провайдера: {packets, length, interval}
    source: str = "link"                        # SOURCES
    raw: str = field(default="", repr=False)    # исходная ссылка
    warnings: list[str] = field(default_factory=list)
    # служебное: заполняет хранилище
    id: str = ""                                # = key()
    sub: str | None = None                      # id подписки; None — добавлен отдельной ссылкой
    country: str | None = None                  # ISO-3166 alpha-2 из флага в имени
    custom_name: str | None = None              # своё имя человека
    description: str | None = None             # meta.serverDescription провайдера

    # ---------------------------------------------------------------- идентичность

    def key(self) -> str:
        """Устойчивый id: не меняется от имени и порядка в подписке (сопоставление при обновлении)."""
        t = self.transport or {}
        host = t.get("host")
        if isinstance(host, list):
            host = ",".join(str(h) for h in host)
        parts = [
            self.proto, (self.host or "").lower(), int(self.port),
            self.uuid or "", self.password or "", self.username or "", self.method or "",
            self.network, str(host or ""), str(t.get("path") or ""), str(t.get("service_name") or ""),
            self.security, str((self.tls or {}).get("sni") or ""), self.flow or "",
            str((self.hy2 or {}).get("ports") or ""), str((self.wg or {}).get("peer_public_key") or ""),
        ]
        if self.proto == "wireguard":
            # Клиентская сторона: два профиля одного сервера с разными ключами и адресами клиента — разные
            # серверы. Только у WireGuard: id остальных протоколов от этого не меняются.
            wg = self.wg or {}
            addresses = wg.get("local_address") or []
            if isinstance(addresses, str):
                addresses = addresses.split(",")
            parts += [str(wg.get("private_key") or ""), ",".join(sorted(str(a).strip() for a in addresses))]
        return hashlib.sha256(json.dumps(parts, ensure_ascii=False).encode("utf-8")).hexdigest()[:16]

    def display_name(self) -> str:
        return self.custom_name or self.name or f"{self.host}:{self.port}"

    # ---------------------------------------------------------------- хранение и страница

    def to_dict(self) -> dict[str, Any]:
        """Для profiles.json — со всеми секретами."""
        return copy.deepcopy(asdict(self))

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Server":
        """Из profiles.json; незнакомые ключи пропускаются (файл мог писать более новый выпуск)."""
        known = {f.name for f in fields(cls)}
        kwargs = {k: copy.deepcopy(v) for k, v in data.items() if k in known}
        kwargs["port"] = int(kwargs.get("port") or 0)
        kwargs["alter_id"] = int(kwargs.get("alter_id") or 0)
        return cls(**kwargs)

    def public(self) -> dict[str, Any]:
        """Для get_state(): без секретов. IP и домен сервера тоже не отдаём — странице они не нужны."""
        engine, reason = engine_for(self)
        return {
            "id": self.id or self.key(), "sub": self.sub, "name": self.display_name(), "country": self.country,
            "proto": self.proto, "transport": self.network, "security": self.security,
            "engine": engine, "supported": engine is not None, "reason": reason,
            "description": self.description, "warnings": list(self.warnings),
        }


def streamed(server: Server) -> bool:
    """Транспорт или TLS поверх протокола. Shadowsocks и SOCKS в sing-box их не имеют — такой сервер
    (outbound провайдера из JSON Xray) открывает только помощник Xray, иначе ядро выдало бы голый протокол."""
    return (server.network != "tcp" or server.security != "none"
            or bool((server.transport or {}).get("header_type")))


def grpc_authority(server: Server) -> str | None:
    """authority gRPC, которую sing-box передать не умеет: он шлёт имя TLS (или адрес, а адрес в
    конфиге — уже IP). None — authority нет или она совпадает с именем TLS."""
    authority = str((server.transport or {}).get("authority") or "").strip()
    if server.network != "grpc" or not authority:
        return None
    sni = str((server.tls or {}).get("sni") or server.host or "").strip() if server.security != "none" else ""
    return None if authority.lower() == sni.lower() else authority


def engine_for(server: Server, *, force_xray: bool = False) -> tuple[str | None, str | None]:
    """Каким ядром открыть сервер: ("sing-box" | "xray" | None, причина для человека).

    sing-box — основное ядро; помощник Xray — для того, чего sing-box не умеет. force_xray — сервер
    нужно провести через помощника ради его возможностей (UDP-шумы, фрагментация Xray). Фрагментация
    провайдера (Server.fragment) — та же просьба: сервер, которого Xray не откроет, идёт в sing-box с его
    фрагментацией TLS."""
    if server.proto not in PROTOCOLS:
        return None, f"протокол {server.proto} пока не поддерживается"
    if server.network not in NETWORKS:
        return None, f"транспорт {server.network} пока не поддерживается"
    if server.network == "quic":
        return None, "транспорт QUIC удалён из Xray и несовместим с ним в sing-box"
    if server.proto == "socks" and streamed(server) and not server.xray_outbound:
        # Свой выход SOCKS помощник не собирает — только outbound провайдера «как есть».
        return None, "SOCKS с TLS или транспортом открывает только помощник Xray — из JSON Xray провайдера"
    tls = server.tls or {}
    hy2 = server.hy2 or {}
    xray_only: list[str] = []
    if server.network in ("xhttp", "kcp"):
        xray_only.append("XHTTP" if server.network == "xhttp" else "mKCP")
    if server.proto == "vless" and server.encryption not in ("", "none"):
        xray_only.append("шифрование VLESS (ML-KEM)")
    if server.network == "grpc" and (server.transport or {}).get("grpc_mode") == "multi":
        xray_only.append("gRPC multi")
    if grpc_authority(server):
        xray_only.append("gRPC authority")
    if (server.transport or {}).get("finalmask"):
        xray_only.append("маскировка finalmask")
    if tls.get("pcs") or tls.get("vcn") or (server.proto == "hysteria2" and hy2.get("pin_sha256")):
        xray_only.append("закрепление сертификата")
    if server.security == "reality" and tls.get("pqv"):
        xray_only.append("REALITY с подписью ML-DSA-65")
    if server.proto in ("shadowsocks", "socks") and streamed(server):
        label = "Shadowsocks" if server.proto == "shadowsocks" else "SOCKS"
        xray_only.append(f"{label} через {server.network}" + (f"/{server.security.upper()}"
                                                               if server.security != "none" else ""))
    singbox_only: list[str] = []
    if tls.get("insecure") and not tls.get("pcs"):
        singbox_only.append("отключённая проверка сертификата (Xray с 2026-06-01 её не принимает)")
    if server.proto == "hysteria2" and hy2.get("obfs") == "gecko":
        singbox_only.append("обфускация gecko")
    if server.proto in ("tuic", "wireguard") or (server.proto == "socks" and not streamed(server)):
        singbox_only.append(server.proto)
    if server.proto == "vmess" and server.alter_id > 0:
        singbox_only.append("устаревший VMess (alterId)")
    if server.proto == "shadowsocks" and server.plugin:
        singbox_only.append(f"плагин {server.plugin.get('name')}")
    if server.network == "http":
        singbox_only.append("транспорт HTTP/2 (удалён из Xray 26)")
    if xray_only and singbox_only:
        return None, f"нужны {', '.join(xray_only)} (только Xray) и {', '.join(singbox_only)} (только sing-box)"
    if xray_only:
        return "xray", "через помощник Xray: " + ", ".join(xray_only)
    if (force_xray or server.fragment) and not singbox_only:
        return "xray", "через помощник Xray" + (": фрагментация провайдера" if server.fragment else "")
    return "sing-box", None


# ------------------------------------------------------------ группы и подписки

@dataclass
class Group:
    """Группа серверов «Самый быстрый» (балансировщик провайдера или вся подписка)."""

    id: str
    sub: str | None
    name: str
    members: list[str] = field(default_factory=list)      # id серверов
    strategy: str = "leastPing"                           # leastPing | leastLoad | random | roundRobin
    probe_url: str = PROBE_URL
    interval: int = 300                                    # секунд, не меньше 30
    fallback: str | None = None                            # id сервера по умолчанию

    def to_dict(self) -> dict[str, Any]:
        return copy.deepcopy(asdict(self))

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Group":
        known = {f.name for f in fields(cls)}
        return cls(**{k: copy.deepcopy(v) for k, v in data.items() if k in known})


@dataclass
class Subscription:
    id: str
    name: str
    url: str = field(default="", repr=False)              # секрет: в адресе токен
    ua_preset: str = "lazeyka"                             # ключ UA_PRESETS
    user_agent: str | None = None                         # для ua_preset == "custom"
    hwid: str | None = field(default=None, repr=False)    # случайный id подписки, если провайдер требует HWID
    added_at: float = 0.0
    updated_at: float | None = None
    last_ok_at: float | None = None
    update_hours: int = 12
    format: str = "links"                                  # SUB_FORMATS
    userinfo: dict[str, int] = field(default_factory=dict)   # upload, download, total, expire (секунды)
    refill_at: float | None = None
    support_url: str | None = None
    web_page_url: str | None = None
    announce: str | None = None
    description: str | None = None
    fallback_urls: list[str] = field(default_factory=list, repr=False)
    provider_routes: bool = False                          # применять маршруты провайдера (по согласию)
    dns: str | None = None                                 # свой DNS подписки (как dns_remote)
    mtu: int | None = None                                 # свой MTU TUN для серверов подписки
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return copy.deepcopy(asdict(self))

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Subscription":
        known = {f.name for f in fields(cls)}
        return cls(**{k: copy.deepcopy(v) for k, v in data.items() if k in known})

    def public(self, servers: int = 0, updating: bool = False,
               probe: dict[str, Any] | None = None) -> dict[str, Any]:
        """Для страницы: без адреса подписки и HWID. probe — ход «Проверить расширенный формат», null — проверки не было."""
        info = self.userinfo or {}
        used = int(info.get("upload") or 0) + int(info.get("download") or 0)
        return {
            "id": self.id, "name": self.name, "format": self.format, "ua_preset": self.ua_preset,
            "user_agent": self.user_agent if self.ua_preset == "custom" else None,
            "update_hours": self.update_hours, "dns": self.dns, "mtu": self.mtu,
            "servers": servers, "updated_at": self.updated_at, "updating": updating, "error": self.error,
            "userinfo": {"used": used, "total": int(info.get("total") or 0),
                         "expire": int(info.get("expire") or 0), "refill_at": self.refill_at},
            "support_url": self.support_url, "web_page_url": self.web_page_url, "announce": self.announce,
            "description": self.description, "hwid": bool(self.hwid), "provider_routes": self.provider_routes,
            "probe": dict(probe) if probe else None,
        }


# ------------------------------------------------------------ план запуска (вход генератора конфигов)

@dataclass
class Ports:
    proxy: int = 20808                    # системный или локальный прокси (mixed)
    internal: int = 0                     # служебный вход: проверка выхода и запросы Лазейки «через VPN»
    clash: int = 0                        # clash API
    helper: dict[str, int] = field(default_factory=dict)   # id сервера → порт входа помощника Xray


@dataclass
class Secrets:
    clash: str = field(default="", repr=False)
    internal_user: str = field(default="", repr=False)
    internal_pass: str = field(default="", repr=False)
    helper_user: str = field(default="", repr=False)
    helper_pass: str = field(default="", repr=False)
    local_user: str | None = field(default=None, repr=False)   # локальный прокси с паролем (local_auth / LAN)
    local_pass: str | None = field(default=None, repr=False)


@dataclass
class TunOptions:
    address4: str                         # своя /30, например "172.31.255.253/30"
    address6: str | None = None           # только при включённом IPv6
    mtu: int = 1500
    exclude: list[str] = field(default_factory=list)   # route_exclude_address
    interface_name: str = "Lazeyka"


@dataclass
class DnsChoice:
    remote: str = "https://1.1.1.1/dns-query"     # через VPN
    direct: str = "https://1.1.1.1/dns-query"     # напрямую: «мимо VPN», «через обход», хосты серверов
    ru: str = "https://77.88.8.8/dns-query"       # российские сайты (пресет «Кроме российских»)
    fakeip: bool = False
    strategy: str = "ipv4_only"                   # ipv4_only | prefer_ipv4 | prefer_ipv6


@dataclass
class BypassProfile:
    """Профиль winws активной стратегии, переведённый в маршрут «через обход»."""

    network: str                          # tcp | udp
    ports: list[str]                      # как в winws: "443", "80", "50000-50100"
    domains_file: Path | None = None      # локальный rule-set (JSON source) доменов профиля
    ips_file: Path | None = None          # локальный rule-set IP (режим IPSet «по списку»)
    exclude_file: Path | None = None      # rule-set IP из --ipset-exclude профиля без IPSet: их winws не трогает
    reject_quic: bool = False             # домены только TCP-профиля: udp:443 → reject (клиент уйдёт на TCP)
    # --filter-l7: discord — правило по процессу Discord; quic, stun, tls, http — условие protocol (sniff)
    l7: list[str] = field(default_factory=list)


@dataclass
class RunPlan:
    """Всё, что нужно генератору: менеджер собирает заранее, генератор не ходит в сеть и систему."""

    mode: str                                         # MODES
    servers: list[Server]                             # все серверы конфига (выбранный или участники группы)
    selected: str                                     # id сервера или "auto:<id группы>"
    groups: list[Group] = field(default_factory=list)
    addresses: dict[str, str] = field(default_factory=dict)   # id сервера → резолвленный IP
    engines: dict[str, str] = field(default_factory=dict)     # id сервера → "sing-box" | "xray"
    preset: str = "all"
    via_zapret: bool = False
    bypass_state: str = "proxy"                       # начальное состояние селектора bypass: direct | proxy
    bypass: list[BypassProfile] = field(default_factory=list)
    voice_ports: list[str] = field(default_factory=list)   # UDP-порты голоса Discord из стратегии
    games_direct: bool = False
    torrents_direct: bool = False
    ip_check_direct: bool = False
    direct_apps: list[str] = field(default_factory=list)
    proxy_apps: list[str] = field(default_factory=list)
    direct_sites: list[str] = field(default_factory=list)
    proxy_sites: list[str] = field(default_factory=list)
    torrent_apps: list[str] = field(default_factory=list)
    rules_files: dict[str, Path] = field(default_factory=dict)   # id набора → локальный .srs
    additions: list[str] = field(default_factory=list)          # «дополнения Лазейки» (российские сервисы)
    profile_rules: list[dict[str, Any]] = field(default_factory=list)  # активный профиль маршрутизации
    ports: Ports = field(default_factory=Ports)
    secrets: Secrets = field(default_factory=Secrets)
    dns: DnsChoice = field(default_factory=DnsChoice)
    tun: TunOptions | None = None
    proxy_listen: str = "127.0.0.1"                   # "0.0.0.0" — «пускать устройства из локальной сети»
    socks_udp: bool = True
    proxy_override: list[str] = field(default_factory=list)
    tls_fragment: bool = False
    mux: bool = False
    noises: bool = False
    fingerprint: str | None = None                    # общий uTLS-отпечаток — серверам без своего fp
    lazeyka_exe: str = ""                             # путь exe Лазейки (в разработке — python.exe)
    xray_exe: str | None = None                       # путь xray.exe помощника
    physical_interface: str | None = None             # имя физического адаптера для sockopt.interface помощника
    log_level: str = "error"
    work_dir: Path = Path(".")
    probe_url: str = PROBE_URL
