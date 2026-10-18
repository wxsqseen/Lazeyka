"""Маршруты своего VPN: пресеты, «через обход» по профилям winws, голос Discord, свои списки.

«Через обход» строится только из аргументов активной стратегии zapret: домен, отправленный
мимо VPN, но не попавший в hostlist, winws не обработает — заблокированный сайт сломался бы,
хотя через сервер он бы открылся (docs/vpnclient-plan.md, 5.5). Домены и IP каждого профиля
пишутся в локальные rule-set файлы (формат source, JSON): sing-box перечитывает их при
изменении, поэтому смена списков zapret не требует перезапуска ядра.

Модуль ничего не знает о ядре и сети: читает файлы списков и пишет файлы правил.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator, NamedTuple

from ..zapret.lists import NONE_MARKER, PLACEHOLDER_DOMAIN
from ..zapret.strategies import DUMMY_PORT
from .model import BypassProfile

# ------------------------------------------------------------ данные

DISCORD_APPS = ("Discord.exe", "DiscordPTB.exe", "DiscordCanary.exe", "Vesktop.exe")

# Торрент-клиенты для «Торренты напрямую» (вместе со sniff bittorrent). Список свой.
TORRENT_APPS = (
    "qbittorrent.exe", "utorrent.exe", "bittorrent.exe", "utweb.exe", "transmission-qt.exe",
    "transmission-daemon.exe", "deluge.exe", "deluged.exe", "tixati.exe", "bitcomet.exe", "biglybt.exe",
    "vuze.exe", "azureus.exe", "picotorrent.exe", "motrix.exe", "aria2c.exe", "fdm.exe", "frostwire.exe",
    "mediaget.exe",
)

# «Дополнения Лазейки»: российские сервисы на иностранных доменах, которых нет в geosite
# category-ru (final_rules 5.3). Обновляются с релизами.
ADDITIONS = (
    "habr.com", "kinescope.io", "kinescopecdn.net", "sber.world", "sber.ws", "sbercoin.com",
    "1cfresh.com", "edadeal.io", "lmru.tech", "vtb24.com", "vtb.digital", "alfabank.com", "bronevik.com",
)

# «Сервисы проверки IP напрямую» (выключено по умолчанию: страницы «мой IP» покажут настоящий адрес).
IP_CHECK_SITES = (
    "ipify.org", "checkip.amazonaws.com", "ifconfig.me", "ifconfig.co", "ip.sb", "ipapi.is", "iplocate.io",
    "api.sypexgeo.net", "showip.net", "ipinfo.io", "ip-api.com", "icanhazip.com", "2ip.ru", "2ip.io",
)

# id наборов правил: файлы rules/<id>.srs, источники — rules.SOURCES.
RU_DOMAINS = "geosite-category-ru"
RU_IPS = "geoip-ru"
GAMES_DOWNLOAD = "geosite-category-game-platforms-download"
BLOCKED_DOMAINS = ("refilter-domains", "russia-inside")
BLOCKED_IPS = "geoip-ru-blocked"

PRESET_RULE_SETS: dict[str, tuple[str, ...]] = {
    "all": (),
    "except_ru": (RU_DOMAINS, RU_IPS),
    "blocked": (*BLOCKED_DOMAINS, BLOCKED_IPS),
}
_IP_SETS = frozenset({RU_IPS, BLOCKED_IPS})

BYPASS_PREFIX = "bypass-"
RULE_SET_VERSION = 3          # формат source: 3 — sing-box 1.11+, ядро 1.14 понимает до 5


def preset_rule_sets(preset: str, *, games: bool) -> list[str]:
    """Какие файлы правил нужны пресету (и переключателю «Загрузки игр напрямую»)."""
    if preset not in PRESET_RULE_SETS:
        raise ValueError(f"неизвестный пресет: {preset}")
    ids = list(PRESET_RULE_SETS[preset])
    if games:
        ids.append(GAMES_DOWNLOAD)
    return ids


def rule_set_tags(rules: Iterable[dict[str, Any]]) -> Iterator[str]:
    """id наборов, на которые ссылаются правила sing-box (и вложенные в logical)."""
    for rule in rules:
        if rule.get("type") == "logical":
            yield from rule_set_tags(rule.get("rules", []))
        value = rule.get("rule_set")
        yield from ([value] if isinstance(value, str) else list(value or []))


_FULL_RANGES = frozenset({"0:65535", "1:65535"})


def catch_all(rule: dict[str, Any]) -> bool:
    """Правило sing-box «весь TCP и UDP» на выход direct или proxy: GlobalProxy профиля, «port: 0-65535»
    провайдера. Правила после него недостижимы — его выход становится route.final."""
    if rule.get("type") == "logical" or rule.get("invert") or rule.get("action", "route") != "route":
        return False
    if rule.get("outbound") not in ("direct", "proxy") or set(rule) - {"network", "port_range", "action", "outbound"}:
        return False
    nets = rule.get("network")
    if nets is not None and not {"tcp", "udp"} <= set([nets] if isinstance(nets, str) else nets):
        return False
    ranges = rule.get("port_range")
    if ranges is not None and not _FULL_RANGES.intersection([ranges] if isinstance(ranges, str) else ranges):
        return False
    return nets is not None or ranges is not None


# Откуда требование «через VPN» — в порядке правил маршрута (план 5.5): свои списки стоят раньше
# «через обход», профиль — после переключателей, пресет — последним.
STRICT_LEVELS = ("user", "profile", "preset")


def vpn_required(proxy_sites: Iterable[str], profile_rules: Iterable[dict[str, Any]], preset: str
                 ) -> list[tuple[str, tuple[str, ...]]]:
    """Наборы, без которых «через VPN» не исполнить: (откуда, альтернативы) — свои списки «только через
    VPN» (user), правила профиля «через VPN» (profile), пресет «Только заблокированное», если его не
    заменил выход по умолчанию профиля (preset). Альтернативы — хватает любой (сбой одного источника
    пресета его не ломает, план 5.5)."""
    out: list[tuple[str, tuple[str, ...]]] = [("user", (s,)) for s in site_rule_sets(proxy_sites)]
    replaced = False
    for rule in profile_rules:
        if catch_all(rule):
            replaced = True
            break
        if rule.get("action", "route") == "route" and rule.get("outbound") == "proxy":
            out += [("profile", (s,)) for s in rule_set_tags([rule])]
    if preset == "blocked" and not replaced:
        out.append(("preset", PRESET_RULE_SETS["blocked"]))
    return list(dict.fromkeys(out))


def missing_vpn_sets(required: Iterable[tuple[str, tuple[str, ...]]], available: Iterable[str]) -> list[str]:
    """Наборы из vpn_required, у которых не нашлось ни одной альтернативы среди available."""
    have = set(available)
    out: list[str] = []
    for _origin, group in required:
        if not have.intersection(group):
            out += [s for s in group if s not in out]
    return out


def strict_level(required: Iterable[tuple[str, tuple[str, ...]]], available: Iterable[str]) -> str | None:
    """С какого места маршрута «через VPN» не исполнить (самое раннее из STRICT_LEVELS); None — всё на месте.
    Генератор тогда не пускает напрямую ничего из того, что стоит после этого места, кроме явных правил
    человека и переключателей: без списка его сайты ушли бы туда (YouTube из своего списка — в обход)."""
    have = set(available)
    levels = [origin for origin, group in required if not have.intersection(group)]
    return min(levels, key=STRICT_LEVELS.index) if levels else None


def rule_set_kind(set_id: str) -> str:
    """"ip" или "domain": IP-наборы ставятся только в route.rules, в DNS-правила — только доменные."""
    if set_id in _IP_SETS or set_id.startswith("geoip-"):
        return "ip"
    if set_id.startswith(BYPASS_PREFIX) and set_id.endswith("-ip"):
        return "ip"
    return "domain"


# ------------------------------------------------------------ строки списков сайтов

class SiteMatch(NamedTuple):
    field: str          # domain | domain_suffix | domain_keyword | domain_regex | ip_cidr | ip_is_private | rule_set
    value: Any
    negate: bool = False


_DOMAIN_RE = re.compile(r"[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?)*")
_SET_NAME_RE = re.compile(r"[a-z0-9][a-z0-9._@!-]*")


def normalize_domain(text: str) -> str | None:
    """Домен в нижнем регистре и punycode; None — не домен."""
    d = (text or "").strip().lower().rstrip(".")
    if d.startswith("*."):
        d = d[2:]
    d = d.lstrip(".")
    if not d or len(d) > 253:
        return None
    if not d.isascii():
        try:
            d = d.encode("idna").decode("ascii")
        except UnicodeError:
            return None
    return d if _DOMAIN_RE.fullmatch(d) else None


def _network(text: str) -> str | None:
    try:
        return str(ipaddress.ip_network(text.strip(), strict=False))
    except ValueError:
        return None


def site_match(entry: str) -> SiteMatch | None:
    """Строка списка сайтов или IP → условие правила sing-box. None — строка не понята.

    Синтаксис Xray и Happ: domain:/full:/regexp:/keyword:, geosite:/geoip: (rule-set SagerNet,
    geoip:private — частные сети, geoip:!X — «не X»), IP и подсети. Как в списках zapret,
    «^домен» — точно этот домен; просто домен — вместе с поддоменами. Строка без точки и без
    префикса — ключевое слово (у Xray простая строка — вхождение подстроки)."""
    text = (entry or "").strip()
    if not text or text.startswith("#"):
        return None
    head, sep, rest = text.partition(":")
    prefix = head.lower() if sep else ""
    if prefix in ("geosite", "geoip"):
        negate = rest.startswith("!")
        name = rest[1:] if negate else rest
        name = name.strip().lower()
        if not _SET_NAME_RE.fullmatch(name):
            return None
        if prefix == "geoip" and name == "private":
            return SiteMatch("ip_is_private", True, negate)
        return SiteMatch("rule_set", f"{prefix}-{name}", negate)
    if prefix == "regexp":
        return SiteMatch("domain_regex", rest) if rest else None
    if prefix == "keyword":
        word = rest.strip().lower()
        return SiteMatch("domain_keyword", word) if word else None
    if prefix in ("full", "domain"):
        d = normalize_domain(rest)
        if d is None:
            return None
        return SiteMatch("domain" if prefix == "full" else "domain_suffix", d)
    if prefix in ("ext", "ext-domain", "ext-ip"):
        return None
    net = _network(text)
    if net is not None:
        return SiteMatch("ip_cidr", net)
    if text.startswith("^"):
        d = normalize_domain(text[1:])
        return SiteMatch("domain", d) if d else None
    d = normalize_domain(text)
    if d is None:
        return None
    return SiteMatch("domain_suffix" if "." in d else "domain_keyword", d)


@dataclass
class SiteGroup:
    """Разобранный список сайтов: поля правила sing-box, наборы правил и непонятые строки."""

    fields: dict[str, list[Any]] = field(default_factory=dict)
    rule_sets: list[str] = field(default_factory=list)
    negated_sets: list[str] = field(default_factory=list)
    private: bool | None = None          # True — частные сети; False — «не частные»
    bad: list[str] = field(default_factory=list)

    def empty(self) -> bool:
        return not (self.fields or self.rule_sets or self.negated_sets or self.private is not None)


def private_match(private: bool) -> dict[str, Any]:
    """geoip:private / geoip:!private → условие sing-box. «ip_is_private: false» ядро считает
    «поле не задано», и правило без условий совпало бы со всем трафиком — отрицание только через invert."""
    return {"ip_is_private": True} if private else {"ip_is_private": True, "invert": True}


def site_rule_sets(entries: Iterable[str]) -> list[str]:
    """Наборы правил, которые нужны списку сайтов (geosite:X, geoip:X и их отрицания) — их скачивает rules.py."""
    group = site_group(entries)
    return list(dict.fromkeys(group.rule_sets + group.negated_sets))


def site_group(entries: Iterable[str]) -> SiteGroup:
    group = SiteGroup()
    for entry in entries:
        m = site_match(entry)
        if m is None:
            if (entry or "").strip() and not entry.strip().startswith("#"):
                group.bad.append(entry.strip())
            continue
        if m.field == "rule_set":
            target = group.negated_sets if m.negate else group.rule_sets
            if m.value not in target:
                target.append(m.value)
        elif m.field == "ip_is_private":
            group.private = not m.negate
        else:
            values = group.fields.setdefault(m.field, [])
            if m.value not in values:
                values.append(m.value)
    return group


# ------------------------------------------------------------ порты

_PORT_ITEM = re.compile(r"(\d{1,5})(?:-(\d{1,5}))?")
_ANY = [(1, 65535)]
Intervals = list[tuple[int, int]]


def _merge(intervals: Iterable[tuple[int, int]]) -> Intervals:
    out: Intervals = []
    for lo, hi in sorted(intervals):
        if out and lo <= out[-1][1] + 1:
            out[-1] = (out[-1][0], max(out[-1][1], hi))
        else:
            out.append((lo, hi))
    return out


def parse_ports(spec: str) -> Intervals | None:
    """Порты winws («80,443,50000-50100», «*» — любые) → интервалы; None — не разобрать
    (в том числе отрицание «~»)."""
    spec = (spec or "").strip()
    if spec == "*":
        return list(_ANY)
    out: Intervals = []
    for item in spec.split(","):
        m = _PORT_ITEM.fullmatch(item.strip())
        if not m:
            return None
        lo = int(m.group(1))
        hi = int(m.group(2) or lo)
        if not (0 < lo <= hi <= 65535):
            return None
        out.append((lo, hi))
    return _merge(out)


def _intersect(a: Intervals, b: Intervals) -> Intervals:
    out: Intervals = []
    for lo1, hi1 in a:
        for lo2, hi2 in b:
            lo, hi = max(lo1, lo2), min(hi1, hi2)
            if lo <= hi:
                out.append((lo, hi))
    return _merge(out)


def _without_dummy(intervals: Intervals) -> Intervals:
    """Порт-заглушка пакета (так он «выключает» игровой фильтр) в маршрут не идёт."""
    dummy = int(DUMMY_PORT)
    out: Intervals = []
    for lo, hi in intervals:
        if lo <= dummy <= hi:
            if lo < dummy:
                out.append((lo, dummy - 1))
            if dummy < hi:
                out.append((dummy + 1, hi))
        else:
            out.append((lo, hi))
    return out


def ports_to_strings(intervals: Intervals) -> list[str]:
    """Интервалы → порты как у winws; [] — любые порты."""
    if intervals == _ANY:
        return []
    return [str(lo) if lo == hi else f"{lo}-{hi}" for lo, hi in intervals]


def _covers(ports: list[str], port: int) -> bool:
    if not ports:
        return True
    for item in ports:
        lo, _, hi = item.partition("-")
        if int(lo) <= port <= int(hi or lo):
            return True
    return False


# ------------------------------------------------------------ разбор профилей winws

_L7_UDP = frozenset({"quic", "discord", "stun", "wireguard", "dht"})
_L7_TCP = frozenset({"http", "tls"})
_VOICE_L7 = frozenset({"discord", "stun"})
# --filter-l7 winws → протокол, который распознаёт sniff sing-box. discord — правило по процессу Discord;
# wireguard, dht и unknown ядро не распознаёт: такой трафик в обход не уходит (идёт через сервер).
L7_SNIFF = {"quic": "quic", "stun": "stun", "tls": "tls", "http": "http"}


@dataclass
class _WinwsProfile:
    index: int
    tcp: str | None = None
    udp: str | None = None
    l7: list[str] = field(default_factory=list)
    hostlists: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    hostlist_exclude: list[str] = field(default_factory=list)
    exclude_domains: list[str] = field(default_factory=list)
    ipsets: list[str] = field(default_factory=list)
    ipset_ips: list[str] = field(default_factory=list)
    ipset_exclude: list[str] = field(default_factory=list)
    exclude_ips: list[str] = field(default_factory=list)

    @property
    def has_lists(self) -> bool:
        return bool(self.hostlists or self.domains or self.ipsets or self.ipset_ips)


def _split_values(value: str) -> list[str]:
    return [v.strip() for v in value.split(",") if v.strip()]


def _parse_profiles(args: list[str]) -> tuple[list[_WinwsProfile], dict[str, Intervals | None], bool]:
    """Аргументы winws → профили (по --new), порты WinDivert и признак --wf-raw."""
    profiles = [_WinwsProfile(0)]
    wf: dict[str, Intervals | None] = {}
    raw = False
    for arg in args:
        if arg == "--new":
            profiles.append(_WinwsProfile(len(profiles)))
            continue
        name, sep, value = arg.partition("=")
        if not sep:
            continue
        p = profiles[-1]
        if name == "--wf-tcp":
            wf["tcp"] = parse_ports(value)
        elif name == "--wf-udp":
            wf["udp"] = parse_ports(value)
        elif name == "--wf-raw":
            raw = True
        elif name == "--filter-tcp":
            p.tcp = value
        elif name == "--filter-udp":
            p.udp = value
        elif name == "--filter-l7":
            p.l7 = [v.lower() for v in _split_values(value)]
        elif name in ("--hostlist", "--hostlist-auto"):
            p.hostlists.append(value)
        elif name == "--hostlist-domains":
            p.domains.extend(_split_values(value))
        elif name == "--hostlist-exclude":
            p.hostlist_exclude.append(value)
        elif name == "--hostlist-exclude-domains":
            p.exclude_domains.extend(_split_values(value))
        elif name == "--ipset":
            p.ipsets.append(value)
        elif name == "--ipset-ip":
            p.ipset_ips.extend(_split_values(value))
        elif name == "--ipset-exclude":
            p.ipset_exclude.append(value)
        elif name == "--ipset-exclude-ip":
            p.exclude_ips.extend(_split_values(value))
    return profiles, wf, raw


def _profile_networks(p: _WinwsProfile, wf: dict[str, Intervals | None], raw: bool
                      ) -> list[tuple[str, Intervals | None]]:
    """(сеть, порты) профиля; None вместо портов — фильтр не разобрать (отрицание «~»)."""
    def captured(proto: str) -> Intervals:
        if proto in wf:
            return wf[proto] or []
        return list(_ANY) if raw else []

    out: list[tuple[str, Intervals | None]] = []
    if p.tcp is not None or p.udp is not None:
        for proto, spec in (("tcp", p.tcp), ("udp", p.udp)):
            if spec is None:
                continue
            own = parse_ports(spec)
            out.append((proto, None if own is None else _without_dummy(_intersect(own, captured(proto)))))
        return out
    l7 = set(p.l7)
    if not (l7 and l7 <= _L7_UDP):
        out.append(("tcp", _without_dummy(captured("tcp"))))
    if not (l7 and l7 <= _L7_TCP):
        out.append(("udp", _without_dummy(captured("udp"))))
    return out


def _describe(network: str, ports: list[str]) -> str:
    return f"{network.upper()} {','.join(ports) if ports else 'любые порты'}"


# ------------------------------------------------------------ чтение списков

def _resolve(value: str, pack_dir: Path) -> Path:
    path = Path(value.strip().strip('"'))
    return path if path.is_absolute() else pack_dir / path


def _read_lines(path: Path) -> list[str] | None:
    try:
        text = path.read_bytes().decode("utf-8-sig", errors="replace")
    except OSError:
        return None
    return [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]


def _collect(files: list[str], inline: list[str], pack_dir: Path, notes: list[str]) -> list[str]:
    lines = list(inline)
    for value in files:
        path = _resolve(value, pack_dir)
        got = _read_lines(path)
        if got is None:
            notes.append(f"Список {path.name} не прочитан — в маршруте он не учтён")
            continue
        lines.extend(got)
    return lines


def _domain_sets(lines: list[str]) -> tuple[set[str], set[str]]:
    """Строки hostlist → (точные домены, домены с поддоменами). Заглушка пакета отбрасывается."""
    exact: set[str] = set()
    suffix: set[str] = set()
    for line in lines:
        is_exact = line.startswith("^")
        d = normalize_domain(line[1:] if is_exact else line)
        if d is None or d == PLACEHOLDER_DOMAIN:
            continue
        (exact if is_exact else suffix).add(d)
    return exact, suffix


def _under(domain: str, suffix: str) -> bool:
    return domain == suffix or domain.endswith("." + suffix)


def domain_rule(include: list[str], exclude: list[str]) -> dict[str, Any] | None:
    """Правило rule-set «домен из include и не из exclude» — как winws применяет hostlist и
    hostlist-exclude. None — после исключений не осталось ни одного домена."""
    exact, suffix = _domain_sets(include)
    x_exact, x_suffix = _domain_sets(exclude)
    suffix = {s for s in suffix if not any(_under(s, x) for x in x_suffix)}
    exact = {e for e in exact if e not in x_exact and not any(_under(e, x) for x in x_suffix)}
    if not exact and not suffix:
        return None
    rule = _domain_fields(exact, suffix)
    # исключения, которые вырезают часть оставшихся доменов (поддомен из «не трогать»)
    rel_suffix = {x for x in x_suffix if any(x != s and _under(x, s) for s in suffix)}
    rel_exact = {x for x in x_exact if any(_under(x, s) for s in suffix)}
    if not rel_suffix and not rel_exact:
        return rule
    return {"type": "logical", "mode": "and",
            "rules": [rule, {**_domain_fields(rel_exact, rel_suffix), "invert": True}]}


def _domain_fields(exact: set[str], suffix: set[str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if exact:
        out["domain"] = sorted(exact)
    if suffix:
        out["domain_suffix"] = sorted(suffix)
    return out


_IPV4 = re.compile(r"(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:/(\d{1,2}))?")


def _intervals_of(lines: list[str]) -> dict[int, Intervals]:
    """Строки IPSet → интервалы адресов по версиям IP. IPv4 разбирается напрямую (в списке zapret
    десятки тысяч подсетей, ipaddress на них медленный), остальное — через ipaddress."""
    out: dict[int, list[tuple[int, int]]] = {4: [], 6: []}
    for raw in lines:
        line = raw.strip()
        if not line or line == NONE_MARKER:
            continue
        m = _IPV4.fullmatch(line)
        if m:
            octets = [int(x) for x in m.groups()[:4]]
            prefix = int(m.group(5)) if m.group(5) is not None else 32
            if max(octets) <= 255 and prefix <= 32:
                value = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]
                size = 1 << (32 - prefix)
                lo = value & ~(size - 1) & 0xFFFFFFFF
                out[4].append((lo, lo + size - 1))
            continue
        try:
            net = ipaddress.ip_network(line, strict=False)
        except ValueError:
            continue
        out[net.version].append((int(net.network_address), int(net.broadcast_address)))
    return {v: _merge(items) for v, items in out.items()}


def _cidrs(lo: int, hi: int, bits: int) -> Iterator[tuple[int, int]]:
    """Интервал адресов → наименьший набор CIDR (начало, длина префикса)."""
    while lo <= hi:
        size = lo & -lo if lo else 1 << bits
        while size > hi - lo + 1:
            size >>= 1
        yield lo, bits - size.bit_length() + 1
        lo += size


def _format(version: int, value: int, prefix: int) -> str:
    if version == 4:
        return f"{value >> 24}.{(value >> 16) & 255}.{(value >> 8) & 255}.{value & 255}/{prefix}"
    return f"{ipaddress.IPv6Address(value)}/{prefix}"


def subtract_networks(include: list[str], exclude: list[str]) -> list[str]:
    """Подсети include минус подсети exclude, заново свёрнутые в CIDR (как --ipset минус --ipset-exclude)."""
    result: list[str] = []
    inc = _intervals_of(include)
    exc = _intervals_of(exclude)
    for version, bits in ((4, 32), (6, 128)):
        a, b = inc[version], exc[version]
        left: Intervals = []
        j = 0                     # оба списка отсортированы: исключения просматриваются один раз
        for lo, hi in a:
            cur = lo
            while j < len(b) and b[j][1] < cur:
                j += 1
            k = j
            while k < len(b) and b[k][0] <= hi and cur <= hi:
                xlo, xhi = b[k]
                if xlo > cur:
                    left.append((cur, xlo - 1))
                cur = max(cur, xhi + 1)
                k += 1
            if cur <= hi:
                left.append((cur, hi))
        for lo, hi in left:
            result.extend(_format(version, start, prefix) for start, prefix in _cidrs(lo, hi, bits))
    return result


# ------------------------------------------------------------ файлы rule-set

def write_rule_set(path: Path, rules: list[dict[str, Any]]) -> bool:
    """Атомарно пишет rule-set формата source. False — содержимое не изменилось (файл не трогали,
    sing-box не будет перечитывать его зря)."""
    data = json.dumps({"version": RULE_SET_VERSION, "rules": rules}, ensure_ascii=False,
                      separators=(",", ":")).encode("utf-8")
    try:
        if path.read_bytes() == data:
            return False
    except OSError:
        pass
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)
    return True


# ------------------------------------------------------------ «через обход»

@dataclass
class BypassResult:
    profiles: list[BypassProfile] = field(default_factory=list)
    voice_ports: list[str] = field(default_factory=list)     # UDP-порты голоса Discord
    notes: list[str] = field(default_factory=list)            # что не перенесено и почему — для «Маршрутов»


def bypass_from_strategy(args: list[str], *, pack_dir: Path, ipset_mode: str, out_dir: Path) -> BypassResult:
    """Аргументы winws активной стратегии (ZapretManager.build_args) → профили «через обход».

    ipset_mode — режим IPSet zapret: loaded — IP-набор профиля (минус --ipset-exclude) идёт в
    маршрут; none — заглушка, правила нет; any — пустой список означает «все адреса», такой
    профиль не переносится (через сервер не шло бы почти ничего). Профили без списков (winws
    трогает всё на своих портах) тоже не переносятся: это «всё», а не выборочный обход."""
    pack_dir = Path(pack_dir)
    out_dir = Path(out_dir)
    result = BypassResult()
    cache: dict[tuple, list[str]] = {}      # один IPSet у нескольких профилей — вычитаем один раз
    profiles, wf, raw = _parse_profiles(list(args))
    for p in profiles:
        nets = [(net, ports) for net, ports in _profile_networks(p, wf, raw) if ports != []]
        if not nets:
            continue
        if any(ports is None for _, ports in nets):
            result.notes.append(f"Профиль {p.index + 1}: отрицание в фильтре портов не поддерживается — не переносится")
            continue
        port_lists = [(net, ports_to_strings(ports)) for net, ports in nets]  # type: ignore[arg-type]
        if not p.has_lists:
            if set(p.l7) & _VOICE_L7:
                exclude_file = _exclude_file(p, pack_dir, out_dir, result.notes, cache)
                for net, ports in port_lists:
                    result.profiles.append(BypassProfile(network=net, ports=ports, l7=list(p.l7),
                                                         exclude_file=exclude_file))
                    if net == "udp":
                        result.voice_ports.extend(x for x in ports if x not in result.voice_ports)
            else:
                where = "; ".join(_describe(n, ports) for n, ports in port_lists)
                result.notes.append(f"Профиль {p.index + 1} ({where}): без списков — обход трогает все сайты "
                                    "на этих портах, такой профиль в маршрут не переносится")
            continue
        if p.l7 and not set(p.l7) & (set(L7_SNIFF) | {"discord"}):
            where = "; ".join(_describe(n, ports) for n, ports in port_lists)
            result.notes.append(f"Профиль {p.index + 1} ({where}): протокол {', '.join(p.l7)} ядро VPN не "
                                "распознаёт — такой трафик идёт через сервер")
            continue
        domains_file, ips_file = _profile_files(p, pack_dir, ipset_mode, out_dir, result.notes, port_lists, cache)
        if domains_file is None and ips_file is None:
            continue
        exclude_file = _exclude_file(p, pack_dir, out_dir, result.notes, cache)
        for net, ports in port_lists:
            result.profiles.append(BypassProfile(
                network=net, ports=ports, domains_file=domains_file, ips_file=ips_file, exclude_file=exclude_file,
                l7=list(p.l7), reject_quic=bool(domains_file) and net == "tcp" and _covers(ports, 443)))
    result.notes = list(dict.fromkeys(result.notes))
    return result


def _exclude_file(p: _WinwsProfile, pack_dir: Path, out_dir: Path, notes: list[str],
                  cache: dict[tuple, list[str]]) -> Path | None:
    """--ipset-exclude профиля без IPSet: адреса, которых winws не трогает, даже если домен из hostlist, —
    отдельным IP-набором (у профиля с IPSet они уже вычтены из его набора). В доменный набор их не
    положить: его читают и DNS-правила, а IP-условия там устарели (план 5.5)."""
    if p.ipsets or p.ipset_ips or not (p.ipset_exclude or p.exclude_ips):
        return None
    lines = _collect(p.ipset_exclude, p.exclude_ips, pack_dir, notes)
    key = ("exclude", tuple(lines))
    if key not in cache:
        cache[key] = subtract_networks(lines, [])
    if not cache[key]:
        return None
    path = out_dir / f"{BYPASS_PREFIX}{p.index}-exclude-ip.json"
    write_rule_set(path, [{"ip_cidr": cache[key]}])
    return path


def _profile_files(p: _WinwsProfile, pack_dir: Path, ipset_mode: str, out_dir: Path, notes: list[str],
                   port_lists: list[tuple[str, list[str]]], cache: dict[tuple, list[str]]
                   ) -> tuple[Path | None, Path | None]:
    """Пишет rule-set файлы профиля: (домены, IP). Профиль с ipset — IP-файл (с доменами внутри,
    если есть и hostlist: winws требует оба условия), иначе — файл доменов."""
    where = "; ".join(_describe(n, ports) for n, ports in port_lists)
    exclude = _collect(p.hostlist_exclude, p.exclude_domains, pack_dir, notes)
    if not (p.ipsets or p.ipset_ips):
        rule = domain_rule(_collect(p.hostlists, p.domains, pack_dir, notes), exclude)
        if rule is None:
            return None, None
        path = out_dir / f"{BYPASS_PREFIX}{p.index}.json"
        write_rule_set(path, [rule])
        return path, None
    if ipset_mode == "none":
        return None, None
    if ipset_mode == "any":
        notes.append(f"IPSet «все адреса»: профиль {p.index + 1} ({where}) не переносится — "
                     "иначе мимо VPN шло бы почти всё")
        return None, None
    raw_ips = _collect(p.ipsets, p.ipset_ips, pack_dir, notes)
    if not raw_ips:
        notes.append(f"Профиль {p.index + 1} ({where}): IPSet пуст — для winws это «все адреса», не переносится")
        return None, None
    excluded = _collect(p.ipset_exclude, p.exclude_ips, pack_dir, notes)
    key = (tuple(raw_ips), tuple(excluded))
    if key not in cache:
        cache[key] = subtract_networks(raw_ips, excluded)
    nets = cache[key]
    if not nets:
        return None, None
    parts: list[dict[str, Any]] = [{"ip_cidr": nets}]
    if p.hostlists or p.domains:
        include = domain_rule(_collect(p.hostlists, p.domains, pack_dir, notes), [])
        if include is None:
            return None, None
        parts.append(include)
    x_exact, x_suffix = _domain_sets(exclude)
    if x_exact or x_suffix:
        parts.append({**_domain_fields(x_exact, x_suffix), "invert": True})
    rule = parts[0] if len(parts) == 1 else {"type": "logical", "mode": "and", "rules": parts}
    path = out_dir / f"{BYPASS_PREFIX}{p.index}-ip.json"
    write_rule_set(path, [rule])
    return None, path
