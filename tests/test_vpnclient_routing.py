"""Свой VPN: «через обход» по профилям winws всех стратегий встроенного пакета, пресеты, списки сайтов."""
import ipaddress
import json
import os
import shutil
from pathlib import Path

import pytest

from app.vpnclient import routing
from app.vpnclient.routing import bypass_from_strategy, domain_rule, site_match, subtract_networks
from app.zapret import lists, strategies

VOICE = ["19294-19344", "50000-50100"]


@pytest.fixture(scope="module")
def pack(pack_dir, tmp_path_factory) -> Path:
    """Копия встроенного пакета с пользовательскими списками, как после lists.sync_user_lists."""
    target = tmp_path_factory.mktemp("bypass-pack") / pack_dir.name
    shutil.copytree(pack_dir, target)
    user = target.parent / "user-lists"
    lists.ensure_user_lists(user)
    lists.save_user_list(user, "list-general-user.txt", "my-blocked.example\r\n")
    lists.save_user_list(user, "list-exclude-user.txt", "mail.discord.com\r\n")
    lists.save_user_list(user, "ipset-exclude-user.txt", "1.1.1.0/24\r\n")
    lists.sync_user_lists(user, target / "lists")
    return target


@pytest.fixture(scope="module")
def loaded_pack(pack, tmp_path_factory) -> Path:
    """Тот же пакет в режиме IPSet «по списку» (полный список из ipset-all.txt.backup)."""
    target = tmp_path_factory.mktemp("bypass-loaded") / pack.name
    shutil.copytree(pack, target)
    lists.set_ipset_mode(target / "lists", "loaded")
    return target


def all_strategies(pack_path: Path) -> list[strategies.Strategy]:
    found, errors = strategies.discover(pack_path)
    assert found and not errors
    return found


def load(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["version"] == routing.RULE_SET_VERSION and isinstance(data["rules"], list) and data["rules"]
    return data


def domains_of(path: Path) -> tuple[set[str], set[str]]:
    """(точные, с поддоменами) из включающей части правила."""
    rule = load(path)["rules"][0]
    include = rule["rules"][0] if rule.get("type") == "logical" else rule
    return set(include.get("domain", [])), set(include.get("domain_suffix", []))


# ------------------------------------------------------------ все стратегии пакета

@pytest.mark.parametrize("mode", ["none", "loaded", "any"])
def test_every_strategy_of_the_pack(pack, loaded_pack, mode, tmp_path):
    pack_path = loaded_pack if mode == "loaded" else pack
    found = all_strategies(pack_path)
    assert len(found) >= 20
    for st in found:
        out = tmp_path / st.id
        res = bypass_from_strategy(st.args(pack_path), pack_dir=pack_path, ipset_mode=mode, out_dir=out)
        assert res.profiles, st.id
        assert res.voice_ports == VOICE, st.id                           # голос Discord есть в каждой
        for prof in res.profiles:
            assert prof.network in ("tcp", "udp")
            assert strategies.DUMMY_PORT not in prof.ports              # заглушка игрового фильтра не идёт в маршрут
            for item in prof.ports:
                assert routing.parse_ports(item) is not None
            files = [p for p in (prof.domains_file, prof.ips_file) if p]
            assert files or set(prof.l7) & {"discord", "stun"}
            for path in files:
                text = path.read_text(encoding="utf-8")
                load(path)
                assert lists.PLACEHOLDER_DOMAIN not in text and lists.NONE_MARKER not in text
            if prof.domains_file and prof.network == "udp":
                exact, suffix = domains_of(prof.domains_file)
                assert "googlevideo.com" not in suffix | exact, st.id    # YouTube winws обрабатывает только по TCP
            if prof.ips_file:
                assert mode == "loaded"
        # домены только TCP-профиля (list-google.txt) — отказ QUIC, чтобы клиент ушёл на TCP
        google = [p for p in res.profiles if p.domains_file and "googlevideo.com" in domains_of(p.domains_file)[1]]
        if any("list-google.txt" in a for a in st.args(pack_path)):
            assert google, st.id
        assert all(p.network == "tcp" and p.reject_quic for p in google), st.id
        udp_domains = [p for p in res.profiles if p.domains_file and p.network == "udp"]
        assert udp_domains and not any(p.reject_quic for p in udp_domains)
        if mode == "any" and any("--ipset=" in a for a in st.args(pack_path)):
            assert any("все адреса" in n for n in res.notes), st.id
        if mode == "none":
            assert not any("IPSet" in n for n in res.notes)


def test_general_profiles(pack, tmp_path):
    st = next(s for s in all_strategies(pack) if s.id == "general")
    res = bypass_from_strategy(st.args(pack), pack_dir=pack, ipset_mode="none", out_dir=tmp_path)
    shape = [(p.network, p.ports, bool(p.domains_file), p.reject_quic, p.l7) for p in res.profiles]
    assert shape == [
        ("udp", ["443"], True, False, []),
        ("udp", VOICE, False, False, ["discord", "stun"]),
        ("tcp", ["2053", "2083", "2087", "2096", "8443"], True, False, []),
        ("tcp", ["443"], True, True, []),
        ("tcp", ["80", "443"], True, True, []),
    ]
    general = res.profiles[0].domains_file
    exact, suffix = domains_of(general)
    assert "dns.google" in exact and "dns.google" not in suffix         # «^домен» — точно этот домен
    assert {"discord.com", "discord.gg", "my-blocked.example"} <= suffix  # свой список человека тоже
    rule = load(general)["rules"][0]                                    # mail.discord.com — в исключениях
    assert rule["type"] == "logical" and rule["rules"][1] == {"domain_suffix": ["mail.discord.com"], "invert": True}
    media = res.profiles[2].domains_file
    assert domains_of(media) == (set(), {"discord.media"})               # --hostlist-domains
    assert general.name == "bypass-0.json" and media.name == "bypass-2.json"


def test_alt5_profile_without_lists_is_not_transferred(pack, tmp_path):
    st = next(s for s in all_strategies(pack) if s.id == "general (ALT5)")
    res = bypass_from_strategy(st.args(pack), pack_dir=pack, ipset_mode="none", out_dir=tmp_path)
    assert not any(p.network == "tcp" for p in res.profiles)
    assert any("без списков" in n and "TCP 80,443" in n for n in res.notes)


def test_exp_quic_profile_and_inline_excludes(loaded_pack, tmp_path):
    st = next(s for s in all_strategies(loaded_pack) if s.id == "general (EXP)")
    res = bypass_from_strategy(st.args(loaded_pack), pack_dir=loaded_pack, ipset_mode="loaded", out_dir=tmp_path)
    quic = res.profiles[0]
    assert (quic.network, quic.ports, quic.l7) == ("udp", ["443", *VOICE], ["quic"])   # порты — из --wf-udp
    tcp_ip = next(p for p in res.profiles if p.ips_file and p.network == "tcp")
    rule = load(tcp_ip.ips_file)["rules"][0]
    excluded = rule["rules"][-1]
    assert excluded["invert"] is True and "fonts.googleapis.com" in excluded["domain_suffix"]


def test_loaded_ipset_minus_excludes(loaded_pack, tmp_path):
    st = next(s for s in all_strategies(loaded_pack) if s.id == "general")
    res = bypass_from_strategy(st.args(loaded_pack), pack_dir=loaded_pack, ipset_mode="loaded", out_dir=tmp_path)
    ip_profiles = [p for p in res.profiles if p.ips_file]
    assert [(p.network, p.ports) for p in ip_profiles] == [("udp", ["443"]), ("tcp", ["80", "443", "8443"])]
    rule = load(ip_profiles[0].ips_file)["rules"][0]
    nets = [ipaddress.ip_network(c) for c in rule["rules"][0]["ip_cidr"]]
    assert len(nets) > 1000
    for excluded in ("10.0.0.0/8", "192.168.0.0/16", "127.0.0.0/8", "1.1.1.0/24"):   # ipset-exclude + свой
        ex = ipaddress.ip_network(excluded)
        assert not any(n.version == ex.version and n.overlaps(ex) for n in nets), excluded
    assert any(ipaddress.ip_address("1.0.0.1") in n for n in nets if n.version == 4)
    assert rule["rules"][1]["invert"] is True and "steamcommunity.com" in rule["rules"][1]["domain_suffix"]


def test_game_filter_ports(loaded_pack, tmp_path):
    st = next(s for s in all_strategies(loaded_pack) if s.id == "general")
    args = st.args(loaded_pack, game_tcp="1024-65535", game_udp="1024-65535")
    res = bypass_from_strategy(args, pack_dir=loaded_pack, ipset_mode="loaded", out_dir=tmp_path)
    assert ("tcp", ["1024-65535"]) in [(p.network, p.ports) for p in res.profiles if p.ips_file]
    assert ("udp", ["1024-65535"]) in [(p.network, p.ports) for p in res.profiles if p.ips_file]


def test_unparsable_filters_and_missing_files(tmp_path):
    lst = tmp_path / "l.txt"
    lst.write_text("example.com\n", encoding="utf-8")
    args = ["--wf-tcp=80,443", "--wf-udp=443", "--filter-tcp=~80", f"--hostlist={lst}", "--new",
            "--filter-tcp=443", "--hostlist=lists/none.txt", "--new", "--filter-udp=443", "--hostlist=rel.txt"]
    (tmp_path / "rel.txt").write_text("rel.example\n", encoding="utf-8")
    res = bypass_from_strategy(args, pack_dir=tmp_path, ipset_mode="none", out_dir=tmp_path / "out")
    assert any("отрицание" in n for n in res.notes)
    assert any("none.txt" in n for n in res.notes)
    assert [(p.network, p.ports) for p in res.profiles] == [("udp", ["443"])]      # относительный путь — от пакета
    assert domains_of(res.profiles[0].domains_file) == (set(), {"rel.example"})


# ------------------------------------------------------------ файлы rule-set

def test_rule_set_files_are_rewritten_atomically(tmp_path, monkeypatch):
    path = tmp_path / "bypass-0.json"
    calls = []
    real = os.replace
    monkeypatch.setattr(routing.os, "replace", lambda a, b: (calls.append((Path(a).name, Path(b).name)), real(a, b)))
    assert routing.write_rule_set(path, [{"domain_suffix": ["a.org"]}]) is True
    assert calls == [("bypass-0.json.tmp", "bypass-0.json")]
    assert routing.write_rule_set(path, [{"domain_suffix": ["a.org"]}]) is False   # то же — файл не трогаем
    assert len(calls) == 1
    assert routing.write_rule_set(path, [{"domain_suffix": ["b.org"]}]) is True
    assert json.loads(path.read_text(encoding="utf-8"))["rules"] == [{"domain_suffix": ["b.org"]}]
    assert [p.name for p in tmp_path.iterdir()] == ["bypass-0.json"]


def test_lists_change_rewrites_same_file(pack, tmp_path):
    st = next(s for s in all_strategies(pack) if s.id == "general")
    first = bypass_from_strategy(st.args(pack), pack_dir=pack, ipset_mode="none", out_dir=tmp_path)
    user = pack / "lists" / "list-general-user.txt"
    old = user.read_bytes()
    try:
        user.write_text("another.example\r\n", encoding="utf-8")
        second = bypass_from_strategy(st.args(pack), pack_dir=pack, ipset_mode="none", out_dir=tmp_path)
    finally:
        user.write_bytes(old)
    assert [p.domains_file for p in first.profiles] == [p.domains_file for p in second.profiles]
    assert "another.example" in domains_of(second.profiles[0].domains_file)[1]


# ------------------------------------------------------------ части

def test_domain_rule_include_minus_exclude():
    assert domain_rule(["google.com", "^exact.example", "domain.example.abc", "Пример.рф"],
                       ["mail.google.com", "exact.example"]) == {
        "type": "logical", "mode": "and",
        "rules": [{"domain_suffix": ["google.com", "xn--e1afmkfd.xn--p1ai"]},
                  {"domain_suffix": ["mail.google.com"], "invert": True}]}
    assert domain_rule(["a.org", "b.org"], ["a.org", "unrelated.net"]) == {"domain_suffix": ["b.org"]}
    assert domain_rule(["^a.org"], ["^a.org"]) is None
    assert domain_rule(["domain.example.abc"], []) is None


def test_subtract_networks():
    assert subtract_networks(["10.0.0.0/8"], ["10.1.0.0/16"]) == [
        "10.0.0.0/16", "10.2.0.0/15", "10.4.0.0/14", "10.8.0.0/13", "10.16.0.0/12", "10.32.0.0/11",
        "10.64.0.0/10", "10.128.0.0/9"]
    assert subtract_networks(["1.1.1.0/24", "203.0.113.113/32", "bad"], []) == ["1.1.1.0/24"]
    assert subtract_networks(["2001:db8::/32"], ["2001:db8::/33"]) == ["2001:db8:8000::/33"]
    assert subtract_networks(["1.0.0.0/24", "1.0.1.0/24"], ["1.0.0.128/25"]) == ["1.0.0.0/25", "1.0.1.0/24"]


def test_parse_ports():
    assert routing.parse_ports("80,443,50000-50100") == [(80, 80), (443, 443), (50000, 50100)]
    assert routing.parse_ports("*") == [(1, 65535)]
    assert routing.parse_ports("~80") is None and routing.parse_ports("70000") is None


@pytest.mark.parametrize("entry,expected", [
    ("example.com", ("domain_suffix", "example.com")),
    ("^dns.google", ("domain", "dns.google")),
    ("full:x.example.org", ("domain", "x.example.org")),
    ("domain:Habr.com", ("domain_suffix", "habr.com")),
    ("keyword:yandex", ("domain_keyword", "yandex")),
    ("yandex", ("domain_keyword", "yandex")),
    ("regexp:^.*\\.su$", ("domain_regex", "^.*\\.su$")),
    ("geosite:category-ru", ("rule_set", "geosite-category-ru")),
    ("geoip:RU", ("rule_set", "geoip-ru")),
    ("geoip:private", ("ip_is_private", True)),
    ("10.0.0.0/8", ("ip_cidr", "10.0.0.0/8")),
    ("1.2.3.4", ("ip_cidr", "1.2.3.4/32")),
    ("*.пример.рф", ("domain_suffix", "xn--e1afmkfd.xn--p1ai")),
])
def test_site_match(entry, expected):
    m = site_match(entry)
    assert (m.field, m.value) == expected and m.negate is False


def test_site_match_negation_and_garbage():
    assert site_match("geoip:!ru") == routing.SiteMatch("rule_set", "geoip-ru", True)
    for bad in ("", "# comment", "ext:geo.dat:ru", "bad domain", "geosite:", "full:"):
        assert site_match(bad) is None
    group = routing.site_group(["a.org", "a.org", "geoip:!cn", "bad domain", "10.0.0.0/8"])
    assert group.fields == {"domain_suffix": ["a.org"], "ip_cidr": ["10.0.0.0/8"]}
    assert group.negated_sets == ["geoip-cn"] and group.bad == ["bad domain"]


def test_presets_and_kinds():
    assert routing.preset_rule_sets("all", games=False) == []
    assert routing.preset_rule_sets("except_ru", games=True) == ["geosite-category-ru", "geoip-ru",
                                                                 routing.GAMES_DOWNLOAD]
    assert routing.preset_rule_sets("blocked", games=False) == ["refilter-domains", "russia-inside", "geoip-ru-blocked"]
    with pytest.raises(ValueError):
        routing.preset_rule_sets("unknown", games=False)
    assert [routing.rule_set_kind(i) for i in ("geoip-ru", "geoip-ru-blocked", "bypass-5-ip", "bypass-0",
                                               "geosite-category-ru", "refilter-domains")] == \
        ["ip", "ip", "ip", "domain", "domain", "domain"]


def test_constants():
    assert {"habr.com", "kinescope.io", "sber.world", "1cfresh.com", "edadeal.io", "lmru.tech", "vtb24.com",
            "alfabank.com"} <= set(routing.ADDITIONS)
    assert routing.DISCORD_APPS == ("Discord.exe", "DiscordPTB.exe", "DiscordCanary.exe", "Vesktop.exe")
    assert "qbittorrent.exe" in routing.TORRENT_APPS
    for domain in routing.ADDITIONS + routing.IP_CHECK_SITES:
        assert routing.normalize_domain(domain) == domain


# ------------------------------------------------------------ исключения IPSet, протоколы L7, наборы «через VPN»

def test_ipset_exclude_of_profile_without_ipset_is_a_separate_ip_set(pack, loaded_pack, tmp_path):
    """--ipset-exclude у профиля только с hostlist: адресов из него winws не трогает даже для доменов из
    списка — отдельный IP-набор (в доменный не положить: его читают и DNS-правила)."""
    st = next(s for s in all_strategies(pack) if s.id == "general")
    res = bypass_from_strategy(st.args(pack), pack_dir=pack, ipset_mode="none", out_dir=tmp_path)
    udp, tcp = res.profiles[0], res.profiles[4]
    assert (udp.exclude_file.name, tcp.exclude_file.name) == ("bypass-0-exclude-ip.json", "bypass-4-exclude-ip.json")
    nets = load(udp.exclude_file)["rules"][0]["ip_cidr"]
    assert "1.1.1.0/24" in nets and "10.0.0.0/8" in nets               # свой ipset-exclude-user и пакетный
    assert routing.rule_set_kind(udp.exclude_file.stem) == "ip"
    assert res.profiles[2].exclude_file is None                         # discord.media — без --ipset-exclude
    loaded = bypass_from_strategy(st.args(loaded_pack), pack_dir=loaded_pack, ipset_mode="loaded",
                                  out_dir=tmp_path / "loaded")
    assert all(p.exclude_file is None for p in loaded.profiles if p.ips_file)   # у IPSet уже вычтены


def test_filter_l7_is_kept_and_unknown_protocols_stay_on_the_server(tmp_path):
    quic = ["--wf-udp=443", "--filter-udp=443", "--filter-l7=quic", "--ipset-ip=203.0.113.0/24"]
    [prof] = bypass_from_strategy(quic, pack_dir=tmp_path, ipset_mode="loaded", out_dir=tmp_path).profiles
    assert (prof.l7, prof.ips_file.name) == (["quic"], "bypass-0-ip.json")
    assert routing.L7_SNIFF["quic"] == "quic"
    other = ["--wf-udp=443", "--filter-udp=443", "--filter-l7=wireguard", "--hostlist-domains=a.example"]
    res = bypass_from_strategy(other, pack_dir=tmp_path, ipset_mode="none", out_dir=tmp_path)
    assert res.profiles == [] and any("wireguard" in n and "через сервер" in n for n in res.notes)


def test_rule_sets_that_vpn_routes_depend_on():
    assert routing.private_match(True) == {"ip_is_private": True}
    assert routing.private_match(False) == {"ip_is_private": True, "invert": True}
    assert routing.site_rule_sets(["geosite:youtube", "geoip:!ru", "a.org", "geosite:youtube", "geoip:private"]) == \
        ["geosite-youtube", "geoip-ru"]
    profile = [{"rule_set": ["geosite-netflix"], "action": "route", "outbound": "proxy"},
               {"rule_set": ["geosite-category-ru"], "action": "route", "outbound": "direct"},
               {"type": "logical", "mode": "and", "rules": [{"rule_set": ["geoip-us"]}, {"port": [443]}],
                "action": "route", "outbound": "proxy"}]
    required = routing.vpn_required(["geosite:youtube"], profile, "blocked")
    assert required == [("user", ("geosite-youtube",)), ("profile", ("geosite-netflix",)), ("profile", ("geoip-us",)),
                        ("preset", routing.PRESET_RULE_SETS["blocked"])]
    have = {"geosite-youtube", "geosite-netflix", "geoip-us"}
    assert routing.missing_vpn_sets(required, have | {"geoip-ru-blocked"}) == []   # пресету хватает одного списка
    assert routing.strict_level(required, have | {"geoip-ru-blocked"}) is None
    assert routing.missing_vpn_sets(required, have) == list(routing.PRESET_RULE_SETS["blocked"])
    assert routing.strict_level(required, have) == "preset"
    assert routing.missing_vpn_sets(required, {"geoip-us", "russia-inside"}) == ["geosite-youtube", "geosite-netflix"]
    assert routing.strict_level(required, {"geoip-us", "russia-inside"}) == "user"   # самое раннее место
    assert routing.strict_level(required, {"geosite-youtube", "russia-inside"}) == "profile"
    # выход по умолчанию профиля заменяет пресет — его списки не обязательны
    everything = {"network": ["tcp", "udp"], "action": "route", "outbound": "proxy"}
    assert routing.vpn_required([], [everything], "blocked") == []
    assert routing.catch_all(everything)
    assert routing.catch_all({"port_range": ["0:65535"], "action": "route", "outbound": "direct"})
    for narrow in ({"network": ["tcp"], "action": "route", "outbound": "proxy"},
                   {"network": ["tcp", "udp"], "rule_set": ["x"], "action": "route", "outbound": "proxy"},
                   {"network": ["tcp", "udp"], "action": "reject"},
                   {"network": ["tcp", "udp"], "invert": True, "action": "route", "outbound": "proxy"}):
        assert not routing.catch_all(narrow), narrow
