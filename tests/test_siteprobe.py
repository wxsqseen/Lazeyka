"""Рентген сайта, белые списки мобильного интернета: разбор шагов curl, вывод из фактов, связка с Core.
Сеть не трогается — curl, DNS и пробы подменены."""
from types import SimpleNamespace

import pytest

from app import helpdesk, siteprobe
from app.siteprobe import Attempt, Facts
from app.vpnclient import routing

# Хвосты curl 8.16 (Schannel) -v, снятые вживую с привязкой к физическому адаптеру.
TRYING = "*   Trying 57.144.222.34:443...\n* Local port: 0\n"
TLS_STARTED = TRYING + "* schannel: disabled automatic use of client certificate\n* ALPN: curl offers http/1.1\n"


@pytest.mark.parametrize("code, out, err, expected", [
    (0, "200 0.200539", TLS_STARTED + "* ALPN: server accepted http/1.1\n* Established connection to x\n",
     Attempt("ok", 200)),
    (0, "451 0.320263", TLS_STARTED, Attempt("ok", 451)),
    (28, "000 0.000000", TRYING + "* Connection timed out after 3009 milliseconds\n", Attempt("tcp")),
    # Имя сайта под фильтром: TCP есть, ClientHello ушёл, ответа нет (время соединения curl при этом — ноль).
    (28, "000 0.000000", TLS_STARTED + "* Connection timed out after 5002 milliseconds\n", Attempt("tls")),
    (35, "000 0.000000", TLS_STARTED + "* schannel: next InitializeSecurityContext failed: SEC_E_INVALID_TOKEN\n",
     Attempt("tls")),
    (60, "000 0.000000", TLS_STARTED + "* schannel: SEC_E_WRONG_PRINCIPAL\n", Attempt("cert")),
    (28, "000 0.150000", TLS_STARTED + "* Established connection to x\n", Attempt("stall")),
    (-1, "", "timeout", Attempt("tcp")),
])
def test_curl_trace_names_the_failed_step(code, out, err, expected):
    assert siteprobe.parse_attempt(code, out, err) == expected


@pytest.mark.parametrize("code, out, expected", [
    # Вживую мимо туннеля, первые 64 КБ: gcore.com, askit-app.de, esm.sh замерли и висели до тайм-аута.
    (28, "16378", True), (28, "15665", True), (28, "25619", True),
    (0, "65536", False), (0, "1334523", False),     # большие ответы проходят
    (0, "15863", None), (0, "577", None),           # страница меньше полосы — не сказать
    (28, "0", None), (28, "120000", False), (-1, "", None),
])
def test_freeze_from_first_64k(code, out, expected):
    assert siteprobe.parse_freeze(code, out) is expected


def _f(direct, **kw):
    return Facts("example.com", direct=direct, **kw)


OK = Attempt("ok", 200)


@pytest.mark.parametrize("facts, verdict, fixes", [
    (_f(Attempt("tls"), zapret="skips", own_vpn=True, vpn=OK), "dpi", ["add_site", "vpn_site"]),
    (_f(Attempt("tls"), zapret="off"), "dpi", ["add_site"]),
    (_f(Attempt("tls"), zapret="handles", own_vpn=True), "dpi", ["vpn_site"]),
    (_f(Attempt("tls"), zapret=None), "dpi", []),
    (_f(Attempt("tcp"), own_vpn=True, vpn=OK), "ip", ["vpn_site"]),
    (_f(Attempt("tcp"), own_vpn=True), "unreachable", []),
    (_f(Attempt("tcp"), own_vpn=True, vpn=Attempt("fail")), "down", []),
    (_f(OK, frozen=True, zapret="skips"), "freeze", ["add_site"]),
    (_f(Attempt("stall"), zapret="handles"), "freeze", []),
    (_f(Attempt("cert"), zapret="skips"), "cert", ["add_site"]),
    (_f(Attempt("ok", 451), own_vpn=True, vpn=OK), "geo", ["vpn_site"]),
    (_f(Attempt("ok", 403), own_vpn=True, vpn=OK), "geo", ["vpn_site"]),
    (_f(OK, own_vpn=True, vpn=Attempt("ok", 403)), "vpn_refused", ["direct_site"]),
    (_f(OK, own_vpn=True, vpn=Attempt("fail")), "vpn_refused", ["direct_site"]),
    (_f(Attempt("tcp"), whitelist=True, own_vpn=True, vpn=OK), "whitelist", ["vpn_site"]),
    (_f(Attempt("tcp"), whitelist=True), "whitelist", []),
    (_f(OK, dns="spoofed"), "dns", []),
    (_f(OK, frozen=False, vpn=OK), "works", []),
    (Facts("example.com", dns="missing"), "down", []),
    (_f(OK, ru_ca=True, vpn=Attempt("ok")), "ru_ca", []),           # Сбер, ВТБ: сертификат Минцифры — не подмена
])
def test_verdict_from_facts(facts, verdict, fixes):
    found = siteprobe.verdict(facts)
    assert (found["verdict"], found["fixes"]) == (verdict, fixes), found["advice"]
    assert found["advice"]


def test_xray_steps_stop_at_the_broken_layer():
    steps = siteprobe.verdict(_f(Attempt("tls"), vpn=OK, zapret="skips", dns="spoofed"))["steps"]
    assert [(s["id"], s["ok"]) for s in steps] == [("dns", False), ("tcp", True), ("tls", False), ("vpn", True)]
    assert steps[2]["detail"] == "оборвалось на имени сайта"
    steps = siteprobe.verdict(_f(OK, frozen=True))["steps"]
    assert [(s["id"], s["ok"]) for s in steps] == [("dns", True), ("tcp", True), ("tls", True), ("answer", True),
                                                   ("freeze", False)]
    advice = siteprobe.verdict(_f(Attempt("tls"), zapret="skips", dns="spoofed"))["advice"]
    assert "Мои сайты" in advice and "DNS через HTTPS" in advice, "подмена адреса — вдобавок к блокировке"


@pytest.mark.parametrize("white, open_, mode", [(2, 0, "whitelist"), (3, 0, "whitelist"), (3, 1, "open"),
                                                (0, 4, "open"), (1, 0, "offline"), (0, 0, "offline")])
def test_network_mode(white, open_, mode):
    assert siteprobe.classify_network(white, open_) == mode


def test_inspect_retries_second_address_and_asks_network_only_on_failure(monkeypatch):
    tried, asked = [], []
    monkeypatch.setattr(siteprobe, "resolve", lambda d: ("ok", ["192.0.2.1", "192.0.2.2"]))
    monkeypatch.setattr(siteprobe, "direct_attempt",
                        lambda d, ip, bind=None: tried.append((ip, bind)) or (Attempt("tcp") if ip.endswith(".1") else OK))
    monkeypatch.setattr(siteprobe, "freeze_check", lambda d, ip, bind=None: False)
    monkeypatch.setattr(siteprobe, "vpn_attempt", lambda d, opener: Attempt("ok", 204))
    facts = siteprobe.inspect("example.com", bind="10.0.0.5", vpn_opener=object(),
                              network_mode=lambda: asked.append(1) or "whitelist")
    assert tried == [("192.0.2.1", "10.0.0.5"), ("192.0.2.2", "10.0.0.5")], "закрыт один адрес — пробуем второй"
    assert facts.direct == OK and facts.frozen is False and facts.vpn == Attempt("ok", 204)
    assert asked == [] and facts.whitelist is False, "открылось напрямую — режим сети не спрашиваем"

    monkeypatch.setattr(siteprobe, "direct_attempt", lambda d, ip, bind=None: Attempt("tls"))
    facts = siteprobe.inspect("example.com", network_mode=lambda: asked.append(1) or "whitelist")
    assert asked == [1] and facts.whitelist and facts.vpn is None and facts.frozen is None


def test_russian_ca_is_not_a_provider_stub(monkeypatch):
    """Вживую 2026-11-10: Сбер, ВТБ, Т-Банк, РЖД отдают сертификат Russian Trusted Sub CA — Windows ему не
    доверяет, и без этой проверки выходило «вместо сайта отвечает провайдер»."""
    calls = []
    monkeypatch.setattr(siteprobe, "resolve", lambda d: ("ok", ["195.242.82.13"]))
    monkeypatch.setattr(siteprobe, "direct_attempt", lambda d, ip, bind=None, insecure=False: calls.append(insecure)
                        or (Attempt("ok", 200) if insecure else Attempt("cert")))
    monkeypatch.setattr(siteprobe, "freeze_check", lambda d, ip, bind=None: None)
    monkeypatch.setattr(siteprobe, "vpn_attempt", lambda d, opener: Attempt("cert"))
    monkeypatch.setattr(siteprobe, "russian_ca", lambda d, ip, bind=None: True)
    facts = siteprobe.inspect("www.vtb.ru", vpn_opener=object())
    assert calls == [False, True] and facts.ru_ca and facts.direct == OK and siteprobe.vpn_works(facts.vpn)
    assert siteprobe.verdict(facts)["verdict"] == "ru_ca"
    monkeypatch.setattr(siteprobe, "russian_ca", lambda d, ip, bind=None: False)     # чужой сертификат — подмена
    facts = siteprobe.inspect("www.vtb.ru")
    assert not facts.ru_ca and siteprobe.verdict(facts)["verdict"] == "cert"


def test_resolve_prefers_system_answer_and_sees_spoofing(monkeypatch):
    answers = {"system": ["93.184.216.34"], "doh": ["93.184.216.35"]}
    monkeypatch.setattr(helpdesk, "system_resolve", lambda d: answers["system"])
    monkeypatch.setattr(helpdesk, "doh_resolve", lambda d: answers["doh"])
    assert siteprobe.resolve("example.com") == ("ok", ["93.184.216.34"])
    answers["system"] = ["198.18.0.7"]                       # fake-ip VPN-программы
    assert siteprobe.resolve("example.com") == ("ok", ["93.184.216.35"])
    answers["system"] = ["127.0.0.1"]                        # заглушка провайдера
    assert siteprobe.resolve("example.com") == ("spoofed", ["93.184.216.35"])
    answers["system"], answers["doh"] = None, None
    assert siteprobe.resolve("nosuch.example") == ("missing", [])


def test_check_site_answer_keeps_old_keys(monkeypatch):
    monkeypatch.setattr(siteprobe, "inspect", lambda name, **kw: _f(Attempt("tls"), zapret="skips"))
    reply = helpdesk.check_site("https://www.Example.com/path")
    assert reply["ok"] and reply["domain"] == "example.com" and reply["verdict"] == "dpi"
    assert reply["can_add"] is True and reply["fixes"] == ["add_site"] and reply["steps"]
    assert helpdesk.check_site("не сайт")["ok"] is False


def test_handles_domain_reads_strategy_lists(tmp_path):
    (tmp_path / "lists").mkdir()
    (tmp_path / "lists" / "list-general.txt").write_text("discord.com\n^exact.example\n", encoding="utf-8")
    (tmp_path / "lists" / "list-exclude.txt").write_text("cdn.discord.com\n", encoding="utf-8")
    args = ["--wf-tcp=80,443", "--filter-tcp=443", "--hostlist=lists/list-general.txt",
            "--hostlist-exclude=lists/list-exclude.txt", "--dpi-desync=fake"]

    def handles(domain, a=args, mode="loaded"):
        return routing.handles_domain(a, pack_dir=tmp_path, ipset_mode=mode, domain=domain)

    assert handles("discord.com") and handles("media.discord.com") and handles("exact.example")
    assert not handles("sub.exact.example") and not handles("cdn.discord.com") and not handles("example.org")
    no_lists = ["--wf-tcp=443", "--filter-tcp=443", "--dpi-desync=fake"]       # как general (ALT5): все сайты
    assert handles("example.org", no_lists)
    ipset = ["--wf-tcp=443", "--filter-tcp=443", "--ipset=lists/ipset-all.txt", "--dpi-desync=fake"]
    assert not handles("example.org", ipset, "loaded") and handles("example.org", ipset, "any")
    udp_only = ["--wf-udp=443", "--filter-udp=443", "--hostlist=lists/list-general.txt"]
    assert not handles("discord.com", udp_only), "QUIC-профиль HTTPS по TCP не обрабатывает"


# ------------------------------------------------------------ связка с Core

def _site_core(tmp_path, monkeypatch, vc=None):
    from tests.test_vpnclient_core import make_core
    core = make_core(tmp_path, vc)
    core.is_admin = True
    core.zapret.pack = SimpleNamespace(path=tmp_path, version="1")
    core.zapret.status = "running"
    monkeypatch.setattr(type(core), "_direct_source", lambda self: "192.168.0.10")
    monkeypatch.setattr(type(core), "_zapret_view", lambda self: SimpleNamespace(
        strategy_args=["--wf-tcp=443", "--filter-tcp=443", "--hostlist-domains=discord.com"],
        pack_dir=tmp_path, ipset_mode="loaded"))
    return core


def test_core_check_site_passes_paths_and_bypass_state(tmp_path, monkeypatch):
    seen = {}
    opener = object()
    vc = SimpleNamespace(probe_opener=lambda: opener, has_servers=lambda: True)
    core = _site_core(tmp_path, monkeypatch, vc)
    monkeypatch.setattr(siteprobe, "network_mode", lambda bind: seen.setdefault("mode_bind", bind) and "whitelist")

    def inspect(name, **kw):
        seen.update(kw, name=name)
        kw["network_mode"]()
        return _f(Attempt("tls"), zapret=kw["zapret"])

    monkeypatch.setattr(siteprobe, "inspect", inspect)
    reply = core.check_site("www.discord.com")
    assert seen["name"] == "discord.com" and seen["bind"] == "192.168.0.10" and seen["vpn_opener"] is opener
    assert seen["zapret"] == "handles" and seen["own_vpn"] is True and seen["mode_bind"] == "192.168.0.10"
    assert reply["verdict"] == "dpi" and core.has_alert("whitelist"), "белый список рентген тоже отмечает плашкой"
    core.check_site("example.org")
    assert seen["zapret"] == "skips"
    core.zapret.status = "stopped"
    core.check_site("example.org")
    assert seen["zapret"] == "off"


def test_core_network_mode_alert_lifecycle(tmp_path, monkeypatch):
    core = _site_core(tmp_path, monkeypatch)
    mode = {"now": "whitelist"}
    monkeypatch.setattr(siteprobe, "network_mode", lambda bind: mode["now"])
    assert core._network_mode(None) == "whitelist"
    alert = next(n for n in core.notices() if n["id"] == "whitelist")
    assert alert["page"] == "zapret" and "белому списку" in alert["text"]
    mode["now"] = "offline"
    core._network_mode(None)
    assert core.has_alert("whitelist"), "нет связи — ещё не значит, что белый список кончился"
    mode["now"] = "open"
    core._network_mode(None)
    assert not core.has_alert("whitelist")


def test_route_site_button_moves_site_between_own_rules(tmp_path):
    from tests.fakes.vpn_world import basic_store, make_manager
    m, _world = make_manager(tmp_path, basic_store())
    m.settings.update(lambda d: d["vpnclient"].update(direct_sites=["chatgpt.com"], proxy_sites=["x.com"]))
    assert m.route_site("chatgpt.com", "proxy") == {}
    vc = m.settings.get("vpnclient")
    assert vc["proxy_sites"] == ["x.com", "chatgpt.com"] and vc["direct_sites"] == []
    m.route_site("chatgpt.com", "direct")
    vc = m.settings.get("vpnclient")
    assert vc["proxy_sites"] == ["x.com"] and vc["direct_sites"] == ["chatgpt.com"]


def test_own_vpn_losing_all_servers_checks_for_whitelist(tmp_path, monkeypatch):
    from tests.fakes.vpn_world import wait_for
    vc = SimpleNamespace(probe_opener=lambda: None, has_servers=lambda: True)
    core = _site_core(tmp_path, monkeypatch, vc)
    asked = []
    monkeypatch.setattr(siteprobe, "network_mode", lambda bind: asked.append(bind) or "whitelist")
    core.alert("vpn-server", "warn", "Ни один сервер не отвечает", page="vpnclient")
    assert wait_for(lambda: core.has_alert("whitelist"))
    assert asked == ["192.168.0.10"], "проверка — мимо туннеля, по прямому подключению"
    alert = next(n for n in core.notices() if n["id"] == "whitelist")
    assert alert["action"] == {"label": "Проверить серверы VPN", "call": "vpnclient_latency", "args": []}
    core.alert("vpn-server", "warn", "Ни один сервер не отвечает (повтор)")
    assert asked == ["192.168.0.10"], "та же поломка — не проверяем заново"


# ------------------------------------------------------------ паспорт провайдера

def test_passport_lays_sites_out_and_rechecks_bypass(tmp_path, monkeypatch):
    """Обход возьмёт — в «Мои сайты» одним сохранением и проверка ещё раз; не пробил — через свой VPN; режут по
    адресу — через VPN; не пускают через VPN — напрямую; открываются — без действий."""
    added, saves = [], []
    vc = SimpleNamespace(probe_opener=lambda: object(), has_servers=lambda: True,
                         smart_add=lambda host, via, why: added.append((host, via, why)) or True)
    core = _site_core(tmp_path, monkeypatch, vc)
    user_list = {"text": "# мои\nexample.org\n"}
    core.zapret.lists_get = lambda: [{"id": "list-general-user.txt", "text": user_list["text"]}]
    core.zapret.lists_save = lambda name, text: saves.append(text) or user_list.update(text=text)
    core._sync_bypass = lambda force=False: None
    monkeypatch.setattr("app.core.time.sleep", lambda s: None)
    monkeypatch.setattr(siteprobe, "PASSPORT_SITES", (
        ("www.instagram.com", "Instagram"), ("rutracker.org", "Rutracker"), ("www.linkedin.com", "LinkedIn"),
        ("www.gosuslugi.ru", "Госуслуги"), ("ya.ru", "Яндекс"), ("chatgpt.com", "ChatGPT")))
    rounds = {"rutracker.org": 0, "www.instagram.com": 0}

    def inspect(domain, **kw):
        if domain in rounds:
            rounds[domain] += 1
            if rounds[domain] == 1 or domain == "www.instagram.com":     # instagram обход не пробил и потом
                return _f(Attempt("tls"), zapret="skips" if rounds[domain] == 1 else "handles", own_vpn=True, vpn=OK)
            return _f(OK, frozen=False, vpn=OK)                       # rutracker после «Моих сайтов» открылся
        if domain == "www.linkedin.com":
            return _f(Attempt("tcp"), own_vpn=True, vpn=OK)
        if domain == "www.gosuslugi.ru":
            return _f(OK, own_vpn=True, vpn=Attempt("fail"))
        if domain == "chatgpt.com":
            return _f(Attempt("ok", 451), own_vpn=True, vpn=OK)
        return _f(OK, frozen=False, vpn=OK)

    monkeypatch.setattr(siteprobe, "inspect", inspect)
    monkeypatch.setattr(siteprobe, "network_mode", lambda bind: "open")
    assert core.passport_check()["ok"]
    state = core.state()["passport"]
    assert not state["running"] and state["total"] == 6 and state["done"] == 6
    got = {i["domain"]: (i["verdict"], i["ok"], i["action"]) for i in state["items"]}
    assert got["rutracker.org"] == ("dpi", True, "добавлен в «Мои сайты» — открывается через обход")
    assert got["www.instagram.com"] == ("dpi", True, "обход не пробил — теперь через свой VPN")
    assert got["www.linkedin.com"] == ("ip", True, "теперь через свой VPN")
    assert got["www.gosuslugi.ru"] == ("vpn_refused", True, "теперь напрямую, мимо VPN")
    assert got["chatgpt.com"] == ("geo", True, "теперь через свой VPN")
    assert got["ya.ru"] == ("works", True, None)
    assert saves == ["# мои\nexample.org\nwww.instagram.com\nrutracker.org\n"], "один перезапуск обхода на всех"
    assert sorted(added) == [("chatgpt.com", "proxy", "geo"), ("www.gosuslugi.ru", "direct", "vpn"),
                             ("www.instagram.com", "proxy", "dpi"), ("www.linkedin.com", "proxy", "ip")]
    assert state["summary"] == "Провайдер режет 3 из 6, сами не пускают из России — 1, Лазейка настроила 5."
    assert all("fixes" not in i and "reason" not in i for i in state["items"]), "внутреннее — не странице"


def test_passport_without_own_vpn_and_with_bypass_off(tmp_path, monkeypatch):
    core = _site_core(tmp_path, monkeypatch, None)
    core.zapret.status = "stopped"
    saves = []
    core.zapret.lists_get = lambda: [{"id": "list-general-user.txt", "text": ""}]
    core.zapret.lists_save = lambda name, text: saves.append(text)
    core._sync_bypass = lambda force=False: None
    monkeypatch.setattr(siteprobe, "PASSPORT_SITES", (("rutracker.org", "Rutracker"), ("www.linkedin.com", "LinkedIn")))
    monkeypatch.setattr(siteprobe, "inspect", lambda domain, **kw: _f(
        Attempt("tls") if domain == "rutracker.org" else Attempt("tcp"), zapret=kw["zapret"]))
    monkeypatch.setattr(siteprobe, "network_mode", lambda bind: "open")
    core.passport_check()
    got = {i["domain"]: (i["ok"], i["action"]) for i in core.state()["passport"]["items"]}
    assert got["rutracker.org"] == (None, "добавлен в «Мои сайты» — включите обход")
    assert got["www.linkedin.com"] == (None, "адрес закрыт или сайт лежит — открыть поможет только свой VPN")
    assert saves == ["rutracker.org\n"]
