"""Умный маршрут своего VPN (vpnclient/learn.py): какие соединения подозрительны, вывод по пробам, наборы «через
сервер» и «напрямую», перепроверка раз в сутки, место правил в конфиге. Ядро не запускается, сеть не трогается."""
import json

import pytest

from app.siteprobe import Attempt, Facts
from app.vpnclient import config, learn
from tests.fakes.vpn_world import basic_store, make_manager, wait_for


def conn(cid, host, *, down=0, up=517, chains=("direct",), port="443", network="tcp"):
    return {"id": cid, "metadata": {"network": network, "host": host, "destinationPort": port},
            "upload": up, "download": down, "chains": list(chains)}


def test_suspects_are_hanging_https_connections():
    seen = {}
    conns = [conn("1", "www.instagram.com"),                                  # ClientHello ушёл, ответа нет
             conn("2", "medium.com", down=16_384),                            # замер на ~16 КБ
             conn("3", "ya.ru", down=48_000),                                 # открылся
             conn("4", "www.gosuslugi.ru", chains=("out-s1", "proxy")),       # через сервер — тоже висит
             conn("4b", "x.com", down=16_384, chains=("out-s1", "proxy")),    # через сервер замер — не наше
             conn("5", "93.184.216.34"),                                      # без имени сайта
             conn("6", "discord.com", port="80"),
             conn("7", "quic.example", network="udp"),
             conn("8", "idle.example", up=0)]
    assert learn.suspects(conns, seen, 100.0) == [], "только что появились — ещё не висят"
    assert learn.suspects(conns, seen, 104.0) == []
    assert learn.suspects(conns, seen, 109.0) == ["www.instagram.com", "medium.com", "www.gosuslugi.ru"]
    conns[1] = conn("2", "medium.com", down=20_000)                           # ответ идёт — не замер
    assert learn.suspects(conns, seen, 114.0) == ["www.instagram.com", "www.gosuslugi.ru"]
    assert learn.suspects([conn("1", "www.instagram.com", chains=("direct", "bypass"))], seen, 119.0) == \
        ["www.instagram.com"], "через селектор «через обход», который сейчас напрямую"
    assert set(seen) == {"1"}, "закрытые соединения забываются"


@pytest.mark.parametrize("host, site", [("i.instagram.com", "instagram.com"), ("instagram.com", "instagram.com"),
                                        ("www.bbc.co.uk", "bbc.co.uk"), ("a.b.com.ru", "b.com.ru"),
                                        ("cdn.discordapp.com", "discordapp.com")])
def test_site_of(host, site):
    assert learn.site_of(host) == site


OK = Attempt("ok", 200)


@pytest.mark.parametrize("facts, mode, alive, expected", [
    (Facts("a.com", direct=Attempt("tls"), vpn=OK), "open", True, ("proxy", "dpi")),
    (Facts("a.com", direct=Attempt("tcp"), vpn=OK), "open", True, ("proxy", "ip")),
    (Facts("a.com", direct=OK, frozen=True, vpn=OK), None, True, ("proxy", "freeze")),
    (Facts("a.com", direct=Attempt("ok", 451), vpn=OK), None, True, ("proxy", "geo")),
    (Facts("a.com", direct=Attempt("tls"), vpn=OK), "whitelist", True, None),      # белый список — не учим
    (Facts("a.com", direct=Attempt("tcp"), vpn=OK), "offline", True, None),        # связь пропала — не учим
    (Facts("a.com", direct=Attempt("tls"), vpn=Attempt("fail")), "open", True, None),   # и через сервер нет
    (Facts("a.com", direct=Attempt("tls"), vpn=None), "open", True, None),
    (Facts("a.com", direct=OK, frozen=False, vpn=OK), None, True, (None, None)),
    (Facts("a.com", direct=OK, frozen=None), None, True, (None, None)),
    # Не пускает через VPN: напрямую открывается, через сервер — нет или 403, а сам VPN работает.
    (Facts("bank.ru", direct=OK, vpn=Attempt("fail")), None, True, ("direct", "vpn")),
    (Facts("bank.ru", direct=OK, vpn=Attempt("ok", 403)), None, True, ("direct", "vpn")),
    (Facts("bank.ru", direct=OK, vpn=Attempt("fail")), None, False, None),        # лёг сам сервер — не учим
    # Авито вживую: 403 и напрямую, и через туннель — защита от ботов, а не «не пускает через VPN».
    (Facts("www.avito.ru", direct=Attempt("ok", 403), vpn=Attempt("ok", 403)), None, True, None),
    (Facts("a.com", dns="missing"), None, True, None),
])
def test_judge(facts, mode, alive, expected):
    assert learn.judge(facts, mode, alive) == expected


class Store:
    def __init__(self):
        self.data = {}

    def load(self):
        return json.loads(json.dumps(self.data))

    def save(self, data):
        self.data = json.loads(json.dumps(data))


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def make_learner(tmp_path, answers, enabled=True):
    clock, changes, probed = Clock(), [], []
    flag = {"on": enabled}

    def probe(host):
        probed.append(host)
        return answers.get(host)

    lr = learn.Learner(Store(), probe, lambda: flag["on"], lambda: changes.append(1), clock=clock)
    lr.write(tmp_path)
    return lr, clock, probed, flag


def rule_set(tmp_path, name=learn.FILE_NAME):
    return json.loads((tmp_path / name).read_text(encoding="utf-8"))["rules"][0]["domain_suffix"]


def hang(lr, clock, host, cid="c1", chains=("direct",)):
    """Соединение висит два опроса подряд."""
    lr.observe([conn(cid, host, chains=chains)])
    clock.now += 10
    lr.observe([conn(cid, host, chains=chains)])


def test_learns_blocked_site_and_writes_rule_set(tmp_path):
    lr, clock, probed, _ = make_learner(tmp_path, {"i.instagram.com": ("proxy", "dpi")})
    assert rule_set(tmp_path) == [learn.PLACEHOLDER], "пустой набор — заглушка"
    assert rule_set(tmp_path, learn.DIRECT_FILE) == [learn.PLACEHOLDER]
    hang(lr, clock, "i.instagram.com")
    assert wait_for(lambda: rule_set(tmp_path) == ["instagram.com"])
    assert probed == ["i.instagram.com"] and rule_set(tmp_path, learn.DIRECT_FILE) == [learn.PLACEHOLDER]
    snap = lr.snapshot()
    assert snap["enabled"] and snap["sites"] == [
        {"domain": "instagram.com", "via": "proxy", "why": "dpi", "label": "провайдер режет по имени сайта",
         "at": 1010.0}]
    hang(lr, clock, "www.instagram.com", "c2")
    clock.now += 60
    lr.observe([])
    assert probed == ["i.instagram.com"], "выученный сайт — проб по его соединениям нет"


def test_learns_service_that_refuses_vpn_as_direct(tmp_path):
    lr, clock, probed, _ = make_learner(tmp_path, {"www.gosuslugi.ru": ("direct", "vpn")})
    hang(lr, clock, "www.gosuslugi.ru", chains=("out-s1", "proxy"))
    assert wait_for(lambda: rule_set(tmp_path, learn.DIRECT_FILE) == ["gosuslugi.ru"])
    assert rule_set(tmp_path) == [learn.PLACEHOLDER]
    assert lr.snapshot()["sites"][0] | {"at": None} == {"domain": "gosuslugi.ru", "via": "direct", "why": "vpn",
                                                        "label": "не пускает через VPN", "at": None}


def test_open_or_unclear_site_is_not_learned_and_not_reprobed_at_once(tmp_path):
    lr, clock, probed, _ = make_learner(tmp_path, {"ok.example": (None, None), "unclear.example": None})
    hang(lr, clock, "ok.example")
    hang(lr, clock, "unclear.example", "c2")
    assert wait_for(lambda: len(probed) == 2 and lr.checking is None)
    hang(lr, clock, "ok.example", "c3")
    hang(lr, clock, "unclear.example", "c4")
    assert probed == ["ok.example", "unclear.example"], "повторная проба — не сразу"
    clock.now += learn.UNCLEAR_AGAIN + 1
    hang(lr, clock, "unclear.example", "c5")
    assert wait_for(lambda: probed[-1:] == ["unclear.example"] and len(probed) == 3)
    assert rule_set(tmp_path) == [learn.PLACEHOLDER]


def test_learned_site_is_rechecked_daily_and_dropped_when_open(tmp_path):
    answers = {"i.instagram.com": ("proxy", "dpi")}
    lr, clock, probed, _ = make_learner(tmp_path, answers)
    hang(lr, clock, "i.instagram.com")
    assert wait_for(lambda: rule_set(tmp_path) == ["instagram.com"])
    clock.now += 3600
    lr.observe([])
    assert len(probed) == 1, "сутки ещё не прошли"
    answers["i.instagram.com"] = (None, None)
    clock.now += learn.RECHECK
    lr.observe([])
    assert wait_for(lambda: rule_set(tmp_path) == [learn.PLACEHOLDER])
    assert probed == ["i.instagram.com", "i.instagram.com"] and lr.snapshot()["sites"] == []


def test_add_forget_and_disable(tmp_path):
    lr, clock, _probed, flag = make_learner(tmp_path, {"a.example": ("proxy", "ip"), "b.example": ("proxy", "dpi")})
    hang(lr, clock, "a.example")
    hang(lr, clock, "b.example", "c2")
    assert wait_for(lambda: rule_set(tmp_path) == ["a.example", "b.example"])
    assert lr.add("online.sberbank.ru", "direct", "vpn") is True
    assert lr.add("online.sberbank.ru", "direct", "vpn") is False, "уже в наборе"
    assert rule_set(tmp_path, learn.DIRECT_FILE) == ["sberbank.ru"]
    lr.forget("a.example")
    assert rule_set(tmp_path) == ["b.example"]
    flag["on"] = False
    lr.write()
    assert rule_set(tmp_path) == [learn.PLACEHOLDER] and rule_set(tmp_path, learn.DIRECT_FILE) == [learn.PLACEHOLDER]
    assert sorted(s["domain"] for s in lr.snapshot()["sites"]) == ["b.example", "sberbank.ru"], \
        "выключен — наборы пусты, а выученное помнится"
    lr.observe([conn("c9", "c.example")])
    clock.now += 10
    lr.observe([conn("c9", "c.example")])
    assert lr._queue.empty(), "выключен — не пробуем"
    flag["on"] = True
    lr.forget(None)
    assert rule_set(tmp_path) == [learn.PLACEHOLDER] and lr.snapshot()["sites"] == []


def test_entries_without_via_are_through_server(tmp_path):
    lr, *_ = make_learner(tmp_path, {})
    lr._store.save({"sites": {"instagram.com": {"why": "dpi", "at": 1.0}}})
    lr.write()
    assert rule_set(tmp_path) == ["instagram.com"] and lr.snapshot()["sites"][0]["via"] == "proxy"


def test_write_for_check_does_not_move_live_file(tmp_path):
    lr, _clock, _probed, _ = make_learner(tmp_path, {})
    other = tmp_path / "check"
    assert lr.write(other, live=False) == {"proxy": other / learn.FILE_NAME, "direct": other / learn.DIRECT_FILE}
    assert lr.write()["proxy"] == tmp_path / learn.FILE_NAME


# ------------------------------------------------------------ конфиг

def test_learned_rules_go_right_after_own_rules(tmp_path):
    from tests.test_vpnclient_config import make_plan, server
    plan = make_plan([server("vless_reality_vision")])
    plan.direct_sites = ["bank.example"]
    plan.via_zapret = False
    plan.learned_file, plan.learned_direct_file = tmp_path / learn.FILE_NAME, tmp_path / learn.DIRECT_FILE
    learn.routing.write_rule_set(plan.learned_file, [{"domain_suffix": ["instagram.com"]}])
    learn.routing.write_rule_set(plan.learned_direct_file, [{"domain_suffix": ["gosuslugi.ru"]}])
    cfg = config.build_singbox(plan)
    rules = cfg["route"]["rules"]
    own = next(i for i, r in enumerate(rules) if r.get("domain_suffix") == ["bank.example"])
    assert rules[own + 1] == {"rule_set": [config.LEARNED_SET], "action": "route", "outbound": config.SELECTOR_PROXY}
    assert rules[own + 2] == {"rule_set": [config.LEARNED_DIRECT_SET], "action": "route", "outbound": config.DIRECT}
    decls = cfg["route"]["rule_set"]
    assert {"type": "local", "tag": "learned", "format": "source", "path": str(plan.learned_file)} in decls
    assert {"type": "local", "tag": "learned-direct", "format": "source", "path": str(plan.learned_direct_file)} in decls
    dns = [{k: v for k, v in r.items() if k in ("rule_set", "server")} for r in cfg["dns"]["rules"]]
    assert {"rule_set": ["learned"], "server": config.DNS_REMOTE} in dns
    assert {"rule_set": ["learned-direct"], "server": config.DNS_DIRECT} in dns
    assert config.validate(cfg) == []


# ------------------------------------------------------------ менеджер

def test_manager_wires_learner_into_plan_sampler_and_settings(tmp_path):
    m, world = make_manager(tmp_path, basic_store())
    m.deps.direct_source = lambda: "192.168.0.10"
    m.start()
    assert m.wait_idle(5)
    plan = m._session.plan
    assert plan.learned_file == m.run_dir / learn.FILE_NAME and plan.learned_file.exists()
    assert plan.learned_direct_file == m.run_dir / learn.DIRECT_FILE and plan.learned_direct_file.exists()
    assert m._session.sampler.on_connections == m._learner.observe
    asked, control = [], []

    def inspect(host, **kw):
        asked.append((host, kw["bind"], kw["vpn_opener"] is not None))
        kw["network_mode"]()
        if host == "www.gosuslugi.ru":
            return Facts(host, direct=Attempt("ok", 200), vpn=Attempt("fail"))
        return Facts(host, direct=Attempt("tls"), vpn=Attempt("ok", 200))

    m.deps.site_inspect = inspect
    m.deps.network_mode = lambda bind: "open"
    m.deps.vpn_control = lambda opener: control.append(1) or Attempt("ok", 404)
    assert m._smart_probe("i.instagram.com") == ("proxy", "dpi")
    assert asked == [("i.instagram.com", "192.168.0.10", True)] and control == []
    assert m._smart_probe("www.gosuslugi.ru") == ("direct", "vpn") and control == [1]
    m.deps.vpn_control = lambda opener: Attempt("fail")
    assert m._smart_probe("www.gosuslugi.ru") is None, "через сервер не открывается ничего — сервер, а не сайт"
    starts = len(world.processes)
    assert m.save_settings({"smart_route": False}) == {}
    assert json.loads(plan.learned_file.read_text(encoding="utf-8"))["rules"][0]["domain_suffix"] == [learn.PLACEHOLDER]
    assert m.snapshot()["routing"]["smart"]["enabled"] is False
    assert m.wait_idle(5) and len(world.processes) == starts, "умный маршрут переключается без перезапуска ядра"


def test_connection_map_names_path_and_reason():
    """Карта соединений (2.0): по сайту — путь и почему; формат rule — как у sing-box 1.14.3 вживую."""
    conns = [
        {"metadata": {"host": "rr4.googlevideo.com"}, "chains": ["direct", "bypass"], "upload": 10, "download": 9000,
         "rule": "rule_set=[bypass-3] => route(bypass)"},
        {"metadata": {"host": "rr4.googlevideo.com"}, "chains": ["direct", "bypass"], "upload": 5, "download": 1000,
         "rule": "rule_set=[bypass-3] => route(bypass)"},
        {"metadata": {"host": "www.instagram.com"}, "chains": ["srv-a", "proxy"], "upload": 1, "download": 500,
         "rule": "rule_set=[learned] => route(proxy)"},
        {"metadata": {"host": "bank.ru"}, "chains": ["direct"], "upload": 1, "download": 100,
         "rule": "rule_set=[learned-direct] => route(direct)"},
        {"metadata": {"host": "www.wikipedia.org"}, "chains": ["direct"], "upload": 1, "download": 50,
         "rule": "domain_suffix=wikipedia.org => route(direct)"},
        {"metadata": {"destinationIP": "1.2.3.4", "host": ""}, "chains": ["srv-a", "proxy"], "upload": 1, "download": 10,
         "rule": "final"},
        {"metadata": {"host": "x.com"}, "chains": ["srv-a", "proxy", "bypass"], "upload": 1, "download": 5,
         "rule": "rule_set=[bypass-3] => route(bypass)"},     # обход упал — «через обход» идёт через сервер
    ]
    rows = learn.connection_map(conns)
    assert [r["host"] for r in rows] == ["rr4.googlevideo.com", "www.instagram.com", "bank.ru", "www.wikipedia.org",
                                         "1.2.3.4", "x.com"]
    by = {r["host"]: (r["path"], r["why"], r["count"]) for r in rows}
    assert by["rr4.googlevideo.com"] == ("bypass", "списки обхода", 2) and rows[0]["down"] == 10000
    assert by["www.instagram.com"] == ("proxy", "умный маршрут", 1)
    assert by["bank.ru"] == ("direct", "умный маршрут: не пускает через VPN", 1)
    assert by["www.wikipedia.org"] == ("direct", "ваше правило для сайта", 1)
    assert by["1.2.3.4"] == ("proxy", "всё остальное", 1)
    assert by["x.com"] == ("proxy", "списки обхода", 1)
    assert len(learn.connection_map(conns, limit=2)) == 2
