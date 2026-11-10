"""Обход по сервисам (2.0, zapret/compose.py) на настоящем пакете стратегий: у YouTube и Discord свои стратегии поверх
базовой, остальное — как было; маршрут своего VPN читает собранные аргументы. winws не запускается."""
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.settings import Settings
from app.vpnclient import routing
from app.zapret import compose
from app.zapret import manager as M
from app.zapret import strategies as st


def args_of(pack_dir: Path, sid: str) -> list[str]:
    name = "general.bat" if sid == "general" else f"{sid}.bat"
    return st.parse_file(pack_dir / name).args(pack_dir)


def desync(profile):
    return [a for a in profile if not a.startswith(("--wf-", "--filter-", "--hostlist", "--ipset"))]


def test_youtube_gets_its_strategy_and_nothing_else_moves(pack_dir):
    base, alt2 = args_of(pack_dir, "general"), args_of(pack_dir, "general (ALT2)")
    out, applied = compose.compose(base, {"youtube": alt2}, [])
    assert applied == ["youtube"]
    mine, theirs, src = compose.split_profiles(out), compose.split_profiles(base), compose.split_profiles(alt2)
    assert len(mine) == len(theirs)
    g = next(i for i, p in enumerate(mine) if any(a.endswith("list-google.txt") for a in p))
    assert [a for a in mine[g] if a.startswith(("--filter-", "--hostlist"))] == \
        [a for a in theirs[g] if a.startswith(("--filter-", "--hostlist"))], "список и порты — базовой"
    assert desync(mine[g]) == desync(src[g]) and desync(mine[g]) != desync(theirs[g]), "обман DPI — из ALT2"
    assert all(mine[i] == theirs[i] for i in range(len(mine)) if i != g)


def test_discord_gets_own_profile_before_general_with_same_exclusions(pack_dir):
    base, fake = args_of(pack_dir, "general"), args_of(pack_dir, "general (FAKE TLS AUTO)")
    domains = compose.discord_domains(pack_dir / "lists" / "list-general.txt")
    assert "discord.com" in domains and "dis.gd" in domains and "discordapp.net" in domains and len(domains) >= 20
    out, applied = compose.compose(base, {"discord": fake}, domains)
    assert applied == ["discord"]
    mine, theirs, src = compose.split_profiles(out), compose.split_profiles(base), compose.split_profiles(fake)
    assert len(mine) == len(theirs) + 1
    general = next(i for i, p in enumerate(theirs) if any(a.endswith("list-general.txt") for a in p)
                   and any(a.startswith("--filter-tcp") for a in p) and not any(a.startswith("--ipset=") for a in p))
    own = mine[general]
    assert own[0] == "--filter-tcp=80,443" and own[1] == "--hostlist-domains=" + ",".join(domains)
    assert [a for a in own if a.startswith(("--hostlist-exclude", "--ipset-exclude"))] == \
        [a for a in theirs[general] if a.startswith(("--hostlist-exclude", "--ipset-exclude"))], \
        "исключения общего профиля (Radmin, Hamachi, свои) — и у профиля Discord"
    assert desync(own) == desync(src[general]) and mine[general + 1] == theirs[general], "общий профиль — как был"
    media = next(i for i, p in enumerate(mine) if "--hostlist-domains=discord.media" in p)
    assert desync(mine[media]) == desync(next(p for p in src if "--hostlist-domains=discord.media" in p)),         "и discord.media (TCP 2053…) — со стратегией Discord"
    assert out[:2] == base[:2] and out[0].startswith("--wf-tcp="), "глобальные --wf-* — на месте"


def test_composed_args_are_read_by_vpn_route_and_bypass_check(pack_dir, tmp_path):
    base = args_of(pack_dir, "general")
    domains = compose.discord_domains(pack_dir / "lists" / "list-general.txt")
    out, _ = compose.compose(base, {"discord": args_of(pack_dir, "general (ALT)"),
                                    "youtube": args_of(pack_dir, "general (ALT2)")}, domains)
    assert routing.handles_domain(out, pack_dir=pack_dir, ipset_mode="loaded", domain="cdn.discordapp.com")
    assert routing.handles_domain(out, pack_dir=pack_dir, ipset_mode="loaded", domain="www.youtube.com")
    result = routing.bypass_from_strategy(out, pack_dir=pack_dir, ipset_mode="loaded", out_dir=tmp_path)
    assert any(p.domains_file and "discord.com" in p.domains_file.read_text(encoding="utf-8")
               for p in result.profiles), "маршрут «через обход» своего VPN видит профиль Discord"


def test_missing_profile_leaves_group_on_base():
    base = ["--wf-tcp=443", "--filter-tcp=443", "--hostlist=x/list-other.txt", "--dpi-desync=fake"]
    out, applied = compose.compose(base, {"youtube": ["--filter-tcp=443", "--dpi-desync=split"],
                                          "discord": ["--dpi-desync=split"]}, ["discord.com"])
    assert out == base and applied == []


def _row(sid, discord, youtube):
    def target(name, good):
        return {"name": name, "http": "ok" if good else "fail", "tls12": "ok" if good else "fail",
                "tls13": "ok" if good else "fail", "ping": 1}
    targets = [target(f"Discord {i}", i < discord) for i in range(4)] + \
        [target(f"YouTube {i}", i < youtube) for i in range(4)]
    return {"id": sid, "started": True, "targets": targets}


def test_group_bests_from_test_results():
    results = [_row("general (ALT)", discord=4, youtube=1), _row("general (ALT2)", discord=1, youtube=4),
               _row("general", discord=2, youtube=2)]
    assert compose.group_bests(results, "general (ALT)") == {"youtube": "general (ALT2)"}
    assert compose.group_bests(results, "general") == {"discord": "general (ALT)", "youtube": "general (ALT2)"}
    tied = [_row("general (ALT)", discord=4, youtube=4), _row("general (ALT2)", discord=4, youtube=4)]
    assert compose.group_bests(tied, "general (ALT2)") == {}, "базовая не хуже — собирать незачем"
    assert compose.group_bests([_row("general", 0, 0)], None) == {}


@pytest.fixture
def real_zm(tmp_path, pack_dir):
    settings = Settings(tmp_path / "s.json")
    z = M.ZapretManager(settings, lambda level, text: None, True)
    z.pack = SimpleNamespace(path=pack_dir, version="1.10.3", published_at=None)
    z.strategies, _errors = st.discover(pack_dir)
    return z


def test_manager_composes_running_args_but_not_test_probes(real_zm, pack_dir):
    z = real_zm
    general = z.strategy("general")
    plain = z.build_args(general)
    assert plain == args_of(pack_dir, "general")
    z.settings.update(lambda d: d["zapret"].__setitem__("group_strategies", {"discord": "general (ALT)",
                                                                             "youtube": "general (ALT2)"}))
    assert z.group_strategies() == {"discord": "general (ALT)", "youtube": "general (ALT2)"}
    composed = z.build_args(general)
    assert composed != plain and len(compose.split_profiles(composed)) == len(compose.split_profiles(plain)) + 1
    assert z.build_args(general, composed=False) == plain, "пробы подбора — стратегия как есть"
    assert z.build_args(z.strategy("general (ALT2)")) != args_of(pack_dir, "general (ALT2)"), \
        "группа на базовой стратегии не собирается, остальные — да"
    with pytest.raises(M.ZapretError):
        z.set_group_strategies({"youtube": "нет такой"})
    z.set_group_strategies({})
    assert z.group_strategies() == {} and z.build_args(general) == plain


def test_core_shows_applied_and_suggested_groups_and_manual_pick_resets(tmp_path, monkeypatch):
    from tests.test_vpnclient_core import make_core
    core = make_core(tmp_path, None)
    strategies = [SimpleNamespace(id=i, label=lbl, usable=True) for i, lbl in
                  (("general", "Стандартная"), ("general (ALT)", "ALT"), ("general (ALT2)", "ALT2"))]
    applied, calls = {}, []
    core.zapret.strategies = strategies
    core.zapret.group_strategies = lambda: dict(applied)
    core.zapret.set_group_strategies = lambda groups: calls.append(("groups", groups))
    core.zapret.strategy = lambda sid=None: strategies[0]
    core.zapret.set_strategy = lambda sid: calls.append(("strategy", sid, dict(core.settings.get("zapret", "group_strategies"))))
    core.tester.group_suggestion = lambda base: {"youtube": "general (ALT2)", "discord": "general (ALT)"}
    applied["discord"] = "general (ALT)"
    groups = core._groups_state(core.settings.snapshot())
    assert {k: groups[k] for k in ("applied", "suggested")} == {"applied": {"discord": {"id": "general (ALT)", "label": "ALT"}},
                      "suggested": {"youtube": {"id": "general (ALT2)", "label": "ALT2"}}}, "уже собранное не советуем"
    assert core.zapret_set_groups({"youtube": "general (ALT2)", "discord": "general (ALT)"}) == {"ok": True}
    assert calls[-1] == ("groups", {"youtube": "general (ALT2)", "discord": "general (ALT)"})
    assert core.zapret_set_groups({"youtube": "нет такой"})["ok"] is False
    core.settings.update(lambda d: d["zapret"].__setitem__("group_strategies", {"youtube": "general (ALT2)"}))
    core.zapret.paused_for_test = False
    assert core.zapret_set_strategy("general")["ok"]
    assert calls[-1] == ("strategy", "general", {}), "стратегию выбрал человек — сборка снята тем же перезапуском"


def test_tester_suggestion_is_cached_per_test_and_base(monkeypatch):
    from app.zapret import tester as T
    t = T.StrategyTester(SimpleNamespace(), lambda *a: None)
    reads = []
    t.state = {"kind": "standard", "finished_at": 5.0, "results": [_row("general (ALT2)", 4, 4), _row("general", 1, 1)]}
    monkeypatch.setattr(T.StrategyTester, "_last_results", lambda self: reads.append(1) or (self.state["results"], 5.0))
    assert t.group_suggestion("general") == {"discord": "general (ALT2)", "youtube": "general (ALT2)"}
    assert t.group_suggestion("general") and len(reads) == 1, "раз в секунду отчёт с диска не читается"
    assert t.group_suggestion("general (ALT2)") == {} and len(reads) == 2


def test_base_with_catch_all_profile_is_not_composed(pack_dir):
    """general (ALT5) — один TCP-профиль «все сайты» (syndata на SYN). Вживую 2026-11-10 профили сервисов перед ним
    ничего не дали: YouTube и Discord — 0 до и после. На такой базе не собираем — и совет её не предложит."""
    base, alt = args_of(pack_dir, "general (ALT5)"), args_of(pack_dir, "general (ALT)")
    domains = compose.discord_domains(pack_dir / "lists" / "list-general.txt")
    assert compose.compose(base, {"youtube": alt, "discord": alt}, domains) == (base, [])


def test_suggestion_only_for_groups_that_compose_on_this_base(real_zm, monkeypatch):
    from app.zapret import tester as T
    t = T.StrategyTester(real_zm, lambda *a: None)
    results = [_row("general (ALT)", 4, 4), _row("general (ALT5)", 0, 0), _row("general (FAKE TLS AUTO)", 0, 4)]
    t.state = {"kind": "standard", "finished_at": 7.0, "results": results}
    monkeypatch.setattr(T.StrategyTester, "_last_results", lambda self: (self.state["results"], 7.0))
    assert t.group_suggestion("general (FAKE TLS AUTO)") == {"discord": "general (ALT)"}
    assert t.group_suggestion("general (ALT5)") == {}, "на базе «все сайты» не собрать — и не советуем"


def test_site_profiles_go_before_general_and_share_one_per_strategy(real_zm, pack_dir):
    z = real_zm
    z.settings.update(lambda d: d["zapret"].__setitem__("site_strategies", {
        "instagram.com": "general (ALT2)", "x.com": "general (ALT2)", "rutracker.org": "general (ALT)"}))
    general = z.strategy("general")
    plain = compose.split_profiles(z.build_args(general, composed=False))
    mine = compose.split_profiles(z.build_args(general))
    assert len(mine) == len(plain) + 2, "сайты одной стратегии — одним профилем"
    site_rows = [p for p in mine if any(a.startswith("--hostlist-domains=") and "discord.media" not in a for a in p)]
    domains = sorted(a.split("=", 1)[1] for p in site_rows for a in p if a.startswith("--hostlist-domains="))
    assert domains == ["instagram.com,x.com", "rutracker.org"]
    assert all(any(a.startswith("--ipset-exclude") for a in p) for p in site_rows), "исключения — как у общего"
    over = compose.split_profiles(z.build_args(general, override={"medium.com": "general (ALT9)"}))
    assert len(over) == len(mine) + 1, "подбор пробует сайт в составе нынешней сборки"
    z.set_site_strategy("x.com", None)
    assert z.site_strategies() == {"instagram.com": "general (ALT2)", "rutracker.org": "general (ALT)"}


def test_autopilot_on_turns_on_self_repair(tmp_path):
    """Один выключатель (2.0): сторож чинит сам, умный маршрут включён; сами части включает страница."""
    from tests.test_vpnclient_core import make_core
    saved = []
    core = make_core(tmp_path, SimpleNamespace(save_settings=lambda values: saved.append(values) or {}))
    core.settings.update(lambda d: d["zapret"].__setitem__("watchdog", "ask"))
    assert core.autopilot_on() == {"ok": True}
    assert core.settings.get("zapret", "watchdog") == "auto" and saved == [{"smart_route": True}]
    assert make_core(tmp_path / "no-vc", None).autopilot_on()["ok"], "без своего VPN — только сторож"
