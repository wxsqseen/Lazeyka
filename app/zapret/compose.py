"""Обход по сервисам (docs/v2-plan.md, часть 1): аргументы winws из базовой стратегии и стратегий, лучших для групп.

Все стратегии пакета Flowseal — одни и те же профили (разделитель --new) с одинаковыми фильтрами и списками;
различаются только параметры обмана DPI. winws применяет первый подходящий профиль, поэтому:
- youtube — у профиля со списком list-google.txt параметры обмана берутся из того же профиля стратегии группы;
- discord — перед общим профилем (list-general.txt по TCP) встаёт свой: домены Discord из list-general.txt, исключения
  общего профиля и параметры общего профиля стратегии группы; так же — профиль discord.media (TCP 2053…).
Нет у стратегии нужного профиля (пакет устроен иначе) — группа остаётся на базовой, ничего не ломается."""
from __future__ import annotations

from pathlib import Path

GROUPS = ("youtube", "discord")
# Итоги подбора по сайтам из targets.txt: имена целей начинаются с этих слов (tester._pretty).
GROUP_TARGETS = {"youtube": ("YouTube", "Google"), "discord": ("Discord",)}
_MATCH = ("--wf-", "--filter-", "--hostlist", "--ipset", "--new")   # к чему относится профиль — не параметры обмана
_EXCLUDE = ("--hostlist-exclude", "--ipset-exclude")


def _name(arg: str) -> str:
    return arg.split("=", 1)[0]


def _is_match(arg: str) -> bool:
    return _name(arg).startswith(_MATCH)


def split_profiles(args: list[str]) -> list[list[str]]:
    profiles: list[list[str]] = [[]]
    for arg in args:
        if arg == "--new":
            profiles.append([])
        else:
            profiles[-1].append(arg)
    return profiles


def join_profiles(profiles: list[list[str]]) -> list[str]:
    out: list[str] = []
    for i, profile in enumerate(profiles):
        if i:
            out.append("--new")
        out.extend(profile)
    return out


def _values(profile: list[str], key: str) -> list[str]:
    return [a.split("=", 1)[1] for a in profile if _name(a) == key and "=" in a]


def _has_list(profile: list[str], file_name: str) -> bool:
    return any(Path(v.strip('"')).name.lower() == file_name for v in _values(profile, "--hostlist"))


def _google(profile: list[str]) -> bool:
    return _has_list(profile, "list-google.txt") and bool(_values(profile, "--filter-tcp"))


def _general_tcp(profile: list[str]) -> bool:
    return (_has_list(profile, "list-general.txt") and bool(_values(profile, "--filter-tcp"))
            and not _values(profile, "--ipset"))


def _discord_media(profile: list[str]) -> bool:
    return "discord.media" in ",".join(_values(profile, "--hostlist-domains")).split(",")


def _find(profiles: list[list[str]], test) -> int | None:
    return next((i for i, p in enumerate(profiles) if test(p)), None)


def _desync(profile: list[str]) -> list[str]:
    return [a for a in profile if not _is_match(a)]


def _filters(profile: list[str]) -> list[str]:
    return [a for a in profile if _is_match(a)]


def discord_domains(list_general: Path) -> list[str]:
    """Домены Discord из list-general.txt пакета (в 1.10.3 — 24): по ним профиль Discord берёт свою стратегию."""
    try:
        lines = list_general.read_text(encoding="utf-8-sig", errors="replace").splitlines()
    except OSError:
        return []
    out = [ln.strip().lower() for ln in lines if ln.strip() and not ln.strip().startswith("#")]
    return [d for d in dict.fromkeys(out) if ("discord" in d and "." in d) or d == "dis.gd"]


def _catch_all(profile: list[str]) -> bool:
    """TCP-профиль на 443 без списков: ловит все сайты (general (ALT5)). Вживую (2026-11-10) профили сервисов перед ним
    не помогли: он действует уже на SYN (syndata), когда имени сайта ещё не видно, — на такой базе не собираем."""
    if _values(profile, "--hostlist") or _values(profile, "--hostlist-domains") or _values(profile, "--ipset"):
        return False
    for spec in _values(profile, "--filter-tcp"):
        for item in spec.split(","):
            lo, _, hi = item.partition("-")
            if lo.isdigit() and int(lo) <= 443 <= int(hi or lo):
                return True
    return False


def _exclusions(profile: list[str]) -> list[str]:
    return [a for a in profile if _name(a).startswith(_EXCLUDE)]


def compose(base: list[str], groups: dict[str, list[str]], domains: list[str],
            sites: list[tuple[list[str], list[str]]] = ()) -> tuple[list[str], list[str]]:
    """base — аргументы базовой стратегии, groups — группа → аргументы её стратегии, domains — домены Discord,
    sites — (домены, аргументы стратегии) для отдельных сайтов: их профили встают перед общим, как у Discord.
    Ответ — (аргументы winws, что собрано: группы и «site»). Нет у базы нужного профиля или раньше него стоит
    профиль «все сайты» — остаётся на базовой."""
    profiles = split_profiles(list(base))
    applied: list[str] = []

    def entry() -> int | None:                  # профиль 0 несёт глобальные --wf-*: перед ним не встаём
        return next((i for i, p in enumerate(profiles) if i and _catch_all(p)), None)

    source = groups.get("youtube")
    if source:
        theirs = split_profiles(list(source))
        b, s, e = _find(profiles, _google), _find(theirs, _google), entry()
        if s is not None and b is not None and (e is None or b < e):
            profiles[b] = _filters(profiles[b]) + _desync(theirs[s])
            applied.append("youtube")
    source = groups.get("discord")
    if source and domains:
        theirs = split_profiles(list(source))
        b, s, e = _find(profiles, _general_tcp), _find(theirs, _general_tcp), entry()
        if s is not None and b and (e is None or b < e):
            at = b
            own = [f"--filter-tcp={_values(profiles[b], '--filter-tcp')[0]}", "--hostlist-domains=" + ",".join(domains),
                   *_exclusions(profiles[b]), *_desync(theirs[s])]
            bm, sm = _find(profiles, _discord_media), _find(theirs, _discord_media)
            if bm is not None and sm is not None:
                profiles[bm] = _filters(profiles[bm]) + _desync(theirs[sm])
            profiles.insert(at, own)
            applied.append("discord")
    for site_domains, source in sites:
        theirs = split_profiles(list(source))
        b, s, e = _find(profiles, _general_tcp), _find(theirs, _general_tcp), entry()
        if site_domains and s is not None and b and (e is None or b < e):
            profiles.insert(b, [f"--filter-tcp={_values(profiles[b], '--filter-tcp')[0]}",
                                "--hostlist-domains=" + ",".join(site_domains), *_exclusions(profiles[b]),
                                *_desync(theirs[s])])
            if "site" not in applied:
                applied.append("site")
    return join_profiles(profiles), applied


def group_bests(results: list[dict], base: str | None) -> dict[str, str]:
    """Лучшая стратегия для каждой группы по итогам стандартного подбора (больше удачных проверок сайтов группы).
    Базовая при равенстве остаётся базовой: собирать незачем. Ответ — только группы, где лучшая не базовая."""
    from .tester import CURL_MODES
    out: dict[str, str] = {}
    for group, prefixes in GROUP_TARGETS.items():
        scores: dict[str, int] = {}
        for row in results:
            if not row.get("started") or not row.get("id"):
                continue
            scores[row["id"]] = sum(1 for t in row.get("targets") or [] if str(t.get("name", "")).startswith(prefixes)
                                    for mode in CURL_MODES if t.get(mode) == "ok")
        if not scores:
            continue
        top = max(scores.values())
        if top == 0 or scores.get(base or "") == top:
            continue
        out[group] = next(sid for sid, score in scores.items() if score == top)
    return out
