"""Умный маршрут своего VPN: сайт, который напрямую не открывается, Лазейка сама пускает через сервер, а сервис,
который не пускает через VPN (банки, Госуслуги, маркетплейсы), — напрямую.

Сигнал — соединения ядра (clash API /connections, раз в 5 с от сэмплера): на 443, с именем сайта, отправлено
больше нуля, а пришло 0 байт (напрямую — ещё и ответ, замерший на ~16 КБ) — и так дольше SUSPECT_AGE. Такой сайт
проверяется пробой «Рентгена» (siteprobe) мимо VPN и через сервер: напрямую не открылся, через сервер открылся,
интернет обычный (не белый список, не обрыв связи) — в набор learned (через сервер); через сервер не открылся,
напрямую открылся, а сам VPN работает — в набор learned-direct. Наборы — локальные rule-set: ядро перечитывает их
само, без перезапуска. Раз в сутки выученные сайты проверяются снова: открываются обоими путями — уходят."""
from __future__ import annotations

import logging
import queue
import threading
import time
from pathlib import Path
from typing import Any, Callable

from .. import siteprobe
from . import routing

log = logging.getLogger("lazeyka.vpnclient.learn")

FILE_NAME = "learned.json"                  # список сайтов (store) и rule-set «через сервер»
DIRECT_FILE = "learned-direct.json"        # rule-set «напрямую»
PLACEHOLDER = "learned.lazeyka.invalid"   # пустой набор ядро не принимает — заглушка, которой нет в интернете
SUSPECT_AGE = 8.0                 # соединение висит столько секунд — подозрение (два опроса сэмплера)
OPEN_AGAIN = 6 * 3600.0           # напрямую открылся — снова проверим не раньше
UNCLEAR_AGAIN = 1800.0            # не ясно (сеть, VPN, белый список) — повтор не раньше
RECHECK = 24 * 3600.0             # выученный сайт — проверка напрямую раз в сутки
RECHECK_EVERY = 600.0             # как часто искать выученные сайты, которым пора на проверку
MAX_SITES = 300
QUEUE_SIZE = 32
_SECOND_LEVEL = frozenset({"co", "com", "net", "org", "gov", "edu", "ac", "ne", "or", "msk", "spb"})


def site_of(host: str) -> str:
    """Имя сайта для набора: instagram.com для i.instagram.com — блокируют обычно весь сайт.
    shortcut: две последние части имени (три — у co.uk, com.ru и т. п.), без списка публичных суффиксов;
    подключить его, если начнут склеиваться чужие сайты на общих доменах вроде *.github.io."""
    labels = host.split(".")
    if len(labels) >= 3 and labels[-2] in _SECOND_LEVEL and len(labels[-1]) == 2:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _named(host: str) -> bool:
    return bool(host) and routing.normalize_domain(host) == host and not host.replace(".", "").isdigit()


def suspects(conns: list[dict], seen: dict[str, tuple[float, int]], now: float) -> list[str]:
    """Хосты зависших соединений — и напрямую, и через сервер. seen — id соединения → (когда увидели впервые,
    сколько пришло в прошлый опрос); обновляется на месте, закрытые соединения из него уходят."""
    out: list[str] = []
    alive: set[str] = set()
    for c in conns:
        if not isinstance(c, dict):
            continue
        meta = c.get("metadata") or {}
        host = str(meta.get("host") or "").lower().rstrip(".")
        chains = c.get("chains") or []
        cid = str(c.get("id") or "")
        if (not cid or not chains or meta.get("network") != "tcp"
                or str(meta.get("destinationPort")) != "443" or not _named(host)):
            continue
        alive.add(cid)
        down, up = int(c.get("download") or 0), int(c.get("upload") or 0)
        first, last = seen.get(cid, (now, -1))
        seen[cid] = (first, down)
        if up <= 0 or now - first < SUSPECT_AGE:
            continue
        frozen = siteprobe.FREEZE_BAND[0] <= down <= siteprobe.FREEZE_BAND[1] and down == last
        if down == 0 or ("direct" in chains and frozen):
            out.append(host)
    for cid in [k for k in seen if k not in alive]:
        del seen[cid]
    return list(dict.fromkeys(out))


# Почему соединение идёт так: по полю rule clash API («rule_set=learned => route(proxy)», «final»). Порядок важен:
# learned-direct раньше learned, свои правила сайтов (domain…) — после наборов.
_WHY = (("learned-direct", "умный маршрут: не пускает через VPN"), ("learned", "умный маршрут"),
        ("bypass", "списки обхода"), ("process_", "правило для программы"), ("ip_is_private", "локальная сеть"),
        ("geosite-category-ru", "российские сайты"), ("geoip-ru-blocked", "список заблокированного"),
        ("geoip-ru", "российские адреса"), ("refilter", "список заблокированного"),
        ("russia_inside", "список заблокированного"), ("game", "загрузки игр"), ("bittorrent", "торренты"),
        ("inbound=", "проверка Лазейки"), ("domain", "ваше правило для сайта"), ("final", "всё остальное"))
MAP_LIMIT = 40


def _why(rule: str) -> str:
    rule = rule.lower()
    return next((label for key, label in _WHY if key in rule), rule.split(" => ")[0] or "—")


def connection_map(conns: list[dict], limit: int = MAP_LIMIT) -> list[dict]:
    """Карта соединений (2.0): по сайту — путь (bypass — обход Лазейки, direct — напрямую, proxy — через сервер), почему
    (правило), трафик и сколько соединений. Самые нагруженные — первыми."""
    rows: dict[str, dict] = {}
    for c in conns:
        if not isinstance(c, dict):
            continue
        meta = c.get("metadata") or {}
        host = str(meta.get("host") or meta.get("destinationIP") or "").lower().rstrip(".")
        if not host:
            continue
        chains = [str(x) for x in c.get("chains") or []]
        path = "bypass" if chains[:1] == ["direct"] and "bypass" in chains else "direct" if chains[:1] == ["direct"] \
            else "proxy"
        row = rows.setdefault(host, {"host": host, "path": path, "why": _why(str(c.get("rule") or "")),
                                     "up": 0, "down": 0, "count": 0})
        row["up"] += int(c.get("upload") or 0)
        row["down"] += int(c.get("download") or 0)
        row["count"] += 1
    return sorted(rows.values(), key=lambda r: -(r["up"] + r["down"]))[:limit]


def judge(facts: siteprobe.Facts, mode: str | None, vpn_alive: bool = True
          ) -> tuple[str | None, str | None] | None:
    """Пробы → (куда, почему): ("proxy", почему) — напрямую не открывается, через сервер открывается, интернет
    обычный; ("direct", "vpn") — через сервер не открывается, напрямую открывается, а сам VPN работает
    (vpn_alive); (None, None) — открывается обоими путями (или напрямую, если через сервер не проверяли);
    None — не ясно. mode — режим сети, если его спрашивали (только когда напрямую не открылось)."""
    d = facts.direct
    if d is None:
        return None
    why = siteprobe.blocked_reason(facts)
    if why is not None:
        if (not d.ok and mode != "open") or not siteprobe.vpn_works(facts.vpn):
            return None
        return "proxy", why
    if not d.ok:
        return None
    if facts.vpn is None or siteprobe.vpn_works(facts.vpn):
        return None, None
    if d.status in (403, 451):
        return None             # и напрямую отказ (защита от ботов, как у Авито) — сравнивать не с чем
    return ("direct", "vpn") if vpn_alive else None


class Learner:
    """Выученные сайты (store: load/save JSON в закрытой папке) и очередь проб в своём потоке.
    probe(host) — judge() по пробам; enabled() — включён ли умный маршрут в настройках."""

    def __init__(self, store: Any, probe: Callable[[str], tuple[str | None, str | None] | None],
                 enabled: Callable[[], bool], on_change: Callable[[], None], clock: Callable[[], float] = time.time):
        self._store = store
        self._probe = probe
        self._enabled = enabled
        self._on_change = on_change
        self._clock = clock
        self._lock = threading.Lock()
        self._seen: dict[str, tuple[float, int]] = {}
        self._next: dict[str, float] = {}           # хост → не пробовать раньше
        self._queue: queue.Queue = queue.Queue(QUEUE_SIZE)
        self._queued: set[str] = set()
        self._thread: threading.Thread | None = None
        self._recheck_at = 0.0
        self._dir: Path | None = None
        self.checking: str | None = None

    # ---------------------------------------------------------------- данные

    def sites(self) -> dict[str, dict]:
        data = self._store.load()
        sites = data.get("sites") if isinstance(data, dict) else None
        return {k: v for k, v in sites.items() if isinstance(v, dict)} if isinstance(sites, dict) else {}

    def _save(self, sites: dict[str, dict]) -> None:
        if len(sites) > MAX_SITES:
            keep = sorted(sites, key=lambda k: sites[k].get("at") or 0)[-MAX_SITES:]
            sites = {k: sites[k] for k in keep}
        self._store.save({"sites": sites})
        self.write()
        self._on_change()

    def snapshot(self) -> dict:
        sites = self.sites()
        items = [{"domain": d, "via": _via(v), "why": v.get("why"),
                  "label": siteprobe.WHY_LABELS.get(v.get("why"), ""), "at": v.get("at")} for d, v in sites.items()]
        items.sort(key=lambda i: -(i["at"] or 0))
        return {"enabled": bool(self._enabled()), "sites": items, "checking": self.checking}

    def add(self, host: str, via: str, why: str) -> bool:
        """Сайт в набор по готовому выводу (паспорт провайдера проверил его сам). True — добавлен впервые."""
        domain = site_of(host)
        now = self._clock()
        with self._lock:
            sites = self.sites()
            fresh = domain not in sites or _via(sites[domain]) != via
            sites[domain] = {"via": via, "why": why, "host": host, "at": now, "checked": now}
            self._save(sites)
        return fresh

    def forget(self, domain: str | None) -> None:
        """Убрать сайт из набора (None — все). Вернётся, если снова окажется заблокированным."""
        with self._lock:
            sites = self.sites()
            for d in ([domain] if domain else list(sites)):
                sites.pop(d, None)
                self._next[d] = self._clock() + OPEN_AGAIN    # человек убрал — не возвращать тут же
            self._save(sites)

    def write(self, out_dir: Path | None = None, *, live: bool = True) -> dict[str, Path] | None:
        """rule-set наборов для ядра ({"proxy": путь, "direct": путь}): в папку конфига out_dir (live — это конфиг
        работающего VPN, дальше наборы обновляются там) или, без out_dir, туда, куда писали для работающего VPN.
        Выключен умный маршрут — в файлах только заглушка: правила в конфиге остаются, переключение без
        перезапуска ядра."""
        folder = Path(out_dir) if out_dir is not None else self._dir
        if folder is None:
            return None
        if live:
            self._dir = folder
        sites = self.sites() if self._enabled() else {}
        paths = {"proxy": folder / FILE_NAME, "direct": folder / DIRECT_FILE}
        for via, path in paths.items():
            domains = sorted(d for d, v in sites.items() if _via(v) == via)
            routing.write_rule_set(path, [{"domain_suffix": domains or [PLACEHOLDER]}])
        return paths

    # ---------------------------------------------------------------- наблюдение и пробы

    def observe(self, conns: list[dict]) -> None:
        """Соединения ядра (зовёт сэмплер раз в 5 с): зависшие — в очередь проб."""
        if not self._enabled():
            self._seen.clear()
            return
        now = self._clock()
        known = self.sites()
        for host in suspects(conns, self._seen, now):
            if site_of(host) not in known:
                self._enqueue(host, now)
        if now >= self._recheck_at:
            self._recheck_at = now + RECHECK_EVERY
            for domain, entry in known.items():
                if now - float(entry.get("checked") or entry.get("at") or 0) >= RECHECK:
                    self._enqueue(entry.get("host") or domain, now)

    def _enqueue(self, host: str, now: float) -> None:
        with self._lock:
            if host in self._queued or now < self._next.get(host, 0.0):
                return
            try:
                self._queue.put_nowait(host)
            except queue.Full:
                return
            self._queued.add(host)
            if self._thread is None or not self._thread.is_alive():
                self._thread = threading.Thread(target=self._run, name="vpnclient-learn", daemon=True)
                self._thread.start()

    def _run(self) -> None:
        while True:
            try:
                host = self._queue.get(timeout=30)
            except queue.Empty:
                return
            try:
                self.checking = host
                self._on_change()
                self._check(host)
            except Exception:  # noqa: BLE001 — одна проба упала: остальные идут
                log.exception("Умный маршрут: проба %s не удалась", host)
            finally:
                self.checking = None
                with self._lock:
                    self._queued.discard(host)
                self._on_change()

    def _check(self, host: str) -> None:
        result = self._probe(host) if self._enabled() else None
        now = self._clock()
        domain = site_of(host)
        with self._lock:
            sites = self.sites()
            if result is None:
                self._next[host] = now + UNCLEAR_AGAIN
                if domain in sites:                     # проверка выученного не удалась — повтор через полчаса
                    sites[domain]["checked"] = now - RECHECK + UNCLEAR_AGAIN
                    self._store.save({"sites": sites})
                return
            via, why = result
            if via is None:
                self._next[host] = now + OPEN_AGAIN
                if sites.pop(domain, None) is not None:
                    log.info("Умный маршрут: %s снова открывается обоими путями — убран из набора", domain)
                    self._save(sites)
                return
            entry = sites.get(domain)
            changed = entry is None or _via(entry) != via
            sites[domain] = {"via": via, "why": why, "host": host,
                             "at": now if changed else entry.get("at") or now, "checked": now}
            if changed:
                log.info("Умный маршрут: %s — %s (%s)", domain, "через сервер" if via == "proxy" else "напрямую",
                         siteprobe.WHY_LABELS.get(why, why))
                self._save(sites)
            else:
                self._store.save({"sites": sites})


def _via(entry: dict) -> str:
    return "direct" if entry.get("via") == "direct" else "proxy"
