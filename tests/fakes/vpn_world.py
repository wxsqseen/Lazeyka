"""Подделки для тестов менеджера своего VPN: хранилище, генератор, ядра, процессы, clash API, прокси.

Всё в памяти и без системы: процессы не запускаются, прокси и WFP не трогаются. World собирает их
вместе и даёт тесту управлять часами, падениями и ответами.
"""
from __future__ import annotations

import itertools
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from types import SimpleNamespace

from app.vpnclient import engines as real_engines
from app.vpnclient import routing as real_routing
from app.vpnclient.clash import ClashError
from app.vpnclient.manager import Deps, VpnClientManager, ZapretView
from app.vpnclient.model import BypassProfile, Group, Server, Subscription
from app.vpnclient.process import ProcessError

PORT_BUSY = ("FATAL[0000] start service: start inbound/mixed[internal-in]: listen tcp 127.0.0.1:{port}: bind: "
             "An attempt was made to access a socket in a way forbidden by its access permissions.")


def server(name: str, sub: str | None = "s-1", *, network: str = "tcp", host: str | None = None,
           uuid: str = "11111111-2222-4333-8444-555555555555") -> Server:
    s = Server("vless", host or f"{name.lower()}.example.com", 443, name=name, uuid=uuid + name[:1],
               network=network, security="reality", tls={"sni": "www.example.com", "pbk": f"pbk-{name}", "sid": "ab"},
               sub=sub)
    s.id = s.key()
    return s


class FakeStore:
    def __init__(self, servers=(), subs=(), groups=(), selected=None):
        self._servers = {s.id: s for s in servers}
        self._subs = {s.id: s for s in subs}
        self._groups = list(groups)
        self._selected = selected
        self._latency: dict = {}
        self._speed: dict = {}
        self.calls: list[tuple] = []

    def load(self):
        pass

    def servers(self):
        return list(self._servers.values())

    def server(self, sid):
        return self._servers.get(sid)

    def subscriptions(self):
        return list(self._subs.values())

    def subscription(self, sid):
        return self._subs.get(sid)

    def groups(self):
        return list(self._groups)

    def selected(self):
        return self._selected

    def select(self, sid):
        self._selected = sid

    def latency(self):
        return dict(self._latency)

    def set_latency(self, sid, ms, error=None, *, save=True):
        self._latency[sid] = {"ms": ms, "at": 1.0, "error": error}
        self.calls.append(("set_latency", sid, save))

    def save(self):
        self.calls.append(("save",))

    def speed(self):
        return dict(self._speed)

    def set_speed(self, sid, mbps):
        self._speed[sid] = {"mbps": mbps, "at": 1.0}

    def add_subscription(self, sub):
        self._subs[sub.id] = sub

    def update_subscription(self, sid, **fields):
        self.calls.append(("update_subscription", sid, fields))
        self._subs[sid] = replace(self._subs[sid], **fields)

    def remove_subscription(self, sid):
        self._subs.pop(sid, None)
        self._servers = {k: v for k, v in self._servers.items() if v.sub != sid}

    def apply_decoded(self, sid, decoded):
        before = {k for k, v in self._servers.items() if v.sub == sid}
        for s in decoded.servers:
            s.sub = sid
            s.id = s.id or s.key()
            self._servers[s.id] = s
        after = {s.id for s in decoded.servers}
        for gone in before - after:
            self._servers.pop(gone)
        self._subs[sid] = replace(self._subs[sid], updated_at=1.0, error=None)
        return SimpleNamespace(added=len(after - before), removed=len(before - after))

    def add_servers(self, servers):
        added = [s for s in servers if s.id not in self._servers]
        for s in servers:
            self._servers[s.id] = s
        return SimpleNamespace(added=len(added), removed=0)

    def remove_server(self, sid):
        self._servers.pop(sid, None)

    def rename_server(self, sid, name):
        self._servers[sid].custom_name = name

    def export_data(self):
        return {"servers": [s.to_dict() for s in self._servers.values()]}

    def import_data(self, data):
        added = 0
        for item in data.get("servers", []):
            s = Server.from_dict(item)
            added += s.id not in self._servers
            self._servers[s.id] = s
        return SimpleNamespace(added=added, removed=0)


class FakeConfig:
    SELECTOR_PROXY = "proxy"
    SELECTOR_BYPASS = "bypass"

    def __init__(self):
        self.plans = []
        self.problems: list[str] = []
        self.last_tags: list[str] = []

    @staticmethod
    def tag(item_id: str) -> str:
        return f"t-{item_id}"

    @staticmethod
    def group_tag(group_id: str) -> str:
        return f"t-auto:{group_id}"

    def build_singbox(self, plan):
        self.plans.append(plan)
        self.last_tags = [self.tag(s.id) for s in plan.servers]
        return {"mode": plan.mode, "servers": [s.id for s in plan.servers], "selected": plan.selected,
                "ports": [plan.ports.proxy, plan.ports.internal, plan.ports.clash]}

    def build_xray(self, plan):
        helper = [sid for sid, engine in plan.engines.items() if engine == "xray"]
        return {"helper": helper, "interface": plan.physical_interface} if helper else None

    def build_delay(self, plan):
        self.last_tags = [self.tag(s.id) for s in plan.servers]
        return {"delay": [s.id for s in plan.servers]}

    def validate(self, cfg):
        return list(self.problems)


def _vkey(version: str) -> tuple[int, ...]:
    return tuple(int(x) for x in version.split("."))


class _Versions(dict):
    """{ядро: множество версий} — и, как engines.versions(name), список версий новыми первыми."""

    def __call__(self, name):
        return sorted(self[name], key=_vkey, reverse=True)


class FakeEngines:
    """Ядра на диске — в памяти. Загрузку, `check` и список релизов GitHub тест задаёт сам."""

    EngineError = real_engines.EngineError
    ReleaseRejected = real_engines.ReleaseRejected
    version_key = staticmethod(_vkey)

    def __init__(self, installed=("sing-box", "xray")):
        self.versions = _Versions({name: ({real_engines.CORES[name].version} if name in installed else set())
                                   for name in real_engines.CORES})
        self.origins: dict[tuple[str, str], str] = {}
        self.installs: list[tuple] = []
        self.checks: list[tuple] = []
        self.check_error: str | None = None
        self.check_errors: dict[str, str] = {}      # версия → FATAL только у неё
        self.install_errors: list[Exception] = []   # по одной на вызов install, затем — успех
        self.install_gate = None                    # threading.Event: install ждёт его (подкачка «идёт»)
        self.latest: dict[str, object] = {}         # ядро → Release | исключение для latest_release
        self.allowed = True
        self.check_gates: dict[str, object] = {}    # версия → threading.Event: check этой версии ждёт его
        self.check_hook = None                      # check(name, path, version) — до ответа (тест смотрит файл)
        self.verify_errors: set[str] = set()        # версии, чей exe «изменён или пропал»

    def spec(self, name):
        return real_engines.CORES[name]

    def background_allowed(self):
        return self.allowed

    def installed(self, name, version=None):
        have = self.versions[name]
        if version:
            return version if version in have else None
        return max(have, key=_vkey) if have else None

    def origin(self, name, version):
        return self.origins.get((name, version)) if version in self.versions[name] else None

    def install(self, name, *, progress=None, source=None, cancel=None, origin="github"):
        version = source.version if isinstance(source, real_engines.Release) else real_engines.CORES[name].version
        if progress:
            progress("downloading", 0.5)
        if self.install_gate is not None:
            self.install_gate.wait(10)
        error = self.install_errors.pop(0) if self.install_errors else None   # None в списке — эта попытка удалась
        if error is not None:
            raise error
        if progress:
            progress("installing", None)
        self.installs.append((name, version))
        self.versions[name].add(version)
        self.origins[(name, version)] = origin
        return version

    def latest_release(self, name):
        value = self.latest.get(name)
        if isinstance(value, Exception):
            raise value
        return value

    def verify(self, name, version=None):
        if version in self.verify_errors:
            raise real_engines.EngineError(f"{name}: файл exe изменён (контрольная сумма не совпала)")
        return Path(f"C:/fake/{name}/{version}/{real_engines.CORES[name].exe}")

    def version_dir(self, name, version):
        return Path(f"C:/fake/{name}/{version}")

    def check(self, name, path, *, version=None):
        gate = self.check_gates.get(version)
        if gate is not None:
            gate.wait(10)
        if self.check_hook is not None:
            self.check_hook(name, path, version)
        self.checks.append((name, version))
        error = self.check_errors.get(version) or self.check_error
        if error:
            raise real_engines.EngineError(error)
        return []

    def prune(self, name, keep):
        gone = [v for v in self.versions[name] if v not in keep]
        self.versions[name].difference_update(gone)
        return gone


class FakeRouting:
    TORRENT_APPS = ("qbittorrent.exe",)
    ADDITIONS = ("habr.com",)

    def __init__(self):
        self.calls = 0

    @staticmethod
    def preset_rule_sets(preset, *, games):
        return []

    def bypass_from_strategy(self, args, *, pack_dir, ipset_mode, out_dir):
        self.calls += 1
        return SimpleNamespace(profiles=[BypassProfile(network="tcp", ports=["443"])], voice_ports=["50000-50100"],
                               notes=["заметка"])

    @staticmethod
    def site_match(text):
        return text if "." in text else None

    # Какие наборы нужны своим спискам и «через VPN» — настоящие чистые функции.
    site_rule_sets = staticmethod(real_routing.site_rule_sets)
    vpn_required = staticmethod(real_routing.vpn_required)
    strict_level = staticmethod(real_routing.strict_level)


class FakeClient:
    """clash API работающего ядра в памяти."""

    def __init__(self, world, port, secret):
        self.world = world
        self.port = port
        self.selects: list[tuple[str, str]] = []
        self.closed = 0
        world.clients.append(self)

    def version(self, timeout=None):
        return "sing-box 1.14.3"

    def select(self, selector, name):
        if self.world.select_error:
            raise ClashError(self.world.select_error, 400)
        self.selects.append((selector, name))

    def close_connections(self):
        self.closed += 1

    def delay(self, name, url, timeout_ms):
        value = self.world.delays.get(name, 50)
        if not isinstance(value, int):
            raise ClashError("нет ответа за 5 с", 504)
        return value

    def group_delay(self, group, url, timeout_ms, *, members=10):
        """Все серверы последнего конфига (рабочего или временного); delays — подмена по тегу."""
        self.world.group_delays += 1
        tags = self.world.config.last_tags
        out = {tag: self.world.delays.get(tag, 50) for tag in tags}
        out.update({k: v for k, v in self.world.delays.items() if k not in out})
        return {k: v for k, v in out.items() if isinstance(v, int)}


class FakeSampler:
    def __init__(self, client, *, groups=()):
        self.groups = groups
        self.started = False
        self.stopped = False
        self.now: dict[str, str] = {}
        self.up = self.down = 0

    def start(self):
        self.started = True

    def stop(self, wait=0.0):
        self.stopped = True

    def totals(self):
        return self.up, self.down

    def snapshot(self):
        return {"stats": {"up": self.up, "down": self.down, "up_rate": 1.0, "down_rate": 2.0, "connections": 3},
                "history": [[1, 1.0, 2.0]], "now": dict(self.now)}


class FakeProcess:
    _pids = itertools.count(5000)

    def __init__(self, world, name, exe, args, *, cwd, on_exit=None, **_kw):
        self.world, self.name, self.exe, self.args, self.cwd, self.on_exit = world, name, exe, args, cwd, on_exit
        self.pid = None
        self._alive = False
        self.stopped = False
        self.tail: list[str] = ["INFO[0000] started"]
        world.processes.append(self)

    def start(self, ready, timeout):
        failure = self.world.start_failures.pop(0) if self.world.start_failures and self.name == "sing-box" else None
        self.world.events.append(("start", self.name))
        if failure is not None:
            raise ProcessError(f"{self.name} завершился при запуске (код 1)", code=1, tail=[failure])
        self.pid = next(self._pids)
        self._alive = True
        if not ready():
            raise ProcessError(f"{self.name} не ответил", tail=self.tail)

    def stop(self, soft=2.0):
        self.world.events.append(("stop", self.name))
        self._alive = False
        self.stopped = True
        return True

    def alive(self):
        return self._alive

    def crash(self, code=3, line="FATAL[0100] something broke"):
        self._alive = False
        self.tail.append(line)
        self.on_exit(code, list(self.tail))


class FakeSysProxy:
    def __init__(self, world):
        self.world = world
        self.applied = None
        self.unavailable: str | None = None

    def available(self):
        return self.unavailable

    def apply(self, host, port, override):
        self.world.events.append(("proxy-apply", f"{host}:{port}"))
        self.applied = f"{host}:{port}"

    def restore(self):
        self.world.events.append(("proxy-restore", self.applied))
        self.applied = None
        return {"restored": 1, "skipped": 0}

    def recover_after_crash(self, port):
        return None

    def owned_address(self):
        return self.applied

    def current(self):
        return []


class FakeKillSwitch:
    def __init__(self):
        self.active = False
        self.enabled_with = None

    def enable(self, *, tun_luid, allow_apps, allow_nets):
        self.active = True
        self.enabled_with = (tun_luid, list(allow_apps), list(allow_nets))

    def disable(self):
        self.active = False


class FakeResolver:
    def __init__(self):
        self.working = "https://1.1.1.1/dns-query"
        self.fail: set[str] = set()
        self.families: list[tuple[str, ...]] = []     # с какими семействами адресов спрашивали

    def resolve(self, host, preferred=None, *, families=("A",)):
        from app.vpnclient.manager import VpnClientError
        self.families.append(tuple(families))
        if host in self.fail:
            raise VpnClientError("нет ответа DNS")
        return "203.0.113." + str(sum(host.encode()) % 200 + 1)


@dataclass
class World:
    tmp: Path
    store: FakeStore
    clock_value: float = 1_760_000_000.0
    clients: list = field(default_factory=list)
    processes: list = field(default_factory=list)
    events: list = field(default_factory=list)
    notices: list = field(default_factory=list)
    alerts: dict = field(default_factory=dict)              # постоянные плашки Core: id → {level, text, action, page}
    start_failures: list = field(default_factory=list)      # строки хвоста для провальных запусков sing-box
    delays: dict = field(default_factory=dict)
    select_error: str | None = None
    exit_ok: bool = True
    view: ZapretView = field(default_factory=lambda: ZapretView(running=True, last_ok=True,
                                                                strategy_args=["--wf-tcp=443"],
                                                                pack_dir=Path("C:/pack"), ipset_mode="loaded"))
    before_core_calls: list = field(default_factory=list)
    changes: int = 0
    group_delays: int = 0

    def clock(self) -> float:
        return self.clock_value

    def advance(self, seconds: float) -> None:
        self.clock_value += seconds


def make_manager(tmp_path: Path, store: FakeStore, *, settings=None, is_admin: bool = True, **overrides):
    from app.settings import Settings
    world = World(tmp=tmp_path, store=store)
    config, engines, routing = FakeConfig(), FakeEngines(), FakeRouting()
    sysproxy, killswitch, resolver = FakeSysProxy(world), FakeKillSwitch(), FakeResolver()
    ports = itertools.count(30000)

    def free_port(preferred=None, *, host="127.0.0.1", avoid=frozenset(), span=20):
        if preferred:
            port = preferred
            while port in avoid:
                port += 1
            return port
        while True:
            port = next(ports)
            if port not in avoid:
                return port

    def exit_check(port, user, password, timeout):
        if not world.exit_ok:
            raise OSError("timed out")
        return {"ip": "203.0.113.5", "country": "NL", "date": None}

    deps = Deps(store=store, modules={"engines": engines, "config": config, "routing": routing},
                rules=SimpleNamespace(paths=lambda ids: {}, missing=lambda ids: [], status=lambda: {},
                                      update=lambda ids, force=False: None),
                sysproxy=sysproxy, killswitch=killswitch,
                process=lambda *a, **kw: FakeProcess(world, *a, **kw),
                clash=lambda port, secret: FakeClient(world, port, secret), sampler=FakeSampler,
                resolver=resolver, free_port=free_port, port_open=lambda port: True, taken_nets=lambda: [],
                physical_interface=lambda: "Ethernet", adapter_luid=lambda name: 42, exit_check=exit_check,
                direct_date=lambda: None, speed_check=lambda *a: 87.4, tcp_reach=lambda *a: 12.0,
                memory=lambda pid: pid * 1000, running_apps=lambda: [{"name": "game.exe", "path": "C:/g/game.exe"}],
                adapters=lambda: [], opener=lambda route: route, clock=world.clock, data_dir=tmp_path / "vpnclient")
    for key, value in overrides.items():
        setattr(deps, key, value)
    settings = settings or Settings(tmp_path / "settings.json")

    def before_core():
        world.before_core_calls.append((manager.own(), len([p for p in world.processes if p.alive()])))

    def on_change(*_a, **_k):
        world.changes += 1

    def alert(alert_id, level, text=None, action=None, page=None):
        if level is None:
            world.alerts.pop(alert_id, None)
        else:
            world.alerts[alert_id] = {"level": level, "text": text, "action": action, "page": page}

    manager = VpnClientManager(settings, lambda level, text, action=None: world.notices.append((level, text)),
                               is_admin, zapret_view=lambda: world.view, on_change=on_change,
                               before_core=before_core, deps=deps, alert=alert)
    world.manager, world.config, world.engines, world.routing = manager, config, engines, routing
    world.sysproxy, world.killswitch, world.resolver, world.settings = sysproxy, killswitch, resolver, settings
    return manager, world


def basic_store(*, xhttp: bool = False) -> FakeStore:
    a, b = server("Amsterdam"), server("Berlin")
    c = server("Helsinki", network="xhttp") if xhttp else server("Helsinki")
    other = server("Other", sub="s-2")
    fresh = World.clock_value       # обновлены только что: автообновление подписок в тестах не стартует
    subs = [Subscription(id="s-1", name="Мой VPN", url="https://sub.example.com/abc123TOKEN", added_at=fresh,
                         updated_at=fresh),
            Subscription(id="s-2", name="Второй", url="https://two.example.com/zzz999TOKEN", added_at=fresh,
                         updated_at=fresh)]
    groups = [Group(id="g-smart", sub="s-1", name="Умная локация", members=[a.id, b.id, c.id])]
    return FakeStore([a, b, c, other], subs, groups, selected=a.id)


def wait_for(cond, timeout: float = 10.0) -> bool:
    """Ожидание по условию (а не по часам)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if cond():
            return True
        time.sleep(0.01)
    return bool(cond())


class FakeSubscription:
    """subscription.py без сети: fetch отвечает по User-Agent, остальное — настоящее (UA, offer, HWID)."""

    def __init__(self):
        from app.vpnclient import subscription as real
        self.real = real
        self.SubscriptionError = real.SubscriptionError
        self.answers: dict[str, object] = {}     # UA → Decoded или SubscriptionError
        self.calls: list[tuple[str, object, str | None]] = []

    def __getattr__(self, name):
        return getattr(self.real, name)

    def fetch(self, url, *, user_agent, hwid=None, opener=None, **_kw):
        self.calls.append((user_agent, opener, hwid))
        answer = self.answers.get(user_agent)
        if isinstance(answer, Exception):
            raise answer
        return self.real.Fetched(200, {}, b"", url, user_agent=user_agent, hwid=bool(hwid))

    def decode(self, body, headers=None, *, sub_id=None):
        answer = self.answers.get(self.calls[-1][0])
        if answer is None:
            return self.real.Decoded(format="links")
        return answer
