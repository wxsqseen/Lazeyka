"""Спасатель сервера: какие маскировки пробуются, как маскировка попадает в конфиг и переживает обновление
подписки, выбор самой быстрой из ответивших, самостоятельный запуск, когда живого сервера нет. Ядро не
запускается (подделки vpn_world), сеть не трогается."""
import copy

import pytest

from app.vpnclient import config, diagnose
from app.vpnclient.manager import rescue_variants
from app.vpnclient.model import Server, engine_for
from tests.fakes.vpn_world import FakeStore, basic_store, make_manager, server, wait_for


def test_variants_only_for_tls_over_tcp():
    reality = server("Amsterdam")
    names = [name for name, _ in rescue_variants(reality)]
    assert names == ["дробление TLS", "отпечаток firefox", "отпечаток safari", "отпечаток edge", "отпечаток random",
                     "дробление TLS и отпечаток firefox"]
    own = copy.deepcopy(reality)
    own.tls = dict(own.tls, fingerprint="firefox")
    assert "отпечаток firefox" not in [n for n, _ in rescue_variants(own)], "свой отпечаток сервера не пробуем"
    hy2 = Server("hysteria2", "hy.example.com", 443, password="p", security="tls")
    plain = Server("vless", "a.example.com", 80, uuid="u")
    assert rescue_variants(hy2) == [] and rescue_variants(plain) == []


def test_mask_in_singbox_and_xray_configs():
    from tests.test_vpnclient_config import make_plan
    tls = Server("trojan", "t.example.com", 443, password="p", security="tls", tls={"sni": "t.example.com",
                                                                                     "fingerprint": "chrome"})
    tls.id = tls.key()
    masked = copy.deepcopy(tls)
    masked.mask = {"fingerprint": "safari", "name": "отпечаток safari"}
    out = config.build_singbox(make_plan([masked]))["outbounds"]
    ob = next(o for o in out if o.get("tag") == config.tag(masked.id))
    assert ob["tls"]["utls"] == {"enabled": True, "fingerprint": "safari"}, "подобранный отпечаток важнее своего"
    masked.mask = {"fragment": True, "name": "дробление TLS"}
    masked.tls = dict(masked.tls, insecure=True)                      # только sing-box: дробит он сам
    ob = next(o for o in config.build_singbox(make_plan([masked]))["outbounds"] if o.get("tag") == config.tag(masked.id))
    assert ob["tls"]["fragment"] is True and ob["tls"]["record_fragment"] is True

    reality = server("Amsterdam")
    reality.mask = {"fragment": True, "name": "дробление TLS"}
    assert engine_for(reality) == ("xray", "через помощник Xray: дробление TLS"), "REALITY дробит только Xray"
    plan = make_plan([reality])
    xr = config.build_xray(plan)
    dial = next(o for o in xr["outbounds"] if o.get("protocol") == "freedom" and "fragment" in o.get("settings", {}))
    assert dial["settings"]["fragment"] == config.XRAY_RESCUE_FRAGMENT, "куски мельче имени сайта"
    reality.mask = {"fingerprint": "edge", "name": "отпечаток edge"}
    assert engine_for(reality)[0] == "sing-box"
    xr = config.build_xray(make_plan([reality], engines={reality.id: "xray"}))
    vless = next(o for o in xr["outbounds"] if o.get("protocol") == "vless")
    assert vless["streamSettings"]["realitySettings"]["fingerprint"] == "edge"


def test_store_keeps_mask_across_subscription_update(tmp_path):
    from app.vpnclient.store import ProfileStore
    from app.vpnclient.model import Subscription
    from app.vpnclient.subscription import Decoded
    store = ProfileStore(tmp_path / "profiles.json")
    store.add_subscription(Subscription(id="s-1", name="Провайдер", url="https://sub.example/x"))
    a = server("Amsterdam")
    store.apply_decoded("s-1", Decoded("links", servers=[copy.deepcopy(a)]))
    sid = store.servers()[0].id
    store.set_mask(sid, {"fragment": True, "name": "дробление TLS", "at": 1.0})
    renamed = copy.deepcopy(a)
    renamed.name = "Амстердам (новое имя у провайдера)"
    store.apply_decoded("s-1", Decoded("links", servers=[renamed]))
    kept = store.servers()[0]
    assert kept.id == sid and kept.mask == {"fragment": True, "name": "дробление TLS", "at": 1.0}
    assert ProfileStore(tmp_path / "profiles.json").servers()[0].mask["name"] == "дробление TLS", "на диске тоже"
    store.set_mask(sid, None)
    assert store.servers()[0].mask is None


def _rescue_world(tmp_path):
    m, world = make_manager(tmp_path, basic_store())
    m.start()
    assert m.wait_idle(5)
    sid = m._session.active
    return m, world, sid


def test_rescue_picks_fastest_answering_mask_and_reconnects(tmp_path):
    m, world, sid = _rescue_world(tmp_path)
    notes = []
    m.notify = lambda level, text: notes.append((level, text))
    trials = [f"t-{sid}~m{i}" for i in range(6)]
    world.delays.update({tag: None for tag in trials})
    world.delays.update({trials[0]: 240, trials[2]: 130, trials[5]: 90})   # сочетание быстрее, но выберется safari
    starts = len(world.processes)
    assert m.rescue(sid) == {}
    assert wait_for(lambda: not m.snapshot()["rescue"]["running"])
    snap = m.snapshot()
    assert snap["rescue"]["found"] == "отпечаток safari" and snap["rescue"]["server"] == sid
    stored = world.store.server(sid)
    assert stored.mask["fingerprint"] == "safari" and stored.mask["name"] == "отпечаток safari"
    assert next(s for s in snap["servers"] if s["id"] == sid)["mask"] == "отпечаток safari"
    assert notes and notes[-1][0] == "success" and "снова отвечает" in notes[-1][1]
    assert m.wait_idle(5) and len(world.processes) > starts, "VPN на этом сервере переподключился"
    assert next(s for s in m._session.plan.servers if s.id == sid).mask["fingerprint"] == "safari"

    assert m.unmask(sid) == {}
    assert world.store.server(sid).mask is None


def test_rescue_that_finds_nothing_says_so(tmp_path):
    m, world, sid = _rescue_world(tmp_path)
    notes = []
    m.notify = lambda level, text: notes.append((level, text))
    world.delays.update({f"t-{sid}~m{i}": None for i in range(6)})
    m.rescue(sid)
    assert wait_for(lambda: not m.snapshot()["rescue"]["running"])
    assert m.snapshot()["rescue"]["found"] is None and world.store.server(sid).mask is None
    assert notes[-1][0] == "warn" and "закрыл сам адрес" in notes[-1][1]
    with pytest.raises(Exception, match="Нет такого сервера"):
        m.rescue("nope")


def test_rescue_starts_itself_when_no_server_answers_and_provider_cuts(tmp_path):
    m, world, sid = _rescue_world(tmp_path)
    notes = []
    m.notify = lambda level, text: notes.append((level, text))
    m._explain_server = lambda *a, **k: diagnose.Reason("isp", "tls_blocked", "Провайдер обрывает соединение.",
                                                         "Попробуйте другой сервер.")
    world.delays.update({f"t-{s.id}": None for s in world.store.servers()})          # никто не отвечает
    world.delays.update({f"t-{sid}~m{i}": None for i in range(6)})
    world.delays[f"t-{sid}~m0"] = 300                                                  # помогло дробление
    assert m._switch_to_fastest(m._session) is False
    assert wait_for(lambda: m.snapshot()["rescue"]["found"] == "дробление TLS")
    assert world.store.server(sid).mask["fragment"] is True
    assert notes[-1][0] == "info", "сама сменила подключение — отчёт, а не тревога"
    world.store.server(sid).mask = None
    m._switch_to_fastest(m._session)
    assert m.snapshot()["rescue"]["found"] == "дробление TLS", "в этой сети уже пробовала — не повторяет"
    m.on_network_change()
    assert sid not in m._rescue_tried, "в новой сети попробует снова"
