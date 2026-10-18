"""Свой VPN: общая модель — контракт между разбором, хранилищем, генератором и интерфейсом."""
import json
from pathlib import Path

import pytest

from app.vpnclient import guard
from app.vpnclient.model import (Group, RunPlan, Server, Subscription, engine_for, split_flag)

DATA = Path(__file__).resolve().parent / "data" / "vpnclient"
CASES = json.loads((DATA / "servers.json").read_text(encoding="utf-8"))["cases"]
SECRET_VALUES = ("11111111-2222-4333-8444-555555555555", "p@ss#w0rd+1", "obfspw", "tuicpw",
                 "wMTJ9bV1x6qRdnQk2eBcUJbQ8Wl0Jp0r3o0t5s6Y7m4=")


@pytest.mark.parametrize("case", CASES, ids=[c["case"] for c in CASES])
def test_reference_servers_roundtrip_and_engine(case):
    server = Server.from_dict(case["server"])
    assert server.to_dict() == case["server"]
    assert server.id == server.key()
    assert engine_for(server)[0] == case["engine"]
    public = server.public()
    assert public["supported"] is (case["engine"] is not None)
    blob = json.dumps(public, ensure_ascii=False)
    assert all(secret not in blob for secret in SECRET_VALUES)
    assert all(secret not in repr(server) for secret in SECRET_VALUES)


def test_key_ignores_name_but_not_credentials():
    a = Server.from_dict(CASES[0]["server"])
    b = Server.from_dict(CASES[0]["server"])
    b.name, b.custom_name = "Другое имя", "Моё"
    assert a.key() == b.key()
    b.uuid = "99999999-2222-4333-8444-555555555555"
    assert a.key() != b.key()


def test_split_flag():
    assert split_flag("\U0001F1F3\U0001F1F1 NL Reality") == ("NL", "NL Reality")
    assert split_flag("Без флага") == (None, "Без флага")
    assert split_flag("\U0001F1E9\U0001F1EA") == ("DE", "DE")


def test_engine_conflict_is_refused_with_reason():
    s = Server("vless", "example.com", 443, network="xhttp", security="tls", tls={"insecure": True})
    engine, reason = engine_for(s)
    assert engine is None and "Xray" in reason and "sing-box" in reason


def test_force_xray_for_noises():
    s = Server("vless", "example.com", 443, security="reality", tls={"pbk": "x"})
    assert engine_for(s) == ("sing-box", None)
    assert engine_for(s, force_xray=True)[0] == "xray"
    wg = Server("wireguard", "203.0.113.40", 51820)
    assert engine_for(wg, force_xray=True)[0] == "sing-box"


def test_subscription_and_group_roundtrip():
    sub = Subscription(id="s-1", name="Мой VPN", url="https://example.com/sub/SECRET-TOKEN",
                       userinfo={"upload": 1, "download": 2, "total": 10, "expire": 0})
    assert Subscription.from_dict(sub.to_dict()) == sub
    public = sub.public(servers=3)
    assert "SECRET-TOKEN" not in json.dumps(public) and "SECRET-TOKEN" not in repr(sub)
    assert public["userinfo"]["used"] == 3
    group = Group(id="g-1", sub="s-1", name="Умная локация", members=["a", "b"])
    assert Group.from_dict(group.to_dict()) == group


def test_runplan_defaults_are_independent():
    a = RunPlan(mode="tun", servers=[], selected="x")
    b = RunPlan(mode="proxy", servers=[], selected="y")
    a.direct_apps.append("game.exe")
    assert b.direct_apps == [] and a.ports is not b.ports


def test_guard_blocks_only_when_flag_set(monkeypatch):
    monkeypatch.setenv("LAZEYKA_NO_CORE", "1")
    with pytest.raises(guard.CoreBlocked):
        guard.ensure_allowed("запуск ядра")
    monkeypatch.setenv("LAZEYKA_NO_CORE", "0")
    guard.ensure_allowed("запуск ядра")
    assert guard.is_static(["check", "-c", "x.json"]) and not guard.is_static(["run", "-c", "x.json"])


def test_tests_cannot_start_a_core(tmp_path):
    import subprocess
    fake = tmp_path / "sing-box.exe"
    fake.write_bytes(b"MZ")
    with pytest.raises(guard.CoreBlocked):
        subprocess.Popen([str(fake), "run", "-c", "config.json"])


def test_state_sample_is_valid_json():
    sample = json.loads((Path(__file__).resolve().parent.parent / "app" / "ui" / "mock-vpnclient-state.json")
                        .read_text(encoding="utf-8"))
    assert sample["mode"] in ("tun", "proxy", "local") and isinstance(sample["servers"], list)


# ------------------------------------------------------------ выбор ядра: что sing-box потерял бы молча

def test_reality_with_mldsa65_goes_to_xray():
    s = Server("vless", "r.example.com", 443, uuid="u", security="reality", tls={"pbk": "x", "sni": "r.example.com"})
    assert engine_for(s) == ("sing-box", None)
    s.tls["pqv"] = "ML-DSA-65-ключ"                    # ключа проверки у sing-box нет — исчез бы
    assert engine_for(s) == ("xray", "через помощник Xray: REALITY с подписью ML-DSA-65")


def test_grpc_authority_other_than_sni_goes_to_xray():
    s = Server("vless", "g.example.com", 443, uuid="u", network="grpc", security="tls", tls={"sni": "g.example.com"},
               transport={"service_name": "svc", "grpc_mode": "gun", "authority": "front.example.net"})
    assert engine_for(s) == ("xray", "через помощник Xray: gRPC authority")
    s.transport["authority"] = "G.Example.com"          # sing-box и так шлёт имя TLS — помощник не нужен
    assert engine_for(s) == ("sing-box", None)
    plain = Server("vless", "203.0.113.5", 80, uuid="u", network="grpc", transport={"authority": "g.example.com"})
    assert engine_for(plain)[0] == "xray"               # без TLS sing-box шлёт адрес — а это уже IP


def test_provider_fragment_prefers_xray_and_falls_back_to_singbox():
    s = Server("trojan", "t.example.com", 443, password="p", security="tls",
               fragment={"packets": "tlshello", "length": "10-20", "interval": "10-20"})
    assert engine_for(s) == ("xray", "через помощник Xray: фрагментация провайдера")
    s.tls = {"insecure": True}                          # Xray такой сервер не откроет — фрагментирует sing-box
    assert engine_for(s) == ("sing-box", None)


def test_shadowsocks_and_socks_with_transport_need_xray():
    ss = Server("shadowsocks", "s.example.com", 443, method="aes-128-gcm", password="p", network="ws",
                security="tls", transport={"path": "/ss"})
    engine, reason = engine_for(ss)
    assert engine == "xray" and "Shadowsocks через ws/TLS" in reason
    ss.plugin = {"name": "obfs-local", "opts": {}}
    assert engine_for(ss)[0] is None                    # плагин — только sing-box, транспорт — только Xray
    socks = Server("socks", "k.example.com", 443, security="tls")
    engine, reason = engine_for(socks)
    assert engine is None and "SOCKS" in reason         # свой выход SOCKS помощник не собирает
    socks.xray_outbound = {"protocol": "socks", "settings": {}}
    assert engine_for(socks)[0] == "xray"
    assert engine_for(Server("socks", "k.example.com", 1080)) == ("sing-box", None)
    assert engine_for(Server("shadowsocks", "s.example.com", 8388, method="aes-128-gcm", password="p")) == \
        ("sing-box", None)


def test_wireguard_key_includes_client_identity():
    peer = {"peer_public_key": "PUB", "local_address": ["10.0.0.2/32", "fd00::2/128"]}
    a = Server("wireguard", "203.0.113.40", 51820, wg={**peer, "private_key": "A"})
    b = Server("wireguard", "203.0.113.40", 51820, wg={**peer, "private_key": "B"})
    c = Server("wireguard", "203.0.113.40", 51820, wg={**peer, "private_key": "A", "local_address": ["10.0.0.3/32"]})
    assert len({a.key(), b.key(), c.key()}) == 3        # один сервер, три клиента — три записи
    same = Server("wireguard", "203.0.113.40", 51820, name="другое имя",
                  wg={**peer, "private_key": "A", "local_address": "fd00::2/128, 10.0.0.2/32"})
    assert same.key() == a.key()                        # порядок и запись адресов не важны
