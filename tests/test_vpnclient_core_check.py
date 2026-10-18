"""Свой VPN: статическая проверка сгенерированных конфигов настоящими ядрами.

Только при LAZEYKA_CORE_CHECK=1. Zip ядер из vendor/cores (кэш для тестов: в сборку ядра больше не
входят) или из LAZEYKA_CORES_DIR сверяются по SHA-256 и распаковываются во временную папку; `sing-box check --disable-color -c` и `xray run -test -c` ничего не поднимают —
страж conftest (фикстура core_static) пропускает только статические команды. Любой вывод `check`
(даже WARN при коде 0) — провал: значит, генератору нужна миграция (план 5.3).
"""
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from app import archive
from app.vpnclient import config, routeprofile, routing
from app.vpnclient.model import DnsChoice, TunOptions, engine_for
from app.zapret import lists, strategies
from tests.test_vpnclient_config import (CASES, MLKEM, _xray_plan, full_plan, make_plan, server,
                                         supported_servers)

pytestmark = pytest.mark.skipif(os.environ.get("LAZEYKA_CORE_CHECK") != "1",
                                reason="статическая проверка ядрами — только с LAZEYKA_CORE_CHECK=1")

ROOT = Path(__file__).resolve().parent.parent
CORES_SRC = Path(os.environ.get("LAZEYKA_CORES_DIR") or ROOT / "vendor" / "cores")
CORES = {
    "sing-box": ("sing-box-1.14.3-windows-amd64.zip",
                 "d8b86ef58936dba9230ec6a57ffa4243933f3c14ef4809828b6c553440ed1518", "sing-box.exe"),
    "xray": ("Xray-windows-64.zip", "d004c39288ce9ada487c6f398c7c545f7d749e44bdfdd59dbc9f865afba4e1ad", "xray.exe"),
}
CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
_COMPILED: dict[str, Path] = {}


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


@pytest.fixture(scope="module")
def cores(tmp_path_factory) -> dict[str, Path]:
    out = {}
    for name, (zip_name, digest, exe) in CORES.items():
        src = CORES_SRC / zip_name
        assert src.is_file(), f"нет {src}: положите официальный zip ядра в vendor/cores (README, «Сборка из исходников»)"
        assert sha256(src) == digest, f"{zip_name}: SHA-256 не совпал с закреплённым"
        target = tmp_path_factory.mktemp(name)
        archive.extract(src, target, max_unpacked=128 * 1024 * 1024, skip=lambda p: p.suffix == ".dat")
        out[name] = target / exe
        assert out[name].is_file()
    return out


def run(exe: Path, *args: str) -> tuple[int, str]:
    proc = subprocess.run([str(exe), *args], capture_output=True, text=True, encoding="utf-8", errors="replace",
                          timeout=120, cwd=str(exe.parent), creationflags=CREATE_NO_WINDOW)
    return proc.returncode, (proc.stdout + proc.stderr).strip()


def check_singbox(cores: dict[str, Path], cfg: dict, path: Path) -> str | None:
    """None — конфиг принят без единой строки вывода; иначе — что сказали validate() и ядро."""
    errors = config.validate(cfg)
    path.write_text(json.dumps(cfg, ensure_ascii=False, indent=1), encoding="utf-8")
    code, out = run(cores["sing-box"], "check", "--disable-color", "-c", str(path))
    if errors or code != 0 or out:
        return f"{path.name}: validate={errors} code={code} {out[:800]}"
    return None


def check_xray(cores: dict[str, Path], cfg: dict, path: Path) -> str | None:
    path.write_text(json.dumps(cfg, ensure_ascii=False, indent=1), encoding="utf-8")
    code, out = run(cores["xray"], "run", "-test", "-c", str(path))
    if code != 0 or "Configuration OK" not in out:
        return f"{path.name}: code={code} {out[-800:]}"
    return None


@pytest.fixture
def rule_files(core_static, cores, tmp_path_factory) -> dict[str, Path]:
    """Крошечные .srs для всех наборов пресетов и профиля — собраны `sing-box rule-set compile`."""
    if not _COMPILED:
        folder = tmp_path_factory.mktemp("srs")
        ids = [*routing.PRESET_RULE_SETS["except_ru"], *routing.PRESET_RULE_SETS["blocked"], routing.GAMES_DOWNLOAD,
               "geosite-youtube", "geosite-category-ads-all"]
        for set_id in ids:
            src = folder / f"{set_id}.json"
            rule = {"ip_cidr": ["192.0.2.0/24"]} if routing.rule_set_kind(set_id) == "ip" \
                else {"domain_suffix": [f"{set_id}.example"]}
            src.write_text(json.dumps({"version": 3, "rules": [rule]}), encoding="utf-8")
            code, out = run(cores["sing-box"], "rule-set", "compile", "--output", str(folder / f"{set_id}.srs"),
                            str(src))
            assert code == 0, out
            _COMPILED[set_id] = folder / f"{set_id}.srs"
    return dict(_COMPILED)


@pytest.mark.parametrize("mode", ["tun", "proxy", "local"])
def test_reference_servers_pass_check(core_static, cores, tmp_path, mode):
    failures = []
    for case in CASES:
        if case["engine"] is None:
            continue
        s = server(case["case"], encryption=MLKEM) if case["case"] == "vless_mlkem" else server(case["case"])
        plan = make_plan([s], mode)
        failures.append(check_singbox(cores, config.build_singbox(plan), tmp_path / f"{case['case']}.json"))
        helper = config.build_xray(plan)
        if helper is not None:
            failures.append(check_xray(cores, helper, tmp_path / f"{case['case']}-xray.json"))
    assert [f for f in failures if f] == []


@pytest.fixture
def pack(pack_dir, tmp_path) -> Path:
    target = tmp_path / pack_dir.name
    shutil.copytree(pack_dir, target)
    user = tmp_path / "user-lists"
    lists.ensure_user_lists(user)
    lists.save_user_list(user, "list-exclude-user.txt", "mail.discord.com\r\n")
    lists.sync_user_lists(user, target / "lists")
    lists.set_ipset_mode(target / "lists", "loaded")
    return target


def test_full_configs_from_real_pack_pass_check(core_static, cores, rule_files, pack, tmp_path):
    found = {s.id: s for s in strategies.discover(pack)[0]}
    profile_rules, _ = routeprofile.to_rules(routeprofile.parse_happ(json.dumps({
        "Name": "Тест", "DirectSites": ["geosite:category-ru", "domain:habr.com"], "DirectIp": ["geoip:private"],
        "ProxySites": ["geosite:youtube"], "ProxyIp": ["geoip:!ru"], "BlockSites": ["geosite:category-ads-all"]})))
    failures = []
    for strategy_id in ("general", "general (ALT5)", "general (EXP)"):
        out_dir = tmp_path / strategy_id
        res = routing.bypass_from_strategy(found[strategy_id].args(pack), pack_dir=pack, ipset_mode="loaded",
                                           out_dir=out_dir)
        for mode in ("tun", "proxy", "local"):
            for preset in ("all", "except_ru", "blocked"):
                plan = full_plan(mode, preset, bypass=res.profiles, voice_ports=res.voice_ports,
                                 rules_files=dict(rule_files), profile_rules=profile_rules, mux=True,
                                 tls_fragment=True, noises=True, fingerprint="firefox", proxy_listen="0.0.0.0",
                                 socks_udp=False, log_level="warning",
                                 tun=TunOptions(address4="172.31.255.253/30", address6="fdfe:dcba:9876::1/126",
                                                mtu=1400, exclude=["10.0.0.0/8", "224.0.0.0/4", "fe80::/10"]))
                name = f"{strategy_id}-{mode}-{preset}".replace(" ", "_")
                failures.append(check_singbox(cores, config.build_singbox(plan), out_dir / f"{name}.json"))
        plan = full_plan("tun", bypass=res.profiles, rules_files=dict(rule_files), noises=True, tls_fragment=True,
                         mux=True)
        failures.append(check_xray(cores, config.build_xray(plan), out_dir / "xray.json"))
        failures.append(check_singbox(cores, config.build_delay(plan), out_dir / "delay.json"))
    assert [f for f in failures if f] == []


def test_dns_variants_pass_check(core_static, cores, tmp_path):
    s = server("vless_reality_vision")
    failures = []
    for i, dns in enumerate([
        DnsChoice(remote="https://dns.google/dns-query", direct="https://dns.quad9.net/dns-query"),
        DnsChoice(remote="https://doh.example.net/dns-query", direct="https://doh.example.org/q",
                  ru="https://77.88.8.8/dns-query", strategy="prefer_ipv4"),
        DnsChoice(fakeip=True, strategy="ipv4_only"),
    ]):
        for mode in ("tun", "proxy"):
            plan = make_plan([s], mode, dns=dns, preset="except_ru", additions=list(routing.ADDITIONS))
            failures.append(check_singbox(cores, config.build_singbox(plan), tmp_path / f"dns-{i}-{mode}.json"))
    assert [f for f in failures if f] == []


def test_all_servers_with_groups_pass_check(core_static, cores, tmp_path):
    servers = supported_servers()
    plan = full_plan("tun", rules_files={}, via_zapret=False, profile_rules=[])
    plan.servers = servers
    plan.engines = {x.id: engine_for(x)[0] for x in servers}
    failures = [check_singbox(cores, config.build_singbox(plan), tmp_path / "all.json"),
                check_xray(cores, config.build_xray(plan), tmp_path / "all-xray.json"),
                check_singbox(cores, config.build_delay(plan), tmp_path / "all-delay.json")]
    assert [f for f in failures if f] == []


def test_forced_helper_protocols_pass_xray_test(core_static, cores, tmp_path):
    """UDP-шумы и фрагментация Xray: всё, что помощник умеет открыть, проходит `xray run -test`."""
    failures = []
    for case in CASES:
        if case["engine"] is None:
            continue
        s = server(case["case"], encryption=MLKEM) if case["case"] == "vless_mlkem" else server(case["case"])
        if engine_for(s, force_xray=True)[0] != "xray" or s.network == "http":
            continue
        plan = make_plan([s], noises=True, tls_fragment=True, mux=True)
        plan.engines = {s.id: "xray"}
        failures.append(check_xray(cores, config.build_xray(plan), tmp_path / f"{case['case']}.json"))
    assert len(failures) >= 15 and [f for f in failures if f] == []


def test_link_finalmask_passes_xray_test(core_static, cores, tmp_path):
    fragment = {"tcp": [{"type": "fragment", "settings": {"packets": "tlshello", "length": "100-200", "delay": "10-20"}}]}
    kcp_mask = {"udp": [{"type": "mkcp-original"}, {"type": "header-wechat"},
                        {"type": "noise", "settings": {"noise": [{"rand": "10-20", "delay": "10-16"}]}}]}
    servers = [server("vless_tls_ws", transport={"path": "/ws?ed=2048", "host": "cdn.example.com",
                                                 "finalmask": fragment}),
               server("vless_kcp", transport={"header_type": "wechat-video", "finalmask": kcp_mask})]
    assert all(engine_for(s)[0] == "xray" for s in servers)
    plan = make_plan(servers)
    assert check_singbox(cores, config.build_singbox(plan), tmp_path / "fm.json") is None
    assert check_xray(cores, config.build_xray(plan), tmp_path / "fm-xray.json") is None


def test_provider_outbound_as_is_passes_xray_test(core_static, cores, tmp_path):
    """Outbound провайдера «как есть» (в том числе ключи в другом регистре) с фрагментацией и шумами."""
    from app.vpnclient.model import Server
    provider = {"Tag": "p", "Protocol": "trojan",
                "Settings": {"Servers": [{"Address": "tr.example.com", "Port": 443, "Password": "secret"}]},
                "StreamSettings": {"Network": "ws", "Security": "tls", "TLSSettings": {"Fingerprint": "chrome"},
                                   "WSSettings": {"Path": "/w"}, "Sockopt": {"DialerProxy": "chain"}}}
    s = Server("trojan", "tr.example.com", 443, name="t", password="secret", network="ws", security="tls",
               source="xray-json", xray_outbound=provider)
    s.id = s.key()
    plan = make_plan([s], tls_fragment=True, noises=True)
    plan.engines = {s.id: "xray"}
    assert check_xray(cores, config.build_xray(plan), tmp_path / "as-is-case.json") is None
    assert check_xray(cores, config.build_xray(_xray_plan()), tmp_path / "as-is-snapshot.json") is None


def test_check_really_rejects_a_broken_config(core_static, cores, tmp_path):
    """Контроль: прогон умеет покраснеть — ядро отвергает конфиг с удалённым полем."""
    cfg = config.build_singbox(make_plan([server("vless_reality_vision")]))
    cfg["outbounds"].append({"type": "block", "tag": "block"})
    assert check_singbox(cores, cfg, tmp_path / "broken.json") is not None
    bad_xray = config.build_xray(make_plan([server("vless_kcp")]))
    bad_xray["outbounds"][1]["streamSettings"]["kcpSettings"]["seed"] = "s33d"   # Xray 26 убрал seed
    assert check_xray(cores, bad_xray, tmp_path / "broken-xray.json") is not None


def test_review_cases_pass_check(core_static, cores, rule_files, tmp_path):
    """Что добавлено по ревью, ядра принимают: отрицания и «не частные сети» в своих списках, DNS по процессу,
    строгий режим без списка «через VPN», исключения TUN без пулов Fake-IP при IPv6, интервал прыжков
    Hysteria2 (sing-box и Xray), помощник для Shadowsocks через WS/TLS, REALITY с ML-DSA-65, gRPC authority и
    Hysteria2 с finalmask провайдера."""
    import base64
    from app import settings
    from app.vpnclient import xrayjson
    from app.vpnclient.model import Server
    failures = []
    s = server("vless_reality_vision")
    lists_plan = make_plan([s], proxy_sites=["geoip:!ru", "geosite:!category-ru", "geosite:youtube"],
                           direct_sites=["geoip:!private"], proxy_apps=["Telegram.exe"], direct_apps=["steam.exe"],
                           rules_files=dict(rule_files))
    failures.append(check_singbox(cores, config.build_singbox(lists_plan), tmp_path / "lists.json"))
    strict = full_plan("tun", "blocked", proxy_sites=["geosite:netflix"], rules_files=dict(rule_files))
    assert config.missing_vpn_sets(strict, rule_files) == ["geosite-netflix"]
    failures.append(check_singbox(cores, config.build_singbox(strict), tmp_path / "strict.json"))
    tun6 = TunOptions(address4="172.31.255.253/30", address6="fdfe:dcba:9876::1/126",
                      exclude=list(settings.DEFAULT_EXCLUDE_NETS))
    v6 = make_plan([s], tun=tun6, dns=DnsChoice(fakeip=True, strategy="prefer_ipv4"))
    failures.append(check_singbox(cores, config.build_singbox(v6), tmp_path / "fakeip-v6.json"))
    hy = server("hysteria2_salamander_hop")
    hy.hy2 = dict(hy.hy2, hop_interval="10-40")
    failures.append(check_singbox(cores, config.build_singbox(make_plan([hy])), tmp_path / "hy2-hop.json"))
    forced = make_plan([hy])
    forced.engines = {hy.id: "xray"}
    failures.append(check_xray(cores, config.build_xray(forced), tmp_path / "hy2-hop-xray.json"))
    ss = Server("shadowsocks", "ss.example.com", 443, name="ss-ws", method="aes-128-gcm", password="pw",
                network="ws", security="tls", transport={"path": "/ss", "host": "cdn.example.com"},
                tls={"sni": "cdn.example.com"})
    pqv = base64.urlsafe_b64encode(bytes(i % 251 for i in range(1952))).decode().rstrip("=")
    reality = server("vless_reality_vision", tls=dict(server("vless_reality_vision").tls, pqv=pqv))
    grpc = server("trojan_grpc_default_port", transport={"service_name": "svc", "grpc_mode": "gun",
                                                         "authority": "front.example.net"})
    mask = {"udp": [{"type": "salamander", "settings": {"password": "obfs"}},
                    {"type": "noise", "settings": {"noise": [{"rand": "10-20", "delay": "10-16"}]}}],
            "quicParams": {"udpHop": {"ports": "20000-30000", "interval": "10-30"}}}
    [hy_mask] = xrayjson.parse({"outbounds": [{
        "tag": "hy", "protocol": "hysteria", "settings": {"version": 2, "address": "hy.example.net", "port": 443},
        "streamSettings": {"network": "hysteria", "security": "tls", "tlsSettings": {"serverName": "hy.example.net"},
                           "hysteriaSettings": {"version": 2, "auth": "secret"}, "finalmask": mask}}]}).servers
    helpers = [ss, reality, grpc, hy_mask]
    for item in helpers:
        item.id = item.key()
        assert engine_for(item)[0] == "xray", item.name
    plan = make_plan(helpers)
    failures.append(check_singbox(cores, config.build_singbox(plan), tmp_path / "helpers.json"))
    failures.append(check_xray(cores, config.build_xray(plan), tmp_path / "helpers-xray.json"))
    assert [f for f in failures if f] == []
