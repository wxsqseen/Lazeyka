"""Свой VPN вживую: настоящие sing-box и Xray, но без TUN, системного прокси и kill switch.

Только с LAZEYKA_CORE_E2E=1 (фикстура core_live). Серверы — локальные экземпляры тех же ядер на 127.0.0.1;
клиент — настоящий VpnClientManager в режиме «Только локальный прокси». Выход серверов в интернет идёт
обычным путём, маршруты и адаптеры ПК не меняются — так можно гонять рядом с работающим чужим VPN.
Нужны zip ядер в vendor/cores (или LAZEYKA_CORES_DIR) и интернет.
"""
from __future__ import annotations

import base64
import json
import os
import shutil
import socket
import subprocess
import urllib.parse
from pathlib import Path

import pytest

from app import paths
from app.filehash import sha256_file
from app.settings import Settings
from app.vpnclient import engines, manager as mgr, sysproxy
from app.vpnclient.manager import VpnClientManager, ZapretView
from tests.fakes.vpn_world import wait_for

ROOT = Path(__file__).resolve().parents[1]
CORES = Path(os.environ.get("LAZEYKA_CORES_DIR") or ROOT / "vendor" / "cores")
SID = "6ba85179e30d4fc2"
WORKING = ["Reality", "WS", "Trojan", "SS2022", "VMess", "Hy2", "TUIC", "XHTTP"]
BROKEN = ["Closed", "BadKey", "BadUser"]

pytestmark = pytest.mark.core_e2e


def _free(kind=socket.SOCK_STREAM) -> int:
    with socket.socket(socket.AF_INET, kind) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _local_download(url, dest, sha256, *, cancel=None, progress=None):
    shutil.copyfile(CORES / url.rsplit("/", 1)[1], dest)
    digest = sha256_file(Path(dest))
    assert digest == sha256.lower()
    return digest


def _out(exe: Path, *args: str) -> str:
    return subprocess.run([str(exe), *args], capture_output=True, text=True, timeout=30,
                          creationflags=subprocess.CREATE_NO_WINDOW).stdout


def _accepts(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.5):
            return True
    except OSError:
        return False


def _servers(tmp: Path, sb: Path, xr: Path) -> tuple[list[subprocess.Popen], dict[str, str], list[int]]:
    """Локальные серверы, ссылки на них (рабочие и заведомо сломанные) и TCP-порты, которые они слушают."""
    uid, bad_uid = _out(sb, "generate", "uuid").strip(), _out(sb, "generate", "uuid").strip()
    keys = dict(line.split(": ", 1) for line in _out(sb, "generate", "reality-keypair").strip().splitlines())
    other = dict(line.split(": ", 1) for line in _out(sb, "generate", "reality-keypair").strip().splitlines())
    pair = _out(sb, "generate", "tls-keypair", "localhost")
    end = pair.index("-----END CERTIFICATE-----") + len("-----END CERTIFICATE-----")
    (tmp / "cert.pem").write_text(pair[:end] + "\n", encoding="ascii")
    (tmp / "key.pem").write_text(pair[pair.index("-----BEGIN PRIVATE KEY-----"):], encoding="ascii")
    ss_key = _out(sb, "generate", "rand", "16", "--base64").strip()
    password = "e2e-" + uid[:8]
    tls = {"enabled": True, "server_name": "localhost",
           "certificate_path": str(tmp / "cert.pem"), "key_path": str(tmp / "key.pem")}
    reality = {"enabled": True, "server_name": "www.microsoft.com",
               "reality": {"enabled": True, "handshake": {"server": "www.microsoft.com", "server_port": 443},
                           "private_key": keys["PrivateKey"], "short_id": [SID]}}
    p = {n: _free() for n in ("reality", "reality2", "ws", "trojan", "ss", "vmess", "closed", "xhttp")}
    p["hy2"], p["tuic"] = _free(socket.SOCK_DGRAM), _free(socket.SOCK_DGRAM)
    inbounds = [
        {"type": "vless", "tag": "reality", "listen": "127.0.0.1", "listen_port": p["reality"],
         "users": [{"uuid": uid, "flow": "xtls-rprx-vision"}], "tls": reality},
        {"type": "vless", "tag": "reality2", "listen": "127.0.0.1", "listen_port": p["reality2"],
         "users": [{"uuid": uid, "flow": "xtls-rprx-vision"}], "tls": reality},
        {"type": "vless", "tag": "ws", "listen": "127.0.0.1", "listen_port": p["ws"], "users": [{"uuid": uid}],
         "transport": {"type": "ws", "path": "/ws"}},
        {"type": "trojan", "tag": "trojan", "listen": "127.0.0.1", "listen_port": p["trojan"],
         "users": [{"password": password}], "tls": tls},
        {"type": "shadowsocks", "tag": "ss", "listen": "127.0.0.1", "listen_port": p["ss"],
         "method": "2022-blake3-aes-128-gcm", "password": ss_key},
        {"type": "vmess", "tag": "vmess", "listen": "127.0.0.1", "listen_port": p["vmess"],
         "users": [{"uuid": uid, "alterId": 0}]},
        {"type": "hysteria2", "tag": "hy2", "listen": "127.0.0.1", "listen_port": p["hy2"],
         "users": [{"password": password}], "tls": {**tls, "alpn": ["h3"]}},
        {"type": "tuic", "tag": "tuic", "listen": "127.0.0.1", "listen_port": p["tuic"],
         "users": [{"uuid": uid, "password": password}], "congestion_control": "bbr",
         "tls": {**tls, "alpn": ["h3"]}},
    ]
    (tmp / "server-sb.json").write_text(json.dumps({"log": {"level": "warn"}, "inbounds": inbounds,
                                                     "outbounds": [{"type": "direct"}]}), encoding="utf-8")
    # REALITY на Xray-сервере с целью www.microsoft.com рукопожатие не проходит — берём Cloudflare.
    xray = {"log": {"loglevel": "warning"},
            "inbounds": [{"listen": "127.0.0.1", "port": p["xhttp"], "protocol": "vless",
                          "settings": {"clients": [{"id": uid}], "decryption": "none"},
                          "streamSettings": {"network": "xhttp", "xhttpSettings": {"path": "/xh"},
                                             "security": "reality",
                                             "realitySettings": {"target": "www.cloudflare.com:443",
                                                                 "serverNames": ["www.cloudflare.com"],
                                                                 "privateKey": keys["PrivateKey"],
                                                                 "shortIds": [SID]}}}],
            "outbounds": [{"protocol": "freedom"}]}
    (tmp / "server-xray.json").write_text(json.dumps(xray), encoding="utf-8")
    flags = subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP
    procs = [subprocess.Popen([str(sb), "run", "-c", str(tmp / "server-sb.json")], creationflags=flags,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL),
             subprocess.Popen([str(xr), "run", "-c", str(tmp / "server-xray.json")], creationflags=flags,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)]
    q = lambda v: urllib.parse.quote(v, safe="")  # noqa: E731
    pub, other_pub = keys["PublicKey"], other["PublicKey"]
    vmess = base64.b64encode(json.dumps({"v": "2", "ps": "VMess", "add": "127.0.0.1", "port": str(p["vmess"]),
                                         "id": uid, "aid": "0", "net": "tcp", "type": "none",
                                         "tls": ""}).encode()).decode()
    ss_user = base64.urlsafe_b64encode(f"2022-blake3-aes-128-gcm:{ss_key}".encode()).decode().rstrip("=")
    reality_q = f"type=tcp&security=reality&sid={SID}&sni=www.microsoft.com&fp=chrome&flow=xtls-rprx-vision"
    links = {
        "Reality": f"vless://{uid}@127.0.0.1:{p['reality']}?{reality_q}&pbk={pub}#Reality",
        "WS": f"vless://{uid}@127.0.0.1:{p['ws']}?type=ws&path={q('/ws')}&security=none#WS",
        "Trojan": f"trojan://{password}@127.0.0.1:{p['trojan']}?security=tls&sni=localhost&allowInsecure=1#Trojan",
        "SS2022": f"ss://{ss_user}@127.0.0.1:{p['ss']}#SS2022",
        "VMess": f"vmess://{vmess}",
        "Hy2": f"hysteria2://{password}@127.0.0.1:{p['hy2']}?sni=localhost&insecure=1#Hy2",
        "TUIC": f"tuic://{uid}:{password}@127.0.0.1:{p['tuic']}?sni=localhost&alpn=h3&insecure=1"
                f"&congestion_control=bbr#TUIC",
        "XHTTP": f"vless://{uid}@127.0.0.1:{p['xhttp']}?type=xhttp&path={q('/xh')}&security=reality&pbk={pub}"
                 f"&sid={SID}&sni=www.cloudflare.com&fp=chrome#XHTTP",
        "Closed": f"vless://{uid}@127.0.0.1:{p['closed']}?type=tcp&security=none#Closed",
        "BadKey": f"vless://{uid}@127.0.0.1:{p['reality2']}?{reality_q}&pbk={other_pub}#BadKey",
        "BadUser": f"vless://{bad_uid}@127.0.0.1:{p['ws']}?type=ws&path={q('/ws')}&security=none#BadUser",
    }
    # Готовность по портам: у sing-box — без REALITY (на пустое соединение он дозванивается до сайта-маски),
    # входы он поднимает все разом; у Xray вход один.
    listening = [p[n] for n in ("ws", "trojan", "ss", "vmess", "xhttp")]
    return procs, links, listening


@pytest.fixture
def live(core_live, tmp_path, monkeypatch):
    """Ядра во временной папке теста, локальные серверы и менеджер в режиме «Только локальный прокси»."""
    def forbidden(*_a, **_k):
        raise AssertionError("живой прогон не должен трогать системный прокси или kill switch")
    monkeypatch.setattr(sysproxy.SysProxy, "apply", forbidden)
    monkeypatch.setattr(mgr.VpnClientManager, "_enable_killswitch", forbidden)
    monkeypatch.setattr(paths, "COMPONENTS_DIR", tmp_path / "components")     # ~120 МБ ядер — в tmp_path,
    monkeypatch.setattr(paths, "TMP_DIR", tmp_path / "tmp")                   # его pytest убирает сам
    for name in ("sing-box", "xray"):
        if not engines.installed(name):
            engines.install(name, download=_local_download)
    sb = engines.version_dir("sing-box", engines.installed("sing-box")) / "sing-box.exe"
    xr = engines.version_dir("xray", engines.installed("xray")) / "xray.exe"
    procs, links, ports = _servers(tmp_path, sb, xr)
    settings = Settings(tmp_path / "settings.json")
    settings.update(lambda d: d["vpnclient"].update(mode="local", via_zapret=False, kill_switch=False,
                                                     core_auto_update=False))
    m = VpnClientManager(settings, lambda *a, **k: None, True, zapret_view=ZapretView,
                         on_change=lambda *a, **k: None)
    try:
        started = wait_for(lambda: any(p.poll() is not None for p in procs)
                           or all(_accepts(port) for port in ports), 30)
        assert started and all(p.poll() is None for p in procs), "локальные серверы не запустились"
        m.init()
        m.import_text("\n".join(links.values()))
        assert wait_for(lambda: not m.snapshot()["import"]["running"], 60)
        yield m, {s["name"]: s["id"] for s in m.snapshot()["servers"]}
    finally:
        m.shutdown()
        for proc in procs:
            proc.terminate()
            proc.wait(10)


def test_live_protocols_switch_speed_latency_and_failures(live):
    m, ids = live
    assert set(WORKING + BROKEN) <= set(ids), f"импортированы не все: {sorted(ids)}"
    report = []
    for name in WORKING:
        m.select(ids[name])
        m.start()
        snap = m.snapshot()
        assert snap["mode"] == "local" and snap["listen"]
        report.append((name, snap["status"], snap["verified"], (snap.get("exit") or {}).get("ip"), snap.get("error")))
        if name == "Reality" and snap["verified"]:
            for other in ("WS", "Trojan"):                       # смена внутри конфига — без переподключения
                m.select(ids[other])
                assert m.snapshot()["status"] == "running"
            m.select(ids[name])
            m.speedtest(None)
            assert wait_for(lambda: not m.snapshot()["speed"]["running"], 90)
            assert (m.snapshot()["speed"]["mbps"] or 0) > 0
        m.stop()
        assert m.snapshot()["status"] == "stopped"
    bad = [r for r in report if not (r[1] == "running" and r[2] and r[3])]
    assert not bad, f"не подключились: {bad}"

    for _ in range(2):        # первый замер греет DNS локальных серверов (у настоящих он тёплый)
        m.latency(None)
        assert wait_for(lambda: not m.snapshot()["latency"]["running"], 120)
    latency = {s["name"]: s["latency"] for s in m.snapshot()["servers"]}
    assert all(latency[n]["ms"] for n in WORKING), latency
    assert all(not latency[n]["ms"] and latency[n]["error"] for n in BROKEN), latency
    # Причина и сторона — по настоящим отказам: закрытый порт и неверные ключи — у VPN-провайдера.
    assert (latency["Closed"]["reason"] or {}).get("code") == "port_closed", latency["Closed"]
    assert all((latency[n]["reason"] or {}).get("side") == "provider" for n in BROKEN), latency

    for name in BROKEN:
        m.select(ids[name])
        try:
            m.start()
        except Exception:  # noqa: BLE001 — отказ запуска тоже честный ответ; проверяем состояние
            pass
        snap = m.snapshot()
        assert not snap["verified"] and snap["error"], (name, snap["status"], snap["error"])
        assert (snap.get("diagnosis") or {}).get("side") == "provider", (name, snap.get("diagnosis"))
        m.stop()
