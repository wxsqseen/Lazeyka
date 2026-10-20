"""Свой VPN: файлы правил — источники, проверка digest и git-blob, версия SRS, атомарная замена.

Сети нет: opener_for отдаёт подделку, которая отвечает по таблице адресов и записывает маршрут."""
import hashlib
import io
import json
import os
import time
import urllib.error
from pathlib import Path

import pytest

from app.vpnclient import rules as rules_mod
from app.updates.github import git_blob_sha1
from app.vpnclient.rules import RulesManager, source_for

RU = "geosite-category-ru"
REFILTER = "refilter-domains"


def srs(version: int = 1, body: bytes = b"payload") -> bytes:
    return b"SRS" + bytes([version]) + body


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class FakeNet:
    """Ответы по адресам: bytes или исключение; для каждого маршрута — свой набор."""

    def __init__(self):
        self.routes: dict[str, dict[str, object]] = {"direct": {}, "core": {}}
        self.calls: list[tuple[str, str]] = []
        self.available = {"direct", "core"}

    def set(self, url: str, value, route: str | None = None) -> None:
        for r in ([route] if route else ["direct", "core"]):
            self.routes[r][url] = value

    def opener_for(self, route: str):
        if route not in self.available:
            return None
        net = self

        class Opener:
            def open(self, request, timeout=None):
                url = request.full_url
                net.calls.append((route, url))
                value = net.routes[route].get(url)
                if value is None:
                    raise urllib.error.URLError("нет ответа")
                if isinstance(value, Exception):
                    raise value
                return FakeResponse(value if isinstance(value, bytes) else json.dumps(value).encode())

        return Opener()


def blob_source(net: FakeNet, set_id: str, data: bytes, *, sha: str | None = None, mirror: int = 0) -> None:
    m = source_for(set_id).mirrors[mirror]
    net.set(m.contents_api(), {"sha": sha or git_blob_sha1(data), "size": len(data)})
    net.set(m.raw_url(), data)


def release_source(net: FakeNet, set_id: str, data: bytes, *, digest: str | None = None) -> str:
    m = source_for(set_id).mirrors[0]
    url = f"https://github.com/{m.repo}/releases/download/v1/{m.path}"
    net.set(f"https://api.github.com/repos/{m.repo}/releases/latest", {
        "tag_name": "v1", "assets": [{"name": m.path, "browser_download_url": url, "size": len(data),
                                      "digest": digest or f"sha256:{hashlib.sha256(data).hexdigest()}"}]})
    net.set(url, data)
    return url


@pytest.fixture
def net():
    return FakeNet()


@pytest.fixture
def manager(tmp_path, net):
    return RulesManager(tmp_path / "rules", opener_for=net.opener_for)


def meta(manager) -> dict:
    return json.loads((manager.dir / "rules.json").read_text(encoding="utf-8"))["items"]


def test_git_blob_verified_and_installed(manager, net):
    data = srs(1, b"ru-domains")
    blob_source(net, RU, data)
    assert manager.update([RU]) == {RU: "updated"}
    assert manager.path(RU).read_bytes() == data
    entry = meta(manager)[RU]
    assert entry["hash"] == f"sha1:{git_blob_sha1(data)}" and entry["size"] == len(data) and entry["version"] == 1
    assert entry["source"] == "SagerNet/sing-geosite:rule-set/geosite-category-ru.srs"
    assert manager.paths([RU, "geoip-ru"]) == {RU: manager.path(RU)}
    assert manager.missing([RU, "geoip-ru"]) == ["geoip-ru"]


def test_digest_verified(manager, net):
    data = srs(3, b"refilter")
    release_source(net, REFILTER, data)
    assert manager.update([REFILTER]) == {REFILTER: "updated"}
    assert meta(manager)[REFILTER]["hash"] == f"sha256:{hashlib.sha256(data).hexdigest()}"


def test_hash_mismatch_keeps_old_file(manager, net):
    old = srs(1, b"old")
    blob_source(net, RU, old)
    manager.update([RU])
    blob_source(net, RU, srs(1, b"tampered"), sha=git_blob_sha1(srs(1, b"other")))
    assert manager.update([RU], force=True) == {RU: "failed"}
    assert manager.path(RU).read_bytes() == old
    assert "хеш" in meta(manager)[RU]["error"]
    release_source(net, REFILTER, srs(1), digest="sha256:" + "0" * 64)
    assert manager.update([REFILTER]) == {REFILTER: "failed"} and not manager.path(REFILTER).exists()


@pytest.mark.parametrize("data,needle", [(srs(6), "версии 6"), (b"PK\x03\x04zip", "не файл rule-set")])
def test_srs_header_and_version(manager, net, data, needle):
    blob_source(net, RU, data)
    assert manager.update([RU]) == {RU: "failed"}
    assert needle in meta(manager)[RU]["error"]
    assert not manager.path(RU).exists()


def test_atomic_replace(manager, net, monkeypatch):
    first, second = srs(1, b"first"), srs(1, b"second")
    blob_source(net, RU, first)
    manager.update([RU])
    calls = []
    real = os.replace
    monkeypatch.setattr(rules_mod.os, "replace", lambda a, b: (calls.append((Path(a).name, Path(b).name)), real(a, b)))
    blob_source(net, RU, second)
    assert manager.update([RU], force=True) == {RU: "updated"}
    assert (f"{RU}.srs.tmp", f"{RU}.srs") in calls
    assert manager.path(RU).read_bytes() == second
    assert sorted(p.name for p in manager.dir.iterdir()) == [f"{RU}.srs", "rules.json"], "ни .tmp, ни лишних копий"


def test_unchanged_and_fresh(manager, net):
    data = srs(1)
    blob_source(net, RU, data)
    assert manager.update([RU]) == {RU: "updated"}
    assert manager.update([RU]) == {RU: "fresh"}                       # не чаще раза в сутки
    downloads = len([c for c in net.calls if "raw.githubusercontent" in c[1]])
    assert manager.update([RU], force=True) == {RU: "same"}             # хеш тот же — не качаем
    assert len([c for c in net.calls if "raw.githubusercontent" in c[1]]) == downloads


def test_route_order_direct_core_jsdelivr(manager, net):
    data = srs(1)
    m = source_for(RU).mirrors[0]
    net.set(m.contents_api(), {"sha": git_blob_sha1(data)}, route="core")      # API напрямую недоступен
    net.set(m.jsdelivr_url(), data, route="core")                               # raw недоступен вовсе
    assert manager.update([RU]) == {RU: "updated"}
    assert net.calls == [("direct", m.contents_api()), ("core", m.contents_api()),
                         ("direct", m.raw_url()), ("core", m.raw_url()),
                         ("direct", m.jsdelivr_url()), ("core", m.jsdelivr_url())]
    net.available = set()
    assert manager.update([RU], force=True) == {RU: "failed"}
    assert "Нет маршрута" in meta(manager)[RU]["error"]


def test_one_source_failure_does_not_break_others(manager, net):
    blob_source(net, RU, srs(1, b"ru"))
    release_source(net, REFILTER, srs(1, b"refilter"))
    net.set("https://api.github.com/repos/itdoginfo/allow-domains/releases/latest",
            urllib.error.HTTPError("u", 403, "rate limited", {"X-RateLimit-Remaining": "0"}, None))
    result = manager.update([RU, "russia-inside", REFILTER, "no-such-set"])
    assert result == {RU: "updated", "russia-inside": "failed", REFILTER: "updated", "no-such-set": "unknown"}
    assert "ограничил" in meta(manager)["russia-inside"]["error"]
    assert set(manager.paths([RU, "russia-inside", REFILTER])) == {RU, REFILTER}


def test_fallback_mirror_then_back_to_primary(manager, net):
    primary, fallback = source_for("geoip-ru").mirrors
    data = srs(1, b"loyalsoldier")
    net.set(fallback.contents_api(), {"sha": git_blob_sha1(data)})
    net.set(fallback.raw_url(), data)
    assert manager.update(["geoip-ru"]) == {"geoip-ru": "updated"}
    assert meta(manager)["geoip-ru"]["source"] == fallback.label
    sager = srs(1, b"sagernet")
    blob_source(net, "geoip-ru", sager)
    assert manager.update(["geoip-ru"], force=True) == {"geoip-ru": "updated"}
    assert meta(manager)["geoip-ru"]["source"] == primary.label and manager.path("geoip-ru").read_bytes() == sager


def test_dynamic_sources_for_profiles():
    s = source_for("geosite-netflix")
    assert s.kind == "domain" and s.mirrors[0].raw_url() == \
        "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-netflix.srs"
    assert source_for("geoip-cn").mirrors[0].repo == "SagerNet/sing-geoip"
    assert source_for("geosite-../x") is None and source_for("something") is None
    for set_id, source in rules_mod.SOURCES.items():
        assert source.id == set_id and source.mirrors and source.kind in ("domain", "ip")


def test_status(manager, net):
    assert manager.status() == {"state": "idle", "updated_at": None, "stale": False, "items": []}
    blob_source(net, RU, srs(1))
    manager.update([RU, "russia-inside"])
    status = manager.status()
    assert status["state"] == "idle" and status["stale"] is False and status["updated_at"]
    items = {i["id"]: i for i in status["items"]}
    assert items[RU]["present"] is True and items[RU]["error"] is None and items[RU]["title"] == "Российские сайты"
    assert items["russia-inside"]["present"] is False and items["russia-inside"]["error"]
    data = json.loads((manager.dir / "rules.json").read_text(encoding="utf-8"))
    data["items"][RU]["updated_at"] = time.time() - 31 * 24 * 3600
    (manager.dir / "rules.json").write_text(json.dumps(data), encoding="utf-8")
    assert manager.status()["stale"] is True


def test_bad_file_on_disk_is_not_offered(manager):
    manager.dir.mkdir(parents=True)
    manager.path(RU).write_bytes(b"garbage")
    assert manager.paths([RU]) == {}
    manager.path(RU).write_bytes(srs(9))
    assert manager.paths([RU]) == {}
    with pytest.raises(rules_mod.RulesError):
        manager.path("../evil")
