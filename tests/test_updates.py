import os

import pytest

from app import paths
from app.updates import github
from app.updates.manager import remove_component_dirs

NETWORK = os.environ.get("LAZEYKA_NO_NETWORK") != "1"


def test_git_blob_sha1_matches_git():
    # git hash-object для "hello\n"
    assert github.git_blob_sha1(b"hello\n") == "ce013625030ba8dba906f756967f9e9ca394464a"


def test_remove_component_dirs_keeps_only_wanted(tmp_path, monkeypatch):
    # Скачанные ядра прокси не должны копиться: после обновления остаётся только текущее.
    root = tmp_path / "tgws"
    monkeypatch.setattr(paths, "TGWS_COMPONENTS_DIR", root)
    for version in ("1.11.1", "1.11.2", "1.11.3"):
        (root / version / "tgws_proxy").mkdir(parents=True)
        (root / version / "tgws_proxy" / "__init__.py").write_text("x", encoding="utf-8")
    (root / "stray.txt").write_text("не папка — не трогаем", encoding="utf-8")

    remove_component_dirs({"1.11.3"})

    assert {p.name for p in root.iterdir() if p.is_dir()} == {"1.11.3"}
    assert (root / "1.11.3" / "tgws_proxy" / "__init__.py").is_file()
    assert (root / "stray.txt").is_file()


def test_remove_component_dirs_without_folder_is_noop(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "TGWS_COMPONENTS_DIR", tmp_path / "missing")
    remove_component_dirs({"1.0.0"})  # не должно падать, если папки ещё нет


@pytest.mark.skipif(not NETWORK, reason="без сети")
def test_vendored_proxy_matches_upstream_tag():
    entries = {e["path"]: e["sha"] for e in github.tree("Flowseal/tg-ws-proxy", "v1.11.2")
               if e.get("type") == "blob" and e["path"].startswith("proxy/") and e["path"].endswith(".py")}
    vendored = paths.resource_dir() / "app" / "vendor" / "tgws_proxy"
    assert entries, "в дереве тега нет proxy/*.py"
    for path, sha in entries.items():
        local = vendored / path.split("/", 1)[1]
        assert local.is_file(), path
        assert github.git_blob_sha1(local.read_bytes()) == sha, path


@pytest.mark.skipif(not NETWORK, reason="без сети")
def test_latest_releases_have_checksums():
    zapret = github.latest_release("Flowseal/zapret-discord-youtube")
    zips = [a for a in zapret["assets"] if a["name"].endswith(".zip")]
    assert zips and all(a["sha256"] for a in zips)
    tg = github.latest_release("Flowseal/tg-ws-proxy")
    assert tg["tag"].startswith("v")
# добавляется в конец tests/test_updates.py
from pathlib import Path

from app import __version__
from app.settings import Settings
from app.updates.manager import UpdateManager, UpdateError, cleanup_stale_exe


class _FakeTg:
    core = None


class _FakeZapret:
    pack = None


def _mgr(tmp_path):
    return UpdateManager(Settings(tmp_path / "s.json"), _FakeZapret(), _FakeTg(), lambda *a: None, is_admin=True)


def _frozen_exe(tmp_path, monkeypatch, content=b"OLD"):
    exe = tmp_path / "Lazeyka.exe"
    exe.write_bytes(content)
    monkeypatch.setattr(paths, "IS_FROZEN", True)
    monkeypatch.setattr(paths, "exe_path", lambda: exe)
    return exe


def test_app_update_available_by_version(tmp_path):
    m = _mgr(tmp_path)
    assert m.current_version("app") == __version__
    m.releases["app"] = {"version": "99.0.0", "assets": []}
    assert m.is_available("app") is True
    m.releases["app"] = {"version": __version__, "assets": []}
    assert m.is_available("app") is False


def test_install_app_replaces_exe_and_keeps_backup(tmp_path, monkeypatch):
    exe = _frozen_exe(tmp_path, monkeypatch, b"OLD")

    def fake_download(url, dest, sha, *, progress=None, **kw):
        Path(dest).write_bytes(b"NEWVERSION")
        if progress:
            progress(10, 10)
        return "deadbeef"

    monkeypatch.setattr(github, "download", fake_download)
    m = _mgr(tmp_path)
    m.releases["app"] = {"version": "1.2.0",
                         "assets": [{"name": "Lazeyka.exe", "url": "http://x", "sha256": "DEADBEEF"}]}
    msg = m._install_app()
    assert exe.read_bytes() == b"NEWVERSION" and "1.2.0" in msg
    backup = m.settings.get("updates", "app_backup")
    assert backup and Path(backup).read_bytes() == b"OLD"
    assert not list(tmp_path.glob(".Lazeyka-*.new"))   # временный файл убран


def test_install_app_refused_without_checksum(tmp_path, monkeypatch):
    _frozen_exe(tmp_path, monkeypatch)
    m = _mgr(tmp_path)
    m.releases["app"] = {"version": "1.2.0", "assets": [{"name": "Lazeyka.exe", "url": "x", "sha256": None}]}
    with pytest.raises(UpdateError):
        m._install_app()


def test_install_app_refused_from_source(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "IS_FROZEN", False)
    m = _mgr(tmp_path)
    m.releases["app"] = {"version": "1.2.0", "assets": []}
    with pytest.raises(UpdateError):
        m._install_app()


def test_rollback_app_restores_backup(tmp_path, monkeypatch):
    exe = _frozen_exe(tmp_path, monkeypatch, b"NEW")
    backup = tmp_path / "Lazeyka.exe.old"
    backup.write_bytes(b"PREV")
    m = _mgr(tmp_path)
    m.settings.update(lambda d: d["updates"].__setitem__("app_backup", str(backup)))
    m._rollback_app()
    assert exe.read_bytes() == b"PREV" and m.settings.get("updates", "app_backup") is None


def test_rollback_app_without_backup_refused(tmp_path, monkeypatch):
    _frozen_exe(tmp_path, monkeypatch)
    m = _mgr(tmp_path)
    with pytest.raises(UpdateError):
        m._rollback_app()


def test_cleanup_stale_exe_keeps_rollback_backup(tmp_path, monkeypatch):
    exe = _frozen_exe(tmp_path, monkeypatch, b"cur")
    keep = tmp_path / "Lazeyka.exe.old"
    keep.write_bytes(b"backup")
    orphan = tmp_path / "Lazeyka.exe-abc123.old"
    orphan.write_bytes(b"orphan")
    partial = tmp_path / ".Lazeyka-deadbe.new"
    partial.write_bytes(b"partial")
    cleanup_stale_exe(str(keep))
    assert keep.is_file()           # резерв для отката сохранён
    assert not orphan.exists()      # осиротевший .old убран
    assert not partial.exists()     # недокачанный .new убран
    assert exe.is_file()


def test_app_rollback_flag_in_snapshot(tmp_path, monkeypatch):
    exe = _frozen_exe(tmp_path, monkeypatch)
    backup = tmp_path / "Lazeyka.exe.old"
    backup.write_bytes(b"prev")
    m = _mgr(tmp_path)
    app = next(i for i in m.snapshot()["items"] if i["id"] == "app")
    assert app["title"] == "Лазейка" and app["can_rollback"] is False
    m.settings.update(lambda d: d["updates"].__setitem__("app_backup", str(backup)))
    app = next(i for i in m.snapshot()["items"] if i["id"] == "app")
    assert app["can_rollback"] is True
