import hashlib

import pytest

from app import paths
from app.updates import github
from app.updates.manager import remove_component_dirs


def test_git_blob_sha1_matches_git():
    # git hash-object для "hello\n" и для пустого файла
    assert github.git_blob_sha1(b"hello\n") == "ce013625030ba8dba906f756967f9e9ca394464a"
    assert github.git_blob_sha1(b"") == "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"


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


@pytest.mark.network
def test_vendored_proxy_matches_upstream_tag():
    entries = {e["path"]: e["sha"] for e in github.tree("Flowseal/tg-ws-proxy", "v1.11.2")
               if e.get("type") == "blob" and e["path"].startswith("proxy/") and e["path"].endswith(".py")}
    vendored = paths.resource_dir() / "app" / "vendor" / "tgws_proxy"
    assert entries, "в дереве тега нет proxy/*.py"
    for path, sha in entries.items():
        local = vendored / path.split("/", 1)[1]
        assert local.is_file(), path
        assert github.git_blob_sha1(local.read_bytes()) == sha, path


@pytest.mark.network
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
from app.updates.manager import UpdateManager, UpdateError, settle_app_files


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
    m.releases["app"] = {"version": "99.0.0", "assets": [{"name": "Lazeyka.exe", "sha256": "DEADBEEF",
                         "url": "https://github.com/wxsqseen/Lazeyka/releases/download/v99.0.0/Lazeyka.exe"}]}
    msg = m._install_app()
    assert exe.read_bytes() == b"NEWVERSION" and "99.0.0" in msg
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


def test_settle_moves_backup_out_of_exe_folder(tmp_path, monkeypatch):
    """Прежняя версия после обновления не остаётся рядом с exe: при запуске новой она переезжает в
    backups папки данных, а временные копии (в том числе после отката) удаляются."""
    (tmp_path / "app").mkdir()
    exe = _frozen_exe(tmp_path / "app", monkeypatch, b"cur")
    backups = tmp_path / "data" / "backups"
    monkeypatch.setattr(paths, "BACKUPS_DIR", backups)
    old = exe.with_name("Lazeyka.exe.old")
    old.write_bytes(b"backup")
    leftovers = [exe.with_name("Lazeyka.exe-abc123.old"), exe.with_name(".Lazeyka-deadbe.new"),
                 exe.with_name(".Lazeyka-1234abcd.old")]          # последний — от отката
    for f in leftovers:
        f.write_bytes(b"x")
    settings = Settings(tmp_path / "s.json")
    settings.update(lambda d: d["updates"].__setitem__("app_backup", str(old)))
    settle_app_files(settings)
    moved = backups / "Lazeyka-previous.exe"
    assert moved.read_bytes() == b"backup" and settings.get("updates", "app_backup") == str(moved)
    assert sorted(f.name for f in exe.parent.iterdir()) == ["Lazeyka.exe"]
    settle_app_files(settings)                     # следующий запуск: копия в backups не трогается
    assert moved.is_file()


def test_settle_keeps_backup_when_data_folder_is_read_only(tmp_path, monkeypatch):
    exe = _frozen_exe(tmp_path, monkeypatch, b"cur")
    monkeypatch.setattr(paths, "BACKUPS_DIR", tmp_path / "data" / "backups")
    old = exe.with_name("Lazeyka.exe.old")
    old.write_bytes(b"backup")
    settings = Settings(tmp_path / "s.json")
    settings.update(lambda d: d["updates"].__setitem__("app_backup", str(old)))
    import shutil as real_shutil

    def denied(*a, **kw):
        raise PermissionError("нет прав")
    monkeypatch.setattr(real_shutil, "copy2", denied)
    settle_app_files(settings)
    assert old.read_bytes() == b"backup" and settings.get("updates", "app_backup") == str(old)


def test_rollback_from_data_backups(tmp_path, monkeypatch):
    exe = _frozen_exe(tmp_path, monkeypatch, b"NEW")
    backups = tmp_path / "data" / "backups"
    backups.mkdir(parents=True)
    backup = backups / "Lazeyka-previous.exe"
    backup.write_bytes(b"PREV")
    m = _mgr(tmp_path)
    m.settings.update(lambda d: d["updates"].__setitem__("app_backup", str(backup)))
    m._rollback_app()
    assert exe.read_bytes() == b"PREV" and not backup.exists()
    assert m.settings.get("updates", "app_backup") is None
    assert not list(tmp_path.glob(".Lazeyka-*.new"))        # копия для замены убрана


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


# ------------------------------------------------------------ ядра своего VPN и явный маршрут

import http.server
import threading
import urllib.request

from app.updates import manager as updates_manager
from app.vpnclient import engines


def _release(version, prerelease=False, asset=None, sha="ab" * 32, repo="SagerNet/sing-box"):
    name = asset or f"sing-box-{version}-windows-amd64.zip"
    return {"tag": f"v{version}", "version": version, "name": version, "notes": "", "prerelease": prerelease,
            "url": f"https://github.com/{repo}/releases/tag/v{version}", "published_at": None,
            "assets": [{"name": name, "url": f"https://github.com/{repo}/releases/download/v{version}/{name}",
                        "sha256": sha, "size": 1}]}


class _FakeVpnClient:
    def __init__(self):
        self.installs = []
        self.rollbacks = []
        self.nudged = 0

    def core_install(self, name, release=None):
        self.installs.append((name, release))
        return None

    def core_rollback(self, name):
        self.rollbacks.append(name)
        return f"откат {name}"

    def core_update_soon(self):
        self.nudged += 1


def test_core_version_is_not_telegram_core(tmp_path, monkeypatch):
    """Прежде любой незнакомый ключ получал версию ядра Telegram-прокси."""
    monkeypatch.setattr(engines, "installed", lambda name, version=None: None)
    m = _mgr(tmp_path)
    m.tg.core = type("C", (), {"version": "1.11.2"})()
    assert m.current_version("vpncore") is None and m.current_version("vpnxray") is None
    assert m.current_version("tgws") == "1.11.2"


def test_uninstalled_core_gives_no_update_badge(tmp_path, monkeypatch):
    monkeypatch.setattr(engines, "installed", lambda name, version=None: None)
    m = _mgr(tmp_path)
    m.releases["vpncore"] = _release("1.14.9")
    assert m.is_available("vpncore") is False and m.available_count() == 0


def test_installed_core_update_badge(tmp_path, monkeypatch):
    monkeypatch.setattr(engines, "installed", lambda name, version=None: "1.14.3" if name == "sing-box" else None)
    m = _mgr(tmp_path)
    m.releases["vpncore"] = _release("1.14.4")
    assert m.is_available("vpncore") is True and m.available_count() == 1
    item = next(i for i in m.snapshot()["items"] if i["id"] == "vpncore")
    assert item["title"] == "Ядро VPN (sing-box)" and item["current"] == "1.14.3" and item["latest"] == "1.14.4"


def test_core_release_is_newest_stable_of_any_series(monkeypatch):
    """Новая серия (1.15, 27.x) — тоже обновление; пре-релизы и метки вида -alpha — нет."""
    listed = [_release("1.16.0-alpha.3", prerelease=True), _release("1.15.1", prerelease=True), _release("1.15.0"),
              _release("1.14.4"), _release("1.14.3")]
    monkeypatch.setattr(updates_manager.github, "releases", lambda repo, pages=1, **kw: listed)
    assert updates_manager.UpdateManager.core_release("sing-box")["version"] == "1.15.0"
    xray = [_release("27.9.9", prerelease=True, asset="Xray-windows-64.zip", repo="XTLS/Xray-core"),
            _release("27.1.2", asset="Xray-windows-64.zip", repo="XTLS/Xray-core"),
            _release("26.3.27", asset="Xray-windows-64.zip", repo="XTLS/Xray-core")]
    monkeypatch.setattr(updates_manager.github, "releases", lambda repo, pages=1, **kw: xray)
    assert updates_manager.UpdateManager.core_release("xray")["version"] == "27.1.2"


def test_core_release_lookup_falls_back_to_system_proxy(monkeypatch):
    used = []

    def releases(repo, pages=1, opener=None):
        used.append(opener)
        if opener == "direct":
            raise github.GitHubError("Нет связи с GitHub: timed out")
        return [_release("1.15.0")]

    monkeypatch.setattr(github, "direct_opener", lambda: "direct")
    monkeypatch.setattr(github, "system_opener", lambda: "system")
    monkeypatch.setattr(github, "releases", releases)
    assert updates_manager.UpdateManager.core_release("sing-box")["version"] == "1.15.0"
    assert used == ["direct", "system"]


def test_auto_updated_cores_do_not_call_for_a_button(tmp_path, monkeypatch):
    """При автообновлении ядра ставятся сами: плашка «Доступно обновление» про них не нужна; не подошедшая
    версия — тоже не повод звать человека. Кнопка «Установить» в пункте остаётся."""
    monkeypatch.setattr(engines, "installed", lambda name, version=None: "1.14.3" if name == "sing-box" else None)
    m = _mgr(tmp_path)
    m.releases["vpncore"] = _release("1.15.0")
    m.vpnclient = _FakeVpnClient()
    assert m.is_available("vpncore") is True and m.available_count() == 0
    m.settings.update(lambda d: d["vpnclient"].__setitem__("core_auto_update", False))
    assert m.available_count() == 1
    m.settings.update(lambda d: d["vpnclient"].__setitem__("core_bad_versions", ["sing-box:1.15.0"]))
    assert m.available_count() == 0 and m.is_available("vpncore") is True


def test_check_nudges_auto_update_when_a_core_is_newer(tmp_path, monkeypatch):
    monkeypatch.setattr(engines, "installed", lambda name, version=None: "1.14.3" if name == "sing-box" else None)
    monkeypatch.setattr(github, "latest_release", lambda repo, **kw: (_ for _ in ()).throw(github.GitHubError("нет")))
    monkeypatch.setattr(updates_manager.UpdateManager, "core_release", staticmethod(lambda name: _release("1.15.0")))
    m = _mgr(tmp_path)
    vc = m.vpnclient = _FakeVpnClient()
    m._check(quiet=True)
    assert vc.nudged == 1 and m.releases["vpncore"]["version"] == "1.15.0"


def test_core_note_shows_on_updates_page(tmp_path, monkeypatch):
    monkeypatch.setattr(engines, "installed", lambda name, version=None: "1.15.0" if name == "sing-box" else None)
    m = _mgr(tmp_path)
    core = {"installed": True, "version": "1.15.0", "in_use": "1.14.3", "auto_updated": True, "state": "idle",
            "progress": None, "message": None, "note": None}
    item = next(i for i in m.snapshot(cores={"sing-box": core})["items"] if i["id"] == "vpncore")
    assert item["state"] == "idle" and "поставлена автоматически" in item["message"]
    assert "со следующего подключения" in item["message"]
    core["note"] = "Версия 1.15.1 не приняла ваши настройки: unknown field. Осталась 1.15.0."
    item = next(i for i in m.snapshot(cores={"sing-box": core})["items"] if i["id"] == "vpncore")
    assert item["message"] == core["note"]


def test_core_rollback_goes_to_previous_version(tmp_path, monkeypatch):
    have = {"sing-box": ["1.15.1", "1.15.0"]}
    monkeypatch.setattr(engines, "installed", lambda name, version=None: (have.get(name) or [None])[0])
    monkeypatch.setattr(engines, "versions", lambda name: list(have.get(name, [])))
    m = _mgr(tmp_path)
    vc = m.vpnclient = _FakeVpnClient()
    assert m._core_can_rollback("vpncore") is True
    assert m._rollback_core("vpncore") == "откат sing-box"
    assert vc.rollbacks == ["sing-box"]
    have["sing-box"] = ["1.14.3"]
    m.forget_core_versions()
    assert m._core_can_rollback("vpncore") is False, "закреплённая и единственная — откатываться некуда"
    with pytest.raises(UpdateError, match="Нет более ранней"):
        m._rollback_core("vpncore")


def test_releases_skips_drafts_and_marks_prereleases(monkeypatch):
    pages = {1: [{"tag_name": "v1.15.0-beta.1", "prerelease": True, "assets": []},
                 {"tag_name": "v1.14.4", "draft": True, "assets": []},
                 {"tag_name": "v1.14.3", "assets": []}]}
    monkeypatch.setattr(github, "http_get_json",
                        lambda url, timeout=15.0, opener=None: pages[int(url.rsplit("page=", 1)[1])])
    found = github.releases("SagerNet/sing-box", per_page=100, pages=2)
    assert [(r["version"], r["prerelease"]) for r in found] == [("1.15.0-beta.1", True), ("1.14.3", False)]


def test_core_update_goes_through_vpn_manager(tmp_path, monkeypatch):
    monkeypatch.setattr(engines, "installed", lambda name, version=None: "1.14.3")
    m = _mgr(tmp_path)
    vc = m.vpnclient = _FakeVpnClient()
    m.releases["vpncore"] = _release("1.14.4")
    m._install_core("vpncore", update=True)
    name, release = vc.installs[0]
    assert name == "sing-box" and release.version == "1.14.4" and release.zip_sha256 == "ab" * 32
    assert release.url.startswith("https://github.com/SagerNet/sing-box/releases/download/v1.14.4/")
    m.releases["vpncore"] = _release("1.14.5", sha=None)
    with pytest.raises(UpdateError, match="контрольной суммы"):
        m._install_core("vpncore", update=True)
    bad = _release("1.14.6")
    bad["assets"][0]["url"] = "https://evil.example.com/sing-box-1.14.6-windows-amd64.zip"
    m.releases["vpncore"] = bad
    with pytest.raises(UpdateError, match="не в релизах"):
        m._install_core("vpncore", update=True)


def test_core_install_without_vpn_module_is_refused(tmp_path):
    m = _mgr(tmp_path)
    with pytest.raises(UpdateError, match="недоступен"):
        m._install_core("vpnxray", update=False)


class _Hello(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        body = b"direct"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture
def local_server():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Hello)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}/"
    server.shutdown()
    server.server_close()


def test_explicit_route_ignores_system_proxy(local_server, monkeypatch, tmp_path):
    """Системный прокси (его ставит и свой VPN, и чужой) запросы Лазейки молча не уводит:
    прокси на мёртвом порту не мешает прямому запросу."""
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    monkeypatch.delenv("NO_PROXY", raising=False)
    assert github.http_get(local_server, timeout=5) == b"direct"
    target = tmp_path / "f.bin"
    github.download(local_server, target, None, timeout=5)
    assert target.read_bytes() == b"direct"
    assert not any(isinstance(h, urllib.request.ProxyHandler) and h.proxies for h in github.direct_opener().handlers)


def test_explicit_route_uses_given_opener(local_server):
    used = []

    class Recording(urllib.request.OpenerDirector):
        def open(self, req, *a, **kw):
            used.append(req.full_url)
            return github.direct_opener().open(req, *a, **kw)

    assert github.http_get(local_server, timeout=5, opener=Recording()) == b"direct"
    assert used == [local_server]


# ------------------------------------------------------------ сверка SHA-256 скачанного

def test_download_with_wrong_checksum_is_refused_and_removed(local_server, tmp_path):
    """На эту сверку полагаются самообновление Лазейки и пакеты zapret: не тот файл — ошибка, на диске его нет."""
    target = tmp_path / "Lazeyka.exe.new"
    with pytest.raises(github.IntegrityError, match="Контрольная сумма"):
        github.download(local_server, target, "0" * 64, timeout=5)
    assert not target.exists()
    good = hashlib.sha256(b"direct").hexdigest()
    assert github.download(local_server, target, good.upper(), timeout=5) == good   # регистр хеша не важен
    assert target.read_bytes() == b"direct"


def test_install_app_with_wrong_checksum_keeps_running_exe(local_server, tmp_path, monkeypatch):
    exe = _frozen_exe(tmp_path, monkeypatch, b"OLD")
    # Сервер — свой, на 127.0.0.1: проверку «файл из релизов GitHub» здесь пропускаем, сверяется хеш.
    monkeypatch.setattr("app.updates.manager._require_release_url", lambda url, repo: None)
    m = _mgr(tmp_path)
    m.releases["app"] = {"version": "99.0.0",
                         "assets": [{"name": "Lazeyka.exe", "url": local_server, "sha256": "0" * 64}]}
    with pytest.raises(github.IntegrityError):
        m._install_app()
    assert exe.read_bytes() == b"OLD", "работающий exe не заменён"
    assert m.settings.get("updates", "app_backup") is None
    assert sorted(p.name for p in tmp_path.iterdir() if p.name != "s.json") == ["Lazeyka.exe"], \
        "ни скачанного файла, ни отодвинутой копии"
