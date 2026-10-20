"""Свой VPN: установка ядер с GitHub, сверка exe, `version` и `check`, маршруты загрузки и выбор релиза —
на поддельных архивах и подменённой загрузке, без сети."""
import dataclasses
import hashlib
import io
import json
import os
import shutil
import threading
import urllib.request
import zipfile
from pathlib import Path

import pytest

from app import paths, winutil
from app.filehash import sha256_file
from app.updates import github
from app.vpnclient import engines, guard

ROOT = Path(__file__).resolve().parent.parent
FAKE_EXE = b"MZ fake sing-box for tests"
FAKE_XRAY = b"MZ fake xray for tests"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _zip(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buf.getvalue()


SINGBOX_ZIP = _zip({"sing-box-1.14.3-windows-amd64/sing-box.exe": FAKE_EXE,
                    "sing-box-1.14.3-windows-amd64/libcronet.dll": b"dll",
                    "sing-box-1.14.3-windows-amd64/LICENSE": b"notice"})
XRAY_ZIP = _zip({"xray.exe": FAKE_XRAY, "geoip.dat": b"geo" * 100, "geosite.dat": b"site" * 100,
                 "wintun.dll": b"wintun", "LICENSE": b"MPL", "LICENSE-wintun.txt": b"wintun license"})


def serve(data: bytes, calls: list | None = None):
    """Подмена загрузки: «скачивает» data и возвращает её SHA-256, как github.download."""
    def download(url, dest, sha256, *, cancel=None, progress=None):
        if calls is not None:
            calls.append(url)
        dest.write_bytes(data)
        if progress:
            progress(len(data), len(data))
        return _sha(data)
    return download


class FakeRunner:
    """Вместо запуска exe: отвечает на `version` и `check` как настоящее ядро."""

    def __init__(self, versions=None):
        self.versions = versions or {"sing-box.exe": "1.14.3", "xray.exe": "26.3.27"}
        self.calls: list[list[str]] = []
        self.check_result = winutil.RunResult(0, "", "")

    def __call__(self, cmd, timeout, cwd=None):
        self.calls.append(list(cmd))
        exe = Path(cmd[0]).name
        if cmd[1:] == ["version"]:
            ver = self.versions[exe]
            if ver is None:
                return winutil.RunResult(1, "", "This app can't run on your PC")
            if exe == "sing-box.exe":
                return winutil.RunResult(0, f"sing-box version {ver}\n\nEnvironment: go1.26.8 windows/amd64\n", "")
            return winutil.RunResult(0, f"Xray {ver} (Xray, Penetrates Everything.) 1a2b3c (go1.26.1 windows/amd64)\n", "")
        return self.check_result


@pytest.fixture
def cores(tmp_path, monkeypatch):
    """Свои папки данных, закреплённые хеши поддельных архивов, разрешённая установка."""
    monkeypatch.setattr(paths, "COMPONENTS_DIR", tmp_path / "components")
    monkeypatch.setattr(paths, "TMP_DIR", tmp_path / "tmp")
    monkeypatch.setattr(guard, "core_blocked", lambda: False)
    specs = {
        "sing-box": dataclasses.replace(engines.CORES["sing-box"], zip_sha256=_sha(SINGBOX_ZIP),
                                        exe_sha256=_sha(FAKE_EXE), zip_size=len(SINGBOX_ZIP)),
        "xray": dataclasses.replace(engines.CORES["xray"], zip_sha256=_sha(XRAY_ZIP),
                                    exe_sha256=_sha(FAKE_XRAY), zip_size=len(XRAY_ZIP)),
    }
    monkeypatch.setattr(engines, "CORES", specs)
    runner = FakeRunner()
    monkeypatch.setattr(engines, "_run", runner)
    return {"runner": runner, "root": tmp_path / "components"}


def test_pinned_versions_and_hashes_match_the_plan():
    sb, xr = engines.CORES["sing-box"], engines.CORES["xray"]
    assert (sb.version, sb.repo) == ("1.14.3", "SagerNet/sing-box")
    assert sb.zip_sha256 == "d8b86ef58936dba9230ec6a57ffa4243933f3c14ef4809828b6c553440ed1518"
    assert sb.exe_sha256 == "5c19bb3f8c12d4e85b3d47fe63123a7624b314b58dd7a8e32f51004f1c4d2faf"
    assert (xr.version, xr.repo) == ("26.3.27", "XTLS/Xray-core")
    assert xr.zip_sha256 == "d004c39288ce9ada487c6f398c7c545f7d749e44bdfdd59dbc9f865afba4e1ad"
    assert len(xr.exe_sha256) == 64
    assert sb.release_url() == ("https://github.com/SagerNet/sing-box/releases/download/v1.14.3/"
                                "sing-box-1.14.3-windows-amd64.zip")
    assert xr.release_url() == "https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-windows-64.zip"
    assert sb.asset_for("1.15.0") == "sing-box-1.15.0-windows-amd64.zip" and xr.asset_for("27.1.2") == xr.asset
    assert sb.source_url() == "https://github.com/SagerNet/sing-box/tree/v1.14.3"


def test_gpl_text_ships_with_the_app():
    text = engines.gpl_text_path().read_text(encoding="utf-8")
    assert "GNU GENERAL PUBLIC LICENSE" in text and "Version 3, 29 June 2007" in text


def test_install_pinned_from_github(cores):
    stages, calls = [], []

    version = engines.install("sing-box", progress=lambda stage, frac: stages.append(stage),
                              download=serve(SINGBOX_ZIP, calls))

    target = cores["root"] / "sing-box" / "1.14.3"
    assert version == "1.14.3" and engines.installed("sing-box") == "1.14.3"
    assert calls == [engines.CORES["sing-box"].release_url()]
    assert (target / "sing-box.exe").read_bytes() == FAKE_EXE
    assert (target / "LICENSE").is_file() and (target / "libcronet.dll").is_file()
    assert "GNU GENERAL PUBLIC LICENSE" in (target / "gpl-3.0.txt").read_text(encoding="utf-8")
    marker = json.loads((target / engines.MARKER).read_text(encoding="utf-8"))
    assert marker["source"] == "github" and marker["exe_sha256"] == _sha(FAKE_EXE)
    assert engines.origin("sing-box", "1.14.3") == "github"
    assert stages[0] == "downloading" and "verifying" in stages and stages[-1] == "installing"
    assert not list((cores["root"] / "sing-box").glob("*.staging"))
    assert not list(paths.TMP_DIR.glob("*.zip")), "скачанный архив удалён"
    assert engines.verify("sing-box") == target / "sing-box.exe"


def test_verify_catches_replaced_exe(cores):
    engines.install("sing-box", download=serve(SINGBOX_ZIP))
    (cores["root"] / "sing-box" / "1.14.3" / "sing-box.exe").write_bytes(b"MZ evil")
    with pytest.raises(engines.EngineError, match="контрольная сумма"):
        engines.verify("sing-box")


def test_bad_archive_hash_installs_nothing(cores):
    with pytest.raises(engines.EngineError, match="архива не совпала"):
        engines.install("sing-box", download=serve(SINGBOX_ZIP + b"tail"))
    assert engines.installed("sing-box") is None
    assert not (cores["root"] / "sing-box" / "1.14.3").exists()
    assert not list(paths.TMP_DIR.glob("*.zip"))


def test_exe_hash_mismatch_is_rejected(cores, monkeypatch):
    spec = dataclasses.replace(engines.CORES["sing-box"], exe_sha256="0" * 64)
    monkeypatch.setitem(engines.CORES, "sing-box", spec)
    with pytest.raises(engines.ReleaseRejected, match="sing-box.exe не совпала"):
        engines.install("sing-box", download=serve(SINGBOX_ZIP))
    assert engines.installed("sing-box") is None
    assert not list((cores["root"] / "sing-box").glob("*"))


def test_wrong_version_inside_archive_is_rejected(cores):
    cores["runner"].versions["sing-box.exe"] = "1.14.2"
    with pytest.raises(engines.ReleaseRejected, match="версия 1.14.2, ожидалась 1.14.3"):
        engines.install("sing-box", download=serve(SINGBOX_ZIP))


def test_failed_swap_restores_previous_install(cores, monkeypatch):
    """Переустановка той же версии: прежняя ушла в .old-*, а новая на её место не встала — прежняя
    возвращается, ядро по-прежнему установлено."""
    engines.install("sing-box", download=serve(SINGBOX_ZIP))
    real_rename = os.rename

    def rename(src, dst):
        if str(src).endswith(".staging"):
            raise PermissionError(5, "Access is denied", str(src))
        return real_rename(src, dst)

    monkeypatch.setattr(engines.os, "rename", rename)
    with pytest.raises(engines.EngineError, match="установка не удалась"):
        engines.install("sing-box", download=serve(SINGBOX_ZIP))
    monkeypatch.setattr(engines.os, "rename", real_rename)
    assert engines.installed("sing-box") == "1.14.3" and engines.verify("sing-box", "1.14.3")
    assert [p.name for p in (cores["root"] / "sing-box").iterdir()] == ["1.14.3"]


def test_install_interrupted_between_renames_is_recovered(cores):
    """Процесс завершился между переименованиями: папки версии нет, прежняя лежит как .old-* — её
    находит первая же проверка установленных версий."""
    engines.install("sing-box", download=serve(SINGBOX_ZIP))
    root = cores["root"] / "sing-box"
    os.rename(root / "1.14.3", root / f"1.14.3{engines.OLD_MARK}deadbeef")
    assert engines.installed("sing-box", "1.14.3") == "1.14.3"
    assert engines.versions("sing-box") == ["1.14.3"] and not list(root.glob(f"*{engines.OLD_MARK}*"))
    engines.prune("sing-box", {"1.14.3"})
    assert engines.installed("sing-box") == "1.14.3", "уборка не удаляет единственную копию"


def test_listing_versions_does_not_block_install(cores, monkeypatch):
    """Уборка прерванной установки (её зовут versions() и installed() — снимок страницы, тикер) не держит
    блокировку установки: install() рядом с ней не отвечает ложным «уже устанавливается»."""
    root = cores["root"] / "sing-box"
    (root / "1.14.3").mkdir(parents=True)
    entered, release = threading.Event(), threading.Event()
    real_iterdir = Path.iterdir

    def slow_iterdir(self):
        if self == root and threading.current_thread().name == "lister":
            entered.set()
            release.wait(5)                  # антивирус или медленный диск: чтение папки занимает время
        return real_iterdir(self)

    monkeypatch.setattr(Path, "iterdir", slow_iterdir)
    lister = threading.Thread(target=engines.versions, args=("sing-box",), name="lister")
    lister.start()
    assert entered.wait(5)
    calls: list[str] = []
    real_download = serve(SINGBOX_ZIP, calls)

    def download(*args, **kwargs):
        release.set()                        # установка уже идёт, пока уборка читает папку, — дальше вместе
        return real_download(*args, **kwargs)

    try:
        assert engines.install("sing-box", download=download) == "1.14.3"
    finally:
        release.set()
        lister.join(5)
    assert calls and engines.installed("sing-box") == "1.14.3"


def test_recovery_waits_for_swap_in_progress(cores, monkeypatch):
    """Переустановка той же версии: между двумя переименованиями папки версии нет, а прежняя лежит как
    .old-*. Уборка в этот миг ждёт конца замены — иначе вернула бы прежнюю на место, и новая не встала бы."""
    engines.install("sing-box", download=serve(SINGBOX_ZIP))
    root = cores["root"] / "sing-box"
    real_rename = os.rename
    recovered = threading.Event()
    lister: list[threading.Thread] = []

    def rename(src, dst):
        real_rename(src, dst)
        if engines.OLD_MARK in Path(dst).name and not lister:     # прежняя ушла в сторону, новой ещё нет
            thread = threading.Thread(target=lambda: (engines._recover_interrupted("sing-box"), recovered.set()))
            lister.append(thread)
            thread.start()
            assert not recovered.wait(0.3), "уборка не должна вмешаться посреди замены"

    monkeypatch.setattr(engines.os, "rename", rename)
    engines.install("sing-box", download=serve(SINGBOX_ZIP))
    lister[0].join(5)
    assert recovered.is_set() and [p.name for p in root.iterdir()] == ["1.14.3"]
    assert engines.verify("sing-box", "1.14.3")


def test_core_that_does_not_answer_version_is_rejected(cores):
    cores["runner"].versions["sing-box.exe"] = None
    with pytest.raises(engines.ReleaseRejected, match=r"Ядро VPN \(sing-box\) не сообщило версию"):
        engines.install("sing-box", download=serve(SINGBOX_ZIP))


def test_messages_agree_with_core_title(cores):
    """«Ядро VPN» — средний род, «Помощник Xray» — мужской: «не установлено» / «не установлен»."""
    with pytest.raises(engines.EngineError, match=r"^Ядро VPN \(sing-box\) 1\.14\.3 не установлено$"):
        engines.verify("sing-box", "1.14.3")
    with pytest.raises(engines.EngineError, match=r"^Помощник Xray не установлен$"):
        engines.verify("xray")
    assert engines.spec("sing-box").agree("запущен") == "запущено"
    assert engines.spec("xray").agree("запущен") == "запущен"


def test_broken_zip_is_rejected(cores, monkeypatch):
    broken = b"PK\x03\x04 not a zip at all"
    rel = engines.Release(version="1.15.0", url="https://example.invalid/sb.zip", zip_sha256=_sha(broken))
    with pytest.raises(engines.ReleaseRejected, match="не распаковался"):
        engines.install("sing-box", source=rel, download=serve(broken))


def test_xray_install_skips_geo_files(cores):
    engines.install("xray", download=serve(XRAY_ZIP))
    target = cores["root"] / "xray" / "26.3.27"
    names = {p.name for p in target.iterdir()}
    assert {"xray.exe", "wintun.dll", "LICENSE", "LICENSE-wintun.txt", engines.MARKER} <= names
    assert "geoip.dat" not in names and "geosite.dat" not in names
    assert "gpl-3.0.txt" not in names


def test_unpack_limit_is_passed_to_archive(cores, monkeypatch):
    seen = {}
    real = engines.archive.extract

    def spy(zip_path, target, **kw):
        seen.update(kw)
        return real(zip_path, target, **kw)

    monkeypatch.setattr(engines.archive, "extract", spy)
    engines.install("sing-box", download=serve(SINGBOX_ZIP))
    assert seen["max_unpacked"] == 128 * 1024 * 1024


def test_new_series_installs_and_records_exe_hash(cores):
    """Новая серия (1.15) больше не отказ: проверка — `check` конфига, её делает менеджер."""
    rel = engines.Release(version="1.15.0", url="https://example.invalid/sb.zip", zip_sha256=_sha(SINGBOX_ZIP))
    cores["runner"].versions["sing-box.exe"] = "1.15.0"
    engines.install("sing-box", source=rel, download=serve(SINGBOX_ZIP), origin="auto")
    assert engines.versions("sing-box") == ["1.15.0"]
    assert engines.verify("sing-box", "1.15.0").name == "sing-box.exe"
    assert engines.origin("sing-box", "1.15.0") == "auto"


def test_unknown_source_is_refused(cores):
    for source in ("bundled", "auto"):
        with pytest.raises(engines.EngineError, match="Неизвестный источник"):
            engines.install("sing-box", source=source, download=serve(SINGBOX_ZIP))


def test_install_is_blocked_by_guard(cores, monkeypatch):
    monkeypatch.setattr(guard, "core_blocked", lambda: True)
    assert engines.background_allowed() is False
    with pytest.raises(guard.CoreBlocked):
        engines.install("sing-box", download=serve(SINGBOX_ZIP))


def test_versions_prune_and_rollback_choice(cores):
    root = cores["root"] / "xray"
    for ver in ("26.3.27", "26.3.28", "27.1.2"):
        (root / ver).mkdir(parents=True)
        (root / ver / engines.MARKER).write_text(json.dumps({"version": ver, "exe_sha256": "x"}), encoding="utf-8")
        (root / ver / "xray.exe").write_bytes(b"MZ")
    (root / "26.3.29.staging").mkdir()
    (root / "27.2.1").mkdir()   # без метки — не установлена
    assert engines.versions("xray") == ["27.1.2", "26.3.28", "26.3.27"]
    assert engines.installed("xray") == "27.1.2", "самая новая — любой серии"
    assert engines.installed("xray", "26.3.27") == "26.3.27"
    assert engines.installed("xray", "27.2.1") is None
    removed = engines.prune("xray", keep={"27.1.2", "26.3.28"})
    assert set(removed) == {"26.3.27", "26.3.29.staging", "27.2.1"}
    assert engines.versions("xray") == ["27.1.2", "26.3.28"]


def test_version_whose_exe_vanished_is_not_installed(cores):
    """Ревью, 7: антивирус удалил sing-box.exe, метка осталась — версия не считается стоящей, и подкачка
    ставит её заново поверх остатков папки."""
    engines.install("sing-box", download=serve(SINGBOX_ZIP))
    (cores["root"] / "sing-box" / "1.14.3" / "sing-box.exe").unlink()
    assert engines.installed("sing-box") is None and engines.installed("sing-box", "1.14.3") is None
    assert engines.versions("sing-box") == []
    assert engines.install("sing-box", download=serve(SINGBOX_ZIP)) == "1.14.3"
    assert engines.verify("sing-box").is_file()


@pytest.mark.parametrize("bad", ["../evil", "1.14.3/../../x", "", "v1.14.3", "1.14.3 "])
def test_version_strings_cannot_escape_the_folder(bad):
    with pytest.raises(engines.EngineError):
        engines.version_dir("sing-box", bad)


def test_check_singbox_fatal_and_warnings(cores, tmp_path):
    engines.install("sing-box", download=serve(SINGBOX_ZIP))
    cfg = tmp_path / "run" / "sing-box.json"
    cfg.parent.mkdir()
    cfg.write_text("{}", encoding="utf-8")
    runner = cores["runner"]
    runner.check_result = winutil.RunResult(
        1, "", "FATAL[0000] decode config at C:\\x\\sing-box.json: route.bogus_field: json: unknown field \"bogus_field\"\n")
    with pytest.raises(engines.EngineError) as err:
        engines.check("sing-box", cfg)
    assert "unknown field" in str(err.value) and "FATAL[" not in str(err.value)
    args = runner.calls[-1][1:]
    assert args[:2] == ["check", "--disable-color"] and args[-2:] == ["-c", str(cfg)]

    runner.check_result = winutil.RunResult(
        0, "", "WARN[0000] `independent_cache` DNS option is deprecated in sing-box 1.14.0\n")
    assert engines.check("sing-box", cfg) == ["`independent_cache` DNS option is deprecated in sing-box 1.14.0"]
    runner.check_result = winutil.RunResult(0, "", "")
    assert engines.check("sing-box", cfg) == []


def test_check_xray_uses_run_test(cores, tmp_path):
    engines.install("xray", download=serve(XRAY_ZIP))
    cfg = tmp_path / "xray.json"
    cfg.write_text("{}", encoding="utf-8")
    runner = cores["runner"]
    runner.check_result = winutil.RunResult(23, "Failed to start: main: failed to load config files: [xray.json] > "
                                                "infra/conf: unknown transport protocol: xhttp2\n", "")
    with pytest.raises(engines.EngineError, match="unknown transport protocol"):
        engines.check("xray", cfg)
    assert runner.calls[-1][1:] == ["run", "-test", "-c", str(cfg)]
    assert guard.is_static(runner.calls[-1][1:])


# ------------------------------------------------------------ маршруты: напрямую, запасной — системный прокси

@pytest.fixture
def routes(monkeypatch):
    """Маршрут виден по opener: напрямую — "direct", через системный прокси — "system"."""
    monkeypatch.setattr(github, "direct_opener", lambda: "direct")
    monkeypatch.setattr(github, "system_opener", lambda: "system")
    state = {"fail": {"direct"}, "error": github.GitHubError("Нет связи с GitHub: timed out"), "used": []}

    def download(url, dest, sha, *, progress=None, cancel=None, timeout=30.0, limit=0, opener=None):
        state["used"].append(opener)
        if opener in state["fail"]:
            raise state["error"]
        dest.write_bytes(b"zip")
        return _sha(b"zip")

    monkeypatch.setattr(github, "download", download)
    return state


def test_download_falls_back_to_system_proxy(routes, tmp_path):
    got = engines._github_download("https://github.com/x/y.zip", tmp_path / "a.zip", _sha(b"zip"), cancel=None,
                                   progress=lambda *_: None)
    assert got == _sha(b"zip") and routes["used"] == ["direct", "system"]


def test_direct_route_is_enough_when_it_works(routes, tmp_path):
    routes["fail"] = set()
    engines._github_download("https://github.com/x/y.zip", tmp_path / "a.zip", _sha(b"zip"), cancel=None,
                             progress=lambda *_: None)
    assert routes["used"] == ["direct"], "системный прокси — только запасной маршрут"


def test_both_routes_failed_explains_both(routes, tmp_path):
    routes["fail"] = {"direct", "system"}
    with pytest.raises(engines.EngineError, match="через системный прокси — тоже"):
        engines._github_download("https://github.com/x/y.zip", tmp_path / "a.zip", "0" * 64, cancel=None,
                                 progress=lambda *_: None)


def test_wrong_file_or_cancel_does_not_try_second_route(routes, tmp_path):
    routes["error"] = github.IntegrityError("Контрольная сумма скачанного файла не совпала")
    with pytest.raises(github.IntegrityError):
        engines._github_download("https://github.com/x/y.zip", tmp_path / "a.zip", "0" * 64, cancel=None,
                                 progress=lambda *_: None)
    assert routes["used"] == ["direct"]
    routes["used"].clear()
    routes["error"] = github.GitHubError("Загрузка отменена")
    cancel = threading.Event()
    cancel.set()
    with pytest.raises(github.GitHubError, match="отменена"):
        engines._github_download("https://github.com/x/y.zip", tmp_path / "a.zip", "0" * 64, cancel=cancel,
                                 progress=lambda *_: None)
    assert routes["used"] == ["direct"]


def test_system_opener_uses_system_proxy_and_direct_does_not(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:18080")
    proxies = [h.proxies for h in github.system_opener().handlers if isinstance(h, urllib.request.ProxyHandler)]
    assert proxies and proxies[0].get("https") == "http://127.0.0.1:18080"
    assert not any(isinstance(h, urllib.request.ProxyHandler) and h.proxies for h in github.direct_opener().handlers)


# ------------------------------------------------------------ какой релиз ставить

def _rel(version, prerelease=False, *, asset=None, sha="ab" * 32, repo="SagerNet/sing-box", url=None):
    name = asset or f"sing-box-{version}-windows-amd64.zip"
    return {"tag": f"v{version}", "version": version, "prerelease": prerelease,
            "assets": [{"name": name, "url": url or f"https://github.com/{repo}/releases/download/v{version}/{name}",
                        "sha256": sha, "size": 1}]}


def test_latest_release_takes_any_series_but_no_prereleases(monkeypatch):
    listed = [_rel("1.16.0-alpha.1", prerelease=True), _rel("1.15.2", prerelease=True), _rel("1.15.1"),
              _rel("1.15.0"), _rel("1.14.4"), _rel("1.14.3")]
    used = []
    monkeypatch.setattr(github, "releases", lambda repo, pages=1, opener=None: used.append(opener) or listed)
    monkeypatch.setattr(github, "direct_opener", lambda: "direct")
    rel = engines.latest_release("sing-box")
    assert rel.version == "1.15.1" and rel.zip_sha256 == "ab" * 32 and rel.exe_sha256 is None
    assert rel.url == "https://github.com/SagerNet/sing-box/releases/download/v1.15.1/sing-box-1.15.1-windows-amd64.zip"
    assert used == ["direct"]
    xray = [_rel("27.1.0", asset="Xray-windows-64.zip", repo="XTLS/Xray-core"),
            _rel("26.3.27", asset="Xray-windows-64.zip", repo="XTLS/Xray-core")]
    monkeypatch.setattr(github, "releases", lambda repo, pages=1, opener=None: xray)
    assert engines.latest_release("xray").version == "27.1.0"
    monkeypatch.setattr(github, "releases", lambda repo, pages=1, opener=None: [_rel("1.15.0-beta.2")])
    assert engines.latest_release("sing-box") is None


def test_release_for_checks_digest_place_and_asset():
    pinned = engines.release_for("sing-box", _rel("1.14.3", sha=None))
    assert pinned == engines.pinned_release("sing-box"), "закреплённая — с хешами из кода"
    with pytest.raises(engines.EngineError, match="контрольной суммы"):
        engines.release_for("sing-box", _rel("1.15.0", sha=None))
    with pytest.raises(engines.EngineError, match="не в релизах"):
        engines.release_for("sing-box", _rel("1.15.0", url="https://evil.example.com/sing-box-1.15.0-windows-amd64.zip"))
    with pytest.raises(engines.EngineError, match="нет архива"):
        engines.release_for("sing-box", _rel("1.15.0", asset="sing-box-1.15.0-linux-amd64.tar.gz"))
    with pytest.raises(engines.EngineError, match="непонятная версия"):
        engines.release_for("sing-box", _rel("1.15.0-rc.1"))


# ------------------------------------------------------------ настоящие ядра — только статические команды

CORES_SRC = Path(os.environ.get("LAZEYKA_CORES_DIR") or ROOT / "vendor" / "cores")


@pytest.mark.core_check
@pytest.mark.parametrize("name", ["sing-box", "xray"])
def test_real_core_installs_and_answers_statically(name, tmp_path, monkeypatch, core_static):
    """Настоящий zip (кэш vendor/cores вместо GitHub): сверка хешей, распаковка, `version` и `check` —
    ничего не запускается."""
    spec = engines.CORES[name]
    src = CORES_SRC / spec.asset
    if not src.is_file():
        pytest.skip(f"нет {spec.asset} в {CORES_SRC}")
    monkeypatch.setattr(paths, "COMPONENTS_DIR", tmp_path / "components")
    monkeypatch.setattr(paths, "TMP_DIR", tmp_path / "tmp")
    monkeypatch.setattr(guard, "core_blocked", lambda: False)   # ставим во временную папку теста

    def from_cache(url, dest, sha256, *, cancel=None, progress=None):
        assert url == spec.release_url()
        shutil.copyfile(src, dest)
        return sha256_file(dest)

    assert engines.install(name, download=from_cache) == spec.version
    assert engines.version(name) == spec.version
    cfg = tmp_path / "check.json"
    cfg.write_text(json.dumps({"log": {"level": "error"}, "outbounds": [{"type": "direct", "tag": "direct"}]}
                              if name == "sing-box" else {"outbounds": [{"protocol": "freedom"}]}), encoding="utf-8")
    assert engines.check(name, cfg) == []
