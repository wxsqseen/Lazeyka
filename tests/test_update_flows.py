"""Сквозная проверка установки обновлений с настоящего GitHub (без запуска winws).

Новых релизов может не быть, поэтому «обновляемся» до текущих версий: путь тот же —
скачивание, проверка хешей, установка рядом, переключение, откат.
"""
import os
import shutil

import pytest

from app import paths
from app.settings import Settings
from app.tgproxy.manager import TgProxyManager
from app.updates import github
from app.updates.manager import UpdateManager
from app.zapret import pack
from app.zapret.manager import ZapretManager

NETWORK = os.environ.get("LAZEYKA_NO_NETWORK") != "1"


@pytest.fixture
def managers(tmp_path):
    for d in (paths.PACKS_DIR, paths.TGWS_COMPONENTS_DIR, paths.TMP_DIR, paths.USER_LISTS_DIR):
        shutil.rmtree(d, ignore_errors=True)
    settings = Settings(tmp_path / "settings.json")
    notes = []
    notify = lambda level, text: notes.append((level, text))  # noqa: E731
    zapret = ZapretManager(settings, notify, is_admin=True)
    zapret.init()
    tg = TgProxyManager(settings, notify)
    tg.load_core()
    updates = UpdateManager(settings, zapret, tg, notify, is_admin=True)
    yield settings, zapret, tg, updates, notes
    tg.stop()


@pytest.mark.skipif(not NETWORK, reason="без сети")
def test_zapret_update_downloads_verifies_installs_and_rolls_back(managers):
    settings, zapret, tg, updates, notes = managers
    # Делаем активной «старую» версию, чтобы настоящий релиз был обновлением.
    manifest = pack.bundled_manifest()
    old = pack.install_zip(manifest["zip"], "1.0.0", source="bundled", expected_sha256=manifest["sha256"])
    zapret.switch_pack(old)
    assert zapret.pack.version == "1.0.0"

    rel = github.latest_release("Flowseal/zapret-discord-youtube")
    updates.releases["zapret"] = rel
    assert updates.is_available("zapret")
    message = updates._install_zapret()
    assert rel["version"] in message
    assert zapret.pack.version == rel["version"]
    assert zapret.pack.source == "github"
    assert settings.get("zapret", "pack") == rel["version"]
    assert any(s.id == "general" for s in zapret.strategies)
    assert updates.snapshot()["items"][0]["can_rollback"]
    back = updates._rollback_zapret()
    assert "возвращены" in back
    assert zapret.pack.version == "1.0.0"


@pytest.mark.skipif(not NETWORK, reason="без сети")
def test_tgws_update_verifies_every_file_and_switches_core(managers):
    settings, zapret, tg, updates, notes = managers
    updates.releases["tgws"] = github.latest_release("Flowseal/tg-ws-proxy")
    message = updates._install_tgws()
    assert "обновлено" in message
    assert tg.core.origin == "updated"
    assert settings.get("tg", "core") == pack.safe_version(updates.releases["tgws"]["version"])
    # После перезапуска приложения подхватывается скачанное ядро.
    fresh = TgProxyManager(settings, lambda *_: None)
    fresh.load_core()
    assert fresh.core.origin == "updated"
    updates._rollback_tgws()
    assert tg.core.origin == "bundled" and settings.get("tg", "core") == "bundled"
