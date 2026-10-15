import logging
import os
import socket

import pytest

from app import paths
from app.settings import Settings
from app.tgproxy import loader
from app.tgproxy.manager import TgError, TgProxyManager, explain_bind_error

from .mtproto_probe import probe

NETWORK = os.environ.get("LAZEYKA_NO_NETWORK") != "1"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def manager(tmp_path):
    settings = Settings(tmp_path / "settings.json")
    port = _free_port()
    settings.update(lambda d: d["tg"].update({"port": port}))
    notes = []
    mgr = TgProxyManager(settings, lambda lvl, text: notes.append((lvl, text)))
    mgr.load_core()
    mgr.notes = notes
    yield mgr
    mgr.stop()


def test_bundled_core_is_compatible():
    core = loader.load_bundled()
    assert core.version == "1.11.2"
    assert loader.check(core) is None


def test_core_from_directory_gets_own_singletons(tmp_path):
    import shutil
    src = paths.resource_dir() / "app" / "vendor" / "tgws_proxy"
    dst = tmp_path / "tgws_proxy"
    shutil.copytree(src, dst)
    updated = loader.load_from_dir(dst, "9.9.9")
    bundled = loader.load_bundled()
    assert updated.origin == "updated"
    assert updated.proxy_config is not bundled.proxy_config
    assert updated.stats is not bundled.stats


def test_broken_core_is_reported(tmp_path):
    pkg = tmp_path / "tgws_proxy"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("import module_that_does_not_exist\n")
    with pytest.raises(loader.CoreError, match="module_that_does_not_exist"):
        loader.load_from_dir(pkg, "0.0.1")


def test_validation_errors(manager):
    clean, errors = manager.validate({
        "host": "localhost", "port": "70000", "secret": "xyz", "dc_ip": "2:1.2.3.4\nbad",
        "cf_domains": "", "worker_domains": "not a domain", "pool_size": 4, "buf_kb": 1,
        "worker_enabled": True,
    })
    assert set(errors) == {"host", "port", "secret", "dc_ip", "worker_domains", "buf_kb"}


def test_valid_settings_round_trip(manager):
    values = manager.settings.get("tg")
    clean, errors = manager.validate(values)
    assert errors == {}
    assert clean["secret"] == values["secret"]


def test_link_format(manager):
    link = manager.link()
    secret = manager.settings.get("tg", "secret")
    assert link == f"tg://proxy?server=127.0.0.1&port={manager.settings.get('tg', 'port')}&secret=dd{secret}"


def test_port_busy_gives_human_error(manager):
    with socket.socket() as blocker:
        blocker.bind(("127.0.0.1", manager.settings.get("tg", "port")))
        blocker.listen()
        with pytest.raises(TgError, match="занят"):
            manager.start()
    assert manager.status == "error"


def test_explain_bind_error():
    err = OSError(10013, "denied")
    err.winerror = 10013
    assert "запрещён" in explain_bind_error(err, 1443)


def test_start_stop_listens(manager):
    manager.start()
    assert manager.status == "running"
    port = manager.settings.get("tg", "port")
    with socket.create_connection(("127.0.0.1", port), timeout=3):
        pass
    manager.stop()
    assert manager.status == "stopped"
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", port), timeout=1).close()


@pytest.mark.skipif(not NETWORK, reason="без сети")
def test_telegram_answers_through_proxy(manager, caplog):
    caplog.set_level(logging.INFO)
    manager.start()
    cfg = manager.settings.get("tg")
    last = None
    for _ in range(3):
        try:
            result = probe("127.0.0.1", cfg["port"], cfg["secret"], dc=2)
            if result["ok"]:
                break
            last = result
        except OSError as exc:
            last = exc
    else:
        pytest.fail(f"Telegram не ответил через прокси: {last}")
    assert result["ok"], result
