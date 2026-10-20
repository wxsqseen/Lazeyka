"""Telegram-прокси: проверка совместимости ядра, загрузка скачанного, запуск и остановка под одной
блокировкой, падение ядра на ходу, переход на встроенное, проверка формы. Настоящий прокси здесь не
запускается: ядро — поддельное, «слушает» оно только флагом _server_instance."""
import asyncio
import shutil
import sys
import threading
import time
from types import SimpleNamespace

import pytest

from app import paths
from app.settings import Settings
from app.tgproxy import loader
from app.tgproxy import manager as tgm
from app.tgproxy.manager import TgError, TgProxyManager

VENDORED = paths.resource_dir() / "app" / "vendor" / "tgws_proxy"


def _stats(**extra):
    base = dict(connections_active=0, connections_total=0, connections_ws=0, bytes_up=0, bytes_down=0)
    base.update(extra)
    return SimpleNamespace(**base)


def fake_core(run, version="9.9.9", origin="updated", stats=None):
    """Ядро с теми же частями, что настоящее; run(main, stop_event) — корутина вместо _run."""
    main = SimpleNamespace(_server_instance=None)

    async def _run(stop_event=None):
        await run(main, stop_event)

    main._run = _run
    config = SimpleNamespace(proxy_config=SimpleNamespace(), parse_dc_ip_list=lambda lines: {},
                             coerce_domain_list=lambda raw: list(raw) if isinstance(raw, list) else [],
                             _refresh_stop=threading.Event())
    return loader.ProxyCore(version=version, origin=origin, package=SimpleNamespace(), main=main, config=config,
                            stats_module=SimpleNamespace(stats=stats or _stats()), utils=SimpleNamespace())


async def serve_until_stopped(main, stop_event):
    main._server_instance = object()
    try:
        await stop_event.wait()
    finally:
        main._server_instance = None


async def serve_then_die(main, stop_event):
    main._server_instance = object()
    await asyncio.sleep(0.2)
    main._server_instance = None            # слушающий сокет умер, занять порт снова не вышло


async def crash_at_start(main, stop_event):
    raise RuntimeError("ядро не поднялось")


@pytest.fixture
def mgr(tmp_path):
    settings = Settings(tmp_path / "s.json")
    m = TgProxyManager(settings, lambda *a: None)
    m.alerts = []
    m.alert = lambda alert_id, level, text, page=None: m.alerts.append((alert_id, level, text, page))
    yield m
    m.stop(remember=False)


def _wait(predicate, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


# ------------------------------------------------------------ совместимость и загрузка ядра

def _copy_core(tmp_path):
    dst = tmp_path / "tgws_proxy"
    shutil.copytree(VENDORED, dst, ignore=shutil.ignore_patterns("__pycache__"))
    return dst


def test_core_without_required_counter_is_rejected(tmp_path):
    """Ядро с переименованным bytes_up проходило check() и роняло тикер каждую секунду."""
    dst = _copy_core(tmp_path)
    stats = dst / "stats.py"
    stats.write_text(stats.read_text(encoding="utf-8").replace("self.bytes_up = 0", "self.bytes_sent = 0"),
                     encoding="utf-8")
    with pytest.raises(loader.CoreError, match="bytes_up"):
        loader.load_from_dir(dst, "9.9.1")
    assert not any(k.startswith(loader.module_name_for("9.9.1")) for k in sys.modules)


def test_core_without_server_instance_is_rejected(tmp_path):
    dst = _copy_core(tmp_path)
    main = dst / "tg_ws_proxy.py"
    main.write_text(main.read_text(encoding="utf-8").replace("_server_instance", "_listener"), encoding="utf-8")
    with pytest.raises(loader.CoreError, match="_server_instance"):
        loader.load_from_dir(dst, "9.9.2")


def test_broken_submodule_becomes_core_error(tmp_path):
    """SyntaxError в подмодуле — тоже CoreError (с переходом на встроенное), а не исключение мимо."""
    dst = _copy_core(tmp_path)
    (dst / "stats.py").write_text("def broken(:\n", encoding="utf-8")
    with pytest.raises(loader.CoreError, match="SyntaxError"):
        loader.load_from_dir(dst, "9.9.3")
    assert not any(k.startswith(loader.module_name_for("9.9.3")) for k in sys.modules)


def test_odd_stats_do_not_break_sampling(mgr):
    mgr._install_core(fake_core(serve_until_stopped, stats=SimpleNamespace(bytes_up="x")))
    mgr.sample()
    snap = mgr.snapshot()
    assert snap["stats"]["up"] == 0 and snap["stats"]["active"] == 0
    mgr.refresh_client()


def _downloaded_dir(version):
    folder = paths.TGWS_COMPONENTS_DIR / version
    shutil.rmtree(folder, ignore_errors=True)
    folder.mkdir(parents=True)
    return folder


def test_failed_downloaded_core_is_alert_and_forgotten(mgr):
    """Скачанное ядро не загрузилось — плашка tg-core, настройка возвращена на встроенное, папка убрана:
    иначе то же самое повторялось бы при каждом запуске."""
    folder = _downloaded_dir("99.0.1")
    (folder / "tgws_proxy").mkdir()
    (folder / "tgws_proxy" / "__init__.py").write_text("raise RuntimeError('сломано')\n", encoding="utf-8")
    mgr.settings.update(lambda d: d["tg"].__setitem__("core", "99.0.1"))
    mgr.load_core()
    assert mgr.core.origin == "bundled"
    assert mgr.settings.get("tg", "core") == "bundled" and not folder.exists()
    assert [(a[0], a[1], a[3]) for a in mgr.alerts] == [("tg-core", "warn", "telegram")]
    assert "99.0.1" in mgr.alerts[0][2] and "сломано" in mgr.core_error


def test_bundled_newer_than_downloaded_never_runs_downloaded_code(mgr):
    """Новая Лазейка принесла ядро не старше скачанного — скачанный код не исполняется вовсе."""
    folder = _downloaded_dir("1.0.0")
    (folder / "tgws_proxy").mkdir()
    marker = folder / "executed"
    (folder / "tgws_proxy" / "__init__.py").write_text(
        f"open({str(marker)!r}, 'w').close()\n", encoding="utf-8")
    mgr.settings.update(lambda d: d["tg"].__setitem__("core", "1.0.0"))
    mgr.load_core()
    assert mgr.core.origin == "bundled" and not marker.exists() and not folder.exists()
    assert mgr.settings.get("tg", "core") == "bundled" and mgr.alerts == []


def test_start_turns_load_failure_into_tg_error(mgr, monkeypatch):
    """Ядро не загрузилось (нет модуля в сборке) — TgError, который ловит автозапуск, а не ModuleNotFoundError."""
    monkeypatch.setattr(loader, "load_bundled",
                        lambda: (_ for _ in ()).throw(ModuleNotFoundError("No module named 'cryptography'")))
    with pytest.raises(TgError, match="не загрузилось"):
        mgr.start()
    assert mgr.status == "error"
    with pytest.raises(TgError, match="настройки не проверить"):
        mgr.validate({})


def test_form_accepts_only_ipv4(mgr):
    mgr._install_core(fake_core(serve_until_stopped))
    for host in ("::", "::1", "localhost", "127.0.0.1x"):
        assert "host" in mgr.validate({"host": host})[1], host
    assert "host" not in mgr.validate({"host": "0.0.0.0"})[1]
    mgr.settings.update(lambda d: d["tg"].__setitem__("host", "0.0.0.0"))
    assert mgr.link().startswith("tg://proxy?server=127.0.0.1&")


# ------------------------------------------------------------ запуск, падение, остановка

def test_crash_while_running_is_error_with_callback(mgr):
    """Ядро вышло само — не «выключен» без причины, а ошибка и колбэк (Core ставит плашку и перезапускает)."""
    crashes = []
    mgr.on_crash = crashes.append
    mgr._install_core(fake_core(serve_then_die))
    mgr.start()
    assert mgr.status == "running"
    assert _wait(lambda: crashes)
    assert mgr.status == "error" and "остановился сам" in mgr.error and crashes == [mgr.error]
    assert mgr.settings.get("tg", "was_running") is True, "включался — при следующем запуске включится снова"


def test_requested_stop_is_not_a_crash(mgr):
    crashes = []
    mgr.on_crash = crashes.append
    core = fake_core(serve_until_stopped)
    mgr._install_core(core)
    mgr.start()
    mgr.stop()
    assert mgr.status == "stopped" and crashes == []
    assert core.config._refresh_stop.is_set(), "поток доменов Cloudflare остановлен вместе с прокси"


def test_downloaded_core_that_fails_falls_back_to_bundled(mgr, monkeypatch):
    bundled = fake_core(serve_until_stopped, version="1.11.2", origin="bundled")
    monkeypatch.setattr(loader, "load_bundled", lambda: bundled)
    mgr.settings.update(lambda d: d["tg"].__setitem__("core", "9.9.9"))
    mgr._install_core(fake_core(crash_at_start))
    mgr.start()
    assert mgr.core is bundled and mgr.status == "running"
    assert mgr.settings.get("tg", "core") == "bundled"
    assert mgr.alerts and mgr.alerts[0][0] == "tg-core" and "ядро не поднялось" in mgr.alerts[0][2]


def test_install_mode_does_not_fall_back(mgr, monkeypatch):
    monkeypatch.setattr(loader, "load_bundled", lambda: pytest.fail("при установке встроенное не подставляется"))
    mgr._install_core(fake_core(crash_at_start))
    with pytest.raises(TgError, match="аварийно"):
        mgr.start(fallback=False)


def test_slow_stop_blocks_new_start_until_old_thread_ends(mgr, monkeypatch):
    """Остановка дольше STOP_WAIT: старый поток не забыт, новый запуск не поднимается рядом с ним."""
    monkeypatch.setattr(tgm, "STOP_WAIT", 0.2)
    release = threading.Event()

    async def stubborn(main, stop_event):
        main._server_instance = object()
        await stop_event.wait()
        await asyncio.get_running_loop().run_in_executor(None, release.wait, 5)
        main._server_instance = None

    mgr._install_core(fake_core(stubborn))
    mgr.start()
    old = mgr._thread
    mgr.stop()
    assert old.is_alive() and mgr._thread is old and mgr.status == "stopped"
    with pytest.raises(TgError, match="ещё не закрылся"):
        mgr.start()
    release.set()
    old.join(5)
    mgr._install_core(fake_core(serve_until_stopped))
    mgr.start()
    assert mgr.status == "running" and mgr._loop is not None, "поля нового запуска не затёрты старым потоком"


def test_restarts_are_serialized(mgr):
    """Сон и смена сети разом: перезапуски идут по очереди, а не наперегонки."""
    mgr._install_core(fake_core(serve_until_stopped))
    mgr.start()
    errors = []

    def restart():
        try:
            mgr.restart()
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    workers = [threading.Thread(target=restart) for _ in range(3)]
    for w in workers:
        w.start()
    for w in workers:
        w.join(10)
    assert errors == [] and mgr.status == "running" and mgr._thread.is_alive()


def test_switch_core_resets_counters(mgr):
    mgr._install_core(fake_core(serve_until_stopped, stats=_stats(bytes_up=10_000, connections_bad=5)))
    mgr.sample()
    mgr.refresh_client()
    assert mgr._last_sample is not None and mgr._bad_seen[0] == 5
    first = mgr.core
    mgr.switch_core(fake_core(serve_until_stopped, version="9.9.8"))
    assert mgr._last_sample is None and mgr._bad_seen == (0, 0.0)
    assert first.config._refresh_stop.is_set()
