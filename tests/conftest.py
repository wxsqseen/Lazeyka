import collections
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Тесты не трогают настоящий ProgramData\Lazeyka: папка данных — всегда своя, временная (даже если
# LAZEYKA_DATA задана в оболочке), и в конце прогона удаляется (pytest_unconfigure).
TEST_DATA = Path(tempfile.mkdtemp(prefix="lazeyka-test-data-"))
os.environ["LAZEYKA_DATA"] = str(TEST_DATA)
# Свой VPN: ядро в тестах не запускается, системный прокси, kill switch и обработчик ссылок
# не трогаются (app/vpnclient/guard.py). Статический `sing-box check` — только с фикстурой core_static.
os.environ["LAZEYKA_NO_CORE"] = "1"

BUNDLED_ZIP = next((ROOT / "vendor" / "zapret").glob("zapret-discord-youtube-*.zip"))

_CORE_EXES = {"sing-box.exe", "xray.exe", "sing-box", "xray"}
_REAL_POPEN = subprocess.Popen


# ------------------------------------------------------------ пропуски по переключателям окружения

# Маркер (pytest.ini) → (пропускать ли сейчас, причина). Других пропусков в наборе быть не должно:
# с --allow-skips прогон падает на любом пропуске, кроме названных переключателей (build/build.ps1).
SWITCHES = {
    "network": (lambda: os.environ.get("LAZEYKA_NO_NETWORK") == "1", "без сети (LAZEYKA_NO_NETWORK=1)"),
    "core_check": (lambda: os.environ.get("LAZEYKA_CORE_CHECK") != "1",
                   "статическая проверка ядрами — только с LAZEYKA_CORE_CHECK=1"),
    "core_e2e": (lambda: os.environ.get("LAZEYKA_CORE_E2E") != "1",
                 "живой прогон ядер — только с LAZEYKA_CORE_E2E=1"),
}
_switched_off: dict[str, str] = {}      # nodeid → маркер, по которому тест пропущен
_skipped: dict[str, str] = {}           # nodeid → причина любого пропуска


def pytest_addoption(parser):
    parser.addoption("--allow-skips", default=None, metavar="МАРКЕРЫ",
                     help="через запятую — переключатели, пропуск по которым допустим (" + ", ".join(SWITCHES)
                          + "); любой другой пропуск проваливает прогон")


def pytest_configure(config):
    allowed = config.getoption("--allow-skips")
    unknown = sorted(set(_split(allowed)) - set(SWITCHES)) if allowed is not None else []
    if unknown:
        raise pytest.UsageError(f"--allow-skips: неизвестные переключатели {unknown}; есть {sorted(SWITCHES)}")


def _split(value: str | None) -> list[str]:
    return [part.strip() for part in (value or "").split(",") if part.strip()]


def pytest_collection_modifyitems(config, items):
    for item in items:
        for name, (switched_off, reason) in SWITCHES.items():
            if item.get_closest_marker(name) is not None and switched_off():
                item.add_marker(pytest.mark.skip(reason=reason))
                _switched_off[item.nodeid] = name
                break


def pytest_runtest_logreport(report):
    if report.skipped:
        reason = report.longrepr[2] if isinstance(report.longrepr, tuple) else str(report.longrepr)
        _skipped[report.nodeid] = reason.removeprefix("Skipped: ")


def pytest_sessionfinish(session, exitstatus):
    allowed = session.config.getoption("--allow-skips")
    if allowed is None:
        return
    stray = {nodeid: reason for nodeid, reason in _skipped.items()
             if _switched_off.get(nodeid) not in _split(allowed)}
    if not stray:
        return
    reporter = session.config.pluginmanager.get_plugin("terminalreporter")
    if reporter is not None:
        reporter.ensure_newline()
        reporter.write_sep("=", f"недопустимые пропуски ({len(stray)}), разрешены только: {allowed or 'никакие'}",
                           red=True)
        for nodeid, reason in stray.items():
            reporter.write_line(f"{nodeid}: {reason}")
    if session.exitstatus == pytest.ExitCode.OK:
        session.exitstatus = pytest.ExitCode.TESTS_FAILED


# ------------------------------------------------------------ временная папка данных

def _make_writable_and_retry(func, path, _exc_info):
    os.chmod(path, stat.S_IWRITE)
    func(path)


def pytest_unconfigure(config):
    """Папка данных прогона (её не удаляет tmp_path: она нужна с импорта app.paths) — в конце прогона."""
    try:
        shutil.rmtree(TEST_DATA, onerror=_make_writable_and_retry)
    except OSError as exc:
        sys.stderr.write(f"Временная папка данных тестов {TEST_DATA} удалена не целиком: {exc}\n")


# ------------------------------------------------------------ общие фикстуры

class _GuardedPopen(_REAL_POPEN):
    """Ядро VPN из тестов — только статическими командами и только под фикстурой core_static."""

    static_ok = False
    live_ok = False      # LAZEYKA_CORE_E2E=1 и фикстура core_live: живой прогон на 127.0.0.1

    def __init__(self, args, *a, **kw):
        exe = kw.get("executable") or (args[0] if isinstance(args, (list, tuple)) and args else str(args).split()[0])
        if Path(str(exe).strip('"')).name.lower() in _CORE_EXES:
            from app.vpnclient.guard import CoreBlocked, is_static
            rest = [str(x) for x in args[1:]] if isinstance(args, (list, tuple)) else str(args).split()[1:]
            if not (_GuardedPopen.live_ok or (_GuardedPopen.static_ok and is_static(rest))):
                raise CoreBlocked(f"тест пытался запустить ядро VPN: {' '.join(map(str, args))[:200]}")
        super().__init__(args, *a, **kw)


@pytest.fixture(autouse=True)
def _no_core_processes(monkeypatch):
    monkeypatch.setattr(subprocess, "Popen", _GuardedPopen)
    yield


@pytest.fixture(autouse=True)
def _no_program_files(monkeypatch, tmp_path_factory):
    """Копия для автозапуска лежит в настоящем Program Files: самообновление и автозапуск в тестах
    видят вместо неё временную папку (копии там нет, пока тест её не положит)."""
    from app import autostart
    target = tmp_path_factory.mktemp("program-files") / "Lazeyka" / "Lazeyka.exe"
    monkeypatch.setattr(autostart, "installed_exe", lambda: target)


@pytest.fixture(autouse=True)
def _log_secrets_isolated():
    """Фильтр секретов журнала один на процесс: что тест в него добавил, следующему не достаётся."""
    from app import log as applog
    with applog._secrets_lock:
        saved = collections.Counter(applog._secrets)
    yield
    with applog._secrets_lock:
        applog._secrets.clear()
        applog._secrets.update(saved)
        applog._rebuild()


@pytest.fixture
def core_static():
    """Разрешить статические команды ядра (version, check, rule-set compile…) — для LAZEYKA_CORE_CHECK=1."""
    _GuardedPopen.static_ok = True
    try:
        yield
    finally:
        _GuardedPopen.static_ok = False


@pytest.fixture
def core_live(monkeypatch):
    """Живой прогон ядер — только с LAZEYKA_CORE_E2E=1 и только в режиме «Только локальный прокси»
    на 127.0.0.1: без TUN, системного прокси и kill switch (их тест дополнительно запрещает)."""
    if os.environ.get("LAZEYKA_CORE_E2E") != "1":
        pytest.skip(SWITCHES["core_e2e"][1])
    monkeypatch.delenv("LAZEYKA_NO_CORE", raising=False)
    _GuardedPopen.live_ok = True
    try:
        yield
    finally:
        _GuardedPopen.live_ok = False


@pytest.fixture(scope="session")
def pack_dir(tmp_path_factory) -> Path:
    """Распакованный встроенный релиз zapret (только для чтения)."""
    target = tmp_path_factory.mktemp("pack")
    with zipfile.ZipFile(BUNDLED_ZIP) as zf:
        zf.extractall(target)
    inner = [p for p in target.iterdir() if p.is_dir()]
    assert len(inner) == 1
    return inner[0]
