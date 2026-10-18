import os
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Тесты не должны трогать настоящий ProgramData\Lazeyka.
os.environ.setdefault("LAZEYKA_DATA", tempfile.mkdtemp(prefix="lazeyka-test-data-"))
# Свой VPN: ядро в тестах не запускается, системный прокси, kill switch и обработчик ссылок
# не трогаются (app/vpnclient/guard.py). Статический `sing-box check` — только с фикстурой core_static.
os.environ["LAZEYKA_NO_CORE"] = "1"

BUNDLED_ZIP = next((ROOT / "vendor" / "zapret").glob("zapret-discord-youtube-*.zip"))

_CORE_EXES = {"sing-box.exe", "xray.exe", "sing-box", "xray"}
_REAL_POPEN = subprocess.Popen


class _GuardedPopen(_REAL_POPEN):
    """Ядро VPN из тестов — только статическими командами и только под фикстурой core_static."""

    static_ok = False

    def __init__(self, args, *a, **kw):
        exe = kw.get("executable") or (args[0] if isinstance(args, (list, tuple)) and args else str(args).split()[0])
        if Path(str(exe).strip('"')).name.lower() in _CORE_EXES:
            from app.vpnclient.guard import CoreBlocked, is_static
            rest = [str(x) for x in args[1:]] if isinstance(args, (list, tuple)) else str(args).split()[1:]
            if not (_GuardedPopen.static_ok and is_static(rest)):
                raise CoreBlocked(f"тест пытался запустить ядро VPN: {' '.join(map(str, args))[:200]}")
        super().__init__(args, *a, **kw)


@pytest.fixture(autouse=True)
def _no_core_processes(monkeypatch):
    monkeypatch.setattr(subprocess, "Popen", _GuardedPopen)
    yield


@pytest.fixture
def core_static():
    """Разрешить статические команды ядра (version, check, rule-set compile…) — для LAZEYKA_CORE_CHECK=1."""
    _GuardedPopen.static_ok = True
    try:
        yield
    finally:
        _GuardedPopen.static_ok = False


@pytest.fixture(scope="session")
def pack_dir(tmp_path_factory) -> Path:
    """Распакованный встроенный релиз zapret (только для чтения)."""
    target = tmp_path_factory.mktemp("pack")
    with zipfile.ZipFile(BUNDLED_ZIP) as zf:
        zf.extractall(target)
    inner = [p for p in target.iterdir() if p.is_dir()]
    assert len(inner) == 1
    return inner[0]
