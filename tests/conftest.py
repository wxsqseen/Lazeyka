import os
import sys
import tempfile
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Тесты не должны трогать настоящий ProgramData\Lazeyka.
os.environ.setdefault("LAZEYKA_DATA", tempfile.mkdtemp(prefix="lazeyka-test-data-"))

BUNDLED_ZIP = next((ROOT / "vendor" / "zapret").glob("zapret-discord-youtube-*.zip"))


@pytest.fixture(scope="session")
def pack_dir(tmp_path_factory) -> Path:
    """Распакованный встроенный релиз zapret (только для чтения)."""
    target = tmp_path_factory.mktemp("pack")
    with zipfile.ZipFile(BUNDLED_ZIP) as zf:
        zf.extractall(target)
    inner = [p for p in target.iterdir() if p.is_dir()]
    assert len(inner) == 1
    return inner[0]
