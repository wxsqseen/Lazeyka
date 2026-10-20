"""Лицензии сборки (build/third_party.py): что попало в exe — по TOC, тексты — из dist-info и build/licenses,
и сборка останавливается на компоненте без текста или без строки в THIRD_PARTY.md."""
import importlib.metadata
import importlib.util
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("build_third_party", ROOT / "build" / "third_party.py")
third_party = sys.modules["build_third_party"] = importlib.util.module_from_spec(_spec)   # dataclass ищет модуль
_spec.loader.exec_module(third_party)
THIRD_PARTY_MD = ROOT / "THIRD_PARTY.md"


def _module_file(dist: str, name: str) -> str:
    return str(next(Path(importlib.metadata.distribution(dist).locate_file(f))
                    for f in importlib.metadata.distribution(dist).files if Path(str(f)).name == name))


def test_components_follow_the_files_of_the_build(tmp_path):
    zapret_zip = next((ROOT / "vendor" / "zapret").glob("*.zip"))
    entries = [
        ("bottle", _module_file("bottle", "bottle.py"), "PYMODULE"),
        ("json", str(Path(sys.base_prefix) / "Lib" / "json" / "__init__.py"), "PYMODULE"),
        ("libssl-3-x64.dll", str(Path(sys.base_prefix) / "DLLs" / "libssl-3-x64.dll"), "BINARY"),
        ("vendor\\zapret\\" + zapret_zip.name, str(zapret_zip), "DATA"),
        ("app\\core.py", str(ROOT / "app" / "core.py"), "PYMODULE"),               # своё — не компонент
        ("base_library.zip", str(tmp_path / "base_library.zip"), "DATA"),
        ("MSVCP140.dll", r"C:\Program Files\Some JDK\bin\MSVCP140.dll", "BINARY"),
    ]
    found = {c.folder: c for c in third_party.components(entries, ROOT, tmp_path)}
    assert set(found) == {"bottle", "cpython", "openssl", "zapret-discord-youtube", "zapret", "windivert",
                          "microsoft-runtime", "pyinstaller"}, "загрузчик PyInstaller — в каждом exe"
    assert found["bottle"].version == importlib.metadata.version("bottle")
    assert all(f.is_file() for c in found.values() for f in c.files)


def test_unknown_file_stops_the_build(tmp_path):
    with pytest.raises(third_party.LicenseError, match="не отнесены ни к одному компоненту"):
        third_party.components([("mystery.dll", r"C:\Elsewhere\mystery.dll", "BINARY")], ROOT, tmp_path)


def test_component_must_be_named_in_third_party_md(tmp_path):
    found = third_party.components([("bottle", _module_file("bottle", "bottle.py"), "PYMODULE")], ROOT, tmp_path)
    third_party.check(found, THIRD_PARTY_MD)
    bare = tmp_path / "THIRD_PARTY.md"
    bare.write_text("# Сторонние компоненты\n\nPyInstaller\n", encoding="utf-8")
    with pytest.raises(third_party.LicenseError, match="не названы в THIRD_PARTY.md: bottle"):
        third_party.check(found, bare)


def test_component_without_license_text_stops_the_build(tmp_path):
    lonely = third_party.Component("lonely", "lonely", "lonely", "1.0", "MIT", [tmp_path / "нет-такого.txt"])
    with pytest.raises(third_party.LicenseError, match="Нет текста лицензии"):
        third_party.check([lonely], THIRD_PARTY_MD)


def test_every_known_component_has_text_and_a_line_in_third_party_md():
    third_party.check([third_party._native(folder) for folder in third_party.NATIVE], THIRD_PARTY_MD)
    assert all(path.is_file() for paths in third_party.EXTRA.values() for path in paths)


def test_license_datas_and_index_match_selftest(tmp_path):
    from app import selftest
    entries = [("pystray", _module_file("pystray", "__init__.py"), "PYMODULE")]
    datas = third_party.license_datas(entries, project_root=ROOT, third_party_md=THIRD_PARTY_MD, work_dir=tmp_path)
    bundle = tmp_path / "bundle"
    for dest, src, kind in datas:
        assert kind == "DATA" and dest.startswith("licenses")
        target = bundle / dest
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(Path(src).read_bytes())
    assert (bundle / "licenses" / "pystray" / "COPYING.LGPL").is_file(), "LGPL pystray — в exe"
    assert "компонентов: 2" in selftest.check_licenses(bundle / "licenses", frozen=True)       # pystray и загрузчик
    (bundle / "licenses" / "pystray" / "COPYING.LGPL").unlink()
    with pytest.raises(FileNotFoundError, match="COPYING.LGPL"):
        selftest.check_licenses(bundle / "licenses", frozen=True)


# ------------------------------------------------------------ закреплённые версии

def _pins(path: Path) -> dict[str, str]:
    pins = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?==([^\s;]+)", line)
        if match:
            pins[third_party.normalized(match.group(1))] = match.group(2)
    return pins


def test_lock_pins_what_requirements_pin_and_what_is_installed():
    """requirements-lock.txt — та же версия каждой прямой зависимости и ровно то, что стоит в окружении:
    тесты и сборка идут на закреплённых пакетах, а не на том, что оказалось в .venv."""
    direct, locked = _pins(ROOT / "requirements.txt"), _pins(ROOT / "requirements-lock.txt")
    assert direct and all(locked.get(name) == version for name, version in direct.items()), \
        {name: (version, locked.get(name)) for name, version in direct.items() if locked.get(name) != version}
    installed = {third_party.normalized(d.metadata["Name"]): d.version for d in importlib.metadata.distributions()}
    assert {name: installed.get(name) for name in locked} == locked
    lock_text = (ROOT / "requirements-lock.txt").read_text(encoding="utf-8")
    assert lock_text.count("==") == len(locked) and lock_text.count("--hash=sha256:") >= len(locked), "у каждого — хеш"
