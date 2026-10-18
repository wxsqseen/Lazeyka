"""Безопасная распаковка: лимит объёма задаёт потребитель, фильтр файлов, zip-slip."""
import zipfile

import pytest

from app import archive


def _zip_with_zeros(path, size):
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        with zf.open("core/big.bin", "w") as out:
            chunk = b"\0" * (1 << 20)
            for _ in range(size // len(chunk)):
                out.write(chunk)
        zf.writestr("core/LICENSE", "license")


def test_limit_is_a_parameter(tmp_path):
    src = tmp_path / "big.zip"
    _zip_with_zeros(src, 65 * 1024 * 1024)          # больше лимита пакета zapret (64 МиБ)
    with pytest.raises(archive.ArchiveError, match="большой объём"):
        archive.extract(src, tmp_path / "a")
    out = archive.extract(src, tmp_path / "b", max_unpacked=128 * 1024 * 1024)
    assert (out / "big.bin").stat().st_size == 65 * 1024 * 1024 and (out / "LICENSE").is_file()


def test_skip_filter(tmp_path):
    src = tmp_path / "x.zip"
    with zipfile.ZipFile(src, "w") as zf:
        zf.writestr("xray.exe", "MZ")
        zf.writestr("geoip.dat", "x")
        zf.writestr("geosite.dat", "x")
        zf.writestr("LICENSE", "l")
    out = archive.extract(src, tmp_path / "x", skip=lambda p: p.name.startswith("geo") and p.suffix == ".dat")
    assert sorted(p.name for p in out.iterdir()) == ["LICENSE", "xray.exe"]


@pytest.mark.parametrize("name", ["../evil.txt", "C:/evil.txt", "a/../../evil.txt", "/abs.txt"])
def test_unsafe_paths(tmp_path, name):
    src = tmp_path / "evil.zip"
    with zipfile.ZipFile(src, "w") as zf:
        zf.writestr(name, "x")
    with pytest.raises(archive.ArchiveError, match="Небезопасный путь"):
        archive.extract(src, tmp_path / "out")
