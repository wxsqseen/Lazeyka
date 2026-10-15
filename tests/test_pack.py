import shutil
import zipfile

import pytest

from app import paths
from app.zapret import pack


@pytest.fixture(autouse=True)
def clean_data():
    shutil.rmtree(paths.PACKS_DIR, ignore_errors=True)
    shutil.rmtree(paths.TMP_DIR, ignore_errors=True)
    yield
    shutil.rmtree(paths.PACKS_DIR, ignore_errors=True)


def test_version_ordering():
    assert pack.version_key("1.10.3") > pack.version_key("1.9.9")
    assert pack.version_key("1.10.3") > pack.version_key("1.10.3b")
    assert pack.version_key("v1.11.2") == pack.version_key("1.11.2")
    assert pack.version_key("1.10") < pack.version_key("1.10.1")


def test_ensure_bundled_installs_once():
    info, fresh = pack.ensure_bundled()
    assert fresh and info is not None and info.version == "1.10.3" and info.source == "bundled"
    assert (info.path / "bin" / "winws.exe").is_file()
    assert (info.path / pack.META_FILE).is_file()
    again, fresh_again = pack.ensure_bundled()
    assert not fresh_again and again.installed_at == info.installed_at
    assert [p.version for p in pack.installed()] == ["1.10.3"]


def test_rollback_is_not_undone_by_bundled_pack():
    pack.ensure_bundled()
    manifest = pack.bundled_manifest()
    pack.install_zip(manifest["zip"], "1.10.4", source="github", expected_sha256=manifest["sha256"])
    info, fresh = pack.ensure_bundled()     # 1.10.3 уже стоит — ничего не ставим и не навязываем
    assert info.version == "1.10.3" and not fresh


def test_bundled_is_skipped_when_newer_is_installed():
    manifest = pack.bundled_manifest()
    pack.install_zip(manifest["zip"], "1.10.9", source="github", expected_sha256=manifest["sha256"])
    info, fresh = pack.ensure_bundled()
    assert info is None and not fresh
    assert [p.version for p in pack.installed()] == ["1.10.9"]


def test_zip_with_drive_in_later_component_is_rejected(tmp_path):
    evil = tmp_path / "evil2.zip"
    with zipfile.ZipFile(evil, "w") as zf:
        zf.writestr("pack/bin/C:evil.txt", "x")
    with pytest.raises(pack.PackError, match="Небезопасный путь"):
        pack.install_zip(evil, "6.6.7", source="github", expected_sha256=None)


def test_checksum_mismatch_is_rejected():
    manifest = pack.bundled_manifest()
    with pytest.raises(pack.PackError, match="Контрольная сумма"):
        pack.install_zip(manifest["zip"], "9.9.9", source="github", expected_sha256="00" * 32)
    assert pack.installed() == []


def test_zip_slip_is_rejected(tmp_path):
    evil = tmp_path / "evil.zip"
    with zipfile.ZipFile(evil, "w") as zf:
        zf.writestr("../../outside.txt", "x")
    with pytest.raises(pack.PackError, match="Небезопасный путь"):
        pack.install_zip(evil, "6.6.6", source="github", expected_sha256=None)


def test_pack_without_winws_is_rejected(tmp_path, pack_dir):
    broken = tmp_path / "broken.zip"
    with zipfile.ZipFile(broken, "w") as zf:
        for path in pack_dir.rglob("*"):
            if path.is_file() and path.name != "winws.exe":
                zf.write(path, "z-1.0/" + path.relative_to(pack_dir).as_posix())
    with pytest.raises(pack.PackError, match="winws.exe"):
        pack.install_zip(broken, "1.0", source="github", expected_sha256=None)


def test_newer_version_installs_side_by_side_and_cleanup(tmp_path):
    old, _ = pack.ensure_bundled()
    manifest = pack.bundled_manifest()
    new = pack.install_zip(manifest["zip"], "1.10.4", source="github", expected_sha256=manifest["sha256"])
    assert {p.version for p in pack.installed()} == {"1.10.3", "1.10.4"}
    assert pack.newest().version == "1.10.4"
    assert old.path.is_dir() and new.path.is_dir()
    pack.cleanup(keep={"1.10.4"})
    assert [p.version for p in pack.installed()] == ["1.10.4"]
