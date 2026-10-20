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
    assert pack.version_key("v1.11.2") == pack.version_key("1.11.2")
    assert pack.version_key("1.10") < pack.version_key("1.10.1")
    assert pack.version_key("1.10") == pack.version_key("1.10.0"), "хвостовой ноль версию не меняет"


def test_flowseal_letter_is_a_later_fix():
    """У Flowseal буква — более позднее исправление той же версии (настоящие теги релизов)."""
    tags = ["1.7.2", "1.7.2b", "1.9.8", "1.9.8b", "1.9.8c", "1.9.9", "1.9.9a", "1.9.9d", "1.10.0", "1.10.3",
            "1.10.3b"]
    assert sorted(reversed(tags), key=pack.version_key) == tags
    assert pack.version_key("1.10.3b") > pack.version_key("1.10.3"), "1.10.3b — обновление для 1.10.3"


def test_prerelease_is_older_than_release():
    """Semver: пре-релиз (через дефис или словом rc/beta) раньше окончательного; с беты предлагается релиз."""
    order = ["1.3.0-alpha.1", "1.3.0-beta", "1.3.0-beta.2", "1.3.0-beta.11", "1.3.0-rc.1", "1.3.0", "1.3.1"]
    assert sorted(reversed(order), key=pack.version_key) == order
    assert pack.version_key("1.3.0rc1") < pack.version_key("1.3.0")
    assert pack.version_key("v1.3.0-rc1") < pack.version_key("1.3.0")
    assert pack.version_key("1.3.0+build5") == pack.version_key("1.3.0")


def test_stale_tmp_is_removed_fresh_is_kept():
    """Хвосты прерванных установок (в том числе ядра Telegram-прокси) убираются, свежие — нет:
    их может писать установка, идущая параллельно."""
    import os
    import time
    paths.TMP_DIR.mkdir(parents=True, exist_ok=True)
    old_dir, fresh_dir = paths.TMP_DIR / "tgws-0badf00d", paths.TMP_DIR / "tgws-11111111"
    old_file, other = paths.TMP_DIR / "app-0badf00d.exe", paths.TMP_DIR / "task-abc.xml"
    for d in (old_dir, fresh_dir):
        (d / "tgws_proxy").mkdir(parents=True)
    old_file.write_bytes(b"x")
    other.write_bytes(b"x")
    hour_ago = time.time() - 2 * pack.STALE_TMP_SECONDS
    for item in (old_dir, old_file, other):
        os.utime(item, (hour_ago, hour_ago))
    pack.remove_stale_tmp()
    assert not old_dir.exists() and not old_file.exists()
    assert fresh_dir.is_dir(), "свежая папка — идущая установка"
    assert other.is_file(), "чужие префиксы не трогаем"


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
