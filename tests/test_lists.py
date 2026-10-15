import shutil

import pytest

from app.zapret import gamefilter as gf
from app.zapret import lists as ls


@pytest.mark.parametrize("value, expected", [
    ("1024-65535", "1024-65535"),
    (" 1024-1934, 1936-65535 ", "1024-1934,1936-65535"),
    ("27015", "27015"),
    ("0-100", None),
    ("100-50", None),
    ("70000", None),
    ("123456", None),
    ("1024-", None),
    ("abc", None),
    ("", None),
    ("1,,2", None),
    ("1024\n", None),
])
def test_validate_range(value, expected):
    assert gf.validate_range(value) == expected


def test_port_values_follow_service_bat():
    assert gf.port_values("disabled", "1024-65535", "1024-65535") == ("12", "12")
    assert gf.port_values("all", "1000-2000", "3000-4000") == ("1000-2000", "3000-4000")
    assert gf.port_values("tcp", "1000-2000", "3000-4000") == ("1000-2000", "12")
    assert gf.port_values("udp", "1000-2000", "3000-4000") == ("12", "3000-4000")
    assert gf.port_values("all", "bad", "") == ("1024-65535", "1024-65535")


@pytest.fixture
def lists_dir(pack_dir, tmp_path):
    target = tmp_path / "lists"
    shutil.copytree(pack_dir / "lists", target)
    return target


def test_bundled_pack_starts_in_none_mode(lists_dir):
    assert ls.detect_ipset_mode(lists_dir) == "none"
    assert ls.count_entries(ls.read_full_ipset(lists_dir)) > 30000


def test_ipset_mode_cycle_keeps_full_list(lists_dir):
    full_before = ls.read_full_ipset(lists_dir)
    ls.set_ipset_mode(lists_dir, "loaded")
    assert ls.detect_ipset_mode(lists_dir) == "loaded"
    ls.set_ipset_mode(lists_dir, "any")
    assert ls.detect_ipset_mode(lists_dir) == "any"
    assert (lists_dir / "ipset-all.txt").read_text() == ""
    ls.set_ipset_mode(lists_dir, "none")
    assert ls.detect_ipset_mode(lists_dir) == "none"
    ls.set_ipset_mode(lists_dir, "loaded")
    assert ls.count_entries(ls.read_full_ipset(lists_dir)) == ls.count_entries(full_before)


def test_loaded_without_full_list_is_refused(tmp_path):
    (tmp_path / "ipset-all.txt").write_text("203.0.113.113/32\r\n")
    with pytest.raises(ValueError):
        ls.set_ipset_mode(tmp_path, "loaded")


def test_store_full_ipset_respects_mode(lists_dir):
    ls.set_ipset_mode(lists_dir, "none")
    count = ls.store_full_ipset(lists_dir, "1.1.1.0/24\n8.8.8.0/24\n")
    assert count == 2
    assert ls.detect_ipset_mode(lists_dir) == "none"
    ls.set_ipset_mode(lists_dir, "loaded")
    assert ls.count_entries((lists_dir / "ipset-all.txt").read_text()) == 2


def test_user_lists_never_empty(tmp_path):
    ls.ensure_user_lists(tmp_path)
    saved = ls.save_user_list(tmp_path, "list-general-user.txt", "  \n\n")
    assert ls.PLACEHOLDER_DOMAIN in saved
    saved = ls.save_user_list(tmp_path, "list-general-user.txt", "example.org\nfoo.com  \n\n")
    assert saved == "example.org\r\nfoo.com\r\n"
    with pytest.raises(ValueError):
        ls.save_user_list(tmp_path, "../evil.txt", "x")


def test_sync_user_lists(tmp_path):
    user = tmp_path / "user"
    target = tmp_path / "lists"
    target.mkdir()
    ls.save_user_list(user, "list-exclude-user.txt", "bank.ru\n")
    ls.sync_user_lists(user, target)
    assert (target / "list-exclude-user.txt").read_text() == "bank.ru\n"
    assert (target / "list-general-user.txt").exists()


def test_sync_adds_managed_block_only_to_working_copy(tmp_path):
    user = tmp_path / "user"
    target = tmp_path / "lists"
    target.mkdir()
    ls.save_user_list(user, "list-exclude-user.txt", "bank.ru\n")
    ls.sync_user_lists(user, target, {"list-exclude-user.txt": ["co.uk"], "list-general-user.txt": []})
    copy = (target / "list-exclude-user.txt").read_text(encoding="utf-8")
    assert "bank.ru" in copy and "co.uk" in copy and ls.MANAGED_HEADER in copy
    assert "co.uk" not in (user / "list-exclude-user.txt").read_text(encoding="utf-8")
    ls.sync_user_lists(user, target, {})
    assert "co.uk" not in (target / "list-exclude-user.txt").read_text(encoding="utf-8")
