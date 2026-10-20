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


# ------------------------------------------------------------ «Мои сайты» и исключённые IP

@pytest.mark.parametrize("raw, expected", [
    ("https://Site.ru/path?q=1", "site.ru"),
    ("http://sub.site.ru:8080/x", "sub.site.ru"),
    ("Пример.рф", "xn--e1afmkfd.xn--p1ai"),
    ("*.discord.gg", "discord.gg"),
    ("^exact.example.com", "^exact.example.com"),
    ("site.ru # мой", None),
    ("не домен", None),
    ("https://", None),
])
def test_clean_domain(raw, expected):
    assert ls.clean_domain(raw) == expected


@pytest.mark.parametrize("raw, expected", [
    ("192.168.0.0/16", "192.168.0.0/16"), ("10.1.2.3", "10.1.2.3"), ("10.1.2.3/8", "10.0.0.0/8"),
    ("10.0.0.1-10.0.0.9", "10.0.0.1-10.0.0.9"), ("2a06:98c0::/29", "2a06:98c0::/29"),
    ("10.0.0.9-10.0.0.1", None), ("1.2.3.300", None), ("site.ru", None),
])
def test_clean_network(raw, expected):
    assert ls.clean_network(raw) == expected


def test_user_sites_are_normalized_and_garbage_is_named(tmp_path):
    saved = ls.save_user_list(tmp_path, "list-general-user.txt", "# мои\nhttps://Site.ru/video\nПример.рф\n")
    assert saved == "# мои\r\nsite.ru\r\nxn--e1afmkfd.xn--p1ai\r\n", "комментарий остаётся, адрес — как понимает winws"
    with pytest.raises(ls.ListError, match=r"строка 2: «не домен»"):
        ls.save_user_list(tmp_path, "list-general-user.txt", "site.ru\nне домен\n")
    with pytest.raises(ls.ListError, match="IP-адрес"):
        ls.save_user_list(tmp_path, "ipset-exclude-user.txt", "192.168.0.0/16\nроутер\n")
    assert (tmp_path / "list-general-user.txt").read_text(encoding="utf-8") == saved.replace("\r\n", "\n"), \
        "отвергнутое не записано"


def test_migration_keeps_original_lists_as_is(tmp_path):
    saved = ls.save_user_list(tmp_path, "list-general-user.txt", "странная строка\n", check=False)
    assert saved == "странная строка\r\n"


def test_emptied_user_file_goes_to_winws_as_placeholder(tmp_path):
    user, target = tmp_path / "user", tmp_path / "lists"
    target.mkdir()
    ls.ensure_user_lists(user)
    (user / "list-general-user.txt").write_bytes(b"")              # опустошили в папке списков
    (user / "ipset-exclude-user.txt").write_bytes(b"# only comment\r\n")
    ls.sync_user_lists(user, target)
    assert ls.PLACEHOLDER_DOMAIN in (target / "list-general-user.txt").read_text(encoding="utf-8")
    assert ls.NONE_MARKER in (target / "ipset-exclude-user.txt").read_text(encoding="utf-8")


def test_lan_vpn_networks_are_always_excluded_by_address(tmp_path):
    """Radmin VPN (26/8) и Hamachi (25/8): игровой фильтр и IPSet «все адреса» их трафик не трогают."""
    user, target = tmp_path / "user", tmp_path / "lists"
    target.mkdir()
    ls.save_user_list(user, "ipset-exclude-user.txt", "192.168.1.0/24\n")
    ls.sync_user_lists(user, target)
    copy = (target / "ipset-exclude-user.txt").read_text(encoding="utf-8").splitlines()
    assert copy[0] == "192.168.1.0/24" and ls.MANAGED_HEADER in copy
    assert "25.0.0.0/8" in copy and "26.0.0.0/8" in copy
    assert "26.0.0.0/8" not in (user / "ipset-exclude-user.txt").read_text(encoding="utf-8"), "свой список не тронут"


def test_downloaded_ipset_must_be_addresses(lists_dir):
    with pytest.raises(ValueError, match="испорчен"):
        ls.store_full_ipset(lists_dir, "<!DOCTYPE html>\n<title>Портал Wi-Fi</title>\n")
    assert ls.store_full_ipset(lists_dir, "1.1.1.0/24\n2606:4700::/32\n") == 2
