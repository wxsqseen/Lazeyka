import json

from app.settings import Settings, defaults
from app.zapret import hosts, migrate


def test_settings_merge_ignores_garbage(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({
        "ui": {"theme": 5, "close_to_tray": False},
        "tg": {"port": "1443", "secret": "zz", "dc_ip": ["2:1.2.3.4"]},
        "updates": {"skipped": {"zapret": "1.10.4"}, "last_check": 123.5},
        "unknown": True,
    }), encoding="utf-8")
    s = Settings(path)
    assert s.get("ui", "theme") == "system"          # неверный тип → умолчание
    assert s.get("ui", "close_to_tray") is False      # верное значение сохраняется
    assert s.get("tg", "port") == 1443                # строка вместо числа → умолчание
    assert len(s.get("tg", "secret")) == 32           # битый ключ заменён
    assert s.get("tg", "dc_ip") == ["2:1.2.3.4"]
    assert s.get("updates", "skipped") == {"zapret": "1.10.4"}
    assert s.get("updates", "last_check") == 123.5
    assert "unknown" not in s.snapshot()


def test_settings_update_is_persisted_atomically(tmp_path):
    s = Settings(tmp_path / "settings.json")
    s.update(lambda d: d["zapret"].__setitem__("strategy", "general (ALT2)"))
    again = Settings(tmp_path / "settings.json")
    assert again.get("zapret", "strategy") == "general (ALT2)"
    assert not (tmp_path / "settings.json.tmp").exists()


def test_settings_without_rights_do_not_create_folder(tmp_path):
    target = tmp_path / "missing" / "settings.json"
    s = Settings(target, allow_create=False)
    s.update(lambda d: d.__setitem__("first_run", False))
    assert not target.parent.exists()
    assert s.writable is False
    assert s.get("first_run") is False  # в памяти изменение есть


def test_defaults_have_fresh_secret():
    assert defaults()["tg"]["secret"] != defaults()["tg"]["secret"]


def _fake_zapret(root, game_filter: str | None):
    (root / "bin").mkdir(parents=True)
    (root / "lists").mkdir()
    (root / "utils").mkdir()
    (root / "service.bat").write_text("@echo off\r\n")
    (root / "lists" / "ipset-all.txt").write_text("")
    if game_filter is not None:
        (root / "utils" / "game_filter.enabled").write_text(game_filter)
    return root


def test_read_game_filter_old_and_new_formats(tmp_path):
    old = _fake_zapret(tmp_path / "old", "all\r\n")
    assert migrate.read_game_filter(old) == {"mode": "all", "tcp": "1024-65535", "udp": "1024-65535"}
    new = _fake_zapret(tmp_path / "new", "mode=udp\r\ntcp=1024-2000\r\nudp=27015\r\n")
    assert migrate.read_game_filter(new) == {"mode": "udp", "tcp": "1024-2000", "udp": "27015"}
    none = _fake_zapret(tmp_path / "none", None)
    assert migrate.read_game_filter(none) is None


def test_root_from_binary(tmp_path):
    root = _fake_zapret(tmp_path / "z", None)
    sys_path = root / "bin" / "WinDivert64.sys"
    assert migrate._root_from_binary(f"\\??\\{sys_path}") == root
    assert migrate._root_from_binary(f'"{root / "bin" / "winws.exe"}" --wf-tcp=80') == root
    assert migrate._root_from_binary(r"C:\Windows\system32\drivers\x.sys") is None


def test_import_copies_only_custom_lists(tmp_path):
    root = _fake_zapret(tmp_path / "z", "mode=all\r\n")
    (root / "lists" / "list-general-user.txt").write_text("# Never leave this file empty\r\ndomain.example.abc\r\n")
    (root / "lists" / "list-exclude-user.txt").write_text("mybank.ru\r\n")
    s = Settings(tmp_path / "settings.json")
    user = tmp_path / "user"
    done = migrate.import_from(root, s, user)
    assert s.get("zapret", "ipset_mode") == "any"
    assert s.get("zapret", "game_filter")["mode"] == "all"
    assert (user / "list-exclude-user.txt").read_bytes() == b"mybank.ru\r\n"
    assert not (user / "list-general-user.txt").exists()
    assert any("Исключения" in item for item in done)


def test_hosts_plan_comments_conflicts_and_keeps_block():
    current = "\n".join([
        "127.0.0.1 localhost",
        "1.2.3.4 github.com",
        hosts.BEGIN, "9.9.9.9 old.example", hosts.END,
    ])
    wanted = [("140.82.121.3", "github.com"), ("162.159.135.232", "discord.com")]
    plan = hosts.plan(current, wanted)
    assert plan["conflicts"] == ["1.2.3.4 github.com"]
    assert hosts.BEGIN not in plan["outside"] and "9.9.9.9 old.example" not in plan["outside"]
    assert ("162.159.135.232", "discord.com") in plan["missing"]


def test_hosts_apply_disables_only_conflicting_names():
    """Строка «старый адрес discord.com + внутреннее имя организации»: отключается discord.com, а внутреннее
    имя остаётся действующим — его сопоставление не теряется."""
    current = ["127.0.0.1 localhost", "10.0.0.5 discord.com intranet.corp  # офис"]
    wanted = [("162.159.135.232", "discord.com")]
    plan = hosts.plan("\n".join(current), wanted)
    assert plan["conflicts"] == ["10.0.0.5 discord.com intranet.corp  # офис"]
    body = hosts._disable_conflicts(plan["outside"], set(plan["conflicts"]), wanted)
    assert body == ["127.0.0.1 localhost", hosts.DISABLED_PREFIX + current[1], "10.0.0.5 intranet.corp # офис"]
    active = hosts.parse("\n".join(body))
    assert ("10.0.0.5", "intranet.corp") in active and ("10.0.0.5", "discord.com") not in active
    assert hosts._disable_conflicts(["1.2.3.4 discord.com"], {"1.2.3.4 discord.com"}, wanted) == [
        hosts.DISABLED_PREFIX + "1.2.3.4 discord.com"], "других имён нет — строка просто отключена"


def test_diagnostics_does_not_claim_timestamps_off_when_unknown(monkeypatch):
    from app.zapret import diagnostics, netcfg
    monkeypatch.setattr(netcfg, "tcp_timestamps_enabled", lambda: None)
    monkeypatch.setattr(diagnostics.winutil, "service_list", lambda drivers=False: [])
    monkeypatch.setattr(diagnostics.winutil, "service_query", lambda name, with_config=False: None)
    monkeypatch.setattr(diagnostics, "_process_running", lambda name: False)
    monkeypatch.setattr(diagnostics, "_vpn_item", lambda *a, **k: diagnostics._item("vpn", "VPN", "ok", "—"))
    monkeypatch.setattr(diagnostics, "doh_configured", lambda: True)
    monkeypatch.setattr(netcfg, "windivert_states", lambda: {})
    item = next(i for i in diagnostics.run_all(None, False) if i["id"] == "tcp_ts")
    assert item["status"] == "info" and "Не удалось узнать" in item["text"] and "Выключены" not in item["text"]
    assert item["fix"]["id"] == "tcp_timestamps"
