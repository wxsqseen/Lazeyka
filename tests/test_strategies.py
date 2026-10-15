from pathlib import Path

import pytest

from app.zapret import strategies as st


def test_discovers_every_strategy_of_the_bundled_pack(pack_dir):
    found, errors = st.discover(pack_dir)
    assert errors == []
    bats = [p for p in pack_dir.glob("*.bat") if not p.name.lower().startswith("service")]
    assert len(found) == len(bats) == 22
    assert all(s.usable for s in found)
    # Порядок как в service.bat: числа сравниваются как числа.
    ids = [s.id for s in found]
    assert ids.index("general (ALT2)") < ids.index("general (ALT10)")
    assert found[0].id == "general"
    assert found[0].label == "Стандартная"


def test_general_args_match_what_cmd_would_pass(pack_dir):
    strategy = st.parse_file(pack_dir / "general.bat")
    args = strategy.args(pack_dir)
    lists = str(pack_dir / "lists") + "\\"
    binp = str(pack_dir / "bin") + "\\"
    assert args[0] == "--wf-tcp=80,443,2053,2083,2087,2096,8443,12"
    assert args[1] == "--wf-udp=443,19294-19344,50000-50100,12"
    assert args[2] == "--filter-udp=443"
    assert args[3] == f"--hostlist={lists}list-general.txt"
    assert f"--dpi-desync-fake-quic={binp}quic_initial_www_google_com.bin" in args
    assert args.count("--new") == 8
    assert args[-1] == "--dpi-desync-cutoff=n2"
    assert all('"' not in a and "^" not in a and "%" not in a for a in args)


def test_game_filter_values_are_substituted(pack_dir):
    strategy = st.parse_file(pack_dir / "general.bat")
    args = strategy.args(pack_dir, game_tcp="1024-65535", game_udp="1024-65535")
    assert args[0].endswith(",1024-65535")
    assert "--filter-tcp=1024-65535" in args
    assert "--filter-udp=1024-65535" in args


def test_caret_bang_becomes_builtin_fake(pack_dir):
    strategy = st.parse_file(pack_dir / "general (FAKE TLS AUTO).bat")
    args = strategy.args(pack_dir)
    assert "--dpi-desync-fake-tls=!" in args
    assert "--dpi-desync-fake-tls=0x00000000" in args
    assert "--dpi-desync-fake-tls-mod=rnd,dupsid,sni=www.google.com" in args


def test_every_referenced_file_exists(pack_dir):
    found, _ = st.discover(pack_dir)
    for strategy in found:
        for path in st.referenced_files(strategy.args(pack_dir)):
            if path.name.endswith("-user.txt"):
                continue  # создаются при первом запуске
            assert path.exists(), f"{strategy.id}: {path}"


def test_unknown_variable_marks_strategy_unusable(tmp_path):
    bat = tmp_path / "general (NEW).bat"
    bat.write_text('start "x" /min "%BIN%winws.exe" --wf-tcp=%NewVar% --new\r\n', encoding="utf-8")
    strategy = st.parse_file(bat)
    assert strategy.unknown_vars == ["NewVar"]
    assert not strategy.usable
    with pytest.raises(st.StrategyError):
        strategy.args(tmp_path)


def test_file_without_winws_is_reported(tmp_path):
    (tmp_path / "general (BROKEN).bat").write_text("@echo off\r\necho hi\r\n", encoding="utf-8")
    found, errors = st.discover(tmp_path)
    assert found == []
    assert len(errors) == 1 and "BROKEN" in errors[0]


@pytest.mark.parametrize("cmdline, expected", [
    ('a b', ['a', 'b']),
    ('"a b" c', ['a b', 'c']),
    ('--x="C:\\a b\\f.txt"', ['--x=C:\\a b\\f.txt']),
    ('a\\\\"b c"', ['a\\b c']),
    ('a\\"b', ['a"b']),
    ('  a   ', ['a']),
    ('""', ['']),
])
def test_split_args_follows_windows_rules(cmdline, expected):
    assert st.split_args(cmdline) == expected


@pytest.mark.parametrize("arg", [
    "plain", "with space", 'quote"inside', "trailing\\", "C:\\dir with space\\",
    "*.glob", "a?b", "", "back\\\\slash\"q",
])
def test_quote_arg_round_trips(arg):
    assert st.split_args(st.quote_arg(arg)) == [arg]


def test_command_line_quotes_glob_characters():
    line = st.command_line(Path("C:/x/winws.exe"), ["--hostlist-domains=*.example.com", "--new"])
    assert '"--hostlist-domains=*.example.com"' in line
    assert line.endswith(" --new")


def test_labels():
    assert st.label_for("general") == "Стандартная"
    assert st.label_for("general (ALT11)") == "ALT11"
    assert st.label_for("general (FAKE TLS AUTO)") == "FAKE TLS AUTO"
    assert st.label_for("custom") == "custom"
