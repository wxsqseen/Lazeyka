"""Исключения Microsoft Defender: без реального вызова PowerShell (подменяем _run_ps)."""
import os

import pytest

from app import winutil
from app.settings import Settings
from app.winutil import RunResult


@pytest.fixture
def no_ps(monkeypatch):
    """Перехватывает запуски PowerShell и отдаёт заранее заданный ответ; копит скрипты."""
    calls: list[str] = []
    box = {"result": RunResult(0, "ok", "")}

    def fake(script: str, timeout: float = 25.0) -> RunResult:
        calls.append(script)
        return box["result"]

    monkeypatch.setattr(winutil, "_run_ps", fake)
    return calls, box


def test_ps_literal_escapes_quotes():
    assert winutil._ps_literal(r"C:\Path") == r"'C:\Path'"
    assert winutil._ps_literal("it's") == "'it''s'"


def test_under_only_inside_roots(tmp_path):
    root = str(tmp_path / "Lazeyka")
    os.makedirs(root)
    assert winutil._under(os.path.join(root, "bin", "winws.exe"), (root,))
    assert winutil._under(root, (root,))
    assert not winutil._under(str(tmp_path / "Downloads" / "x.exe"), (root,))
    assert not winutil._under(r"C:\Windows\System32", (root,))


def test_add_exclusions_refuses_paths_outside_lazeyka(no_ps, tmp_path):
    calls, _ = no_ps
    root = str(tmp_path / "Lazeyka")
    os.makedirs(root)
    res = winutil.defender_add_exclusions([r"C:\\"], [r"C:\Windows\System32\cmd.exe"], (root,))
    assert res.code == 1 and not calls   # ничего широкого в PowerShell не ушло


def test_add_exclusions_builds_commands_for_in_root_targets(no_ps, tmp_path):
    calls, _ = no_ps
    root = str(tmp_path / "Lazeyka")
    os.makedirs(root)
    winws = os.path.join(root, "bin", "winws.exe")
    outside = str(tmp_path / "Downloads" / "Lazeyka.exe")
    res = winutil.defender_add_exclusions([root], [winws, outside], (root,))
    assert res.code == 0 and len(calls) == 1
    script = calls[0]
    assert f"Add-MpPreference -ExclusionPath {winutil._ps_literal(root)}" in script
    assert f"Add-MpPreference -ExclusionProcess {winutil._ps_literal(winws)}" in script
    assert "Downloads" not in script   # путь вне папок Лазейки отброшен


def test_exclusions_parse_json(monkeypatch):
    monkeypatch.setattr(winutil, "_run_ps", lambda *a, **k: RunResult(
        0, '{"paths":["C:\\\\ProgramData\\\\Lazeyka\\\\"],"procs":["C:\\\\winws.exe"]}', ""))
    paths, procs = winutil.defender_exclusions()
    assert r"c:\programdata\lazeyka" in paths and r"c:\winws.exe" in procs


def test_exclusions_empty_when_powershell_silent(monkeypatch):
    monkeypatch.setattr(winutil, "_run_ps", lambda *a, **k: RunResult(0, "", ""))
    assert winutil.defender_exclusions() == (set(), set())


# ------------------------------------------------------------ сторона core

class _FakeZapret:
    def __init__(self, pack=True):
        from types import SimpleNamespace

        from app import paths
        self.pack = SimpleNamespace(path="X") if pack else None
        self.winws_exe = os.path.join(str(paths.DATA), "zapret", "packs", "1.10.3", "bin", "winws.exe")
        self.available = pack
        self.av_removal_seen = True
        self.inited = 0

    def init(self):
        self.inited += 1


def _core(tmp_path, admin=True, pack=True):
    from app.core import Core
    core = Core.__new__(Core)
    core.is_admin = admin
    core.settings = Settings(tmp_path / "s.json")
    core.zapret = _FakeZapret(pack=pack)
    core.defender_state = {"checked": False, "running": False}
    core._notices = []
    core.background = lambda name, fn, on_error: fn()
    core.notify = lambda *a, **k: None
    return core


def test_targets_are_only_lazeyka(tmp_path, monkeypatch):
    core = _core(tmp_path)
    paths_ex, procs, roots = core._defender_targets()
    # Каждый процесс обязан лежать внутри заявленных корней.
    assert all(any(winutil._under(p, (r,)) for r in roots) for p in procs)
    assert core.zapret.winws_exe in procs
    from app import paths
    assert str(paths.DATA) in roots   # папка данных — среди исключаемых корней


def test_defender_exclude_requires_admin(tmp_path):
    core = _core(tmp_path, admin=False)
    with pytest.raises(PermissionError):
        core.defender_exclude()


def test_defender_exclude_passes_only_in_root_targets(tmp_path, monkeypatch):
    core = _core(tmp_path)
    captured = {}

    def fake_add(paths_ex, procs, roots):
        captured["paths"], captured["procs"], captured["roots"] = paths_ex, procs, roots
        return RunResult(0, "ok", "")

    monkeypatch.setattr(winutil, "defender_add_exclusions", fake_add)
    monkeypatch.setattr(winutil, "defender_present", lambda: True)
    monkeypatch.setattr(winutil, "defender_active", lambda: True)
    monkeypatch.setattr(winutil, "defender_exclusions", lambda: (set(), set()))
    res = core.defender_exclude()
    assert res["ok"]
    assert captured["roots"] and all(winutil._under(p, captured["roots"]) for p in captured["procs"])


def test_defender_exclude_reports_failure(tmp_path, monkeypatch):
    core = _core(tmp_path)
    monkeypatch.setattr(winutil, "defender_add_exclusions", lambda *a: RunResult(1, "", "доступ запрещён"))
    res = core.defender_exclude()
    assert not res["ok"] and "доступ запрещён" in res["error"]


def test_notice_only_after_removal_and_not_excluded(tmp_path):
    core = _core(tmp_path)
    core.updates = _NoUpdates()
    core._conflicts = []
    core._original_tgws = False
    core._dismissed = set()
    # Defender ещё не проверен — кнопки нет.
    assert not _has_defender_notice(core)
    core.defender_state = {"active": True, "excluded": False}
    assert _has_defender_notice(core)
    # Уже в исключениях — не предлагаем.
    core.defender_state = {"active": True, "excluded": True}
    assert not _has_defender_notice(core)
    # Удаления не было — молчим даже при активном Defender.
    core.zapret.av_removal_seen = False
    core.defender_state = {"active": True, "excluded": False}
    assert not _has_defender_notice(core)


class _NoUpdates:
    releases: dict = {}

    def available_count(self):
        return 0


def _has_defender_notice(core) -> bool:
    return any(n["id"] == "defender" for n in core._persistent_notices())
