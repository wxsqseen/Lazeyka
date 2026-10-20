"""Контракт страницы и ядра: ключи state()["vpnclient"] — как в эталоне app/ui/mock-vpnclient-state.json
(его же грузит имитация интерфейса). Проверяются заглушка «недоступно», передача снимка менеджера
и снимок настоящего VpnClientManager."""
from app.core import vpnclient_placeholder
from app.settings import Settings

from tests.test_vpnclient_core import FakeManager, make_core, mock_state

# Разделы, у которых в эталоне — словарь постоянной формы.
NESTED = ("stats", "latency", "speed", "import", "routing", "settings", "traffic", "memory")


def _check_shape(got: dict, expected: dict) -> None:
    assert set(got) == set(expected)
    for key in NESTED:
        assert isinstance(got[key], dict), key
        assert set(got[key]) == set(expected[key]), key
    assert set(got["routing"]["rules"]) == set(expected["routing"]["rules"])
    assert set(got["cores"]) == set(expected["cores"])
    for name, core in expected["cores"].items():
        assert set(got["cores"][name]) == set(core), name


def test_placeholder_matches_mock(tmp_path):
    settings = Settings(tmp_path / "s.json").snapshot()
    _check_shape(vpnclient_placeholder(settings, "нет модуля"), mock_state())


def test_placeholder_settings_come_from_settings(tmp_path):
    s = Settings(tmp_path / "s.json")
    s.update(lambda d: d["vpnclient"].update({"port": 20900, "preset": "except_ru"}))
    vc = vpnclient_placeholder(s.snapshot(), "нет модуля")
    assert vc["settings"]["port"] == 20900 and vc["routing"]["preset"] == "except_ru"
    assert vc["available"] is False and vc["unavailable_reason"] == "нет модуля"


def test_state_passes_manager_snapshot(tmp_path):
    core = make_core(tmp_path, FakeManager())
    _check_shape(core.state()["vpnclient"], mock_state())


def test_state_without_manager_has_same_keys(tmp_path):
    core = make_core(tmp_path, None)
    _check_shape(core.state()["vpnclient"], mock_state())


def test_state_survives_broken_snapshot(tmp_path):
    vc = FakeManager()
    vc.snapshot = lambda: 1 / 0
    core = make_core(tmp_path, vc)
    got = core.state()["vpnclient"]
    _check_shape(got, mock_state())
    assert got["available"] is False and "не ответил" in got["unavailable_reason"]


def test_real_manager_snapshot_matches_mock(tmp_path):
    from app.vpnclient.manager import VpnClientManager
    core = make_core(tmp_path, None)
    manager = VpnClientManager(core.settings, lambda *a, **k: None, True,
                               zapret_view=lambda: None, on_change=lambda *a, **k: None)
    _check_shape(manager.snapshot(), mock_state())
