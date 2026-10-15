import threading
import time

import pytest

from app import paths
from app.errors import UserError
from app.tgproxy.manager import _component_dir
from app.webview_guard import _origin
from app.zapret.tester import StrategyTester


@pytest.mark.parametrize("value", ["C:\\evil", "..\\..\\x", "1.11.3/../../x", "", "v1.2", "a b"])
def test_component_dir_rejects_paths_from_settings(value):
    assert _component_dir(value) is None


def test_component_dir_accepts_version():
    target = _component_dir("1.11.3")
    assert target is not None
    assert target.is_relative_to(paths.TGWS_COMPONENTS_DIR.resolve())
    assert target.name == "tgws_proxy"


@pytest.mark.parametrize("uri, origin", [
    ("http://127.0.0.1:51234/index.html", "http://127.0.0.1:51234"),
    ("http://127.0.0.1:51234/", "http://127.0.0.1:51234"),
    ("https://127.0.0.1:51234/", None),
    ("http://localhost:51234/", None),
    ("http://127.0.0.1.evil.com:80/", None),
    ("file:///C:/x.html", None),
    ("https://github.com/", None),
])
def test_navigation_origin(uri, origin):
    assert _origin(uri) == origin


class _FakeStrategy:
    def __init__(self, sid):
        self.id = sid
        self.label = sid
        self.usable = True


class _FakeZapret:
    is_admin = True
    pack = object()
    unavailable_reason = None
    strategies = [_FakeStrategy("general")]


def test_second_test_start_is_refused():
    tester = StrategyTester(_FakeZapret(), lambda *_: None)
    gate = threading.Event()
    tester._run = lambda kind, chosen: gate.wait(5)  # подбор «идёт», пока не отпустим
    tester.start("standard", None)
    with pytest.raises(UserError, match="уже идёт"):
        tester.start("standard", None)
    gate.set()
    tester.join(5)
    assert not tester.running


def test_unavailable_bypass_refuses_test():
    z = _FakeZapret()
    z.is_admin = False
    z.unavailable_reason = "Для работы обхода нужны права администратора."
    with pytest.raises(UserError, match="права администратора"):
        StrategyTester(z, lambda *_: None).start("standard", None)
