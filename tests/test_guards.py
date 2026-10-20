import sys
import threading
from types import SimpleNamespace

import pytest

from app import paths, webview_guard
from app.errors import UserError
from app.tgproxy.manager import _component_dir
from app.webview_guard import ALLOW, OUTSIDE, REFUSE, _origin, navigation_decision
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


UI = "http://127.0.0.1:51234"


@pytest.mark.parametrize("uri, allowed, decision, pinned", [
    ("about:blank", None, ALLOW, None),                              # pywebview открывает сам, ничего не закрепляем
    ("about:blank", UI, ALLOW, UI),
    (UI + "/index.html", None, ALLOW, UI),                           # первая навигация закрепляет интерфейс
    ("https://github.com/", None, REFUSE, None),                     # первая — не на встроенный сервер
    ("http://localhost:51234/", None, REFUSE, None),
    (UI, UI, ALLOW, UI),
    (UI + "/js/app.js", UI, ALLOW, UI),
    ("http://127.0.0.1:51235/", UI, OUTSIDE, UI),                    # другой порт того же адреса
    ("http://127.0.0.1:512345/", UI, OUTSIDE, UI),                   # тот же префикс, другой порт
    (UI + "@evil.example/", UI, OUTSIDE, UI),                        # «пользователь@хост» в адресе
    ("blob:" + UI + "/0b5e", UI, OUTSIDE, UI),                       # blob того же источника Chromium пускает
    ("data:text/html,<h1>x</h1>", UI, OUTSIDE, UI),
    ("file:///C:/x.html", UI, OUTSIDE, UI),
    ("https://github.com/", UI, OUTSIDE, UI),
])
def test_navigation_decision(uri, allowed, decision, pinned):
    assert navigation_decision(uri, allowed) == (decision, pinned)


def test_navigation_lock_is_wired_into_webview(monkeypatch):
    """install() ставит решение в обработчики EdgeChrome: отменённое не доходит до pywebview, чужое — в браузер."""
    calls, opened = [], []

    class FakeEdgeChrome:
        def on_navigation_start(self, sender, args):
            calls.append(str(args.Uri))

        def on_new_window_request(self, sender, args):
            raise AssertionError("новое окно pywebview не открывает")

        def on_webview_ready(self, sender, args):
            return None

    import webview.platforms
    fake = SimpleNamespace(EdgeChrome=FakeEdgeChrome)
    monkeypatch.setitem(sys.modules, "webview.platforms.edgechromium", fake)
    monkeypatch.setattr(webview.platforms, "edgechromium", fake, raising=False)
    monkeypatch.setattr(webview_guard, "_installed", False)
    monkeypatch.setattr(webview_guard.winutil, "open_unelevated", opened.append)
    webview_guard.install()

    window = FakeEdgeChrome()
    nav = [SimpleNamespace(Uri=uri, Cancel=False)
           for uri in (UI + "/index.html", UI + "/app.css", "https://github.com/x", "blob:" + UI + "/1")]
    for args in nav:
        window.on_navigation_start(None, args)
    assert calls == [UI + "/index.html", UI + "/app.css"]
    assert [args.Cancel for args in nav] == [False, False, True, True]
    assert opened == ["https://github.com/x"], "веб-ссылка — в обычный браузер, blob — никуда"
    new_window = SimpleNamespace(Uri="https://example.com/", Handled=False)
    window.on_new_window_request(None, new_window)
    assert new_window.Handled and opened[-1] == "https://example.com/"


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
