import re
import threading
import time

import pytest

from app.zapret import tester


def test_targets_from_pack(pack_dir):
    targets = tester.load_targets(pack_dir)
    names = [t.name for t in targets]
    assert "Discord Main" in names and "YouTube Video Redirect" in names
    ping_only = [t for t in targets if t.url is None]
    assert {t.ping_host for t in ping_only} >= {"1.1.1.1", "8.8.8.8"}
    discord = next(t for t in targets if t.name == "Discord Main")
    assert discord.url == "https://discord.com" and discord.ping_host == "discord.com"


def test_targets_fallback_without_pack():
    assert len(tester.load_targets(None)) == len(tester.DEFAULT_TARGETS)


def _row(ok_count: int, ping: int | None):
    statuses = ["ok"] * ok_count + ["fail"] * (3 - ok_count)
    return {"name": "x", "url": "https://x", "http": statuses[0], "tls12": statuses[1],
            "tls13": statuses[2], "ping": ping}


def test_summarize_and_pick_best():
    a = tester.summarize("a", "A", [_row(3, 20), _row(1, None)])
    b = tester.summarize("b", "B", [_row(3, 20), _row(1, 30)])
    c = tester.summarize("c", "C", [_row(0, None), _row(0, None)])
    assert (a["ok"], a["fail"], a["ping_ok"], a["ping_total"]) == (4, 2, 1, 2)
    assert b["ping_ok"] == 2
    assert tester.pick_best([a, b, c]) == "b"   # при равенстве успешных — больше ответов ping
    assert tester.pick_best([c]) is None         # ничего не открылось — лучшей нет


def test_unsupported_tls_is_not_a_failure():
    row = {"name": "x", "url": "https://x", "http": "ok", "tls12": "ok", "tls13": "unsup", "ping": 5}
    s = tester.summarize("a", "A", [row])
    assert (s["ok"], s["fail"], s["unsup"], s["score"]) == (2, 0, 1, 1.0)


def test_candidates_prefer_previous_leaders(monkeypatch):
    class Z:
        strategies = [_FakeStrategy(s) for s in ("general", "general (ALT)", "general (ALT2)", "general (ALT5)")]

    t = tester.StrategyTester.__new__(tester.StrategyTester)
    t.zapret = Z()
    t.state = {"kind": "standard", "finished_at": 1.0, "results": [
        {"id": "general (ALT5)", "ok": 30, "ping_ok": 3, "score": 0.9, "started": True},
        {"id": "general (ALT)", "ok": 10, "ping_ok": 3, "score": 0.3, "started": True},
    ]}
    ids = [s.id for s in t.candidates(exclude="general (ALT)")]
    assert ids[0] == "general (ALT5)"
    assert "general (ALT)" not in ids
    assert set(ids) <= {"general", "general (ALT2)", "general (ALT5)"}


class _FakeStrategy:
    def __init__(self, sid):
        self.id = sid
        self.label = sid
        self.usable = True


# ------------------------------------------------------------ исходы curl и контрольные адреса

@pytest.mark.parametrize("code, err, expected", [
    (0, "", "ok"),
    (6, "curl: (6) Could not resolve host: discord.com", "dns"),
    (60, "curl: (60) SSL certificate problem: self-signed certificate", "ssl"),
    (35, "curl: (35) schannel: failed to receive handshake, SSL/TLS connection failed", "fail"),
    (35, "curl: (35) Recv failure: Connection was reset", "fail"),
    (35, "curl: (35) schannel: TLS 1.3 not supported on Windows prior to 11", "unsup"),
    (2, "curl: option --tls-max: is unknown", "unsup"),
    (4, "curl: (4) A requested feature, protocol or option was not found built-in", "unsup"),
    (28, "curl: (28) Connection timed out after 2001 milliseconds", "fail"),
])
def test_classify_curl(code, err, expected):
    """Сброс рукопожатия DPI — провал, а не «не поддерживается»; «не найден адрес» — не «подмена сертификата»."""
    assert tester.classify_curl(code, err) == expected


def test_dns_failure_counts_against_strategy_and_score_formula_stays():
    row = {"name": "x", "url": "https://x", "http": "ok", "tls12": "dns", "tls13": "unsup", "ping": None}
    s = tester.summarize("a", "A", [row])
    assert (s["ok"], s["fail"], s["unsup"]) == (1, 1, 1)
    assert s["score"] == 0.5, "score = ok / (ok + fail): страница считает «из» так же"


def test_control_needs_any_one_of_independent_targets(monkeypatch):
    asked = []

    def curl(url, mode, timeout=4, cancel=None, bind=None):
        asked.append(url)
        return "ok" if "msftconnecttest" in url else "fail"
    monkeypatch.setattr(tester, "curl_check", curl)
    assert tester.control_ok() is True, "ya.ru заблокирован — интернет от этого не пропал"
    assert any(re.match(r"https?://\d+\.\d+\.\d+\.\d+/", url) for url in tester.CONTROL_URLS), \
        "хотя бы один адрес — без DNS"
    monkeypatch.setattr(tester, "curl_check", lambda *a, **k: "fail")
    assert tester.control_ok() is False


def test_control_returns_on_first_answer(monkeypatch):
    gate = threading.Event()

    def curl(url, mode, timeout=4, cancel=None, bind=None):
        if "ya.ru" in url:
            return "ok"
        gate.wait(5)                                   # остальные молчат до таймаута
        return "fail"
    monkeypatch.setattr(tester, "curl_check", curl)
    began = time.monotonic()
    assert tester.control_ok() is True
    assert time.monotonic() - began < 2
    gate.set()


def test_candidates_rank_by_successes_not_share():
    """Одна удача при остальных «не поддерживается» даёт долю 1.0 — но лидер тот, у кого больше открылось."""
    class Z:
        strategies = [_FakeStrategy(s) for s in ("general", "general (ALT)", "general (ALT2)")]

    t = tester.StrategyTester.__new__(tester.StrategyTester)
    t.zapret = Z()
    t.state = {"kind": "standard", "finished_at": 1.0, "results": [
        {"id": "general (ALT)", "ok": 1, "fail": 0, "ping_ok": 0, "score": 1.0, "started": True},
        {"id": "general (ALT2)", "ok": 30, "fail": 6, "ping_ok": 3, "score": 0.83, "started": True},
    ]}
    assert [s.id for s in t.candidates(exclude=None)][:2] == ["general (ALT2)", "general (ALT)"]
