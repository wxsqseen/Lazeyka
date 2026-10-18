"""Свой VPN: клиент clash API и сэмплер трафика — на поддельном HTTP-сервере 127.0.0.1."""
import time

import pytest

from app.vpnclient.clash import ClashClient, ClashError, TrafficSampler
from tests.fakes.fake_clash import FakeClash

URL = "https://www.gstatic.com/generate_204"


@pytest.fixture
def api():
    fake = FakeClash().start()
    yield fake
    fake.stop()


def _client(api, secret=None) -> ClashClient:
    return ClashClient(api.port, secret or api.secret)


def _wait(cond, timeout=10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if cond():
            return True
        time.sleep(0.02)
    return False


def test_version_with_bearer_and_without(api):
    assert _client(api).version() == "sing-box 1.14.3"
    with pytest.raises(ClashError) as err:
        _client(api, secret="wrong").version()
    assert err.value.status == 401


def test_requests_ignore_system_proxy(api, monkeypatch):
    # Системный прокси может указывать на само ядро (режим прокси) или на мёртвый порт.
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("http_proxy", "http://127.0.0.1:9")
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    assert _client(api).version() == "sing-box 1.14.3"


def test_secret_not_in_repr(api):
    assert api.secret not in repr(_client(api))


def test_dead_port_is_a_clear_error():
    with pytest.raises(ClashError, match="не отвечает"):
        ClashClient(9, "x").version()


def test_select_and_errors(api):
    client = _client(api)
    client.select("bypass", "direct")
    assert api.proxies["bypass"]["now"] == "direct"
    with pytest.raises(ClashError, match="Must be a Selector"):
        client.select("auto", "srv-a")
    with pytest.raises(ClashError, match="not found"):
        client.select("proxy", "nope")


def test_proxies_and_one_proxy(api):
    client = _client(api)
    assert client.proxies()["proxy"]["all"] == ["srv-a", "srv-b", "auto"]
    assert client.proxy("auto")["now"] == "srv-b"


def test_close_connections(api):
    _client(api).close_connections()
    assert api.closed == 1 and ("DELETE", "/connections") in api.requests


def test_delay_ok_timeout_error(api):
    client = _client(api)
    assert client.delay("srv-a", URL, 5000) == 87
    with pytest.raises(ClashError, match="нет ответа за 5 с") as err:
        client.delay("srv-b", URL, 5000)
    assert err.value.status == 504
    api.delays["srv-a"] = "error"
    with pytest.raises(ClashError, match="ошибка соединения"):
        client.delay("srv-a", URL, 5000)
    api.delays["srv-a"] = 0      # 0 мс sing-box считает ошибкой
    with pytest.raises(ClashError):
        client.delay("srv-a", URL, 5000)


@pytest.mark.parametrize("url, timeout", [("http://www.gstatic.com/generate_204", 5000), (URL, 0),
                                          (URL, 32768), (URL, True)])
def test_delay_arguments_are_checked_before_request(api, url, timeout):
    with pytest.raises(ClashError):
        _client(api).delay("srv-a", url, timeout)
    assert not any(path.endswith("/delay") for _, path in api.requests)


def test_group_delay_skips_failed_members(api):
    assert _client(api).group_delay("proxy", URL, 5000) == {"srv-a": 87}
    with pytest.raises(ClashError, match="нет в работающей"):
        _client(api).group_delay("nope", URL, 5000)


def test_sampler_rates_totals_history_and_connections(api):
    api.connections = {"downloadTotal": 5000, "uploadTotal": 700, "connections": [{"id": "1"}, {"id": "2"}],
                       "memory": 1}
    sampler = TrafficSampler(_client(api), groups=("auto",))
    sampler.start()
    try:
        assert _wait(lambda: sampler.snapshot()["stats"]["connections"] == 2)
        api.traffic.put({"up": 100, "down": 2000})
        api.traffic.put({"up": 50, "down": 1000})
        assert _wait(lambda: len(sampler.snapshot()["history"]) == 2)
        snap = sampler.snapshot()
        assert snap["stats"]["up_rate"] == 50.0 and snap["stats"]["down_rate"] == 1000.0
        assert snap["stats"]["up"] == 700 + 150 and snap["stats"]["down"] == 5000 + 3000
        assert snap["now"] == {"auto": "srv-b"}
        assert all(len(point) == 3 for point in snap["history"])
    finally:
        api.traffic.put(None)   # ядро остановлено — поток /traffic закрылся
        sampler.stop(wait=5)
    assert not sampler.running


def test_sampler_survives_dead_api():
    sampler = TrafficSampler(ClashClient(9, "x"))
    sampler.start()
    time.sleep(0.3)
    assert sampler.running and sampler.snapshot()["stats"]["up_rate"] == 0.0
    sampler.stop(wait=5)
    assert not sampler.running
