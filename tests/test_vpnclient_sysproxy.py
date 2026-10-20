"""Свой VPN: системный прокси на поддельном WinINet — LAN и RAS, PAC, исключения, «не наш — не трогаем»."""
import copy
import json
import pathlib

import pytest

from app.vpnclient import guard, sysproxy
from app.vpnclient.sysproxy import (PROXY_TYPE_AUTO_DETECT, PROXY_TYPE_AUTO_PROXY_URL, PROXY_TYPE_DIRECT,
                                    PROXY_TYPE_PROXY, ProxySettings, SysProxy, SysProxyError)

OURS = "127.0.0.1:20808"
OVERRIDE = ["<local>", "localhost", "127.*", "192.168.*"]


class FakeWinInet:
    def __init__(self):
        self.conns = {
            None: ProxySettings(PROXY_TYPE_DIRECT | PROXY_TYPE_AUTO_DETECT, "", "", ""),
            "Билайн L2TP": ProxySettings(PROXY_TYPE_DIRECT | PROXY_TYPE_AUTO_PROXY_URL, "", "",
                                         "http://wpad.corp/proxy.pac"),
        }
        self.refreshed = 0
        self.fail_on = ()      # имя подключения, на котором WinINet откажет (None — это LAN)

    def connections(self):
        return list(self.conns)

    def query(self, conn):
        return copy.copy(self.conns[conn])

    def apply(self, conn, settings):
        if conn in self.fail_on:
            raise SysProxyError("отказ WinINet")
        self.conns[conn] = copy.copy(settings)

    def refresh(self):
        self.refreshed += 1


@pytest.fixture
def fake():
    return FakeWinInet()


@pytest.fixture
def proxy(tmp_path, fake):
    return SysProxy(tmp_path / "sysproxy-backup.json", backend=fake, same_user=lambda: True)


def test_apply_sets_lan_and_ras_and_saves_every_field(proxy, fake):
    before = copy.deepcopy(fake.conns)
    proxy.apply("127.0.0.1", 20808, OVERRIDE)
    for conn in fake.conns.values():
        assert conn.points_to(OURS) and conn.flags == PROXY_TYPE_DIRECT | PROXY_TYPE_PROXY
        assert conn.bypass.split(";")[0] == "<local>" and "192.168.*" in conn.bypass
    assert fake.conns["Билайн L2TP"].autoconfig_url == "http://wpad.corp/proxy.pac"
    assert fake.refreshed == 1
    backup = json.loads(proxy.backup_path.read_text(encoding="utf-8"))
    assert backup["address"] == OURS
    saved = {c["name"]: ProxySettings.from_dict(c) for c in backup["connections"]}
    assert saved == before


def test_restore_returns_pac_and_autodetect(proxy, fake):
    before = copy.deepcopy(fake.conns)
    proxy.apply("127.0.0.1", 20808, OVERRIDE)
    assert proxy.restore() == {"restored": 2, "skipped": 0, "failed": 0}
    assert fake.conns == before
    assert not proxy.backup_path.exists()


def test_restore_continues_after_one_connection_fails(proxy, fake):
    before = copy.deepcopy(fake.conns)
    proxy.apply("127.0.0.1", 20808, OVERRIDE)
    fake.fail_on = (None,)                          # LAN не возвращается — RAS всё равно возвращаем
    assert proxy.restore() == {"restored": 1, "skipped": 0, "failed": 1}
    assert fake.conns["Билайн L2TP"] == before["Билайн L2TP"] and fake.refreshed == 2
    assert proxy.backup_path.exists()               # копия остаётся для повтора
    fake.fail_on = ()
    assert proxy.restore() == {"restored": 1, "skipped": 1, "failed": 0}
    assert fake.conns == before and not proxy.backup_path.exists()


def test_close_refuses_new_apply_but_restore_works(proxy, fake):
    before = copy.deepcopy(fake.conns)
    proxy.apply("127.0.0.1", 20808, OVERRIDE)
    proxy.close()
    with pytest.raises(SysProxyError):
        proxy.apply("127.0.0.1", 20808, OVERRIDE)
    assert proxy.restore()["restored"] == 2 and fake.conns == before


def test_restore_waits_for_apply_in_progress(proxy, fake):
    """Выход Лазейки восстанавливает прокси, пока очередь менеджера его включает: restore ждёт конца
    apply и возвращает всё (раньше копия удалялась до включения и прокси оставался на мёртвом порту)."""
    import threading
    before = copy.deepcopy(fake.conns)
    started, release = threading.Event(), threading.Event()
    real_apply = fake.apply

    def slow_apply(conn, settings):
        started.set()
        release.wait(5)
        real_apply(conn, settings)
    fake.apply = slow_apply
    worker = threading.Thread(target=proxy.apply, args=("127.0.0.1", 20808, OVERRIDE))
    worker.start()
    assert started.wait(5)
    results = []
    restorer = threading.Thread(target=lambda: results.append(proxy.restore()))
    restorer.start()
    restorer.join(0.3)
    assert restorer.is_alive()                      # ждёт блокировку, пока apply не закончит
    fake.apply = real_apply
    release.set()
    worker.join(5)
    restorer.join(5)
    assert results == [{"restored": 2, "skipped": 0, "failed": 0}]
    assert fake.conns == before and not proxy.backup_path.exists()


def test_not_ours_is_left_alone(proxy, fake):
    proxy.apply("127.0.0.1", 20808, OVERRIDE)
    fake.conns[None] = ProxySettings(PROXY_TYPE_PROXY, "10.0.0.1:3128", "<local>", "")   # поменял человек
    result = proxy.restore()
    assert result == {"restored": 1, "skipped": 1, "failed": 0}
    assert fake.conns[None].server == "10.0.0.1:3128"
    assert fake.conns["Билайн L2TP"].flags & PROXY_TYPE_AUTO_PROXY_URL


def test_restore_without_rights_to_delete_backup(proxy, fake, monkeypatch):
    before = copy.deepcopy(fake.conns)
    proxy.apply("127.0.0.1", 20808, OVERRIDE)
    real_unlink = pathlib.Path.unlink

    def deny(self, missing_ok=False):
        if self == proxy.backup_path:
            raise PermissionError(5, "Отказано в доступе")
        return real_unlink(self, missing_ok=missing_ok)

    monkeypatch.setattr(pathlib.Path, "unlink", deny)
    assert proxy.restore()["restored"] == 2
    assert fake.conns == before
    # копия осталась, но повторный возврат ничего не трогает: прокси уже не наш
    assert proxy.restore() == {"restored": 0, "skipped": 2, "failed": 0}


def test_second_apply_keeps_original_backup(proxy, fake):
    before = copy.deepcopy(fake.conns)
    proxy.apply("127.0.0.1", 20808, OVERRIDE)
    proxy.apply("127.0.0.1", 20809, OVERRIDE)      # перезапуск на другом порту
    assert fake.conns[None].points_to("127.0.0.1:20809")
    proxy.restore()
    assert fake.conns == before


def test_failed_apply_reverts_what_was_changed(proxy, fake):
    before = copy.deepcopy(fake.conns)
    fake.fail_on = ("Билайн L2TP",)
    with pytest.raises(SysProxyError, match="не включился"):
        proxy.apply("127.0.0.1", 20808, OVERRIDE)
    assert fake.conns == before


def test_recover_after_crash(tmp_path, fake):
    before = copy.deepcopy(fake.conns)
    first = SysProxy(tmp_path / "backup.json", backend=fake, same_user=lambda: True)
    first.apply("127.0.0.1", 20808, OVERRIDE)
    # Лазейку убили: следующий запуск видит копию и наш адрес
    second = SysProxy(tmp_path / "backup.json", backend=fake, same_user=lambda: True)
    assert second.owned_address() == OURS
    assert second.recover_after_crash(20808) == {"restored": 2, "skipped": 0, "failed": 0}
    assert fake.conns == before
    assert second.recover_after_crash(20808) is None


def test_turn_off_dead_foreign_proxy(proxy, fake):
    fake.conns[None] = ProxySettings(PROXY_TYPE_PROXY, "127.0.0.1:10809", "<local>", "")
    assert proxy.turn_off("127.0.0.1:10809") == 1
    lan = fake.conns[None]
    assert not lan.flags & PROXY_TYPE_PROXY and lan.flags & PROXY_TYPE_DIRECT and lan.server == "127.0.0.1:10809"
    assert fake.conns["Билайн L2TP"].flags & PROXY_TYPE_AUTO_PROXY_URL
    assert proxy.turn_off("127.0.0.1:10809") == 0


def test_other_account_cannot_use_proxy_mode(tmp_path, fake):
    proxy = SysProxy(tmp_path / "b.json", backend=fake, same_user=lambda: False)
    assert "другой учётной записи" in proxy.available()
    with pytest.raises(SysProxyError, match="другой учётной записи"):
        proxy.apply("127.0.0.1", 20808, OVERRIDE)
    assert not (tmp_path / "b.json").exists()
    assert SysProxy(tmp_path / "c.json", backend=fake, same_user=lambda: None).available() is None


def test_real_backend_is_guarded(tmp_path, monkeypatch):
    monkeypatch.setattr(guard, "core_blocked", lambda: True)
    proxy = SysProxy(tmp_path / "b.json")
    with pytest.raises(guard.CoreBlocked):
        proxy.apply("127.0.0.1", 20808, OVERRIDE)
    with pytest.raises(guard.CoreBlocked):
        proxy.restore()
    assert not (tmp_path / "b.json").exists()


@pytest.mark.parametrize("server, flags, expected", [
    (OURS, PROXY_TYPE_PROXY, True),
    ("http=127.0.0.1:20808;https=127.0.0.1:20808", PROXY_TYPE_PROXY | PROXY_TYPE_DIRECT, True),
    ("http=127.0.0.1:20808;https=10.0.0.1:3128", PROXY_TYPE_PROXY, False),
    (OURS, PROXY_TYPE_DIRECT, False),
    ("", PROXY_TYPE_PROXY, False),
])
def test_points_to(server, flags, expected):
    assert ProxySettings(flags, server).points_to(OURS) is expected


def test_real_wininet_read_only_smoke():
    """Только чтение: раскладка структур WinINet и RAS на настоящей системе (ничего не меняется)."""
    backend = sysproxy.WinInet()
    conns = backend.connections()
    assert conns[0] is None and all(isinstance(c, str) for c in conns[1:])
    lan = backend.query(None)
    known = PROXY_TYPE_DIRECT | PROXY_TYPE_PROXY | PROXY_TYPE_AUTO_PROXY_URL | PROXY_TYPE_AUTO_DETECT
    assert isinstance(lan.flags, int) and not lan.flags & ~known, f"флаги WinINet не разобраны: {lan.flags:#x}"
    assert isinstance(lan.server, str) and isinstance(lan.bypass, str)


def test_user_sids_are_readable():
    sid = sysproxy.process_user_sid()
    assert sid and sid.startswith("S-1-5-")
    shell = sysproxy.shell_user_sid()                  # None — нет рабочего стола (служба, сеанс без оболочки)
    assert shell is None or shell.startswith("S-1-5-")
    assert sysproxy.shell_user_matches() is (None if shell is None else shell == sid)
