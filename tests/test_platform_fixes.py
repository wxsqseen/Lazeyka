"""Мелочи платформы по аудиту: подсказка значка в единицах UTF-16, действия меню трея, стенд интерфейса без
чужих запросов, ветка реестра человека за компьютером, тексты ошибок служб, ключ Telegram-прокси в журнале,
адреса сайтов кириллицей. Система не трогается: реестр, значок и сеть — подделки."""
import ctypes
from ctypes import wintypes
from types import SimpleNamespace

import pytest

from app import log as applog
from tests.fakes.vpn_world import wait_for

FLAG = "\U0001F1F3\U0001F1F1"      # флаг Нидерландов: два символа, четыре единицы UTF-16


# ------------------------------------------------------------ значок в трее

class _Tip(ctypes.Structure):
    _fields_ = [("szTip", wintypes.WCHAR * 128), ("szInfo", wintypes.WCHAR * 256)]


def test_utf16_cut_never_splits_a_pair():
    from app.tray import utf16_cut
    assert utf16_cut("a" * 125 + FLAG, 127) == "a" * 125 + FLAG[0]
    assert utf16_cut("a" * 126 + FLAG, 127) == "a" * 126
    assert utf16_cut("короткий", 127) == "короткий"


def _tray(core):
    from app.tray import Tray
    tray = Tray.__new__(Tray)
    tray.core = core
    tray.notes = []
    tray.notify = tray.notes.append
    return tray


def _core(**kw):
    core = SimpleNamespace(zapret=SimpleNamespace(status="stopped", available=True),
                           tg=SimpleNamespace(status="stopped"), vpnclient=None, shown=[], calls=[])
    core.show = lambda: core.shown.append(1)
    core.vpn_preflight = lambda component: {"ok": True, "ask": False, "component": component}
    for name in ("zapret_start", "zapret_stop", "tg_start", "tg_stop"):
        setattr(core, name, (lambda n: lambda *a, **k: core.calls.append(n) or {"ok": True})(name))
    for key, value in kw.items():
        setattr(core, key, value)
    return core


def test_tooltip_with_flag_in_server_name_fits_windows():
    """Флаг страны в имени сервера: по символам 127, а в единицах UTF-16 — больше 128, и Windows
    отвергала подсказку (ValueError), значок переставал обновляться."""
    class Vpn:
        def snapshot(self):
            return {"available": True, "status": "running", "selected": {"name": FLAG * 12},
                    "stats": {"down_rate": 1843200.0, "up_rate": 15360.0}}

    tray = _tray(_core(vpnclient=Vpn(), active_alerts=lambda: [{"level": "warn", "text": FLAG * 40}]))
    tip = tray._tooltip()
    holder = _Tip()
    holder.szTip = tip                     # как pystray: не помещается — ValueError
    assert len(tip.encode("utf-16-le")) // 2 <= 127
    assert tip.splitlines()[2] == "Discord и YouTube: обход выключен"
    holder.szInfo = __import__("app.tray", fromlist=["utf16_cut"]).utf16_cut(FLAG * 200, 255)


def test_tray_zapret_toggle_goes_through_vpn_window():
    """Включение обхода из трея рядом с чужим VPN — окно Лазейки с вопросом, а не включение вслепую."""
    core = _core()
    core.vpn_preflight = lambda component: {"ok": True, "ask": True, "vpn": {"label": "Incy"}}
    tray = _tray(core)
    tray._toggle_zapret()
    tray._toggle_tg()
    assert core.calls == [] and core.shown == [1, 1] and "Incy" in tray.notes[0] and "обход" in tray.notes[0]
    core.vpn_preflight = lambda component: {"ok": True, "ask": False}
    tray._toggle_zapret()
    assert core.calls == ["zapret_start"]


def test_tray_actions_report_errors_instead_of_raising():
    def fail(*a, **k):
        raise PermissionError("Нужны права администратора — перезапустите Лазейку с ними")

    core = _core(zapret_set_strategy=fail, tg_start=fail)
    tray = _tray(core)
    tray._choose("general")()
    tray._toggle_tg()
    assert tray.notes == ["Нужны права администратора — перезапустите Лазейку с ними"] * 2


def test_tray_connect_telegram_reports_result():
    """«Подключить Telegram» из трея: ответ ядра не теряется, а выключенный прокси включается."""
    core = _core()
    core.tg_open_in_telegram = lambda: {"ok": False, "error": "Не получилось открыть Telegram автоматически."}
    tray = _tray(core)
    tray._open_telegram()
    assert wait_for(lambda: tray.notes == ["Не получилось открыть Telegram автоматически."])
    assert core.calls == ["tg_start"]


# ------------------------------------------------------------ стенд интерфейса

def _headers(**kw):
    out = {"Host": "127.0.0.1:8765"}
    out.update({k.replace("_", "-"): v for k, v in kw.items()})
    return out


def test_ui_bridge_refuses_foreign_pages():
    from tools.ui_bridge import TOKEN_HEADER, request_allowed, shim
    token = "t0ken"
    ok_post = _headers(Origin="http://127.0.0.1:8765", Sec_Fetch_Site="same-origin", **{TOKEN_HEADER: token})
    assert request_allowed("POST", ok_post, 8765, token)
    assert request_allowed("GET", _headers(Sec_Fetch_Site="none"), 8765, token)
    assert not request_allowed("POST", _headers(**{TOKEN_HEADER: "wrong"}), 8765, token)
    assert not request_allowed("POST", _headers(), 8765, token), "форма с чужого сайта токена не знает"
    assert not request_allowed("POST", dict(ok_post, Host="evil.example:8765"), 8765, token), "DNS rebinding"
    assert not request_allowed("POST", dict(ok_post, Origin="https://evil.example"), 8765, token)
    assert not request_allowed("GET", _headers(Sec_Fetch_Site="cross-site"), 8765, token), "shim с токеном"
    body = shim(["vpn_probe"], token).decode()
    assert TOKEN_HEADER in body and '"t0ken"' in body and '["vpn_probe"]' in body


# ------------------------------------------------------------ человек за компьютером и Лазейка под другим админом

class FakeRegistry:
    HKEY_CURRENT_USER, HKEY_USERS, REG_SZ = 1, 3, 1

    def __init__(self, values=None):
        self.keys: dict = {}
        self.values = values or {}

    class Key:
        def __init__(self, root, path):
            self.root, self.path = root, path

        def __enter__(self):
            return self

        def __exit__(self, *a):
            pass

    def CreateKey(self, root, path):
        self.keys.setdefault((root, path), {})
        return self.Key(root, path)

    def OpenKey(self, root, path):
        if (root, path) not in self.keys and (root, path) not in self.values:
            raise FileNotFoundError(path)
        return self.Key(root, path)

    def SetValueEx(self, key, name, reserved, kind, value):
        self.keys[(key.root, key.path)][name] = (value, kind)

    def QueryValueEx(self, key, name):
        return self.values[(key.root, key.path)][name]

    def DeleteKey(self, root, path):
        del self.keys[(root, path)]


def test_deeplink_goes_to_desk_user_hive(monkeypatch):
    from app.vpnclient import deeplink, guard
    registry = FakeRegistry()
    monkeypatch.setattr(deeplink, "winreg", registry)
    monkeypatch.setattr(guard, "ensure_allowed", lambda action: None)
    monkeypatch.setattr(deeplink, "process_user_sid", lambda: "S-1-5-21-1-1001")      # администратор из UAC
    monkeypatch.setattr(deeplink, "shell_user_sid", lambda: "S-1-5-21-1-1002")        # тот, кто за компьютером
    deeplink.register(r"C:\Program Files\Lazeyka\Lazeyka.exe")
    roots = {root for root, _path in registry.keys}
    assert roots == {registry.HKEY_USERS}
    assert (registry.HKEY_USERS, r"S-1-5-21-1-1002_Classes\lazeyka\shell\open\command") in registry.keys
    monkeypatch.setattr(deeplink, "process_user_sid", lambda: "S-1-5-21-1-1002")
    assert deeplink._branch() == (registry.HKEY_CURRENT_USER, r"Software\Classes\lazeyka")


def test_system_proxy_is_read_from_desk_user(monkeypatch):
    """VPN-прокси человека (Happ) виден, даже если Лазейка запущена под другим администратором."""
    from app import vpn
    from app.vpnclient import sysproxy
    key = r"S-1-5-21-1-1002\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    registry = FakeRegistry({(3, key): {"ProxyEnable": (1, 4), "ProxyServer": ("127.0.0.1:10808", 1)}})
    monkeypatch.setattr(vpn, "winreg", registry)
    monkeypatch.setattr(sysproxy, "process_user_sid", lambda: "S-1-5-21-1-1001")
    monkeypatch.setattr(sysproxy, "shell_user_sid", lambda: "S-1-5-21-1-1002")
    assert vpn.system_proxy() == "http://127.0.0.1:10808"
    monkeypatch.setattr(sysproxy, "shell_user_sid", lambda: None)        # оболочки нет — свой HKCU
    assert vpn.user_hive() == (registry.HKEY_CURRENT_USER, "") and vpn.system_proxy() is None


# ------------------------------------------------------------ тексты

def test_service_errors_name_only_real_services():
    from app import winutil
    ctypes.set_last_error(5)
    scm = str(winutil._err("Не открыт диспетчер служб Windows"))
    assert "«" not in scm and "SCM" not in scm and "WinError 5" in scm
    ctypes.set_last_error(5)
    assert "«winws»" in str(winutil._err("Не получено состояние службы", "winws"))


def test_tg_secret_never_reaches_the_journal():
    from app.tgproxy.manager import TgProxyManager
    holder = SimpleNamespace()
    secret = "0123456789abcdef0123456789abcdef"
    TgProxyManager._hide_secret(holder, secret)
    try:
        for line in (f"  Secret:        {secret}", f"tg://proxy?server=127.0.0.1&port=1443&secret=dd{secret}",
                     f"secret=ee{secret}676f6f676c652e636f6d"):
            assert secret not in applog.scrub(line)
        new = "fedcba9876543210fedcba9876543210"
        TgProxyManager._hide_secret(holder, new)
        assert new not in applog.scrub(new)
    finally:
        applog.remove_secrets([holder._hidden_secret])


@pytest.mark.parametrize("raw, expected", [
    ("кремль.рф", "xn--e1ajeds9e.xn--p1ai"),
    ("https://www.Кремль.РФ/path", "xn--e1ajeds9e.xn--p1ai"),
    ("xn--d1abbgf6aiiy.xn--p1ai", "xn--d1abbgf6aiiy.xn--p1ai"),
])
def test_check_site_understands_cyrillic_domains(raw, expected):
    from app import helpdesk
    assert helpdesk.normalize_domain(raw) == expected
