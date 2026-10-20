"""Секреты своего VPN не утекают: ни в get_state(), ни в отчёт помощи, ни в журнал — фильтр стоит
на обработчиках (файл и кольцевой буфер), поэтому ловит и notify(), и _guard, и log.exception."""
import json
import logging
import urllib.parse

import pytest

from app import helpdesk
from app import log as applog
from app.vpnclient import model

from tests.test_vpnclient_core import FakeManager, make_core, mock_state

UUID = "9d1c3b7e-55aa-4c1e-b0f2-1234567890ab"
PASSWORD = "hy2-Pa55w0rd-very-secret"
SUB_TOKEN = "Zx9TokenAbc123def456"
SUB = f"https://panel.example.com/api/sub/{SUB_TOKEN}"
SECRETS = (UUID, PASSWORD, SUB, SUB_TOKEN)


@pytest.fixture
def journal(tmp_path):
    """Настоящий журнал (log.setup) во временной папке; после теста — прежние обработчики."""
    root = logging.getLogger()
    saved, level = list(root.handlers), root.level
    log_file = applog.setup(tmp_path / "logs")
    yield log_file
    for handler in list(root.handlers):
        root.removeHandler(handler)
        if handler is not applog.ring:
            handler.close()
    for handler in saved:
        root.addHandler(handler)
    root.setLevel(level)


@pytest.fixture
def secrets():
    applog.add_secrets([UUID, PASSWORD, SUB])
    yield
    applog.remove_secrets([UUID, PASSWORD, SUB])


def _journal_text(log_file) -> str:
    for handler in logging.getLogger().handlers:
        handler.flush()
    ring = "\n".join(ln["msg"] for ln in applog.ring.since(0, "all", limit=100000)["lines"])
    return log_file.read_text(encoding="utf-8") + "\n" + ring


def _clean(text: str) -> bool:
    return not any(s in text for s in SECRETS)


def test_scrub_variants(secrets):
    assert applog.scrub(f"ключ {UUID}") == f"ключ {applog.MASK}"
    assert SUB_TOKEN not in applog.scrub(f"GET /api/sub/{SUB_TOKEN} → 403")       # токен из пути подписки
    assert "subscribe" in applog.scrub("subscribe")                             # слово — не токен


# Каждый вариант секрета — своей строкой журнала, в которой есть только он: иначе его маскирует сосед.

def test_scrub_percent_encoded_secret():
    secret = "p@ss/wörd+42&x"
    applog.add_secrets([secret])
    encoded = urllib.parse.quote(secret, safe="")
    assert applog.scrub(f"запрос ?password={encoded}") == f"запрос ?password={applog.MASK}"


def test_scrub_path_and_query_of_address():
    applog.add_secrets(["https://panel.example.com/private-area/sub?id=5"])
    assert applog.scrub("GET /private-area/sub?id=5 → 403") == f"GET {applog.MASK} → 403"   # путь с запросом


def test_scrub_query_of_address():
    applog.add_secrets(["https://panel.example.com/sub?token=Qw3rTy9uIo"])
    assert applog.scrub("параметры token=Qw3rTy9uIo отклонены") == f"параметры {applog.MASK} отклонены"


def test_scrub_token_from_address_path():
    applog.add_secrets([SUB])
    assert applog.scrub(f"зеркало https://mirror.example.net/s/{SUB_TOKEN}") == \
        f"зеркало https://mirror.example.net/s/{applog.MASK}"                    # тот же токен, другой адрес


@pytest.mark.parametrize("field", ["msg", "exc_text", "stack_info"])
def test_secret_filter_cleans_every_text_of_record(secrets, field):
    record = logging.LogRecord("lazeyka.vpnclient", logging.ERROR, __file__, 1, "сообщение", (), None)
    setattr(record, field, f"{field}: ключ {UUID}")
    assert applog.secret_filter.filter(record) is True
    assert getattr(record, field) == f"{field}: ключ {applog.MASK}"


def test_remove_secrets_is_refcounted():
    applog.add_secrets(["shared-secret-1"])
    applog.add_secrets(["shared-secret-1"])
    applog.remove_secrets(["shared-secret-1"])
    assert "shared-secret-1" not in applog.scrub("shared-secret-1")
    applog.remove_secrets(["shared-secret-1"])
    assert applog.scrub("shared-secret-1") == "shared-secret-1"


def test_notify_keeps_secrets_out_of_state_and_journal(tmp_path, journal, secrets):
    core = make_core(tmp_path, FakeManager())
    core.notify("error", f"Подписка {SUB} не загрузилась: сервер отклонил ключ {UUID}")
    state = json.dumps(core.state(), ensure_ascii=False)
    assert _clean(state) and "Подписка" in state
    assert _clean(_journal_text(journal))


def test_guard_keeps_secrets_out_of_reply_and_journal(tmp_path, journal, secrets):
    from app.api import Api
    core = make_core(tmp_path, FakeManager())

    def boom_user(_id):
        raise RuntimeError(f"сервер {UUID} не ответил")

    def boom_bug(_id):
        raise KeyError(SUB)                        # не UserError: _guard пишет log.exception и repr

    core.vpnclient_select = boom_user
    core.vpnclient_qr = boom_bug
    api = Api(core)
    first, second = api.vpnclient_select("x"), api.vpnclient_qr("x")
    assert first["ok"] is False and second["ok"] is False
    assert _clean(first["error"]) and _clean(second["error"]) and "Внутренняя ошибка" in second["error"]
    text = _journal_text(journal)
    assert "Ошибка в vpnclient_qr" in text and "Traceback" in text and _clean(text)


def test_log_exception_and_args_are_scrubbed(journal, secrets):
    logger = logging.getLogger("lazeyka.vpnclient.manager")
    try:
        raise ValueError(f"подписка {SUB} вернула 403, пароль {PASSWORD}")
    except ValueError:
        logger.exception("Подписка не обновилась: %s", SUB)
    logger.warning("ядро: %s", f"vless://{UUID}@203.0.113.10:443")
    text = _journal_text(journal)
    assert "Подписка не обновилась" in text and "ValueError" in text and _clean(text)
    lines = applog.ring.since(0, "vpn", limit=100000)["lines"]
    assert any("Подписка не обновилась" in ln["msg"] for ln in lines)


def test_repr_and_public_of_server_have_no_secrets():
    server = model.Server(proto="vless", host="nl1.example.com", port=443, name="Амстердам", uuid=UUID,
                          password=PASSWORD, security="reality",
                          tls={"sni": "www.example.com", "pbk": "Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw"},
                          raw=f"vless://{UUID}@nl1.example.com:443#x", xray_outbound={"settings": {"id": UUID}})
    for text in (repr(server), json.dumps(server.public(), ensure_ascii=False)):
        assert _clean(text) and "Z84J2" not in text and "vless://" not in text
    assert "nl1.example.com" not in json.dumps(server.public())


def test_report_has_no_secrets_and_no_server_addresses(secrets):
    vc = mock_state()
    vc["error_kind"] = "tls"
    vc["diagnosis"] = {"side": "provider", "code": "keys_outdated", "text": "…", "advice": "…"}
    state = {
        "app": {"admin": True}, "zapret": {"status": "running"}, "tg": {"status": "running"},
        "vpn": {"active": False, "compat": True, "servers": [], "adapters": [],
                "filter": {"mode": "vpn", "interfaces": [17], "servers": ["198.51.100.7"],
                           "servers_seen": ["198.51.100.7"]}},
        "vpnclient": vc, "diag": {"items": []},
    }
    tail = [
        {"lvl": "error", "t": 0, "src": "vpn", "msg": f"dial tcp nl1.example.net:443 (203.0.113.9): ключ {UUID}"},
        {"lvl": "warn", "t": 0, "src": "app", "msg": "Обход исключил сервер 198.51.100.7 из перехвата"},
        {"lvl": "warn", "t": 0, "src": "vpn", "msg": f"Подписка {SUB} не обновилась, config.json в 07:00:00"},
        {"lvl": "warn", "t": 0, "src": "vpn", "msg": "выход 203.0.113.5 проверен"},
    ]
    text = helpdesk.build_report(state, tail)
    assert "Свой VPN: running" in text and "серверов 5" in text and "vless/tcp/reality" in text
    assert "Ошибка своего VPN: tls" in text
    assert "Причина: keys_outdated (provider)" in text and "Нет ответа: udp_blocked (isp) ×1" in text, \
        "причины — кодами, без имён серверов"
    assert _clean(text)
    for leaked in ("nl1.example.net", "203.0.113.9", "198.51.100.7", "203.0.113.5", "Амстердам", "panel.example.com"):
        assert leaked not in text, leaked
    assert "config.json" in text and "07:00:00" in text            # имена файлов и время — не адреса


# ------------------------------------------------------------ закрытая папка с ключами

def test_private_sddl_has_no_read_for_users():
    import ctypes
    from app import security
    assert security.PRIVATE_SDDL == "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
    for who in ("BU", "WD", "AU", "IU"):
        assert f";;;{who})" not in security.PRIVATE_SDDL
    descriptor = ctypes.c_void_p()
    assert security._advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        security.PRIVATE_SDDL, 1, ctypes.byref(descriptor), None)
    security._kernel32.LocalFree(descriptor)


def test_secure_private_dir_does_nothing_in_tests(tmp_path):
    from app import security
    target = tmp_path / "vpnclient"
    security.secure_private_dir(target)
    assert not target.exists()


def test_secure_private_dir_applies_private_acl(tmp_path, monkeypatch):
    from app import paths, security
    applied, removed = [], []
    monkeypatch.setattr(paths, "test_data_override", lambda: False)
    monkeypatch.setattr(security, "_apply_protected_acl", lambda path, sddl=security.SDDL: applied.append((path, sddl)))
    monkeypatch.setattr(security, "is_link", lambda path: path.name == "link")
    monkeypatch.setattr(security, "_remove", lambda path: removed.append(path))
    security.secure_private_dir(tmp_path / "vpnclient")
    assert (tmp_path / "vpnclient").is_dir() and applied == [(tmp_path / "vpnclient", security.PRIVATE_SDDL)]
    security.secure_private_dir(tmp_path / "link")       # ссылку на чужую папку — убрать и создать заново
    assert removed == [tmp_path / "link"] and applied[-1][1] == security.PRIVATE_SDDL
