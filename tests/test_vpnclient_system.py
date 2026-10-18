"""Системные части VPN: WFP/реестр/экран — только подделки, канал — отдельный на тест."""
from __future__ import annotations

import base64
import copy
import ctypes
import io
import json
import logging
import sys
import threading
import time
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest
from PIL import Image

from app.errors import UserError
from app.vpnclient import backup, deeplink, guard, killswitch as ks, qr


@pytest.fixture(autouse=True)
def no_system_changes(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Тест обратился к настоящему WFP, реестру или экрану")

    monkeypatch.setattr(ks, "_load_backend", forbidden)
    monkeypatch.setattr(qr.ImageGrab, "grab", forbidden)
    monkeypatch.setattr(deeplink, "winreg", SimpleNamespace(
        HKEY_CURRENT_USER=1, REG_SZ=1, CreateKey=forbidden, DeleteKey=forbidden,
        OpenKey=forbidden, QueryValueEx=forbidden, SetValueEx=forbidden))


@pytest.fixture(scope="module")
def encrypted():
    data = {"servers": [{"name": "Москва", "password": "секрет сервера"}],
            "settings": {"ipv6": True}, "groups": [], "subscriptions": [{"url": "https://vpn.test/private"}]}
    return data, backup.export_bytes(data, "пароль 1234")


def test_backup_roundtrip_and_format(encrypted):
    data, blob = encrypted
    assert issubclass(backup.BackupError, UserError)
    assert blob.startswith(b"LAZEYKA-VPN-BACKUP 1\n")
    assert "секрет сервера".encode() not in blob
    assert b"https://vpn.test/private" not in blob
    header = json.loads(blob.split(b"\n")[1])
    assert (header["kdf"], header["n"], header["r"], header["p"]) == ("scrypt", 32768, 8, 1)
    assert len(base64.b64decode(header["salt"])) == 16
    assert len(base64.b64decode(header["nonce"])) == 12
    assert backup.import_bytes(blob, "пароль 1234") == data
    second = backup.export_bytes(data, "пароль 1234")
    header2 = json.loads(second.split(b"\n")[1])
    assert header2["salt"] != header["salt"] and header2["nonce"] != header["nonce"]
    assert backup.import_bytes(second, "пароль 1234") == data


def test_backup_wrong_password(encrypted):
    with pytest.raises(backup.BackupError, match="Неверный пароль или файл повреждён"):
        backup.import_bytes(encrypted[1], "другой пароль")


@pytest.mark.parametrize("damage", ["ciphertext", "aad", "salt", "nonce", "truncated", "base64"])
def test_backup_damage(encrypted, damage):
    first, header, payload = encrypted[1].split(b"\n")
    if damage == "ciphertext":
        raw = bytearray(base64.b64decode(payload))
        raw[0] ^= 1
        payload = base64.b64encode(raw)
    elif damage == "aad":
        header = b" " + header  # те же поля JSON, другие аутентифицированные байты
    elif damage in ("salt", "nonce"):
        meta = json.loads(header)
        meta[damage] = "AA=="
        header = json.dumps(meta).encode()
    elif damage == "truncated":
        payload = payload[:12]
    else:
        payload = b"!" + payload[1:]
    with pytest.raises(backup.BackupError, match="Неверный пароль или файл повреждён"):
        backup.import_bytes(b"\n".join((first, header, payload)), "пароль 1234")


@pytest.mark.parametrize("first, message", [(b"LAZEYKA-VPN-BACKUP 2", "более новой"),
    (b"LAZEYKA-VPN-BACKUP 0", "не резервная"), (b"LAZEYKA-VPN-BACKUP x", "не резервная"),
    (b"OTHER 1", "не резервная")])
def test_backup_version(encrypted, first, message):
    with pytest.raises(backup.BackupError, match=message):
        backup.import_bytes(first + b"\n" + encrypted[1].split(b"\n", 1)[1], "пароль 1234")


def test_backup_limits_and_untrusted_kdf(encrypted, monkeypatch):
    with pytest.raises(backup.BackupError, match="8 символов"):
        backup.export_bytes({}, "1234567")
    with pytest.raises(backup.BackupError, match="объектом JSON"):
        backup.export_bytes([], "12345678")
    with pytest.raises(backup.BackupError, match="записать данные"):
        backup.export_bytes({"bad": object()}, "12345678")
    first, header, payload = encrypted[1].split(b"\n")
    meta = json.loads(header)
    meta["n"] = 2**60
    monkeypatch.setattr(backup, "_key", lambda *a: pytest.fail("Не проверены параметры scrypt"))
    with pytest.raises(backup.BackupError, match="повреждён"):
        backup.import_bytes(b"\n".join((first, json.dumps(meta).encode(), payload)), "пароль 1234")
    monkeypatch.setattr(backup, "MAX_BYTES", 100)
    with pytest.raises(backup.BackupError, match="20 МБ"):
        backup.import_bytes(encrypted[1], "пароль 1234")
    with pytest.raises(backup.BackupError, match="20 МБ"):
        backup.export_bytes({"data": "a" * 100}, "пароль 1234")


def test_qr_file_roundtrip(tmp_path):
    text = "vless://id@example.test:443?security=tls#Москва+VPN"
    data_url = qr.png_data_url(text)
    assert issubclass(qr.QrError, UserError)
    assert data_url.startswith("data:image/png;base64,")
    path = tmp_path / "server.png"
    path.write_bytes(base64.b64decode(data_url.split(",", 1)[1]))
    assert qr.decode_file(path) == [text]


def test_qr_limits_and_bad_images(tmp_path, monkeypatch):
    with pytest.raises(qr.QrError, match="слишком длинная"):
        qr.png_data_url("я" * 1451)
    with pytest.raises(qr.QrError, match="Нет текста"):
        qr.png_data_url("")
    with pytest.raises(qr.QrError, match="от 1 до 16"):
        qr.png_data_url("text", box=10000)
    path = tmp_path / "bad.svg"
    path.write_text("<svg/>")
    with pytest.raises(qr.QrError, match="Выберите картинку"):
        qr.decode_file(path)
    path = tmp_path / "bad.png"
    path.write_bytes(b"not png")
    with pytest.raises(qr.QrError, match="открыть картинку"):
        qr.decode_file(path)
    Image.new("RGB", (30, 30), "white").save(path)
    assert qr.decode_file(path) == []
    monkeypatch.setattr(qr, "MAX_PIXELS", 500)
    with pytest.raises(qr.QrError, match="слишком большое"):
        qr.decode_file(path)


def test_qr_screen_uses_only_fake(monkeypatch):
    png = base64.b64decode(qr.png_data_url("https://vpn.test/sub").split(",")[1])
    calls = []

    def grab(**kwargs):
        calls.append(kwargs)
        return Image.open(io.BytesIO(png))

    monkeypatch.setattr(qr.ImageGrab, "grab", grab)
    assert qr.decode_screen() == ["https://vpn.test/sub"]
    assert calls == [{"all_screens": True}]
    monkeypatch.setattr(qr.ImageGrab, "grab", lambda **kw: Image.new("RGB", (64, 64), "white"))
    with pytest.raises(qr.QrError, match="На экране не найден QR-код"):
        qr.decode_screen()


@pytest.mark.parametrize("url, expected", [
    ("lazeyka://import/https://vpn.test/sub?a=b+c#имя", "https://vpn.test/sub?a=b+c#имя"),
    ("lazeyka://import/vless%3A%2F%2Fid%40test%3A443%23%D0%AF", "vless://id@test:443#Я"),
    ("lazeyka://import/YWJj+ZGVm==", "YWJj+ZGVm=="),
    ("lazeyka://import/a%252Fb%2Bc", "a%2Fb+c"),
    ("lazeyka://connect/server", None), ("lazeyka://disconnect", None),
    ("lazeyka://toggle", None), ("lazeyka://status", None),
    ("lazeyka://import", None), ("lazeyka://import/", None),
    ("lazeyka://import@host/text", None), ("lazeyka://import:123/text", None),
    ("lazeyka:///import/text", None), ("https://import/text", None),
    (" lazeyka://import/x", None), ("lazeyka://import/%FF", None),
    ("lazeyka://import/%00", None), (None, None),
])
def test_deeplink_parse(url, expected):
    assert deeplink.SCHEME == "lazeyka"
    assert deeplink.parse(url) == expected


def test_deeplink_parse_byte_limit():
    prefix = "lazeyka://import/"
    assert deeplink.parse(prefix + "a" * (65536 - len(prefix))) is not None
    assert deeplink.parse(prefix + "a" * (65537 - len(prefix))) is None
    assert deeplink.parse(prefix + "я" * 32768) is None


class FakeRegistry:
    HKEY_CURRENT_USER, REG_SZ = 1, 1

    def __init__(self):
        self.keys = {}

    class Key:
        def __init__(self, path):
            self.path = path

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    def CreateKey(self, root, path):
        assert root == self.HKEY_CURRENT_USER
        parts = path.split("\\")
        for count in range(1, len(parts) + 1):
            self.keys.setdefault("\\".join(parts[:count]), {})
        return self.Key(path)

    def OpenKey(self, root, path):
        assert root == self.HKEY_CURRENT_USER
        if path not in self.keys:
            raise FileNotFoundError(path)
        return self.Key(path)

    def SetValueEx(self, key, name, reserved, kind, value):
        self.keys[key.path][name] = (value, kind)

    def QueryValueEx(self, key, name):
        try:
            return self.keys[key.path][name]
        except KeyError:
            raise FileNotFoundError(name)

    def DeleteKey(self, root, path):
        assert root == self.HKEY_CURRENT_USER
        if path not in self.keys:
            raise FileNotFoundError(path)
        assert not any(k.startswith(path + "\\") for k in self.keys)
        del self.keys[path]


def test_register_unregister_fake_only(monkeypatch):
    registry = FakeRegistry()
    monkeypatch.setattr(deeplink, "winreg", registry)
    monkeypatch.delenv("LAZEYKA_NO_CORE", raising=False)
    calls = []
    real_guard = guard.ensure_allowed

    def allowed(action):
        calls.append(action)
        real_guard(action)

    monkeypatch.setattr(guard, "ensure_allowed", allowed)
    assert not deeplink.registered()
    exe = r"C:\Лазейка App\Lazeyka.exe"
    deeplink.register(exe)
    assert deeplink.registered()
    key = r"Software\Classes\lazeyka"
    assert registry.keys[key][""] == ("URL:Лазейка", 1)
    assert registry.keys[key]["URL Protocol"] == ("", 1)
    assert registry.keys[key + r"\DefaultIcon"][""] == (f'"{exe}",0', 1)
    assert registry.keys[key + r"\shell\open\command"][""] == (f'"{exe}" "%1"', 1)
    deeplink.unregister()
    deeplink.unregister()
    assert not deeplink.registered()
    assert calls == ["регистрация ссылок lazeyka://"] * 3
    assert all(not k.startswith(key) for k in registry.keys)


def test_real_registry_guard_precedes_access(monkeypatch):
    monkeypatch.setenv("LAZEYKA_NO_CORE", "1")
    with pytest.raises(guard.CoreBlocked, match="LAZEYKA_NO_CORE=1"):
        deeplink.register(r"C:\Lazeyka.exe")
    with pytest.raises(guard.CoreBlocked, match="LAZEYKA_NO_CORE=1"):
        deeplink.unregister()


@pytest.fixture
def pipe_name():
    return rf"\\.\pipe\Lazeyka.Tests.{uuid.uuid4().hex}"


def test_pipe_roundtrip_and_stop(pipe_name):
    texts, received = [], threading.Event()

    def accept(text):
        texts.append(text)
        received.set()

    server = deeplink.LinkServer(pipe_name=pipe_name)
    server.start(accept)
    try:
        for text in ["lazeyka://import/https://vpn.test/a+b#Москва", "vless://текст", "я" * 32768]:
            received.clear()
            assert deeplink.send_to_running(text, pipe_name=pipe_name)
            assert received.wait(3)
            assert texts[-1] == text
        assert not deeplink.send_to_running("я" * 32769, pipe_name=pipe_name)
    finally:
        server.stop()
    assert not server._thread.is_alive()
    server.stop()
    assert not deeplink.send_to_running("text", timeout=0.05, pipe_name=pipe_name)


def _open_pipe(pipe_name):
    api = deeplink._PipeApi()
    handle = api.kernel.CreateFileW(pipe_name, 0x40000000, 0, None, 3, 0x40110000, None)
    assert handle != ctypes.c_void_p(-1).value
    return api, handle


def test_pipe_stop_with_silent_client(pipe_name):
    server = deeplink.LinkServer(pipe_name=pipe_name)
    server.start(lambda text: pytest.fail("Клиент ничего не отправлял"))
    api, handle = _open_pipe(pipe_name)
    try:
        started = time.monotonic()
        server.stop()
        assert not server._thread.is_alive()
        assert time.monotonic() - started < 2
    finally:
        api.kernel.CloseHandle(handle)
        server.stop()


@pytest.mark.parametrize("payload", [b"\xff", b"a" * 65538, b"nul\0text"],
                         ids=["invalid-utf8", "oversized", "nul"])
def test_pipe_rejects_bad_message_and_recovers(pipe_name, payload):
    texts, received = [], threading.Event()
    server = deeplink.LinkServer(pipe_name=pipe_name)
    server.start(lambda text: (texts.append(text), received.set()))
    api, handle = _open_pipe(pipe_name)
    try:
        buffer = ctypes.create_string_buffer(payload, len(payload))
        try:
            api.io(handle, "write", buffer, deadline=time.monotonic() + 2)
        except OSError:
            pass  # слишком большой пакет может быть отвергнут до завершения WriteFile
    finally:
        api.kernel.CloseHandle(handle)
    try:
        assert deeplink.send_to_running("valid", pipe_name=pipe_name)
        assert received.wait(3)
        assert texts == ["valid"]
    finally:
        server.stop()


def test_pipe_acl_and_flags():
    calls = {}
    api = deeplink._PipeApi.__new__(deeplink._PipeApi)
    api.user_sid = lambda: "S-1-5-21-123-456-789-1001"

    def convert(sddl, revision, target, length):
        calls["sddl"] = sddl
        ctypes.cast(target, ctypes.POINTER(ctypes.c_void_p))[0] = 123
        return True

    def create(name, mode, pipe_mode, count, out_size, in_size, timeout, attrs):
        calls["create"] = (mode, pipe_mode, count, in_size)
        attrs = ctypes.cast(attrs, ctypes.POINTER(deeplink.SECURITY_ATTRIBUTES)).contents
        assert attrs.lpSecurityDescriptor == 123 and not attrs.bInheritHandle
        return 456

    api.advapi = SimpleNamespace(ConvertStringSecurityDescriptorToSecurityDescriptorW=convert)
    api.kernel = SimpleNamespace(CreateNamedPipeW=create, LocalFree=lambda ptr: calls.update(freed=ptr.value))
    assert api.create(r"\\.\pipe\Fake") == 456
    assert calls["sddl"] == "D:(A;;GRGW;;;S-1-5-21-123-456-789-1001)S:(ML;;NW;;;ME)"
    assert calls["create"] == (0x40080001, 0x0E, 1, 65537)
    assert calls["freed"] == 123


def _read(pointer, kind):
    return ctypes.cast(pointer, ctypes.POINTER(kind)).contents


class FakeWfp:
    def __init__(self, fail=None):
        self.fail = fail
        self.calls = []
        self.rules = {}
        self.previous = {}
        self.allocations = {}
        self.freed = []
        self.serial = 0
        self.session_flags = None

    def _result(self, method):
        self.calls.append(method)
        return 5 if self.fail == method else 0

    def FwpmEngineOpen0(self, server, auth, identity, session, handle):
        self.session_flags = _read(session, ks.FWPM_SESSION0).flags
        assert server is None and auth == 10 and identity is None
        code = self._result("open")
        if not code:
            _read(handle, ctypes.c_void_p).value = 123
        return code

    def FwpmEngineClose0(self, handle):
        assert handle.value == 123
        code = self._result("close")
        if not code:
            self.rules = {}
        return code

    def FwpmTransactionBegin0(self, handle, flags):
        self.previous = copy.deepcopy(self.rules)
        return self._result("begin")

    def FwpmTransactionCommit0(self, handle):
        return self._result("commit")

    def FwpmTransactionAbort0(self, handle):
        self.rules = self.previous
        return self._result("abort")

    def FwpmSubLayerAdd0(self, handle, pointer, security):
        sub = _read(pointer, ks.FWPM_SUBLAYER0)
        assert bytes(sub.subLayerKey) == bytes(ks.SUBLAYER_KEY)
        assert sub.flags == 0 and sub.weight > 0 and security is None
        return self._result("sublayer")

    def FwpmGetAppIdFromFileName0(self, filename, target):
        data = filename.lower().encode("utf-16-le") + b"\0\0"
        buffer = (ctypes.c_uint8 * len(data)).from_buffer_copy(data)
        blob = ks.FWP_BYTE_BLOB(len(data), buffer)
        pointer = ctypes.pointer(blob)
        self.allocations[ctypes.addressof(blob)] = (blob, buffer)
        ctypes.cast(target, ctypes.POINTER(ctypes.POINTER(ks.FWP_BYTE_BLOB)))[0] = pointer
        return self._result("app")

    def FwpmFreeMemory0(self, pointer):
        address = _read(pointer, ctypes.c_void_p).value
        assert address in self.allocations
        self.freed.append(address)
        del self.allocations[address]

    def FwpmFilterAdd0(self, handle, pointer, security, filter_id):
        rule = _read(pointer, ks.FWPM_FILTER0)
        assert rule.flags == 0  # нет PERSISTENT, BOOTTIME и обхода чужих запретов
        assert rule.weight.type == ks.FWP_UINT64
        assert bytes(rule.subLayerKey) == bytes(ks.SUBLAYER_KEY)
        conditions = []
        for index in range(rule.numFilterConditions):
            cond = rule.filterCondition[index]
            value = cond.conditionValue
            if value.type == ks.FWP_UINT8:
                parsed = value.uint8
            elif value.type == ks.FWP_UINT16:
                parsed = value.uint16
            elif value.type == ks.FWP_UINT32:
                parsed = value.uint32
            elif value.type == ks.FWP_UINT64:
                parsed = value.uint64.contents.value
            elif value.type == ks.FWP_BYTE_BLOB_TYPE:
                blob = value.byteBlob.contents
                parsed = ctypes.string_at(blob.data, blob.size)
            elif value.type == ks.FWP_V4_ADDR_MASK:
                parsed = (value.v4AddrMask.contents.addr, value.v4AddrMask.contents.mask)
            elif value.type == ks.FWP_V6_ADDR_MASK:
                parsed = (bytes(value.v6AddrMask.contents.addr), value.v6AddrMask.contents.prefixLength)
            else:
                pytest.fail(f"Неизвестный тип условия: {value.type}")
            conditions.append((bytes(cond.fieldKey), cond.matchType, value.type, parsed))
        self.serial += 1
        _read(filter_id, ctypes.c_uint64).value = self.serial
        self.rules[self.serial] = {"layer": bytes(rule.layerKey), "action": rule.action.type,
                                  "weight": rule.weight.uint64.contents.value, "conditions": conditions}
        return self._result("filter")

    def FwpmFilterDeleteById0(self, handle, filter_id):
        del self.rules[filter_id]
        return self._result("delete")


def test_wfp_x64_abi():
    assert ctypes.sizeof(ctypes.c_void_p) == 8
    expected = [(ks.GUID, 16), (ks.FWP_BYTE_BLOB, 16), (ks.FWP_VALUE0, 16),
                (ks.FWP_CONDITION_VALUE0, 16), (ks.FWP_V4_ADDR_AND_MASK, 8),
                (ks.FWP_V6_ADDR_AND_MASK, 17), (ks.FWPM_SESSION0, 72),
                (ks.FWPM_SUBLAYER0, 72), (ks.FWPM_FILTER_CONDITION0, 40), (ks.FWPM_FILTER0, 200)]
    for kind, size in expected:
        assert ctypes.sizeof(kind) == size
    assert ks.FWPM_FILTER0.filterCondition.offset == 120
    assert ks.FWPM_FILTER0.context.offset == 152
    assert ks.FWPM_FILTER0.effectiveWeight.offset == 184
    assert ks.FWPM_SESSION0.sid.offset == 48


def test_killswitch_filters_and_disable():
    api = FakeWfp()
    switch = ks.KillSwitch(backend=api)
    assert issubclass(ks.KillSwitchError, UserError)
    assert not switch.active
    switch.enable(tun_luid=0x123456789ABCDEF0, allow_apps=[r"C:\VPN\Core.exe"],
                  allow_nets=["192.168.1.15/24", "fd00:1234::12/64"])
    assert switch.active and api.session_flags == ks.FWPM_SESSION_FLAG_DYNAMIC
    assert api.calls[0:3] == ["open", "begin", "sublayer"] and api.calls[-1] == "commit"
    assert not api.allocations and len(api.freed) == 1
    assert len(api.rules) == 28
    for layer, version in ks._LAYERS:
        rules = [r for r in api.rules.values() if r["layer"] == bytes(layer)]
        blocked = [r for r in rules if r["action"] == ks.FWP_ACTION_BLOCK]
        permitted = [r for r in rules if r["action"] == ks.FWP_ACTION_PERMIT]
        assert len(blocked) == 1 and blocked[0]["conditions"] == []
        assert all(r["weight"] > blocked[0]["weight"] for r in permitted)
        conditions = [c for rule in permitted for c in rule["conditions"]]
        assert (bytes(ks.FWPM_CONDITION_FLAGS), ks.FWP_MATCH_FLAGS_ALL_SET, ks.FWP_UINT32, 1) in conditions
        assert (bytes(ks.FWPM_CONDITION_IP_LOCAL_INTERFACE), 0, ks.FWP_UINT64, 0x123456789ABCDEF0) in conditions
        assert (bytes(ks.FWPM_CONDITION_ALE_APP_ID), 0, ks.FWP_BYTE_BLOB_TYPE,
                'c:\\vpn\\core.exe\0'.encode("utf-16-le")) in conditions
        network = next(c for c in conditions if c[0] == bytes(ks.FWPM_CONDITION_IP_REMOTE_ADDRESS))
        if version == 4:
            assert network[2:] == (ks.FWP_V4_ADDR_MASK, (0xC0A80100, 0xFFFFFF00))
            expected_ports = {(68, 67), (67, 68)}
        else:
            assert network[2:] == (ks.FWP_V6_ADDR_MASK, (bytes.fromhex("fd001234000000000000000000000000"), 64))
            expected_ports = {(546, 547), (547, 546)}
        actual_ports = set()
        for rule in permitted:
            values = {c[0]: c[3] for c in rule["conditions"]}
            if bytes(ks.FWPM_CONDITION_IP_PROTOCOL) in values:
                assert values[bytes(ks.FWPM_CONDITION_IP_PROTOCOL)] == 17
                actual_ports.add((values[bytes(ks.FWPM_CONDITION_IP_LOCAL_PORT)],
                                  values[bytes(ks.FWPM_CONDITION_IP_REMOTE_PORT)]))
        assert actual_ports == expected_ports
    switch.disable()
    switch.disable()
    assert not switch.active and api.calls.count("close") == 1 and not api.rules


@pytest.mark.parametrize("stage", ["open", "begin", "sublayer", "app", "filter", "commit"])
def test_killswitch_failure_rolls_back(stage):
    api = FakeWfp(fail=stage)
    switch = ks.KillSwitch(backend=api)
    with pytest.raises(ks.KillSwitchError, match="права администратора"):
        switch.enable(tun_luid=None, allow_apps=[r"C:\VPN\core.exe"], allow_nets=[])
    assert not switch.active and not api.rules and not api.allocations
    if stage not in ("open", "begin"):
        assert "abort" in api.calls
    assert ("close" in api.calls) == (stage != "open")


def test_killswitch_reconfigure_is_atomic():
    api = FakeWfp()
    switch = ks.KillSwitch(backend=api)
    switch.enable(tun_luid=10, allow_apps=[], allow_nets=[])
    original = copy.deepcopy(api.rules)
    api.fail = "commit"
    with pytest.raises(ks.KillSwitchError):
        switch.enable(tun_luid=20, allow_apps=[], allow_nets=[])
    assert switch.active and api.rules == original and "close" not in api.calls
    api.fail = None
    switch.enable(tun_luid=30, allow_apps=[], allow_nets=[])
    assert switch.active and api.calls.count("open") == 1
    assert not set(original).intersection(api.rules)
    luids = [c[3] for rule in api.rules.values() for c in rule["conditions"]
             if c[0] == bytes(ks.FWPM_CONDITION_IP_LOCAL_INTERFACE)]
    assert luids == [30] * 4
    switch.disable()


def test_killswitch_close_failure_keeps_state():
    api = FakeWfp()
    switch = ks.KillSwitch(backend=api)
    switch.enable(tun_luid=None, allow_apps=[], allow_nets=[])
    api.fail = "close"
    with pytest.raises(ks.KillSwitchError):
        switch.disable()
    assert switch.active
    api.fail = None
    switch.disable()
    assert not switch.active


def test_killswitch_guard_and_bad_inputs(monkeypatch):
    monkeypatch.setenv("LAZEYKA_NO_CORE", "1")
    real = ks.KillSwitch()
    with pytest.raises(guard.CoreBlocked, match="kill switch"):
        real.enable(tun_luid=None, allow_apps=[], allow_nets=[])
    assert not real.active
    real.disable()
    api = FakeWfp()
    fake = ks.KillSwitch(backend=api)
    for options in [dict(tun_luid=-1, allow_apps=[], allow_nets=[]),
                    dict(tun_luid=None, allow_apps=["core.exe"], allow_nets=[]),
                    dict(tun_luid=None, allow_apps=[], allow_nets=["broken"]),
                    dict(tun_luid=2**64, allow_apps=[], allow_nets=[])]:
        with pytest.raises(ks.KillSwitchError):
            fake.enable(**options)
    assert api.calls == []


@pytest.fixture
def fake_main(monkeypatch, tmp_path):
    import app
    from app import main

    calls = []

    class Event:
        def __init__(self):
            self.handlers = []

        def __iadd__(self, handler):
            self.handlers.append(handler)
            return self

    window = SimpleNamespace(
        events=SimpleNamespace(before_show=Event(), loaded=Event()),
        show=lambda: calls.append("show"), hide=lambda: calls.append("hide"))
    core = SimpleNamespace(
        settings=SimpleNamespace(get=lambda *keys: "dark" if keys == ("ui", "theme") else False),
        startup=lambda: calls.append("startup"), shutdown=lambda: calls.append("shutdown"))
    tray = SimpleNamespace(start=lambda: calls.append("tray-start"), refresh=lambda: None,
                           stop=lambda: calls.append("tray-stop"), notify=lambda *a: None,
                           icon=SimpleNamespace())
    instance = SimpleNamespace(already_running=False, signal_existing=lambda: calls.append("signal"),
                               listen=lambda show: calls.append("listen"), close=lambda: None,
                               wait_for_previous=lambda timeout: True)

    class Server:
        def start(self, on_text):
            calls.append("link-start")
            self.on_text = on_text

        def stop(self):
            calls.append("link-stop")

    server = Server()
    webview = SimpleNamespace(renderer="edgechromium", create_window=lambda *a, **kw: window)

    def start(**kwargs):
        calls.append("webview-start")
        for handler in window.events.loaded.handlers:
            handler()

    webview.start = start
    monkeypatch.setitem(sys.modules, "webview", webview)
    for name, module in {
        "webview_guard": SimpleNamespace(install=lambda: None),
        "api": SimpleNamespace(Api=lambda core: object()),
        "core": SimpleNamespace(Core=lambda **kwargs: core),
        "tray": SimpleNamespace(Tray=lambda core: tray),
    }.items():
        monkeypatch.setitem(sys.modules, "app." + name, module)
        monkeypatch.setattr(app, name, module, raising=False)
    monkeypatch.setattr(main.winutil, "is_admin", lambda: False)
    monkeypatch.setattr(main.winutil, "SingleInstance", lambda name: instance)
    monkeypatch.setattr(main.paths, "logs_dir", lambda **kw: tmp_path)
    monkeypatch.setattr(main.paths, "ui_dir", lambda: tmp_path)
    monkeypatch.setattr(main.paths, "resource_dir", lambda: tmp_path)
    monkeypatch.setattr(main.applog, "setup", lambda path: tmp_path / "fake.log")
    monkeypatch.setattr(deeplink, "LinkServer", lambda: server)
    monkeypatch.setattr(deeplink, "send_to_running", lambda text: calls.append(("send", text)) or True)
    monkeypatch.delenv("LAZEYKA_UI_SELFCHECK", raising=False)
    return SimpleNamespace(main=main, core=core, server=server, webview=webview,
                           instance=instance, calls=calls)


def test_main_forwards_to_existing_instance(fake_main):
    env = fake_main
    env.instance.already_running = True
    link = "lazeyka://import/https://vpn.test/private"
    assert env.main.main([link, "--no-elevate"]) == 0
    assert env.calls == [("send", link), "signal"]


def test_main_pending_and_incoming_links(fake_main):
    env = fake_main
    pending, incoming = "lazeyka://import/first", "lazeyka://import/second"
    env.core.vpnclient_deeplink = lambda text: env.calls.append(("import", text))
    load = env.webview.start

    def run(**kwargs):
        load(**kwargs)
        env.server.on_text(incoming)

    env.webview.start = run
    assert env.main.main(["--no-elevate", pending, "--hidden"]) == 0
    assert env.calls.index("startup") < env.calls.index("link-start")
    assert env.calls.index("webview-start") < env.calls.index(("import", pending))
    assert env.calls.count(("import", pending)) == 1
    assert env.calls.count(("import", incoming)) == 1
    assert env.calls.count("show") == 2
    assert env.calls.index("link-stop") < env.calls.index("shutdown")


def test_main_missing_handler_and_error_are_private(fake_main, caplog):
    env = fake_main
    caplog.set_level(logging.INFO)
    assert env.main.main(["--no-elevate", "lazeyka://import/private-secret"]) == 0
    assert "ещё недоступен" in caplog.text
    assert "private-secret" not in caplog.text
    assert "show" in env.calls

    def broken(text):
        raise RuntimeError(text)

    env.core.vpnclient_deeplink = broken
    env.server.on_text("private-secret")
    assert "Не удалось открыть импорт" in caplog.text
    assert "private-secret" not in caplog.text


def test_main_stops_server_when_window_fails(fake_main):
    env = fake_main

    def broken(**kwargs):
        raise RuntimeError("нет окна")

    env.webview.start = broken
    with pytest.raises(RuntimeError, match="нет окна"):
        env.main.main(["--no-elevate"])
    assert env.calls.count("link-stop") == 1
