"""Kill switch WFP: только свои фильтры, одна динамическая сессия."""
from __future__ import annotations

import ctypes
import ipaddress
import logging
import ntpath
import threading
import uuid
from ctypes import wintypes
from typing import Any

from .. import winutil
from ..errors import UserError
from . import guard

log = logging.getLogger("lazeyka.vpnclient.killswitch")


class KillSwitchError(UserError):
    pass


# ABI Windows SDK: fwptypes.h / fwpmtypes.h. Без _pack_: указатели и UINT64
# выровнены на 8 байт в x64. UINT64 в FWP_VALUE0 — указатель, не само число.
class GUID(ctypes.Structure):
    _fields_ = [("Data1", ctypes.c_uint32), ("Data2", ctypes.c_uint16),
                ("Data3", ctypes.c_uint16), ("Data4", ctypes.c_uint8 * 8)]

    @classmethod
    def parse(cls, value: str) -> GUID:
        return cls.from_buffer_copy(uuid.UUID(value).bytes_le)


class FWP_BYTE_BLOB(ctypes.Structure):
    _fields_ = [("size", ctypes.c_uint32), ("data", ctypes.POINTER(ctypes.c_uint8))]


class FWP_V4_ADDR_AND_MASK(ctypes.Structure):
    _fields_ = [("addr", ctypes.c_uint32), ("mask", ctypes.c_uint32)]  # host order


class FWP_V6_ADDR_AND_MASK(ctypes.Structure):
    _fields_ = [("addr", ctypes.c_uint8 * 16), ("prefixLength", ctypes.c_uint8)]


class _VALUE_UNION(ctypes.Union):
    # Неиспользуемые SID, TOKEN_INFORMATION и массивы тоже являются указателями.
    _fields_ = [("uint8", ctypes.c_uint8), ("uint16", ctypes.c_uint16),
                ("uint32", ctypes.c_uint32), ("uint64", ctypes.POINTER(ctypes.c_uint64)),
                ("int8", ctypes.c_int8), ("int16", ctypes.c_int16), ("int32", ctypes.c_int32),
                ("int64", ctypes.POINTER(ctypes.c_int64)), ("float32", ctypes.c_float),
                ("double64", ctypes.POINTER(ctypes.c_double)),
                ("byteBlob", ctypes.POINTER(FWP_BYTE_BLOB)), ("pointer", ctypes.c_void_p),
                ("unicodeString", wintypes.LPWSTR)]


class FWP_VALUE0(ctypes.Structure):
    _anonymous_ = ("value",)
    _fields_ = [("type", ctypes.c_uint32), ("value", _VALUE_UNION)]


class _CONDITION_UNION(ctypes.Union):
    _fields_ = _VALUE_UNION._fields_ + [
        ("v4AddrMask", ctypes.POINTER(FWP_V4_ADDR_AND_MASK)),
        ("v6AddrMask", ctypes.POINTER(FWP_V6_ADDR_AND_MASK)), ("rangeValue", ctypes.c_void_p)]


class FWP_CONDITION_VALUE0(ctypes.Structure):
    _anonymous_ = ("value",)
    _fields_ = [("type", ctypes.c_uint32), ("value", _CONDITION_UNION)]


class FWPM_DISPLAY_DATA0(ctypes.Structure):
    _fields_ = [("name", wintypes.LPWSTR), ("description", wintypes.LPWSTR)]


class FWPM_SESSION0(ctypes.Structure):
    _fields_ = [("sessionKey", GUID), ("displayData", FWPM_DISPLAY_DATA0),
                ("flags", ctypes.c_uint32), ("txnWaitTimeoutInMSec", ctypes.c_uint32),
                ("processId", wintypes.DWORD), ("sid", ctypes.c_void_p),
                ("username", wintypes.LPWSTR), ("kernelMode", wintypes.BOOL)]


class FWPM_SUBLAYER0(ctypes.Structure):
    _fields_ = [("subLayerKey", GUID), ("displayData", FWPM_DISPLAY_DATA0),
                ("flags", ctypes.c_uint32), ("providerKey", ctypes.POINTER(GUID)),
                ("providerData", FWP_BYTE_BLOB), ("weight", ctypes.c_uint16)]


class FWPM_FILTER_CONDITION0(ctypes.Structure):
    _fields_ = [("fieldKey", GUID), ("matchType", ctypes.c_uint32),
                ("conditionValue", FWP_CONDITION_VALUE0)]


class _ACTION_UNION(ctypes.Union):
    _fields_ = [("filterType", GUID), ("calloutKey", GUID)]


class FWPM_ACTION0(ctypes.Structure):
    _anonymous_ = ("value",)
    _fields_ = [("type", ctypes.c_uint32), ("value", _ACTION_UNION)]


class _CONTEXT_UNION(ctypes.Union):
    # GUID в этом союзе делает размер 16, UINT64 — выравнивание 8.
    _fields_ = [("rawContext", ctypes.c_uint64), ("providerContextKey", GUID)]


class FWPM_FILTER0(ctypes.Structure):
    _anonymous_ = ("context",)
    _fields_ = [("filterKey", GUID), ("displayData", FWPM_DISPLAY_DATA0),
                ("flags", ctypes.c_uint32), ("providerKey", ctypes.POINTER(GUID)),
                ("providerData", FWP_BYTE_BLOB), ("layerKey", GUID), ("subLayerKey", GUID),
                ("weight", FWP_VALUE0), ("numFilterConditions", ctypes.c_uint32),
                ("filterCondition", ctypes.POINTER(FWPM_FILTER_CONDITION0)),
                ("action", FWPM_ACTION0), ("context", _CONTEXT_UNION),
                ("reserved", ctypes.POINTER(GUID)), ("filterId", ctypes.c_uint64),
                ("effectiveWeight", FWP_VALUE0)]


FWPM_SESSION_FLAG_DYNAMIC = 0x00000001
FWP_UINT8, FWP_UINT16, FWP_UINT32, FWP_UINT64 = 1, 2, 3, 4
FWP_BYTE_BLOB_TYPE, FWP_V4_ADDR_MASK, FWP_V6_ADDR_MASK = 12, 256, 257
FWP_MATCH_EQUAL, FWP_MATCH_FLAGS_ALL_SET = 0, 6
FWP_CONDITION_FLAG_IS_LOOPBACK = 1
FWP_ACTION_BLOCK, FWP_ACTION_PERMIT = 0x1001, 0x1002
SUBLAYER_KEY = GUID.parse("ab0be8c8-c136-45c1-946b-31b264125362")

# GUID из fwpmu.h; это ключи четырёх слоёв ALE и разрешённых на них условий.
FWPM_LAYER_ALE_AUTH_CONNECT_V4 = GUID.parse("c38d57d1-05a7-4c33-904f-7fbceee60e82")
FWPM_LAYER_ALE_AUTH_CONNECT_V6 = GUID.parse("4a72393b-319f-44bc-84c3-ba54dcb3b6b4")
FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4 = GUID.parse("e1cd9fe7-f4b5-4273-96c0-592e487b8650")
FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6 = GUID.parse("a3b42c97-9f04-4672-b87e-cee9c483257f")
FWPM_CONDITION_FLAGS = GUID.parse("632ce23b-5167-435c-86d7-e903684aa80c")
FWPM_CONDITION_IP_REMOTE_ADDRESS = GUID.parse("b235ae9a-1d64-49b8-a44c-5ff3d9095045")
FWPM_CONDITION_IP_LOCAL_INTERFACE = GUID.parse("4cd62a49-59c3-4969-b7f3-bda5d32890a4")
FWPM_CONDITION_ALE_APP_ID = GUID.parse("d78e1e87-8644-4ea5-9437-d809ecefc971")
FWPM_CONDITION_IP_PROTOCOL = GUID.parse("3971ef2b-623e-4f9a-8cb1-6e79b806b9a7")
FWPM_CONDITION_IP_LOCAL_PORT = GUID.parse("0c1ba1af-5765-453f-af22-a8f791ac775b")
FWPM_CONDITION_IP_REMOTE_PORT = GUID.parse("c35a604d-d22b-4e1a-91b4-68f674ee674b")
_LAYERS = ((FWPM_LAYER_ALE_AUTH_CONNECT_V4, 4), (FWPM_LAYER_ALE_AUTH_CONNECT_V6, 6),
           (FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, 4), (FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, 6))


def _load_backend() -> Any:
    # По полному пути: голое имя в процессе с правами сначала ищется в папке exe, а fwpuclnt.dll — не из
    # KnownDLLs, подложенную рядом библиотеку Windows подхватила бы.
    dll = ctypes.WinDLL(winutil.system32("fwpuclnt.dll"), use_last_error=True)
    handle, pointer, dword = wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD
    definitions = {
        "FwpmEngineOpen0": [wintypes.LPCWSTR, dword, pointer, ctypes.POINTER(FWPM_SESSION0),
                            ctypes.POINTER(handle)],
        "FwpmEngineClose0": [handle],
        "FwpmTransactionBegin0": [handle, dword],
        "FwpmTransactionCommit0": [handle],
        "FwpmTransactionAbort0": [handle],
        "FwpmSubLayerAdd0": [handle, ctypes.POINTER(FWPM_SUBLAYER0), pointer],
        "FwpmFilterAdd0": [handle, ctypes.POINTER(FWPM_FILTER0), pointer, ctypes.POINTER(ctypes.c_uint64)],
        "FwpmFilterDeleteById0": [handle, ctypes.c_uint64],
        "FwpmGetAppIdFromFileName0": [wintypes.LPCWSTR, ctypes.POINTER(ctypes.POINTER(FWP_BYTE_BLOB))],
    }
    for name, args in definitions.items():
        function = getattr(dll, name)
        function.argtypes, function.restype = args, dword
    dll.FwpmFreeMemory0.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
    dll.FwpmFreeMemory0.restype = None
    return dll


def _check(code: int, action: str) -> None:
    if not code:
        return
    code = code & 0xFFFFFFFF
    reasons = {
        5: "нужны права администратора", 0x80070005: "нужны права администратора",
        1062: "служба базовой фильтрации Windows не запущена",
        1722: "служба базовой фильтрации Windows недоступна",
        0x80320009: "подслой Лазейки уже используется", 0x80320012: "истекло время ожидания WFP",
        0x80320036: "достигнут предел числа подслоёв WFP",
        0x80320027: "Windows отвергла тип условия фильтра",
        0x80320035: "Windows отвергла параметры фильтра",
    }
    reason = reasons.get(code, "Windows не смогла применить фильтры")
    raise KillSwitchError(f"Kill switch: {action} — {reason} (код 0x{code:08X})")


def _condition(key: GUID, kind: int, value: Any, *, match: int = FWP_MATCH_EQUAL) -> FWPM_FILTER_CONDITION0:
    result = FWPM_FILTER_CONDITION0(fieldKey=key, matchType=match)
    result.conditionValue.type = kind
    field = {FWP_UINT8: "uint8", FWP_UINT16: "uint16", FWP_UINT32: "uint32",
             FWP_UINT64: "uint64", FWP_BYTE_BLOB_TYPE: "byteBlob",
             FWP_V4_ADDR_MASK: "v4AddrMask", FWP_V6_ADDR_MASK: "v6AddrMask"}[kind]
    setattr(result.conditionValue, field, value)
    return result


def _remote_net(net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> FWPM_FILTER_CONDITION0:
    """Условие «удалённый адрес в этой подсети»."""
    if net.version == 4:
        mask = FWP_V4_ADDR_AND_MASK(int(net.network_address), int(net.netmask))
        return _condition(FWPM_CONDITION_IP_REMOTE_ADDRESS, FWP_V4_ADDR_MASK, ctypes.pointer(mask))
    mask6 = FWP_V6_ADDR_AND_MASK((ctypes.c_uint8 * 16)(*net.network_address.packed), net.prefixlen)
    return _condition(FWPM_CONDITION_IP_REMOTE_ADDRESS, FWP_V6_ADDR_MASK, ctypes.pointer(mask6))


def _lan_networks(items) -> list[tuple[int, list]]:
    """Проверенные (LUID, сети) для allow_lan; неверное — KillSwitchError с тем, что пришло."""
    out = []
    for item in items or ():
        try:
            luid, nets = item
            parsed = list(dict.fromkeys(ipaddress.ip_network(net, strict=False) for net in nets))
        except (ValueError, TypeError) as exc:
            raise KillSwitchError(f"Kill switch: неверная локальная сеть {item!r}") from exc
        if type(luid) is not int or not 0 < luid < 2**64:
            raise KillSwitchError(f"Kill switch: неверный LUID адаптера локальной сети ({luid!r})")
        if parsed:
            out.append((luid, parsed))
    return out


class KillSwitch:
    """backend — объект с Fwpm* API; в тестах он копирует структуры и возвращает коды."""

    def __init__(self, backend=None) -> None:
        self._backend = backend
        self._real = backend is None or isinstance(backend, ctypes.CDLL)
        self._handle = wintypes.HANDLE()
        self._filter_ids: list[int] = []
        self._lock = threading.RLock()

    @property
    def active(self) -> bool:
        with self._lock:
            return bool(self._handle.value and self._filter_ids)

    def enable(self, *, tun_luid: int, allow_apps: list[str], allow_nets: list[str],
               allow_lan: list[tuple[int, list[str]]] | tuple = ()) -> None:
        """allow_lan — (LUID, сети) виртуальных локальных сетей (Radmin VPN, Hamachi…): их сети разрешены
        только через их же адаптер, так что интернет через них мимо TUN не пройдёт."""
        if self._real:
            guard.ensure_allowed("kill switch")
        if tun_luid is None:
            # Без разрешения своего TUN фильтры закрыли бы интернет и самому VPN: «Подключено», а не
            # открывается ничего. Прежние фильтры (если были) остаются как есть — решает вызывающий.
            raise KillSwitchError("Kill switch: адаптер своего VPN не найден — включать запрет без него нельзя")
        if type(tun_luid) is not int or not 0 < tun_luid < 2**64:
            raise KillSwitchError("Kill switch: неверный LUID интерфейса TUN")
        try:
            nets = list(dict.fromkeys(ipaddress.ip_network(net, strict=False) for net in allow_nets))
        except (ValueError, TypeError) as exc:
            raise KillSwitchError("Kill switch: неверный адрес разрешённой подсети") from exc
        lan = _lan_networks(allow_lan)
        apps = list(dict.fromkeys(allow_apps))
        if any(not isinstance(app, str) or not ntpath.isabs(app) or "\x00" in app for app in apps):
            raise KillSwitchError("Kill switch: нужен полный путь к разрешённой программе")
        with self._lock:
            try:
                if self._backend is None:
                    self._backend = _load_backend()
                self._enable(tun_luid, apps, nets, lan)
            except OSError as exc:
                raise KillSwitchError("Kill switch: не удалось обратиться к фильтрации Windows") from exc

    def _enable(self, tun_luid: int, apps: list[str], nets: list, lan: list | tuple = ()) -> None:
        api = self._backend
        fresh = not self._handle.value
        transaction = False
        blobs: list = []
        try:
            if fresh:
                session = FWPM_SESSION0()
                session.displayData.name = "Лазейка — kill switch"
                session.flags = FWPM_SESSION_FLAG_DYNAMIC
                session.txnWaitTimeoutInMSec = 5000
                _check(api.FwpmEngineOpen0(None, 10, None, ctypes.byref(session), ctypes.byref(self._handle)),
                       "не удалось открыть сессию")  # RPC_C_AUTHN_WINNT
            _check(api.FwpmTransactionBegin0(self._handle, 0), "не удалось начать транзакцию")
            transaction = True
            if fresh:
                sublayer = FWPM_SUBLAYER0(subLayerKey=SUBLAYER_KEY, weight=0x8000)
                sublayer.displayData.name = "Лазейка — kill switch"
                _check(api.FwpmSubLayerAdd0(self._handle, ctypes.byref(sublayer), None),
                       "не удалось добавить подслой")
            for app in apps:
                blob = ctypes.POINTER(FWP_BYTE_BLOB)()
                code = api.FwpmGetAppIdFromFileName0(app, ctypes.byref(blob))
                if blob:
                    blobs.append(blob)
                _check(code, "не удалось определить разрешённую программу")
                if not blob:
                    raise KillSwitchError("Kill switch: Windows не вернула идентификатор программы")

            ids: list[int] = []

            def add(layer: GUID, name: str, conditions: list[FWPM_FILTER_CONDITION0], permit: bool = True) -> None:
                rule = FWPM_FILTER0(layerKey=layer, subLayerKey=SUBLAYER_KEY)
                rule.filterKey = GUID.from_buffer_copy(uuid.uuid4().bytes_le)
                rule.displayData.name = "Лазейка — " + name
                rule.weight.type = FWP_UINT64
                rule.weight.uint64 = ctypes.pointer(ctypes.c_uint64(100 if permit else 1))
                rule.action.type = FWP_ACTION_PERMIT if permit else FWP_ACTION_BLOCK
                # Мягкое разрешение: чужие запрещающие фильтры продолжают действовать.
                rule.numFilterConditions = len(conditions)
                rule.filterCondition = (FWPM_FILTER_CONDITION0 * len(conditions))(*conditions)
                filter_id = ctypes.c_uint64()
                _check(api.FwpmFilterAdd0(self._handle, ctypes.byref(rule), None, ctypes.byref(filter_id)),
                       "не удалось добавить фильтр")
                ids.append(filter_id.value)

            for layer, version in _LAYERS:
                add(layer, "loopback", [_condition(FWPM_CONDITION_FLAGS, FWP_UINT32,
                    FWP_CONDITION_FLAG_IS_LOOPBACK, match=FWP_MATCH_FLAGS_ALL_SET)])
                add(layer, "интерфейс TUN", [_condition(FWPM_CONDITION_IP_LOCAL_INTERFACE,
                    FWP_UINT64, ctypes.pointer(ctypes.c_uint64(tun_luid)))])
                for net in nets:
                    if net.version == version:
                        add(layer, "разрешённая подсеть", [_remote_net(net)])
                for luid, lan_nets in lan:
                    for net in lan_nets:
                        if net.version == version:
                            add(layer, "локальная сеть", [_condition(FWPM_CONDITION_IP_LOCAL_INTERFACE, FWP_UINT64,
                                                                     ctypes.pointer(ctypes.c_uint64(luid))),
                                                          _remote_net(net)])
                for blob in blobs:
                    add(layer, "разрешённая программа", [_condition(FWPM_CONDITION_ALE_APP_ID,
                        FWP_BYTE_BLOB_TYPE, blob)])
                # Порты всегда локальный/удалённый, независимо от направления ALE.
                # Разрешены обе роли DHCP; произвольный UDP на порт сервера не разрешаем.
                ports = ((68, 67), (67, 68)) if version == 4 else ((546, 547), (547, 546))
                for local, remote in ports:
                    add(layer, "DHCP", [
                        _condition(FWPM_CONDITION_IP_PROTOCOL, FWP_UINT8, 17),
                        _condition(FWPM_CONDITION_IP_LOCAL_PORT, FWP_UINT16, local),
                        _condition(FWPM_CONDITION_IP_REMOTE_PORT, FWP_UINT16, remote)])
                add(layer, "запрет остального трафика", [], permit=False)
            # Повторное enable заменяет правила атомарно, включая новый LUID после перезапуска TUN.
            for filter_id in self._filter_ids:
                _check(api.FwpmFilterDeleteById0(self._handle, filter_id), "не удалось заменить фильтр")
            _check(api.FwpmTransactionCommit0(self._handle), "не удалось применить фильтры")
            transaction = False
            self._filter_ids = ids
        except Exception:
            if transaction:
                code = api.FwpmTransactionAbort0(self._handle)
                if code:
                    log.warning("Не удалось отменить транзакцию kill switch: 0x%08X", code)
            if fresh and self._handle.value:
                # Закрытие динамической сессии убирает даже частично созданные объекты.
                self.disable()
            raise
        finally:
            for blob in blobs:
                api.FwpmFreeMemory0(ctypes.cast(ctypes.byref(blob), ctypes.POINTER(ctypes.c_void_p)))

    def disable(self) -> None:
        with self._lock:
            if self._handle.value:
                _check(self._backend.FwpmEngineClose0(self._handle), "не удалось снять фильтры")
                self._handle = wintypes.HANDLE()
                self._filter_ids = []
