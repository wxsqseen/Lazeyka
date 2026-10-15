"""Мини-клиент MTProto: проверяет, что прокси довозит запрос до Telegram и обратно.

Делает obfuscated2-рукопожатие с секретом (как Telegram Desktop с dd-ссылкой),
отправляет req_pq_multi и ждёт resPQ с тем же nonce. Ключи авторизации не
создаются, аккаунт не нужен.
"""
from __future__ import annotations

import hashlib
import os
import socket
import struct
import time

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

PADDED_INTERMEDIATE = b"\xdd\xdd\xdd\xdd"
REQ_PQ_MULTI = 0xBE7E8EF1
RES_PQ = 0x05162463


def _ctr(key: bytes, iv: bytes):
    return Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()


def _init_packet(secret: bytes, dc: int):
    while True:
        init = bytearray(os.urandom(64))
        if init[0] == 0xEF or bytes(init[:4]) in (b"HEAD", b"POST", b"GET ", b"OPTI", b"\xee\xee\xee\xee",
                                                    b"\xdd\xdd\xdd\xdd", b"\x16\x03\x01\x02"):
            continue
        if init[4:8] == b"\x00\x00\x00\x00":
            continue
        break
    init[56:60] = PADDED_INTERMEDIATE
    init[60:62] = struct.pack("<h", dc)
    enc = _ctr(hashlib.sha256(bytes(init[8:40]) + secret).digest(), bytes(init[40:56]))
    rev = bytes(init[8:56])[::-1]
    dec = _ctr(hashlib.sha256(rev[:32] + secret).digest(), rev[32:48])
    encrypted = enc.update(bytes(init))
    packet = bytes(init[:56]) + encrypted[56:64]
    return packet, enc, dec


def probe(host: str, port: int, secret_hex: str, dc: int = 2, timeout: float = 20.0) -> dict:
    secret = bytes.fromhex(secret_hex)
    packet, enc, dec = _init_packet(secret, dc)
    nonce = os.urandom(16)
    msg_id = (int(time.time() * (2 ** 32))) & ~3
    body = struct.pack("<I", REQ_PQ_MULTI) + nonce
    payload = struct.pack("<qqi", 0, msg_id, len(body)) + body
    frame = struct.pack("<I", len(payload)) + payload

    started = time.monotonic()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(packet + enc.update(frame))
        buf = b""
        need = None
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                raise ConnectionError("прокси закрыл соединение без ответа")
            buf += dec.update(chunk)
            if need is None and len(buf) >= 4:
                need = struct.unpack("<I", buf[:4])[0] + 4
            if need is not None and len(buf) >= need:
                break
    reply = buf[4:need]
    auth_key_id, _msg_id, length = struct.unpack("<qqi", reply[:20])
    constructor = struct.unpack("<I", reply[20:24])[0]
    return {
        "ok": auth_key_id == 0 and constructor == RES_PQ and reply[24:40] == nonce,
        "constructor": hex(constructor),
        "latency_ms": round((time.monotonic() - started) * 1000),
        "length": length,
    }
