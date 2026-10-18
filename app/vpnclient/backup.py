"""Резервная копия VPN: scrypt и AES-256-GCM, без открытых секретов."""
from __future__ import annotations

import base64
import binascii
import json
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from ..errors import UserError

MAGIC = b"LAZEYKA-VPN-BACKUP 1\n"
MAX_BYTES = 20 * 1024 * 1024
_DAMAGED = "Неверный пароль или файл повреждён"


class BackupError(UserError):
    pass


def _key(password: str, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(password.encode("utf-8"))


def export_bytes(data: dict, password: str) -> bytes:
    if not isinstance(password, str) or len(password) < 8:
        raise BackupError("Пароль должен содержать не меньше 8 символов")
    if not isinstance(data, dict):
        raise BackupError("Данные резервной копии должны быть объектом JSON")
    try:
        plain = json.dumps(data, ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise BackupError("Не удалось записать данные резервной копии") from exc
    salt, nonce = os.urandom(16), os.urandom(12)
    header = json.dumps({"kdf": "scrypt", "n": 32768, "r": 8, "p": 1,
                         "salt": base64.b64encode(salt).decode("ascii"),
                         "nonce": base64.b64encode(nonce).decode("ascii")},
                        separators=(",", ":")).encode("ascii")
    if len(MAGIC) + len(header) + 1 + 4 * ((len(plain) + 16 + 2) // 3) > MAX_BYTES:
        raise BackupError("Резервная копия больше 20 МБ")
    # AAD — точные байты строки заголовка, без завершающего перевода строки.
    encrypted = AESGCM(_key(password, salt)).encrypt(nonce, plain, header)
    return MAGIC + header + b"\n" + base64.b64encode(encrypted)


def import_bytes(blob: bytes, password: str) -> dict:
    if not isinstance(blob, bytes):
        raise BackupError("Это не резервная копия Лазейки")
    if len(blob) > MAX_BYTES:
        raise BackupError("Резервная копия больше 20 МБ")
    first, sep, rest = blob.partition(b"\n")
    prefix = b"LAZEYKA-VPN-BACKUP "
    if not sep or not first.startswith(prefix):
        raise BackupError("Это не резервная копия Лазейки")
    version = first[len(prefix):]
    if not version.isdigit() or len(version) > 10:
        raise BackupError("Это не резервная копия Лазейки")
    if int(version) > 1:
        raise BackupError("Файл создан более новой версией")
    if first + b"\n" != MAGIC:
        raise BackupError("Это не резервная копия Лазейки")
    try:
        header, sep, ciphertext = rest.partition(b"\n")
        if not sep or len(header) > 4096 or not isinstance(password, str):
            raise ValueError("header")
        meta = json.loads(header)
        # Параметры из недоверенного файла не должны заставить scrypt занять всю память.
        if (not isinstance(meta, dict) or set(meta) != {"kdf", "n", "r", "p", "salt", "nonce"}
                or meta["kdf"] != "scrypt"
                or any(type(meta[k]) is not int or meta[k] != v
                       for k, v in (("n", 32768), ("r", 8), ("p", 1)))):
            raise ValueError("kdf")
        salt = base64.b64decode(meta["salt"], validate=True)
        nonce = base64.b64decode(meta["nonce"], validate=True)
        encrypted = base64.b64decode(ciphertext, validate=True)
        if len(salt) != 16 or len(nonce) != 12 or len(encrypted) < 16:
            raise ValueError("length")
        plain = AESGCM(_key(password, salt)).decrypt(nonce, encrypted, header)
        data = json.loads(plain)
        if not isinstance(data, dict):
            raise ValueError("object")
        return data
    except (InvalidTag, ValueError, TypeError, KeyError, UnicodeError, binascii.Error,
            RecursionError) as exc:
        raise BackupError(_DAMAGED) from exc
