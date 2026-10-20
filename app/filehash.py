"""SHA-256 файла на диске: сверка скачанного и установленного — пакетов zapret, ядер своего VPN,
копии Лазейки для автозапуска."""
from __future__ import annotations

import hashlib
from pathlib import Path

_CHUNK = 1 << 20      # читаем по мегабайту: архив ядра — десятки мегабайт, держать целиком незачем


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()
