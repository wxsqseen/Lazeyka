"""Настройки приложения: JSON-файл с умолчаниями и атомарной записью."""
from __future__ import annotations

import copy
import json
import logging
import os
import threading
from pathlib import Path
from typing import Any, Callable

log = logging.getLogger("lazeyka.settings")

SCHEMA = 1


def _new_secret() -> str:
    return os.urandom(16).hex()


def defaults() -> dict:
    return {
        "schema": SCHEMA,
        "first_run": True,
        "ui": {
            "theme": "system",
            "close_to_tray": True,
            "start_minimized": False,
            "tray_hint_shown": False,
        },
        "startup": {
            "autostart": False,
            "zapret": True,
            "tg": True,
        },
        "updates": {
            "check": True,
            "last_check": None,
            "skipped": {},
        },
        "vpn": {
            "compat": True,               # обход не трогает интерфейсы и серверы VPN
            "ask": True,                  # спрашивать при включении, если работает VPN
            "known": [],                  # VPN, про которые уже ответили «не спрашивать»
            "overrides": {},              # {GUID адаптера: "direct" | "tunnel"} — поправки человека
        },
        "zapret": {
            "pack": None,                 # версия активного пакета стратегий
            "strategy": "general",
            "mode": "app",                # app | service
            "game_filter": {"mode": "disabled", "tcp": "1024-65535", "udp": "1024-65535"},
            "ipset_mode": None,           # None — как в пакете
            "ipset_custom": False,        # пользователь скачивал свежий список IP
            "fakes": {"discord": None, "game": None},
            "tcp_timestamps": True,
            "watchdog": "ask",            # ask | auto | off
            "was_running": False,
        },
        "tg": {
            "host": "127.0.0.1",
            "port": 1443,
            "secret": _new_secret(),
            "dc_ip": ["2:149.154.167.220", "4:149.154.167.220"],
            "cfproxy": True,
            "h2": True,
            "cf_domains_enabled": False,
            "cf_domains": [],
            "worker_enabled": False,
            "worker_domains": [],
            "pool_size": 4,
            "buf_kb": 256,
            "no_secure": False,
            "verbose": False,
            "core": "bundled",            # bundled | версия скачанного ядра
            "zapret_sync": True,          # согласовывать списки zapret с Cloudflare-маршрутами
            "was_running": True,
        },
    }


# Ключи, где допустим null вместо значения умолчания другого типа.
_NULLABLE = {
    ("updates", "last_check"),
    ("zapret", "pack"),
    ("zapret", "ipset_mode"),
    ("zapret", "fakes", "discord"),
    ("zapret", "fakes", "game"),
}


def _merge(default: Any, loaded: Any, path: tuple = ()) -> Any:
    if isinstance(default, dict):
        if not isinstance(loaded, dict):
            return copy.deepcopy(default)
        out = {}
        for key, value in default.items():
            out[key] = _merge(value, loaded.get(key, value), path + (key,)) if key in loaded \
                else copy.deepcopy(value)
        # Словари без схемы (skipped) переносим целиком.
        if not default:
            out = {k: v for k, v in loaded.items() if isinstance(k, str)}
        return out
    if loaded is None and (default is None or path in _NULLABLE):
        return None
    if default is None:
        return loaded if isinstance(loaded, (str, int, float, bool)) else None
    if isinstance(default, bool):
        return loaded if isinstance(loaded, bool) else default
    if isinstance(default, int):
        return loaded if isinstance(loaded, int) and not isinstance(loaded, bool) else default
    if isinstance(default, float):
        return float(loaded) if isinstance(loaded, (int, float)) and not isinstance(loaded, bool) else default
    if isinstance(default, str):
        return loaded if isinstance(loaded, str) else default
    if isinstance(default, list):
        if isinstance(loaded, list) and all(isinstance(x, str) for x in loaded):
            return list(loaded)
        return list(default)
    return default


class Settings:
    def __init__(self, path: Path, allow_create: bool = True):
        self.path = path
        self.allow_create = allow_create  # без прав администратора папку данных не создаём
        self._lock = threading.RLock()
        self.created = not path.exists()
        self.writable = True
        self._data = self._load()

    def _load(self) -> dict:
        base = defaults()
        if not self.path.exists():
            return base
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            log.warning("Не удалось прочитать настройки %s: %r — использую умолчания", self.path, exc)
            return base
        data = _merge(base, raw)
        if not _valid_secret(data["tg"]["secret"]):
            data["tg"]["secret"] = _new_secret()
        return data

    def snapshot(self) -> dict:
        with self._lock:
            return copy.deepcopy(self._data)

    def get(self, *keys: str) -> Any:
        with self._lock:
            node: Any = self._data
            for key in keys:
                node = node[key]
            return copy.deepcopy(node)

    def update(self, mutate: Callable[[dict], None]) -> dict:
        """Меняет настройки под блокировкой и сразу сохраняет на диск."""
        with self._lock:
            draft = copy.deepcopy(self._data)
            mutate(draft)
            merged = _merge(defaults(), draft)
            if not _valid_secret(merged["tg"]["secret"]):
                merged["tg"]["secret"] = self._data["tg"]["secret"]
            self._data = merged
            self.save()
            return copy.deepcopy(self._data)

    def save(self) -> bool:
        with self._lock:
            payload = json.dumps(self._data, ensure_ascii=False, indent=2)
            tmp = self.path.with_suffix(".json.tmp")
            try:
                if not self.path.parent.is_dir():
                    if not self.allow_create:
                        raise PermissionError("папка данных ещё не создана, а прав на её создание нет")
                    self.path.parent.mkdir(parents=True, exist_ok=True)
                tmp.write_text(payload, encoding="utf-8")
                os.replace(tmp, self.path)
                self.writable = True
                self.created = False
                return True
            except OSError as exc:
                self.writable = False
                log.warning("Не удалось сохранить настройки в %s: %r", self.path, exc)
                return False


def _valid_secret(value: str) -> bool:
    if not isinstance(value, str) or len(value) != 32:
        return False
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return True


def import_tgwsproxy_config(settings: Settings) -> bool:
    """Переносит настройки оригинального TgWsProxy, чтобы ссылка в Telegram осталась прежней."""
    appdata = os.environ.get("APPDATA")
    if not appdata:
        return False
    source = Path(appdata) / "TgWsProxy" / "config.json"
    if not source.is_file():
        return False
    try:
        cfg = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        log.warning("Конфиг TgWsProxy не прочитан: %r", exc)
        return False
    if not isinstance(cfg, dict):
        return False

    def mutate(data: dict) -> None:
        tg = data["tg"]
        mapping = {
            "host": "host", "port": "port", "secret": "secret", "dc_ip": "dc_ip",
            "cfproxy": "cfproxy", "h2": "h2", "pool_size": "pool_size", "buf_kb": "buf_kb",
            "no_secure": "no_secure", "verbose": "verbose",
            "cfproxy_user_domain_enabled": "cf_domains_enabled",
            "cfproxy_user_domain": "cf_domains",
            "cfproxy_worker_enabled": "worker_enabled",
            "cfproxy_worker_domain": "worker_domains",
        }
        for src, dst in mapping.items():
            if src in cfg:
                tg[dst] = cfg[src]
        if not _valid_secret(tg.get("secret", "")):
            tg["secret"] = _new_secret()

    settings.update(mutate)
    log.info("Импортированы настройки TgWsProxy из %s", source)
    return True
