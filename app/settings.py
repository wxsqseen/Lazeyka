"""Настройки приложения: JSON-файл с умолчаниями и атомарной записью."""
from __future__ import annotations

import copy
import ipaddress
import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any, Callable

log = logging.getLogger("lazeyka.settings")

SCHEMA = 1

# Свой VPN: не заворачивать в туннель локальные сети, link-local и multicast (LAN, Hyper-V
# работают как прежде) и не пускать через системный прокси локальные адреса (WinINet ProxyOverride).
DEFAULT_EXCLUDE_NETS = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "224.0.0.0/4",
                        "fc00::/7", "fe80::/10", "ff00::/8")
# 172.16.0.0/12 — это 172.16.*–172.31.*. Маска «172.2*» захватила бы и публичные 172.200.*–172.255.*.
_PRIVATE_172 = tuple(f"172.{n}.*" for n in range(16, 32))
DEFAULT_PROXY_OVERRIDE = ("<local>", "localhost", "127.*", "10.*", *_PRIVATE_172, "192.168.*")
_LEGACY_172_MASK = "172.2*"            # было в умолчаниях до 1.2.3 — заменяется при чтении настроек
DEFAULT_TG_HOST = "127.0.0.1"
# settings.json занят (антивирус, резервное копирование) — столько попыток прочитать его при запуске.
READ_ATTEMPTS = 5
READ_RETRY_DELAY = 0.1   # секунд между попытками


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
            "scale": 1.0,                 # масштаб окна 0.8–1.5
        },
        "startup": {
            "autostart": False,
            "zapret": True,
            "tg": True,
            "vpnclient": False,           # включать свой VPN при запуске
        },
        "updates": {
            "check": True,
            "last_check": None,
            "skipped": {},
            "app_backup": None,   # путь к прежнему exe после самообновления (для отката)
            "app_backup_for": None,       # exe, к которому относится эта копия (Program Files или «Загрузки»)
            "app_backup_version": None,   # версия этой копии
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
            "host": DEFAULT_TG_HOST,
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
        # Свой VPN (docs/vpnclient-plan.md). Только не секретное: ссылки, ключи и адреса
        # подписок лежат в vpnclient/profiles.json.
        "vpnclient": {
            "mode": "tun",                # tun | proxy | local
            "preset": "all",              # all | except_ru | blocked
            "via_zapret": True,           # Discord и YouTube — через обход Лазейки
            "games_direct": False,
            "torrents_direct": False,
            "ip_check_direct": False,
            "direct_apps": [],            # программы мимо VPN
            "proxy_apps": [],             # программы только через VPN
            "direct_sites": [],
            "proxy_sites": [],
            "exclude_nets": list(DEFAULT_EXCLUDE_NETS),
            "proxy_override": list(DEFAULT_PROXY_OVERRIDE),
            "port": 20808,                # системный и локальный прокси
            "local_auth": False,          # логин и пароль на локальный прокси
            "socks_udp": True,
            "allow_lan": False,
            "dns_remote": "auto",         # auto | cloudflare | google | quad9 | adguard | yandex | https://…
            "dns_direct": "auto",
            "fakeip": False,
            "ip_strategy": "ipv4_only",   # ipv4_only | prefer_ipv4 | prefer_ipv6
            "ipv6": False,
            "tun_mtu": 1500,
            "kill_switch": False,
            "on_sleep": "reconnect",      # reconnect | disconnect
            "tls_fragment": False,
            "mux": False,
            "noises": False,
            "fingerprint": "chrome",
            "latency_on_update": True,
            "sort": "latency",            # none | latency | name
            "deeplink": False,            # обработчик ссылок lazeyka://
            "sub_update_hours": 12,
            "verbose": False,
            "singbox_version": None,      # установленные версии ядер
            "xray_version": None,
            "core_auto_update": True,     # ставить новые версии ядер самой, без кнопки
            "core_bad_versions": [],      # "sing-box:1.15.0" — не прошли check или не запустились: не ставим
            "core_trial": [],             # поставлены обновлением и ещё ни разу не запустились: откат при сбое
            "core_good": [],              # "sing-box:1.14.3" — последняя версия, которой можно доверять: на неё откат
            "was_running": False,
        },
    }


# Ключи, где допустим null вместо значения умолчания другого типа.
_NULLABLE = {
    ("updates", "last_check"),
    ("updates", "app_backup"),
    ("updates", "app_backup_for"),
    ("updates", "app_backup_version"),
    ("zapret", "pack"),
    ("zapret", "ipset_mode"),
    ("zapret", "fakes", "discord"),
    ("zapret", "fakes", "game"),
    ("vpnclient", "singbox_version"),
    ("vpnclient", "xray_version"),
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


class SettingsSaveError(OSError):
    """Настройки не записались на диск (update(strict=True)): изменение отменено и в памяти."""


def _sanitize(data: dict, previous: dict | None = None) -> dict:
    """Значения, которые нельзя оставить как пришли: ключ прокси, адрес, который он слушает (только
    IPv4: IPv6 asyncio слушал бы без IPv4, а ссылка для Telegram ведёт на 127.0.0.1), маска исключений
    прокси из прежних версий."""
    tg = data["tg"]
    if not _valid_secret(tg["secret"]):
        tg["secret"] = previous["tg"]["secret"] if previous else _new_secret()
    if not _valid_ipv4(tg["host"]):
        tg["host"] = previous["tg"]["host"] if previous else DEFAULT_TG_HOST
    override = data["vpnclient"]["proxy_override"]
    if _LEGACY_172_MASK in override:
        at = override.index(_LEGACY_172_MASK)
        rest = [x for x in override if x != _LEGACY_172_MASK]
        extra = [x for x in _PRIVATE_172 if x not in rest]
        data["vpnclient"]["proxy_override"] = rest[:at] + extra + rest[at:]
    return data


class Settings:
    """settings.json: запись — через временный файл с fsync, прежняя версия остаётся в settings.json.bak.
    Повреждённый файл не превращается молча в умолчания: он откладывается (settings.json.broken-<время>),
    читается резервная копия, а что случилось — в recovered (Core покажет плашку). Файл есть, но не
    прочитался, и резервной копии нет — настройки по умолчанию только в памяти: до перезапуска ничего не
    пишется (write_blocked), иначе первая же запись затёрла бы настоящий файл, а вторая — и его копию."""

    def __init__(self, path: Path, allow_create: bool = True):
        self.path = path
        self.backup_path = path.with_name(path.name + ".bak")
        self.allow_create = allow_create  # без прав администратора папку данных не создаём
        self._lock = threading.RLock()
        self.created = not path.exists() and not self.backup_path.exists()
        self.writable = True
        self.last_error: str | None = None
        self.recovered: str | None = None   # текст для плашки: файл был повреждён и чем его заменили
        self.write_blocked: str | None = None   # почему запись отключена до перезапуска (None — пишем)
        self._data = self._load()

    @staticmethod
    def _read(path: Path) -> tuple[dict | None, str]:
        """(настройки или None, что с файлом): "ok"; "missing" — нет; "broken" — повреждён (не UTF-8, не
        JSON, не объект); "unreadable" — есть, но не прочитался и после повторов (занят, нет прав): такой
        файл не откладывается. Метка BOM (так сохраняет Блокнот) повреждением не считается."""
        error: OSError | None = None
        for attempt in range(READ_ATTEMPTS):
            if attempt:
                time.sleep(READ_RETRY_DELAY)
            try:
                text = path.read_text(encoding="utf-8-sig")
                break
            except FileNotFoundError:
                return None, "missing"
            except UnicodeError as exc:   # сохранён не в UTF-8 (ANSI) или с испорченным байтом
                log.warning("Настройки %s повреждены: %r", path, exc)
                return None, "broken"
            except OSError as exc:
                error = exc
        else:
            log.warning("Не удалось прочитать настройки %s за %d попыток: %r", path, READ_ATTEMPTS, error)
            return None, "unreadable"
        try:
            raw = json.loads(text)
        except ValueError as exc:
            log.warning("Настройки %s повреждены: %r", path, exc)
            return None, "broken"
        return (raw, "ok") if isinstance(raw, dict) else (None, "broken")

    def _load(self) -> dict:
        raw, state = self._read(self.path)
        if state == "broken":
            raw = self._recover()
        elif state != "ok" and self.backup_path.exists():
            # Запись прервалась между переименованиями (свежего файла ещё нет) или он не читается сейчас.
            raw, backup_state = self._read(self.backup_path)
            if backup_state == "broken" and state == "missing":
                raw = self._reset("Файл настроек не найден, а его резервная копия повреждена")
        if raw is None and state == "unreadable":
            raw = self._block_writes()
        if raw is None:
            return defaults()
        return _sanitize(_merge(defaults(), raw))

    def _recover(self) -> dict:
        """settings.json повреждён: отложить его (не затирать следующей записью) и взять резервную копию."""
        broken = self.path.with_name(f"{self.path.name}.broken-{time.strftime('%Y%m%d-%H%M%S')}")
        try:
            os.replace(self.path, broken)
            kept = f" Повреждённый файл сохранён как {broken.name}."
        except OSError as exc:
            log.warning("Повреждённые настройки не отложены: %r", exc)
            kept = ""
        raw, backup_state = self._read(self.backup_path)
        if raw is None:
            backup = "резервная копия тоже повреждена" if backup_state == "broken" else "резервной копии нет"
            return self._reset(f"Файл настроек был повреждён, {backup}", kept)
        self.recovered = f"Файл настроек был повреждён — восстановлены настройки из резервной копии.{kept}"
        self.created = False
        log.error("%s", self.recovered)
        return raw

    def _reset(self, what: str, kept: str = "") -> dict:
        """Настроек не осталось ни в файле, ни в резервной копии: умолчания, о чём — плашка."""
        self.recovered = (f"{what} — настройки сброшены к умолчаниям, ключ Telegram-прокси новый (подключите "
                          f"Telegram заново).{kept}")
        self.created = False
        log.error("%s", self.recovered)
        return {"first_run": False}   # человек уже проходил приветствие: показывать его снова незачем

    def _block_writes(self) -> dict:
        """settings.json есть, но не прочитался, а резервной копии нет (одна запись в жизни файла или
        переход с 1.2): работаем на умолчаниях, а файл не трогаем до перезапуска."""
        self.writable = False
        self.write_blocked = ("файл настроек не прочитался при запуске — пока Лазейку не перезапустят, "
                              "изменения не сохраняются, чтобы не затереть его")
        self.recovered = (f"Файл настроек {self.path} не прочитался при запуске (его держит другая программа "
                          "или к нему нет доступа). Пока работают настройки по умолчанию с временным ключом "
                          "Telegram-прокси, а изменения не сохраняются, чтобы не затереть ваш файл. "
                          "Перезапустите Лазейку.")
        log.error("%s", self.recovered)
        return {"first_run": False}

    def snapshot(self) -> dict:
        with self._lock:
            return copy.deepcopy(self._data)

    def get(self, *keys: str) -> Any:
        with self._lock:
            node: Any = self._data
            for key in keys:
                node = node[key]
            return copy.deepcopy(node)

    def update(self, mutate: Callable[[dict], None], *, strict: bool = False) -> dict:
        """Меняет настройки под блокировкой и сразу сохраняет на диск.

        strict=True — для записей, без которых дальше нельзя (куда отложена прежняя версия exe):
        не сохранилось — изменение отменяется и в памяти, а вызывающий получает SettingsSaveError."""
        with self._lock:
            before = self._data
            draft = copy.deepcopy(before)
            mutate(draft)
            self._data = _sanitize(_merge(defaults(), draft), before)
            if not self.save() and strict:
                self._data = before
                raise SettingsSaveError(f"Не удалось сохранить настройки в {self.path}: {self.last_error}")
            return copy.deepcopy(self._data)

    def save(self) -> bool:
        with self._lock:
            if self.write_blocked:
                self.last_error = self.write_blocked
                return False
            payload = json.dumps(self._data, ensure_ascii=False, indent=2)
            tmp = self.path.with_suffix(".json.tmp")
            try:
                if not self.path.parent.is_dir():
                    if not self.allow_create:
                        raise PermissionError("папка данных ещё не создана, а прав на её создание нет")
                    self.path.parent.mkdir(parents=True, exist_ok=True)
                with open(tmp, "w", encoding="utf-8") as f:
                    f.write(payload)
                    f.flush()
                    os.fsync(f.fileno())    # на диске до переименования: сбой питания не оставит пустой файл
                if self.path.exists():
                    try:
                        os.replace(self.path, self.backup_path)
                    except OSError as exc:   # резервная копия занята — сохранить важнее, чем её обновить
                        log.debug("Резервная копия настроек не обновлена: %r", exc)
                os.replace(tmp, self.path)
                self.writable = True
                self.created = False
                self.last_error = None
                return True
            except OSError as exc:
                self.writable = False
                self.last_error = str(exc)
                log.warning("Не удалось сохранить настройки в %s: %r", self.path, exc)
                return False


def read_saved(path: Path) -> dict | None:
    """Сохранённые настройки без Settings: ничего не пишет и не откладывает — для решения до запуска Core
    (autostart.stray_launch). Нет ни файла, ни резервной копии — умолчания; не прочитались — None."""
    for candidate in (path, path.with_name(path.name + ".bak")):
        raw, state = Settings._read(candidate)
        if state == "ok":
            return _merge(defaults(), raw)
        if state != "missing":
            return None
    return defaults()


def _valid_secret(value: str) -> bool:
    if not isinstance(value, str) or len(value) != 32:
        return False
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return True


def _valid_ipv4(value: object) -> bool:
    try:
        return isinstance(value, str) and ipaddress.ip_address(value.strip()).version == 4
    except ValueError:
        return False


# Поля конфига оригинального TgWsProxy → поля tg в настройках Лазейки.
_TGWS_FIELDS = {
    "host": "host", "port": "port", "secret": "secret", "dc_ip": "dc_ip",
    "cfproxy": "cfproxy", "h2": "h2", "pool_size": "pool_size", "buf_kb": "buf_kb",
    "no_secure": "no_secure", "verbose": "verbose",
    "cfproxy_user_domain_enabled": "cf_domains_enabled",
    "cfproxy_user_domain": "cf_domains",
    "cfproxy_worker_enabled": "worker_enabled",
    "cfproxy_worker_domain": "worker_domains",
}
_TGWS_SWITCHES = {"cf_domains": "cf_domains_enabled", "worker_domains": "worker_enabled"}

Validate = Callable[[dict], "tuple[dict, dict]"]


def import_tgwsproxy_config(settings: Settings, validate: Validate, appdata: str | None = None) -> bool:
    """Переносит настройки оригинального TgWsProxy, чтобы ссылка в Telegram осталась прежней.

    validate — проверка формы Telegram-прокси (TgProxyManager.validate): переносится только то, что она
    приняла; домены строкой разбираются как в форме, а переключатель без доменов выключается.
    appdata — папка AppData того, кто сидит за компьютером (по умолчанию — из окружения процесса)."""
    appdata = appdata if appdata is not None else os.environ.get("APPDATA")
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
    candidate = settings.get("tg")
    for src, dst in _TGWS_FIELDS.items():
        if src in cfg:
            candidate[dst] = cfg[src]
    clean, errors = validate(candidate)
    for field, switch in _TGWS_SWITCHES.items():
        if field in errors or not clean.get(field):
            clean[field] = []
            clean[switch] = False      # включённый переключатель без доменов не даст прокси запуститься
            errors.pop(field, None)
    if errors:
        log.warning("Из конфига TgWsProxy не перенесено (не прошло проверку): %s", ", ".join(sorted(errors)))
    imported = {key: clean[key] for key in set(_TGWS_FIELDS.values()) if key in clean}
    settings.update(lambda d: d["tg"].update(imported))
    log.info("Импортированы настройки TgWsProxy из %s", source)
    return True
