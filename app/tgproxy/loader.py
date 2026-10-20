"""Загрузка ядра tg-ws-proxy: встроенного или скачанного обновлением.

Скачанное ядро загружается под уникальным именем модуля, поэтому у него свои
синглтоны (proxy_config, stats, пулы) и оно не пересекается со встроенным.
"""
from __future__ import annotations

import asyncio
import importlib
import importlib.util
import logging
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from ..errors import UserError

log = logging.getLogger("lazeyka.tg.loader")

BUNDLED_PACKAGE = "app.vendor.tgws_proxy"
REQUIRED_CONFIG_FIELDS = (
    "port", "host", "secret", "dc_redirects", "buffer_size", "pool_size", "fallback_cfproxy",
    "cfproxy_user_domains", "cfproxy_worker_domains", "cfproxy_h2_media", "disable_secure",
)
# Счётчики, без которых не обойтись (скорость, график, «Telegram подключён»). Остальные — по возможности.
REQUIRED_STATS_FIELDS = ("connections_active", "connections_total", "connections_ws", "bytes_up", "bytes_down")


class CoreError(UserError):
    pass


@dataclass
class ProxyCore:
    version: str
    origin: str               # bundled | updated
    package: ModuleType
    main: ModuleType          # tg_ws_proxy
    config: ModuleType
    stats_module: ModuleType
    utils: ModuleType

    @property
    def proxy_config(self):
        return self.config.proxy_config

    @property
    def stats(self):
        return self.stats_module.stats

    def server_listening(self) -> bool:
        return getattr(self.main, "_server_instance", None) is not None


def _assemble(package_name: str, origin: str) -> ProxyCore:
    package = importlib.import_module(package_name)
    main = importlib.import_module(f"{package_name}.tg_ws_proxy")
    config = importlib.import_module(f"{package_name}.config")
    stats_module = importlib.import_module(f"{package_name}.stats")
    utils = importlib.import_module(f"{package_name}.utils")
    core = ProxyCore(
        version=str(getattr(package, "__version__", "?")), origin=origin, package=package,
        main=main, config=config, stats_module=stats_module, utils=utils,
    )
    problem = check(core)
    if problem:
        raise CoreError(problem)
    return core


def check(core: ProxyCore) -> str | None:
    """Совместимо ли ядро с тем, как приложение его использует."""
    run = getattr(core.main, "_run", None)
    if run is None or not asyncio.iscoroutinefunction(run):
        return "в ядре нет функции _run(stop_event)"
    pc = getattr(core.config, "proxy_config", None)
    if pc is None:
        return "в ядре нет proxy_config"
    missing = [f for f in REQUIRED_CONFIG_FIELDS if not hasattr(pc, f)]
    if missing:
        return "в proxy_config нет полей: " + ", ".join(missing)
    for name in ("parse_dc_ip_list", "coerce_domain_list"):
        if not callable(getattr(core.config, name, None)):
            return f"в ядре нет функции {name}"
    if not hasattr(core.main, "_server_instance"):
        return "в ядре нет _server_instance (по нему видно, что прокси слушает порт)"
    st = getattr(core.stats_module, "stats", None)
    if st is None:
        return "в ядре нет статистики"
    missing = [f for f in REQUIRED_STATS_FIELDS if not hasattr(st, f)]
    if missing:
        return "в статистике ядра нет полей: " + ", ".join(missing)
    if not callable(getattr(core.utils, "create_ssl_context", None)):
        return "в ядре нет create_ssl_context"
    return None


def load_bundled() -> ProxyCore:
    return _assemble(BUNDLED_PACKAGE, "bundled")


def module_name_for(version: str) -> str:
    return "tgws_proxy_" + re.sub(r"[^0-9A-Za-z]", "_", version)


def _forget_modules(name: str) -> None:
    """Убрать из sys.modules пакет ядра и его подмодули: следующая попытка загрузит его заново."""
    for key in [k for k in sys.modules if k == name or k.startswith(name + ".")]:
        del sys.modules[key]


def load_from_dir(package_dir: Path, version: str) -> ProxyCore:
    name = module_name_for(version)
    if name not in sys.modules:
        init = package_dir / "__init__.py"
        if not init.is_file():
            raise CoreError(f"нет файла {init}")
        spec = importlib.util.spec_from_file_location(name, init,
                                                      submodule_search_locations=[str(package_dir)])
        if spec is None or spec.loader is None:
            raise CoreError("не удалось подготовить загрузку ядра")
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        try:
            spec.loader.exec_module(module)
        except Exception as exc:
            _forget_modules(name)
            raise CoreError(f"ядро не загрузилось: {exc!r}") from exc
    try:
        return _assemble(name, "updated")
    except CoreError:
        _forget_modules(name)
        raise
    except ImportError as exc:
        _forget_modules(name)
        missing = getattr(exc, "name", None)
        hint = f" (нужен модуль {missing}, которого нет в этой сборке)" if missing else ""
        raise CoreError(f"ядро не загрузилось: {exc}{hint}") from exc
    except Exception as exc:  # noqa: BLE001 — чужой код: SyntaxError, RuntimeError в подмодуле
        _forget_modules(name)
        raise CoreError(f"ядро не загрузилось: {exc!r}") from exc
