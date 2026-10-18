"""Методы, доступные странице через window.pywebview.api.

Здесь только обёртки: проверка типов аргументов и превращение исключений в
ответ {"ok": false, "error": ...}. Ядро хранится в приватном атрибуте, чтобы
pywebview не опубликовал его методы для JavaScript.
"""
from __future__ import annotations

import functools
import logging
from typing import Any, Callable

from .core import Core, fail
from .errors import UserError
from .log import scrub

log = logging.getLogger("lazeyka.api")


def _guard(fn: Callable[..., Any]) -> Callable[..., Any]:
    """Исключение → {ok: false}. Текст ошибки чистится от секретов своего VPN: он уходит на
    страницу (в журнал — тоже вычищенным, фильтром на обработчиках)."""
    @functools.wraps(fn)
    def wrapper(self: "Api", *args: Any) -> Any:
        try:
            return fn(self, *args)
        except (UserError, PermissionError) as exc:
            return fail(scrub(str(exc) or type(exc).__name__))
        except (ValueError, RuntimeError, OSError) as exc:
            return fail(scrub(str(exc) or type(exc).__name__))
        except Exception as exc:  # noqa: BLE001
            log.exception("Ошибка в %s", fn.__name__)
            return fail(scrub(f"Внутренняя ошибка: {exc!r}"))
    return wrapper


def _str_or_none(value: Any) -> str | None:
    return str(value) if isinstance(value, (str, int)) and not isinstance(value, bool) and str(value) else None


def _str_list(value: Any) -> list[str] | None:
    return [str(v) for v in value if isinstance(v, (str, int)) and not isinstance(v, bool)] \
        if isinstance(value, list) else None


class Api:
    def __init__(self, core: Core):
        self._core = core

    # ---- состояние
    @_guard
    def get_state(self):
        return self._core.state()

    @_guard
    def get_logs(self, after_id=0, source="all"):
        return self._core.logs(int(after_id or 0), str(source or "all"))

    # ---- приложение
    @_guard
    def finish_onboarding(self, opts=None):
        return self._core.finish_onboarding(opts if isinstance(opts, dict) else {})

    @_guard
    def save_settings(self, partial=None):
        return self._core.save_settings(partial if isinstance(partial, dict) else {})

    @_guard
    def dismiss_notice(self, notice_id):
        return self._core.dismiss_notice(str(notice_id))

    @_guard
    def open_url(self, url):
        return self._core.open_url(url)

    @_guard
    def open_path(self, kind):
        return self._core.open_path(str(kind))

    @_guard
    def copy_text(self, text):
        return self._core.copy_text(str(text))

    @_guard
    def relaunch_admin(self):
        return self._core.relaunch_admin()

    @_guard
    def hide_window(self):
        return self._core.hide()

    @_guard
    def quit_app(self):
        return self._core.quit()

    # ---- zapret
    @_guard
    def zapret_start(self, quiet=False):
        return self._core.zapret_start(quiet=bool(quiet))

    @_guard
    def zapret_stop(self):
        return self._core.zapret_stop()

    @_guard
    def zapret_restart(self):
        return self._core.zapret_restart()

    @_guard
    def zapret_set_strategy(self, strategy_id):
        return self._core.zapret_set_strategy(str(strategy_id))

    @_guard
    def zapret_set_game_filter(self, mode, tcp="", udp=""):
        return self._core.zapret_set_game_filter(str(mode), str(tcp), str(udp))

    @_guard
    def zapret_set_ipset(self, mode):
        return self._core.zapret_set_ipset(str(mode))

    @_guard
    def zapret_update_ipset(self):
        return self._core.zapret_update_ipset()

    @_guard
    def zapret_set_mode(self, mode):
        return self._core.zapret_set_mode(str(mode))

    @_guard
    def zapret_check(self):
        return self._core.zapret_check()

    @_guard
    def zapret_fix(self):
        return self._core.zapret_fix()

    @_guard
    def zapret_fix_revert(self):
        return self._core.zapret_fix_revert()

    @_guard
    def zapret_test_start(self, kind="standard", ids=None):
        if ids is not None:
            ids = [str(i) for i in ids] if isinstance(ids, list) else None
        return self._core.zapret_test_start(str(kind), ids)

    @_guard
    def zapret_test_cancel(self):
        return self._core.zapret_test_cancel()

    @_guard
    def zapret_fix_conflict(self, conflict_id):
        return self._core.zapret_fix_conflict(str(conflict_id))

    @_guard
    def lists_get(self):
        return self._core.lists_get()

    @_guard
    def lists_save(self, list_id, text):
        return self._core.lists_save(str(list_id), str(text))

    @_guard
    def fakes_get(self):
        return self._core.fakes_get()

    @_guard
    def fakes_set(self, slot, name=None):
        return self._core.fakes_set(str(slot), str(name) if name else None)

    @_guard
    def hosts_check(self):
        return self._core.hosts_check()

    @_guard
    def hosts_apply(self):
        return self._core.hosts_apply()

    # ---- Telegram
    @_guard
    def tg_start(self):
        return self._core.tg_start()

    @_guard
    def tg_stop(self):
        return self._core.tg_stop()

    @_guard
    def tg_restart(self):
        return self._core.tg_restart()

    @_guard
    def tg_open_in_telegram(self):
        return self._core.tg_open_in_telegram()

    @_guard
    def tg_copy_link(self):
        return self._core.tg_copy_link()

    @_guard
    def tg_save_settings(self, values=None):
        return self._core.tg_save_settings(values if isinstance(values, dict) else {})

    @_guard
    def tg_regen_secret(self):
        return self._core.tg_regen_secret()

    @_guard
    def tg_test(self):
        return self._core.tg_test()

    @_guard
    def tg_close_original(self):
        return self._core.tg_close_original()

    # ---- диагностика
    @_guard
    def diag_run(self):
        return self._core.diag_run()

    @_guard
    def diag_fix(self, fix_id):
        return self._core.diag_fix(str(fix_id))

    @_guard
    def discord_clear_cache(self):
        return self._core.discord_clear_cache()

    # ---- помощь
    @_guard
    def dns_check(self):
        return self._core.dns_check()

    @_guard
    def dns_open_settings(self):
        return self._core.dns_open_settings()

    @_guard
    def help_report(self):
        return self._core.help_report()

    @_guard
    def check_site(self, domain=""):
        return self._core.check_site(str(domain))

    @_guard
    def lists_add_site(self, domain=""):
        return self._core.lists_add_site(str(domain))

    @_guard
    def defender_check(self):
        return self._core.defender_check()

    @_guard
    def defender_exclude(self):
        return self._core.defender_exclude()

    # ---- VPN
    @_guard
    def vpn_preflight(self, component="zapret"):
        return self._core.vpn_preflight(str(component))

    @_guard
    def vpn_probe(self):
        return self._core.vpn_probe()

    @_guard
    def vpn_answer(self, remember=False, compat=True):
        return self._core.vpn_answer(bool(remember), bool(compat))

    @_guard
    def vpn_set_compat(self, on=True):
        return self._core.vpn_set_compat(bool(on))

    @_guard
    def vpn_set_ask(self, on=True):
        return self._core.vpn_set_ask(bool(on))

    @_guard
    def vpn_forget(self):
        return self._core.vpn_forget()

    @_guard
    def vpn_set_override(self, adapter_id="", kind=None):
        return self._core.vpn_set_override(str(adapter_id), str(kind) if kind else None)

    # ---- обновления
    @_guard
    def updates_check(self):
        return self._core.updates_check()

    @_guard
    def updates_install(self, key):
        return self._core.updates_install(str(key))

    @_guard
    def updates_skip(self, key):
        return self._core.updates_skip(str(key))

    @_guard
    def updates_rollback(self, key):
        return self._core.updates_rollback(str(key))

    # ---- свой VPN
    @_guard
    def vpnclient_import(self, text="", ua_preset=None, hwid=False):
        """text пустой или null — повторить прошлое добавление (страница так предлагает другой UA или HWID)."""
        if text is not None and not isinstance(text, str):
            return fail("Вставьте ссылку на подписку или сервер")
        if text and len(text) > 5 * 1024 * 1024:
            return fail("Слишком длинный текст")
        return self._core.vpnclient_import(text.strip() if text and text.strip() else None,
                                           _str_or_none(ua_preset), bool(hwid))

    @_guard
    def vpnclient_sub_update(self, sub_id=None):
        return self._core.vpnclient_sub_update(_str_or_none(sub_id))

    @_guard
    def vpnclient_sub_remove(self, sub_id):
        return self._core.vpnclient_sub_remove(str(sub_id))

    @_guard
    def vpnclient_sub_set(self, sub_id, values=None):
        return self._core.vpnclient_sub_set(str(sub_id), values if isinstance(values, dict) else {})

    @_guard
    def vpnclient_server_remove(self, server_id):
        return self._core.vpnclient_server_remove(str(server_id))

    @_guard
    def vpnclient_server_rename(self, server_id, name=""):
        return self._core.vpnclient_server_rename(str(server_id), str(name or ""))

    @_guard
    def vpnclient_copy_link(self, server_id):
        return self._core.vpnclient_copy_link(str(server_id))

    @_guard
    def vpnclient_open_link(self, sub_id, kind):
        if kind not in ("support", "page"):
            return fail("Неизвестная ссылка подписки")
        return self._core.vpnclient_open_link(str(sub_id), kind)

    @_guard
    def vpnclient_select(self, server_id):
        return self._core.vpnclient_select(str(server_id))

    @_guard
    def vpnclient_preflight(self):
        return self._core.vpnclient_preflight()

    @_guard
    def vpnclient_start(self, quiet=False):
        return self._core.vpnclient_start(quiet=bool(quiet))

    @_guard
    def vpnclient_stop(self):
        return self._core.vpnclient_stop()

    @_guard
    def vpnclient_restart(self):
        return self._core.vpnclient_restart()

    @_guard
    def vpnclient_set_mode(self, mode):
        return self._core.vpnclient_set_mode(str(mode))

    @_guard
    def vpnclient_latency(self, ids=None):
        if ids is not None and not isinstance(ids, list):
            return fail("Неверный список серверов")
        return self._core.vpnclient_latency(_str_list(ids))

    @_guard
    def vpnclient_save_settings(self, values=None):
        return self._core.vpnclient_save_settings(values if isinstance(values, dict) else {})

    @_guard
    def vpnclient_core_install(self, name):
        return self._core.vpnclient_core_install(str(name))

    @_guard
    def vpnclient_rules_update(self):
        return self._core.vpnclient_rules_update()

    @_guard
    def vpnclient_running_apps(self):
        return self._core.vpnclient_running_apps()

    @_guard
    def vpnclient_import_file(self):
        return self._core.vpnclient_import_file()

    @_guard
    def vpnclient_import_qr(self, source="screen"):
        return self._core.vpnclient_import_qr(str(source))

    @_guard
    def vpnclient_qr(self, item_id):
        return self._core.vpnclient_qr(str(item_id))

    @_guard
    def vpnclient_backup_export(self, password=""):
        if not isinstance(password, str) or not password:
            return fail("Придумайте пароль для резервной копии")
        return self._core.vpnclient_backup_export(password)

    @_guard
    def vpnclient_backup_import(self, password=""):
        if not isinstance(password, str) or not password:
            return fail("Введите пароль резервной копии")
        return self._core.vpnclient_backup_import(password)

    @_guard
    def vpnclient_profile_import(self, text=""):
        if not isinstance(text, str) or not text.strip():
            return fail("Вставьте профиль маршрутизации")
        return self._core.vpnclient_profile_import(text)

    @_guard
    def vpnclient_profile_set(self, profile_id, active=True):
        return self._core.vpnclient_profile_set(str(profile_id), bool(active))

    @_guard
    def vpnclient_profile_remove(self, profile_id):
        return self._core.vpnclient_profile_remove(str(profile_id))

    @_guard
    def vpnclient_speedtest(self, server_id=None):
        return self._core.vpnclient_speedtest(_str_or_none(server_id))

    @_guard
    def vpnclient_deeplink_confirm(self, token, accept=False):
        return self._core.vpnclient_deeplink_confirm(str(token), bool(accept))

    @_guard
    def vpnclient_sub_probe(self, sub_id):
        return self._core.vpnclient_sub_probe(str(sub_id))

    @_guard
    def vpnclient_help(self):
        return self._core.vpnclient_help()

    @_guard
    def vpnclient_proxy_fix(self):
        return self._core.vpnclient_proxy_fix()

    @_guard
    def vpnclient_open_adapters(self):
        return self._core.vpnclient_open_adapters()
