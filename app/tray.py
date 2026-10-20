"""Значок в области уведомлений."""
from __future__ import annotations

import logging
import threading
from typing import TYPE_CHECKING

import pystray

from . import APP_NAME, icons
from .errors import UserError

if TYPE_CHECKING:
    from .core import Core

log = logging.getLogger("lazeyka.tray")

WM_RBUTTONUP = 0x0205
TOOLTIP_MAX = 127      # szTip — 128 единиц UTF-16 вместе с завершающим нулём
NOTIFY_MAX = 255       # szInfo — 256 единиц UTF-16
MENU_SERVERS = 20      # серверов в подменю «Сервер»; остальные — в окне
ALERT_LINE = 44        # текст плашки в подсказке: строки состояния тоже должны поместиться в 127 знаков

_NAMES = {"running": "работает", "starting": "запускается", "stopping": "останавливается",
          "stopped": "выключен", "error": "ошибка"}


def utf16_cut(text: str, units: int) -> str:
    """Не длиннее units единиц UTF-16 — так считают поля значка Windows. Флаг страны в имени сервера или
    эмодзи — две единицы на символ: обрезка по символам переполняла szTip, и подсказка не обновлялась."""
    out: list[str] = []
    used = 0
    for ch in text:
        size = 2 if ord(ch) > 0xFFFF else 1
        if used + size > units:
            break
        out.append(ch)
        used += size
    return "".join(out)


def _rate(value: float | int | None) -> str:
    """Байт/с → «1,8 МБ/с»."""
    v = float(value or 0)
    for unit, size in (("ГБ/с", 1 << 30), ("МБ/с", 1 << 20), ("КБ/с", 1 << 10)):
        if v >= size:
            return f"{v / size:.1f}".replace(".", ",") + f" {unit}"
    return f"{int(v)} Б/с"


class _Icon(pystray.Icon):
    """Меню пересобирается в потоке трея прямо перед показом.

    pystray на Windows строит меню заранее; пересборка из другого потока, пока
    меню открыто, — гонка. Так галочки и список стратегий всегда актуальны.
    """

    def _on_notify(self, wparam, lparam):
        if lparam == WM_RBUTTONUP:
            try:
                self._update_menu()
            except Exception:  # noqa: BLE001
                log.debug("Меню трея не пересобрано", exc_info=True)
        return super()._on_notify(wparam, lparam)


class Tray:
    def __init__(self, core: "Core"):
        self.core = core
        self._images: dict[str, object] = {}
        self.icon = _Icon("Lazeyka", self._image("off"), APP_NAME, menu=self._menu())

    def _image(self, status: str):
        if status not in self._images:
            self._images[status] = icons.draw(64, status)
        return self._images[status]

    # ------------------------------------------------------------ свой VPN

    def _vpn(self) -> dict | None:
        """Снимок своего VPN; None — модуля нет или он не ответил."""
        vc = getattr(self.core, "vpnclient", None)
        if vc is None:
            return None
        try:
            snap = vc.snapshot()
        except Exception:  # noqa: BLE001 — значок не должен падать из-за VPN
            log.debug("Снимок своего VPN не получен", exc_info=True)
            return None
        return snap if isinstance(snap, dict) and snap.get("available", True) else None

    def _alerts(self) -> list[dict]:
        """Видимые плашки warn и error (серьёзные первыми): поломки, о которых Лазейка не уведомляет."""
        get = getattr(self.core, "active_alerts", None)
        if get is None:
            return []
        try:
            return [a for a in get() if isinstance(a, dict)]
        except Exception:  # noqa: BLE001 — значок не должен падать из-за плашек
            log.debug("Плашки для значка не получены", exc_info=True)
            return []

    def _status(self) -> str:
        """Цвет значка: по компонентам, а плашка поверх — error красит в красный, warn в янтарный
        («работает, но не всё в порядке»: сторож, свой VPN без выхода…)."""
        status = self._component_status()
        levels = {a.get("level") for a in self._alerts()}
        if status == "error" or "error" in levels:
            return "error"
        if "warn" in levels:
            return "partial"
        return status

    def _component_status(self) -> str:
        """Цвет по трём компонентам. Обход без прав и выключенный свой VPN не в счёт:
        «всё работает» — это всё, что человек включал."""
        z, t = self.core.zapret.status, self.core.tg.status
        vpn = self._vpn()
        v = vpn.get("status") if vpn else None
        states = [t]
        if self.core.zapret.available:
            states.append(z)
        if v and v != "stopped":
            states.append(v)
        if "error" in (z, t, v):
            return "error"
        running = [s == "running" for s in states]
        if all(running):
            return "on"
        if any(running):
            return "partial"
        return "off"

    def _vpn_line(self, vpn: dict | None) -> str | None:
        if vpn is None:
            return None
        status = vpn.get("status") or "stopped"
        if status != "running":
            return f"VPN: {_NAMES.get(status, status)}"
        sel = vpn.get("selected") or {}
        actual = sel.get("actual") or {}
        name = str(actual.get("name") or sel.get("name") or "работает")[:24]
        stats = vpn.get("stats") or {}
        return f"VPN: {name} ↓{_rate(stats.get('down_rate'))} ↑{_rate(stats.get('up_rate'))}"

    def _tooltip(self) -> str:
        z = _NAMES.get(self.core.zapret.status, self.core.zapret.status)
        t = _NAMES.get(self.core.tg.status, self.core.tg.status)
        lines = [APP_NAME, f"Discord и YouTube: обход {z}", f"Telegram-прокси: {t}"]
        alerts = self._alerts()
        if alerts:   # сразу под именем: подсказку Windows обрезает по длине
            text = " ".join(str(alerts[0].get("text") or "").split())
            if utf16_cut(text, ALERT_LINE) != text:
                text = utf16_cut(text, ALERT_LINE - 1).rstrip() + "…"
            more = f" (+{len(alerts) - 1})" if len(alerts) > 1 else ""
            lines.insert(1, f"Проблема: {text}{more}")
        vpn_line = self._vpn_line(self._vpn())
        if vpn_line:
            lines.append(vpn_line)
        return utf16_cut("\n".join(lines), TOOLTIP_MAX)

    # ------------------------------------------------------------ меню

    def _menu(self) -> pystray.Menu:
        core = self.core
        item = pystray.MenuItem
        return pystray.Menu(
            item(f"Открыть {APP_NAME}", lambda: core.show(), default=True),
            pystray.Menu.SEPARATOR,
            item("Discord и YouTube", self._toggle_zapret,
                 checked=lambda _i: core.zapret.status in ("running", "starting"),
                 enabled=lambda _i: core.zapret.available),
            item("Стратегия", pystray.Menu(self._strategy_items),
                 enabled=lambda _i: core.zapret.available and bool(core.zapret.strategies)),
            item("Telegram-прокси", self._toggle_tg,
                 checked=lambda _i: core.tg.status in ("running", "starting")),
            item("Подключить Telegram", self._open_telegram),
            item("Свой VPN", self._toggle_vpn,
                 checked=lambda _i: (self._vpn() or {}).get("status") in ("running", "starting"),
                 enabled=lambda _i: bool(self._server_choices(self._vpn())),
                 visible=lambda _i: self._vpn() is not None),
            item("Сервер", pystray.Menu(self._server_items),
                 enabled=lambda _i: bool(self._server_choices(self._vpn())),
                 visible=lambda _i: self._vpn() is not None),
            pystray.Menu.SEPARATOR,
            item(lambda _i: f"Есть обновления ({core.updates.available_count()})", lambda: core.show(),
                 visible=lambda _i: core.updates.available_count() > 0),
            item("Выход", lambda: core.quit()),
        )

    def _strategy_items(self):
        core = self.core
        for strategy in core.zapret.strategies:
            if not strategy.usable:
                continue
            yield pystray.MenuItem(
                strategy.label,
                self._choose(strategy.id),
                checked=lambda _i, sid=strategy.id: sid == core.settings.get("zapret", "strategy"),
                radio=True,
            )
        if not core.zapret.strategies:
            yield pystray.MenuItem("Нет стратегий", None, enabled=False)

    @staticmethod
    def _auto_target(vpn: dict) -> str | None:
        """Куда ведёт «Самый быстрый»: уже выбранная группа, подписка выбранного сервера,
        единственная подписка или первая группа."""
        selected = vpn.get("selected") or {}
        sid = str(selected.get("id") or "")
        if sid.startswith("auto:"):
            return sid
        servers = {s.get("id"): s for s in vpn.get("servers") or [] if isinstance(s, dict)}
        sub = (servers.get(sid) or {}).get("sub")
        subs = [s.get("id") for s in vpn.get("subscriptions") or [] if isinstance(s, dict)]
        groups = [g.get("id") for g in vpn.get("groups") or [] if isinstance(g, dict)]
        target = sub or (subs[0] if len(subs) == 1 else None) or (groups[0] if groups else None)
        return f"auto:{target}" if target else None

    def _server_choices(self, vpn: dict | None) -> list[tuple[str, str]]:
        """(id, подпись) для подменю: до 20 поддерживаемых серверов и «Самый быстрый»."""
        if not vpn:
            return []
        out: list[tuple[str, str]] = []
        auto = self._auto_target(vpn)
        if auto:
            out.append((auto, "Самый быстрый"))
        for s in vpn.get("servers") or []:
            if not isinstance(s, dict) or not s.get("supported") or not s.get("id"):
                continue
            name = str(s.get("name") or s["id"])[:40]
            country = s.get("country")
            out.append((str(s["id"]), f"{country} · {name}" if country else name))
            if len(out) >= MENU_SERVERS + (1 if auto else 0):
                break
        return out

    def _server_items(self):
        vpn = self._vpn()
        choices = self._server_choices(vpn)
        selected = str(((vpn or {}).get("selected") or {}).get("id") or "")
        for sid, label in choices:
            yield pystray.MenuItem(label, self._select_server(sid),
                                   checked=lambda _i, sid=sid: sid == selected, radio=True)
        if not choices:
            yield pystray.MenuItem("Нет серверов", None, enabled=False)

    def _select_server(self, server_id: str):
        def action(_icon=None, _item=None) -> None:
            try:
                result = self.core.vpnclient_select(server_id)
            except (UserError, PermissionError, OSError, ValueError) as exc:
                result = {"ok": False, "error": str(exc)}
            if not result.get("ok"):
                self.notify(result.get("error", "Сервер не выбран"))
        return action

    def _toggle_vpn(self, _icon=None, _item=None) -> None:
        core = self.core
        try:
            if ((self._vpn() or {}).get("status")) in ("running", "starting"):
                result = core.vpnclient_stop()
            else:
                # Чужой VPN или прокси — окно «Уже работает другой VPN» живёт в окне Лазейки.
                check = core.vpnclient_preflight()
                if check.get("ok") and check.get("ask"):
                    core.show()
                    conflict = check.get("conflict") or {}
                    self.notify(conflict.get("text") or "Уже работает другой VPN — откройте Лазейку.")
                    return
                result = core.vpnclient_start(quiet=True)
        except (UserError, PermissionError, OSError, ValueError) as exc:
            result = {"ok": False, "error": str(exc)}
        if not result.get("ok"):
            self.notify(result.get("error", "Свой VPN не переключился"))

    def _report(self, call, failure: str) -> dict:
        """Вызов ядра из меню: ошибка — уведомлением, а не исключением в потоке значка."""
        try:
            result = call()
        except (UserError, PermissionError, OSError, ValueError, RuntimeError) as exc:
            result = {"ok": False, "error": str(exc)}
        if not isinstance(result, dict):
            result = {"ok": True}
        if not result.get("ok"):
            self.notify(result.get("error") or failure)
        return result

    def _vpn_asks(self, component: str) -> bool:
        """Работает чужой VPN, про который нужно спросить («Работает VPN»): окно Лазейки, а не включение
        вслепую — там можно включить совместимость. True — включать не надо."""
        check = self._report(lambda: self.core.vpn_preflight(component), "VPN не проверен")
        if not (check.get("ok") and check.get("ask")):
            return False
        self.core.show()
        label = (check.get("vpn") or {}).get("label") or "VPN"
        what = "обход" if component == "zapret" else "Telegram-прокси"
        self.notify(f"Работает {label}. Включите {what} в окне Лазейки — там можно включить совместимость с VPN.")
        return True

    def _choose(self, strategy_id: str):
        def action(_icon=None, _item=None) -> None:
            self._report(lambda: self.core.zapret_set_strategy(strategy_id), "Стратегия не применена")
        return action

    def _toggle_zapret(self, _icon=None, _item=None) -> None:
        core = self.core
        if core.zapret.status in ("running", "starting"):
            self._report(core.zapret_stop, "Обход не выключился")
        elif not self._vpn_asks("zapret"):
            self._report(core.zapret_start, "Обход не включился")

    def _toggle_tg(self, _icon=None, _item=None) -> None:
        core = self.core
        if core.tg.status in ("running", "starting"):
            self._report(core.tg_stop, "Telegram-прокси не выключился")
        elif not self._vpn_asks("tg"):
            self._report(core.tg_start, "Telegram-прокси не включился")

    def _open_telegram(self, _icon=None, _item=None) -> None:
        """Как кнопка «Подключить Telegram»: прокси выключен — включить, затем открыть ссылку. Фоном: ядро
        ждёт, пока прокси начнёт слушать порт, а поток значка ждать не должен."""
        def work() -> None:
            core = self.core
            if core.tg.status not in ("running", "starting"):
                if self._vpn_asks("tg") or not self._report(core.tg_start, "Telegram-прокси не включился").get("ok"):
                    return
            result = self._report(core.tg_open_in_telegram, "Telegram не открылся")
            if result.get("ok") and result.get("warning"):
                self.notify(result["warning"])

        threading.Thread(target=work, name="tray-telegram", daemon=True).start()

    # ------------------------------------------------------------ жизненный цикл

    def start(self) -> None:
        threading.Thread(target=self._run, name="tray", daemon=True).start()

    def _run(self) -> None:
        try:
            self.icon.run()
        except Exception:  # noqa: BLE001
            log.exception("Значок в трее упал")

    def refresh(self) -> None:
        """Значок и подсказка; меню обновится само при следующем открытии."""
        try:
            self.icon.icon = self._image(self._status())
            self.icon.title = self._tooltip()
        except Exception:  # noqa: BLE001
            log.debug("Трей ещё не готов", exc_info=True)

    def notify(self, text: str) -> None:
        try:
            self.icon.notify(utf16_cut(text, NOTIFY_MAX), APP_NAME)
        except Exception:  # noqa: BLE001
            log.debug("Уведомление в трее не показано", exc_info=True)

    def stop(self) -> None:
        try:
            self.icon.stop()
        except Exception:  # noqa: BLE001
            pass
