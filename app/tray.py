"""Значок в области уведомлений."""
from __future__ import annotations

import logging
import threading
from typing import TYPE_CHECKING

import pystray

from . import APP_NAME, icons

if TYPE_CHECKING:
    from .core import Core

log = logging.getLogger("lazeyka.tray")

WM_RBUTTONUP = 0x0205


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

    def _status(self) -> str:
        z, t = self.core.zapret.status, self.core.tg.status
        if "error" in (z, t):
            return "error"
        running = [s == "running" for s in (z, t)]
        if all(running) or (running[1] and not self.core.zapret.available):
            return "on"
        if any(running):
            return "partial"
        return "off"

    def _tooltip(self) -> str:
        names = {"running": "работает", "starting": "запускается", "stopping": "останавливается",
                 "stopped": "выключен", "error": "ошибка"}
        z = names.get(self.core.zapret.status, self.core.zapret.status)
        t = names.get(self.core.tg.status, self.core.tg.status)
        text = f"{APP_NAME}\nDiscord и YouTube: {z}\nTelegram: {t}"
        return text[:127]

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
            item("Подключить Telegram", lambda: core.tg_open_in_telegram()),
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

    def _choose(self, strategy_id: str):
        def action(_icon=None, _item=None) -> None:
            result = self.core.zapret_set_strategy(strategy_id)
            if not result.get("ok"):
                self.notify(result.get("error", "Стратегия не применена"))
        return action

    def _toggle_zapret(self, _icon=None, _item=None) -> None:
        core = self.core
        try:
            if core.zapret.status in ("running", "starting"):
                core.zapret_stop()
            else:
                core.zapret_start()
        except PermissionError as exc:
            self.notify(str(exc))

    def _toggle_tg(self, _icon=None, _item=None) -> None:
        if self.core.tg.status in ("running", "starting"):
            self.core.tg_stop()
        else:
            self.core.tg_start()

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
            self.icon.notify(text[:250], APP_NAME)
        except Exception:  # noqa: BLE001
            log.debug("Уведомление в трее не показано", exc_info=True)

    def stop(self) -> None:
        try:
            self.icon.stop()
        except Exception:  # noqa: BLE001
            pass
