"""Страховка связи: Лазейка запустила winws — не пропал ли из-за него интернет целиком.

Жалоба: «с обходом полностью вырубается интернет». Страховка срабатывает после любого удачного
запуска winws Лазейкой — включение, перезапуск, смена стратегии и фильтров, подбор, сон, перестройка
под сеть, служба Windows: менеджер обхода зовёт probe() перед запуском (есть ли связь, пока нового winws
нет) и started() — сразу после. Проверка идёт по условию, а не по часам: первая — как только winws готов.

Ложно не обвиняем. Связи не было и до запуска — судить не по чему: страховка ждёт смены сети, а если
сеть так и не сменилась (адрес у адаптера был ещё до входа в Windows), — появления связи; её нет и через
несколько минут — та же проверка. Иначе схема A/B/A: с обходом связи нет → обход выключается без
запоминания → без него связь есть, и не один раз подряд → обход включается снова → связи опять нет →
обход выключен, плашка (в режиме службы — и запуск службы вместе с Windows: без Лазейки её некому
проверить). Без обхода связи тоже нет — дело не в нём: обход включается обратно, плашка — по итогу этого
запуска.

Проверка состояния и действие (выключить, включить) — под блокировкой обхода: иначе страховка прежнего
запуска выключила бы winws, только что запущенный перестройкой под сеть. Пока обход выключен страховкой
(zapret.guard_paused), подбор, начатый в это время, считает его работавшим и вернёт сам."""
from __future__ import annotations

import logging
import threading
import time
from typing import Callable

log = logging.getLogger("lazeyka.zapret.guard")

TRIES = 3            # проверок связи с работающим обходом, прежде чем заподозрить его
CONFIRM = 2          # удач подряд без обхода: связь вернулась сама, а не случайно мелькнула
PAUSE = 2.0          # секунд между проверками связи
BUSY_WAIT = 180.0    # идёт подбор — решение ждёт его конца не дольше (подбор сам перезапустит обход)
BUSY_POLL = 0.5
LINK_POLL = 30.0     # обход запущен без связи — так часто смотреть, не появилась ли она
LINK_FIRST = 120.0   # связи так и нет — через столько проверить, не обход ли её рвёт
LINK_AGAIN = 600.0   # и без обхода её не было — следующая такая проверка не раньше

GUARD_ALERT = "zapret-guard"           # интернета нет и без обхода / выключить обход не удалось
GUARD_OFF_ALERT = "zapret-guard-off"   # обход выключен сам: с ним пропадал интернет
DOWN_ALERT = "zapret-down"             # обход не включился обратно
_RETRY = {"label": "Включить снова", "call": "zapret_start", "args": []}
_STOP = {"label": "Выключить обход", "call": "zapret_stop", "args": []}


class ConnectivityGuard:
    """online() — открылся ли хоть один проверочный адрес; alert(id, level|None, text, action=, page=) —
    постоянные плашки Core; busy() — идёт подбор стратегии; hint() — совет в плашке «обход выключен»."""

    def __init__(self, zapret, online: Callable[[], bool], alert: Callable[..., None],
                 busy: Callable[[], bool] = lambda: False, hint: Callable[[], str] = lambda: "",
                 pause: float = PAUSE):
        self.zapret = zapret
        self.online = online
        self.alert = alert
        self.busy = busy
        self.hint = hint
        self.pause = pause
        self._lock = threading.Lock()
        self._gen = 0             # номер последнего запуска winws: новый запуск отменяет прежнюю проверку
        self._pending = False     # запущен без связи — проверить, когда сеть сменится или связь появится
        self._closed = False      # Лазейка выходит — ничего не включать
        self._closing = threading.Event()   # будит ожидание связи на выходе
        self._local = threading.local()

    # ------------------------------------------------------------ хуки менеджера обхода

    def probe(self) -> bool | None:
        """Перед запуском winws: есть ли связь без него. None — не проверяли (свой перезапуск
        страховки: связь без обхода она только что проверила сама; Лазейка выходит)."""
        if self._mine() or self._closed:
            return None
        try:
            return bool(self.online())
        except Exception:  # noqa: BLE001 — не проверили: страховка всё равно присмотрит
            log.debug("Связь перед запуском обхода не проверена", exc_info=True)
            return None

    def started(self, online_before: bool | None) -> None:
        """winws запущен Лазейкой. Свои перезапуски страховки новую проверку не начинают."""
        if self._mine():
            return
        with self._lock:
            if self._closed:
                return
            self._gen += 1
            gen = self._gen
            self._pending = online_before is False
        if online_before is False:
            log.info("Связи не было и до запуска обхода — проверю его, когда сеть сменится или связь появится")
            self._await_link(gen, LINK_FIRST)
            return
        threading.Thread(target=self.run, args=(gen,), name="zapret-guard", daemon=True).start()

    def close(self) -> None:
        """Лазейка выходит: идущая проверка бросается и обход обратно не включает. Службу Windows,
        выключенную посреди проверки (zapret.guard_paused), возвращает выход Core."""
        with self._lock:
            self._gen += 1
            self._closed = True
            self._pending = False
        self._closing.set()

    def network_changed(self) -> None:
        """Сеть сменилась (Wi-Fi подключился после входа в Windows): обход, запущенный без связи,
        теперь можно проверить."""
        with self._lock:
            pending, self._pending = self._pending, False
        if pending and self.zapret.status == "running":
            self.started(None)

    # ------------------------------------------------------------ проверка

    def run(self, gen: int) -> None:
        self._local.mine = True
        try:
            self._judge(gen)
        except Exception:  # noqa: BLE001 — страховка не должна ронять поток с ошибкой без следа
            log.exception("Страховка связи не досмотрела обход")
        finally:
            self._local.mine = False

    def _judge(self, gen: int) -> None:
        if self._holds(gen) is not False:
            return
        log.warning("После запуска обхода не открывается ни один проверочный адрес — проверяю связь без него")
        if not self._stop(gen):
            return
        online = self._online_without_bypass(gen)
        if online is None:
            return
        if not online:
            self._restore_offline(gen)
            return
        log.warning("Без обхода связь есть — включаю обход ещё раз, чтобы убедиться, что дело в нём")
        if not self._start_again(gen):
            return
        if self._holds(gen) is not False:
            log.info("Со вторым запуском обхода связь есть: пропадала сама сеть, а не из-за обхода")
            return
        if self._stop(gen, final=True):
            log.warning("С обходом связь пропала снова — обход выключен до «Включить снова»")
            text = "Обход выключен: с ним пропадал интернет, без него связь есть."
            hint = self.hint()
            self.alert(GUARD_OFF_ALERT, "error", f"{text} {hint}" if hint else text, action=_RETRY, page="zapret")

    def _holds(self, gen: int) -> bool | None:
        """Связь с работающим обходом: True — есть, False — нет ни разу из TRIES, None — следить
        больше незачем (обход выключили, перезапустили или поставили на паузу подбора)."""
        for attempt in range(TRIES):
            if not self._watching(gen):
                return None
            if self.online():
                return True
            if attempt + 1 < TRIES:
                time.sleep(self.pause)
        if self.busy():
            # Подбор сам останавливает и запускает обход: решать, пока он идёт, — мешать ему.
            if not self._wait_idle() or not self._watching(gen):
                return None
            return bool(self.online())
        return False if self._watching(gen) else None

    def _online_without_bypass(self, gen: int) -> bool | None:
        """Без обхода: CONFIRM удач подряд — связь есть. None — человек вмешался (включил или выключил)."""
        streak = 0
        attempts = TRIES + CONFIRM - 1
        for attempt in range(attempts):
            if not self._paused_by_us(gen):
                return None
            streak = streak + 1 if self.online() else 0
            if streak >= CONFIRM:
                return True
            if attempt + 1 < attempts:
                time.sleep(self.pause)
        return False

    def _wait_idle(self) -> bool:
        deadline = time.monotonic() + BUSY_WAIT
        while self.busy():
            if time.monotonic() >= deadline:
                log.info("Подбор идёт дольше %.0f с — страховка не вмешивается", BUSY_WAIT)
                return False
            time.sleep(BUSY_POLL)
        return True

    def _await_link(self, gen: int, delay: float) -> None:
        threading.Thread(target=self._link_watch, args=(gen, delay), name="zapret-guard-link", daemon=True).start()

    def _link_watch(self, gen: int, delay: float) -> None:
        """Обход запущен без связи, а сеть может и не смениться (адрес у адаптера был ещё до входа в Windows).
        Связь появилась при работающем обходе — он её не рвёт; нет её и через delay — проверить по схеме A/B/A."""
        deadline = time.monotonic() + delay
        try:
            while not self._closing.wait(LINK_POLL):
                with self._lock:
                    if self._gen != gen or not self._pending:
                        return
                if not self._watching(gen):
                    if self.zapret.status != "running":
                        return            # обход выключили или он упал — ждать нечего
                    continue              # пауза подбора: он сам запустит обход заново
                if self.online():
                    with self._lock:
                        if self._gen == gen:
                            self._pending = False
                    log.info("Связь появилась при работающем обходе — он её не рвёт")
                    return
                if time.monotonic() < deadline:
                    continue
                with self._lock:
                    if self._gen != gen or not self._pending:
                        return
                    self._pending = False
                log.warning("Связи нет %.0f с после запуска обхода, а сеть не сменилась — проверяю, не обход ли "
                            "её рвёт", delay)
                self.run(gen)
                return
        except Exception:  # noqa: BLE001 — поток ожидания: без следа не падать
            log.exception("Страховка связи не дождалась сети")

    def _watching(self, gen: int) -> bool:
        z = self.zapret
        return self._gen == gen and z.status == "running" and not z.paused_for_test

    def _paused_by_us(self, gen: int) -> bool:
        """Обход выключила страховка, и с тех пор его никто не включал и не выключал сам: выключение
        человеком запоминается (was_running), включение — новый запуск."""
        z = self.zapret
        return (self._gen == gen and z.status in ("stopped", "error") and not z.paused_for_test
                and bool(z.settings.get("zapret", "was_running")))

    def _mine(self) -> bool:
        return bool(getattr(self._local, "mine", False))

    # ------------------------------------------------------------ действия

    def _stop(self, gen: int, final: bool = False) -> bool:
        """Выключить обход без запоминания. final — итог «с ним пропадал интернет»: служба Windows больше
        не стартует вместе с системой («Включить снова» вернёт), а подбор не считает обход работавшим."""
        z = self.zapret
        with z.lock:
            if not self._watching(gen):
                return False
            try:
                # не запоминать: ошибись страховка — после перезапуска обход вернётся
                if final:
                    z.stop(remember=False, hold=True)
                else:
                    z.stop(remember=False)
            except Exception as exc:  # noqa: BLE001 — не выключился: хотя бы сказать и дать кнопку
                log.exception("Обход не выключился после пропажи связи")
                self.alert(GUARD_ALERT, "error", "После запуска обхода пропал интернет, а выключить обход не "
                                                 f"удалось: {exc}", action=_STOP, page="zapret")
                return False
            z.guard_paused = not final
        return True

    def _start_again(self, gen: int) -> bool:
        z = self.zapret
        with z.lock:
            if not self._paused_by_us(gen):
                return False
            z.guard_paused = False
            try:
                z.start()
            except Exception as exc:  # noqa: BLE001
                log.warning("Обход не включился снова после проверки связи: %s", exc)
                self.alert(DOWN_ALERT, "error", f"Обход не включился снова после проверки связи: {exc}",
                           action=_RETRY)
                return False
        return True

    def _restore_offline(self, gen: int) -> None:
        """Связи нет и без обхода — дело не в нём: включить обратно. Плашка — по итогу запуска."""
        if not self._paused_by_us(gen):
            return
        log.info("Без обхода интернета тоже нет — дело не в нём, включаю обход обратно")
        if not self._start_again(gen):
            return
        with self._lock:
            again = self._gen == gen and not self._closed
            if again:
                self._pending = True   # сеть вернётся с новым адресом или связь появится — проверить обход тогда
        if again:
            self._await_link(gen, LINK_AGAIN)
        self.alert(GUARD_ALERT, "warn", "Интернета нет и без обхода — дело не в нём: проверьте подключение или "
                                        "роутер. Обход снова включён.", page="zapret")
