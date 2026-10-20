"""Один экземпляр: блокировка папки данных на компьютер (все сеансы Windows), канал «покажи окно» с
первой секунды и закрытие его на выходе, DLL Windows по полному пути."""
import threading
import uuid

from app import winutil


def _in_thread(fn):
    box = {}
    worker = threading.Thread(target=lambda: box.setdefault("value", fn()))
    worker.start()
    worker.join(10)
    return box["value"]


def test_data_lock_is_exclusive_across_holders(tmp_path):
    first = winutil.DataLock(tmp_path, trusted_owners=None)
    second = winutil.DataLock(tmp_path, trusted_owners=None)
    assert first.name.startswith("Global\\Lazeyka.Data.")
    assert first.acquire(0.1) is True
    assert _in_thread(lambda: second.acquire(0.1)) is False, "папку держит другая Лазейка"
    first.release()
    assert _in_thread(lambda: second.acquire(0.1)) is True


def test_data_lock_per_data_folder(tmp_path):
    assert winutil.DataLock(tmp_path / "a").name != winutil.DataLock(tmp_path / "b").name


def test_squatted_lock_does_not_stop_lazeyka(tmp_path):
    """Мьютекс заранее создал не администратор — Лазейку так не остановить: блокировка пропускается
    с заметкой в журнал."""
    squatter = winutil.DataLock(tmp_path, trusted_owners=None)
    assert squatter.acquire(0.1)
    victim = winutil.DataLock(tmp_path)          # доверяет только администраторам и SYSTEM
    assert _in_thread(lambda: victim.acquire(0.1)) is True
    assert "не администратор" in victim.note
    squatter.release()


def test_show_channel_exists_before_listen_and_closes_on_exit():
    name = f"LazeykaTest-{uuid.uuid4().hex[:8]}"
    first = winutil.SingleInstance(name)
    second = winutil.SingleInstance(name)
    assert not first.already_running and second.already_running
    assert second.signal_existing() is True, "второй запуск во время долгого старта показывает окно"
    shown = threading.Event()
    first.listen(shown.set)
    assert shown.wait(5), "сигнал, пришедший до listen, не потерян"
    first.close()
    deadline = threading.Event()
    for _ in range(50):
        if not second.signal_existing():
            break
        deadline.wait(0.05)
    assert second.signal_existing() is False, "выходящий экземпляр больше не принимает «покажи окно»"


def test_system_dll_comes_from_system32():
    dll = winutil.system_dll("dnsapi.dll")
    assert dll._name.lower() == winutil.system32("dnsapi.dll").lower()
