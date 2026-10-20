"""Папка данных: фактические права, а не только владелец и метка; недоверенное содержимое — в сторону с
переносом данных человека, а не удаление; перенос — как транзакция (занятый файл, сбой посреди переноса);
пустая папка переносного режима — без откладывания; диск без прав доступа — понятный отказ. Права на
настоящие папки не меняются: применение списка доступа подменено; службы не трогаются: подменены."""
import _winapi
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from app import paths, security, winutil

SAFE_ROOT = "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"


@pytest.mark.parametrize("sddl, protected, problem", [
    (SAFE_ROOT, True, None),
    ("D:AI(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIID;0x1200a9;;;BU)", False, None),   # наследник
    ("D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", True, None),                                # закрытая vpnclient
    ("D:AI(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIID;0x1200a9;;;BU)", True, "наследуются"),
    ("D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;BU)", True, "не только администратор"),
    ("D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;S-1-5-21-1-2-3-1001)", True, "S-1-5-21-1-2-3-1001"),
    ("D:PAI(A;OICI;FA;;;SY)(A;;GW;;;WD)", True, "WD"),
    ("D:PAI(A;OICI;FA;;;SY)(A;;ZZ;;;BU)", True, "не только администратор"),   # незнакомое право — опасно
    ("D:PAI(D;OICI;FA;;;BU)(A;OICI;FA;;;SY)", True, None),                    # запрет — не разрешение
    ("D:NO_ACCESS_CONTROL", False, "не разобрать"),                          # NULL DACL — всё всем
])
def test_dacl_problem(sddl, protected, problem):
    found = security.dacl_problem(sddl, protected)
    assert (found is None) if problem is None else (problem in found), found


def test_ordinary_temp_folder_is_not_trusted(tmp_path):
    (tmp_path / security.MARKER).write_text("ok", encoding="ascii")
    assert security.untrusted_reason(tmp_path) == "владелец не администратор"
    assert security.acl_problem(tmp_path) is not None, "во временной папке пишет её владелец"
    assert security.keeps_acls(tmp_path) is True


def _untrusted_folder(root):
    (root / "vpnclient").mkdir(parents=True)
    (root / "zapret" / "user").mkdir(parents=True)
    (root / "zapret" / "packs" / "1.10.3" / "bin").mkdir(parents=True)
    (root / "settings.json").write_text(json.dumps({
        "first_run": False, "tg": {"secret": "ab" * 16, "core": "1.11.9"},
        "updates": {"app_backup": r"C:\Users\x\evil.exe", "app_backup_for": "x", "app_backup_version": "1"}}),
        encoding="utf-8")
    (root / "vpnclient" / "profiles.json").write_text('{"servers": []}', encoding="utf-8")
    (root / "zapret" / "user" / "list-general-user.txt").write_text("my.site\n", encoding="utf-8")
    (root / "zapret" / "packs" / "1.10.3" / "bin" / "winws.exe").write_bytes(b"MZ-tampered")


def _no_acl(path, sddl=security.SDDL):
    pass


def _asides(folder):
    return sorted(p for p in folder.iterdir() if "-untrusted-" in p.name)


def test_untrusted_folder_is_set_aside_and_user_data_comes_back(tmp_path):
    """Копия LazeykaData Проводником (владелец — пользователь) не теряет настройки и профили, а
    программы из неё не запускаются: они остаются в отложенной папке."""
    root = tmp_path / "LazeykaData"
    _untrusted_folder(root)
    applied = []
    notes, result = security.rebuild(root, "владелец не администратор",
                                     apply_acl=lambda path, sddl=security.SDDL: applied.append((path, sddl)))
    [aside] = result.folders
    assert aside.parent == tmp_path and aside.name.startswith("LazeykaData-untrusted-")
    assert (aside / "zapret" / "packs" / "1.10.3" / "bin" / "winws.exe").is_file()
    assert not (root / "zapret" / "packs").exists(), "программы и код — только заново"
    assert (root / security.MARKER).is_file()
    restored = json.loads((root / "settings.json").read_text(encoding="utf-8"))
    assert restored["tg"]["secret"] == "ab" * 16 and restored["first_run"] is False
    assert restored["tg"]["core"] == "bundled" and restored["updates"]["app_backup"] is None, \
        "пути к программам из недоверенной папки не берутся"
    assert (root / "vpnclient" / "profiles.json").read_text(encoding="utf-8") == '{"servers": []}'
    assert (root / "zapret" / "user" / "list-general-user.txt").read_text(encoding="utf-8") == "my.site\n"
    assert (root, security.SDDL) in applied and (aside, security.PRIVATE_SDDL) in applied
    assert any("перенесено" in n for n in notes)
    assert not (aside / security.PENDING_MARKER).exists(), "перенос закончен — метки незаконченного нет"


def test_all_user_data_comes_back_and_secrets_stay_private(tmp_path, monkeypatch):
    """Без логина и пароля локального прокси «Пускать устройства из сети» открывал бы прокси в сеть без
    пароля; профили маршрутов, копии hosts и резервная копия настроек — тоже данные человека. JSON,
    который не разбирается, не возвращается; файлы своего VPN — только в закрытую папку."""
    root = tmp_path / "LazeykaData"
    vc = root / "vpnclient"
    vc.mkdir(parents=True)
    (root / "settings.json").write_text(json.dumps({"vpnclient": {"allow_lan": True, "local_auth": True}}),
                                        encoding="utf-8")
    (root / "settings.json.bak").write_text(json.dumps({"updates": {"app_backup": r"C:\x\evil.exe"}}),
                                            encoding="utf-8")
    (vc / "local-proxy.json").write_text(json.dumps({"user": "me", "password": "s3cret"}), encoding="utf-8")
    (vc / "routing-profiles.json").write_text(json.dumps([{"id": "r-1", "name": "Мой профиль"}]),
                                              encoding="utf-8")
    (vc / "traffic.json").write_bytes(b"{not json")
    (root / "backups").mkdir()
    (root / "backups" / "hosts-20261001-120000.bak").write_text("127.0.0.1 localhost\n", encoding="utf-8")
    (root / "backups" / "Lazeyka-previous.exe").write_bytes(b"MZ")
    secured = []
    monkeypatch.setattr(security, "secure_private_dir", lambda path: secured.append(path))
    _, result = security.rebuild(root, "тест", apply_acl=_no_acl)
    assert json.loads((vc / "local-proxy.json").read_text(encoding="utf-8")) == {"user": "me", "password": "s3cret"}
    assert json.loads((vc / "routing-profiles.json").read_text(encoding="utf-8"))[0]["name"] == "Мой профиль"
    assert not (vc / "traffic.json").exists(), "не JSON — не данные"
    assert (root / "backups" / "hosts-20261001-120000.bak").read_text(encoding="utf-8") == "127.0.0.1 localhost\n"
    assert not (root / "backups" / "Lazeyka-previous.exe").exists(), "программа — не данные"
    assert json.loads((root / "settings.json.bak").read_text(encoding="utf-8"))["updates"]["app_backup"] is None
    assert set(secured) == {vc}, "ключи своего VPN — только в закрытую папку"
    assert security.restored_titles(result.restored) == [
        "настройки", "логин и пароль локального прокси", "профили маршрутов", "копии файла hosts"]


def test_oversized_or_linked_data_is_not_brought_back(tmp_path):
    aside, root = tmp_path / "aside", tmp_path / "root"
    (aside / "zapret" / "user").mkdir(parents=True)
    root.mkdir()
    (aside / "settings.json").write_text("{не json", encoding="utf-8")
    big = aside / "zapret" / "user" / "big.txt"
    with open(big, "wb") as f:
        f.truncate(security.USER_DATA_LIMIT + 1)
    assert security.restore_user_data([aside], root) == ([], [])


def test_links_inside_untrusted_folder_are_not_followed(tmp_path):
    """Папка-ссылка в недоверенной папке увела бы чтение в чужую папку, жёсткая ссылка отдала бы
    содержимое чужого файла: такое назад не переносится."""
    elsewhere = tmp_path / "admin-only"
    (elsewhere / "user").mkdir(parents=True)
    (elsewhere / "user" / "secret.txt").write_text("чужое", encoding="utf-8")
    (elsewhere / "profiles.json").write_text("{}", encoding="utf-8")
    aside, root = tmp_path / "aside", tmp_path / "root"
    aside.mkdir()
    root.mkdir()
    _winapi.CreateJunction(str(elsewhere), str(aside / "zapret"))
    _winapi.CreateJunction(str(elsewhere), str(aside / "vpnclient"))
    os.link(elsewhere / "profiles.json", aside / "settings.json")
    assert security.restore_user_data([aside], root) == ([], [])
    assert list(root.iterdir()) == []


def _hold_service_files(root):
    """Как работающая служба winws держит свой exe: переименовать его (и папку с ним) нельзя."""
    binary = root / "zapret" / "packs" / "1.9.8" / "bin" / "winws.exe"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"MZ")
    return open(binary, "rb")


def test_busy_file_refuses_without_losing_anything(tmp_path):
    """Файл занят — раньше содержимое удалялось вместо переноса, и свои списки пропадали. Теперь ничего не
    удаляется, данные человека возвращаются в корень и при отказе, а текст отказа называет занятый файл и
    отложенную папку. Метки доверия нет: следующий запуск разберёт папку снова."""
    root = tmp_path / "LazeykaData"
    _untrusted_folder(root)
    held = _hold_service_files(root)
    try:
        with pytest.raises(security.DataFolderError) as caught:
            security.rebuild(root, "тест", apply_acl=_no_acl)
    finally:
        held.close()
    [aside] = _asides(tmp_path)
    text = str(caught.value)
    assert "winws.exe" in text and str(aside) in text
    assert not (root / security.MARKER).exists()
    assert (aside / security.PENDING_MARKER).is_file(), "незаконченный перенос узнаётся по метке"
    assert (root / "zapret" / "user" / "list-general-user.txt").read_text(encoding="utf-8") == "my.site\n"
    assert json.loads((root / "settings.json").read_text(encoding="utf-8"))["tg"]["secret"] == "ab" * 16
    assert (aside / "zapret" / "user" / "list-general-user.txt").is_file(), "оригинал — в отложенной папке"
    assert (root / "zapret" / "packs" / "1.9.8" / "bin" / "winws.exe").is_file(), "занятый файл не удалён"
    assert not (root / "zapret" / "packs" / "1.10.3").exists(), "остальное переехало"


def test_next_start_finishes_transfer_from_every_unfinished_folder(tmp_path, monkeypatch):
    """Два запуска подряд упираются в занятый файл, третий проходит: данные человека — из всех
    незаконченных отложенных папок, а не застревают в первой; метки незаконченного снимаются."""
    monkeypatch.setattr(security, "_trusted_aside", lambda aside: True)
    root = tmp_path / "LazeykaData"
    (root / "vpnclient").mkdir(parents=True)
    (root / "vpnclient" / "profiles.json").write_text('{"servers": [1]}', encoding="utf-8")
    (root / "settings.json").write_text('{"first_run": false}', encoding="utf-8")
    created = []          # отложенные папки в порядке появления: в имени время только до секунды
    held = _hold_service_files(root)
    try:
        for _ in range(2):
            with pytest.raises(security.DataFolderError):
                security.rebuild(root, "тест", apply_acl=_no_acl)
            created += [a for a in _asides(tmp_path) if a not in created]
            assert json.loads((root / "vpnclient" / "profiles.json").read_text(encoding="utf-8")) == {"servers": [1]}
    finally:
        held.close()
    _, result = security.rebuild(root, "нет метки защищённой папки", apply_acl=_no_acl)
    created += [a for a in _asides(tmp_path) if a not in created]
    assert result.folders == created and len(created) == 3
    assert not any((a / security.PENDING_MARKER).exists() for a in created)
    assert (root / security.MARKER).is_file()
    assert json.loads((root / "vpnclient" / "profiles.json").read_text(encoding="utf-8")) == {"servers": [1]}
    assert json.loads((root / "settings.json").read_text(encoding="utf-8"))["first_run"] is False
    assert sorted(os.listdir(root)) == [security.MARKER, "settings.json", "vpnclient"]


def _pending_aside(root, stamp, files, written_ns=0):
    aside = root.parent / f"{root.name}-untrusted-{stamp}-abcd"
    for rel, text in files.items():
        (aside / rel).parent.mkdir(parents=True, exist_ok=True)
        (aside / rel).write_text(text, encoding="utf-8")
    marker = aside / security.PENDING_MARKER
    marker.write_text("ok", encoding="ascii")
    if written_ns:
        os.utime(marker, ns=(written_ns, written_ns))   # порядок папок — по времени метки
    return aside


def test_interrupted_transfer_is_finished_older_first_newer_on_top(tmp_path, monkeypatch):
    """Сбой между переносом в сторону и возвратом данных (раньше метка доверия стояла уже до возврата, и
    данные оставались в отложенной папке навсегда): следующий запуск возвращает их из незаконченных папок
    по порядку — более новые поверх."""
    monkeypatch.setattr(security, "_trusted_aside", lambda aside: True)
    root = tmp_path / "LazeykaData"
    root.mkdir()
    newer = _pending_aside(root, "20261002-100000", {"settings.json": '{"ui": {"theme": "light"}}'},
                           written_ns=2 * 10 ** 18)
    older = _pending_aside(root, "20261001-100000", {"settings.json": '{"ui": {"theme": "dark"}}',
                                                     "zapret/user/list-general-user.txt": "old.site\n"},
                           written_ns=10 ** 18)
    _, result = security.rebuild(root, "нет метки защищённой папки", apply_acl=_no_acl)
    assert result.folders == [older, newer], "пустой корень — новой отложенной папки не нужно"
    assert json.loads((root / "settings.json").read_text(encoding="utf-8"))["ui"]["theme"] == "light"
    assert (root / "zapret" / "user" / "list-general-user.txt").read_text(encoding="utf-8") == "old.site\n"
    assert (root / security.MARKER).is_file() and not (newer / security.PENDING_MARKER).exists()
    alert = security.untrusted_alert(result)
    assert "Назад перенесли: настройки, свои списки." in alert and "эти папки" in alert


def test_unwritten_data_keeps_transfer_unfinished(tmp_path, monkeypatch):
    """Данные не записались назад — метки доверия нет, отложенная папка остаётся незаконченной."""
    root = tmp_path / "LazeykaData"
    _untrusted_folder(root)
    real = security._write_restored

    def failing(target_root, rel, data):
        if rel == "settings.json":
            raise OSError(28, "На диске недостаточно места")
        real(target_root, rel, data)

    monkeypatch.setattr(security, "_write_restored", failing)
    with pytest.raises(security.DataFolderError, match="settings.json"):
        security.rebuild(root, "тест", apply_acl=_no_acl)
    [aside] = _asides(tmp_path)
    assert not (root / security.MARKER).exists() and (aside / security.PENDING_MARKER).is_file()
    assert (aside / "settings.json").is_file()


def test_pending_marker_in_someone_elses_folder_is_ignored(tmp_path):
    """В ProgramData папки может создавать любой: «незаконченный перенос» в папке не от администраторов —
    подложенные данные, их не берём."""
    root = tmp_path / "LazeykaData"
    root.mkdir()
    _pending_aside(root, "20261001-100000", {"settings.json": '{"tg": {"host": "0.0.0.0"}}'})
    assert security._unfinished_asides(root) == []


def test_empty_portable_folder_is_secured_without_setting_aside(tmp_path):
    """Переносной режим включается пустой папкой LazeykaData, которую создаёт сам человек: раньше первый
    запуск откладывал пустоту и ставил плашку «нельзя было доверять… перенесены… удалите эту папку»."""
    root = tmp_path / "LazeykaData"
    root.mkdir()
    applied = []
    notes, result = security.rebuild(root, security.untrusted_reason(root),
                                     apply_acl=lambda path, sddl=security.SDDL: applied.append(path))
    assert result is None and applied == [root]
    assert sorted(os.listdir(tmp_path)) == ["LazeykaData"], "отложенной папки нет"
    assert (root / security.MARKER).is_file()
    assert not any("перенесено" in n for n in notes)


def test_folder_with_only_logs_keeps_them(tmp_path):
    """Запуск без прав пишет журнал в LazeykaData/logs: такая папка — тоже не повод откладывать. У журналов —
    новый владелец (администраторы), иначе человек вернул бы себе запись."""
    root = tmp_path / "LazeykaData"
    (root / "logs").mkdir(parents=True)
    (root / "logs" / "lazeyka.log").write_text("запуск без прав\n", encoding="utf-8")
    applied = []
    _, result = security.rebuild(root, "тест", apply_acl=lambda path, sddl=security.SDDL: applied.append(path))
    assert result is None and applied == [root, root / "logs"]
    assert (root / "logs" / "lazeyka.log").is_file()


@pytest.mark.parametrize("planted", ["code", "hardlink"])
def test_logs_with_anything_else_are_set_aside(tmp_path, planted):
    """В журналах — программа или жёсткая ссылка (Лазейка дописывала бы журнал в чужой файл): это уже не
    «только журналы», папка разбирается как обычно."""
    root = tmp_path / "LazeykaData"
    (root / "logs").mkdir(parents=True)
    if planted == "code":
        (root / "logs" / "version.dll").write_bytes(b"MZ")
    else:
        (tmp_path / "system.ini").write_text("[x]", encoding="ascii")
        os.link(tmp_path / "system.ini", root / "logs" / "lazeyka.log")
    _, result = security.rebuild(root, "тест", apply_acl=_no_acl)
    assert result is not None and not (root / "logs").exists()


def test_alert_says_nothing_was_restored_when_nothing_was():
    text = security.untrusted_alert(security.SetAside(folders=[Path("C:/x/LazeykaData-untrusted-1")]))
    assert "перенесли" not in text and "нечего" in text and "эту папку" in text


def test_data_root_on_fat32_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "test_data_override", lambda: False)
    monkeypatch.setattr(paths, "DATA", tmp_path / "LazeykaData")
    monkeypatch.setattr(security, "keeps_acls", lambda path: False)
    with pytest.raises(security.DataFolderError, match="FAT32"):
        security.secure_data_root([])


def test_secure_data_root_moves_untrusted_aside(tmp_path, monkeypatch):
    root = tmp_path / "LazeykaData"
    _untrusted_folder(root)
    monkeypatch.setattr(paths, "test_data_override", lambda: False)
    monkeypatch.setattr(paths, "DATA", root)
    monkeypatch.setattr(security, "_apply_protected_acl", lambda path, sddl=security.SDDL: None)
    monkeypatch.setattr(winutil, "service_query", lambda name, with_config=False: None)
    notes = []
    result = security.secure_data_root(notes)
    assert result is not None and result.folders[0].is_dir() and (root / "settings.json").is_file()
    assert sorted(os.listdir(root)) == sorted([security.MARKER, "settings.json", "vpnclient", "zapret"])
    assert any("выставлены заново" in n for n in notes)


@pytest.mark.parametrize("binary, state, stops", [
    ('"{root}\\zapret\\packs\\1.9.8\\bin\\winws.exe" --wf-tcp=80,443', "running", True),
    ('"C:\\ProgramData\\Lazeyka\\zapret\\packs\\1.9.8\\bin\\winws.exe" --hostlist="{root}\\x.txt"', "running",
     False),
    ('"{root}-old\\zapret\\bin\\winws.exe"', "running", False),
    ('"{root}\\zapret\\packs\\1.9.8\\bin\\winws.exe"', "stopped", False),
])
def test_own_service_is_stopped_only_when_its_winws_is_inside(tmp_path, monkeypatch, binary, state, stops):
    """Служба Лазейки из недоверенной папки запускает от SYSTEM код, который могли подменить, и держит его
    файлы — её останавливаем перед разбором. Службу другой папки данных не трогаем."""
    root = tmp_path / "LazeykaData"
    asked, stopped = [], []

    def query(name, with_config=False):
        asked.append(name)
        return SimpleNamespace(name=name, state=state, pid=1, binary=binary.format(root=root), start_type=2)

    monkeypatch.setattr(winutil, "service_query", query)
    monkeypatch.setattr(winutil, "service_stop", lambda name, wait=10.0: stopped.append(name) or True)
    notes, was_stopped = security.stop_own_service(root)
    assert asked == ["LazeykaZapret"]
    assert stopped == (["LazeykaZapret"] if stops else []) and bool(notes) is stops and was_stopped is stops
