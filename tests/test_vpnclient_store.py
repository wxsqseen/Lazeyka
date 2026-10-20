"""Свой VPN: profiles.json — атомарная запись, закрытая папка, битый файл, лимиты, слияние подписки."""
import json
from urllib.parse import quote

import pytest

from app.vpnclient import store as store_module
from app.vpnclient.links import parse_link
from app.vpnclient.model import Group, Subscription
from app.vpnclient.store import ProfileStore, StoreError, match_servers
from app.vpnclient.subscription import Decoded, SubMeta

U1 = "11111111-2222-4333-8444-555555555555"
U2 = "22222222-3333-4444-8555-666666666666"
U3 = "33333333-4444-4555-8666-777777777777"


def _server(name: str, host: str = "a.example.com", port: int = 443, uuid: str = U1, path: str | None = None):
    return parse_link(f"vless://{uuid}@{host}:{port}?security=tls&type=ws&path={quote(path or '/' + name)}#{quote(name)}")


def _decoded(servers, groups=(), **meta) -> Decoded:
    return Decoded("links", servers=list(servers), groups=list(groups), meta=SubMeta(**meta))


@pytest.fixture
def secured():
    return []


@pytest.fixture
def path(tmp_path):
    return tmp_path / "data" / "vpnclient" / "profiles.json"


@pytest.fixture
def store(path, secured):
    return ProfileStore(path, secure=secured.append)


def _sub(store: ProfileStore, url: str = "https://sub.example.com/s/TOKEN", **fields) -> Subscription:
    return store.add_subscription(Subscription(id="", name=fields.pop("name", ""), url=url, **fields))


# ------------------------------------------------------------ файл и папка

def test_limits_match_the_plan():
    assert (store_module.MAX_SUBSCRIPTIONS, store_module.MAX_SERVERS) == (50, 2000)


def test_folder_is_secured_before_first_write(store, path, secured):
    assert secured == [] and not path.parent.exists()
    _sub(store)
    store.select(None)
    assert secured == [path.parent]                       # одной копии хранилища — один раз
    ProfileStore(path, secure=secured.append).save()
    # Папка уже была (её могли создать раньше с правами по наследству) — всё равно закрываем.
    assert secured == [path.parent, path.parent]


def test_failed_securing_of_existing_folder_keeps_it(path):
    path.parent.mkdir(parents=True)
    (path.parent / "traffic.json").write_text("{}", encoding="utf-8")

    def deny(folder):
        raise PermissionError("нет прав")
    with pytest.raises(StoreError):
        _sub(ProfileStore(path, secure=deny))
    assert not path.exists() and (path.parent / "traffic.json").exists()


def test_failed_securing_writes_nothing(path):
    def deny(folder):
        raise PermissionError("нет прав")
    store = ProfileStore(path, secure=deny)
    with pytest.raises(StoreError):
        _sub(store)
    assert not path.parent.exists()


def test_atomic_save_and_reload(store, path):
    sub = _sub(store, name="Мой VPN")
    store.apply_decoded(sub.id, _decoded([_server("A"), _server("B", host="b.example.com")]))
    store.select(store.servers()[1].id)
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["schema"] == 1 and set(data) == {"schema", "subscriptions", "servers", "groups", "selected", "latency",
                                                 "speed"}
    assert data["subscriptions"][0]["url"] == "https://sub.example.com/s/TOKEN"    # секреты — только в этом файле
    assert [p.name for p in path.parent.iterdir()] == ["profiles.json"]           # .tmp не остаётся
    again = ProfileStore(path)
    assert again.export_data() == store.export_data() and again.load_error is None


def test_failed_replace_keeps_the_previous_file(store, path, monkeypatch):
    _sub(store)
    before = path.read_bytes()

    def boom(src, dst):
        raise PermissionError(13, "Отказано в доступе")
    monkeypatch.setattr(store_module.os, "replace", boom)
    with pytest.raises(StoreError):
        _sub(store, url="https://other.example.com/s")
    assert path.read_bytes() == before and not path.with_name("profiles.json.tmp").exists()


@pytest.mark.parametrize("content", [b"{\xd0\xbd\xd0\xb5 json", b'{"schema": 2, "servers": []}', b"[]", b"\xff\xfe"])
def test_broken_file_is_kept_aside_not_silently_lost(path, content):
    path.parent.mkdir(parents=True)
    path.write_bytes(content)
    store = ProfileStore(path)
    [bad] = [p for p in path.parent.iterdir() if p.name.startswith("profiles.json.bad-")]
    assert bad.read_bytes() == content
    assert bad.name in store.load_error and "повреждён" in store.load_error
    assert store.subscriptions() == [] and store.servers() == []
    assert json.loads(path.read_text(encoding="utf-8"))["schema"] == 1           # на месте — уже исправный файл


def test_broken_file_without_backup_makes_store_read_only(path, monkeypatch):
    path.parent.mkdir(parents=True)
    path.write_bytes(b"{oops")

    def no_copy(src, dst):
        raise OSError(28, "Нет места на диске")
    monkeypatch.setattr(store_module.shutil, "copy2", no_copy)
    store = ProfileStore(path)
    assert "не удалось" in store.load_error
    with pytest.raises(StoreError):
        _sub(store)
    assert path.read_bytes() == b"{oops"


def test_damaged_entries_are_skipped_with_message(path):
    good = _server("A").to_dict()
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"schema": 1, "subscriptions": [{"name": "без id"}],
                                "servers": [good, {"name": "без протокола"}, dict(_server("B").to_dict(), sub="s-нет")],
                                "groups": [], "selected": "нет-такого", "latency": {good["id"]: {"ms": 5}}}),
                    encoding="utf-8")
    store = ProfileStore(path)
    assert [s.name for s in store.servers()] == ["A"] and store.selected() is None
    assert store.latency(good["id"]) == {"ms": 5}
    assert "3" in store.load_error


# ------------------------------------------------------------ подписки

def test_subscription_limit_and_duplicates(store, monkeypatch):
    monkeypatch.setattr(store_module, "MAX_SUBSCRIPTIONS", 2)
    first = _sub(store)
    assert first.id.startswith("s-") and first.added_at > 0
    with pytest.raises(StoreError):
        _sub(store, url="https://SUB.Example.com/s/TOKEN/")          # тот же адрес
    _sub(store, url="https://second.example.com/s")
    with pytest.raises(StoreError):
        _sub(store, url="https://third.example.com/s")
    with pytest.raises(StoreError):
        _sub(store, url="  ")


def test_update_subscription(store):
    first, second = _sub(store), _sub(store, url="https://second.example.com/s")
    updated = store.update_subscription(first.id, name="Новое имя", ua_preset="incy", update_hours=6)
    assert (updated.name, updated.ua_preset, updated.update_hours) == ("Новое имя", "incy", 6)
    with pytest.raises(ValueError):
        store.update_subscription(first.id, unknown_field=1)
    with pytest.raises(ValueError):
        store.update_subscription(first.id, id="s-другой")
    with pytest.raises(StoreError):
        store.update_subscription(first.id, url=second.url)
    with pytest.raises(StoreError):
        store.update_subscription("s-нет", name="x")


def test_first_import_takes_servers_groups_and_provider_meta(store):
    sub = _sub(store)
    a, b = _server("A"), _server("B", host="b.example.com")
    group = Group(id="g-1", sub=None, name="Умная", members=[a.id, b.id, "чужой"], fallback="чужой")
    report = store.apply_decoded(sub.id, _decoded(
        [a, b], [group], title="Мой VPN", userinfo={"total": 10, "expire": 0}, announce="Работы ночью",
        support_url="https://t.me/support", update_hours=6, fallback_urls=["https://mirror.example.com/s"]), now=100.0)
    assert (report.added, report.removed, report.kept, report.selection) == ([a.id, b.id], [], [], None)
    saved = store.subscription(sub.id)
    assert (saved.name, saved.userinfo, saved.announce, saved.support_url, saved.update_hours, saved.updated_at,
            saved.last_ok_at, saved.format, saved.fallback_urls) == (
        "Мой VPN", {"total": 10, "expire": 0}, "Работы ночью", "https://t.me/support", 6, 100.0, 100.0, "links",
        ["https://mirror.example.com/s"])
    assert [s.sub for s in store.servers()] == [sub.id, sub.id]
    [stored] = store.groups(sub.id)
    assert (stored.sub, stored.members, stored.fallback) == (sub.id, [a.id, b.id], None)


def test_update_keeps_selection_latency_and_own_names(store):
    sub = _sub(store)
    servers = [_server("A"), _server("B", host="b.example.com")]
    store.apply_decoded(sub.id, _decoded(servers))
    store.select(servers[1].id)
    store.set_latency(servers[1].id, 87, at=5.0)
    store.rename_server(servers[1].id, "Мой сервер")
    report = store.apply_decoded(sub.id, _decoded([_server("A"), _server("B", host="b.example.com")]))
    assert (report.added, report.removed, report.kept, report.selection) == ([], [], [s.id for s in servers], None)
    assert store.selected() == servers[1].id
    assert store.latency(servers[1].id) == {"ms": 87, "at": 5.0, "error": None}
    assert store.server(servers[1].id).custom_name == "Мой сервер"


def test_rekeyed_server_is_found_by_name_and_carries_everything(store):
    sub = _sub(store)
    old = _server("Амстердам", uuid=U1)
    store.apply_decoded(sub.id, _decoded([old]))
    store.select(old.id)
    store.set_latency(old.id, 40)
    store.set_speed(old.id, 87.44)
    store.rename_server(old.id, "Дом")
    new = _server("Амстердам", uuid=U2)                        # провайдер сменил ключ
    report = store.apply_decoded(sub.id, _decoded([new]))
    assert report.remapped == {old.id: new.id} and report.selection == (old.id, new.id)
    assert (report.added, report.removed, report.kept) == ([], [], [new.id])
    assert store.selected() == new.id and store.latency(new.id)["ms"] == 40 and store.latency(old.id) == {}
    assert store.speed(new.id)["mbps"] == 87.4 and store.server(new.id).custom_name == "Дом"


def test_matching_falls_back_to_credentials_then_unique_address():
    old = [_server("X", host="h.example.com", uuid=U1, path="/a"), _server("M", host="m.example.com", uuid=U1),
           _server("P1", host="p.example.com", uuid=U1), _server("P2", host="p.example.com", uuid=U2, path="/p2")]
    new = [_server("Y", host="h.example.com", uuid=U1, path="/b"),        # другое имя и путь — те же учётные данные
           _server("N", host="m.example.com", uuid=U3),                   # всё другое, но адрес один такой
           _server("Q1", host="p.example.com", uuid=U3), _server("Q2", host="p.example.com", uuid=U3, path="/q2")]
    pairs = match_servers(old, new)
    assert {n: o.name for n, o in ((k, v) for k, v in pairs.items())} == {new[0].id: "X", new[1].id: "M"}


def test_vanished_selected_server(store):
    sub = _sub(store)
    a, b = _server("A"), _server("B", host="b.example.com")
    group = Group(id="g-1", sub=sub.id, name="Умная", members=[a.id, b.id])
    store.apply_decoded(sub.id, _decoded([a, b], [group]))
    store.select(b.id)
    report = store.apply_decoded(sub.id, _decoded([_server("A")], [Group(id="g-1", sub=sub.id, name="Умная",
                                                                          members=[a.id])]))
    assert report.removed == [b.id] and report.selection == (b.id, None) and report.suggested == "auto:g-1"
    assert store.selected() == b.id                           # что делать дальше, решает менеджер
    store.select(a.id)
    report = store.apply_decoded(sub.id, _decoded([_server("C", host="c.example.com")]))
    assert report.selection == (a.id, None) and report.suggested == store.servers(sub.id)[0].id


def test_error_or_empty_answer_does_not_wipe_the_list(store):
    sub = _sub(store)
    servers = [_server("A"), _server("B", host="b.example.com")]
    store.apply_decoded(sub.id, _decoded(servers), now=10.0)
    report = store.apply_decoded(sub.id, _decoded([], userinfo={"expire": 1}), now=20.0)
    assert report.kept == [s.id for s in servers] and report.removed == [] and report.added == []
    assert [s.id for s in store.servers(sub.id)] == [s.id for s in servers]
    saved = store.subscription(sub.id)
    assert (saved.userinfo, saved.updated_at, saved.last_ok_at) == ({"expire": 1}, 20.0, 10.0)


def test_selected_group_follows_its_new_id(store):
    sub = _sub(store)
    a = _server("A")
    store.apply_decoded(sub.id, _decoded([a], [Group(id="g-old", sub=sub.id, name="Умная", members=[a.id])]))
    store.select("auto:g-old")
    report = store.apply_decoded(sub.id, _decoded([_server("A")], [Group(id="g-new", sub=sub.id, name="Умная",
                                                                          members=[a.id])]))
    assert report.selection == ("auto:g-old", "auto:g-new") and store.selected() == "auto:g-new"
    report = store.apply_decoded(sub.id, _decoded([_server("A")]))
    assert report.selection == ("auto:g-new", None) and report.suggested == f"auto:{sub.id}"


def test_server_limit_and_foreign_servers(store, monkeypatch):
    monkeypatch.setattr(store_module, "MAX_SERVERS", 3)
    manual = store.add_servers([_server("Свой", host="own.example.com")])
    assert len(manual.added) == 1
    first = _sub(store)
    report = store.apply_decoded(first.id, _decoded([_server(n, host=f"{n}.example.com") for n in "abc"]))
    assert len(report.added) == 2 and report.skipped == 1                    # лимит: один свой + два
    second = _sub(store, url="https://second.example.com/s")
    report = store.apply_decoded(second.id, _decoded([_server("a", host="a.example.com"), _server("Свой", host="own.example.com")]))
    assert report.added == [] and report.skipped == 2                        # такие серверы уже есть
    with pytest.raises(StoreError):
        store.add_servers([_server("лишний", host="x.example.com")])


def test_add_servers_and_filters(store):
    a = _server("A")
    assert store.add_servers([a, a]).added == [a.id]
    assert store.add_servers([a]).kept == [a.id]
    sub = _sub(store)
    store.apply_decoded(sub.id, _decoded([_server("B", host="b.example.com")]))
    assert [s.name for s in store.servers(None)] == ["A"]
    assert [s.name for s in store.servers(sub.id)] == ["B"]
    assert [s.name for s in store.servers()] == ["A", "B"]
    copy_ = store.servers()[0]
    copy_.name = "изменено"
    assert store.server(a.id).name == "A"                                     # наружу — копии


def test_pasting_link_again_updates_its_parameters(store, path):
    """В key() нет ключа REALITY: повторная вставка ссылки с новым pbk обновляет сервер, своё имя остаётся."""
    base = (f"vless://{U1}@srv.example.com:443?type=tcp&security=reality&sni=www.example.com&fp=chrome&sid=ab"
            "&flow=xtls-rprx-vision&pbk=")
    old = parse_link(base + "Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw#a")
    new = parse_link(base + "AAAJ2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw#a")
    assert old.key() == new.key()
    store.add_servers([old])
    store.rename_server(old.key(), "Мой")
    report = store.add_servers([new])
    assert report.updated == [old.key()] and report.added == [] and report.kept == []
    kept = store.server(old.key())
    assert kept.tls["pbk"].startswith("AAA") and kept.custom_name == "Мой"
    assert ProfileStore(path).server(old.key()).tls["pbk"].startswith("AAA"), "записано на диск"
    assert store.add_servers([new]).kept == [old.key()], "та же ссылка — без изменений"


def test_pasted_link_does_not_rewrite_subscription_server(store):
    """Сервер подписки ведёт провайдер: вставленная отдельно ссылка его не меняет."""
    sub = _sub(store)
    a = _server("A")
    store.apply_decoded(sub.id, _decoded([a]))
    changed = parse_link(a.raw.replace("#A", "#Другое"))
    report = store.add_servers([changed])
    assert report.kept == [a.id] and not report.updated and store.server(a.id).name == "A"


def test_remove_server_and_subscription(store):
    sub = _sub(store)
    a, b = _server("A"), _server("B", host="b.example.com")
    store.apply_decoded(sub.id, _decoded([a, b], [Group(id="g-1", sub=sub.id, name="Г", members=[a.id])]))
    store.set_latency(a.id, 10)
    store.select("auto:g-1")
    assert store.remove_server(a.id) and not store.remove_server(a.id)
    assert store.groups() == [] and store.selected() is None and store.latency(a.id) == {}
    store.select(f"auto:{sub.id}")
    assert store.remove_subscription(sub.id) == [b.id]
    assert store.servers() == [] and store.subscriptions() == [] and store.selected() is None
    with pytest.raises(StoreError):
        store.remove_subscription(sub.id)


def test_rename_and_select_validation(store):
    a = _server("A")
    store.add_servers([a])
    assert store.rename_server(a.id, "  Мой\nсервер ").custom_name == "Мой сервер"
    assert store.rename_server(a.id, "   ").custom_name is None
    with pytest.raises(StoreError):
        store.rename_server("нет", "x")
    for bad in ("нет", "auto:g-нет", "auto:s-нет"):
        with pytest.raises(StoreError):
            store.select(bad)
    sub = _sub(store)
    store.select(f"auto:{sub.id}")
    store.select(None)
    assert store.selected() is None


def test_latency_batch_is_saved_once(store, path):
    servers = [_server("A"), _server("B", host="b.example.com")]
    store.add_servers(servers)
    for number, server in enumerate(servers):
        store.set_latency(server.id, 10 + number, error=None, at=1.0, save=False)
    store.set_latency("удалённый", 5)                                      # результат для удалённого — мимо
    assert ProfileStore(path).latency() == {}
    store.save()
    assert ProfileStore(path).latency() == {servers[0].id: {"ms": 10, "at": 1.0, "error": None},
                                            servers[1].id: {"ms": 11, "at": 1.0, "error": None}}
    store.set_latency(servers[0].id, None, error="нет ответа за 5 с", at=2.0)
    assert store.latency(servers[0].id) == {"ms": None, "at": 2.0, "error": "нет ответа за 5 с"}


def test_export_import_roundtrip(store, tmp_path):
    sub = _sub(store)
    store.apply_decoded(sub.id, _decoded([_server("A")]))
    store.select(store.servers()[0].id)
    other = ProfileStore(tmp_path / "other" / "profiles.json")
    report = other.import_data(store.export_data())
    assert report.added == [s.id for s in store.servers()] and other.export_data() == store.export_data()
    with pytest.raises(StoreError):
        other.import_data({"schema": 99})
    assert other.export_data() == store.export_data()


def test_import_merges_with_what_is_already_there(store, tmp_path):
    mine = _sub(store, url="https://sub.example.com/s/TOKEN")
    store.apply_decoded(mine.id, _decoded([_server("A")]))
    backup = ProfileStore(tmp_path / "backup" / "profiles.json")
    same = _sub(backup, url="https://sub.example.com/s/TOKEN")          # та же подписка, другой id
    backup.apply_decoded(same.id, _decoded([_server("A"), _server("B", host="b.example.com")]))
    extra = _sub(backup, url="https://extra.example.com/s")
    backup.apply_decoded(extra.id, _decoded([_server("C", host="c.example.com")]))
    report = store.import_data(backup.export_data())
    a, b, c = (_server(n, host=f"{n.lower()}.example.com").id for n in "ABC")
    assert (report.added, report.kept, report.skipped) == ([b, c], [a], 0)
    assert len(store.subscriptions()) == 2                              # своя + новая из копии
    assert store.server(b).sub == mine.id                               # к уже известной подписке


def test_latency_error_can_be_passed_positionally(store):
    a = _server("A")
    store.add_servers([a])
    store.set_latency(a.id, None, "нет ответа", at=3.0)
    store.set_speed(a.id, None, "обрыв", at=4.0)
    assert store.latency(a.id) == {"ms": None, "at": 3.0, "error": "нет ответа"}
    assert store.speed(a.id) == {"mbps": None, "at": 4.0, "error": "обрыв"}


def test_reload_keeps_the_broken_file_message(path):
    path.parent.mkdir(parents=True)
    path.write_bytes(b"{oops")
    store = ProfileStore(path)
    message = store.load_error
    store.load()                                                         # менеджер перечитывает сразу
    assert store.load_error == message and "повреждён" in message


def _wg(name: str, private: str, address: str):
    from app.vpnclient.links import finish
    from app.vpnclient.model import Server
    return finish(Server("wireguard", "203.0.113.40", 51820, name=name,
                         wg={"private_key": private, "peer_public_key": "PUB", "local_address": [address]}))


def test_wireguard_clients_of_one_server_are_separate_and_old_ids_still_match(store):
    """Два профиля WireGuard одного сервера с разными ключами клиента — два сервера, а не дубль. Запись,
    сохранённая с прежним id (до клиента в key()), при обновлении подписки сопоставляется и несёт всё с собой."""
    sub = _sub(store)
    home, work = _wg("Дом", "PRIV-A", "10.0.0.2/32"), _wg("Работа", "PRIV-B", "10.0.0.3/32")
    report = store.apply_decoded(sub.id, _decoded([home, work]))
    assert report.added == [home.id, work.id] and home.id != work.id
    old = _wg("Дом", "PRIV-A", "10.0.0.2/32")
    old.id, old.sub = "0123456789abcdef", sub.id               # так его записал прежний выпуск
    store._state.servers = [s for s in store._state.servers if s.id != home.id] + [old]
    store.select(old.id)
    store.set_latency(old.id, 33)
    report = store.apply_decoded(sub.id, _decoded([_wg("Дом", "PRIV-A", "10.0.0.2/32"), work]))
    assert report.remapped == {old.id: home.id} and store.selected() == home.id
    assert store.latency(home.id)["ms"] == 33 and not report.added and not report.removed


def test_same_link_saved_under_an_old_id_is_not_added_twice(store):
    single = _wg("WG", "PRIV-C", "10.0.0.4/32")
    single.id = "fedcba9876543210"                            # прежний id той же ссылки
    store._state.servers.append(single)
    report = store.add_servers([_wg("WG", "PRIV-C", "10.0.0.4/32")])
    assert report.added == [] and len(store.servers()) == 1
