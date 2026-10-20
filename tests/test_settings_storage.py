"""settings.json: резервная копия и повреждённый файл, строгая запись, исключения системного прокси,
адрес Telegram-прокси, перенос настроек TG WS Proxy."""
import json

import pytest

from app import settings as settings_mod
from app.settings import Settings, SettingsSaveError, import_tgwsproxy_config


def test_private_172_masks_cover_only_172_16_to_31():
    """«172.2*» захватывала публичные 172.200.*–172.255.*: их трафик уходил мимо VPN."""
    override = settings_mod.DEFAULT_PROXY_OVERRIDE
    assert "172.2*" not in override
    assert [m for m in override if m.startswith("172.")] == [f"172.{n}.*" for n in range(16, 32)]


def test_saved_legacy_mask_is_replaced_in_place(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({"vpnclient": {"proxy_override": ["<local>", "172.2*", "my.host"]}}), encoding="utf-8")
    override = Settings(path).get("vpnclient", "proxy_override")
    assert override == ["<local>", *[f"172.{n}.*" for n in range(16, 32)], "my.host"]


def test_save_keeps_previous_version_as_backup(tmp_path):
    s = Settings(tmp_path / "settings.json")
    s.update(lambda d: d["zapret"].__setitem__("strategy", "general (ALT2)"))
    s.update(lambda d: d["zapret"].__setitem__("strategy", "general (ALT3)"))
    backup = json.loads((tmp_path / "settings.json.bak").read_text(encoding="utf-8"))
    assert backup["zapret"]["strategy"] == "general (ALT2)"
    assert not (tmp_path / "settings.json.tmp").exists()


def test_broken_file_is_set_aside_and_backup_used(tmp_path):
    """Повреждённый settings.json не превращается молча в умолчания (новый ключ Telegram, приветствие)."""
    s = Settings(tmp_path / "settings.json")
    s.update(lambda d: d.__setitem__("first_run", False))
    secret = s.get("tg", "secret")
    s.update(lambda d: d["zapret"].__setitem__("strategy", "general (ALT2)"))
    (tmp_path / "settings.json").write_text("{обрыв", encoding="utf-8")
    again = Settings(tmp_path / "settings.json")
    assert again.get("tg", "secret") == secret and again.get("first_run") is False
    assert "восстановлены настройки из резервной копии" in again.recovered
    assert list(tmp_path.glob("settings.json.broken-*")), "повреждённый файл сохранён, а не затёрт"
    assert again.created is False


def test_broken_file_without_backup_is_reported(tmp_path):
    (tmp_path / "settings.json").write_text("not json", encoding="utf-8")
    s = Settings(tmp_path / "settings.json")
    assert "сброшены к умолчаниям" in s.recovered and s.get("first_run") is False and s.created is False


def test_interrupted_write_falls_back_to_backup(tmp_path):
    """Сбой между переименованиями: settings.json ещё нет, прежняя версия — в .bak."""
    s = Settings(tmp_path / "settings.json")
    s.update(lambda d: d["zapret"].__setitem__("strategy", "general (ALT2)"))
    s.update(lambda d: d["zapret"].__setitem__("strategy", "general (ALT3)"))
    (tmp_path / "settings.json").unlink()
    again = Settings(tmp_path / "settings.json")
    assert again.get("zapret", "strategy") == "general (ALT2)" and again.recovered is None


def test_strict_update_fails_loudly_and_changes_nothing(tmp_path, monkeypatch):
    s = Settings(tmp_path / "settings.json")
    monkeypatch.setattr(s, "save", lambda: False)
    with pytest.raises(SettingsSaveError):
        s.update(lambda d: d["updates"].__setitem__("app_backup", "C:/x.old"), strict=True)
    assert s.get("updates", "app_backup") is None, "не сохранилось — нет и в памяти"
    s.update(lambda d: d["updates"].__setitem__("app_backup", "C:/y.old"))   # нестрогая — как прежде
    assert s.get("updates", "app_backup") == "C:/y.old"


@pytest.mark.parametrize("host", ["::", "::1", "localhost", "", 5])
def test_proxy_host_is_ipv4(tmp_path, host):
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({"tg": {"host": host}}), encoding="utf-8")
    s = Settings(path)
    assert s.get("tg", "host") == "127.0.0.1"
    s.update(lambda d: d["tg"].__setitem__("host", "0.0.0.0"))
    s.update(lambda d: d["tg"].__setitem__("host", "::"))
    assert s.get("tg", "host") == "0.0.0.0", "неверный адрес не перезаписывает прежний"


# ------------------------------------------------------------ перенос настроек TG WS Proxy

def _tgws_config(tmp_path, cfg):
    folder = tmp_path / "AppData" / "TgWsProxy"
    folder.mkdir(parents=True)
    (folder / "config.json").write_text(json.dumps(cfg), encoding="utf-8")
    return str(tmp_path / "AppData")


@pytest.fixture
def validate(tmp_path):
    from app.tgproxy.manager import TgProxyManager
    mgr = TgProxyManager(Settings(tmp_path / "v.json"), lambda *a: None)
    mgr.load_core()
    return mgr.validate


def test_tgws_import_parses_domain_strings_and_checks_values(tmp_path, validate):
    appdata = _tgws_config(tmp_path, {
        "host": "::", "port": 1444, "secret": "ab" * 16, "cfproxy_user_domain_enabled": True,
        "cfproxy_user_domain": "my.example.com, second.example.org", "cfproxy_worker_enabled": True,
        "cfproxy_worker_domain": ""})
    s = Settings(tmp_path / "settings.json")
    assert import_tgwsproxy_config(s, validate, appdata=appdata) is True
    tg = s.get("tg")
    assert tg["port"] == 1444 and tg["secret"] == "ab" * 16
    assert tg["host"] == "127.0.0.1", "IPv6 не переносится: прокси слушал бы без IPv4"
    assert tg["cf_domains"] == ["my.example.com", "second.example.org"] and tg["cf_domains_enabled"] is True
    assert tg["worker_domains"] == [] and tg["worker_enabled"] is False, "переключатель без доменов выключен"


def test_tgws_import_without_validator_result_changes_nothing_invalid(tmp_path):
    appdata = _tgws_config(tmp_path, {"port": 1555, "dc_ip": ["bad"]})
    s = Settings(tmp_path / "settings.json")
    before = s.get("tg", "dc_ip")
    import_tgwsproxy_config(s, lambda values: ({"port": 1555}, {"dc_ip": "Неверная строка"}), appdata=appdata)
    assert s.get("tg", "port") == 1555 and s.get("tg", "dc_ip") == before


def test_locked_file_is_not_called_broken(tmp_path, monkeypatch):
    """Файл занят (антивирус) или не читается без прав — это не повреждение: он не откладывается."""
    s = Settings(tmp_path / "settings.json")
    s.update(lambda d: d["zapret"].__setitem__("strategy", "general (ALT2)"))
    s.update(lambda d: d["zapret"].__setitem__("strategy", "general (ALT3)"))
    real = type(tmp_path).read_text

    def locked(self, *a, **kw):
        if self.name == "settings.json":
            raise PermissionError("файл занят")
        return real(self, *a, **kw)

    monkeypatch.setattr(type(tmp_path), "read_text", locked)
    again = Settings(tmp_path / "settings.json")
    assert again.recovered is None and again.get("zapret", "strategy") == "general (ALT2)"
    assert (tmp_path / "settings.json").exists() and not list(tmp_path.glob("*.broken-*"))


# ------------------------------------------------------------ кодировка и файл, который не прочитался

def _saved_by_human(path, **sections):
    data = {"first_run": False, "tg": {"secret": "ab" * 16}, **sections}
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")


def test_ansi_file_is_broken_not_a_crash(tmp_path):
    """Файл, сохранённый в ANSI (недопустимый байт UTF-8), ронял конструктор Settings и с ним запуск
    Core. Теперь это повреждение: файл откладывается, настройки — из резервной копии."""
    s = Settings(tmp_path / "settings.json")
    s.update(lambda d: d["zapret"].__setitem__("strategy", "general (ALT2)"))
    s.update(lambda d: d["zapret"].__setitem__("strategy", "general (ALT3)"))
    (tmp_path / "settings.json").write_bytes('{"zapret": {"strategy": "Моя"}}'.encode("cp1251"))
    again = Settings(tmp_path / "settings.json")
    assert again.get("zapret", "strategy") == "general (ALT2)"
    assert "восстановлены настройки из резервной копии" in again.recovered
    assert list(tmp_path.glob("settings.json.broken-*"))


def test_broken_backup_is_reported_as_broken(tmp_path):
    (tmp_path / "settings.json").write_bytes(b"\xff\xfe{")
    (tmp_path / "settings.json.bak").write_bytes(b"\xff\xfe{")
    s = Settings(tmp_path / "settings.json")
    assert "резервная копия тоже повреждена" in s.recovered and s.get("first_run") is False


def test_missing_file_with_broken_backup_is_reported(tmp_path):
    """Запись прервалась между переименованиями, а резервная копия повреждена: не молчаливые умолчания
    с приветствием и новым ключом Telegram, а плашка."""
    (tmp_path / "settings.json.bak").write_bytes('{"ui": {"theme": "тёмная"}}'.encode("cp1251"))
    s = Settings(tmp_path / "settings.json")
    assert "резервная копия повреждена" in s.recovered and s.get("first_run") is False


def test_file_with_bom_is_read(tmp_path):
    """Блокнот сохраняет UTF-8 с меткой BOM — это не повреждение."""
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({"first_run": False, "zapret": {"strategy": "general (ALT2)"}}),
                    encoding="utf-8-sig")
    s = Settings(path)
    assert s.recovered is None and s.get("zapret", "strategy") == "general (ALT2)"
    assert not list(tmp_path.glob("*.broken-*"))


def _locked_reads(monkeypatch, path_type, times):
    """settings.json не читается первые times попыток (None — никогда): занят или нет доступа."""
    real = path_type.read_text
    calls = {"n": 0}

    def flaky(self, *a, **kw):
        if self.name == "settings.json" and (times is None or calls["n"] < times):
            calls["n"] += 1
            raise PermissionError(32, "файл занят другим процессом")
        return real(self, *a, **kw)

    monkeypatch.setattr(path_type, "read_text", flaky)
    monkeypatch.setattr(settings_mod, "READ_RETRY_DELAY", 0.0)
    return calls


def test_briefly_locked_file_is_read_on_retry(tmp_path, monkeypatch):
    path = tmp_path / "settings.json"
    _saved_by_human(path, zapret={"strategy": "general (ALT5)"})
    calls = _locked_reads(monkeypatch, type(tmp_path), times=2)
    s = Settings(path)
    assert calls["n"] == 2 and s.recovered is None and s.writable is True
    assert s.get("zapret", "strategy") == "general (ALT5)" and s.get("tg", "secret") == "ab" * 16


def test_unreadable_file_without_backup_is_never_overwritten(tmp_path, monkeypatch):
    """Файл есть, но не прочитался, а резервной копии нет (одна запись в жизни файла, переход с 1.2):
    раньше — молча умолчания, первая запись затирала файл, вторая — и копию. Теперь — умолчания только
    в памяти, без приветствия, запись отключена до перезапуска, и об этом плашка."""
    path = tmp_path / "settings.json"
    _saved_by_human(path, zapret={"strategy": "general (ALT5)"})
    before = path.read_bytes()
    calls = _locked_reads(monkeypatch, type(tmp_path), times=None)
    s = Settings(path)
    assert calls["n"] == settings_mod.READ_ATTEMPTS
    assert s.get("first_run") is False and s.writable is False and s.write_blocked
    assert "Перезапустите Лазейку" in s.recovered and "не сохраняются" in s.recovered
    s.update(lambda d: d["updates"].__setitem__("last_check", 1.0))
    s.update(lambda d: d["updates"].__setitem__("last_check", 2.0))
    assert path.read_bytes() == before and not (tmp_path / "settings.json.bak").exists()
    with pytest.raises(SettingsSaveError, match="не прочитался"):
        s.update(lambda d: d["updates"].__setitem__("app_backup", "C:/x.old"), strict=True)


def test_read_saved_does_not_touch_files(tmp_path):
    """Чтение до запуска Core (решение об автозапуске): повреждённое не откладывается, нет файлов — умолчания."""
    path = tmp_path / "settings.json"
    assert settings_mod.read_saved(path)["startup"]["autostart"] is False
    path.write_text('{"startup": {"autostart": true}}', encoding="utf-8")
    assert settings_mod.read_saved(path)["startup"]["autostart"] is True
    path.write_text("{обрыв", encoding="utf-8")
    assert settings_mod.read_saved(path) is None
    assert sorted(p.name for p in tmp_path.iterdir()) == ["settings.json"]
