"""Диагностика частых причин, по которым zapret не работает.

Перенос пункта «Run Diagnostics» из service.bat: те же проверки, но с кнопками
исправления вместо вопросов в консоли.
"""
from __future__ import annotations

import logging
import os
import re
import shutil
import stat
import time
import winreg
from pathlib import Path

import psutil

from .. import paths, winutil
from . import netcfg
from .runner import foreign_winws

log = logging.getLogger("lazeyka.zapret.diag")

CONFLICT_SERVICES = ("GoodbyeDPI", "discordfix_zapret", "winws1", "winws2", "zapret")
DISCORD_FLAVOURS = (
    ("discord", "Discord.exe", "Discord"),
    ("discordptb", "DiscordPTB.exe", "Discord PTB"),
    ("discordcanary", "DiscordCanary.exe", "Discord Canary"),
    ("discorddevelopment", "DiscordDevelopment.exe", "Discord Development"),
)


def _item(id_: str, title: str, status: str, text: str, fix: tuple[str, str] | None = None) -> dict:
    return {"id": id_, "title": title, "status": status, "text": text,
            "fix": {"id": fix[0], "label": fix[1]} if fix else None}


def _process_running(name: str) -> bool:
    name = name.lower()
    for proc in psutil.process_iter(["name"]):
        try:
            if (proc.info["name"] or "").lower() == name:
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return False


def run_all(pack_dir: Path | None, zapret_running: bool, own=None, compat: bool | None = None,
            overrides: dict | None = None) -> list[dict]:
    """own — снимок своего VPN Лазейки (vpn.OwnVpn): его адаптер и прокси — не чужие. compat — включена ли
    «Совместимость с VPN» (None — неизвестно), overrides — поправки человека к адаптерам."""
    items: list[dict] = []
    services = winutil.service_list()
    names = [(n, d, s) for n, d, s in services]
    # Как `sc query` в service.bat: в счёт идут только работающие службы.
    active = [(n, d, s) for n, d, s in names if s != "stopped"]

    def has_service(pattern: str) -> list[str]:
        rx = re.compile(pattern, re.I)
        return [n for n, d, _s in active if rx.search(n) or rx.search(d)]

    # Base Filtering Engine
    bfe = winutil.service_query("BFE")
    if bfe and bfe.state == "running":
        items.append(_item("bfe", "Base Filtering Engine", "ok", "Служба работает"))
    else:
        items.append(_item("bfe", "Base Filtering Engine", "error",
                           "Служба не запущена — без неё WinDivert не работает. Включите её в services.msc."))

    # Системный прокси
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings") as key:
            enabled = winreg.QueryValueEx(key, "ProxyEnable")[0]
            server = winreg.QueryValueEx(key, "ProxyServer")[0] if enabled else ""
    except OSError:
        enabled, server = 0, ""
    own_proxy = (getattr(own, "proxy", None) or "").split("://")[-1].lower()
    if enabled and own_proxy and own_proxy in str(server).lower():
        items.append(_item("proxy", "Системный прокси", "ok", "Его включил свой VPN Лазейки"))
    elif enabled:
        items.append(_item("proxy", "Системный прокси", "warn",
                           f"Включён прокси {server}. Если вы им не пользуетесь — выключите его в "
                           "параметрах Windows."))
    else:
        items.append(_item("proxy", "Системный прокси", "ok", "Не используется"))

    # TCP timestamps
    ts = netcfg.tcp_timestamps_enabled()
    if ts is True:
        items.append(_item("tcp_ts", "TCP timestamps", "ok", "Включены"))
    elif ts is None:
        # netsh не ответил или ответил непонятно — «выключены» было бы выдумкой.
        items.append(_item("tcp_ts", "TCP timestamps", "info",
                           "Не удалось узнать, включены ли они. Часть стратегий (fooling=ts) без них не работает — "
                           "можно включить на всякий случай.", ("tcp_timestamps", "Включить")))
    else:
        items.append(_item("tcp_ts", "TCP timestamps", "warn",
                           "Выключены — часть стратегий (fooling=ts) без них не работает.",
                           ("tcp_timestamps", "Включить")))

    # Известные конфликтующие программы
    if _process_running("AdguardSvc.exe"):
        items.append(_item("adguard", "Adguard", "error",
                           "Запущен Adguard — он мешает Discord при работающем zapret."))
    killer = has_service(r"Killer")
    if killer:
        items.append(_item("killer", "Killer Networking", "error",
                           f"Найдены службы Killer ({', '.join(killer[:3])}) — они конфликтуют с zapret."))
    intel = [n for n, d, _s in active
             if all(re.search(word, f"{n} {d}", re.I) for word in ("Intel", "Connectivity", "Network"))]
    if intel:
        items.append(_item("intel", "Intel Connectivity Network Service", "error",
                           "Служба Intel Connectivity конфликтует с zapret — отключите её."))
    if has_service(r"^TracSrvWrapper$|^EPWD$"):
        items.append(_item("checkpoint", "Check Point", "error",
                           "Найден Check Point — он конфликтует с zapret, попробуйте его удалить."))
    if has_service(r"SmartByte"):
        items.append(_item("smartbyte", "SmartByte", "error",
                           "Найден SmartByte — отключите его в services.msc или удалите."))

    # VPN — по адаптерам и системному прокси: по именам служб не угадать (Radmin VPN — не VPN в
    # интернет, а у Incy и Happ слова «VPN» в названии нет). Только сообщаем.
    items.append(_vpn_item(own, compat, overrides))

    # Безопасный DNS
    if doh_configured():
        items.append(_item("doh", "Безопасный DNS", "ok", "Настроен DNS через HTTPS"))
    else:
        items.append(_item("doh", "Безопасный DNS", "info",
                           "Включите «безопасный DNS» в браузере или в параметрах Windows 11 — "
                           "иначе провайдер может подменять адреса сайтов."))

    # hosts
    from .hosts import hosts_path
    hosts = hosts_path()
    try:
        content = hosts.read_text(encoding="utf-8", errors="replace").lower()
        active = "\n".join(ln for ln in content.splitlines() if ln.strip() and not ln.strip().startswith("#"))
        if "youtube.com" in active or "youtu.be" in active:
            items.append(_item("hosts_yt", "Файл hosts", "warn",
                               "В hosts есть записи для youtube.com или youtu.be — они могут ломать YouTube."))
    except OSError:
        pass

    # Пакет и драйвер
    if pack_dir is not None:
        sys_file = pack_dir / "bin" / "WinDivert64.sys"
        if not sys_file.is_file():
            items.append(_item("windivert_sys", "Драйвер WinDivert", "error",
                               "Файла WinDivert64.sys нет — скорее всего, его удалил антивирус. "
                               "Добавьте папку данных Лазейки в исключения и переустановите пакет."))
        if paths.has_non_ascii(pack_dir):
            items.append(_item("path", "Путь к пакету", "warn",
                               "В пути к пакету есть кириллица — это может мешать winws."))

    states = netcfg.windivert_states()
    loaded = any(s in ("running", "stop_pending") for s in states.values())
    if loaded and not zapret_running and not foreign_winws(set()):
        driver = netcfg.windivert_driver_path()
        if netcfg.windivert_from_zapret():
            items.append(_item("windivert_stale", "WinDivert", "warn",
                               f"Драйвер WinDivert остался загруженным от zapret ({driver.parent.parent}), "
                               "хотя winws не работает. Если обход не запускается — выгрузите его.",
                               ("windivert_cleanup", "Выгрузить драйвер")))
        else:
            # Драйвер чужой программы (VPN, ускоритель игр) — только сообщаем.
            items.append(_item("windivert_foreign", "WinDivert", "info",
                               f"WinDivert использует другая программа ({driver or 'путь неизвестен'}). "
                               "Лазейка его не трогает; если обход не запускается — закройте ту программу."))
    else:
        items.append(_item("windivert", "WinDivert", "ok", "Конфликтов драйвера нет"))

    conflicts = [n for n in CONFLICT_SERVICES if winutil.service_query(n) is not None]
    for name in conflicts:
        text = ("Служба оригинального zapret — она конфликтует с Лазейкой." if name == "zapret"
                else f"Служба {name} — другой обход блокировок, конфликтует с zapret.")
        items.append(_item(f"service_{name}", f"Служба {name}", "error", text,
                           (f"remove_service:{name}", "Удалить службу")))
    if not conflicts:
        items.append(_item("conflicts", "Другие обходы", "ok", "Конфликтующих служб нет"))
    return items


def _vpn_item(own=None, compat: bool | None = None, overrides: dict | None = None) -> dict:
    from .. import vpn
    try:
        snap = vpn.scan(overrides, own=own)
    except Exception:  # noqa: BLE001
        log.debug("VPN не проверен", exc_info=True)
        return _item("vpn", "VPN", "info", "Не удалось проверить сетевые адаптеры.")
    return _item("vpn", "VPN", *vpn_verdict(snap, compat))


def vpn_verdict(snap, compat: bool | None) -> tuple[str, str]:
    """(уровень, текст) пункта «VPN»: что обход делает с ним при нынешней «Совместимости с VPN». Выключена —
    обход перехватывает и туннели, и виртуальные сети (Radmin VPN), так что «не трогает» было бы неправдой."""
    if snap.foreign_active:
        if compat is False:
            effect = " «Совместимость с VPN» выключена — обход может мешать VPN."
        elif not snap.foreign_internet:
            effect = (" Соединение VPN с сервером обход не трогает." if compat and snap.foreign_servers else
                      " Сервер VPN определить не удалось — обход может задевать соединение с ним." if compat else "")
        else:
            effect = (" «Совместимость с VPN» включена — обход не трогает его туннель." if compat else
                      " При включённой «Совместимости с VPN» обход его туннель не трогает.")
        if snap.foreign_internet:
            how = "весь трафик" if snap.full_tunnel else "часть трафика"
            head = f"Работает {snap.foreign_label} ({how})."
        else:
            head = (f"Работает {snap.foreign_label} через системный прокси: браузер и программы, которые его "
                    "слушают, идут через VPN.")
        return "info", head + effect + " Что куда идёт — на странице «Обход»."
    if snap.own_active:
        return "ok", "Работает свой VPN Лазейки — обход не трогает ни его туннель, ни соединение с сервером."
    lan = [a.app or a.name for a in snap.tunnels if a.role == "lan"]
    if lan:
        names = ", ".join(lan[:3])
        if compat is False:
            return "info", (f"VPN в интернет не работает. Виртуальные сети ({names}) обход перехватывает, пока "
                            "«Совместимость с VPN» выключена.")
        if compat:
            return "ok", f"VPN в интернет не работает. Виртуальные сети ({names}) обход не трогает."
        return "ok", (f"VPN в интернет не работает. Виртуальные сети ({names}) обход не трогает при включённой "
                      "«Совместимости с VPN».")
    return "ok", "VPN не обнаружен"


def doh_configured() -> bool:
    """Есть ли где-нибудь под InterfaceSpecificParameters значение DohFlags > 0."""
    base = r"SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base) as root:
            return _has_doh_flags(root, depth=0)
    except OSError:
        return False


def _has_doh_flags(key, depth: int) -> bool:
    try:
        if int(winreg.QueryValueEx(key, "DohFlags")[0]) > 0:
            return True
    except (OSError, ValueError, TypeError):
        pass
    if depth >= 6:
        return False
    for i in range(4096):
        try:
            name = winreg.EnumKey(key, i)
        except OSError:
            break
        try:
            with winreg.OpenKey(key, name) as sub:
                if _has_doh_flags(sub, depth + 1):
                    return True
        except OSError:
            continue
    return False


def apply_fix(fix_id: str) -> str:
    if fix_id == "tcp_timestamps":
        if netcfg.enable_tcp_timestamps():
            return "TCP timestamps включены"
        raise RuntimeError("Не удалось включить TCP timestamps")
    if fix_id == "windivert_cleanup":
        removed = netcfg.remove_windivert()
        return "Драйвер WinDivert выгружен" if removed else "WinDivert не найден"
    if fix_id.startswith("remove_service:"):
        name = fix_id.split(":", 1)[1]
        if name not in CONFLICT_SERVICES:
            raise RuntimeError("Неизвестная служба")
        winutil.service_delete(name)
        if not foreign_winws(set()):
            netcfg.remove_windivert()
        return f"Служба {name} удалена"
    raise RuntimeError("Неизвестное исправление")


def _is_link(path: Path) -> bool:
    """Символическая ссылка или junction: через них удаление ушло бы в чужую папку."""
    try:
        attrs = os.lstat(path).st_file_attributes
    except OSError:
        return False
    return bool(attrs & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def clear_discord_cache() -> list[str]:
    """Закрывает Discord и удаляет его кэши (Cache, Code Cache, GPUCache)."""
    appdata = os.environ.get("APPDATA")
    report: list[str] = []
    if not appdata:
        return ["Не найдена папка AppData"]
    found = False
    for folder, exe, title in DISCORD_FLAVOURS:
        base = Path(appdata) / folder
        if not base.is_dir() or _is_link(base) or _is_link(Path(appdata)):
            continue
        found = True
        procs = [p for p in psutil.process_iter(["name"]) if (p.info["name"] or "").lower() == exe.lower()]
        for p in procs:
            try:
                p.kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        if procs:
            psutil.wait_procs(procs, timeout=5)
            time.sleep(0.5)
            report.append(f"{title} закрыт")
        for cache in ("Cache", "Code Cache", "GPUCache"):
            target = base / cache
            if target.is_dir() and not _is_link(target):
                shutil.rmtree(target, ignore_errors=True)
                report.append(f"{title}: {'не удалось удалить' if target.exists() else 'очищен'} «{cache}»")
    if not found:
        report.append("Discord не найден")
    return report
