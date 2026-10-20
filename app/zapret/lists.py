"""Списки доменов и IP: режимы IPSet и пользовательские списки."""
from __future__ import annotations

import ipaddress
import os
import re
from pathlib import Path

NONE_MARKER = "203.0.113.113/32"   # адрес из TEST-NET-3: так пакет делает ipset «пустым»
PLACEHOLDER_DOMAIN = "domain.example.abc"
# Radmin VPN (26/8) и Hamachi (25/8) — виртуальные локальные сети, а не интернет: игровой фильтр и IPSet
# «все адреса» трогали бы их трафик. Исключаются по адресу всегда, служебным блоком рабочей копии.
LAN_VPN_NETS = ("25.0.0.0/8", "26.0.0.0/8")

IPSET_FILE = "ipset-all.txt"
IPSET_BACKUP = "ipset-all.txt.backup"
IPSET_MODES = ("none", "loaded", "any")

# Пользовательские списки: имя файла, заголовок, подсказка, содержимое по умолчанию.
USER_LISTS = {
    "list-general-user.txt": (
        "Мои сайты",
        "Домены, которые нужно открывать через обход. По одному на строку, поддомены учитываются.",
        f"# Never leave this file empty\r\n{PLACEHOLDER_DOMAIN}\r\n",
    ),
    "list-exclude-user.txt": (
        "Исключения",
        "Домены, которые обход трогать не должен (например, если сайт сломался после включения).",
        f"{PLACEHOLDER_DOMAIN}\r\n",
    ),
    "ipset-exclude-user.txt": (
        "Исключённые IP",
        "IP-адреса и подсети, которые обход трогать не должен. Пример: 192.168.0.0/16",
        f"{NONE_MARKER}\r\n",
    ),
}

BUILTIN_LISTS = {
    "list-general.txt": ("Встроенные сайты", "Discord, Cloudflare и другие сайты из пакета zapret."),
    "list-google.txt": ("YouTube и Google", "Домены YouTube, которые обрабатываются отдельной стратегией."),
    "list-exclude.txt": ("Встроенные исключения", "Банки, госуслуги и сайты, которые не нужно трогать."),
    "ipset-exclude.txt": ("Локальные сети", "Подсети, которые никогда не обрабатываются."),
}


DOMAIN_LISTS = ("list-general-user.txt", "list-exclude-user.txt")


class ListError(ValueError):
    """В списке есть строки, которых winws не поймёт: текст — какие именно."""


def _write_text(path: Path, text: str) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(text.encode("utf-8"))
    os.replace(tmp, path)


def normalize_text(text: str) -> str:
    """Строки без пробелов по краям, окончания CRLF, без пустого хвоста — так списки лежат в пакете."""
    lines = [ln.strip() for ln in text.replace("\r\n", "\n").replace("\r", "\n").split("\n")]
    while lines and not lines[-1]:
        lines.pop()
    return "\r\n".join(lines) + ("\r\n" if lines else "")


def _has_entries(text: str) -> bool:
    return any(ln.strip() and not ln.strip().startswith("#") for ln in text.splitlines())


_HOST_RE = re.compile(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})")


def clean_domain(text: str) -> str | None:
    """Домен так, как его сопоставляет winws: без схемы, пути, порта и «*.», в нижнем регистре и
    punycode («https://Пример.рф/путь» → «xn--e1afmkfd.xn--p1ai»). «^» в начале (только сам домен,
    без поддоменов) сохраняется. None — не домен."""
    value = (text or "").strip().lower()
    exact = value.startswith("^")
    value = re.sub(r"^[a-z][a-z0-9+.-]*://", "", value.removeprefix("^"))
    value = re.split(r"[/?#]", value, maxsplit=1)[0].rsplit("@", 1)[-1]
    value = re.sub(r":\d*$", "", value).strip(".").removeprefix("*.")
    if not value.isascii():
        try:
            value = value.encode("idna").decode("ascii")
        except UnicodeError:
            return None
    if not _HOST_RE.fullmatch(value):
        return None
    return ("^" if exact else "") + value


def clean_network(text: str) -> str | None:
    """IP-адрес, подсеть или диапазон «адрес-адрес» для ipset winws. None — не адрес."""
    value = (text or "").strip()
    try:
        if "-" in value:
            first, last = (ipaddress.ip_address(part.strip()) for part in value.split("-", 1))
            return f"{first}-{last}" if first.version == last.version and first <= last else None
        network = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None
    return str(network) if "/" in value else str(network.network_address)


def clean_list(name: str, text: str) -> str:
    """Записи списка в виде, понятном winws; комментарии и пустые строки — как были. Непонятные
    строки — ListError с их номерами: молча выброшенный сайт человек искал бы долго."""
    domains = name in DOMAIN_LISTS
    out: list[str] = []
    bad: list[tuple[int, str]] = []
    for number, raw in enumerate(text.replace("\r\n", "\n").replace("\r", "\n").split("\n"), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            out.append(line)
            continue
        cleaned = clean_domain(line) if domains else clean_network(line)
        if cleaned is None:
            bad.append((number, line))
        else:
            out.append(cleaned)
    if bad:
        shown = "; ".join(f"строка {number}: «{line[:60]}»" for number, line in bad[:3])
        more = f" и ещё {len(bad) - 3}" if len(bad) > 3 else ""
        what = "домен" if domains else "IP-адрес, подсеть или диапазон"
        raise ListError(f"Не похоже на {what} — {shown}{more}")
    return "\n".join(out)


# ------------------------------------------------------------ пользовательские списки

def ensure_user_lists(user_dir: Path) -> None:
    user_dir.mkdir(parents=True, exist_ok=True)
    for name, (_title, _hint, default) in USER_LISTS.items():
        path = user_dir / name
        if not path.exists():
            _write_text(path, default)


def save_user_list(user_dir: Path, name: str, text: str, check: bool = True) -> str:
    """Сохраняет список. Пустой список заменяется заглушкой: пустой файл winws понимает иначе.
    check — привести записи к виду winws и отвергнуть непонятные (ListError); перенос из
    оригинального zapret берёт файлы как есть — с ними тот уже работал."""
    if name not in USER_LISTS:
        raise ValueError(f"Неизвестный список: {name}")
    normalized = normalize_text(clean_list(name, text) if check else text)
    if not _has_entries(normalized):
        normalized = USER_LISTS[name][2]
    user_dir.mkdir(parents=True, exist_ok=True)
    _write_text(user_dir / name, normalized)
    return normalized


MANAGED_HEADER = "# Лазейка: добавлено автоматически (Telegram-прокси, сети Radmin VPN и Hamachi)"


def sync_user_lists(user_dir: Path, lists_dir: Path, extra: dict[str, list[str]] | None = None) -> None:
    """Копирует пользовательские списки в папку lists активного пакета.

    extra — домены, которые Лазейка добавляет сама (например, для Telegram-прокси), и всегда —
    сети LAN-VPN в исключённые IP: они дописываются отдельным блоком только в рабочую копию, свои
    списки не меняются. Список без записей (файл опустошили в папке списков) уходит заглушкой.
    """
    ensure_user_lists(user_dir)
    for name, (_title, _hint, default) in USER_LISTS.items():
        src = (user_dir / name).read_bytes()
        if not _has_entries(src.decode("utf-8", errors="replace")):
            src = default.encode("utf-8")
        added = [d for d in (extra or {}).get(name, []) if d]
        if name == "ipset-exclude-user.txt":
            added = [*LAN_VPN_NETS, *(a for a in added if a not in LAN_VPN_NETS)]
        if added:
            body = src.decode("utf-8", errors="replace").rstrip("\r\n")
            src = (body + "\r\n" + MANAGED_HEADER + "\r\n" + "\r\n".join(added) + "\r\n").encode("utf-8")
        dst = lists_dir / name
        if not dst.exists() or dst.read_bytes() != src:
            tmp = dst.with_name(dst.name + ".tmp")
            tmp.write_bytes(src)
            os.replace(tmp, dst)


def adopt_user_lists(user_dir: Path, lists_dir: Path) -> None:
    """Первый запуск: если в пакете уже есть свои *-user.txt, берём их."""
    user_dir.mkdir(parents=True, exist_ok=True)
    for name in USER_LISTS:
        src = lists_dir / name
        dst = user_dir / name
        if src.is_file() and not dst.exists():
            dst.write_bytes(src.read_bytes())


# ------------------------------------------------------------ IPSet

def detect_ipset_mode(lists_dir: Path) -> str:
    path = lists_dir / IPSET_FILE
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return "none"
    if not text.strip():
        return "any"
    if NONE_MARKER in text:
        return "none"
    return "loaded"


def _full_list_path(lists_dir: Path) -> Path:
    return lists_dir / (IPSET_FILE if detect_ipset_mode(lists_dir) == "loaded" else IPSET_BACKUP)


def read_full_ipset(lists_dir: Path) -> str | None:
    path = _full_list_path(lists_dir)
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    return text if _has_entries(text) and NONE_MARKER not in text else None


def count_entries(text: str | None) -> int:
    if not text:
        return 0
    return sum(1 for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#"))


def set_ipset_mode(lists_dir: Path, mode: str) -> None:
    """Переключает режим так же, как service.bat, но без потери полного списка."""
    if mode not in IPSET_MODES:
        raise ValueError(f"Неизвестный режим IPSet: {mode}")
    full = read_full_ipset(lists_dir)
    if mode == "loaded":
        if full is None:
            raise ValueError("Полного списка IP нет — сначала обновите его.")
        _write_text(lists_dir / IPSET_FILE, full)
        return
    if full is not None:
        _write_text(lists_dir / IPSET_BACKUP, full)
    _write_text(lists_dir / IPSET_FILE, f"{NONE_MARKER}\r\n" if mode == "none" else "")


def store_full_ipset(lists_dir: Path, text: str) -> int:
    """Кладёт свежий полный список, не меняя текущий режим."""
    if not _has_entries(text):
        raise ValueError("Скачанный список IP пуст")
    try:
        normalized = normalize_text(clean_list(IPSET_FILE, text))
    except ListError as exc:
        # Страница ошибки или портала вместо списка: winws с ней не запустился бы вовсе.
        raise ValueError(f"Скачанный список IP испорчен: {exc}") from exc
    if detect_ipset_mode(lists_dir) == "loaded":
        _write_text(lists_dir / IPSET_FILE, normalized)
    else:
        _write_text(lists_dir / IPSET_BACKUP, normalized)
    return count_entries(normalized)
