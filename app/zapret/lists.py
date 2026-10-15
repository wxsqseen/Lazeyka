"""Списки доменов и IP: режимы IPSet и пользовательские списки."""
from __future__ import annotations

import os
from pathlib import Path

NONE_MARKER = "203.0.113.113/32"   # адрес из TEST-NET-3: так пакет делает ipset «пустым»
PLACEHOLDER_DOMAIN = "domain.example.abc"

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


def _write_text(path: Path, text: str) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(text.encode("utf-8"))
    os.replace(tmp, path)


def _normalize(text: str) -> str:
    lines = [ln.strip() for ln in text.replace("\r\n", "\n").replace("\r", "\n").split("\n")]
    while lines and not lines[-1]:
        lines.pop()
    return "\r\n".join(lines) + ("\r\n" if lines else "")


def _has_entries(text: str) -> bool:
    return any(ln.strip() and not ln.strip().startswith("#") for ln in text.splitlines())


# ------------------------------------------------------------ пользовательские списки

def ensure_user_lists(user_dir: Path) -> None:
    user_dir.mkdir(parents=True, exist_ok=True)
    for name, (_title, _hint, default) in USER_LISTS.items():
        path = user_dir / name
        if not path.exists():
            _write_text(path, default)


def save_user_list(user_dir: Path, name: str, text: str) -> str:
    """Сохраняет список. Пустой список заменяется заглушкой: пустой файл winws понимает иначе."""
    if name not in USER_LISTS:
        raise ValueError(f"Неизвестный список: {name}")
    normalized = _normalize(text)
    if not _has_entries(normalized):
        normalized = USER_LISTS[name][2]
    user_dir.mkdir(parents=True, exist_ok=True)
    _write_text(user_dir / name, normalized)
    return normalized


MANAGED_HEADER = "# Лазейка: для Telegram-прокси (добавлено автоматически)"


def sync_user_lists(user_dir: Path, lists_dir: Path, extra: dict[str, list[str]] | None = None) -> None:
    """Копирует пользовательские списки в папку lists активного пакета.

    extra — домены, которые Лазейка добавляет сама (например, для Telegram-прокси):
    они дописываются отдельным блоком только в рабочую копию, свои списки не меняются.
    """
    ensure_user_lists(user_dir)
    for name in USER_LISTS:
        src = (user_dir / name).read_bytes()
        added = [d for d in (extra or {}).get(name, []) if d]
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
    normalized = _normalize(text)
    if detect_ipset_mode(lists_dir) == "loaded":
        _write_text(lists_dir / IPSET_FILE, normalized)
    else:
        _write_text(lists_dir / IPSET_BACKUP, normalized)
    return count_entries(normalized)
