"""Стратегии zapret: разбор general*.bat из пакета Flowseal.

Строку запуска winws не переписываем руками, а читаем из .bat-файлов пакета —
так новые и изменённые стратегии приходят вместе с обновлением пакета.

Разбор повторяет то, что делает cmd.exe с этими файлами: склейка строк по `^`,
подстановка переменных, снятие экранирования `^` вне кавычек. Затем строка
делится на аргументы по правилам разбора командной строки программ Windows.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from ..errors import UserError

DUMMY_PORT = "12"  # так пакет «выключает» игровой фильтр: порт, который никто не слушает

_VAR = re.compile(r"%(~dp0|[A-Za-z_][A-Za-z0-9_]*)%")
_KNOWN_VARS = {"BIN", "LISTS", "~dp0", "GameFilter", "GameFilterTCP", "GameFilterUDP"}


class StrategyError(UserError, ValueError):
    pass


@dataclass
class Strategy:
    id: str                 # имя файла без .bat — так стратегию называет и сам пакет
    label: str
    file: Path
    raw: str                # хвост строки запуска после winws.exe, с переменными
    unknown_vars: list[str] = field(default_factory=list)

    @property
    def usable(self) -> bool:
        return not self.unknown_vars

    def args(self, pack_dir: Path, game_tcp: str = DUMMY_PORT, game_udp: str = DUMMY_PORT,
             game_any: str | None = None) -> list[str]:
        if self.unknown_vars:
            raise StrategyError(f"Стратегия «{self.id}» использует неизвестные переменные: "
                                + ", ".join(self.unknown_vars))
        values = {
            "~dp0": str(pack_dir) + "\\",
            "BIN": str(pack_dir / "bin") + "\\",
            "LISTS": str(pack_dir / "lists") + "\\",
            "GameFilter": game_any if game_any is not None else game_tcp,
            "GameFilterTCP": game_tcp,
            "GameFilterUDP": game_udp,
        }
        expanded = expand_vars(self.raw, values)
        return split_args(unescape_carets(expanded))


def label_for(stem: str) -> str:
    if stem.lower() == "general":
        return "Стандартная"
    m = re.fullmatch(r"general\s*\((.+)\)", stem, flags=re.IGNORECASE)
    return m.group(1).strip() if m else stem


def natural_key(name: str) -> str:
    """Сортировка как в service.bat: числа дополняются нулями до 8 знаков."""
    return re.sub(r"\d+", lambda m: m.group(0).rjust(8, "0"), name.lower())


def join_continuations(text: str) -> list[str]:
    """Склеивает строки, оканчивающиеся на `^` (перенос строки в cmd)."""
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    logical: list[str] = []
    buf = ""
    for line in lines:
        if line.endswith("^") and not line.endswith("^^"):
            buf += line[:-1]
            continue
        logical.append(buf + line)
        buf = ""
    if buf:
        logical.append(buf)
    return logical


def find_winws_tail(text: str) -> str:
    for line in join_continuations(text):
        stripped = line.strip()
        if stripped.startswith("::") or stripped.lower().startswith("rem "):
            continue
        idx = line.lower().find("winws.exe")
        if idx < 0:
            continue
        tail = line[idx + len("winws.exe"):]
        if tail.startswith('"'):
            tail = tail[1:]
        return tail.strip()
    raise StrategyError("в файле нет строки запуска winws.exe")


def expand_vars(text: str, values: dict[str, str]) -> str:
    out = text.replace("%%", "\x00")
    out = _VAR.sub(lambda m: values.get(m.group(1), m.group(0)), out)
    return out.replace("\x00", "%")


def unescape_carets(text: str) -> str:
    """`^x` → `x` вне кавычек, как это делает cmd при разборе строки."""
    out = []
    in_quotes = False
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == '"':
            in_quotes = not in_quotes
            out.append(ch)
        elif ch == "^" and not in_quotes and i + 1 < len(text):
            i += 1
            out.append(text[i])
        else:
            out.append(ch)
        i += 1
    return "".join(out)


def split_args(cmdline: str) -> list[str]:
    """Делит строку на аргументы по правилам CommandLineToArgvW."""
    args: list[str] = []
    cur: list[str] = []
    in_quotes = False
    have_token = False
    i = 0
    n = len(cmdline)
    while i < n:
        ch = cmdline[i]
        if ch == "\\":
            j = i
            while j < n and cmdline[j] == "\\":
                j += 1
            count = j - i
            if j < n and cmdline[j] == '"':
                cur.append("\\" * (count // 2))
                if count % 2:
                    cur.append('"')
                    i = j + 1
                else:
                    i = j
                have_token = True
                continue
            cur.append("\\" * count)
            have_token = True
            i = j
            continue
        if ch == '"':
            if in_quotes and i + 1 < n and cmdline[i + 1] == '"':
                cur.append('"')
                i += 2
                continue
            in_quotes = not in_quotes
            have_token = True
            i += 1
            continue
        if ch in " \t" and not in_quotes:
            if have_token:
                args.append("".join(cur))
                cur = []
                have_token = False
            i += 1
            continue
        cur.append(ch)
        have_token = True
        i += 1
    if have_token:
        args.append("".join(cur))
    return args


_NEEDS_QUOTES = re.compile(r'[\s"*?\[\]{}\'~]')


def quote_arg(arg: str) -> str:
    """Кавычки для программ на cygwin (winws): иначе он раскрыл бы `*` и `?` как маски файлов."""
    if arg and not _NEEDS_QUOTES.search(arg):
        return arg
    out = ['"']
    backslashes = 0
    for ch in arg:
        if ch == "\\":
            backslashes += 1
            continue
        if ch == '"':
            out.append("\\" * (backslashes * 2 + 1))
            out.append('"')
        else:
            out.append("\\" * backslashes)
            out.append(ch)
        backslashes = 0
    out.append("\\" * (backslashes * 2))
    out.append('"')
    return "".join(out)


def command_line(exe: Path, args: list[str]) -> str:
    return " ".join([quote_arg(str(exe))] + [quote_arg(a) for a in args])


def parse_file(path: Path) -> Strategy:
    data = path.read_bytes()
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = data.decode("cp866", errors="replace")
    raw = find_winws_tail(text)
    unknown = sorted({m.group(1) for m in _VAR.finditer(raw.replace("%%", ""))} - _KNOWN_VARS)
    return Strategy(id=path.stem, label=label_for(path.stem), file=path, raw=raw, unknown_vars=unknown)


def discover(pack_dir: Path) -> tuple[list[Strategy], list[str]]:
    """Все стратегии пакета и список ошибок разбора (по одной на файл)."""
    strategies: list[Strategy] = []
    errors: list[str] = []
    if not pack_dir.is_dir():
        return strategies, [f"Нет папки пакета: {pack_dir}"]
    files = [p for p in pack_dir.glob("*.bat") if not p.name.lower().startswith("service")]
    # Скобки убираем из ключа, чтобы «FAKE TLS AUTO» шла раньше «FAKE TLS AUTO ALT».
    for path in sorted(files, key=lambda p: natural_key(re.sub(r"[()]", "", p.stem))):
        try:
            strategies.append(parse_file(path))
        except (OSError, StrategyError) as exc:
            errors.append(f"{path.name}: {exc}")
    return strategies, errors


def referenced_files(args: list[str]) -> list[Path]:
    """Файлы, на которые ссылаются аргументы (для проверки целостности пакета)."""
    files: list[Path] = []
    for arg in args:
        if "=" not in arg:
            continue
        value = arg.split("=", 1)[1]
        if value.startswith("@"):
            value = value[1:]
        if re.match(r"^[A-Za-z]:\\", value):
            files.append(Path(value))
    return files
