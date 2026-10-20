"""Сторонние компоненты Lazeyka.exe и тексты их лицензий — по тому, что реально попало в сборку.

lazeyka.spec передаёт сюда TOC анализа PyInstaller (модули, библиотеки, данные). Каждый файл сборки
сопоставляется с источником: пакет Python — по записи RECORD его dist-info, CPython — по папке
интерпретатора, библиотеки Microsoft — по имени. Тексты лицензий берутся из dist-info (и из build/licenses
для того, чего там нет) и кладутся в exe папкой licenses/ с оглавлением README.txt.

Сборка останавливается, если файл не удалось отнести ни к одному компоненту, если у компонента нет текста
лицензии или если компонент не назван в THIRD_PARTY.md: новая зависимость не уйдёт в exe молча.
"""
from __future__ import annotations

import importlib.metadata as metadata
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
VENDORED = HERE / "licenses"
BUNDLE_DIR = "licenses"
INDEX_NAME = "README.txt"
_LICENSE_FILE = re.compile(r"^(LICEN[CS]E|COPYING|NOTICE|AUTHORS)", re.I)
_MICROSOFT_RUNTIME = re.compile(r"^(vcruntime140(_1)?|msvcp140(_\d)?|ucrtbase|api-ms-win-[a-z0-9-]+)\.dll$", re.I)


@dataclass
class Component:
    folder: str              # папка в licenses/
    listed_as: str           # так компонент назван в THIRD_PARTY.md
    title: str
    version: str
    license: str
    files: list[Path] = field(default_factory=list)


# Не из dist-info: папка → (как назван в THIRD_PARTY.md, название, лицензия, тексты).
NATIVE = {
    "cpython": ("CPython", "CPython", "PSF-2.0", [Path(sys.base_prefix) / "LICENSE.txt"]),
    "openssl": ("OpenSSL", "OpenSSL", "Apache-2.0", [VENDORED / "openssl-LICENSE.txt"]),
    "libffi": ("libffi", "libffi", "MIT", [VENDORED / "libffi-LICENSE.txt"]),
    "expat": ("Expat", "Expat", "MIT", [VENDORED / "expat-COPYING.txt"]),
    "mpdecimal": ("libmpdec", "libmpdec (mpdecimal)", "BSD-2-Clause", [VENDORED / "mpdecimal-LICENSE.txt"]),
    "xz": ("XZ Utils", "liblzma (XZ Utils)", "0BSD", [VENDORED / "xz-COPYING.0BSD.txt"]),
    "zlib": ("zlib", "zlib", "Zlib", [VENDORED / "zlib-LICENSE.txt"]),
    "microsoft-runtime": ("Visual C++ Runtime", "Microsoft Visual C++ Runtime и Universal C Runtime",
                          "распространяемый код Microsoft", [VENDORED / "microsoft-runtime.txt"]),
    "zapret-discord-youtube": ("zapret-discord-youtube", "zapret-discord-youtube (стратегии, списки)", "MIT",
                               [VENDORED / "zapret-discord-youtube-LICENSE.txt"]),
    "zapret": ("zapret", "zapret / winws", "MIT", [VENDORED / "zapret-LICENSE.txt"]),
    "windivert": ("WinDivert", "WinDivert", "LGPL-3.0 или GPL-2.0", [VENDORED / "windivert-LICENSE.txt"]),
    "tg-ws-proxy": ("tg-ws-proxy", "tg-ws-proxy", "MIT", [ROOT / "app" / "vendor" / "tgws_proxy" / "LICENSE"]),
    "twemoji-country-flags": ("Twemoji Country Flags", "Twemoji Country Flags (шрифт флагов)", "CC-BY-4.0, MIT",
                              [ROOT / "app" / "ui" / "fonts" / "TwemojiCountryFlags-LICENSE.md"]),
}
# Чужое, что лежит в дереве проекта: начало пути от корня проекта → компоненты.
PROJECT_PARTS = {
    "vendor/zapret/": ("zapret-discord-youtube", "zapret", "windivert"),
    "app/vendor/tgws_proxy/": ("tg-ws-proxy",),
    "app/ui/fonts/TwemojiCountryFlags": ("twemoji-country-flags",),
}
# Библиотеки внутри CPython со своей лицензией: файл сборки → компоненты.
CPYTHON_PARTS = {
    "libcrypto-3-x64.dll": ("openssl",), "libssl-3-x64.dll": ("openssl",), "_ssl.pyd": ("openssl",),
    "_hashlib.pyd": ("openssl",), "libffi-8.dll": ("libffi",), "_ctypes.pyd": ("libffi",),
    "pyexpat.pyd": ("expat",), "_elementtree.pyd": ("expat",), "_decimal.pyd": ("mpdecimal",),
    "_lzma.pyd": ("xz",), "python311.dll": ("zlib",),
}
# Название лицензии там, где метаданные пакета его не дают или дают расплывчато («BSD License»).
LICENSE_NAMES = {
    "pyinstaller": "GPL-2.0-or-later с исключением для загрузчика",
    "pyinstaller-hooks-contrib": "Apache-2.0 (runtime-хуки), GPL-2.0-or-later",
    "clr-loader": "MIT", "colorama": "BSD-3-Clause", "hyperframe": "MIT", "pystray": "LGPL-3.0",
    "pywebview": "BSD-3-Clause", "qrcode": "BSD-3-Clause",
}
# Тексты сверх dist-info: у пакета их нет или он несёт чужой код.
EXTRA = {
    "proxy-tools": [VENDORED / "proxy_tools-LICENSE.txt"],
    "pywebview": [VENDORED / "webview2-sdk-LICENSE.txt"],       # DLL Microsoft Edge WebView2 SDK в пакете
}


class LicenseError(Exception):
    pass


def normalized(name: str) -> str:
    """Имя пакета по PEP 503: регистр и разделители -_. не важны."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _key(path: str | Path) -> str:
    return os.path.normcase(os.path.realpath(path))


def _owners() -> dict[str, metadata.Distribution]:
    """Файл → установленный пакет, по RECORD каждого dist-info."""
    owners = {}
    for dist in metadata.distributions():
        for item in dist.files or ():
            owners[_key(dist.locate_file(item))] = dist
    return owners


def _dist_license(dist: metadata.Distribution) -> str:
    meta = dist.metadata
    text = meta.get("License-Expression") or (meta.get("License") or "").strip()
    if text and "\n" not in text and len(text) <= 60:
        return text
    classifiers = [c.rsplit(" :: ", 1)[-1] for c in meta.get_all("Classifier") or () if c.startswith("License ::")]
    return ", ".join(classifiers) or "см. текст"


def _dist_files(dist: metadata.Distribution) -> list[Path]:
    """Тексты лицензий из dist-info; одноимённые (LICENSE в корне и в licenses/) — один раз."""
    files: dict[str, Path] = {}
    for item in dist.files or ():
        path = Path(str(item))
        if path.parts and path.parts[0].endswith(".dist-info") and _LICENSE_FILE.match(path.name):
            files.setdefault(path.name.lower(), Path(dist.locate_file(item)))
    return list(files.values())


def _from_dist(dist: metadata.Distribution) -> Component:
    name = dist.metadata["Name"]
    key = normalized(name)
    return Component(key, key, name, dist.version, LICENSE_NAMES.get(key) or _dist_license(dist),
                     _dist_files(dist) + EXTRA.get(key, []))


def _native(folder: str) -> Component:
    listed_as, title, license_name, files = NATIVE[folder]
    version = sys.version.split()[0] if folder == "cpython" else ""
    return Component(folder, listed_as, title, version, license_name, list(files))


def components(entries: Iterable[tuple], project_root: Path, work_dir: Path) -> list[Component]:
    """Компоненты сборки по её TOC: (имя в сборке, исходный файл, тип) — как в Analysis.pure/binaries/datas.
    Загрузчик PyInstaller в TOC не виден, но есть в каждом exe — он в списке всегда. В work_dir PyInstaller
    кладёт то, что собрал сам: base_library.zip — стандартная библиотека CPython, остальное — его загрузчик."""
    owners = _owners()
    base, venv, project = _key(sys.base_prefix), _key(sys.prefix), _key(project_root)
    generated = _key(work_dir)
    found = {"pyinstaller": _from_dist(metadata.distribution("pyinstaller"))}
    unknown = []
    for dest, src, _kind in entries:
        if not src:
            continue
        path, name = _key(src), Path(dest).name.lower()
        dist = owners.get(path)
        if dist is not None:
            component = _from_dist(dist)
            found.setdefault(component.folder, component)
        elif path.startswith(generated + os.sep):
            if name == "base_library.zip":
                found.setdefault("cpython", _native("cpython"))
        elif venv != base and path.startswith(venv + os.sep):
            unknown.append(f"{dest} ← {src} (в окружении, но не в RECORD ни одного пакета)")
        elif path.startswith(project + os.sep):     # своё (MIT), кроме чужих частей из PROJECT_PARTS
            rel = Path(path).relative_to(project).as_posix().lower()
            for prefix, folders in PROJECT_PARTS.items():
                if rel.startswith(prefix.lower()):
                    for folder in folders:
                        found.setdefault(folder, _native(folder))
        elif path.startswith(base + os.sep):
            for folder in ("cpython", *CPYTHON_PARTS.get(name, ())):
                found.setdefault(folder, _native(folder))
        elif _MICROSOFT_RUNTIME.match(name):
            found.setdefault("microsoft-runtime", _native("microsoft-runtime"))
        else:
            unknown.append(f"{dest} ← {src}")
    if unknown:
        raise LicenseError("Файлы сборки не отнесены ни к одному компоненту (опишите их в build/third_party.py "
                           f"и THIRD_PARTY.md): {'; '.join(unknown[:10])}")
    return sorted(found.values(), key=lambda c: c.folder)


def check(found: list[Component], third_party_md: Path) -> None:
    """У каждого компонента есть текст лицензии, и каждый назван в THIRD_PARTY.md."""
    without_text = [c.title for c in found if not c.files or not all(f.is_file() for f in c.files)]
    if without_text:
        raise LicenseError("Нет текста лицензии у компонентов сборки: " + ", ".join(without_text))
    listed = normalized(third_party_md.read_text(encoding="utf-8"))
    unlisted = [c.listed_as for c in found
                if not re.search(rf"(?<![a-z0-9]){re.escape(normalized(c.listed_as))}(?![a-z0-9])", listed)]
    if unlisted:
        raise LicenseError(f"Компоненты сборки не названы в {third_party_md.name}: " + ", ".join(unlisted))


def index_text(found: list[Component]) -> str:
    lines = ["Сторонние компоненты Lazeyka.exe и тексты их лицензий (папка licenses внутри exe).",
             "Список составлен при сборке по тому, что попало в exe; подробнее — THIRD_PARTY.md.", ""]
    for c in found:
        version = f" {c.version}" if c.version else ""
        files = ", ".join(f"{c.folder}/{f.name}" for f in c.files)
        lines.append(f"{c.title}{version} — {c.license}: {files}")
    return "\n".join(lines) + "\n"


def license_datas(entries: Iterable[tuple], *, project_root: Path, third_party_md: Path,
                  work_dir: Path) -> list[tuple[str, str, str]]:
    """Записи DATA для Analysis.datas: licenses/<компонент>/<файл> и оглавление licenses/README.txt."""
    found = components(entries, project_root, work_dir)
    check(found, third_party_md)
    work_dir.mkdir(parents=True, exist_ok=True)
    index = work_dir / f"licenses-{INDEX_NAME}"
    index.write_text(index_text(found), encoding="utf-8")
    datas = [(os.path.join(BUNDLE_DIR, INDEX_NAME), str(index), "DATA")]
    for c in found:
        datas += [(os.path.join(BUNDLE_DIR, c.folder, f.name), str(f), "DATA") for f in c.files]
    return datas
