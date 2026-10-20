"""Сборка: версия exe совпадает с версией приложения, WebP в сборке есть и читается, самопроверка
получает путь отчёта целиком."""
import re

from app import __version__, paths, selftest

BUILD = paths.resource_dir() / "build"


def _numeric(version: str) -> tuple[int, ...]:
    core = re.split(r"[-+]", version, maxsplit=1)[0]
    numbers = tuple(int(part) for part in core.split("."))
    return numbers + (0,) * (4 - len(numbers))


def test_version_info_matches_app_version():
    """Версия в свойствах exe (build/version_info.txt) — та же, что __version__: иначе Windows и
    самообновление видели бы разные номера."""
    text = (BUILD / "version_info.txt").read_text(encoding="utf-8")
    want = _numeric(__version__)
    for field in ("filevers", "prodvers"):
        found = re.search(rf"{field}=\(([\d, ]+)\)", text)
        assert found and tuple(int(x) for x in found.group(1).split(",")) == want, field
    dotted = ".".join(map(str, want))
    for field in ("FileVersion", "ProductVersion"):
        assert f"StringStruct(u'{field}', u'{dotted}')" in text, field


def test_webp_is_built_in():
    spec = (BUILD / "lazeyka.spec").read_text(encoding="utf-8")
    excludes = re.search(r"excludes=\[(.*?)\]", spec, re.S).group(1)
    assert "PIL._webp" not in excludes and '"PIL._webp"' in spec
    assert selftest.check_webp() == "WebP записывается и читается"


def test_window_engine_files_are_not_filtered_out():
    """1.3.0 не запускалась: сборка вырезала webview/lib/runtimes/win-arm64 и win-x86, а pywebview при загрузке
    окна (platforms/edgechromium.py) ищет папки всех трёх архитектур. Фильтр чужих архитектур их не трогает,
    а самопроверка exe грузит движок окна так же, как main()."""
    import webview.util
    spec = (BUILD / "lazeyka.spec").read_text(encoding="utf-8")
    foreign = re.search(r"_FOREIGN = \((.*?)\)", spec, re.S).group(1).lower()
    for platform in ("win-arm64", "win-x64", "win-x86"):
        assert platform not in foreign, platform
        assert webview.util.interop_dll_path(platform)          # и в исходной раскладке pywebview она есть
    assert "webbrowserinterop" not in foreign
    source = (paths.resource_dir() / "app" / "selftest.py").read_text(encoding="utf-8")
    assert '_check(results, "Окно WebView2", window_engine)' in source and "webview_guard.install()" in source


def test_selftest_report_path_is_quoted():
    script = (BUILD / "build.ps1").read_text(encoding="utf-8-sig")
    assert "-ArgumentList ('--selftest \"{0}\"' -f $report)" in script
