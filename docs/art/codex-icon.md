# Значок: генерация в Codex

Значок нарисован встроенным генератором изображений Codex (CLI из расширения VS Code), выбран вариант 2 из трёх.
Затем `build/clean_codex_icon.py` убирает белый фон, приводит цвета к палитре (#232529, #7D818A, #F2F3F5) и обрезает плитку — результат в `assets/icon-master.png`; из него `app/icons.py` делает ICO и значки трея со статусной точкой.

Команда (из папки черновиков, рядом reference.png — прежний вариант знака):

```
codex exec -s workspace-write --skip-git-repo-check -i reference.png -o result.md - < prompt.md
.venv\Scripts\python.exe build\clean_codex_icon.py <папка-черновиков> assets\icon-master.png
```

## Промпт

```text
Generate app icon artwork with your built-in image generator. Do not write or run any code, do not touch any files except the PNG images you save in the current working directory.

App: "Лазейка" (Lazeyka) — a small Windows utility that lets Discord, YouTube and Telegram work through network blocks. The name means "a small gap / loophole".

The attached reference.png shows the concept: a dark rounded-square tile, a vertical wall broken by a gap in the middle, and an arrow passing through that gap. Keep this concept but make it look like a refined, professionally designed icon.

Style requirements (very important — the owner wants strict minimalism, nothing colourful or flashy):
- Flat, geometric, minimal. No gradients, no shadows, no glow, no texture, no noise, no 3D, no outlines around the tile, no text or letters.
- Monochrome only: tile in near-black graphite (#232529), wall pieces in mid grey (#7D818A), arrow in off-white (#F2F3F5). No other colours.
- Very few shapes, thick strokes, generous negative space, so it stays readable when shrunk to 16×16 pixels in the Windows taskbar tray.
- Rounded square tile (corner radius about 24% of the size) centred on a plain pure white background, the tile filling about 90% of the canvas. Square 1:1 image.

Make 3 variants with small differences in proportions (for example: arrow thickness, wall thickness, size of the gap, arrowhead shape — one variant may use a slightly rounded arrowhead), and save them as icon-v1.png, icon-v2.png and icon-v3.png in the current directory. Then reply with one short sentence per file describing it.
```
