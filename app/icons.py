"""Значок приложения для трея, окна и exe.

Основа — `assets/icon-master.png`: рисунок, сгенерированный Codex (минималистичный
знак «стрелка проходит в проём стены»), очищенный от фона и приведённый к палитре.
Если файла нет, тот же знак рисуется кодом. Точка статуса в трее рисуется поверх.
"""
from __future__ import annotations

import functools

from PIL import Image, ImageDraw

from . import paths

TILE = (35, 37, 41, 255)        # #232529
WALL = (125, 129, 138, 255)     # #7D818A
ARROW = (242, 243, 245, 255)    # #F2F3F5
RING = (17, 18, 20, 255)
STATUS_COLORS = {
    "on": (76, 175, 122),       # спокойный зелёный
    "partial": (201, 151, 58),  # приглушённый янтарный
    "error": (209, 96, 96),     # приглушённый красный
    "off": (138, 142, 150),     # серый
}


@functools.lru_cache(maxsize=1)
def _master() -> Image.Image | None:
    try:
        return Image.open(paths.resource_dir() / "assets" / "icon-master.png").convert("RGBA")
    except OSError:
        return None


def _vector(s: int) -> Image.Image:
    mask = Image.new("L", (s, s), 0)
    ImageDraw.Draw(mask).rounded_rectangle([0, 0, s - 1, s - 1], radius=int(s * 0.24), fill=255)
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    img.paste(Image.new("RGBA", (s, s), TILE), (0, 0), mask)
    d = ImageDraw.Draw(img)
    y = s // 2
    wall_w, wall_x, gap = int(s * 0.085), int(s * 0.40), int(s * 0.13)
    d.rounded_rectangle([wall_x, int(s * 0.16), wall_x + wall_w, y - gap], radius=wall_w // 2, fill=WALL)
    d.rounded_rectangle([wall_x, y + gap, wall_x + wall_w, int(s * 0.84)], radius=wall_w // 2, fill=WALL)
    shaft, tip = int(s * 0.09), int(s * 0.84)
    d.rounded_rectangle([int(s * 0.16), y - shaft // 2, tip - int(s * 0.12), y + shaft // 2],
                        radius=shaft // 2, fill=ARROW)
    head = int(s * 0.15)
    base = tip - head - int(s * 0.02)
    d.polygon([(tip, y), (base, y - head), (base, y + head)], fill=ARROW)
    return img


def draw(size: int = 256, status: str | None = None) -> Image.Image:
    s = size * 4
    master = _master()
    img = master.resize((s, s), Image.LANCZOS) if master is not None else _vector(s)
    if status in STATUS_COLORS:
        dot = Image.new("RGBA", (s, s), (0, 0, 0, 0))
        d = ImageDraw.Draw(dot)
        r = int(s * 0.17)
        ring = int(s * 0.05)
        c = s - r - ring
        d.ellipse([c - r - ring, c - r - ring, c + r + ring, c + r + ring], fill=RING)
        d.ellipse([c - r, c - r, c + r, c + r], fill=STATUS_COLORS[status] + (255,))
        img = Image.alpha_composite(img, dot)
    return img.resize((size, size), Image.LANCZOS)


def save_ico(path) -> None:
    sizes = [16, 20, 24, 32, 40, 48, 64, 128, 256]
    images = [draw(n) for n in sizes]
    images[-1].save(path, format="ICO", sizes=[(n, n) for n in sizes], append_images=images[:-1])
