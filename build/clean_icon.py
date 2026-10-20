"""Черновик значка (icon-v2.png в папке черновиков) → assets/icon-master.png: без белого фона, в цветах плитки.

    clean_icon.py <папка-черновиков> <результат.png>

Как получен черновик — docs/art/icon.md.
"""
import sys
from PIL import Image, ImageDraw, ImageFilter
art, out = sys.argv[1], sys.argv[2]
src = Image.open(f"{art}/icon-v2.png").convert("RGB")
W, H = src.size
light = src.convert("L").point(lambda v: 255 if v > 200 else 0)
for corner in ((0, 0), (W - 1, 0), (0, H - 1), (W - 1, H - 1)):
    if light.getpixel(corner) == 255:
        ImageDraw.floodfill(light, corner, 128)
bg = light.point(lambda v: 255 if v == 128 else 0)
near_edge = bg.filter(ImageFilter.MaxFilter(17))          # полоса ~8 px вокруг фона
TILE = (35, 37, 41); WALL = (125, 129, 138); ARROW = (242, 243, 245)
pal = (TILE, WALL, ARROW)
out_px = []
for (r, g, b), m, e in zip(src.getdata(), bg.getdata(), near_edge.getdata()):
    if m:
        out_px.append(TILE + (0,))
    elif e:
        out_px.append(TILE + (255,))
    else:
        i = min(range(3), key=lambda k: (r - pal[k][0]) ** 2 + (g - pal[k][1]) ** 2 + (b - pal[k][2]) ** 2)
        out_px.append(pal[i] + (255,))
img = Image.new("RGBA", (W, H)); img.putdata(out_px)
l, t, r, b = bg.point(lambda v: 0 if v else 255).getbbox()
side = max(r - l, b - t); cx = (l + r) // 2; cy = (t + b) // 2
img.crop((cx - side // 2, cy - side // 2, cx + side // 2, cy + side // 2)).save(out)
print("ok", side)
