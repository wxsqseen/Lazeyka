"""Иллюстрация Codex → прозрачный PNG в двух цветах палитры Лазейки (серый и акцент), со сглаживанием.

Фон белый: покрытие пикселя считается по отклонению от белого вдоль канала с наибольшим контрастом
для его краски — так мягкие края остаются мягкими и на тёмной, и на светлой теме.

    clean_codex_art.py <черновик.png> <результат.png> [--box X0,Y0,X1,Y1] [--width 640]

Без --box поля обрезаются по рисунку (как у vpn-empty.png). С --box вырезается одна и та же область
черновика: так у семьи картинок одного состояния (vpn-off, vpn-connect, vpn-error) одинаковые
размеры и масштаб, и ноутбук со стеной не прыгают при смене состояния.
"""
import argparse

from PIL import Image

GREY = (125, 129, 138)     # #7D818A
BLUE = (91, 141, 239)      # #5B8DEF
MIN_COVERAGE = 0.06        # слабее — шум генератора на белом фоне
PAD_X, PAD_Y = 0.06, 0.10  # поля вокруг рисунка без --box, доля его ширины и высоты


def parse_box(text: str) -> tuple[int, int, int, int]:
    parts = [int(part) for part in text.split(",")]
    if len(parts) != 4 or parts[0] >= parts[2] or parts[1] >= parts[3]:
        raise argparse.ArgumentTypeError(f"нужно X0,Y0,X1,Y1 с X0 < X1 и Y0 < Y1, получено {text!r}")
    return parts[0], parts[1], parts[2], parts[3]


def two_colour(img: Image.Image) -> Image.Image:
    W, H = img.size
    out = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    src_px = img.load()
    dst_px = out.load()
    for y in range(H):
        for x in range(W):
            r, g, b = src_px[x, y]
            blue = (b - r) > 45 and b > 150
            ink = BLUE if blue else GREY
            # покрытие: по красному каналу у обеих красок наибольший контраст с белым
            a = (255 - r) / (255 - ink[0])
            a = max(0.0, min(1.0, a))
            if a < MIN_COVERAGE:
                continue
            dst_px[x, y] = ink + (round(a * 255),)
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("src")
    parser.add_argument("out")
    parser.add_argument("--box", type=parse_box, help="область черновика X0,Y0,X1,Y1 вместо обрезки по рисунку")
    parser.add_argument("--width", type=int, default=640, help="ширина результата, px")
    args = parser.parse_args()

    img = Image.open(args.src).convert("RGB")
    W, H = img.size
    out = two_colour(img)
    bbox = out.getbbox()
    if bbox is None:
        raise SystemExit(f"{args.src}: на белом фоне не нашлось рисунка")
    if args.box:
        left, top, right, bottom = args.box
        if right > W or bottom > H:
            raise SystemExit(f"--box {args.box} выходит за черновик {W}×{H}")
        if not (left <= bbox[0] and top <= bbox[1] and bbox[2] <= right and bbox[3] <= bottom):
            raise SystemExit(f"--box {args.box} режет рисунок: он занимает {bbox}")
    else:
        left, top, right, bottom = bbox
        pad_x, pad_y = int((right - left) * PAD_X), int((bottom - top) * PAD_Y)
        left, top = max(0, left - pad_x), max(0, top - pad_y)
        right, bottom = min(W, right + pad_x), min(H, bottom + pad_y)
    crop = out.crop((left, top, right, bottom))
    target_h = round(crop.height * args.width / crop.width)
    crop = crop.resize((args.width, target_h), Image.LANCZOS)
    crop.save(args.out, optimize=True)
    print("ok", crop.size)


if __name__ == "__main__":
    main()
