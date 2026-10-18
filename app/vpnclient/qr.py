"""QR для явного обмена ссылками: генерация, файл или снимок экрана."""
from __future__ import annotations

import base64
import io
import warnings
from pathlib import Path

import qrcode
import zxingcpp
from PIL import Image, ImageGrab, UnidentifiedImageError
from qrcode.exceptions import DataOverflowError

from ..errors import UserError

MAX_TEXT_BYTES = 2900
MAX_PIXELS = 40_000_000
_EXTENSIONS = {".png", ".jpg", ".jpeg", ".bmp", ".gif", ".webp"}
_FORMATS = {"PNG", "JPEG", "BMP", "GIF", "WEBP"}


class QrError(UserError):
    pass


def png_data_url(text: str, *, box: int = 8) -> str:
    try:
        payload = text.encode("utf-8")
    except (AttributeError, UnicodeError) as exc:
        raise QrError("Не удалось прочитать текст для QR-кода") from exc
    if not payload:
        raise QrError("Нет текста для QR-кода")
    if len(payload) > MAX_TEXT_BYTES:
        raise QrError("Ссылка слишком длинная для QR-кода (не больше 2900 байт)")
    if type(box) is not int or not 1 <= box <= 16:
        raise QrError("Размер точки QR-кода должен быть от 1 до 16")
    code = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=box, border=4)
    code.add_data(payload)
    try:
        code.make(fit=True)
    except DataOverflowError as exc:
        raise QrError("Ссылка слишком длинная для QR-кода") from exc
    with io.BytesIO() as stream:
        code.make_image(fill_color="black", back_color="white").save(stream, format="PNG")
        return "data:image/png;base64," + base64.b64encode(stream.getvalue()).decode("ascii")


def _decode(image: Image.Image) -> list[str]:
    if image.width * image.height > MAX_PIXELS:
        raise QrError("Изображение слишком большое (не больше 40 миллионов пикселей)")
    try:
        with image.convert("RGB") as rgb:
            codes = zxingcpp.read_barcodes(rgb, formats=zxingcpp.BarcodeFormat.QRCode)
        return list(dict.fromkeys(code.text for code in codes if code.valid and code.text))
    except (ValueError, RuntimeError) as exc:
        raise QrError("Не удалось распознать QR-код") from exc


def decode_file(path: str | Path) -> list[str]:
    if Path(path).suffix.lower() not in _EXTENSIONS:
        raise QrError("Выберите картинку PNG, JPG, BMP, GIF или WebP")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(path) as image:
                if image.format not in _FORMATS:
                    raise QrError("Выберите картинку PNG, JPG, BMP, GIF или WebP")
                return _decode(image)
    except (Image.DecompressionBombError, Image.DecompressionBombWarning) as exc:
        raise QrError("Изображение слишком большое") from exc
    except (OSError, UnidentifiedImageError, ValueError) as exc:
        raise QrError("Не удалось открыть картинку с QR-кодом") from exc


def decode_screen() -> list[str]:
    try:
        with ImageGrab.grab(all_screens=True) as image:
            texts = _decode(image)
    except OSError as exc:
        raise QrError("Не удалось получить снимок экрана") from exc
    if not texts:
        raise QrError("На экране не найден QR-код")
    return texts
