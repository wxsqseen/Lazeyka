# Картинка пустого «Своего VPN»: промпт и обработка

Иллюстрация для страницы «Свой VPN», пока не добавлено ни одного сервера. Черновики — три варианта по промпту
ниже; выбран вариант 3: прямой путь к серверу и маленький плюс. К промпту прикладывался `reference-icon.png` —
значок Лазейки, чтобы картинка была из той же семьи.

`build/clean_art.py` убирает белый фон и сводит цвета к двум из палитры — серый #7D818A и акцент #5B8DEF.
Покрытие пикселя считается по отклонению от белого, поэтому мягкие края остаются мягкими и на тёмной, и на светлой
теме. Затем скрипт обрезает поля и уменьшает до ширины 640 px. Результат — `app/ui/img/vpn-empty.png`;
повторный прогон на `vpn-empty-v3.png` даёт тот же файл байт в байт.

Обработка выбранного черновика:

```
.venv\Scripts\python.exe build\clean_art.py <папка-черновиков>\vpn-empty-v3.png app\ui\img\vpn-empty.png
```

## Промпт

```text
Generate illustration artwork with your built-in image generator. Do not write or run any code, do not touch any files except the PNG images you save in the current working directory.

App: "Лазейка" (Lazeyka) — a small Windows utility that lets Discord, YouTube and Telegram work through network blocks, and now can also connect through the user's own VPN server (the user brings their own subscription). The attached reference-icon.png is the app icon: a dark tile, a vertical wall broken by a gap, an arrow passing through the gap. The illustration must feel like part of the same family.

What to draw: an empty-state illustration for the page "Свой VPN" (Your own VPN), shown when the user has not added any server yet. Concept: on the left a simple laptop/computer outline; a path line leaves it, passes through a gap in a vertical wall (the brand motif), and continues to a small server rack / globe outline on the right, as if a private route to "your server". Optionally a small plus sign near the server hinting "add your server".

Style requirements (very important — the owner wants strict minimalism, nothing colourful or flashy):
- Flat line illustration, geometric, minimal. Uniform medium-thick strokes with round caps. No gradients, no shadows, no glow, no texture, no 3D, no text or letters, no people.
- Only two colours: all lines and shapes in mid grey (#7D818A), and ONE accent element (the path line / arrow through the gap) in calm blue (#5B8DEF). No fills except the accent arrowhead. No other colours.
- Plain pure white background (#FFFFFF), the drawing centred with generous margins, wide 4:3 landscape image.
- It will be shown at about 320×240 px on both a dark and a light app background, so keep it simple and readable at that size.

Make 3 variants with small differences (for example: globe vs server rack on the right, straight vs gently curved path, with or without the small plus sign) and save them as vpn-empty-v1.png, vpn-empty-v2.png and vpn-empty-v3.png in the current directory. Then reply with one short sentence per file describing it.
```

## Черновики

- `vpn-empty-v1.png` — ноутбук соединён с сервером прямой синей стрелкой через проём в стене.
- `vpn-empty-v2.png` — ноутбук соединён с глобусом плавно изогнутым синим путём.
- `vpn-empty-v3.png` — прямой путь к серверу и маленький серый плюс (выбран).
