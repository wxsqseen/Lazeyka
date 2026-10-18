# Картинки состояний «Своего VPN»: генерация в Codex

Карточка «Подключение» на странице «VPN», пока VPN не подключён, показывает вместо пустых нулей скорости
и плоского графика картинку состояния и одну фразу о том, что дальше. Картинки нарисованы встроенным
генератором изображений Codex (CLI из расширения VS Code) — той же семьёй, что и `vpn-empty.png`
(`codex-vpn-empty.md`): серые линии #7D818A, один синий акцент #5B8DEF, ноутбук — стена с проёмом — сервер.

| Состояние | Файл | Выбран | Что на картинке |
|---|---|---|---|
| Выключено (и «недоступно») | `app/ui/img/vpn-off.png` | вариант 1 из 3 | серый пунктир до сервера, синий значок питания на экране ноутбука |
| Подключаемся, проверяем выход | `app/ui/img/vpn-connect.png` | вариант 1 из 3 | синие точки через проём, не доходят до сервера; по ним бежит волна |
| Не подключилось | `app/ui/img/vpn-error.png` | вариант 1 из 3 | синяя стрелка обрывается перед сервером, между ними серый «×» |
| Готовим ядро VPN (первое включение) | `app/ui/img/vpn-core.png` | вариант 3 из 3 | облако → синяя стрелка → ноутбук с шестерёнкой; по стрелке бежит волна |

Почему эти варианты. В «Выключено» пунктир говорит «маршрут готов, но не идёт», а синий значок питания
подсказывает действие; вариант без маршрута (3) читался как пустое состояние. В «Подключаемся» ровный ряд
точек (1) читается как «в пути» и лучше всех годится для бегущей волны. В «Не подключилось» обрыв со
спокойным серым «×» (1) понятнее крестика на сервере (2) — тот похож на «удалить сервер». Для ядра облако
со стрелкой к ноутбуку (3) повторяет композицию семьи «слева направо»; посылка со щитом (2) выбивается из
семьи, а ноутбук со стрелкой сверху (1) квадратный и мелкий в широкой карточке.

Где и как показаны (`app/ui/js/pages/vpnclient.js`, `sceneFor`; `app/ui/css/vpnclient.css`, `.vc-scene`):

- Статистика и картинка лежат в одной ячейке сетки: высота карточки не меняется, при смене состояния
  они плавно сменяют друг друга. Трафик за день и всего, пока цифры спрятаны, — в нижней строке карточки.
- Картинка 240×97 (в узком окне 200 px), `alt=""` — смысл несёт фраза рядом; не загрузилась — остаётся фраза.
- Волна в «Подключаемся» и «Готовим ядро» — CSS-маска только над синим путём (`--path-*` — его границы
  в долях картинки), остальной рисунок не мерцает. При `prefers-reduced-motion: reduce` волны нет, путь
  виден целиком.
- Картинка ядра показывается в той же сцене, пока ядро ставится впервые (ещё не установлено и в
  состоянии downloading, verifying или installing) и когда первая загрузка не удалась; фоновое обновление
  уже стоящего ядра сцену не занимает. В другом месте её можно поставить классами
  `vc-scene__art vc-scene__art--core` (с волной) или простым `<img src="img/vpn-core.png" alt="">`.

## Очистка

`build/clean_codex_art.py` убирает белый фон и сводит цвета к двум из палитры, как для `vpn-empty.png`.
Для этой семьи добавлен ключ `--box`: вырезается одна и та же область черновика, а не поля по рисунку, —
у трёх картинок сцены (выключено, подключаемся, не подключилось) одинаковые размеры 640×258 и масштаб,
ноутбук и стена при смене состояния стоят на месте. Без `--box` скрипт работает как раньше: прогон на
`vpn-empty-v3.png` даёт `vpn-empty.png` байт в байт.

Команды (из папки черновиков; рядом `reference-icon.png` — значок Лазейки и `reference-family.png` —
черновик `vpn-empty-v3.png`, по которому подбирались линии):

```
codex exec -s workspace-write --skip-git-repo-check -i reference-icon.png -i reference-family.png -o result.md - < prompt.md
.venv\Scripts\python.exe build\clean_codex_art.py <черновики>\off-v1.png app\ui\img\vpn-off.png --box 78,312,1318,812
.venv\Scripts\python.exe build\clean_codex_art.py <черновики>\connect-v1.png app\ui\img\vpn-connect.png --box 78,312,1318,812
.venv\Scripts\python.exe build\clean_codex_art.py <черновики>\error-v1.png app\ui\img\vpn-error.png --box 78,312,1318,812
.venv\Scripts\python.exe build\clean_codex_art.py <черновики>\core-v3.png app\ui\img\vpn-core.png --box 103,298,1343,798
```

Области `--box` подобраны по рисункам: у трёх картинок сцены они занимают x 138–1256, y 340–783 черновика
1448×1086, у картинки ядра — x 131–1315, y 378–717. Если рисунок не влезает в область, скрипт откажется
резать и назовёт его границы.

## Промпт «Выключено»

```text
Generate illustration artwork with your built-in image generator. Do not write or run any code, do not touch any files except the PNG images you save in the current working directory.

App: "Лазейка" (Lazeyka) — a small Windows utility that lets Discord, YouTube and Telegram work through network blocks, and can also connect through the user's own VPN server. The attached reference-icon.png is the app icon: a dark tile, a vertical wall broken by a gap, an arrow passing through the gap. The attached reference-family.png is an existing illustration from the same page: a laptop, a path through a gap in a vertical wall, and a server. The new illustration must look like a sibling of reference-family.png — the same stroke weight, the same round caps and rounded corners, the same way of drawing the laptop and the server, the same proportions and empty space.

What to draw: an illustration for the state "Выключено" (VPN is off, the server is ready): the user already added a server, the route is prepared but not active. Same scene as reference-family.png (laptop on the left, vertical wall with a gap in the middle, server on the right). Calm, at rest.

Style requirements (very important — the owner wants strict minimalism, nothing colourful or flashy):
- Flat line illustration, geometric, minimal. Uniform medium-thick strokes with round caps, exactly like reference-family.png. No gradients, no shadows, no glow, no texture, no 3D, no text, letters or numbers, no people.
- Only two colours: all lines and shapes in mid grey (#7D818A), and ONE accent element in calm blue (#5B8DEF). No fills except a small accent arrowhead or dot. No red, no green, no other colours.
- Plain pure white background (#FFFFFF), the drawing centred with generous margins, wide 4:3 landscape image.
- It will be shown at about 240×100 px on both a dark and a light app background, so keep it simple and readable at that size.
- The route is grey and dashed (inactive). The only blue element is a small power symbol (circle with a vertical line at the top, like a power button icon) — no other blue.

Make 3 variants with small differences and save them as off-v1.png, off-v2.png and off-v3.png in the current directory:
1. off-v1.png — grey dashed route from the laptop through the gap to the server; a small blue power symbol drawn on the laptop screen.
2. off-v2.png — grey dashed route from the laptop through the gap to the server; a small blue power symbol floating above the laptop, at the same place and size as the small plus sign in reference-family.png but near the laptop.
3. off-v3.png — no route at all, only the laptop, the wall with the gap and the server; a small blue power symbol on the laptop screen.
Then reply with one short sentence per file describing it.
```

## Промпт «Подключаемся»

```text
Generate illustration artwork with your built-in image generator. Do not write or run any code, do not touch any files except the PNG images you save in the current working directory.

App: "Лазейка" (Lazeyka) — a small Windows utility that lets Discord, YouTube and Telegram work through network blocks, and can also connect through the user's own VPN server. The attached reference-icon.png is the app icon: a dark tile, a vertical wall broken by a gap, an arrow passing through the gap. The attached reference-family.png is an existing illustration from the same page: a laptop, a path through a gap in a vertical wall, and a server. The new illustration must look like a sibling of reference-family.png — the same stroke weight, the same round caps and rounded corners, the same way of drawing the laptop and the server, the same proportions and empty space.

What to draw: an illustration for the state "Подключаюсь" (Connecting): the VPN is establishing the route to the user's server, which takes a second or two. Same scene as reference-family.png (laptop on the left, vertical wall with a gap in the middle, server on the right) but the route is still being built.

Style requirements (very important — the owner wants strict minimalism, nothing colourful or flashy):
- Flat line illustration, geometric, minimal. Uniform medium-thick strokes with round caps, exactly like reference-family.png. No gradients, no shadows, no glow, no texture, no 3D, no text, letters or numbers, no people.
- Only two colours: all lines and shapes in mid grey (#7D818A), and ONE accent element in calm blue (#5B8DEF). No fills except a small accent arrowhead or dot. No red, no green, no other colours.
- Plain pure white background (#FFFFFF), the drawing centred with generous margins, wide 4:3 landscape image.
- It will be shown at about 240×100 px on both a dark and a light app background, so keep it simple and readable at that size.
- The accent (blue) is the route only. No plus sign.

Make 3 variants with small differences and save them as connect-v1.png, connect-v2.png and connect-v3.png in the current directory:
1. connect-v1.png — the blue route is a row of evenly spaced round dots from the laptop through the gap, stopping a little before the server (no arrowhead).
2. connect-v2.png — the blue route is a solid line from the laptop to the gap, then three blue dots after the gap leading towards the server.
3. connect-v3.png — the blue route is a dashed line with a small arrowhead, reaching just past the gap; the server on the right is drawn the same as in reference-family.png.
Then reply with one short sentence per file describing it.
```

## Промпт «Не подключилось»

```text
Generate illustration artwork with your built-in image generator. Do not write or run any code, do not touch any files except the PNG images you save in the current working directory.

App: "Лазейка" (Lazeyka) — a small Windows utility that lets Discord, YouTube and Telegram work through network blocks, and can also connect through the user's own VPN server. The attached reference-icon.png is the app icon: a dark tile, a vertical wall broken by a gap, an arrow passing through the gap. The attached reference-family.png is an existing illustration from the same page: a laptop, a path through a gap in a vertical wall, and a server. The new illustration must look like a sibling of reference-family.png — the same stroke weight, the same round caps and rounded corners, the same way of drawing the laptop and the server, the same proportions and empty space.

What to draw: an illustration for the state "Не подключилось" (Could not connect): the VPN tried to reach the user's server but the server did not answer or rejected the connection. Same scene as reference-family.png (laptop on the left, vertical wall with a gap in the middle, server on the right). It must stay calm and friendly — a small, clear break in the route, not an alarm. No red colour, no warning triangles, no exclamation marks.

Style requirements (very important — the owner wants strict minimalism, nothing colourful or flashy):
- Flat line illustration, geometric, minimal. Uniform medium-thick strokes with round caps, exactly like reference-family.png. No gradients, no shadows, no glow, no texture, no 3D, no text, letters or numbers, no people.
- Only two colours: all lines and shapes in mid grey (#7D818A), and ONE accent element in calm blue (#5B8DEF). No fills except a small accent arrowhead or dot. No red, no green, no other colours.
- Plain pure white background (#FFFFFF), the drawing centred with generous margins, wide 4:3 landscape image.
- It will be shown at about 240×100 px on both a dark and a light app background, so keep it simple and readable at that size.
- The accent (blue) is the route only. The break mark, if any, is grey.

Make 3 variants with small differences and save them as error-v1.png, error-v2.png and error-v3.png in the current directory:
1. error-v1.png — the blue route goes from the laptop through the gap and ends before the server; in the empty space between the route end and the server there is a small grey "×" made of two short strokes.
2. error-v2.png — the blue route goes from the laptop through the gap and stops at the server; the server has a small grey "×" badge at its top right corner (placed like the small plus sign in reference-family.png).
3. error-v3.png — the blue route goes through the gap and is visibly broken into two pieces just before the server: a short gap in the line with two tiny grey slanted strokes marking the break.
Then reply with one short sentence per file describing it.
```

## Промпт «Готовим ядро VPN»

```text
Generate illustration artwork with your built-in image generator. Do not write or run any code, do not touch any files except the PNG images you save in the current working directory.

App: "Лазейка" (Lazeyka) — a small Windows utility that lets Discord, YouTube and Telegram work through network blocks, and can also connect through the user's own VPN server. The attached reference-icon.png is the app icon: a dark tile, a vertical wall broken by a gap, an arrow passing through the gap. The attached reference-family.png is an existing illustration from the same page: a laptop, a path through a gap in a vertical wall, and a server. The new illustration must look like a sibling of reference-family.png — the same stroke weight, the same round caps and rounded corners, the same way of drawing the laptop and the server, the same proportions and empty space.

What to draw: an illustration for the state "Готовлю ядро VPN" (Preparing the VPN engine). On the first start Lazeyka downloads the VPN engine (a small program) from the official GitHub release, checks its checksum and installs it — this happens once and takes a few seconds. The picture should calmly say "the engine is being delivered to your computer and checked", not "error" and not "waiting forever".

Style requirements (very important — the owner wants strict minimalism, nothing colourful or flashy):
- Flat line illustration, geometric, minimal. Uniform medium-thick strokes with round caps, exactly like reference-family.png. No gradients, no shadows, no glow, no texture, no 3D, no text, letters or numbers, no people.
- Only two colours: all lines and shapes in mid grey (#7D818A), and ONE accent element in calm blue (#5B8DEF). No fills except a small accent arrowhead or dot. No red, no green, no other colours.
- Plain pure white background (#FFFFFF), the drawing centred with generous margins, wide 4:3 landscape image.
- It will be shown at about 240×100 px on both a dark and a light app background, so keep it simple and readable at that size.
- The accent (blue) is the download arrow / delivery path only.

Make 3 variants with different concepts and save them as core-v1.png, core-v2.png and core-v3.png in the current directory:
1. core-v1.png — the laptop from reference-family.png whose screen shows a simple gear (the engine); a blue downward arrow above the laptop points into the screen.
2. core-v2.png — a package box outline (simple flat front view of a closed box with a tape line) with a blue downward arrow entering it from above, and a small grey check mark in a small shield next to the box (the download is verified).
3. core-v3.png — on the left a small cloud outline, on the right the laptop from reference-family.png with a small gear on its screen; a blue path with an arrowhead goes from the cloud to the laptop.
Then reply with one short sentence per file describing it.
```

## Ответ Codex

- `off-v1.png` — серый пунктирный маршрут и синий символ питания на экране ноутбука (выбран).
- `off-v2.png` — серый пунктирный маршрут и синий символ питания над ноутбуком.
- `off-v3.png` — сцена без маршрута, синий символ питания на экране ноутбука.
- `connect-v1.png` — ровный ряд синих точек через проём, не доходит до сервера (выбран).
- `connect-v2.png` — сплошная синяя линия до проёма, дальше три точки.
- `connect-v3.png` — синий пунктир с маленькой стрелкой сразу за проёмом.
- `error-v1.png` — синяя стрелка обрывается перед сервером, между ними серый «×» (выбран).
- `error-v2.png` — синяя стрелка доходит до сервера, серый «×» у его угла.
- `error-v3.png` — синяя линия разорвана после стены, разрыв отмечен двумя серыми штрихами.
- `core-v1.png` — ноутбук с шестерёнкой и синей стрелкой загрузки сверху.
- `core-v2.png` — посылка со стрелкой загрузки и щитом с галочкой проверки.
- `core-v3.png` — синяя стрелка доставки из облака к ноутбуку с шестерёнкой (выбран).
