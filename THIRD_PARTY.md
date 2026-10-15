# Сторонние компоненты

«Лазейка» объединяет чужие проекты с открытым кодом. Все они распространяются
на условиях своих лицензий; их тексты лежат рядом с кодом или внутри архивов.

| Компонент | Откуда | Что используется | Лицензия |
|---|---|---|---|
| zapret-discord-youtube | https://github.com/Flowseal/zapret-discord-youtube | Релиз 1.10.3 без изменений (`vendor/zapret/*.zip`): стратегии `general*.bat`, списки, `bin/` | MIT © Flowseal, bol-van |
| zapret / winws | https://github.com/bol-van/zapret, https://github.com/bol-van/zapret-win-bundle | `winws.exe`, `cygwin1.dll` из релиза выше | MIT © bol-van |
| WinDivert | https://github.com/basil00/WinDivert | `WinDivert.dll`, `WinDivert64.sys` из релиза выше | LGPL-3.0 / GPL-2.0 |
| tg-ws-proxy | https://github.com/Flowseal/tg-ws-proxy | Папка `proxy/` тега v1.11.2 без изменений (`app/vendor/tgws_proxy`) | MIT © Flowseal |
| pywebview | https://github.com/r0x0r/pywebview | Окно на WebView2 | BSD-3-Clause |
| pythonnet | https://github.com/pythonnet/pythonnet | Мост к .NET для pywebview | MIT |
| pystray | https://github.com/moses-palmer/pystray | Значок в трее | LGPL-3.0 |
| Pillow | https://github.com/python-pillow/Pillow | Рисование значка | MIT-CMU |
| psutil | https://github.com/giampaolo/psutil | Поиск процессов | BSD-3-Clause |
| cryptography | https://github.com/pyca/cryptography | AES-CTR для MTProto | Apache-2.0 / BSD |
| httpx, h2, certifi | https://github.com/encode/httpx и др. | HTTP/2 в ядре прокси, корневые сертификаты | BSD-3-Clause, MIT, MPL-2.0 |

Проверки «DPI 16–20 КБ» берут список целей из https://github.com/hyperion-cs/dpi-checkers
(Apache-2.0) — так же, как это делает утилита тестов zapret-discord-youtube.

Хотите поддержать авторов — это Flowseal и bol-van; ссылки на их страницы
поддержки есть в README их репозиториев.
