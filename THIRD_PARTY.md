# Сторонние компоненты

«Лазейка» объединяет чужие проекты с открытым кодом. Все они распространяются на условиях своих
лицензий. Тексты лицензий всего, что входит в `Lazeyka.exe`, лежат внутри exe в папке `licenses`
(оглавление — `licenses/README.txt`): их собирает сборка по фактическому составу exe
(`build/third_party.py`), и компонент без текста лицензии или без строки в этом файле её останавливает.
Тексты zapret и tg-ws-proxy лежат и в их собственных папках сборки.

## Программы и данные

| Компонент | Откуда | Что используется | Лицензия |
|---|---|---|---|
| zapret-discord-youtube | https://github.com/Flowseal/zapret-discord-youtube | Релиз 1.10.3 без изменений (`vendor/zapret/*.zip`): стратегии `general*.bat`, списки, `bin/` | MIT © Flowseal, bol-van |
| zapret / winws | https://github.com/bol-van/zapret, https://github.com/bol-van/zapret-win-bundle | `winws.exe`, `cygwin1.dll` из релиза выше | MIT © bol-van |
| WinDivert | https://github.com/basil00/WinDivert | `WinDivert.dll`, `WinDivert64.sys` из релиза выше | LGPL-3.0 / GPL-2.0 |
| tg-ws-proxy | https://github.com/Flowseal/tg-ws-proxy | Папка `proxy/` тега v1.11.2 без изменений (`app/vendor/tgws_proxy`) | MIT © Flowseal |
| sing-box | https://github.com/SagerNet/sing-box | Ядро своего VPN. В Lazeyka.exe не входит: при запуске Лазейка скачивает официальный релиз без изменений со страницы проекта на GitHub — закреплённый v1.14.3 (`sing-box-1.14.3-windows-amd64.zip`, SHA-256 в коде), новые версии — автообновлением (хеш — digest GitHub) — ставит в `components/sing-box/<версия>/` и запускает отдельным процессом. Исходный код — по ссылке ниже | GPL-3.0-or-later © nekohasekai; «no derivative work may use the name or imply association with this application without prior consent» |
| Xray-core | https://github.com/XTLS/Xray-core | Помощник своего VPN для XHTTP, mKCP и VLESS ML-KEM: официальный релиз (закреплённый v26.3.27 — `Xray-windows-64.zip`, SHA-256 в коде) так же скачивается с GitHub без изменений; `components/xray/<версия>/`, отдельный процесс | MPL-2.0 © Project X |
| Wintun | https://www.wintun.net | `wintun.dll` 0.14.1 (подпись WireGuard LLC) встроен в `sing-box.exe` и лежит рядом с `xray.exe` — оба приходят из релизов ядер; не изменяется | WireGuard LLC Prebuilt Binaries License |
| Списки маршрутов | SagerNet/sing-geosite, SagerNet/sing-geoip, 1andrevich/Re-filter-lists, itdoginfo/allow-domains, runetfreedom/russia-v2ray-rules-dat, Loyalsoldier/geoip | Не входят в сборку; скачиваются у источника при выборе пресета маршрутов | GPL-3.0 (sing-geosite и sing-geoip, runetfreedom; данные v2fly — MIT, MaxMind GeoLite2), MIT (Re-filter-lists), CC-BY-SA-4.0 (Loyalsoldier), itdoginfo — без лицензии (только скачивание по запросу) |
| Twemoji Country Flags | https://github.com/talkjs/country-flag-emoji-polyfill, графика — https://github.com/twitter/twemoji | Шрифт флагов стран для страницы «VPN» (Windows не рисует эмодзи-флаги): `app/ui/fonts/TwemojiCountryFlags.woff2` из npm-пакета `country-flag-emoji-polyfill` 0.1.10 без изменений, SHA-256 `9f04f14429bb6a9f415c7a4dd902a918d7e81a4f7526c415496fdb063954e3b8` (архив пакета сверен с sha512 реестра npm). Лежит в сборке, по сети не загружается. Текст лицензии — `app/ui/fonts/TwemojiCountryFlags-LICENSE.md` | Графика флагов © Twitter, Inc. и участники Twemoji — CC-BY-4.0; подмножество шрифта Twemoji Mozilla и код пакета — MIT © TalkJS |

## Библиотеки внутри Lazeyka.exe

Все — без изменений; версии закреплены в `requirements-lock.txt`.

| Компонент | Откуда | Зачем | Лицензия |
|---|---|---|---|
| CPython 3.11 | https://www.python.org | Интерпретатор и стандартная библиотека (с bzip2 — её текст в лицензии CPython) | PSF-2.0 |
| OpenSSL 3 | https://www.openssl.org | TLS стандартной библиотеки (`libssl`, `libcrypto`); своя копия — внутри cryptography | Apache-2.0 |
| libffi | https://github.com/libffi/libffi | `ctypes`: вызовы Windows API | MIT |
| Expat | https://github.com/libexpat/libexpat | Разбор XML в стандартной библиотеке | MIT |
| libmpdec (mpdecimal) | https://www.bytereef.org/mpdecimal/ | Модуль `decimal` | BSD-2-Clause |
| XZ Utils (liblzma) | https://tukaani.org/xz/ | Модуль `lzma` | 0BSD |
| zlib | https://zlib.net | Сжатие в стандартной библиотеке | Zlib |
| Visual C++ Runtime, Universal C Runtime | Microsoft | `VCRUNTIME140*.dll`, `MSVCP140.dll`, `ucrtbase.dll`, `api-ms-win-*.dll` — библиотеки, без которых не запускаются CPython и расширения | Распространяемый код Microsoft |
| PyInstaller (загрузчик exe) и pyinstaller-hooks-contrib | https://github.com/pyinstaller/pyinstaller | Загрузчик, который распаковывает и запускает exe; runtime-хуки | GPL-2.0-or-later с исключением, разрешающим распространять собранные программы на любых условиях; runtime-хуки — Apache-2.0 |
| pywebview | https://github.com/r0x0r/pywebview | Окно на WebView2 | BSD-3-Clause |
| Microsoft Edge WebView2 SDK | https://www.nuget.org/packages/Microsoft.Web.WebView2 | `Microsoft.Web.WebView2.*.dll`, `WebView2Loader.dll` из пакета pywebview | Лицензия Microsoft (BSD-подобная) |
| bottle, proxy_tools | https://github.com/bottlepy/bottle, https://github.com/jtushman/proxy_tools | Зависимости pywebview | MIT |
| pythonnet, clr_loader, cffi, pycparser | https://github.com/pythonnet/pythonnet, https://github.com/pythonnet/clr-loader, https://github.com/python-cffi/cffi, https://github.com/eliben/pycparser | Мост к .NET для pywebview | MIT, MIT, MIT-0, BSD-3-Clause |
| pystray, six | https://github.com/moses-palmer/pystray, https://github.com/benjaminp/six | Значок в трее | LGPL-3.0, MIT |
| Pillow | https://github.com/python-pillow/Pillow | Рисование значка, картинки QR | MIT-CMU (и лицензии встроенных в него библиотек — в его тексте) |
| psutil | https://github.com/giampaolo/psutil | Поиск процессов | BSD-3-Clause |
| cryptography | https://github.com/pyca/cryptography | AES-CTR для MTProto | Apache-2.0 OR BSD-3-Clause |
| httpx, httpcore, h11, h2, hpack, hyperframe, anyio, idna | https://github.com/encode/httpx и др. | HTTP/2 в ядре Telegram-прокси | BSD-3-Clause (httpx, httpcore, idna), MIT (остальные) |
| certifi | https://github.com/certifi/python-certifi | Корневые сертификаты | MPL-2.0 |
| typing_extensions, packaging | https://github.com/python/typing_extensions, https://github.com/pypa/packaging | Зависимости anyio, cryptography, pywebview и bottle | PSF-2.0, Apache-2.0 OR BSD-2-Clause |
| qrcode, colorama | https://github.com/lincolnloop/python-qrcode, https://github.com/tartley/colorama | QR-код ссылки подписки или сервера | BSD-3-Clause |
| zxing-cpp | https://github.com/zxing-cpp/zxing-cpp | Распознавание QR-кода с картинки или снимка экрана | Apache-2.0 |

pystray (LGPL-3.0) не изменялся; его исходный код — пакет `pystray` 0.19.5 на PyPI. Заменить его своей
версией можно, собрав Lazeyka.exe из исходников этого репозитория (README, «Сборка из исходников»).
Исходный код certifi (MPL-2.0) — по ссылке в таблице.

## Ядра своего VPN

Ядра своего VPN — отдельные программы: Лазейка передаёт им файл конфигурации и обращается к их
HTTP-API на 127.0.0.1; их код в Лазейку не входит, и лицензия Лазейки (MIT) на них не
распространяется. Лазейка не связана с проектами sing-box, Xray и WireGuard и не одобрена ими.
Лазейка бинарники ядер не распространяет — их скачивает с GitHub сам компьютер человека; исходный код
закреплённых версий: https://github.com/SagerNet/sing-box/tree/v1.14.3,
https://github.com/XTLS/Xray-core/tree/v26.3.27 (других — по тегу версии), https://git.zx2c4.com/wintun/
(GPL-2.0). Текст GPL-3.0 и лицензии ядер лежат в папке ядра рядом с его exe.

Проверки «DPI 16–20 КБ» берут список целей из https://github.com/hyperion-cs/dpi-checkers
(Apache-2.0) — так же, как это делает утилита тестов zapret-discord-youtube.

Хотите поддержать авторов — это Flowseal и bol-van; ссылки на их страницы
поддержки есть в README их репозиториев.
