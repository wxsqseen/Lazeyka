# Контракт UI ↔ ядро

Интерфейс — статическая страница `app/ui/index.html` внутри окна pywebview (WebView2).
Python отдаёт объект API; JS вызывает его как `window.pywebview.api.<метод>(...)`,
каждый вызов возвращает Promise. Объект появляется после события `pywebviewready`.

Ядро не пушит события в страницу: страница опрашивает `get_state()` раз в секунду
(во время теста стратегий и установки обновлений — раз в 400 мс) и `get_logs()`
на странице журнала.

Все строки, пришедшие из ядра (имена стратегий, тексты ошибок, заметки к релизам,
строки журнала), — недоверенные данные: выводить только через `textContent`,
никогда через `innerHTML`.

## Ответ действий

Любой метод-действие возвращает

```json
{ "ok": true }
{ "ok": false, "error": "Текст для человека", "errors": { "port": "Порт должен быть числом 1–65535" } }
```

`errors` есть только у методов сохранения форм — ключи совпадают с полями формы.
Долгие действия (тесты, обновления, диагностика) возвращаются сразу, а прогресс
виден в `get_state()`.

## `get_state()`

```jsonc
{
  "app": {
    "name": "Лазейка",
    "version": "1.0.0",
    "admin": true,              // процесс запущен с правами администратора
    "first_run": false,         // показать приветственный экран
    "data_dir": "C:\\ProgramData\\Lazeyka",
    "busy": null                // строка, если идёт глобальная операция
  },

  // Плашки и уведомления сверху. level: info | success | warn | error. Подробно — «Постоянные плашки» ниже.
  "notices": [
    { "id": "update-available", "level": "info", "text": "Доступно обновление zapret 1.10.4",
      "action": { "label": "Открыть", "page": "updates" },  // либо { "label": "...", "call": "имя_метода", "args": [] }
      "dismissible": true,
      "persistent": true,      // true — висит, пока условие есть; false — временное уведомление (25–60 с)
      "page": null }           // страница, где плашку показать ещё и под заголовком; null — только главная
  ],

  "zapret": {
    "available": true,          // false — нет прав администратора или пакет не установлен
    "unavailable_reason": null, // текст, если available=false
    "status": "running",        // stopped | starting | running | stopping | error
    "error": null,
    "mode": "app",              // app — winws запускает приложение; service — служба Windows
    "strategy": "general (ALT2)",
    "strategies": [ { "id": "general", "label": "Стандартная" }, { "id": "general (ALT2)", "label": "ALT2" } ],
    "started_at": 1760466000.5, // unix-время запуска или null
    "pack": { "version": "1.10.3" },
    "game_filter": { "mode": "disabled", "tcp": "1024-65535", "udp": "1024-65535" }, // disabled | all | tcp | udp
    "ipset": { "mode": "none", "count": 33048 },  // none | loaded | any; count — подсетей в полном списке
    "service": { "installed": false, "running": false, "strategy": null },
    "conflicts": [ { "id": "service:GoodbyeDPI", "text": "Запущен GoodbyeDPI — он мешает zapret", "fix_label": "Удалить службу" } ],

    // Быстрая проверка «открываются ли сайты сейчас»
    "check": {
      "running": false,
      "at": 1760466100.0,
      "results": [ { "id": "discord", "label": "Discord", "ok": true, "detail": "3/3" },
                   { "id": "youtube", "label": "YouTube", "ok": false, "detail": "1/4" } ]
    },

    // Подбор стратегии
    "test": {
      "running": false,
      "kind": "standard",       // standard | dpi
      "total": 21, "done": 21,
      "current": null,          // id стратегии, которая тестируется сейчас
      "best": "general (ALT2)",
      "error": null,            // текст, если подбор не начался или прервался из-за ошибки
      "cancelled": false,       // подбор остановил человек — это не ошибка, error при этом null
      "finished_at": 1760466300.0,
      "results": [
        { "id": "general (ALT2)", "label": "ALT2", "ok": 34, "fail": 2, "unsup": 0,
          "ping_ok": 4, "ping_total": 4, "score": 0.94, "started": true,
          "targets": [ { "name": "Discord", "url": "https://discord.com",
                         "http": "ok", "tls12": "ok", "tls13": "fail", "ping": 23 } ] }
          // http/tls12/tls13: ok | fail | unsup | ssl | dns | null(не проверялось); ping: мс или null
          // ssl — подменён сертификат, dns — адрес не нашёлся (обе — неудачи, входят в fail);
          // unsup — только то, чего не умеют curl или Windows (TLS 1.3 до Windows 11): в score не входит.
          // score = ok / (ok + fail)
      ]
    }
  },

  "tg": {
    "status": "running",        // stopped | starting | running | error
    "error": null,
    "host": "127.0.0.1", "port": 1443,
    "link": "tg://proxy?server=127.0.0.1&port=1443&secret=dd…",
    "version": "1.11.2",        // версия ядра tg-ws-proxy
    "core": "bundled",          // bundled — встроенное ядро; updated — скачанное обновлением
    "started_at": 1760466000.5,
    "stats": { "active": 3, "total": 120, "ws": 100, "cf": 5, "h2": 2, "tcp_fallback": 1, "bad": 0,
               "up": 123456, "down": 9876543, "up_rate": 1200.5, "down_rate": 56000.0 },
    "history": [ [1760466000, 1200.5, 56000.0] ],   // до 120 точек: время, байт/с вверх, байт/с вниз
    "test": { "running": false, "at": null,
              "results": [ { "name": "Прямой WebSocket (DC2)", "ok": true, "detail": "101 Switching Protocols" } ] }
  },

  "updates": {
    "auto_check": true,
    "checking": false,
    "last_check": 1760466000.0,
    "error": null,              // не проверился хоть один пункт: все — первая ошибка, часть — «Не удалось проверить «…»: …»
    "count": 1,                 // сколько обновлений доступно (бейдж в меню); ждущая перезапуска Лазейка не в счёт
    "items": [
      { "id": "zapret", "title": "Стратегии zapret", "subtitle": "Flowseal/zapret-discord-youtube",
        "current": "1.10.3", "latest": "1.10.4", "available": true, "skipped": false,
        "published_at": "2026-10-01T10:00:00Z", "notes": "текст из релиза", "url": "https://github.com/…",
        "state": "idle",        // idle | downloading | verifying | installing | done | rolling_back | rolled_back | error
        "progress": null,       // 0..1 во время скачивания
        "message": null,
        "can_rollback": false,
        "checked": true,        // GitHub ответил про этот пункт в этом сеансе («Всё актуально» — только когда у всех установленных)
        "check_error": null,    // почему пункт не проверился в последний раз
        "restart": false }      // только app: новый exe уже на диске — нужна кнопка «Перезапустить» (app_restart), как в плашке app-restart
    ]
  },

  "settings": {
    "theme": "system",          // system | dark | light
    "close_to_tray": true,
    "start_minimized": false,
    "autostart": false,
    "zapret_on_start": true,
    "tg_on_start": true,
    "check_updates": true,
    "tcp_timestamps": true
  },

  "tg_settings": {
    "host": "127.0.0.1", "port": 1443, "secret": "32 hex",
    "dc_ip": ["2:149.154.167.220", "4:149.154.167.220"],
    "cfproxy": true, "h2": true,
    "cf_domains_enabled": false, "cf_domains": [],
    "worker_enabled": false, "worker_domains": [],
    "pool_size": 4, "buf_kb": 256, "no_secure": false, "verbose": false
  },

  "diag": {
    "running": false,
    "at": null,
    "items": [ { "id": "bfe", "title": "Base Filtering Engine", "status": "ok", "text": "Служба работает",
                 "fix": null } ]   // status: ok | warn | error | info; fix: { "id": "...", "label": "Исправить" }
  }
}
```

## Методы

| Метод | Аргументы | Что делает |
|---|---|---|
| `get_state()` | — | Снимок выше |
| `get_logs(after_id, source)` | `int`, `"all" \| "app" \| "zapret" \| "tg"` | `{ "lines": [ {"id", "t", "src", "lvl", "msg"} ], "last_id": int }`, `lvl`: debug/info/warn/error |
| `finish_onboarding(opts)` | `{ "check_updates": bool, "autostart": bool }` | Закрывает приветствие |
| `save_settings(partial)` | часть `settings` | Сохраняет, применяет автозапуск и тему |
| `dismiss_notice(id)` | `str` | Скрывает плашку; постоянную — пока её поломка не пройдёт и не появится снова |
| `open_url(url)` | `https://…` | Открывает в браузере пользователя |
| `open_path(kind)` | `"logs" \| "data" \| "lists"` | Открывает папку в Проводнике |
| `copy_text(text)` | `str` | Кладёт текст в буфер обмена |
| `relaunch_admin()` | — | Перезапуск с правами администратора |
| `app_restart()` | — | После самообновления или отката Лазейки: запустить exe с `--replace` (дождётся выхода этого) и выйти |
| `hide_window()` / `quit_app()` | — | Свернуть в трей / выйти полностью |
| `zapret_start()` / `zapret_stop()` / `zapret_restart()` | — | Управление обходом |
| `zapret_set_strategy(id)` | `str` | Выбрать стратегию (перезапустит, если работает) |
| `zapret_set_game_filter(mode, tcp, udp)` | `str, str, str` | Ошибки валидации — в `errors.tcp/udp` |
| `zapret_set_ipset(mode)` | `"none" \| "loaded" \| "any"` | Режим IPSet |
| `zapret_update_ipset()` | — | Скачать свежий список IP; синхронно, `{ ok, message }` |
| `zapret_set_mode(mode)` | `"app" \| "service"` | Переключить на службу Windows и обратно |
| `zapret_check()` | — | Быстрая проверка доступности (фоном) |
| `zapret_test_start(kind, ids)` | `"standard" \| "dpi"`, `null \| [id]` | Подбор стратегии (фоном) |
| `zapret_test_cancel()` | — | Остановить подбор |
| `zapret_fix_conflict(id)` | `str` | Устранить конфликт |
| `lists_get()` | — | `{ "lists": [ {"id", "title", "hint", "text", "editable"} ] }` |
| `lists_save(id, text)` | `str, str` | Сохранить пользовательский список. Записи приводятся к виду winws (домен без схемы, пути и порта, кириллица — в punycode; IP — адрес, подсеть или диапазон); непонятные строки — `{ok:false, error:"Не похоже на домен — строка 2: «…»"}`, ничего не записано. Во время подбора — отказ |
| `fakes_get()` / `fakes_set(slot, name)` | `"discord" \| "game"`, `str` | `{ files, discord, game }` — активные фейки (для опытных); `fakes_set` перезапускает работающий обход с новым фейком |
| `hosts_check()` / `hosts_apply()` | — | `{ up_to_date, missing, conflicts, total, text }` / `{ added, disabled, backup }` |
| `tg_start()` / `tg_stop()` / `tg_restart()` | — | Управление прокси |
| `tg_open_in_telegram()` / `tg_copy_link()` | — | Подключить Telegram Desktop. Если прокси как раз включается (`tg_start`), ждёт включения; прокси не работает — `{ok:false}` с причиной, ссылка не открывается |
| `tg_save_settings(values)` | `tg_settings` | Ошибки — в `errors`; `host` — только IPv4 (`0.0.0.0` — все адреса). Ядро прокси не загрузилось — `{ok:false}` с причиной |
| `tg_regen_secret()` | — | Новый ключ (ссылку в Telegram нужно будет обновить) |
| `tg_test()` | — | Проверка маршрутов до Telegram (фоном) |
| `tg_close_original()` | — | Закрыть оригинальный TG WS Proxy, если он занимает порт (кнопка в плашке) |
| `diag_run()` / `diag_fix(id)` | — | Диагностика |
| `discord_clear_cache()` | — | Очистка кэша Discord: `{ok, message}` — отчёт через «; » («Discord закрыт; Discord: очищен «Cache»», «…не удалось удалить «Cache»», «Discord не найден»); пустой — папок кэша нет, чистить нечего |
| `updates_check()` | — | Проверить сейчас |
| `updates_install(id)` / `updates_skip(id)` / `updates_rollback(id)` | `"zapret" \| "tgws" \| "app" \| "vpncore" \| "vpnxray"` | Только по нажатию. Итог (`done`, `rolled_back` или `error`) приходит уведомлением, когда задача закончилась. Откат — состояние `rolling_back` без этапов и хешей; после него у пункта снова видны «Установить» и «Пропустить» |

## Версия 1.1 — дополнения

### Новые поля `get_state()`

```jsonc
{
  "zapret": {
    // «Найти и включить»: проверка → если не открывается, быстрый перебор лидеров → включение лучшей
    "fix": {
      "running": false,
      "stage": "check",          // check | pick | apply | verify | done | failed | null
      "message": "Проверяем, открываются ли Discord и YouTube…",
      "current": null,           // id стратегии, которую пробуем сейчас
      "tried": ["general (ALT2)"],
      "found": "general (ALT5)", // какая стратегия заработала (null — ни одна)
      "previous": "general",     // что было до — для «Вернуть прежнюю»
      "results": [ { "id": "discord", "label": "Discord", "ok": true, "detail": "3/3" } ],
      "finished_at": 1760466300.0
    },
    // Сторож: фоновая проверка, пока обход включён
    "watchdog": {
      "mode": "ask",             // ask — сообщить и предложить; auto — чинить самому; off
      "last_at": 1760466000.0,
      "last_ok": true,
      "failing": [],             // ["YouTube"] — что перестало открываться
      "vpn": false               // трафик идёт через VPN — сторож молчит
    },
    "best": { "id": "general (ALT5)", "label": "ALT5", "score": 0.94, "at": 1760466300.0 },  // лучшая по последнему подбору или null
    "scores": { "general (ALT5)": 0.94 }   // результаты последнего подбора по стратегиям
  },
  "tg": {
    "client": {
      "telegram_running": true,  // процесс Telegram Desktop (или форк) запущен
      "connected": false,        // есть живые соединения через прокси
      "stale_key": false,        // Telegram стучится со старым ключом
      "hint": "Telegram запущен, но не использует прокси — нажмите «Подключить Telegram»."
    }
  },
  "tg_settings": { "zapret_sync": true },   // согласовывать zapret с Cloudflare-маршрутами прокси
  "settings": { "watchdog": "ask" },
  "dns": {
    "running": false, "at": null,
    "doh_enabled": false,      // в Windows включён DNS через HTTPS
    "spoofed": ["discord.com"],// домены, которые провайдерский DNS подменяет (пусто — всё честно)
    "providers": [ { "id": "cloudflare", "name": "Cloudflare", "ip": "1.1.1.1", "ok": true, "ms": 23 } ],
    "message": "Провайдер подменяет адреса: discord.com. Включите DNS через HTTPS — …"
  }
}
```

### Новые методы

| Метод | Аргументы | Что делает |
|---|---|---|
| `zapret_fix()` | — | «Найти и включить» (фоном, прогресс — `zapret.fix`) |
| `zapret_fix_revert()` | — | Вернуть стратегию, которая была до «Найти и включить» |
| `dns_check()` | — | Проверить DNS (фоном, результат — `dns`) |
| `dns_open_settings()` | — | Открыть параметры сети Windows, где включается DNS через HTTPS |
| `help_report()` | — | `{ ok, text, copied }` — отчёт для помощи без ключей и имён, уже в буфере обмена |
| `check_site(domain)` | `str` | `{ ok, domain, verdict, advice, can_add }`; verdict: `works` / `blocked` / `dns` / `down` |
| `lists_add_site(domain)` | `str` | Добавить домен в «Мои сайты» |

## Версия 1.1 — VPN рядом с обходом

«Совместимость с VPN»: обход перехватывает пакеты только на прямых подключениях
(Ethernet, Wi-Fi, PPPoE, Hyper-V), а туннели VPN и соединения с сервером VPN не трогает.
Работает для любого VPN: признак — драйвер адаптера (Wintun, WireGuard, TAP, OpenVPN DCO,
VPN-подключения Windows…), а не его имя.

### Состояние `vpn`

```jsonc
"vpn": {
  "compat": true,            // переключатель «Совместимость с VPN» (отдельная кнопка)
  "ask": true,               // спрашивать при включении, если работает VPN
  "known": false,            // про этот VPN уже ответили «больше не спрашивать»
  "active": true,            // работает VPN в интернет
  "full_tunnel": true,       // весь интернет по умолчанию идёт через VPN
  "label": "Incy или Happ",  // как назвать VPN человеку; null, если VPN нет
  "candidates": ["Incy", "Happ"], // программы, которые могут держать этот туннель
  "apps": ["Incy", "Radmin VPN", "Happ"], // все запущенные VPN-программы
  "servers": ["203.0.113.7"],     // серверы VPN — исключены из перехвата (у VPN-прокси — по соединениям ядра)
  "source_ip": true,         // есть прямой выход в интернет: проверки обхода идут мимо VPN
  "at": 1760000000.0,
  "adapters": [              // без петли и системных туннелей IPv6
    {"id": "{2e21…}", "index": 5, "name": "wwan99", "description": "Wintun Tunnel",
     "kind": "tunnel",       // tunnel — обход не трогает; direct — обходит
     "role": "internet",     // у туннелей: internet | lan (Radmin и Hamachi — всегда) | idle; у прямых — ""
     "reason": "туннель VPN", "up": true, "app": null}
  ],
  "overrides": {"{guid}": "direct"},     // поправки человека
  "filter": {                // что применено к работающему обходу
    "mode": "vpn",           // plain — как обычно; vpn — с исключениями; error — не собрался
    "interfaces": [17, 19], "servers": ["203.0.113.7"], "error": null, "at": 1760000000.0
  },
  "routes": {                // «что куда идёт»; null — ещё не проверяли
    "running": false, "at": 1760000000.0, "full_tunnel": true, "checked_direct": true,
    "error": false,
    "items": [
      {"id": "discord",  "label": "Discord",         "via": "vpn"},
      {"id": "youtube",  "label": "YouTube",         "via": "direct"},
      {"id": "telegram", "label": "Telegram-прокси", "via": "vpn"},
      {"id": "other",    "label": "Остальные сайты", "via": "vpn"}
    ]
  }
}
```

`via`: `vpn` — через VPN (обход не участвует); `direct` — мимо VPN (Discord и YouTube
обрабатывает обход); `blocked` — идёт мимо VPN и без обхода не открывается; `unknown` —
определить не удалось. Определяется по адресу, с которого сайт видит запрос, поэтому
работает и для VPN с правилами внутри программы.

Флаг `direct` у `zapret.check`, `zapret.fix` и `zapret.test`: проверка шла мимо VPN —
показать «проверено напрямую, мимо VPN». `zapret.watchdog.vpn: true` — сторож молчит,
потому что Discord и YouTube идут через VPN.

### Методы

| Метод | Ответ | Что делает |
|---|---|---|
| `vpn_preflight(component)` | `{ok, ask, component, compat, vpn}` | Перед включением `"zapret"` или `"tg"`. `ask: true` — показать окно «Работает VPN»; проверка маршрутов уже запущена (смотреть `vpn.routes`). Страница ждёт ответа не дольше 15 с: не ответил или отказал — тост с причиной и включение без окна |
| `vpn_probe()` | `{ok}` | Запустить проверку «что куда идёт» |
| `vpn_answer(remember, compat)` | `{ok}` | Ответ в окне: запомнить VPN и/или включить совместимость |
| `zapret_start(quiet)` | `{ok}` | `quiet: true` — после окна: без повторного уведомления про VPN |
| `vpn_set_compat(on)` | `{ok, message}` | Переключатель; работающий обход перезапускается с новым фильтром |
| `vpn_set_ask(on)` | `{ok}` | «Спрашивать при включении» |
| `vpn_forget()` | `{ok, message}` | Снова спрашивать про все VPN |
| `vpn_set_override(id, kind)` | `{ok}` | `kind`: `"direct"`, `"tunnel"` или `null` (автоматически) |

Уведомления: при подключении VPN во время работы обхода — `info` с действием
`{page: "zapret"}`; если совместимость выключена — постоянная плашка `compat-off` (`warn`) с действием
`{call: "vpn_set_compat", args: [true]}`: висит, пока VPN подключён, совместимость выключена и обход работает.

#### Уточнения после ревью

- `vpn.mode`: `"tunnel"` — VPN через туннель (адаптер), `"proxy"` — VPN-программа в режиме
  системного прокси (Happ, Hiddify, v2rayN часто работают так по умолчанию), `null` — VPN нет.
  `vpn.proxy` — адрес этого прокси (например `http://127.0.0.1:10808`). В режиме прокси
  туннеля нет, перехват обхода ничего не исключает, но окно «Работает VPN» всё равно
  показывается: браузер и Discord ходят через прокси.
- `vpn.routes.mode` (`tunnel` | `proxy`), `vpn.routes.checked_vpn` и `checked_direct` —
  удалось ли получить эталоны «через VPN» и «напрямую». Если нет, часть строк будет `unknown`.
- Под таблицей «Что куда идёт» всегда мелкая сноска: «Определено проверочными запросами
  Лазейки. Если в VPN есть правила для отдельных программ, у них маршрут может отличаться».
- Служба Windows и совместимость: фильтр службы собирает Лазейка. Если обход работает как
  служба, совместимость включена и автозапуск Лазейки выключен — подсказка в карточке
  совместимости: «Включите автозапуск Лазейки: после перезагрузки она проверит, не поменялись
  ли сетевые подключения, и обновит фильтр службы».
- `vpn.unseparable`: работающие VPN, которые умеют обходиться без отдельного адаптера (ExpressVPN с
  Lightway Turbo, AdGuard VPN без WinTun). «Работающие» — их процесс держит соединения с адреса прямого
  подключения: служба, которая просто висит в фоне, в список не попадает. Если туннеля не видно, а список
  не пуст, — предупреждение: отделить их трафик Лазейка не может, совместимость не поможет.
- Роль `internet` у туннеля — только с доказательством: через него идут проверочные адреса и при этом он
  перебивает существующий прямой маршрут по умолчанию либо VPN выводит свой сервер из туннеля (маршрут /32
  через прямой шлюз, эндпоинт WireGuard). Прямой маршрут пропал (Wi-Fi переподключается, сон) — туннель,
  который уже был VPN, им и остаётся, а новый роль не получает: пропажа прямого маршрута — не «подключился
  VPN». Radmin VPN и Hamachi — всегда `lan`, даже с маршрутом по умолчанию (у Radmin — через 26.0.0.1).
- Уведомление «Обход его не трогает: интерфейс и сервер VPN исключены» — только когда обход работает с
  фильтром, собранным под этот VPN (`filter.mode: "vpn"`), и «сервер» — только если он найден и исключён.
  Фильтр не собрался — уведомления нет, говорит плашка `zapret-vpnfilter`. VPN в режиме системного прокси —
  своё уведомление: исключён ли сервер или определить его не удалось.

## Версия 1.1 — Microsoft Defender

Против ложного срабатывания Defender на драйвер WinDivert. В состоянии:

```jsonc
"defender": {
  "checked": true,       // проверка уже выполнялась
  "running": false,      // идёт проверка
  "present": true,       // Defender установлен
  "active": true,        // включена защита в реальном времени
  "excluded": false,     // файлы Лазейки уже в исключениях Defender
  "at": 1760000000.0
}
```

Методы:

| Метод | Что делает |
|---|---|
| `defender_check()` | Фоном узнаёт `present` / `active` / `excluded` (результат — в `defender`) |
| `defender_exclude()` | Добавляет папки и файлы Лазейки в доверенные Defender (нужны права администратора); по успеху чинит пакет, если драйвер был удалён |

Кнопку «Добавить в исключения Defender» ядро само показывает постоянной плашкой `defender` (её можно скрыть),
когда антивирус реально удалял файлы (`defender` активен и `excluded: false`). Для проактивного сценария
страница может вызвать `defender_check()` и, если `active && excluded === false`, предложить
`defender_exclude()`. Текст для человека: это ложное срабатывание, добавляются только файлы
Лазейки, остальное Defender по-прежнему проверяет.

Страховка связи: после любого запуска winws Лазейкой (включение, перезапуск, смена стратегии и фильтров,
подбор, сон, перестройка под сеть, служба) ядро проверяет, открывается ли хоть один проверочный адрес. Нет —
выключает обход и проверяет без него; связь есть — включает снова и, если связи опять нет, выключает:
плашка `zapret-guard-off` с «Включить снова» (`{call: "zapret_start"}`). Без обхода связи нет — дело не в нём:
обход включается обратно, плашка `zapret-guard` говорит, что интернета нет и без него (а если обход не включился —
`zapret-down`). Отдельных полей не требует.

## Версия 1.1 — самообновление Лазейки

В `updates.items` добавлен третий компонент с `id: "app"` (title «Лазейка», subtitle
`wxsqseen/Lazeyka`) — ровно той же формы, что `zapret` и `tgws`, поэтому страница обновлений
рисует его тем же кодом. Отличия для текста:
- проверка — по SHA-256 из релиза на GitHub (ассет `Lazeyka.exe`);
- после установки нужен **перезапуск** (новый exe встаёт на место старого, сработает со
  следующего запуска); сообщение в `message`/`done` это говорит;
- `can_rollback: true`, пока есть сохранённая прежняя версия (`settings.updates.app_backup`). До перезапуска
  это скрытый `Lazeyka.exe.old` рядом с exe, при запуске новой версии он переезжает в `backups` папки данных
  (`Lazeyka-previous.exe`) — рядом с exe ничего не остаётся;
  откат возвращает её;
- `install`/`rollback` требуют прав администратора и работают только в собранном приложении
  (из исходников самообновление недоступно);
- после установки или отката до перезапуска `restart: true`, `available: false`, в счётчик и плашку `update:…`
  пункт не входит, повторная установка — отказ; вместо них постоянная плашка `app-restart` с
  `{call: "app_restart"}`;
- копия для отката относится к своему exe (`settings.updates.app_backup_for`): у копии в Program Files и exe в
  «Загрузках» папка данных общая, а откатывать каждый должен свою; копия для автозапуска в Program Files получает
  тот же проверенный exe и `version.txt`;
- новая версия должна быть новее работающей, файл — из `https://github.com/wxsqseen/Lazeyka/releases/download/`.

Методы прежние: `updates_install("app")`, `updates_rollback("app")`, `updates_skip("app")`, плюс `app_restart()`.

## Версия 1.2 — свой VPN

Встроенный клиент своего VPN-сервера: ссылки `vless://`, `vmess://`, `ss://`, `trojan://`, `hysteria2://`,
`tuic://` и другие, а также подписки. Ядро — sing-box, помощник для того, чего sing-box не умеет (XHTTP, mKCP, ML-KEM…), —
Xray. Оба запускаются отдельными процессами, как winws. Устройство — `docs/vpnclient-plan.md`.

### Состояние `vpnclient`

Эталон — `app/ui/mock-vpnclient-state.json`: его грузит `mock-vpnclient.js`, а
`tests/test_vpnclient_contract.py` сверяет с ним ключи `get_state()["vpnclient"]`. Новое поле сначала
добавляется в эталон. Ниже то, что из эталона не видно.

- `available: false` — клиент не собрался при запуске Лазейки; причина — в `unavailable_reason`, остальные
  поля — заглушка той же формы.
- `cores["sing-box" | "xray"]` — единственный источник хода установки ядер. В exe ядер нет (с 2026-10-18): Лазейка
  скачивает их с GitHub сразу при запуске (с правами администратора) и обновляет сама. `state`: `idle` |
  `downloading` | `verifying` | `installing` | `error`. Поля:
  - `version` — активная версия (с неё начнётся следующее подключение); `in_use` — версия работающего ядра или
    `null`; `in_use` ≠ `version` — «новая заработает при следующем подключении»;
  - `auto_updated` — активную версию поставило автообновление;
  - `installed: false` и `state` не `idle` — первая подкачка: «Готовим ядро VPN: 45 %», «Включить» её дождётся;
    `installed: true` и `state` не `idle` — рядом ставится обновление, строку состояния и кнопку оно не занимает;
  - `state: "error"` при `installed: false` — подкачка не вышла: причина — в `message`, следующая попытка —
    `retry_at` (unix-время, повторы через 1, 5, 15 минут, дальше раз в час). Кнопка «Скачать ещё раз» —
    `vpnclient_core_install(name)`; её же несёт постоянная плашка `vpn-core:<ядро>` (без уведомлений);
  - `note` — итог автообновления для «Обновлений» и карточки ядра («Обновлено автоматически до 1.15.0…»,
    «Версия … не приняла ваши настройки… Осталась …»), иначе `null`;
  - `needed: false` у Xray — ни одному серверу помощник не нужен (скачивается он всё равно, при запуске).
- `settings.core_auto_update` — обновлять ядра автоматически (по умолчанию `true`); сохраняется
  `vpnclient_save_settings`, перезапуска не требует.
- `status`: `stopped` | `starting` | `running` | `stopping` | `error`. `verified: true` — проверочный запрос
  через сервер прошёл, `exit` — адрес и страна выхода. `running` и `verified: false` — ядро работает, а через
  сервер ничего не открывается: показать `error`.
- `error_kind`: `port` | `admin` | `conflict` | `timeout` | `tls` | `auth` | `clock` | `unsupported` | `core` |
  `other` — по нему страница выбирает подсказку («сверьте часы», «порт занят»…).
- `diagnosis: {side, code, text, advice} | null` — почему не вышло и чья это сторона (только вместе с `error`):
  при включении, падении ядра и когда ядро работает, а выход не проверен. `side`: `you` (компьютер или сеть
  человека) | `isp` (интернет-провайдер: блокировка, подмена) | `provider` (VPN-провайдер: сервер, подписка) |
  `lazeyka` (наша ошибка) | `unknown` (не ясно — `text` честно называет обе версии и как проверить). `text` —
  почему, `advice` — что сделать. Страница показывает его в карточке «Подключение» («Почему», «Чья сторона»,
  «Что сделать»); есть `diagnosis` — общий совет по `error_kind` не нужен. У отказов самой Лазейки, текст
  которых уже говорит, что делать (включать нечего, ядро не скачалось), — `null`. При «выход не проверен»
  `error` = `diagnosis.text`. Коды — таблица ниже.
- `servers[].latency.reason` — то же `{side, code, text, advice}` у «нет ответа» после проверки задержки
  (`null`, пока ответ есть или причину не определили). Причина сохраняется вместе с задержкой. Код
  `killswitch` — сервер не проверяли (kill switch), это не «нет ответа»: показывать «не проверено».
- `mode`: `tun` (весь компьютер), `proxy` (системный прокси), `local` (только порт `listen`, системный прокси
  не меняется). Это выбранный режим: сменили его, пока VPN включён или включается, — VPN переподключится в нём
  (ход — в `status`). `listen` есть только в `proxy` и `local` — адрес для программ на этом ПК,
  `127.0.0.1:<порт>` (и с «Пускать устройства из сети»: ядро тогда слушает и сеть — только с логином и
  паролем; их нет — слушает только этот ПК, плашка `vpn-local-auth`).
- `config_servers: [id] | null` — серверы работающего конфига, как ядро их получило (`session.plan.servers`:
  без серверов, чей адрес не получен, и только выбранное, если конфиг со всей подпиской не собрался). Выбор
  такого сервера — без переподключения, тест скорости — только через них. `null` — сеанса нет (VPN выключен,
  включается или не включился). Список не меняется от переключений внутри конфига; страница берёт его, а не
  повторяет правило `manager._selection`.
- `settings.fingerprint` — общий TLS-отпечаток для серверов без своего; отпечаток из ссылки (`fp=`) важнее.
- `selected.kind`: `server` или `auto` (id вида `auto:<группа|подписка>`). У `auto` в `actual` — сервер,
  который ядро выбрало сейчас.
- `stats.up` и `stats.down` — байты за сеанс, `up_rate`, `down_rate` и `history` — байты в секунду;
  точка `history` — `[время, отдача, загрузка]`.
- `servers[].supported: false` — сервер не собрать ни одним ядром, причина — в `reason`. У работающих `reason`
  поясняет выбор ядра («через помощник Xray: XHTTP»). `warnings` — что ядро проигнорирует.
- `subscriptions[]`: без адреса подписки и HWID — это секреты. Имена и тексты провайдера проходят через фильтр
  секретов; `support_url`/`web_page_url` с секретом подписки в адресе (часто это сама подписка) приходят как
  `"hidden"` — их открывает `vpnclient_open_link`. `user_agent` заполнен только у
  `ua_preset: "custom"`; `probe: null` — «Проверить расширенный формат» ещё не нажимали, иначе
  `{running, ua_preset, text}`.
- `import.offer` — подсказка после неудачного или неполного импорта: `{kind, text, options, sub}`.
  `kind`: `ua` (провайдер не отдал подписку этому приложению), `hwid` (просит привязку устройства),
  `html` (вместо подписки пришла страница), `stub` (заглушка провайдера), `extended` (у подписки может быть
  формат с маршрутами — проверить), `switch` (расширенный формат нашёлся — переключить). `options` — список
  строк: пресеты UA (`v2rayn`, `happ`, `incy`…) или `"hwid"`. Повтор с другим пресетом —
  `vpnclient_import(null, preset)`, с HWID — `vpnclient_import(null, null, true)`. Повторять текст из поля
  импорта можно только по предложению, с которым закончился этот импорт; по `switch` (и по предложению
  импорта не из поля) — `vpnclient_sub_set(sub, {ua_preset})`, затем `vpnclient_sub_update(sub)`.
  `vpnclient_sub_set` снимает предложение и `probe` этой подписки: они были для прежних свойств.
- `routing.bypass`: `direct` — сайты обхода (Discord, YouTube…) идут мимо сервера и обрабатываются обходом;
  `proxy` — через сервер. Почему так — в `bypass_note`. Переключается само по состоянию обхода.
- `settings.local_password_set` — пароль локального порта задан; сам пароль странице не отдаётся.
- `deeplink_request: {token, kind, summary}` — открыта ссылка `lazeyka://import/<…>`, нужно окно «Добавить …?».
  `kind`: `subscription` (в `summary` — хост подписки) или `links` («Ссылок на серверы: N» — по тому же разбору,
  что импорт). Текста ссылки в состоянии нет. Ответ — `vpnclient_deeplink_confirm(token, accept)`. Другие
  ссылки `lazeyka://`, повреждённые и без серверов окна не открывают — уведомление «Ссылка lazeyka:// не подошла».
- `conflict: {kind, label, text}` — с чем свой VPN не уживётся: `tunnel` (работает другой VPN-туннель — или
  интернет идёт через чужой туннель, а «VPN в интернет» не доказан, `vpn.Snapshot.unproven`: тогда `text` —
  «Интернет сейчас идёт через …», `label` — программа по драйверу или «VPN «<имя адаптера>»»),
  `proxy` (будет заменён чужой системный прокси), `uac_user` (Лазейка запущена от другой учётной записи и не
  может менять её прокси). У `tunnel` бывает `proxy_denied` — почему режим «Системный прокси» здесь недоступен
  (та же чужая учётная запись): тогда `text` не советует «включите Лазейку как системный прокси», а страница не
  предлагает кнопок, которые откажут. `proxy_denied` и `text` у `uac_user` — короткая причина без совета
  («Системный прокси здесь недоступен: Лазейка запущена от другой учётной записи»): что делать, говорит страница.
  `uac_user` менеджер запоминает в `vpnclient_preflight` и держит до следующего; страница показывает его, только
  пока выбран режим `proxy`. Заголовок у окна перед включением и у плашки страницы — один.

### Причины «нет ответа» (`diagnosis`, `servers[].latency.reason`)

Определяет `diagnose.explain` по фактам, которые менеджер собирает только по отказу (не по тику): контрольный
сайт напрямую (`ya.ru`, затем `1.1.1.1`), прямые пробы до сервера мимо ядра (TCP, затем рукопожатие TLS с SNI
сервера — у TLS и REALITY), ответы DNS через HTTPS и DNS сети, задержки соседей по подписке (эта проверка или не
старше 15 минут), срок и трафик подписки, флаг лимита устройств из заголовков подписки, часы (Date ответа
напрямую — для VMess и REALITY), что сказал журнал ядра. Проверка задержки пробует напрямую не больше 16
молчащих серверов; «выход не проверен» повторяется каждые 15 с, а причина пересчитывается не чаще раза в минуту.
Код для страницы — короткая метка (`texts.js`, `VPNC_REASONS`), полный текст — во всплывающей подсказке.

| code | side | Когда |
|---|---|---|
| `no_internet` | you | Ни один контрольный сайт напрямую не открывается |
| `dns_down` | you | Адрес сервера не получен: не отвечают ни DNS через HTTPS, ни DNS сети |
| `clock` | you | VMess/REALITY и часы расходятся с Date ответа больше чем на 90 с (или ядро пишет про время) |
| `conflict`, `admin`, `port_busy` | you | Ядро не запустилось: мешает другой VPN; Windows не дала создать адаптер TUN («доступ запрещён»), хотя права администратора есть — драйвер Wintun занят другим VPN, его блокирует антивирус или политика (у `admin` при этом `error_kind: conflict`: помогает то же — режим «Системный прокси»); порт занят |
| `dns_blocked` | isp | DNS через HTTPS не отвечает, а DNS сети имя знает |
| `dpi` | isp | TCP до сервера есть, рукопожатие TLS обрывается или виснет (или TCP сбрасывают сразу) |
| `udp_blocked` | isp | Сервер на UDP (Hysteria2, TUIC, WireGuard, mKCP) молчит, другие на UDP тоже, а на TCP отвечают |
| `dns_missing` | provider | DNS через HTTPS ответил: такого имени нет (NXDOMAIN) или у имени нет ни одного адреса |
| `ipv6_only` | you | У имени нет адреса IPv4, а IPv6 не спрашивали: в «Подробнее» — «Только IPv4» |
| `port_closed` | provider | TCP до сервера — отказ (порт закрыт) |
| `server_down` | provider | Сервер молчит, а соседи по подписке отвечают |
| `keys_outdated` | provider | Путь свободен (TCP и TLS проходят), ядро пишет об отказе TLS/REALITY |
| `auth_rejected` | provider | Ядро пишет, что сервер не принял ключ |
| `bad_params` | provider | Ядро не запустилось: параметры сервера (ключ REALITY, пароль) не разбираются |
| `sub_expired`, `traffic_out` | provider | По userinfo подписки срок прошёл или трафик кончился |
| `device_limit` | provider | Подписка ответила `x-hwid-max-devices-reached` |
| `no_exit` | provider | Сервер на связи (TCP и TLS проходят), журнал молчит, а выхода нет |
| `core_failed`, `helper_failed` | lazeyka | Ядро или помощник Xray не запустились, упали, не приняли конфигурацию |
| `unsupported` | lazeyka | Конфиг для сервера не собрать |
| `killswitch` | lazeyka | Сервер не проверяли: kill switch не выпускает временное ядро замера |
| `all_down` | unknown | Молчит вся подписка, интернет есть: блокирует интернет-провайдер или сбой у VPN-провайдера |
| `tcp_timeout` | unknown | TCP до сервера молчит, сравнить не с кем |
| `udp_silent` | unknown | Сервер на UDP молчит, сравнить не с кем |
| `dns_retry` | unknown | Адрес не получен, а сейчас DNS через HTTPS отвечает |
| `dns_error` | unknown | DNS через HTTPS ответил ошибкой (SERVFAIL, REFUSED) — об имени это ничего не говорит |
| `unknown` | unknown | Фактов не хватило |

### Рядом с прежними полями

- `vpn.own: {active, mode}` — работает ли свой VPN. Чужой VPN описывают прежние поля `vpn`; свой адаптер
  помечен `adapters[].own: true` и в перехват обхода не попадает. `vpn.filter.mode: "own"` — фильтр обхода
  собран под свой VPN.
- `settings.vpnclient_on_start` — включать свой VPN при запуске Лазейки; `settings.ui_scale` — масштаб
  интерфейса 0.8–1.5. Сохраняются через `save_settings`.
- `updates.items`: `vpncore` («Ядро VPN (sing-box)») и `vpnxray` («Помощник Xray») — той же формы, что `zapret`,
  `tgws` и `app`; ход установки берётся из `vpnclient.cores`. `latest` — самый новый стабильный релиз любой серии.
  В `state: "idle"` у них бывает `message` — пояснение (итог автообновления, «поставлена автоматически»): показать
  спокойной плашкой. При автообновлении ядра в `updates.count` не входят; версия, которая не подошла, — тоже.
  `can_rollback` — есть прежняя установленная версия (или закреплённая старше текущей); откат помечает текущую,
  и автообновление её больше не поставит.
- `get_logs(after_id, "vpn")` — журнал своего VPN; адреса подписок, ключи и пароли в нём заменены на `<секрет>`.

### Методы

Все возвращают ответ действия. Долгие (импорт, обновление подписок, задержка, скорость, запуск) возвращаются
сразу, ход — в состоянии.

| Метод | Аргументы | Что делает |
|---|---|---|
| `vpnclient_import(text, ua_preset, hwid)` | `str \| null, str \| null, bool` | Ссылки, подписка, base64, JSON Xray; `text: null` — повторить прошлое добавление. На sing-box JSON и Clash YAML — понятный отказ с `offer` |
| `vpnclient_import_file()` | — | Окно выбора файла: `.conf/.json/.txt` или картинка с QR; отмена — `{ok, cancelled: true}` |
| `vpnclient_import_qr(source)` | `"screen" \| "file"` | QR со снимка экрана или из картинки |
| `vpnclient_sub_update(id)` | `str \| null` | Обновить подписку; `null` — все |
| `vpnclient_sub_set(id, values)` | `str, {name, ua_preset, ua, hwid, update_hours, dns, mtu, provider_routes}` | Свойства подписки; ошибки — в `errors`. `ua` проверяется, только если итоговый пресет — `custom` (у других `null` и `""` — не ошибка); `dns` — `null` (как в «Подробнее»), `auto`, имя резолвера или `https://…`; `mtu` — `null` или 576–9000. Смена `dns`, `mtu`, `provider_routes` перезапускает работающий VPN |
| `vpnclient_sub_probe(id)` | `str` | «Проверить расширенный формат»: ход — в `subscriptions[].probe`, итог — в `import.offer` |
| `vpnclient_sub_remove(id)` | `str` | Удалить подписку с её серверами |
| `vpnclient_server_rename(id, name)` / `vpnclient_server_remove(id)` | `str` | |
| `vpnclient_copy_link(id)` | `str` | Ссылка сервера в буфер обмена (явная кнопка: странице ссылка не отдаётся) |
| `vpnclient_open_link(sub_id, kind)` | `str, "support" \| "page"` | Открыть ссылку провайдера в браузере; нужна, когда в состоянии вместо адреса `"hidden"` |
| `vpnclient_qr(id)` | `str` (сервер или подписка) | `{ok, png}` — data URL картинки QR |
| `vpnclient_select(id)` | `str` | Сервер или `auto:<группа\|подписка>`; на работающем VPN — без перезапуска, если сервер в конфиге. В конфиге (`manager._selection`) — выбранный при включении сервер (у «Самого быстрого» — серверы группы) и остальные поддерживаемые серверы его подписки по порядку списка, всего не больше 16; какие именно вошли — `config_servers` в снимке |
| `vpnclient_preflight()` | — | `{ok, ask, conflict}` перед включением; `ask: true` — показать окно с `conflict.text`. Оба факта сразу: чужой туннель с `proxy_denied`; `uac_user` важнее чужого системного прокси. Страница ждёт ответа не дольше 15 с: не ответил или отказал — тост с причиной и включение без окна |
| `vpnclient_start(quiet)` | `bool` | Включить (нужны права администратора); `quiet: true` — после окна конфликта |
| `vpnclient_stop()` / `vpnclient_restart()` | — | |
| `vpnclient_set_mode(mode)` | `"tun" \| "proxy" \| "local"` | Не фоном: `{ok: true}` — режим уже сменён (следующее включение — в нём), отказ — режим прежний (`proxy` недоступен под чужой учётной записью UAC). Работающий VPN переподключается фоном, ход — в `status`. Без сеанса и не в `tun` снимает kill switch, оставшийся после падения, — и когда режим сменили посреди включения, а оно не удалось (проверка — в очереди за включением; вернули `tun` раньше — фильтры остаются) |
| `vpnclient_latency(ids)` | `[id] \| null` | Задержка фоном; `null` — все серверы |
| `vpnclient_speedtest(id)` | `str \| null` | Скорость через включённый VPN (`null` — текущий сервер), итог — в `speed` и `servers[].speed` |
| `vpnclient_save_settings(values)` | ключи `routing` и `settings` | Ошибки — в `errors`; `local_user` и `local_password` — отдельные поля формы: пустое — «не менять», обязательны, только когда нужен вход по паролю (`local_auth` или `allow_lan`); тот же логин и пароль — не изменение (VPN не перезапускается). Смена `kill_switch` применяется и без сеанса (снимает фильтры после падения) |
| `vpnclient_running_apps()` | — | `{ok, apps: [{name, path}]}` — выбор программ для маршрутов |
| `vpnclient_rules_update()` | — | Скачать или обновить списки для маршрутов |
| `vpnclient_profile_import(text)` / `vpnclient_profile_set(id, active)` / `vpnclient_profile_remove(id)` | | Профили маршрутизации; активен один |
| `vpnclient_core_install(name)` | `"sing-box" \| "xray"` | Скачать с GitHub и поставить закреплённую версию ядра («Скачать», «Скачать ещё раз»); ход — в `cores` |
| `vpnclient_backup_export(password)` / `vpnclient_backup_import(password)` | `str` | Резервная копия профилей (scrypt + AES-GCM) через окно сохранения или открытия |
| `vpnclient_deeplink_confirm(token, accept)` | `str, bool` | Ответ на окно ссылки `lazeyka://` |
| `vpnclient_help()` | — | `{ok, items: [{id, level, title, text, fix}]}` — находки панели «Свой VPN не подключается» |
| `vpnclient_proxy_fix()` | — | Кнопка находки: вернуть свой прокси после аварии или выключить чужой мёртвый |
| `vpnclient_open_adapters()` | — | Открыть «Сетевые подключения» Windows (DNS адаптера человек правит сам) |

Уведомления (временные) — только ответы на действия человека и отчёты о том, что Лазейка сама сменила его
выбор: сервер перестал отвечать и выбран самый быстрый (`info`, без уведомления Windows); выбранный сервер пропал
из подписки (с действием `{label: "Переключиться", call: "vpnclient_select", args: [id]}`); соединение с ним
прервалось, а живого соседа в работающем конфиге нет — выбрана замена (предложенная при обновлении подписки, иначе
«Самый быстрый» подписки), VPN переподключается (`info`); итог обновления подписки по кнопке. Поломки, найденные
без нажатия, — постоянные плашки `vpn-*` (список ниже).

## Постоянные плашки (решение владельца 2026-10-18)

О поломке, которую Лазейка нашла сама (не в ответ на нажатие), — только плашка в окне: ни временного
уведомления, ни уведомления Windows из трея. Плашка висит, пока проблема есть, и исчезает сама, когда всё снова
работает. Ответы на нажатия («Подписка обновлена», «Не удалось: …») остаются временными уведомлениями.

- В `notices` у плашки `persistent: true` и `page`. Главная показывает все `notices`; остальные страницы — под
  заголовком только постоянные плашки со своим `page` (вставляет оболочка `app.js`, страницы о них не знают).
- Порядок: прежние постоянные (`admin`, `update:…`, `app-restart`, `conflict:…`, `tgws-original`, `defender`), затем плашки
  (сначала `error`, потом `warn`, `info`; при равенстве — давние), затем временные.
- Крестик (`dismiss_notice`) прячет плашку, пока её поломка не пройдёт; вернётся поломка — вернётся и плашка.
  Повтор той же поломки (сторож раз в 10 минут) плашку не «воскрешает» и в журнал пишется только при смене текста.
- Значок в трее: видимая плашка `error` — красная точка, `warn` — янтарная; в подсказке строка «Проблема: …».
  Точка раздела в меню слева перекрашивается так же по плашкам со своим `page`.
- Действие `{call: "zapret_start" | "tg_start" | "vpnclient_start"}` страница выполняет через те же окна, что и
  большие кнопки («Работает VPN», «Уже работает другой VPN»), и под теми же ключами занятости. `zapret_fix`,
  `vpnclient_stop`, `vpnclient_restart` и `app_restart` — тоже под ключами кнопок страниц: два нажатия — один вызов.

| id | level | page | Когда ставится | Когда снимается |
|---|---|---|---|---|
| `watchdog` | warn | zapret | Сторож: два сбоя подряд. ask — «X перестал открываться. Найти рабочую стратегию?» с `zapret_fix`; auto — «… подбираем рабочую стратегию.», после неудачного подбора — итог с `zapret_fix`; при тех же стратегии, фильтрах, пакете и сети подбор сам не повторяется | Удачная проверка (сторожа или «Проверить»), удачный «Найти и включить», обход выключен, сторож выключен, трафик идёт через VPN |
| `zapret-guard` | warn/error | zapret | warn — интернета нет и без обхода, обход снова включён; error — после запуска обхода пропал интернет, а выключить обход не удалось (`zapret_stop`) | Проверочный сайт открылся (перепроверка раз в минуту, пока плашка висит, — и при выключенном стороже; или сам сторож), «Проверить» показала, что хоть что-то открывается, обход выключен |
| `zapret-guard-off` | error | zapret | Обход выключен сам: с ним дважды пропадал интернет, без него связь есть (`zapret_start`) | Обход снова работает (включили по кнопке или вручную); человек нажал «Выключить» или «Перезапустить» |
| `zapret-down` | warn/error | — | winws упал: «перезапускаем» (warn) или «Обход остановился» (error, `zapret_start`); обход не включился при запуске Лазейки, после сна, после проб «Найти и включить» или после перестройки фильтра под сеть или свой VPN | Обход снова работает; человек нажал «Включить», «Выключить» или «Перезапустить»; обход выключен человеком |
| `zapret-vpnfilter` | warn | zapret | Фильтр совместимости с VPN не собрался: рядом с VPN в интернет обход не запущен (повтор сам, через 30 с), рядом с Radmin/Hamachi — работает как обычно | Собрался; обход выключен |
| `zapret-service` | warn | zapret | Служба запускает winws из прежнего пакета, перенастроить её не вышло | Служба перенастроена; режим «служба» выключен |
| `zapret-filter` | warn/error | zapret | Обход не перестроился под новую сеть или свой VPN, но работает по-старому (упал при перестройке — `zapret-down`) | Перестроился; обход выключен |
| `compat-off` | warn | zapret | Подключён чужой VPN, а совместимость выключена (`vpn_set_compat`) | Совместимость включена, VPN отключился, обход выключен |
| `tg-down` | warn/error | — | Telegram-прокси не включился при запуске Лазейки, после сна или смены сети (error, `tg_start`); работал и остановился сам — «перезапускаем» (warn) и одна попытка через 3 с, не вышло или падает снова чаще раза в минуту — «остановился» (error, `tg_start`) | Прокси работает; человек нажал «Включить», «Выключить», «Перезапустить» |
| `tg-core` | error/warn | telegram | Ядро Telegram-прокси не загрузилось при запуске (error); скачанное обновлением не загрузилось или не запустилось — работает встроенное, настройка и папка скачанного убраны (warn) | До перезапуска Лазейки |
| `app-restart` | info | — | Лазейка обновлена или откачена, а работает прежний процесс (`app_restart`) | Перезапуск |
| `settings-broken` | warn | — | `settings.json` был повреждён: восстановлен из `settings.json.bak` или сброшен (повреждённый отложен как `settings.json.broken-<время>`) | До перезапуска Лазейки |
| `data-untrusted` | warn | — | Папке данных нельзя было доверять (владелец, метка, права на папки и программы): содержимое отложено в `<папка>-untrusted-<время>`, настройки, профили и свои списки перенесены, программы ставятся заново | До перезапуска Лазейки |
| `data-path` | warn | zapret | Переносной режим: в пути к папке данных кириллица или пробелы — winws может не запуститься | До перезапуска Лазейки |
| `autostart` | warn | — | Автозапуск включён, но здесь не работает: переносной режим или Лазейка запущена от имени другой учётной записи (`save_settings` с `autostart: false`) | До перезапуска Лазейки |
| `vpnclient-autostart` | warn/error | — | Свой VPN не включился при запуске Лазейки (конфликт или ошибка; `{page: "vpnclient"}`) | VPN включается или работает; человек нажал «Включить», «Выключить», «Перезапустить» |
| `vpnclient-init`, `vpn-store` | error | vpnclient | Свой VPN не подготовлен / профили не прочитаны при запуске | До перезапуска Лазейки |
| `vpnclient-net` | error | vpnclient | Свой VPN не перепроверил подключение после смены сети | Следующая удачная перепроверка |
| `vpn-exit` | warn | vpnclient | Ядро работает, а выход через сервер не проверен (`vpnclient_restart`); в тексте — почему, «Чья сторона: …» и что сделать (`diagnosis`) | Выход проверен; VPN выключен или перезапускается |
| `vpn-crash` | warn/error | — (vpnclient, если kill switch закрыл интернет) | Ядро упало: «перезапускаем» (warn); «Свой VPN остановился» (error, `vpnclient_start` или `vpnclient_stop`, если kill switch держит интернет закрытым); автоматический перезапуск (после падения, правила, маршруты, сеть, настройки, сервер вне конфига, подписка обновилась, а сервер замолчал) не удался: «Свой VPN не перезапустился … Повторим через 30 с / 2 мин / 5 мин» (error, те же действия; повтор — раз в 5 минут до успеха или «Выключить»). Не удался из-за выбора (выбранного сервера или группы нет, их не открыть, а заменить нечем; конфиг для выбранного не собрать) — без «Повторим»: с тем же выбором не удастся никогда, действие `{label: "Выбрать сервер", page: "vpnclient"}` (с закрытым kill switch — по-прежнему `vpnclient_stop`) | VPN снова работает или выключен |
| `vpn-server` | warn | vpnclient | Выбранный сервер не отвечает, а другого живого в подписке нет; в тексте — причина и чья сторона | Сервер ответил, переключились на другой (сами или человек выбрал другой сервер или «Самый быстрый»), VPN выключен |
| `vpn-killswitch` | warn | vpnclient | Kill switch не включился (в том числе не нашёлся адаптер своего VPN — по адресу его подсети); VPN работает без него, прежние фильтры сняты. Или: сменились локальные сети (включили Radmin, Hamachi), а фильтры под них не переставились — прежние фильтры того же TUN работают, не открыты только новые сети; повтор — проверкой здоровья раз в минуту | Включился (переставился); kill switch выключен в настройках; VPN выключен |
| `vpn-local-auth` | warn | vpnclient | Вход по паролю нужен («Пускать устройства из сети» или «Вход по паролю» в режимах прокси), а логина и пароля нет (`local-proxy.json` пропал): без пароля сеть не пускаем — вход только для этого ПК (`{label: "Открыть VPN", page: "vpnclient"}`) | Логин и пароль заданы; вход по паролю выключен; VPN выключен или перезапускается |
| `vpn-sub:<id>` | warn | vpnclient | Подписка не обновилась по расписанию или провайдер сообщает «истекла» (`vpnclient_sub_update`) | Обновилась без замечаний; подписку удалили |
| `vpn-rules` | info/warn | vpnclient | Списки для маршрутов ещё не скачаны (info) / не скачались при включении VPN (warn, `vpnclient_rules_update`) | Скачались; при включении VPN нужные уже на диске или маршрутам списки не нужны («Всё через VPN») |
| `vpn-profile` | warn | vpnclient | Профиль маршрутов не применён при включении | Применился; активного профиля нет |
| `vpn-core:<ядро>` | error | vpnclient | Ядро не скачалось фоновой подкачкой (`vpnclient_core_install`) | Ядро поставлено |
