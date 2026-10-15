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

  // Плашки сверху. level: info | success | warn | error
  "notices": [
    { "id": "update-available", "level": "info", "text": "Доступно обновление zapret 1.10.4",
      "action": { "label": "Открыть", "page": "updates" },  // либо { "label": "...", "call": "имя_метода", "args": [] }
      "dismissible": true }
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
      "error": null,
      "finished_at": 1760466300.0,
      "results": [
        { "id": "general (ALT2)", "label": "ALT2", "ok": 34, "fail": 2, "unsup": 0,
          "ping_ok": 4, "ping_total": 4, "score": 0.94, "started": true,
          "targets": [ { "name": "Discord", "url": "https://discord.com",
                         "http": "ok", "tls12": "ok", "tls13": "fail", "ping": 23 } ] }
          // http/tls12/tls13: ok | fail | unsup | ssl | null(не проверялось); ping: мс или null
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
    "error": null,
    "count": 1,                 // сколько обновлений доступно (бейдж в меню)
    "items": [
      { "id": "zapret", "title": "Стратегии zapret", "subtitle": "Flowseal/zapret-discord-youtube",
        "current": "1.10.3", "latest": "1.10.4", "available": true, "skipped": false,
        "published_at": "2026-10-01T10:00:00Z", "notes": "текст из релиза", "url": "https://github.com/…",
        "state": "idle",        // idle | downloading | verifying | installing | done | error
        "progress": null,       // 0..1 во время скачивания
        "message": null,
        "can_rollback": false }
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
| `dismiss_notice(id)` | `str` | Скрывает плашку |
| `open_url(url)` | `https://…` | Открывает в браузере пользователя |
| `open_path(kind)` | `"logs" \| "data" \| "lists"` | Открывает папку в Проводнике |
| `copy_text(text)` | `str` | Кладёт текст в буфер обмена |
| `relaunch_admin()` | — | Перезапуск с правами администратора |
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
| `lists_save(id, text)` | `str, str` | Сохранить пользовательский список |
| `fakes_get()` / `fakes_set(slot, name)` | `"discord" \| "game"`, `str` | `{ files, discord, game }` — активные фейки (для опытных) |
| `hosts_check()` / `hosts_apply()` | — | `{ up_to_date, missing, conflicts, total, text }` / `{ added, disabled, backup }` |
| `tg_start()` / `tg_stop()` / `tg_restart()` | — | Управление прокси |
| `tg_open_in_telegram()` / `tg_copy_link()` | — | Подключить Telegram Desktop |
| `tg_save_settings(values)` | `tg_settings` | Ошибки — в `errors` |
| `tg_regen_secret()` | — | Новый ключ (ссылку в Telegram нужно будет обновить) |
| `tg_test()` | — | Проверка маршрутов до Telegram (фоном) |
| `tg_close_original()` | — | Закрыть оригинальный TG WS Proxy, если он занимает порт (кнопка в плашке) |
| `diag_run()` / `diag_fix(id)` | — | Диагностика |
| `discord_clear_cache()` | — | Очистка кэша Discord |
| `updates_check()` | — | Проверить сейчас |
| `updates_install(id)` / `updates_skip(id)` / `updates_rollback(id)` | `"zapret" \| "tgws"` | Только по нажатию |

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
  "servers": ["203.0.113.7"],     // серверы VPN — исключены из перехвата
  "source_ip": true,         // есть прямое подключение: проверки обхода идут мимо VPN
  "at": 1760000000.0,
  "adapters": [              // без петли и системных туннелей IPv6
    {"id": "{2e21…}", "index": 5, "name": "wwan99", "description": "Wintun Tunnel",
     "kind": "tunnel",       // tunnel — обход не трогает; direct — обходит
     "role": "internet",     // у туннелей: internet | lan (Radmin, Hamachi…) | idle; у прямых — ""
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
| `vpn_preflight(component)` | `{ok, ask, component, compat, vpn}` | Перед включением `"zapret"` или `"tg"`. `ask: true` — показать окно «Работает VPN»; проверка маршрутов уже запущена (смотреть `vpn.routes`) |
| `vpn_probe()` | `{ok}` | Запустить проверку «что куда идёт» |
| `vpn_answer(remember, compat)` | `{ok}` | Ответ в окне: запомнить VPN и/или включить совместимость |
| `zapret_start(quiet)` | `{ok}` | `quiet: true` — после окна: без повторного уведомления про VPN |
| `vpn_set_compat(on)` | `{ok, message}` | Переключатель; работающий обход перезапускается с новым фильтром |
| `vpn_set_ask(on)` | `{ok}` | «Спрашивать при включении» |
| `vpn_forget()` | `{ok, message}` | Снова спрашивать про все VPN |
| `vpn_set_override(id, kind)` | `{ok}` | `kind`: `"direct"`, `"tunnel"` или `null` (автоматически) |

Уведомления: при подключении VPN во время работы обхода — `info` с действием
`{page: "zapret"}`; если совместимость выключена — `warn` с действием
`{call: "vpn_set_compat", args: [true]}`.

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
- `vpn.unseparable`: запущенные VPN, которые умеют работать без отдельного адаптера (ExpressVPN с
  Lightway Turbo, AdGuard VPN без WinTun). Если туннеля не видно, а список не пуст, — предупреждение:
  отделить их трафик Лазейка не может, совместимость не поможет.

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

Кнопку «Добавить в исключения Defender» ядро само показывает уведомлением, когда антивирус
реально удалял файлы (`defender` активен и `excluded: false`). Для проактивного сценария
страница может вызвать `defender_check()` и, если `active && excluded === false`, предложить
`defender_exclude()`. Текст для человека: это ложное срабатывание, добавляются только файлы
Лазейки, остальное Defender по-прежнему проверяет.

Страховка связи: после включения обхода, если пропал интернет, ядро шлёт `error`-уведомление
с действием `{call: "zapret_stop"}` — отдельных полей не требует.
