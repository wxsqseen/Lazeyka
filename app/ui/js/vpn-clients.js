'use strict';
/*
 * Как пустить Discord и YouTube мимо VPN («раздельное туннелирование»): домены и инструкции.
 * Первая запись — общая инструкция для любого VPN. name сравнивается с vpn.candidates из ядра
 * (без учёта регистра). Пути в интерфейсах собраны по исходникам и строкам самих программ
 * (октябрь 2026); где путь не проверен на живом окне, это сказано в note.
 */
(function (Lz) {
  /* Эти домены стоит пустить мимо VPN: тогда их обрабатывает обход Лазейки. YouTube нужно
     пускать целиком — ссылки на видео привязаны к адресу, и половина «напрямую», половина
     «через VPN» даёт ошибку воспроизведения. */
  Lz.texts.VPN_BYPASS_DOMAINS = [
    'discord.com', 'discord.gg', 'discordapp.com', 'discordapp.net', 'discord.media', 'discordcdn.com',
    'youtube.com', 'youtu.be', 'googlevideo.com', 'ytimg.com', 'ggpht.com', 'youtube-nocookie.com',
    'youtubei.googleapis.com',
  ];

  const VOICE = 'Голос Discord доменом мимо VPN не пустить: адрес голосового сервера приходит не через DNS. '
    + 'Для голоса нужно правило по программе Discord.exe.';
  const TELEGRAM = 'Прокси Telegram ходит наружу из Lazeyka.exe — добавьте и её, если Telegram должен идти мимо VPN.';
  const NO_SPLIT = 'Пока всё идёт через VPN, обход Лазейки для Discord и YouTube не нужен — но и не мешает.';

  Lz.texts.vpnClients = [
    {
      id: 'general',
      name: 'Любой VPN',
      steps: [
        'Откройте настройки VPN-программы.',
        'Найдите «Раздельное туннелирование», «Маршрутизация», «Исключения» или «Приложения в обход VPN».',
        'Лучше всего — правило по программе: Discord.exe (так мимо VPN пойдёт и голос) и Lazeyka.exe (Telegram-прокси).',
        'Для YouTube — домены из списка ниже, целиком: часть «напрямую», часть «через VPN» ломает видео.',
        'Сохраните настройки и переподключите VPN, затем нажмите «Что куда идёт».',
      ],
      note: null,
    },
    {
      id: 'incy', name: 'Incy',
      steps: [
        'Включите режим TUN: правила по приложениям работают только в нём.',
        'Настройки → «Раздельное туннелирование» → «Прокси по приложениям» → «Включить Per-App Proxy».',
        'Режим «В обход VPN» («Выбранные приложения идут напрямую») → «Выберите приложение» → Discord.exe и Lazeyka.exe.',
        'YouTube по доменам — через «Профили маршрутизации» (поле DirectSites: geosite:youtube).',
      ],
      note: 'Путь собран по надписям Incy 3.8, само окно не проверялось — пункты могут называться чуть иначе. '
        + 'Новый профиль маршрутизации заменяет профиль вашего провайдера VPN — если он у вас есть, ограничьтесь '
        + 'правилами по приложениям. Если в Incy включён Kill Switch, проверки обхода мимо VPN он может блокировать.',
    },
    {
      id: 'happ', name: 'Happ',
      steps: [
        'Включите режим TUN.',
        '«Настройки прокси для приложений» → «Режим маршрутизации трафика» → «Прямое подключение для выбранных приложений».',
        '«Из списка процессов» или «Выберите исполняемый файл» → Discord.exe и Lazeyka.exe.',
        'YouTube по доменам — профилем маршрутизации: DirectSites: geosite:youtube, geosite:discord.',
      ],
      note: 'Если Happ предложит «Выгрузить процессы» и среди «конфликтующих» будет winws.exe — не соглашайтесь: '
        + 'это выключит обход Лазейки. По сообщениям пользователей, режим Xray TUN в Happ хуже уживается с zapret, '
        + 'чем Happ TUN и sing-box.',
    },
    {
      id: 'hiddify', name: 'Hiddify',
      steps: [
        'В Hiddify 4.1 своих правил по сайтам и программам нет — только «Настройки → Маршрутизация → Регион: Россия» '
          + '(российские сайты напрямую) и «Обход локальной сети».',
      ],
      note: NO_SPLIT + ' Если нужен Discord через обход, а остальное через VPN, подойдёт программа с правилами по '
        + 'приложениям: v2rayN, Throne, Clash Verge Rev, Happ, Incy.',
    },
    {
      id: 'v2rayn', name: 'v2rayN',
      steps: [
        '«Настройки» → «Настройки маршрутизации» → откройте активный набор правил (или «Добавить набор правил»).',
        '«Добавить правило»: «Процесс (Linux/Windows)» — Discord.exe и Lazeyka.exe, OutboundTag — direct.',
        'Ещё правило: «Домен» — geosite:discord и geosite:youtube, OutboundTag — direct.',
        '«Установить как активное правило» и переподключитесь.',
      ],
      note: 'Правила по процессу работают в режиме TUN.',
    },
    {
      id: 'v2raytun', name: 'v2RayTun',
      steps: [],
      note: 'Правила по сайтам и исключение программ в v2RayTun для Windows не описаны. ' + NO_SPLIT,
    },
    {
      id: 'nekobox', name: 'NekoBox',
      steps: [
        '«Настройки TUN-режима» → «Пропускать процессы» → Discord.exe и Lazeyka.exe.',
        'Домены: «Настройки маршрутов» → «Базовые маршруты» → «Напрямую» → geosite:discord, geosite:youtube.',
      ],
      note: null,
    },
    {
      id: 'throne', name: 'Throne',
      steps: [
        '«Настройки» → «Настройки маршрутизации» → «Профили маршрутизации» → «Редактировать».',
        'Вкладка «Основные настройки», поле «Напрямую», по строке: processName:Discord.exe, processName:Lazeyka.exe, '
          + 'suffix:discord.com, suffix:discord.gg, suffix:youtube.com, suffix:googlevideo.com, suffix:ytimg.com.',
        'Сохраните и переподключитесь.',
      ],
      note: null,
    },
    {
      id: 'clash-verge', name: 'Clash Verge',
      steps: [
        '«Профили» → правый клик по профилю → «Редактировать правила» → «Добавить правило в начало».',
        'Правила: PROCESS-NAME, Discord.exe → DIRECT; PROCESS-NAME, Lazeyka.exe → DIRECT; GEOSITE, discord → DIRECT; '
          + 'GEOSITE, youtube → DIRECT.',
        'Сохраните — правила применятся сразу.',
      ],
      note: 'В режиме TUN Clash Verge Rev по умолчанию включает fake-ip DNS — проверка DNS в «Помощи» это учитывает.',
    },
    {
      id: 'flclash', name: 'FlClash',
      steps: [
        '«Инструменты» → «Общие» → включите поиск процессов: без него правило по программе не сработает.',
        '«Инструменты» → «Расширенная конфигурация» → «Добавленные правила»: PROCESS-NAME,Discord.exe,DIRECT; '
          + 'PROCESS-NAME,Lazeyka.exe,DIRECT; GEOSITE,discord,DIRECT; GEOSITE,youtube,DIRECT.',
      ],
      note: null,
    },
    {
      id: 'karing', name: 'Karing',
      steps: [
        '«Маршрутизация» → «Личные правила» → новая группа.',
        '«Имя процесса» — Discord.exe и Lazeyka.exe; «Суффикс доменного имени» — домены из списка ниже.',
        '«Правила маршрутизации» → для этой группы выберите «Напрямую».',
      ],
      note: 'В режиме TUN Karing по умолчанию включает fake-ip DNS.',
    },
    {
      id: 'amneziavpn', name: 'AmneziaVPN',
      steps: [
        '«Настройки» → «Соединение» → «Раздельное туннелирование приложений» → «Открыть исполняемый файл» → Discord.exe '
          + 'и Lazeyka.exe («Приложения из списка не должны работать через VPN»).',
        'Для YouTube — «Раздельное туннелирование сайтов» → «Адреса из списка не должны открываться через VPN» → домены из списка.',
      ],
      note: 'В AmneziaVPN по умолчанию включён Soft KillSwitch: проверки обхода мимо VPN он может блокировать.',
    },
    {
      id: 'amneziawg', name: 'AmneziaWG',
      steps: [],
      note: 'В клиенте AmneziaWG правил по сайтам и программам нет — только список AllowedIPs. Удобнее настроить '
        + 'исключения в AmneziaVPN. ' + NO_SPLIT,
    },
    {
      id: 'wireguard', name: 'WireGuard',
      steps: [
        'В официальном WireGuard нет правил по сайтам и программам — только список AllowedIPs (что идёт в туннель).',
        'Флажок «Block untunneled traffic (kill-switch)» блокирует всё мимо туннеля, в том числе проверки обхода.',
      ],
      note: NO_SPLIT + ' Если нужен Discord через обход — удобнее клиент с правилами по приложениям '
        + '(AmneziaVPN, Proton VPN, Mullvad и другие).',
    },
    {
      id: 'openvpn', name: 'OpenVPN',
      steps: [],
      note: 'Раздельного туннелирования в интерфейсе OpenVPN нет — только правка конфигурации (route-nopull и свои '
        + 'маршруты). ' + NO_SPLIT,
    },
    {
      id: 'outline', name: 'Outline',
      steps: [],
      note: 'В Outline для Windows раздельного туннелирования нет. ' + NO_SPLIT,
    },
    {
      id: 'warp', name: 'Cloudflare WARP',
      steps: [
        'Preferences → Advanced → Split Tunnels → режим Exclude → добавьте домены из списка ниже.',
      ],
      note: 'Правил по программам WARP не поддерживает, поэтому голос Discord так мимо VPN не пустить. Исключение по '
        + 'доменам срабатывает, только если DNS идёт через WARP: браузер со своим DNS по HTTPS его обходит.',
    },
    {
      id: 'protonvpn', name: 'Proton VPN',
      steps: [
        '⚙ «Настройки» → «Раздельное туннелирование» → «Режим исключения» → добавьте Discord.exe и Lazeyka.exe.',
      ],
      note: 'Раздельное туннелирование — на платном тарифе. Исключённые программы выходят напрямую даже при kill switch.',
    },
    {
      id: 'nordvpn', name: 'NordVPN',
      steps: ['Settings → Split tunneling → Add apps → Discord.exe и Lazeyka.exe (на Windows — только программы).'],
      note: null,
    },
    {
      id: 'kaspersky', name: 'Kaspersky VPN',
      steps: ['Settings → Split Tunneling → «Apps that never connect via VPN» → Discord.exe и Lazeyka.exe.'],
      note: null,
    },
    {
      id: 'adguardvpn', name: 'AdGuard VPN',
      steps: ['Вкладка «Исключения» → «VPN везде, кроме исключений» → добавьте домены из списка ниже.'],
      note: 'В режиме «Использовать WinTun» AdGuard VPN конфликтует с zapret (это признано у AdGuard). А без отдельного '
        + 'адаптера Лазейка не может отделить его трафик от прямого — совместимость с VPN тут не поможет.',
    },
    {
      id: 'windscribe', name: 'Windscribe',
      steps: ['«Настройки» → «Подключение» → «Раздельное туннелирование» → «Исключающий» → Discord.exe и Lazeyka.exe.'],
      note: null,
    },
    {
      id: 'surfshark', name: 'Surfshark',
      steps: ['Settings → VPN settings → Bypasser → «Bypass VPN» → программы Discord.exe и Lazeyka.exe, сайты из списка.'],
      note: null,
    },
    {
      id: 'expressvpn', name: 'ExpressVPN',
      steps: ['Profile → Split Tunneling → «Bypass VPN» для выбранных программ → Discord.exe и Lazeyka.exe.'],
      note: 'С протоколом Lightway Turbo ExpressVPN не создаёт отдельного адаптера — Лазейка не может отделить его '
        + 'трафик от прямого, и совместимость с VPN для него не работает. С другими протоколами всё в порядке.',
    },
    {
      id: 'mullvad', name: 'Mullvad',
      steps: ['«Настройки» → Split tunneling → добавьте Discord.exe и Lazeyka.exe.'],
      note: 'Исключённые программы обходят kill switch Mullvad.',
    },
  ];

  /* Общие оговорки — для подсказок рядом с инструкциями. */
  Lz.texts.VPN_NOTES = { voice: VOICE, telegram: TELEGRAM };
})(window.Lz);
