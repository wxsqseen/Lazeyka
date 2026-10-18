'use strict';
/* Человеческие названия режимов, результатов и состояний — общие для главной и подробных страниц. */
(function (Lz) {
  const GAME_FILTER = {
    disabled: { label: 'Выключен', chip: 'Игры: выключено' },
    all: { label: 'TCP и UDP', chip: 'Игры: TCP и UDP' },
    tcp: { label: 'Только TCP', chip: 'Игры: TCP' },
    udp: { label: 'Только UDP', chip: 'Игры: UDP' },
  };

  const IPSET = {
    none: {
      label: 'Не использовать',
      chip: 'IP-список выключен',
      text: 'Обход работает только для сайтов из списков доменов. Самый аккуратный режим — подходит почти всем.',
    },
    loaded: {
      label: 'По списку',
      chip: 'IP-список включён',
      text: 'Дополнительно обходим подсети из списка IP — нужно для игр и сервисов за Cloudflare, у которых нет понятного домена.',
    },
    any: {
      label: 'Все адреса',
      chip: 'Все IP-адреса',
      text: 'Обходим трафик к любым IP-адресам. Включайте, только если другие режимы не помогли: могут замедлиться посторонние сайты.',
    },
  };

  /* Результаты проверки сайта при подборе стратегии. */
  const CHECK_RESULT = {
    ok: 'работает',
    fail: 'не открывается',
    unsup: 'не поддерживается',
    ssl: 'подмена сертификата',
    none: 'не проверялось',
  };

  const CORE_KIND = {
    bundled: 'встроенное ядро',
    updated: 'обновлённое ядро',
  };

  function gameFilter(mode) {
    return GAME_FILTER[mode] || GAME_FILTER.disabled;
  }

  function ipset(mode) {
    return IPSET[mode] || IPSET.none;
  }

  function strategyLabel(zapret, id) {
    if (!id) return '';
    const list = (zapret && Array.isArray(zapret.strategies)) ? zapret.strategies : [];
    const found = list.find((item) => item.id === id);
    return found && found.label ? found.label : id;
  }

  const BEST_MARK = '★ лучшая';

  /**
   * Оценка стратегии по последнему подбору: лучшая ли она и какая доля проверок прошла
   * (score — null, если стратегию не проверяли). Ядро без поля best (до версии 1.1)
   * отмечает лучшую только в результатах текущего подбора.
   */
  function strategyRating(zapret, id) {
    const source = zapret || {};
    const bestId = 'best' in source
      ? (source.best && source.best.id) || null
      : (source.test && source.test.best) || null;
    const scores = source.scores && typeof source.scores === 'object' ? source.scores : {};
    const raw = Object.prototype.hasOwnProperty.call(scores, id) ? Number(scores[id]) : NaN;
    return { best: Boolean(id) && id === bestId, score: Number.isFinite(raw) ? raw : null };
  }

  /** Подпись в выпадающем списке стратегий: «ALT2 · 97 % · ★ лучшая»; непроверенные — просто имя. */
  function strategyChoiceLabel(zapret, item) {
    const rating = strategyRating(zapret, item.id);
    const parts = [item.label || item.id];
    if (rating.score !== null) parts.push(Lz.fmt.percent(rating.score));
    if (rating.best) parts.push(BEST_MARK);
    return parts.join(' · ');
  }

  /**
   * Строка о подключении Telegram к прокси: { tone, text }. Подсказку ядра (tg.client.hint)
   * показываем, пока Telegram не подключён; соединения считаем по живой статистике —
   * она свежее, чем tg.client, который ядро обновляет раз в несколько секунд.
   */
  function telegramConnection(tg) {
    const source = tg || {};
    const client = source.client || {};
    const active = Number(source.stats && source.stats.active) || 0;
    if (source.status === 'error') return { tone: 'err', text: 'Прокси не работает' };
    if (source.status !== 'running') return { tone: 'off', text: 'Прокси выключен' };
    if (client.connected || active > 0) {
      const count = active > 0 ? ` · ${Lz.fmt.count(active, 'соединение', 'соединения', 'соединений')}` : '';
      return { tone: 'ok', text: `Telegram подключён${count}` };
    }
    if (client.hint) {
      return { tone: client.stale_key || client.telegram_running ? 'warn' : 'off', text: String(client.hint) };
    }
    return { tone: 'off', text: 'Ждём, когда Telegram подключится' };
  }

  /** Строка сторожа под проверкой доступности; пустая, если сторож выключен или ещё не проверял. */
  function watchdogLine(watchdog) {
    const source = watchdog || {};
    if (!source.mode || source.mode === 'off' || !source.last_at) return '';
    if (source.vpn) return 'Сторож молчит: трафик идёт через VPN';
    const failing = Array.isArray(source.failing) ? source.failing.filter(Boolean).map(String) : [];
    if (failing.length) {
      return `Сторож: ${failing.join(' и ')} ${failing.length > 1 ? 'не открываются' : 'не открывается'}`;
    }
    return `Сторож проверил ${Lz.fmt.relative(source.last_at)}`;
  }

  /* ---------- Свой VPN ---------- */

  const VPNC_MODES = {
    tun: {
      label: 'Весь трафик (TUN)',
      short: 'Весь трафик',
      text: 'Через сервер идут все программы, включая игры и голос Discord. Лазейка создаёт свой сетевой адаптер — настраивать программы не нужно.',
    },
    proxy: {
      label: 'Системный прокси',
      short: 'Системный прокси',
      text: 'Через сервер идут браузеры и программы, которые слушают системный прокси Windows. Игры и голос Discord — напрямую. Когда VPN выключится, прежний прокси вернётся.',
    },
    local: {
      label: 'Только локальный прокси',
      short: 'Локальный прокси',
      text: 'Настройки Windows не меняются: прокси работает только на этом компьютере, и программы, которым он нужен, вы указываете сами.',
    },
  };

  const VPNC_PRESETS = {
    all: { label: 'Всё через VPN', text: 'Весь трафик идёт через ваш сервер, кроме того, что обрабатывает обход Лазейки.' },
    except_ru: { label: 'Кроме российских сайтов', text: 'Российские сайты, банки и госуслуги открываются напрямую, остальное — через сервер.' },
    blocked: { label: 'Только заблокированное', text: 'Через сервер — только сайты из списков блокировок, остальное напрямую.' },
  };

  /* Пресеты User-Agent подписки (app/vpnclient/model.py: UA_PRESETS). */
  const VPNC_UA = {
    lazeyka: 'Лазейка (честный)',
    v2rayn: 'как v2rayN',
    happ: 'как Happ',
    incy: 'как Incy',
    custom: 'Свой',
  };

  const VPNC_FORMAT = { links: 'ссылки', 'xray-json': 'JSON Xray с группами', sip008: 'SIP008' };

  const VPNC_PROTO = {
    vless: 'VLESS', vmess: 'VMess', trojan: 'Trojan', shadowsocks: 'Shadowsocks', hysteria2: 'Hysteria2',
    tuic: 'TUIC', socks: 'SOCKS5', wireguard: 'WireGuard',
  };
  const VPNC_TRANSPORT = {
    ws: 'WebSocket', grpc: 'gRPC', httpupgrade: 'HTTPUpgrade', xhttp: 'XHTTP', http: 'HTTP/2', kcp: 'mKCP', quic: 'QUIC',
  };
  const VPNC_SECURITY = { tls: 'TLS', reality: 'REALITY' };
  /* У этих протоколов свой транспорт поверх QUIC или UDP — tcp/tls в подписи только путают. */
  const VPNC_OWN_TRANSPORT = new Set(['hysteria2', 'tuic', 'wireguard']);

  /* Причины, по которым свой VPN не подключился (vpnclient.error_kind), и что с этим делать. */
  const VPNC_ERRORS = {
    port: {
      title: 'Порт занят',
      advice: 'Порт локального прокси заняла другая программа. Смените порт в «Подробнее» или закройте программу, которая его держит.',
    },
    admin: {
      title: 'Нет прав на режим «Весь трафик»',
      advice: 'Своему сетевому адаптеру нужны права администратора. Перезапустите Лазейку с ними или включите режим «Системный прокси».',
    },
    conflict: {
      title: 'Мешает другой VPN',
      advice: 'Два VPN в режиме «Весь трафик» ломают маршруты друг другу. Выключите другой VPN или включите Лазейку как системный прокси.',
    },
    timeout: {
      title: 'Сервер не отвечает',
      advice: 'Сервер не ответил вовремя. Проверьте задержку и выберите другой сервер или «Самый быстрый».',
    },
    tls: {
      title: 'Сервер отклонил соединение',
      advice: 'Обычно так бывает, когда провайдер сменил ключ или адрес маскировки (SNI). Обновите подписку; не поможет — выберите другой сервер.',
    },
    auth: {
      title: 'Сервер не принял ключ',
      advice: 'Ключ или пароль не подошли — так бывает, когда подписка закончилась или ключ перевыпустили. Обновите подписку или продлите её у провайдера.',
    },
    clock: {
      title: 'Часы компьютера сбиты',
      advice: 'VMess и REALITY не работают, если часы спешат или отстают больше чем на минуту. Синхронизируйте время в параметрах Windows.',
    },
    unsupported: {
      title: 'Сервер не поддерживается',
      advice: 'Этот сервер не открывается ни одним из ядер Лазейки. Выберите другой сервер.',
    },
    core: {
      title: 'Ядро VPN остановилось',
      advice: 'Ядро завершилось с ошибкой. Если оно проработало дольше минуты, Лазейка перезапустит его сама; подробности — в журнале.',
    },
    other: { title: 'Свой VPN не подключился', advice: 'Подробности — в журнале.' },
  };

  /* Ядра своего VPN: что сказать перед скачиванием (размер официального zip, лицензия, где исходники). */
  const VPNC_CORES = {
    'sing-box': {
      title: 'Ядро VPN (sing-box)',
      version: '1.14.3',
      size: 32853953,
      license: 'GPL-3.0-or-later',
      source: 'https://github.com/SagerNet/sing-box/tree/v1.14.3',
      note: 'Ядро sing-box — сторонний проект: Лазейка запускает его отдельной программой и не связана с его авторами.',
    },
    xray: {
      title: 'Помощник Xray',
      version: '26.3.27',
      size: 20913304,
      license: 'MPL-2.0',
      source: 'https://github.com/XTLS/Xray-core/tree/v26.3.27',
      note: 'Нужен только серверам, которых не умеет основное ядро: XHTTP, mKCP, VLESS с ML-KEM, gRPC multi.',
    },
  };
  const VPNC_CORE_ACTIVE = new Set(['downloading', 'verifying', 'installing']);

  const COUNTRY_NAMES = {
    AE: 'ОАЭ', AL: 'Албания', AM: 'Армения', AR: 'Аргентина', AT: 'Австрия', AU: 'Австралия', AZ: 'Азербайджан',
    BA: 'Босния и Герцеговина', BE: 'Бельгия', BG: 'Болгария', BR: 'Бразилия', BY: 'Беларусь', CA: 'Канада',
    CH: 'Швейцария', CL: 'Чили', CN: 'Китай', CY: 'Кипр', CZ: 'Чехия', DE: 'Германия', DK: 'Дания', EE: 'Эстония',
    EG: 'Египет', ES: 'Испания', FI: 'Финляндия', FR: 'Франция', GB: 'Великобритания', GE: 'Грузия', GR: 'Греция',
    HK: 'Гонконг', HR: 'Хорватия', HU: 'Венгрия', ID: 'Индонезия', IE: 'Ирландия', IL: 'Израиль', IN: 'Индия',
    IS: 'Исландия', IT: 'Италия', JP: 'Япония', KG: 'Киргизия', KR: 'Южная Корея', KZ: 'Казахстан', LT: 'Литва',
    LU: 'Люксембург', LV: 'Латвия', MD: 'Молдова', ME: 'Черногория', MK: 'Северная Македония', MX: 'Мексика',
    MY: 'Малайзия', NL: 'Нидерланды', NO: 'Норвегия', NZ: 'Новая Зеландия', PL: 'Польша', PT: 'Португалия',
    RO: 'Румыния', RS: 'Сербия', RU: 'Россия', SE: 'Швеция', SG: 'Сингапур', SI: 'Словения', SK: 'Словакия',
    TH: 'Таиланд', TR: 'Турция', TW: 'Тайвань', UA: 'Украина', US: 'США', UZ: 'Узбекистан', VN: 'Вьетнам',
    ZA: 'ЮАР',
  };

  const RUNNING_STATES = new Set(['running', 'starting']);

  function vpncMode(mode) {
    return VPNC_MODES[mode] || VPNC_MODES.tun;
  }

  function vpncPreset(preset) {
    return VPNC_PRESETS[preset] || VPNC_PRESETS.all;
  }

  function vpncError(kind) {
    return VPNC_ERRORS[kind] || VPNC_ERRORS.other;
  }

  function countryName(code) {
    const key = String(code || '').toUpperCase();
    return COUNTRY_NAMES[key] || key;
  }

  /** «VLESS · XHTTP · REALITY», «Hysteria2»: протокол, необычный транспорт и защита. */
  function vpncProto(server) {
    const source = server || {};
    const parts = [VPNC_PROTO[source.proto] || String(source.proto || '').toUpperCase()];
    if (!VPNC_OWN_TRANSPORT.has(source.proto)) {
      if (VPNC_TRANSPORT[source.transport]) parts.push(VPNC_TRANSPORT[source.transport]);
      if (VPNC_SECURITY[source.security]) parts.push(VPNC_SECURITY[source.security]);
    }
    return parts.filter(Boolean).join(' · ');
  }

  /**
   * Ядро, без которого не включиться, ещё готовится (Лазейка качает его с GitHub при запуске или по
   * «Включить»): «Готовлю ядро VPN: 45 %», «Готовлю помощник Xray…». Иначе null. Обновление уже
   * установленного ядра идёт фоном и строку состояния не занимает (оно видно в «Подробнее → Ядра»).
   * short — без подробностей ядра (message): для подписи под кнопкой питания.
   */
  function vpncCoreProgress(cores, short) {
    const source = cores && typeof cores === 'object' ? cores : {};
    for (const name of Object.keys(VPNC_CORES)) {
      const core = source[name];
      if (!core || core.installed || !VPNC_CORE_ACTIVE.has(core.state)) continue;
      const what = name === 'xray' ? 'помощник Xray' : 'ядро VPN';
      if (core.message && !short) return String(core.message);
      const pct = core.state === 'downloading' && core.progress != null ? `: ${Lz.fmt.percent(core.progress)}` : '…';
      return `Готовлю ${what}${pct}`;
    }
    return null;
  }

  /**
   * Нужное ядро не скачалось: «Ядро VPN не скачано · повторю в 14:05». Причина и кнопка «Скачать ещё раз» —
   * в постоянной плашке вверху страницы, здесь — только состояние. Иначе null.
   */
  function vpncCoreMissing(cores) {
    const source = cores && typeof cores === 'object' ? cores : {};
    for (const name of Object.keys(VPNC_CORES)) {
      const core = source[name];
      if (!core || core.installed || core.state !== 'error' || core.needed === false) continue;
      const what = name === 'xray' ? 'Помощник Xray не скачан' : 'Ядро VPN не скачано';
      const at = Number(core.retry_at) > 0 ? new Date(Number(core.retry_at) * 1000) : null;
      const when = at ? ` · повторю в ${String(at.getHours()).padStart(2, '0')}:${String(at.getMinutes()).padStart(2, '0')}` : '';
      return `${what}${when}`;
    }
    return null;
  }

  function vpncHasServers(vc) {
    const source = vc || {};
    return (Array.isArray(source.servers) && source.servers.length > 0)
      || (Array.isArray(source.subscriptions) && source.subscriptions.length > 0);
  }

  /** Выход через сервер: «Нидерланды, 203.0.113.5»; пусто, если проверки ещё не было. */
  function vpncExit(exit) {
    if (!exit || !exit.ip) return '';
    return exit.country ? `${countryName(exit.country)}, ${exit.ip}` : String(exit.ip);
  }

  /**
   * Строка состояния своего VPN: { tone, text }. «Подключено» — только после проверки выхода
   * через сервер (verified), до неё — «Проверяем соединение…».
   */
  function vpncLine(vc) {
    const source = vc || {};
    if (source.available === false) return { tone: 'off', text: String(source.unavailable_reason || 'Свой VPN сейчас недоступен.') };
    switch (source.status) {
      case 'error':
        return { tone: 'err', text: String(source.error || vpncError(source.error_kind).title) };
      case 'starting':
        return { tone: 'warn', text: vpncCoreProgress(source.cores) || 'Подключаемся к серверу…' };
      case 'stopping':
        return { tone: 'warn', text: 'Выключаем…' };
      case 'running': {
        if (!source.verified) return { tone: 'warn', text: 'Проверяем соединение…' };
        const exit = vpncExit(source.exit);
        return { tone: 'ok', text: exit ? `Подключено · выход ${exit}` : 'Подключено' };
      }
      default: {
        const installing = vpncCoreProgress(source.cores);
        if (installing) return { tone: 'warn', text: installing };
        const missing = vpncCoreMissing(source.cores);
        if (missing) return { tone: 'warn', text: missing };
        return { tone: 'off', text: vpncHasServers(source) ? 'Выключено' : 'Серверов пока нет — добавьте подписку' };
      }
    }
  }

  /** Статус для пилюли и кнопки питания: running без проверки выхода — «Проверяем…». */
  function vpncPillStatus(vc) {
    const source = vc || {};
    if (source.available === false) return 'locked';
    const status = source.status || 'stopped';
    return status === 'running' && !source.verified ? 'verifying' : status;
  }

  function vpncRunning(status) {
    return RUNNING_STATES.has(status);
  }

  /** Подпись под кнопкой питания: коротко, подробности — в строке состояния рядом. */
  function vpncCaption(vc, pillStatus) {
    const source = vc || {};
    switch (pillStatus) {
      case 'running':
        return source.started_at ? `Работает ${Lz.fmt.since(source.started_at)}` : 'Подключено';
      case 'verifying':
        return 'Проверяем выход через сервер…';
      case 'starting':
        return vpncCoreProgress(source.cores, true) || 'Подключаемся…';
      case 'stopping':
        return 'Выключаем…';
      case 'error':
        return 'Не подключилось';
      case 'locked':
        return 'Недоступно';
      default:
        return vpncHasServers(source) ? 'Нажмите, чтобы включить' : 'Сначала добавьте сервер';
    }
  }

  Lz.texts = {
    GAME_FILTER,
    IPSET,
    CHECK_RESULT,
    CORE_KIND,
    BEST_MARK,
    VPNC_MODES,
    VPNC_PRESETS,
    VPNC_UA,
    VPNC_FORMAT,
    VPNC_ERRORS,
    VPNC_CORES,
    VPNC_CORE_ACTIVE,
    gameFilter,
    ipset,
    strategyLabel,
    strategyRating,
    strategyChoiceLabel,
    telegramConnection,
    watchdogLine,
    vpncMode,
    vpncPreset,
    vpncError,
    vpncProto,
    vpncCoreProgress,
    vpncCoreMissing,
    vpncHasServers,
    vpncExit,
    vpncLine,
    vpncPillStatus,
    vpncRunning,
    vpncCaption,
    countryName,
  };
})(window.Lz);
