'use strict';
/*
 * Имитация дополнений контракта 1.1 для Telegram и «Помощи» (docs/ui-contract.md,
 * «Версия 1.1 — дополнения»): подключён ли Telegram к прокси, согласование с обходом,
 * проверка DNS, проверка сайта, «Мои сайты» и отчёт для помощи. Подключается из mock.js.
 *
 * Дополнительные параметры адреса:
 *   demo=tg-hint   — Telegram запущен, но не подключён к прокси
 *   demo=dns       — сразу проверить DNS
 *   clipboard=0    — отчёт для помощи не удалось положить в буфер обмена
 */
(window.LzMockExtensions = window.LzMockExtensions || []).push(function installHelpV11(mock) {
  const { state, api, params, nowSec, later, ok, fail, log } = mock;

  const TG_ACCEPT_MS = 1800;
  const STALE_KEY_SEC = 30;
  const DNS_CHECK_MS = 1500;
  const SITE_CHECK_MS = 1100;
  const REPORT_MS = 500;
  const REPORT_WARNINGS = 15;
  const DNS_PROVIDERS = [
    { id: 'cloudflare', name: 'Cloudflare', ip: '1.1.1.1', ok: true, ms: 23 },
    { id: 'google', name: 'Google', ip: '8.8.8.8', ok: true, ms: 31 },
    { id: 'quad9', name: 'Quad9', ip: '9.9.9.9', ok: false, ms: null },
  ];
  const SPOOFED_DOMAINS = ['discord.com'];
  const BLOCKED_SITES = new Set(['rutracker.org', 'linkedin.com', 'nnmclub.to', 'x.com', 'instagram.com', 'facebook.com', 'medium.com']);
  const DOWN_TLDS = new Set(['test', 'invalid', 'example', 'localhost']);
  const DOMAIN_PATTERN = /^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;

  /* ---------- Клиент Telegram ---------- */

  const telegramClient = { running: true, linked: true, staleUntil: 0 };

  function refreshClient() {
    const tg = state.tg;
    const proxyOn = tg.status === 'running';
    const stale = proxyOn && nowSec() < telegramClient.staleUntil;
    const connected = proxyOn && telegramClient.linked && !stale;
    let hint = null;
    if (proxyOn && stale) hint = 'Telegram подключается со старым ключом — нажмите «Подключить Telegram» ещё раз.';
    else if (proxyOn && !connected && telegramClient.running) hint = 'Telegram запущен, но не использует прокси — нажмите «Подключить Telegram».';
    else if (proxyOn && !connected) hint = 'Запустите Telegram Desktop и нажмите «Подключить Telegram».';
    tg.client = { telegram_running: telegramClient.running, connected, stale_key: stale, hint };
  }

  /** Telegram помнит старую ссылку: после смены ключа или адреса он стучится со старым ключом, пока его не подключат заново. */
  function forgetTelegramLink() {
    telegramClient.linked = false;
    telegramClient.staleUntil = nowSec() + STALE_KEY_SEC;
  }

  const openInTelegram = api.tg_open_in_telegram;
  api.tg_open_in_telegram = function tgOpenInTelegram() {
    later(TG_ACCEPT_MS, () => {
      telegramClient.running = true;
      telegramClient.linked = true;
      telegramClient.staleUntil = 0;
    });
    return openInTelegram();
  };

  const regenSecret = api.tg_regen_secret;
  api.tg_regen_secret = function tgRegenSecret() {
    forgetTelegramLink();
    return regenSecret();
  };

  const saveTelegram = api.tg_save_settings;
  api.tg_save_settings = function tgSaveSettings(values) {
    const before = state.tg.link;
    const result = saveTelegram(values);
    if (state.tg.link !== before) forgetTelegramLink();
    return result;
  };

  /* ---------- DNS ---------- */

  let dohEnabled = false;

  function dnsMessage(spoofed) {
    if (spoofed.length) {
      return `Провайдер подменяет адреса: ${spoofed.join(', ')}. Включите DNS через HTTPS — без этого обход может не помочь.`;
    }
    if (!dohEnabled) {
      return 'Подмены не видно, но DNS через HTTPS выключен. Его стоит включить: провайдер может начать подменять адреса в любой момент.';
    }
    return 'DNS в порядке: подмены нет, DNS через HTTPS включён.';
  }

  api.dns_check = function dnsCheck() {
    if (state.dns.running) return ok();
    state.dns = { ...state.dns, running: true };
    later(DNS_CHECK_MS, () => {
      const spoofed = dohEnabled ? [] : SPOOFED_DOMAINS.slice();
      state.dns = {
        running: false, at: nowSec(), doh_enabled: dohEnabled, spoofed,
        providers: DNS_PROVIDERS.map((provider) => ({ ...provider })), message: dnsMessage(spoofed),
      };
    });
    return ok();
  };

  /* Будто человек открыл параметры и включил DNS через HTTPS: следующая проверка подмены не найдёт. */
  api.dns_open_settings = function dnsOpenSettings() {
    log('app', 'info', 'Открываем параметры сети Windows');
    dohEnabled = true;
    return ok();
  };

  /* ---------- Проверка сайта и «Мои сайты» ---------- */

  function normalizeDomain(text) {
    let value = String(text || '').trim().toLowerCase();
    value = value.replace(/^[a-z]+:\/\//, '').split('/')[0].split(':')[0].replace(/^\.+|\.+$/g, '');
    if (value.startsWith('www.')) value = value.slice(4);
    return DOMAIN_PATTERN.test(value) ? value : null;
  }

  function userSitesList() {
    return mock.LISTS.find((list) => list.id === 'general-user');
  }

  function userSites() {
    return userSitesList().text.split(/\r?\n/).map((line) => line.trim()).filter((line) => line && !line.startsWith('#'));
  }

  const IP_BLOCKED = new Set(['linkedin.com', 'telegram.org']);
  const FROZEN_SITES = new Set(['medium.com', 'hetzner.com']);
  const GEO_SITES = new Set(['chatgpt.com', 'openai.com', 'notion.so']);
  const VPN_REFUSED = new Set(['lk.example-bank.ru']);
  const RU_CA_SITES = new Set(['sberbank.ru', 'vtb.ru', 'tbank.ru', 'rzd.ru']);

  const step = (id, label, isOk, detail) => ({ id, label, ok: isOk, detail });

  /** Как siteprobe.verdict ядра: шаги «Рентгена» и кнопки. */
  function siteVerdict(name) {
    const tld = name.slice(name.lastIndexOf('.') + 1);
    const vpn = state.vpnclient || {};
    const vpnOn = vpn.status === 'running';
    const ownVpn = Array.isArray(vpn.servers) && vpn.servers.length > 0;
    const vpnStep = (works) => (vpnOn ? [step('vpn', 'Через свой VPN', works, works ? 'код 200' : 'не открывается')] : []);
    const vpnFix = ownVpn ? ['vpn_site'] : [];
    const via = vpnOn ? ' Через ваш VPN сайт открывается.' : '';
    const dns = step('dns', 'Адрес сайта (DNS)', true, 'настоящий адрес');
    const tcp = step('tcp', 'Соединение с сервером', true, 'есть');
    const tls = step('tls', 'Защищённое соединение', true, 'есть');
    if (DOWN_TLDS.has(tld) || name.startsWith('nosuch')) {
      return { verdict: 'down', fixes: [], steps: [step('dns', 'Адрес сайта (DNS)', false, 'имя не находится ни у провайдера, ни в DNS через HTTPS'),
        step('tcp', 'Соединение с сервером', null, 'не проверялось: адреса нет')],
      advice: 'Такого сайта нет или он не отвечает — дело не в блокировке.' };
    }
    if (SPOOFED_DOMAINS.includes(name) && !dohEnabled) {
      return { verdict: 'dns', fixes: [], steps: [step('dns', 'Адрес сайта (DNS)', false, 'провайдер подменяет адрес'), tcp, tls,
        step('answer', 'Ответ сайта', true, 'код 200'), step('freeze', 'Большие ответы', true, 'проходят'), ...vpnStep(true)],
      advice: 'Сайт открывается по настоящему адресу, но провайдер подменяет адрес. Включите DNS через HTTPS — проверка DNS ниже.' };
    }
    if (IP_BLOCKED.has(name)) {
      const steps = [dns, step('tcp', 'Соединение с сервером', false, 'адрес не отвечает'), ...vpnStep(true)];
      if (!vpnOn) {
        return { verdict: 'unreachable', fixes: [], steps,
          advice: `Адрес сайта не отвечает: либо провайдер его закрыл, либо сайт лежит.${ownVpn ? ' Включите свой VPN и проверьте ещё раз — станет ясно, что именно.' : ''}` };
      }
      return { verdict: 'ip', fixes: vpnFix, steps,
        advice: 'Провайдер закрыл адрес сайта: соединение не устанавливается. Обход тут не поможет — через ваш VPN сайт открывается.' };
    }
    if (GEO_SITES.has(name)) {
      return { verdict: 'geo', fixes: vpnFix, steps: [dns, tcp, tls, step('answer', 'Ответ сайта', false, 'код 451 — сайт не пускает из этой страны'), ...vpnStep(true)],
        advice: `Сайт сам не пускает пользователей из России (ответ 451) — обход тут не поможет, нужен VPN.${vpnOn ? ' Через ваш VPN он открывается.' : ''}` };
    }
    if (VPN_REFUSED.has(name) && vpnOn) {
      return { verdict: 'vpn_refused', fixes: ['direct_site'], steps: [dns, tcp, tls, step('answer', 'Ответ сайта', true, 'код 200'),
        step('freeze', 'Большие ответы', true, 'проходят'), step('vpn', 'Через свой VPN', false, 'код 403 — сайт не пускает')],
      advice: 'Напрямую сайт открывается, а через ваш VPN — нет: сайт не пускает из-за границы или с адресов VPN. Пустите его мимо VPN.' };
    }
    if (RU_CA_SITES.has(name)) {
      return { verdict: 'ru_ca', fixes: [], steps: [dns, tcp, step('tls', 'Защищённое соединение', true, 'есть, сертификат российского удостоверяющего центра (Минцифры)'),
        step('answer', 'Ответ сайта', true, 'код 200'), ...vpnStep(true)],
      advice: 'Сайт открывается, но его сертификат выдал российский удостоверяющий центр (Минцифры). Chrome, Edge и Firefox без него покажут ошибку сертификата — откройте сайт в Яндекс Браузере или установите сертификат Минцифры (инструкция — на Госуслугах).' };
    }
    const zapretOn = state.zapret.status === 'running';
    const ownStrategy = Boolean(zapretOn && state.zapret.groups && state.zapret.groups.sites && state.zapret.groups.sites[name]);
    const listed = userSites().includes(name) || ownStrategy;
    const pick = state.app.admin ? ['pick_site'] : [];
    if ((BLOCKED_SITES.has(name) || FROZEN_SITES.has(name)) && !(zapretOn && listed && (BLOCKED_SITES.has(name) || ownStrategy))) {
      const frozen = FROZEN_SITES.has(name);
      const what = frozen
        ? 'Соединение устанавливается, но замирает — так провайдеры режут сайты на зарубежных хостингах (обрыв после ~16 КБ).'
        : 'Провайдер обрывает соединение на имени сайта — так работает его фильтр (DPI).';
      const steps = frozen
        ? [dns, tcp, tls, step('answer', 'Ответ сайта', true, 'код 200'), step('freeze', 'Большие ответы', false, 'замирают после ~16 КБ'), ...vpnStep(true)]
        : [dns, tcp, step('tls', 'Защищённое соединение', false, 'оборвалось на имени сайта'), ...vpnStep(true)];
      if (zapretOn && listed) {
        return { verdict: frozen ? 'freeze' : 'dpi', fixes: [...pick, ...vpnFix], steps,
          advice: `${what} Обход этот сайт обрабатывает, но нынешняя стратегия его не пробивает.${ownVpn ? ' Надёжнее — через свой VPN.' : ''}${via}` };
      }
      return { verdict: frozen ? 'freeze' : 'dpi', fixes: ['add_site', ...(zapretOn ? pick : []), ...vpnFix], steps,
        advice: zapretOn ? `${what} Обход этот сайт сейчас не обрабатывает — добавьте его в «Мои сайты».${via}`
          : `${what} Добавьте сайт в «Мои сайты» и включите обход.${via}` };
    }
    return { verdict: 'works', fixes: [], steps: [dns, tcp, tls, step('answer', 'Ответ сайта', true, 'код 200'),
      step('freeze', 'Большие ответы', true, 'проходят'), ...vpnStep(true)],
    advice: 'Сайт открывается. Если в браузере нет — очистите кэш браузера или проверьте блокировщик рекламы.' };
  }

  api.check_site = function checkSite(domain) {
    const name = normalizeDomain(domain);
    if (!name) return fail('Введите адрес сайта, например example.com');
    const found = siteVerdict(name);
    return ok({ domain: name, ...found, can_add: found.fixes.includes('add_site') }, SITE_CHECK_MS);
  };

  /* ---------- Паспорт провайдера (как Core.passport_check) ---------- */

  const PASSPORT_SITES = [['youtube.com', 'YouTube'], ['discord.com', 'Discord'], ['web.telegram.org', 'Telegram'],
    ['instagram.com', 'Instagram'], ['x.com', 'X'], ['facebook.com', 'Facebook'], ['linkedin.com', 'LinkedIn'],
    ['chatgpt.com', 'ChatGPT'], ['rutracker.org', 'Rutracker'], ['medium.com', 'Medium'], ['patreon.com', 'Patreon'],
    ['github.com', 'GitHub'], ['wikipedia.org', 'Википедия'], ['ya.ru', 'Яндекс'], ['gosuslugi.ru', 'Госуслуги']];
  const PASSPORT_SHORT = { works: 'открывается', dns: 'открывается, но провайдер подменяет адрес', down: 'не отвечает',
    ru_ca: 'открывается, сертификат Минцифры',
    unreachable: 'адрес не отвечает', ip: 'провайдер закрыл адрес', dpi: 'провайдер режет по имени',
    freeze: 'замирает после ~16 КБ', cert: 'вместо сайта отвечает провайдер', geo: 'сам не пускает из России',
    vpn_refused: 'не пускает через VPN', whitelist: 'белый список' };
  const PASSPORT_CUT = new Set(['ip', 'dpi', 'freeze', 'cert']);
  const PASSPORT_STEP_MS = 160;

  function smartAdd(domain, via, why, label) {
    const routing = state.vpnclient && state.vpnclient.routing;
    if (!routing || routing.smart_route === false || !routing.smart) return false;
    routing.smart.sites = routing.smart.sites.filter((site) => site.domain !== domain);
    routing.smart.sites.unshift({ domain, via, why, label, at: nowSec() });
    return true;
  }

  function passportItems() {
    const vpn = state.vpnclient || {};
    const ownVpn = Array.isArray(vpn.servers) && vpn.servers.length > 0;
    const smartLabel = { ip: 'провайдер закрыл адрес сайта', dpi: 'провайдер режет по имени сайта', freeze: 'соединение замирает после ~16 КБ', geo: 'сайт не пускает из России' };
    const zapretOn = state.zapret.status === 'running';
    const toZapret = [];
    const items = PASSPORT_SITES.map(([domain, label]) => {
      const found = siteVerdict(domain);
      const item = { domain, label, verdict: found.verdict, what: PASSPORT_SHORT[found.verdict] || '', action: null, ok: null };
      const fixes = found.fixes;
      const smart = (via, why, done) => {
        if (smartAdd(domain, via, why, via === 'direct' ? 'не пускает через VPN' : smartLabel[why] || '')) Object.assign(item, { action: done, ok: true });
        else item.action = `включите умный маршрут своего VPN — и Лазейка пустит его ${via === 'proxy' ? 'через сервер' : 'напрямую'}`;
      };
      if (['works', 'dns', 'ru_ca'].includes(found.verdict)) item.ok = true;
      else if (fixes.includes('direct_site')) smart('direct', 'vpn', 'теперь напрямую, мимо VPN');
      else if (fixes.includes('add_site')) toZapret.push({ item, found, smart });
      else if (fixes.includes('vpn_site')) smart('proxy', found.verdict === 'geo' ? 'geo' : found.verdict, 'теперь через свой VPN');
      else if (found.verdict === 'unreachable') item.action = ownVpn ? 'включите свой VPN и проверьте ещё раз — станет ясно, закрыт ли адрес' : 'адрес закрыт или сайт лежит — открыть поможет только свой VPN';
      else if (PASSPORT_CUT.has(found.verdict) || found.verdict === 'geo') item.action = 'нужен свой VPN: добавьте подписку на странице «Свой VPN»';
      return item;
    });
    if (toZapret.length) {
      const list = userSitesList();
      const have = userSites();
      const fresh = toZapret.map((entry) => entry.item.domain).filter((domain) => !have.includes(domain));
      if (fresh.length) list.text = `${have.concat(fresh).join('\n')}\n`;
      for (const { item, found, smart } of toZapret) {
        if (!zapretOn) { item.action = 'добавлен в «Мои сайты» — включите обход'; continue; }
        const again = siteVerdict(item.domain);
        if (['works', 'dns', 'ru_ca'].includes(again.verdict)) Object.assign(item, { action: 'добавлен в «Мои сайты» — открывается через обход', ok: true });
        else if (again.fixes.includes('vpn_site')) smart('proxy', again.verdict, 'обход не пробил — теперь через свой VPN');
        else item.action = 'добавлен в «Мои сайты», но обход его пока не пробил';
      }
      if (zapretOn) mock.startZapret('список изменён');
    }
    return items;
  }

  function passportSummary(items) {
    const cut = items.filter((item) => PASSPORT_CUT.has(item.verdict)).length;
    const parts = [`Провайдер режет ${cut} из ${items.length}`];
    const geo = items.filter((item) => item.verdict === 'geo').length;
    if (geo) parts.push(`сами не пускают из России — ${geo}`);
    const fixed = items.filter((item) => item.ok && !['works', 'dns', 'ru_ca'].includes(item.verdict)).length;
    if (fixed) parts.push(`Лазейка настроила ${fixed}`);
    return `${parts.join(', ')}.`;
  }

  state.passport = { running: false, stage: null, done: 0, total: 0, at: null, items: [], summary: null };

  api.passport_check = function passportCheck() {
    if (state.passport.running) return ok();
    const total = PASSPORT_SITES.length;
    state.passport = { running: true, stage: 'check', done: 0, total, at: null, items: [], summary: null };
    for (let i = 1; i <= total; i += 1) later(PASSPORT_STEP_MS * i, () => { state.passport = { ...state.passport, done: i }; });
    later(PASSPORT_STEP_MS * (total + 4), () => { state.passport = { ...state.passport, stage: 'recheck' }; });
    later(PASSPORT_STEP_MS * (total + 10), () => {
      const items = passportItems();
      state.passport = { running: false, stage: null, done: total, total, at: nowSec(), items, summary: passportSummary(items) };
    });
    return ok();
  };

  api.lists_add_site = function listsAddSite(domain) {
    const name = normalizeDomain(domain);
    if (!name) return fail('Некорректный адрес сайта');
    const entries = userSites();
    if (entries.includes(name)) return ok({ message: `${name} уже в «Моих сайтах»` });
    userSitesList().text = `${entries.concat(name).join('\n')}\n`;
    if (state.zapret.status === 'running') mock.startZapret('список изменён');
    return ok({ message: `${name} добавлен в «Мои сайты»` });
  };

  /* ---------- Отчёт для помощи ---------- */

  function clock(unixSeconds) {
    return new Date(unixSeconds * 1000).toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  }

  /** Как ядро (helpdesk.build_report): без ключа прокси, имени пользователя и путей профиля. */
  function reportText() {
    const zapret = state.zapret;
    const tg = state.tg;
    const filter = zapret.game_filter || {};
    const stats = tg.stats || {};
    const lines = [
      `${state.app.name} ${state.app.version}`,
      'Windows: Windows-11-10.0.26200-SP0 (AMD64)',
      `Администратор: ${state.app.admin ? 'да' : 'нет'}`,
      '',
      `zapret: ${zapret.status} · режим ${zapret.mode} · пакет ${zapret.pack.version}`,
      `Стратегия: ${zapret.strategy}`,
      `Игровой фильтр: ${filter.mode} (TCP ${filter.tcp}, UDP ${filter.udp})`,
      `IPSet: ${zapret.ipset.mode}`,
    ];
    if (zapret.error) lines.push(`Ошибка обхода: ${zapret.error}`);
    const results = Array.isArray(zapret.check.results) ? zapret.check.results : [];
    if (results.length) {
      lines.push(`Проверка: ${results.map((result) => `${result.label} ${result.ok ? '✓' : '✗'} (${result.detail})`).join(', ')}`);
    }
    lines.push('', `Telegram-прокси: ${tg.status} · ядро ${tg.version} (${tg.core})`,
      `Соединения: активных ${stats.active}, всего ${stats.total}, WS ${stats.ws}, Cloudflare ${stats.cf}, TCP ${stats.tcp_fallback}`);
    const problems = state.diag.items.filter((item) => item.status === 'warn' || item.status === 'error');
    if (problems.length) lines.push('', 'Диагностика:', ...problems.map((item) => `- ${item.title}: ${item.text}`));
    const warnings = mock.logs.filter((line) => line.lvl === 'warn' || line.lvl === 'error').slice(-REPORT_WARNINGS);
    if (warnings.length) lines.push('', 'Последние предупреждения:', ...warnings.map((line) => `- ${clock(line.t)} ${line.msg}`));
    return lines.join('\n');
  }

  api.help_report = function helpReport() {
    return ok({ text: reportText(), copied: params.get('clipboard') !== '0' }, REPORT_MS);
  };

  /* ---------- Состояние ---------- */

  state.tg_settings.zapret_sync = true;
  state.dns = { running: false, at: null, doh_enabled: null, spoofed: [], providers: [], message: null };

  const getState = api.get_state;
  api.get_state = function getStateWithClient() {
    refreshClient();
    return getState();
  };
  refreshClient();
  mock.onTick(refreshClient);

  Object.assign(mock.demos, {
    'tg-hint': () => {
      telegramClient.linked = false;
    },
    dns: () => api.dns_check(),
  });
});
