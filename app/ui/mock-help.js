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

  function siteVerdict(name) {
    const tld = name.slice(name.lastIndexOf('.') + 1);
    if (SPOOFED_DOMAINS.includes(name) && !dohEnabled) {
      return { verdict: 'dns', can_add: false, advice: 'Провайдер подменяет адрес сайта. Включите DNS через HTTPS — проверка DNS ниже.' };
    }
    if (DOWN_TLDS.has(tld) || name.startsWith('nosuch')) {
      return { verdict: 'down', can_add: false, advice: 'Такого сайта нет или он не отвечает — дело не в блокировке.' };
    }
    const bypassed = state.zapret.status === 'running' && userSites().includes(name);
    if (BLOCKED_SITES.has(name) && !bypassed) {
      return { verdict: 'blocked', can_add: true, advice: 'Сайт не открывается. Добавьте его в «Мои сайты» — обход начнёт его обрабатывать.' };
    }
    return { verdict: 'works', can_add: false, advice: 'Сайт открывается. Если в браузере нет — очистите кэш браузера или проверьте блокировщик рекламы.' };
  }

  api.check_site = function checkSite(domain) {
    const name = normalizeDomain(domain);
    if (!name) return fail('Введите адрес сайта, например example.com');
    return ok({ domain: name, ...siteVerdict(name) }, SITE_CHECK_MS);
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
