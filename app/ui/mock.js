'use strict';
/*
 * Имитация ядра Лазейки — только для разработки интерфейса и скриншотов.
 * Загружается из app.js, когда в адресе есть ?mock, а настоящего pywebview нет.
 * Вместе с дополнениями версии 1.1 — mock-zapret.js (проверка доступности, «Найти и включить»,
 * оценки стратегий, сторож), mock-help.js (клиент Telegram, DNS, проверка сайта, отчёт)
 * и mock-vpn.js (VPN рядом с обходом) — реализует весь контракт docs/ui-contract.md на таймерах.
 *
 * Параметры адреса:
 *   firstrun=0|1   — показывать приветствие (по умолчанию 1); onb=1..3 — с какого шага
 *   admin=0|1      — права администратора (по умолчанию 1)
 *   theme=system|dark|light
 *   demo=test|install|diag|check — сразу запустить долгую операцию (ещё значения — в дополнениях)
 *   demo=update|downloading|verifying|installing|done|error|uptodate — застывшее состояние
 *     страницы «Обновления» для скриншотов и ручной проверки UI (таймеры не меняют его)
 */
(function () {
  const params = new URLSearchParams(window.location.search);
  const flag = (name, fallback) => (params.has(name) ? params.get(name) !== '0' : fallback);

  const STATE_DELAY_MS = 25;
  const ACTION_DELAY_MS = 220;
  const TICK_MS = 1000;
  const HISTORY_POINTS = 120;
  const TEST_STEP_MS = 540;
  const DIAG_MS = 2600;
  const UPDATE_CHECK_MS = 1600;
  const AUTO_UPDATE_CHECK_DELAY_MS = 1200;
  const DOWNLOAD_STEP_MS = 380;
  const DOWNLOAD_STEPS = 10;
  const LOG_BACKLOG = 140;
  const LOG_RESPONSE_LIMIT = 500;
  const LOG_KEEP = 5000;
  const PORT_MAX = 65535;
  const KB = 1024;
  const MB = KB * KB;

  /* ---------- Мелочи ---------- */

  const nowSec = () => Date.now() / 1000;
  const random = (min, max) => min + Math.random() * (max - min);
  const randomInt = (min, max) => Math.floor(random(min, max + 1));
  const chance = (p) => Math.random() < p;
  const pick = (list) => list[Math.floor(Math.random() * list.length)];
  const clamp = (value, min, max) => Math.max(min, Math.min(max, value));
  const clone = (value) => JSON.parse(JSON.stringify(value));
  const later = (ms, fn) => setTimeout(fn, ms);
  const reply = (value, ms = ACTION_DELAY_MS) => new Promise((resolve) => setTimeout(() => resolve(clone(value)), ms));
  const ok = (extra, ms) => reply({ ok: true, ...(extra || {}) }, ms);
  const fail = (error, errors) => reply(errors ? { ok: false, error, errors } : { ok: false, error });
  const hex = (length) => Array.from({ length }, () => '0123456789abcdef'[randomInt(0, 15)]).join('');

  /* ---------- Данные ---------- */

  const STRATEGY_IDS = [
    'general', 'general (ALT)', 'general (ALT2)', 'general (ALT3)', 'general (ALT4)', 'general (ALT5)',
    'general (ALT6)', 'general (ALT7)', 'general (ALT8)', 'general (ALT9)', 'general (ALT10)',
    'general (ALT11)', 'general (ALT12)', 'general (ALT13)', 'general (FAKE TLS AUTO)',
    'general (FAKE TLS AUTO ALT)', 'general (FAKE TLS AUTO ALT2)', 'general (FAKE TLS AUTO ALT3)',
    'general (SIMPLE FAKE)', 'general (SIMPLE FAKE ALT)', 'general (SIMPLE FAKE ALT2)', 'general (EXP)',
  ];
  const STRATEGIES = STRATEGY_IDS.map((id) => {
    const match = /\((.+)\)/.exec(id);
    return { id, label: id === 'general' ? 'Стандартная' : match[1] };
  });
  /* Насколько хорошо стратегия «пробивает» провайдера в этой имитации. */
  const STRATEGY_QUALITY = {
    'general (ALT2)': 0.97, 'general (ALT)': 0.9, 'general (FAKE TLS AUTO)': 0.88, general: 0.74,
    'general (ALT5)': 0.86, 'general (SIMPLE FAKE)': 0.58, 'general (EXP)': 0,
  };
  const BROKEN_STRATEGY = 'general (EXP)';

  const STANDARD_TARGETS = [
    ['Discord', 'https://discord.com'],
    ['Discord Gateway', 'https://gateway.discord.gg'],
    ['Discord CDN', 'https://cdn.discordapp.com'],
    ['Discord Updates', 'https://updates.discord.com'],
    ['YouTube', 'https://www.youtube.com'],
    ['youtu.be', 'https://youtu.be'],
    ['YouTube картинки', 'https://i.ytimg.com'],
    ['YouTube видео', 'https://redirector.googlevideo.com'],
    ['Google', 'https://www.google.com'],
    ['Google Static', 'https://www.gstatic.com'],
    ['Cloudflare', 'https://www.cloudflare.com'],
    ['Cloudflare CDN', 'https://cdnjs.cloudflare.com'],
  ];
  const DPI_TARGETS = [
    ['Hetzner, Германия', 'https://speed.hetzner.de'],
    ['OVH, Франция', 'https://proof.ovh.net'],
    ['DigitalOcean, Нидерланды', 'https://ams3.digitaloceanspaces.com'],
    ['Cloudflare', 'https://speed.cloudflare.com'],
    ['Akamai', 'https://a248.e.akamai.net'],
    ['Fastly', 'https://www.fastly.com'],
  ];
  const PING_TOTAL = 4;

  const FAKE_FILES = [
    'quic_initial_www_google_com', 'quic_initial_5ka_ru', 'quic_initial_rutube_ru', 'quic_initial_4pda_to',
    'quic_initial_tencent_com', 'quic_initial_steamcommunity_com', 'tls_clienthello_www_google_com',
    'tls_clienthello_max_ru', 'tls_clienthello_www_sferum_ru', 'tls_clienthello_sochi_park',
    'tls_clienthello_5ka_ru', 'tls_clienthello_4pda_to', 'stun', 'stun2',
  ];

  const LISTS = [
    {
      id: 'general-user',
      title: 'Мои сайты',
      hint: 'Домены, которые нужно пропускать через обход вдобавок к встроенным спискам. По одному на строку.',
      text: 'rutracker.org\nanilibria.tv\n',
      editable: true,
    },
    {
      id: 'exclude-user',
      title: 'Не трогать',
      hint: 'Домены, к которым обход не применяется, даже если они есть во встроенных списках.',
      text: 'sberbank.ru\ngosuslugi.ru\n',
      editable: true,
    },
    {
      id: 'ipset-exclude-user',
      title: 'Исключённые IP',
      hint: 'Адреса и подсети, которые обход не трогает. Формат: 192.168.0.0/16.',
      text: '203.0.113.113/32\n',
      editable: true,
    },
    {
      id: 'general',
      title: 'Discord и сервисы',
      hint: 'Встроенный список из пакета стратегий. Чтобы добавить сайт, используйте «Мои сайты».',
      text: ['dis.gd', 'discord.app', 'discord.co', 'discord.com', 'discord.design', 'discord.dev', 'discord.gg',
        'discord.gift', 'discord.media', 'discord.new', 'discord.store', 'discordapp.com', 'discordapp.net',
        'discordcdn.com', 'discordstatus.com', 'cloudflare-ech.com', 'cloudflareclient.com', 'frankerfacez.com',
        'betterttv.net', '7tv.app'].join('\n'),
      editable: false,
    },
    {
      id: 'google',
      title: 'YouTube и Google',
      hint: 'Встроенный список из пакета стратегий.',
      text: ['yt3.ggpht.com', 'yt4.ggpht.com', 'googlevideo.com', 'youtube.com', 'youtu.be', 'ytimg.com',
        'youtubei.googleapis.com', 'youtube-nocookie.com', 'play.google.com', 'www.gstatic.com'].join('\n'),
      editable: false,
    },
  ];

  const RELEASE_NOTES = [
    'Что нового в 1.10.4',
    '',
    '• Стратегия ALT6 снова работает у провайдеров с DPI на 16–20 КБ',
    '• Обновлены списки Discord: добавлены discord.design и dis.gd',
    '• ipset-all.txt: +412 подсетей Cloudflare',
    '• Игровой фильтр принимает несколько диапазонов портов через запятую',
    '',
    'Полный список изменений: https://github.com/Flowseal/zapret-discord-youtube/releases/tag/1.10.4',
  ].join('\n');

  /* ---------- Состояние ---------- */

  const startedAt = nowSec();
  const admin = flag('admin', true);
  const theme = ['system', 'dark', 'light'].includes(params.get('theme')) ? params.get('theme') : 'system';
  const secret = 'a3f1c29e7b5d40e8916c2d7f0b4e8a61';

  const state = {
    app: {
      name: 'Лазейка',
      version: '1.0.0',
      admin,
      first_run: flag('firstrun', true),
      data_dir: 'C:\\ProgramData\\Lazeyka',
      busy: null,
    },
    notices: [],
    zapret: {
      available: admin,
      unavailable_reason: admin ? null
        : 'Лазейка запущена без прав администратора, а драйверу WinDivert они нужны, чтобы перехватывать трафик.',
      status: admin ? 'running' : 'stopped',
      error: null,
      mode: 'app',
      strategy: 'general (ALT2)',
      strategies: STRATEGIES,
      started_at: admin ? startedAt - 4320 : null,
      pack: { version: '1.10.3' },
      game_filter: { mode: 'disabled', tcp: '1024-65535', udp: '1024-65535' },
      ipset: { mode: 'none', count: 33048 },
      service: { installed: false, running: false, strategy: null },
      conflicts: [
        { id: 'service:GoodbyeDPI', text: 'Запущена служба GoodbyeDPI — она перехватывает тот же трафик и мешает zapret.', fix_label: 'Удалить службу' },
      ],
      /* Проверку доступности ведёт mock-zapret.js: что открывается, зависит от стратегии. */
      check: { running: false, at: null, results: [] },
      test: { running: false, kind: 'standard', total: 0, done: 0, current: null, best: null, error: null, finished_at: null, results: [] },
    },
    tg: {
      status: 'running',
      error: null,
      host: '127.0.0.1',
      port: 1443,
      link: '',
      version: '1.11.2',
      core: 'bundled',
      started_at: startedAt - 2820,
      stats: { active: 3, total: 128, ws: 112, cf: 9, h2: 4, tcp_fallback: 3, bad: 0, up: 23456789, down: 318765432, up_rate: 0, down_rate: 0 },
      history: [],
      test: { running: false, at: null, results: [] },
    },
    updates: {
      auto_check: true,
      checking: false,
      last_check: startedAt - 86400 * 1.3,
      error: null,
      count: 0,
      items: [
        {
          id: 'zapret', title: 'Стратегии zapret', subtitle: 'Flowseal/zapret-discord-youtube',
          current: '1.10.3', latest: '1.10.3', available: false, skipped: false,
          published_at: '2026-09-20T13:46:00Z', notes: '', url: 'https://github.com/Flowseal/zapret-discord-youtube/releases',
          state: 'idle', progress: null, message: null, can_rollback: false,
        },
        {
          id: 'tgws', title: 'Прокси для Telegram', subtitle: 'Flowseal/tg-ws-proxy',
          current: '1.11.2', latest: '1.11.2', available: false, skipped: false,
          published_at: '2026-09-28T09:10:00Z', notes: '', url: 'https://github.com/Flowseal/tg-ws-proxy/releases',
          state: 'idle', progress: null, message: null, can_rollback: false,
        },
      ],
    },
    settings: {
      theme,
      close_to_tray: true,
      start_minimized: false,
      autostart: false,
      zapret_on_start: true,
      tg_on_start: true,
      check_updates: true,
      tcp_timestamps: true,
    },
    tg_settings: {
      host: '127.0.0.1', port: 1443, secret,
      dc_ip: ['2:149.154.167.220', '4:149.154.167.220'],
      cfproxy: true, h2: true,
      cf_domains_enabled: false, cf_domains: [],
      worker_enabled: false, worker_domains: [],
      pool_size: 4, buf_kb: 256, no_secure: false, verbose: false,
    },
    diag: { running: false, at: null, items: [] },
  };

  const fakes = { discord: 'quic_initial_www_google_com', game: 'quic_initial_5ka_ru' };
  let hostsUpToDate = false;
  const previousVersions = {};
  let testTimer = null;

  function refreshLink() {
    const settings = state.tg_settings;
    state.tg.host = settings.host;
    state.tg.port = settings.port;
    state.tg.link = `tg://proxy?server=${settings.host}&port=${settings.port}&secret=dd${settings.secret}`;
  }
  refreshLink();

  /* ---------- Журнал ---------- */

  const logs = [];
  let logId = 0;
  const LOG_SAMPLES = {
    app: [
      ['info', 'Состояние сохранено в C:\\ProgramData\\Lazeyka\\state.json'],
      ['info', 'Проверка конфликтов: найдена служба GoodbyeDPI'],
      ['debug', 'Опрос служб Windows занял 41 мс'],
      ['info', 'Окно показано'],
      ['warn', 'Служба GoodbyeDPI всё ещё запущена — обход может работать нестабильно'],
    ],
    zapret: [
      ['info', 'winws: windivert initialized. capture is started.'],
      ['info', 'winws: loaded hostlist lists\\list-general.txt (58 hosts)'],
      ['info', 'winws: loaded hostlist lists\\list-google.txt (22 hosts)'],
      ['debug', 'winws: desync profile 2: fake,multisplit for discord.com:443'],
      ['debug', 'winws: udp 50007 discord voice → fake quic_initial_www_google_com'],
      ['warn', 'winws: tcp retransmission to 162.159.130.234:443, повторяем с другим профилем'],
    ],
    tg: [
      ['info', 'DC2 → WebSocket kws2.web.telegram.org: подключено за 84 мс'],
      ['info', 'DC4 медиа → Cloudflare (HTTP/2): подключено за 131 мс'],
      ['debug', 'pool: 4/4 соединений готовы, попаданий 37 из 41'],
      ['warn', 'DC5: WebSocket не ответил за 5 с — переключаемся на Cloudflare'],
      ['info', 'Новый клиент Telegram 127.0.0.1:53814'],
      ['error', 'DC1: TCP напрямую — соединение сброшено провайдером'],
    ],
  };

  function log(src, lvl, msg, at) {
    logId += 1;
    logs.push({ id: logId, t: at || nowSec(), src, lvl, msg });
    if (logs.length > LOG_KEEP) logs.splice(0, logs.length - LOG_KEEP);
  }

  function randomLog(at) {
    const src = pick(['app', 'zapret', 'zapret', 'tg', 'tg', 'tg']);
    const [lvl, msg] = pick(LOG_SAMPLES[src]);
    log(src, lvl, msg, at);
  }

  for (let i = 0; i < LOG_BACKLOG; i += 1) randomLog(startedAt - (LOG_BACKLOG - i) * 4.2);
  log('app', 'info', 'Лазейка 1.0.0 запущена');

  /* ---------- Telegram: статистика ---------- */

  let upRate = 14 * KB;
  let downRate = 160 * KB;

  /** Идёт ли трафик Telegram через прокси: прокси работает, и клиент (о нём знает mock-help.js) подключён. */
  function telegramLinked() {
    const tg = state.tg;
    return tg.status === 'running' && !(tg.client && tg.client.connected === false);
  }

  function nextRates() {
    if (!telegramLinked()) return [0, 0];
    downRate = chance(0.07) ? random(600 * KB, 2.4 * MB) : clamp(downRate * random(0.62, 1.3) + random(-24, 24) * KB, 6 * KB, 2.6 * MB);
    upRate = clamp(upRate * random(0.7, 1.3) + random(-4, 4) * KB, 1.5 * KB, 220 * KB);
    return [upRate, downRate];
  }

  for (let i = HISTORY_POINTS; i > 0; i -= 1) {
    const [up, down] = nextRates();
    state.tg.history.push([Math.round(startedAt - i), Math.round(up), Math.round(down)]);
  }

  function tickTelegram() {
    const tg = state.tg;
    const stats = tg.stats;
    const [up, down] = nextRates();
    stats.up_rate = Math.round(up);
    stats.down_rate = Math.round(down);
    stats.up += Math.round(up);
    stats.down += Math.round(down);
    if (telegramLinked()) {
      stats.active = clamp(stats.active + (chance(0.25) ? pick([-1, 1]) : 0), 1, 6);
      if (chance(0.18)) {
        stats.total += 1;
        const route = pick(['ws', 'ws', 'ws', 'ws', 'cf', 'h2', 'tcp_fallback']);
        stats[route] += 1;
      }
    } else {
      stats.active = 0;
    }
    tg.history.push([Math.round(nowSec()), stats.up_rate, stats.down_rate]);
    if (tg.history.length > HISTORY_POINTS) tg.history.splice(0, tg.history.length - HISTORY_POINTS);
  }

  /* Раз в секунду: трафик Telegram, затем подписчики из дополнений (сторож, клиент Telegram). */
  const tickHandlers = [];
  setInterval(() => {
    tickTelegram();
    for (const handler of tickHandlers) handler();
    if (chance(0.55)) randomLog();
  }, TICK_MS);

  /* ---------- zapret ---------- */

  function zapretRun(statusDuring, delayMs, done) {
    state.zapret.status = statusDuring;
    later(delayMs, done);
  }

  function startZapret(reason) {
    const zapret = state.zapret;
    zapret.error = null;
    zapretRun('starting', 1100, () => {
      if (zapret.strategy === BROKEN_STRATEGY) {
        zapret.status = 'error';
        zapret.started_at = null;
        zapret.error = 'winws.exe завершился с кодом 1: стратегия «EXP» требует более новый драйвер WinDivert.';
        log('zapret', 'error', zapret.error);
        return;
      }
      zapret.status = 'running';
      zapret.started_at = nowSec();
      log('zapret', 'info', `winws запущен (${reason}), стратегия ${zapret.strategy}`);
    });
  }

  function stopZapret() {
    zapretRun('stopping', 600, () => {
      state.zapret.status = 'stopped';
      state.zapret.started_at = null;
      log('zapret', 'info', 'winws остановлен');
    });
  }

  function requireZapret() {
    return state.zapret.available ? null : fail('Обход недоступен: нужны права администратора. Перезапустите Лазейку от имени администратора.');
  }

  /** Те же правила, что у service.bat: порты и диапазоны через запятую. */
  function portsError(text) {
    const value = String(text || '').replace(/\s+/g, '');
    if (!value) return 'Укажите хотя бы один порт или диапазон';
    for (const item of value.split(',')) {
      const match = /^([1-9]\d{0,4})(?:-([1-9]\d{0,4}))?$/.exec(item);
      if (!match) return `«${item}» — не порт и не диапазон`;
      const start = Number(match[1]);
      const end = Number(match[2] || match[1]);
      if (start > PORT_MAX || end > PORT_MAX) return `Порт не может быть больше ${PORT_MAX}`;
      if (start > end) return `В диапазоне ${item} начало больше конца`;
    }
    return null;
  }

  function checkResult(quality, allowUnsup) {
    if (Math.random() < quality) return 'ok';
    if (allowUnsup && chance(0.25)) return 'unsup';
    return chance(0.12) ? 'ssl' : 'fail';
  }

  function testStrategy(id, kind) {
    const label = STRATEGIES.find((item) => item.id === id).label;
    if (id === BROKEN_STRATEGY) {
      return { id, label, ok: 0, fail: 0, unsup: 0, ping_ok: 0, ping_total: 0, score: 0, started: false, targets: [] };
    }
    const quality = STRATEGY_QUALITY[id] != null ? STRATEGY_QUALITY[id] : random(0.3, 0.9);
    const targets = (kind === 'dpi' ? DPI_TARGETS : STANDARD_TARGETS).map(([name, url]) => ({
      name,
      url,
      http: kind === 'dpi' ? null : checkResult(quality, false),
      tls12: checkResult(quality, false),
      tls13: checkResult(quality, name === 'Discord Updates'),
      ping: chance(quality) ? randomInt(18, 90) : null,
    }));
    let okCount = 0;
    let failCount = 0;
    let unsupCount = 0;
    for (const target of targets) {
      for (const key of ['http', 'tls12', 'tls13']) {
        if (target[key] === 'ok') okCount += 1;
        else if (target[key] === 'unsup') unsupCount += 1;
        else if (target[key]) failCount += 1;
      }
    }
    const pingOk = clamp(Math.round(PING_TOTAL * quality + random(-0.6, 0.6)), 0, PING_TOTAL);
    const checked = okCount + failCount;
    const score = checked ? 0.85 * (okCount / checked) + 0.15 * (pingOk / PING_TOTAL) : 0;
    return {
      id, label, ok: okCount, fail: failCount, unsup: unsupCount,
      ping_ok: kind === 'dpi' ? 0 : pingOk, ping_total: kind === 'dpi' ? 0 : PING_TOTAL,
      score: Math.round(score * 100) / 100, started: true, targets,
    };
  }

  function bestResult(results) {
    const started = results.filter((result) => result.started && result.score > 0);
    if (!started.length) return null;
    return started.reduce((best, result) => (result.score > best.score ? result : best)).id;
  }

  function finishTest(cancelled) {
    const test = state.zapret.test;
    clearTimeout(testTimer);
    testTimer = null;
    test.running = false;
    test.current = null;
    test.finished_at = nowSec();
    test.best = bestResult(test.results);
    log('zapret', 'info', cancelled
      ? `Подбор остановлен на ${test.done} из ${test.total}`
      : `Подбор завершён, лучшая стратегия: ${test.best || 'не найдена'}`);
  }

  function runTestStep(queue, kind) {
    const test = state.zapret.test;
    if (!test.running) return;
    const id = queue[test.done];
    test.results.push(testStrategy(id, kind));
    test.done += 1;
    if (test.done >= test.total) {
      finishTest(false);
      return;
    }
    test.current = queue[test.done];
    testTimer = later(TEST_STEP_MS, () => runTestStep(queue, kind));
  }

  /* ---------- Обновления ---------- */

  function updateItem(id) {
    return state.updates.items.find((item) => item.id === id);
  }

  function recount() {
    state.updates.count = state.updates.items.filter((item) => item.available && !item.skipped && item.state !== 'done').length;
  }

  function setNotice(notice) {
    state.notices = state.notices.filter((item) => item.id !== notice.id).concat(notice);
  }

  function dropNotice(id) {
    state.notices = state.notices.filter((item) => item.id !== id);
  }

  function checkForUpdates() {
    const updates = state.updates;
    if (updates.checking) return;
    updates.checking = true;
    updates.error = null;
    later(UPDATE_CHECK_MS, () => {
      updates.checking = false;
      updates.last_check = nowSec();
      const item = updateItem('zapret');
      if (item.current !== '1.10.4') {
        Object.assign(item, {
          latest: '1.10.4', available: true, published_at: '2026-10-09T14:20:00Z', notes: RELEASE_NOTES,
          url: 'https://github.com/Flowseal/zapret-discord-youtube/releases/tag/1.10.4',
        });
        if (!item.skipped) {
          setNotice({
            id: 'update-available', level: 'info', text: 'Вышли новые стратегии zapret 1.10.4',
            action: { label: 'Посмотреть', page: 'updates' }, dismissible: true,
          });
        }
      }
      recount();
      log('app', 'info', `Проверка обновлений: доступно ${updates.count}`);
    });
  }

  function installUpdate(item) {
    let step = 0;
    item.state = 'downloading';
    item.progress = 0;
    item.message = null;
    const size = 3.6;
    const tick = () => {
      step += 1;
      item.progress = step / DOWNLOAD_STEPS;
      item.message = `Скачиваем: ${(size * item.progress).toFixed(1).replace('.', ',')} из 3,6 МБ`;
      if (step < DOWNLOAD_STEPS) {
        later(DOWNLOAD_STEP_MS, tick);
        return;
      }
      item.state = 'verifying';
      item.progress = null;
      item.message = 'Проверяем целостность файла…';
      later(900, () => {
        item.state = 'installing';
        item.message = 'Устанавливаем и перезапускаем обход…';
        later(1300, () => {
          previousVersions[item.id] = item.current;
          item.current = item.latest;
          item.available = false;
          item.state = 'done';
          item.can_rollback = true;
          item.message = `Готово: установлена версия ${item.latest}. Предыдущую мы сохранили — её можно вернуть кнопкой «Откатить».`;
          if (item.id === 'zapret') state.zapret.pack.version = item.latest;
          dropNotice('update-available');
          recount();
          log('app', 'info', `Установлено обновление ${item.title} ${item.latest}`);
        });
      });
    };
    later(DOWNLOAD_STEP_MS, tick);
  }

  /*
   * Застывшее состояние обновления zapret для скриншотов и ручной проверки UI.
   * Отменяет автопроверку, чтобы она не перетёрла заданные поля, и ничего не планирует:
   * страница остаётся в этом состоянии, сколько нужно.
   */
  function freezeZapretUpdate(overrides) {
    if (autoCheckTimer) clearTimeout(autoCheckTimer);
    dropNotice('update-available');
    const item = updateItem('zapret');
    Object.assign(item, {
      latest: '1.10.4', available: true, skipped: false,
      published_at: '2026-10-09T14:20:00Z', notes: RELEASE_NOTES,
      url: 'https://github.com/Flowseal/zapret-discord-youtube/releases/tag/1.10.4',
      state: 'idle', progress: null, message: null, can_rollback: false,
    }, overrides || {});
    state.updates.checking = false;
    state.updates.last_check = nowSec();
    recount();
  }

  /* ---------- Диагностика ---------- */

  function diagItems() {
    const zapret = state.zapret;
    const hasConflict = zapret.conflicts.some((conflict) => conflict.id === 'service:GoodbyeDPI');
    return [
      { id: 'bfe', title: 'Base Filtering Engine', status: 'ok', text: 'Служба работает', fix: null },
      {
        id: 'admin', title: 'Права администратора', status: admin ? 'ok' : 'error',
        text: admin ? 'Лазейка запущена от имени администратора' : 'Без прав администратора обход не запустится',
        fix: admin ? null : { id: 'relaunch', label: 'Перезапустить' },
      },
      { id: 'tcp_ts', title: 'TCP timestamps', status: 'ok', text: 'Включены', fix: null },
      hasConflict
        ? { id: 'goodbyedpi', title: 'Другие обходы', status: 'error', text: 'Запущена служба GoodbyeDPI — она перехватывает тот же трафик, что и zapret.', fix: { id: 'goodbyedpi', label: 'Удалить службу' } }
        : { id: 'goodbyedpi', title: 'Другие обходы', status: 'ok', text: 'Не найдено', fix: null },
      { id: 'adguard', title: 'AdGuard', status: 'warn', text: 'AdGuard запущен и может мешать Discord. Добавьте Discord в исключения или выключите фильтрацию HTTPS.', fix: null },
      { id: 'vpn', title: 'VPN', status: 'warn', text: 'Найдена служба NordVPN. Пока работает обход, VPN лучше выключить.', fix: null },
      hostsUpToDate
        ? { id: 'hosts', title: 'Файл hosts', status: 'ok', text: 'Лишних записей нет', fix: null }
        : { id: 'hosts', title: 'Файл hosts', status: 'warn', text: 'В hosts есть записи для youtube.com — YouTube может не открываться.', fix: { id: 'hosts', label: 'Убрать записи' } },
      { id: 'killer', title: 'Killer Network Service', status: 'ok', text: 'Не найдено', fix: null },
      { id: 'intel', title: 'Intel Connectivity Network Service', status: 'ok', text: 'Не найдено', fix: null },
      { id: 'smartbyte', title: 'SmartByte', status: 'ok', text: 'Не найдено', fix: null },
      { id: 'windivert', title: 'Драйвер WinDivert', status: 'ok', text: 'Установлен и не занят другими программами', fix: null },
      { id: 'doh', title: 'Защищённый DNS', status: 'info', text: 'Windows не использует DNS-over-HTTPS. Если сайты всё равно не открываются, включите его в параметрах сети.', fix: null },
    ];
  }

  /* ---------- Проверки Telegram ---------- */

  function telegramRoutes() {
    const settings = state.tg_settings;
    return [
      { name: 'WebSocket напрямую, DC2', ok: true, detail: '101 Switching Protocols · 84 мс' },
      { name: 'WebSocket напрямую, DC4', ok: true, detail: '101 Switching Protocols · 97 мс' },
      { name: 'WebSocket напрямую, DC5', ok: false, detail: 'Нет ответа за 5 с' },
      { name: 'Cloudflare, HTTP/2', ok: settings.cfproxy, detail: settings.cfproxy ? '200 OK · 131 мс' : 'Выключено в настройках' },
      { name: 'Cloudflare Worker', ok: false, detail: settings.worker_enabled ? 'Домен не отвечает' : 'Не настроен' },
      { name: 'TCP напрямую, DC1', ok: false, detail: 'Соединение сброшено провайдером' },
    ];
  }

  function validateTelegram(values) {
    const errors = {};
    if (!values || typeof values !== 'object') return { form: 'Пустые настройки' };
    if (!String(values.host || '').trim()) errors.host = 'Укажите адрес';
    if (!Number.isInteger(values.port) || values.port < 1 || values.port > PORT_MAX) errors.port = 'Порт должен быть числом 1–65535';
    if (!/^[0-9a-f]{32}$/.test(String(values.secret || ''))) errors.secret = 'Ключ — 32 шестнадцатеричных символа';
    if (!Array.isArray(values.dc_ip) || values.dc_ip.some((line) => !/^\d+:\S+$/.test(line))) errors.dc_ip = 'Формат строки: номер:адрес';
    if (!Number.isInteger(values.pool_size) || values.pool_size < 1 || values.pool_size > 64) errors.pool_size = 'От 1 до 64';
    if (!Number.isInteger(values.buf_kb) || values.buf_kb < 4 || values.buf_kb > 4096) errors.buf_kb = 'От 4 до 4096 КБ';
    return errors;
  }

  function restartTelegram() {
    state.tg.status = 'starting';
    later(800, () => {
      state.tg.status = 'running';
      state.tg.started_at = nowSec();
      log('tg', 'info', `Прокси слушает ${state.tg.host}:${state.tg.port}`);
    });
  }

  /* ---------- API ---------- */

  const api = {
    get_state: () => reply(state, STATE_DELAY_MS),

    get_logs(afterId, source) {
      const after = Number(afterId) || 0;
      const matched = logs.filter((line) => line.id > after && (source === 'all' || !source || line.src === source));
      return reply({ lines: matched.slice(-LOG_RESPONSE_LIMIT), last_id: logId }, STATE_DELAY_MS);
    },

    finish_onboarding(opts) {
      state.app.first_run = false;
      state.settings.check_updates = Boolean(opts && opts.check_updates);
      state.settings.autostart = Boolean(opts && opts.autostart);
      state.updates.auto_check = state.settings.check_updates;
      log('app', 'info', 'Приветствие пройдено');
      return ok();
    },

    save_settings(partial) {
      if (!partial || typeof partial !== 'object') return fail('Нечего сохранять');
      const unknown = Object.keys(partial).filter((key) => !(key in state.settings));
      if (unknown.length) return fail(`Неизвестные настройки: ${unknown.join(', ')}`);
      if ('theme' in partial && !['system', 'dark', 'light'].includes(partial.theme)) return fail('Нет такой темы');
      Object.assign(state.settings, partial);
      if ('check_updates' in partial) state.updates.auto_check = Boolean(partial.check_updates);
      return ok();
    },

    dismiss_notice(id) {
      dropNotice(id);
      return ok();
    },

    open_url(url) {
      if (!/^https:\/\//.test(String(url))) return fail('Открываем только адреса https://');
      log('app', 'info', `Открываем в браузере: ${url}`);
      return ok();
    },

    open_path(kind) {
      if (!['logs', 'data', 'lists'].includes(kind)) return fail(`Неизвестная папка: ${kind}`);
      log('app', 'info', `Открываем папку: ${kind}`);
      return ok();
    },

    copy_text(text) {
      log('app', 'debug', `В буфер обмена: ${String(text).length} символов`);
      return ok();
    },

    relaunch_admin() {
      log('app', 'info', 'Перезапуск с правами администратора');
      later(1500, () => {
        state.app.admin = true;
        state.zapret.available = true;
        state.zapret.unavailable_reason = null;
      });
      return ok();
    },

    hide_window: () => ok(),
    quit_app: () => ok(),

    zapret_start() {
      const denied = requireZapret();
      if (denied) return denied;
      startZapret('по кнопке');
      return ok();
    },

    zapret_stop() {
      stopZapret();
      return ok();
    },

    zapret_restart() {
      const denied = requireZapret();
      if (denied) return denied;
      startZapret('перезапуск');
      return ok();
    },

    zapret_set_strategy(id) {
      const denied = requireZapret();
      if (denied) return denied;
      if (!STRATEGY_IDS.includes(id)) return fail(`Стратегии «${id}» нет в пакете`);
      state.zapret.strategy = id;
      log('zapret', 'info', `Выбрана стратегия ${id}`);
      if (state.zapret.status === 'running' || state.zapret.status === 'error') startZapret('смена стратегии');
      return ok();
    },

    zapret_set_game_filter(mode, tcp, udp) {
      if (!['disabled', 'all', 'tcp', 'udp'].includes(mode)) return fail(`Неизвестный режим: ${mode}`);
      const errors = {};
      const tcpError = portsError(tcp);
      const udpError = portsError(udp);
      if (tcpError) errors.tcp = tcpError;
      if (udpError) errors.udp = udpError;
      if (Object.keys(errors).length) return fail('Проверьте диапазоны портов', errors);
      state.zapret.game_filter = { mode, tcp: String(tcp).replace(/\s+/g, ''), udp: String(udp).replace(/\s+/g, '') };
      if (state.zapret.status === 'running') startZapret('игровой фильтр');
      return ok();
    },

    zapret_set_ipset(mode) {
      if (!['none', 'loaded', 'any'].includes(mode)) return fail(`Неизвестный режим: ${mode}`);
      state.zapret.ipset.mode = mode;
      if (state.zapret.status === 'running') startZapret('список IP');
      return ok();
    },

    zapret_update_ipset() {
      state.zapret.ipset.count = 33048 + randomInt(10, 600);
      return ok({ message: `Список IP обновлён: ${state.zapret.ipset.count.toLocaleString('ru-RU')} подсетей` }, 1400);
    },

    zapret_set_mode(mode) {
      if (!['app', 'service'].includes(mode)) return fail(`Неизвестный режим: ${mode}`);
      const zapret = state.zapret;
      state.app.busy = mode === 'service' ? 'Устанавливаем службу Windows…' : 'Удаляем службу Windows…';
      later(1500, () => {
        state.app.busy = null;
        zapret.mode = mode;
        zapret.service = mode === 'service'
          ? { installed: true, running: true, strategy: zapret.strategy }
          : { installed: false, running: false, strategy: null };
      });
      return ok(null, 600);
    },

    zapret_test_start(kind, ids) {
      const denied = requireZapret();
      if (denied) return denied;
      const test = state.zapret.test;
      if (test.running) return fail('Подбор уже идёт');
      const queue = Array.isArray(ids) && ids.length ? ids.filter((id) => STRATEGY_IDS.includes(id)) : STRATEGY_IDS.slice();
      Object.assign(test, {
        running: true, kind: kind === 'dpi' ? 'dpi' : 'standard', total: queue.length, done: 0,
        current: queue[0], best: null, error: null, finished_at: null, results: [],
      });
      log('zapret', 'info', `Подбор стратегий: ${queue.length}, проверка ${test.kind}`);
      testTimer = later(TEST_STEP_MS, () => runTestStep(queue, test.kind));
      return ok();
    },

    zapret_test_cancel() {
      if (state.zapret.test.running) finishTest(true);
      return ok();
    },

    zapret_fix_conflict(id) {
      later(700, () => {
        state.zapret.conflicts = state.zapret.conflicts.filter((conflict) => conflict.id !== id);
        log('app', 'info', `Конфликт устранён: ${id}`);
      });
      return ok(null, 500);
    },

    lists_get: () => reply({ lists: LISTS }),

    lists_save(id, text) {
      const list = LISTS.find((item) => item.id === id);
      if (!list) return fail(`Списка «${id}» нет`);
      if (!list.editable) return fail('Встроенные списки менять нельзя');
      const bad = String(text).split(/\r?\n/).map((line) => line.trim()).find((line) => line && /\s/.test(line));
      if (bad) return fail(`Строка «${bad}» содержит пробел — по одному домену или адресу на строку`);
      list.text = String(text);
      if (state.zapret.status === 'running') startZapret('список изменён');
      return ok();
    },

    fakes_get: () => reply({ current: { ...fakes }, files: FAKE_FILES }),

    fakes_set(slot, name) {
      if (!(slot in fakes)) return fail(`Неизвестный слот: ${slot}`);
      if (!FAKE_FILES.includes(name)) return fail(`Файла ${name}.bin нет в папке bin`);
      fakes[slot] = name;
      return ok();
    },

    hosts_check() {
      return ok(hostsUpToDate
        ? { up_to_date: true, text: 'Файл hosts в порядке — все записи на месте.' }
        : { up_to_date: false, text: 'В hosts не хватает 6 записей для голосовых серверов Discord.' }, 900);
    },

    hosts_apply() {
      hostsUpToDate = true;
      return ok(null, 900);
    },

    tg_start() {
      restartTelegram();
      return ok();
    },

    tg_stop() {
      state.tg.status = 'stopped';
      state.tg.started_at = null;
      log('tg', 'info', 'Прокси остановлен');
      return ok();
    },

    tg_restart() {
      restartTelegram();
      return ok();
    },

    tg_open_in_telegram() {
      log('app', 'info', 'Открываем ссылку tg://proxy в Telegram Desktop');
      return ok();
    },

    tg_copy_link: () => ok(),

    tg_save_settings(values) {
      const errors = validateTelegram(values);
      if (Object.keys(errors).length) return fail('Проверьте поля, отмеченные красным', errors);
      Object.assign(state.tg_settings, clone(values));
      refreshLink();
      if (state.tg.status === 'running') restartTelegram();
      return ok();
    },

    tg_regen_secret() {
      state.tg_settings.secret = hex(32);
      refreshLink();
      if (state.tg.status === 'running') restartTelegram();
      return ok();
    },

    tg_test() {
      const test = state.tg.test;
      if (test.running) return ok();
      test.running = true;
      later(2300, () => {
        test.running = false;
        test.at = nowSec();
        test.results = telegramRoutes();
      });
      return ok();
    },

    diag_run() {
      const diag = state.diag;
      if (diag.running) return ok();
      diag.running = true;
      later(DIAG_MS, () => {
        diag.running = false;
        diag.at = nowSec();
        diag.items = diagItems();
      });
      return ok();
    },

    diag_fix(id) {
      later(900, () => {
        if (id === 'goodbyedpi') state.zapret.conflicts = state.zapret.conflicts.filter((c) => c.id !== 'service:GoodbyeDPI');
        if (id === 'hosts') hostsUpToDate = true;
        state.diag.items = state.diag.items.map((item) => (item.fix && item.fix.id === id
          ? { ...item, status: 'ok', text: 'Исправлено', fix: null } : item));
      });
      return ok(null, 600);
    },

    discord_clear_cache: () => ok(null, 1200),

    updates_check() {
      checkForUpdates();
      return ok();
    },

    updates_install(id) {
      const item = updateItem(id);
      if (!item) return fail(`Неизвестный компонент: ${id}`);
      if (!item.available) return fail('Новой версии нет — устанавливать нечего');
      if (['downloading', 'verifying', 'installing'].includes(item.state)) return fail('Обновление уже устанавливается');
      installUpdate(item);
      return ok();
    },

    updates_skip(id) {
      const item = updateItem(id);
      if (!item) return fail(`Неизвестный компонент: ${id}`);
      item.skipped = true;
      dropNotice('update-available');
      recount();
      return ok();
    },

    updates_rollback(id) {
      const item = updateItem(id);
      if (!item || !item.can_rollback) return fail('Откатывать нечего');
      item.state = 'installing';
      item.message = 'Возвращаем предыдущую версию…';
      later(1300, () => {
        item.current = previousVersions[item.id] || item.current;
        item.available = item.latest !== item.current;
        item.skipped = false;
        item.can_rollback = false;
        item.state = 'idle';
        item.message = null;
        if (item.id === 'zapret') state.zapret.pack.version = item.current;
        recount();
      });
      return ok();
    },
  };

  /* ---------- Запуск имитации ---------- */

  const autoCheckTimer = state.settings.check_updates
    ? later(AUTO_UPDATE_CHECK_DELAY_MS, checkForUpdates) : null;

  const DEMOS = {
    test: () => api.zapret_test_start('standard', null),
    diag: () => api.diag_run(),
    check: () => api.zapret_check(),
    install: () => later(AUTO_UPDATE_CHECK_DELAY_MS + UPDATE_CHECK_MS, () => api.updates_install('zapret')),
    /* Застывшие состояния страницы «Обновления» — для скриншотов и ручной проверки UI. */
    update: () => freezeZapretUpdate(),
    downloading: () => freezeZapretUpdate({ state: 'downloading', progress: 0.42, message: 'Скачиваем: 1,5 из 3,6 МБ' }),
    verifying: () => freezeZapretUpdate({ state: 'verifying', message: 'Проверяем целостность файла…' }),
    installing: () => freezeZapretUpdate({ state: 'installing', message: 'Устанавливаем и перезапускаем обход…' }),
    done: () => freezeZapretUpdate({
      state: 'done', available: false, current: '1.10.4', can_rollback: true,
      message: 'Готово: установлена версия 1.10.4. Предыдущую мы сохранили — её можно вернуть кнопкой «Откатить».',
    }),
    error: () => freezeZapretUpdate({
      state: 'error',
      message: 'Не удалось проверить архив: SHA-256 не совпал с релизом на GitHub. Файл мог скачаться с ошибкой — попробуйте ещё раз.',
    }),
    uptodate: () => {
      if (autoCheckTimer) clearTimeout(autoCheckTimer);
      state.updates.last_check = nowSec();
      recount();
    },
  };
  const DEMO_DELAY_MS = 300;

  function publish() {
    const demo = DEMOS[params.get('demo')];
    if (demo) later(DEMO_DELAY_MS, demo);
    window.pywebview = { api };
    window.dispatchEvent(new Event('pywebviewready'));
  }

  /*
   * Дополнения версии 1.1 живут в отдельных файлах и регистрируются в window.LzMockExtensions.
   * Подключаем их по порядку и только потом объявляем ядро готовым.
   */
  const EXTENSION_FILES = ['mock-zapret.js', 'mock-help.js', 'mock-vpn.js'];

  function loadScript(src) {
    return new Promise((resolve, reject) => {
      const script = document.createElement('script');
      script.src = src;
      script.addEventListener('load', resolve);
      script.addEventListener('error', () => reject(new Error(`${src} не загрузился`)));
      document.head.append(script);
    });
  }

  async function installExtensions() {
    const context = {
      state, api, params, logs, startedAt,
      demos: DEMOS,
      onTick: (handler) => tickHandlers.push(handler),
      nowSec, later, ok, fail, log,
      STRATEGIES, STRATEGY_IDS, STRATEGY_QUALITY, LISTS,
      startZapret, requireZapret, bestResult, setNotice, dropNotice,
    };
    for (const file of EXTENSION_FILES) {
      try {
        await loadScript(file);
      } catch (err) {
        console.error(`Имитация работает без ${file} — часть контракта 1.1 недоступна:`, err);
      }
    }
    for (const install of window.LzMockExtensions || []) {
      try {
        install(context);
      } catch (err) {
        console.error('Дополнение имитации не установилось:', err);
      }
    }
    publish();
  }

  installExtensions();
})();
