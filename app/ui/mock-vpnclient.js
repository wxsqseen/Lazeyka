'use strict';
/*
 * Имитация раздела контракта «Версия 1.2 — свой VPN» (docs/vpnclient-plan.md, раздел 6):
 * состояние vpnclient из mock-vpnclient-state.json и все методы vpnclient_* на таймерах —
 * импорт с ходом, задержки, тест скорости, установка ядер, переключение сервера, конфликт
 * с чужим VPN, ссылки lazeyka://. Подключается из mock.js — отдельно не работает.
 * Эталон грузится fetch'ем по относительному пути: страницу открывают через http-сервер.
 *
 * Параметры адреса:
 *   vpnc=on         — подключено в режиме «Весь трафик» (по умолчанию, как в эталоне)
 *   vpnc=off        — выключено, серверы есть
 *   vpnc=proxy      — подключено как системный прокси
 *   vpnc=tun        — первое включение: ядро ещё качается с GitHub, «Включить» ждёт его, затем «Проверяем соединение…»
 *   vpnc=nocore     — ядро не скачалось при запуске: плашка «Скачать ещё раз», повтор по расписанию
 *   vpnc=autoupdate — ядро обновилось само до 1.15.0 и заработает со следующего подключения
 *   vpnc=empty      — ни одной подписки и сервера: пустое состояние, ядра не установлены
 *   vpnc=error      — не подключилось: сервер отклонил рукопожатие REALITY
 *   vpnc=conflict   — работает Incy: при включении — окно «Уже работает другой VPN»
 *   vpnc=uac        — то же, но Лазейка запущена от другой учётной записи UAC: режим прокси недоступен
 *   vpnc=xhttp      — выбран сервер XHTTP, он работает через помощник Xray
 *   vpnc=import     — идёт импорт подписки, затем предложение представиться другим клиентом
 *   vpnc=offer      — сразу предложение после импорта (панель ответила 403)
 *   vpnc=deeplink   — пришла ссылка lazeyka:// — окно «Добавить из ссылки?»
 *   vpnc=expiring   — подписка заканчивается через 2 дня, израсходовано 93 % трафика
 *   vpnc=coreupdate — вышло обновление ядра sing-box 1.14.4
 *   scale=0.8…1.5   — масштаб окна (settings.ui_scale)
 *   vpncdemo=start|qr|props|backup|apps|delete|menu|rename|dirty — открыть окно раздела (для скриншотов)
 */
(window.LzMockExtensions = window.LzMockExtensions || []).push(function installVpnClient(mock) {
  const { state, api, params, nowSec, later, ok, fail, log } = mock;

  const STATE_URL = 'mock-vpnclient-state.json';
  const SCENARIO = params.get('vpnc') || 'on';
  /* Эталон снят «сейчас»; имитация сдвигает все его времена так, будто VPN включили 12 минут назад. */
  const STARTED_AGO_SEC = 720;
  const HISTORY_POINTS = 120;
  const KB = 1024;
  const MB = KB * KB;
  const GB = MB * KB;
  const DAY_SEC = 86400;
  const PORT_MAX = 65535;
  const START_MS = 1100;
  const VERIFY_MS = 1600;
  const STOP_MS = 600;
  const RESELECT_MS = 900;
  const LATENCY_STEP_MS = 260;
  const SPEED_MS = 2600;
  const RULES_MS = 2400;
  const SUB_UPDATE_MS = 1500;
  const PROBE_MS = 1800;
  const CORE_STEP_MS = 1200;
  const DOWNLOAD_STEPS = 8;
  const DOWNLOAD_STEP_MS = 260;
  const IMPORT_STEP_MS = SCENARIO === 'import' ? 3200 : 1000;
  const UPDATE_HOURS_MAX = 72;
  const QR_MODULES = 29;
  const QR_SCALE = 8;
  const LOG_SAMPLES = [
    ['info', 'outbound/vless[proxy]: соединение с 203.0.113.5:443 (REALITY, Vision)'],
    ['debug', 'dns: discord.com → dns-direct (через обход Лазейки)'],
    ['info', 'clash api: селектор bypass = direct'],
    ['debug', 'router: youtube.com → bypass (профиль TCP 443 стратегии ALT2)'],
    ['warn', 'outbound/vless[proxy]: повтор рукопожатия после обрыва сети'],
  ];
  const RUNNING_APPS = [
    { name: 'Discord.exe', path: 'C:\\Users\\User\\AppData\\Local\\Discord\\app-1.0.9205\\Discord.exe' },
    { name: 'chrome.exe', path: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe' },
    { name: 'firefox.exe', path: 'C:\\Program Files\\Mozilla Firefox\\firefox.exe' },
    { name: 'steam.exe', path: 'C:\\Program Files (x86)\\Steam\\steam.exe' },
    { name: 'qbittorrent.exe', path: 'C:\\Program Files\\qBittorrent\\qbittorrent.exe' },
    { name: 'Telegram.exe', path: 'C:\\Users\\User\\AppData\\Roaming\\Telegram Desktop\\Telegram.exe' },
    { name: 'Code.exe', path: 'C:\\Users\\User\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe' },
  ];
  const EXIT_IP = { NL: '203.0.113.5', DE: '203.0.113.17', FI: '203.0.113.33', SE: '203.0.113.49', PL: '203.0.113.65' };
  const BASE_LATENCY = { NL: 64, DE: 81, FI: 142, SE: 96, PL: 58 };
  const RULE_ITEMS = [
    { id: 'geosite-category-ru', title: 'Российские домены (sing-geosite)', size: 8704 },
    { id: 'geoip-ru', title: 'Российские IP (sing-geoip)', size: 50176 },
    { id: 'geosite-category-game-platforms-download', title: 'Загрузки игр (sing-geosite)', size: 1843 },
    { id: 'refilter-domains', title: 'Заблокированные домены (re:filter)', size: 579584 },
    { id: 'russia-inside', title: 'Заблокированные домены (itdoginfo)', size: 8806 },
    { id: 'geoip-ru-blocked', title: 'Заблокированные IP (runetfreedom)', size: 200704 },
  ];
  const ROUTING_KEYS = new Set(['preset', 'via_zapret', 'games_direct', 'torrents_direct', 'ip_check_direct',
    'direct_apps', 'proxy_apps', 'direct_sites', 'proxy_sites']);
  /* Как _LIVE_KEYS ядра: без перезапуска меняются только эти, остальное входит в конфиг. */
  const LIVE_KEYS = new Set(['sort', 'latency_on_update', 'sub_update_hours', 'deeplink', 'on_sleep', 'kill_switch', 'core_auto_update']);
  const UA_PRESET_OPTIONS = ['v2rayn', 'happ', 'incy'];
  const UA_PRESETS = ['lazeyka', ...UA_PRESET_OPTIONS, 'custom'];
  const UA_LABEL = { v2rayn: 'как v2rayN', happ: 'как Happ', incy: 'как Incy' };
  const MODES = ['tun', 'proxy', 'local'];
  /* Чужой VPN и учётная запись UAC — то, что в ядре видят Core (_own_conflict) и менеджер (preflight). */
  const FOREIGN_TUNNEL = SCENARIO === 'conflict' || SCENARIO === 'uac' ? 'Incy' : null;
  const PROXY_DENIED = SCENARIO === 'uac'
    ? 'Режим «Системный прокси» недоступен: Лазейка запущена от имени другой учётной записи (в окне UAC ввели пароль другого администратора), и её прокси не подействует на ваши программы. Включите режим «Весь трафик» или запустите Лазейку из своей учётной записи.'
    : null;
  const SUPPORTED_SCHEMES = /^(vless|vmess|ss|trojan|hysteria2|hy2|tuic|wireguard|socks5?):\/\//i;
  const UNSUPPORTED_SCHEMES = /^(anytls|naive\+https|ssr|trojan-go|amneziawg|sstp|openconnect):\/\//i;

  let vc = null;
  /* Адреса подписок — секрет ядра; имитация держит их у себя, как profiles.json. */
  const subUrls = new Map();
  /* Пароль локального прокси и свои User-Agent подписок странице не отдаются — как local-proxy.json ядра. */
  let localPassword = null;
  const customAgents = new Map();
  /* Следы других VPN для панели «Помощи» (vpnclient_help): мёртвый прокси и DNS после Incy — в сценарии error. */
  let traces = SCENARIO === 'error' ? [
    {
      id: 'vpnclient_dead_proxy', level: 'error', fix: 'vpnclient_proxy_fix', address: '127.0.0.1:10809', ours: false,
      title: 'Системный прокси указывает на выключенную программу',
      text: 'В настройках Windows включён прокси 127.0.0.1:10809, но там никто не отвечает — браузеры не откроют сайты. Его оставила другая VPN-программа после аварии: выключите его.',
    },
    {
      id: 'vpnclient_fake_dns', level: 'error', fix: 'vpnclient_open_adapters',
      title: 'DNS адаптера «Ethernet» — остаток другого VPN',
      text: 'У адаптера «Ethernet» DNS-сервер 198.18.0.2: так его настраивают VPN-программы (например, Incy), а после аварии не возвращают. В свойствах адаптера → IP версии 4 выберите «Получить адрес DNS-сервера автоматически».',
    },
  ] : [];
  let upRate = 14 * KB;
  let downRate = 900 * KB;
  let idCounter = 0;

  const random = (min, max) => min + Math.random() * (max - min);
  const randomInt = (min, max) => Math.floor(random(min, max + 1));
  const clamp = (value, min, max) => Math.max(min, Math.min(max, value));
  const clone = (value) => JSON.parse(JSON.stringify(value));
  const newId = (prefix) => {
    idCounter += 1;
    return `${prefix}${Date.now().toString(16).slice(-6)}${idCounter}`;
  };
  const today = () => new Date().toISOString().slice(0, 10);

  /* ---------- Эталон и сценарии ---------- */

  function rebase(data) {
    const shift = nowSec() - STARTED_AGO_SEC - Number(data.started_at || nowSec());
    const move = (value) => (typeof value === 'number' && value > 0 ? value + shift : value);
    data.started_at = move(data.started_at);
    if (data.exit) data.exit.at = move(data.exit.at);
    for (const sub of data.subscriptions) {
      sub.updated_at = move(sub.updated_at);
      if (sub.userinfo) {
        sub.userinfo.expire = move(sub.userinfo.expire);
        sub.userinfo.refill_at = move(sub.userinfo.refill_at);
      }
    }
    for (const server of data.servers) {
      if (server.latency) server.latency.at = move(server.latency.at);
      if (server.speed) server.speed.at = move(server.speed.at);
    }
    data.traffic.day = today();
    data.history = [];
  }

  function serverById(id) {
    return vc.servers.find((server) => server.id === id) || null;
  }

  function selectedFor(id) {
    if (String(id).startsWith('auto:')) {
      const target = String(id).slice('auto:'.length);
      const group = vc.groups.find((item) => item.id === target);
      const members = group
        ? group.members.map(serverById).filter(Boolean)
        : vc.servers.filter((server) => server.sub === target);
      const live = members.filter((server) => server.supported && !(server.latency && server.latency.error));
      const ms = (server) => (server.latency && server.latency.ms) || Number.MAX_SAFE_INTEGER;
      const best = live.reduce((a, b) => (a && ms(a) <= ms(b) ? a : b), null);
      if (!best) return null;
      const sub = vc.subscriptions.find((item) => item.id === target);
      /* Как ядро: сервер, который выбрал «Самый быстрый», известен только у работающего VPN. */
      return {
        id: String(id), kind: 'auto', name: group ? group.name : `${sub ? sub.name : 'Подписка'}: самый быстрый`, country: null,
        proto: best.proto, transport: best.transport, security: best.security, engine: best.engine,
        actual: vc.status === 'running' ? { id: best.id, name: best.name, country: best.country } : null,
      };
    }
    const server = serverById(id);
    if (!server) return null;
    return {
      id: server.id, kind: 'server', name: server.name, country: server.country, proto: server.proto,
      transport: server.transport, security: server.security, engine: server.engine, actual: null,
    };
  }

  function exitFor(selected) {
    const country = selected ? (selected.actual ? selected.actual.country : selected.country) : null;
    return { ip: EXIT_IP[country] || '203.0.113.99', country: country || null, at: nowSec() };
  }

  /** «Самый быстрый» после смены статуса: actual — только у работающего VPN. */
  function refreshAuto() {
    if (vc.selected && vc.selected.kind === 'auto') vc.selected = selectedFor(vc.selected.id) || vc.selected;
  }

  function resetRuntime() {
    vc.started_at = null;
    vc.verified = false;
    vc.exit = null;
    vc.listen = null;
    vc.stats = { up: 0, down: 0, up_rate: 0, down_rate: 0, connections: 0 };
    vc.memory = { 'sing-box': null, xray: null };
    refreshAuto();
  }

  function needsXray() {
    const selected = vc.selected;
    return Boolean(selected && selected.engine === 'xray') || vc.servers.some((server) => server.engine === 'xray');
  }

  function applyScenario() {
    vc.subscriptions.forEach((sub) => { sub.probe = null; });
    vc.routing_profiles = [{ id: 'r-ru', name: 'Россия', source: 'subscription', active: false, summary: { direct: 12, proxy: 3, block: 2 } }];
    switch (SCENARIO) {
      case 'off':
        vc.status = 'stopped';
        resetRuntime();
        break;
      case 'proxy':
        vc.mode = 'proxy';
        vc.listen = `127.0.0.1:${vc.settings.port}`;
        break;
      case 'tun':
        vc.status = 'stopped';
        resetRuntime();
        Object.assign(vc.cores['sing-box'], { installed: false, version: null, in_use: null });
        Object.assign(vc.cores.xray, { installed: false, version: null, in_use: null });
        vc.selected = selectedFor('b1c2d3e4f5a6b7c8');
        later(500, () => api.vpnclient_start(true));
        break;
      case 'empty':
        vc.status = 'stopped';
        resetRuntime();
        vc.subscriptions = [];
        vc.servers = [];
        vc.groups = [];
        vc.selected = null;
        vc.routing_profiles = [];
        vc.traffic = { today_up: 0, today_down: 0, total_up: 0, total_down: 0, day: today() };
        Object.assign(vc.cores['sing-box'], { installed: false, version: null, in_use: null });
        Object.assign(vc.cores.xray, { installed: false, version: null, in_use: null, needed: false });
        break;
      case 'nocore': {
        vc.status = 'stopped';
        resetRuntime();
        const reason = 'Нет связи с GitHub: timed out (через системный прокси — тоже).';
        const retryAt = nowSec() + 300;
        Object.assign(vc.cores['sing-box'], { installed: false, version: null, in_use: null, state: 'error', message: reason, retry_at: retryAt });
        Object.assign(vc.cores.xray, { installed: false, version: null, in_use: null, state: 'error', message: reason, retry_at: retryAt });
        for (const name of ['sing-box', 'xray']) {
          const what = name === 'xray' ? 'Помощник Xray не скачался' : 'Ядро VPN не скачалось';
          const at = new Date(retryAt * 1000);
          setCoreAlert(name, `${what}: ${reason.replace(/\.$/, '')}. Повторю в ${String(at.getHours()).padStart(2, '0')}:${String(at.getMinutes()).padStart(2, '0')}.`);
        }
        break;
      }
      case 'autoupdate':
        Object.assign(vc.cores['sing-box'], {
          version: '1.15.0', in_use: '1.14.3', auto_updated: true,
          note: 'Обновлено автоматически до 1.15.0 — заработает при следующем подключении.',
        });
        break;
      case 'error':
        vc.status = 'error';
        resetRuntime();
        vc.error_kind = 'tls';
        vc.error = 'Сервер «Амстердам» отклонил рукопожатие REALITY.';
        log('vpn', 'error', 'outbound/vless[proxy]: REALITY: processed invalid connection — сервер отклонил рукопожатие');
        break;
      case 'conflict':
      case 'uac':
        vc.status = 'stopped';
        resetRuntime();
        vc.conflict = snapshotConflict();
        break;
      case 'xhttp':
        vc.selected = selectedFor('d3e4f5a6b7c8d9e0');
        vc.exit = exitFor(vc.selected);
        break;
      case 'import':
        later(400, () => api.vpnclient_import('https://sub.example.com/api/sub/7f3c?needua', null));
        break;
      case 'offer':
        vc.import = {
          running: false, message: null, error: null,
          offer: {
            kind: 'ua', sub: vc.subscriptions[0] ? vc.subscriptions[0].id : null,
            text: 'Панель ответила «403 Forbidden» на честный User-Agent Лазейки. Многие панели отдают серверы только знакомым клиентам — можно представиться одним из них.',
            options: UA_PRESET_OPTIONS,
          },
        };
        break;
      case 'deeplink':
        vc.status = 'stopped';
        resetRuntime();
        vc.deeplink_request = { token: 'dl-1', kind: 'subscription', summary: 'Подписка с sub.example.org' };
        break;
      case 'expiring': {
        const sub = vc.subscriptions[0];
        if (sub) {
          sub.userinfo.used = Math.round(sub.userinfo.total * 0.93);
          sub.userinfo.expire = nowSec() + 2 * DAY_SEC - 3600;
        }
        break;
      }
      default:
        break;
    }
  }

  function coreUpdateItems() {
    const singbox = vc.cores['sing-box'];
    const xray = vc.cores.xray;
    const newer = SCENARIO === 'coreupdate' && singbox.installed;
    return [
      {
        id: 'vpncore', title: 'Ядро VPN (sing-box)', subtitle: 'SagerNet/sing-box · сторонний проект, GPL-3.0',
        current: singbox.version, latest: newer ? '1.14.4' : singbox.version, available: newer, skipped: false,
        published_at: newer ? '2026-10-15T09:30:00Z' : '2026-10-09T12:00:00Z',
        notes: newer ? 'sing-box 1.14.4\n\n• Исправлено переподключение TUN после сна\n• REALITY: совместимость с новыми серверами Xray' : '',
        url: `https://github.com/SagerNet/sing-box/releases/tag/v${newer ? '1.14.4' : singbox.version || '1.14.3'}`,
        /* Итог автообновления ядро шлёт пояснением в idle (vpnc=autoupdate); откатиться можно к прежней. */
        state: 'idle', progress: null, message: singbox.note || null, can_rollback: Boolean(singbox.auto_updated),
      },
      {
        id: 'vpnxray', title: 'Помощник Xray', subtitle: 'XTLS/Xray-core · сторонний проект, MPL-2.0',
        current: xray.version, latest: xray.version, available: false, skipped: false,
        published_at: '2026-03-27T10:00:00Z', notes: '', url: 'https://github.com/XTLS/Xray-core/releases/tag/v26.3.27',
        state: 'idle', progress: null, message: null, can_rollback: false,
      },
    ];
  }

  function setup(data, error) {
    if (!data) {
      state.vpnclient = {
        available: false,
        unavailable_reason: `Имитация не загрузила ${STATE_URL} (${error && error.message ? error.message : 'причина неизвестна'}). Откройте страницу через http-сервер, а не как файл.`,
        status: 'stopped', cores: {}, servers: [], subscriptions: [], groups: [], routing: {}, settings: {},
      };
      return;
    }
    vc = data;
    rebase(vc);
    applyScenario();
    for (let i = HISTORY_POINTS; i > 0; i -= 1) {
      const [up, down] = vc.status === 'running' ? nextRates() : [0, 0];
      vc.history.push([Math.round(nowSec() - i), Math.round(up), Math.round(down)]);
    }
    state.vpnclient = vc;
    state.updates.items.push(...coreUpdateItems());
    log('vpn', 'info', vc.status === 'running'
      ? `sing-box ${vc.cores['sing-box'].version}: запущен, режим ${vc.mode}, сервер «${vc.selected ? vc.selected.name : '—'}»`
      : 'Свой VPN выключен');
  }

  /* ---------- Трафик и журнал ---------- */

  function nextRates() {
    downRate = Math.random() < 0.08 ? random(1.2 * MB, 4.5 * MB) : clamp(downRate * random(0.6, 1.35) + random(-60, 60) * KB, 20 * KB, 5 * MB);
    upRate = clamp(upRate * random(0.7, 1.3) + random(-6, 6) * KB, 2 * KB, 400 * KB);
    return [upRate, downRate];
  }

  function tick() {
    if (!vc) return;
    const running = vc.status === 'running';
    const [up, down] = running ? nextRates() : [0, 0];
    const stats = vc.stats;
    stats.up_rate = Math.round(up);
    stats.down_rate = Math.round(down);
    stats.up += Math.round(up);
    stats.down += Math.round(down);
    vc.traffic.today_up += Math.round(up);
    vc.traffic.today_down += Math.round(down);
    vc.traffic.total_up += Math.round(up);
    vc.traffic.total_down += Math.round(down);
    if (running) {
      stats.connections = clamp(stats.connections + randomInt(-2, 2), 6, 80);
      vc.memory['sing-box'] = Math.round(clamp((vc.memory['sing-box'] || 40 * MB) + random(-0.4, 0.4) * MB, 30 * MB, 80 * MB));
      vc.memory.xray = needsXray() && vc.cores.xray.installed ? Math.round(clamp((vc.memory.xray || 24 * MB) + random(-0.3, 0.3) * MB, 18 * MB, 60 * MB)) : null;
      const sub = vc.subscriptions[0];
      if (sub && sub.userinfo) sub.userinfo.used += Math.round(up + down);
      if (Math.random() < 0.3) {
        const [lvl, msg] = LOG_SAMPLES[randomInt(0, LOG_SAMPLES.length - 1)];
        log('vpn', lvl, msg);
      }
    }
    vc.history.push([Math.round(nowSec()), stats.up_rate, stats.down_rate]);
    if (vc.history.length > HISTORY_POINTS) vc.history.splice(0, vc.history.length - HISTORY_POINTS);
  }

  /* ---------- Ядра ---------- */

  /** Постоянная плашка «не скачалось» — как ставит менеджер своего VPN (vpn-core:<ядро>). */
  function setCoreAlert(name, text) {
    const id = `vpn-core:${name}`;
    state.notices = state.notices.filter((item) => item.id !== id).concat({
      id, level: 'error', text, page: 'vpnclient', persistent: true, dismissible: true,
      action: { label: 'Скачать ещё раз', call: 'vpnclient_core_install', args: [name] },
    });
  }

  function clearCoreAlert(name) {
    state.notices = state.notices.filter((item) => item.id !== `vpn-core:${name}`);
  }

  function updateItem(id) {
    return state.updates.items.find((item) => item.id === id) || null;
  }

  const CORE_ACTIVE = new Set(['downloading', 'verifying', 'installing']);

  /** Пункт «Обновлений» повторяет ход установки ядра; итог «done» ставит только обновление. */
  function mirror(name) {
    const item = updateItem(name === 'xray' ? 'vpnxray' : 'vpncore');
    const core = vc.cores[name];
    if (!item) return;
    item.current = core.version;
    if (item.latest == null) item.latest = core.version;
    if (CORE_ACTIVE.has(core.state)) Object.assign(item, { state: core.state, progress: core.progress, message: core.message });
    else if (CORE_ACTIVE.has(item.state)) Object.assign(item, { state: 'idle', progress: null, message: null });
  }

  /** Установка или обновление ядра: скачивание с GitHub, сверка SHA-256, распаковка. */
  function installCore(name, opts) {
    const options = opts || {};
    const core = vc.cores[name];
    const version = options.version || core.version || (name === 'xray' ? '26.3.27' : '1.14.3');
    const what = name === 'xray' ? 'помощник Xray' : 'ядро VPN';
    return new Promise((resolve) => {
      function step(stateName, message, progress) {
        Object.assign(core, { state: stateName, message, progress: progress == null ? null : progress });
        mirror(name);
      }
      function finish() {
        Object.assign(core, { installed: true, version, state: 'idle', progress: null, message: null, retry_at: null });
        mirror(name);
        clearCoreAlert(name);
        log('vpn', 'info', `${what} ${version}: установлено, SHA-256 совпал`);
        resolve(true);
      }
      function verify() {
        step('verifying', `Проверяем SHA-256: ${what} ${version}…`);
        later(CORE_STEP_MS, () => {
          step('installing', `Ставим ${what} ${version} в закрытую папку…`);
          later(CORE_STEP_MS, finish);
        });
      }
      let done = 0;
      const size = name === 'xray' ? 19.9 : 31.3;
      const download = () => {
        done += 1;
        step('downloading', `Скачиваем с GitHub: ${(size * done / DOWNLOAD_STEPS).toFixed(1).replace('.', ',')} из ${String(size).replace('.', ',')} МБ`, done / DOWNLOAD_STEPS);
        if (done < DOWNLOAD_STEPS) later(DOWNLOAD_STEP_MS, download);
        else later(DOWNLOAD_STEP_MS, verify);
      };
      download();
    });
  }

  /* ---------- Запуск и остановка ---------- */

  function finishStart() {
    if (vc.status !== 'starting') return;
    const selected = vc.selected;
    if (selected && selected.kind === 'server') {
      const server = serverById(selected.id);
      if (server && server.latency && server.latency.error) {
        vc.status = 'error';
        vc.error_kind = 'timeout';
        vc.error = `Сервер «${server.name}» не ответил за 8 с.`;
        log('vpn', 'error', `outbound[proxy]: dial tcp ${server.name}: i/o timeout`);
        return;
      }
    }
    vc.status = 'running';
    refreshAuto();
    vc.started_at = nowSec();
    vc.stats = { up: 0, down: 0, up_rate: 0, down_rate: 0, connections: randomInt(8, 20) };
    vc.listen = vc.mode === 'tun' ? null : `127.0.0.1:${vc.settings.port}`;
    vc.memory = { 'sing-box': 38 * MB, xray: needsXray() && vc.cores.xray.installed ? 22 * MB : null };
    log('vpn', 'info', `sing-box ${vc.cores['sing-box'].version}: запущен, ${vc.mode === 'tun' ? 'TUN «Lazeyka» 172.19.0.1/30' : `прокси ${vc.listen}`}`);
    later(VERIFY_MS, () => {
      if (vc.status !== 'running') return;
      vc.verified = true;
      vc.exit = exitFor(vc.selected);
      log('vpn', 'info', `Выход проверен: ${vc.exit.ip}, ${vc.exit.country || '—'}`);
    });
  }

  async function startSequence() {
    vc.error = null;
    vc.error_kind = null;
    resetRuntime();
    vc.status = 'starting';
    if (!vc.cores['sing-box'].installed) await installCore('sing-box');
    if (needsXray() && !vc.cores.xray.installed) await installCore('xray');
    if (vc.status !== 'starting') return;
    later(START_MS, finishStart);
  }

  function stopSequence() {
    vc.status = 'stopping';
    later(STOP_MS, () => {
      vc.status = 'stopped';
      resetRuntime();
      log('vpn', 'info', 'Свой VPN выключен, системный прокси возвращён');
    });
  }

  function restartSequence(reason) {
    log('vpn', 'info', `Переподключаемся: ${reason}`);
    vc.status = 'starting';
    vc.verified = false;
    vc.exit = null;
    refreshAuto();
    later(START_MS, finishStart);
  }

  function tunnelConflict(label) {
    return { kind: 'tunnel', label, text: `Уже работает ${label} — два VPN мешают друг другу: выключите ${label} или включите Лазейку как системный прокси.` };
  }

  /*
   * Плашка конфликта в снимке — как Core: зависит от режима (в режиме прокси туннелю Incy не мешаем).
   * Только для сценариев conflict и uac: фоновый чужой VPN имитации (mock-vpn.js) плашку в других
   * сценариях не ставит, его видит окно перед включением (ownConflict).
   */
  function snapshotConflict() {
    return FOREIGN_TUNNEL && vc.mode === 'tun' ? tunnelConflict(FOREIGN_TUNNEL) : null;
  }

  /** Как Core._own_conflict перед включением: с чем свой VPN не уживётся в текущем режиме. */
  function ownConflict() {
    const foreign = state.vpn || {};
    const tunnel = FOREIGN_TUNNEL || (foreign.active && foreign.mode === 'tunnel' ? foreign.label || 'другой VPN' : null);
    if (tunnel && vc.mode === 'tun') return tunnelConflict(tunnel);
    if (foreign.active && foreign.mode === 'proxy' && vc.mode === 'proxy') {
      const label = foreign.label || 'другой программы';
      return { kind: 'proxy', label, text: `Лазейка заменит системный прокси ${label} и вернёт его, когда выключится.` };
    }
    return null;
  }

  /** Как VpnClientManager.preflight: режим прокси под чужой учётной записью UAC. */
  function uacConflict() {
    return vc.mode === 'proxy' && PROXY_DENIED ? { kind: 'uac_user', label: 'Свой VPN', text: PROXY_DENIED } : null;
  }

  /* ---------- Задержка и скорость ---------- */

  function measureLatency(server) {
    if (server.name === 'Стокгольм') return { ms: null, at: nowSec(), error: 'нет ответа за 5 с' };
    const base = BASE_LATENCY[server.country] || (server.latency && server.latency.ms) || randomInt(70, 260);
    return { ms: Math.round(base * random(0.85, 1.25)), at: nowSec(), error: null };
  }

  function runLatency(ids) {
    const queue = vc.servers.filter((server) => server.supported && (!ids || ids.includes(server.id)));
    vc.latency = { running: true, done: 0, total: queue.length };
    const next = () => {
      const server = queue[vc.latency.done];
      if (!server) {
        vc.latency.running = false;
        if (vc.selected && vc.selected.kind === 'auto') vc.selected = selectedFor(vc.selected.id) || vc.selected;
        log('vpn', 'info', `Задержка проверена у ${queue.length} серверов`);
        return;
      }
      server.latency = measureLatency(server);
      vc.latency.done += 1;
      later(LATENCY_STEP_MS, next);
    };
    later(LATENCY_STEP_MS, next);
  }

  /* ---------- Импорт ---------- */

  function finishImport(result) {
    vc.import = { running: false, message: result.message || null, error: result.error || null, offer: result.offer || null };
  }

  function makeServer(fields) {
    return {
      id: newId('m'), sub: null, name: 'Сервер', country: null, proto: 'vless', transport: 'tcp', security: 'reality',
      engine: 'sing-box', supported: true, reason: null, description: null, warnings: [],
      latency: { ms: null, at: null, error: null }, speed: null, ...fields,
    };
  }

  function serverFromLink(line) {
    const scheme = line.split('://')[0].toLowerCase();
    const label = decodeURIComponent((line.split('#')[1] || '').trim()) || `Сервер ${vc.servers.length + 1}`;
    const proto = { ss: 'shadowsocks', hy2: 'hysteria2', socks: 'socks', socks5: 'socks' }[scheme] || scheme;
    return makeServer({
      name: label,
      proto,
      security: ['vless', 'trojan', 'vmess'].includes(proto) ? 'tls' : 'none',
      transport: line.includes('type=xhttp') ? 'xhttp' : 'tcp',
      engine: line.includes('type=xhttp') ? 'xray' : 'sing-box',
      reason: line.includes('type=xhttp') ? 'через помощник Xray: XHTTP' : null,
    });
  }

  function addServers(sub) {
    const extended = sub.ua_preset === 'happ' || sub.ua_preset === 'incy';
    const servers = [
      makeServer({ sub: sub.id, name: 'Варшава', country: 'PL' }),
      makeServer({ sub: sub.id, name: 'Берлин', country: 'DE', proto: 'trojan', security: 'tls' }),
      makeServer({ sub: sub.id, name: 'Рига', country: 'LV', proto: 'hysteria2', security: 'tls' }),
    ];
    vc.servers.push(...servers);
    sub.servers = servers.length;
    sub.format = extended ? 'xray-json' : 'links';
    if (extended) vc.groups.push({ id: newId('g-'), sub: sub.id, name: 'Авто', members: servers.map((server) => server.id) });
    if (!vc.selected) vc.selected = selectedFor(servers[0].id);
    if (vc.settings.latency_on_update) later(300, () => runLatency(servers.map((server) => server.id)));
  }

  function newSubscription(url, ua) {
    const host = (url.split('/')[2] || 'подписка').replace(/^www\./, '');
    const sub = {
      id: newId('s-'), name: host, format: null, ua_preset: ua || 'lazeyka', servers: 0,
      updated_at: null, updating: false, error: null,
      userinfo: { used: 3 * GB, total: 200 * GB, expire: nowSec() + 30 * DAY_SEC, refill_at: null },
      support_url: null, web_page_url: `https://${host}/`, announce: null, description: null, hwid: false,
      provider_routes: false, user_agent: null, update_hours: 12, dns: null, mtu: null, probe: null,
    };
    vc.subscriptions.push(sub);
    subUrls.set(url, sub.id);
    return sub;
  }

  /** Загрузка подписки с её UA и HWID — как _update_sub в ядре: {message, error, offer}; ошибка список не стирает. */
  function fetchSub(sub, url) {
    const ua = UA_PRESET_OPTIONS;
    let failure = null;
    if (/needua/.test(url) && sub.ua_preset === 'lazeyka') {
      failure = {
        error: 'Панель ответила «403 Forbidden»',
        offer: { kind: 'ua', options: ua, text: 'Панель ответила «403 Forbidden» на честный User-Agent Лазейки. Многие панели отдают серверы только знакомым клиентам — можно представиться одним из них.' },
      };
    } else if (/hwid/.test(url) && !sub.hwid) {
      failure = {
        error: 'Пустой ответ: панель выдаёт серверы только устройствам с идентификатором',
        offer: { kind: 'hwid', options: ['hwid'], text: 'Панель вернула пустой ответ и заголовок x-hwid-limit: она выдаёт серверы только устройствам с идентификатором.' },
      };
    } else if (/page|html/.test(url)) {
      failure = {
        error: 'По адресу — веб-страница, а не подписка',
        offer: { kind: 'html', options: ua, text: 'По адресу открылась веб-страница личного кабинета. Найдите на ней кнопку «Скопировать ссылку подписки» и вставьте её сюда.' },
      };
    }
    if (failure) {
      sub.error = failure.error;
      return { error: failure.error, offer: { ...failure.offer, sub: sub.id } };
    }
    if (!sub.servers) addServers(sub);
    else if (sub.ua_preset === 'happ' || sub.ua_preset === 'incy') sub.format = 'xray-json';
    sub.error = null;
    sub.updated_at = nowSec();
    const message = `Подписка «${sub.name}»: серверов ${sub.servers}`;
    if (sub.format === 'links' && sub.ua_preset === 'lazeyka') {
      return {
        message,
        offer: { kind: 'extended', sub: sub.id, options: ua, text: 'Панель отдала простой список ссылок — другим клиентам она может отдавать полный формат с группами и «Самым быстрым».' },
      };
    }
    return { message };
  }

  function importText(source, uaPreset) {
    const text = String(source || '').trim();
    if (/crypt/i.test(text)) {
      return { error: 'Это зашифрованная ссылка для Happ или Incy — Лазейка её не откроет. Возьмите у провайдера обычную ссылку https://… (часто она подписана «для v2rayN» или «для других приложений»).' };
    }
    if (/^https?:\/\//i.test(text) && !text.includes('\n')) {
      const existingId = subUrls.get(text);
      const existing = existingId ? vc.subscriptions.find((sub) => sub.id === existingId) : null;
      if (existing) {
        if (uaPreset && uaPreset !== existing.ua_preset) existing.ua_preset = uaPreset;
        return fetchSub(existing, text);
      }
      const sub = newSubscription(text, uaPreset);
      const outcome = fetchSub(sub, text);
      if (outcome.error) outcome.message = 'Подписка добавлена, но серверы пока не получены';
      return outcome;
    }
    const lines = text.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
    const supported = lines.filter((line) => SUPPORTED_SCHEMES.test(line));
    const unsupported = lines.filter((line) => UNSUPPORTED_SCHEMES.test(line));
    if (!supported.length) {
      if (unsupported.length) return { error: `Ссылка ${unsupported[0].split('://')[0]}:// пока не поддерживается — ни одно ядро Лазейки не умеет такой протокол.` };
      return { error: 'Не похоже на ссылку или подписку. Нужен адрес https://… или ссылка vless://, vmess://, ss://, trojan://, hysteria2://, tuic://, wireguard://, socks://.' };
    }
    const servers = supported.map(serverFromLink);
    vc.servers.push(...servers);
    if (!vc.selected) vc.selected = selectedFor(servers[0].id);
    const extra = unsupported.length ? `; не разобрано строк: ${unsupported.length}` : '';
    return { message: `Добавлено серверов: ${servers.length}${extra}` };
  }

  function startImport(source, uaPreset, progressText) {
    vc.import = { running: true, message: progressText || 'Загружаем подписку…', error: null, offer: null };
    later(IMPORT_STEP_MS, () => {
      vc.import.message = 'Разбираем ответ панели…';
      later(IMPORT_STEP_MS, () => finishImport(importText(source, uaPreset)));
    });
  }

  /* ---------- QR (только имитация: картинка похожа на QR, но не читается) ---------- */

  function hashOf(text) {
    let hash = 2166136261;
    for (const ch of String(text)) {
      hash ^= ch.codePointAt(0);
      hash = Math.imul(hash, 16777619) >>> 0;
    }
    return hash;
  }

  function fakeQr(text) {
    const canvas = document.createElement('canvas');
    canvas.width = QR_MODULES * QR_SCALE;
    canvas.height = QR_MODULES * QR_SCALE;
    const ctx = canvas.getContext('2d');
    ctx.fillStyle = '#FFFFFF';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = '#111214';
    let seed = hashOf(text) || 1;
    const rand = () => {
      seed ^= seed << 13;
      seed ^= seed >>> 17;
      seed ^= seed << 5;
      return (seed >>> 0) / 4294967296;
    };
    const finder = (x, y) => {
      ctx.fillRect(x * QR_SCALE, y * QR_SCALE, 7 * QR_SCALE, 7 * QR_SCALE);
      ctx.fillStyle = '#FFFFFF';
      ctx.fillRect((x + 1) * QR_SCALE, (y + 1) * QR_SCALE, 5 * QR_SCALE, 5 * QR_SCALE);
      ctx.fillStyle = '#111214';
      ctx.fillRect((x + 2) * QR_SCALE, (y + 2) * QR_SCALE, 3 * QR_SCALE, 3 * QR_SCALE);
    };
    const inFinder = (x, y) => (x < 8 && y < 8) || (x > QR_MODULES - 9 && y < 8) || (x < 8 && y > QR_MODULES - 9);
    for (let y = 0; y < QR_MODULES; y += 1) {
      for (let x = 0; x < QR_MODULES; x += 1) {
        if (!inFinder(x, y) && rand() > 0.52) ctx.fillRect(x * QR_SCALE, y * QR_SCALE, QR_SCALE, QR_SCALE);
      }
    }
    finder(0, 0);
    finder(QR_MODULES - 7, 0);
    finder(0, QR_MODULES - 7);
    return canvas.toDataURL('image/png');
  }

  /* ---------- Проверка значений — как в ядре (manager._VALIDATORS, _check_local_auth, _sub_changes) ---------- */

  const PORT_MIN = 1024;
  const NAME_LIMIT = 64;
  const UA_MAX = 256;
  const SUB_MTU = [576, 9000];
  const DNS_URL_MAX = 200;
  const LIST_LIMIT = 500;
  const SHORT_LIST_LIMIT = 100;
  const DNS_NAMES = new Set(['auto', 'cloudflare', 'google', 'quad9', 'adguard', 'yandex']);
  const LOGIN = /^[A-Za-z0-9._-]{1,64}$/;
  const PASSWORD = /^[\x21-\x39\x3B-\x7E]{1,128}$/;
  const EXE = /^(?:[A-Za-z]:\\(?:[^<>"|?*\\]+\\)*)?[^\\/:<>"|?*]+\.exe$/i;
  const SITE = /^[\w.*:/-]{1,253}$/;
  const NET = /^(\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?|[0-9a-f]*:[0-9a-f:.]*(\/\d{1,3})?)$/i;
  const LIST_KEYS = new Set(['direct_apps', 'proxy_apps', 'direct_sites', 'proxy_sites', 'exclude_nets', 'proxy_override']);

  const intIn = (min, max) => (value) => Number.isInteger(value) && value >= min && value <= max;
  const rule = (ok, text) => (value) => (ok(value) ? null : text);
  const flag = rule((value) => typeof value === 'boolean', 'Нужно «да» или «нет»');
  const choice = (options, text) => rule((value) => options.includes(value), text);

  function dnsOk(value) {
    if (DNS_NAMES.has(value)) return true;
    if (typeof value !== 'string' || value.length > DNS_URL_MAX) return false;
    try {
      const url = new URL(value.trim());
      return url.protocol === 'https:' && Boolean(url.hostname);
    } catch (err) {
      return false;               // не адрес вовсе — как urlsplit без схемы в ядре
    }
  }

  function list(itemOk, text, limit) {
    return (value) => {
      if (!Array.isArray(value) || value.length > limit || !value.every((item) => typeof item === 'string')) return `${text} (не больше ${limit} строк)`;
      const bad = value.map((item) => item.trim()).filter(Boolean).find((item) => !itemOk(item));
      return bad === undefined ? null : `${text}: «${bad.slice(0, 60)}»`;
    };
  }

  const SETTING_RULES = {
    preset: choice(['all', 'except_ru', 'blocked'], 'Неизвестный набор маршрутов'),
    via_zapret: flag, games_direct: flag, torrents_direct: flag, ip_check_direct: flag,
    direct_apps: list((item) => EXE.test(item) && item.length <= 260, 'Нужен файл программы .exe', LIST_LIMIT),
    proxy_apps: list((item) => EXE.test(item) && item.length <= 260, 'Нужен файл программы .exe', LIST_LIMIT),
    direct_sites: list((item) => SITE.test(item), 'Не похоже на сайт или сеть', LIST_LIMIT),
    proxy_sites: list((item) => SITE.test(item), 'Не похоже на сайт или сеть', LIST_LIMIT),
    port: rule(intIn(PORT_MIN, PORT_MAX), `Порт — от ${PORT_MIN} до ${PORT_MAX}`),
    local_auth: flag, socks_udp: flag, allow_lan: flag, fakeip: flag, ipv6: flag, kill_switch: flag, tls_fragment: flag,
    mux: flag, noises: flag, latency_on_update: flag, deeplink: flag, verbose: flag, core_auto_update: flag,
    dns_remote: rule(dnsOk, 'DNS — из списка или адрес https://…/dns-query'),
    dns_direct: rule(dnsOk, 'DNS — из списка или адрес https://…/dns-query'),
    ip_strategy: choice(['ipv4_only', 'prefer_ipv4', 'prefer_ipv6'], 'Неизвестный режим IPv4/IPv6'),
    tun_mtu: rule(intIn(1280, 9000), 'MTU — от 1280 до 9000'),
    exclude_nets: list((item) => NET.test(item), 'Нужна сеть вида 192.168.0.0/16', SHORT_LIST_LIMIT),
    proxy_override: list((item) => !item.includes(';') && item.length <= 200, 'Исключение без «;»', SHORT_LIST_LIMIT),
    on_sleep: choice(['reconnect', 'disconnect'], 'Неизвестное действие после сна'),
    fingerprint: choice(['', 'chrome', 'firefox', 'edge', 'safari', '360', 'qq', 'ios', 'android', 'random', 'randomized'], 'Неизвестный отпечаток TLS'),
    sort: choice(['none', 'latency', 'name'], 'Неизвестная сортировка'),
    sub_update_hours: rule(intIn(1, UPDATE_HOURS_MAX), `Интервал обновления — от 1 до ${UPDATE_HOURS_MAX} часов`),
  };

  function normalized(key, value) {
    if (LIST_KEYS.has(key)) return [...new Set(value.map((item) => item.trim()).filter(Boolean))];
    return typeof value === 'string' ? value.trim() : value;
  }

  function localAuthError(key, value) {
    if (typeof value !== 'string') return 'Нужна строка';
    if (key === 'local_user') return LOGIN.test(value) ? null : 'Логин — латиница и цифры, без пробелов и двоеточия';
    return PASSWORD.test(value) ? null : 'Пароль — от 1 до 128 латинских символов, без пробелов и двоеточия';
  }

  /** Как _sub_changes ядра: {changes, errors}; свой UA проверяется, только если итоговый пресет — «Свой». */
  function subChanges(sub, values) {
    const errors = {};
    const changes = {};
    if ('name' in values) {
      const name = String(values.name || '').trim();
      if (!name || name.length > NAME_LIMIT) errors.name = `Название — от 1 до ${NAME_LIMIT} символов`;
      else changes.name = name;
    }
    if ('ua_preset' in values) {
      if (!UA_PRESETS.includes(values.ua_preset)) errors.ua_preset = 'Неизвестный User-Agent';
      else changes.ua_preset = values.ua_preset;
    }
    const preset = 'ua_preset' in changes ? changes.ua_preset : sub.ua_preset;
    if (preset === 'custom' && ('ua' in values || changes.ua_preset === 'custom')) {
      const ua = String(values.ua || customAgents.get(sub.id) || '').trim();
      if (!ua || ua.length > UA_MAX || !/^[\x20-\x7E]+$/.test(ua)) {
        errors.ua = `User-Agent: только латиница (ASCII), без переводов строк, не длиннее ${UA_MAX} символов`;
      } else {
        changes.user_agent = ua;
      }
    }
    if ('hwid' in values) changes.hwid = Boolean(values.hwid);
    if ('update_hours' in values) {
      if (!intIn(1, UPDATE_HOURS_MAX)(values.update_hours)) errors.update_hours = `Интервал обновления — от 1 до ${UPDATE_HOURS_MAX} часов`;
      else changes.update_hours = values.update_hours;
    }
    if ('dns' in values) {
      const value = values.dns || null;
      if (value !== null && !dnsOk(value)) errors.dns = 'Свой DNS подписки — из списка или адрес https://…/dns-query';
      else changes.dns = value === null ? null : String(value).trim();
    }
    if ('mtu' in values) {
      const mtu = values.mtu == null ? null : values.mtu;
      if (mtu !== null && !intIn(SUB_MTU[0], SUB_MTU[1])(mtu)) errors.mtu = `MTU подписки — пусто или от ${SUB_MTU[0]} до ${SUB_MTU[1]}`;
      else changes.mtu = mtu;
    }
    if ('provider_routes' in values) changes.provider_routes = Boolean(values.provider_routes);
    return { changes, errors };
  }

  /* ---------- Методы ---------- */

  function requireVc() {
    return vc ? null : fail(state.vpnclient && state.vpnclient.unavailable_reason ? state.vpnclient.unavailable_reason : 'Свой VPN не загрузился');
  }

  Object.assign(api, {
    vpnclient_preflight() {
      if (!vc) return ok({ ask: false, conflict: null });
      const conflict = ownConflict() || uacConflict();
      return ok({ ask: Boolean(conflict), conflict });
    },

    vpnclient_start(quiet) {
      const denied = requireVc();
      if (denied) return denied;
      if (!vc.servers.length) return fail('Сначала добавьте подписку или сервер');
      if (['running', 'starting'].includes(vc.status)) return ok();
      log('vpn', 'info', `Включаем свой VPN${quiet ? ' (после окна про другой VPN)' : ''}`);
      startSequence();
      return ok();
    },

    vpnclient_stop() {
      const denied = requireVc();
      if (denied) return denied;
      if (vc.status === 'stopped') return ok();
      stopSequence();
      return ok();
    },

    vpnclient_restart() {
      const denied = requireVc();
      if (denied) return denied;
      if (vc.status !== 'running') return fail('Свой VPN не включён — перезапускать нечего');
      restartSequence('по кнопке');
      return ok();
    },

    vpnclient_set_mode(mode) {
      const denied = requireVc();
      if (denied) return denied;
      if (!MODES.includes(mode)) return fail(`Неизвестный режим: ${mode}`);
      /* Как ядро: режим меняется до ответа, недоступный — отказом, а не «изменён». */
      if (mode === 'proxy' && PROXY_DENIED) return fail(PROXY_DENIED);
      vc.mode = mode;
      if (vc.status === 'running') restartSequence(`режим ${mode}`);
      return ok();
    },

    vpnclient_select(id) {
      const denied = requireVc();
      if (denied) return denied;
      const server = serverById(String(id));
      if (server && !server.supported) return fail(`Сервер «${server.name}» не поддерживается: ${server.reason}`);
      const selected = selectedFor(String(id));
      if (!selected) return fail('Такого сервера больше нет — обновите список');
      vc.selected = selected;
      log('vpn', 'info', `Выбран сервер «${selected.name}»${vc.status === 'running' ? ' — переключаем без перезапуска' : ''}`);
      if (vc.status === 'running') {
        vc.verified = false;
        later(RESELECT_MS, () => {
          if (vc.status !== 'running') return;
          vc.verified = true;
          vc.exit = exitFor(vc.selected);
        });
      }
      return ok();
    },

    vpnclient_latency(ids) {
      const denied = requireVc();
      if (denied) return denied;
      if (vc.latency.running) return ok();
      runLatency(Array.isArray(ids) ? ids.map(String) : null);
      return ok();
    },

    vpnclient_speedtest(id) {
      const denied = requireVc();
      if (denied) return denied;
      if (vc.status !== 'running') return fail('Включите VPN — скорость меряется через выбранный сервер');
      if (vc.speed.running) return ok();
      const target = id ? String(id) : (vc.selected && (vc.selected.actual ? vc.selected.actual.id : vc.selected.id));
      const server = serverById(target);
      if (!server) return fail('Сервер для теста не найден');
      vc.speed = { running: true, server: server.id, mbps: null, at: null };
      later(SPEED_MS, () => {
        const mbps = Math.round(random(38, 128) * 10) / 10;
        vc.speed = { running: false, server: server.id, mbps, at: nowSec() };
        server.speed = { mbps, at: nowSec() };
        log('vpn', 'info', `Тест скорости через «${server.name}»: ${mbps} Мбит/с`);
      });
      return ok();
    },

    vpnclient_import(text, uaPreset) {
      const denied = requireVc();
      if (denied) return denied;
      if (vc.import.running) return fail('Предыдущее добавление ещё идёт');
      const source = String(text == null ? '' : text).trim();
      if (!source) return fail('Вставьте ссылку, подписку или текст со ссылками');
      if (uaPreset != null && !['lazeyka', 'custom', ...UA_PRESET_OPTIONS].includes(uaPreset)) return fail('Неизвестный User-Agent');
      startImport(source, uaPreset || null, /^https?:\/\//i.test(source) ? `Загружаем подписку ${source.split('/')[2] || ''}…` : 'Разбираем ссылки…');
      return ok();
    },

    vpnclient_import_file() {
      const denied = requireVc();
      if (denied) return denied;
      startImport('wireguard://home.conf#Дом (WireGuard)', null, 'Читаем home.conf…');
      return ok(null, 700);
    },

    vpnclient_import_qr(source) {
      const denied = requireVc();
      if (denied) return denied;
      if (!['screen', 'file'].includes(source)) return fail(`Неизвестный источник QR: ${source}`);
      startImport('vless://example@203.0.113.80:443?security=reality#Сервер из QR', null, source === 'screen' ? 'Ищем QR-код на снимке экрана…' : 'Ищем QR-код на картинке…');
      return ok(null, source === 'file' ? 700 : 300);
    },

    vpnclient_sub_update(id) {
      const denied = requireVc();
      if (denied) return denied;
      const subs = id == null ? vc.subscriptions : vc.subscriptions.filter((sub) => sub.id === id);
      if (!subs.length) return fail('Подписка не найдена');
      for (const sub of subs) {
        sub.updating = true;
        later(SUB_UPDATE_MS, () => {
          sub.updating = false;
          const url = [...subUrls].find(([, subId]) => subId === sub.id);
          if (url) {
            const outcome = fetchSub(sub, url[0]);
            log('vpn', outcome.error ? 'warn' : 'info', outcome.error ? `Подписка «${sub.name}» не обновилась: ${outcome.error}` : outcome.message);
            return;
          }
          sub.updated_at = nowSec();
          sub.error = null;
          if (sub.ua_preset === 'happ' || sub.ua_preset === 'incy') sub.format = 'xray-json';
          log('vpn', 'info', `Подписка «${sub.name}» обновлена: +0 / −0`);
          if (vc.settings.latency_on_update) runLatency(vc.servers.filter((server) => server.sub === sub.id).map((server) => server.id));
        });
      }
      return ok();
    },

    vpnclient_sub_remove(id) {
      const denied = requireVc();
      if (denied) return denied;
      if (!vc.subscriptions.some((sub) => sub.id === id)) return fail('Подписка не найдена');
      const removed = new Set(vc.servers.filter((server) => server.sub === id).map((server) => server.id));
      vc.subscriptions = vc.subscriptions.filter((sub) => sub.id !== id);
      vc.servers = vc.servers.filter((server) => server.sub !== id);
      vc.groups = vc.groups.filter((group) => group.sub !== id);
      const selected = vc.selected;
      if (selected && (removed.has(selected.id) || removed.has(selected.actual && selected.actual.id) || selected.id === `auto:${id}`)) {
        vc.selected = vc.servers.length ? selectedFor(vc.servers[0].id) : null;
        if (['running', 'starting'].includes(vc.status)) stopSequence();
      }
      return ok();
    },

    vpnclient_sub_set(id, values) {
      const denied = requireVc();
      if (denied) return denied;
      const sub = vc.subscriptions.find((item) => item.id === id);
      if (!sub) return fail('Такой подписки нет');
      const { changes, errors } = subChanges(sub, values && typeof values === 'object' ? values : {});
      if (Object.keys(errors).length) return fail('Проверьте поля', errors);
      const { user_agent: agent, ...rest } = changes;
      Object.assign(sub, rest);
      if (agent) customAgents.set(sub.id, agent);
      sub.user_agent = sub.ua_preset === 'custom' ? customAgents.get(sub.id) || null : null;
      /* Проверка формата и предложение по этой подписке были для прежних свойств. */
      sub.probe = null;
      if (vc.import.offer && vc.import.offer.sub === sub.id) vc.import = { ...vc.import, offer: null };
      log('vpn', 'info', `Свойства подписки «${sub.name}» сохранены: ${Object.keys(changes).join(', ') || 'без изменений'}`);
      return ok();
    },

    /* Как sub_probe ядра: формат богаче нашёлся — probe у подписки и предложение «switch» в import.offer. */
    vpnclient_sub_probe(id) {
      const denied = requireVc();
      if (denied) return denied;
      const sub = vc.subscriptions.find((item) => item.id === id);
      if (!sub) return fail('Такой подписки нет');
      if (sub.probe && sub.probe.running) return fail('Проверка формата уже идёт');
      sub.probe = { running: true, ua_preset: null, text: null };
      later(PROBE_MS, () => {
        if (!sub.probe || !sub.probe.running) return;
        const preset = sub.ua_preset === 'happ' ? 'incy' : 'happ';
        const text = `Провайдер отдаёт расширенный формат (JSON с группами) приложению «${UA_LABEL[preset]}». Переключить подписку?`;
        sub.probe = { running: false, ua_preset: preset, text };
        vc.import = { ...vc.import, running: false, offer: { kind: 'switch', text, options: [preset], sub: sub.id } };
      });
      return ok();
    },

    vpnclient_server_remove(id) {
      const denied = requireVc();
      if (denied) return denied;
      if (!serverById(String(id))) return fail('Сервер не найден');
      vc.servers = vc.servers.filter((server) => server.id !== id);
      vc.groups.forEach((group) => { group.members = group.members.filter((member) => member !== id); });
      for (const sub of vc.subscriptions) sub.servers = vc.servers.filter((server) => server.sub === sub.id).length;
      if (vc.selected && vc.selected.id === id) vc.selected = vc.servers.length ? selectedFor(vc.servers[0].id) : null;
      return ok();
    },

    vpnclient_server_rename(id, name) {
      const denied = requireVc();
      if (denied) return denied;
      const server = serverById(String(id));
      if (!server) return fail('Сервер не найден');
      const value = String(name || '').trim();
      if (!value) return fail('Введите название', { name: 'Введите название' });
      if (value.length > 64) return fail('Слишком длинное название', { name: 'Не длиннее 64 символов' });
      server.name = value;
      if (vc.selected && vc.selected.id === server.id) vc.selected.name = value;
      return ok();
    },

    vpnclient_copy_link(id) {
      const denied = requireVc();
      if (denied) return denied;
      const server = serverById(String(id));
      if (!server) return fail('Сервер не найден');
      log('app', 'debug', `В буфер обмена: ссылка сервера «${server.name}»`);
      return ok();
    },

    vpnclient_open_link(subId, kind) {
      const denied = requireVc();
      if (denied) return denied;
      const sub = vc.subscriptions.find((item) => item.id === String(subId));
      if (!sub) return fail('Такой подписки нет');
      if (!['support', 'page'].includes(kind)) return fail('Неизвестная ссылка подписки');
      log('app', 'debug', `Стенд: открыть ссылку «${kind}» подписки «${sub.name}»`);
      return ok();
    },

    vpnclient_qr(id) {
      const denied = requireVc();
      if (denied) return denied;
      const known = serverById(String(id)) || vc.subscriptions.find((sub) => sub.id === id);
      if (!known) return fail('Сервер или подписка не найдены');
      return ok({ png: fakeQr(`lazeyka-mock:${id}`) }, 400);
    },

    vpnclient_save_settings(values) {
      const denied = requireVc();
      if (denied) return denied;
      if (!values || typeof values !== 'object') return fail('Нечего сохранять');
      /* Дальше — как save_settings ядра: проверка, логин и пароль, что изменилось и нужен ли перезапуск. */
      const errors = {};
      const clean = {};
      const credentials = {};
      for (const [key, value] of Object.entries(values)) {
        if (key === 'local_user' || key === 'local_password') {
          if (value === '' || value == null) continue;          // пусто — «не менять»
          const problem = localAuthError(key, value);
          if (problem) errors[key] = problem;
          else credentials[key] = value;
          continue;
        }
        const check = SETTING_RULES[key];
        if (!check) {
          log('app', 'debug', `Стенд: ядро не знает настройку «${key}» и пропустит её`);
          continue;
        }
        const problem = check(value);
        if (problem) errors[key] = problem;
        else clean[key] = normalized(key, value);
      }
      const before = (key) => (ROUTING_KEYS.has(key) ? vc.routing[key] : vc.settings[key]);
      const after = (key) => (key in clean ? clean[key] : before(key));
      const authUpdate = {};
      if (credentials.local_user && credentials.local_user !== vc.settings.local_user) authUpdate.user = credentials.local_user;
      if (credentials.local_password && credentials.local_password !== localPassword) authUpdate.password = credentials.local_password;
      const wantsAuth = after('local_auth') || after('allow_lan');
      if (wantsAuth && !(authUpdate.user || vc.settings.local_user)) errors.local_user = errors.local_user || 'Для входа по паролю задайте логин';
      if (wantsAuth && !(authUpdate.password || localPassword)) errors.local_password = errors.local_password || 'Для входа по паролю задайте пароль';
      if (Object.keys(errors).length) return fail('Проверьте поля', errors);
      const changed = new Set(Object.keys(clean).filter((key) => JSON.stringify(before(key)) !== JSON.stringify(clean[key])));
      if (Object.keys(authUpdate).length && wantsAuth) changed.add('local_auth');
      if (authUpdate.user) vc.settings.local_user = authUpdate.user;
      if (authUpdate.password) {
        localPassword = authUpdate.password;
        vc.settings.local_password_set = true;
      }
      for (const [key, value] of Object.entries(clean)) {
        if (ROUTING_KEYS.has(key)) vc.routing[key] = clone(value);
        else vc.settings[key] = clone(value);
      }
      const restart = [...changed].some((key) => !LIVE_KEYS.has(key));
      if (changed.size) log('vpn', 'info', `Настройки своего VPN: ${[...changed].join(', ')}${restart ? ' — нужен перезапуск' : ''}`);
      if ('via_zapret' in values) {
        vc.routing.bypass = values.via_zapret && vc.status === 'running' ? 'direct' : null;
        vc.routing.bypass_note = values.via_zapret
          ? 'Discord и YouTube идут через обход: он работает и последняя проверка прошла.'
          : 'Переключатель выключен.';
      }
      if ('preset' in values && values.preset !== 'all' && !vc.routing.rules.updated_at) api.vpnclient_rules_update();
      if (restart && vc.status === 'running') {
        restartSequence('новые настройки');
        return ok({ message: 'Сохранено. Свой VPN переподключается, чтобы применить настройки.' });
      }
      return ok();
    },

    vpnclient_core_install(name) {
      const denied = requireVc();
      if (denied) return denied;
      const core = vc.cores[name];
      if (!core) return fail(`Неизвестное ядро: ${name}`);
      if (CORE_ACTIVE.has(core.state)) return fail('Ядро уже ставится');
      installCore(name);
      return ok();
    },

    vpnclient_rules_update() {
      const denied = requireVc();
      if (denied) return denied;
      const rules = vc.routing.rules;
      if (rules.state === 'downloading') return ok();
      Object.assign(rules, { state: 'downloading', message: 'Скачиваем списки маршрутов…', error: null });
      later(RULES_MS, () => {
        Object.assign(rules, {
          state: 'idle', updated_at: nowSec(), stale: false, message: null, error: null,
          items: RULE_ITEMS.map((item) => ({ ...item, updated_at: nowSec(), error: null })),
        });
        log('vpn', 'info', `Списки маршрутов обновлены: ${RULE_ITEMS.length}`);
      });
      return ok();
    },

    vpnclient_running_apps: () => ok({ apps: RUNNING_APPS }, 500),

    vpnclient_backup_export(password) {
      const denied = requireVc();
      if (denied) return denied;
      if (String(password || '').length < 8) return fail('Пароль не короче 8 символов');
      log('vpn', 'info', 'Резервная копия своего VPN сохранена');
      return ok({ message: 'Резервная копия сохранена: Документы\\Lazeyka-VPN.lzbackup' }, 900);
    },

    vpnclient_backup_import(password) {
      const denied = requireVc();
      if (denied) return denied;
      if (String(password) === 'wrong') return fail('Не получилось открыть копию: неверный пароль или файл повреждён');
      return ok({ message: 'Из копии добавлено: 1 подписка, 10 серверов — совпадения объединены' }, 900);
    },

    vpnclient_profile_import(text) {
      const denied = requireVc();
      if (denied) return denied;
      const value = String(text || '').trim();
      if (!/^(happ|incy):\/\/routing\//i.test(value) && !value.startsWith('{')) {
        return fail('Не похоже на профиль маршрутизации: нужна ссылка happ://routing/… или incy://routing/… либо текст профиля в JSON');
      }
      const profile = { id: newId('r-'), name: 'Профиль из ссылки', source: 'link', active: false, summary: { direct: 14, proxy: 2, block: 3 } };
      vc.routing_profiles.push(profile);
      return ok({ message: `Профиль «${profile.name}» добавлен выключенным — посмотрите правила и включите его` });
    },

    vpnclient_profile_set(id, active) {
      const denied = requireVc();
      if (denied) return denied;
      const profile = vc.routing_profiles.find((item) => item.id === id);
      if (!profile) return fail('Профиль не найден');
      vc.routing_profiles.forEach((item) => { item.active = item.id === id ? Boolean(active) : (active ? false : item.active); });
      return ok();
    },

    vpnclient_profile_remove(id) {
      const denied = requireVc();
      if (denied) return denied;
      vc.routing_profiles = vc.routing_profiles.filter((item) => item.id !== id);
      return ok();
    },

    vpnclient_help: () => ok({ items: traces }, 500),

    vpnclient_proxy_fix() {
      const before = traces.length;
      traces = traces.filter((item) => item.id !== 'vpnclient_dead_proxy');
      return ok({ message: before !== traces.length ? 'Мёртвый прокси выключен' : 'Мёртвого прокси не нашлось' }, 600);
    },

    vpnclient_open_adapters() {
      log('app', 'info', 'Открываем «Сетевые подключения» Windows');
      return ok();
    },

    vpnclient_deeplink_confirm(token, accept) {
      const denied = requireVc();
      if (denied) return denied;
      const request = vc.deeplink_request;
      if (!request || request.token !== token) return fail('Запрос уже не актуален');
      vc.deeplink_request = null;
      if (accept) startImport('https://sub.example.org/api/sub/2b9e', null, 'Загружаем подписку sub.example.org…');
      return ok();
    },
  });

  /* Обновление ядер с «Обновлений» — та же установка, что со страницы VPN (cores — единственный источник хода). */
  const installUpdate = api.updates_install;
  api.updates_install = function updatesInstallWithCores(id) {
    if (id !== 'vpncore' && id !== 'vpnxray') return installUpdate(id);
    if (!vc) return fail('Свой VPN не загрузился');
    const item = updateItem(id);
    const name = id === 'vpncore' ? 'sing-box' : 'xray';
    if (!item || !item.available) return fail('Новой версии нет — устанавливать нечего');
    installCore(name, { version: item.latest }).then(() => {
      Object.assign(item, {
        state: 'done', available: false, can_rollback: true, progress: null,
        message: `Готово: ${item.title} ${item.latest}. Прошлая версия сохранена — её можно вернуть кнопкой «Откатить».`,
      });
      if (vc.status === 'running') restartSequence('новое ядро');
    });
    return ok();
  };

  /* Общие настройки: «Включать свой VPN при запуске» и масштаб окна. */
  state.settings.vpnclient_on_start = false;
  /* scale=1.25 в адресе — масштаб окна, будто его уже выбрали в настройках. */
  state.settings.ui_scale = clamp(Number(params.get('scale')) || 1, 0.8, 1.5);
  const saveSettings = api.save_settings;
  api.save_settings = function saveSettingsWithScale(partial) {
    if (partial && 'ui_scale' in partial) {
      const value = Number(partial.ui_scale);
      if (!Number.isFinite(value) || value < 0.8 || value > 1.5) return fail('Масштаб — от 80 до 150 %');
    }
    return saveSettings(partial);
  };

  mock.ownVpn = () => (vc && vc.status === 'running' ? { active: true, mode: vc.mode } : { active: false, mode: null });

  const ready = fetch(STATE_URL, { cache: 'no-store' })
    .then((response) => {
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return response.json();
    })
    .then((data) => setup(data, null))
    .catch((err) => {
      console.error(`Имитация своего VPN: ${STATE_URL} не загрузился —`, err);
      setup(null, err);
    });

  const getState = api.get_state;
  api.get_state = async function getStateWithVpnClient(...args) {
    await ready;
    state.updates.count = state.updates.items.filter((item) => item.available && !item.skipped && item.state !== 'done').length;
    /* Конфликт Core пересчитывает в каждом снимке: он зависит от режима и чужого VPN. */
    if (vc) vc.conflict = snapshotConflict() || uacConflict();
    return getState(...args);
  };

  mock.onTick(tick);

  /*
   * Окна для скриншотов и ручной проверки: vpncdemo=start|qr|props|backup|apps|delete|menu|rename|dirty.
   * Нажимают кнопки интерфейса или открывают окна страницы, когда она уже нарисована.
   */
  const UI_DEMO_DELAY_MS = 1500;
  const MENU_DELAY_MS = 200;
  const click = (selector) => {
    const el = document.querySelector(selector);
    if (el) el.click();
    else console.warn(`Имитация: не нашли ${selector} для vpncdemo`);
  };
  const UI_DEMOS = {
    start: () => click('.page--vpnclient .page-head__actions .btn--primary'),
    qr: () => window.Lz.vcDialogs.showQr({ id: vc.servers[0].id, title: vc.servers[0].name }),
    props: () => window.Lz.vcDialogs.subProperties(vc.subscriptions[0]),
    backup: () => window.Lz.vcDialogs.backupPassword('export'),
    apps: () => window.Lz.vcDialogs.pickApp({ title: 'Мимо VPN' }),
    rename: () => window.Lz.vcDialogs.renameServer(vc.servers[0]),
    menu: () => click('[data-fk^="server-menu:"]'),
    /* Черновик «Подробнее»: другой порт и логин с паролем — видна закреплённая панель «Сохранить» (вместе с focus=more). */
    dirty: () => {
      const input = document.querySelector('input[id^="vc-port"]');
      if (!input) return;
      input.value = '20900';
      input.dispatchEvent(new Event('input', { bubbles: true }));
      click('.vc-more-form .switch');
    },
    delete: () => {
      click('[data-fk^="sub-menu:"]');
      later(MENU_DELAY_MS, () => click('.menu .menu__item--danger'));
    },
  };
  const uiDemo = UI_DEMOS[params.get('vpncdemo')];
  if (uiDemo) ready.then(() => later(UI_DEMO_DELAY_MS, () => vc && uiDemo()));
});
