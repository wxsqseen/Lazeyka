'use strict';
/*
 * Имитация раздела контракта «Версия 1.1 — VPN рядом с обходом»: состояние vpn, окно перед
 * включением (vpn_preflight), «что куда идёт», совместимость, поправки адаптеров.
 * Подключается из mock.js — отдельно не работает.
 *
 * Параметры адреса:
 *   vpn=on|off|nocompat|error|proxy — VPN-туннель (по умолчанию) / VPN нет / совместимость
 *                               выключена / фильтр для VPN не собрался / VPN в режиме системного
 *                               прокси (без туннеля; эталон «напрямую» не получен — часть строк unknown)
 *   demo=vpn-probe            — сразу проверить, что куда идёт
 */
(window.LzMockExtensions = window.LzMockExtensions || []).push(function installVpn(mock) {
  const { state, api, params, nowSec, later, ok, fail, log } = mock;

  const PROBE_MS = 2200;
  const KNOWN_LIMIT = 20;
  const GUID_PATTERN = /^\{[0-9a-f-]{36}\}$/;
  const VPN_SERVER = '203.0.113.7';
  const VPN_PROXY = 'http://127.0.0.1:10808';
  const ADAPTERS = [
    {
      id: '{2e21a4c4-7d0a-4d64-9a51-6b1f0e7c1a01}', index: 23, name: 'wwan99', description: 'Wintun Tunnel',
      kind: 'tunnel', role: 'internet', reason: 'туннель VPN', up: true, app: null, vpnOnly: true,
    },
    {
      id: '{4b1f2c33-9d5e-4c1b-8f0a-2a6e5d4c3b02}', index: 19, name: 'Radmin VPN', description: 'Famatech Radmin VPN Ethernet Adapter',
      kind: 'tunnel', role: 'lan', reason: 'адаптер VPN', up: true, app: 'Radmin VPN',
    },
    {
      id: '{7a9c1e55-3b2d-4f6a-9c8e-1d2f3a4b5c03}', index: 12, name: 'Ethernet', description: 'Realtek PCIe 2.5GbE Family Controller',
      kind: 'direct', role: '', reason: 'сетевая карта', up: true, app: null,
    },
    {
      id: '{9e8d7c6b-5a4f-4e3d-8c2b-1a0f9e8d7c04}', index: 31, name: 'vEthernet (Default Switch)', description: 'Hyper-V Virtual Ethernet Adapter',
      kind: 'direct', role: '', reason: 'виртуальный адаптер', up: true, app: null,
    },
  ];
  /* Свой VPN Лазейки: Discord и YouTube — через обход («через обход Лазейки» включено), остальное — через сервер. */
  const PROBE_OWN = [
    { id: 'discord', label: 'Discord', via: 'direct' },
    { id: 'youtube', label: 'YouTube', via: 'direct' },
    { id: 'telegram', label: 'Telegram-прокси', via: 'vpn' },
    { id: 'other', label: 'Остальные сайты', via: 'vpn' },
  ];
  const OWN_ADAPTER = {
    id: '{6c0f9d1e-2b3a-4c5d-8e7f-0a1b2c3d4e05}', index: 41, name: 'Lazeyka', description: 'sing-box TUN (Wintun)',
    kind: 'tunnel', role: 'internet', reason: 'свой VPN Лазейки', up: true, app: 'Лазейка', own: true,
  };
  /* Туннель: Discord — через VPN, YouTube — мимо VPN, Telegram-прокси — через VPN. */
  const PROBE_TUNNEL = [
    { id: 'discord', label: 'Discord', via: 'vpn' },
    { id: 'youtube', label: 'YouTube', via: 'direct' },
    { id: 'telegram', label: 'Telegram-прокси', via: 'vpn' },
    { id: 'other', label: 'Остальные сайты', via: 'vpn' },
  ];
  /* Системный прокси: браузер и Discord идут через него; эталон «напрямую» не получен — Telegram не определить. */
  const PROBE_PROXY = [
    { id: 'discord', label: 'Discord', via: 'vpn' },
    { id: 'youtube', label: 'YouTube', via: 'vpn' },
    { id: 'telegram', label: 'Telegram-прокси', via: 'unknown' },
    { id: 'other', label: 'Остальные сайты', via: 'vpn' },
  ];

  const scenario = params.get('vpn') || 'on';
  const proxyMode = scenario === 'proxy';
  const tunnelUp = !proxyMode && !['off', '0', 'none'].includes(scenario);
  const settings = { compat: scenario !== 'nocompat', ask: true, known: [], overrides: {} };
  let routes = null;

  /* ---------- Снимок ---------- */

  function ownVpn() {
    return mock.ownVpn ? mock.ownVpn() : { active: false, mode: null };
  }

  function adapters() {
    const list = ADAPTERS.filter((adapter) => tunnelUp || !adapter.vpnOnly).map((adapter) => {
      const { vpnOnly, ...plain } = adapter;
      const override = settings.overrides[adapter.id];
      if (override === 'direct') return { ...plain, kind: 'direct', role: '', reason: 'задано вручную' };
      if (override === 'tunnel') return { ...plain, kind: 'tunnel', role: plain.role || 'lan', reason: 'задано вручную' };
      return plain;
    });
    const own = ownVpn();
    return own.active && own.mode === 'tun' ? [...list, { ...OWN_ADAPTER }] : list;
  }

  /** То же, что ядро отдаёт как vpn.snapshot_dict: без настроек, фильтра и маршрутов. */
  function snapshot() {
    const list = adapters();
    /* Свой адаптер «Lazeyka» чужим VPN не считается. */
    const internet = list.some((adapter) => !adapter.own && adapter.kind === 'tunnel' && adapter.role === 'internet');
    const proxy = proxyMode ? VPN_PROXY : null;
    const active = internet || Boolean(proxy);
    let candidates = [];
    /* vpn=noname: программа туннеля не опознана — ядро называет VPN по адаптеру (vpn.Snapshot.label). */
    if (internet && scenario !== 'noname') candidates = ['Incy', 'Happ'];
    else if (proxy) candidates = ['Happ'];
    let label = candidates.join(' или ');
    if (!label && internet) label = `VPN «${list.find((a) => !a.own && a.kind === 'tunnel' && a.role === 'internet').name}»`;
    return {
      active,
      mode: internet ? 'tunnel' : (proxy ? 'proxy' : null),
      full_tunnel: internet,
      proxy,
      label: active ? label : null,
      candidates,
      apps: ['Radmin VPN', ...candidates],
      servers: internet ? [VPN_SERVER] : [],
      source_ip: true,
      at: nowSec(),
      adapters: list,
    };
  }

  function signature(snap) {
    const tunnels = snap.adapters.filter((a) => !a.own && a.kind === 'tunnel' && a.role === 'internet').map((a) => `Wintun:${a.id}`);
    return snap.proxy ? [...tunnels, `proxy:${snap.proxy}`] : tunnels;
  }

  function isKnown(snap) {
    const sig = signature(snap);
    return snap.active && sig.length > 0 && sig.every((item) => settings.known.includes(item));
  }

  /** Что применено к работающему обходу — как zapret.vpn_applied в ядре. */
  function appliedFilter(snap) {
    const zapret = state.zapret;
    const tunnels = snap.adapters.filter((a) => a.kind === 'tunnel');
    const interfaces = snap.adapters.filter((a) => a.kind === 'direct').map((a) => a.index).sort((a, b) => a - b);
    /* Совместимость выключена, а свой VPN работает: исключаются только свой туннель и свои серверы. */
    if (zapret.status === 'running' && !settings.compat && ownVpn().active) {
      return { mode: 'own', interfaces, servers: ['203.0.113.5'], error: null, at: zapret.started_at };
    }
    if (zapret.status !== 'running' || !settings.compat || !tunnels.length) return { mode: 'plain' };
    if (scenario === 'error') {
      return { mode: 'error', error: 'WinDivert не принял фильтр: превышена длина выражения', interfaces, servers_seen: snap.servers };
    }
    return { mode: 'vpn', interfaces, servers: snap.servers, servers_seen: snap.servers, error: null, at: zapret.started_at };
  }

  function directChecks(snap) {
    return Boolean(snap.active && snap.full_tunnel && snap.source_ip);
  }

  function refreshVpn() {
    const snap = snapshot();
    if (!snap.active && !ownVpn().active) routes = null;
    state.vpn = {
      ...snap,
      compat: settings.compat,
      ask: settings.ask,
      known: isKnown(snap),
      overrides: { ...settings.overrides },
      filter: appliedFilter(snap),
      routes: routes ? { ...routes } : null,
      /* Свой VPN Лазейки (mock-vpnclient.js задаёт mock.ownVpn) — чужим он не считается. */
      own: ownVpn(),
    };
  }

  function restartIfRunning(reason) {
    if (state.zapret.status === 'running') mock.startZapret(reason);
  }

  function requireAdmin() {
    return state.app.admin ? null : fail('Нужны права администратора — перезапустите Лазейку с ними');
  }

  /* ---------- Методы ---------- */

  api.vpn_probe = function vpnProbe() {
    if (routes && routes.running) return ok();
    const snap = snapshot();
    const ownOnly = !snap.active && ownVpn().active;
    if (!snap.active && !ownOnly) {
      routes = null;
      return ok();
    }
    routes = { running: true, at: null, items: routes ? routes.items : null };
    later(PROBE_MS, () => {
      const viaProxy = snap.mode === 'proxy';
      let source = viaProxy ? PROBE_PROXY : PROBE_TUNNEL;
      if (ownOnly) source = PROBE_OWN;
      const items = source.map((item) => ({ ...item }));
      routes = {
        running: false, at: nowSec(), full_tunnel: snap.full_tunnel, mode: viaProxy ? 'proxy' : 'tunnel',
        checked_vpn: true, checked_direct: !viaProxy, error: false, items,
      };
      log('app', 'info', `Маршруты при VPN: ${items.map((item) => `${item.id}=${item.via}`).join(', ')}`);
    });
    return ok();
  };

  api.vpn_preflight = function vpnPreflight(component) {
    const snap = snapshot();
    const ask = snap.active && settings.ask && !isKnown(snap);
    if (ask) api.vpn_probe();
    return ok({ ask, component: String(component), compat: settings.compat, vpn: snap });
  };

  api.vpn_answer = function vpnAnswer(remember, compat) {
    const snap = snapshot();
    if (remember && snap.active) settings.known = [...new Set([...settings.known, ...signature(snap)])].slice(-KNOWN_LIMIT);
    const changed = settings.compat !== Boolean(compat);
    settings.compat = Boolean(compat);
    if (changed) restartIfRunning('совместимость с VPN');
    return ok();
  };

  api.vpn_set_compat = function vpnSetCompat(on) {
    const denied = requireAdmin();
    if (denied) return denied;
    settings.compat = Boolean(on);
    if (settings.compat) mock.dropNotice('compat-off');   /* как Core._reconcile_alerts */
    restartIfRunning('совместимость с VPN');
    return ok({
      message: settings.compat ? 'Обход не будет трогать трафик VPN.'
        : 'Совместимость с VPN выключена: обход снова перехватывает все подключения.',
    });
  };

  api.vpn_set_ask = function vpnSetAsk(on) {
    settings.ask = Boolean(on);
    return ok();
  };

  api.vpn_forget = function vpnForget() {
    settings.known = [];
    return ok({ message: 'Лазейка снова спросит при включении рядом с VPN.' });
  };

  api.vpn_set_override = function vpnSetOverride(id, kind) {
    const denied = requireAdmin();
    if (denied) return denied;
    const guid = String(id || '').toLowerCase();
    if (!GUID_PATTERN.test(guid)) return fail('Неизвестный адаптер');
    if (![null, undefined, '', 'direct', 'tunnel'].includes(kind)) return fail('Неизвестный вариант');
    if (kind) settings.overrides[guid] = kind;
    else delete settings.overrides[guid];
    if (settings.compat) restartIfRunning('поправка адаптера');
    return ok();
  };

  /* Как ядро (_vpn_note_on_start): без окна про VPN — уведомление, что обход включён рядом с VPN. */
  const startZapret = api.zapret_start;
  api.zapret_start = function zapretStartNearVpn(quiet) {
    if (!state.zapret.available) return startZapret();
    const result = startZapret();
    const snap = snapshot();
    if (!quiet && snap.active) {
      mock.setNotice(settings.compat
        ? { id: 'vpn-start', level: 'info', text: `Обход включён рядом с VPN (${snap.label}): трафик VPN он не трогает.`,
          action: { label: 'Что куда идёт', page: 'zapret' }, dismissible: true }
        : { id: 'compat-off', level: 'warn', text: `Подключён VPN (${snap.label}), а совместимость с VPN выключена — обход может мешать VPN.`,
          action: { label: 'Включить совместимость', call: 'vpn_set_compat', args: [true] }, dismissible: true,
          persistent: true, page: 'zapret' });
    }
    return result;
  };

  /* Проверки обхода идут мимо VPN, если весь интернет сейчас в туннеле (флаг direct). */
  const startTest = api.zapret_test_start;
  api.zapret_test_start = function zapretTestStartNearVpn(...args) {
    const result = startTest(...args);
    state.zapret.test.direct = directChecks(snapshot());
    return result;
  };

  const getState = api.get_state;
  api.get_state = function getStateWithVpn() {
    refreshVpn();
    return getState();
  };

  refreshVpn();
  /* Начальную проверку mock-zapret.js сделал до этого дополнения — отметим, что она шла мимо VPN. */
  if (state.zapret.check.results) state.zapret.check.direct = directChecks(snapshot());
  mock.demos['vpn-probe'] = () => api.vpn_probe();
});
