'use strict';
/*
 * Прокси только для этого браузера. Режим «lazeyka» — SOCKS5 на локальный прокси Лазейки (свой VPN в режиме «Только
 * локальный прокси»); режим «proxy» — прокси человека (HTTP, HTTPS, SOCKS5, SOCKS4), тогда Лазейка не нужна.
 * Протокол человек выбирает сам: угадывать его по адресу нельзя — у провайдера один и тот же ip:порт бывает HTTP.
 * Логин и пароль HTTP(S)-прокси расширение подставляет само (webRequest.onAuthRequired) — право на это просится,
 * только когда логин задан. По SOCKS5 и HTTP имя сайта получает прокси — DNS идёт через него, а не к провайдеру;
 * WebRTC без прокси не ходит. Прокси не отвечает — страницы не открываются, а не идут мимо него.
 */
const DEFAULT_PORT = 20808;          // порт локального прокси Лазейки по умолчанию (vpnclient Ports.proxy)
const SCHEMES = ['http', 'https', 'socks5', 'socks4'];
const AUTH_LIMIT = 2;                // столько раз подряд отдаём пароль на один запрос — дальше он неверный

async function load() {
  return chrome.storage.local.get({ on: false, port: DEFAULT_PORT, mode: 'lazeyka', proxy: null, authFailed: false });
}

/** Проверка того, что ввёл человек: протокол, хост, порт, логин и пароль (пароль — только для HTTP и HTTPS). */
function checkProxy(input) {
  const scheme = String(input.scheme || '').toLowerCase();
  if (!SCHEMES.includes(scheme)) throw new Error('Выберите протокол прокси');
  let host = String(input.host || '').trim().toLowerCase().replace(/^\[|\]$/g, '');
  const port = Number(input.port);
  if (!/^([a-z0-9-]+\.)*[a-z0-9-]+$/.test(host) && !/^[0-9a-f:.]+$/.test(host)) {
    throw new Error('Адрес прокси — IP или имя, например 217.69.167.122 или proxy.example.com');
  }
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Порт прокси — число от 1 до 65535');
  const user = String(input.user || '');
  const pass = String(input.pass || '');
  if ((user || pass) && scheme.startsWith('socks')) {
    throw new Error('SOCKS-прокси с логином и паролем браузеры на Chromium не поддерживают. Возьмите у провайдера ' +
                    'HTTP-прокси (тот же адрес обычно работает и так) или подключите его через Лазейку.');
  }
  if (pass && !user) throw new Error('Пароль есть, а логина нет — укажите логин');
  host = host.includes(':') ? host : host.replace(/\.$/, '');
  return { scheme, host, port, user, pass };
}

function server(state) {
  if (state.mode === 'proxy' && state.proxy) {
    return { scheme: state.proxy.scheme, host: state.proxy.host, port: state.proxy.port };
  }
  return { scheme: 'socks5', host: '127.0.0.1', port: state.port };
}

async function apply(state) {
  if (state.on && (state.mode !== 'proxy' || state.proxy)) {
    await chrome.proxy.settings.set({
      scope: 'regular',
      value: { mode: 'fixed_servers', rules: { singleProxy: server(state), bypassList: ['<local>'] } },
    });
    await chrome.privacy.network.webRTCIPHandlingPolicy.set({ value: 'disable_non_proxied_udp' });
  } else {
    await chrome.proxy.settings.clear({ scope: 'regular' });
    await chrome.privacy.network.webRTCIPHandlingPolicy.clear({});
  }
  await badge(state.on ? 'on' : 'off');
}

async function badge(kind) {
  const look = { on: ['ВКЛ', '#2e7d32'], off: ['', '#2e7d32'], error: ['!', '#c62828'] }[kind];
  await chrome.action.setBadgeText({ text: look[0] });
  await chrome.action.setBadgeBackgroundColor({ color: look[1] });
}

/** Кто управляет прокси браузера: другое расширение-прокси перебивает наши настройки. */
async function control() {
  const { levelOfControl } = await chrome.proxy.settings.get({});
  return levelOfControl;
}

/* ---------- Логин и пароль прокси ---------- */

const tries = new Map();             // requestId → сколько раз уже отдали пароль

function onAuth(details, callback) {
  load().then(async (state) => {
    const p = state.proxy;
    const challenger = details.challenger || {};
    const ours = details.isProxy && p && String(challenger.host || '').toLowerCase() === p.host
      && Number(challenger.port) === p.port;
    if (!ours || !p.user) {             // не наш прокси или логин не задан — пусть спросит сам браузер
      callback({});
      return;
    }
    if (!state.on || state.mode !== 'proxy') {
      // Выключено, а запоздавший запрос ещё просит пароль: отказ без окна входа браузера — иначе оно встало бы поверх
      // окна расширения и то перестало бы отвечать на нажатия (нашлось проверкой с неверным паролем).
      callback({ cancel: true });
      return;
    }
    const count = (tries.get(details.requestId) || 0) + 1;
    tries.set(details.requestId, count);
    setTimeout(() => tries.delete(details.requestId), 60000);
    if (count > AUTH_LIMIT) {        // прокси снова просит пароль — тот, что дали, не подошёл
      await chrome.storage.local.set({ authFailed: true });
      await badge('error');
      callback({ cancel: true });
      return;
    }
    callback({ authCredentials: { username: p.user, password: p.pass } });
  }).catch(() => callback({}));
}

/* Право на webRequest — необязательное: появляется, когда человек задал логин. Слушатель — сразу при запуске
 * service worker (иначе событие его не разбудит) и сразу после выдачи права. */
function hookAuth() {
  const api = chrome.webRequest && chrome.webRequest.onAuthRequired;
  if (api && !api.hasListener(onAuth)) api.addListener(onAuth, { urls: ['<all_urls>'] }, ['asyncBlocking']);
}
hookAuth();
if (chrome.permissions && chrome.permissions.onAdded) chrome.permissions.onAdded.addListener(hookAuth);

async function authReady() {
  if (!chrome.permissions) return false;
  return chrome.permissions.contains({ permissions: ['webRequest', 'webRequestAuthProvider'], origins: ['<all_urls>'] });
}

chrome.runtime.onStartup.addListener(async () => apply(await load()));
chrome.runtime.onInstalled.addListener(async () => apply(await load()));

// Прокси не отвечает (Лазейка или прокси выключены) — красный значок до следующего включения.
chrome.proxy.onProxyError.addListener(async () => {
  if ((await load()).on) await badge('error');
});

chrome.runtime.onMessage.addListener((message, _sender, reply) => {
  (async () => {
    const state = await load();
    if (message.type === 'set') {
      const next = { ...state };
      if ('port' in message) {
        const port = Number(message.port);
        if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Порт — число от 1 до 65535');
        next.port = port;
      }
      if ('mode' in message) next.mode = message.mode === 'proxy' ? 'proxy' : 'lazeyka';
      if ('proxy' in message) {
        const input = { ...message.proxy };
        if (input.pass === undefined) {      // окно пароль не меняло — тот же логин, тот же пароль
          input.pass = state.proxy && state.proxy.user === input.user ? state.proxy.pass || '' : '';
        }
        next.proxy = checkProxy(input);
        next.authFailed = false;
      }
      if ('on' in message) {
        next.on = Boolean(message.on);
        next.authFailed = false;
      }
      if (next.on && next.mode === 'proxy' && !next.proxy) throw new Error('Сначала укажите адрес прокси');
      Object.assign(state, next);
      await chrome.storage.local.set(state);
      await apply(state);
    }
    const { pass, ...shown } = state.proxy || {};
    reply({ ok: true, ...state, proxy: state.proxy ? { ...shown, hasPass: Boolean(pass) } : null,
            authReady: await authReady(), control: await control() });
  })().catch((err) => reply({ ok: false, error: String(err && err.message ? err.message : err) }));
  return true;
});
