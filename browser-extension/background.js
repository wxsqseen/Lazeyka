'use strict';
/*
 * Прокси только для этого браузера: SOCKS5 на локальный прокси Лазейки (свой VPN в режиме «Только локальный
 * прокси»). Имя сайта по SOCKS5 Chromium отдаёт прокси, а не адрес — DNS идёт через сервер, а не к провайдеру;
 * WebRTC без прокси не ходит. Лазейка выключена — страницы не открываются, а не идут мимо VPN.
 */
const DEFAULT_PORT = 20808;          // порт локального прокси Лазейки по умолчанию (vpnclient Ports.proxy)

async function load() {
  return chrome.storage.local.get({ on: false, port: DEFAULT_PORT });
}

async function apply({ on, port }) {
  if (on) {
    await chrome.proxy.settings.set({
      scope: 'regular',
      value: {
        mode: 'fixed_servers',
        rules: { singleProxy: { scheme: 'socks5', host: '127.0.0.1', port }, bypassList: ['<local>'] },
      },
    });
    await chrome.privacy.network.webRTCIPHandlingPolicy.set({ value: 'disable_non_proxied_udp' });
  } else {
    await chrome.proxy.settings.clear({ scope: 'regular' });
    await chrome.privacy.network.webRTCIPHandlingPolicy.clear({});
  }
  await badge(on ? 'on' : 'off');
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

chrome.runtime.onStartup.addListener(async () => apply(await load()));
chrome.runtime.onInstalled.addListener(async () => apply(await load()));

// Прокси не отвечает (Лазейка выключена или VPN не в режиме локального прокси) — красный значок до следующего включения.
chrome.proxy.onProxyError.addListener(async () => {
  if ((await load()).on) await badge('error');
});

chrome.runtime.onMessage.addListener((message, _sender, reply) => {
  (async () => {
    const state = await load();
    if (message.type === 'set') {
      const port = Number(message.port);
      if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Порт — число от 1 до 65535');
      Object.assign(state, { on: Boolean(message.on), port });
      await chrome.storage.local.set(state);
      await apply(state);
    }
    reply({ ok: true, ...state, control: await control() });
  })().catch((err) => reply({ ok: false, error: String(err && err.message ? err.message : err) }));
  return true;
});
