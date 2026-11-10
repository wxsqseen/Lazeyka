'use strict';
/* Окно расширения: режим (Лазейка или свой прокси), протокол, адрес, логин и пароль, включить, проверка выхода. */
const EXIT_URL = 'https://1.1.1.1/cdn-cgi/trace';   // тот же адрес проверки выхода, что у Лазейки
const CHECK_TIMEOUT_MS = 8000;
const AUTH_PERMISSIONS = { permissions: ['webRequest', 'webRequestAuthProvider'], origins: ['<all_urls>'] };
const SCHEME_ALIAS = { socks: 'socks5', socks5h: 'socks5' };
const SCHEME_NAME = { http: 'HTTP', https: 'HTTPS', socks5: 'SOCKS5', socks4: 'SOCKS4' };

const $ = (id) => document.getElementById(id);
const statusEl = $('status');
const toggleEl = $('toggle');
const portEl = $('port');
const schemeEl = $('scheme');
const addrEl = $('addr');
const userEl = $('user');
const passEl = $('pass');
const errorEl = $('proxy-error');
const savedEl = $('proxy-saved');
const modeEls = [...document.querySelectorAll('input[name="mode"]')];
let state = null;

function send(message) {
  return chrome.runtime.sendMessage(message);
}

function show(text, kind) {
  statusEl.textContent = text;
  statusEl.className = kind || '';
}

function showError(text) {
  errorEl.textContent = text || '';
  errorEl.hidden = !text;
}

function hostPort(proxy) {
  return `${proxy.host.includes(':') ? `[${proxy.host}]` : proxy.host}:${proxy.port}`;
}

/**
 * Строка от провайдера → поля. «http://логин:пароль@ip:порт», «логин:пароль@ip:порт», «ip:порт:логин:пароль»,
 * «логин:пароль:ip:порт», «ip:порт». Протокол — только если он есть в строке; иначе остаётся выбранный.
 */
function parsePasted(text) {
  let rest = String(text || '').trim();
  const out = {};
  const scheme = rest.match(/^([a-z0-9]+):\/\//i);
  if (scheme) {
    const name = scheme[1].toLowerCase();
    out.scheme = SCHEME_ALIAS[name] || name;
    rest = rest.slice(scheme[0].length);
  }
  rest = rest.replace(/\/+$/, '');
  const at = rest.lastIndexOf('@');
  if (at >= 0) {
    const cred = rest.slice(0, at);
    const colon = cred.indexOf(':');
    out.user = colon < 0 ? cred : cred.slice(0, colon);
    out.pass = colon < 0 ? '' : cred.slice(colon + 1);
    out.addr = rest.slice(at + 1);
    return out;
  }
  const parts = rest.split(':');
  if (parts.length === 4 && /^\d+$/.test(parts[1])) {
    Object.assign(out, { addr: `${parts[0]}:${parts[1]}`, user: parts[2], pass: parts[3] });
  } else if (parts.length === 4 && /^\d+$/.test(parts[3])) {
    Object.assign(out, { addr: `${parts[2]}:${parts[3]}`, user: parts[0], pass: parts[1] });
  } else {
    out.addr = rest;
  }
  return out;
}

function splitAddr(addr) {
  const text = String(addr || '').trim();
  const v6 = text.match(/^\[([^\]]+)\]:(\d+)$/);
  if (v6) return { host: v6[1], port: v6[2] };
  const colon = text.lastIndexOf(':');
  return colon < 0 ? { host: text, port: '' } : { host: text.slice(0, colon), port: text.slice(colon + 1) };
}

/** Что ввёл человек — для фона. Пароль не меняли (поле пустое, логин тот же) — undefined: фон оставит сохранённый. */
function formProxy() {
  const { host, port } = splitAddr(addrEl.value);
  const proxy = { scheme: schemeEl.value, host, port: Number(port), user: userEl.value.trim() };
  const keep = !passEl.value && state && state.proxy && state.proxy.hasPass && state.proxy.user === proxy.user;
  if (!keep) proxy.pass = passEl.value;
  return proxy;
}

/** Выход: адрес и страна из ответа Cloudflare; null — прокси не ответил. */
async function exitInfo() {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), CHECK_TIMEOUT_MS);
  try {
    const response = await fetch(EXIT_URL, { cache: 'no-store', signal: controller.signal });
    const fields = Object.fromEntries((await response.text()).split('\n').map((line) => line.split('=')));
    return { ip: fields.ip || '?', loc: fields.loc || '' };
  } catch (err) {
    console.debug('Проверка выхода не прошла:', err);
    return null;
  } finally {
    clearTimeout(timer);
  }
}

function renderForm() {
  const p = state.proxy;
  const editing = [addrEl, userEl, passEl, schemeEl].includes(document.activeElement);
  if (!editing) {
    schemeEl.value = p ? p.scheme : 'http';
    addrEl.value = p ? hostPort(p) : '';
    userEl.value = p ? p.user || '' : '';
    passEl.value = '';
    passEl.placeholder = p && p.hasPass ? 'сохранён — введите, чтобы сменить' : 'если есть';
  }
  savedEl.hidden = !p;
  if (p) {
    savedEl.textContent = `Сохранено: ${SCHEME_NAME[p.scheme]} ${hostPort(p)}${p.user ? `, логин ${p.user}` : ''}` +
      (p.user && !state.authReady ? '. При включении браузер спросит разрешение подставлять пароль.' : '');
  }
}

async function render() {
  const own = state.mode === 'proxy';
  toggleEl.disabled = false;
  toggleEl.textContent = state.on ? 'Выключить для браузера' : 'Включить для браузера';
  toggleEl.classList.toggle('is-on', state.on);
  for (const el of modeEls) el.checked = el.value === state.mode;
  $('port-row').hidden = own;
  $('proxy-row').hidden = !own;
  if (document.activeElement !== portEl) portEl.value = state.port;
  renderForm();
  if (state.control === 'controlled_by_other_extensions') {
    show('Прокси браузера сейчас настраивает другое расширение — выключите его, иначе Лазейка не сработает.', 'bad');
    return;
  }
  if (!state.on) {
    show(own && !state.proxy ? 'Укажите прокси и включите.' : 'Выключено: браузер ходит в интернет как обычно.');
    return;
  }
  show(own ? 'Проверяем выход через прокси…' : 'Проверяем выход через VPN…');
  const checked = state;
  const exit = await exitInfo();
  if (state !== checked) return;             // пока проверяли, выключили или сменили прокси — итог уже не про сейчас
  const fresh = await send({ type: 'get' });
  if (exit) {
    show(`Работает: браузер выходит в интернет через ${exit.ip}${exit.loc ? ` (${exit.loc})` : ''}.`, 'ok');
  } else if (own && fresh.ok && fresh.authFailed) {
    show('Прокси не принял логин и пароль — проверьте их у провайдера.', 'bad');
  } else if (own) {
    show(`Прокси ${SCHEME_NAME[state.proxy.scheme]} ${hostPort(state.proxy)} не отвечает. Проверьте протокол (у провайдера ` +
         'он указан рядом с адресом), адрес и порт. Пока так — страницы не откроются: мимо прокси браузер не пойдёт.', 'bad');
  } else {
    show(`Лазейка не отвечает на 127.0.0.1:${state.port}. Включите свой VPN в режиме «Только локальный прокси» ` +
         'или проверьте порт. Пока так — страницы не откроются (мимо VPN браузер не пойдёт).', 'bad');
  }
}

/*
 * Изменения — по очереди: ввели адрес и сразу нажали «Включить» — поле теряет фокус и сохраняется раньше, чем
 * дойдёт нажатие; кнопку на это время не блокируем, иначе нажатие пропало бы. Проверка выхода очередь не держит.
 */
let queue = Promise.resolve();

function update(changes) {
  // Упало одно звено — следующие всё равно идут (иначе после первой ошибки окно молча перестало бы слушаться).
  queue = queue.catch((err) => console.error('Окно расширения:', err)).then(async () => {
    const reply = await send({ type: 'set', ...changes });
    if (!reply.ok) {
      if ('proxy' in changes) showError(reply.error);
      else show(reply.error, 'bad');
      toggleEl.disabled = false;
      return;
    }
    if ('proxy' in changes) showError('');
    state = reply;
    render();
  });
  return queue;
}

function saveProxy() {
  if (!addrEl.value.trim()) return queue;
  return update({ proxy: formProxy() });
}

toggleEl.addEventListener('click', async () => {
  toggleEl.disabled = true;             // двойное нажатие не переключает дважды
  const turningOn = !state.on;
  // Право подставлять пароль — по нажатию (иначе браузер не покажет вопрос): только если логин задан.
  if (turningOn && state.mode === 'proxy' && userEl.value.trim() && !state.authReady && chrome.permissions) {
    try {
      await chrome.permissions.request(AUTH_PERMISSIONS);
    } catch (err) {
      console.debug('Разрешение не запрошено:', err);
    }
  }
  if (state.mode === 'proxy') await saveProxy();
  if (state.mode === 'proxy' && !errorEl.hidden) {
    toggleEl.disabled = false;
    return;
  }
  update({ on: turningOn });
});
portEl.addEventListener('change', () => update({ port: portEl.value }));
addrEl.addEventListener('paste', (event) => {
  const text = (event.clipboardData || window.clipboardData).getData('text');
  if (!/[@:].*[:@]|:\/\//.test(text)) return;        // просто «ip:порт» — вставится как есть
  event.preventDefault();
  const found = parsePasted(text);
  if (found.scheme && SCHEME_NAME[found.scheme]) schemeEl.value = found.scheme;
  addrEl.value = found.addr || '';
  if ('user' in found) userEl.value = found.user;
  if ('pass' in found) passEl.value = found.pass;
  saveProxy();
});
for (const el of [schemeEl, addrEl, userEl, passEl]) el.addEventListener('change', () => saveProxy());
$('proxy-row').addEventListener('submit', (event) => {
  event.preventDefault();
  saveProxy();
});
for (const el of modeEls) el.addEventListener('change', () => update({ mode: el.value }));

(async () => {
  state = await send({ type: 'get' });
  if (!state.ok) {
    show(state.error, 'bad');
    return;
  }
  await render();
})();
