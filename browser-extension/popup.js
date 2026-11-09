'use strict';
/* Окно расширения: включить или выключить прокси браузера, порт и проверка выхода через сервер. */
const EXIT_URL = 'https://1.1.1.1/cdn-cgi/trace';   // тот же адрес проверки выхода, что у Лазейки
const CHECK_TIMEOUT_MS = 8000;

const statusEl = document.getElementById('status');
const toggleEl = document.getElementById('toggle');
const portEl = document.getElementById('port');
let state = null;

function send(message) {
  return chrome.runtime.sendMessage(message);
}

function show(text, kind) {
  statusEl.textContent = text;
  statusEl.className = kind || '';
}

/** Выход через сервер: адрес и страна из ответа Cloudflare; null — прокси не ответил. */
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

async function render() {
  toggleEl.disabled = false;
  toggleEl.textContent = state.on ? 'Выключить для браузера' : 'Включить для браузера';
  toggleEl.classList.toggle('is-on', state.on);
  if (document.activeElement !== portEl) portEl.value = state.port;
  if (state.control === 'controlled_by_other_extensions') {
    show('Прокси браузера сейчас настраивает другое расширение — выключите его, иначе Лазейка не сработает.', 'bad');
    return;
  }
  if (!state.on) {
    show('Выключено: браузер ходит в интернет как обычно.');
    return;
  }
  show('Проверяем выход через VPN…');
  const checked = state;
  const exit = await exitInfo();
  if (state !== checked) return;             // пока проверяли, выключили или сменили порт — итог уже не про сейчас
  if (exit) {
    show(`Работает: браузер выходит в интернет через ${exit.ip}${exit.loc ? ` (${exit.loc})` : ''}.`, 'ok');
  } else {
    show(`Лазейка не отвечает на 127.0.0.1:${state.port}. Включите свой VPN в режиме «Только локальный прокси» ` +
         'или проверьте порт. Пока так — страницы не откроются (мимо VPN браузер не пойдёт).', 'bad');
  }
}

/*
 * Изменения — по очереди: ввели порт и сразу нажали «Включить» — поле теряет фокус и сохраняет порт раньше, чем
 * дойдёт нажатие; кнопку на это время не блокируем, иначе нажатие пропало бы. Проверка выхода очередь не держит:
 * «Выключить» срабатывает сразу.
 */
let queue = Promise.resolve();

function update(changes) {
  queue = queue.then(async () => {
    const reply = await send({ type: 'set', on: state.on, port: state.port, ...changes });
    if (!reply.ok) {
      show(reply.error, 'bad');
      toggleEl.disabled = false;
      return;
    }
    state = reply;
    render();
  });
  return queue;
}

toggleEl.addEventListener('click', () => {
  toggleEl.disabled = true;             // двойное нажатие не переключает дважды
  update({ on: !state.on });
});
portEl.addEventListener('change', () => update({ port: portEl.value }));

(async () => {
  state = await send({ type: 'get' });
  if (!state.ok) {
    show(state.error, 'bad');
    return;
  }
  await render();
})();
