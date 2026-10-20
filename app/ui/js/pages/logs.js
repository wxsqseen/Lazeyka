'use strict';
/*
 * Журнал: живой хвост строк из четырёх источников. get_logs опрашивается только
 * пока страница открыта. Автопрокрутка встаёт на паузу, когда пользователь
 * листает вверх, и возобновляется, когда он возвращается вниз.
 */
(function (Lz) {
  const { h, icon, setText, setHidden } = Lz.dom;
  const ui = Lz.ui;
  const fmt = Lz.fmt;

  const LOG_POLL_MS = 1000;
  const LOG_TIMEOUT_MS = 8000;
  const MAX_LINES = 2000;
  /* Ядро кладёт в буфер обмена не больше 100 000 символов (core.copy_text) — копируем самые свежие строки. */
  const COPY_LIMIT = 100000;
  const STICK_THRESHOLD_PX = 40;
  /* Подпись фильтра и метка строки — одно имя: строки «Лазейка» показывает фильтр «Лазейка». */
  const SOURCES = [
    { value: 'all', label: 'Все' },
    { value: 'app', label: 'Лазейка', title: 'Сама Лазейка: запуск, настройки, проверки' },
    { value: 'zapret', label: 'zapret', title: 'Обход блокировок' },
    { value: 'tg', label: 'Telegram', title: 'Telegram-прокси' },
    { value: 'vpn', label: 'Свой VPN', title: 'Свой VPN: ядра, подписки, маршруты' },
  ];
  const SOURCE_TAG = { app: 'Лазейка', zapret: 'zapret', tg: 'Telegram', vpn: 'Свой VPN' };
  const LEVEL_WORD = { debug: 'отладка', info: 'инфо', warn: 'внимание', error: 'ошибка' };

  function create() {
    let source = 'all';
    let lastId = 0;
    let timer = null;
    let active = false;
    let fetching = false;
    let refetchQueued = false;
    let generation = 0;
    let stick = true;
    let unseen = 0;
    /* get_logs отказал или молчит: пустой экран — не «пока пусто», о причине говорит плашка над ним. */
    let failing = false;

    const viewport = h('div', {
      class: 'log',
      role: 'log',
      'aria-live': 'off',
      'aria-label': 'Строки журнала',
      tabIndex: 0,
    });
    const emptyNote = h('div', { class: 'log__empty' },
      ui.emptyState({ icon: 'list', title: 'Пока пусто', text: 'Новые строки появятся здесь, как только что-нибудь произойдёт.' }));
    const jumpLabel = h('span');
    const jump = h('button', { type: 'button', class: 'log-jump', hidden: true },
      icon('arrowDown', { size: 16 }), jumpLabel);
    const errorBox = ui.slot((text) => (text ? ui.callout({ tone: 'err', text }) : null));

    const sourceSeg = ui.segmented({
      label: 'Источник',
      value: source,
      options: SOURCES,
      onChange: (value) => {
        source = value;
        restart();
      },
    });
    const copyBtn = ui.button({ label: 'Копировать', icon: 'copy', size: 'sm', busyKey: 'copy_text', onClick: () => copyVisible() });
    const folderBtn = ui.button({
      label: 'Папка логов',
      icon: 'folder',
      size: 'sm',
      busyKey: 'open_path:logs',
      onClick: () => Lz.actions.openPath('logs'),
    });
    const clearBtn = ui.button({ label: 'Очистить экран', icon: 'eraser', size: 'sm', kind: 'ghost', onClick: () => clearScreen() });

    const header = ui.pageHeader({
      title: 'Журнал',
      subtitle: 'Что происходит внутри: запуск обхода, работа прокси и своего VPN, проверки и ошибки.',
    });
    const toolbar = h('div', { class: 'log-toolbar' },
      sourceSeg.el, h('span', { class: 'spacer' }), copyBtn.el, folderBtn.el, clearBtn.el);
    const frame = h('div', { class: 'card log-card' }, viewport, emptyNote, jump);
    const el = h('div', { class: 'page__inner page__inner--fill' }, header.el, toolbar, errorBox.el, frame);

    function isAtBottom() {
      return viewport.scrollTop + viewport.clientHeight >= viewport.scrollHeight - STICK_THRESHOLD_PX;
    }

    function updateJump() {
      setHidden(jump, stick || unseen === 0);
      setText(jumpLabel, `Новые строки: ${fmt.integer(unseen)}`);
    }

    function updateEmpty() {
      setHidden(emptyNote, failing || viewport.childElementCount > 0);
    }

    function lineEl(line) {
      const level = LEVEL_WORD[line.lvl] ? line.lvl : 'info';
      const src = SOURCE_TAG[line.src] ? line.src : 'app';
      return h('div', { class: `log__line is-${level}` },
        h('span', { class: 'log__time num', text: fmt.clock(line.t) }),
        h('span', { class: `log__src src-${src}`, text: SOURCE_TAG[src] }),
        h('span', { class: 'sr-only', text: `${LEVEL_WORD[level]}: ` }),
        h('span', { class: 'log__msg', text: line.msg == null ? '' : String(line.msg) }));
    }

    function trimOverflow() {
      const excess = viewport.childElementCount - MAX_LINES;
      if (excess <= 0) return;
      const heightBefore = viewport.scrollHeight;
      for (let i = 0; i < excess; i += 1) viewport.firstElementChild.remove();
      if (!stick) viewport.scrollTop -= heightBefore - viewport.scrollHeight;
    }

    function append(lines) {
      const fragment = document.createDocumentFragment();
      for (const line of lines) fragment.append(lineEl(line));
      viewport.append(fragment);
      trimOverflow();
      if (stick) viewport.scrollTop = viewport.scrollHeight;
      else unseen += lines.length;
      updateJump();
      updateEmpty();
    }

    function schedule(delayMs) {
      clearTimeout(timer);
      timer = active ? setTimeout(fetchLines, delayMs) : null;
    }

    async function fetchLines() {
      if (fetching) {
        refetchQueued = true;
        return;
      }
      fetching = true;
      refetchQueued = false;
      const requestGeneration = generation;
      try {
        /* Отказ ядра — ошибка в плашке, а не «новых строк нет». */
        const result = await Lz.api.query('get_logs', LOG_TIMEOUT_MS, lastId, source);
        if (requestGeneration !== generation) return;
        const lines = result && Array.isArray(result.lines) ? result.lines : [];
        if (lines.length) append(lines);
        const nextId = Number(result && result.last_id);
        if (Number.isFinite(nextId)) lastId = nextId;
        failing = false;
        errorBox.update(null);
      } catch (err) {
        failing = true;
        errorBox.update(`Журнал не обновляется: ${Lz.api.describeError(err)}`);
      } finally {
        updateEmpty();
        fetching = false;
        schedule(refetchQueued || requestGeneration !== generation ? 0 : LOG_POLL_MS);
      }
    }

    function restart() {
      generation += 1;
      lastId = 0;
      unseen = 0;
      stick = true;
      viewport.replaceChildren();
      updateJump();
      updateEmpty();
      schedule(0);
    }

    function clearScreen() {
      viewport.replaceChildren();
      unseen = 0;
      stick = true;
      updateJump();
      updateEmpty();
    }

    /**
     * Строки экрана от старых к новым; не помещаются в буфер целиком — берём самые свежие (хвост),
     * а в тосте — сколько строк скопировано на самом деле.
     */
    function copyVisible() {
      const rows = [...viewport.children].map((row) => {
        const time = row.querySelector('.log__time').textContent;
        const src = row.querySelector('.log__src').textContent;
        const msg = row.querySelector('.log__msg').textContent;
        const level = (row.className.match(/is-(\w+)/) || [])[1] || 'info';
        return `${time} [${src}] ${level.toUpperCase()} ${msg}`;
      });
      if (!rows.length) {
        ui.toast({ kind: 'info', text: 'На экране нет строк — копировать нечего.' });
        return;
      }
      const tail = [];
      let size = 0;
      for (let i = rows.length - 1; i >= 0; i -= 1) {
        const added = rows[i].length + (tail.length ? 1 : 0);
        if (size + added > COPY_LIMIT) break;
        tail.unshift(rows[i]);
        size += added;
      }
      if (!tail.length) tail.push(rows[rows.length - 1].slice(-COPY_LIMIT));
      const lines = fmt.count(tail.length, 'строка', 'строки', 'строк');
      const what = tail.length < rows.length
        ? `${fmt.plural(tail.length, 'последняя', 'последние', 'последние')} ${lines} журнала (все в буфер не помещаются)`
        : `${lines} журнала`;
      Lz.actions.copyText(tail.join('\n'), what);
    }

    viewport.addEventListener('scroll', () => {
      stick = isAtBottom();
      if (stick) unseen = 0;
      updateJump();
    }, { passive: true });

    jump.addEventListener('click', () => {
      stick = true;
      unseen = 0;
      viewport.scrollTop = viewport.scrollHeight;
      updateJump();
      viewport.focus({ preventScroll: true });
    });

    updateEmpty();

    return {
      el,
      update() {},
      show() {
        active = true;
        if (stick) viewport.scrollTop = viewport.scrollHeight;
        schedule(0);
      },
      hide() {
        active = false;
        schedule(0);
      },
    };
  }

  /* stateless — журнал живёт своим опросом get_logs и снимка состояния не ждёт (app.js: экран загрузки). */
  Lz.pages.logs = { title: 'Журнал', icon: 'list', create, layout: 'fill', stateless: true };
})(window.Lz);
