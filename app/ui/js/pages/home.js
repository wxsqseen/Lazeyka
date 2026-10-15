'use strict';
/*
 * Главная: уведомления, сводка, две карточки (home-cards.js) — обход для Discord/YouTube и прокси
 * для Telegram — и строка про VPN, если он работает.
 */
(function (Lz) {
  const { h, icon, setText, setHidden } = Lz.dom;
  const ui = Lz.ui;
  const texts = Lz.texts;

  const NOTICE_TONE = { info: 'info', success: 'ok', warn: 'warn', error: 'err' };
  const NOTICE_ICON = { info: 'info', ok: 'checkCircle', warn: 'alert', err: 'alertCircle' };

  /* ---------- Уведомления ---------- */

  function createNotices() {
    const hiddenIds = new Set();
    let latest = [];
    const view = ui.slot(render, { cls: 'notices' });

    function runNoticeAction(action) {
      const page = action.page ? Lz.nav.resolve(String(action.page)) : null;
      if (page) {
        Lz.nav.go(page);
      } else if (action.call) {
        Lz.api.run({ method: String(action.call), args: Array.isArray(action.args) ? action.args : [] });
      }
    }

    async function dismiss(id) {
      hiddenIds.add(id);
      update(latest);
      const result = await Lz.api.run({ method: 'dismiss_notice', args: [id], key: `dismiss_notice:${id}` });
      if (!result || !result.ok) {
        hiddenIds.delete(id);
        update(latest);
      }
    }

    function noticeEl(notice) {
      const tone = NOTICE_TONE[notice.level] || 'info';
      const action = notice.action && notice.action.label ? ui.button({
        label: notice.action.label,
        kind: 'secondary',
        size: 'sm',
        onClick: () => runNoticeAction(notice.action),
      }) : null;
      const close = notice.dismissible ? ui.button({
        icon: 'x',
        kind: 'ghost',
        size: 'sm',
        ariaLabel: 'Скрыть уведомление',
        title: 'Скрыть',
        onClick: () => dismiss(notice.id),
      }) : null;
      if (action) action.el.dataset.fk = `notice-action:${notice.id}`;
      if (close) close.el.dataset.fk = `notice-close:${notice.id}`;
      return h('div', { class: `notice notice--${tone}`, role: tone === 'err' ? 'alert' : 'status' },
        h('span', { class: 'notice__icon', 'aria-hidden': 'true' }, icon(NOTICE_ICON[tone], { size: 18 })),
        h('p', { class: 'notice__text', text: notice.text }),
        action && action.el,
        close && close.el);
    }

    function render(list) {
      return list.map(noticeEl);
    }

    function update(notices) {
      latest = Array.isArray(notices) ? notices : [];
      for (const id of hiddenIds) {
        if (!latest.some((notice) => notice.id === id)) hiddenIds.delete(id);
      }
      view.update(latest.filter((notice) => !hiddenIds.has(notice.id)));
    }

    return { el: view.el, update };
  }

  /* ---------- Сводка ---------- */

  const ZAPRET_PHRASE = {
    running: 'Discord и YouTube открываются',
    starting: 'обход запускается',
    stopping: 'обход выключается',
    error: 'обход не запустился',
    stopped: 'обход для Discord и YouTube выключен',
  };
  const TELEGRAM_PHRASE = {
    running: 'Telegram ускорен',
    starting: 'прокси для Telegram запускается',
    stopping: 'прокси для Telegram выключается',
    error: 'прокси для Telegram не запустился',
    stopped: 'прокси для Telegram выключен',
  };

  function capitalize(text) {
    return text.charAt(0).toUpperCase() + text.slice(1);
  }

  /** Только подтверждённое: «открываются» — если свежая проверка прошла, «ускорен» — если Telegram подключён. */
  function zapretPhrase(zapret, status) {
    if (status === 'locked') return 'для обхода Discord и YouTube нужны права администратора';
    if (zapret.fix && zapret.fix.running) return 'подбираем стратегию для Discord и YouTube';
    if (status !== 'running') return ZAPRET_PHRASE[status] || ZAPRET_PHRASE.stopped;
    const results = zapret.check && Array.isArray(zapret.check.results) ? zapret.check.results : [];
    if (results.length && results.every((r) => r.ok)) return ZAPRET_PHRASE.running;
    if (results.some((r) => !r.ok)) return 'обход включён, но открывается не всё';
    return 'обход для Discord и YouTube включён';
  }

  function telegramPhrase(tg, status) {
    if (status !== 'running') return TELEGRAM_PHRASE[status] || TELEGRAM_PHRASE.stopped;
    const connected = texts.telegramConnection(tg).tone === 'ok';
    return connected ? TELEGRAM_PHRASE.running : 'прокси ждёт, когда подключится Telegram';
  }

  function summary(state) {
    const zapret = state.zapret || {};
    const tg = state.tg || {};
    const zapretStatus = zapret.available === false ? 'locked' : (zapret.status || 'stopped');
    const tgStatus = tg.status || 'stopped';
    if (zapretStatus === 'stopped' && tgStatus === 'stopped' && !(zapret.fix && zapret.fix.running)) {
      return 'Всё выключено. Нажмите на большую кнопку, чтобы включить.';
    }
    const zp = zapretPhrase(zapret, zapretStatus);
    const tp = telegramPhrase(tg, tgStatus);
    if (zp === ZAPRET_PHRASE.running && tp === TELEGRAM_PHRASE.running) {
      return 'Всё работает: Discord и YouTube открываются, Telegram ускорен.';
    }
    return `${capitalize(zp)}. ${capitalize(tp)}.`;
  }

  /* ---------- VPN ---------- */

  /** Тихая строка под карточками, пока работает VPN: трогает ли его обход и где посмотреть подробности. */
  function createVpnLine() {
    const text = h('span', { class: 'conn__text' });
    const line = h('p', { class: 'conn', role: 'status' }, h('span', { class: 'conn__dot', 'aria-hidden': 'true' }), text);
    const link = ui.button({
      label: 'Что куда идёт',
      iconRight: 'arrowRight',
      kind: 'link',
      size: 'sm',
      onClick: () => Lz.nav.go('zapret', { focus: 'vpn' }),
    });
    const el = h('div', { class: 'home-vpn', hidden: true }, line, link.el);
    return {
      el,
      update(state) {
        const view = Lz.vpn.homeLine(state.vpn);
        setHidden(el, !view);
        if (!view) return;
        line.dataset.tone = view.tone;
        setText(text, view.text);
      },
    };
  }

  /* ---------- Страница ---------- */

  function create() {
    const header = ui.pageHeader({ title: 'Главная', subtitle: '' });
    const notices = createNotices();
    const zapretHero = Lz.homeCards.createZapretHero();
    const telegramHero = Lz.homeCards.createTelegramHero();
    const vpnLine = createVpnLine();
    const el = h('div', { class: 'page__inner page__inner--home' },
      header.el,
      notices.el,
      h('div', { class: 'hero-grid' }, zapretHero.el, telegramHero.el),
      vpnLine.el);

    function update(state) {
      setText(header.subtitleEl, summary(state));
      notices.update(state.notices);
      zapretHero.update(state);
      telegramHero.update(state);
      vpnLine.update(state);
    }

    return { el, update };
  }

  Lz.pages.home = { title: 'Главная', icon: 'home', create };
})(window.Lz);
