'use strict';
/*
 * Плашки и уведомления из state.notices.
 * Главная показывает всё: постоянные плашки (persistent: true — поломка, найденная Лазейкой самой;
 * висит, пока проблема есть) и временные уведомления. Остальные страницы (app.js) — только
 * постоянные плашки со своим page, под заголовком. Тексты из ядра недоверенные: только textContent.
 */
(function (Lz) {
  const { h, icon } = Lz.dom;
  const ui = Lz.ui;

  const TONE = { info: 'info', success: 'ok', warn: 'warn', error: 'err' };
  const TONE_ICON = { info: 'info', ok: 'checkCircle', warn: 'alert', err: 'alertCircle' };
  const HIDE_MAX_MS = 10000;

  /*
   * Закрытое крестиком прячется сразу, не дожидаясь ответа ядра, — до первого снимка, в котором его
   * уже нет (дальше прячет само ядро), и не дольше HIDE_MAX_MS. Набор один на все экземпляры: его
   * чистит снимок любой открытой страницы, иначе экземпляр ушедшей страницы спрятал бы новое появление
   * той же проблемы с тем же id.
   */
  const hidden = new Map();   // id → до какого времени прятать

  function pruneHidden(notices) {
    const now = Date.now();
    for (const [id, until] of hidden) {
      if (until <= now || !notices.some((notice) => notice && notice.id === id)) hidden.delete(id);
    }
  }

  /* Включение — через те же окна, что и большие кнопки («Работает VPN», «Уже работает другой VPN»). */
  const GATED = {
    zapret_start: () => Lz.actions.startZapret(),
    tg_start: () => Lz.actions.startTelegram(),
    vpnclient_start: () => Lz.vpnclientGate.start(),
  };

  function runAction(notice) {
    const action = notice.action || {};
    const page = action.page ? Lz.nav.resolve(String(action.page)) : null;
    if (page) {
      Lz.nav.go(page);
      return;
    }
    if (!action.call) return;
    const method = String(action.call);
    if (Object.prototype.hasOwnProperty.call(GATED, method)) {
      GATED[method]();
      return;
    }
    Lz.api.run({ method, args: Array.isArray(action.args) ? action.args : [], key: `notice:${notice.id}` });
  }

  /**
   * opts.page — показывать только постоянные плашки этой страницы; без него — все (главная).
   * Возвращает { el, update(notices) }.
   */
  function create(opts) {
    const pageName = opts && opts.page ? String(opts.page) : null;
    let latest = [];
    const view = ui.slot((list) => renderList(list), { cls: ['notices', pageName && 'notices--page'] });

    async function dismiss(id) {
      hidden.set(id, Date.now() + HIDE_MAX_MS);
      render(latest);
      const result = await Lz.api.run({ method: 'dismiss_notice', args: [id], key: `dismiss_notice:${id}` });
      if (!result || !result.ok) {
        hidden.delete(id);
        render(latest);
      }
    }

    function noticeEl(notice) {
      const tone = TONE[notice.level] || 'info';
      const persistent = notice.persistent === true;
      const action = notice.action && notice.action.label ? ui.button({
        label: String(notice.action.label),
        kind: 'secondary',
        size: 'sm',
        busyKey: notice.action.call ? `notice:${notice.id}` : null,
        onClick: () => runAction(notice),
      }) : null;
      const close = notice.dismissible ? ui.button({
        icon: 'x',
        kind: 'ghost',
        size: 'sm',
        ariaLabel: persistent ? 'Скрыть плашку, пока проблема не повторится' : 'Скрыть уведомление',
        title: persistent ? 'Скрыть, пока не повторится' : 'Скрыть',
        onClick: () => dismiss(notice.id),
      }) : null;
      if (action) action.el.dataset.fk = `notice-action:${notice.id}`;
      if (close) close.el.dataset.fk = `notice-close:${notice.id}`;
      return h('div', {
        class: ['notice', `notice--${tone}`, persistent && 'notice--persistent'],
        role: tone === 'err' ? 'alert' : 'status',
      },
      h('span', { class: 'notice__icon', 'aria-hidden': 'true' }, icon(TONE_ICON[tone], { size: 18 })),
      h('p', { class: 'notice__text', text: String(notice.text == null ? '' : notice.text) }),
      action && action.el,
      close && close.el);
    }

    function renderList(list) {
      return list.map(noticeEl);
    }

    function wanted(notice) {
      if (!notice || typeof notice !== 'object' || hidden.has(notice.id)) return false;
      if (!pageName) return true;
      return notice.persistent === true && notice.page != null && Lz.nav.resolve(String(notice.page)) === pageName;
    }

    function render(notices) {
      view.update(notices.filter(wanted));
    }

    function update(notices) {
      latest = Array.isArray(notices) ? notices : [];
      pruneHidden(latest);
      render(latest);
    }

    return { el: view.el, update };
  }

  Lz.notices = { create };
})(window.Lz);
