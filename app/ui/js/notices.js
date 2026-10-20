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

  /*
   * Включение — через те же окна, что и большие кнопки («Работает VPN», «Уже работает другой VPN»), и под теми же
   * ключами: кнопка плашки занята, пока идёт включение с любой кнопки, и второго окна не откроет.
   */
  const GATED = {
    zapret_start: { run: () => Lz.actions.startZapret(), key: () => Lz.actions.POWER_KEY.zapret },
    tg_start: { run: () => Lz.actions.startTelegram(), key: () => Lz.actions.POWER_KEY.tg },
    vpnclient_start: { run: () => Lz.vpnclientGate.start(), key: () => Lz.vpnclientGate.POWER_KEY },
    /* «Найти и включить» сторожа — та же кнопка, что на главной: один подбор, одна занятая кнопка. */
    zapret_fix: { run: () => Lz.fix.start(), key: () => Lz.fix.BUSY_KEYS },
    vpnclient_stop: { run: () => Lz.vpnclientGate.stop(), key: () => Lz.vpnclientGate.POWER_KEY },
  };
  /*
   * Те же действия, что у кнопок страниц, — под их ключами: «Переподключить» в плашке и в шапке «Своего VPN»,
   * «Перезапустить» в плашке и в карточке Лазейки — два нажатия дают один вызов.
   */
  const SHARED_KEY = {
    vpnclient_restart: 'vpnclient_restart',
    app_restart: 'app_restart',
  };

  function actionKey(notice) {
    const method = String(notice.action.call);
    return Object.prototype.hasOwnProperty.call(SHARED_KEY, method) ? SHARED_KEY[method] : `notice:${notice.id}`;
  }

  function gated(method) {
    return Object.prototype.hasOwnProperty.call(GATED, method) ? GATED[method] : null;
  }

  function runAction(notice) {
    const action = notice.action || {};
    const page = action.page ? Lz.nav.resolve(String(action.page)) : null;
    if (page) {
      Lz.nav.go(page);
      return;
    }
    if (!action.call) return;
    const method = String(action.call);
    const gate = gated(method);
    if (gate) {
      gate.run();
      return;
    }
    Lz.api.run({ method, args: Array.isArray(action.args) ? action.args : [], key: actionKey(notice) });
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
      const gate = notice.action && notice.action.call ? gated(String(notice.action.call)) : null;
      const action = notice.action && notice.action.label ? ui.button({
        label: String(notice.action.label),
        kind: 'secondary',
        size: 'sm',
        busyKey: gate ? gate.key() : (notice.action.call ? actionKey(notice) : null),
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
