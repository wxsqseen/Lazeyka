'use strict';
/*
 * Свой VPN: включение и выключение с любых страниц. Перед включением — окно «Уже работает
 * другой VPN» (решает ядро: vpnclient_preflight). Окна «Скачать ядро?» нет: ядра Лазейка
 * скачивает с GitHub сама при запуске, а «Включить» во время подкачки ждёт её (ход — на
 * странице «VPN»). Здесь же — окно «Добавить из ссылки lazeyka://?»: ссылка может прийти в
 * любой момент, поэтому оно следит за снимками само.
 */
(function (Lz) {
  const { h, icon, uid } = Lz.dom;
  const ui = Lz.ui;
  const texts = Lz.texts;

  const POWER_KEY = 'vpnclient_power';
  const DEEPLINK_KIND = {
    subscription: 'Подписка',
    links: 'Серверы',
    profile: 'Профиль маршрутизации',
  };

  /* ---------- Окно «Уже работает другой VPN» ---------- */

  function conflictTitle(conflict) {
    const label = conflict.label ? String(conflict.label) : '';
    if (conflict.kind === 'proxy') return label ? `Работает системный прокси ${label}` : 'Уже работает системный прокси';
    if (conflict.kind === 'uac_user') return 'Системный прокси недоступен';
    return label ? `Уже работает другой VPN — ${label}` : 'Уже работает другой VPN';
  }

  function conflictText(conflict) {
    if (conflict.text) return String(conflict.text);
    const label = conflict.label ? String(conflict.label) : 'другой VPN';
    if (conflict.kind === 'proxy') return `Лазейка заменит системный прокси ${label} и вернёт его, когда выключится.`;
    if (conflict.kind === 'uac_user') return 'Лазейка запущена от другой учётной записи и не может поменять ваш системный прокси.';
    return `Два VPN мешают друг другу: выключите ${label} или включите Лазейку как системный прокси.`;
  }

  /** Promise<'proxy' | 'tun' | 'force' | null>: как включать, null — человек передумал. */
  function askConflict(conflict) {
    return new Promise((resolve) => {
      const titleId = uid('vc-conflict-title');
      const textId = uid('vc-conflict-text');
      let modal = null;
      let settled = false;
      const finish = (answer) => {
        if (settled) return;
        settled = true;
        modal.close();
        resolve(answer);
      };

      const cancel = ui.button({ label: 'Отмена', onClick: () => finish(null) });
      const buttons = [cancel.el];
      let primary = null;
      let note = null;
      if (conflict.kind === 'proxy') {
        primary = ui.button({ label: 'Включить', kind: 'primary', onClick: () => finish('force') });
      } else if (conflict.kind === 'uac_user') {
        primary = ui.button({ label: 'Включить весь трафик (TUN)', kind: 'primary', onClick: () => finish('tun') });
      } else {
        const force = ui.button({ label: 'Всё равно включить', onClick: () => finish('force') });
        buttons.push(force.el);
        primary = ui.button({ label: 'Включить как системный прокси', kind: 'primary', onClick: () => finish('proxy') });
        note = 'Как системный прокси Лазейка не создаёт свой адаптер и уживается с другим VPN: через ваш сервер пойдут браузеры и программы, которые слушают прокси Windows.';
      }
      buttons.push(primary.el);

      const content = h('div', { class: 'dialog' },
        h('div', { class: 'dialog__icon', 'aria-hidden': 'true' }, icon('shieldAlert', { size: 22 })),
        h('h2', { class: 'dialog__title', id: titleId, text: conflictTitle(conflict) }),
        h('p', { class: 'dialog__text', id: textId, text: conflictText(conflict) }),
        note ? h('p', { class: 'dialog__details', text: note }) : null,
        h('div', { class: 'dialog__actions vc-dialog__actions--wrap' }, buttons));
      modal = ui.openModal({
        content,
        labelledBy: titleId,
        describedBy: textId,
        cls: 'modal--dialog modal--vc-wide',
        onEscape: () => finish(null),
        initialFocus: primary.el,
      });
    });
  }

  /**
   * Перед включением: спросить, если работает чужой VPN. Promise<{ proceed, quiet, mode }>:
   * quiet — окно показывали (ядро не повторит предупреждение), mode — сначала сменить режим.
   * Ошибка проверки не мешает включить: ядро само скажет, если что-то пойдёт не так.
   */
  async function preflight() {
    if (!Lz.api.hasMethod('vpnclient_preflight')) return { proceed: true, quiet: false, mode: null };
    let reply;
    try {
      reply = await Lz.api.call('vpnclient_preflight');
    } catch (err) {
      console.warn('vpnclient_preflight не ответил — включаем без окна про другой VPN:', err);
      return { proceed: true, quiet: false, mode: null };
    }
    if (!reply || !reply.ask || !reply.conflict) {
      if (reply && reply.ok === false) console.warn(`vpnclient_preflight отказал: ${reply.error} — включаем без окна`);
      return { proceed: true, quiet: false, mode: null };
    }
    const answer = await askConflict(reply.conflict);
    if (!answer) return { proceed: false, quiet: true, mode: null };
    return { proceed: true, quiet: true, mode: answer === 'proxy' || answer === 'tun' ? answer : null };
  }

  /* ---------- Включить и выключить ---------- */

  /* Пока идут окна перед включением, повторное нажатие ничего не открывает. */
  let starting = false;

  async function startFlow() {
    const gate = await preflight();
    if (!gate.proceed) return null;
    if (gate.mode) {
      /* Ядро меняет режим до ответа: ok — режим уже другой, отказ (прокси под чужой учётной записью UAC) —
       * VPN не включаем вовсе, иначе он поднял бы TUN рядом с чужим VPN. */
      const switched = await Lz.api.run({ method: 'vpnclient_set_mode', args: [gate.mode], key: POWER_KEY });
      if (!switched || !switched.ok) return switched;
    }
    return Lz.api.run({ method: 'vpnclient_start', args: [gate.quiet], key: POWER_KEY });
  }

  async function start() {
    const state = Lz.store.state;
    const vc = state && state.vpnclient;
    if (!vc) {
      ui.toast({ kind: 'error', text: 'Ядро Лазейки не сообщает о своём VPN — обновите Лазейку.' });
      return null;
    }
    if (!texts.vpncHasServers(vc)) {
      ui.toast({ kind: 'info', text: 'Сначала добавьте подписку или сервер.' });
      Lz.nav.go('vpnclient', { focus: 'add' });
      return null;
    }
    if (starting) return null;
    starting = true;
    try {
      return await startFlow();
    } finally {
      starting = false;
    }
  }

  function stop() {
    return Lz.api.run({ method: 'vpnclient_stop', key: POWER_KEY });
  }

  function toggle(status) {
    return texts.vpncRunning(status) ? stop() : start();
  }

  /** Выбрать сервер или «Самый быстрый»; на работающем ядре ядро переключит без перезапуска. */
  function select(id) {
    return Lz.api.run({ method: 'vpnclient_select', args: [id], key: `vpnclient_select:${id}` });
  }

  /* ---------- Окно «Добавить из ссылки lazeyka://?» ---------- */

  const answeredTokens = new Set();
  let deeplinkModal = null;
  let deeplinkToken = null;

  function closeDeeplink() {
    if (deeplinkModal) deeplinkModal.close();
    deeplinkModal = null;
    deeplinkToken = null;
  }

  function showDeeplink(request) {
    closeDeeplink();
    const token = String(request.token);
    deeplinkToken = token;
    const titleId = uid('vc-deeplink-title');
    const textId = uid('vc-deeplink-text');

    async function answer(accept) {
      answeredTokens.add(token);
      closeDeeplink();
      await Lz.api.run({
        method: 'vpnclient_deeplink_confirm',
        args: [token, accept],
        key: 'vpnclient_deeplink_confirm',
        success: accept ? 'Добавляем — ход виден на странице «VPN»' : null,
      });
    }

    const cancel = ui.button({ label: 'Не добавлять', onClick: () => answer(false) });
    const accept = ui.button({ label: 'Добавить', kind: 'primary', icon: 'plus', onClick: () => answer(true) });
    const kind = DEEPLINK_KIND[request.kind] || 'Ссылка';
    const content = h('div', { class: 'dialog' },
      h('div', { class: 'dialog__icon', 'aria-hidden': 'true' }, icon('link', { size: 22 })),
      h('h2', { class: 'dialog__title', id: titleId, text: 'Добавить из ссылки lazeyka://?' }),
      h('p', { class: 'dialog__text', id: textId, text: 'Ссылку передал браузер или другая программа. Без вашего согласия Лазейка ничего не добавит и ничего не включит.' }),
      h('div', { class: 'vc-deeplink' },
        h('span', { class: 'vc-deeplink__kind', text: kind }),
        h('span', { class: 'vc-deeplink__text', text: String(request.summary || request.text || 'Подробностей нет') })),
      h('div', { class: 'dialog__actions' }, cancel.el, accept.el));
    deeplinkModal = ui.openModal({
      content,
      labelledBy: titleId,
      describedBy: textId,
      cls: 'modal--dialog',
      onEscape: () => answer(false),
      initialFocus: cancel.el,
    });
  }

  Lz.store.subscribe((state) => {
    const request = state && state.vpnclient ? state.vpnclient.deeplink_request : null;
    if (request && request.token != null) {
      const token = String(request.token);
      if (token !== deeplinkToken && !answeredTokens.has(token)) showDeeplink(request);
      return;
    }
    /* Ядро сняло запрос (ответили из другого окна или вышел срок) — окно больше не нужно. */
    if (deeplinkModal) closeDeeplink();
  });

  Lz.vpnclientGate = { start, stop, toggle, select, POWER_KEY };
})(window.Lz);
