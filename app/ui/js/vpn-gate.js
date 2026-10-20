'use strict';
/*
 * Окно «Работает VPN» перед включением обхода или Telegram-прокси. Спрашивать ли — решает
 * ядро (vpn_preflight); оно же уже запустило проверку «что куда идёт», окно следит за ней
 * по снимкам состояния. Из трея окна нет: там ядро само присылает уведомление.
 */
(function (Lz) {
  const { h, icon, uid } = Lz.dom;
  const ui = Lz.ui;

  const LEAD = {
    zapret: 'Обход и VPN будут работать вместе. Вот что куда пойдёт:',
    tg: 'Telegram-прокси и VPN будут работать вместе. Вот что куда пойдёт:',
  };
  /* Проверка обычно отвечает сразу; зависшая не должна держать кнопку включения занятой вечно. */
  const PREFLIGHT_TIMEOUT_MS = 15000;

  function checkbox(label, checked) {
    const input = h('input', { type: 'checkbox', class: 'check__input', checked });
    return { input, el: h('label', { class: 'check' }, input, h('span', { class: 'check__label', text: label })) };
  }

  /** Promise<{ remember, compat } | null>: null — человек передумал. */
  function askUser(component, reply) {
    return new Promise((resolve) => {
      const label = (reply.vpn && reply.vpn.label) || 'VPN';
      const titleId = uid('vpn-title');
      const textId = uid('vpn-text');
      let modal = null;
      let unsubscribe = null;
      let settled = false;

      function finish(answer) {
        if (settled) return;
        settled = true;
        if (unsubscribe) unsubscribe();
        modal.close();
        resolve(answer);
      }

      function showHowTo() {
        finish(null);
        Lz.nav.go('help', { symptom: 'vpn' });
      }

      const compat = reply.compat === false ? checkbox('Не трогать трафик VPN (рекомендуется)', true) : null;
      const remember = checkbox('Больше не спрашивать для этого VPN', false);
      const routes = ui.slot((data) => Lz.vpn.renderRoutes(data, showHowTo), { cls: 'vpn-routes vpn-dialog__routes' });
      const cancelBtn = ui.button({ label: 'Отмена', onClick: () => finish(null) });
      const confirmBtn = ui.button({
        label: 'Включить вместе с VPN',
        kind: 'primary',
        onClick: () => finish({ remember: remember.input.checked, compat: compat ? compat.input.checked : true }),
      });
      const content = h('div', { class: 'dialog vpn-dialog' },
        h('div', { class: 'dialog__icon', 'aria-hidden': 'true' }, icon('shieldCheck', { size: 22 })),
        /* «VPN «wwan99»» уже со словом VPN — заголовок без повтора: «Работает VPN «wwan99»». */
        h('h2', { class: 'dialog__title', id: titleId, text: /^VPN\b/.test(label) ? `Работает ${label}` : `Работает VPN — ${label}` }),
        h('p', { class: 'dialog__text', id: textId, text: LEAD[component] || LEAD.zapret }),
        routes.el,
        h('div', { class: 'vpn-dialog__checks' }, compat && compat.el, remember.el),
        h('div', { class: 'dialog__actions' }, cancelBtn.el, confirmBtn.el));

      modal = ui.openModal({
        content,
        labelledBy: titleId,
        describedBy: textId,
        cls: 'modal--dialog modal--vpn',
        onEscape: () => finish(null),
        initialFocus: confirmBtn.el,
      });
      unsubscribe = Lz.store.subscribe((state) => routes.update(Lz.vpn.routesData(state, component)));
    });
  }

  /*
   * Проверка не ответила за PREFLIGHT_TIMEOUT_MS или отказала — включаем без окна, как и раньше при её ошибке:
   * обход и прокси работают и рядом с VPN, а про VPN обход скажет уведомлением сам (zapret_start без quiet).
   * Не включать вовсе значило бы, что сломанная проверка выключает обход. Человеку — тост, а не молчание.
   */
  function withoutWindow(reason) {
    ui.toast({ kind: 'warn', text: `Не удалось проверить, работает ли VPN: ${Lz.fmt.sentence(reason)} Включаем без окна «Работает VPN».` });
    return { proceed: true, asked: false };
  }

  /**
   * Перед включением: спросить, если работает VPN. Promise<{ proceed, asked }>: asked — окно
   * показывали и человек согласился (тогда обход включают тихо: zapret_start(true)).
   * Ядро без проверки VPN или ошибка проверки не мешают включить как обычно.
   */
  async function confirmStart(component) {
    if (!Lz.api.hasMethod('vpn_preflight')) return { proceed: true, asked: false };
    let reply;
    try {
      reply = await Lz.api.callWithTimeout('vpn_preflight', PREFLIGHT_TIMEOUT_MS, component);
    } catch (err) {
      return withoutWindow(Lz.api.describeError(err));
    }
    if (reply && reply.ok === false) return withoutWindow(String(reply.error || 'ядро отказало и не назвало причину'));
    if (!reply || !reply.ask) return { proceed: true, asked: false };
    Lz.store.refreshSoon();
    const answer = await askUser(component, reply);
    if (!answer) return { proceed: false, asked: true };
    const saved = await Lz.api.run({ method: 'vpn_answer', args: [answer.remember, answer.compat] });
    return { proceed: Boolean(saved && saved.ok), asked: true };
  }

  Lz.vpnGate = { confirmStart };
})(window.Lz);
