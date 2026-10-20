'use strict';
/*
 * Главная: плашки и уведомления (notices.js — все, в том числе постоянные плашки других страниц),
 * сводка, карточки (home-cards.js) — обход для Discord/YouTube, Telegram-прокси и во всю ширину
 * «Свой VPN» (без серверов — тихая строка) — и строка про чужой VPN.
 */
(function (Lz) {
  const { h, setText, setHidden } = Lz.dom;
  const ui = Lz.ui;
  const texts = Lz.texts;

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
    starting: 'Telegram-прокси запускается',
    stopping: 'Telegram-прокси выключается',
    error: 'Telegram-прокси не запустился',
    stopped: 'Telegram-прокси выключен',
  };

  /* По тому, что написано на пилюле карточки (vpncPillShown): проверка выхода не прошла — «нет выхода». */
  const VPNC_PHRASE = {
    running: 'свой VPN подключён',
    verifying: 'свой VPN проверяет соединение',
    noexit: 'через свой VPN сайты не открываются',
    starting: 'свой VPN подключается',
    stopping: 'свой VPN выключается',
    error: 'свой VPN не подключился',
  };

  /** Фраза про свой VPN; null — его не настроили или он выключен (тогда о нём молчим). */
  function vpnclientPhrase(state) {
    const vc = state.vpnclient;
    if (!vc || vc.available === false || !texts.vpncHasServers(vc)) return null;
    return VPNC_PHRASE[texts.vpncPillShown(vc)] || null;
  }

  function capitalize(text) {
    return text.charAt(0).toUpperCase() + text.slice(1);
  }

  /**
   * Почему обход недоступен — коротко, для сводки. Без прав — так и сказать; с правами причина другая
   * (например, пакет стратегий ещё не установлен) — её называет ядро.
   */
  function lockedPhrase(zapret, admin) {
    const reason = String(zapret.unavailable_reason || '').trim().replace(/\.$/, '');
    if (admin && reason) return reason.charAt(0).toLowerCase() + reason.slice(1);
    if (admin) return 'обход Discord и YouTube сейчас недоступен';
    return 'для обхода Discord и YouTube нужны права администратора';
  }

  /** Только подтверждённое: «открываются» — если свежая проверка прошла, «ускорен» — если Telegram подключён. */
  function zapretPhrase(zapret, status, admin) {
    if (status === 'locked') return lockedPhrase(zapret, admin);
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
    const vp = vpnclientPhrase(state);
    if (zapretStatus === 'stopped' && tgStatus === 'stopped' && !(zapret.fix && zapret.fix.running) && !vp) {
      return 'Всё выключено. Нажмите на большую кнопку, чтобы включить.';
    }
    const zp = zapretPhrase(zapret, zapretStatus, Boolean(state.app && state.app.admin));
    const tp = telegramPhrase(tg, tgStatus);
    if (zp === ZAPRET_PHRASE.running && tp === TELEGRAM_PHRASE.running && (!vp || vp === VPNC_PHRASE.running)) {
      return vp
        ? 'Всё работает: Discord и YouTube открываются, Telegram ускорен, свой VPN подключён.'
        : 'Всё работает: Discord и YouTube открываются, Telegram ускорен.';
    }
    return `${[zp, tp, vp].filter(Boolean).map(capitalize).join('. ')}.`;
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
    const notices = Lz.notices.create();
    const zapretHero = Lz.homeCards.createZapretHero();
    const telegramHero = Lz.homeCards.createTelegramHero();
    const vpnclientHero = Lz.homeCards.createVpnClientHero();
    const vpnclientLine = Lz.homeCards.createVpnClientLine();
    const vpnLine = createVpnLine();
    const el = h('div', { class: 'page__inner page__inner--home' },
      header.el,
      notices.el,
      h('div', { class: 'hero-grid' }, zapretHero.el, telegramHero.el, vpnclientHero.el),
      vpnclientLine.el,
      vpnLine.el);

    function updateVpnClient(state) {
      const vc = state.vpnclient;
      const configured = Boolean(vc) && texts.vpncHasServers(vc);
      setHidden(vpnclientHero.el, !configured);
      setHidden(vpnclientLine.el, !vc || configured);
      if (configured) vpnclientHero.update(state);
    }

    function update(state) {
      setText(header.subtitleEl, summary(state));
      notices.update(state.notices);
      zapretHero.update(state);
      telegramHero.update(state);
      updateVpnClient(state);
      vpnLine.update(state);
    }

    return { el, update };
  }

  Lz.pages.home = { title: 'Главная', icon: 'home', create };
})(window.Lz);
