'use strict';
/*
 * «Найти и включить» (zapret_fix): кнопка, ход подбора и итог — общие для главной,
 * «Помощи» и приветствия. Процесс ведёт ядро; страница только показывает zapret.fix.
 */
(function (Lz) {
  const { h, icon } = Lz.dom;
  const ui = Lz.ui;
  const texts = Lz.texts;

  const FIX_KEY = 'zapret_fix';
  const POWER_KEY = Lz.actions.POWER_KEY.zapret;
  /* Кнопки «Найти и включить» заняты и своим ключом, и ключом включения обхода (кнопка питания, плашки). */
  const BUSY_KEYS = [FIX_KEY, POWER_KEY];
  const REVERT_KEY = 'zapret_fix_revert';
  const FINISHED_STAGES = new Set(['done', 'failed']);
  const RUNNING_LIKE = new Set(['running', 'starting']);
  const STATUS_ICON_SIZE = 16;
  const DIRECT_NOTE = 'проверено напрямую, мимо VPN';

  function fixOf(zapret) {
    return (zapret && zapret.fix) || {};
  }

  function callFix() {
    return Lz.api.run({ method: 'zapret_fix', key: `${FIX_KEY}:call` });
  }

  /**
   * «Найти и включить» включает выключенный обход — тогда сначала окно «Работает VPN», если нужно. Это то же
   * включение, что у кнопки питания, поэтому оно держит и её ключ: «Включить» и «Найти и включить» подряд дают одно
   * окно и один старт. Кнопка занята с нажатия до ответа ядра: двойное нажатие второго подбора не даст.
   */
  function start() {
    return Lz.api.hold(FIX_KEY, async () => {
      const state = Lz.store.state;
      const status = state && state.zapret ? state.zapret.status : 'stopped';
      if (RUNNING_LIKE.has(status)) return callFix();
      return Lz.api.hold(POWER_KEY, async () => {
        const gate = await Lz.vpnGate.confirmStart('zapret');
        if (!gate.proceed) return null;
        return callFix();
      });
    });
  }

  function revert() {
    return Lz.api.run({
      method: 'zapret_fix_revert',
      key: REVERT_KEY,
      success: (result) => result.message || 'Прежняя стратегия возвращена',
    });
  }

  /** Состояние кнопки — сериализуемое, чтобы класть его в данные слотов. */
  function flags(zapret) {
    const source = zapret || {};
    return {
      running: Boolean(fixOf(source).running),
      blocked: source.available === false || Boolean(source.test && source.test.running),
    };
  }

  /** Главная кнопка. set(flags(zapret)): занята, пока идёт подбор; недоступна без прав и во время полного подбора. */
  function button(opts) {
    const options = opts || {};
    const ctl = ui.button({
      label: 'Найти и включить',
      icon: 'sparkle',
      kind: 'primary',
      size: options.size,
      busyKey: BUSY_KEYS,
      title: 'Проверит Discord и YouTube и, если они не открываются, подберёт и включит рабочую стратегию',
      onClick: () => start(),
    });
    if (options.fk) ctl.el.dataset.fk = options.fk;
    return {
      el: ctl.el,
      set(state) {
        ctl.setBusy(Boolean(state && state.running));
        ctl.setDisabled(Boolean(state && state.blocked));
      },
    };
  }

  /**
   * Итог «Найти и включить» новее последней проверки доступности — тогда показываем его,
   * а не чипы проверки. Ядро забывает проверку, как только меняется стратегия, поэтому
   * после удачного подбора проверки обычно нет совсем.
   */
  function isLatest(zapret) {
    const fix = fixOf(zapret);
    if (fix.running) return true;
    if (!FINISHED_STAGES.has(fix.stage) || !fix.finished_at) return false;
    const check = (zapret && zapret.check) || {};
    return !check.at || Number(fix.finished_at) >= Number(check.at);
  }

  /** Пояснение под сообщением ядра во время перебора: какую стратегию пробуем и какие не подошли. */
  function pickDetail(zapret, fix) {
    if (fix.stage !== 'pick') return '';
    const parts = [];
    const current = fix.current ? texts.strategyLabel(zapret, fix.current) : '';
    if (current && !String(fix.message || '').includes(current)) parts.push(`Пробуем «${current}»`);
    const rejected = (Array.isArray(fix.tried) ? fix.tried : [])
      .filter((id) => id !== fix.current)
      .map((id) => texts.strategyLabel(zapret, id));
    if (rejected.length) parts.push(`${parts.length ? 'не подошли' : 'Не подошли'}: ${rejected.join(', ')}`);
    return parts.join(' · ');
  }

  /** Данные для render(): ход подбора, его итог или null, если показывать нечего. */
  function view(zapret) {
    const fix = fixOf(zapret);
    if (fix.running) {
      return {
        running: true,
        message: String(fix.message || 'Ищем рабочую стратегию…'),
        detail: capitalize([pickDetail(zapret, fix), fix.direct ? 'проверяем напрямую, мимо VPN' : ''].filter(Boolean).join(' · ')),
      };
    }
    if (!isLatest(zapret)) return null;
    const done = fix.stage === 'done';
    /* Обход с тех пор выключили — «открываются» уже неправда; неудача же остаётся в силе. */
    if (done && zapret.status !== 'running' && zapret.status !== 'starting') return null;
    const canRevert = Boolean(fix.found && fix.previous && fix.found !== fix.previous);
    return {
      running: false,
      tone: done ? 'ok' : 'warn',
      message: String(fix.message || (done ? 'Готово.' : 'Рабочую стратегию подобрать не получилось.')),
      detail: fix.direct ? capitalize(DIRECT_NOTE) : '',
      revertTo: canRevert ? texts.strategyLabel(zapret, fix.previous) : null,
    };
  }

  function capitalize(text) {
    return text ? text.charAt(0).toUpperCase() + text.slice(1) : '';
  }

  /** «Проверено 4 мин назад · напрямую, мимо VPN» — подпись под чипами проверки. */
  function checkedLine(ago, direct) {
    if (!ago) return direct ? capitalize(DIRECT_NOTE) : '';
    return `Проверено ${ago}${direct ? ' · напрямую, мимо VPN' : ''}`;
  }

  function revertLink(label) {
    const link = ui.button({
      label: 'Вернуть прежнюю',
      kind: 'link',
      size: 'sm',
      busyKey: REVERT_KEY,
      title: `Вернуть «${label}»`,
      onClick: () => revert(),
    });
    link.el.dataset.fk = 'fix-revert';
    return link.el;
  }

  function render(data) {
    if (!data) return null;
    if (data.running) {
      return h('div', { class: 'fix-status', role: 'status' },
        h('span', { class: 'spinner fix-status__icon', 'aria-hidden': 'true' }),
        h('div', { class: 'fix-status__body' },
          h('p', { class: 'fix-status__text', text: data.message }),
          data.detail ? h('p', { class: 'fix-status__detail', text: data.detail }) : null));
    }
    return h('div', { class: `fix-status fix-status--${data.tone}`, role: 'status' },
      icon(data.tone === 'ok' ? 'checkCircle' : 'alertCircle', { size: STATUS_ICON_SIZE, cls: 'fix-status__icon' }),
      h('div', { class: 'fix-status__body' },
        h('p', { class: 'fix-status__text', text: data.message }),
        data.detail ? h('p', { class: 'fix-status__detail', text: data.detail }) : null,
        data.revertTo ? revertLink(data.revertTo) : null));
  }

  /** Чипы быстрой проверки: «✓ Discord», «✕ YouTube»; подробности — во всплывающей подсказке. */
  function checkChips(results) {
    return h('div', { class: 'checks' }, results.map((item) => ui.chip({
      icon: item.ok ? 'check' : 'x',
      text: item.label || item.id,
      tone: item.ok ? 'ok' : 'err',
      title: item.detail ? `${item.label || item.id}: ${item.detail}` : null,
    })));
  }

  Lz.fix = { FIX_KEY, BUSY_KEYS, start, revert, flags, button, isLatest, view, render, checkChips, checkedLine };
})(window.Lz);
