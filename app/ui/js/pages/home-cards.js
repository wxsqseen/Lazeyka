'use strict';
/* Главная: карточки «Discord и YouTube» и «Telegram» с большой кнопкой питания. */
(function (Lz) {
  const { h, icon, uid, setText, setHidden } = Lz.dom;
  const ui = Lz.ui;
  const fmt = Lz.fmt;
  const texts = Lz.texts;

  function heroHead({ title, subtitle, pill }) {
    return h('header', { class: 'hero__head' },
      h('div', { class: 'hero__titles' },
        h('h2', { class: 'hero__title', text: title }),
        h('p', { class: 'hero__sub', text: subtitle })),
      pill.el);
  }

  /* ---------- Карточка обхода ---------- */

  function zapretCaption(zapret) {
    if (zapret.fix && zapret.fix.running) return 'Ищем рабочую стратегию…';
    switch (zapret.status) {
      case 'running':
        return zapret.started_at ? `Работает ${fmt.since(zapret.started_at)}` : 'Обход включён';
      case 'starting':
        return 'Запускаем обход…';
      case 'stopping':
        return 'Выключаем обход…';
      case 'error':
        return zapret.error || 'Обход не запустился. Подробности — в журнале.';
      default:
        return 'Нажмите, чтобы включить';
    }
  }

  function renderModeChips(data) {
    return [
      ui.chip({
        icon: 'gamepad',
        text: texts.gameFilter(data.game).chip,
        tone: data.game && data.game !== 'disabled' ? 'accent' : null,
        title: 'Настроить фильтры',
        onClick: () => Lz.nav.go('zapret', { focus: 'filters' }),
      }),
      ui.chip({
        icon: 'globe',
        text: texts.ipset(data.ipset).chip,
        tone: data.ipset && data.ipset !== 'none' ? 'accent' : null,
        title: 'Настроить фильтры',
        onClick: () => Lz.nav.go('zapret', { focus: 'filters' }),
      }),
    ];
  }

  /** Под кнопками: ход «Найти и включить», идущая проверка или чипы последней проверки с итогом подбора. */
  function renderCheckArea(data) {
    if (data.fix && data.fix.running) return Lz.fix.render(data.fix);
    if (data.checking) {
      return h('p', { class: 'hero__hint' }, h('span', { class: 'spinner spinner--inline', 'aria-hidden': 'true' }),
        'Проверяем, открываются ли сайты…');
    }
    const nodes = [
      data.results.length ? Lz.fix.checkChips(data.results) : null,
      Lz.fix.render(data.fix),
    ].filter(Boolean);
    if (!nodes.length) {
      return h('p', { class: 'hero__hint', text: 'Проверьте, открываются ли Discord и YouTube прямо сейчас.' });
    }
    return nodes;
  }

  function createZapretHero() {
    const pill = ui.statusPill();
    const power = Lz.power.create({
      label: 'Обход блокировок для Discord и YouTube',
      onToggle: (status) => Lz.actions.toggleZapret(status),
    });
    const caption = h('p', { class: 'hero__caption', 'aria-live': 'polite' });
    const powerArea = h('div', { class: 'hero__power' }, power.el, caption);

    const lockedText = h('p', { class: 'hero__locked-text' });
    const relaunch = ui.actionButton({
      method: 'relaunch_admin',
      label: 'Перезапустить с правами администратора',
      icon: 'shieldCheck',
      kind: 'primary',
    });
    const lockedArea = h('div', { class: 'hero__locked', hidden: true },
      h('div', { class: 'hero__locked-icon', 'aria-hidden': 'true' }, icon('lock', { size: 30 })),
      h('p', { class: 'hero__locked-title', text: 'Обход пока недоступен' }),
      lockedText,
      relaunch.el);

    const selectId = uid('strategy');
    const strategy = ui.selectControl({
      id: selectId,
      cls: 'select--grow',
      onChange: (id) => Lz.actions.setStrategy(id),
    });
    const modeChips = ui.slot(renderModeChips, { cls: 'chips' });
    const settingsSection = h('div', { class: 'hero__section' },
      h('div', { class: 'hero__row' },
        h('label', { class: 'hero__label', for: selectId, text: 'Стратегия' }),
        strategy.el),
      modeChips.el);

    const fixBtn = Lz.fix.button({ size: 'sm' });
    /* Без иконки: рядом с главной кнопкой обе помещаются в узкую карточку. */
    const checkBtn = ui.button({
      label: 'Проверить доступность',
      size: 'sm',
      busyKey: 'zapret_check',
      onClick: () => Lz.api.run({ method: 'zapret_check' }),
    });
    const pickLink = ui.button({
      label: 'Подобрать стратегию',
      iconRight: 'arrowRight',
      kind: 'link',
      size: 'sm',
      title: 'Полный подбор: Лазейка по очереди проверит все стратегии',
      onClick: () => Lz.nav.go('zapret', { focus: 'test' }),
    });
    const checkArea = ui.slot(renderCheckArea, { cls: 'hero__checks' });
    const checkedAgo = h('p', { class: 'hero__hint', hidden: true });
    const watchdogLine = h('p', { class: 'hero__hint', hidden: true });
    const checkSection = h('div', { class: 'hero__section hero__section--end' },
      h('div', { class: 'hero__row hero__row--buttons' }, fixBtn.el, checkBtn.el),
      checkArea.el,
      h('div', { class: 'hero__foot' },
        h('div', { class: 'hero__meta' }, checkedAgo, watchdogLine),
        pickLink.el));

    const el = h('article', { class: 'panel hero hero--zapret', dataset: { state: 'stopped' } },
      heroHead({ title: 'Discord и YouTube', subtitle: 'Обход замедления · zapret', pill }),
      powerArea,
      lockedArea,
      h('div', { class: 'hero__sep', 'aria-hidden': 'true' }),
      settingsSection,
      checkSection);

    function updateChecks(zapret, available, fixFlags) {
      const check = zapret.check || {};
      const checking = Boolean(check.running);
      const results = Array.isArray(check.results) ? check.results : [];
      fixBtn.set(fixFlags);
      checkBtn.setBusy(checking);
      checkBtn.setDisabled(!available || fixFlags.running);
      checkArea.update({ checking, results, fix: Lz.fix.view(zapret) });

      const shown = !checking && !fixFlags.running && results.length > 0;
      const checked = shown ? Lz.fix.checkedLine(fmt.relative(check.at), Boolean(check.direct)) : '';
      setText(checkedAgo, checked);
      setHidden(checkedAgo, !checked);
      const watchdog = texts.watchdogLine(zapret.watchdog);
      setText(watchdogLine, watchdog);
      setHidden(watchdogLine, !watchdog);
    }

    function update(state) {
      const zapret = state.zapret || {};
      const available = zapret.available !== false;
      const status = available ? (zapret.status || 'stopped') : 'locked';
      const fixFlags = Lz.fix.flags(zapret);
      if (el.dataset.state !== status) el.dataset.state = status;
      pill.set(status);

      setHidden(powerArea, !available);
      setHidden(lockedArea, available);
      /* Во время «Найти и включить» обходом управляет ядро: кнопка питания и выбор стратегии ждут. */
      power.update(zapret.status, { disabled: !available || fixFlags.running });
      setText(caption, zapretCaption(zapret));
      caption.classList.toggle('is-error', zapret.status === 'error' && !fixFlags.running);

      setText(lockedText, zapret.unavailable_reason || 'Для обхода нужны права администратора.');
      setHidden(relaunch.el, Boolean(state.app && state.app.admin));

      const strategies = Array.isArray(zapret.strategies) ? zapret.strategies : [];
      const options = strategies.map((item) => ({ value: item.id, label: texts.strategyChoiceLabel(zapret, item) }));
      if (!zapret.strategy) options.unshift({ value: '', label: 'Не выбрана' });
      strategy.setOptions(options);
      strategy.sync(zapret.strategy || '');
      strategy.setDisabled(!available || fixFlags.running);

      modeChips.update({
        game: zapret.game_filter ? zapret.game_filter.mode : 'disabled',
        ipset: zapret.ipset ? zapret.ipset.mode : 'none',
      });
      updateChecks(zapret, available, fixFlags);
    }

    return { el, update };
  }

  /* ---------- Карточка Telegram ---------- */

  function telegramCaption(tg) {
    switch (tg.status) {
      case 'running':
        return `Прокси ${tg.host || '127.0.0.1'}:${tg.port || ''}`;
      case 'starting':
        return 'Запускаем прокси…';
      case 'stopping':
        return 'Выключаем прокси…';
      case 'error':
        return tg.error || 'Прокси не запустился. Подробности — в журнале.';
      default:
        return 'Нажмите, чтобы включить';
    }
  }

  function statTile(iconName, label, valueEl, modifier) {
    return h('div', { class: ['stat', modifier && `stat--${modifier}`] },
      h('span', { class: 'stat__label' }, iconName ? icon(iconName, { size: 14 }) : null, label),
      valueEl);
  }

  function createTelegramHero() {
    const pill = ui.statusPill();
    const power = Lz.power.create({
      label: 'Прокси для Telegram',
      onToggle: (status) => Lz.actions.toggleTelegram(status),
    });
    const caption = h('p', { class: 'hero__caption', 'aria-live': 'polite' });

    const connect = ui.button({
      label: 'Подключить Telegram',
      kind: 'primary',
      cls: 'btn--grow',
      onClick: (event, ctl) => Lz.actions.connectTelegram(ctl),
    });
    const copy = ui.button({
      label: 'Скопировать ссылку',
      busyKey: 'tg_copy_link',
      title: 'Ссылка tg://proxy — её можно открыть в Telegram на этом компьютере',
      onClick: () => Lz.actions.copyLink(),
    });

    const connDot = h('span', { class: 'conn__dot', 'aria-hidden': 'true' });
    const connText = h('span', { class: 'conn__text' });
    const conn = h('p', { class: 'conn', role: 'status' }, connDot, connText);
    const upValue = h('span', { class: 'stat__value num' });
    const downValue = h('span', { class: 'stat__value num' });
    const totalValue = h('span', { class: 'stat__value num' });
    const spark = ui.sparkline({ label: 'Скорость за последние две минуты' });
    const statsSection = h('div', { class: 'hero__section hero__section--end hero__stats' },
      h('div', { class: 'stats' },
        statTile('arrowUp', 'Отдача', upValue, 'up'),
        statTile('arrowDown', 'Загрузка', downValue, 'down'),
        statTile(null, 'За сеанс', totalValue)),
      h('div', { class: 'spark-wrap' }, spark.el));

    const el = h('article', { class: 'panel hero hero--tg', dataset: { state: 'stopped' } },
      heroHead({ title: 'Telegram', subtitle: 'Ускорение без VPN · tg-ws-proxy', pill }),
      h('div', { class: 'hero__power' }, power.el, caption),
      h('div', { class: 'hero__sep', 'aria-hidden': 'true' }),
      h('div', { class: 'hero__section' },
        h('div', { class: 'hero__row hero__row--buttons' }, connect.el, copy.el),
        conn),
      statsSection);

    function update(state) {
      const tg = state.tg || {};
      const status = tg.status || 'stopped';
      const stats = tg.stats || {};
      if (el.dataset.state !== status) el.dataset.state = status;
      pill.set(status);
      power.update(status);
      setText(caption, telegramCaption(tg));
      caption.classList.toggle('is-error', status === 'error');
      caption.classList.toggle('mono', status === 'running');

      const line = texts.telegramConnection(tg);
      conn.dataset.tone = line.tone;
      setText(connText, line.text);
      setText(upValue, fmt.rate(stats.up_rate || 0));
      setText(downValue, fmt.rate(stats.down_rate || 0));
      setText(totalValue, fmt.bytes((Number(stats.up) || 0) + (Number(stats.down) || 0)));
      statsSection.classList.toggle('is-idle', status !== 'running');
      spark.update(tg.history);
    }

    return { el, update };
  }

  Lz.homeCards = { createZapretHero, createTelegramHero };
})(window.Lz);
