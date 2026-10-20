'use strict';
/* Страница «Обход»: управление zapret и все его настройки. Секции — в zapret-vpn.js, zapret-strategies.js и zapret-options.js. */
(function (Lz) {
  const { h, setText } = Lz.dom;
  const ui = Lz.ui;

  function subtitle(zapret) {
    const parts = ['Discord и YouTube через zapret'];
    if (zapret.pack && zapret.pack.version) parts.push(`пакет стратегий ${zapret.pack.version}`);
    if (zapret.mode === 'service') parts.push('служба Windows');
    return parts.join(' · ');
  }

  function renderBanner(data) {
    if (data.locked) {
      const relaunch = data.admin ? null : ui.actionButton({
        method: 'relaunch_admin',
        label: 'Перезапустить с правами администратора',
        icon: 'shieldCheck',
        kind: 'primary',
        size: 'sm',
      }).el;
      return ui.callout({
        tone: 'warn',
        title: 'Обход недоступен',
        text: data.reason || 'Для обхода нужны права администратора.',
        actions: relaunch,
      });
    }
    if (data.status === 'error') {
      const logs = ui.button({ label: 'Открыть журнал', size: 'sm', onClick: () => Lz.nav.go('logs') }).el;
      return ui.callout({ tone: 'err', title: 'Обход не запустился', text: data.error || 'Подробности — в журнале.', actions: logs });
    }
    return null;
  }

  function create() {
    const sections = Lz.zapretSections;
    let status = 'stopped';

    const pill = ui.statusPill();
    const restartBtn = ui.actionButton({ method: 'zapret_restart', label: 'Перезапустить', icon: 'refresh', success: 'Обход перезапущен' });
    const powerBtn = ui.button({
      label: 'Включить',
      icon: 'power',
      kind: 'primary',
      busyKey: 'zapret_power',
      onClick: () => Lz.actions.toggleZapret(status),
    });
    const header = ui.pageHeader({
      title: 'Обход блокировок',
      actions: [pill.el, restartBtn.el, powerBtn.el],
    });
    const banner = ui.slot(renderBanner, { cls: 'page__banners' });

    const vpn = sections.createVpnSection();
    const strategy = sections.createStrategySection();
    const test = sections.createTestSection();
    const filters = sections.createFiltersSection();
    const lists = sections.createListsSection();
    const mode = sections.createModeSection();
    const advanced = sections.createAdvancedSection();
    const all = [vpn, strategy, test, filters, lists, mode, advanced];
    const anchors = {
      vpn: vpn.el, strategy: strategy.el, test: test.el, filters: filters.el, lists: lists.el, mode: mode.el, advanced: advanced.el,
    };

    const el = h('div', { class: 'page__inner' }, header.el, banner.el, all.map((section) => section.el));

    function update(state) {
      const zapret = state.zapret || {};
      const available = zapret.available !== false;
      status = zapret.status || 'stopped';
      pill.set(available ? status : 'locked');
      setText(header.subtitleEl, subtitle(zapret));
      const running = status === 'running' || status === 'starting';
      /* Во время подбора и «Найти и включить» обходом управляет ядро — оно отказало бы «Идёт подбор…». */
      const managed = Boolean((zapret.test && zapret.test.running) || (zapret.fix && zapret.fix.running));
      powerBtn.setLabel(running ? 'Выключить' : 'Включить');
      powerBtn.setDisabled(!available || status === 'stopping' || managed);
      restartBtn.setDisabled(!available || status !== 'running' || managed);
      const busyTitle = managed ? 'Идёт подбор стратегии — дождитесь окончания или остановите его' : null;
      powerBtn.el.title = busyTitle || '';
      restartBtn.el.title = busyTitle || '';
      banner.update({
        locked: !available,
        admin: Boolean(state.app && state.app.admin),
        reason: zapret.unavailable_reason || null,
        status,
        error: zapret.error || null,
      });
      for (const section of all) section.update(state);
    }

    function show(opts) {
      lists.show();
      const target = opts && opts.focus ? anchors[opts.focus] : null;
      if (!target) return;
      if (opts.focus === 'advanced') advanced.open();
      requestAnimationFrame(() => target.scrollIntoView({ block: 'start', behavior: Lz.nav.scrollBehavior() }));
    }

    return { el, update, show };
  }

  Lz.pages.zapret = { title: 'Обход', icon: 'route', create };
})(window.Lz);
