'use strict';
/* Приветствие при первом запуске: три коротких шага, затем finish_onboarding. */
(function (Lz) {
  const { h, icon, uid, setText, setHidden } = Lz.dom;
  const ui = Lz.ui;

  const STEP_COUNT = 3;
  const FEATURES = [
    { icon: 'route', title: 'Discord и YouTube', text: 'Обход замедления на базе zapret — включается одной кнопкой.' },
    { icon: 'send', title: 'Telegram', text: 'Локальный прокси, который ускоряет Telegram Desktop без VPN.' },
    { icon: 'download', title: 'Обновления — по вашей команде', text: 'Сообщаем о новых версиях, а ставим только когда вы нажмёте.' },
  ];

  let modal = null;
  /* Последний шаг показывает ход «Найти и включить», поэтому получает каждый снимок состояния. */
  let updateFinalStep = null;
  let finishedLocally = false;

  function welcomeStep(titleId) {
    return h('div', { class: 'onb__step' },
      Lz.brand.tile(52),
      h('h2', { class: 'onb__title', id: titleId, text: 'Добро пожаловать в Лазейку' }),
      h('p', { class: 'onb__text', text: 'Когда тормозят Discord, YouTube или Telegram, Лазейка находит обходной путь. Всё в одном окне и без настроек вслепую.' }),
      h('ul', { class: 'onb__features' }, FEATURES.map((feature) => h('li', { class: 'onb__feature' },
        icon(feature.icon, { size: 20 }),
        h('div', null,
          h('p', { class: 'onb__feature-title', text: feature.title }),
          h('p', { class: 'onb__feature-text', text: feature.text }))))));
  }

  function choicesStep(choices) {
    const updates = ui.switchRow({
      title: 'Сообщать об обновлениях',
      description: 'Только уведомление — без вас ничего не скачивается и не устанавливается.',
      checked: choices.check_updates,
      onChange: (value) => {
        choices.check_updates = value;
        return true;
      },
    });
    const autostart = ui.switchRow({
      title: 'Запускать вместе с Windows',
      description: 'Лазейка будет тихо стартовать в трее при входе в систему.',
      checked: choices.autostart,
      onChange: (value) => {
        choices.autostart = value;
        return true;
      },
    });
    return h('div', { class: 'onb__step' },
      h('h2', { class: 'onb__title', text: 'Пара настроек' }),
      h('p', { class: 'onb__text', text: 'Их всегда можно поменять в «Настройках».' }),
      h('div', { class: 'settings-list onb__settings' }, updates.el, autostart.el));
  }

  /** Текст задачи «Discord и YouTube»: что сделает кнопка — или почему её нет. */
  function zapretTaskText(state) {
    const zapret = state.zapret || {};
    if (!(state.app && state.app.admin)) {
      return 'Обходу нужны права администратора: без них драйвер WinDivert не видит трафик. Windows попросит подтверждение.';
    }
    if (zapret.available === false) return zapret.unavailable_reason || 'Обход сейчас недоступен.';
    return 'Лазейка проверит, открываются ли они, и, если нет, сама подберёт и включит рабочую стратегию.';
  }

  /**
   * Последний шаг: «Найти и включить» — единственное главное действие; ход подбора виден
   * прямо здесь. Без прав администратора вместо него — перезапуск с правами.
   */
  function finalStep(onPickStrategy) {
    const fix = Lz.fix.button();
    const relaunch = ui.actionButton({
      method: 'relaunch_admin',
      label: 'Перезапустить с правами администратора',
      icon: 'shieldCheck',
      kind: 'primary',
    });
    const zapretText = h('p', { class: 'onb__feature-text' });
    const progress = ui.slot(Lz.fix.render, { cls: 'onb__fix' });
    const pickLink = ui.button({
      label: 'Полный подбор',
      iconRight: 'arrowRight',
      kind: 'link',
      size: 'sm',
      title: 'Проверить все стратегии по очереди',
      onClick: () => onPickStrategy(),
    });
    const connect = ui.button({
      label: 'Подключить Telegram',
      icon: 'plug',
      onClick: (event, ctl) => Lz.actions.connectTelegram(ctl),
    });
    const el = h('div', { class: 'onb__step' },
      h('h2', { class: 'onb__title', text: 'Почти готово' }),
      h('div', { class: 'onb__task' },
        h('p', { class: 'onb__feature-title', text: 'Discord и YouTube' }),
        zapretText,
        fix.el,
        relaunch.el,
        progress.el,
        pickLink.el),
      h('div', { class: 'onb__task' },
        h('p', { class: 'onb__feature-title', text: 'Telegram' }),
        h('p', { class: 'onb__feature-text', text: 'Telegram Desktop откроется и предложит добавить прокси — нажмите «Подключиться».' }),
        connect.el));

    function update(state) {
      const zapret = state.zapret || {};
      const admin = Boolean(state.app && state.app.admin);
      setHidden(fix.el, !admin);
      setHidden(relaunch.el, admin);
      fix.set(Lz.fix.flags(zapret));
      setText(zapretText, zapretTaskText(state));
      progress.update(Lz.fix.view(zapret));
      setHidden(pickLink.el, !(admin && zapret.fix && !zapret.fix.running && zapret.fix.stage === 'failed'));
    }

    return { el, update };
  }

  /** Шаг, с которого открыть приветствие: ?onb=3 — сразу последний (для скриншотов и проверки). */
  function initialStep() {
    const requested = Number(Lz.params.get('onb'));
    return Number.isInteger(requested) && requested >= 1 && requested <= STEP_COUNT ? requested - 1 : 0;
  }

  function open(state) {
    const settings = state.settings || {};
    const choices = { check_updates: settings.check_updates !== false, autostart: Boolean(settings.autostart) };
    const titleId = uid('onb-title');
    let step = 0;

    const final = finalStep(() => finish({ then: () => Lz.nav.go('zapret', { focus: 'test' }) }));
    const steps = [
      welcomeStep(titleId),
      choicesStep(choices),
      final.el,
    ];
    const dots = h('div', { class: 'onb__dots', 'aria-hidden': 'true' },
      steps.map(() => h('span', { class: 'onb__dot' })));
    const stepLabel = h('span', { class: 'sr-only', 'aria-live': 'polite' });
    const back = ui.button({ label: 'Назад', kind: 'ghost', onClick: () => go(step - 1) });
    const next = ui.button({
      label: 'Дальше',
      kind: 'primary',
      busyKey: 'finish_onboarding',
      onClick: () => (step < STEP_COUNT - 1 ? go(step + 1) : finish()),
    });
    const skip = ui.button({ label: 'Пропустить', kind: 'ghost', size: 'sm', busyKey: 'finish_onboarding', onClick: () => finish() });

    const body = h('div', { class: 'onb' },
      h('div', { class: 'onb__skip' }, skip.el),
      h('div', { class: 'onb__steps' }, steps),
      h('footer', { class: 'onb__foot' }, dots, stepLabel, back.el, next.el));

    function go(index) {
      step = Math.max(0, Math.min(STEP_COUNT - 1, index));
      steps.forEach((node, i) => setHidden(node, i !== step));
      [...dots.children].forEach((dot, i) => dot.classList.toggle('is-on', i === step));
      setText(stepLabel, `Шаг ${step + 1} из ${STEP_COUNT}`);
      setHidden(back.el, step === 0);
      next.setLabel(step === STEP_COUNT - 1 ? 'Готово' : 'Дальше');
      const focusTarget = steps[step].querySelector('h2');
      if (focusTarget) {
        focusTarget.tabIndex = -1;
        focusTarget.focus({ preventScroll: true });
      }
    }

    async function finish(opts) {
      const result = await Lz.api.run({
        method: 'finish_onboarding',
        args: [{ check_updates: choices.check_updates, autostart: choices.autostart }],
      });
      if (!result || !result.ok) return;
      finishedLocally = true;
      close();
      if (opts && opts.then) opts.then();
    }

    modal = ui.openModal({ content: body, labelledBy: titleId, cls: 'modal--onboarding' });
    updateFinalStep = final.update;
    go(initialStep());
  }

  function close() {
    if (!modal) return;
    modal.close();
    modal = null;
    updateFinalStep = null;
  }

  /** Вызывается на каждом снимке состояния: открывает или закрывает приветствие и обновляет последний шаг. */
  function sync(state) {
    const wanted = Boolean(state.app && state.app.first_run) && !finishedLocally;
    if (wanted && !modal) open(state);
    else if (!wanted && modal) close();
    if (updateFinalStep) updateFinalStep(state);
  }

  Lz.onboarding = { sync };
})(window.Lz);
