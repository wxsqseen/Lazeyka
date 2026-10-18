'use strict';
/*
 * «Помощь» → «Что не работает?»: выбор беды и панели Discord и YouTube — проверка доступности
 * и «Найти и включить». В каждой панели не больше двух действий. Остальные панели — в help-panels.js
 * и help-vpn.js (VPN рядом с обходом и «Свой VPN не подключается»).
 */
(function (Lz) {
  const { h, setHidden } = Lz.dom;
  const ui = Lz.ui;
  const fmt = Lz.fmt;
  const panels = Lz.helpPanels;
  const { lead, note, actions, spinnerLine, withKey } = panels.parts;

  /* При выборе Discord или YouTube проверяем доступность, только если прошлому результату больше минуты. */
  const CHECK_FRESH_SEC = 60;
  const SYMPTOMS = [
    { value: 'discord', label: 'Discord', icon: 'chat' },
    { value: 'youtube', label: 'YouTube', icon: 'video' },
    { value: 'game', label: 'Игра', icon: 'gamepad' },
    { value: 'telegram', label: 'Telegram', icon: 'send' },
    { value: 'site', label: 'Сайт', icon: 'globe' },
    { value: 'vpn', label: 'VPN', icon: 'shieldCheck', title: 'У меня включён VPN' },
    { value: 'vpnclient', label: 'Свой VPN', icon: 'vpn', title: 'Свой VPN не подключается' },
  ];
  const SERVICE_TEXT = {
    discord: {
      checking: 'Проверяем, открывается ли Discord…',
      unknown: 'Проверим, открывается ли Discord через обход.',
      off: 'Обход выключен — без него Discord может не открываться. «Найти и включить» включит обход, проверит Discord и при необходимости подберёт стратегию.',
      ok: 'Discord открывается. Если приложение всё равно висит на подключении или не грузит картинки — очистите его кэш.',
      fail: 'Discord не открывается. Лазейка подберёт стратегию, с которой он заработает, и сразу её включит.',
      after: 'Если Discord всё равно висит на подключении — очистите его кэш.',
    },
    youtube: {
      checking: 'Проверяем, открывается ли YouTube и грузится ли видео…',
      unknown: 'Проверим, открывается ли YouTube и грузится ли видео.',
      off: 'Обход выключен — без него YouTube обычно тормозит. «Найти и включить» включит обход, проверит YouTube и при необходимости подберёт стратегию.',
      ok: 'YouTube открывается, видео грузится. Если в браузере всё равно тормозит — обновите страницу с Ctrl+F5 или перезапустите браузер.',
      fail: 'YouTube не открывается или не грузит видео. Лазейка подберёт стратегию, с которой он заработает, и сразу её включит.',
      after: 'Если в браузере всё равно тормозит — обновите страницу с Ctrl+F5.',
    },
  };

  /* ---------- Discord и YouTube ---------- */

  function lockedCallout(data) {
    const relaunch = data.admin ? null : ui.actionButton({
      method: 'relaunch_admin',
      label: 'Перезапустить с правами администратора',
      icon: 'shieldCheck',
      kind: 'primary',
      size: 'sm',
    }).el;
    return ui.callout({ tone: 'warn', title: 'Обход недоступен', text: data.reason || 'Для обхода нужны права администратора.', actions: relaunch });
  }

  function fixButton(flags) {
    const btn = Lz.fix.button({ fk: 'symptom-fix' });
    btn.set(flags);
    return btn.el;
  }

  function checkButton(label) {
    return withKey(ui.button({
      label,
      icon: 'refresh',
      busyKey: 'zapret_check',
      onClick: () => Lz.api.run({ method: 'zapret_check' }),
    }).el, 'symptom-check');
  }

  function fullTestButton() {
    return withKey(ui.button({
      label: 'Полный подбор',
      iconRight: 'arrowRight',
      onClick: () => Lz.nav.go('zapret', { focus: 'test' }),
    }).el, 'symptom-test');
  }

  function clearCacheButton() {
    return withKey(ui.actionButton({
      method: 'discord_clear_cache',
      label: 'Очистить кэш Discord',
      icon: 'eraser',
      success: 'Кэш Discord очищен. Запустите Discord заново.',
      confirm: {
        title: 'Очистить кэш Discord?',
        text: 'Discord будет закрыт, а его кэш удалён — это помогает, если он завис на подключении или не грузит картинки. Аккаунт, сообщения и настройки останутся.',
        confirmLabel: 'Закрыть Discord и очистить',
        icon: 'eraser',
      },
    }).el, 'symptom-cache');
  }

  function checkResults(data) {
    return [
      Lz.fix.checkChips(data.results),
      data.checked ? h('p', { class: 'muted small', text: data.checked }) : null,
    ];
  }

  function renderService(service, data) {
    const text = SERVICE_TEXT[service];
    if (data.locked) return lockedCallout(data);
    if (data.fix && data.fix.running) return [Lz.fix.render(data.fix), actions(fixButton(data.fixFlags))];
    if (data.checking) return spinnerLine(text.checking);
    const cache = service === 'discord' ? clearCacheButton() : null;
    if (data.fix) {
      const outcome = Lz.fix.render(data.fix);
      if (data.fix.tone === 'ok') return [outcome, note(text.after), actions(checkButton('Проверить ещё раз'), cache)];
      return [outcome, actions(fullTestButton(), cache || checkButton('Проверить ещё раз'))];
    }
    if (data.ok === true) return [lead(text.ok), checkResults(data), actions(cache, checkButton('Проверить ещё раз'))];
    if (data.ok === false) {
      return [lead(text.fail), checkResults(data), actions(fixButton(data.fixFlags), cache || checkButton('Проверить ещё раз'))];
    }
    if (!data.on) return [lead(text.off), actions(fixButton(data.fixFlags), cache)];
    return [lead(text.unknown), actions(checkButton('Проверить'), cache)];
  }

  function serviceData(service, state) {
    const zapret = state.zapret || {};
    const check = zapret.check || {};
    const results = Array.isArray(check.results) ? check.results : [];
    const result = results.find((item) => item.id === service);
    return {
      locked: zapret.available === false,
      admin: Boolean(state.app && state.app.admin),
      reason: zapret.unavailable_reason || null,
      on: zapret.status === 'running' || zapret.status === 'starting',
      checking: Boolean(check.running),
      fix: Lz.fix.view(zapret),
      fixFlags: Lz.fix.flags(zapret),
      results,
      ok: result ? Boolean(result.ok) : null,
      checked: results.length ? Lz.fix.checkedLine(fmt.relative(check.at), Boolean(check.direct)) : '',
    };
  }

  /** Проверить доступность при выборе панели, если обход работает, а свежего результата нет. */
  function checkIfStale(state) {
    const zapret = state.zapret || {};
    const check = zapret.check || {};
    const fix = zapret.fix || {};
    if (zapret.available === false || zapret.status !== 'running' || check.running || fix.running) return;
    const lastAt = Math.max(Number(check.at) || 0, Lz.fix.isLatest(zapret) ? Number(fix.finished_at) || 0 : 0);
    if (lastAt && fmt.nowSeconds() - lastAt < CHECK_FRESH_SEC) return;
    Lz.api.run({ method: 'zapret_check' });
  }

  function createServicePanel(service) {
    const view = ui.slot((data) => renderService(service, data), { cls: 'symptom' });
    return {
      el: view.el,
      update: (state) => view.update(serviceData(service, state)),
      activate: checkIfStale,
    };
  }

  /* ---------- Выбор ---------- */

  /** options.initial — беда, выбранная заранее (?symptom=discord в адресе). */
  function createSymptoms(opts) {
    const options = opts || {};
    const byName = {
      discord: createServicePanel('discord'),
      youtube: createServicePanel('youtube'),
      game: panels.createGamePanel(),
      telegram: panels.createTelegramPanel(),
      site: panels.createSitePanel(),
      vpn: panels.createVpnPanel(),
      vpnclient: panels.createVpnClientPanel(),
    };
    let selected = null;
    let latest = null;
    let activationPending = false;

    const card = ui.card({ title: 'Что не работает?' });
    const chooser = ui.segmented({
      labelledBy: card.titleEl.id,
      value: null,
      options: SYMPTOMS,
      cls: 'symptoms',
      onChange: (value) => select(value),
    });
    const hint = h('p', { class: 'symptom-hint', text: 'Выберите, что не работает, — покажем, что проверить и как починить.' });
    for (const panel of Object.values(byName)) setHidden(panel.el, true);
    card.body.append(chooser.el, h('div', { class: 'symptom-area' }, hint, Object.values(byName).map((panel) => panel.el)));

    function refresh() {
      if (!selected || !latest) return;
      const panel = byName[selected];
      panel.update(latest);
      if (activationPending) {
        activationPending = false;
        if (panel.activate) panel.activate(latest);
      }
    }

    function select(value) {
      if (!Object.prototype.hasOwnProperty.call(byName, value)) return false;
      selected = value;
      chooser.set(value);
      setHidden(hint, true);
      for (const [name, panel] of Object.entries(byName)) setHidden(panel.el, name !== value);
      activationPending = true;
      refresh();
      return true;
    }

    if (options.initial) select(options.initial);

    return {
      el: card.el,
      update(state) {
        latest = state;
        refresh();
      },
      select,
    };
  }

  Lz.helpSections = Object.assign(Lz.helpSections || {}, { createSymptoms });
})(window.Lz);
