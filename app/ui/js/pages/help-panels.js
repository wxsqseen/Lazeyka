'use strict';
/*
 * «Помощь» → «Что не работает?»: общие кусочки панелей и простые панели — «Игра», «Telegram», «Сайт».
 * Панели Discord и YouTube (проверка и «Найти и включить») и сам выбор — в help-symptoms.js.
 */
(function (Lz) {
  const { h, icon, uid, setText, setHidden } = Lz.dom;
  const ui = Lz.ui;
  const fmt = Lz.fmt;
  const texts = Lz.texts;

  const VERDICT_VIEW = {
    works: { tone: 'ok', title: (domain) => `${domain} открывается` },
    ru_ca: { tone: 'info', title: (domain) => `${domain} открывается с российским сертификатом` },
    dns: { tone: 'warn', title: (domain) => `Провайдер подменяет адрес ${domain}` },
    down: { tone: 'info', title: (domain) => `${domain} не отвечает` },
    unreachable: { tone: 'warn', title: (domain) => `${domain} не отвечает по адресу` },
    ip: { tone: 'warn', title: (domain) => `Провайдер закрыл адрес ${domain}` },
    dpi: { tone: 'warn', title: (domain) => `Провайдер режет ${domain} по имени` },
    freeze: { tone: 'warn', title: (domain) => `Соединение с ${domain} замирает` },
    cert: { tone: 'warn', title: (domain) => `Вместо ${domain} отвечает провайдер` },
    geo: { tone: 'warn', title: (domain) => `${domain} не пускает из России` },
    vpn_refused: { tone: 'warn', title: (domain) => `${domain} не пускает через VPN` },
    whitelist: { tone: 'warn', title: () => 'Интернет по белому списку' },
  };

  /** Кнопки рентгена: что сделать с сайтом. done — уже сделано (вместо кнопки — метка). */
  const FIX_VIEW = {
    add_site: { label: 'Добавить в «Мои сайты»', done: 'В «Моих сайтах»', method: 'lists_add_site', args: (d) => [d] },
    /* Подбор идёт фоном: итог — строкой под кнопками (state.zapret.groups.pick), метки «сделано» нет. */
    pick_site: { label: 'Подобрать обход для сайта', done: 'Подбираем…', method: 'zapret_pick', args: (d) => ['site', d], async: true },
    vpn_site: { label: 'Пускать через свой VPN', done: 'Через свой VPN', method: 'vpnclient_route_site', args: (d) => [d, 'proxy'] },
    direct_site: { label: 'Пускать мимо VPN', done: 'Мимо VPN', method: 'vpnclient_route_site', args: (d) => [d, 'direct'] },
  };

  /* ---------- Общие кусочки ---------- */

  function lead(text) {
    return h('p', { class: 'symptom__lead', text });
  }

  function note(text) {
    return h('p', { class: 'symptom__text', text });
  }

  function actions(...buttons) {
    return h('div', { class: 'symptom__actions' }, buttons.filter(Boolean));
  }

  function spinnerLine(text) {
    return h('p', { class: 'muted' }, h('span', { class: 'spinner spinner--inline', 'aria-hidden': 'true' }), text);
  }

  /** Ключ фокуса: после перестройки панели фокус вернётся на кнопку с тем же data-fk. */
  function withKey(el, key) {
    el.dataset.fk = key;
    return el;
  }

  /* ---------- Игра ---------- */

  function renderModes(data) {
    return [
      ui.chip({ icon: 'gamepad', text: texts.gameFilter(data.game).chip, tone: data.game !== 'disabled' ? 'accent' : null }),
      ui.chip({ icon: 'globe', text: texts.ipset(data.ipset).chip, tone: data.ipset !== 'none' ? 'accent' : null }),
    ];
  }

  function gameStatus(zapret) {
    if (zapret.available === false) return 'Обход сейчас не работает — значит, игре мешает не он.';
    if (zapret.status === 'running' || zapret.status === 'starting') return '';
    return 'Обход выключен — проверьте игру. Потом включите его снова: без него Discord и YouTube тормозят.';
  }

  function createGamePanel() {
    const stop = ui.button({
      label: 'Выключить обход на время проверки',
      icon: 'pause',
      busyKey: 'zapret_power',
      onClick: () => Lz.api.run({ method: 'zapret_stop', key: 'zapret_power', success: 'Обход выключен — зайдите в игру и проверьте' }),
    });
    const start = ui.button({
      label: 'Включить обход снова',
      icon: 'power',
      busyKey: 'zapret_power',
      onClick: () => Lz.actions.startZapret(),
    });
    const filters = ui.button({
      label: 'Открыть фильтры',
      iconRight: 'arrowRight',
      kind: 'ghost',
      onClick: () => Lz.nav.go('zapret', { focus: 'filters' }),
    });
    const modes = ui.slot(renderModes, { cls: 'chips' });
    const status = h('p', { class: 'symptom__text', hidden: true });
    const el = h('div', { class: 'symptom' },
      lead('Обход может мешать играм. Игровой фильтр пропускает через zapret порты игр, а список IP — трафик к целым подсетям; у некоторых игр от этого растёт пинг или рвётся соединение.'),
      modes.el,
      note('Выключите обход и зайдите в игру. Заработала — значит, дело в фильтрах: откройте их и выключите игровой фильтр или список IP.'),
      status,
      actions(stop.el, start.el, filters.el));

    return {
      el,
      update(state) {
        const zapret = state.zapret || {};
        const locked = zapret.available === false;
        const on = zapret.status === 'running' || zapret.status === 'starting';
        setHidden(stop.el, locked || !on);
        setHidden(start.el, locked || on);
        stop.setDisabled(zapret.status === 'starting');
        start.setDisabled(zapret.status === 'stopping');
        modes.update({
          game: zapret.game_filter ? zapret.game_filter.mode : 'disabled',
          ipset: zapret.ipset ? zapret.ipset.mode : 'none',
        });
        const text = gameStatus(zapret);
        setText(status, text);
        setHidden(status, !text);
      },
    };
  }

  /* ---------- Telegram ---------- */

  function createTelegramPanel() {
    const connText = h('span', { class: 'conn__text' });
    const conn = h('p', { class: 'conn', role: 'status' }, h('span', { class: 'conn__dot', 'aria-hidden': 'true' }), connText);
    const reconnect = ui.button({
      label: 'Подключить Telegram заново',
      icon: 'plug',
      kind: 'primary',
      onClick: (event, ctl) => Lz.actions.connectTelegram(ctl),
    });
    const test = ui.button({
      label: 'Проверить маршруты',
      icon: 'route',
      busyKey: 'tg_test',
      onClick: () => Lz.api.run({ method: 'tg_test' }),
    });
    const results = ui.slot((data) => (data.running || data.results.length ? Lz.telegramRoutes.renderResults(data) : null),
      { cls: 'test-results' });
    const el = h('div', { class: 'symptom' },
      conn,
      note('Не грузятся сообщения или медиа — подключите Telegram к прокси заново: Telegram Desktop откроется и предложит подключиться. «Проверить маршруты» покажет, какие пути до серверов Telegram открыты у провайдера.'),
      actions(reconnect.el, test.el),
      results.el);

    return {
      el,
      update(state) {
        const tg = state.tg || {};
        const line = texts.telegramConnection(tg);
        conn.dataset.tone = line.tone;
        setText(connText, line.text);
        const routes = tg.test || {};
        test.setBusy(Boolean(routes.running));
        results.update({
          running: Boolean(routes.running),
          results: Array.isArray(routes.results) ? routes.results : [],
          ago: fmt.relative(routes.at),
        });
      },
    };
  }

  /* ---------- Сайт ---------- */

  function renderSteps(steps) {
    if (!steps.length) return null;
    return h('ul', { class: 'checklist site-steps' }, steps.map((step) => {
      const state = step.ok === true ? 'is-ok' : step.ok === false ? 'is-fail' : 'is-skip';
      const glyph = step.ok === true ? 'checkCircle' : step.ok === false ? 'xCircle' : 'alertCircle';
      return h('li', { class: ['checklist__item', state] },
        h('span', { class: 'checklist__icon', 'aria-hidden': 'true' }, icon(glyph, { size: 18 })),
        h('span', { class: 'checklist__name', text: step.label }),
        h('span', { class: 'sr-only', text: step.ok === true ? 'в порядке' : step.ok === false ? 'не проходит' : 'не проверялось' }),
        step.detail ? h('span', { class: 'checklist__detail', text: step.detail }) : null);
    }));
  }

  function createSitePanel() {
    let result = null;
    let done = new Set();
    let pick = null;            // подбор обхода для сайта: state.zapret.groups.pick

    const inputId = uid('site');
    const input = ui.textInput({ id: inputId, placeholder: 'example.com', inputMode: 'url', maxLength: 253 });
    const checkBtn = ui.button({ label: 'Проверить', icon: 'search', busyKey: 'check_site', onClick: () => submit() });
    const field = ui.field({ label: 'Адрес сайта', control: h('div', { class: 'input-group site-form' }, input, checkBtn.el), inputId });
    const verdict = ui.slot(renderVerdict, { cls: 'site-verdict' });

    function renderVerdict(data) {
      if (!data) return null;
      if (data.checking) return spinnerLine(`Проверяем ${data.checking}…`);
      const view = VERDICT_VIEW[data.verdict] || { tone: 'info', title: (domain) => domain };
      const picking = Boolean(data.pick && data.pick.key === data.domain && data.pick.running);
      const buttons = data.fixes.filter((id) => FIX_VIEW[id] && !(id === 'pick_site' && picking)).map((id, index) => (data.done.includes(id)
        ? h('span', { class: 'tag tag--ok', text: FIX_VIEW[id].done })
        : withKey(ui.button({
          label: FIX_VIEW[id].label,
          kind: index === 0 ? 'primary' : 'secondary',
          size: 'sm',
          busyKey: `site-fix-${id}`,
          onClick: () => applyFix(id),
        }).el, `site-${id}`)));
      /* Кнопки — строкой под вердиктом: справа в плашке две кнопки сжимали текст до слова в строке. */
      const picked = data.pick && data.pick.key === data.domain && data.pick.message && data.pickAsked ? data.pick : null;
      return [
        ui.callout({ tone: view.tone, title: view.title(data.domain), text: data.advice }),
        buttons.length ? h('div', { class: 'site-fixes' }, buttons) : null,
        picked && picked.running ? spinnerLine(picked.message) : null,
        picked && !picked.running ? ui.callout({ tone: picked.found ? 'ok' : 'warn', title: picked.found ? 'Обход подобран' : 'Обход не подобрался', text: picked.message }) : null,
        renderSteps(data.steps),
      ];
    }

    function show() {
      verdict.update(result ? { ...result, done: [...done], pick, pickAsked: done.has('pick_site') } : null);
    }

    async function submit() {
      const value = input.value.trim();
      if (!value) {
        field.setError('Введите адрес сайта, например example.com');
        input.focus();
        return;
      }
      field.setError(null);
      verdict.update({ checking: value });
      const response = await Lz.api.run({ method: 'check_site', args: [value], key: 'check_site', silent: true });
      if (!response) return;
      if (!response.ok) {
        result = null;
        field.setError(response.error);
      } else {
        result = {
          domain: String(response.domain || value),
          verdict: String(response.verdict || ''),
          advice: String(response.advice || ''),
          steps: Array.isArray(response.steps) ? response.steps : [],
          fixes: Array.isArray(response.fixes) ? response.fixes : (response.can_add ? ['add_site'] : []),
        };
        done = new Set();
      }
      show();
    }

    async function applyFix(id) {
      if (!result) return;
      const domain = result.domain;
      const fix = FIX_VIEW[id];
      const response = await Lz.api.run({
        method: fix.method,
        args: fix.args(domain),
        key: `site-fix-${id}`,
        success: (reply) => reply.message || `${domain}: ${fix.done.toLowerCase()}`,
      });
      if (response && response.ok && result && result.domain === domain) {
        if (!fix.async) done.add(id);
        else done.add('pick_site');           // кнопку подбора не меняем на метку: итог покажет строка под ней
        show();
      }
    }

    input.addEventListener('keydown', (event) => {
      if (event.key !== 'Enter') return;
      event.preventDefault();
      submit();
    });
    input.addEventListener('input', () => field.setError(null));

    const el = h('div', { class: 'symptom' },
      lead('Проверим сайт по шагам — адрес, соединение, имя сайта, большие ответы, путь через свой VPN — и скажем, что именно его режет и что с этим сделать.'),
      field.el,
      verdict.el);
    return {
      el,
      update(state) {
        const groups = state.zapret && state.zapret.groups;
        const next = groups && groups.pick ? groups.pick : null;
        if (JSON.stringify(next) === JSON.stringify(pick)) return;
        pick = next;
        if (result) show();
      },
    };
  }

  Lz.helpPanels = {
    parts: { lead, note, actions, spinnerLine, withKey },
    createGamePanel,
    createTelegramPanel,
    createSitePanel,
  };
})(window.Lz);
