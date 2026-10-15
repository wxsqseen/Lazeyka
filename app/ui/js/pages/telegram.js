'use strict';
/* Страница «Telegram»: подключение, живая статистика, проверка маршрутов и настройки прокси. */
(function (Lz) {
  const { h, icon, setText, setHidden } = Lz.dom;
  const ui = Lz.ui;
  const fmt = Lz.fmt;
  const texts = Lz.texts;

  const MANUAL_PATH = ['Настройки', 'Продвинутые настройки', 'Тип соединения', 'Использовать собственный прокси', 'MTProto'];
  const ROUTES = [
    ['ws', 'WebSocket напрямую'],
    ['cf', 'Через Cloudflare'],
    ['h2', 'HTTP/2'],
    ['tcp_fallback', 'TCP напрямую'],
    ['bad', 'Отклонено'],
  ];

  /** Сервер, порт и ключ для ручной настройки берём из ссылки tg://proxy — так их видит Telegram. */
  function manualValues(tg, settings) {
    const link = String(tg.link || '');
    const query = link.includes('?') ? new URLSearchParams(link.slice(link.indexOf('?') + 1)) : new URLSearchParams();
    const secretFromSettings = settings && settings.secret ? `dd${settings.secret}` : '';
    return {
      server: query.get('server') || tg.host || '',
      port: query.get('port') || (tg.port != null ? String(tg.port) : ''),
      secret: query.get('secret') || secretFromSettings,
    };
  }

  function createConnectionCard() {
    const connect = ui.button({
      label: 'Подключить Telegram',
      kind: 'primary',
      onClick: (event, ctl) => Lz.actions.connectTelegram(ctl),
    });
    const copyLink = ui.button({
      label: 'Скопировать ссылку',
      busyKey: 'tg_copy_link',
      onClick: () => Lz.actions.copyLink(),
    });
    const copy = (value, label) => Lz.actions.copyText(value, label);
    const server = ui.copyField({ label: 'Сервер', onCopy: copy });
    const port = ui.copyField({ label: 'Порт', onCopy: copy });
    const secret = ui.copyField({ label: 'Ключ', secret: true, onCopy: copy });

    const path = h('ol', { class: 'crumbs', 'aria-label': 'Путь в настройках Telegram' },
      MANUAL_PATH.map((step) => h('li', { class: 'crumbs__item', text: step })));

    const connText = h('span', { class: 'conn__text' });
    const conn = h('p', { class: 'conn connect__status', role: 'status' },
      h('span', { class: 'conn__dot', 'aria-hidden': 'true' }), connText);

    const card = ui.card({ title: 'Подключение' });
    card.body.append(conn, h('div', { class: 'connect' },
      h('div', { class: 'connect__col' },
        h('h3', { class: 'connect__title' }, h('span', { class: 'step-badge', text: '1' }), 'Автоматически'),
        h('p', { class: 'connect__text', text: 'Нажмите — Telegram Desktop откроется и предложит добавить прокси. Останется нажать «Подключиться».' }),
        h('div', { class: 'connect__buttons' }, connect.el, copyLink.el)),
      h('div', { class: 'connect__col connect__col--manual' },
        h('h3', { class: 'connect__title' }, h('span', { class: 'step-badge step-badge--muted', text: '2' }), 'Или вручную'),
        path,
        h('div', { class: 'copy-list' }, server.el, port.el, secret.el))));

    return {
      el: card.el,
      update(state) {
        const tg = state.tg || {};
        const line = texts.telegramConnection(tg);
        conn.dataset.tone = line.tone;
        setText(connText, line.text);
        const values = manualValues(tg, state.tg_settings);
        server.set(values.server);
        port.set(values.port);
        secret.set(values.secret);
      },
    };
  }

  function createStatsCard() {
    const values = {
      active: h('span', { class: 'kpi__value num' }),
      total: h('span', { class: 'kpi__value num' }),
      upRate: h('span', { class: 'kpi__value num' }),
      downRate: h('span', { class: 'kpi__value num' }),
      up: h('span', { class: 'kpi__value num' }),
      down: h('span', { class: 'kpi__value num' }),
    };
    const kpi = (label, valueEl, mod) => h('div', { class: ['kpi', mod && `kpi--${mod}`] }, h('span', { class: 'kpi__label', text: label }), valueEl);
    const spark = ui.sparkline({ label: 'Скорость отдачи и загрузки за две минуты' });
    const routes = ui.slot((data) => ROUTES.map(([key, label]) => h('span', { class: ['route', key === 'bad' && data[key] > 0 && 'route--bad'] },
      h('span', { class: 'route__label', text: label }),
      h('span', { class: 'route__value num', text: fmt.integer(data[key] || 0) }))), { cls: 'routes' });
    const idleNote = h('p', { class: 'muted small', text: 'Прокси выключен — статистика появится, когда он заработает.' });

    const card = ui.card({ title: 'Сейчас' });
    card.body.append(
      h('div', { class: 'kpis' },
        kpi('Соединений', values.active),
        kpi('За сеанс', values.total),
        kpi('Отдача', values.upRate, 'up'),
        kpi('Загрузка', values.downRate, 'down'),
        kpi('Отправлено', values.up),
        kpi('Получено', values.down)),
      h('div', { class: 'spark-wrap spark-wrap--tall' }, spark.el),
      h('p', { class: 'routes__title', text: 'Как шли соединения' }),
      routes.el,
      idleNote);

    return {
      el: card.el,
      update(state) {
        const tg = state.tg || {};
        const stats = tg.stats || {};
        setText(values.active, fmt.integer(stats.active || 0));
        setText(values.total, fmt.integer(stats.total || 0));
        setText(values.upRate, fmt.rate(stats.up_rate || 0));
        setText(values.downRate, fmt.rate(stats.down_rate || 0));
        setText(values.up, fmt.bytes(stats.up || 0));
        setText(values.down, fmt.bytes(stats.down || 0));
        spark.update(tg.history);
        routes.update({
          ws: stats.ws, cf: stats.cf, h2: stats.h2, tcp_fallback: stats.tcp_fallback, bad: stats.bad,
        });
        const idle = tg.status !== 'running';
        card.el.classList.toggle('is-idle', idle);
        setHidden(idleNote, !idle);
      },
    };
  }

  function renderTestResults(data) {
    if (data.running) {
      return h('p', { class: 'muted' }, h('span', { class: 'spinner spinner--inline', 'aria-hidden': 'true' }), 'Проверяем маршруты до серверов Telegram…');
    }
    if (!data.results.length) {
      return ui.emptyState({
        icon: 'route',
        title: 'Проверка ещё не запускалась',
        text: 'Покажет, какие пути до Telegram открыты у вашего провайдера.',
      });
    }
    return [
      h('ul', { class: 'checklist' }, data.results.map((item) => h('li', { class: ['checklist__item', item.ok ? 'is-ok' : 'is-fail'] },
        h('span', { class: 'checklist__icon', 'aria-hidden': 'true' }, icon(item.ok ? 'checkCircle' : 'xCircle', { size: 18 })),
        h('span', { class: 'checklist__name', text: item.name }),
        h('span', { class: 'sr-only', text: item.ok ? 'работает' : 'не работает' }),
        item.detail ? h('span', { class: 'checklist__detail mono', text: item.detail }) : null))),
      data.ago ? h('p', { class: 'muted small', text: `Проверено ${data.ago}` }) : null,
    ];
  }

  function createTestCard() {
    const runBtn = ui.button({
      label: 'Проверить маршруты',
      icon: 'route',
      size: 'sm',
      busyKey: 'tg_test',
      onClick: () => Lz.api.run({ method: 'tg_test' }),
    });
    const results = ui.slot(renderTestResults, { cls: 'test-results' });
    const card = ui.card({ title: 'Проверка маршрутов' });
    card.body.append(
      h('div', { class: 'route-test__intro' },
        h('p', { class: 'route-test__text', text: 'Пробуем достучаться до Telegram всеми способами, которые умеет прокси.' }),
        runBtn.el),
      results.el);
    return {
      el: card.el,
      update(state) {
        const test = (state.tg && state.tg.test) || {};
        runBtn.setBusy(Boolean(test.running));
        results.update({
          running: Boolean(test.running),
          results: Array.isArray(test.results) ? test.results : [],
          ago: fmt.relative(test.at),
        });
      },
    };
  }

  function subtitle(tg) {
    const parts = ['Локальный MTProto-прокси через WebSocket'];
    if (tg.version) parts.push(`tg-ws-proxy ${tg.version}`);
    if (tg.core && texts.CORE_KIND[tg.core]) parts.push(texts.CORE_KIND[tg.core]);
    return parts.join(' · ');
  }

  function create() {
    let status = 'stopped';
    const pill = ui.statusPill();
    const restartBtn = ui.actionButton({ method: 'tg_restart', label: 'Перезапустить', icon: 'refresh', success: 'Прокси перезапущен' });
    const powerBtn = ui.button({
      label: 'Включить',
      icon: 'power',
      kind: 'primary',
      busyKey: 'tg_power',
      onClick: () => Lz.actions.toggleTelegram(status),
    });
    const header = ui.pageHeader({ title: 'Telegram', actions: [pill.el, restartBtn.el, powerBtn.el] });
    const banner = ui.slot((data) => (data.error
      ? ui.callout({ tone: 'err', title: 'Прокси не запустился', text: data.error, actions: ui.button({ label: 'Открыть журнал', size: 'sm', onClick: () => Lz.nav.go('logs') }).el })
      : null), { cls: 'page__banners' });

    const connection = createConnectionCard();
    const stats = createStatsCard();
    const test = createTestCard();
    const form = Lz.telegramForm.create();
    const sections = [connection, stats, test, form];

    const el = h('div', { class: 'page__inner' },
      header.el,
      banner.el,
      connection.el,
      h('div', { class: 'grid-2 grid-2--stretch' }, stats.el, test.el),
      form.el);

    return {
      el,
      update(state) {
        const tg = state.tg || {};
        status = tg.status || 'stopped';
        pill.set(status);
        setText(header.subtitleEl, subtitle(tg));
        const running = status === 'running' || status === 'starting';
        powerBtn.setLabel(running ? 'Выключить' : 'Включить');
        restartBtn.setDisabled(status !== 'running');
        banner.update({ error: status === 'error' ? (tg.error || 'Подробности — в журнале.') : null });
        for (const section of sections) section.update(state);
      },
    };
  }

  Lz.pages.telegram = { title: 'Telegram', icon: 'send', create };
  /* Список проверенных маршрутов нужен и «Помощи» — панели «Telegram». */
  Lz.telegramRoutes = { renderResults: renderTestResults };
})(window.Lz);
