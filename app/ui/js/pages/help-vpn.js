'use strict';
/*
 * «Помощь» → «VPN»: как Лазейка уживается с VPN, что куда идёт сейчас и как пустить Discord
 * и YouTube мимо VPN в популярных программах (тексты инструкций — js/vpn-clients.js).
 * «Помощь» → «Свой VPN»: почему не подключается свой VPN Лазейки и что с этим сделать.
 */
(function (Lz) {
  const { h, uid, setText, setHidden } = Lz.dom;
  const ui = Lz.ui;
  const texts = Lz.texts;
  const { lead, note, actions } = Lz.helpPanels.parts;

  const GENERAL_ID = 'general';
  const OWN_ID = 'lazeyka';

  function stepsList(steps) {
    return h('ol', { class: 'steps' }, steps.map((text, index) => h('li', { class: 'steps__item' },
      h('span', { class: 'step-badge', text: String(index + 1) }),
      h('span', { text }))));
  }

  function clientSteps(client) {
    return [
      client.steps && client.steps.length ? stepsList(client.steps) : null,
      client.note ? note(client.note) : null,
    ];
  }

  function clientByName(name) {
    const key = String(name || '').toLowerCase();
    return texts.vpnClients.find((client) => client.id !== GENERAL_ID && client.id !== OWN_ID
      && client.name.toLowerCase() === key) || null;
  }

  /** Программы, которые могут держать этот VPN (vpn.candidates), — с инструкциями для каждой. */
  function renderDetected(data) {
    const clients = data.candidates.map(clientByName).filter(Boolean);
    if (!clients.length) return null;
    const title = clients.length > 1
      ? `VPN держит одна из программ: ${clients.map((client) => client.name).join(', ')}. Инструкции для каждой:`
      : `VPN держит ${clients[0].name}. Как это сделать в ней:`;
    return [
      h('p', { class: 'symptom__text', text: title }),
      clients.map((client) => h('div', { class: 'vpn-client' },
        h('p', { class: 'vpn-client__name', text: client.name }),
        clientSteps(client))),
    ];
  }

  function vpnLine(vpn) {
    if (!vpn.active && Lz.vpn.ownActive(vpn)) return { tone: 'ok', text: 'Сейчас работает свой VPN Лазейки.' };
    if (!vpn.active) return { tone: 'off', text: 'VPN сейчас не обнаружен.' };
    if (vpn.mode === 'proxy') {
      return { tone: 'ok', text: `Сейчас работает ${Lz.vpn.proxyName(vpn)}${vpn.proxy ? ` (${vpn.proxy})` : ''}.` };
    }
    return { tone: 'ok', text: `Сейчас работает ${vpn.label || 'VPN'}.` };
  }

  function createVpnPanel() {
    const general = texts.vpnClients.find((client) => client.id === GENERAL_ID);
    const own = texts.vpnClients.find((client) => client.id === OWN_ID);
    const programs = texts.vpnClients.filter((client) => client.id !== GENERAL_ID);
    /* Свой VPN Лазейки показан отдельной плашкой выше — в списке по умолчанию первая чужая программа. */
    const firstForeign = programs.find((client) => client.id !== OWN_ID);
    let pickedId = firstForeign ? firstForeign.id : null;
    /* Пока человек сам не выбрал программу, список предлагает ту, что не показана выше. */
    let pickedByUser = false;
    let detectedIds = [];

    const connText = h('span', { class: 'conn__text' });
    const conn = h('p', { class: 'conn', role: 'status' }, h('span', { class: 'conn__dot', 'aria-hidden': 'true' }), connText);
    const probe = ui.button({
      label: 'Что куда идёт',
      icon: 'route',
      busyKey: 'vpn_probe',
      onClick: () => Lz.api.run({ method: 'vpn_probe' }),
    });
    const copyDomains = ui.button({
      label: 'Скопировать домены',
      icon: 'copy',
      busyKey: 'copy_text',
      onClick: () => Lz.actions.copyText(texts.VPN_BYPASS_DOMAINS.join('\n'), 'Домены'),
    });
    const probeRow = actions(probe.el);
    const routes = ui.slot((data) => (data.checked ? Lz.vpn.renderRoutes(data, null) : null), { cls: 'vpn-routes' });
    const detected = ui.slot(renderDetected, { cls: 'vpn-clients' });

    const pickerId = uid('vpn-program');
    const pickerLabel = h('label', { class: 'field__label', for: pickerId, text: 'Инструкция для программы' });
    const picked = h('div', { class: 'vpn-client' });
    const picker = ui.selectControl({
      id: pickerId,
      onChange: (id) => {
        pickedId = id;
        pickedByUser = true;
        showPicked();
        return true;
      },
    });
    picker.setOptions(programs.map((client) => ({ value: client.id, label: client.name })));
    picker.sync(pickedId);

    function showPicked() {
      const client = programs.find((item) => item.id === pickedId);
      picked.replaceChildren();
      if (client) Lz.dom.append(picked, [clientSteps(client)]);
    }
    showPicked();

    function syncPicker(candidates) {
      const ids = candidates.map(clientByName).filter(Boolean).map((client) => client.id);
      if (ids.join() === detectedIds.join()) return;
      detectedIds = ids;
      setText(pickerLabel, ids.length ? 'Другая программа' : 'Инструкция для программы');
      if (pickedByUser || !ids.includes(pickedId)) return;
      const other = programs.find((client) => !ids.includes(client.id));
      if (!other) return;
      pickedId = other.id;
      picker.sync(pickedId);
      showPicked();
    }

    const el = h('div', { class: 'symptom' },
      lead('Лазейка работает рядом с любым VPN: обход не трогает туннель VPN и соединения с его сервером.'),
      conn,
      note('Discord и YouTube, которые идут через VPN, обход не обрабатывает — им он и не нужен. Чтобы они шли через обход (быстрее и без нагрузки на VPN), пустите их мимо VPN: это называется раздельным туннелированием.'),
      probeRow,
      routes.el,
      h('div', { class: 'divider', 'aria-hidden': 'true' }),
      h('h3', { class: 'subsection__title', text: 'Как пустить Discord и YouTube мимо VPN' }),
      own ? ui.callout({ tone: 'ok', title: own.name, text: own.note }) : null,
      general ? clientSteps(general) : null,
      h('div', { class: 'chips' }, texts.VPN_BYPASS_DOMAINS.map((domain) => ui.chip({ text: domain }))),
      actions(copyDomains.el),
      detected.el,
      h('div', { class: 'vpn-picker' }, pickerLabel, picker.el),
      picked);

    return {
      el,
      update(state) {
        const vpn = state.vpn || {};
        const line = vpnLine(vpn);
        conn.dataset.tone = line.tone;
        setText(connText, line.text);
        const relevant = Lz.vpn.routesRelevant(vpn);
        setHidden(probeRow, !relevant);
        probe.setBusy(Boolean(vpn.routes && vpn.routes.running));
        routes.update(relevant ? Lz.vpn.routesData(state, 'view') : { checked: false });
        const candidates = Array.isArray(vpn.candidates) ? vpn.candidates.map(String) : [];
        detected.update({ candidates });
        syncPicker(candidates);
      },
    };
  }

  /* ---------- Свой VPN не подключается ---------- */

  /** «Самый быстрый» той группы или подписки, где выбранный сервер; null — выбирать не из чего. */
  function fastestId(vc) {
    const selected = vc.selected;
    if (!selected || !selected.id || String(selected.id).startsWith('auto:')) return null;
    const groups = Array.isArray(vc.groups) ? vc.groups : [];
    const group = groups.find((item) => Array.isArray(item.members) && item.members.map(String).includes(String(selected.id)));
    if (group) return `auto:${group.id}`;
    const servers = Array.isArray(vc.servers) ? vc.servers : [];
    const server = servers.find((item) => String(item.id) === String(selected.id));
    return server && server.sub ? `auto:${server.sub}` : null;
  }

  function vcButton(label, iconName, onClick, opts) {
    const options = opts || {};
    const btn = ui.button({ label, icon: iconName, kind: options.kind, busyKey: options.busyKey, onClick });
    btn.el.dataset.fk = `vc-help:${label}`;
    return btn.el;
  }

  function latencyButton() {
    return vcButton('Проверить задержку', 'pulse',
      () => Lz.api.run({ method: 'vpnclient_latency', args: [null], key: 'vpnclient_latency' }), { busyKey: 'vpnclient_latency' });
  }

  function fastestButton(id) {
    return id ? vcButton('Выбрать самый быстрый', 'zap', () => Lz.vpnclientGate.select(id), { kind: 'primary' }) : null;
  }

  /** Действия по причине ошибки (vpnclient.error_kind) — не больше двух, как во всех панелях. */
  function errorActions(data) {
    const go = (focus) => () => Lz.nav.go('vpnclient', { focus });
    const toProxy = () => Lz.api.run({
      method: 'vpnclient_set_mode',
      args: ['proxy'],
      key: 'vpnclient_set_mode',
      success: 'Режим «Системный прокси» выбран — включите VPN снова',
    });
    const updateSubs = () => Lz.api.run({ method: 'vpnclient_sub_update', args: [null], key: 'vpnclient_sub_update:all' });
    switch (data.kind) {
      case 'port':
        return [vcButton('Сменить порт', 'sliders', go('more'), { kind: 'primary' })];
      case 'admin':
      case 'conflict':
        return [vcButton('Включить как системный прокси', 'globe', toProxy, { kind: 'primary', busyKey: 'vpnclient_set_mode' })];
      case 'timeout':
        return [fastestButton(data.fastest), latencyButton()];
      case 'tls':
      case 'auth':
        return [vcButton('Обновить подписки', 'refresh', updateSubs, { kind: 'primary', busyKey: 'vpnclient_sub_update:all' })];
      case 'unsupported':
        return [vcButton('Выбрать другой сервер', 'server', go('servers'), { kind: 'primary' })];
      default:
        return [vcButton('Открыть журнал', 'list', () => Lz.nav.go('logs'))];
    }
  }

  function renderVpnClient(data) {
    if (!data.present) {
      return note('Ядро Лазейки этой версии не сообщает о своём VPN — обновите Лазейку на странице «Обновления».');
    }
    if (!data.hasServers) {
      return [
        lead('Своему VPN нужен сервер, а Лазейка серверы не продаёт и не раздаёт. Добавьте подписку вашего VPN на VLESS, VMess, Shadowsocks, Trojan, Hysteria2, TUIC, WireGuard или SOCKS.'),
        actions(vcButton('Добавить подписку', 'plus', () => Lz.nav.go('vpnclient', { focus: 'add' }), { kind: 'primary' })),
      ];
    }
    if (data.status === 'locked') return note('Свой VPN сейчас недоступен — причина написана выше.');
    if (data.status === 'error') {
      const kind = texts.vpncError(data.kind);
      return [
        ui.callout({ tone: 'err', title: kind.title, text: data.error || kind.title }),
        note(kind.advice),
        actions(...errorActions(data)),
      ];
    }
    if (data.status === 'running' && !data.verified) {
      return [
        lead('Ядро запущено, но выход через сервер ещё не подтверждён. Обычно проверка занимает пару секунд; если она идёт дольше минуты — сервер не пропускает трафик.'),
        actions(fastestButton(data.fastest), latencyButton()),
      ];
    }
    if (data.status === 'running') {
      return [
        lead('Свой VPN подключён, выход через сервер проверен. Если какой-то сайт всё равно не открывается — посмотрите, что куда идёт, и добавьте сайт в «Маршруты».'),
        actions(
          vcButton('Что куда идёт', 'route', () => Lz.api.run({ method: 'vpn_probe' }), { busyKey: 'vpn_probe' }),
          vcButton('Открыть маршруты', 'arrowRight', () => Lz.nav.go('vpnclient', { focus: 'routing' }))),
      ];
    }
    if (data.status === 'starting' || data.status === 'stopping') return lead('Подождите несколько секунд — свой VPN как раз переключается.');
    return [
      lead('Свой VPN выключен. Включите его — если не подключится, здесь появятся причина и что с ней сделать.'),
      actions(vcButton('Включить свой VPN', 'power', () => Lz.vpnclientGate.start(), { kind: 'primary', busyKey: Lz.vpnclientGate.POWER_KEY })),
    ];
  }

  /* Следы других VPN и своего после аварии (vpnclient_help): кнопки — методы ядра из item.fix. */
  const TRACE_FIX_LABEL = {
    vpnclient_proxy_fix: 'Исправить прокси',
    vpnclient_open_adapters: 'Открыть сетевые подключения',
  };
  const TRACE_TONE = { error: 'err', warn: 'warn', info: 'info' };
  const HELP_TIMEOUT_MS = 8000;
  const TRACES_FALLBACK = 'Следы других VPN — DNS адаптера в сети 198.18.0.0/15 без туннеля, системный прокси на мёртвый порт, '
    + 'оставшийся адаптер Lazeyka — найдёт «Проверка компьютера» внизу страницы.';

  function traceItem(item, onFixed) {
    const tone = TRACE_TONE[item.level] || 'info';
    const label = TRACE_FIX_LABEL[item.fix];
    const key = `${item.fix}:${item.id}`;
    const fix = label ? ui.button({
      label,
      icon: 'wrench',
      size: 'sm',
      kind: tone === 'err' ? 'primary' : 'secondary',
      busyKey: key,
      onClick: async () => {
        const result = await Lz.api.run({ method: String(item.fix), key, success: (reply) => reply.message || 'Готово' });
        if (result && result.ok) onFixed();
      },
    }) : null;
    if (fix) fix.el.dataset.fk = `trace:${item.id}`;
    return h('li', { class: `issue issue--${tone}` },
      h('span', { class: 'issue__icon', 'aria-hidden': 'true' }, Lz.dom.icon(tone === 'err' ? 'alertCircle' : 'alert', { size: 18 })),
      h('div', { class: 'issue__body' },
        h('p', { class: 'issue__title', text: item.title || item.id }),
        item.text ? h('p', { class: 'issue__text', text: item.text }) : null),
      fix && fix.el);
  }
  function createVpnClientPanel() {
    let tracesState = { loading: false, items: null, error: null };
    const connText = h('span', { class: 'conn__text' });
    const conn = h('p', { class: 'conn', role: 'status' }, h('span', { class: 'conn__dot', 'aria-hidden': 'true' }), connText);
    const body = ui.slot(renderVpnClient, { cls: 'symptom' });
    const routes = ui.slot((data) => (data.checked ? Lz.vpn.renderRoutes(data, null) : null), { cls: 'vpn-routes' });
    const traces = ui.slot((data) => {
      if (!data.supported) return note(TRACES_FALLBACK);
      if (data.loading && !data.items) return Lz.helpPanels.parts.spinnerLine('Ищем следы других VPN…');
      if (data.error) return note(`Следы других VPN проверить не удалось: ${data.error}`);
      if (!data.items) return null;
      if (!data.items.length) return h('p', { class: 'ok-line' }, Lz.dom.icon('checkCircle', { size: 18 }), 'Следов других VPN не нашлось: прокси и DNS адаптеров в порядке.');
      return h('ul', { class: 'issue-list' }, data.items.map((item) => traceItem(item, load)));
    }, { cls: 'vc-traces' });

    function render() {
      traces.update({ supported: Lz.api.hasMethod('vpnclient_help'), ...tracesState });
    }

    async function load() {
      if (!Lz.api.hasMethod('vpnclient_help') || tracesState.loading) {
        render();
        return;
      }
      tracesState = { ...tracesState, loading: true, error: null };
      render();
      try {
        const reply = await Lz.api.callWithTimeout('vpnclient_help', HELP_TIMEOUT_MS);
        if (reply && reply.ok === false) throw new Error(reply.error || 'ядро отказало');
        const items = reply && Array.isArray(reply.items) ? reply.items : [];
        tracesState = {
          loading: false,
          error: null,
          items: items.map((item) => ({
            id: String(item.id || ''),
            level: String(item.level || 'info'),
            title: item.title ? String(item.title) : '',
            text: item.text ? String(item.text) : '',
            fix: item.fix ? String(item.fix) : null,
          })),
        };
      } catch (err) {
        tracesState = { loading: false, items: null, error: Lz.api.describeError(err) };
      }
      render();
    }

    const el = h('div', { class: 'symptom' },
      conn,
      body.el,
      routes.el,
      h('h3', { class: 'subsection__title vc-traces__title', text: 'Следы других VPN' }),
      traces.el);
    render();
    return {
      el,
      /* Панель выбрали — проверяем прокси и DNS адаптеров заново (это дёшево и только чтение). */
      activate() {
        load();
      },
      update(state) {
        const vc = state.vpnclient || null;
        const source = vc || {};
        const line = texts.vpncLine(source);
        conn.dataset.tone = vc ? line.tone : 'off';
        setText(connText, vc ? line.text : 'Свой VPN недоступен в этой версии');
        /* При ошибке её текст — в плашке ниже: строка состояния его бы повторила. */
        setHidden(conn, Boolean(vc) && source.status === 'error');
        body.update({
          present: Boolean(vc),
          hasServers: texts.vpncHasServers(source),
          status: source.available === false ? 'locked' : (source.status || 'stopped'),
          verified: Boolean(source.verified),
          kind: source.error_kind || null,
          error: source.error ? String(source.error) : null,
          fastest: vc ? fastestId(source) : null,
        });
        routes.update(Lz.vpn.ownActive(state.vpn) ? Lz.vpn.routesData(state, 'view') : { checked: false });
      },
    };
  }

  Object.assign(Lz.helpPanels, { createVpnPanel, createVpnClientPanel });
})(window.Lz);
