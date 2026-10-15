'use strict';
/*
 * «Помощь» → «VPN»: как Лазейка уживается с VPN, что куда идёт сейчас и как пустить Discord
 * и YouTube мимо VPN в популярных программах (тексты инструкций — js/vpn-clients.js).
 */
(function (Lz) {
  const { h, uid, setText, setHidden } = Lz.dom;
  const ui = Lz.ui;
  const texts = Lz.texts;
  const { lead, note, actions } = Lz.helpPanels.parts;

  const GENERAL_ID = 'general';

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
    return texts.vpnClients.find((client) => client.id !== GENERAL_ID && client.name.toLowerCase() === key) || null;
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
    if (!vpn.active) return { tone: 'off', text: 'VPN сейчас не обнаружен.' };
    if (vpn.mode === 'proxy') {
      return { tone: 'ok', text: `Сейчас работает ${Lz.vpn.proxyName(vpn)}${vpn.proxy ? ` (${vpn.proxy})` : ''}.` };
    }
    return { tone: 'ok', text: `Сейчас работает ${vpn.label || 'VPN'}.` };
  }

  function createVpnPanel() {
    const general = texts.vpnClients.find((client) => client.id === GENERAL_ID);
    const programs = texts.vpnClients.filter((client) => client.id !== GENERAL_ID);
    let pickedId = programs.length ? programs[0].id : null;
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
        setHidden(probeRow, !vpn.active);
        probe.setBusy(Boolean(vpn.routes && vpn.routes.running));
        routes.update(vpn.active ? Lz.vpn.routesData(state, 'view') : { checked: false });
        const candidates = Array.isArray(vpn.candidates) ? vpn.candidates.map(String) : [];
        detected.update({ candidates });
        syncPicker(candidates);
      },
    };
  }

  Object.assign(Lz.helpPanels, { createVpnPanel });
})(window.Lz);
