'use strict';
/*
 * Обход: «Совместимость с VPN» — отдельный переключатель, строка состояния, «что куда идёт»,
 * а в «Подробнее» — адаптеры с поправками, «спрашивать при включении» и сброс ответов.
 */
(function (Lz) {
  const { h, setText, setHidden } = Lz.dom;
  const ui = Lz.ui;

  const OVERRIDE_OPTIONS = [
    { value: '', label: 'Автоматически' },
    { value: 'direct', label: 'Прямое подключение' },
    { value: 'tunnel', label: 'VPN — не трогать' },
  ];
  const KIND_TEXT = { tunnel: 'VPN — обход не трогает', direct: 'прямое — обход работает' };
  const ROLE_TEXT = { internet: 'через него идёт интернет', lan: 'локальная сеть', idle: 'простаивает' };

  /* ---------- Адаптеры ---------- */

  function adapterMeta(adapter) {
    return [
      adapter.description,
      KIND_TEXT[adapter.kind] || adapter.kind,
      adapter.reason,
      adapter.kind === 'tunnel' ? ROLE_TEXT[adapter.role] || adapter.role : null,
      adapter.up === false ? 'отключён' : null,
    ].filter(Boolean).join(' · ');
  }

  async function setOverride(id, kind) {
    const result = await Lz.api.run({ method: 'vpn_set_override', args: [id, kind || null], key: `vpn_set_override:${id}` });
    return Boolean(result && result.ok);
  }

  function adapterRow(adapter, data) {
    const name = String(adapter.name || adapter.id);
    /* Программу показываем, если имя адаптера её не называет: «wwan99 · Incy», но не «Radmin VPN · Radmin VPN». */
    const app = adapter.app && !name.toLowerCase().includes(String(adapter.app).toLowerCase()) ? String(adapter.app) : '';
    const select = ui.selectControl({
      label: `Как считать адаптер «${name}»`,
      cls: 'vpn-adapter__select',
      onChange: (value) => setOverride(adapter.id, value),
    });
    select.setOptions(OVERRIDE_OPTIONS);
    select.sync(data.overrides[adapter.id] || '');
    select.setDisabled(!data.admin);
    select.select.dataset.fk = `vpn-override:${adapter.id}`;
    return h('li', { class: 'vpn-adapter' },
      h('div', { class: 'vpn-adapter__text' },
        h('p', { class: 'vpn-adapter__name' }, name, app ? h('span', { class: 'vpn-adapter__app', text: ` · ${app}` }) : null),
        h('p', { class: 'vpn-adapter__meta', text: adapterMeta(adapter) })),
      select.el);
  }

  function renderAdapters(data) {
    if (!data.adapters.length) return h('p', { class: 'muted small', text: 'Сетевые адаптеры ещё не прочитаны.' });
    return h('ul', { class: 'vpn-adapters' }, data.adapters.map((adapter) => adapterRow(adapter, data)));
  }

  function createDetails() {
    const adapters = ui.slot(renderAdapters);
    const proxyValue = h('span', { class: 'kv__value mono' });
    const proxyRow = h('div', { class: 'kv vpn-proxy', hidden: true },
      h('span', { class: 'kv__key', text: 'Системный прокси VPN' }), proxyValue);
    const askRow = ui.switchRow({
      title: 'Спрашивать при включении',
      description: 'Если работает VPN, перед включением обхода или прокси Лазейка покажет, что куда пойдёт.',
      onChange: async (on) => {
        const result = await Lz.api.run({ method: 'vpn_set_ask', args: [on] });
        return Boolean(result && result.ok);
      },
    });
    const forget = ui.actionButton({
      method: 'vpn_forget',
      label: 'Снова спрашивать про все VPN',
      icon: 'undo',
      size: 'sm',
      success: (result) => result.message || 'Лазейка снова спросит при включении рядом с VPN.',
    });
    const content = h('div', { class: 'advanced' },
      proxyRow,
      h('div', { class: 'subsection' },
        h('h3', { class: 'subsection__title', text: 'Сетевые адаптеры' }),
        h('p', { class: 'subsection__text', text: 'Туннели VPN обход не трогает, прямые подключения — обходит. Если Лазейка ошиблась с адаптером, поправьте вручную.' }),
        adapters.el),
      h('div', { class: 'divider', 'aria-hidden': 'true' }),
      h('div', { class: 'settings-list' }, askRow.el),
      h('div', { class: 'subsection__foot' }, forget.el));
    const disclosure = ui.disclosure({ title: 'Подробнее', content });

    return {
      el: h('div', { class: 'card__disclosure' }, disclosure.el),
      update(state) {
        const vpn = state.vpn || {};
        setText(proxyValue, vpn.proxy || '');
        setHidden(proxyRow, !(vpn.mode === 'proxy' && vpn.proxy));
        adapters.update({
          adapters: Array.isArray(vpn.adapters) ? vpn.adapters : [],
          overrides: vpn.overrides && typeof vpn.overrides === 'object' ? vpn.overrides : {},
          admin: Boolean(state.app && state.app.admin),
        });
        askRow.sw.set(vpn.ask !== false);
      },
    };
  }

  /* ---------- Служба Windows ---------- */

  /**
   * Фильтр службы собирает Лазейка: без её автозапуска служба после перезагрузки не узнает,
   * что сетевые подключения поменялись. Подсказка — только когда это действительно так.
   */
  function renderServiceHint(show) {
    if (!show) return null;
    const enable = ui.button({
      label: 'Включить автозапуск',
      size: 'sm',
      busyKey: 'save_settings:autostart',
      onClick: () => Lz.api.run({
        method: 'save_settings',
        args: [{ autostart: true }],
        key: 'save_settings:autostart',
        success: 'Автозапуск Лазейки включён',
      }),
    }).el;
    return ui.callout({
      tone: 'info',
      text: 'Включите автозапуск Лазейки: после перезагрузки она проверит, не поменялись ли сетевые подключения, и обновит фильтр службы.',
      actions: enable,
    });
  }

  /* ---------- Карточка ---------- */

  async function setCompat(on) {
    const result = await Lz.api.run({
      method: 'vpn_set_compat',
      args: [on],
      success: (reply) => reply.message || (on ? 'Обход не будет трогать трафик VPN.' : 'Совместимость с VPN выключена.'),
    });
    return Boolean(result && result.ok);
  }

  function createVpnSection() {
    const compat = ui.switchRow({
      title: 'Не трогать трафик VPN',
      description: 'Обход перехватывает только прямые подключения — Ethernet, Wi-Fi, PPPoE, Hyper-V. Туннели VPN и соединения с сервером VPN он не трогает. Подходит для любого VPN.',
      onChange: (on) => setCompat(on),
    });
    const statusText = h('span', { class: 'conn__text' });
    const status = h('p', { class: 'conn', role: 'status' }, h('span', { class: 'conn__dot', 'aria-hidden': 'true' }), statusText);
    const probe = ui.button({
      label: 'Что куда идёт',
      icon: 'route',
      size: 'sm',
      busyKey: 'vpn_probe',
      onClick: () => Lz.api.run({ method: 'vpn_probe' }),
    });
    const routes = ui.slot((data) => (data.checked ? Lz.vpn.renderRoutes(data, () => Lz.nav.go('help', { symptom: 'vpn' })) : null),
      { cls: 'vpn-routes' });
    const serviceHint = ui.slot(renderServiceHint, { cls: 'vpn-service-hint' });
    const details = createDetails();

    const card = ui.card({ title: 'Совместимость с VPN' });
    card.body.append(compat.el, h('div', { class: 'vpn-state' }, status, probe.el), serviceHint.el, routes.el, details.el);

    return {
      el: card.el,
      update(state) {
        const vpn = state.vpn || {};
        const zapret = state.zapret || {};
        const settings = state.settings || {};
        compat.sw.set(vpn.compat !== false);
        compat.sw.setDisabled(!(state.app && state.app.admin));
        const line = Lz.vpn.compatStatus(vpn, zapret);
        status.dataset.tone = line.tone;
        setText(statusText, line.text);
        setHidden(probe.el, !vpn.active);
        probe.setBusy(Boolean(vpn.routes && vpn.routes.running));
        serviceHint.update(zapret.mode === 'service' && vpn.compat !== false && settings.autostart === false);
        routes.update(vpn.active ? Lz.vpn.routesData(state, 'view') : { checked: false });
        details.update(state);
      },
    };
  }

  Lz.zapretSections = Object.assign(Lz.zapretSections || {}, { createVpnSection });
})(window.Lz);
