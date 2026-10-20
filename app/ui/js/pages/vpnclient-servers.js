'use strict';
/*
 * Свой VPN → «Серверы»: подписки с трафиком и сроком, группы с «Самым быстрым» первой строкой,
 * серверы с задержкой цветом, поиск и сортировка. Выбор сервера на работающем VPN переключает
 * без перезапуска (решает ядро). Список перестраивается только при изменении своего среза данных.
 */
(function (Lz) {
  const { h, icon, setText } = Lz.dom;
  const ui = Lz.ui;
  const fmt = Lz.fmt;
  const texts = Lz.texts;
  const view = Lz.vcView;
  const dialogs = Lz.vcDialogs;
  const gate = Lz.vpnclientGate;

  const SORT_OPTIONS = [
    { value: 'none', label: 'Как в подписке' },
    { value: 'latency', label: 'По задержке' },
    { value: 'name', label: 'По имени' },
  ];
  const AUTO_PREFIX = 'auto:';
  const MIN_SERVERS_FOR_AUTO = 2;
  const nameCollator = new Intl.Collator('ru', { sensitivity: 'base', numeric: true });

  /* ---------- Подготовка данных ---------- */

  function latencyKey(row) {
    if (!row.supported) return Number.MAX_SAFE_INTEGER;
    const ms = Number(row.latency && row.latency.ms);
    if (row.latency && row.latency.error) return Number.MAX_SAFE_INTEGER - 1;
    return Number.isFinite(ms) && ms > 0 ? ms : Number.MAX_SAFE_INTEGER - 2;
  }

  function sortRows(rows, mode) {
    if (mode === 'latency') return rows.slice().sort((a, b) => latencyKey(a) - latencyKey(b));
    if (mode === 'name') return rows.slice().sort((a, b) => nameCollator.compare(a.name, b.name));
    return rows;
  }

  function matches(row, query) {
    if (!query) return true;
    const haystack = [row.name, row.country, texts.countryName(row.country), row.proto, row.description]
      .filter(Boolean).join(' ').toLowerCase();
    return haystack.includes(query);
  }

  function serverRow(server, ctx) {
    const id = String(server.id);
    return {
      id,
      name: String(server.name || 'Без названия'),
      country: server.country || null,
      proto: texts.vpncProto(server),
      engine: server.engine || null,
      supported: server.supported !== false,
      reason: server.reason ? String(server.reason) : null,
      description: server.description ? String(server.description) : null,
      latency: server.latency || null,
      speed: view.speedText(server.speed),
      selected: id === ctx.selectedId,
      actual: id === ctx.actualId,
      pending: id === ctx.pendingId,
      sub: server.sub || null,
      /* В конфиге работающего VPN (выбранный и до 15 серверов его подписки): тест скорости — только через них. */
      inConfig: Boolean(ctx.configIds && ctx.configIds.has(id)),
      /* Что ядро проигнорирует в ссылке — человеческими словами (texts.vpncWarning). */
      warnings: (Array.isArray(server.warnings) ? server.warnings : []).map((code) => texts.vpncWarning(code)).filter(Boolean),
    };
  }

  /** «Самый быстрый» группы или подписки: сейчас выбран — кто внутри, иначе — лучший по задержке. */
  function autoRow(id, rows, ctx) {
    const supported = rows.filter((row) => row.supported);
    const timed = supported.filter((row) => Number(row.latency && row.latency.ms) > 0 && !(row.latency && row.latency.error));
    const best = timed.length ? timed.reduce((a, b) => (Number(a.latency.ms) <= Number(b.latency.ms) ? a : b)) : null;
    const selected = id === ctx.selectedId;
    let meta = 'Лазейка сама выберет сервер с наименьшей задержкой и переключится, если он перестанет отвечать';
    if (selected && ctx.actualName) meta = `Сейчас — ${ctx.actualName}. Переключится сам, если сервер перестанет отвечать`;
    else if (best) meta = `Лучший сейчас — ${best.name}`;
    return {
      id,
      auto: true,
      name: 'Самый быстрый',
      meta,
      latency: best ? best.latency : null,
      selected,
      pending: id === ctx.pendingId,
      count: supported.length,
    };
  }

  function subView(sub) {
    const usage = view.usage(sub);
    const meta = [fmt.count(Number(sub.servers) || 0, 'сервер', 'сервера', 'серверов')];
    if (texts.VPNC_FORMAT[sub.format]) meta.push(texts.VPNC_FORMAT[sub.format]);
    if (sub.updated_at) meta.push(`обновлена ${fmt.relative(sub.updated_at)}`);
    if (sub.ua_preset && sub.ua_preset !== 'lazeyka' && texts.VPNC_UA_NAME[sub.ua_preset]) meta.push(`UA: ${texts.VPNC_UA_NAME[sub.ua_preset]}`);
    if (sub.hwid) meta.push('HWID');
    const probe = sub.probe && typeof sub.probe === 'object' ? sub.probe : null;
    return {
      id: String(sub.id),
      name: String(sub.name || 'Подписка'),
      meta: meta.join(' · '),
      format: sub.format || null,
      updating: Boolean(sub.updating),
      error: sub.error ? String(sub.error) : null,
      announce: sub.announce ? String(sub.announce) : null,
      description: sub.description ? String(sub.description) : null,
      support: providerLink(sub.support_url, 'support'),
      page: providerLink(sub.web_page_url, 'page'),
      usage: usage.hasLimits ? {
        /* До десятой доли процента: иначе растущий трафик перестраивал бы список каждую секунду. */
        share: usage.share == null ? null : Math.round(usage.share * 1000) / 1000,
        traffic: usage.trafficText,
        expire: usage.expireText,
        refill: usage.refillText,
        tone: usage.tone,
      } : null,
      warnings: usage.warnings,
      probe: probe ? { running: Boolean(probe.running), text: probe.text ? String(probe.text) : '', ua: probe.ua_preset || null } : null,
      raw: {
        id: sub.id, name: sub.name, ua_preset: sub.ua_preset, user_agent: sub.user_agent, hwid: sub.hwid,
        update_hours: sub.update_hours, dns: sub.dns, mtu: sub.mtu, provider_routes: sub.provider_routes,
      },
    };
  }

  /** Срез для слота: подписки → группы и остальные серверы, ручные серверы — отдельным разделом. */
  function listData(snap, local) {
    const vc = snap.vc;
    const selected = vc.selected || null;
    const ctx = {
      selectedId: selected ? String(selected.id) : null,
      actualId: selected && selected.actual ? String(selected.actual.id) : null,
      actualName: selected && selected.actual ? String(selected.actual.name || '') : '',
      pendingId: local.pendingId,
      configIds: vc.status === 'running' ? view.configServerIds(vc) : null,
    };
    const query = local.query;
    const sort = local.sort;
    const rowsById = new Map(snap.servers.map((server) => [String(server.id), serverRow(server, ctx)]));
    const grouped = new Set();
    const sections = [];
    let shown = 0;

    function pack(rows) {
      const filtered = sortRows(rows.filter((row) => matches(row, query)), sort);
      shown += filtered.length;
      return filtered;
    }

    for (const sub of snap.subscriptions) {
      const subId = String(sub.id);
      const groups = snap.groups.filter((group) => String(group.sub) === subId).map((group) => {
        const members = (Array.isArray(group.members) ? group.members : []).map((id) => rowsById.get(String(id))).filter(Boolean);
        members.forEach((row) => grouped.add(row.id));
        const rows = pack(members);
        const auto = members.length >= MIN_SERVERS_FOR_AUTO ? autoRow(`${AUTO_PREFIX}${group.id}`, members, ctx) : null;
        return { id: String(group.id), name: String(group.name || 'Группа'), count: members.length, auto: query ? null : auto, rows };
      });
      const restAll = snap.servers.filter((server) => String(server.sub) === subId && !grouped.has(String(server.id)))
        .map((server) => rowsById.get(String(server.id)));
      const subAuto = !groups.length && restAll.length >= MIN_SERVERS_FOR_AUTO && !query
        ? autoRow(`${AUTO_PREFIX}${subId}`, restAll, ctx) : null;
      sections.push({
        kind: 'sub',
        sub: subView(sub),
        groups: groups.filter((group) => group.rows.length || group.auto),
        rest: pack(restAll),
        restTitle: groups.length ? 'Другие серверы' : null,
        auto: subAuto,
      });
    }

    const manual = snap.servers.filter((server) => !server.sub || !snap.subscriptions.some((sub) => String(sub.id) === String(server.sub)))
      .map((server) => rowsById.get(String(server.id)));
    if (manual.length) sections.push({ kind: 'manual', rows: pack(manual), total: manual.length });

    return {
      sections,
      query,
      shown,
      total: snap.servers.length,
      running: vc.status === 'running',
      subHours: Number(snap.settings.sub_update_hours) || null,
    };
  }

  /* ---------- Действия ---------- */

  const FOCUS_WAIT_SNAPSHOTS = 10;

  /**
   * Удалённая строка уносит с собой и фокус (кнопку «⋯»). Когда список перестроится без неё, фокус — на первую
   * из оставшихся кнопок candidates (ключи data-fk). Ждём перерисовку по снимкам состояния, а не по часам, и
   * не трогаем фокус, если человек уже перевёл его сам.
   */
  function keepFocusAfterRemoval(goneFk, candidates) {
    let seen = 0;
    let unsubscribe = null;
    let finished = false;
    const finish = () => {
      finished = true;
      if (unsubscribe) unsubscribe();
    };
    unsubscribe = Lz.store.subscribe(() => {
      if (finished) return;
      seen += 1;
      if (Lz.dom.byFk(goneFk)) {
        if (seen >= FOCUS_WAIT_SNAPSHOTS) finish();
        return;
      }
      const active = document.activeElement;
      if (!active || active === document.body || !active.isConnected) {
        const target = candidates.map((key) => Lz.dom.byFk(key)).find((node) => node && node.offsetParent !== null);
        if (target) target.focus({ preventScroll: false });
      }
      finish();
    });
    if (finished) unsubscribe();
  }

  /** Соседняя строка списка (следующая, иначе предыдущая) — её кнопка выбора. */
  function neighbourFk(fk, selector) {
    const node = Lz.dom.byFk(fk);
    const item = node && node.closest(selector);
    const next = item && (item.nextElementSibling || item.previousElementSibling);
    const pick = next && next.querySelector('[data-fk]');
    return pick ? pick.dataset.fk : null;
  }

  function confirmRemoveServer(row) {
    const fromSub = Boolean(row.sub);
    return ui.confirm({
      title: `Удалить сервер ${fmt.quote(row.name)}?`,
      text: fromSub
        ? 'Сервер пропадёт из списка. Если провайдер оставит его в подписке, он вернётся при следующем обновлении.'
        : 'Сервер будет удалён из Лазейки. Чтобы вернуть его, понадобится ссылка.',
      confirmLabel: 'Удалить',
      tone: 'danger',
      icon: 'trash',
    });
  }

  async function removeServer(row) {
    if (!(await confirmRemoveServer(row))) return;
    const goneFk = `server:${row.id}`;
    const near = neighbourFk(goneFk, '.vc-server');
    const result = await Lz.api.run({ method: 'vpnclient_server_remove', args: [row.id], key: `vpnclient_server_remove:${row.id}`, success: 'Сервер удалён' });
    if (result && result.ok) keepFocusAfterRemoval(goneFk, [near, 'servers-search', 'vc-add-field'].filter(Boolean));
  }

  async function removeSub(sub) {
    const confirmed = await ui.confirm({
      title: `Удалить подписку ${fmt.quote(sub.name)}?`,
      text: 'Пропадут её серверы, группы и свои имена серверов. Если VPN подключён через неё, он выключится. Вернуть подписку можно, добавив ссылку заново.',
      confirmLabel: 'Удалить подписку',
      tone: 'danger',
      icon: 'trash',
    });
    if (!confirmed) return;
    const goneFk = `sub-update:${sub.id}`;
    const near = neighbourFk(`sub-section:${sub.id}`, '.vc-sub-wrap');
    const result = await Lz.api.run({ method: 'vpnclient_sub_remove', args: [sub.id], key: `vpnclient_sub_remove:${sub.id}`, success: 'Подписка удалена' });
    if (result && result.ok) keepFocusAfterRemoval(goneFk, [near, 'servers-search', 'vc-add-field'].filter(Boolean));
  }

  function speedtest(id) {
    return Lz.api.run({ method: 'vpnclient_speedtest', args: [id], key: 'vpnclient_speedtest' });
  }

  function latency(ids) {
    return Lz.api.run({ method: 'vpnclient_latency', args: [ids], key: 'vpnclient_latency' });
  }

  /* ---------- Отрисовка ---------- */

  /** Тест скорости меряет через включённый VPN и только серверы его конфига (выбранный и до 15 из его подписки). */
  function speedItem(row, data) {
    let label = 'Тест скорости';
    let title = null;
    if (!data.running) label = 'Тест скорости — включите VPN';
    else if (!row.inConfig) {
      label = 'Тест скорости — сначала выберите этот сервер';
      title = 'Этого сервера нет в текущем подключении: в него входят выбранный сервер и до 15 других из его подписки. Выберите этот сервер — тогда скорость можно будет измерить.';
    }
    return {
      label,
      title,
      icon: 'gauge',
      disabled: !row.supported || !data.running || !row.inConfig,
      onSelect: () => speedtest(row.id),
    };
  }

  function rowMenu(row, data) {
    return ui.menuButton({
      ariaLabel: `Действия с сервером ${fmt.quote(row.name)}`,
      title: 'Действия',
      fk: `server-menu:${row.id}`,
      items: () => [
        { label: 'Переименовать', icon: 'edit', onSelect: () => dialogs.renameServer(row) },
        {
          label: 'Скопировать ссылку',
          icon: 'copy',
          onSelect: () => Lz.api.run({
            method: 'vpnclient_copy_link',
            args: [row.id],
            key: `vpnclient_copy_link:${row.id}`,
            success: 'Ссылка сервера скопирована. В ней ключ доступа — не публикуйте её.',
          }),
        },
        { label: 'QR-код для телефона или ТВ', icon: 'qr', onSelect: () => dialogs.showQr({ id: row.id, title: row.name }) },
        { label: 'Проверить задержку', icon: 'pulse', disabled: !row.supported, onSelect: () => latency([row.id]) },
        speedItem(row, data),
        { label: 'Удалить', icon: 'trash', tone: 'danger', onSelect: () => removeServer(row) },
      ],
    }).el;
  }

  function pickServer(row, onPick) {
    if (row.selected || row.pending || row.supported === false) return;
    onPick(row.id);
  }

  function markEl(row) {
    return h('span', { class: 'vc-server__mark', 'aria-hidden': 'true' }, row.pending ? h('span', { class: 'spinner' }) : null);
  }

  function serverItem(row, data, onPick) {
    let metaText = row.proto;
    let title = null;
    if (!row.supported) {
      metaText = `не поддерживается: ${row.reason || 'ни одно ядро не умеет этот сервер'}`;
      title = metaText;
    } else if (row.engine === 'xray') {
      /* Причину («через помощник Xray: XHTTP») — в подсказку: транспорт уже назван в подписи протокола. */
      metaText = `${row.proto} · через помощник Xray`;
      title = row.reason || null;
    }
    const pick = h('button', {
      type: 'button',
      class: 'vc-server__pick',
      'aria-pressed': String(row.selected),
      'aria-disabled': String(!row.supported),
      title,
      dataset: { fk: `server:${row.id}` },
    },
    markEl(row),
    view.flag(row.country),
    h('span', { class: 'vc-server__text' },
      h('span', { class: 'vc-server__name' },
        /* Длинное имя обрезается многоточием — целиком оно во всплывающей подсказке. */
        h('span', { class: 'vc-server__label', text: row.name, title: row.name }),
        row.actual ? h('span', { class: 'vc-tag', text: 'сейчас' }) : null),
      h('span', { class: ['vc-server__meta', !row.supported && 'is-unsupported', row.engine === 'xray' && 'is-xray'], text: metaText }),
      /* «Нет ответа»: чья сторона и коротко почему; полный текст и что сделать — в подсказке. */
      row.supported ? view.reasonEl(row.latency, 'vc-server__why') : null,
      row.supported && row.warnings.length ? h('span', {
        class: 'vc-server__warn',
        title: `Ядро не учтёт:\n${row.warnings.join('\n')}`,
        text: `Не учтено: ${row.warnings[0]}${row.warnings.length > 1 ? ` и ещё ${row.warnings.length - 1}` : ''}`,
      }) : null,
      row.description ? h('span', { class: 'vc-server__desc', text: row.description }) : null),
    row.speed ? h('span', { class: 'vc-server__speed num', title: 'Скорость по последнему тесту', text: row.speed }) : null,
    row.supported ? view.latencyEl(row.latency, 'vc-server__latency') : h('span', { class: 'vc-server__latency' }));
    pick.addEventListener('click', () => pickServer(row, onPick));
    return h('li', {
      class: ['vc-server', row.selected && 'is-selected', !row.supported && 'is-unsupported', row.pending && 'is-pending'],
    }, pick, rowMenu(row, data));
  }

  function autoItem(row, onPick) {
    const pick = h('button', {
      type: 'button',
      class: 'vc-server__pick',
      'aria-pressed': String(row.selected),
      dataset: { fk: `server:${row.id}` },
    },
    markEl(row),
    view.flag(null, { auto: true }),
    h('span', { class: 'vc-server__text' },
      h('span', { class: 'vc-server__name' }, h('span', { class: 'vc-server__label', text: row.name })),
      h('span', { class: 'vc-server__meta', text: row.meta })),
    view.latencyEl(row.latency, 'vc-server__latency'));
    pick.addEventListener('click', () => pickServer(row, onPick));
    return h('li', { class: ['vc-server', 'vc-server--auto', row.selected && 'is-selected', row.pending && 'is-pending'] },
      pick, h('span', { class: 'vc-server__menu-gap', 'aria-hidden': 'true' }));
  }

  function serverList(rows, auto, data, onPick) {
    const items = [];
    if (auto) items.push(autoItem(auto, onPick));
    for (const row of rows) items.push(serverItem(row, data, onPick));
    return h('ul', { class: 'vc-servers' }, items);
  }

  /** Ссылка провайдера: https-адрес или «hidden:вид» — в адресе секрет подписки, его открывает ядро по id. */
  function providerLink(value, kind) {
    if (value === 'hidden') return `hidden:${kind}`;
    return typeof value === 'string' && value.startsWith('https://') ? value : null;
  }

  /** role — ключ фокуса кнопки («support», «page», «renew»): список перестраивается, фокус остаётся на ней. */
  function linkButton(label, url, subId, role) {
    const hidden = url.startsWith('hidden:');
    const btn = ui.button({
      label,
      iconRight: 'external',
      kind: 'link',
      size: 'sm',
      busyKey: 'open_url',
      onClick: () => (hidden
        ? Lz.api.run({ method: 'vpnclient_open_link', args: [subId, url.slice('hidden:'.length)], key: 'open_url' })
        : Lz.actions.openUrl(url)),
    }).el;
    btn.dataset.fk = `sub-link:${subId}:${role}`;
    return btn;
  }

  function renderUsage(sub) {
    if (!sub.usage) return null;
    /* Без лимита трафика полоски нет: пустая шкала «из ∞» только путает. */
    let bar = null;
    if (sub.usage.share != null) {
      bar = ui.progressBar({ label: `Трафик подписки ${fmt.quote(sub.name)}` });
      bar.set(sub.usage.share);
      bar.el.classList.toggle('is-warn', sub.usage.tone === 'warn');
      bar.el.classList.toggle('is-err', sub.usage.tone === 'err');
    }
    return h('div', { class: 'vc-usage' },
      h('div', { class: 'vc-usage__row' },
        h('span', { class: 'vc-usage__traffic num', text: sub.usage.traffic }),
        h('span', { class: 'vc-usage__expire', text: [sub.usage.expire, sub.usage.refill].filter(Boolean).join(' · ') })),
      bar && bar.el);
  }

  /** Срок и трафик на исходе — одна плашка с кнопкой «Продлить», если провайдер дал страницу подписки. */
  function renderWarnings(sub) {
    if (!sub.warnings.length) return null;
    const tone = sub.warnings.some((warning) => warning.tone === 'err') ? 'err' : 'warn';
    const renewUrl = sub.page || sub.support;
    return ui.callout({
      tone,
      text: sub.warnings.map((warning) => warning.text).join(' '),
      actions: renewUrl ? linkButton('Продлить', renewUrl, sub.id, 'renew') : null,
    });
  }

  /* Ключ фокуса проверки формата: «Проверить…», пока она идёт, и «Переключить на…» по её итогу — одна кнопка. */
  const probeKey = (sub) => `sub-probe:${sub.id}`;

  /** Нашёлся формат богаче — «Переключить на…»; иначе кнопка проверки остаётся в ссылках подписки. */
  function switchFound(sub) {
    return Boolean(sub.probe && !sub.probe.running && sub.probe.ua);
  }

  function renderProbe(sub) {
    if (!sub.probe) return null;
    if (sub.probe.running) {
      return h('p', { class: 'vc-sub__note muted' }, h('span', { class: 'spinner spinner--inline', 'aria-hidden': 'true' }),
        'Проверяем, отдаёт ли панель расширенный формат другим клиентам…');
    }
    const action = switchFound(sub) ? ui.button({
      label: `Переключить на ${texts.VPNC_UA_NAME[sub.probe.ua] || sub.probe.ua}`,
      size: 'sm',
      busyKey: `vpnclient_sub_set:${sub.id}`,
      onClick: async () => {
        const saved = await Lz.api.run({ method: 'vpnclient_sub_set', args: [sub.id, { ua_preset: sub.probe.ua }], key: `vpnclient_sub_set:${sub.id}` });
        if (!saved || !saved.ok) return;
        /* Кнопка уйдёт вместе с проверкой — фокус на «Обновить» этой подписки: там виден ход. */
        const update = Lz.dom.byFk(`sub-update:${sub.id}`);
        if (update) update.focus({ preventScroll: true });
        Lz.api.run({ method: 'vpnclient_sub_update', args: [sub.id], key: `vpnclient_sub_update:${sub.id}`, success: 'Подписка обновляется в новом формате' });
      },
    }).el : null;
    if (action) action.dataset.fk = probeKey(sub);
    return ui.callout({ tone: 'info', text: sub.probe.text || 'Проверка завершена.', actions: action });
  }

  function subMenu(sub, ids) {
    return ui.menuButton({
      ariaLabel: `Действия с подпиской ${fmt.quote(sub.name)}`,
      title: 'Действия',
      fk: `sub-menu:${sub.id}`,
      items: () => [
        { label: 'Проверить задержку', icon: 'pulse', disabled: !ids.length, onSelect: () => latency(ids) },
        { label: 'QR-код подписки', icon: 'qr', onSelect: () => dialogs.showQr({ id: sub.id, title: sub.name }) },
        sub.format === 'links' ? {
          label: 'Проверить расширенный формат',
          icon: 'search',
          onSelect: () => Lz.api.run({ method: 'vpnclient_sub_probe', args: [sub.id], key: `vpnclient_sub_probe:${sub.id}` }),
        } : null,
        { label: 'Удалить подписку', icon: 'trash', tone: 'danger', onSelect: () => removeSub(sub) },
      ],
    }).el;
  }

  function renderSubSection(section, data, onPick) {
    const sub = section.sub;
    const refresh = ui.button({
      label: sub.updating ? 'Обновляем…' : 'Обновить',
      icon: 'refresh',
      size: 'sm',
      busyKey: `vpnclient_sub_update:${sub.id}`,
      onClick: () => Lz.api.run({ method: 'vpnclient_sub_update', args: [sub.id], key: `vpnclient_sub_update:${sub.id}` }),
    });
    refresh.setBusy(sub.updating);
    refresh.el.dataset.fk = `sub-update:${sub.id}`;
    const props = ui.button({ label: 'Свойства', icon: 'sliders', size: 'sm', kind: 'ghost', onClick: () => dialogs.subProperties(sub.raw, data.subHours) });
    props.el.dataset.fk = `sub-props:${sub.id}`;
    const ids = [...section.groups.flatMap((group) => group.rows), ...section.rest].map((row) => row.id);
    const links = [
      sub.support && linkButton('Поддержка', sub.support, sub.id, 'support'),
      sub.page && linkButton('Страница подписки', sub.page, sub.id, 'page'),
    ].filter(Boolean);
    /* Кнопка не пропадает, пока идёт проверка, — фокус с клавиатуры остаётся на ней до итога. */
    let checkFormat = null;
    if (sub.format === 'links' && !switchFound(sub)) {
      const checked = Boolean(sub.probe && !sub.probe.running);
      const btn = ui.button({
        label: checked ? 'Проверить ещё раз' : 'Проверить расширенный формат',
        kind: 'link',
        size: 'sm',
        busyKey: `vpnclient_sub_probe:${sub.id}`,
        title: 'Панель может отдавать другим клиентам формат с группами и «Самым быстрым». Ничего не меняем без вас.',
        onClick: () => Lz.api.run({ method: 'vpnclient_sub_probe', args: [sub.id], key: `vpnclient_sub_probe:${sub.id}` }),
      });
      btn.setBusy(Boolean(sub.probe && sub.probe.running));
      btn.el.dataset.fk = probeKey(sub);
      checkFormat = btn.el;
    }

    return h('section', { class: 'vc-sub vc-sub-wrap', 'aria-label': `Подписка ${fmt.quote(sub.name)}`, dataset: { fk: `sub-section:${sub.id}` } },
      h('header', { class: 'vc-sub__head' },
        h('div', { class: 'vc-sub__titles' },
          h('h3', { class: 'vc-sub__name', text: sub.name }),
          h('p', { class: 'vc-sub__meta', text: sub.meta })),
        h('div', { class: 'vc-sub__actions' }, refresh.el, props.el, subMenu(sub, ids))),
      renderUsage(sub),
      renderWarnings(sub),
      sub.error ? ui.callout({
        tone: 'warn',
        title: 'Подписка не обновилась',
        text: `${sub.error} Серверы остались от прошлого удачного обновления.`,
      }) : null,
      sub.announce ? h('p', { class: 'vc-sub__announce' }, icon('info', { size: 15 }), h('span', { text: sub.announce })) : null,
      sub.description ? h('p', { class: 'vc-sub__note muted', text: sub.description }) : null,
      renderProbe(sub),
      links.length || checkFormat ? h('div', { class: 'vc-sub__links' }, links, checkFormat) : null,
      section.groups.map((group) => h('div', { class: 'vc-group' },
        h('p', { class: 'vc-group__title' }, h('span', { text: group.name }), h('span', { class: 'vc-group__count num', text: String(group.count) })),
        serverList(group.rows, group.auto, data, onPick))),
      section.rest.length || section.auto ? h('div', { class: 'vc-group' },
        section.restTitle ? h('p', { class: 'vc-group__title' }, h('span', { text: section.restTitle })) : null,
        serverList(section.rest, section.auto, data, onPick)) : null);
  }

  function renderManualSection(section, data, onPick) {
    if (!section.rows.length) return null;
    return h('section', { class: 'vc-sub vc-sub-wrap', 'aria-label': 'Серверы, добавленные вручную' },
      h('header', { class: 'vc-sub__head' },
        h('div', { class: 'vc-sub__titles' },
          h('h3', { class: 'vc-sub__name', text: 'Добавлены вручную' }),
          h('p', { class: 'vc-sub__meta', text: `${fmt.count(section.total, 'сервер', 'сервера', 'серверов')} по ссылкам` }))),
      serverList(section.rows, null, data, onPick));
  }

  function renderList(data, onPick) {
    if (!data.total && !data.sections.length) return null;
    if (data.query && !data.shown) {
      return ui.emptyState({ icon: 'search', title: 'Ничего не нашлось', text: 'Ищем по названию, стране и протоколу: «NL», «Германия», «Hysteria».' });
    }
    return data.sections.map((section) => (section.kind === 'sub'
      ? renderSubSection(section, data, onPick)
      : renderManualSection(section, data, onPick)));
  }

  /* ---------- Карточка ---------- */

  function createServersSection() {
    const local = { query: '', sort: 'latency', pendingId: null, sortPending: false };
    let snap = null;

    const search = h('input', {
      class: 'input input--search',
      type: 'search',
      placeholder: 'Найти сервер',
      'aria-label': 'Найти сервер',
      autocomplete: 'off',
      spellcheck: false,
    });
    search.dataset.fk = 'servers-search';
    search.addEventListener('input', () => {
      local.query = search.value.trim().toLowerCase();
      render();
    });
    const sortSeg = ui.segmented({
      label: 'Сортировка серверов',
      value: local.sort,
      size: 'sm',
      options: SORT_OPTIONS,
      onChange: async (value, previous) => {
        local.sort = value;
        local.sortPending = true;
        render();
        let saved = false;
        try {
          const result = await Lz.api.run({ method: 'vpnclient_save_settings', args: [{ sort: value }], key: 'vpnclient_save_settings:sort' });
          saved = Boolean(result && result.ok);
        } finally {
          local.sortPending = false;
          if (!saved) {
            local.sort = previous;
            render();
          }
        }
        return saved;
      },
    });

    const latencyBtn = ui.button({
      label: 'Проверить задержку',
      icon: 'pulse',
      size: 'sm',
      busyKey: 'vpnclient_latency',
      onClick: () => latency(null),
    });
    const speedBtn = ui.button({
      label: 'Тест скорости',
      icon: 'gauge',
      size: 'sm',
      busyKey: 'vpnclient_speedtest',
      title: 'Скачивание через выбранный сервер, не дольше 10 секунд',
      onClick: () => speedtest(null),
    });
    const speedLine = h('p', { class: 'vc-servers__speed muted small', hidden: true });

    async function pick(id) {
      local.pendingId = id;
      render();
      try {
        await gate.select(id);
      } finally {
        local.pendingId = null;
        render();
      }
    }

    const list = ui.slot((data) => renderList(data, pick), { cls: 'vc-list' });
    const card = ui.card({
      title: 'Серверы',
      /* «Обычно»: в подключение входят выбранный и до 15 серверов его подписки (vcView.configServerIds). */
      subtitle: 'Нажмите на сервер, чтобы выбрать его. Включённый VPN обычно переключится на сервер той же подписки без переподключения, на сервер другой подписки — переподключится на пару секунд.',
      actions: [latencyBtn.el, speedBtn.el],
    });
    card.body.append(
      h('div', { class: 'vc-toolbar' },
        h('div', { class: 'search vc-toolbar__search' }, icon('search', { size: 16, cls: 'search__icon' }), search),
        h('span', { class: 'spacer' }),
        sortSeg.el),
      speedLine,
      list.el);

    function render() {
      if (!snap) return;
      list.update(listData(snap, local));
    }

    return {
      el: card.el,
      update(state) {
        snap = view.snapshot(state);
        const vc = snap.vc;
        const settings = snap.settings;
        if (!local.sortPending && settings.sort && settings.sort !== local.sort) {
          local.sort = settings.sort;
          sortSeg.set(local.sort);
        }
        const lat = vc.latency || {};
        const latRunning = Boolean(lat.running);
        latencyBtn.setBusy(latRunning);
        latencyBtn.setLabel(latRunning && lat.total ? `Проверяем ${fmt.integer(lat.done || 0)} из ${fmt.integer(lat.total)}…` : 'Проверить задержку');
        const supported = snap.servers.some((server) => server.supported !== false);
        latencyBtn.setDisabled(!supported);
        const speed = vc.speed || {};
        const running = vc.status === 'running';
        speedBtn.setBusy(Boolean(speed.running));
        speedBtn.setLabel(speed.running ? 'Меряем скорость…' : 'Тест скорости');
        speedBtn.setDisabled(!running && !speed.running);
        speedBtn.el.title = running ? 'Скачивание через выбранный сервер, не дольше 10 секунд' : 'Включите VPN — скорость меряется через выбранный сервер';
        const result = view.speedText(speed);
        const server = speed.server ? snap.servers.find((item) => String(item.id) === String(speed.server)) : null;
        const through = server ? `через сервер ${fmt.quote(server.name)}` : 'через выбранный сервер';
        const lineText = !speed.running && result
          ? `Скорость ${through}: ${result}${speed.at ? ` · ${fmt.relative(speed.at)}` : ''}`
          : '';
        setText(speedLine, lineText);
        speedLine.hidden = !lineText;
        render();
      },
    };
  }

  Lz.vcSections = Object.assign(Lz.vcSections || {}, { createServersSection });
})(window.Lz);
