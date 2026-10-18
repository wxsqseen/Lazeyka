'use strict';
/*
 * Свой VPN → «Маршруты»: пресет, «Discord и YouTube — через обход Лазейки» с тем, что сейчас,
 * игры, торренты и проверка IP напрямую, программы и сайты мимо VPN или только через VPN,
 * профили маршрутизации Happ/Incy и состояние списков маршрутов.
 */
(function (Lz) {
  const { h, icon, uid, setText, setHidden } = Lz.dom;
  const ui = Lz.ui;
  const fmt = Lz.fmt;
  const texts = Lz.texts;
  const view = Lz.vcView;
  const dialogs = Lz.vcDialogs;

  const SAVE = 'vpnclient_save_settings';
  const PRESET_ORDER = ['all', 'except_ru', 'blocked'];
  const PRESET_ICON = { all: 'globe', except_ru: 'home', blocked: 'shieldAlert' };
  const EXE_PATTERN = /^[^<>"|?*\r\n]+\.exe$/i;
  const SITE_ROWS = 6;
  const RULES_ACTIVE = new Set(['downloading', 'verifying', 'updating']);
  const PROFILE_SOURCE = { subscription: 'из подписки', manual: 'добавлен вручную', link: 'из ссылки', provider: 'маршруты провайдера' };

  const TOGGLES = [
    {
      key: 'games_direct',
      title: 'Загрузки игр — напрямую',
      description: 'Steam, Epic Games, Battle.net и другие лаунчеры качают игры мимо сервера: быстрее и не тратит трафик подписки.',
    },
    {
      key: 'torrents_direct',
      title: 'Торренты — напрямую',
      description: 'Торрент-клиенты и протокол BitTorrent идут мимо сервера — многие провайдеры VPN запрещают торренты.',
    },
    {
      key: 'ip_check_direct',
      title: 'Сервисы проверки IP — напрямую',
      description: 'Сайты вроде 2ip.ru увидят ваш настоящий адрес. Включайте, если они нужны, чтобы проверять провайдера.',
    },
  ];

  async function save(values, success) {
    Lz.store.patch((state) => {
      const routing = state.vpnclient && state.vpnclient.routing;
      if (routing) Object.assign(routing, values);
    });
    const result = await Lz.api.run({ method: SAVE, args: [values], key: `${SAVE}:${Object.keys(values).join(',')}`, success });
    return result;
  }

  function lines(text) {
    return String(text || '').split(/\r?\n/).map((line) => line.trim()).filter((line) => line && !line.startsWith('#'));
  }

  /* ---------- Пресет ---------- */

  function createPresetChooser() {
    let current = 'all';
    let pending = false;
    const buttons = PRESET_ORDER.map((value) => {
      const preset = texts.vpncPreset(value);
      const btn = h('button', { type: 'button', class: 'mode__option vc-preset', role: 'radio' },
        h('span', { class: 'mode__icon', 'aria-hidden': 'true' }, icon(PRESET_ICON[value], { size: 20 })),
        h('span', { class: 'mode__text' },
          h('span', { class: 'mode__title', text: preset.label }),
          h('span', { class: 'mode__desc', text: preset.text })),
        h('span', { class: 'mode__radio', 'aria-hidden': 'true' }));
      btn.addEventListener('click', () => choose(value));
      btn.addEventListener('keydown', (event) => {
        const step = { ArrowRight: 1, ArrowDown: 1, ArrowLeft: -1, ArrowUp: -1 }[event.key];
        if (!step) return;
        event.preventDefault();
        const index = (PRESET_ORDER.indexOf(value) + step + PRESET_ORDER.length) % PRESET_ORDER.length;
        buttons[index].focus();
        choose(PRESET_ORDER[index]);
      });
      return btn;
    });
    const el = h('div', { class: 'mode vc-presets', role: 'radiogroup', 'aria-label': 'Что пускать через VPN' }, buttons);

    async function choose(value) {
      if (value === current || pending) return;
      const previous = current;
      current = value;
      pending = true;
      render();
      try {
        const result = await save({ preset: value }, value === 'all' ? null : 'Пресет выбран. Списки маршрутов скачаются, если их ещё нет.');
        if (!result || !result.ok) current = previous;
      } finally {
        pending = false;
        render();
      }
    }

    function render() {
      buttons.forEach((btn, index) => {
        const on = PRESET_ORDER[index] === current;
        btn.setAttribute('aria-checked', String(on));
        btn.tabIndex = on ? 0 : -1;
      });
      el.classList.toggle('is-pending', pending);
    }
    render();

    return {
      el,
      set(value) {
        if (pending || !PRESET_ORDER.includes(value) || value === current) return;
        current = value;
        render();
      },
    };
  }

  /* ---------- Через обход ---------- */

  /** Что сейчас с Discord и YouTube: пояснение ядра (bypass_note), а без него — своё по положению селектора. */
  function bypassLine(routing) {
    const note = routing.bypass_note ? String(routing.bypass_note) : '';
    if (!routing.via_zapret) return { tone: 'off', text: 'Выключено: Discord и YouTube идут через сервер, как всё остальное.' };
    if (routing.bypass === 'direct') return { tone: 'ok', text: note || 'Сейчас Discord и YouTube идут через обход Лазейки.' };
    if (routing.bypass === 'proxy') {
      return { tone: 'warn', text: note || 'Сейчас Discord и YouTube идут через VPN: обход выключен или его последняя проверка не прошла.' };
    }
    return { tone: 'off', text: note || 'Переключение заработает, когда включится свой VPN.' };
  }

  /* ---------- Программы ---------- */

  function createAppList({ key, title, description, pickTitle }) {
    let items = [];
    let pending = false;
    const inputId = uid('vc-app');
    const input = ui.textInput({ id: inputId, mono: true, placeholder: 'Discord.exe', maxLength: 260, label: `${title}: имя exe или путь` });
    const field = ui.field({ control: h('div', { class: 'input-group' }, input), inputId });
    const chips = ui.slot((data) => (data.items.length
      ? data.items.map((name) => h('span', { class: 'vc-chip' },
        h('span', { class: 'vc-chip__text mono', text: name }),
        h('button', {
          type: 'button',
          class: 'vc-chip__remove',
          'aria-label': `Убрать ${name}`,
          title: 'Убрать',
          dataset: { fk: `app-remove:${key}:${name}` },
          onClick: () => apply(items.filter((item) => item !== name)),
        }, icon('x', { size: 13 }))))
      : h('p', { class: 'vc-apps-empty', text: 'Пока ни одной программы' })), { cls: 'vc-chips' });

    async function apply(next) {
      if (pending) return false;
      pending = true;
      const previous = items;
      items = next;
      chips.update({ items });
      try {
        const result = await save({ [key]: next });
        if (!result || !result.ok) {
          items = previous;
          chips.update({ items });
          if (result && result.errors && result.errors[key]) field.setError(result.errors[key]);
          return false;
        }
        return true;
      } finally {
        pending = false;
      }
    }

    async function add(raw) {
      const value = String(raw || '').trim().replace(/^"(.*)"$/, '$1');
      if (!value) return;
      if (!EXE_PATTERN.test(value)) {
        field.setError('Нужно имя exe-файла, например Discord.exe, или полный путь к нему');
        return;
      }
      if (items.some((item) => item.toLowerCase() === value.toLowerCase())) {
        field.setError('Эта программа уже в списке');
        return;
      }
      field.setError(null);
      if (await apply([...items, value])) input.value = '';
    }

    const addBtn = ui.button({ label: 'Добавить', size: 'sm', onClick: () => add(input.value) });
    const pickBtn = ui.button({
      label: 'Из запущенных…',
      iconRight: 'arrowRight',
      size: 'sm',
      kind: 'link',
      onClick: async () => {
        const name = await dialogs.pickApp({ title: pickTitle });
        if (name) add(name);
      },
    });
    input.addEventListener('keydown', (event) => {
      if (event.key !== 'Enter') return;
      event.preventDefault();
      add(input.value);
    });
    input.addEventListener('input', () => field.setError(null));

    const el = h('div', { class: 'vc-applist' },
      h('div', { class: 'vc-applist__head' }, h('p', { class: 'vc-applist__title', text: title }), pickBtn.el),
      h('p', { class: 'vc-applist__desc', text: description }),
      chips.el,
      h('div', { class: 'vc-applist__add' }, field.el, addBtn.el));

    return {
      el,
      update(list) {
        if (pending) return;
        items = Array.isArray(list) ? list.map(String) : [];
        chips.update({ items });
      },
    };
  }

  /* ---------- Сайты ---------- */

  const SITE_LISTS = [
    { key: 'direct_sites', title: 'Мимо VPN', hint: 'Эти сайты откроются напрямую. Домен целиком с поддоменами: example.com. По одному на строку.' },
    { key: 'proxy_sites', title: 'Только через VPN', hint: 'Эти сайты всегда идут через сервер — даже при пресете «Только заблокированное». По одному на строку.' },
  ];

  function createSitesEditor() {
    let selected = SITE_LISTS[0].key;
    const server = { direct_sites: '', proxy_sites: '' };
    const drafts = new Map();
    const panelId = uid('vc-sites');
    const areaId = uid('vc-sites-text');
    const tabsCtl = ui.tabs({
      label: 'Свои списки сайтов',
      panelId,
      onSelect: (id) => {
        selected = id;
        render();
      },
    });
    const hint = h('p', { class: 'list-panel__hint' });
    const area = ui.textArea({
      id: areaId,
      rows: SITE_ROWS,
      label: 'Сайты, по одному на строку',
      placeholder: 'example.com',
      onInput: (value) => {
        drafts.set(selected, value);
        fieldErr.setError(null);
        render();
      },
    });
    const fieldErr = ui.field({ control: area, inputId: areaId });
    const meta = h('span', { class: 'list-panel__meta num' });
    const reset = ui.button({ label: 'Отменить изменения', kind: 'ghost', size: 'sm', onClick: () => {
      drafts.delete(selected);
      area.value = server[selected];
      fieldErr.setError(null);
      render();
    } });
    const saveBtn = ui.button({ label: 'Сохранить', kind: 'primary', size: 'sm', busyKey: `${SAVE}:sites`, onClick: () => commit() });
    const panel = h('div', { class: 'list-panel', id: panelId, role: 'tabpanel' },
      hint, fieldErr.el,
      h('div', { class: 'list-panel__footer' }, meta, h('span', { class: 'spacer' }), reset.el, saveBtn.el));

    function textOf(key) {
      return drafts.has(key) ? drafts.get(key) : server[key];
    }

    function dirty(key) {
      return drafts.has(key) && drafts.get(key) !== server[key];
    }

    function render() {
      tabsCtl.set(SITE_LISTS.map((list) => ({ id: list.key, title: list.title, mark: dirty(list.key) })), selected);
      const list = SITE_LISTS.find((item) => item.key === selected);
      setText(hint, list.hint);
      const text = textOf(selected);
      if (document.activeElement !== area && area.value !== text) area.value = text;
      panel.setAttribute('aria-label', list.title);
      setText(meta, fmt.count(lines(text).length, 'сайт', 'сайта', 'сайтов'));
      setHidden(reset.el, !dirty(selected));
      saveBtn.setDisabled(!dirty(selected));
    }

    async function commit() {
      const key = selected;
      const values = lines(textOf(key));
      const bad = values.find((line) => /\s/.test(line) || line.includes('/'));
      if (bad) {
        fieldErr.setError(`«${bad}» — не домен. Пишите только домен, без http:// и пробелов: example.com`);
        return;
      }
      const result = await Lz.api.run({ method: SAVE, args: [{ [key]: values }], key: `${SAVE}:sites`, success: 'Список сайтов сохранён' });
      if (!result) return;
      if (!result.ok) {
        fieldErr.setError((result.errors && result.errors[key]) || null);
        return;
      }
      server[key] = values.join('\n');
      drafts.delete(key);
      area.value = server[key];
      render();
    }

    return {
      el: h('div', { class: 'vc-sites' }, tabsCtl.el, panel),
      update(routing) {
        for (const list of SITE_LISTS) {
          const value = Array.isArray(routing[list.key]) ? routing[list.key].map(String).join('\n') : '';
          if (value !== server[list.key]) {
            server[list.key] = value;
            if (drafts.get(list.key) === value) drafts.delete(list.key);
          }
        }
        render();
      },
    };
  }

  /* ---------- Профили маршрутизации ---------- */

  function summaryText(summary) {
    const source = summary || {};
    const parts = [];
    if (source.direct) parts.push(`напрямую ${fmt.integer(source.direct)}`);
    if (source.proxy) parts.push(`через VPN ${fmt.integer(source.proxy)}`);
    if (source.block) parts.push(`заблокировать ${fmt.integer(source.block)}`);
    return parts.length ? parts.join(' · ') : 'правил нет';
  }

  async function setProfile(profile, active) {
    if (active) {
      const summary = profile.summary || {};
      const confirmed = await ui.confirm({
        title: `Включить профиль «${profile.name}»?`,
        text: `Правила профиля: ${summaryText(summary)}. Свои правила Лазейки — программы, сайты и «через обход» — останутся важнее.`,
        details: summary.block ? 'Профиль блокирует часть адресов — эти сайты перестанут открываться, пока он включён.' : null,
        confirmLabel: 'Включить профиль',
        icon: 'route',
      });
      if (!confirmed) return false;
    }
    const result = await Lz.api.run({
      method: 'vpnclient_profile_set',
      args: [profile.id, active],
      key: `vpnclient_profile_set:${profile.id}`,
      success: active ? 'Профиль маршрутизации включён' : 'Профиль выключен',
    });
    return Boolean(result && result.ok);
  }

  async function removeProfile(profile) {
    const confirmed = await ui.confirm({
      title: `Удалить профиль «${profile.name}»?`,
      text: 'Его правила перестанут действовать. Профиль из подписки вернётся при её обновлении.',
      confirmLabel: 'Удалить',
      tone: 'danger',
      icon: 'trash',
    });
    if (confirmed) Lz.api.run({ method: 'vpnclient_profile_remove', args: [profile.id], key: `vpnclient_profile_remove:${profile.id}`, success: 'Профиль удалён' });
  }

  function renderProfiles(data) {
    if (!data.items.length) return h('p', { class: 'vc-apps-empty', text: 'Профилей нет. Их присылают некоторые провайдеры в подписке или ссылкой happ://routing/…' });
    return h('ul', { class: 'vc-profiles' }, data.items.map((profile) => {
      const sw = ui.switchControl({
        checked: Boolean(profile.active),
        label: `Профиль «${profile.name}»`,
        onChange: (on) => setProfile(profile, on),
      });
      sw.el.dataset.fk = `profile:${profile.id}`;
      const remove = ui.button({
        icon: 'trash',
        kind: 'ghost',
        size: 'sm',
        ariaLabel: `Удалить профиль «${profile.name}»`,
        title: 'Удалить',
        onClick: () => removeProfile(profile),
      });
      remove.el.dataset.fk = `profile-remove:${profile.id}`;
      return h('li', { class: ['vc-profile', profile.active && 'is-active'] },
        h('div', { class: 'vc-profile__text' },
          h('p', { class: 'vc-profile__name' }, profile.name,
            profile.source && PROFILE_SOURCE[profile.source] ? h('span', { class: 'vc-profile__source', text: ` · ${PROFILE_SOURCE[profile.source]}` }) : null),
          h('p', { class: 'vc-profile__summary', text: summaryText(profile.summary) })),
        remove.el, sw.el);
    }));
  }

  function createProfiles() {
    const inputId = uid('vc-profile');
    const input = ui.textInput({ id: inputId, mono: true, placeholder: 'happ://routing/…, incy://routing/… или текст профиля', maxLength: 65536 });
    const field = ui.field({ control: h('div', { class: 'input-group' }, input), inputId });
    const importBtn = ui.button({
      label: 'Добавить профиль',
      size: 'sm',
      busyKey: 'vpnclient_profile_import',
      onClick: () => importProfile(),
    });
    const list = ui.slot(renderProfiles, { cls: 'vc-profiles-wrap' });

    async function importProfile() {
      const text = input.value.trim();
      if (!text) {
        field.setError('Вставьте ссылку на профиль или его текст');
        return;
      }
      field.setError(null);
      const result = await Lz.api.run({
        method: 'vpnclient_profile_import',
        args: [text],
        silent: true,
        success: (reply) => reply.message || 'Профиль добавлен выключенным — посмотрите правила и включите его',
      });
      if (!result) return;
      if (!result.ok) field.setError(result.error);
      else input.value = '';
    }
    input.addEventListener('keydown', (event) => {
      if (event.key !== 'Enter') return;
      event.preventDefault();
      importProfile();
    });
    input.addEventListener('input', () => field.setError(null));

    const el = h('div', { class: 'subsection' },
      h('h3', { class: 'subsection__title' }, icon('list', { size: 18 }), 'Профили маршрутизации'),
      h('p', { class: 'subsection__text', text: 'Правила в формате Happ и Incy: какие сайты и адреса пускать напрямую, через VPN или блокировать. Перед включением Лазейка покажет, что профиль меняет.' }),
      list.el,
      h('div', { class: 'vc-applist__add' }, field.el, importBtn.el));

    return {
      el,
      update(profiles) {
        list.update({
          items: profiles.map((profile) => ({
            id: String(profile.id),
            name: String(profile.name || 'Профиль'),
            source: profile.source || null,
            active: Boolean(profile.active),
            summary: profile.summary || {},
          })),
        });
      },
    };
  }

  /* ---------- Списки маршрутов ---------- */

  function rulesLine(rules, preset) {
    const state = String(rules.state || 'idle');
    if (RULES_ACTIVE.has(state)) return { tone: 'warn', busy: true, text: rules.message ? String(rules.message) : 'Скачиваем списки маршрутов…' };
    if (state === 'error') return { tone: 'err', text: `Списки не скачались: ${rules.error || rules.message || 'подробности в журнале'}. Пресет работает на прежних.` };
    if (!rules.updated_at) {
      return {
        tone: 'off',
        text: preset === 'all' ? 'Списки ещё не скачивались — для «Всё через VPN» они не нужны.' : 'Списки ещё не скачаны — нажмите «Обновить списки».',
      };
    }
    if (rules.stale) return { tone: 'warn', text: `Списки обновлены ${fmt.relative(rules.updated_at)} — им больше 30 дней, лучше обновить.` };
    return { tone: 'ok', text: `Списки обновлены ${fmt.relative(rules.updated_at)}.` };
  }

  function renderRuleItems(items) {
    if (!items.length) return null;
    return h('ul', { class: 'vc-rules' }, items.map((item) => h('li', { class: ['vc-rules__item', item.error && 'is-error'] },
      h('span', { class: 'vc-rules__title', text: item.title || item.id }),
      h('span', { class: 'vc-rules__meta', text: item.error ? String(item.error) : [item.size ? fmt.bytes(item.size) : '', item.updated_at ? fmt.relative(item.updated_at) : ''].filter(Boolean).join(' · ') }))));
  }

  function createRules() {
    const dotText = h('span', { class: 'conn__text' });
    const status = h('p', { class: 'conn', role: 'status' }, h('span', { class: 'conn__dot', 'aria-hidden': 'true' }), dotText);
    const update = ui.actionButton({
      method: 'vpnclient_rules_update',
      label: 'Обновить списки',
      icon: 'refresh',
      size: 'sm',
    });
    const items = ui.slot((data) => renderRuleItems(data), { cls: 'vc-rules-wrap' });
    const disclosure = ui.disclosure({ title: 'Какие списки', content: items.el });
    const el = h('div', { class: 'subsection' },
      h('h3', { class: 'subsection__title' }, icon('download', { size: 18 }), 'Списки маршрутов'),
      h('p', { class: 'subsection__text', text: 'Для пресетов и загрузок игр Лазейка скачивает открытые списки: SagerNet sing-geosite и sing-geoip, re:filter, itdoginfo allow-domains. Проверяет их не чаще раза в сутки.' }),
      h('div', { class: 'vpn-state' }, status, update.el),
      disclosure.el);
    return {
      el,
      update(routing) {
        const rules = routing.rules && typeof routing.rules === 'object' ? routing.rules : {};
        const line = rulesLine(rules, routing.preset);
        status.dataset.tone = line.tone;
        setText(dotText, line.text);
        update.setBusy(Boolean(line.busy));
        const list = Array.isArray(rules.items) ? rules.items : [];
        items.update(list.map((item) => ({
          id: String(item.id || ''), title: item.title ? String(item.title) : '', size: item.size || null,
          updated_at: item.updated_at || null, error: item.error ? String(item.error) : null,
        })));
        setHidden(disclosure.el, !list.length);
      },
    };
  }

  /* ---------- Карточка ---------- */

  function createRoutingSection() {
    const presets = createPresetChooser();
    const viaZapret = ui.switchRow({
      title: 'Discord и YouTube — через обход Лазейки',
      description: 'Discord, YouTube и голос Discord идут мимо сервера: их обрабатывает обход — быстрее и без нагрузки на VPN. Выключится обход или перестанет справляться — они на лету уйдут на сервер.',
      onChange: async (on) => {
        const result = await save({ via_zapret: on });
        return Boolean(result && result.ok);
      },
    });
    const bypassText = h('span', { class: 'conn__text' });
    const bypass = h('p', { class: 'conn vc-bypass', role: 'status' }, h('span', { class: 'conn__dot', 'aria-hidden': 'true' }), bypassText);
    const toggles = {};
    const togglesList = h('div', { class: 'settings-list' }, TOGGLES.map((toggle) => {
      const row = ui.switchRow({
        title: toggle.title,
        description: toggle.description,
        onChange: async (on) => {
          const result = await save({ [toggle.key]: on });
          return Boolean(result && result.ok);
        },
      });
      toggles[toggle.key] = row.sw;
      return row.el;
    }));

    const directApps = createAppList({
      key: 'direct_apps',
      title: 'Мимо VPN',
      pickTitle: 'Программа мимо VPN',
      description: 'Ходят в интернет напрямую, как без VPN.',
    });
    const proxyApps = createAppList({
      key: 'proxy_apps',
      title: 'Только через VPN',
      pickTitle: 'Программа только через VPN',
      description: 'Всегда идут через сервер, при любом пресете.',
    });
    const appsNote = h('p', { class: 'vc-note', hidden: true });
    /* Профиль маршрутизации провайдера заменяет пресет: его правила и его «всё остальное». */
    const presetNote = h('p', { class: 'vc-note', hidden: true });
    const sites = createSitesEditor();
    const profiles = createProfiles();
    const rules = createRules();

    const card = ui.card({
      title: 'Маршруты',
      subtitle: 'Что идёт через ваш сервер, а что — напрямую или через обход Лазейки. Меняется на лету, без переподключения.',
    });
    card.body.append(
      presets.el,
      presetNote,
      h('div', { class: 'divider', 'aria-hidden': 'true' }),
      h('div', { class: 'settings-list' }, viaZapret.el),
      bypass,
      h('div', { class: 'divider', 'aria-hidden': 'true' }),
      togglesList,
      h('div', { class: 'divider', 'aria-hidden': 'true' }),
      h('div', { class: 'subsection' },
        h('h3', { class: 'subsection__title' }, icon('window', { size: 18 }), 'Программы'),
        appsNote,
        h('div', { class: 'grid-2 vc-applists' }, directApps.el, proxyApps.el)),
      h('div', { class: 'divider', 'aria-hidden': 'true' }),
      h('div', { class: 'subsection' },
        h('h3', { class: 'subsection__title' }, icon('globe', { size: 18 }), 'Сайты'),
        sites.el),
      h('div', { class: 'divider', 'aria-hidden': 'true' }),
      profiles.el,
      h('div', { class: 'divider', 'aria-hidden': 'true' }),
      rules.el);

    return {
      el: card.el,
      update(state) {
        const snap = view.snapshot(state);
        const routing = snap.routing;
        presets.set(routing.preset || 'all');
        const active = (snap.profiles || []).find((profile) => profile && profile.active);
        const presetText = active ? `Сейчас включён профиль «${String(active.name || 'провайдера')}» — пресет не действует: `
          + 'сайты идут по правилам профиля. Выключите профиль ниже, чтобы вернуть пресет.' : '';
        setText(presetNote, presetText);
        setHidden(presetNote, !presetText);
        viaZapret.sw.set(routing.via_zapret !== false);
        const line = bypassLine({ ...routing, via_zapret: routing.via_zapret !== false });
        bypass.dataset.tone = line.tone;
        setText(bypassText, line.text);
        for (const toggle of TOGGLES) toggles[toggle.key].set(Boolean(routing[toggle.key]));
        directApps.update(routing.direct_apps);
        proxyApps.update(routing.proxy_apps);
        const mode = snap.vc.mode || 'tun';
        const note = mode === 'tun' ? '' : 'Сейчас режим «'
          + `${texts.vpncMode(mode).short}»: правила по программам сработают только для тех, что ходят через прокси. Для всех программ включите «Весь трафик (TUN)».`;
        setText(appsNote, note);
        setHidden(appsNote, !note);
        sites.update(routing);
        profiles.update(snap.profiles);
        rules.update(routing);
      },
    };
  }

  Lz.vcSections = Object.assign(Lz.vcSections || {}, { createRoutingSection });
})(window.Lz);
