'use strict';
/* Обход: фильтры, списки сайтов, режим работы и настройки для опытных. */
(function (Lz) {
  const { h, icon, uid, setText, setHidden } = Lz.dom;
  const ui = Lz.ui;
  const fmt = Lz.fmt;
  const texts = Lz.texts;

  const PORT_MAX = 65535;
  const PORT_ITEM = /^([1-9]\d{0,4})(?:-([1-9]\d{0,4}))?$/;
  const GAME_MODES = ['disabled', 'all', 'tcp', 'udp'];
  const IPSET_MODES = ['none', 'loaded', 'any'];
  const LIST_ROWS = 12;
  /* Пока идёт подбор или «Найти и включить», ядро отказывает в смене фильтров, списков и режима («Идёт подбор…»). */
  const MANAGED_TITLE = 'Идёт подбор стратегии — дождитесь окончания или остановите его';

  function isManaged(zapret) {
    return Boolean(zapret && ((zapret.test && zapret.test.running) || (zapret.fix && zapret.fix.running)));
  }

  /* ---------- Фильтры ---------- */

  /** Те же правила, что у service.bat: порты и диапазоны через запятую, 1–65535, начало ≤ конца. */
  function validatePorts(text) {
    const value = String(text || '').replace(/\s+/g, '');
    if (!value) return 'Укажите порты, например 1024-65535';
    for (const item of value.split(',')) {
      const match = PORT_ITEM.exec(item);
      if (!match) return `«${item}» — не порт и не диапазон. Пример: 1024-65535 или 80,443`;
      const start = Number(match[1]);
      const end = Number(match[2] || match[1]);
      if (start > PORT_MAX || end > PORT_MAX) return `Порт не может быть больше ${PORT_MAX}`;
      if (start > end) return `В диапазоне ${item} начало больше конца`;
    }
    return null;
  }

  function createGameFilter() {
    const dirty = { tcp: false, udp: false };
    let server = { mode: 'disabled', tcp: '', udp: '' };

    const titleId = uid('gf-title');
    const tcpId = uid('gf-tcp');
    const udpId = uid('gf-udp');
    const tcpInput = ui.textInput({ id: tcpId, mono: true, placeholder: '1024-65535', onInput: () => onPortsInput('tcp') });
    const udpInput = ui.textInput({ id: udpId, mono: true, placeholder: '1024-65535', onInput: () => onPortsInput('udp') });
    const tcpField = ui.field({ label: 'Порты TCP', control: tcpInput, inputId: tcpId });
    const udpField = ui.field({ label: 'Порты UDP', control: udpInput, inputId: udpId });
    const applyBtn = ui.button({
      label: 'Применить порты',
      kind: 'primary',
      size: 'sm',
      busyKey: 'zapret_set_game_filter',
      onClick: () => apply(modeSeg.get()),
    });
    const modeSeg = ui.segmented({
      labelledBy: titleId,
      value: 'disabled',
      options: GAME_MODES.map((mode) => ({ value: mode, label: texts.GAME_FILTER[mode].label })),
      onChange: (mode) => apply(mode),
    });

    function inputsFor(mode) {
      return { tcp: mode === 'all' || mode === 'tcp', udp: mode === 'all' || mode === 'udp' };
    }

    function onPortsInput(proto) {
      const input = proto === 'tcp' ? tcpInput : udpInput;
      dirty[proto] = input.value.trim() !== String(server[proto] || '');
      (proto === 'tcp' ? tcpField : udpField).setError(null);
      setHidden(applyBtn.el, !(dirty.tcp || dirty.udp));
    }

    /**
     * Порты проверяем только у тех протоколов, которые выбранный режим использует:
     * неверный черновик UDP не должен мешать выключить фильтр или включить «Только TCP».
     * Для неиспользуемого протокола с неверным черновиком отправляем сохранённое значение.
     */
    function portsFor(proto, relevant) {
      const draft = (proto === 'tcp' ? tcpInput : udpInput).value.trim();
      const error = validatePorts(draft);
      if (relevant) return { value: draft, error };
      return { value: error ? String(server[proto] || '') : draft, error: null };
    }

    async function apply(mode) {
      const relevant = inputsFor(mode);
      const tcp = portsFor('tcp', relevant.tcp);
      const udp = portsFor('udp', relevant.udp);
      tcpField.setError(tcp.error);
      udpField.setError(udp.error);
      if (tcp.error || udp.error) return false;
      const result = await Lz.api.run({
        method: 'zapret_set_game_filter',
        args: [mode, tcp.value, udp.value],
        success: 'Игровой фильтр сохранён',
      });
      if (!result) return false;
      if (!result.ok) {
        const fieldErrors = result.errors || {};
        tcpField.setError(fieldErrors.tcp || null);
        udpField.setError(fieldErrors.udp || null);
        return false;
      }
      dirty.tcp = false;
      dirty.udp = false;
      setHidden(applyBtn.el, true);
      return true;
    }

    const el = h('div', { class: 'subsection' },
      h('div', { class: 'subsection__head' },
        h('h3', { class: 'subsection__title', id: titleId }, icon('gamepad', { size: 18 }), 'Игровой фильтр'),
        modeSeg.el),
      h('p', { class: 'subsection__text', text: 'Расширяет обход на порты игр и голосовых чатов. Включайте, если не работают игры или голос в Discord; в остальных случаях лучше оставить выключенным.' }),
      h('div', { class: 'ports' }, tcpField.el, udpField.el, h('div', { class: 'ports__apply' }, applyBtn.el)));
    setHidden(applyBtn.el, true);

    function update(zapret) {
      const gf = zapret.game_filter || {};
      server = { mode: gf.mode || 'disabled', tcp: gf.tcp || '', udp: gf.udp || '' };
      modeSeg.set(server.mode);
      modeSeg.setDisabled(zapret.available === false || isManaged(zapret));
      applyBtn.setDisabled(isManaged(zapret));
      applyBtn.el.title = isManaged(zapret) ? MANAGED_TITLE : '';
      if (!dirty.tcp) ui.syncValue(tcpInput, server.tcp);
      if (!dirty.udp) ui.syncValue(udpInput, server.udp);
      const relevant = inputsFor(server.mode);
      tcpField.el.classList.toggle('is-muted', !relevant.tcp);
      udpField.el.classList.toggle('is-muted', !relevant.udp);
    }

    return { el, update };
  }

  function createIpset() {
    const titleId = uid('ipset-title');
    const explanation = h('p', { class: 'subsection__text' });
    const countText = h('span', { class: 'muted small num' });
    const modeSeg = ui.segmented({
      labelledBy: titleId,
      value: 'none',
      options: IPSET_MODES.map((mode) => ({ value: mode, label: texts.IPSET[mode].label, title: texts.IPSET[mode].text })),
      onChange: async (mode) => {
        setText(explanation, texts.ipset(mode).text);
        const result = await Lz.api.run({ method: 'zapret_set_ipset', args: [mode] });
        return Boolean(result && result.ok);
      },
    });
    const refreshBtn = ui.actionButton({
      method: 'zapret_update_ipset',
      label: 'Обновить список IP',
      icon: 'refresh',
      size: 'sm',
      success: (result) => result.message || 'Список IP обновлён',
    });

    const el = h('div', { class: 'subsection' },
      h('div', { class: 'subsection__head' },
        h('h3', { class: 'subsection__title', id: titleId }, icon('globe', { size: 18 }), 'Список IP-адресов'),
        modeSeg.el),
      explanation,
      h('div', { class: 'subsection__foot' }, refreshBtn.el, countText));

    function update(zapret) {
      const ipset = zapret.ipset || {};
      const mode = ipset.mode || 'none';
      modeSeg.set(mode);
      modeSeg.setDisabled(zapret.available === false || isManaged(zapret));
      refreshBtn.setDisabled(zapret.available === false || isManaged(zapret));
      setText(explanation, texts.ipset(modeSeg.get()).text);
      setText(countText, ipset.count ? `В полном списке ${fmt.count(ipset.count, 'подсеть', 'подсети', 'подсетей')}` : '');
    }

    return { el, update };
  }

  function createFiltersSection() {
    const game = createGameFilter();
    const ipset = createIpset();
    const card = ui.card({
      title: 'Фильтры',
      subtitle: 'Что ещё, кроме сайтов из списков, пропускать через обход.',
    });
    card.body.append(game.el, h('div', { class: 'divider', 'aria-hidden': 'true' }), ipset.el);
    return {
      el: card.el,
      update(state) {
        const zapret = state.zapret || {};
        game.update(zapret);
        ipset.update(zapret);
      },
    };
  }

  /* ---------- Списки ---------- */

  function lineCount(text) {
    return String(text || '').split(/\r?\n/).filter((line) => line.trim()).length;
  }

  function createListsSection() {
    let lists = null;
    let loading = false;
    let loadError = null;
    let selectedId = null;
    let managed = false;
    const drafts = new Map();

    const panelId = uid('list-panel');
    const areaId = uid('list-text');
    const tabsCtl = ui.tabs({
      label: 'Списки',
      panelId,
      onSelect: (id) => {
        selectedId = id;
        render();
      },
    });
    const hint = h('p', { class: 'list-panel__hint' });
    /* Отказ ядра при сохранении («Не похоже на домен — строка 2: «…»») — у поля своего списка, до правки. */
    const saveErrors = new Map();
    const area = ui.textArea({
      id: areaId,
      rows: LIST_ROWS,
      label: 'Содержимое списка',
      onInput: (value) => {
        if (selectedId) {
          drafts.set(selectedId, value);
          saveErrors.delete(selectedId);
        }
        render();
      },
    });
    const areaField = ui.field({ control: area, inputId: areaId });
    const meta = h('span', { class: 'list-panel__meta num' });
    const readonlyTag = h('span', { class: 'tag', text: 'Встроенный — только просмотр' });
    const resetBtn = ui.button({ label: 'Отменить изменения', kind: 'ghost', size: 'sm', onClick: () => resetDraft() });
    const saveBtn = ui.button({ label: 'Сохранить', kind: 'primary', size: 'sm', busyKey: 'lists_save', onClick: () => save() });
    const panel = h('div', { class: 'list-panel', id: panelId, role: 'tabpanel' },
      hint,
      areaField.el,
      h('div', { class: 'list-panel__footer' }, meta, h('span', { class: 'spacer' }), readonlyTag, resetBtn.el, saveBtn.el));
    /* Пустой слот прячется (list-status:empty): иначе лишний отступ над вкладками. */
    const status = ui.slot((data) => {
      if (data.loading) return h('p', { class: 'muted' }, h('span', { class: 'spinner spinner--inline', 'aria-hidden': 'true' }), 'Загружаем списки…');
      if (data.error) {
        return ui.callout({
          tone: 'err',
          title: 'Списки не загрузились',
          text: data.error,
          actions: ui.button({ label: 'Повторить', size: 'sm', onClick: () => load() }).el,
        });
      }
      if (data.empty) return ui.emptyState({ icon: 'list', title: 'Списков нет', text: 'Ядро не вернуло ни одного списка.' });
      return null;
    }, { cls: 'list-status' });

    const openFolder = ui.button({
      label: 'Папка списков',
      icon: 'folder',
      kind: 'ghost',
      size: 'sm',
      busyKey: 'open_path:lists',
      onClick: () => Lz.actions.openPath('lists'),
    });
    const card = ui.card({
      title: 'Списки сайтов',
      subtitle: 'Какие сайты и адреса пропускать через обход, а какие — не трогать. Один домен или адрес на строку.',
      actions: openFolder.el,
    });
    card.body.append(status.el, tabsCtl.el, panel);

    function current() {
      return lists ? lists.find((list) => list.id === selectedId) || null : null;
    }

    function textOf(list) {
      return drafts.has(list.id) ? drafts.get(list.id) : String(list.text || '');
    }

    function isDirty(list) {
      return drafts.has(list.id) && drafts.get(list.id) !== String(list.text || '');
    }

    function render() {
      const ready = Array.isArray(lists) && lists.length > 0;
      status.update({ loading: loading && !lists, error: loadError, empty: Array.isArray(lists) && !lists.length });
      setHidden(tabsCtl.el, !ready);
      setHidden(panel, !ready);
      if (!ready) return;
      tabsCtl.set(lists.map((list) => ({ id: list.id, title: list.title || list.id, mark: isDirty(list) })), selectedId);
      const list = current();
      if (!list) return;
      const editable = Boolean(list.editable);
      const text = textOf(list);
      setText(hint, list.hint || '');
      if (document.activeElement !== area && area.value !== text) area.value = text;
      area.readOnly = !editable;
      area.classList.toggle('is-readonly', !editable);
      panel.setAttribute('aria-label', list.title || list.id);
      setText(meta, fmt.count(lineCount(text), 'строка', 'строки', 'строк'));
      setHidden(readonlyTag, editable);
      setHidden(saveBtn.el, !editable);
      setHidden(resetBtn.el, !editable || !isDirty(list));
      areaField.setError(saveErrors.get(list.id) || null);
      saveBtn.setDisabled(!isDirty(list) || managed);
      saveBtn.el.title = managed ? MANAGED_TITLE : '';
    }

    function resetDraft() {
      const list = current();
      if (!list) return;
      drafts.delete(list.id);
      saveErrors.delete(list.id);
      area.value = String(list.text || '');
      render();
    }

    async function save() {
      const list = current();
      if (!list || !list.editable) return;
      const text = textOf(list);
      const result = await Lz.api.run({
        method: 'lists_save',
        args: [list.id, text],
        silent: true,
        success: `Список ${fmt.quote(list.title || list.id)} сохранён`,
      });
      if (!result) return;
      if (!result.ok) {
        saveErrors.set(list.id, result.error);
        render();
        if (selectedId === list.id) area.focus({ preventScroll: true });
        return;
      }
      list.text = text;
      drafts.delete(list.id);
      saveErrors.delete(list.id);
      render();
      load();
    }

    async function load() {
      loading = true;
      render();
      try {
        const result = Lz.api.unwrap('lists_get', await Lz.api.call('lists_get'));
        lists = result && Array.isArray(result.lists) ? result.lists : [];
        loadError = null;
      } catch (err) {
        loadError = `Не получилось загрузить списки: ${Lz.api.describeError(err)}`;
      } finally {
        loading = false;
      }
      if (lists && !lists.some((list) => list.id === selectedId)) {
        selectedId = lists.length ? lists[0].id : null;
      }
      render();
    }

    return {
      el: card.el,
      update(state) {
        const next = isManaged(state.zapret);
        if (next === managed) return;
        managed = next;
        render();
      },
      /*
       * Перечитываем при каждом показе: «Помощь → Сайт» дописывает домены в «Мои сайты»,
       * и старый текст в редакторе затёр бы их при следующем сохранении. Черновики остаются.
       */
      show() {
        if (!loading) load();
      },
    };
  }

  /* ---------- Режим работы ---------- */

  const MODE_OPTIONS = [
    {
      value: 'app',
      icon: 'window',
      title: 'Вместе с Лазейкой',
      text: 'Обход работает, пока запущена Лазейка, даже свёрнутая в трей. Закрыли программу — обход выключился.',
    },
    {
      value: 'service',
      icon: 'server',
      title: 'Служба Windows',
      text: 'Обход работает всегда: стартует с Windows, даже если Лазейка закрыта. Стратегия запоминается при установке службы.',
    },
  ];

  function serviceSummary(zapret) {
    const service = zapret.service || {};
    if (!service.installed) return 'Служба не установлена.';
    const parts = ['Служба установлена', service.running ? 'работает' : 'остановлена'];
    if (service.strategy) parts.push(`стратегия ${texts.strategyLabel(zapret, service.strategy)}`);
    return `${parts.join(' · ')}.`;
  }

  function createModeSection() {
    let current = 'app';
    let locked = false;
    let pending = false;
    const info = h('p', { class: 'mode__info' });

    const buttons = MODE_OPTIONS.map((option) => {
      const btn = h('button', { type: 'button', class: 'mode__option', role: 'radio' },
        h('span', { class: 'mode__icon', 'aria-hidden': 'true' }, icon(option.icon, { size: 22 })),
        h('span', { class: 'mode__text' },
          h('span', { class: 'mode__title', text: option.title }),
          h('span', { class: 'mode__desc', text: option.text })),
        h('span', { class: 'mode__radio', 'aria-hidden': 'true' }));
      btn.addEventListener('click', () => choose(option.value));
      btn.addEventListener('keydown', (event) => {
        if (event.key !== 'ArrowLeft' && event.key !== 'ArrowRight' && event.key !== 'ArrowUp' && event.key !== 'ArrowDown') return;
        event.preventDefault();
        const next = MODE_OPTIONS.find((item) => item.value !== option.value);
        buttons[MODE_OPTIONS.indexOf(next)].focus();
      });
      return btn;
    });

    async function choose(mode) {
      if (mode === current || locked || pending) return;
      if (mode === 'service') {
        const confirmed = await ui.confirm({
          title: 'Установить службу Windows?',
          text: 'zapret будет запускаться вместе с Windows и работать, даже когда Лазейка закрыта. Вернуть обычный режим можно здесь же в любой момент.',
          confirmLabel: 'Установить службу',
          icon: 'server',
        });
        if (!confirmed) return;
      }
      pending = true;
      render();
      try {
        await Lz.api.run({ method: 'zapret_set_mode', args: [mode] });
      } finally {
        pending = false;
        render();
      }
    }

    function render() {
      buttons.forEach((btn, index) => {
        const isOn = MODE_OPTIONS[index].value === current;
        btn.setAttribute('aria-checked', String(isOn));
        btn.tabIndex = isOn ? 0 : -1;
        btn.setAttribute('aria-disabled', String(locked || pending));
      });
      group.classList.toggle('is-pending', pending);
    }

    const card = ui.card({ title: 'Режим работы' });
    const group = h('div', { class: 'mode', role: 'radiogroup', 'aria-labelledby': card.titleEl.id }, buttons);
    card.body.append(group, info);

    return {
      el: card.el,
      update(state) {
        const zapret = state.zapret || {};
        if (!pending) current = zapret.mode === 'service' ? 'service' : 'app';
        locked = zapret.available === false || isManaged(zapret);
        setText(info, serviceSummary(zapret));
        render();
      },
    };
  }

  /* ---------- Дополнительно ---------- */

  function normalizeFakes(result) {
    const source = result && typeof result === 'object' ? result : {};
    const current = source.current && typeof source.current === 'object' ? source.current : source;
    const files = Array.isArray(source.files) ? source.files : (Array.isArray(source.available) ? source.available : []);
    return {
      files: files.map(String),
      discord: current.discord ? String(current.discord) : '',
      game: current.game ? String(current.game) : '',
    };
  }

  function createFakes() {
    let loaded = false;
    const slots = [
      { id: 'discord', label: 'Голос Discord (UDP)' },
      { id: 'game', label: 'Игровой фильтр (UDP)' },
    ];
    const controls = slots.map((slotInfo) => {
      const id = uid(`fake-${slotInfo.id}`);
      const select = ui.selectControl({
        id,
        onChange: async (name) => {
          /* Работающий обход ядро перезапускает с новым фейком само (zapret.manager._apply_if_running). */
          const zapret = Lz.store.state && Lz.store.state.zapret;
          const running = Boolean(zapret && zapret.status === 'running');
          const result = await Lz.api.run({
            method: 'fakes_set',
            args: [slotInfo.id, name],
            key: `fakes_set:${slotInfo.id}`,
            success: running ? 'Фейк заменён; работающий обход перезапущен' : 'Фейк заменён',
          });
          return Boolean(result && result.ok);
        },
      });
      return { slotInfo, select, field: ui.field({ label: slotInfo.label, control: select.el, inputId: id }) };
    });
    const message = h('p', { class: 'muted small', hidden: true });
    const el = h('div', { class: 'subsection' },
      h('h3', { class: 'subsection__title' }, icon('zap', { size: 18 }), 'Активные фейки'),
      h('p', { class: 'subsection__text', text: 'Пакеты-приманки, которыми zapret сбивает с толку DPI. Меняйте, только если голос в Discord или игры не подключаются.' }),
      h('div', { class: 'grid-2' }, controls.map((control) => control.field.el)),
      message);

    async function load() {
      loaded = true;
      try {
        const data = normalizeFakes(Lz.api.unwrap('fakes_get', await Lz.api.call('fakes_get')));
        const options = data.files.map((name) => ({ value: name, label: name }));
        for (const control of controls) {
          const value = data[control.slotInfo.id];
          const withCurrent = value && !data.files.includes(value) ? [{ value, label: value }, ...options] : options;
          control.select.setOptions(value ? withCurrent : [{ value: '', label: 'Не выбран' }, ...withCurrent]);
          control.select.sync(value);
        }
        setHidden(message, true);
      } catch (err) {
        loaded = false;
        setText(message, `Не получилось прочитать фейки: ${Lz.api.describeError(err)}`);
        setHidden(message, false);
      }
    }

    return {
      el,
      show() {
        if (!loaded) load();
      },
      setLocked(locked) {
        for (const control of controls) control.select.setDisabled(locked);
      },
    };
  }

  function hostsMessage(result) {
    if (!result || !result.ok) return null;
    const text = result.text || result.message;
    if (result.up_to_date === true) return { tone: 'ok', text: text || 'Файл hosts в порядке.' };
    if (result.up_to_date === false) return { tone: 'warn', text: text || 'Файл hosts стоит обновить.' };
    return { tone: 'info', text: text || 'Проверка завершена.' };
  }

  /** Итог hosts_apply ({added, disabled, backup}): сколько добавлено, сколько своих строк отключено и где копия. */
  function hostsApplied(result) {
    const parts = [`записей добавлено: ${fmt.integer(Number(result.added) || 0)}`];
    if (Number(result.disabled) > 0) parts.push(`ваших строк с другими адресами закомментировано: ${fmt.integer(result.disabled)}`);
    const backup = result.backup ? ` Копия прежнего файла: ${result.backup}` : '';
    return `Файл hosts обновлён: ${parts.join('; ')}.${backup}`;
  }

  function createHosts() {
    const resultBox = ui.slot((data) => (data ? ui.callout({ tone: data.tone, text: data.text }) : null));

    async function check() {
      const result = await Lz.api.run({ method: 'hosts_check' });
      if (result) resultBox.update(hostsMessage(result));
    }

    /* После обновления — проверка заново: прежний итог «нужно обновить» остался бы на экране. */
    async function apply() {
      const confirmed = await ui.confirm({
        title: 'Обновить файл hosts?',
        text: 'Лазейка добавит в системный файл hosts актуальные записи из репозитория zapret-discord-youtube. Ваши строки, где у тех же доменов другие адреса, будут закомментированы, остальные записи останутся. Перед изменением Лазейка сохранит копию файла.',
        confirmLabel: 'Обновить',
        icon: 'alert',
      });
      if (!confirmed) return;
      const result = await Lz.api.run({ method: 'hosts_apply', success: hostsApplied });
      if (result && result.ok) await check();
    }

    const checkBtn = ui.button({ label: 'Проверить', icon: 'search', size: 'sm', busyKey: 'hosts_check', onClick: () => check() });
    const applyBtn = ui.button({ label: 'Обновить hosts', icon: 'download', size: 'sm', busyKey: 'hosts_apply', onClick: () => apply() });
    const el = h('div', { class: 'subsection' },
      h('h3', { class: 'subsection__title' }, icon('server', { size: 18 }), 'Файл hosts'),
      h('p', { class: 'subsection__text', text: 'Некоторые серверы Discord открываются стабильнее, если их адреса прописаны в hosts.' }),
      h('div', { class: 'subsection__foot' }, checkBtn.el, applyBtn.el),
      resultBox.el);
    resultBox.update(null);
    return {
      el,
      setLocked(locked) {
        checkBtn.setDisabled(locked);
        applyBtn.setDisabled(locked);
      },
    };
  }

  function renderConflicts(data) {
    const conflicts = data.list;
    if (!conflicts.length) {
      return h('p', { class: 'ok-line' }, icon('checkCircle', { size: 18 }), 'Конфликтов не найдено.');
    }
    return h('ul', { class: 'issue-list' }, conflicts.map((conflict) => h('li', { class: 'issue issue--err issue--inline' },
      h('span', { class: 'issue__icon', 'aria-hidden': 'true' }, icon('alertCircle', { size: 18 })),
      h('p', { class: 'issue__text', text: conflict.text }),
      conflict.fix_label ? fixConflictButton(conflict, data.managed) : null)));
  }

  function fixConflictButton(conflict, managed) {
    const btn = ui.actionButton({
      method: 'zapret_fix_conflict',
      args: [conflict.id],
      key: `zapret_fix_conflict:${conflict.id}`,
      label: conflict.fix_label,
      icon: 'wrench',
      size: 'sm',
      title: managed ? MANAGED_TITLE : null,
      success: 'Готово',
    });
    btn.setDisabled(managed);
    return btn.el;
  }

  function createAdvancedSection() {
    const fakes = createFakes();
    const hosts = createHosts();
    const conflicts = ui.slot(renderConflicts);
    const conflictsBlock = h('div', { class: 'subsection' },
      h('h3', { class: 'subsection__title' }, icon('shieldAlert', { size: 18 }), 'Конфликты'),
      h('p', { class: 'subsection__text', text: 'Другие обходы и сетевые фильтры, которые мешают zapret работать.' }),
      conflicts.el);
    const content = h('div', { class: 'advanced' },
      conflictsBlock,
      h('div', { class: 'divider', 'aria-hidden': 'true' }),
      fakes.el,
      h('div', { class: 'divider', 'aria-hidden': 'true' }),
      hosts.el);
    const disclosure = ui.disclosure({
      title: 'Дополнительно',
      content,
      cls: 'disclosure--section',
      onToggle: (open) => {
        if (open) fakes.show();
      },
    });
    const el = h('section', { class: 'section-disclosure' }, disclosure.el);

    return {
      el,
      update(state) {
        const zapret = state.zapret || {};
        const list = Array.isArray(zapret.conflicts) ? zapret.conflicts : [];
        conflicts.update({ list, managed: isManaged(zapret) });
        disclosure.setBadge(list.length ? fmt.count(list.length, 'конфликт', 'конфликта', 'конфликтов') : '', 'err');
        const locked = zapret.available === false;
        fakes.setLocked(locked || isManaged(zapret));
        hosts.setLocked(locked);
      },
      open() {
        disclosure.setOpen(true);
      },
    };
  }

  Lz.zapretSections = Object.assign(Lz.zapretSections || {}, {
    createFiltersSection,
    createListsSection,
    createModeSection,
    createAdvancedSection,
    validatePorts,
  });
})(window.Lz);
