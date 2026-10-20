'use strict';
/*
 * Свой VPN → «Подробнее»: локальный прокси, DNS, IPv4/IPv6, TUN, исключения, kill switch,
 * поведение после сна, маскировка, подписки и журнал — одной формой с черновиком (опрос не
 * трогает поля, которые человек уже поменял); резервная копия с паролем; ядра и их исходники.
 */
(function (Lz) {
  const { h, icon, uid, setText, setHidden } = Lz.dom;
  const ui = Lz.ui;
  const fmt = Lz.fmt;
  const texts = Lz.texts;
  const view = Lz.vcView;
  const dialogs = Lz.vcDialogs;

  const SAVE_KEY = 'vpnclient_save_settings:more';
  /* Границы — как у ядра (manager._VALIDATORS, _check_local_auth): порты ниже 1024 системные. */
  const PORT_MIN = 1024;
  const PORT_MAX = 65535;
  const MTU_MIN = 1280;
  const MTU_MAX = 9000;
  const HOURS_MIN = 1;
  const HOURS_MAX = 72;
  const CIDR = /^(\d{1,3}(\.\d{1,3}){3}\/\d{1,2}|[0-9a-f:]+\/\d{1,3})$/i;
  const LOGIN = /^[A-Za-z0-9._-]{1,64}$/;
  const PASSWORD = /^[\x21-\x39\x3B-\x7E]{1,128}$/;
  const IP_OPTIONS = [
    { value: 'ipv4_only', label: 'Только IPv4' },
    { value: 'prefer_ipv4', label: 'Сначала IPv4' },
    { value: 'prefer_ipv6', label: 'Сначала IPv6' },
  ];
  const SLEEP_OPTIONS = [
    { value: 'reconnect', label: 'Переподключить' },
    { value: 'disconnect', label: 'Выключить VPN' },
  ];
  /*
   * Все значения manager.FINGERPRINTS: пустое — «как в ссылке» (своего отпечатка Лазейка не добавляет). Значения
   * нет в списке — <select> показал бы пустоту, поэтому список полный.
   */
  const FINGERPRINTS = ['', 'chrome', 'firefox', 'edge', 'safari', '360', 'qq', 'ios', 'android', 'random', 'randomized'];
  const FINGERPRINT_LABEL = {
    '': 'Как в ссылке',
    360: '360 Browser',
    qq: 'QQ Browser',
    random: 'случайный',
    randomized: 'случайный на каждое соединение',
  };
  const CORE_UPDATE_ID = { 'sing-box': 'vpncore', xray: 'vpnxray' };
  const CORE_STATE_TEXT = { downloading: 'скачиваем с GitHub', verifying: 'проверяем SHA-256', installing: 'ставим', error: 'не скачалось' };

  /* ---------- Поля формы ---------- */

  /** Поле-строка: число, текст или пароль. get() — строка как есть, разбор — в values(). */
  function textControl(key, label, opts) {
    const options = opts || {};
    const id = uid(`vc-${key}`);
    const input = ui.textInput({ id, mono: options.mono !== false, placeholder: options.placeholder, inputMode: options.inputMode, maxLength: options.maxLength });
    if (options.password) input.type = 'password';
    const field = ui.field({ label, hint: options.hint, control: input, inputId: id, cls: options.cls });
    return {
      el: field.el,
      input,
      field,
      get: () => input.value,
      set: (value, force) => {
        if (force) input.value = value;
        else ui.syncValue(input, value);
      },
      setError: (message) => field.setError(message),
      focus: () => input.focus(),
      watch: (fn) => input.addEventListener('input', () => {
        field.setError(null);
        fn();
      }),
    };
  }

  function linesControl(key, label, hint) {
    const id = uid(`vc-${key}`);
    const area = ui.textArea({ id, rows: 4 });
    const field = ui.field({ label, hint, control: area, inputId: id });
    return {
      el: field.el,
      get: () => area.value,
      set: (value, force) => {
        if (force) area.value = value;
        else ui.syncValue(area, value);
      },
      setError: (message) => field.setError(message),
      focus: () => area.focus(),
      watch: (fn) => area.addEventListener('input', () => {
        field.setError(null);
        fn();
      }),
    };
  }

  function flagControl(title, description) {
    let listener = null;
    const row = ui.switchRow({
      title,
      description,
      onChange: () => {
        if (listener) listener();
        return true;
      },
    });
    return {
      el: row.el,
      get: () => row.sw.get(),
      set: (value) => row.sw.set(Boolean(value)),
      setError: () => {},
      focus: () => row.sw.el.focus(),
      watch: (fn) => { listener = fn; },
    };
  }

  /** Сегменты справа от заголовка — как «Тема» в настройках. */
  function choiceControl(title, description, options) {
    let listener = null;
    const titleId = uid('vc-choice');
    const seg = ui.segmented({
      labelledBy: titleId,
      value: options[0].value,
      options,
      size: 'sm',
      onChange: () => {
        if (listener) listener();
        return true;
      },
    });
    const el = h('div', { class: 'setting setting--static' },
      h('div', { class: 'setting__text' },
        h('div', { class: 'setting__title', id: titleId, text: title }),
        description ? h('p', { class: 'setting__desc', text: description }) : null),
      seg.el);
    return {
      el,
      get: () => seg.get(),
      set: (value) => seg.set(value),
      setError: () => {},
      focus: () => {},
      watch: (fn) => { listener = fn; },
    };
  }

  function selectControl(key, label, options, hint) {
    let listener = null;
    const id = uid(`vc-${key}`);
    const select = ui.selectControl({
      id,
      onChange: () => {
        if (listener) listener();
        return true;
      },
    });
    select.setOptions(options);
    const field = ui.field({ label, hint, control: select.el, inputId: id });
    return {
      el: field.el,
      get: () => select.select.value,
      set: (value, force) => {
        if (force || document.activeElement !== select.select) select.select.value = value;
      },
      setError: (message) => field.setError(message),
      focus: () => select.select.focus(),
      watch: (fn) => { listener = fn; },
    };
  }

  /** DNS: готовый резолвер из списка или свой адрес DNS через HTTPS — тот же выбор, что в свойствах подписки. */
  function dnsControl(key, label, hint) {
    let listener = null;
    const id = uid(`vc-${key}`);
    const choice = dialogs.dnsChoice({
      id,
      label,
      onChange: () => {
        field.setError(null);
        if (listener) listener();
      },
    });
    const field = ui.field({ label, hint, control: choice.el, inputId: id });
    return {
      el: field.el,
      get: choice.get,
      set: choice.set,
      setError: (message) => field.setError(message),
      focus: choice.focus,
      watch: (fn) => { listener = fn; },
    };
  }

  /* ---------- Значения ---------- */

  const NUMBER_KEYS = new Set(['port', 'tun_mtu', 'sub_update_hours']);
  const LINE_KEYS = new Set(['exclude_nets', 'proxy_override']);

  function splitLines(text) {
    return String(text || '').split(/[\r\n]+/).map((line) => line.trim()).filter(Boolean);
  }

  /** Снимок ядра → значения контролов (строки для полей, булевы для переключателей). */
  function draftFromServer(settings) {
    const draft = {};
    for (const key of Object.keys(settings)) {
      const value = settings[key];
      if (LINE_KEYS.has(key)) draft[key] = Array.isArray(value) ? value.join('\n') : '';
      else if (NUMBER_KEYS.has(key)) draft[key] = value == null ? '' : String(value);
      else draft[key] = value;
    }
    draft.local_password = '';
    return draft;
  }

  function parseValue(key, raw) {
    if (LINE_KEYS.has(key)) return splitLines(raw);
    if (NUMBER_KEYS.has(key)) {
      const text = String(raw).trim();
      return /^\d+$/.test(text) ? Number(text) : text;
    }
    if (typeof raw === 'string') return raw.trim();
    return raw;
  }

  /** Вход по паролю нужен своему прокси и устройствам из сети: без логина ядро не пустит их в прокси. */
  function wantsAuth(values) {
    return Boolean(values.local_auth || values.allow_lan);
  }

  function validate(values, settings) {
    const errors = {};
    if (!Number.isInteger(values.port) || values.port < PORT_MIN || values.port > PORT_MAX) {
      errors.port = `Порт — целое число от ${PORT_MIN} до ${PORT_MAX}`;
    }
    if (wantsAuth(values)) {
      if (!LOGIN.test(values.local_user || '')) errors.local_user = 'Логин — латиница, цифры, точка, дефис или подчёркивание, до 64 символов';
      if (values.local_password && !PASSWORD.test(values.local_password)) {
        errors.local_password = 'Пароль — до 128 латинских символов, без пробелов и двоеточия';
      } else if (!values.local_password && !settings.local_password_set) {
        errors.local_password = 'Задайте пароль';
      }
    }
    for (const key of ['dns_remote', 'dns_direct']) {
      const problem = dialogs.dnsError(values[key]);
      if (problem) errors[key] = problem;
    }
    if (!Number.isInteger(values.tun_mtu) || values.tun_mtu < MTU_MIN || values.tun_mtu > MTU_MAX) errors.tun_mtu = `От ${MTU_MIN} до ${MTU_MAX}`;
    const badNet = values.exclude_nets.find((line) => !CIDR.test(line));
    if (badNet) errors.exclude_nets = `«${badNet}» — не подсеть. Формат: 192.168.0.0/16 или fc00::/7`;
    const badOverride = values.proxy_override.find((line) => /[\s;]/.test(line));
    if (badOverride) errors.proxy_override = `«${badOverride}» — по одному адресу на строку, без пробелов и точек с запятой`;
    if (!Number.isInteger(values.sub_update_hours) || values.sub_update_hours < HOURS_MIN || values.sub_update_hours > HOURS_MAX) {
      errors.sub_update_hours = `Целое число от ${HOURS_MIN} до ${HOURS_MAX}`;
    }
    return errors;
  }

  /* ---------- Форма настроек ---------- */

  function createSettingsForm() {
    const c = {
      port: textControl('port', 'Порт', { inputMode: 'numeric', maxLength: 5, placeholder: '20808', hint: 'Для режимов «Системный прокси» и «Только локальный прокси».' }),
      local_auth: flagControl('Логин и пароль на прокси', 'Без них прокси может использовать любая программа на этом компьютере.'),
      local_user: textControl('local_user', 'Логин', { maxLength: 64 }),
      local_password: textControl('local_password', 'Пароль', { password: true, maxLength: 128 }),
      socks_udp: flagControl('UDP через SOCKS', 'Нужен играм и голосовым чатам, которые подключаются через SOCKS5.'),
      allow_lan: flagControl('Пускать устройства из сети',
        'Телефон или приставка в вашей сети смогут ходить через прокси по адресу этого компьютера — по логину и паролю из полей выше. Для мобильного хот-спота Windows в режиме «Весь трафик» раздача идёт через адаптер Lazeyka.'),
      dns_remote: dnsControl('dns_remote', 'DNS через VPN', 'Для сайтов, которые идут через сервер.'),
      dns_direct: dnsControl('dns_direct', 'DNS напрямую', 'Для сайтов мимо VPN и адресов серверов. Провайдерский DNS не используется — он подменяет адреса.'),
      fakeip: flagControl('FakeIP', 'Программы получают выдуманные адреса, а сайт узнаётся по ним. Чуть быстрее открывает сайты в режиме «Весь трафик», но некоторые программы от этого ломаются.'),
      ip_strategy: choiceControl('IPv4 и IPv6', 'Каким адресам сайтов отдавать предпочтение.', IP_OPTIONS),
      ipv6: flagControl('IPv6 через VPN', 'Даёт своему адаптеру адрес IPv6. Без него IPv6 в режиме «Весь трафик» закрыт — адрес не утечёт мимо сервера.'),
      tun_mtu: textControl('tun_mtu', 'MTU адаптера', { inputMode: 'numeric', maxLength: 4, placeholder: '1500', hint: `От ${MTU_MIN} до ${MTU_MAX}. Меняйте, если сайты грузятся не до конца.` }),
      exclude_nets: linesControl('exclude_nets', 'Исключённые подсети', 'Эти сети идут мимо VPN: домашняя сеть, принтеры, Radmin. По одной на строку.'),
      proxy_override: linesControl('proxy_override', 'Исключения системного прокси', 'К этим адресам Windows ходит без прокси. <local> — все адреса без точки. По одному на строку.'),
      kill_switch: flagControl('Kill switch',
        'Только в режиме «Весь трафик (TUN)». Пока VPN включён, интернет идёт только через сервер: упало ядро — сайты не откроются, пока VPN не переподключится. Обход Лазейки и локальная сеть работают. Закрыли Лазейку — запрет снимается сам.'),
      on_sleep: choiceControl('После сна', 'Что делать, когда компьютер проснулся.', SLEEP_OPTIONS),
      tls_fragment: flagControl('Фрагментация ClientHello', 'Режет первое сообщение TLS на части — помогает, если провайдер узнаёт и режет соединение с сервером.'),
      mux: flagControl('Мультиплексирование (mux)', 'Несколько соединений в одном: быстрее открываются страницы. С XTLS Vision не работает — таким серверам Лазейка его не включит.'),
      noises: flagControl('UDP-шумы', 'Перед соединением отправляет случайные пакеты — против блокировок QUIC и Hysteria. Сервер подключается через помощник Xray.'),
      fingerprint: selectControl('fingerprint', 'TLS-отпечаток', FINGERPRINTS.map((value) => ({ value, label: FINGERPRINT_LABEL[value] || value })),
        'Каким браузером притворяться при рукопожатии, если в ссылке сервера отпечаток не указан. Указан — берётся он.'),
      latency_on_update: flagControl('Проверять задержку после обновления подписки', 'Список серверов сразу покажет, какие отвечают быстрее.'),
      sub_update_hours: textControl('sub_update_hours', 'Обновлять подписки каждые, ч', { inputMode: 'numeric', maxLength: 2, hint: 'Если провайдер не прислал свой интервал.' }),
      verbose: flagControl('Подробный журнал ядра', 'Внимание: в журнал попадут адреса сайтов, которые вы открываете. Включайте только на время поиска ошибки и не отправляйте журнал посторонним.'),
      deeplink: flagControl('Открывать ссылки lazeyka://',
        'Кнопки «Добавить в Лазейку» на сайтах провайдеров откроют окно добавления. Без вашего подтверждения ничего не добавится, а включать и выключать VPN ссылки не умеют.'),
      core_auto_update: flagControl('Обновлять ядра автоматически',
        'Новая версия sing-box или Xray скачивается с GitHub, сверяется по SHA-256 и проверяется на ваших серверах и настройках. Подошла — заработает со следующего подключения, прежняя остаётся для отката; не подошла или не запустилась — остаётся прежняя.'),
    };
    const keys = Object.keys(c);
    let serverKey = null;
    let settings = {};
    let baseline = null;
    /* Ошибка в логине или пароле — поля видны и при выключенном входе, до отмены или удачного сохранения. */
    let authErrorShown = false;

    const authBox = h('div', { class: 'form-nested vc-auth' }, h('div', { class: 'form-grid form-grid--2' }, c.local_user.el, c.local_password.el));
    const dirtyText = h('span', { class: 'form-actions__text' });
    const cancelBtn = ui.button({ label: 'Отменить', kind: 'ghost', onClick: () => cancel() });
    const saveBtn = ui.button({ label: 'Сохранить', kind: 'primary', icon: 'check', busyKey: SAVE_KEY, onClick: () => save() });
    const actions = h('div', { class: 'form-actions vc-form-actions' }, dirtyText, h('span', { class: 'spacer' }), cancelBtn.el, saveBtn.el);

    const section = (iconName, title, ...children) => h('div', { class: 'subsection' },
      h('h3', { class: 'subsection__title' }, icon(iconName, { size: 18 }), title), children);

    const el = h('div', { class: 'vc-more-form' },
      section('plug', 'Локальный прокси',
        h('div', { class: 'form-grid vc-form-grid--port' }, c.port.el),
        h('div', { class: 'settings-list' }, c.local_auth.el, authBox, c.socks_udp.el, c.allow_lan.el)),
      h('div', { class: 'divider', 'aria-hidden': 'true' }),
      section('globe', 'DNS и адреса',
        h('div', { class: 'form-grid form-grid--2' }, c.dns_remote.el, c.dns_direct.el),
        h('div', { class: 'settings-list' }, c.fakeip.el, c.ip_strategy.el, c.ipv6.el)),
      h('div', { class: 'divider', 'aria-hidden': 'true' }),
      section('vpn', 'Весь трафик (TUN) и системный прокси',
        h('div', { class: 'form-grid vc-form-grid--port' }, c.tun_mtu.el),
        h('div', { class: 'form-grid form-grid--2' }, c.exclude_nets.el, c.proxy_override.el),
        h('div', { class: 'settings-list' }, c.kill_switch.el, c.on_sleep.el)),
      h('div', { class: 'divider', 'aria-hidden': 'true' }),
      section('key', 'Маскировка',
        h('div', { class: 'settings-list' }, c.tls_fragment.el, c.mux.el, c.noises.el),
        h('div', { class: 'form-grid vc-form-grid--fp' }, c.fingerprint.el)),
      h('div', { class: 'divider', 'aria-hidden': 'true' }),
      section('refresh', 'Подписки, ядра, журнал и ссылки',
        h('div', { class: 'settings-list' }, c.latency_on_update.el),
        h('div', { class: 'form-grid vc-form-grid--port' }, c.sub_update_hours.el),
        h('div', { class: 'settings-list' }, c.core_auto_update.el, c.verbose.el, c.deeplink.el)),
      actions);

    function currentDraft() {
      const draft = {};
      for (const key of keys) draft[key] = c[key].get();
      return draft;
    }

    /** Все поля формы, разобранные, — для проверки. */
    function values(draft) {
      const out = {};
      for (const key of keys) out[key] = parseValue(key, draft[key]);
      return out;
    }

    /**
     * Что уходит в ядро: логин и пароль — только когда вход по паролю нужен и их поменяли (пустой пароль —
     * «не менять»). Иначе тот же логин выглядел бы изменением и перезапускал VPN на любом сохранении.
     */
    function payload(all) {
      const out = { ...all };
      const auth = wantsAuth(all);
      if (!auth || !baseline || all.local_user === parseValue('local_user', baseline.local_user)) delete out.local_user;
      if (!auth || !all.local_password) delete out.local_password;
      return out;
    }

    function isDirty() {
      return Boolean(baseline) && JSON.stringify(payload(values(currentDraft()))) !== JSON.stringify(payload(values(baseline)));
    }

    function refresh() {
      const draft = currentDraft();
      setHidden(authBox, !(wantsAuth(draft) || authErrorShown));
      c.local_password.input.placeholder = settings.local_password_set ? 'задан — оставьте пустым, чтобы не менять' : '';
      const dirty = isDirty();
      setText(dirtyText, dirty ? 'Есть несохранённые изменения' : 'Изменений нет');
      actions.classList.toggle('is-dirty', dirty);
      cancelBtn.setDisabled(!dirty);
      saveBtn.setDisabled(!dirty);
    }

    for (const key of keys) c[key].watch(refresh);

    function write(draft, force) {
      for (const key of keys) {
        if (key === 'local_password' && !force) continue;
        c[key].set(draft[key] == null ? '' : draft[key], force);
      }
    }

    /** Новые настройки из ядра: нетронутые поля подтягиваем, правки человека оставляем. */
    function merge(next) {
      const incoming = draftFromServer(next);
      if (!baseline) {
        baseline = incoming;
        write(incoming, true);
        return;
      }
      const draft = currentDraft();
      for (const key of keys) {
        if (key === 'local_password') continue;
        if (JSON.stringify(parseValue(key, draft[key])) === JSON.stringify(parseValue(key, baseline[key]))) {
          c[key].set(incoming[key] == null ? '' : incoming[key], false);
        }
      }
      baseline = incoming;
    }

    function clearErrors() {
      for (const key of keys) c[key].setError(null);
      authErrorShown = false;
    }

    function showErrors(errors) {
      let first = null;
      for (const key of keys) {
        const message = errors[key] || null;
        c[key].setError(message);
        if (message && !first) first = key;
      }
      authErrorShown = Boolean(errors.local_user || errors.local_password);
      refresh();
      if (first) c[first].focus();
      return Boolean(first);
    }

    function cancel() {
      write(baseline, true);
      clearErrors();
      refresh();
    }

    async function save() {
      const all = values(currentDraft());
      if (showErrors(validate(all, settings))) {
        ui.toast({ kind: 'error', text: 'Проверьте поля, отмеченные красным.' });
        return;
      }
      const out = payload(all);
      const result = await Lz.api.run({
        method: 'vpnclient_save_settings',
        args: [out],
        key: SAVE_KEY,
        success: (reply) => reply.message || 'Настройки своего VPN сохранены',
      });
      if (!result) return;
      if (!result.ok) {
        if (result.errors) showErrors(result.errors);
        return;
      }
      c.local_password.set('', true);
      baseline = draftFromServer({ ...settings, ...out, local_password_set: settings.local_password_set || Boolean(out.local_password) });
      clearErrors();
      refresh();
    }

    return {
      el,
      update(nextSettings) {
        const key = JSON.stringify(nextSettings);
        if (key !== serverKey) {
          serverKey = key;
          settings = nextSettings;
          merge(nextSettings);
        }
        refresh();
      },
    };
  }

  /* ---------- Резервная копия ---------- */

  async function backup(kind) {
    const password = await dialogs.backupPassword(kind);
    if (password == null) return;
    const exporting = kind === 'export';
    await Lz.api.run({
      method: exporting ? 'vpnclient_backup_export' : 'vpnclient_backup_import',
      args: [password],
      key: `vpnclient_backup_${kind}`,
      /* Окно выбора файла закрыли — ядро отвечает {ok, cancelled}: молчим. */
      success: (reply) => (reply.cancelled ? '' : reply.message || (exporting ? 'Резервная копия сохранена' : 'Резервная копия восстановлена')),
    });
  }

  function createBackup() {
    const exportBtn = ui.button({ label: 'Экспорт…', icon: 'upload', size: 'sm', busyKey: 'vpnclient_backup_export', onClick: () => backup('export') });
    const importBtn = ui.button({ label: 'Импорт…', icon: 'download', size: 'sm', busyKey: 'vpnclient_backup_import', onClick: () => backup('import') });
    return h('div', { class: 'subsection' },
      h('h3', { class: 'subsection__title' }, icon('lock', { size: 18 }), 'Резервная копия'),
      h('p', { class: 'subsection__text', text: 'Подписки, серверы, группы и настройки своего VPN — в файл, зашифрованный вашим паролем. Пригодится при переустановке Windows или переезде на другой компьютер.' }),
      h('div', { class: 'subsection__foot' }, exportBtn.el, importBtn.el));
  }

  /* ---------- Ядра ---------- */

  function hhmm(seconds) {
    const at = new Date(Number(seconds) * 1000);
    return `${String(at.getHours()).padStart(2, '0')}:${String(at.getMinutes()).padStart(2, '0')}`;
  }

  /*
   * Что с ядром: ставится (первая подкачка или обновление рядом с работающей версией), не скачалось
   * (с причиной и временем повтора), не установлено или установлено — какой версии, автоматически ли и
   * работает ли VPN ещё на прежней.
   */
  function coreStatus(name, core) {
    const info = texts.VPNC_CORES[name];
    if (texts.VPNC_CORE_ACTIVE.has(core.state)) {
      return core.installed
        ? `${core.version} · обновление: ${CORE_STATE_TEXT[core.state]}…`
        : `${info.version} · ${CORE_STATE_TEXT[core.state]}…`;
    }
    if (core.state === 'error') {
      const reason = core.message ? String(core.message) : CORE_STATE_TEXT.error;
      return core.retry_at ? `${reason} Повторим в ${hhmm(core.retry_at)}.` : reason;
    }
    if (!core.installed) {
      if (name === 'xray' && core.needed === false) return `не установлен · скачается с GitHub при запуске Лазейки (${fmt.bytes(info.size)}), пока не нужен ни одному серверу`;
      return `не установлено · скачается с GitHub при запуске Лазейки (${fmt.bytes(info.size)})`;
    }
    const parts = [`${core.version || info.version} · установлено${core.auto_updated ? ' автоматически' : ''}`];
    if (core.in_use && core.version && core.in_use !== core.version) parts.push(`сейчас работает ${core.in_use}, новая — со следующего подключения`);
    return parts.join(' · ');
  }

  function installCore(name) {
    Lz.api.run({ method: 'vpnclient_core_install', args: [name], key: `vpnclient_core_install:${name}` });
  }

  function renderCore(data) {
    const { name, core, update } = data;
    const info = texts.VPNC_CORES[name];
    const active = texts.VPNC_CORE_ACTIVE.has(core.state);
    let progress = null;
    if (active) {
      const bar = ui.progressBar({ label: core.installed ? `Обновление: ${info.title}` : `Установка: ${info.title}` });
      bar.set(core.state === 'downloading' && core.progress != null ? core.progress : null);
      progress = h('div', { class: 'vc-core__progress' }, core.message ? h('p', { class: 'muted small', text: core.message }) : null, bar.el);
    }
    const buttons = [];
    if (!active && (!core.installed || core.state === 'error')) {
      buttons.push(ui.button({
        label: core.state === 'error' ? 'Скачать ещё раз' : 'Скачать',
        icon: 'download',
        size: 'sm',
        busyKey: `vpnclient_core_install:${name}`,
        onClick: () => installCore(name),
      }).el);
    }
    if (!active && core.installed && update && update.available && !update.skipped) {
      buttons.push(ui.actionButton({
        method: 'updates_install',
        args: [update.id],
        key: `updates_install:${update.id}`,
        label: `Обновить ядро до ${update.latest}`,
        icon: 'download',
        size: 'sm',
        kind: 'primary',
      }).el);
    } else if (!active && core.installed) {
      buttons.push(ui.button({
        label: 'Обновления ядра',
        icon: 'refresh',
        size: 'sm',
        kind: 'ghost',
        title: data.auto ? 'Ядро обновляется само; версии и «Откатить» — на странице «Обновления»' : 'Проверить новую версию на странице «Обновления»',
        onClick: () => Lz.nav.go('updates'),
      }).el);
    }
    buttons.push(ui.button({
      label: 'Исходный код',
      iconRight: 'external',
      kind: 'link',
      size: 'sm',
      busyKey: 'open_url',
      title: info.source,
      onClick: () => Lz.actions.openUrl(info.source),
    }).el);
    buttons.forEach((btn, index) => { btn.dataset.fk = `core:${name}:${index}`; });
    return h('div', { class: 'vc-core' },
      h('div', { class: 'vc-core__head' },
        h('div', { class: 'vc-core__titles' },
          h('p', { class: 'vc-core__title', text: info.title }),
          h('p', { class: ['vc-core__status', core.state === 'error' && 'is-error'], text: coreStatus(name, core) })),
        h('span', { class: 'tag', text: info.license })),
      h('p', { class: 'vc-core__note', text: info.note }),
      core.note && !active ? h('p', { class: 'muted small vc-core__result', text: core.note }) : null,
      progress,
      h('div', { class: 'subsection__foot' }, buttons));
  }

  function createCores() {
    const slots = Object.keys(texts.VPNC_CORES).map((name) => ({ name, slot: ui.slot(renderCore) }));
    const el = h('div', { class: 'subsection' },
      h('h3', { class: 'subsection__title' }, icon('server', { size: 18 }), 'Ядра'),
      h('p', { class: 'subsection__text', text: 'Своего ядра у Лазейки нет: соединение держат официальные сборки sing-box и Xray — отдельными программами, без изменений. Лазейка скачивает их с GitHub при запуске, сверяет SHA-256 перед установкой и перед каждым запуском и обновляет сама (выключается выше, в «Подписки, ядра, журнал и ссылки»).' }),
      h('div', { class: 'vc-cores' }, slots.map((item) => item.slot.el)),
      h('p', { class: 'licence', text: 'sing-box распространяется по GPL-3.0-or-later, Xray-core — по MPL-2.0, Wintun — по лицензии WireGuard LLC. Исходный код — по ссылкам выше, на страницах этих проектов. Текст GPL-3.0 лежит рядом с установленным sing-box. Лазейка не связана с этими проектами и не одобрена ими.' }));
    return {
      el,
      update(state) {
        const snap = view.snapshot(state);
        const items = state.updates && Array.isArray(state.updates.items) ? state.updates.items : [];
        for (const item of slots) {
          const core = snap.cores[item.name] && typeof snap.cores[item.name] === 'object' ? snap.cores[item.name] : {};
          const update = items.find((entry) => entry.id === CORE_UPDATE_ID[item.name]) || null;
          item.slot.update({
            name: item.name,
            auto: snap.settings.core_auto_update !== false,
            core: {
              installed: Boolean(core.installed), version: core.version || null, in_use: core.in_use || null,
              auto_updated: Boolean(core.auto_updated), needed: core.needed !== false, state: core.state || 'idle',
              progress: core.progress == null ? null : Number(core.progress), message: core.message ? String(core.message) : null,
              retry_at: Number(core.retry_at) > 0 ? Number(core.retry_at) : null, note: core.note ? String(core.note) : null,
            },
            update: update ? { id: update.id, available: Boolean(update.available), skipped: Boolean(update.skipped), latest: update.latest || '' } : null,
          });
        }
      },
    };
  }

  /* ---------- Раздел ---------- */

  function createMoreSection() {
    const form = createSettingsForm();
    const cores = createCores();
    const content = h('div', { class: 'advanced vc-more' },
      form.el,
      createBackup(),
      h('div', { class: 'divider', 'aria-hidden': 'true' }),
      cores.el);
    const disclosure = ui.disclosure({ title: 'Подробнее', content, cls: 'disclosure--section' });
    return {
      el: h('section', { class: 'section-disclosure' }, disclosure.el),
      open() {
        disclosure.setOpen(true);
      },
      update(state) {
        const snap = view.snapshot(state);
        form.update(snap.settings);
        cores.update(state);
        const failed = Object.values(snap.cores).some((core) => core && core.state === 'error');
        disclosure.setBadge(failed ? 'ядро не скачалось' : '', 'err');
      },
    };
  }

  Lz.vcSections = Object.assign(Lz.vcSections || {}, { createMoreSection });
})(window.Lz);
