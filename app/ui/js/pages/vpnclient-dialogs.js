'use strict';
/*
 * Свой VPN: окна страницы — QR-код, переименование сервера, свойства подписки, пароль
 * резервной копии и выбор программы из запущенных. Секреты (ссылки, ключи) окна не видят:
 * QR рисует ядро по явному нажатию, ссылку в буфер кладёт тоже ядро.
 */
(function (Lz) {
  const { h, icon, uid, setText, setHidden } = Lz.dom;
  const ui = Lz.ui;
  const texts = Lz.texts;

  const NAME_MAX = 64;
  const UA_MAX = 256;
  const PASSWORD_MIN = 8;
  const UPDATE_HOURS_MIN = 1;
  const UPDATE_HOURS_MAX = 72;
  const DEFAULT_UPDATE_HOURS = 12;
  /* Свой MTU подписки — как SUB_MTU в ядре; общий MTU адаптера в «Подробнее» — от 1280 (с IPv6 меньше нельзя). */
  const SUB_MTU_MIN = 576;
  const MTU_MAX = 9000;
  /* DNS — как его понимает ядро (manager._dns): auto, имя резолвера или адрес https://…/dns-query до 200 символов. */
  const DNS_OPTIONS = [
    { value: 'auto', label: 'Автоматически' },
    { value: 'cloudflare', label: 'Cloudflare' },
    { value: 'google', label: 'Google' },
    { value: 'quad9', label: 'Quad9' },
    { value: 'adguard', label: 'AdGuard' },
    { value: 'yandex', label: 'Яндекс' },
    { value: 'custom', label: 'Свой адрес https://' },
  ];
  const DNS_CUSTOM = 'custom';
  const DNS_URL_MAX = 200;
  const DOH_URL = /^https:\/\/[^\s/?#]+([/?#]\S*)?$/;
  const APPS_TIMEOUT_MS = 8000;
  const PNG_DATA_URL = /^data:image\/png;base64,[A-Za-z0-9+/=]+$/;
  const PRINTABLE_ASCII = /^[\x20-\x7E]*$/;
  const EXE_NAME = /\.exe$/i;

  /**
   * Окно с формой: onSubmit() → Promise<boolean>, true — закрыть. Enter в однострочном поле
   * отправляет форму; пока идёт вызов, кнопка показывает загрузку.
   */
  function formDialog({ title, text, iconName, body, submitLabel, onSubmit, initialFocus, cls, danger }) {
    const titleId = uid('vc-dlg-title');
    const textId = text ? uid('vc-dlg-text') : null;
    let modal = null;
    let busy = false;

    const cancel = ui.button({ label: 'Отмена', onClick: () => modal.close() });
    const submit = ui.button({
      label: submitLabel,
      kind: danger ? 'danger' : 'primary',
      onClick: () => send(),
    });

    async function send() {
      if (busy) return;
      busy = true;
      submit.setBusy(true);
      try {
        if (await onSubmit()) modal.close();
      } finally {
        busy = false;
        submit.setBusy(false);
      }
    }

    const content = h('div', { class: 'dialog vc-form-dialog' },
      iconName ? h('div', { class: 'dialog__icon', 'aria-hidden': 'true' }, icon(iconName, { size: 22 })) : null,
      h('h2', { class: 'dialog__title', id: titleId, text: title }),
      text ? h('p', { class: 'dialog__text', id: textId, text }) : null,
      h('div', { class: 'vc-form-dialog__body' }, body),
      h('div', { class: 'dialog__actions' }, cancel.el, submit.el));
    content.addEventListener('keydown', (event) => {
      if (event.key === 'Enter' && event.target instanceof HTMLInputElement && event.target.type !== 'checkbox') {
        event.preventDefault();
        send();
      }
    });
    modal = ui.openModal({
      content,
      labelledBy: titleId,
      describedBy: textId,
      cls: ['modal--dialog', cls].filter(Boolean).join(' '),
      onEscape: () => modal.close(),
      initialFocus: initialFocus || submit.el,
    });
    return modal;
  }

  function inputField(label, opts) {
    const options = opts || {};
    const id = uid('vc-field');
    const input = ui.textInput({
      id,
      mono: options.mono,
      placeholder: options.placeholder,
      maxLength: options.maxLength,
      inputMode: options.inputMode,
    });
    if (options.type) input.type = options.type;
    if (options.value != null) input.value = String(options.value);
    const field = ui.field({ label, hint: options.hint, control: input, inputId: id, cls: options.cls });
    input.addEventListener('input', () => field.setError(null));
    return { input, field, el: field.el };
  }

  /* ---------- DNS: резолвер из списка или свой адрес ---------- */

  /**
   * Выбор DNS для «Подробнее» и свойств подписки. inherit — подпись первого пункта «как в общих
   * настройках» (значение ''); onChange — смена пункта или ввод своего адреса.
   */
  function dnsChoice({ id, label, inherit, onChange }) {
    const select = ui.selectControl({
      id,
      onChange: () => {
        sync();
        if (onChange) onChange();
        if (isCustom()) custom.focus();
        return true;
      },
    });
    select.setOptions([...(inherit ? [{ value: '', label: inherit }] : []), ...DNS_OPTIONS]);
    const custom = ui.textInput({ mono: true, placeholder: 'https://dns.example/dns-query', maxLength: DNS_URL_MAX, label: `${label}: свой адрес` });
    custom.addEventListener('input', () => {
      if (onChange) onChange();
    });

    function isCustom() {
      return select.select.value === DNS_CUSTOM;
    }

    function sync() {
      setHidden(custom, !isCustom());
    }
    sync();

    return {
      el: h('div', { class: 'vc-dns' }, select.el, custom),
      /* Пустой свой адрес — «https://»: его отвергнет dnsError, а не молча заменит общий DNS. */
      get: () => (isCustom() ? custom.value.trim() || 'https://' : select.select.value),
      set: (value, force) => {
        const text = String(value || (inherit ? '' : 'auto'));
        const own = text.startsWith('https://');
        if (force || document.activeElement !== select.select) select.select.value = own ? DNS_CUSTOM : text;
        if (own) {
          if (force) custom.value = text;
          else ui.syncValue(custom, text);
        }
        sync();
      },
      focus: () => (isCustom() ? custom.focus() : select.select.focus()),
    };
  }

  /** Свой адрес DNS через HTTPS — та же проверка, что в ядре; имена из списка и '' не проверяются. */
  function dnsError(value) {
    const text = String(value || '');
    if (!text.startsWith('https://')) return null;
    return text.length <= DNS_URL_MAX && DOH_URL.test(text) ? null : 'Адрес DNS через HTTPS, например https://dns.example/dns-query';
  }

  /* ---------- QR-код ---------- */

  /** QR ссылки сервера или подписки — для телефона или ТВ. Рисует ядро: в коде ключ доступа. */
  async function showQr({ id, title }) {
    const result = await Lz.api.run({ method: 'vpnclient_qr', args: [id], key: `vpnclient_qr:${id}` });
    if (!result || !result.ok) return;
    const png = String(result.png || '');
    if (!PNG_DATA_URL.test(png)) {
      ui.toast({ kind: 'error', text: 'Ядро вернуло QR-код в неожиданном виде — показать его не получится.' });
      return;
    }
    const titleId = uid('vc-qr-title');
    let modal = null;
    const close = ui.button({ label: 'Закрыть', kind: 'primary', onClick: () => modal.close() });
    const content = h('div', { class: 'dialog vc-qr' },
      h('h2', { class: 'dialog__title', id: titleId, text: title }),
      h('p', { class: 'dialog__text', text: 'Наведите камеру телефона или телевизора с VPN-клиентом.' }),
      h('div', { class: 'vc-qr__frame' }, h('img', { class: 'vc-qr__img', src: png, alt: `QR-код: ${title}`, width: 240, height: 240 })),
      h('p', { class: 'dialog__details' }, icon('alert', { size: 14, cls: 'vc-qr__warn' }),
        'В коде — ключ доступа к серверу. Не показывайте его посторонним и не выкладывайте снимок.'),
      h('div', { class: 'dialog__actions' }, close.el));
    modal = ui.openModal({ content, labelledBy: titleId, cls: 'modal--dialog modal--vc-qr', onEscape: () => modal.close(), initialFocus: close.el });
  }

  /* ---------- Переименование сервера ---------- */

  function renameServer(server) {
    const name = inputField('Название', { value: server.name || '', maxLength: NAME_MAX });
    formDialog({
      title: 'Переименовать сервер',
      text: 'Своё имя сохранится и после обновления подписки.',
      iconName: 'edit',
      body: name.el,
      submitLabel: 'Сохранить',
      initialFocus: name.input,
      onSubmit: async () => {
        const value = name.input.value.trim();
        if (!value) {
          name.field.setError('Введите название');
          return false;
        }
        const result = await Lz.api.run({
          method: 'vpnclient_server_rename',
          args: [server.id, value],
          key: `vpnclient_server_rename:${server.id}`,
          success: 'Сервер переименован',
          silent: true,
        });
        if (!result) return false;
        if (!result.ok) {
          name.field.setError((result.errors && result.errors.name) || result.error);
          return false;
        }
        return true;
      },
    });
    name.input.select();
  }

  /* ---------- Свойства подписки ---------- */

  /** defaultHours — интервал из общих настроек: старое ядро может не прислать update_hours подписки. */
  function subProperties(sub, defaultHours) {
    const nameField = inputField('Название', { value: sub.name || '', maxLength: NAME_MAX });
    const uaId = uid('vc-ua');
    const uaSelect = ui.selectControl({ id: uaId, onChange: () => syncUa() });
    uaSelect.setOptions(Object.keys(texts.VPNC_UA).map((value) => ({ value, label: texts.VPNC_UA[value] })));
    uaSelect.sync(sub.ua_preset || 'lazeyka');
    const uaPresetField = ui.field({
      label: 'User-Agent',
      hint: 'Как Лазейка представляется панели. Некоторые панели отдают полный формат с группами только «своим» клиентам.',
      control: uaSelect.el,
      inputId: uaId,
    });
    const uaField = inputField('Свой User-Agent', { value: sub.user_agent || '', maxLength: UA_MAX, mono: true, placeholder: 'MyClient/1.0' });
    const hours = inputField('Обновлять каждые, ч', {
      value: sub.update_hours != null ? sub.update_hours : (defaultHours || DEFAULT_UPDATE_HOURS),
      inputMode: 'numeric',
      maxLength: 2,
      mono: true,
      hint: `${UPDATE_HOURS_MIN}–${UPDATE_HOURS_MAX} ч, пока Лазейка запущена.`,
    });
    const dnsId = uid('vc-sub-dns');
    const dns = dnsChoice({ id: dnsId, label: 'DNS через VPN', inherit: 'Как в «Подробнее»', onChange: () => dnsField.setError(null) });
    dns.set(sub.dns || '', true);
    const dnsField = ui.field({
      label: 'DNS через VPN',
      hint: 'Для сайтов через серверы этой подписки: резолвер из списка или свой адрес DNS через HTTPS.',
      control: dns.el,
      inputId: dnsId,
    });
    const mtu = inputField('MTU', {
      value: sub.mtu != null ? sub.mtu : '',
      inputMode: 'numeric',
      maxLength: 4,
      mono: true,
      hint: `Пусто — как в общих настройках. Своё — от ${SUB_MTU_MIN} до ${MTU_MAX}.`,
    });
    const hwid = ui.switchRow({
      title: 'Отправлять идентификатор устройства (HWID)',
      description:
        'Некоторые панели без него не отдают серверы. Лазейка отправит случайный идентификатор этой подписки, а не номер компьютера.',
      checked: Boolean(sub.hwid),
    });
    const routes = ui.switchRow({
      title: 'Маршруты провайдера',
      description: 'Применять правила маршрутизации, если провайдер прислал их в подписке. Свои правила Лазейки остаются важнее.',
      checked: Boolean(sub.provider_routes),
    });
    const formError = h('p', { class: 'field__error', hidden: true });

    function syncUa() {
      const custom = uaSelect.select.value === 'custom';
      uaField.input.disabled = !custom;
      uaField.el.classList.toggle('is-muted', !custom);
    }
    syncUa();

    const fieldByKey = {
      name: nameField.field, ua_preset: uaPresetField, ua: uaField.field, update_hours: hours.field, dns: dnsField, mtu: mtu.field,
    };

    function numberOrNull(raw) {
      const text = String(raw).trim();
      if (!text) return null;
      return /^\d+$/.test(text) ? Number(text) : NaN;
    }

    function validate(values) {
      const errors = {};
      if (!values.name) errors.name = 'Введите название';
      if (values.ua_preset === 'custom') {
        if (!values.ua) errors.ua = 'Укажите User-Agent или выберите готовый';
        else if (!PRINTABLE_ASCII.test(values.ua)) errors.ua = 'Только латиница, цифры и знаки, без переносов строк';
      }
      if (!Number.isInteger(values.update_hours) || values.update_hours < UPDATE_HOURS_MIN || values.update_hours > UPDATE_HOURS_MAX) {
        errors.update_hours = `Целое число от ${UPDATE_HOURS_MIN} до ${UPDATE_HOURS_MAX}`;
      }
      const dnsProblem = dnsError(values.dns);
      if (dnsProblem) errors.dns = dnsProblem;
      if (values.mtu !== null && (!Number.isInteger(values.mtu) || values.mtu < SUB_MTU_MIN || values.mtu > MTU_MAX)) {
        errors.mtu = `Пусто или число от ${SUB_MTU_MIN} до ${MTU_MAX}`;
      }
      return errors;
    }

    function showErrors(errors) {
      let shown = false;
      for (const [key, field] of Object.entries(fieldByKey)) {
        field.setError(errors[key] || null);
        if (errors[key]) shown = true;
      }
      return shown;
    }

    formDialog({
      title: 'Свойства подписки',
      iconName: 'sliders',
      cls: 'modal--vc-wide',
      body: [
        nameField.el,
        h('div', { class: 'vc-form-grid' }, uaPresetField.el, uaField.el),
        h('div', { class: 'settings-list vc-form-dialog__switches' }, hwid.el),
        h('div', { class: 'vc-form-grid' }, hours.el, mtu.el),
        dnsField.el,
        h('div', { class: 'settings-list vc-form-dialog__switches' }, routes.el),
        formError,
      ],
      submitLabel: 'Сохранить',
      initialFocus: nameField.input,
      onSubmit: async () => {
        const values = {
          name: nameField.input.value.trim(),
          ua_preset: uaSelect.select.value,
          hwid: hwid.sw.get(),
          update_hours: numberOrNull(hours.input.value),
          dns: dns.get() || null,
          mtu: numberOrNull(mtu.input.value),
          provider_routes: routes.sw.get(),
        };
        /* Свой User-Agent — только у пресета «Свой»: у остальных поле выключено, и ядро его не ждёт. */
        if (values.ua_preset === 'custom') values.ua = uaField.input.value.trim();
        setHidden(formError, true);
        if (showErrors(validate(values))) return false;
        const result = await Lz.api.run({
          method: 'vpnclient_sub_set',
          args: [sub.id, values],
          key: `vpnclient_sub_set:${sub.id}`,
          success: 'Свойства подписки сохранены',
          silent: true,
        });
        if (!result) return false;
        if (!result.ok) {
          const errors = result.errors || {};
          if (!showErrors(errors)) {
            setText(formError, result.error);
            setHidden(formError, false);
          }
          return false;
        }
        return true;
      },
    });
  }

  /* ---------- Пароль резервной копии ---------- */

  /** Promise<string | null>: пароль, null — человек передумал. kind: 'export' | 'import'. */
  function backupPassword(kind) {
    return new Promise((resolve) => {
      const exporting = kind === 'export';
      const first = inputField('Пароль', { type: 'password', maxLength: 256, hint: exporting ? `Не короче ${PASSWORD_MIN} символов. Без него копию не открыть — восстановить пароль нельзя.` : null });
      const second = exporting ? inputField('Пароль ещё раз', { type: 'password', maxLength: 256 }) : null;
      let answered = false;
      const modal = formDialog({
        title: exporting ? 'Резервная копия своего VPN' : 'Восстановить из резервной копии',
        text: exporting
          ? 'В файл попадут подписки, серверы, группы и настройки VPN. Он шифруется паролем: без пароля его никто не прочитает.'
          : 'Введите пароль, которым копия была зашифрована. Подписки и серверы из неё добавятся к вашим, как при обновлении подписки.',
        iconName: exporting ? 'upload' : 'download',
        body: [first.el, second && second.el],
        submitLabel: exporting ? 'Выбрать файл и сохранить' : 'Выбрать файл',
        initialFocus: first.input,
        onSubmit: async () => {
          const password = first.input.value;
          if (exporting && password.length < PASSWORD_MIN) {
            first.field.setError(`Пароль не короче ${PASSWORD_MIN} символов`);
            return false;
          }
          if (!password) {
            first.field.setError('Введите пароль');
            return false;
          }
          if (second && second.input.value !== password) {
            second.field.setError('Пароли не совпадают');
            return false;
          }
          answered = true;
          resolve(password);
          return true;
        },
      });
      const close = modal.close;
      modal.close = () => {
        close();
        if (!answered) resolve(null);
      };
    });
  }

  /* ---------- Программа из запущенных ---------- */

  /** Promise<string | null>: имя exe выбранной программы. */
  function pickApp({ title }) {
    return new Promise((resolve) => {
      const titleId = uid('vc-apps-title');
      let modal = null;
      let settled = false;
      let apps = null;
      let loadError = null;
      let query = '';

      function finish(value) {
        if (settled) return;
        settled = true;
        modal.close();
        resolve(value);
      }

      const search = h('input', {
        class: 'input input--search',
        type: 'search',
        placeholder: 'Найти программу',
        'aria-label': 'Найти программу',
        autocomplete: 'off',
        spellcheck: false,
      });
      const list = ui.slot((data) => {
        if (data.error) return ui.callout({ tone: 'err', text: data.error });
        if (!data.apps) return h('p', { class: 'muted' }, h('span', { class: 'spinner spinner--inline', 'aria-hidden': 'true' }), 'Смотрим, какие программы запущены…');
        const shown = data.apps.filter((app) => !data.query
          || String(app.name || '').toLowerCase().includes(data.query)
          || String(app.path || '').toLowerCase().includes(data.query));
        if (!shown.length) return ui.emptyState({ icon: 'search', title: 'Ничего не нашлось', text: 'Программа должна быть запущена. Или закройте окно и впишите имя exe вручную.' });
        return h('ul', { class: 'vc-apps' }, shown.map((app) => h('li', null,
          h('button', { type: 'button', class: 'vc-apps__item', dataset: { fk: `app:${app.name}` }, onClick: () => finish(String(app.name)) },
            icon('window', { size: 16 }),
            h('span', { class: 'vc-apps__text' },
              h('span', { class: 'vc-apps__name', text: app.name }),
              app.path ? h('span', { class: 'vc-apps__path mono', text: app.path }) : null)))));
      }, { cls: 'vc-apps-wrap' });
      search.addEventListener('input', () => {
        query = search.value.trim().toLowerCase();
        render();
      });

      function render() {
        list.update({ apps, error: loadError, query });
      }

      const cancel = ui.button({ label: 'Отмена', onClick: () => finish(null) });
      const content = h('div', { class: 'dialog' },
        h('h2', { class: 'dialog__title', id: titleId, text: title }),
        h('p', { class: 'dialog__text', text: 'Выберите программу — правило сработает по имени её exe-файла в режиме «Весь трафик».' }),
        h('div', { class: 'search vc-apps-search' }, icon('search', { size: 16, cls: 'search__icon' }), search),
        list.el,
        h('div', { class: 'dialog__actions' }, cancel.el));
      modal = ui.openModal({ content, labelledBy: titleId, cls: 'modal--dialog modal--vc-wide', onEscape: () => finish(null), initialFocus: search });
      render();

      Lz.api.callWithTimeout('vpnclient_running_apps', APPS_TIMEOUT_MS)
        .then((result) => {
          const raw = result && Array.isArray(result.apps) ? result.apps : [];
          apps = raw.filter((app) => app && EXE_NAME.test(String(app.name || '')));
          if (result && result.ok === false) loadError = result.error || 'Ядро не вернуло список программ.';
        })
        .catch((err) => {
          loadError = `Не получилось узнать запущенные программы: ${Lz.api.describeError(err)}`;
        })
        .finally(render);
    });
  }

  Lz.vcDialogs = { formDialog, inputField, dnsChoice, dnsError, showQr, renameServer, subProperties, backupPassword, pickApp };
})(window.Lz);
