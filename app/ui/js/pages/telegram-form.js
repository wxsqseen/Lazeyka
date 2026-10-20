'use strict';
/*
 * Форма настроек tg-ws-proxy. Черновик живёт отдельно от снимка ядра:
 * опрос не трогает поля, которые пользователь уже поменял, а нетронутые — подтягивает.
 */
(function (Lz) {
  const { h, icon, uid, setText } = Lz.dom;
  const ui = Lz.ui;

  const PORT_MAX = 65535;
  const SECRET_PATTERN = /^[0-9a-f]{32}$/i;
  /* Ключ из карточки «Подключение» и из ссылки tg://proxy — с приставкой dd (или ee): в поле — без неё. */
  const PREFIXED_SECRET = /^(?:dd|ee)([0-9a-f]{32})/i;
  const SECRET_INPUT_MAX = 128;
  /* Те же границы, что у ядра (tgproxy/manager.py): пул 0–32 соединений, буфер 4–4096 КБ. */
  const POOL_MIN = 0;
  const POOL_MAX = 32;
  const BUF_MIN = 4;
  const BUF_MAX = 4096;
  const DC_LINE_PATTERN = /^\d+:\S+$/;
  const DOMAIN_PATTERN = /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;
  const INTEGER_PATTERN = /^\d+$/;
  const TEXT_KEYS = ['host', 'port', 'secret', 'dc_ip', 'cf_domains', 'worker_domains', 'pool_size', 'buf_kb'];
  const LIST_KEYS = new Set(['dc_ip', 'cf_domains', 'worker_domains']);
  const NUMBER_KEYS = new Set(['port', 'pool_size', 'buf_kb']);
  const FLAG_KEYS = ['cfproxy', 'h2', 'cf_domains_enabled', 'worker_enabled', 'zapret_sync', 'no_secure', 'verbose'];
  /* Флаги, которые ядро считает включёнными, если в настройках их ещё нет. */
  const FLAG_DEFAULTS = { zapret_sync: true };

  function splitLines(text) {
    return String(text || '').split(/[\r\n,;]+/).map((line) => line.trim()).filter(Boolean);
  }

  /** Снимок ядра → черновик формы (всё текстовое — строками, списки — построчно). */
  function draftFromServer(settings) {
    const source = settings || {};
    const draft = {};
    for (const key of TEXT_KEYS) {
      const value = source[key];
      if (LIST_KEYS.has(key)) draft[key] = Array.isArray(value) ? value.join('\n') : String(value || '');
      else draft[key] = value == null ? '' : String(value);
    }
    for (const key of FLAG_KEYS) draft[key] = source[key] == null ? Boolean(FLAG_DEFAULTS[key]) : Boolean(source[key]);
    return draft;
  }

  /** Черновик → значения для tg_save_settings. */
  function valuesFromDraft(draft) {
    const values = {};
    for (const key of TEXT_KEYS) {
      const raw = String(draft[key] || '').trim();
      if (LIST_KEYS.has(key)) values[key] = splitLines(raw);
      else if (NUMBER_KEYS.has(key)) values[key] = INTEGER_PATTERN.test(raw) ? Number(raw) : raw;
      else values[key] = key === 'secret' ? raw.toLowerCase() : raw;
    }
    for (const key of FLAG_KEYS) values[key] = Boolean(draft[key]);
    return values;
  }

  function sameValues(a, b) {
    return JSON.stringify(valuesFromDraft(a)) === JSON.stringify(valuesFromDraft(b));
  }

  function validate(values) {
    const errors = {};
    if (!values.host) errors.host = 'Укажите адрес, например 127.0.0.1';
    if (!Number.isInteger(values.port) || values.port < 1 || values.port > PORT_MAX) {
      errors.port = `Порт — целое число от 1 до ${PORT_MAX}`;
    }
    if (!SECRET_PATTERN.test(values.secret)) errors.secret = 'Ключ — ровно 32 символа: цифры и буквы a–f';
    const badDc = values.dc_ip.find((line) => !DC_LINE_PATTERN.test(line));
    if (badDc) errors.dc_ip = `Строка «${badDc}» не в формате номер:адрес, например 2:149.154.167.220`;
    const badCf = values.cf_domains_enabled ? values.cf_domains.find((d) => !DOMAIN_PATTERN.test(d)) : null;
    if (badCf) errors.cf_domains = `«${badCf}» не похоже на домен`;
    if (values.cf_domains_enabled && !values.cf_domains.length) errors.cf_domains = 'Добавьте хотя бы один домен или выключите свои домены';
    const badWorker = values.worker_enabled ? values.worker_domains.find((d) => !DOMAIN_PATTERN.test(d)) : null;
    if (badWorker) errors.worker_domains = `«${badWorker}» не похоже на домен`;
    if (values.worker_enabled && !values.worker_domains.length) errors.worker_domains = 'Укажите домен воркера, например name.workers.dev';
    if (!Number.isInteger(values.pool_size) || values.pool_size < POOL_MIN || values.pool_size > POOL_MAX) {
      errors.pool_size = `Целое число от ${POOL_MIN} до ${POOL_MAX}`;
    }
    if (!Number.isInteger(values.buf_kb) || values.buf_kb < BUF_MIN || values.buf_kb > BUF_MAX) {
      errors.buf_kb = `Целое число от ${BUF_MIN} до ${BUF_MAX}`;
    }
    return errors;
  }

  function create() {
    let server = null;
    let baseline = null;
    let draft = null;
    let secretVisible = false;
    const fields = {};
    const inputs = {};
    const switches = {};

    /* --- построение полей --- */

    function onTextInput(key, value) {
      if (!draft) return;
      let text = value;
      if (key === 'secret') {
        /* Вставили ключ из карточки или ссылки (dd + 32 символа) — оставляем сам ключ, а не обрезаем хвост. */
        const match = PREFIXED_SECRET.exec(String(value).trim());
        if (match) {
          text = match[1];
          inputs.secret.value = text;
        }
      }
      draft[key] = text;
      fields[key].setError(null);
      refresh();
    }

    function textField(key, label, opts) {
      const options = opts || {};
      const id = uid(`tg-${key}`);
      const control = options.multiline
        ? ui.textArea({ id, rows: options.rows || 3, placeholder: options.placeholder, onInput: (v) => onTextInput(key, v) })
        : ui.textInput({ id, mono: options.mono, placeholder: options.placeholder, inputMode: options.inputMode, maxLength: options.maxLength, onInput: (v) => onTextInput(key, v) });
      inputs[key] = control;
      const wrapped = options.addon ? h('div', { class: 'input-group' }, control, options.addon) : control;
      fields[key] = ui.field({ label, hint: options.hint, control: wrapped, inputId: id, cls: options.cls });
      return fields[key].el;
    }

    function flagRow(key, title, description) {
      const row = ui.switchRow({
        title,
        description,
        checked: false,
        onChange: (value) => {
          if (draft) draft[key] = value;
          refresh();
          return true;
        },
      });
      switches[key] = row.sw;
      return row.el;
    }

    const secretToggle = ui.button({
      icon: 'eye',
      kind: 'ghost',
      size: 'sm',
      ariaLabel: 'Показать ключ',
      title: 'Показать',
      onClick: () => {
        secretVisible = !secretVisible;
        renderSecretVisibility();
      },
    });
    const regenBtn = ui.actionButton({
      method: 'tg_regen_secret',
      label: 'Сгенерировать новый',
      icon: 'refresh',
      size: 'sm',
      success: 'Новый ключ готов. Подключите Telegram заново.',
      confirm: {
        title: 'Сгенерировать новый ключ?',
        text: 'Старая ссылка перестанет работать: Telegram нужно будет подключить заново кнопкой «Подключить Telegram».',
        confirmLabel: 'Сгенерировать',
        tone: 'danger',
        icon: 'key',
      },
    });

    const connection = h('div', { class: 'form-grid form-grid--3' },
      textField('host', 'Адрес', { mono: true, placeholder: '127.0.0.1', hint: 'Обычно 127.0.0.1 — только этот компьютер.' }),
      textField('port', 'Порт', { mono: true, placeholder: '1443', inputMode: 'numeric', maxLength: 5 }),
      textField('secret', 'Ключ (secret)', {
        mono: true,
        maxLength: SECRET_INPUT_MAX,
        addon: secretToggle.el,
        cls: 'field--secret',
        hint: '32 символа: цифры и буквы a–f. В Telegram он вводится с приставкой dd — вставленный с ней ключ Лазейка примет без неё.',
      }));
    const regenRow = h('div', { class: 'regen' },
      icon('alert', { size: 16, cls: 'regen__icon' }),
      h('p', { class: 'regen__text', text: 'Новый ключ отключит Telegram от прокси до повторного подключения.' }),
      regenBtn.el);

    const dcBlock = textField('dc_ip', 'Адреса дата-центров', {
      multiline: true,
      rows: 3,
      placeholder: '2:149.154.167.220',
      hint: 'Номер DC и IP через двоеточие, по одному на строку. Если не уверены — оставьте как есть.',
    });

    const cloudflare = h('div', { class: 'form-group' },
      flagRow('cfproxy', 'Запасной путь через Cloudflare', 'Если прямое подключение к Telegram не проходит, трафик пойдёт через Cloudflare.'),
      h('div', { class: 'form-nested' },
        flagRow('h2', 'HTTP/2 для медиа', 'Быстрее грузит фото и видео через Cloudflare.'),
        flagRow('cf_domains_enabled', 'Свои домены Cloudflare', 'Вместо встроенного списка доменов.'),
        textField('cf_domains', 'Домены', { multiline: true, rows: 2, placeholder: 'example.com', hint: 'По одному на строку.' })));

    const worker = h('div', { class: 'form-group' },
      flagRow('worker_enabled', 'Cloudflare Worker', 'Свой воркер на Cloudflare как ещё один запасной путь.'),
      h('div', { class: 'form-nested' },
        textField('worker_domains', 'Домены воркера', { multiline: true, rows: 2, placeholder: 'name.workers.dev', hint: 'По одному на строку.' })));

    const zapretSync = h('div', { class: 'form-group' },
      flagRow('zapret_sync', 'Согласовывать с обходом (zapret)',
        'Лазейка сама добавляет домены Cloudflare-маршрутов прокси в списки обхода — так фото и видео в Telegram не ломаются при включённом обходе.'));

    const advancedContent = h('div', { class: 'advanced' },
      h('div', { class: 'form-grid form-grid--2' },
        textField('pool_size', 'Размер пула соединений', { mono: true, inputMode: 'numeric', maxLength: 2, hint: 'Сколько соединений держать заранее: от 0 до 32. По умолчанию 4.' }),
        textField('buf_kb', 'Буфер, КБ', { mono: true, inputMode: 'numeric', maxLength: 4, hint: 'От 4 до 4096. По умолчанию 256.' })),
      flagRow('no_secure', 'Отключить защищённый режим', 'Только для отладки: прокси примет клиентов без проверки ключа.'),
      flagRow('verbose', 'Подробный журнал', 'Пишет в журнал каждую операцию — пригодится для отчёта об ошибке.'));
    const advanced = ui.disclosure({ title: 'Дополнительно', content: advancedContent });

    const dirtyText = h('span', { class: 'form-actions__text' });
    const cancelBtn = ui.button({ label: 'Отменить', kind: 'ghost', onClick: () => cancel() });
    const saveBtn = ui.button({ label: 'Сохранить', kind: 'primary', icon: 'check', busyKey: 'tg_save_settings', onClick: () => save() });
    const actionsBar = h('div', { class: 'form-actions' }, dirtyText, h('span', { class: 'spacer' }), cancelBtn.el, saveBtn.el);

    const card = ui.card({
      title: 'Настройки прокси',
      subtitle: 'После сохранения прокси перезапустится. Telegram переподключится сам, если не менялись адрес, порт и ключ.',
    });
    card.body.append(
      connection,
      regenRow,
      dcBlock,
      h('div', { class: 'divider', 'aria-hidden': 'true' }),
      cloudflare,
      worker,
      zapretSync,
      h('div', { class: 'card__disclosure' }, advanced.el),
      actionsBar);

    /* --- синхронизация --- */

    function renderSecretVisibility() {
      inputs.secret.classList.toggle('is-masked', !secretVisible);
      secretToggle.setIcon(secretVisible ? 'eyeOff' : 'eye');
      secretToggle.el.setAttribute('aria-label', secretVisible ? 'Скрыть ключ' : 'Показать ключ');
      secretToggle.el.title = secretVisible ? 'Скрыть' : 'Показать';
    }

    function writeControls(force) {
      for (const key of TEXT_KEYS) {
        if (force) inputs[key].value = draft[key];
        else ui.syncValue(inputs[key], draft[key]);
      }
      for (const key of FLAG_KEYS) switches[key].set(draft[key]);
    }

    function isDirty() {
      return Boolean(draft && baseline) && !sameValues(draft, baseline);
    }

    function refresh() {
      if (!draft) return;
      const dirty = isDirty();
      const cfOn = draft.cfproxy;
      switches.h2.setDisabled(!cfOn);
      switches.cf_domains_enabled.setDisabled(!cfOn);
      fields.cf_domains.el.classList.toggle('is-muted', !(cfOn && draft.cf_domains_enabled));
      inputs.cf_domains.disabled = !(cfOn && draft.cf_domains_enabled);
      fields.worker_domains.el.classList.toggle('is-muted', !draft.worker_enabled);
      inputs.worker_domains.disabled = !draft.worker_enabled;
      setText(dirtyText, dirty ? 'Есть несохранённые изменения' : 'Изменений нет');
      actionsBar.classList.toggle('is-dirty', dirty);
      cancelBtn.setDisabled(!dirty);
      saveBtn.setDisabled(!dirty);
    }

    function clearErrors() {
      for (const key of TEXT_KEYS) fields[key].setError(null);
    }

    function showErrors(errors) {
      let first = null;
      for (const key of TEXT_KEYS) {
        const message = errors[key] || null;
        fields[key].setError(message);
        if (message && !first) first = key;
      }
      if (first && (first === 'pool_size' || first === 'buf_kb')) advanced.setOpen(true);
      if (first) inputs[first].focus();
    }

    /** Ядро прислало новые настройки: нетронутые поля обновляем, правки пользователя сохраняем. */
    function merge(nextServer) {
      const incoming = draftFromServer(nextServer);
      if (!draft) {
        draft = { ...incoming };
        baseline = incoming;
        writeControls(true);
        return;
      }
      for (const key of [...TEXT_KEYS, ...FLAG_KEYS]) {
        if (draft[key] === baseline[key]) draft[key] = incoming[key];
      }
      baseline = incoming;
      writeControls(false);
    }

    function cancel() {
      draft = { ...baseline };
      writeControls(true);
      clearErrors();
      refresh();
    }

    async function save() {
      const values = valuesFromDraft(draft);
      const errors = validate(values);
      if (Object.keys(errors).length) {
        showErrors(errors);
        ui.toast({ kind: 'error', text: 'Проверьте поля, отмеченные красным.' });
        return;
      }
      clearErrors();
      const result = await Lz.api.run({ method: 'tg_save_settings', args: [values], success: 'Настройки прокси сохранены' });
      if (!result) return;
      if (!result.ok) {
        if (result.errors) showErrors(result.errors);
        return;
      }
      baseline = draftFromServer(values);
      draft = { ...baseline };
      writeControls(false);
      refresh();
    }

    renderSecretVisibility();

    return {
      el: card.el,
      update(state) {
        const next = state.tg_settings || {};
        const key = JSON.stringify(next);
        if (key !== server) {
          server = key;
          merge(next);
        }
        refresh();
      },
    };
  }

  Lz.telegramForm = { create, validate, valuesFromDraft, draftFromServer };
})(window.Lz);
