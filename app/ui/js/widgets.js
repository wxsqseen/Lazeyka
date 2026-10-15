'use strict';
/* Общие элементы управления и раскладки. Ничего из данных ядра не идёт в разметку — только в текст. */
(function (Lz) {
  const { h, s, icon, uid, setText, setHidden, setAttr } = Lz.dom;

  const SMALL_ICON = 16;
  const REGULAR_ICON = 18;
  const SECRET_MASK_MAX = 24;

  /* ---------- Кнопка ---------- */

  const buttonControllers = new WeakMap();

  /**
   * Кнопка с состоянием загрузки. busyKey связывает её с вызовом Lz.api.run:
   * пока вызов с этим ключом идёт, кнопка показывает спиннер и не нажимается.
   * Неактивная кнопка остаётся в порядке Tab (aria-disabled), чтобы не терять фокус.
   */
  function button(options) {
    const {
      label, icon: iconName, kind = 'secondary', size, onClick, busyKey, title, ariaLabel, cls, iconRight,
    } = options;
    const iconSize = size === 'sm' ? SMALL_ICON : REGULAR_ICON;
    let iconEl = iconName ? icon(iconName, { size: iconSize }) : null;
    const labelEl = label != null ? h('span', { class: 'btn__label', text: label }) : null;
    const el = h('button', {
      type: 'button',
      class: ['btn', `btn--${kind}`, size && `btn--${size}`, label == null && 'btn--icon', cls],
      title,
      'aria-label': ariaLabel,
      dataset: busyKey ? { busyKey } : null,
    }, h('span', { class: 'spinner', 'aria-hidden': 'true' }), iconEl, labelEl,
    iconRight ? icon(iconRight, { size: iconSize, cls: 'btn__icon-right' }) : null);

    const ctl = { el, busy: false, disabled: false };
    ctl.sync = function sync() {
      const busy = ctl.busy || Boolean(busyKey && Lz.api.isBusy(busyKey));
      el.classList.toggle('is-busy', busy);
      setAttr(el, 'aria-busy', busy);
      setAttr(el, 'aria-disabled', busy || ctl.disabled);
    };
    ctl.setBusy = (value) => { ctl.busy = Boolean(value); ctl.sync(); };
    ctl.setDisabled = (value) => { ctl.disabled = Boolean(value); ctl.sync(); };
    ctl.setLabel = (text) => { if (labelEl) setText(labelEl, text); };
    ctl.setIcon = (name) => {
      const next = icon(name, { size: iconSize });
      if (iconEl) iconEl.replaceWith(next);
      else el.insertBefore(next, labelEl);
      iconEl = next;
    };
    ctl.isInactive = () => el.getAttribute('aria-disabled') === 'true';

    el.addEventListener('click', (event) => {
      if (ctl.isInactive()) {
        event.preventDefault();
        return;
      }
      if (onClick) onClick(event, ctl);
    });
    buttonControllers.set(el, ctl);
    ctl.sync();
    return ctl;
  }

  Lz.api.onBusyChange(() => {
    document.querySelectorAll('[data-busy-key]').forEach((el) => {
      const ctl = buttonControllers.get(el);
      if (ctl) ctl.sync();
    });
  });

  /** Кнопка-действие: вызывает метод ядра с индикацией загрузки. */
  function actionButton(options) {
    const { method, args, success, key, confirm, ...rest } = options;
    const busyKey = key || method;
    return button({
      ...rest,
      busyKey,
      onClick: async () => {
        if (confirm && !(await Lz.ui.confirm(confirm))) return;
        const callArgs = typeof args === 'function' ? args() : (args || []);
        await Lz.api.run({ method, args: callArgs, key: busyKey, success });
      },
    });
  }

  /* ---------- Переключатель ---------- */

  /**
   * role="switch". onChange(value) может вернуть Promise; если он разрешится
   * в false, переключатель вернётся назад. Пока вызов идёт, внешние set() игнорируются,
   * чтобы опрос состояния не «отбрасывал» только что нажатый переключатель.
   */
  function switchControl({ checked = false, onChange, labelledBy, describedBy, label }) {
    const el = h('button', {
      type: 'button',
      class: 'switch',
      role: 'switch',
      'aria-labelledby': labelledBy,
      'aria-describedby': describedBy,
      'aria-label': label,
    }, h('span', { class: 'switch__thumb', 'aria-hidden': 'true' }));
    let value = Boolean(checked);
    let disabled = false;
    let pending = false;

    function render() {
      setAttr(el, 'aria-checked', value);
      setAttr(el, 'aria-disabled', disabled);
    }

    el.addEventListener('click', async () => {
      if (disabled || pending) return;
      const next = !value;
      value = next;
      render();
      if (!onChange) return;
      pending = true;
      try {
        const accepted = await onChange(next);
        if (accepted === false) {
          value = !next;
          render();
        }
      } finally {
        pending = false;
      }
    });

    render();
    return {
      el,
      get: () => value,
      set(next) {
        if (pending || Boolean(next) === value) return;
        value = Boolean(next);
        render();
      },
      setDisabled(next) {
        disabled = Boolean(next);
        render();
      },
    };
  }

  /** Строка настройки: заголовок, пояснение и переключатель справа. Клик по тексту тоже переключает. */
  function switchRow({ title, description, checked, onChange }) {
    const titleId = uid('sw-title');
    const descId = description ? uid('sw-desc') : null;
    const sw = switchControl({ checked, onChange, labelledBy: titleId, describedBy: descId });
    const descEl = description ? h('p', { class: 'setting__desc', id: descId, text: description }) : null;
    const text = h('div', { class: 'setting__text' },
      h('div', { class: 'setting__title', id: titleId, text: title }), descEl);
    text.addEventListener('click', () => sw.el.click());
    const el = h('div', { class: 'setting' }, text, sw.el);
    return {
      el,
      sw,
      setDescription(value) {
        if (descEl) setText(descEl, value);
      },
    };
  }

  /* ---------- Сегментированный выбор (radiogroup) ---------- */

  function segmented({ options, value, onChange, label, labelledBy, size, cls }) {
    const el = h('div', {
      class: ['seg', size && `seg--${size}`, cls],
      role: 'radiogroup',
      'aria-label': label,
      'aria-labelledby': labelledBy,
    });
    let current = value;
    let disabled = false;
    let pending = false;

    const buttons = options.map((option, index) => {
      const btn = h('button', { type: 'button', class: 'seg__opt', role: 'radio', title: option.title },
        option.icon ? icon(option.icon, { size: SMALL_ICON }) : null,
        h('span', { text: option.label }));
      btn.addEventListener('click', () => choose(index));
      btn.addEventListener('keydown', (event) => onKey(event, index));
      return btn;
    });
    el.append(...buttons);

    function render() {
      const selectedIndex = options.findIndex((option) => option.value === current);
      buttons.forEach((btn, index) => {
        const isOn = index === selectedIndex;
        setAttr(btn, 'aria-checked', isOn);
        btn.tabIndex = isOn || (selectedIndex < 0 && index === 0) ? 0 : -1;
      });
      setAttr(el, 'aria-disabled', disabled);
    }

    async function choose(index) {
      const next = options[index].value;
      if (disabled || pending || next === current) return;
      const previous = current;
      current = next;
      render();
      if (!onChange) return;
      pending = true;
      try {
        const accepted = await onChange(next, previous);
        if (accepted === false) {
          current = previous;
          render();
        }
      } finally {
        pending = false;
      }
    }

    const KEY_STEP = { ArrowRight: 1, ArrowDown: 1, ArrowLeft: -1, ArrowUp: -1 };
    function onKey(event, index) {
      let next = -1;
      if (event.key in KEY_STEP) next = (index + KEY_STEP[event.key] + buttons.length) % buttons.length;
      else if (event.key === 'Home') next = 0;
      else if (event.key === 'End') next = buttons.length - 1;
      if (next < 0) return;
      event.preventDefault();
      buttons[next].focus();
      choose(next);
    }

    render();
    return {
      el,
      get: () => current,
      set(next) {
        if (pending || next === current) return;
        current = next;
        render();
      },
      setDisabled(next) {
        disabled = Boolean(next);
        render();
      },
    };
  }

  /* ---------- Выпадающий список ---------- */

  /**
   * Нативный <select>. sync(value) меняет выбор, только когда значение в ядре
   * действительно изменилось, — не мешает пользователю, пока список открыт.
   * onChange(value) может вернуть Promise<boolean>; false откатывает выбор.
   */
  function selectControl({ id, label, onChange, cls }) {
    const select = h('select', { class: 'select__input', id, 'aria-label': label });
    const el = h('div', { class: ['select', cls] }, select, icon('chevronDown', { size: SMALL_ICON, cls: 'select__chevron' }));
    let optionsKey = '';
    let synced = null;

    function setOptions(list) {
      const key = JSON.stringify(list);
      if (key === optionsKey) return;
      optionsKey = key;
      select.replaceChildren(...list.map((option) => new Option(option.label, option.value)));
      if (synced != null) select.value = synced;
    }

    function sync(value) {
      if (value === synced) return;
      synced = value;
      select.value = value == null ? '' : value;
    }

    select.addEventListener('change', async () => {
      if (!onChange) return;
      const accepted = await onChange(select.value);
      if (accepted === false && synced != null) select.value = synced;
    });

    return {
      el,
      select,
      setOptions,
      sync,
      setDisabled(value) {
        select.disabled = Boolean(value);
      },
    };
  }

  /* ---------- Поля ввода ---------- */

  function textInput({ id, placeholder, mono, inputMode, maxLength, onInput, label }) {
    const input = h('input', {
      class: ['input', mono && 'mono'],
      id,
      type: 'text',
      placeholder,
      inputmode: inputMode,
      maxlength: maxLength,
      autocomplete: 'off',
      spellcheck: false,
      'aria-label': label,
    });
    if (onInput) input.addEventListener('input', () => onInput(input.value));
    return input;
  }

  function textArea({ id, rows = 4, placeholder, onInput, label, readOnly }) {
    const area = h('textarea', {
      class: 'textarea mono',
      id,
      rows,
      placeholder,
      spellcheck: false,
      autocomplete: 'off',
      'aria-label': label,
      readOnly,
    });
    if (onInput) area.addEventListener('input', () => onInput(area.value));
    return area;
  }

  /** Записывает значение в поле, только если пользователь сейчас в нём не печатает. */
  function syncValue(control, value) {
    const text = value == null ? '' : String(value);
    if (document.activeElement === control || control.value === text) return;
    control.value = text;
  }

  /** Поле формы: подпись, контрол, подсказка, сообщение об ошибке. */
  function field({ label, hint, control, inputId, cls }) {
    const errorId = uid('err');
    const errorEl = h('p', { class: 'field__error', id: errorId, hidden: true });
    const hintEl = hint ? h('p', { class: 'field__hint', text: hint }) : null;
    const el = h('div', { class: ['field', cls] },
      label ? h('label', { class: 'field__label', for: inputId, text: label }) : null,
      control, hintEl, errorEl);
    const target = inputId ? el.querySelector(`#${inputId}`) : null;
    return {
      el,
      setError(message) {
        setText(errorEl, message || '');
        setHidden(errorEl, !message);
        el.classList.toggle('has-error', Boolean(message));
        if (target) {
          if (message) {
            target.setAttribute('aria-invalid', 'true');
            target.setAttribute('aria-describedby', errorId);
          } else {
            target.removeAttribute('aria-invalid');
            target.removeAttribute('aria-describedby');
          }
        }
      },
    };
  }

  /* ---------- Раскладка ---------- */

  function pageHeader({ title, subtitle, actions }) {
    const subtitleEl = h('p', { class: 'page-head__sub', text: subtitle || '' });
    const actionsEl = h('div', { class: 'page-head__actions' }, actions);
    const el = h('header', { class: 'page-head' },
      h('div', { class: 'page-head__titles' }, h('h1', { class: 'page-head__title', text: title }), subtitleEl),
      actionsEl);
    return { el, subtitleEl, actionsEl };
  }

  /** Секция: тихая подпись (мелкие серые капители) и пояснение над плоской панелью. */
  function card({ title, subtitle, actions, cls, tag = 'section' }) {
    const titleId = uid('card');
    const titleEl = title ? h('h2', { class: 'card__title', id: titleId, text: title }) : null;
    const subtitleEl = subtitle != null ? h('p', { class: 'card__sub', text: subtitle }) : null;
    const actionsEl = actions ? h('div', { class: 'card__actions' }, actions) : null;
    const head = title ? h('header', { class: 'card__head' },
      h('div', { class: 'card__titles' }, titleEl, subtitleEl),
      actionsEl) : null;
    const body = h('div', { class: 'card__body' });
    const el = h(tag, { class: ['card', cls], 'aria-labelledby': title ? titleId : null }, head, body);
    return { el, head, body, titleEl, subtitleEl, actionsEl };
  }

  /**
   * Контейнер, который перестраивается только при изменении своего среза данных
   * (сравнение по JSON). Фокус внутри переносится на элемент с тем же data-fk.
   */
  function slot(render, opts) {
    const options = opts || {};
    const el = h(options.tag || 'div', { class: options.cls, ...(options.attrs || {}) });
    let lastKey;

    function focusedKey() {
      const active = document.activeElement;
      if (!active || active === el || !el.contains(active)) return null;
      return active.dataset ? active.dataset.fk || null : null;
    }

    function restoreFocus(key) {
      for (const node of el.querySelectorAll('[data-fk]')) {
        if (node.dataset.fk === key) {
          node.focus({ preventScroll: true });
          return;
        }
      }
    }

    function update(data) {
      const key = JSON.stringify(data === undefined ? null : data);
      if (key === lastKey) return false;
      lastKey = key;
      const keyToRestore = focusedKey();
      const nodes = render(data);
      el.replaceChildren();
      Lz.dom.append(el, [nodes]);
      if (keyToRestore) restoreFocus(keyToRestore);
      return true;
    }

    return {
      el,
      update,
      invalidate() {
        lastKey = undefined;
      },
    };
  }

  /* ---------- Индикаторы ---------- */

  const STATUS_VIEW = {
    running: { text: 'Работает', tone: 'ok' },
    starting: { text: 'Запускается…', tone: 'warn' },
    stopping: { text: 'Останавливается…', tone: 'warn' },
    stopped: { text: 'Выключено', tone: 'off' },
    error: { text: 'Ошибка', tone: 'err' },
    locked: { text: 'Недоступно', tone: 'off' },
  };

  function statusPill() {
    const textEl = h('span', { class: 'pill__text' });
    const el = h('span', { class: 'pill' }, h('span', { class: 'pill__dot', 'aria-hidden': 'true' }), textEl);
    return {
      el,
      set(status) {
        const view = STATUS_VIEW[status] || STATUS_VIEW.stopped;
        el.dataset.tone = view.tone;
        el.dataset.status = status;
        setText(textEl, view.text);
      },
    };
  }

  function chip({ icon: iconName, text, tone, title, onClick }) {
    const tag = onClick ? 'button' : 'span';
    return h(tag, {
      class: ['chip', tone && `chip--${tone}`, onClick && 'chip--action'],
      type: onClick ? 'button' : null,
      title,
      onClick,
    }, iconName ? icon(iconName, { size: 14 }) : null, h('span', { text }));
  }

  function progressBar({ label } = {}) {
    const fill = h('div', { class: 'progress__fill' });
    const el = h('div', {
      class: 'progress',
      role: 'progressbar',
      'aria-valuemin': '0',
      'aria-valuemax': '100',
      'aria-label': label,
    }, fill);
    return {
      el,
      set(fraction) {
        const value = Number(fraction);
        if (fraction == null || !Number.isFinite(value)) {
          el.classList.add('is-indeterminate');
          el.removeAttribute('aria-valuenow');
          fill.style.width = '';
          return;
        }
        const pct = Math.max(0, Math.min(1, value)) * 100;
        el.classList.remove('is-indeterminate');
        setAttr(el, 'aria-valuenow', Math.round(pct));
        fill.style.width = `${pct.toFixed(1)}%`;
      },
    };
  }

  const TONE_ICON = { info: 'info', ok: 'checkCircle', warn: 'alert', err: 'alertCircle', off: 'info' };

  function callout({ tone = 'info', title, text, actions }) {
    return h('div', { class: `callout callout--${tone}`, role: tone === 'err' ? 'alert' : null },
      icon(TONE_ICON[tone] || 'info', { size: REGULAR_ICON, cls: 'callout__icon' }),
      h('div', { class: 'callout__body' },
        title ? h('p', { class: 'callout__title', text: title }) : null,
        text ? h('p', { class: 'callout__text', text }) : null),
      actions ? h('div', { class: 'callout__actions' }, actions) : null);
  }

  function emptyState({ icon: iconName = 'info', title, text, action }) {
    return h('div', { class: 'empty' },
      h('div', { class: 'empty__icon', 'aria-hidden': 'true' }, icon(iconName, { size: 22 })),
      title ? h('p', { class: 'empty__title', text: title }) : null,
      text ? h('p', { class: 'empty__text', text }) : null,
      action || null);
  }

  /* ---------- Спарклайн скорости ---------- */

  const SPARK_WIDTH = 300;
  const SPARK_HEIGHT = 60;
  const SPARK_PADDING = 3;
  const SPARK_MIN_SCALE = 16 * 1024;
  const SPARK_HEADROOM = 1.18;
  const HISTORY_CAPACITY = 120;

  /** Две тонкие линии: загрузка (акцент, едва заметная заливка) и отдача (серая). history — [[время, вверх, вниз], …]. */
  function sparkline({ label }) {
    const area = s('path', { class: 'spark__area' });
    const lineDown = s('path', { class: 'spark__line spark__line--down' });
    const lineUp = s('path', { class: 'spark__line spark__line--up' });
    const el = s('svg', {
      class: 'spark',
      viewBox: `0 0 ${SPARK_WIDTH} ${SPARK_HEIGHT}`,
      preserveAspectRatio: 'none',
      role: 'img',
      'aria-label': label,
    }, area, lineUp, lineDown);

    function toY(value, max) {
      const usable = SPARK_HEIGHT - SPARK_PADDING * 2;
      return (SPARK_HEIGHT - SPARK_PADDING - (value / max) * usable).toFixed(1);
    }

    function update(history) {
      const points = Array.isArray(history) ? history.slice(-HISTORY_CAPACITY) : [];
      if (points.length < 2) {
        area.setAttribute('d', '');
        lineDown.setAttribute('d', '');
        lineUp.setAttribute('d', '');
        return;
      }
      const ups = points.map((p) => Math.max(0, Number(p[1]) || 0));
      const downs = points.map((p) => Math.max(0, Number(p[2]) || 0));
      const max = Math.max(SPARK_MIN_SCALE, ...ups, ...downs) * SPARK_HEADROOM;
      const step = SPARK_WIDTH / (HISTORY_CAPACITY - 1);
      const offset = (HISTORY_CAPACITY - points.length) * step;
      const x = (i) => (offset + i * step).toFixed(1);
      const path = (values) => values.map((v, i) => `${i ? 'L' : 'M'}${x(i)} ${toY(v, max)}`).join(' ');
      const down = path(downs);
      lineDown.setAttribute('d', down);
      lineUp.setAttribute('d', path(ups));
      area.setAttribute('d', `${down} L${x(points.length - 1)} ${SPARK_HEIGHT} L${x(0)} ${SPARK_HEIGHT} Z`);
    }

    return { el, update };
  }

  /* ---------- Раскрывающийся блок ---------- */

  function disclosure({ title, content, open = false, onToggle, cls }) {
    const regionId = uid('disc');
    const badge = h('span', { class: 'disclosure__badge', hidden: true });
    const btn = h('button', {
      type: 'button',
      class: 'disclosure__btn',
      'aria-expanded': String(open),
      'aria-controls': regionId,
    }, icon('chevronRight', { size: REGULAR_ICON, cls: 'disclosure__chevron' }),
    h('span', { class: 'disclosure__title', text: title }), badge);
    const region = h('div', { class: 'disclosure__region', id: regionId, hidden: !open }, content);
    const el = h('div', { class: ['disclosure', cls, open && 'is-open'] }, btn, region);
    let isOpen = open;

    function setOpen(next) {
      isOpen = Boolean(next);
      setAttr(btn, 'aria-expanded', isOpen);
      region.hidden = !isOpen;
      el.classList.toggle('is-open', isOpen);
      if (onToggle) onToggle(isOpen);
    }

    btn.addEventListener('click', () => setOpen(!isOpen));
    return {
      el,
      region,
      setOpen,
      isOpen: () => isOpen,
      setBadge(text, tone) {
        setText(badge, text || '');
        setHidden(badge, !text);
        badge.dataset.tone = tone || '';
      },
    };
  }

  /* ---------- Вкладки ---------- */

  /** role="tablist"; items — [{ id, title, mark }], mark — точка «есть несохранённые изменения». */
  function tabs({ label, onSelect, panelId }) {
    const el = h('div', { class: 'tabs', role: 'tablist', 'aria-label': label });
    let renderedKey = '';
    let buttons = [];
    let ids = [];

    function focusAndSelect(index) {
      buttons[index].focus();
      onSelect(ids[index]);
    }

    function set(items, selectedId) {
      const key = JSON.stringify([items, selectedId]);
      if (key === renderedKey) return;
      renderedKey = key;
      const hadFocus = el.contains(document.activeElement);
      ids = items.map((item) => item.id);
      buttons = items.map((item, index) => {
        const isSelected = item.id === selectedId;
        const btn = h('button', {
          type: 'button',
          class: 'tab',
          role: 'tab',
          'aria-selected': String(isSelected),
          'aria-controls': panelId,
          tabIndex: isSelected ? 0 : -1,
        }, h('span', { text: item.title }), item.mark ? h('span', { class: 'tab__mark', title: 'Есть несохранённые изменения' }) : null);
        btn.addEventListener('click', () => onSelect(item.id));
        btn.addEventListener('keydown', (event) => {
          if (event.key === 'ArrowRight') focusAndSelect((index + 1) % items.length);
          else if (event.key === 'ArrowLeft') focusAndSelect((index - 1 + items.length) % items.length);
          else return;
          event.preventDefault();
        });
        return btn;
      });
      el.replaceChildren(...buttons);
      if (hadFocus) {
        const selectedIndex = ids.indexOf(selectedId);
        if (selectedIndex >= 0) buttons[selectedIndex].focus({ preventScroll: true });
      }
    }

    return { el, set };
  }

  /* ---------- Значение с кнопкой «скопировать» ---------- */

  function copyField({ label, secret = false, onCopy }) {
    const valueEl = h('span', { class: 'copy-field__value mono' });
    let value = '';
    let revealed = !secret;
    const toggle = secret ? button({
      icon: 'eye', kind: 'ghost', size: 'sm', ariaLabel: 'Показать ключ', onClick: () => {
        revealed = !revealed;
        render();
      },
    }) : null;
    const copy = button({
      icon: 'copy', kind: 'ghost', size: 'sm', ariaLabel: `Скопировать: ${label}`, title: 'Скопировать',
      onClick: () => onCopy(value, label),
    });

    function render() {
      const masked = '•'.repeat(Math.min(value.length, SECRET_MASK_MAX));
      setText(valueEl, revealed ? value : masked);
      valueEl.classList.toggle('is-masked', !revealed);
      if (toggle) {
        toggle.setIcon(revealed ? 'eyeOff' : 'eye');
        toggle.el.setAttribute('aria-label', revealed ? 'Скрыть ключ' : 'Показать ключ');
        toggle.el.title = revealed ? 'Скрыть' : 'Показать';
      }
    }

    const el = h('div', { class: 'copy-field' },
      h('span', { class: 'copy-field__label', text: label }),
      valueEl,
      h('span', { class: 'copy-field__actions' }, toggle && toggle.el, copy.el));
    render();
    return {
      el,
      set(next) {
        const text = next == null ? '' : String(next);
        if (text === value) return;
        value = text;
        render();
      },
    };
  }

  Lz.ui = Object.assign(Lz.ui || {}, {
    STATUS_VIEW,
    button,
    actionButton,
    switchControl,
    switchRow,
    segmented,
    selectControl,
    textInput,
    textArea,
    syncValue,
    field,
    pageHeader,
    card,
    slot,
    statusPill,
    chip,
    progressBar,
    callout,
    emptyState,
    sparkline,
    disclosure,
    tabs,
    copyField,
  });
})(window.Lz);
