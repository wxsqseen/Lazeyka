'use strict';
/*
 * Построение DOM без innerHTML. Любая строка попадает в документ только как
 * текстовый узел или значение свойства — данные ядра не интерпретируются как разметка.
 */
(function (Lz) {
  const SVG_NS = 'http://www.w3.org/2000/svg';
  const DEFAULT_ICON_SIZE = 20;
  const DEFAULT_ICON_STROKE = 1.5;
  /* Эти ключи задаются свойствами элемента, а не атрибутами. */
  const DOM_PROPERTIES = new Set([
    'value', 'checked', 'disabled', 'hidden', 'readOnly', 'selected', 'tabIndex', 'spellcheck', 'open',
  ]);

  function appendChildren(parent, children) {
    for (const child of children) {
      if (child == null || child === false || child === true) continue;
      if (Array.isArray(child)) appendChildren(parent, child);
      else parent.append(child instanceof Node ? child : document.createTextNode(String(child)));
    }
    return parent;
  }

  function applyProps(el, props) {
    if (!props) return;
    for (const key of Object.keys(props)) {
      const value = props[key];
      if (value == null || value === false) continue;
      if (key === 'class') {
        el.setAttribute('class', Array.isArray(value) ? value.filter(Boolean).join(' ') : value);
      } else if (key === 'text') {
        el.textContent = String(value);
      } else if (key === 'dataset') {
        for (const name of Object.keys(value)) {
          if (value[name] != null) el.dataset[name] = String(value[name]);
        }
      } else if (/^on[A-Z]/.test(key)) {
        el.addEventListener(key.slice(2).toLowerCase(), value);
      } else if (DOM_PROPERTIES.has(key)) {
        el[key] = value;
      } else {
        el.setAttribute(key, value === true ? '' : String(value));
      }
    }
  }

  /** HTML-элемент: h('button', { class: 'btn', onClick }, 'Текст', childNode). */
  function h(tag, props, ...children) {
    const el = document.createElement(tag);
    applyProps(el, props);
    return appendChildren(el, children);
  }

  /** SVG-элемент; атрибуты задаются как есть. */
  function s(tag, attrs, ...children) {
    const el = document.createElementNS(SVG_NS, tag);
    if (attrs) {
      for (const key of Object.keys(attrs)) {
        if (attrs[key] != null) el.setAttribute(key, String(attrs[key]));
      }
    }
    return appendChildren(el, children);
  }

  function icon(name, opts) {
    const options = opts || {};
    const size = options.size || DEFAULT_ICON_SIZE;
    const svg = s('svg', {
      class: options.cls ? `icon ${options.cls}` : 'icon',
      width: size,
      height: size,
      viewBox: '0 0 24 24',
      fill: 'none',
      stroke: 'currentColor',
      'stroke-width': options.stroke || DEFAULT_ICON_STROKE,
      'stroke-linecap': 'round',
      'stroke-linejoin': 'round',
      'aria-hidden': 'true',
      focusable: 'false',
    });
    const spec = Lz.icons[name];
    if (!spec) {
      console.warn(`Иконка «${name}» не найдена в Lz.icons`);
      return svg;
    }
    for (const part of spec) {
      if (typeof part === 'string') {
        svg.append(s('path', { d: part }));
      } else {
        const { t, ...attrs } = part;
        svg.append(s(t, attrs));
      }
    }
    return svg;
  }

  let idCounter = 0;
  function uid(prefix) {
    idCounter += 1;
    return `${prefix || 'lz'}-${idCounter}`;
  }

  /** Меняет текст, только если он отличается: не сбивает выделение и не дёргает раскладку. */
  function setText(el, value) {
    const text = value == null ? '' : String(value);
    if (el.textContent !== text) el.textContent = text;
  }

  function setHidden(el, hidden) {
    if (el.hidden !== Boolean(hidden)) el.hidden = Boolean(hidden);
  }

  function setAttr(el, name, value) {
    const text = String(value);
    if (el.getAttribute(name) !== text) el.setAttribute(name, text);
  }

  Lz.dom = { h, s, icon, uid, setText, setHidden, setAttr, append: appendChildren };
})(window.Lz);
