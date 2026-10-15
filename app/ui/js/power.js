'use strict';
/*
 * Большая круглая кнопка питания — центр карточек на главной.
 * Плоский контурный круг; включено — круг залит акцентом. Внешний вид целиком
 * задаётся data-state (running | starting | stopping | stopped | error),
 * поэтому смена состояния анимируется CSS-переходами, а не перестройкой DOM.
 */
(function (Lz) {
  const { h, s, icon, setAttr } = Lz.dom;

  const VIEWBOX = 124;
  const CENTER = VIEWBOX / 2;
  const ARC_RADIUS = 61;
  const GLYPH_SIZE = 34;
  const GLYPH_STROKE = 1.6;
  const TRANSITIONAL = new Set(['starting', 'stopping']);

  /**
   * @param {{ label: string, onToggle: (status: string) => void }} options
   *   onToggle получает текущий статус и сам решает, включать или выключать.
   */
  function create({ label, onToggle }) {
    const ring = s('svg', { class: 'power__ring', viewBox: `0 0 ${VIEWBOX} ${VIEWBOX}`, 'aria-hidden': 'true' },
      s('circle', { class: 'power__arc', cx: CENTER, cy: CENTER, r: ARC_RADIUS }));
    const btn = h('button', {
      type: 'button',
      class: 'power__btn',
      role: 'switch',
      'aria-checked': 'false',
      'aria-label': label,
    }, icon('power', { size: GLYPH_SIZE, stroke: GLYPH_STROKE, cls: 'power__glyph' }));
    const el = h('div', { class: 'power', dataset: { state: 'stopped' } }, ring, btn);

    let status = 'stopped';
    let disabled = false;

    btn.addEventListener('click', () => {
      if (disabled || TRANSITIONAL.has(status)) return;
      onToggle(status);
    });

    function update(nextStatus, opts) {
      const options = opts || {};
      status = nextStatus || 'stopped';
      disabled = Boolean(options.disabled);
      if (el.dataset.state !== status) el.dataset.state = status;
      setAttr(btn, 'aria-checked', status === 'running' || status === 'starting');
      setAttr(btn, 'aria-busy', TRANSITIONAL.has(status));
      setAttr(btn, 'aria-disabled', disabled || TRANSITIONAL.has(status));
      el.classList.toggle('is-disabled', disabled);
    }

    return { el, button: btn, update };
  }

  Lz.power = { create };
})(window.Lz);
