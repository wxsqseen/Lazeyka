'use strict';
/*
 * Большая круглая кнопка питания — центр карточек на главной.
 * Плоский контурный круг; включено — круг залит акцентом. Внешний вид целиком
 * задаётся data-state (running | starting | stopping | stopped | error),
 * поэтому смена состояния анимируется CSS-переходами, а не перестройкой DOM.
 */
(function (Lz) {
  const { h, s, icon, setAttr, setText } = Lz.dom;

  const VIEWBOX = 124;
  const CENTER = VIEWBOX / 2;
  const ARC_RADIUS = 61;
  const GLYPH_SIZE = 34;
  const GLYPH_STROKE = 1.6;
  const TRANSITIONAL = new Set(['starting', 'stopping']);
  const PENDING_CAPTION = 'Включаем…';

  /**
   * @param {{ label: string, onToggle: (status: string) => void, busyKey?: string }} options
   *   onToggle получает текущий статус и сам решает, включать или выключать. busyKey — ключ Lz.api:
   *   пока включение идёт (окно «Работает VPN», ответ ядра), кнопка выглядит запускающейся и не нажимается.
   */
  function create({ label, onToggle, busyKey }) {
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

    const pending = () => Boolean(busyKey && Lz.api.isBusy(busyKey));

    /* Включение уже нажато (проверка перед ним, окно «Работает VPN», ответ ядра), а ядро ещё не включает. */
    function isStarting() {
      return pending() && !TRANSITIONAL.has(status) && status !== 'running';
    }

    btn.addEventListener('click', () => {
      if (disabled || TRANSITIONAL.has(status) || pending()) return;
      onToggle(status);
    });

    function render() {
      /* Показываем «запускается», а не прежнее «выключено». */
      const shown = isStarting() ? 'starting' : status;
      const busy = TRANSITIONAL.has(shown);
      if (el.dataset.state !== shown) el.dataset.state = shown;
      setAttr(btn, 'aria-checked', shown === 'running' || shown === 'starting');
      setAttr(btn, 'aria-busy', busy);
      setAttr(btn, 'aria-disabled', disabled || busy);
      el.classList.toggle('is-disabled', disabled);
    }

    function update(nextStatus, opts) {
      const options = opts || {};
      status = nextStatus || 'stopped';
      disabled = Boolean(options.disabled);
      render();
    }

    if (busyKey) Lz.api.onBusyChange(render);

    return { el, button: btn, update, isStarting };
  }

  /**
   * Подпись под кнопкой питания. Пока включение нажато, а ядро ещё не включает (power.isStarting), — «Включаем…»,
   * как и сама кнопка, а не прежнее «Нажмите, чтобы включить». Диктор зачитывает смену состояния, но не счётчик
   * «Работает 1 ч 12 мин»: он меняется каждую минуту (в первую — каждую секунду) и стоит в узле, скрытом от диктора.
   * set(text, quietTail, { error }) — то, что показать без нажатого включения.
   */
  function caption(power, cls) {
    const main = h('span');
    const tail = h('span', { 'aria-hidden': 'true' });
    const el = h('p', { class: cls, 'aria-live': 'polite' }, main, tail);
    let wanted = { text: '', tail: '', error: false };

    function render() {
      const starting = power.isStarting();
      setText(main, starting ? PENDING_CAPTION : wanted.text);
      setText(tail, starting ? '' : wanted.tail);
      el.classList.toggle('is-error', wanted.error && !starting);
    }

    Lz.api.onBusyChange(render);

    return {
      el,
      set(text, quietTail, opts) {
        wanted = { text: text || '', tail: quietTail || '', error: Boolean(opts && opts.error) };
        render();
      },
    };
  }

  Lz.power = { create, caption };
})(window.Lz);
