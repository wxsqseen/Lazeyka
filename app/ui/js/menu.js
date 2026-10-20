'use strict';
/*
 * Кнопка «⋯» с меню действий (переименовать, QR, удалить…). Меню кладётся в body поверх
 * страницы, чтобы его не обрезала прокрутка, и закрывается по Escape, щелчку мимо и прокрутке.
 * Слоты перестраиваются при изменении данных: если кнопку заменили такой же (тот же data-fk),
 * меню переезжает к новой, а если кнопка пропала совсем — закрывается.
 */
(function (Lz) {
  const { h, icon, setAttr, byFk } = Lz.dom;

  const GAP_PX = 4;
  const EDGE_PX = 8;
  const ANCHOR_CHECK_MS = 250;
  const ITEM_ICON = 16;

  let current = null;

  /** Масштаб окна (settings.ui_scale) задан CSS zoom на <html>: координаты для fixed — в «незумленных» пикселях. */
  function zoomFactor() {
    const value = Number(Lz.scale && Lz.scale.current);
    return Number.isFinite(value) && value > 0 ? value : 1;
  }

  function closeCurrent(restoreFocus) {
    if (current) current.close(restoreFocus);
  }

  function place(menu, anchor) {
    const zoom = zoomFactor();
    const rect = anchor.getBoundingClientRect();
    const box = menu.getBoundingClientRect();
    let left = rect.right - box.width;
    left = Math.max(EDGE_PX, Math.min(left, window.innerWidth - box.width - EDGE_PX));
    let top = rect.bottom + GAP_PX;
    if (top + box.height > window.innerHeight - EDGE_PX && rect.top - GAP_PX - box.height >= EDGE_PX) {
      top = rect.top - GAP_PX - box.height;
    }
    /* Ни снизу, ни сверху не помещается (крупный масштаб, низкое окно) — прижимаем к краю окна: прокрутка
     * меню закрывает, и нижние пункты («Удалить») иначе было бы не достать. Выше окна — своя прокрутка (CSS). */
    top = Math.max(EDGE_PX, Math.min(top, window.innerHeight - box.height - EDGE_PX));
    menu.style.left = `${(left / zoom).toFixed(1)}px`;
    menu.style.top = `${(top / zoom).toFixed(1)}px`;
  }

  function openMenu({ trigger, ariaLabel, list, fk }) {
    const buttons = list.map((item) => {
      const btn = h('button', {
        type: 'button',
        class: ['menu__item', item.tone && `menu__item--${item.tone}`],
        role: 'menuitem',
        tabIndex: -1,
        title: item.title,
      }, item.icon ? icon(item.icon, { size: ITEM_ICON }) : null, h('span', { text: item.label }));
      setAttr(btn, 'aria-disabled', Boolean(item.disabled));
      btn.addEventListener('click', () => {
        if (item.disabled) return;
        close(true);
        item.onSelect();
      });
      return btn;
    });
    const menu = h('div', { class: 'menu', role: 'menu', 'aria-label': ariaLabel }, buttons);
    const entry = { anchor: trigger, close };
    let anchorTimer = null;

    function enabledItems() {
      return buttons.filter((btn) => btn.getAttribute('aria-disabled') !== 'true');
    }

    function focusAt(index) {
      const enabled = enabledItems();
      if (enabled.length) enabled[(index + enabled.length) % enabled.length].focus();
    }

    function close(restoreFocus) {
      if (current !== entry) return;
      current = null;
      clearInterval(anchorTimer);
      document.removeEventListener('pointerdown', onOutside, true);
      window.removeEventListener('scroll', onScroll, true);
      window.removeEventListener('resize', onScroll);
      menu.remove();
      setAttr(entry.anchor, 'aria-expanded', false);
      if (restoreFocus && entry.anchor.isConnected) entry.anchor.focus({ preventScroll: true });
    }

    function onOutside(event) {
      if (!menu.contains(event.target) && !entry.anchor.contains(event.target)) close(false);
    }

    function onScroll(event) {
      if (!menu.contains(event.target)) close(false);
    }

    /* Кнопку перерисовал слот — переезжаем к новой с тем же ключом или закрываемся. */
    function followAnchor() {
      if (entry.anchor.isConnected) return;
      const replacement = byFk(fk);
      if (!replacement) {
        close(false);
        return;
      }
      entry.anchor = replacement;
      setAttr(replacement, 'aria-expanded', true);
      place(menu, replacement);
    }

    menu.addEventListener('keydown', (event) => {
      const index = enabledItems().indexOf(document.activeElement);
      const moves = { ArrowDown: index + 1, ArrowUp: index - 1, Home: 0, End: -1 };
      if (event.key === 'Escape') {
        event.preventDefault();
        event.stopPropagation();
        close(true);
      } else if (event.key in moves) {
        event.preventDefault();
        focusAt(moves[event.key]);
      } else if (event.key === 'Tab') {
        /* Меню вне порядка обхода (в конце body): фокус — обратно на кнопку «⋯», и Tab идёт дальше от неё,
         * а не с начала страницы. */
        close(true);
      }
    });

    document.body.append(menu);
    place(menu, trigger);
    current = entry;
    setAttr(trigger, 'aria-expanded', true);
    document.addEventListener('pointerdown', onOutside, true);
    window.addEventListener('scroll', onScroll, true);
    window.addEventListener('resize', onScroll);
    anchorTimer = setInterval(followAnchor, ANCHOR_CHECK_MS);
    focusAt(0);
  }

  /**
   * items — массив или функция, возвращающая [{ label, icon, onSelect, tone: 'danger', disabled, title }].
   * Пустые элементы (null/false) пропускаются: так удобно собирать меню по условиям.
   * fk — ключ кнопки (data-fk): по нему меню находит её после перерисовки слота.
   */
  function menuButton({ ariaLabel, title, items, size = 'sm', fk, cls }) {
    const trigger = Lz.ui.button({
      icon: 'more',
      kind: 'ghost',
      size,
      cls,
      ariaLabel,
      title: title || ariaLabel,
      onClick: () => {
        if (current && current.anchor === trigger.el) {
          closeCurrent(true);
          return;
        }
        closeCurrent(false);
        const list = (typeof items === 'function' ? items() : items || []).filter(Boolean);
        if (list.length) openMenu({ trigger: trigger.el, ariaLabel, list, fk });
      },
    });
    trigger.el.setAttribute('aria-haspopup', 'menu');
    trigger.el.setAttribute('aria-expanded', 'false');
    if (fk) trigger.el.dataset.fk = fk;
    return trigger;
  }

  /* closeMenu(true) — вернуть фокус на кнопку «⋯» (окно поверх меню вернёт его туда же, когда закроется). */
  Lz.ui = Object.assign(Lz.ui || {}, { menuButton, closeMenu: (restoreFocus) => closeCurrent(Boolean(restoreFocus)) });
})(window.Lz);
