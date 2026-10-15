'use strict';
/* Всплывающие уведомления, модальные окна и подтверждения опасных действий. */
(function (Lz) {
  const { h, icon, uid } = Lz.dom;

  const TOAST_TIMEOUT_MS = 4000;
  const ERROR_TOAST_TIMEOUT_MS = 7000;
  const TOAST_RESUME_MS = 2000;
  const MAX_TOASTS = 4;
  /* Запасной срок на случай, если анимация ухода не запустится (например, при reduced motion). */
  const LEAVE_FALLBACK_MS = 400;
  const TOAST_ICON = { success: 'checkCircle', error: 'alertCircle', info: 'info', warn: 'alert' };
  const FOCUSABLE = 'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

  /* ---------- Тосты ---------- */

  let toastRegion = null;

  function getToastRegion() {
    if (!toastRegion) {
      toastRegion = h('div', { class: 'toasts', 'aria-live': 'polite' });
      document.body.append(toastRegion);
    }
    return toastRegion;
  }

  function removeAfterAnimation(el) {
    let removed = false;
    const remove = () => {
      if (removed) return;
      removed = true;
      el.remove();
    };
    el.addEventListener('animationend', remove, { once: true });
    setTimeout(remove, LEAVE_FALLBACK_MS);
  }

  function toast({ kind = 'info', text, timeout }) {
    if (!text) return;
    const region = getToastRegion();
    const closeBtn = h('button', { type: 'button', class: 'toast__close', 'aria-label': 'Закрыть уведомление' },
      icon('x', { size: 16 }));
    const el = h('div', { class: `toast toast--${kind}`, role: kind === 'error' ? 'alert' : 'status' },
      icon(TOAST_ICON[kind] || 'info', { size: 18, cls: 'toast__icon' }),
      h('p', { class: 'toast__text', text }),
      closeBtn);

    let timer = null;
    function dismiss() {
      clearTimeout(timer);
      if (el.classList.contains('is-leaving')) return;
      el.classList.add('is-leaving');
      removeAfterAnimation(el);
    }

    region.append(el);
    while (region.children.length > MAX_TOASTS) region.firstElementChild.remove();
    timer = setTimeout(dismiss, timeout || (kind === 'error' ? ERROR_TOAST_TIMEOUT_MS : TOAST_TIMEOUT_MS));
    el.addEventListener('mouseenter', () => clearTimeout(timer));
    el.addEventListener('mouseleave', () => {
      clearTimeout(timer);
      timer = setTimeout(dismiss, TOAST_RESUME_MS);
    });
    closeBtn.addEventListener('click', dismiss);
  }

  /* ---------- Модальные окна ---------- */

  const modalStack = [];

  function setBackgroundInert(inert) {
    const app = document.getElementById('app');
    if (app) app.inert = inert;
  }

  function trapTab(event, dialog) {
    const items = [...dialog.querySelectorAll(FOCUSABLE)].filter((node) => node.offsetParent !== null);
    if (!items.length) {
      event.preventDefault();
      dialog.focus();
      return;
    }
    const first = items[0];
    const last = items[items.length - 1];
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  }

  /**
   * Открывает модальное окно поверх приложения: фон становится inert,
   * Tab не выходит за пределы окна, при закрытии фокус возвращается на место.
   */
  function openModal({ content, labelledBy, describedBy, onEscape, cls, initialFocus }) {
    const returnFocus = document.activeElement;
    const dialog = h('div', {
      class: ['modal', cls],
      role: 'dialog',
      'aria-modal': 'true',
      'aria-labelledby': labelledBy,
      'aria-describedby': describedBy,
      tabIndex: -1,
    }, content);
    const backdrop = h('div', { class: 'modal-backdrop' }, dialog);
    const entry = { backdrop, close };

    function onKeyDown(event) {
      if (modalStack[modalStack.length - 1] !== entry) return;
      if (event.key === 'Tab') trapTab(event, dialog);
      else if (event.key === 'Escape' && onEscape) {
        event.preventDefault();
        onEscape();
      }
    }

    function close() {
      const index = modalStack.indexOf(entry);
      if (index < 0) return;
      modalStack.splice(index, 1);
      document.removeEventListener('keydown', onKeyDown, true);
      backdrop.classList.add('is-leaving');
      removeAfterAnimation(backdrop);
      if (!modalStack.length) setBackgroundInert(false);
      if (returnFocus && returnFocus.isConnected && typeof returnFocus.focus === 'function') {
        returnFocus.focus({ preventScroll: true });
      }
    }

    document.body.append(backdrop);
    modalStack.push(entry);
    setBackgroundInert(true);
    document.addEventListener('keydown', onKeyDown, true);
    (initialFocus || dialog).focus({ preventScroll: true });
    return { el: dialog, close };
  }

  /**
   * Подтверждение: Promise<boolean>. Для опасных действий (tone: 'danger')
   * по умолчанию в фокусе «Отмена», чтобы случайный Enter ничего не сломал.
   */
  function confirmDialog({ title, text, details, confirmLabel = 'Продолжить', cancelLabel = 'Отмена', tone = 'primary', icon: iconName = 'alert' }) {
    return new Promise((resolve) => {
      const titleId = uid('dlg-title');
      const textId = uid('dlg-text');
      let modal = null;
      let settled = false;
      const finish = (answer) => {
        if (settled) return;
        settled = true;
        modal.close();
        resolve(answer);
      };
      const cancelBtn = Lz.ui.button({ label: cancelLabel, kind: 'secondary', onClick: () => finish(false) });
      const confirmBtn = Lz.ui.button({
        label: confirmLabel,
        kind: tone === 'danger' ? 'danger' : 'primary',
        onClick: () => finish(true),
      });
      const content = h('div', { class: 'dialog' },
        h('div', { class: `dialog__icon dialog__icon--${tone}`, 'aria-hidden': 'true' }, icon(iconName, { size: 22 })),
        h('h2', { class: 'dialog__title', id: titleId, text: title }),
        h('p', { class: 'dialog__text', id: textId, text }),
        details ? h('p', { class: 'dialog__details', text: details }) : null,
        h('div', { class: 'dialog__actions' }, cancelBtn.el, confirmBtn.el));
      modal = openModal({
        content,
        labelledBy: titleId,
        describedBy: textId,
        cls: 'modal--dialog',
        onEscape: () => finish(false),
        initialFocus: tone === 'danger' ? cancelBtn.el : confirmBtn.el,
      });
    });
  }

  Lz.ui = Object.assign(Lz.ui || {}, { toast, openModal, confirm: confirmDialog });
})(window.Lz);
