'use strict';
/*
 * Обновления. Главное обещание Лазейки: мы только сообщаем о новой версии,
 * а скачиваем и ставим — исключительно по нажатию пользователя.
 */
(function (Lz) {
  const { h, icon, setText, setHidden } = Lz.dom;
  const ui = Lz.ui;
  const fmt = Lz.fmt;

  const ACTIVE_STATES = new Set(['downloading', 'verifying', 'installing']);
  const STATE_TEXT = {
    downloading: 'Скачиваем…',
    verifying: 'Проверяем скачанный файл…',
    installing: 'Устанавливаем…',
    done: 'Обновление установлено.',
    error: 'Не получилось установить обновление.',
  };

  function badgeFor(item) {
    if (item.state === 'error') return { tone: 'err', text: 'Ошибка' };
    if (ACTIVE_STATES.has(item.state)) return { tone: 'warn', text: 'Устанавливается' };
    if (item.state === 'done') return { tone: 'ok', text: 'Установлено' };
    if (item.available && item.skipped) return { tone: 'off', text: 'Версия пропущена' };
    if (item.available) return { tone: 'accent', text: 'Есть обновление' };
    return { tone: 'ok', text: 'Актуальная версия' };
  }

  function renderActions(data) {
    const { item } = data;
    if (ACTIVE_STATES.has(item.state)) return null;
    const buttons = [];
    if (item.available && item.state !== 'done') {
      buttons.push(ui.actionButton({
        method: 'updates_install',
        args: [item.id],
        key: `updates_install:${item.id}`,
        label: item.state === 'error' ? 'Повторить' : 'Установить',
        icon: 'download',
        kind: 'primary',
      }).el);
      if (!item.skipped) {
        buttons.push(ui.actionButton({
          method: 'updates_skip',
          args: [item.id],
          key: `updates_skip:${item.id}`,
          label: 'Пропустить версию',
          icon: 'skip',
          kind: 'ghost',
          success: 'Хорошо, про эту версию больше не напомним',
        }).el);
      }
    }
    if (item.url) {
      buttons.push(ui.button({
        label: 'Открыть на GitHub',
        icon: 'external',
        kind: 'ghost',
        busyKey: 'open_url',
        onClick: () => Lz.actions.openUrl(item.url),
      }).el);
    }
    if (item.can_rollback) {
      buttons.push(ui.actionButton({
        method: 'updates_rollback',
        args: [item.id],
        key: `updates_rollback:${item.id}`,
        label: 'Откатить',
        icon: 'undo',
        kind: 'ghost',
        success: 'Предыдущая версия возвращена',
        confirm: {
          title: `Откатить «${item.title || item.id}»?`,
          text: 'Вернём предыдущую версию, которую Лазейка сохранила перед обновлением. Если компонент сейчас работает, он перезапустится.',
          confirmLabel: 'Откатить',
          tone: 'danger',
          icon: 'undo',
        },
      }).el);
    }
    buttons.forEach((btn, index) => { btn.dataset.fk = `update-action:${index}`; });
    return buttons;
  }

  function createItemCard() {
    const title = h('h2', { class: 'update__title' });
    const subtitle = h('p', { class: 'update__sub' });
    const badge = h('span', { class: 'badge' });
    const current = h('span', { class: 'version__current num' });
    const arrow = h('span', { class: 'version__arrow', 'aria-hidden': 'true' }, icon('arrowRight', { size: 16 }));
    const latest = h('span', { class: 'version__latest num' });
    const published = h('span', { class: 'version__date' });
    const versionLine = h('p', { class: 'version' }, h('span', { class: 'sr-only', text: 'Версии: ' }), current, arrow, latest, published);
    const notesText = h('div', { class: 'notes', tabIndex: 0 });
    const notes = ui.disclosure({ title: 'Что нового', content: notesText });
    const progress = ui.progressBar({ label: 'Ход обновления' });
    const progressText = h('p', { class: 'update__progress-text', 'aria-live': 'polite' });
    const progressBox = h('div', { class: 'update__progress', hidden: true }, progressText, progress.el);
    const message = ui.slot((data) => (data ? ui.callout({ tone: data.tone, text: data.text }) : null));
    const actions = ui.slot(renderActions, { cls: 'update__actions' });

    const el = h('section', { class: 'panel update' },
      h('header', { class: 'update__head' },
        h('div', { class: 'update__titles' }, title, subtitle),
        badge),
      versionLine,
      progressBox,
      message.el,
      actions.el,
      h('div', { class: 'update__notes' }, notes.el));

    function update(item) {
      setText(title, item.title || item.id);
      setText(subtitle, item.subtitle || '');
      setHidden(subtitle, !item.subtitle);
      const view = badgeFor(item);
      badge.dataset.tone = view.tone;
      setText(badge, view.text);

      const hasNewer = Boolean(item.available && item.latest && item.latest !== item.current);
      versionLine.classList.toggle('has-newer', hasNewer);
      setText(current, item.current || '—');
      setHidden(arrow, !hasNewer);
      setHidden(latest, !hasNewer);
      setText(latest, item.latest || '');
      const date = fmt.date(item.published_at);
      const ago = fmt.relative(item.published_at);
      const dateText = date ? `${hasNewer ? 'выпущена' : 'от'} ${date}${ago && ago !== date ? ` (${ago})` : ''}` : '';
      setText(published, dateText);
      setHidden(published, !dateText);

      const active = ACTIVE_STATES.has(item.state);
      setHidden(progressBox, !active);
      if (active) {
        progress.set(item.state === 'downloading' && item.progress != null ? item.progress : null);
        setText(progressText, item.message || STATE_TEXT[item.state]);
      }
      if (item.state === 'error') message.update({ tone: 'err', text: item.message || STATE_TEXT.error });
      else if (item.state === 'done') message.update({ tone: 'ok', text: item.message || STATE_TEXT.done });
      else message.update(null);

      actions.update({ item: {
        id: item.id,
        title: item.title,
        url: item.url,
        state: item.state,
        available: Boolean(item.available),
        skipped: Boolean(item.skipped),
        can_rollback: Boolean(item.can_rollback),
      } });

      const notesValue = String(item.notes || '').trim();
      setText(notesText, notesValue || 'Автор не оставил описания к этой версии.');
      setHidden(notes.el.parentElement, !notesValue && !hasNewer);
    }

    return { el, update };
  }

  function create() {
    const cards = new Map();

    const autoCheck = ui.switchRow({
      title: 'Проверять при запуске',
      description: 'Только уведомление о новой версии — ничего не скачивается без вас.',
      onChange: async (value) => {
        const result = await Lz.api.run({ method: 'save_settings', args: [{ check_updates: value }] });
        return Boolean(result && result.ok);
      },
    });
    const checkBtn = ui.button({
      label: 'Проверить сейчас',
      icon: 'refresh',
      busyKey: 'updates_check',
      onClick: () => Lz.api.run({ method: 'updates_check' }),
    });
    const lastCheck = h('p', { class: 'policy__last' });
    const globalError = ui.slot((text) => (text ? ui.callout({ tone: 'err', title: 'Проверка не удалась', text }) : null));

    const policy = h('section', { class: 'panel policy' },
      h('div', { class: 'policy__main' },
        h('div', { class: 'policy__icon', 'aria-hidden': 'true' }, icon('shieldCheck', { size: 22 })),
        h('div', { class: 'policy__text' },
          h('h2', { class: 'policy__title', text: 'Обновления — только когда вы захотите' }),
          h('p', { class: 'policy__desc', text: 'Лазейка только сообщает о новых версиях. Скачиваем и устанавливаем — лишь после того, как вы нажмёте «Установить». Никаких самовольных загрузок и внезапно открытых страниц.' }))),
      h('div', { class: 'policy__controls' },
        autoCheck.el,
        h('div', { class: 'policy__check' }, checkBtn.el, lastCheck)));

    const list = h('div', { class: 'updates-list' });
    const empty = ui.emptyState({
      icon: 'download',
      title: 'Сведений об обновлениях пока нет',
      text: 'Нажмите «Проверить сейчас» — мы только посмотрим, есть ли новые версии.',
    });

    const header = ui.pageHeader({ title: 'Обновления', subtitle: 'Стратегии zapret и ядро прокси для Telegram' });
    const el = h('div', { class: 'page__inner' }, header.el, policy, globalError.el, list, empty);

    function syncItems(items) {
      const seen = new Set();
      items.forEach((item, index) => {
        const id = String(item.id);
        seen.add(id);
        let card = cards.get(id);
        if (!card) {
          card = createItemCard();
          cards.set(id, card);
        }
        if (list.children[index] !== card.el) list.insertBefore(card.el, list.children[index] || null);
        card.update(item);
      });
      for (const [id, card] of cards) {
        if (!seen.has(id)) {
          card.el.remove();
          cards.delete(id);
        }
      }
    }

    return {
      el,
      update(state) {
        const updates = state.updates || {};
        const settings = state.settings || {};
        autoCheck.sw.set(settings.check_updates != null ? settings.check_updates : updates.auto_check);
        checkBtn.setBusy(Boolean(updates.checking));
        checkBtn.setLabel(updates.checking ? 'Проверяем…' : 'Проверить сейчас');
        const ago = fmt.relative(updates.last_check);
        setText(lastCheck, ago ? `Последняя проверка: ${ago}` : 'Ещё не проверяли');
        globalError.update(updates.error || null);
        const items = Array.isArray(updates.items) ? updates.items : [];
        syncItems(items);
        setHidden(empty, items.length > 0);
      },
    };
  }

  Lz.pages.updates = { title: 'Обновления', icon: 'download', create };
})(window.Lz);
