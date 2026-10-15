'use strict';
/*
 * Обновления. Главное обещание Лазейки: мы только сообщаем о новой версии,
 * а скачиваем и ставим — исключительно по нажатию пользователя. Браузер сам
 * ничего не открывает: страница релиза — лишь по клику.
 *
 * На каждый компонент (стратегии zapret и ядро прокси для Telegram) — отдельная
 * карточка: текущая версия → новая, что нового, как файл проверяется, и ход установки
 * по этапам (скачивание → проверка → установка → готово).
 */
(function (Lz) {
  const { h, icon, setText, setHidden } = Lz.dom;
  const ui = Lz.ui;
  const fmt = Lz.fmt;

  const ACTIVE_STATES = new Set(['downloading', 'verifying', 'installing']);

  /* Этап установки по индексу; done — четвёртый, отдельно. */
  const STEP_INDEX = { downloading: 0, verifying: 1, installing: 2 };
  const STEPS = ['Скачивание', 'Проверка', 'Установка', 'Готово'];

  const STATE_TEXT = {
    downloading: 'Скачиваем обновление…',
    verifying: 'Проверяем целостность файла…',
    installing: 'Устанавливаем и перезапускаем компонент…',
    done: 'Обновление установлено.',
    error: 'Не удалось установить обновление.',
  };

  /*
   * Как проверяется подлинность файла у каждого компонента. В контракте отдельного
   * поля нет: способ проверки определяется компонентом (zapret — архив по SHA-256
   * из релиза GitHub, ядро — файлы по git-хешам тега).
   */
  const VERIFY = {
    zapret: {
      idle: 'Перед установкой архив сверяется по SHA-256 из релиза на GitHub.',
      doing: 'Сверяем SHA-256 архива с релизом на GitHub…',
      done: 'Контрольная сумма SHA-256 совпала с релизом на GitHub.',
    },
    tgws: {
      idle: 'Перед установкой файлы ядра сверяются по git-хешам тега.',
      doing: 'Сверяем git-хеши файлов ядра с тегом…',
      done: 'Git-хеши файлов ядра совпали с тегом.',
    },
    app: {
      idle: 'Новый Lazeyka.exe сверяется по SHA-256 из релиза на GitHub; после установки нужен перезапуск.',
      doing: 'Сверяем SHA-256 файла с релизом на GitHub…',
      done: 'Контрольная сумма совпала. Перезапустите Лазейку, чтобы запустить новую версию.',
    },
  };
  const VERIFY_FALLBACK = {
    idle: 'Перед установкой файлы сверяются по контрольным суммам из релиза.',
    doing: 'Сверяем контрольные суммы с релизом…',
    done: 'Контрольные суммы совпали с релизом.',
  };

  function badgeFor(item) {
    if (item.state === 'error') return { tone: 'err', text: 'Ошибка' };
    if (ACTIVE_STATES.has(item.state)) return { tone: 'warn', text: 'Устанавливается' };
    if (item.state === 'done') return { tone: 'ok', text: 'Установлено' };
    if (item.available && item.skipped) return { tone: 'off', text: 'Версия пропущена' };
    if (item.available) return { tone: 'accent', text: 'Есть обновление' };
    return { tone: 'ok', text: 'Актуальная версия' };
  }

  /* ---------- Этапы установки ---------- */

  function createStepper() {
    const steps = STEPS.map((label) => {
      const marker = h('span', { class: 'stepper__marker' },
        h('span', { class: 'stepper__dot', 'aria-hidden': 'true' }),
        icon('check', { size: 13, cls: 'stepper__check' }));
      return {
        el: h('li', { class: 'stepper__step' }, marker, h('span', { class: 'stepper__label', text: label })),
      };
    });
    const el = h('ol', { class: 'stepper' }, steps.map((step) => step.el));

    function update(state) {
      const current = state === 'done' ? 3 : (STEP_INDEX[state] != null ? STEP_INDEX[state] : -1);
      steps.forEach((step, index) => {
        let status = 'pending';
        if (index < current) status = 'done';
        else if (index === current) status = state === 'done' ? 'done' : 'active';
        step.el.dataset.status = status;
      });
    }

    return { el, update };
  }

  /* ---------- Строка доверия: как проверяется файл ---------- */

  function createTrust() {
    const iconBox = h('span', { class: 'update__trust-icon', 'aria-hidden': 'true' });
    const textEl = h('span', { class: 'update__trust-text' });
    const el = h('p', { class: 'update__trust' }, iconBox, textEl);

    function setIcon(kind) {
      iconBox.replaceChildren(kind === 'doing'
        ? h('span', { class: 'spinner', 'aria-hidden': 'true' })
        : icon(kind === 'done' ? 'shieldCheck' : 'lock', { size: 15 }));
    }

    function update(item) {
      const cfg = VERIFY[item.id] || VERIFY_FALLBACK;
      let phase = null;
      if (item.state === 'verifying') phase = 'doing';
      else if (item.state === 'installing' || item.state === 'done') phase = 'done';
      else if (item.available && item.state !== 'error') phase = 'idle';
      setHidden(el, !phase);
      if (!phase) return;
      el.dataset.state = phase;
      setIcon(phase);
      setText(textEl, cfg[phase]);
    }

    return { el, update };
  }

  /* ---------- Действия карточки ---------- */

  function renderActions(data) {
    const { item } = data;
    if (ACTIVE_STATES.has(item.state)) return null;
    const buttons = [];

    if (item.admin && item.available && item.state !== 'done') {
      buttons.push(ui.actionButton({
        method: 'updates_install',
        args: [item.id],
        key: `updates_install:${item.id}`,
        label: item.state === 'error' ? 'Повторить установку' : 'Установить',
        icon: item.state === 'error' ? 'refresh' : 'download',
        kind: 'primary',
        cls: 'btn--hero',
      }).el);
    }

    if (item.url && (item.available || item.state === 'done' || item.state === 'error')) {
      buttons.push(ui.button({
        label: 'Открыть на GitHub',
        icon: 'external',
        kind: 'ghost',
        busyKey: 'open_url',
        onClick: () => Lz.actions.openUrl(item.url),
      }).el);
    }

    if (item.admin && item.available && !item.skipped && item.state !== 'done') {
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

    if (item.admin && item.can_rollback) {
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

    if (!buttons.length) return null;
    buttons.forEach((btn, index) => { btn.dataset.fk = `update-action:${index}`; });
    return buttons;
  }

  /* ---------- Карточка компонента ---------- */

  function createItemCard() {
    const title = h('h2', { class: 'update__title' });
    const subtitle = h('p', { class: 'update__sub' });
    const badge = h('span', { class: 'badge' });

    const current = h('span', { class: 'version__current num' });
    const arrow = h('span', { class: 'version__arrow', 'aria-hidden': 'true' }, icon('arrowRight', { size: 16 }));
    const latest = h('span', { class: 'version__latest num' });
    const published = h('span', { class: 'version__date' });
    const versionLine = h('p', { class: 'version' },
      h('span', { class: 'sr-only', text: 'Версии: ' }), current, arrow, latest, published);

    const trust = createTrust();

    const stepper = createStepper();
    const progress = ui.progressBar({ label: 'Ход обновления' });
    const progressText = h('p', { class: 'update__progress-text', 'aria-live': 'polite' });
    const progressBox = h('div', { class: 'update__progress', hidden: true }, progressText, progress.el);
    const stage = h('div', { class: 'update__stage', hidden: true }, stepper.el, progressBox);

    const message = ui.slot((data) => (data ? ui.callout({ tone: data.tone, text: data.text }) : null), { cls: 'update__message' });
    const actions = ui.slot(renderActions, { cls: 'update__actions' });

    const notesText = h('div', { class: 'notes', tabIndex: 0 });
    const notes = ui.disclosure({ title: 'Что нового в этой версии', content: notesText });
    const notesBox = h('div', { class: 'update__notes' }, notes.el);

    const el = h('section', { class: 'panel update' },
      h('header', { class: 'update__head' },
        h('div', { class: 'update__titles' }, title, subtitle),
        badge),
      versionLine,
      trust.el,
      stage,
      message.el,
      actions.el,
      notesBox);

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

      trust.update(item);

      const active = ACTIVE_STATES.has(item.state);
      const showStage = active || item.state === 'done';
      setHidden(stage, !showStage);
      if (showStage) stepper.update(item.state);
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
        admin: Boolean(item.admin),
      } });

      const notesValue = String(item.notes || '').trim();
      setText(notesText, notesValue);
      setHidden(notesBox, !notesValue);
    }

    return { el, update };
  }

  /* ---------- Страница ---------- */

  function renderBanner(data) {
    if (!data || data.admin) return null;
    return ui.callout({
      tone: 'warn',
      title: 'Для установки нужны права администратора',
      text: 'Новые версии и описание изменений видны и так, но скачать и установить обновление Лазейка сможет только с правами администратора.',
      actions: ui.actionButton({
        method: 'relaunch_admin',
        label: 'Перезапустить с правами администратора',
        icon: 'shieldCheck',
        kind: 'primary',
        size: 'sm',
      }).el,
    });
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

    const policy = h('section', { class: 'panel policy' },
      h('div', { class: 'policy__main' },
        h('div', { class: 'policy__icon', 'aria-hidden': 'true' }, icon('shieldCheck', { size: 22 })),
        h('div', { class: 'policy__text' },
          h('h2', { class: 'policy__title', text: 'Обновления — только когда вы захотите' }),
          h('p', { class: 'policy__desc', text: 'Лазейка только сообщает о новых версиях. Скачиваем и устанавливаем — лишь после того, как вы нажмёте «Установить». Никаких самовольных загрузок и внезапно открытых страниц.' }))),
      h('div', { class: 'policy__controls' },
        autoCheck.el,
        h('div', { class: 'policy__check' }, checkBtn.el, lastCheck)));

    const banner = ui.slot(renderBanner, { cls: 'page__banners' });
    const globalError = ui.slot((text) => (text ? ui.callout({ tone: 'err', title: 'Проверка не удалась', text }) : null));
    const allok = ui.slot((data) => (data ? ui.callout({
      tone: 'ok',
      title: 'Всё актуально',
      text: 'Установлены последние версии Лазейки, стратегий zapret и ядра прокси.',
    }) : null));

    const list = h('div', { class: 'updates-list' });
    const empty = ui.emptyState({
      icon: 'download',
      title: 'Сведений об обновлениях пока нет',
      text: 'Нажмите «Проверить сейчас» — мы только посмотрим, есть ли новые версии.',
    });

    const header = ui.pageHeader({ title: 'Обновления', subtitle: 'Сама Лазейка, стратегии zapret и ядро прокси для Telegram' });
    const el = h('div', { class: 'page__inner' }, header.el, banner.el, policy, globalError.el, allok.el, list, empty);

    function syncItems(items, admin) {
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
        card.update({ ...item, admin });
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
        const admin = Boolean(state.app && state.app.admin);

        autoCheck.sw.set(settings.check_updates != null ? settings.check_updates : updates.auto_check);
        checkBtn.setBusy(Boolean(updates.checking));
        checkBtn.setLabel(updates.checking ? 'Проверяем…' : 'Проверить сейчас');
        const ago = fmt.relative(updates.last_check);
        setText(lastCheck, ago ? `Последняя проверка: ${ago}` : 'Ещё не проверяли');

        banner.update({ admin });
        globalError.update(updates.error || null);

        const items = Array.isArray(updates.items) ? updates.items : [];
        syncItems(items, admin);
        setHidden(empty, items.length > 0);

        const calm = items.length > 0 && items.every((item) => !item.available
          && !ACTIVE_STATES.has(item.state) && item.state !== 'done' && item.state !== 'error');
        allok.update(calm ? true : null);
      },
    };
  }

  Lz.pages.updates = { title: 'Обновления', icon: 'download', create };
})(window.Lz);
