'use strict';
/*
 * Страница «Помощь»: паспорт провайдера, «Что не работает?» (help-symptoms.js), DNS (help-dns.js), отчёт
 * для того, кто помогает, и «Проверка компьютера» (help-diag.js) — бывшая страница «Диагностика».
 */
(function (Lz) {
  const { h, icon, setText, setHidden } = Lz.dom;
  const ui = Lz.ui;

  /* ---------- Паспорт провайдера ---------- */

  const PASSPORT_STAGE = {
    check: (p) => `Проверяем сайты: ${p.done || 0} из ${p.total || 0}…`,
    apply: () => 'Раскладываем: что в обход, что через ваш VPN, что мимо него…',
    recheck: () => 'Проверяем ещё раз то, что добавили в обход…',
  };

  function renderPassport(items) {
    if (!items.length) return null;
    return h('ul', { class: 'checklist passport' }, items.map((item) => {
      const fine = item.ok === true;
      const quiet = item.verdict === 'down' || item.verdict === 'unreachable';
      return h('li', { class: ['checklist__item', fine ? 'is-ok' : quiet ? 'is-skip' : 'is-fail'] },
        h('span', { class: 'checklist__icon', 'aria-hidden': 'true' },
          icon(fine ? 'checkCircle' : quiet ? 'alertCircle' : 'xCircle', { size: 18 })),
        h('span', { class: 'checklist__name', text: item.label }),
        h('span', { class: 'sr-only', text: fine ? 'работает' : 'не работает' }),
        h('span', { class: 'checklist__detail', text: [item.what, item.action].filter(Boolean).join(' — ') }));
    }));
  }

  function createPassport() {
    const run = ui.button({
      label: 'Проверить и настроить',
      icon: 'search',
      kind: 'primary',
      busyKey: 'passport_check',
      onClick: () => Lz.api.run({ method: 'passport_check', key: 'passport_check' }),
    });
    const progress = ui.slot((text) => (text ? Lz.helpPanels.parts.spinnerLine(text) : null), { cls: 'passport__progress' });
    const summary = h('p', { class: 'passport__summary', hidden: true });
    const list = ui.slot(renderPassport, { cls: 'passport-wrap' });
    const card = ui.card({ title: 'Паспорт провайдера' });
    card.body.append(
      h('div', { class: 'action-row' },
        h('div', { class: 'action-row__text' },
          h('p', { class: 'action-row__title', text: 'Что режет ваш провайдер?' }),
          h('p', { class: 'action-row__desc', text: 'Проверим 15 популярных сайтов и сразу всё разложим: что откроет обход, что пойдёт через ваш VPN, а что — мимо него. Около минуты.' })),
        run.el),
      progress.el,
      summary,
      list.el);
    return {
      el: card.el,
      update(state) {
        const passport = state.passport && typeof state.passport === 'object' ? state.passport : {};
        const running = Boolean(passport.running);
        run.setBusy(running);
        progress.update(running ? (PASSPORT_STAGE[passport.stage] || PASSPORT_STAGE.check)(passport) : '');
        const text = running ? '' : String(passport.summary || '');
        setText(summary, text);
        setHidden(summary, !text);
        const items = Array.isArray(passport.items) ? passport.items : [];
        list.update(running ? [] : items.map((item) => ({
          label: String(item.label || item.domain || ''), verdict: String(item.verdict || ''),
          what: item.what ? String(item.what) : '', action: item.action ? String(item.action) : '', ok: item.ok === true,
        })));
      },
    };
  }

  function createReport() {
    const preview = h('pre', { class: 'notes report__text', tabIndex: 0, 'aria-label': 'Текст отчёта' });
    const disclosure = ui.disclosure({ title: 'Показать отчёт', content: preview });
    setHidden(disclosure.el, true);

    async function copyReport() {
      const result = await Lz.api.run({ method: 'help_report' });
      if (!result || !result.ok) return;
      const text = String(result.text || '');
      setText(preview, text);
      setHidden(disclosure.el, !text);
      if (result.copied === false) {
        ui.toast({ kind: 'warn', text: 'Не получилось положить отчёт в буфер обмена — откройте его ниже и скопируйте вручную.' });
        disclosure.setOpen(true);
        return;
      }
      ui.toast({ kind: 'success', text: 'Отчёт скопирован — вставьте его в сообщение тому, кто помогает' });
    }

    const copyBtn = ui.button({ label: 'Скопировать отчёт', icon: 'copy', busyKey: 'help_report', onClick: () => copyReport() });
    const card = ui.card({ title: 'Отчёт для помощи' });
    card.body.append(
      h('div', { class: 'action-row' },
        h('div', { class: 'action-row__text' },
          h('p', { class: 'action-row__title', text: 'Нужна помощь человека?' }),
          h('p', { class: 'action-row__desc', text: 'Соберём версии, состояние обхода и прокси и последние предупреждения — без ключа прокси и имени пользователя. Отчёт сразу окажется в буфере обмена.' })),
        copyBtn.el),
      disclosure.el);
    return { el: card.el, update() {} };
  }

  function create() {
    const sections = Lz.helpSections;
    const header = ui.pageHeader({
      title: 'Помощь',
      /* «Выберите, что не работает…» — подсказка в карточке признаков; здесь — что есть на странице. */
      subtitle: 'Подсказки по признакам, проверка DNS и компьютера, отчёт для помощи человека.',
    });
    const symptoms = sections.createSymptoms({ initial: Lz.params.get('symptom') });
    const all = [createPassport(), symptoms, sections.createDns(), createReport(), sections.createDiagnostics()];
    const el = h('div', { class: 'page__inner' }, header.el, all.map((section) => section.el));

    return {
      el,
      update(state) {
        for (const section of all) section.update(state);
      },
      /* Lz.nav.go('help', { symptom: 'vpn' }) — сразу открыть нужную панель. */
      show(opts) {
        if (!opts || !opts.symptom || !symptoms.select(opts.symptom)) return;
        requestAnimationFrame(() => symptoms.el.scrollIntoView({ block: 'start', behavior: Lz.nav.scrollBehavior() }));
      },
    };
  }

  Lz.pages.help = { title: 'Помощь', icon: 'help', create };
})(window.Lz);
