'use strict';
/*
 * Страница «Помощь»: «Что не работает?» (help-symptoms.js), DNS (help-dns.js), отчёт для того,
 * кто помогает, и «Проверка компьютера» (help-diag.js) — бывшая страница «Диагностика».
 */
(function (Lz) {
  const { h, setText, setHidden } = Lz.dom;
  const ui = Lz.ui;

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
    const all = [symptoms, sections.createDns(), createReport(), sections.createDiagnostics()];
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
