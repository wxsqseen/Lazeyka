'use strict';
/* «Помощь» → «Проверка компьютера»: поиск того, что мешает обходу (бывшая страница «Диагностика»). */
(function (Lz) {
  const { h, icon } = Lz.dom;
  const ui = Lz.ui;
  const fmt = Lz.fmt;

  const STATUS_VIEW = {
    ok: { icon: 'checkCircle', tone: 'ok', word: 'в порядке' },
    warn: { icon: 'alert', tone: 'warn', word: 'предупреждение' },
    error: { icon: 'xCircle', tone: 'err', word: 'проблема' },
    info: { icon: 'info', tone: 'info', word: 'к сведению' },
  };
  const STATUS_ORDER = { error: 0, warn: 1, info: 2, ok: 3 };

  function summaryText(items) {
    const counts = { ok: 0, warn: 0, error: 0, info: 0 };
    for (const item of items) counts[item.status in counts ? item.status : 'info'] += 1;
    const parts = [];
    if (counts.error) parts.push(fmt.count(counts.error, 'проблема', 'проблемы', 'проблем'));
    if (counts.warn) parts.push(fmt.count(counts.warn, 'предупреждение', 'предупреждения', 'предупреждений'));
    if (counts.ok) parts.push(`${fmt.integer(counts.ok)} в порядке`);
    return { counts, text: parts.join(' · ') };
  }

  function itemEl(item) {
    const view = STATUS_VIEW[item.status] || STATUS_VIEW.info;
    const fix = item.fix && item.fix.id ? ui.actionButton({
      method: 'diag_fix',
      args: [item.fix.id],
      key: `diag_fix:${item.fix.id}`,
      label: item.fix.label || 'Исправить',
      icon: 'wrench',
      size: 'sm',
      kind: view.tone === 'err' ? 'primary' : 'secondary',
      success: 'Готово. Запустите проверку ещё раз, чтобы убедиться.',
    }) : null;
    if (fix) fix.el.dataset.fk = `fix:${item.fix.id}`;
    return h('li', { class: `issue issue--${view.tone}` },
      h('span', { class: 'issue__icon', 'aria-hidden': 'true' }, icon(view.icon, { size: 18 })),
      h('div', { class: 'issue__body' },
        h('p', { class: 'issue__title' }, item.title || item.id, h('span', { class: 'sr-only', text: ` — ${view.word}` })),
        item.text ? h('p', { class: 'issue__text', text: item.text }) : null),
      fix && fix.el);
  }

  function renderResults(data) {
    if (!data.items.length) {
      if (data.running) {
        return h('p', { class: 'muted' }, h('span', { class: 'spinner spinner--inline', 'aria-hidden': 'true' }), 'Проверяем службы, программы и настройки сети…');
      }
      return ui.emptyState({
        icon: 'pulse',
        title: 'Проверка ещё не запускалась',
        text: 'Займёт несколько секунд. Ничего не меняем без вашего нажатия на «Исправить».',
      });
    }
    const sorted = data.items.slice().sort((a, b) => (STATUS_ORDER[a.status] ?? 2) - (STATUS_ORDER[b.status] ?? 2));
    const summary = summaryText(data.items);
    const tone = summary.counts.error ? 'err' : (summary.counts.warn ? 'warn' : 'ok');
    return [
      h('div', { class: `diag-summary diag-summary--${tone}` },
        icon(tone === 'ok' ? 'checkCircle' : 'alert', { size: 18 }),
        h('span', { text: tone === 'ok' ? 'Всё в порядке' : summary.text }),
        data.running ? h('span', { class: 'spinner spinner--inline', 'aria-hidden': 'true' }) : null,
        data.ago ? h('span', { class: 'diag-summary__time', text: `проверено ${data.ago}` }) : null),
      h('ul', { class: 'issue-list' }, sorted.map(itemEl)),
    ];
  }

  function createDiagnostics() {
    const runBtn = ui.button({
      label: 'Запустить проверку',
      icon: 'play',
      size: 'sm',
      busyKey: 'diag_run',
      onClick: () => Lz.api.run({ method: 'diag_run' }),
    });
    const results = ui.slot(renderResults);
    const card = ui.card({
      title: 'Проверка компьютера',
      subtitle: 'Найдём, что мешает обходу: конфликтующие программы, службы и настройки Windows.',
      actions: runBtn.el,
    });
    card.body.append(results.el);

    return {
      el: card.el,
      update(state) {
        const diag = state.diag || {};
        runBtn.setBusy(Boolean(diag.running));
        runBtn.setLabel(diag.running ? 'Проверяем…' : 'Запустить проверку');
        results.update({
          running: Boolean(diag.running),
          items: Array.isArray(diag.items) ? diag.items : [],
          ago: fmt.relative(diag.at),
        });
      },
    };
  }

  Lz.helpSections = Object.assign(Lz.helpSections || {}, { createDiagnostics });
})(window.Lz);
