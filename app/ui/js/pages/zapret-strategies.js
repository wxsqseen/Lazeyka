'use strict';
/* Обход: выбор стратегии и автоматический подбор лучшей. */
(function (Lz) {
  const { h, icon, setText, setHidden } = Lz.dom;
  const ui = Lz.ui;
  const fmt = Lz.fmt;
  const texts = Lz.texts;

  const GOOD_SCORE = 0.9;
  const FAIR_SCORE = 0.6;
  const DIRECT_SENTENCE = 'Проверено напрямую, мимо VPN.';
  const CHECK_CLASS = { ok: 'ok', fail: 'fail', unsup: 'unsup', ssl: 'ssl' };
  const CHECK_PARTS = [['HTTP', 'http'], ['TLS 1.2', 'tls12'], ['TLS 1.3', 'tls13']];
  const KIND_HINT = {
    standard: 'Проверяем HTTP и TLS до Discord, YouTube, Google и Cloudflare с каждой стратегией. Пара минут; на это время обход будет переключаться.',
    dpi: 'Ищем «заморозку» соединения на 16–20 КБ — так режет трафик DPI у части провайдеров. Дольше, зато ловит «вечную загрузку».',
  };

  /* ---------- Список стратегий ---------- */

  /** Справа от имени: «★ лучшая» и доля успешных проверок; у непроверенных стратегий — ничего. */
  function ratingTag(rating) {
    if (!rating || (!rating.best && rating.score === null)) return null;
    return h('span', { class: ['strategy__rating', rating.best && 'is-best'] },
      rating.best ? h('span', { class: 'strategy__best', title: 'Лучшая по результатам подбора' },
        icon('star', { size: 13, cls: 'icon--filled' }), 'лучшая') : null,
      rating.score !== null ? h('span', {
        class: 'strategy__score num',
        title: 'Доля успешных проверок в последнем подборе',
        text: fmt.percent(rating.score),
      }) : null);
  }

  function strategyButton(item, data, onPick) {
    const isActive = item.id === data.active;
    const isPending = item.id === data.pending;
    const label = item.label || item.id;
    const btn = h('button', {
      type: 'button',
      class: ['strategy', isActive && 'is-active', isPending && 'is-pending'],
      'aria-pressed': String(isActive),
      'aria-disabled': String(Boolean(data.locked)),
      title: label !== item.id ? item.id : null,
      dataset: { fk: `strategy:${item.id}` },
    },
    h('span', { class: 'strategy__mark', 'aria-hidden': 'true' }, isPending ? h('span', { class: 'spinner' }) : null),
    h('span', { class: 'strategy__label', text: label }),
    ratingTag(data.ratings[item.id]));
    btn.addEventListener('click', () => {
      if (!isActive && !data.locked) onPick(item.id);
    });
    return btn;
  }

  function createStrategySection() {
    let query = '';
    let pendingId = null;
    let latest = null;

    const search = h('input', {
      class: 'input input--search',
      type: 'search',
      placeholder: 'Найти стратегию',
      'aria-label': 'Найти стратегию',
      autocomplete: 'off',
      spellcheck: false,
    });
    const searchBox = h('div', { class: 'search' }, icon('search', { size: 16, cls: 'search__icon' }), search);
    search.addEventListener('input', () => {
      query = search.value.trim().toLowerCase();
      render();
    });

    async function pick(id) {
      pendingId = id;
      render();
      try {
        await Lz.actions.setStrategy(id);
      } finally {
        pendingId = null;
        render();
      }
    }

    const grid = ui.slot((data) => {
      const items = data.items.filter((item) => !data.query ||
        String(item.label || '').toLowerCase().includes(data.query) ||
        String(item.id).toLowerCase().includes(data.query));
      if (!data.items.length) {
        return ui.emptyState({ icon: 'route', title: 'Стратегий нет', text: 'Пакет стратегий не найден. Установите его на странице «Обновления».' });
      }
      if (!items.length) {
        return ui.emptyState({ icon: 'search', title: 'Ничего не нашлось', text: 'Попробуйте «ALT», «FAKE» или «SIMPLE».' });
      }
      return items.map((item) => strategyButton(item, data, pick));
    }, { cls: 'strategies', attrs: { role: 'group', 'aria-label': 'Стратегии' } });

    const card = ui.card({
      title: 'Стратегия',
      subtitle: 'Набор приёмов, которым zapret обходит замедление. Не открывается что-то — выберите другую или запустите подбор.',
      actions: searchBox,
    });
    card.body.append(grid.el);

    function render() {
      if (!latest) return;
      const zapret = latest.zapret || {};
      const items = Array.isArray(zapret.strategies) ? zapret.strategies : [];
      const ratings = Object.create(null);
      for (const item of items) ratings[item.id] = texts.strategyRating(zapret, item.id);
      grid.update({
        items,
        active: zapret.strategy || null,
        ratings,
        pending: pendingId,
        locked: zapret.available === false,
        query,
      });
    }

    return {
      el: card.el,
      update(state) {
        latest = state;
        render();
      },
    };
  }

  /* ---------- Подбор ---------- */

  function scoreTone(score) {
    if (score >= GOOD_SCORE) return 'ok';
    if (score >= FAIR_SCORE) return 'warn';
    return 'err';
  }

  function targetCell(target) {
    const states = CHECK_PARTS.map(([, key]) => target[key] || null);
    const description = CHECK_PARTS
      .map(([name], index) => `${name} — ${texts.CHECK_RESULT[states[index] || 'none'] || states[index]}`)
      .join(', ');
    const ping = target.ping != null ? `, пинг ${target.ping} мс` : '';
    const name = target.name || target.url || 'Сайт';
    return h('span', { class: 'tcell', title: `${name}: ${description}${ping}` },
      states.map((value) => h('i', { class: `tcell__seg is-${CHECK_CLASS[value] || 'none'}` })));
  }

  function rankCell(result, index, best) {
    if (result.id === best) {
      return h('td', { class: 'results__rank is-best', title: 'Лучшая' }, icon('star', { size: 16, cls: 'icon--filled' }));
    }
    return h('td', { class: 'results__rank', text: String(index + 1) });
  }

  function scoreCell(result) {
    const score = Math.max(0, Math.min(1, Number(result.score) || 0));
    const total = (Number(result.ok) || 0) + (Number(result.fail) || 0) + (Number(result.unsup) || 0);
    return h('td', { class: 'results__score' },
      h('div', { class: `score score--${scoreTone(score)}` },
        h('div', { class: 'score__bar' }, h('div', { class: 'score__fill', style: `width: ${(score * 100).toFixed(1)}%` })),
        h('span', { class: 'score__value num', text: fmt.percent(score) })),
      total ? h('span', { class: 'results__counts num', text: `${result.ok || 0} из ${total}` }) : null);
  }

  function actionCell(result, data) {
    if (result.id === data.active && data.zapretOn) {
      return h('td', { class: 'results__action' }, h('span', { class: 'tag tag--ok', text: 'Работает' }));
    }
    const btn = ui.button({
      label: 'Включить',
      size: 'sm',
      onClick: async (event, ctl) => {
        ctl.setBusy(true);
        try {
          await Lz.actions.useStrategy(result.id);
        } finally {
          ctl.setBusy(false);
        }
      },
    });
    btn.el.dataset.fk = `use:${result.id}`;
    btn.setDisabled(data.running || data.locked || result.started === false);
    return h('td', { class: 'results__action' }, btn.el);
  }

  function resultRow(result, index, data) {
    const failed = result.started === false;
    const targets = Array.isArray(result.targets) ? result.targets : [];
    return h('tr', { class: [result.id === data.best && 'is-best', failed && 'is-failed'] },
      rankCell(result, index, data.best),
      h('th', { scope: 'row', class: 'results__name' },
        h('span', { class: 'results__label', text: result.label || result.id }),
        result.label && result.label !== result.id ? h('span', { class: 'results__id', text: result.id }) : null),
      h('td', { class: 'results__targets' }, failed
        ? h('span', { class: 'muted', text: 'Не запустилась' })
        : h('span', { class: 'tstrip' }, targets.map(targetCell))),
      h('td', { class: 'results__ping num', text: result.ping_total ? `${result.ping_ok || 0}/${result.ping_total}` : '—' }),
      scoreCell(result),
      actionCell(result, data));
  }

  function legend() {
    const item = (cls, text) => h('span', { class: 'legend__item' }, h('i', { class: `legend__swatch is-${cls}` }), text);
    return h('p', { class: 'legend' },
      item('ok', 'работает'),
      item('fail', 'не открывается'),
      item('ssl', 'подмена сертификата'),
      item('unsup', 'не поддерживается'),
      item('none', 'не проверялось'),
      h('span', { class: 'legend__note', text: 'В каждом квадрате — HTTP, TLS 1.2 и TLS 1.3' }));
  }

  function sortResults(results) {
    return results.slice().sort((a, b) => {
      const failedA = a.started === false ? 1 : 0;
      const failedB = b.started === false ? 1 : 0;
      if (failedA !== failedB) return failedA - failedB;
      return (Number(b.score) || 0) - (Number(a.score) || 0) || (Number(b.ok) || 0) - (Number(a.ok) || 0);
    });
  }

  function renderResults(data) {
    if (!data.results.length) return null;
    const rows = sortResults(data.results).map((result, index) => resultRow(result, index, data));
    return [
      h('div', { class: 'table-wrap' },
        h('table', { class: 'results' },
          h('thead', null, h('tr', null,
            h('th', { scope: 'col', class: 'results__rank' }, h('span', { class: 'sr-only', text: 'Место' })),
            h('th', { scope: 'col', text: 'Стратегия' }),
            h('th', { scope: 'col', text: 'Сайты' }),
            h('th', { scope: 'col', class: 'results__ping', text: 'Пинг' }),
            h('th', { scope: 'col', text: 'Успешно' }),
            h('th', { scope: 'col' }, h('span', { class: 'sr-only', text: 'Действие' })))),
          h('tbody', null, rows))),
      legend(),
    ];
  }

  function renderSummary(data) {
    if (data.error) return ui.callout({ tone: 'err', title: 'Подбор прервался', text: data.error });
    if (data.running) return null;
    if (!data.results.length) {
      return ui.emptyState({
        icon: 'sparkle',
        title: 'Подбор ещё не запускался',
        text: 'Нажмите «Начать подбор» — Лазейка сама найдёт стратегию, с которой у вас всё открывается.',
      });
    }
    const finishedText = data.finishedAgo ? ` Закончили ${data.finishedAgo}.` : '';
    const directText = data.direct ? ` ${DIRECT_SENTENCE}` : '';
    if (data.done < data.total) {
      return ui.callout({ tone: 'info', text: `Подбор остановлен: проверено ${data.done} из ${data.total}.${finishedText}${directText}` });
    }
    if (!data.best) {
      return ui.callout({ tone: 'warn', title: 'Ни одна стратегия не справилась', text: `Попробуйте проверку DPI или включите IP-список в фильтрах ниже.${directText}` });
    }
    const bestResult = data.results.find((result) => result.id === data.best);
    const bestLabel = bestResult ? bestResult.label || bestResult.id : data.best;
    const text = [
      bestResult ? `${fmt.percent(bestResult.score)} проверок прошли успешно.` : null,
      data.finishedAgo ? `Закончили ${data.finishedAgo}.` : null,
      data.direct ? DIRECT_SENTENCE : null,
    ].filter(Boolean).join(' ');
    let action = null;
    if (data.best === data.active && data.zapretOn) {
      action = h('span', { class: 'tag tag--ok', text: 'Работает' });
    } else {
      action = ui.button({
        label: data.best === data.active ? 'Включить обход' : `Включить ${bestLabel}`,
        kind: 'primary',
        size: 'sm',
        busyKey: 'zapret_power',
        onClick: () => Lz.actions.useStrategy(data.best),
      }).el;
    }
    return ui.callout({ tone: 'ok', title: `Лучшая стратегия — ${bestLabel}`, text, actions: action });
  }

  function createTestSection() {
    let kind = 'standard';

    const kindHint = h('p', { class: 'test__hint', text: KIND_HINT.standard });
    const kindSeg = ui.segmented({
      label: 'Вид проверки',
      value: kind,
      options: [
        { value: 'standard', label: 'Обычная' },
        { value: 'dpi', label: 'DPI 16–20 КБ' },
      ],
      onChange: (value) => {
        kind = value;
        setText(kindHint, KIND_HINT[value]);
      },
    });
    const startBtn = ui.button({
      label: 'Начать подбор',
      icon: 'play',
      kind: 'primary',
      busyKey: 'zapret_test_start',
      onClick: () => Lz.api.run({ method: 'zapret_test_start', args: [kind, null] }),
    });
    const cancelBtn = ui.actionButton({ method: 'zapret_test_cancel', label: 'Остановить', icon: 'stop', size: 'sm' });
    const progress = ui.progressBar({ label: 'Ход подбора' });
    const progressText = h('p', { class: 'test__progress-text', 'aria-live': 'polite' });
    const progressBox = h('div', { class: 'test__progress', hidden: true },
      h('div', { class: 'test__progress-row' }, progressText, cancelBtn.el),
      progress.el);
    const controls = h('div', { class: 'test__controls' }, kindSeg.el, startBtn.el);
    const summary = ui.slot(renderSummary, { cls: 'test__summary' });
    const resultsView = ui.slot(renderResults, { cls: 'test__results' });

    const card = ui.card({
      title: 'Подбор стратегии',
      subtitle: 'Лазейка по очереди включит каждую стратегию и проверит, какие сайты открываются.',
    });
    card.body.append(controls, kindHint, progressBox, summary.el, resultsView.el);

    function update(state) {
      const zapret = state.zapret || {};
      const test = zapret.test || {};
      const running = Boolean(test.running);
      const total = Number(test.total) || 0;
      const done = Number(test.done) || 0;
      const locked = zapret.available === false;

      setHidden(controls, running);
      setHidden(kindHint, running);
      setHidden(progressBox, !running);
      startBtn.setDisabled(locked);
      kindSeg.setDisabled(locked);
      if (running) {
        progress.set(total ? done / total : null);
        const current = test.current ? `«${texts.strategyLabel(zapret, test.current)}»` : 'следующую стратегию';
        const direct = test.direct ? ' · напрямую, мимо VPN' : '';
        setText(progressText, total ? `Проверяем ${current} · ${done} из ${total}${direct}` : `Проверяем ${current}${direct}`);
      }

      const results = Array.isArray(test.results) ? test.results : [];
      const best = test.best || null;
      const active = zapret.strategy || null;
      const zapretOn = zapret.status === 'running' || zapret.status === 'starting';
      summary.update({
        running,
        results,
        best,
        active,
        zapretOn,
        error: test.error || null,
        done,
        total,
        finishedAgo: fmt.relative(test.finished_at),
        direct: Boolean(test.direct),
      });
      resultsView.update({ running, results, best, active, locked, zapretOn });
    }

    return { el: card.el, update };
  }

  Lz.zapretSections = Object.assign(Lz.zapretSections || {}, {
    createStrategySection,
    createTestSection,
  });
})(window.Lz);
