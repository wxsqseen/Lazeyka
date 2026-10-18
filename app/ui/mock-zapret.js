'use strict';
/*
 * Имитация дополнений контракта 1.1 для обхода (docs/ui-contract.md, «Версия 1.1 — дополнения»):
 * быстрая проверка доступности, «Найти и включить» и возврат стратегии, оценки стратегий
 * по последнему подбору, сторож. Подключается из mock.js — отдельно не работает.
 *
 * Дополнительные параметры адреса:
 *   demo=fix       — провайдер «сломал» текущую стратегию, сразу запускается «Найти и включить»
 *   demo=fix-fail  — то же, но не подходит ни одна стратегия: подбор заканчивается неудачей
 *   demo=watchdog  — сторож заметил, что YouTube перестал открываться, и предлагает починить
 */
(window.LzMockExtensions = window.LzMockExtensions || []).push(function installZapretV11(mock) {
  const { state, api, nowSec, later, ok, fail, log } = mock;

  const QUICK_CHECK_MS = 2400;
  const FIX_STEP_MS = { start: 1600, check: 1400, probe: 1500, apply: 1300, verify: 1300 };
  const FIX_MAX_CANDIDATES = 6;
  const NOTICE_TTL_MS = 25000;
  /* С какого «качества» стратегии (STRATEGY_QUALITY в mock.js) открываются Discord и YouTube. */
  const DISCORD_FROM_QUALITY = 0.6;
  const YOUTUBE_FROM_QUALITY = 0.85;
  const UNKNOWN_QUALITY = 0.5;
  const LAST_CHECK_AGO_SEC = 250;
  const WATCHDOG_MODES = ['ask', 'auto', 'off'];
  const WATCHDOG_INTERVAL_SEC = 600;
  const WATCHDOG_LAST_AGO_SEC = 180;
  const DAY_SEC = 86400;
  const DEFAULT_CANDIDATES = [
    'general', 'general (ALT)', 'general (ALT2)', 'general (FAKE TLS AUTO)', 'general (SIMPLE FAKE)', 'general (ALT5)',
  ];
  /* Оценки «прошлого» полного подбора — будто его запускали позавчера. */
  const LAST_REPORT = {
    at: mock.startedAt - 2 * DAY_SEC,
    scores: {
      'general (ALT2)': 0.97, 'general (ALT)': 0.91, 'general (FAKE TLS AUTO)': 0.88, 'general (ALT5)': 0.86,
      general: 0.74, 'general (SIMPLE FAKE)': 0.58, 'general (ALT3)': 0.41, 'general (ALT6)': 0.33,
    },
  };

  /* ---------- Что открывается ---------- */

  /* Стратегии, у которых «провайдер» начал резать видео YouTube (demo=fix, demo=watchdog). */
  const degraded = new Set();
  let checkFingerprint = null;

  function label(id) {
    const found = mock.STRATEGIES.find((item) => item.id === id);
    return found ? found.label : String(id);
  }

  function opensWith(id) {
    const known = mock.STRATEGY_QUALITY[id];
    const quality = known != null ? known : UNKNOWN_QUALITY;
    return { discord: quality >= DISCORD_FROM_QUALITY, youtube: quality >= YOUTUBE_FROM_QUALITY && !degraded.has(id) };
  }

  function quickCheck() {
    const zapret = state.zapret;
    const opens = zapret.status === 'running' ? opensWith(zapret.strategy) : { discord: false, youtube: false };
    return [
      { id: 'discord', label: 'Discord', ok: opens.discord, detail: opens.discord ? '3/3' : '1/3' },
      { id: 'youtube', label: 'YouTube', ok: opens.youtube, detail: opens.youtube ? '3/3, видео ✓' : '2/3, видео ✗' },
    ];
  }

  function fingerprint() {
    const zapret = state.zapret;
    return JSON.stringify([zapret.status, zapret.strategy, zapret.game_filter, zapret.ipset.mode, zapret.started_at]);
  }

  /** Проверки идут мимо VPN, если весь интернет сейчас в туннеле (state.vpn ведёт mock-vpn.js). */
  function checksDirect() {
    const vpn = state.vpn;
    return Boolean(vpn && vpn.active && vpn.full_tunnel && vpn.source_ip);
  }

  function storeCheck(results, at) {
    state.zapret.check = { running: false, at: at || nowSec(), results, direct: checksDirect() };
    checkFingerprint = fingerprint();
  }

  /** Как ядро: результат проверки забываем, как только обход перенастроили или перезапустили. */
  function forgetStaleCheck() {
    const check = state.zapret.check;
    if (!check.running && check.results && checkFingerprint !== fingerprint()) {
      state.zapret.check = { running: false, at: null, results: null };
    }
  }

  api.zapret_check = function zapretCheck() {
    const check = state.zapret.check;
    if (check.running) return ok();
    state.zapret.check = { running: true, at: check.at, results: check.results };
    later(QUICK_CHECK_MS, () => storeCheck(quickCheck()));
    return ok();
  };

  /* ---------- Оценки стратегий ---------- */

  function refreshRatings() {
    const zapret = state.zapret;
    const test = zapret.test;
    const fromTest = test.kind === 'standard' && test.results.length > 0;
    const scores = fromTest
      ? Object.fromEntries(test.results.filter((result) => result.started).map((result) => [result.id, result.score]))
      : { ...LAST_REPORT.scores };
    const bestId = fromTest
      ? mock.bestResult(test.results)
      : Object.keys(scores).reduce((best, id) => (best === null || scores[id] > scores[best] ? id : best), null);
    zapret.scores = scores;
    zapret.best = bestId
      ? { id: bestId, label: label(bestId), score: scores[bestId] ?? null, at: fromTest ? test.finished_at : LAST_REPORT.at }
      : null;
  }

  /* ---------- «Найти и включить» ---------- */

  function setFix(changes) {
    Object.assign(state.zapret.fix, changes);
  }

  function finishFix(stage, message, found) {
    setFix({ running: false, stage, message, found: found || null, current: null, finished_at: nowSec() });
    log('zapret', stage === 'done' ? 'info' : 'warn', `«Найти и включить»: ${message}`);
    /* Как Core._reconcile_fix: удача снимает плашку сторожа, неудача подбора сторожа — меняет её текст. */
    if (stage === 'done') {
      mock.dropNotice('watchdog');
    } else if (watchdogFixing) {
      watchdogAlert(`${watchdogFixing}, а подобрать стратегию не вышло. ${message}`, true);
    }
    watchdogFixing = null;
  }

  /* Постоянная плашка сторожа (persistent): висит до удачной проверки, уведомлений нет. */
  let watchdogFixing = null;
  function watchdogAlert(text, withAction) {
    mock.setNotice({
      id: 'watchdog', level: 'warn', text, page: 'zapret', persistent: true, dismissible: true,
      action: withAction ? { label: 'Найти и включить', call: 'zapret_fix', args: [] } : null,
    });
  }

  function noticeFor(id, level, text) {
    mock.setNotice({ id, level, text, action: null, dismissible: true });
    later(NOTICE_TTL_MS, () => mock.dropNotice(id));
  }

  function candidates(exclude) {
    const scores = state.zapret.scores || {};
    const ranked = Object.keys(scores).filter((id) => scores[id] > 0).sort((a, b) => scores[b] - scores[a]);
    const order = ranked.concat(DEFAULT_CANDIDATES.filter((id) => !ranked.includes(id)));
    return order.filter((id) => id !== exclude && mock.STRATEGY_IDS.includes(id)).slice(0, FIX_MAX_CANDIDATES);
  }

  function verifyStep(found) {
    setFix({ stage: 'verify', message: 'Проверяем ещё раз…' });
    later(FIX_STEP_MS.verify, () => {
      const results = quickCheck();
      setFix({ results });
      if (!results.every((result) => result.ok)) {
        finishFix('failed', `«${label(found)}» прошла пробу, но проверка после включения не прошла. Попробуйте полный подбор.`, found);
        return;
      }
      finishFix('done', `Включили «${label(found)}»: Discord и YouTube открываются.`, found);
      noticeFor('fix-done', 'success', `Обход починен: включена стратегия «${label(found)}».`);
    });
  }

  function applyStep(found) {
    setFix({ stage: 'apply', current: null, message: `Включаем «${label(found)}»…` });
    state.zapret.strategy = found;
    mock.startZapret('найти и включить');
    later(FIX_STEP_MS.apply, () => verifyStep(found));
  }

  /** Как ядро: на время проб обход выключен, каждая стратегия запускается отдельно и проверяется. */
  function pickStep(queue, index) {
    const zapret = state.zapret;
    if (index === 0) {
      zapret.status = 'stopped';
      zapret.started_at = null;
      setFix({ stage: 'pick' });
    }
    if (index >= queue.length) {
      mock.startZapret('после проб');
      finishFix('failed', 'Среди лучших стратегий подходящей не нашлось. Запустите полный подбор — он проверит все стратегии.');
      return;
    }
    const id = queue[index];
    setFix({ current: id, tried: zapret.fix.tried.concat(id), message: `Пробуем «${label(id)}»…` });
    later(FIX_STEP_MS.probe, () => {
      const opens = opensWith(id);
      if (opens.discord && opens.youtube) applyStep(id);
      else pickStep(queue, index + 1);
    });
  }

  function checkStep() {
    const fix = state.zapret.fix;
    setFix({ message: 'Проверяем, открываются ли Discord и YouTube…' });
    later(FIX_STEP_MS.check, () => {
      const results = quickCheck();
      setFix({ results });
      if (results.every((result) => result.ok)) {
        finishFix('done', `Всё открывается на «${label(fix.previous)}» — менять ничего не нужно.`, fix.previous);
        return;
      }
      pickStep(candidates(fix.previous), 0);
    });
  }

  api.zapret_fix = function zapretFix() {
    const denied = mock.requireZapret();
    if (denied) return denied;
    const zapret = state.zapret;
    if (zapret.fix.running || zapret.test.running) return fail('Подбор уже идёт');
    zapret.fix = {
      running: true, stage: 'check', message: 'Проверяем, открываются ли Discord и YouTube…', current: null,
      tried: [], found: null, previous: zapret.strategy, results: null, finished_at: null, direct: checksDirect(),
    };
    log('zapret', 'info', '«Найти и включить»: проверяем текущую стратегию');
    if (zapret.status === 'running') {
      checkStep();
    } else {
      setFix({ message: 'Включаем обход…' });
      mock.startZapret('найти и включить');
      later(FIX_STEP_MS.start, checkStep);
    }
    return ok();
  };

  api.zapret_fix_revert = function zapretFixRevert() {
    const denied = mock.requireZapret();
    if (denied) return denied;
    const zapret = state.zapret;
    const previous = zapret.fix.previous;
    if (!previous) return fail('Возвращать нечего');
    if (zapret.fix.running || zapret.test.running) return fail('Дождитесь окончания подбора');
    zapret.strategy = previous;
    if (zapret.status === 'running' || zapret.status === 'error') mock.startZapret('возврат стратегии');
    setFix({ found: previous, message: `Вернули «${label(previous)}».` });
    return ok({ message: `Вернули стратегию «${previous}».` });
  };

  const startTest = api.zapret_test_start;
  api.zapret_test_start = function zapretTestStart(...args) {
    if (state.zapret.fix.running) return fail('Подбор уже идёт');
    return startTest(...args);
  };

  /* ---------- Сторож ---------- */

  let watchdogNextAt = mock.startedAt - WATCHDOG_LAST_AGO_SEC + WATCHDOG_INTERVAL_SEC;

  function runWatchdogCheck() {
    const results = quickCheck();
    const failing = results.filter((result) => !result.ok).map((result) => result.label);
    Object.assign(state.zapret.watchdog, { last_at: nowSec(), last_ok: !failing.length, failing });
    storeCheck(results);
    if (!failing.length) {
      mock.dropNotice('watchdog');
      return;
    }
    const what = failing.join(' и ');
    const stopped = failing.length > 1 ? 'перестали открываться' : 'перестал открываться';
    if (state.settings.watchdog === 'auto') {
      watchdogAlert(`${what} ${stopped} — подбираю рабочую стратегию.`, false);
      watchdogFixing = `${what} ${stopped}`;
      api.zapret_fix();
      return;
    }
    watchdogAlert(`${what} ${stopped}. Найти рабочую стратегию?`, true);
  }

  function watchdogTick() {
    const zapret = state.zapret;
    if (state.settings.watchdog === 'off' || zapret.status !== 'running' || zapret.fix.running || zapret.test.running) return;
    if (nowSec() < watchdogNextAt) return;
    watchdogNextAt = nowSec() + WATCHDOG_INTERVAL_SEC;
    runWatchdogCheck();
  }

  const saveSettings = api.save_settings;
  api.save_settings = function saveSettingsWithWatchdog(partial) {
    if (partial && 'watchdog' in partial && !WATCHDOG_MODES.includes(partial.watchdog)) return fail('Неизвестный режим сторожа');
    return saveSettings(partial);
  };

  /* ---------- Состояние ---------- */

  Object.assign(state.zapret, {
    fix: {
      running: false, stage: null, message: null, current: null, tried: [], found: null, previous: null,
      results: null, finished_at: null, direct: false,
    },
    watchdog: {
      mode: 'ask',
      last_at: state.app.admin ? mock.startedAt - WATCHDOG_LAST_AGO_SEC : null,
      last_ok: state.app.admin ? true : null,
      failing: [],
      vpn: false,
    },
    best: null,
    scores: {},
  });
  state.settings.watchdog = 'ask';
  if (state.zapret.status === 'running') storeCheck(quickCheck(), mock.startedAt - LAST_CHECK_AGO_SEC);

  /** Поля, которые ядро вычисляет на лету: оценки, режим сторожа, свежесть проверки. */
  function refreshDerived() {
    refreshRatings();
    state.zapret.watchdog.mode = state.settings.watchdog;
    forgetStaleCheck();
  }

  const getState = api.get_state;
  api.get_state = function getStateWithZapretV11() {
    refreshDerived();
    return getState();
  };
  refreshDerived();
  mock.onTick(watchdogTick);

  /* ---------- Демонстрации ---------- */

  function breakCurrentStrategy() {
    degraded.add(state.zapret.strategy);
    degraded.add('general (ALT)');
  }

  Object.assign(mock.demos, {
    fix: () => {
      breakCurrentStrategy();
      api.zapret_fix();
    },
    'fix-fail': () => {
      for (const id of mock.STRATEGY_IDS) degraded.add(id);
      api.zapret_fix();
    },
    watchdog: () => {
      breakCurrentStrategy();
      runWatchdogCheck();
    },
  });
});
