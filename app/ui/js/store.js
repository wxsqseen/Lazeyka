'use strict';
/*
 * Снимок состояния ядра. Ядро ничего не присылает само — страница опрашивает
 * get_state(): раз в секунду, а во время долгих операций — чаще.
 */
(function (Lz) {
  const POLL_INTERVAL_MS = 1000;
  const FAST_POLL_INTERVAL_MS = 400;
  const OFFLINE_AFTER_FAILURES = 3;
  const STATE_TIMEOUT_MS = 8000;
  const ACTIVE_UPDATE_STATES = new Set(['downloading', 'verifying', 'installing']);
  const ACTIVE_RULES_STATES = new Set(['downloading', 'verifying', 'updating']);

  const stateListeners = new Set();
  const connectionListeners = new Set();
  let state = null;
  let timer = null;
  let polling = false;
  let refreshQueued = false;
  let failures = 0;
  let online = true;
  /* Растёт после каждого действия: снимок, запрошенный до действия, уже устарел. */
  let mutationSeq = 0;

  /** Свой VPN: импорт, задержки, тест скорости, установка ядер и списков маршрутов, обновление подписок. */
  function vpnclientBusy(vc) {
    if (!vc || typeof vc !== 'object') return false;
    const cores = vc.cores && typeof vc.cores === 'object' ? Object.values(vc.cores) : [];
    const rules = vc.routing && vc.routing.rules;
    const subs = Array.isArray(vc.subscriptions) ? vc.subscriptions : [];
    return Boolean(
      (vc.import && vc.import.running) ||
      (vc.latency && vc.latency.running) ||
      (vc.speed && vc.speed.running) ||
      cores.some((core) => core && ACTIVE_UPDATE_STATES.has(core.state)) ||
      (rules && ACTIVE_RULES_STATES.has(rules.state)) ||
      subs.some((sub) => sub && (sub.updating || (sub.probe && sub.probe.running)))
    );
  }

  function needsFastPolling(snapshot) {
    if (!snapshot) return false;
    const test = snapshot.zapret && snapshot.zapret.test;
    const fix = snapshot.zapret && snapshot.zapret.fix;
    const routes = snapshot.vpn && snapshot.vpn.routes;
    const items = (snapshot.updates && Array.isArray(snapshot.updates.items)) ? snapshot.updates.items : [];
    return Boolean(
      (test && test.running) ||
      (fix && fix.running) ||
      (routes && routes.running) ||
      (snapshot.diag && snapshot.diag.running) ||
      items.some((item) => ACTIVE_UPDATE_STATES.has(item.state)) ||
      vpnclientBusy(snapshot.vpnclient)
    );
  }

  function emitState() {
    for (const listener of stateListeners) {
      try {
        listener(state);
      } catch (err) {
        console.error('Ошибка при отрисовке состояния:', err);
      }
    }
  }

  function setOnline(next, error) {
    if (next === online) return;
    online = next;
    for (const listener of connectionListeners) listener({ online, error });
  }

  function schedule(delayMs) {
    clearTimeout(timer);
    timer = setTimeout(poll, delayMs);
  }

  async function poll() {
    timer = null;
    if (polling) {
      refreshQueued = true;
      return;
    }
    polling = true;
    refreshQueued = false;
    const requestedAtSeq = mutationSeq;
    try {
      const next = await Lz.api.callWithTimeout('get_state', STATE_TIMEOUT_MS);
      if (!next || typeof next !== 'object') {
        throw new Error(`get_state вернул ${next === null ? 'null' : typeof next} вместо объекта`);
      }
      failures = 0;
      setOnline(true, null);
      if (requestedAtSeq !== mutationSeq) {
        refreshQueued = true;
        return;
      }
      state = next;
      emitState();
    } catch (err) {
      failures += 1;
      console.warn(`get_state не удался (${failures} раз подряд):`, err);
      if (failures >= OFFLINE_AFTER_FAILURES) setOnline(false, Lz.api.describeError(err));
    } finally {
      polling = false;
      schedule(refreshQueued ? 0 : (needsFastPolling(state) ? FAST_POLL_INTERVAL_MS : POLL_INTERVAL_MS));
    }
  }

  /** Отметить, что ядро изменило состояние: ответы на более ранние запросы отбрасываются. */
  function noteMutation() {
    mutationSeq += 1;
  }

  /** Перечитать состояние как можно скорее (после действия пользователя). */
  function refreshSoon() {
    if (polling) refreshQueued = true;
    else schedule(0);
  }

  /**
   * Оптимистичная правка локального снимка, чтобы переключатель не «отскакивал»
   * до следующего опроса. Следующий get_state всё равно перезапишет снимок.
   */
  function patch(mutator) {
    if (!state) return;
    mutator(state);
    emitState();
  }

  function subscribe(listener) {
    stateListeners.add(listener);
    if (state) listener(state);
    return () => stateListeners.delete(listener);
  }

  function onConnection(listener) {
    connectionListeners.add(listener);
    return () => connectionListeners.delete(listener);
  }

  function start() {
    schedule(0);
  }

  Lz.store = {
    get state() {
      return state;
    },
    start,
    subscribe,
    onConnection,
    noteMutation,
    refreshSoon,
    patch,
  };
})(window.Lz);
