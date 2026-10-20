'use strict';
/*
 * Вызовы ядра через window.pywebview.api и единая обработка ответов действий:
 * { ok: true } или { ok: false, error, errors }.
 */
(function (Lz) {
  const METHOD_NAME = /^[a-z][a-z0-9_]*$/;
  const inflight = new Set();
  const busyListeners = new Set();

  function backend() {
    const bridge = window.pywebview;
    return bridge && bridge.api ? bridge.api : null;
  }

  function isReady() {
    const api = backend();
    return Boolean(api && typeof api.get_state === 'function');
  }

  function describeError(err) {
    if (err == null) return 'причина не указана';
    if (typeof err === 'string') return err;
    if (err.message) return String(err.message);
    try {
      return JSON.stringify(err);
    } catch (jsonErr) {
      console.debug('Ошибку не удалось сериализовать:', jsonErr);
      return String(err);
    }
  }

  function hasMethod(method) {
    const api = backend();
    return Boolean(
      api && METHOD_NAME.test(method) && Object.prototype.hasOwnProperty.call(api, method) &&
      typeof api[method] === 'function'
    );
  }

  /** Сырой вызов: возвращает то, что вернуло ядро, или бросает исключение. */
  async function call(method, ...args) {
    if (!hasMethod(method)) {
      throw new Error(`в ядре нет метода ${method} — версии интерфейса и ядра не совпадают`);
    }
    return backend()[method](...args);
  }

  /**
   * Вызов с ограничением по времени: зависший вызов ядра превращается в ошибку,
   * а не в молчание, при котором интерфейс тихо перестаёт обновляться.
   */
  function callWithTimeout(method, timeoutMs, ...args) {
    let timer = null;
    const timeout = new Promise((resolve, reject) => {
      timer = setTimeout(() => reject(new Error(`${method} не ответил за ${Math.round(timeoutMs / 1000)} с`)), timeoutMs);
    });
    return Promise.race([call(method, ...args), timeout]).finally(() => clearTimeout(timer));
  }

  /**
   * Ответ метода-запроса (get_state, get_logs, lists_get…): данные или отказ ядра { ok: false, error }.
   * Отказ превращается в исключение (refusal: true), а не принимается за пустые данные.
   */
  function unwrap(method, result) {
    if (result && typeof result === 'object' && result.ok === false) {
      const err = new Error(result.error ? String(result.error) : `ядро отклонило ${method} и не назвало причину`);
      err.refusal = true;
      throw err;
    }
    return result;
  }

  /** Данные метода-запроса с ограничением по времени; отказ ядра — исключение. */
  async function query(method, timeoutMs, ...args) {
    return unwrap(method, await callWithTimeout(method, timeoutMs, ...args));
  }

  /** Вызов действия: всегда возвращает объект с полем ok и не бросает исключений. */
  async function action(method, ...args) {
    let result;
    try {
      result = await call(method, ...args);
    } catch (err) {
      return { ok: false, error: `Не получилось выполнить ${method}: ${describeError(err)}` };
    }
    if (result && typeof result === 'object') {
      if (result.ok === false && !result.error) {
        result.error = `Ядро отклонило ${method} и не назвало причину.`;
      }
      if (result.ok === undefined) result.ok = true;
      return result;
    }
    console.warn(`Метод ${method} вернул ${result === null ? 'null' : typeof result} вместо { ok }; считаем, что действие выполнено.`);
    return { ok: true };
  }

  function isBusy(key) {
    return inflight.has(key);
  }

  /**
   * Действие в несколько шагов (окно перед включением, затем вызов ядра): пока оно идёт, кнопки с этим key
   * заняты, а повторное нажатие ничего не начинает — возвращает null. Вызовы Lz.api.run внутри — с другими ключами.
   */
  async function hold(key, fn) {
    if (inflight.has(key)) return null;
    inflight.add(key);
    emitBusy();
    try {
      return await fn();
    } finally {
      inflight.delete(key);
      emitBusy();
    }
  }

  function onBusyChange(listener) {
    busyListeners.add(listener);
    return () => busyListeners.delete(listener);
  }

  function emitBusy() {
    for (const listener of busyListeners) listener();
  }

  /**
   * Действие с индикацией: пока вызов идёт, кнопки с тем же key показывают загрузку;
   * ошибка превращается в тост, а состояние сразу перечитывается.
   */
  async function run(options) {
    const { method, args = [], key = method, success, silent = false } = options;
    if (inflight.has(key)) return null;
    inflight.add(key);
    emitBusy();
    let result;
    try {
      result = await action(method, ...args);
    } finally {
      inflight.delete(key);
      if (Lz.store) Lz.store.noteMutation();
      emitBusy();
    }
    if (!result.ok) {
      if (!silent) Lz.ui.toast({ kind: 'error', text: result.error });
    } else if (success) {
      Lz.ui.toast({ kind: 'success', text: typeof success === 'function' ? success(result) : success });
    }
    if (Lz.store) Lz.store.refreshSoon();
    return result;
  }

  Lz.api = {
    backend, isReady, hasMethod, call, callWithTimeout, unwrap, query, action, run, hold, isBusy, onBusyChange, describeError,
  };
})(window.Lz);
