'use strict';
/*
 * Общее пространство имён интерфейса Лазейки.
 * Подключается в <head> синхронно: тема должна примениться до первой отрисовки,
 * иначе окно на долю секунды мигнёт не тем цветом.
 */
(function () {
  const Lz = (window.Lz = window.Lz || {});

  Lz.params = new URLSearchParams(window.location.search);
  Lz.pages = Lz.pages || {};

  const THEME_STORAGE_KEY = 'lazeyka.theme';
  const THEME_PREFERENCES = ['system', 'dark', 'light'];
  const lightSchemeQuery = window.matchMedia('(prefers-color-scheme: light)');
  let themePreference = null;

  function resolveTheme(preference) {
    if (preference === 'dark' || preference === 'light') return preference;
    return lightSchemeQuery.matches ? 'light' : 'dark';
  }

  function rememberTheme(preference) {
    try {
      window.localStorage.setItem(THEME_STORAGE_KEY, preference);
    } catch (err) {
      console.debug('Тема не сохранена в localStorage, при следующем запуске возьмём системную:', err);
    }
  }

  function recallTheme() {
    try {
      return window.localStorage.getItem(THEME_STORAGE_KEY);
    } catch (err) {
      console.debug('Сохранённая тема не прочитана из localStorage:', err);
      return null;
    }
  }

  function applyTheme(preference) {
    const next = THEME_PREFERENCES.includes(preference) ? preference : 'system';
    const resolved = resolveTheme(next);
    if (next === themePreference && document.documentElement.dataset.theme === resolved) return;
    themePreference = next;
    document.documentElement.dataset.theme = resolved;
    rememberTheme(next);
  }

  lightSchemeQuery.addEventListener('change', () => {
    if (themePreference === 'system') {
      document.documentElement.dataset.theme = resolveTheme('system');
    }
  });

  /*
   * Пока сохранение выбранной темы не подтверждено ядром, снимок состояния
   * ещё содержит старую тему — hold() не даёт ему перекрасить окно обратно.
   */
  let heldPreference = null;

  function syncFromState(preference) {
    if (heldPreference !== null) {
      if (preference !== heldPreference) return;
      heldPreference = null;
    }
    applyTheme(preference);
  }

  Lz.theme = {
    apply: applyTheme,
    sync: syncFromState,
    hold(preference) {
      heldPreference = preference;
      applyTheme(preference);
    },
    release() {
      heldPreference = null;
    },
    get preference() {
      return themePreference;
    },
  };

  applyTheme(Lz.params.get('theme') || recallTheme() || 'system');

  /*
   * Масштаб окна (settings.ui_scale, 0.8–1.5) — CSS zoom на <html>: вместе со страницей
   * масштабируются окна и тосты. Запоминается, чтобы окно не прыгало при запуске.
   */
  const SCALE_STORAGE_KEY = 'lazeyka.scale';
  const SCALE_MIN = 0.8;
  const SCALE_MAX = 1.5;
  let scaleValue = 1;
  let heldScale = null;

  function clampScale(value) {
    const n = Number(value);
    if (value == null || value === '' || !Number.isFinite(n)) return 1;
    return Math.min(SCALE_MAX, Math.max(SCALE_MIN, n));
  }

  function applyScale(value) {
    const next = clampScale(value);
    if (next === scaleValue && document.documentElement.style.zoom === (next === 1 ? '' : String(next))) return;
    scaleValue = next;
    document.documentElement.style.zoom = next === 1 ? '' : String(next);
    /* Высоты в vh делятся на масштаб (app.css): внутри zoom они уже умножены на него. */
    document.documentElement.style.setProperty('--ui-zoom', String(next));
    try {
      window.localStorage.setItem(SCALE_STORAGE_KEY, String(next));
    } catch (err) {
      console.debug('Масштаб не сохранён в localStorage, при следующем запуске возьмём из настроек:', err);
    }
  }

  function recallScale() {
    try {
      return window.localStorage.getItem(SCALE_STORAGE_KEY);
    } catch (err) {
      console.debug('Сохранённый масштаб не прочитан из localStorage:', err);
      return null;
    }
  }

  Lz.scale = {
    MIN: SCALE_MIN,
    MAX: SCALE_MAX,
    apply: applyScale,
    /* Ядро без ui_scale (до версии 1.2) не трогает масштаб. */
    sync(value) {
      if (value == null) return;
      if (heldScale !== null) {
        if (clampScale(value) !== heldScale) return;
        heldScale = null;
      }
      applyScale(value);
    },
    hold(value) {
      heldScale = clampScale(value);
      applyScale(value);
    },
    release() {
      heldScale = null;
    },
    get current() {
      return scaleValue;
    },
  };

  applyScale(Lz.params.get('scale') || recallScale() || 1);
})();
