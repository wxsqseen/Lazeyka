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
})();
