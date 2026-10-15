'use strict';
/*
 * Точка входа: оболочка (меню слева и страницы справа) и подключение к ядру.
 * Ядро — window.pywebview.api; оно появляется после события pywebviewready.
 * Только если в адресе есть ?mock и ядра нет, подгружается имитация из mock.js.
 */
(function (Lz) {
  const { h, icon, setText, setHidden, setAttr } = Lz.dom;
  const ui = Lz.ui;

  const PAGE_ORDER = ['home', 'zapret', 'telegram', 'help', 'updates', 'logs', 'settings'];
  /* Старые имена страниц: «Диагностика» стала разделом «Помощи», ссылки page=diag продолжают работать. */
  const PAGE_ALIASES = { diag: 'help' };
  const MOCK_GRACE_MS = 150;
  const SLOW_BACKEND_HINT_MS = 6000;
  const STATUS_DOT_TONE = { running: 'ok', starting: 'warn', stopping: 'warn', error: 'err' };

  const pages = new Map();
  const scrollPositions = new Map();
  const navButtons = new Map();
  const navDots = new Map();
  let currentPage = null;
  let started = false;

  /* ---------- Оболочка ---------- */

  const appRoot = document.getElementById('app');
  const pagesRoot = h('div', { class: 'pages' });
  const bannerRoot = h('div', { class: 'banners' });
  const offlineBanner = h('div', { class: 'banner banner--offline', role: 'alert', hidden: true },
    icon('alertCircle', { size: 16 }), h('span', { class: 'banner__text' }));
  const busyBanner = h('div', { class: 'banner banner--busy', role: 'status', hidden: true },
    h('span', { class: 'spinner', 'aria-hidden': 'true' }), h('span', { class: 'banner__text' }));
  bannerRoot.append(offlineBanner, busyBanner);

  const bootScreen = h('div', { class: 'boot' },
    h('div', { class: 'boot__inner' },
      Lz.brand.mark(36),
      h('p', { class: 'boot__text' }, h('span', { class: 'spinner spinner--inline', 'aria-hidden': 'true' }), 'Подключаемся к ядру…'),
      h('p', { class: 'boot__hint', hidden: true })));

  const versionText = h('span', { class: 'sidebar__version num' });
  const roleText = h('span', { class: 'role__text' });
  let roleIcon = icon('shieldCheck', { size: 16 });
  const roleBadge = h('button', { type: 'button', class: 'role', hidden: true }, roleIcon, roleText);
  roleBadge.addEventListener('click', async () => {
    if (roleBadge.dataset.role !== 'limited') return;
    const confirmed = await ui.confirm({
      title: 'Перезапустить с правами администратора?',
      text: 'Без них не работает обход для Discord и YouTube: драйверу WinDivert нужны права администратора. Windows попросит подтверждение.',
      confirmLabel: 'Перезапустить',
      icon: 'shieldCheck',
    });
    if (confirmed) Lz.api.run({ method: 'relaunch_admin' });
  });

  function buildNav() {
    const nav = h('nav', { class: 'nav', 'aria-label': 'Разделы' });
    for (const name of PAGE_ORDER) {
      const page = Lz.pages[name];
      const dot = h('span', { class: 'nav__dot', 'aria-hidden': 'true' });
      const badge = h('span', { class: 'nav__badge', hidden: true });
      const btn = h('button', { type: 'button', class: 'nav__item', title: page.title },
        icon(page.icon, { size: 18 }),
        h('span', { class: 'nav__label', text: page.title }),
        dot,
        badge);
      btn.addEventListener('click', () => go(name));
      navButtons.set(name, { btn, badge });
      navDots.set(name, dot);
      nav.append(btn);
    }
    return nav;
  }

  function buildShell() {
    const sidebar = h('aside', { class: 'sidebar' },
      h('div', { class: 'brand' }, Lz.brand.mark(22), h('span', { class: 'brand__name', text: 'Лазейка' })),
      buildNav(),
      h('div', { class: 'sidebar__foot' }, roleBadge, versionText));
    const main = h('main', { class: 'main' }, bannerRoot, pagesRoot, bootScreen);
    appRoot.replaceChildren(sidebar, main);
  }

  /* ---------- Страницы ---------- */

  function mountPage(name) {
    let entry = pages.get(name);
    if (entry) return entry;
    const definition = Lz.pages[name];
    const instance = definition.create();
    const host = h('section', {
      class: ['page', `page--${name}`, definition.layout === 'fill' && 'page--fill'],
      hidden: true,
    }, instance.el);
    pagesRoot.append(host);
    entry = { host, instance };
    pages.set(name, entry);
    return entry;
  }

  function scrollBehavior() {
    return window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth';
  }

  /** Имя страницы из адреса, уведомления или ссылки → имя из PAGE_ORDER; null — такой страницы нет. */
  function resolvePage(requested) {
    const name = Object.prototype.hasOwnProperty.call(PAGE_ALIASES, requested) ? PAGE_ALIASES[requested] : requested;
    return PAGE_ORDER.includes(name) ? name : null;
  }

  function go(requested, opts) {
    const name = resolvePage(requested) || 'home';
    const switching = currentPage !== name;
    if (currentPage && switching) {
      const previous = pages.get(currentPage);
      scrollPositions.set(currentPage, previous.host.scrollTop);
      previous.host.hidden = true;
      if (previous.instance.hide) previous.instance.hide();
    }
    const entry = mountPage(name);
    currentPage = name;
    entry.host.hidden = false;
    for (const [page, nav] of navButtons) {
      if (page === name) nav.btn.setAttribute('aria-current', 'page');
      else nav.btn.removeAttribute('aria-current');
    }
    if (Lz.store.state) entry.instance.update(Lz.store.state);
    if (switching) entry.host.scrollTop = scrollPositions.get(name) || 0;
    if (entry.instance.show) entry.instance.show(opts || {});
  }

  function initialPage() {
    const fromQuery = Lz.params.get('page');
    const fromHash = window.location.hash.replace(/^#\/?/, '');
    return resolvePage(fromQuery) || resolvePage(fromHash) || 'home';
  }

  /* ---------- Отрисовка состояния ---------- */

  function renderSidebar(state) {
    const app = state.app || {};
    setText(versionText, app.version ? `Версия ${app.version}` : '');
    const limited = !app.admin;
    const role = limited ? 'limited' : 'admin';
    if (roleBadge.dataset.role !== role) {
      roleBadge.dataset.role = role;
      const nextIcon = icon(limited ? 'shieldAlert' : 'shieldCheck', { size: 16 });
      roleIcon.replaceWith(nextIcon);
      roleIcon = nextIcon;
      setText(roleText, limited ? 'Ограниченный режим' : 'Администратор');
      roleBadge.title = limited
        ? 'Запущено без прав администратора — обход недоступен. Нажмите, чтобы перезапустить.'
        : 'Запущено с правами администратора';
      setAttr(roleBadge, 'aria-disabled', !limited);
      roleBadge.tabIndex = limited ? 0 : -1;
    }
    setHidden(roleBadge, false);

    const count = Number(state.updates && state.updates.count) || 0;
    const updatesNav = navButtons.get('updates');
    setText(updatesNav.badge, count > 99 ? '99+' : String(count));
    setHidden(updatesNav.badge, count <= 0);
    updatesNav.btn.setAttribute('aria-label', count > 0 ? `Обновления, доступно: ${count}` : 'Обновления');

    const zapret = state.zapret || {};
    const tg = state.tg || {};
    navDots.get('zapret').dataset.tone = zapret.available === false ? '' : (STATUS_DOT_TONE[zapret.status] || '');
    navDots.get('telegram').dataset.tone = STATUS_DOT_TONE[tg.status] || '';
  }

  function renderBusy(state) {
    const busy = state.app && state.app.busy ? String(state.app.busy) : '';
    setText(busyBanner.querySelector('.banner__text'), busy);
    setHidden(busyBanner, !busy);
  }

  function onState(state) {
    if (!started) {
      started = true;
      bootScreen.remove();
      appRoot.removeAttribute('aria-busy');
      go(initialPage());
    }
    Lz.theme.sync(state.settings ? state.settings.theme : 'system');
    renderSidebar(state);
    renderBusy(state);
    const entry = currentPage ? pages.get(currentPage) : null;
    if (entry) entry.instance.update(state);
    Lz.onboarding.sync(state);
  }

  function onConnection({ online, error }) {
    setText(offlineBanner.querySelector('.banner__text'),
      online ? '' : `Нет связи с ядром Лазейки — пробуем снова. ${error ? `(${error})` : ''}`.trim());
    setHidden(offlineBanner, online);
  }

  /* ---------- Запуск ---------- */

  function showBootHint(text) {
    const hint = bootScreen.querySelector('.boot__hint');
    if (!hint || started) return;
    setText(hint, text || 'Ядро не отвечает. Если страница открыта в обычном браузере, добавьте к адресу ?mock — запустится имитация ядра.');
    setHidden(hint, false);
  }

  function loadMockIfNoBackend() {
    if (window.pywebview) return;
    const script = document.createElement('script');
    script.src = 'mock.js';
    script.addEventListener('error', () => showBootHint('Не удалось загрузить mock.js — имитация ядра недоступна.'));
    document.head.append(script);
  }

  function waitForBackend() {
    return new Promise((resolve) => {
      if (Lz.api.isReady()) {
        resolve();
        return;
      }
      let mockTimer = null;
      const hintTimer = setTimeout(() => showBootHint(), SLOW_BACKEND_HINT_MS);
      function onReady() {
        if (!Lz.api.isReady()) return;
        window.removeEventListener('pywebviewready', onReady);
        clearTimeout(mockTimer);
        clearTimeout(hintTimer);
        resolve();
      }
      window.addEventListener('pywebviewready', onReady);
      if (Lz.params.has('mock')) mockTimer = setTimeout(loadMockIfNoBackend, MOCK_GRACE_MS);
    });
  }

  Lz.nav = { go, resolve: resolvePage, scrollBehavior, get current() { return currentPage; } };

  buildShell();
  waitForBackend().then(() => {
    Lz.store.subscribe(onState);
    Lz.store.onConnection(onConnection);
    Lz.store.start();
  });
})(window.Lz);
