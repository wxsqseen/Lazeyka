'use strict';
/*
 * VPN рядом с обходом: «что куда идёт» (подписи, таблица, пояснение) и строки состояния.
 * Общее для окна перед включением (vpn-gate.js), страницы «Обход», главной и «Помощи».
 */
(function (Lz) {
  const { h, icon } = Lz.dom;
  const ui = Lz.ui;

  /* Их обрабатывает обход Лазейки, если они идут мимо VPN. */
  const BYPASS_TARGETS = new Set(['discord', 'youtube']);
  const VIA_TEXT = {
    vpn: 'через VPN',
    direct: 'напрямую',
    blocked: 'мимо VPN — без обхода не откроется',
    unknown: 'не удалось определить',
  };
  /* Telegram ходит к прокси Лазейки, а прокси — дальше к серверам Telegram. */
  const TELEGRAM_NEXT = { vpn: 'через VPN', direct: 'напрямую', blocked: 'напрямую' };
  const RUNNING_LIKE = new Set(['running', 'starting']);
  const ROUTES_FOOTNOTE = 'Определено проверочными запросами Лазейки. Если в VPN есть правила для отдельных программ, у них маршрут может отличаться.';

  function viaOf(item) {
    return Object.prototype.hasOwnProperty.call(VIA_TEXT, item.via) ? item.via : 'unknown';
  }

  /**
   * Строка таблицы. component — что включаем ('zapret' | 'tg'); bypassOn — обход работает
   * или вот-вот включится: только тогда Discord и YouTube мимо VPN идут «через обход Лазейки».
   */
  function routeRow(item, opts) {
    const via = viaOf(item);
    if (item.id === 'telegram' && opts.component === 'tg') {
      const next = TELEGRAM_NEXT[via];
      return { label: 'Telegram', via, text: next ? `прокси Лазейки → дальше ${next}` : `прокси Лазейки → ${VIA_TEXT.unknown}` };
    }
    if (via === 'direct' && BYPASS_TARGETS.has(item.id) && opts.bypassOn) {
      return { label: item.label || item.id, via, text: 'через обход Лазейки' };
    }
    return { label: item.label || item.id, via, text: VIA_TEXT[via] };
  }

  /**
   * Срез vpn.routes для слотов. component: 'zapret' / 'tg' — окно перед включением обхода
   * или прокси; 'view' — как есть сейчас (страница «Обход», «Помощь»). explain — показывать
   * ли пояснение про Discord и YouTube: в окне для Telegram оно к делу, только если обход работает.
   */
  function routesData(state, component) {
    const vpn = (state && state.vpn) || {};
    const zapret = (state && state.zapret) || {};
    const routes = vpn.routes || null;
    const bypassOn = component === 'zapret' || RUNNING_LIKE.has(zapret.status);
    return {
      component,
      bypassOn,
      explain: component !== 'tg' || bypassOn,
      running: Boolean(routes && routes.running),
      error: Boolean(routes && routes.error),
      items: routes && Array.isArray(routes.items) ? routes.items : null,
      checked: Boolean(routes),
    };
  }

  function namesOf(items) {
    return items.map((item) => item.label || item.id).join(' и ');
  }

  /** Пояснение под таблицей: что из Discord и YouTube идёт через VPN, а что достанется обходу. */
  function explanationTexts(items) {
    const targets = items.filter((item) => BYPASS_TARGETS.has(item.id));
    const viaVpn = targets.filter((item) => item.via === 'vpn');
    const toBypass = targets.filter((item) => item.via === 'direct' || item.via === 'blocked');
    const texts = { vpn: '', bypass: '' };
    if (viaVpn.length) {
      const many = viaVpn.length > 1;
      texts.vpn = `${namesOf(viaVpn)} сейчас ${many ? 'идут' : 'идёт'} через VPN — обход ${many ? 'им' : 'ему'} не нужен, `
        + `но и не мешает. Чтобы ${many ? 'они шли' : 'он шёл'} через обход (быстрее, без нагрузки на VPN), `
        + `добавьте ${many ? 'их' : 'его'} в исключения VPN.`;
    }
    if (toBypass.length) {
      const many = toBypass.length > 1;
      texts.bypass = `${namesOf(toBypass)} ${many ? 'идут' : 'идёт'} мимо VPN — ${many ? 'их' : 'его'} будет обрабатывать обход.`;
    }
    return texts;
  }

  /**
   * Таблица «что куда идёт» и пояснение. data — routesData(); howTo — что делать по ссылке
   * «Как это сделать» (null — ссылку не показывать, например в самой «Помощи»).
   */
  function renderRoutes(data, howTo) {
    if (data.running || (!data.items && !data.error)) {
      return h('p', { class: 'muted small vpn-routes__wait' },
        h('span', { class: 'spinner spinner--inline', 'aria-hidden': 'true' }), 'Проверяем, что куда идёт…');
    }
    if (!data.items) {
      return h('p', { class: 'muted small', text: 'Не удалось проверить, что куда идёт. Попробуйте ещё раз.' });
    }
    const rows = data.items.map((item) => routeRow(item, data));
    const table = [
      h('dl', { class: 'vpn-routes__table' }, rows.map((row) => [
        h('dt', { class: 'vpn-routes__label', text: row.label }),
        h('dd', { class: ['vpn-routes__via', `is-${row.via}`] },
          row.via === 'blocked' ? icon('alert', { size: 14, cls: 'vpn-routes__icon' }) : null,
          h('span', { text: row.text })),
      ])),
      h('p', { class: 'vpn-routes__footnote', text: ROUTES_FOOTNOTE }),
    ];
    if (!data.explain) return table;
    const texts = explanationTexts(data.items);
    const howToLink = texts.vpn && howTo ? ui.button({
      label: 'Как это сделать',
      iconRight: 'arrowRight',
      kind: 'link',
      size: 'sm',
      onClick: () => howTo(),
    }).el : null;
    return [
      table,
      texts.vpn ? h('p', { class: 'vpn-routes__note', text: texts.vpn }) : null,
      howToLink,
      texts.bypass && data.bypassOn ? h('p', { class: 'vpn-routes__note', text: texts.bypass }) : null,
    ];
  }

  /* ---------- Строки состояния ---------- */

  function quoted(names) {
    return names.map((name) => `«${name}»`).join(', ');
  }

  /** «туннель «wwan99» и сервер VPN исключены» — что именно обход не трогает. */
  function excludedText(vpn) {
    const adapters = Array.isArray(vpn.adapters) ? vpn.adapters : [];
    const tunnels = adapters.filter((a) => a.kind === 'tunnel' && a.role === 'internet').map((a) => String(a.name || a.id));
    const servers = Array.isArray(vpn.servers) ? vpn.servers : [];
    let what = 'туннель VPN';
    if (tunnels.length === 1) what = `туннель ${quoted(tunnels)}`;
    else if (tunnels.length > 1) what = `туннели ${quoted(tunnels)}`;
    if (servers.length) return `${what} и сервер VPN исключены`;
    return `${what} ${tunnels.length > 1 ? 'исключены' : 'исключён'}`;
  }

  /** «Happ через системный прокси»; ядро без имени программы уже называет его «VPN через системный прокси». */
  function proxyName(vpn) {
    const label = String(vpn.label || 'VPN');
    return label.includes('прокси') ? label : `${label} через системный прокси`;
  }

  /** Строка под переключателем на странице «Обход»: { tone, text }. */
  function compatStatus(vpn, zapret) {
    const source = vpn || {};
    const filter = source.filter || {};
    const unseparable = Array.isArray(source.unseparable) ? source.unseparable : [];
    if (!source.active && unseparable.length) {
      return {
        tone: 'warn',
        text: `Запущен ${unseparable.join(' и ')}. Такие VPN умеют работать без отдельного адаптера `
          + '(ExpressVPN — протокол Lightway Turbo, AdGuard VPN — режим без WinTun): тогда Лазейка не может '
          + 'отделить их трафик от прямого, и совместимость с VPN не поможет.',
      };
    }
    if (!source.active) {
      return source.compat === false
        ? { tone: 'off', text: 'VPN не обнаружен. Совместимость выключена: если подключите VPN, обход будет задевать и его трафик.' }
        : { tone: 'off', text: 'VPN не обнаружен. Когда подключите VPN, обход сам перестанет трогать его трафик.' };
    }
    /* VPN в режиме системного прокси: туннеля нет, исключать из перехвата нечего — совместимость ни при чём. */
    if (source.mode === 'proxy') {
      return { tone: 'ok', text: `Работает ${proxyName(source)}: браузер и Discord ходят через него, перехват обхода ничего не исключает.` };
    }
    const label = source.label || 'VPN';
    if (source.compat === false) return { tone: 'warn', text: `Работает ${label}, а совместимость выключена — обход может мешать VPN.` };
    if (filter.mode === 'error') {
      return {
        tone: 'err',
        text: `Совместимость не включилась: ${filter.error || 'фильтр для VPN не собрался'}. Обход работает как обычно и может задевать трафик VPN.`,
      };
    }
    if (zapret && zapret.status === 'running' && filter.mode !== 'vpn') {
      return { tone: 'warn', text: `Работает ${label}. Исключения для VPN к обходу ещё не применены.` };
    }
    return { tone: 'ok', text: `Работает ${label}. Обход его не трогает: ${excludedText(source)}.` };
  }

  /** Тихая строка на главной; null — VPN нет. */
  function homeLine(vpn) {
    const source = vpn || {};
    if (!source.active) return null;
    if (source.mode === 'proxy') return { tone: 'ok', text: `VPN: ${proxyName(source)} — обход ему не мешает` };
    const label = source.label || 'VPN';
    if (source.compat === false) return { tone: 'warn', text: `VPN: ${label} — совместимость выключена, обход может ему мешать` };
    if (source.filter && source.filter.mode === 'error') return { tone: 'err', text: `VPN: ${label} — совместимость не включилась` };
    return { tone: 'ok', text: `VPN: ${label} — обход его не трогает` };
  }

  Lz.vpn = { routeRow, routesData, renderRoutes, explanationTexts, compatStatus, homeLine, proxyName };
})(window.Lz);
