'use strict';
/*
 * Свой VPN: общие кусочки для страницы «VPN», карточки на главной и «Помощи» —
 * флаг страны, задержка цветом, трафик и срок подписки.
 * Все строки из ядра идут только в текст.
 */
(function (Lz) {
  const { h, icon } = Lz.dom;
  const fmt = Lz.fmt;
  const texts = Lz.texts;

  const LATENCY_GOOD_MS = 150;
  const LATENCY_FAIR_MS = 400;
  const EXPIRE_WARN_DAYS = 3;
  const TRAFFIC_WARN_SHARE = 0.9;
  const DAY_SEC = 86400;
  /* Срок в секундах: ядро переводит миллисекунды заголовка, но на всякий случай понимаем и их. */
  const MS_THRESHOLD = 32e9;
  const BITS_IN_BYTE = 8;
  const REGIONAL_A = 0x1F1E6;
  const LETTER_A = 65;

  /** Срез состояния своего VPN с гарантированными массивами — страница не падает на неполном снимке. */
  function snapshot(state) {
    const vc = state && state.vpnclient && typeof state.vpnclient === 'object' ? state.vpnclient : null;
    const source = vc || {};
    const list = (value) => (Array.isArray(value) ? value : []);
    return {
      present: Boolean(vc),
      vc: source,
      servers: list(source.servers),
      subscriptions: list(source.subscriptions),
      groups: list(source.groups),
      profiles: list(source.routing_profiles),
      routing: source.routing && typeof source.routing === 'object' ? source.routing : {},
      settings: source.settings && typeof source.settings === 'object' ? source.settings : {},
      cores: source.cores && typeof source.cores === 'object' ? source.cores : {},
    };
  }

  function flagCode(code) {
    const value = String(code || '').toUpperCase();
    return /^[A-Z]{2}$/.test(value) ? value : '';
  }

  /** «NL» → эмодзи-флаг из двух региональных индикаторов (U+1F1E6 — буква A). */
  function flagEmoji(code) {
    return String.fromCodePoint(...Array.from(code, (letter) => REGIONAL_A + letter.charCodeAt(0) - LETTER_A));
  }

  /**
   * Флаг страны с названием во всплывающей подсказке; без страны — значок глобуса.
   * Windows сам эмодзи-флаги не рисует: их глифы даёт локальный шрифт Twemoji Country Flags (vpnclient.css).
   */
  function flag(code, opts) {
    const options = opts || {};
    const value = flagCode(code);
    if (!value) {
      return h('span', { class: ['vc-flag', 'vc-flag--none', options.cls], title: 'Страна не указана', 'aria-hidden': 'true' },
        icon(options.auto ? 'zap' : 'globe', { size: 12 }));
    }
    const name = texts.countryName(value);
    return h('span', { class: ['vc-flag', 'vc-flag--emoji', options.cls], role: 'img', 'aria-label': name, title: name, text: flagEmoji(value) });
  }

  /** Задержка: { tone: ok | warn | err | off, text, title }. */
  function latencyView(latency) {
    const source = latency || {};
    if (source.error) return { tone: 'err', text: 'нет ответа', title: String(source.error) };
    const ms = Number(source.ms);
    if (source.ms == null || !Number.isFinite(ms) || ms <= 0) return { tone: 'off', text: '—', title: 'Задержку ещё не проверяли' };
    let tone = 'err';
    if (ms < LATENCY_GOOD_MS) tone = 'ok';
    else if (ms < LATENCY_FAIR_MS) tone = 'warn';
    const ago = fmt.relative(source.at);
    return { tone, text: `${fmt.integer(ms)}${fmt.NBSP}мс`, title: ago ? `Проверено ${ago}` : null };
  }

  function latencyEl(latency, cls) {
    const view = latencyView(latency);
    return h('span', { class: ['vc-latency', `is-${view.tone}`, cls, 'num'], title: view.title, text: view.text });
  }

  /** Скорость теста: «87,4 Мбит/с». */
  function speedText(speed) {
    if (!speed || speed.mbps == null) return '';
    const mbps = Number(speed.mbps);
    if (!Number.isFinite(mbps)) return '';
    return `${mbps >= 100 ? fmt.integer(mbps) : String(Math.round(mbps * 10) / 10).replace('.', ',')}${fmt.NBSP}Мбит/с`;
  }

  /** Мбит/с из байт в секунду — для подписей рядом со скоростью теста. */
  function mbps(bytesPerSecond) {
    return (Number(bytesPerSecond) || 0) * BITS_IN_BYTE / 1e6;
  }

  function toSeconds(value) {
    const n = Number(value);
    if (!Number.isFinite(n) || n <= 0) return null;
    return n > MS_THRESHOLD ? n / 1000 : n;
  }

  /**
   * Трафик и срок подписки: доля, подписи и предупреждения (за 3 дня до конца и при 90 %).
   * total 0 — безлимит, expire 0 — бессрочно.
   */
  function usage(sub) {
    const info = (sub && sub.userinfo) || {};
    const used = Math.max(0, Number(info.used) || 0);
    const total = Math.max(0, Number(info.total) || 0);
    const expire = toSeconds(info.expire);
    const refill = toSeconds(info.refill_at);
    const now = fmt.nowSeconds();
    const share = total > 0 ? Math.min(1, used / total) : null;
    const left = expire ? expire - now : null;
    const daysLeft = left != null ? Math.ceil(left / DAY_SEC) : null;
    const warnings = [];
    if (left != null && left <= 0) warnings.push({ tone: 'err', text: 'Срок подписки закончился — продлите её у провайдера.' });
    else if (daysLeft != null && daysLeft <= EXPIRE_WARN_DAYS) {
      warnings.push({ tone: 'warn', text: `Подписка закончится через ${fmt.count(daysLeft, 'день', 'дня', 'дней')} — не забудьте продлить.` });
    }
    if (share != null && share >= 1) warnings.push({ tone: 'err', text: 'Трафик по подписке закончился.' });
    else if (share != null && share >= TRAFFIC_WARN_SHARE) {
      warnings.push({ tone: 'warn', text: `Израсходовано ${fmt.percent(share)} трафика подписки.` });
    }
    let expireText = 'бессрочно';
    if (expire) {
      const when = fmt.date(expire);
      if (left <= 0) expireText = `закончилась ${when}`;
      else expireText = `до ${when} · ${daysLeft > 1 ? `ещё ${fmt.count(daysLeft, 'день', 'дня', 'дней')}` : 'последний день'}`;
    }
    return {
      share,
      hasLimits: total > 0 || Boolean(expire),
      trafficText: total > 0 ? `${fmt.bytes(used)} из ${fmt.bytes(total)}` : (used > 0 ? `${fmt.bytes(used)}, без лимита` : 'трафик без лимита'),
      expireText,
      refillText: refill ? `сброс трафика ${fmt.date(refill)}` : '',
      warnings,
      tone: warnings.some((w) => w.tone === 'err') ? 'err' : (warnings.length ? 'warn' : null),
    };
  }

  /**
   * Выбранный сервер для подписей: имя, страна, протокол. У «Самого быстрого» — сервер, который выбрало ядро,
   * и группа («Амстердам · Умная локация»); пока VPN выключен (actual: null), сервера нет — только группа.
   */
  function selectedView(vc) {
    const selected = vc && vc.selected;
    if (!selected || !selected.id) return null;
    const auto = selected.kind === 'auto' || String(selected.id).startsWith('auto:');
    const actual = auto && selected.actual ? selected.actual : null;
    return {
      id: String(selected.id),
      auto,
      name: String((actual && actual.name) || selected.name || (auto ? 'Самый быстрый' : 'Сервер')),
      group: actual ? String(selected.name || 'Самый быстрый') : '',
      country: (actual && actual.country) || selected.country || null,
      proto: texts.vpncProto(selected),
      viaXray: selected.engine === 'xray',
    };
  }

  /** Строка «чип + имя» выбранного сервера. */
  function selectedLine(view, cls) {
    if (!view) return h('span', { class: ['vc-selected', cls, 'is-empty'], text: 'Сервер не выбран' });
    return h('span', { class: ['vc-selected', cls] },
      flag(view.country, { auto: view.auto && !view.country }),
      h('span', { class: 'vc-selected__name', text: view.name, title: view.name }),
      view.group ? h('span', { class: 'vc-selected__group', text: `· ${view.group}` }) : null);
  }

  /** Сумма трафика «↓ 393 МБ ↑ 17,9 МБ». */
  function trafficPair(down, up) {
    return `↓${fmt.NBSP}${fmt.bytes(down || 0)}  ↑${fmt.NBSP}${fmt.bytes(up || 0)}`;
  }

  Lz.vcView = {
    snapshot,
    flag,
    latencyView,
    latencyEl,
    speedText,
    mbps,
    usage,
    selectedView,
    selectedLine,
    trafficPair,
  };
})(window.Lz);
