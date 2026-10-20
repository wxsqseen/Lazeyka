'use strict';
/* Настройки: тема и масштаб, поведение окна и запуска, сторож обхода, сеть; «О программе» с благодарностями авторам. */
(function (Lz) {
  const { h, uid, setText } = Lz.dom;
  const ui = Lz.ui;
  const texts = Lz.texts;

  const THEME_OPTIONS = [
    { value: 'system', label: 'Как в Windows', icon: 'monitor' },
    { value: 'dark', label: 'Тёмная', icon: 'moon' },
    { value: 'light', label: 'Светлая', icon: 'sun' },
  ];

  const SCALE_OPTIONS = [0.8, 0.9, 1, 1.1, 1.25, 1.5].map((value) => ({ value, label: `${Math.round(value * 100)} %` }));

  const LAUNCH_TOGGLES = [
    {
      key: 'close_to_tray',
      title: 'Сворачивать в трей при закрытии',
      description: 'Крестик прячет окно, а обход и прокси продолжают работать. Выйти совсем — из меню значка в трее.',
    },
    {
      key: 'start_minimized',
      title: 'Запускать свёрнутой',
      description: 'При старте окно не показывается — Лазейка сразу уходит в трей.',
    },
    {
      key: 'autostart',
      title: 'Запускать вместе с Windows',
      description: 'Лазейка стартует при входе в систему.',
    },
    {
      key: 'zapret_on_start',
      title: 'Включать обход при запуске',
      description: 'Discord и YouTube заработают сразу, без нажатия кнопки.',
    },
    {
      key: 'tg_on_start',
      title: 'Включать Telegram-прокси при запуске',
      description: 'Telegram подключится к прокси, как только Лазейка запустится.',
    },
    {
      key: 'vpnclient_on_start',
      title: 'Включать свой VPN при запуске',
      description: 'Лазейка подключится к выбранному серверу сразу после старта — если вы добавили подписку или сервер.',
    },
  ];

  const WATCHDOG_OPTIONS = [
    { value: 'ask', label: 'Спрашивать', title: 'Сообщит, что Discord или YouTube перестали открываться, и предложит «Найти и включить»' },
    { value: 'auto', label: 'Чинить сам', title: 'Сам подберёт и включит рабочую стратегию' },
    { value: 'off', label: 'Выключен', title: 'Не проверять в фоне' },
  ];

  const UPDATE_TOGGLES = [
    {
      key: 'check_updates',
      title: 'Проверять обновления при запуске',
      description: 'Только уведомление о новой версии: Лазейку, стратегии и Telegram-прокси обновляем лишь по вашей кнопке. Ядра своего VPN Лазейка скачивает и обновляет сама — это выключается на странице «Свой VPN».',
    },
  ];

  const NETWORK_TOGGLES = [
    {
      key: 'tcp_timestamps',
      title: 'Включать TCP timestamps',
      description: 'Некоторым стратегиям нужна эта настройка Windows. Лазейка включает её сама перед запуском обхода; выключайте, только если точно знаете зачем.',
    },
  ];

  const CREDITS = [
    {
      name: 'Flowseal/zapret-discord-youtube',
      text: 'Стратегии и списки для Discord и YouTube',
      url: 'https://github.com/Flowseal/zapret-discord-youtube',
    },
    {
      name: 'bol-van/zapret',
      text: 'Движок winws, на котором работает обход',
      url: 'https://github.com/bol-van/zapret',
    },
    {
      name: 'Flowseal/tg-ws-proxy',
      text: 'Telegram-прокси через WebSocket',
      url: 'https://github.com/Flowseal/tg-ws-proxy',
    },
    {
      name: 'SagerNet/sing-box',
      text: 'Ядро своего VPN — сторонний проект',
      url: 'https://github.com/SagerNet/sing-box/tree/v1.14.3',
    },
    {
      name: 'XTLS/Xray-core',
      text: 'Помощник своего VPN для XHTTP и mKCP',
      url: 'https://github.com/XTLS/Xray-core/tree/v26.3.27',
    },
  ];

  function saveSetting(key, value) {
    Lz.store.patch((state) => {
      if (state.settings) state.settings[key] = value;
    });
    return Lz.api.run({ method: 'save_settings', args: [{ [key]: value }], key: `save_settings:${key}` })
      .then((result) => Boolean(result && result.ok));
  }

  function toggleList(definitions, rows, rowsByKey) {
    return h('div', { class: 'settings-list' }, definitions.map((definition) => {
      const row = ui.switchRow({
        title: definition.title,
        description: definition.description,
        onChange: (value) => saveSetting(definition.key, value),
      });
      rows[definition.key] = row.sw;
      if (rowsByKey) rowsByKey[definition.key] = row;
      return row.el;
    }));
  }

  /*
   * Автозапуск здесь не работает (переносной режим, Лазейка под чужой учётной записью): ядро отказывает при
   * включении (ответ — тостом), а если он был включён раньше — ставит плашку autostart. Её текст — и под
   * переключателем: выключить его по-прежнему можно, включить снова ядро не даст.
   */
  const AUTOSTART_NOTICE = 'autostart';

  function kvRow(key, valueEl, action) {
    return h('div', { class: 'kv' }, h('span', { class: 'kv__key', text: key }), valueEl, action || null);
  }

  /** Строка настройки с выбором справа (тема, сторож): заголовок, пояснение и сегменты. */
  function choiceRow({ title, description, control, titleId }) {
    return h('div', { class: 'setting setting--static' },
      h('div', { class: 'setting__text' },
        h('div', { class: 'setting__title', id: titleId, text: title }),
        h('p', { class: 'setting__desc', text: description })),
      control.el);
  }

  function create() {
    const rows = {};
    const launchRows = {};

    const themeSeg = ui.segmented({
      label: 'Тема оформления',
      value: Lz.theme.preference || 'system',
      options: THEME_OPTIONS,
      onChange: async (value) => {
        Lz.theme.hold(value);
        const ok = await saveSetting('theme', value);
        if (!ok) Lz.theme.release();
        return ok;
      },
    });
    const scaleTitleId = uid('scale-title');
    const scaleSeg = ui.segmented({
      labelledBy: scaleTitleId,
      value: Lz.scale.current,
      options: SCALE_OPTIONS,
      onChange: async (value, previous) => {
        Lz.scale.hold(value);
        const ok = await saveSetting('ui_scale', value);
        if (!ok) {
          Lz.scale.release();
          Lz.scale.apply(previous);
        }
        return ok;
      },
    });
    const appearance = ui.card({ title: 'Оформление' });
    appearance.body.append(h('div', { class: 'settings-list' },
      choiceRow({
        title: 'Тема',
        description: '«Как в Windows» следует за системной темой.',
        control: themeSeg,
      }),
      choiceRow({
        title: 'Масштаб окна',
        description: 'Крупнее или мельче всё: текст, кнопки и окна.',
        control: scaleSeg,
        titleId: scaleTitleId,
      })));

    const launch = ui.card({ title: 'Запуск и окно' });
    const hideBtn = ui.actionButton({ method: 'hide_window', label: 'Свернуть в трей', icon: 'tray', size: 'sm' });
    const quitBtn = ui.actionButton({
      method: 'quit_app',
      label: 'Выйти из Лазейки',
      icon: 'power',
      size: 'sm',
      kind: 'ghost',
      confirm: {
        title: 'Выйти из Лазейки?',
        text: 'Обход для Discord и YouTube, Telegram-прокси и свой VPN выключатся. Служба Windows, если вы её установили, продолжит работать.',
        confirmLabel: 'Выйти',
        tone: 'danger',
        icon: 'power',
      },
    });
    launch.body.append(toggleList(LAUNCH_TOGGLES, rows, launchRows), h('div', { class: 'button-row' }, hideBtn.el, quitBtn.el));

    const watchdogTitleId = uid('watchdog-title');
    const watchdogSeg = ui.segmented({
      labelledBy: watchdogTitleId,
      value: 'ask',
      options: WATCHDOG_OPTIONS,
      onChange: (value) => saveSetting('watchdog', value),
    });
    const bypass = ui.card({ title: 'Обход' });
    bypass.body.append(choiceRow({
      title: 'Сторож обхода',
      description: 'Раз в 10 минут проверяет, открываются ли Discord и YouTube; после сна и смены сети — сразу.',
      control: watchdogSeg,
      titleId: watchdogTitleId,
    }));

    const updates = ui.card({ title: 'Обновления' });
    updates.body.append(toggleList(UPDATE_TOGGLES, rows));

    const network = ui.card({ title: 'Сеть' });
    network.body.append(toggleList(NETWORK_TOGGLES, rows));

    const appVersion = h('p', { class: 'about__meta num' });
    const zapretVersion = h('span', { class: 'kv__value num' });
    const tgVersion = h('span', { class: 'kv__value num' });
    const vpnCoreVersion = h('span', { class: 'kv__value num' });
    const dataDir = h('span', { class: 'kv__value mono' });
    const openData = ui.button({
      label: 'Открыть',
      icon: 'folder',
      size: 'sm',
      kind: 'ghost',
      busyKey: 'open_path:data',
      onClick: () => Lz.actions.openPath('data'),
    });
    const about = ui.card({ title: 'О программе' });
    about.body.append(
      h('div', { class: 'about' },
        Lz.brand.tile(48),
        h('div', null,
          h('p', { class: 'about__name', text: 'Лазейка' }),
          appVersion)),
      h('div', { class: 'kv-list' },
        kvRow('Стратегии zapret', zapretVersion),
        kvRow('tg-ws-proxy', tgVersion),
        kvRow('Ядра своего VPN', vpnCoreVersion),
        kvRow('Папка данных', dataDir, openData.el)),
      h('p', { class: 'about__label', text: 'Спасибо авторам' }),
      h('div', { class: 'kv-list' }, CREDITS.map((credit) => h('div', { class: 'kv kv--credit' },
        h('span', { class: 'kv__key mono', text: credit.name }),
        h('span', { class: 'kv__value kv__value--muted', text: credit.text }),
        ui.button({
          icon: 'external',
          kind: 'ghost',
          size: 'sm',
          ariaLabel: `Открыть ${credit.name} на GitHub`,
          title: 'Открыть на GitHub',
          onClick: () => Lz.actions.openUrl(credit.url),
        }).el))),
      h('p', { class: 'licence', text: 'Лазейка — свободная программа под лицензией MIT. zapret, zapret-discord-youtube и tg-ws-proxy — проекты их авторов и распространяются на условиях своих лицензий. sing-box (GPL-3.0-or-later) и Xray-core (MPL-2.0) Лазейка запускает отдельными программами без изменений; она не связана с этими проектами и не одобрена ими.' }));

    const header = ui.pageHeader({ title: 'Настройки' });
    const el = h('div', { class: 'page__inner' }, header.el, appearance.el, launch.el, bypass.el, updates.el, network.el, about.el);

    return {
      el,
      update(state) {
        const settings = state.settings || {};
        themeSeg.set(settings.theme || 'system');
        if (settings.ui_scale != null) scaleSeg.set(Number(settings.ui_scale));
        watchdogSeg.set(settings.watchdog || 'ask');
        for (const key of Object.keys(rows)) rows[key].set(Boolean(settings[key]));
        const notices = Array.isArray(state.notices) ? state.notices : [];
        const refused = notices.find((notice) => notice && notice.id === AUTOSTART_NOTICE && notice.text);
        const autostartInfo = LAUNCH_TOGGLES.find((item) => item.key === 'autostart');
        launchRows.autostart.setDescription(refused ? String(refused.text) : autostartInfo.description);
        const app = state.app || {};
        const zapret = state.zapret || {};
        const tg = state.tg || {};
        setText(appVersion, `Версия ${app.version || '—'}`);
        setText(zapretVersion, zapret.pack && zapret.pack.version ? zapret.pack.version : 'не установлены');
        const core = tg.core && texts.CORE_KIND[tg.core] ? `, ${texts.CORE_KIND[tg.core]}` : '';
        setText(tgVersion, tg.version ? `${tg.version}${core}` : '—');
        const cores = state.vpnclient && state.vpnclient.cores ? state.vpnclient.cores : {};
        const coreParts = [['sing-box', 'sing-box'], ['xray', 'Xray']]
          .filter(([name]) => cores[name] && cores[name].installed && cores[name].version)
          .map(([name, label]) => `${label} ${cores[name].version}`);
        setText(vpnCoreVersion, coreParts.length ? coreParts.join(' · ') : 'не установлены');
        setText(dataDir, app.data_dir || '—');
      },
    };
  }

  Lz.pages.settings = { title: 'Настройки', icon: 'sliders', create };
})(window.Lz);
