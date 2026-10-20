'use strict';
/*
 * Страница «Свой VPN»: шапка, плашки, карточка «Подключение» (кнопка питания, сервер, режим,
 * скорость, трафик, память ядер; пока VPN не подключён — картинка состояния вместо нулей, при отказе —
 * почему, чья сторона и что сделать)
 * и разделы из vpnclient-servers.js, vpnclient-add.js,
 * vpnclient-routing.js и vpnclient-more.js. «Добавить» всегда первым, сразу под шапкой: пока серверов
 * нет — большая карточка, когда есть — строка над «Подключением» (вторая подписка без прокрутки).
 */
(function (Lz) {
  const { h, setText, setHidden } = Lz.dom;
  const ui = Lz.ui;
  const fmt = Lz.fmt;
  const texts = Lz.texts;
  const view = Lz.vcView;
  const gate = Lz.vpnclientGate;

  const MODE_ORDER = ['tun', 'proxy', 'local'];
  const MEMORY_LABEL = { 'sing-box': 'sing-box', xray: 'Xray' };
  /* Картинка состояния вместо нулей скорости, пока VPN не подключён (docs/art/vpn-states.md). */
  const SCENE_ART = {
    off: 'img/vpn-off.png',
    connect: 'img/vpn-connect.png',
    error: 'img/vpn-error.png',
    core: 'img/vpn-core.png',
  };
  const SCENE_ART_SIZE = { width: 240, height: 97 };
  /* Ошибки, при которых помогает другой сервер; остальные (порт, права, часы) чинятся иначе. */
  const SERVER_ERRORS = new Set(['timeout', 'tls', 'auth', 'unsupported']);

  /* ---------- Подключение ---------- */

  /**
   * Через что пойдёт трафик — с родовым словом снаружи кавычек: «через сервер «Амстердам»» для сервера
   * (и сервера, который выбрала группа), «через группу «Умная локация»» — пока группа ещё не выбрала сервер.
   * { via, viaIt } — «через …» и «через него / через неё»; пусто — сервер не выбран.
   */
  function routeVia(target) {
    if (!target) return { via: '', viaIt: '' };
    const name = Lz.fmt.quote(target.name);
    if (target.auto && !target.group) return { via: `через группу ${name}`, viaIt: 'через неё', group: true };
    return { via: `через сервер ${name}`, viaIt: 'через него', group: false };
  }

  /**
   * Что показать вместо скорости и трафика: { kind, text }; null — VPN работает и выход через
   * сервер проверен, тогда видна статистика. Строка состояния и подпись под кнопкой уже называют
   * состояние, поэтому текст сцены не повторяет его, а говорит, что дальше.
   */
  function sceneFor(vc, cores, pillStatus) {
    /* Подключено и выход проверен — только цифры: подкачка ядра рядом их не заменяет. */
    if (pillStatus === 'running') return null;
    const route = routeVia(view.selectedView(vc));
    /* Не подключилось или через сервер ничего не открывается — почему, чья сторона и что сделать. */
    const why = vc.error && (pillStatus === 'error' || pillStatus === 'verifying') ? texts.vpncReason(vc.diagnosis) : null;
    if (why) return { kind: 'error', why };
    /* Обновление уже стоящего ядра и подкачка ненужного помощника (needed: false) идут фоном — только первая нужная. */
    if (texts.vpncCoreFirstInstall(cores)) {
      return {
        kind: 'core',
        text: 'Готовим ядро VPN — это нужно один раз. Лазейка скачивает официальную сборку с GitHub и сверяет её SHA-256, дальше VPN включается за пару секунд.',
      };
    }
    if (pillStatus !== 'error' && texts.vpncCoreMissing(cores)) {
      return {
        kind: 'core',
        text: 'Ядро VPN не скачалось — причина и кнопка «Скачать ещё раз» вверху страницы. Лазейка повторит и сама, а «Включить» попробует скачать его сразу.',
      };
    }
    switch (pillStatus) {
      case 'starting':
      case 'verifying':
        return {
          kind: 'connect',
          text: route.via
            ? `Строим маршрут ${route.via} и проверяем, что сайты ${route.viaIt} открываются.`
            : 'Строим маршрут и проверяем, что сайты через него открываются.',
        };
      case 'error': {
        const through = route.via ? `${route.via.charAt(0).toUpperCase()}${route.via.slice(1)} подключиться` : 'Подключиться';
        return {
          kind: 'error',
          text: SERVER_ERRORS.has(vc.error_kind)
            ? `${through} не вышло. Попробуйте другой сервер или «Самый быстрый»\u00A0— подробности вверху страницы.`
            : 'Подключиться не вышло. Что случилось и что делать\u00A0— вверху страницы.',
        };
      }
      case 'locked':
        return { kind: 'off', text: 'Свой VPN сейчас недоступен\u00A0— причина вверху страницы.' };
      default: {
        let next = 'Свой VPN выключен. Выберите сервер в списке ниже и включите VPN кнопкой питания.';
        if (route.via && route.group) {
          next = `Свой VPN выключен. Включите его кнопкой питания\u00A0— трафик пойдёт ${route.via}: Лазейка выберет в ней самый быстрый сервер.`;
        } else if (route.via) {
          next = `Свой VPN выключен. Включите его кнопкой питания\u00A0— трафик пойдёт ${route.via}.`;
        }
        return { kind: 'off', text: next };
      }
    }
  }

  /** Картинки всех сцен создаются сразу: смена состояния не ждёт загрузки и не мигает. */
  function createScene() {
    const arts = new Map(Object.entries(SCENE_ART).map(([kind, src]) => {
      const art = h('img', { class: ['vc-scene__art', `vc-scene__art--${kind}`], src, alt: '', ...SCENE_ART_SIZE, decoding: 'async', hidden: true });
      /* Не загрузилась — остаётся только текст. */
      art.addEventListener('error', () => {
        art.dataset.broken = '1';
        setHidden(art, true);
      }, { once: true });
      return [kind, art];
    }));
    const text = h('p', { class: 'vc-scene__text' });
    const why = createWhy();
    return {
      el: h('div', { class: 'vc-scene' }, [...arts.values()], text, why.el),
      set(scene) {
        for (const [kind, art] of arts) setHidden(art, kind !== scene.kind || art.dataset.broken === '1');
        setHidden(text, Boolean(scene.why));
        setHidden(why.el, !scene.why);
        if (scene.why) why.set(scene.why);
        else setText(text, scene.text);
      },
    };
  }

  /** Причина отказа тремя строками: «Почему», «Чья сторона», «Что сделать» (texts.vpncReason). */
  function createWhy() {
    const reason = h('dd', { class: 'vc-scene__why-text' });
    const side = h('span', { class: 'vc-why__side' });
    const advice = h('dd', { class: 'vc-scene__why-text' });
    const adviceRow = h('div', { class: 'vc-scene__why-row' }, h('dt', { text: 'Что сделать' }), advice);
    const el = h('dl', { class: 'vc-scene__why', hidden: true },
      h('div', { class: 'vc-scene__why-row' }, h('dt', { text: 'Почему' }), reason),
      h('div', { class: 'vc-scene__why-row' }, h('dt', { text: 'Чья сторона' }), h('dd', null, side)),
      adviceRow);
    return {
      el,
      set(data) {
        el.dataset.side = data.side;
        setText(reason, data.text);
        setText(side, data.sideLabel);
        setText(advice, data.advice);
        setHidden(adviceRow, !data.advice);
      },
    };
  }

  function renderSelected(data) {
    if (!data.view) {
      return [
        h('p', { class: 'vc-conn__server' }, h('span', { class: 'vc-selected is-empty', text: 'Сервер не выбран' })),
        h('p', { class: 'vc-conn__proto', text: 'Выберите сервер в списке ниже или «Самый быстрый».' }),
      ];
    }
    const meta = [data.view.proto, data.view.viaXray ? 'через помощник Xray' : null].filter(Boolean).join(' · ');
    return [
      h('p', { class: 'vc-conn__server' }, view.selectedLine(data.view, 'vc-selected--lg')),
      h('p', { class: 'vc-conn__proto', text: meta }),
    ];
  }

  function kpi(label, valueEl, mod) {
    return h('div', { class: ['kpi', mod && `kpi--${mod}`] }, h('span', { class: 'kpi__label', text: label }), valueEl);
  }

  function createConnectionCard(onChangeServer) {
    let status = 'stopped';
    const power = Lz.power.create({ label: 'Свой VPN', busyKey: gate.POWER_KEY, onToggle: () => gate.toggle(status) });
    const caption = Lz.power.caption(power, 'vc-conn__caption');

    const statusText = h('span', { class: 'conn__text' });
    const statusLine = h('p', { class: 'conn vc-conn__status', role: 'status' }, h('span', { class: 'conn__dot', 'aria-hidden': 'true' }), statusText);
    const installBar = ui.progressBar({ label: 'Готовим ядро VPN' });
    const installBox = h('div', { class: 'vc-conn__install', hidden: true }, installBar.el);

    const server = ui.slot(renderSelected, { cls: 'vc-conn__selected' });
    const change = ui.button({ label: 'Сменить сервер', iconRight: 'arrowRight', kind: 'link', size: 'sm', onClick: () => onChangeServer() });

    let modePending = false;
    const modeSeg = ui.segmented({
      label: 'Режим своего VPN',
      value: 'tun',
      size: 'sm',
      options: MODE_ORDER.map((mode) => ({ value: mode, label: texts.vpncMode(mode).label, title: texts.vpncMode(mode).text })),
      onChange: async (mode) => {
        modePending = true;
        try {
          const running = texts.vpncRunning(status);
          const result = await Lz.api.run({
            method: 'vpnclient_set_mode',
            args: [mode],
            key: 'vpnclient_set_mode',
            success: running ? 'Режим изменён — VPN переподключается' : null,
          });
          return Boolean(result && result.ok);
        } finally {
          modePending = false;
        }
      },
    });
    const modeText = h('p', { class: 'vc-conn__hint' });
    const listenValue = h('span', { class: 'mono' });
    const copyListen = ui.button({
      icon: 'copy',
      kind: 'ghost',
      size: 'sm',
      ariaLabel: 'Скопировать адрес прокси',
      title: 'Скопировать',
      onClick: () => Lz.actions.copyText(listenValue.textContent, 'Адрес прокси'),
    });
    const listenRow = h('p', { class: 'vc-conn__listen', hidden: true },
      h('span', { class: 'vc-conn__listen-label', text: 'Прокси для программ' }), listenValue, copyListen.el);

    const values = {
      down: h('span', { class: 'kpi__value num' }),
      up: h('span', { class: 'kpi__value num' }),
      connections: h('span', { class: 'kpi__value num' }),
      session: h('span', { class: 'kpi__value num' }),
      today: h('span', { class: 'kpi__value num' }),
      total: h('span', { class: 'kpi__value num' }),
    };
    const spark = ui.sparkline({ label: 'Скорость своего VPN за две минуты' });
    const memoryText = h('span');
    const trafficTitle = h('span');
    const scene = createScene();
    /* Статистика и сцена делят одну ячейку сетки: высота карточки не прыгает при смене состояния. */
    const statsView = h('div', { class: 'vc-conn__view' },
      h('div', { class: 'vc-conn__live' },
        h('div', { class: 'kpis' },
          kpi('Загрузка', values.down, 'down'),
          kpi('Отдача', values.up, 'up'),
          kpi('Соединений', values.connections),
          kpi('За сеанс', values.session),
          kpi('Сегодня', values.today),
          kpi('Всего', values.total)),
        h('div', { class: 'spark-wrap spark-wrap--tall' }, spark.el)),
      scene.el);
    const stats = h('div', { class: 'vc-conn__stats' },
      statsView,
      h('p', { class: 'vc-conn__foot' }, memoryText, trafficTitle));

    const card = ui.card({ title: 'Подключение' });
    card.body.classList.add('vc-conn');
    card.body.append(
      h('div', { class: 'vc-conn__main' },
        h('div', { class: 'vc-conn__power' }, power.el, caption.el),
        h('div', { class: 'vc-conn__info' },
          statusLine,
          installBox,
          h('div', { class: 'vc-conn__block' },
            h('div', { class: 'vc-conn__block-head' }, h('span', { class: 'vc-conn__label', text: 'Сервер' }), change.el),
            server.el),
          h('div', { class: 'vc-conn__block' },
            h('span', { class: 'vc-conn__label', text: 'Режим' }),
            modeSeg.el,
            modeText,
            listenRow))),
      stats);

    return {
      el: card.el,
      update(state) {
        const snap = view.snapshot(state);
        const vc = snap.vc;
        const pillStatus = texts.vpncPillStatus(vc);
        status = vc.status || 'stopped';
        const available = vc.available !== false;
        power.update(pillStatus === 'verifying' ? 'running' : (available ? status : 'stopped'), { disabled: !available || !texts.vpncHasServers(vc) });
        const [captionText, captionQuiet] = texts.vpncCaptionParts(vc, pillStatus);
        caption.set(captionText, captionQuiet, { error: status === 'error' });

        const line = texts.vpncLine(vc);
        statusLine.dataset.tone = line.tone;
        setText(statusText, line.text);
        const installing = pillStatus === 'running' ? null : texts.vpncCoreFirstInstall(snap.cores);
        setHidden(installBox, !installing);
        if (installing) installBar.set(installing.state === 'downloading' && installing.progress != null ? installing.progress : null);

        server.update({ view: view.selectedView(vc) });

        const mode = MODE_ORDER.includes(vc.mode) ? vc.mode : 'tun';
        if (!modePending) modeSeg.set(mode);
        modeSeg.setDisabled(!available || status === 'starting' || status === 'stopping');
        setText(modeText, texts.vpncMode(modeSeg.get()).text);
        const listen = vc.listen || (mode !== 'tun' && snap.settings.port ? `127.0.0.1:${snap.settings.port}` : '');
        setText(listenValue, listen);
        setHidden(listenRow, mode === 'tun' || !listen);

        const statsData = vc.stats || {};
        const traffic = vc.traffic || {};
        setText(values.down, fmt.rate(statsData.down_rate || 0));
        setText(values.up, fmt.rate(statsData.up_rate || 0));
        setText(values.connections, fmt.integer(statsData.connections || 0));
        setText(values.session, fmt.bytes((Number(statsData.up) || 0) + (Number(statsData.down) || 0)));
        setText(values.today, fmt.bytes((Number(traffic.today_up) || 0) + (Number(traffic.today_down) || 0)));
        setText(values.total, fmt.bytes((Number(traffic.total_up) || 0) + (Number(traffic.total_down) || 0)));
        spark.update(vc.history);
        const memory = vc.memory && typeof vc.memory === 'object' ? vc.memory : {};
        const memoryParts = Object.keys(MEMORY_LABEL).filter((name) => Number(memory[name]) > 0)
          .map((name) => `${MEMORY_LABEL[name]} ${fmt.bytes(memory[name])}`);
        setText(memoryText, memoryParts.length ? `Память ядер: ${memoryParts.join(' · ')}` : 'Ядра не запущены');
        stats.classList.toggle('is-idle', status !== 'running');

        const sceneNow = sceneFor(vc, snap.cores, pillStatus);
        statsView.classList.toggle('is-scene', Boolean(sceneNow));
        if (sceneNow) scene.set(sceneNow);
        /* Пока цифры скорости спрятаны за сценой, трафик за день и всего — в нижней строке. */
        setText(trafficTitle, sceneNow
          ? `Сегодня ${values.today.textContent} · всего ${values.total.textContent}`
          : `За сеанс ${view.trafficPair(statsData.down, statsData.up)}`);
      },
    };
  }

  /* ---------- Плашки ---------- */

  function renderBanner(data) {
    if (!data.present) {
      return ui.callout({
        tone: 'info',
        title: 'Свой VPN появится после обновления',
        text: 'Ядро Лазейки этой версии не сообщает о своём VPN. Обновите Лазейку на странице «Обновления».',
      });
    }
    if (!data.available) {
      const relaunch = data.admin ? null : ui.actionButton({
        method: 'relaunch_admin',
        label: 'Перезапустить с правами администратора',
        icon: 'shieldCheck',
        kind: 'primary',
        size: 'sm',
      }).el;
      return ui.callout({ tone: 'warn', title: 'Свой VPN недоступен', text: data.reason || 'Подробности — в журнале.', actions: relaunch });
    }
    if (data.status === 'error') {
      const kind = texts.vpncError(data.kind);
      const logs = ui.button({ label: 'Открыть журнал', size: 'sm', onClick: () => Lz.nav.go('logs') }).el;
      const help = ui.button({ label: 'Что делать', size: 'sm', kind: 'ghost', onClick: () => Lz.nav.go('help', { symptom: 'vpnclient' }) }).el;
      /* Есть причина — почему, чья сторона и что сделать показывает карточка «Подключение» ниже: здесь только что случилось. */
      const advice = data.diagnosed ? '' : kind.advice;
      return ui.callout({
        tone: 'err',
        title: kind.title,
        text: data.error && data.error !== kind.title ? `${data.error} ${advice}`.trim() : (advice || data.error || kind.title),
        actions: [help, logs],
      });
    }
    if (data.conflict && data.status !== 'running') return renderConflict(data);
    return null;
  }

  /**
   * С чем свой VPN не уживётся (vpnclient.conflict): чужой туннель, чужой системный прокси или режим прокси под
   * чужой учётной записью UAC (uac_user). Кнопка — только та, что сработает: под чужой учётной записью
   * системный прокси недоступен (proxy_denied), и «Перейти на системный прокси» отказал бы.
   */
  function renderConflict(data) {
    const conflict = data.conflict;
    if (conflict.kind === 'uac_user') {
      /* Ядро помнит отказ с прошлого «Включить»; режим уже «Весь трафик» — плашке не о чем говорить. */
      if (data.mode !== 'proxy') return null;
      return ui.callout({
        tone: 'warn',
        title: gate.conflictTitle(conflict),
        text: fmt.sentence(conflict.text || 'Лазейка запущена от другой учётной записи и не может поменять ваш системный прокси'),
        actions: ui.actionButton({
          method: 'vpnclient_set_mode',
          args: ['tun'],
          label: 'Весь трафик (TUN)',
          size: 'sm',
          success: 'Режим «Весь трафик» выбран',
        }).el,
      });
    }
    const toProxy = conflict.kind === 'tunnel' && data.mode === 'tun' && !conflict.proxyDenied ? ui.actionButton({
      method: 'vpnclient_set_mode',
      args: ['proxy'],
      label: 'Перейти на системный прокси',
      size: 'sm',
      success: 'Режим «Системный прокси» выбран',
    }).el : null;
    /* Заголовок — тот же, что у окна перед включением: одна поломка, одно название. */
    return ui.callout({
      tone: 'warn',
      title: gate.conflictTitle(conflict),
      text: [conflict.text || 'Два VPN мешают друг другу', conflict.proxyDenied].filter(Boolean).map(fmt.sentence).join(' '),
      actions: toProxy,
    });
  }

  /* ---------- Страница ---------- */

  function subtitle(snap) {
    const versions = [['sing-box', 'sing-box'], ['xray', 'Xray']]
      .filter(([name]) => snap.cores[name] && snap.cores[name].installed && snap.cores[name].version)
      .map(([name, label]) => `${label} ${snap.cores[name].version}`);
    return versions.length ? ['Ваш сервер', ...versions].join(' · ') : 'Подключение к вашему серверу по подписке вашего VPN';
  }

  function create() {
    let status = 'stopped';
    const sections = Lz.vcSections;
    const pill = ui.statusPill();
    /* «Переподключить» — как в плашке vpn-exit ядра: одно действие, одно название и один ключ (notices.js). */
    const restartBtn = ui.actionButton({ method: 'vpnclient_restart', label: 'Переподключить', icon: 'refresh', success: 'Свой VPN переподключается' });
    const powerBtn = ui.button({
      label: 'Включить',
      icon: 'power',
      kind: 'primary',
      busyKey: gate.POWER_KEY,
      onClick: () => gate.toggle(status),
    });
    const header = ui.pageHeader({ title: 'Свой VPN', actions: [pill.el, restartBtn.el, powerBtn.el] });
    const banner = ui.slot(renderBanner, { cls: 'page__banners' });

    const servers = sections.createServersSection();
    const connection = createConnectionCard(() => scrollTo(servers.el));
    const add = sections.createAddSection();
    const routing = sections.createRoutingSection();
    const more = sections.createMoreSection();
    const all = [add, connection, servers, routing, more];
    const anchors = { servers: servers.el, add: add.el, routing: routing.el, more: more.el, connection: connection.el };

    const el = h('div', { class: 'page__inner page__inner--vpnclient' }, header.el, banner.el, all.map((section) => section.el));

    function scrollTo(target) {
      requestAnimationFrame(() => target.scrollIntoView({ block: 'start', behavior: Lz.nav.scrollBehavior() }));
    }

    return {
      el,
      update(state) {
        const snap = view.snapshot(state);
        const vc = snap.vc;
        status = vc.status || 'stopped';
        const available = snap.present && vc.available !== false;
        pill.set(snap.present ? texts.vpncPillShown(vc) : 'locked');
        setText(header.subtitleEl, subtitle(snap));
        const running = texts.vpncRunning(status);
        const empty = !texts.vpncHasServers(vc);
        powerBtn.setLabel(running ? 'Выключить' : 'Включить');
        powerBtn.setDisabled(!available || status === 'stopping' || (empty && !running));
        restartBtn.setDisabled(!available || status !== 'running');
        banner.update({
          present: snap.present,
          available: vc.available !== false,
          admin: Boolean(state.app && state.app.admin),
          reason: vc.unavailable_reason || null,
          status,
          kind: vc.error_kind || null,
          error: vc.error ? String(vc.error) : null,
          diagnosed: Boolean(texts.vpncReason(vc.diagnosis)),
          mode: vc.mode || 'tun',
          conflict: vc.conflict && typeof vc.conflict === 'object' ? {
            kind: vc.conflict.kind || null,
            label: vc.conflict.label ? String(vc.conflict.label) : null,
            text: vc.conflict.text ? String(vc.conflict.text) : null,
            proxyDenied: vc.conflict.proxy_denied ? String(vc.conflict.proxy_denied) : null,
          } : null,
        });
        setHidden(connection.el, empty || !snap.present);
        setHidden(servers.el, empty || !snap.present);
        setHidden(add.el, !snap.present);
        setHidden(routing.el, !snap.present);
        setHidden(more.el, !snap.present);
        if (!snap.present) return;
        for (const section of all) section.update(state);
      },
      /* Lz.nav.go('vpnclient', { focus: 'add' | 'servers' | 'routing' | 'more' }). */
      show(opts) {
        const focus = opts && opts.focus;
        const target = focus ? anchors[focus] : null;
        if (!target) return;
        if (focus === 'more') more.open();
        scrollTo(target);
        if (focus === 'add') add.focus();
      },
    };
  }

  /* Одно имя везде: пункт меню, заголовок страницы и ссылки на неё — «Свой VPN»; чужой VPN — «другой VPN». */
  Lz.pages.vpnclient = { title: 'Свой VPN', icon: 'vpn', create };
})(window.Lz);
