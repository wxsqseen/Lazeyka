'use strict';
/*
 * Свой VPN → «Добавить»: поле для ссылки или адреса подписки, буфер обмена, файл и QR,
 * ход импорта и предложения ядра (представиться другим клиентом, отправить HWID, проверить
 * расширенный формат). Раздел стоит первым на странице. Пока серверов нет — большая карточка
 * «приносите свою подписку» с картинкой; когда серверы есть — та же форма сжимается в строку
 * над «Подключением»: поле, «Добавить» и «⋯» с буфером, файлом и QR, итог импорта — под строкой.
 */
(function (Lz) {
  const { h, icon, uid, setHidden } = Lz.dom;
  const ui = Lz.ui;
  const texts = Lz.texts;

  const IMPORT_KEY = 'vpnclient_import';
  const EMPTY_ART = 'img/vpn-empty.png';
  const AREA_ROWS = 3;
  const AREA_PLACEHOLDER = 'https://… или vless://… — можно несколько ссылок, по одной на строку';
  const BAR_PLACEHOLDER = 'Вставьте ссылку на подписку или сервер';
  const BAR_ICON = 18;
  const IDLE = { running: false, message: '', error: '', offer: null };
  /* Другие способы добавить: в большой карточке — кнопками, в строке — пунктами меню «⋯». */
  const SOURCES = [
    {
      method: 'vpnclient_import_file',
      args: [],
      key: 'vpnclient_import_file',
      label: 'Из файла',
      icon: 'file',
      title: 'Файл .conf (WireGuard), .json, .txt или картинка с QR-кодом',
    },
    {
      method: 'vpnclient_import_qr',
      args: ['screen'],
      key: 'vpnclient_import_qr:screen',
      label: 'QR со снимка экрана',
      icon: 'monitor',
      title: 'Откройте QR-код провайдера на экране и нажмите — Лазейка найдёт его на снимке экрана',
    },
    { method: 'vpnclient_import_qr', args: ['file'], key: 'vpnclient_import_qr:file', label: 'QR из картинки', icon: 'image' },
  ];
  const OFFER_TONE = { ua: 'warn', hwid: 'warn', html: 'err', stub: 'info', extended: 'info', switch: 'ok' };
  const OFFER_TITLE = {
    ua: 'Панель не отдала серверы Лазейке',
    hwid: 'Панель просит идентификатор устройства',
    html: 'Это веб-страница, а не подписка',
    stub: 'Сообщение провайдера',
    extended: 'Подписка в простом формате',
    switch: 'Нашёлся расширенный формат',
  };

  /* ---------- Пустое состояние ---------- */

  /**
   * Иллюстрация — обычный файл img/vpn-empty.png в рамке фиксированного размера (object-fit),
   * поэтому его можно заменить картинкой любых пропорций; не загрузилась — рамка просто прячется.
   */
  function emptyHero() {
    const art = h('img', { class: 'vc-empty__art', src: EMPTY_ART, alt: '', width: 200, height: 150, decoding: 'async' });
    art.addEventListener('error', () => setHidden(art, true), { once: true });
    return h('div', { class: 'vc-empty' },
      art,
      h('div', { class: 'vc-empty__text' },
        h('p', { class: 'vc-empty__title', text: 'Подключите свой VPN' }),
        h('p', { class: 'vc-empty__lead', text: 'Лазейка не продаёт и не раздаёт серверы — подойдёт подписка вашего VPN на VLESS, VMess, Shadowsocks, Trojan, Hysteria2, TUIC, WireGuard или SOCKS.' }),
        h('p', { class: 'vc-empty__hint', text: 'Ссылка обычно лежит в личном кабинете или боте провайдера: «Подписка», «Ссылка для v2rayN, Happ или Incy». Discord и YouTube по-прежнему пойдут через обход Лазейки.' })));
  }

  /* ---------- Ход импорта и предложения ---------- */

  /** Ключ фокуса: перестроенная карточка вернёт фокус на кнопку с тем же data-fk. */
  function fk(el, key) {
    el.dataset.fk = key;
    return el;
  }

  /** Предложение ядра (vpnclient.import.offer) в виде для карточки и для сравнения по JSON. */
  function offerOf(imp) {
    if (!imp.offer || typeof imp.offer !== 'object') return null;
    return {
      kind: String(imp.offer.kind || ''),
      text: imp.offer.text ? String(imp.offer.text) : '',
      options: Array.isArray(imp.offer.options) ? imp.offer.options.map(String) : [],
      sub: imp.offer.sub ? String(imp.offer.sub) : null,
    };
  }

  /** Подпись кнопки пресета: «Попробовать как v2rayN», «Переключить на Happ», «Попробовать с честным User-Agent». */
  function presetLabel(kind, preset) {
    const name = texts.VPNC_UA_NAME[preset] || preset;
    if (kind === 'switch') return preset === 'lazeyka' ? 'Вернуть честный User-Agent' : `Переключить на ${name}`;
    return preset === 'lazeyka' ? 'Попробовать с честным User-Agent' : `Попробовать как ${name}`;
  }

  /**
   * Кнопки предложения ядра (vpnclient.import.offer = {kind, text, options, sub}): options — пресеты
   * User-Agent (v2rayN, Happ…) и «hwid». Что делать по нажатию, решает карточка (retry, probe).
   * extended — «Проверить расширенный формат» безопасной пробой (vpnclient_sub_probe): подписка не меняется,
   * итог придёт предложением switch; switch — проверка уже нашла формат богаче: переключаем подписку.
   */
  function offerActions(offer, retry, probe, probing) {
    const options = Array.isArray(offer.options) ? offer.options.map(String) : [];
    if (offer.kind === 'extended') {
      if (!offer.sub) return [];
      const check = ui.button({
        label: probing ? 'Проверяем формат…' : 'Проверить расширенный формат',
        size: 'sm',
        busyKey: `vpnclient_sub_probe:${offer.sub}`,
        title: 'Лазейка спросит панель от имени других клиентов и покажет, что нашлось. Подписку она не меняет.',
        onClick: () => probe(offer),
      });
      check.setBusy(Boolean(probing));
      return [fk(check.el, 'offer:probe')];
    }
    const buttons = options.filter((preset) => texts.VPNC_UA[preset] && preset !== 'custom')
      .map((preset) => fk(ui.button({
        label: presetLabel(offer.kind, preset),
        size: 'sm',
        busyKey: IMPORT_KEY,
        onClick: () => retry(offer, { ua_preset: preset }),
      }).el, `offer:${preset}`));
    if (options.includes('hwid') && offer.sub) {
      buttons.push(fk(ui.button({
        label: 'Отправить HWID и повторить',
        size: 'sm',
        kind: 'primary',
        busyKey: IMPORT_KEY,
        title: 'Лазейка отправит случайный идентификатор этой подписки, а не номер компьютера',
        onClick: () => retry(offer, { hwid: true }),
      }).el, 'offer:hwid'));
    }
    return buttons;
  }

  /**
   * Итог импорта ядро держит до следующего добавления, а раздел стоит первым на странице —
   * поэтому у готового итога есть крестик «Скрыть» (dismiss).
   */
  function renderProgress(data, retry, dismiss, probe) {
    if (data.running) {
      return h('p', { class: 'vc-import__progress', role: 'status' },
        h('span', { class: 'spinner spinner--inline', 'aria-hidden': 'true' }), data.message || 'Добавляем…');
    }
    let note = null;
    if (data.offer) {
      const actions = offerActions(data.offer, retry, probe, data.probing);
      note = ui.callout({
        tone: OFFER_TONE[data.offer.kind] || 'info',
        title: OFFER_TITLE[data.offer.kind] || null,
        text: [data.offer.kind === 'extended' ? data.message : '', data.offer.text || data.error || data.message || '']
          .filter(Boolean).join('. '),
        actions: actions.length ? actions : null,
      });
    } else if (data.error) {
      note = ui.callout({ tone: 'err', title: 'Не получилось добавить', text: data.error });
    } else if (data.message) {
      note = ui.callout({ tone: 'ok', text: data.message });
    }
    if (!note) return null;
    const close = ui.button({ icon: 'x', kind: 'ghost', size: 'sm', ariaLabel: 'Скрыть итог добавления', title: 'Скрыть', onClick: dismiss });
    return h('div', { class: 'vc-import__note' }, note, fk(close.el, 'import:dismiss'));
  }

  /* ---------- Карточка ---------- */

  function createAddSection() {
    let submitted = null;
    let wasRunning = false;
    /*
     * Импорт из поля (а не QR, файлом или ссылкой lazeyka://): fieldImport — итог ещё не пришёл,
     * importKeyBefore — снимок vpnclient.import до нажатия. Быстрый импорт может закончиться между
     * опросами, поэтому конец ловим по смене снимка, а не только по running.
     */
    let fieldImport = false;
    let importKeyBefore = null;
    let lastImportKey = null;
    /* Предложение, с которым закончился импорт из поля: только по нему «Попробовать» повторяет текст поля. */
    let fieldOfferKey = null;
    /* Предложение, по которому уже нажали «Попробовать» без текста под рукой: ответ появится в карточке подписки. */
    let handledOffer = null;
    /* Снимок vpnclient.import, итог которого скрыли крестиком; новое добавление покажет свой итог. */
    let dismissedKey = null;
    /* Строка над «Подключением» (серверы есть) или большая карточка пустого состояния; null — до первого состояния. */
    let compact = null;
    let running = false;

    /*
     * Поле — textarea и в строке: в <input> вставка нескольких ссылок или JSON склеилась бы в одну строку
     * (ядро делит текст по переводам строк). В строке высота следует за текстом (field-sizing в CSS).
     */
    const areaId = uid('vc-import');
    const area = ui.textArea({ id: areaId, rows: AREA_ROWS, placeholder: AREA_PLACEHOLDER });
    /* Сюда возвращается фокус, если удалили последнюю подписку (vpnclient-servers.js). */
    area.dataset.fk = 'vc-add-field';
    const barActions = h('div', { class: 'vc-add__actions' });
    const box = h('div', { class: 'vc-add__box' }, icon('link', { size: BAR_ICON, cls: 'vc-add__icon' }), area, barActions);
    const field = ui.field({
      label: 'Вставьте ссылку или адрес подписки',
      hint: 'Подписка https://…, ссылки vless:// vmess:// ss:// trojan:// hysteria2:// tuic:// wireguard:// socks://, base64 или ссылка «добавить в приложение» от провайдера.',
      control: box,
      inputId: areaId,
    });
    const label = field.el.querySelector('.field__label');
    area.addEventListener('input', () => field.setError(null));
    area.addEventListener('keydown', (event) => {
      /* Enter — добавить, Shift+Enter — новая строка (вторая ссылка вручную). */
      if (event.key !== 'Enter' || event.shiftKey || event.isComposing) return;
      event.preventDefault();
      if (!addBtn.isInactive()) submit();
    });

    async function submit(textOverride) {
      const text = String(textOverride != null ? textOverride : area.value).trim();
      if (!text) {
        field.setError('Поле пустое — вставьте ссылку на подписку или сервер');
        area.focus();
        return;
      }
      field.setError(null);
      submitted = text;
      handledOffer = null;
      dismissedKey = null;
      fieldImport = true;
      importKeyBefore = lastImportKey;
      const result = await Lz.api.run({ method: 'vpnclient_import', args: [text, null], key: IMPORT_KEY, silent: true });
      if (result && !result.ok) {
        fieldImport = false;
        field.setError(result.error);
      }
    }

    /** Кнопка предложения исчезнет с ответом ядра — фокус заранее на «Добавить» той же карточки. */
    function moveFocusFromOffer(target) {
      if (progress.el.contains(document.activeElement)) target.focus({ preventScroll: true });
    }

    /**
     * Повтор по предложению: сначала свойство подписки (UA или HWID). Предложение — итог импорта из поля:
     * тот же адрес из поля ещё раз, ответ останется здесь. Иначе («Переключить на…» после проверки формата,
     * QR, файл, lazeyka://) — обновляем подписку предложения, итог будет в её карточке: текст поля к ней
     * отношения не имеет, и повтор сменил бы UA у другой подписки.
     */
    async function retry(offer, change) {
      const fromField = offer.kind !== 'switch' && Boolean(submitted) && JSON.stringify(offer) === fieldOfferKey;
      dismissedKey = null;
      if (offer.sub) {
        const saved = await Lz.api.run({ method: 'vpnclient_sub_set', args: [offer.sub, change], key: IMPORT_KEY });
        if (!saved || !saved.ok) return;
      }
      if (fromField) {
        /* Это снова импорт из поля: удался — ссылку из поля уберём, новое предложение — тоже его. */
        fieldImport = true;
        importKeyBefore = lastImportKey;
        moveFocusFromOffer(addBtn.el);
        const result = await Lz.api.run({ method: 'vpnclient_import', args: [submitted, change.ua_preset || null], key: IMPORT_KEY });
        if (!result || !result.ok) fieldImport = false;
        return;
      }
      if (!offer.sub) return;
      handledOffer = JSON.stringify(offer);
      moveFocusFromOffer(addBtn.el);
      await Lz.api.run({
        method: 'vpnclient_sub_update',
        args: [offer.sub],
        key: IMPORT_KEY,
        success: 'Обновляем подписку — результат появится в её карточке в «Серверах»',
      });
    }

    async function paste() {
      let text = '';
      try {
        text = navigator.clipboard && navigator.clipboard.readText ? await navigator.clipboard.readText() : '';
      } catch (err) {
        console.warn('Буфер обмена не прочитан:', err);
        ui.toast({ kind: 'warn', text: 'Не получилось прочитать буфер обмена — вставьте ссылку в поле сочетанием Ctrl+V.' });
        area.focus();
        return;
      }
      if (!text.trim()) {
        ui.toast({ kind: 'info', text: 'В буфере обмена нет текста. Скопируйте ссылку у провайдера и нажмите ещё раз.' });
        return;
      }
      area.value = text.trim();
      submit(area.value);
    }

    /**
     * Файл и QR: тот же вызов из кнопки карточки и из меню «⋯». Файл WireGuard (.conf) ядро добавляет сразу и
     * отвечает итогом в message («Добавлено серверов WireGuard: 1») — показываем его; окно файла закрыли — молчим.
     */
    function fromSource(source) {
      dismissedKey = null;
      return Lz.api.run({
        method: source.method,
        args: source.args,
        key: source.key,
        success: (result) => (result.cancelled ? '' : String(result.message || '')),
      });
    }

    /** «Проверить расширенный формат» из предложения extended: проба без смены подписки (итог — предложение switch). */
    function probe(offer) {
      dismissedKey = null;
      return Lz.api.run({ method: 'vpnclient_sub_probe', args: [offer.sub], key: `vpnclient_sub_probe:${offer.sub}` });
    }

    /** Итог импорта скрыт крестиком: фокус с исчезнувшей кнопки — в поле. */
    function dismiss() {
      const hadFocus = progress.el.contains(document.activeElement);
      dismissedKey = lastImportKey;
      progress.update(IDLE);
      if (hadFocus) area.focus({ preventScroll: true });
    }

    const addBtn = ui.button({ label: 'Добавить', icon: 'plus', kind: 'primary', busyKey: IMPORT_KEY, onClick: () => submit() });
    const pasteBtn = ui.button({ label: 'Вставить из буфера', icon: 'clipboard', busyKey: IMPORT_KEY, onClick: () => paste() });
    const sourceBtns = SOURCES.map((source) => ui.button({
      label: source.label,
      icon: source.icon,
      size: 'sm',
      kind: 'ghost',
      title: source.title,
      busyKey: source.key,
      onClick: () => fromSource(source),
    }));
    /* size: null — обычная высота, вровень с «Добавить» в строке. */
    const moreBtn = ui.menuButton({
      ariaLabel: 'Другие способы добавить',
      title: 'Буфер обмена, файл или QR-код',
      size: null,
      fk: 'add-more',
      items: () => [
        { label: 'Вставить из буфера', icon: 'clipboard', disabled: running, onSelect: () => paste() },
        ...SOURCES.map((source) => ({
          label: source.label,
          icon: source.icon,
          title: source.title,
          disabled: running || Lz.api.isBusy(source.key),
          onSelect: () => fromSource(source),
        })),
      ],
    });
    barActions.append(moreBtn.el);
    const progress = ui.slot((data) => renderProgress(data, retry, dismiss, probe), { cls: 'vc-import__result' });
    const hero = h('div', { class: 'vc-empty-wrap', hidden: true }, emptyHero());
    const mainGroup = h('div', { class: 'vc-import__group' }, addBtn.el, pasteBtn.el);
    /* Не помещаются в строку — файл и QR уходят вниз все вместе, справа. */
    const buttons = h('div', { class: 'vc-import__buttons' },
      mainGroup,
      h('div', { class: 'vc-import__group vc-import__group--more' }, sourceBtns.map((btn) => btn.el)));

    const card = ui.card({ cls: 'vc-add', title: 'Добавить', subtitle: 'Подписку вашего VPN или отдельные серверы по ссылкам.' });
    card.body.append(hero, field.el, buttons, progress.el);

    /**
     * Строка или большая карточка. «Добавить» переезжает между ними сам (одна кнопка — один busy и фокус
     * для предложений); переезд снимает с него фокус, а спрятанные кнопки теряют его — возвращаем рядом.
     */
    function setCompact(next) {
      if (next === compact) return;
      compact = next;
      const focused = document.activeElement;
      card.el.classList.toggle('vc-add--bar', compact);
      card.el.classList.toggle('is-empty', !compact);
      setHidden(hero, compact);
      label.classList.toggle('sr-only', compact);
      area.rows = compact ? 1 : AREA_ROWS;
      area.placeholder = compact ? BAR_PLACEHOLDER : AREA_PLACEHOLDER;
      if (compact) barActions.prepend(addBtn.el);
      else mainGroup.prepend(addBtn.el);
      if (focused === addBtn.el) addBtn.el.focus({ preventScroll: true });
      else if (compact && buttons.contains(focused)) moreBtn.el.focus({ preventScroll: true });
      else if (!compact && focused === moreBtn.el) area.focus({ preventScroll: true });
    }

    return {
      el: card.el,
      focus() {
        area.focus({ preventScroll: true });
      },
      update(state) {
        const snap = Lz.vcView.snapshot(state);
        setCompact(texts.vpncHasServers(snap.vc));
        const imp = snap.vc.import || {};
        running = Boolean(imp.running);
        const importKey = JSON.stringify(imp);
        const offer = offerOf(imp);
        /* Импорт начался не из поля — текст поля к нему отношения не имеет. */
        if (running && !wasRunning && !fieldImport) {
          submitted = null;
          fieldOfferKey = null;
        }
        /*
         * Ход импорта из поля виден — конец поймаем по running: итог может совпасть с прошлым снимком
         * («Добавлено серверов: 1» у второй ссылки подряд), и по смене снимка поле бы не очистилось.
         */
        if (fieldImport && running) importKeyBefore = null;
        if (fieldImport && !running && importKey !== importKeyBefore) {
          fieldImport = false;
          fieldOfferKey = offer ? JSON.stringify(offer) : null;
          /* Успех (подсказка «расширенный формат» — тоже успех) — ссылку из поля убираем: в ней ключ доступа. */
          const succeeded = !imp.error && (!imp.offer || imp.offer.kind === 'extended');
          if (succeeded && submitted && area.value.trim() === submitted) {
            area.value = '';
            submitted = null;
          }
        }
        lastImportKey = importKey;
        wasRunning = running;
        addBtn.setBusy(running);
        for (const ctl of [pasteBtn, moreBtn, ...sourceBtns]) ctl.setDisabled(running);
        if (running) {
          handledOffer = null;
          dismissedKey = null;
        }
        /* По этому предложению уже действуем через карточку подписки — прежний итог импорта больше не нужен. */
        const stale = Boolean(offer) && JSON.stringify(offer) === handledOffer;
        const dismissed = !running && importKey === dismissedKey;
        /* Проба формата по предложению extended идёт — кнопка занята до итога (он придёт предложением switch). */
        const probing = Boolean(offer && offer.kind === 'extended' && snap.subscriptions.some((sub) => String(sub.id) === offer.sub
          && sub.probe && sub.probe.running));
        progress.update(stale || dismissed ? IDLE : {
          running,
          message: imp.message ? String(imp.message) : '',
          error: imp.error ? String(imp.error) : '',
          offer,
          probing,
        });
      },
    };
  }

  Lz.vcSections = Object.assign(Lz.vcSections || {}, { createAddSection });
})(window.Lz);
