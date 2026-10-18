'use strict';
/*
 * Свой VPN → «Добавить»: поле для ссылки или адреса подписки, буфер обмена, файл и QR,
 * ход импорта и предложения ядра (представиться другим клиентом, отправить HWID, проверить
 * расширенный формат). Пока серверов нет — пустое состояние «приносите свою подписку».
 */
(function (Lz) {
  const { h, uid, setHidden } = Lz.dom;
  const ui = Lz.ui;
  const texts = Lz.texts;

  const IMPORT_KEY = 'vpnclient_import';
  const EMPTY_ART = 'img/vpn-empty.png';
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

  /**
   * Кнопки предложения ядра (vpnclient.import.offer = {kind, text, options, sub}): options — пресеты
   * User-Agent («как Happ»…) и «hwid». Что делать по нажатию, решает карточка (retry).
   */
  function offerActions(offer, retry) {
    const options = Array.isArray(offer.options) ? offer.options.map(String) : [];
    /* extended — стоит проверить другой UA; switch — проверка уже нашла формат богаче: переключаем подписку. */
    const verb = offer.kind === 'extended' ? 'Проверить' : offer.kind === 'switch' ? 'Переключить на' : 'Попробовать';
    const buttons = options.filter((preset) => texts.VPNC_UA[preset] && preset !== 'custom')
      .map((preset) => fk(ui.button({
        label: preset === 'lazeyka' ? `${verb} с честным User-Agent` : `${verb} ${texts.VPNC_UA[preset]}`,
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

  function renderProgress(data, retry) {
    if (data.running) {
      return h('p', { class: 'vc-import__progress', role: 'status' },
        h('span', { class: 'spinner spinner--inline', 'aria-hidden': 'true' }), data.message || 'Добавляем…');
    }
    if (data.offer) {
      const actions = offerActions(data.offer, retry);
      return ui.callout({
        tone: OFFER_TONE[data.offer.kind] || 'info',
        title: OFFER_TITLE[data.offer.kind] || null,
        text: [data.offer.kind === 'extended' ? data.message : '', data.offer.text || data.error || data.message || '']
          .filter(Boolean).join('. '),
        actions: actions.length ? actions : null,
      });
    }
    if (data.error) return ui.callout({ tone: 'err', title: 'Не получилось добавить', text: data.error });
    if (data.message) return ui.callout({ tone: 'ok', text: data.message });
    return null;
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

    const areaId = uid('vc-import');
    const area = ui.textArea({
      id: areaId,
      rows: 3,
      placeholder: 'https://… или vless://… — можно несколько ссылок, по одной на строку',
    });
    const field = ui.field({
      label: 'Вставьте ссылку или адрес подписки',
      hint: 'Подписка https://…, ссылки vless:// vmess:// ss:// trojan:// hysteria2:// tuic:// wireguard:// socks://, base64 или ссылка «добавить в приложение» от провайдера.',
      control: area,
      inputId: areaId,
    });
    area.addEventListener('input', () => field.setError(null));
    area.addEventListener('keydown', (event) => {
      if (event.key === 'Enter' && (event.ctrlKey || event.metaKey)) {
        event.preventDefault();
        submit();
      }
    });

    async function submit(textOverride) {
      const text = String(textOverride != null ? textOverride : area.value).trim();
      if (!text) {
        field.setError('Вставьте ссылку на подписку или сервер');
        area.focus();
        return;
      }
      field.setError(null);
      submitted = text;
      handledOffer = null;
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

    const addBtn = ui.button({ label: 'Добавить', icon: 'plus', kind: 'primary', busyKey: IMPORT_KEY, onClick: () => submit() });
    const pasteBtn = ui.button({ label: 'Вставить из буфера', icon: 'clipboard', busyKey: IMPORT_KEY, onClick: () => paste() });
    const fileBtn = ui.actionButton({
      method: 'vpnclient_import_file',
      label: 'Из файла',
      icon: 'file',
      size: 'sm',
      kind: 'ghost',
      title: 'Файл .conf (WireGuard), .json, .txt или картинка с QR-кодом',
    });
    const screenBtn = ui.actionButton({
      method: 'vpnclient_import_qr',
      args: ['screen'],
      key: 'vpnclient_import_qr:screen',
      label: 'QR со снимка экрана',
      icon: 'monitor',
      size: 'sm',
      kind: 'ghost',
      title: 'Откройте QR-код провайдера на экране и нажмите — Лазейка найдёт его на снимке экрана',
    });
    const imageBtn = ui.actionButton({
      method: 'vpnclient_import_qr',
      args: ['file'],
      key: 'vpnclient_import_qr:file',
      label: 'QR из картинки',
      icon: 'image',
      size: 'sm',
      kind: 'ghost',
    });
    const progress = ui.slot((data) => renderProgress(data, retry), { cls: 'vc-import__result' });
    const hero = h('div', { class: 'vc-empty-wrap', hidden: true }, emptyHero());

    const card = ui.card({ title: 'Добавить', subtitle: 'Подписку вашего VPN или отдельные серверы по ссылкам.' });
    card.body.append(
      hero,
      field.el,
      /* Не помещаются в строку — файл и QR уходят вниз все вместе, справа. */
      h('div', { class: 'vc-import__buttons' },
        h('div', { class: 'vc-import__group' }, addBtn.el, pasteBtn.el),
        h('div', { class: 'vc-import__group vc-import__group--more' }, fileBtn.el, screenBtn.el, imageBtn.el)),
      progress.el);

    return {
      el: card.el,
      focus() {
        area.focus({ preventScroll: true });
      },
      update(state) {
        const snap = Lz.vcView.snapshot(state);
        const empty = !texts.vpncHasServers(snap.vc);
        setHidden(hero, !empty);
        card.el.classList.toggle('is-empty', empty);
        const imp = snap.vc.import || {};
        const running = Boolean(imp.running);
        const importKey = JSON.stringify(imp);
        const offer = offerOf(imp);
        /* Импорт начался не из поля — текст поля к нему отношения не имеет. */
        if (running && !wasRunning && !fieldImport) {
          submitted = null;
          fieldOfferKey = null;
        }
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
        for (const ctl of [pasteBtn, fileBtn, screenBtn, imageBtn]) ctl.setDisabled(running);
        if (running) handledOffer = null;
        /* По этому предложению уже действуем через карточку подписки — прежний итог импорта больше не нужен. */
        const stale = Boolean(offer) && JSON.stringify(offer) === handledOffer;
        progress.update(stale ? { running: false, message: '', error: '', offer: null } : {
          running,
          message: imp.message ? String(imp.message) : '',
          error: imp.error ? String(imp.error) : '',
          offer,
        });
      },
    };
  }

  Lz.vcSections = Object.assign(Lz.vcSections || {}, { createAddSection });
})(window.Lz);
