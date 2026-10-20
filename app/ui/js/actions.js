'use strict';
/*
 * Команды, которые вызываются с нескольких страниц: включить/выключить, подключить Telegram, скопировать.
 * Включение обхода и прокси идёт через окно «Работает VPN» (vpn-gate.js), если ядро просит спросить.
 */
(function (Lz) {
  const RUNNING_LIKE = new Set(['running', 'starting']);
  /*
   * Ключи включения: заняты всё время от нажатия до ответа ядра — и пока идёт vpn_preflight, и пока открыто
   * окно «Работает VPN». Повторное нажатие (двойной щелчок, кнопка плашки) второго окна и старта не даст.
   */
  const POWER_KEY = { zapret: 'zapret_power', tg: 'tg_power' };
  /* Идущее включение по ключу: второй вызов во время него получает тот же Promise, а не null «уже идёт». */
  const starting = new Map();

  /**
   * Одно включение на ключ. Кто позвал во время идущего (кнопка питания, затем «Подключить Telegram»), дождётся
   * его итога. Ключ занят чем-то другим (выключение, «Найти и включить») — null, как прежде.
   */
  function startOnce(key, flow) {
    if (starting.has(key)) return starting.get(key);
    const promise = Lz.api.hold(key, flow).finally(() => starting.delete(key));
    starting.set(key, promise);
    return promise;
  }

  /** Включить обход. null — человек отказался в окне про VPN или ключ занят другим действием. */
  function startZapret() {
    return startOnce(POWER_KEY.zapret, async () => {
      const gate = await Lz.vpnGate.confirmStart('zapret');
      if (!gate.proceed) return null;
      return Lz.api.run({ method: 'zapret_start', args: gate.asked ? [true] : [], key: 'zapret_start' });
    });
  }

  /** Включить Telegram-прокси. null — человек отказался в окне про VPN или ключ занят другим действием. */
  function startTelegram() {
    return startOnce(POWER_KEY.tg, async () => {
      const gate = await Lz.vpnGate.confirmStart('tg');
      if (!gate.proceed) return null;
      return Lz.api.run({ method: 'tg_start', key: 'tg_start' });
    });
  }

  function toggleZapret(status) {
    if (RUNNING_LIKE.has(status)) {
      return Lz.api.run({ method: 'zapret_stop', key: 'zapret_power' });
    }
    return startZapret();
  }

  function toggleTelegram(status) {
    if (RUNNING_LIKE.has(status)) {
      return Lz.api.run({ method: 'tg_stop', key: 'tg_power' });
    }
    return startTelegram();
  }

  async function setStrategy(id) {
    const result = await Lz.api.run({ method: 'zapret_set_strategy', args: [id], key: 'zapret_set_strategy' });
    return Boolean(result && result.ok);
  }

  /** Выбрать стратегию и, если обход выключен, сразу его включить — «Включить» значит «заработает». */
  async function useStrategy(id) {
    if (!(await setStrategy(id))) return false;
    const state = Lz.store.state;
    const status = state && state.zapret ? state.zapret.status : 'stopped';
    if (RUNNING_LIKE.has(status)) return true;
    const started = await startZapret();
    return Boolean(started && started.ok);
  }

  /**
   * «Подключить Telegram»: если прокси выключен — сначала включаем его (или ждём уже начатое включение),
   * иначе Telegram получит ссылку на неработающий адрес. null от включения — человек отказался в окне
   * (или прокси как раз выключают): открывать Telegram не к чему.
   */
  async function connectTelegram(buttonCtl) {
    if (buttonCtl) buttonCtl.setBusy(true);
    try {
      const state = Lz.store.state;
      const status = state && state.tg ? state.tg.status : 'stopped';
      if (!RUNNING_LIKE.has(status)) {
        const started = await startTelegram();
        if (!started || !started.ok) return;
      }
      await Lz.api.run({
        method: 'tg_open_in_telegram',
        success: 'Открываем Telegram — подтвердите подключение к прокси в его окне.',
      });
    } finally {
      if (buttonCtl) buttonCtl.setBusy(false);
    }
  }

  function copyLink() {
    return Lz.api.run({
      method: 'tg_copy_link',
      success: 'Ссылка скопирована. Откройте её в Telegram, чтобы подключиться.',
    });
  }

  function copyText(text, what) {
    return Lz.api.run({
      method: 'copy_text',
      args: [String(text == null ? '' : text)],
      key: 'copy_text',
      success: what ? `Скопировано: ${what.toLowerCase()}` : 'Скопировано',
    });
  }

  function openUrl(url) {
    return Lz.api.run({ method: 'open_url', args: [url], key: 'open_url' });
  }

  function openPath(kind) {
    return Lz.api.run({ method: 'open_path', args: [kind], key: `open_path:${kind}` });
  }

  Lz.actions = {
    POWER_KEY,
    startZapret,
    startTelegram,
    toggleZapret,
    toggleTelegram,
    setStrategy,
    useStrategy,
    connectTelegram,
    copyLink,
    copyText,
    openUrl,
    openPath,
  };
})(window.Lz);
