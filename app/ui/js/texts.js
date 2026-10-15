'use strict';
/* Человеческие названия режимов, результатов и состояний — общие для главной и подробных страниц. */
(function (Lz) {
  const GAME_FILTER = {
    disabled: { label: 'Выключен', chip: 'Игры: выключено' },
    all: { label: 'TCP и UDP', chip: 'Игры: TCP и UDP' },
    tcp: { label: 'Только TCP', chip: 'Игры: TCP' },
    udp: { label: 'Только UDP', chip: 'Игры: UDP' },
  };

  const IPSET = {
    none: {
      label: 'Не использовать',
      chip: 'IP-список выключен',
      text: 'Обход работает только для сайтов из списков доменов. Самый аккуратный режим — подходит почти всем.',
    },
    loaded: {
      label: 'По списку',
      chip: 'IP-список включён',
      text: 'Дополнительно обходим подсети из списка IP — нужно для игр и сервисов за Cloudflare, у которых нет понятного домена.',
    },
    any: {
      label: 'Все адреса',
      chip: 'Все IP-адреса',
      text: 'Обходим трафик к любым IP-адресам. Включайте, только если другие режимы не помогли: могут замедлиться посторонние сайты.',
    },
  };

  /* Результаты проверки сайта при подборе стратегии. */
  const CHECK_RESULT = {
    ok: 'работает',
    fail: 'не открывается',
    unsup: 'не поддерживается',
    ssl: 'подмена сертификата',
    none: 'не проверялось',
  };

  const CORE_KIND = {
    bundled: 'встроенное ядро',
    updated: 'обновлённое ядро',
  };

  function gameFilter(mode) {
    return GAME_FILTER[mode] || GAME_FILTER.disabled;
  }

  function ipset(mode) {
    return IPSET[mode] || IPSET.none;
  }

  function strategyLabel(zapret, id) {
    if (!id) return '';
    const list = (zapret && Array.isArray(zapret.strategies)) ? zapret.strategies : [];
    const found = list.find((item) => item.id === id);
    return found && found.label ? found.label : id;
  }

  const BEST_MARK = '★ лучшая';

  /**
   * Оценка стратегии по последнему подбору: лучшая ли она и какая доля проверок прошла
   * (score — null, если стратегию не проверяли). Ядро без поля best (до версии 1.1)
   * отмечает лучшую только в результатах текущего подбора.
   */
  function strategyRating(zapret, id) {
    const source = zapret || {};
    const bestId = 'best' in source
      ? (source.best && source.best.id) || null
      : (source.test && source.test.best) || null;
    const scores = source.scores && typeof source.scores === 'object' ? source.scores : {};
    const raw = Object.prototype.hasOwnProperty.call(scores, id) ? Number(scores[id]) : NaN;
    return { best: Boolean(id) && id === bestId, score: Number.isFinite(raw) ? raw : null };
  }

  /** Подпись в выпадающем списке стратегий: «ALT2 · 97 % · ★ лучшая»; непроверенные — просто имя. */
  function strategyChoiceLabel(zapret, item) {
    const rating = strategyRating(zapret, item.id);
    const parts = [item.label || item.id];
    if (rating.score !== null) parts.push(Lz.fmt.percent(rating.score));
    if (rating.best) parts.push(BEST_MARK);
    return parts.join(' · ');
  }

  /**
   * Строка о подключении Telegram к прокси: { tone, text }. Подсказку ядра (tg.client.hint)
   * показываем, пока Telegram не подключён; соединения считаем по живой статистике —
   * она свежее, чем tg.client, который ядро обновляет раз в несколько секунд.
   */
  function telegramConnection(tg) {
    const source = tg || {};
    const client = source.client || {};
    const active = Number(source.stats && source.stats.active) || 0;
    if (source.status === 'error') return { tone: 'err', text: 'Прокси не работает' };
    if (source.status !== 'running') return { tone: 'off', text: 'Прокси выключен' };
    if (client.connected || active > 0) {
      const count = active > 0 ? ` · ${Lz.fmt.count(active, 'соединение', 'соединения', 'соединений')}` : '';
      return { tone: 'ok', text: `Telegram подключён${count}` };
    }
    if (client.hint) {
      return { tone: client.stale_key || client.telegram_running ? 'warn' : 'off', text: String(client.hint) };
    }
    return { tone: 'off', text: 'Ждём, когда Telegram подключится' };
  }

  /** Строка сторожа под проверкой доступности; пустая, если сторож выключен или ещё не проверял. */
  function watchdogLine(watchdog) {
    const source = watchdog || {};
    if (!source.mode || source.mode === 'off' || !source.last_at) return '';
    if (source.vpn) return 'Сторож молчит: трафик идёт через VPN';
    const failing = Array.isArray(source.failing) ? source.failing.filter(Boolean).map(String) : [];
    if (failing.length) {
      return `Сторож: ${failing.join(' и ')} ${failing.length > 1 ? 'не открываются' : 'не открывается'}`;
    }
    return `Сторож проверил ${Lz.fmt.relative(source.last_at)}`;
  }

  Lz.texts = {
    GAME_FILTER,
    IPSET,
    CHECK_RESULT,
    CORE_KIND,
    BEST_MARK,
    gameFilter,
    ipset,
    strategyLabel,
    strategyRating,
    strategyChoiceLabel,
    telegramConnection,
    watchdogLine,
  };
})(window.Lz);
