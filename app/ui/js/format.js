'use strict';
/* Человекочитаемые числа, размеры, скорости и время — по-русски. */
(function (Lz) {
  const NBSP = ' ';
  const BYTES_STEP = 1024;
  const BYTE_UNITS = ['Б', 'КБ', 'МБ', 'ГБ', 'ТБ'];
  /* Ниже 10 — всегда один знак после запятой («1,0 МБ/с»), ниже 100 — по необходимости, выше — целые. */
  const FIXED_DECIMAL_BELOW = 10;
  const ONE_DECIMAL_BELOW = 100;
  const JUST_NOW_SEC = 45;
  const MINUTE = 60;
  const HOUR = 3600;
  const DAY = 86400;
  const WEEK_DAYS = 7;

  const integerFormat = new Intl.NumberFormat('ru-RU', { maximumFractionDigits: 0 });
  const decimalFormat = new Intl.NumberFormat('ru-RU', { maximumFractionDigits: 1 });
  const fixedDecimalFormat = new Intl.NumberFormat('ru-RU', { minimumFractionDigits: 1, maximumFractionDigits: 1 });
  const dateFormat = new Intl.DateTimeFormat('ru-RU', { day: 'numeric', month: 'long', year: 'numeric' });
  const clockFormat = new Intl.DateTimeFormat('ru-RU', { hour: '2-digit', minute: '2-digit', second: '2-digit' });

  function toNumber(value) {
    const n = Number(value);
    return Number.isFinite(n) ? n : null;
  }

  /** Русское склонение после числа: plural(5, 'минута', 'минуты', 'минут') → 'минут'. */
  function plural(n, one, few, many) {
    const abs = Math.abs(Math.trunc(n));
    const lastTwo = abs % 100;
    const last = abs % 10;
    if (last === 1 && lastTwo !== 11) return one;
    if (last >= 2 && last <= 4 && (lastTwo < 12 || lastTwo > 14)) return few;
    return many;
  }

  function integer(value) {
    const n = toNumber(value);
    return n === null ? '—' : integerFormat.format(n);
  }

  function count(value, one, few, many) {
    const n = toNumber(value) || 0;
    return `${integerFormat.format(n)}${NBSP}${plural(n, one, few, many)}`;
  }

  function bytes(value) {
    let n = toNumber(value);
    if (n === null || n < 0) return '—';
    let unit = 0;
    while (n >= BYTES_STEP && unit < BYTE_UNITS.length - 1) {
      n /= BYTES_STEP;
      unit += 1;
    }
    let text;
    if (unit === 0 || n >= ONE_DECIMAL_BELOW) text = integerFormat.format(n);
    else if (n < FIXED_DECIMAL_BELOW) text = fixedDecimalFormat.format(n);
    else text = decimalFormat.format(n);
    return `${text}${NBSP}${BYTE_UNITS[unit]}`;
  }

  function rate(value) {
    const text = bytes(value);
    return text === '—' ? text : `${text}/с`;
  }

  function percent(fraction) {
    const n = toNumber(fraction);
    return n === null ? '—' : `${Math.round(n * 100)}${NBSP}%`;
  }

  function nowSeconds() {
    return Date.now() / 1000;
  }

  /** Длительность: «40 с», «12 мин», «1 ч 12 мин», «2 д 3 ч». */
  function duration(seconds) {
    const total = Math.max(0, Math.floor(toNumber(seconds) || 0));
    const days = Math.floor(total / DAY);
    const hours = Math.floor((total % DAY) / HOUR);
    const minutes = Math.floor((total % HOUR) / MINUTE);
    if (days > 0) return `${days}${NBSP}д ${hours}${NBSP}ч`;
    if (hours > 0) return `${hours}${NBSP}ч ${minutes}${NBSP}мин`;
    if (minutes > 0) return `${minutes}${NBSP}мин`;
    return `${total}${NBSP}с`;
  }

  function since(unixSeconds) {
    const start = toNumber(unixSeconds);
    return start === null ? '' : duration(nowSeconds() - start);
  }

  function parseTime(value) {
    if (value == null || value === '') return null;
    if (typeof value === 'number') return new Date(value * 1000);
    const parsed = new Date(String(value));
    return Number.isNaN(parsed.getTime()) ? null : parsed;
  }

  /**
   * «только что», «2 мин назад», «3 ч назад», «вчера», «4 дня назад», дальше — дата. Целые единицы —
   * с округлением вниз: иначе 59,5 минуты стали бы «60 мин назад», а 23,5 часа — «24 ч назад».
   */
  function relative(value) {
    const date = parseTime(value);
    if (!date) return '';
    const diff = Math.max(0, (Date.now() - date.getTime()) / 1000);
    if (diff < JUST_NOW_SEC) return 'только что';
    if (diff < HOUR) return `${Math.max(1, Math.floor(diff / MINUTE))}${NBSP}мин назад`;
    if (diff < DAY) return `${Math.floor(diff / HOUR)}${NBSP}ч назад`;
    const days = Math.floor(diff / DAY);
    if (days === 1) return 'вчера';
    if (days < WEEK_DAYS) return `${days}${NBSP}${plural(days, 'день', 'дня', 'дней')} назад`;
    return dateFormat.format(date);
  }

  function date(value) {
    const parsed = parseTime(value);
    return parsed ? dateFormat.format(parsed) : '';
  }

  function clock(value) {
    const parsed = parseTime(value);
    return parsed ? clockFormat.format(parsed) : '';
  }

  /**
   * Название в ёлочках: «Мой VPN». Если в нём уже есть ёлочки (имя из ядра или от провайдера), внутренние
   * становятся „лапками“ — «Маршруты „Мой VPN“», а не «Маршруты «Мой VPN»».
   */
  function quote(text) {
    return `«${String(text == null ? '' : text).replace(/«/g, '„').replace(/»/g, '“')}»`;
  }

  /** Текст из ядра — законченным предложением: ядро ставит точку в конце не всегда. Пустой — ''. */
  function sentence(text) {
    const value = String(text == null ? '' : text).trim();
    if (!value) return '';
    return /[.!?…]$/.test(value) ? value : `${value}.`;
  }

  Lz.fmt = { NBSP, plural, integer, count, bytes, rate, percent, duration, since, relative, date, clock, nowSeconds, quote, sentence };
})(window.Lz);
