'use strict';
/*
 * Знак Лазейки: стена с проёмом посередине и стрелка, проходящая сквозь проём.
 * tile() — плитка как у значка приложения (тот же рисунок, что в logo.svg);
 * mark() — те же фигуры без плитки, цветом текста, чтобы подходить к обеим темам.
 */
(function (Lz) {
  const { s } = Lz.dom;

  const TILE_COLOR = '#232529';
  const WALL_COLOR = '#7D818A';
  const ARROW_COLOR = '#F2F3F5';
  const WALL_OPACITY_IN_MARK = 0.45;
  /* Фигуры занимают область ~8..56 из 64 — для знака без плитки обрезаем поля. */
  const MARK_VIEWBOX = '7 7 50 50';

  function shapes(wallAttrs, arrowAttrs) {
    return [
      s('rect', { x: 24.84, y: 8.32, width: 6.88, height: 15.8, rx: 3.44, ...wallAttrs }),
      s('rect', { x: 24.84, y: 39.49, width: 6.88, height: 15.97, rx: 3.44, ...wallAttrs }),
      s('rect', { x: 9.47, y: 28.09, width: 35.5, height: 7.38, rx: 3.69, ...arrowAttrs }),
      s('path', { d: 'M54.42 31.75 L43.73 23.52 L43.73 39.99 Z', ...arrowAttrs }),
    ];
  }

  function tile(size) {
    return s('svg', {
      class: 'brand-tile',
      width: size,
      height: size,
      viewBox: '0 0 64 64',
      'aria-hidden': 'true',
      focusable: 'false',
    },
    s('rect', { width: 64, height: 64, rx: 14, fill: TILE_COLOR }),
    shapes({ fill: WALL_COLOR }, { fill: ARROW_COLOR }));
  }

  function mark(size) {
    return s('svg', {
      class: 'brand-mark',
      width: size,
      height: size,
      viewBox: MARK_VIEWBOX,
      'aria-hidden': 'true',
      focusable: 'false',
    }, shapes({ fill: 'currentColor', 'fill-opacity': WALL_OPACITY_IN_MARK }, { fill: 'currentColor' }));
  }

  Lz.brand = { tile, mark };
})(window.Lz);
