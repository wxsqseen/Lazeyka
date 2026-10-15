'use strict';
/* «Помощь» → DNS: подменяет ли провайдер адреса сайтов и как включить DNS через HTTPS в Windows 11. */
(function (Lz) {
  const { h, icon } = Lz.dom;
  const ui = Lz.ui;
  const fmt = Lz.fmt;

  const DOH_STEPS = [
    'Параметры → Сеть и Интернет → ваше подключение (Wi-Fi или Ethernet).',
    'Назначение DNS-сервера → Изменить → Вручную, включите IPv4: 1.1.1.1 и 8.8.8.8.',
    'Шифрование DNS — «Только зашифрованный (DNS поверх HTTPS)», затем «Сохранить».',
  ];

  function messageTone(data) {
    if (data.spoofed.length) return 'warn';
    return data.doh_enabled ? 'ok' : 'info';
  }

  function providerChip(provider) {
    const name = String(provider.name || provider.id || 'DNS');
    const ms = Number(provider.ms);
    let state = 'недоступен';
    if (provider.ok) state = provider.ms != null && Number.isFinite(ms) ? `${fmt.integer(ms)}${fmt.NBSP}мс` : 'доступен';
    return ui.chip({
      icon: provider.ok ? 'check' : 'x',
      tone: provider.ok ? 'ok' : 'err',
      text: `${name} · ${state}`,
      title: provider.ip ? `${name}, ${provider.ip}` : null,
    });
  }

  function chipsRow(label, chips) {
    return h('div', { class: 'dns-row' },
      h('span', { class: 'dns-row__label', text: label }),
      h('div', { class: 'chips' }, chips));
  }

  function renderResult(data) {
    if (data.running) {
      return h('p', { class: 'muted' }, h('span', { class: 'spinner spinner--inline', 'aria-hidden': 'true' }),
        'Сравниваем ответы DNS провайдера с защищённым DNS…');
    }
    if (!data.at) return null;
    return [
      ui.callout({ tone: messageTone(data), text: data.message || 'Проверка закончена.' }),
      data.spoofed.length ? chipsRow('Подменяются', data.spoofed.map((domain) => ui.chip({ icon: 'x', tone: 'err', text: domain }))) : null,
      data.providers.length ? chipsRow('DNS через HTTPS', data.providers.map(providerChip)) : null,
      data.ago ? h('p', { class: 'muted small', text: `Проверено ${data.ago}` }) : null,
    ];
  }

  function createDns() {
    const checkBtn = ui.button({
      label: 'Проверить DNS',
      icon: 'search',
      busyKey: 'dns_check',
      onClick: () => Lz.api.run({ method: 'dns_check' }),
    });
    const result = ui.slot(renderResult, { cls: 'dns-result' });
    const openSettings = ui.actionButton({
      method: 'dns_open_settings',
      label: 'Открыть параметры сети Windows',
      icon: 'external',
      size: 'sm',
    });
    const steps = h('ol', { class: 'steps' }, DOH_STEPS.map((text, index) => h('li', { class: 'steps__item' },
      h('span', { class: 'step-badge', text: String(index + 1) }),
      h('span', { text }))));

    const card = ui.card({
      title: 'DNS',
      subtitle: 'Провайдер может подменять адреса сайтов — тогда обход не поможет. Защита от этого — DNS через HTTPS.',
    });
    card.body.append(
      h('div', { class: 'action-row' },
        h('div', { class: 'action-row__text' },
          h('p', { class: 'action-row__desc dns__intro', text: 'Сравним ответы DNS провайдера с ответами защищённого DNS и проверим, доступны ли Cloudflare, Google и Quad9.' })),
        checkBtn.el),
      result.el,
      h('div', { class: 'divider', 'aria-hidden': 'true' }),
      h('div', { class: 'subsection' },
        h('h3', { class: 'subsection__title' }, icon('shieldCheck', { size: 18 }), 'Как включить DNS через HTTPS в Windows 11'),
        steps,
        h('div', { class: 'subsection__foot' }, openSettings.el)));

    return {
      el: card.el,
      update(state) {
        const dns = state.dns || {};
        checkBtn.setBusy(Boolean(dns.running));
        result.update({
          running: Boolean(dns.running),
          at: dns.at || null,
          ago: fmt.relative(dns.at),
          doh_enabled: Boolean(dns.doh_enabled),
          spoofed: Array.isArray(dns.spoofed) ? dns.spoofed.map(String) : [],
          providers: Array.isArray(dns.providers) ? dns.providers : [],
          message: dns.message ? String(dns.message) : '',
        });
      },
    };
  }

  Lz.helpSections = Object.assign(Lz.helpSections || {}, { createDns });
})(window.Lz);
