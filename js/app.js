/* ============================================================
   SecLab · app.js
   Hash router and home view.
   ============================================================ */

const SLApp = (() => {
  'use strict';
  const { h, icon } = SL;

  const TOOLS = [
    {
      href: '#/payload', name: 'Decoder', icon: 'code', key: 'D',
      line: 'Peel encoded payloads layer by layer.',
      points: ['URL, Base64, Base32, hex, HTML entities, JS escapes, JWT, gzip', 'X-ray any payload into its working parts', 'Injection contexts and why payloads fail']
    },
    {
      href: '#/asm', name: 'Assembly annotator', icon: 'cpu', key: 'A',
      line: 'Paste objdump or gdb output, get every line explained.',
      points: ['x86, x86-64 and ARM64, Intel or AT&T', 'Canaries, syscalls, unsafe calls, ROP gadgets', 'Calling conventions and frame sizes']
    },
    {
      href: '#/linux', name: 'Linux error reference', icon: 'terminal', key: 'L',
      line: 'Paste an error, learn what it means and how to fix it.',
      points: ['60 common errors with diagnosis commands', 'Scanner for whole blocks of terminal output', 'errno, signals and exit codes decoded']
    }
  ];

  function home() {
    return h('div', { class: 'view home' },
      h('section', { class: 'home-hero' },
        h('div', { class: 'eyebrow' }, 'Security field kit'),
        h('h1', { class: 'display h1' }, 'Understand it, then exploit it'),
        h('p', { class: 'lead' }, 'Three reference tools that explain the why behind payloads, binaries and Linux errors. Paste something in and learn from the breakdown. Nothing leaves your browser.')),
      h('div', { class: 'home-tools' },
        TOOLS.map(t => h('a', { class: 'home-tool card hover', href: t.href },
          h('div', { class: 'ht-top' }, h('span', { class: 'ht-icon' }, icon(t.icon, 20)), h('span', { class: 'ht-key mono' }, t.key)),
          h('h2', {}, t.name),
          h('p', { class: 'dim' }, t.line),
          h('ul', {}, t.points.map(p => h('li', {}, p))),
          h('span', { class: 'ht-go' }, 'Open ', icon('chevron-right', 14))))),
      h('p', { class: 'muted small home-note' }, 'Practice what you learn here in ', h('a', { href: CF.hrefFor(CF.SUITE[2]) }, 'HackGrid'), ', then hunt real programs with ', h('a', { href: CF.hrefFor(CF.SUITE[0]) }, 'BountyFlow'), '.'));
  }

  function route() {
    const hash = location.hash || '#/';
    const main = document.getElementById('main');
    window.scrollTo(0, 0);
    main.innerHTML = '';
    const base = '#/' + (hash.replace(/^#\/?/, '').split('/')[0] || '');
    document.querySelectorAll('.cf-nav a').forEach(a => a.classList.toggle('active', a.getAttribute('href') === base));

    let view;
    if (hash.startsWith('#/asm')) view = SLAsm.view();
    else if (hash.startsWith('#/linux')) view = SLErrors.view();
    else if (hash.startsWith('#/payload')) view = SLPayload.view();
    else view = home();
    main.append(view);
  }

  function init() {
    CF.initChrome('seclab');
    window.addEventListener('hashchange', route);
    // keyboard shortcuts on the home page: D, A, L
    document.addEventListener('keydown', e => {
      if ((location.hash || '#/') !== '#/' || e.ctrlKey || e.metaKey || e.altKey || /input|textarea|select/i.test(e.target.tagName)) return;
      const t = TOOLS.find(x => x.key.toLowerCase() === e.key.toLowerCase());
      if (t) location.hash = t.href;
    });
    route();
  }

  return { init };
})();

document.addEventListener('DOMContentLoaded', SLApp.init);
