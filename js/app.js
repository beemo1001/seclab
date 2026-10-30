/* ============================================================
   SecLab · app.js
   Boot screen, hash router, home view.
   ============================================================ */

const SLApp = (() => {
  'use strict';
  const { h, icon } = SL;

  /* ---------- boot screen (instant: no network work here) ---------- */
  const MARK_SVG = `
    <g class="mark-sweep">
      <circle cx="24" cy="24" r="20" fill="none" stroke="#dce5f4" stroke-width="2.8" stroke-linecap="round" stroke-dasharray="103.67 12.57"/>
      <path d="M33.1 6.2A20 20 0 0 1 41.8 14.9" fill="none" stroke="#f43f5e" stroke-width="3.4" stroke-linecap="round"/>
    </g>
    <path d="M18 18.5 23.5 24 18 29.5" fill="none" stroke="#dce5f4" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
    <path d="M27 19.5v9" stroke="#dce5f4" stroke-width="2.5" stroke-linecap="round"/>`;

  function boot() {
    const wrap = h('div', { class: 'boot' });
    wrap.innerHTML = `
      <div class="boot-inner">
        <svg viewBox="0 0 48 48" class="boot-mark" aria-hidden="true">${MARK_SVG}</svg>
        <div class="boot-word">Sec<em>Lab</em></div>
        <div class="boot-tag">the student security field kit</div>
        <div class="boot-bar"><div class="boot-fill" id="bootFill" style="width:100%"></div></div>
        <div class="boot-status" id="bootStatus">loading tools...</div>
      </div>`;
    document.body.append(wrap);
    setTimeout(() => wrap.classList.add('done'), 380);
    setTimeout(() => wrap.remove(), 950);
  }

  /* ---------- home view ---------- */
  function home() {
    const tools = [
      {
        href: '#/asm', name: 'Assembly Annotator', icon: 'cpu', tint: '',
        desc: 'Paste assembly from a pwn challenge, objdump or gdb. Every single line gets a plain-English explanation, and the engine extracts what actually matters: stack canaries, syscalls, unsafe library calls, ROP gadgets, PIE addressing and frame sizes.',
        learn: ['x86, x86-64 and ARM64, Intel or AT&T syntax', 'Prologues, epilogues, calling conventions, syscalls', 'Security findings with student next steps']
      },
      {
        href: '#/linux', name: '🐧 Linux Error Reference', icon: 'terminal', tint: 't-green',
        desc: 'Sixty of the errors every Linux user meets, each with the real meaning, the diagnosis commands and the actual fix. Plus the errno, signal and exit-code tables, an exit code decoder, and a scanner that reads a whole block of terminal output.',
        learn: ['Why the error happens, not just how to silence it', 'Diagnosis commands you run yourself, explained', 'errno 1 to 116, signals 1 to 31, exit codes decoded']
      },
      {
        href: '#/payload', name: 'Payload Lab', icon: 'code', tint: 't-red',
        desc: 'Not a cheat sheet. A systematic approach: decode payloads layer by layer, X-ray them into functional elements, learn the grammar of all 11 injection contexts, and follow the 7-step method for reading any web app like a blueprint.',
        learn: ['Layered decoder: URL, base64, hex, entities, JWT, gzip', 'X-ray: every element explained with its bypass variants', 'Why payloads fail: 14 diagnosed failures and their fixes']
      }
    ];

    return h('div', { class: 'view' },
      h('div', { class: 'hero' },
        h('span', { class: 'hero-kicker' }, icon('shield', 13), 'SecLab · student security field kit'),
        h('h1', {}, 'Understand the machine, ', h('em', {}, 'then'), ' exploit the machine.'),
        h('p', {}, 'Three tools that teach you to fish: an assembly annotator that explains every instruction, a Linux error reference that builds your diagnosis instincts, and a payload lab that turns payload lists into systematic methodology. Everything runs in your browser, everything is free, nothing is sent anywhere.'),
        h('div', { class: 'hero-cta' },
          h('a', { class: 'btn primary', href: '#/payload' }, icon('code', 14), 'Start with the Payload Lab'),
          h('a', { class: 'btn', href: '#/asm' }, icon('cpu', 14), 'Annotate assembly'))),
      h('div', { class: 'tool-grid' },
        tools.map(t => h('a', { class: 'card tool-card ' + t.tint, href: t.href },
          h('span', { class: 'tool-icon' }, icon(t.icon, 19)),
          h('span', { class: 'tool-name' }, t.name),
          h('span', { class: 'tool-desc' }, t.desc),
          h('span', { class: 'tool-learn' }, h('b', {}, 'You will learn'), t.learn.map(l => h('span', { class: 'dim', style: 'display:flex;gap:6px' }, icon('check', 11), l))),
          h('span', { class: 'tool-go' }, 'Open the tool ', icon('chevron-right', 13))))),
      h('div', { class: 'card card-pad playbook-card', style: 'margin-top:22px' },
        h('div', { class: 'pb-title' }, icon('brain', 14), 'The philosophy'),
        h('p', { style: 'font-size:13px;color:var(--text-2);line-height:1.7;max-width:840px' },
          'This is not a payload cheat sheet. You will not find strings to blindly throw at forms. It is a systematic approach to understanding web applications, binaries and operating systems at a fundamental level, so you can craft solutions that work in any environment. ',
          h('b', { style: 'color:var(--text)' }, 'Think of it as learning to fish instead of being handed a fish.'),
          ' By the end you can read any web app like a blueprint, understand why payloads fail and fix them, escalate basic findings into serious reports, and adapt to any framework, filter or protection mechanism.'),
        h('p', { class: 'dim', style: 'font-size:12px;margin-top:10px' },
          'Educational tooling. Only test systems you are authorized to test. Stay in scope. Hack ethically.'))
    );
  }

  /* ---------- router ---------- */
  function route() {
    const hash = location.hash || '#/';
    const main = document.getElementById('main');
    if (!main) return;
    window.scrollTo(0, 0);
    main.innerHTML = '';

    document.querySelectorAll('.nav a').forEach(a =>
      a.classList.toggle('active', a.getAttribute('href') === hash.split('/').slice(0, 2).join('/')));

    let view;
    if (hash.startsWith('#/asm')) view = SLAsm.view();
    else if (hash.startsWith('#/linux')) view = SLErrors.view();
    else if (hash.startsWith('#/payload')) view = SLPayload.view();
    else view = home();
    main.append(view);
  }

  function init() {
    boot();
    window.addEventListener('hashchange', route);
    route();
  }

  return { init };
})();

document.addEventListener('DOMContentLoaded', SLApp.init);
