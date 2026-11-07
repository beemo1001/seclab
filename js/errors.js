/* ============================================================
   SecLab · errors.js
   The Linux Error Reference view: paste an error, get the
   explanation, the diagnosis commands and the real fix.
   Includes errno / signal / exit-code tables and a decoder.
   ============================================================ */

const SLErrors = (() => {
  'use strict';
  const { h, icon } = SL;

  const state = { tab: 'errors', q: '', cat: 'all', open: new Set() };

  /* ---------------- search ---------------- */
  const norm = s => String(s || '')
    .toLowerCase()
    .replace(/\/[^\s'"`]*/g, ' ')                    // paths
    .replace(/https?:\/\/\S+/g, ' ')
    .replace(/"[^"]*"/g, ' ')
    .replace(/'[^']*'/g, ' ')
    .replace(/\b\d{1,3}(\.\d{1,3}){3}\b/g, ' ')      // IPs
    .replace(/[<>()[\]{}|&;$`!?:.,\\]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();

  const bigrams = s => {
    const out = new Set();
    const t = s.replace(/\s+/g, '');
    for (let i = 0; i < t.length - 1; i++) out.add(t.slice(i, i + 2));
    return out;
  };

  function scoreEntry(e, qNorm, qTokens, qBigrams, qRaw) {
    let score = 0;
    const hay = norm(e.err + ' ' + (e.aka || []).join(' '));
    const full = norm(e.err + ' ' + (e.aka || []).join(' ') + ' ' + e.meaning + ' ' + (e.causes || []).join(' '));
    // core phrase: the error name without parenthetical examples
    const eCore = norm(String(e.err).replace(/\(.*?\)/g, ''));

    // trigger phrases match the raw text (before path stripping)
    if (qRaw && e.trig && e.trig.some(t => qRaw.includes(t))) score += 90;

    if (qNorm && hay.includes(qNorm)) score += 100;
    if (qNorm && full.includes(qNorm)) score += 40;
    // containment of the core phrase: full weight only when the phrase is
    // distinctive. Generic phrases shared by several entries ("no such file
    // or directory", "permission denied") get a small bonus so specific
    // entries can win on their own signals.
    if (eCore.length >= 6 && qNorm.includes(eCore)) score += (CORE_COUNT[eCore] > 1 ? 25 : 80);

    // token overlap
    let hits = 0;
    for (const t of qTokens) {
      if (t.length < 3) continue;
      if (hay.split(' ').includes(t)) hits += 4;
      else if (full.includes(t)) hits += 1;
    }
    score += hits;

    // leading-token agreement: compiler prefixes like "fatal error:" line up
    const eLead = eCore.split(' ').slice(0, 4);
    const qLead = qNorm.split(' ').slice(0, 4);
    let lead = 0;
    for (let i = 0; i < Math.min(eLead.length, qLead.length); i++) if (eLead[i] === qLead[i] && eLead[i].length >= 3) lead++;
    if (lead >= 3) score += 35; else if (lead === 2) score += 15;

    // typo tolerance via shared bigrams against the error name
    const eB = bigrams(hay.split(' ').slice(0, 8).join(' '));
    let shared = 0;
    for (const b of qBigrams) if (eB.has(b)) shared++;
    if (qBigrams.size && shared / qBigrams.size > 0.55) score += 25;

    // numeric signals: errno / exit codes, only when the query is short
    // or explicitly about them (long pasted output contains random numbers)
    const numericish = qTokens.length <= 3;
    const wantsErrno = /errno/.test(qNorm) || numericish;
    const wantsExit = /exit|code|status/.test(qNorm) || numericish;
    for (const t of qTokens) {
      const n = parseInt(t, 10);
      if (!isNaN(n) && String(n) === t) {
        if (e.errno === n && wantsErrno) score += 70;
        if (n >= 128 && n <= 255 && wantsExit) {
          const sig = n - 128;
          if (e.id === 'sigkill-oom' && sig === 9) score += 60;
          if (e.id === 'sigterm' && sig === 15) score += 60;
          if (e.id === 'segfault' && sig === 11) score += 60;
          if (e.id === 'sigill' && sig === 4) score += 60;
          if (e.id === 'sigbus' && sig === 7) score += 60;
          if (e.id === 'sigfpe' && sig === 8) score += 60;
        }
      }
    }
    // category words
    if (state.cat !== 'all' && e.cat === state.cat) score += 15;
    return score;
  }

  // how many entries share each core phrase (for graded containment)
  const CORE_COUNT = {};
  ERRDB.ERRORS.forEach(e => {
    const c = norm(String(e.err).replace(/\(.*?\)/g, ''));
    CORE_COUNT[c] = (CORE_COUNT[c] || 0) + 1;
  });

  function search(q) {
    const qNorm = norm(q);
    if (!qNorm) return [];
    const qTokens = qNorm.split(' ');
    const qB = bigrams(qNorm);
    return ERRDB.ERRORS
      .map(e => ({ e, s: scoreEntry(e, qNorm, qTokens, qB, String(q).toLowerCase()) }))
      .filter(x => x.s >= 12)
      .sort((a, b) => b.s - a.s)
      .map(x => x.e);
  }

  // scan pasted terminal output for every recognized error
  function scanOutput(text) {
    const found = new Map();
    for (const line of text.split(/\r?\n/)) {
      if (line.trim().length < 8) continue;
      const qNorm = norm(line);
      if (!qNorm) continue;
      const qTokens = qNorm.split(' ');
      const qB = bigrams(qNorm.slice(0, 90));
      const hits = ERRDB.ERRORS
        .map(e => ({ e, s: scoreEntry(e, qNorm, qTokens, qB, line.toLowerCase()) }))
        .filter(x => x.s >= 32)
        .sort((a, b) => b.s - a.s);
      if (hits.length && !found.has(hits[0].e.id)) found.set(hits[0].e.id, { e: hits[0].e, line: line.trim().slice(0, 160) });
    }
    return [...found.values()];
  }

  /* ---------------- rendering ---------------- */
  function cmdBlock(c) {
    return h('div', {},
      h('div', { class: 'cmd-line' },
        h('span', { class: 'cmd-text' }, c.cmd),
        SL.copyBtn(c.cmd)),
      c.why ? h('div', { class: 'cmd-why' }, c.why) : null);
  }

  function entryCard(entry) {
    const cat = ERRDB.CATS.find(c => c.id === entry.cat);
    const open = state.open.has(entry.id);
    const rel = (entry.related || []).map(id => ERRDB.ERRORS.find(x => x.id === id)).filter(Boolean);
    return h('div', { class: 'card err-card' + (open ? ' open' : '') },
      h('div', {
        class: 'err-head', onclick: () => {
          if (state.open.has(entry.id)) state.open.delete(entry.id); else state.open.add(entry.id);
          render();
        }
      },
        h('span', { class: 'err-name' }, entry.err),
        h('span', { class: 'badges' },
          entry.errno ? h('span', { class: 'badge blue mono' }, 'errno ' + entry.errno) : null,
          h('span', { class: 'badge' }, cat ? cat.name : entry.cat)),
        icon('chevron-down', 15, 'err-chev')),
      h('div', { class: 'err-meaning' }, entry.meaning),
      h('div', { class: 'err-body' },
        h('div', {},
          h('div', { class: 'err-sec-title' }, icon('search', 13), 'Why it happens'),
          h('div', { class: 'err-list' }, entry.causes.map((c, i) => h('div', {}, h('span', { class: 'num' }, String(i + 1).padStart(2, '0')), c)))),
        h('div', {},
          h('div', { class: 'err-sec-title' }, icon('stethoscope', 13), 'Diagnose it yourself'),
          entry.diagnose.map(cmdBlock)),
        h('div', {},
          h('div', { class: 'err-sec-title' }, icon('wrench', 13), 'The fix'),
          h('div', { class: 'err-list' }, entry.fix.map((f, i) => h('div', {}, h('span', { class: 'num' }, String(i + 1).padStart(2, '0')), f)))),
        h('div', {},
          h('div', { class: 'err-sec-title' }, icon('shield-check', 13), 'Prevention'),
          h('div', { class: 'err-list' }, h('div', {}, entry.prevent))),
        rel.length ? h('div', {},
          h('div', { class: 'err-sec-title' }, icon('link', 13), 'Related errors'),
          h('div', { class: 'chips-wrap' }, rel.map(r =>
            h('button', {
              class: 'chip clickable mono', onclick: ev => {
                ev.stopPropagation();
                state.open.add(r.id);
                state.q = '';
                render();
                const el = document.getElementById('err-' + r.id);
                if (el) el.scrollIntoView({ behavior: 'smooth', block: 'center' });
              }
            }, r.err)))) : null,
        h('div', { class: 'pb-expect' }, icon('brain', 14), h('span', {}, entry.tip))));
  }

  function tableTab(title, iconName, cols, rows, decodeHint) {
    return h('div', { class: 'card', style: 'overflow:hidden' },
      h('div', { class: 'panel-head', style: 'padding:14px 16px 4px' },
        h('span', { class: 'panel-title' }, icon(iconName, 14), title),
        h('span', { class: 'tab-info' }, rows.length + ' rows')),
      decodeHint || null,
      h('div', { class: 'scroll-y' },
        h('table', { class: 'ref-table' },
          h('thead', {}, h('tr', {}, cols.map(c => h('th', {}, c)))),
          h('tbody', {}, rows.map(r => h('tr', {},
            h('td', { class: 'mono' }, r[0]), h('td', { class: 'mono' }, r[1]), h('td', {}, r[2])))))));
  }

  function exitDecoder() {
    const inp = h('input', {
      class: 'input', type: 'text', placeholder: 'e.g. 137',
      style: 'max-width:220px'
    });
    const out = h('div', { class: 'empty-note' }, 'Exit codes above 128 mean the process was killed by signal (code minus 128). Try 130, 137 or 143.');
    const decode = () => {
      out.innerHTML = '';
      const v = parseInt(inp.value, 10);
      if (isNaN(v) || v < 0 || v > 255) { out.append('Enter a number between 0 and 255.'); return; }
      if (v === 0) out.append(h('span', { class: 'why-green', style: 'color:var(--green-2)' }, '0: success, the command did its job.'));
      else if (v === 1) out.append('1: general failure (read the error message above it).');
      else if (v === 2) out.append('2: misuse of a shell builtin, often a bad option.');
      else if (v === 126) out.append('126: found but not executable. Check the execute bit (chmod +x) and the format (file ./program).');
      else if (v === 127) out.append('127: command not found. The PATH search came up empty.');
      else if (v > 128) {
        const sig = v - 128;
        const row = ERRDB.SIGNALS.find(s => s[0] === sig);
        out.append(
          h('span', {}, v + ' = 128 + ' + sig + ': killed by signal ' + (row ? row[1] : sig) + '. '),
          h('span', { style: 'color:var(--amber)' }, row ? row[2] : 'Unknown signal number.'));
      }
      else out.append(v + ': a program-specific code. Read the tool\'s docs (many use 2, 3, 4 for specific failures).');
    };
    inp.addEventListener('input', decode);
    return h('div', { class: 'cmd-line', style: 'margin:12px 16px; background:var(--bg-2)' },
      h('span', { class: 'dim small', style: 'white-space:nowrap' }, 'Decode exit code:'),
      inp,
      out);
  }

  /* ---------------- main render ---------------- */
  let rootEl = null;

  function render() {
    if (!rootEl) return;
    const main = rootEl.querySelector('#errMain');
    if (!main) return;
    main.innerHTML = '';

    if (state.tab === 'errno') {
      main.append(tableTab('errno reference (Linux)', 'binary', ['#', 'Name', 'Meaning'], ERRDB.ERRNO));
      return;
    }
    if (state.tab === 'signals') {
      main.append(tableTab('Signals', 'activity', ['#', 'Name', 'What it means'], ERRDB.SIGNALS));
      return;
    }
    if (state.tab === 'exit') {
      main.append(tableTab('Exit codes', 'flag', ['Code', 'Name', 'Meaning'], ERRDB.EXITCODES, exitDecoder()));
      return;
    }

    // errors tab
    const searchInput = h('textarea', {
      class: 'input search-input', id: 'errSearch', rows: 2, spellcheck: false,
      placeholder: 'Paste the exact error text (or a whole chunk of terminal output)...',
      oninput: SL.debounce(ev => { state.q = ev.target.value; render(); }, 250)
    });
    searchInput.value = state.q;
    const searchWrap = h('div', { class: 'card card-pad', style: 'margin-bottom:14px' },
      h('div', { class: 'search-wrap' },
        h('span', { class: 'search-ic' }, icon('search', 15)),
        searchInput),
      h('p', { class: 'hint' },
        'Search understands full messages, fragments, exit codes (137) and errno numbers (13). Paste a block of output and it scans every line for recognized errors.'));

    // category rail
    const catRail = h('div', { class: 'cat-rail' },
      ERRDB.CATS.map(c => {
        const n = ERRDB.ERRORS.filter(e => e.cat === c.id).length;
        return h('button', {
          class: 'cat-link' + (state.cat === c.id ? ' active' : ''),
          onclick: () => { state.cat = state.cat === c.id ? 'all' : c.id; render(); }
        }, icon(c.icon, 14), c.name, h('span', { class: 'cat-n' }, n));
      }),
      h('button', {
        class: 'cat-link' + (state.cat === 'all' ? ' active' : ''),
        onclick: () => { state.cat = 'all'; render(); }
      }, icon('grid', 14), 'All categories', h('span', { class: 'cat-n' }, ERRDB.ERRORS.length)));

    const content = h('div', {});
    const q = state.q.trim();

    if (q) {
      // multi-line paste: scan
      if (q.includes('\n') || q.length > 90) {
        const hits = scanOutput(q);
        content.append(h('div', { class: 'result-meta' },
          'Scanned your output: ',
          h('span', { class: 'result-count' }, hits.length + ' error' + (hits.length === 1 ? '' : 's') + ' recognized'),
          hits.length ? '' : '. Nothing matched: try pasting just the error line.'));
        hits.forEach(hit => {
          content.append(h('p', { class: 'small dim mono', style: 'margin:6px 0 0 2px' }, 'matched: ' + hit.line));
          content.append(entryCard(hit.e));
          state.open.add(hit.e.id);
        });
        if (!hits.length) content.append(h('div', { class: 'empty-note' }, 'Tip: the scanner matches known error phrases. Copy the exact failing line (usually the one with "error" or "denied") and search again.'));
      } else {
        const results = search(q);
        if (results.length) {
          results.slice(0, 8).forEach((e, i) => {
            if (i === 0) state.open.add(e.id);   // auto-expand the best match
            const card = entryCard(e);
            card.id = 'err-' + e.id;
            content.append(card);
          });
        } else {
          const cat = state.cat === 'all' ? '' : ' in this category';
          content.append(h('div', { class: 'card card-pad empty-state' },
            h('div', { class: 'big-icon' }, icon('search', 24)),
            h('h3', {}, 'No match' + cat),
            h('p', { class: 'dim' }, 'Try fewer words: the core message only ("connection refused", "unable to locate"). Numbers like errno or exit codes work too. Or browse the categories on the left.')));
        }
      }
    } else {
      const list = state.cat === 'all' ? ERRDB.ERRORS : ERRDB.ERRORS.filter(e => e.cat === state.cat);
      content.append(h('div', { class: 'result-meta' },
        h('span', { class: 'result-count' }, list.length + ' errors'),
        state.cat !== 'all' ? h('span', { class: 'result-filters' }, 'in ' + (ERRDB.CATS.find(c => c.id === state.cat) || {}).name) : '',
        h('span', { class: 'result-filters' }, 'click any card to expand the full diagnosis')));
      list.forEach(e => { const c = entryCard(e); c.id = 'err-' + e.id; content.append(c); });
    }

    main.append(searchWrap, h('div', { class: 'err-layout' }, catRail, content));

    // keep focus in the search box after re-render
    const inp = main.querySelector('#errSearch');
    if (inp && state.q) { inp.focus(); const L = inp.value.length; inp.setSelectionRange(L, L); }
  }

  function view() {
    const tabs = [['errors', 'Errors', 'alert'], ['errno', 'errno table', 'binary'], ['signals', 'Signals', 'activity'], ['exit', 'Exit codes', 'flag']];
    rootEl = h('div', { class: 'view' },
      SL.sectionTitle('terminal', 'Linux error reference'),
      h('p', { class: 'section-sub' },
        'Paste an error message, an exit code like 137 or a whole block of terminal output. Each match explains what it means, how to diagnose it yourself and how to fix it.'),
      h('div', { class: 'tab-row' },
        tabs.map(([id, label, ic]) => h('button', {
          class: 'tab' + (state.tab === id ? ' active' : ''),
          onclick: () => { state.tab = id; render(); }
        }, icon(ic, 13), label))),
      h('div', { id: 'errMain' }));
    render();
    return rootEl;
  }

  return { view, _search: search, _scan: scanOutput, _norm: norm };
})();
