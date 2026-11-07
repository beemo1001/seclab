/* ============================================================
   SecLab · payload.js
   The Payload Lab: layered decoder, payload X-ray, context
   reference, methodology and failure diagnostics.
   Learning to fish, not being handed a fish.
   ============================================================ */

const SLPayload = (() => {
  'use strict';
  const { h, icon } = SL;

  const state = {
    tab: 'decode',
    dec: { input: '', rot13: false, reverse: false, layers: null, final: '', err: null, busy: false },
    xray: { input: '', result: null }
  };

  /* ================= DECODER ENGINE ================= */

  const ENT = {
    lt: '<', gt: '>', amp: '&', quot: '"', apos: "'", nbsp: ' ', copy: '©', reg: '®',
    colon: ':', semi: ';', sol: '/',bsol: '\\', excl: '!', quest: '?', lpar: '(', rpar: ')',
    lbrack: '[', rbrack: ']', lbrace: '{', rbrace: '}', equals: '=', plus: '+', dash: '-',
    hash: '#', commat: '@', dollar: '$', percnt: '%', period: '.', comma: ','
  };

  function bytesToText(bytes) {
    try { return new TextDecoder('utf-8', { fatal: true }).decode(bytes); }
    catch (e) { return new TextDecoder('utf-8').decode(bytes); } // replacement chars show as garbage: caller gates on printability
  }

  function b64ToBytes(s) {
    s = s.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    const bin = atob(s);
    return Uint8Array.from(bin, c => c.charCodeAt(0));
  }

  function b32decode(s) {
    const alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    const clean = s.replace(/=+$/, '').toUpperCase();
    if (!/^[A-Z2-7]+$/.test(clean)) return null;
    let bits = 0, value = 0; const out = [];
    for (const ch of clean) {
      value = (value << 5) | alpha.indexOf(ch); bits += 5;
      if (bits >= 8) { out.push((value >>> (bits - 8)) & 0xff); bits -= 8; }
    }
    return Uint8Array.from(out);
  }

  async function tryGunzip(bytes) {
    if (bytes.length > 2 && bytes[0] === 0x1f && bytes[1] === 0x8b) {
      const out = await inflate(bytes, 'gzip');
      if (out) return { format: 'gzip', bytes: out };
    }
    if (bytes.length > 2 && bytes[0] === 0x78 && [0x01, 0x9c, 0xda, 0x5e].includes(bytes[1])) {
      let out = await inflate(bytes, 'deflate');
      if (out) return { format: 'zlib (deflate)', bytes: out };
      out = await inflate(bytes, 'deflate-raw');
      if (out) return { format: 'raw DEFLATE', bytes: out };
    }
    return null;
  }

  async function inflate(bytes, format) {
    try {
      if (typeof DecompressionStream === 'undefined') return null;
      const ds = new DecompressionStream(format);
      const stream = new Blob([bytes]).stream().pipeThrough(ds);
      const buf = await new Response(stream).arrayBuffer();
      return new Uint8Array(buf);
    } catch (e) { return null; }
  }

  const decodeJsEscapes = s => s.replace(/\\(x[0-9a-fA-F]{2}|u\{[0-9a-fA-F]{1,6}\}|u[0-9a-fA-F]{4}|[0-3][0-7]{1,2}|[nrtbvf'"\\0])/g, (m, g) => {
    if (g[0] === 'x') return String.fromCharCode(parseInt(g.slice(1), 16));
    if (g[0] === 'u') {
      const hex = g[1] === '{' ? g.slice(2, -1) : g.slice(1);
      return String.fromCodePoint(parseInt(hex, 16));
    }
    if (/^[0-7]/.test(g)) return String.fromCharCode(parseInt(g, 8));
    return ({ n: '\n', r: '\r', t: '\t', b: '\b', v: '\v', f: '\f', '0': '\0', "'": "'", '"': '"', '\\': '\\' })[g] || m;
  });

  const decodeEntities = s => s.replace(/&(#x?[0-9a-f]+|[a-z]+);/gi, (m, g) => {
    if (g[0] === '#') {
      const isHex = g[1] === 'x' || g[1] === 'X';
      const code = parseInt(g.slice(isHex ? 2 : 1), isHex ? 16 : 10);
      return Number.isFinite(code) ? String.fromCodePoint(code) : m;
    }
    return ENT[g.toLowerCase()] || m;
  });

  const rot13 = s => s.replace(/[a-z]/gi, c => {
    const base = c <= 'Z' ? 65 : 97;
    return String.fromCharCode((c.charCodeAt(0) - base + 13) % 26 + base);
  });

  async function decodeOnce(cur) {
    const pr = SL.printableRatio;
    // 1. JWT
    const jwtM = /^(eyJ[A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]*)$/.exec(cur.trim());
    if (jwtM) {
      const header = bytesToText(b64ToBytes(jwtM[1]));
      const claims = bytesToText(b64ToBytes(jwtM[2]));
      let pretty = '';
      try { pretty = JSON.stringify(JSON.parse(header), null, 1) + '\n' + JSON.stringify(JSON.parse(claims), null, 1); }
      catch (e) { pretty = header + '\n' + claims; }
      return {
        name: 'JWT (JSON Web Token)', why: 'The eyJ prefix is base64 of {" . Three dot-separated segments: header, claims, signature. The first two decode without any secret: the signature only matters for tampering.',
        to: pretty, printable: true
      };
    }
    // 2. URL encoding
    if (/%[0-9a-f]{2}/i.test(cur)) {
      let out;
      try { out = decodeURIComponent(cur); } catch (e) { out = null; }
      if (out != null && out !== cur && pr(out) > 0.6) {
        return { name: 'URL encoding', why: 'Percent-encoding is legitimate transport syntax for URLs. Attackers layer it so that filters decode once and see nothing, while the application decodes twice and executes.', to: out, printable: true };
      }
    }
    // 3. HTML entities
    if (/&(#x?[0-9a-f]+|[a-z]+);/i.test(cur)) {
      const out = decodeEntities(cur);
      if (out !== cur && pr(out) > 0.6) {
        return { name: 'HTML entity encoding', why: 'Entities are how honest output encoding works. The attack angle: if a filter checks the raw string but the browser decodes entities BEFORE parsing, &lt; becomes < after the gate has closed.', to: out, printable: true };
      }
    }
    // 4. JS escapes
    if (/\\(x[0-9a-fA-F]{2}|u\{?[0-9a-fA-F]{4}\}?|[0-7]{2,3}|[nrt])/i.test(cur)) {
      const out = decodeJsEscapes(cur);
      if (out !== cur && pr(out) > 0.6) {
        return { name: 'JavaScript escape sequences', why: '\\xNN and \\uNNNN build strings at runtime with no filter-triggering words. Common in obfuscated XSS and in deobfuscation work.', to: out, printable: true };
      }
    }
    // 5. charcode arrays
    const ccM = /^\s*(?:String\s*\.\s*fromCharCode\s*\()?\s*((?:\d{1,3}\s*,\s*){3,}\d{1,3})\s*\)?\s*;?\s*$/.exec(cur);
    if (ccM) {
      const nums = ccM[1].split(',').map(n => parseInt(n, 10));
      if (nums.every(n => n >= 9 && n <= 126)) {
        return { name: 'Character codes (fromCharCode style)', why: 'The payload is stored as numbers and assembled at runtime. Filters matching strings see only digits: the string never exists until execution.', to: nums.map(n => String.fromCharCode(n)).join(''), printable: true };
      }
    }
    // 6. hex string
    const hexM = /^(?:0x)?([0-9a-f]{8,})$/i.exec(cur.trim());
    if (hexM && hexM[1].length % 2 === 0) {
      const bytes = Uint8Array.from(hexM[1].match(/../g).map(x => parseInt(x, 16)));
      const gz = await tryGunzip(bytes);
      if (gz) return { name: 'Hex-encoded gzip', why: 'Hex outside, gzip inside: double packaging for transport. Magic bytes 1f 8b give it away.', to: bytesToText(gz.bytes), printable: pr(bytesToText(gz.bytes)) > 0.6 };
      const txt = bytesToText(bytes);
      if (pr(txt) > 0.75) return { name: 'Hex encoding', why: 'Every byte as two hex digits. Used to smuggle payloads through filters that reject special characters but pass letters and digits.', to: txt, printable: true };
    }
    // 7. base32
    if (/^[A-Z2-7]{8,}=*$/.test(cur.trim())) {
      const bytes = b32decode(cur.trim());
      if (bytes) {
        const txt = bytesToText(bytes);
        if (pr(txt) > 0.75) return { name: 'Base32', why: 'Uppercase letters and digits 2 to 7 only. Popular in phishing URLs and DNS exfiltration because it survives case-insensitive systems.', to: txt, printable: true };
      }
    }
    // 8. base64
    const b64M = /^[A-Za-z0-9+/\-_]{12,}={0,2}$/.exec(cur.trim());
    if (b64M) {
      let bytes = null;
      try { bytes = b64ToBytes(cur.trim()); } catch (e) { bytes = null; }
      if (bytes && bytes.length) {
        const gz = await tryGunzip(bytes);
        if (gz) return { name: 'Base64-wrapped gzip', why: 'Compressed then encoded: common in web tokens, cookies and exfil channels. Magic bytes 1f 8b at the start after decoding.', to: bytesToText(gz.bytes), printable: true };
        const txt = bytesToText(bytes);
        if (pr(txt) > 0.75) {
          return { name: 'Base64', why: 'The universal smuggling format: filters and eyes both pass it. Three letters plus digits plus padding hides any payload.', to: txt, printable: true };
        }
      }
    }
    return null;
  }

  async function decodeAll(input) {
    const layers = [];
    let cur = input.trim();
    for (let i = 0; i < 8; i++) {
      const one = await decodeOnce(cur);
      if (!one) break;
      layers.push({ name: one.name, why: one.why, from: cur, to: one.to });
      cur = one.to;
      if (one.printable === false) break;
    }
    // manual transforms
    if (state.dec.reverse && cur.length > 3) {
      const rev = [...cur].reverse().join('');
      layers.push({ name: 'Reversed', why: 'Trivial obfuscation: read it backwards.', from: cur, to: rev });
      cur = rev;
    }
    if (state.dec.rot13 && /[a-z]/i.test(cur)) {
      const r = rot13(cur);
      if (r !== cur) { layers.push({ name: 'ROT13', why: 'The classic letter rotation. Zero security, pure obfuscation: it defeats the eye, not the machine.', from: cur, to: r }); cur = r; }
    }
    return { layers, final: cur };
  }

  /* ================= X-RAY ENGINE ================= */

  function xrayScan(input) {
    const all = [];
    PLDATA.TOKENS.forEach((t, ti) => {
      const re = new RegExp(t.re.source, t.re.flags.includes('g') ? t.re.flags : t.re.flags + 'g');
      let m, guard = 0;
      while ((m = re.exec(input)) && guard++ < 40) {
        all.push({ ti, match: m[0], start: m.index, end: m.index + m[0].length });
        if (m.index === re.lastIndex) re.lastIndex++;
      }
    });
    // non-overlapping pick for highlighting (prefer earlier start, then longer, then token priority)
    all.sort((a, b) => a.start - b.start || (b.end - b.start) - (a.end - a.start) || a.ti - b.ti);
    const spans = []; let lastEnd = -1;
    for (const f of all) { if (f.start >= lastEnd) { spans.push(f); lastEnd = f.end; } }
    // token types matched anywhere (for the cards)
    const types = new Map();
    for (const f of all) {
      if (!types.has(f.ti)) types.set(f.ti, []);
      if (types.get(f.ti).length < 3) types.get(f.ti).push(f.match);
    }
    return { spans, types: [...types.entries()].sort((a, b) => a[0] - b[0]) };
  }

  /* ================= VIEWS ================= */

  function layerTree(layers, final, fromInput) {
    const wrap = h('div', { class: 'layer-tree' });
    layers.forEach((l, i) => {
      wrap.append(
        h('div', { class: 'layer-card' },
          h('div', { class: 'layer-head' },
            h('span', { class: 'layer-n' }, String(i + 1)),
            h('span', { class: 'layer-name' }, l.name),
            h('span', { class: 'layer-why' }, l.why)),
          h('div', { class: 'layer-body' },
            h('div', { class: 'layer-out' }, l.to),
            h('div', { class: 'layer-actions' }, SL.copyBtn(l.to, 'Decoded layer copied')))));
      if (i < layers.length - 1) wrap.append(h('div', { class: 'layer-arrow' }, icon('chevron-down', 13), 'peel again'));
    });
    if (!layers.length) {
      wrap.append(h('div', { class: 'card card-pad empty-state' },
        h('div', { class: 'big-icon' }, icon('search', 24)),
        h('h3', {}, 'No known encoding detected'),
        h('p', { class: 'dim' }, 'This input looks like plain text already. Paste the raw payload into the X-ray tab to analyze what it does, or try the reversed / ROT13 toggles.')));
      return wrap;
    }
    wrap.append(
      h('div', { class: 'layer-arrow' }, icon('check', 13), 'final layer'),
      h('div', { class: 'card card-pad', style: 'border-color:rgba(52,211,153,.35)' },
        h('div', { class: 'panel-head' },
          h('span', { class: 'panel-title' }, icon('flag', 14), 'Final payload'),
          h('span', { style: 'display:flex;gap:8px' },
            SL.copyBtn(final, 'Final payload copied'),
            h('button', {
              class: 'btn small', onclick: () => {
                state.xray.input = final;
                state.tab = 'xray';
                render();
              }
            }, icon('search-code', 13), 'Open in X-ray'))),
        h('div', { class: 'layer-out' }, final)));
    return wrap;
  }

  const CAT_CLASS = { xss: 'hl-xss', cmdi: 'hl-cmdi', sqli: 'hl-sqli', trav: 'hl-trav', ssrf: 'hl-ssrf', ssti: 'hl-ssti', misc: 'hl-misc' };
  const CAT_NAME = { xss: 'XSS / HTML injection', cmdi: 'command injection', sqli: 'SQL injection', trav: 'path traversal', ssrf: 'SSRF', ssti: 'template injection', misc: 'other injection' };

  function xrayResult() {
    const input = state.xray.input;
    if (!input.trim()) return h('div', { class: 'card card-pad empty-state' },
      h('div', { class: 'big-icon' }, icon('search-code', 24)),
      h('h3', {}, 'Nothing to analyze yet'),
      h('p', { class: 'dim' }, 'Paste a payload (or send one from the Decode tab). The X-ray splits it into its functional elements and explains what each part does, why it exists, and which filter bypasses exist for it.'));

    const { spans, types } = xrayScan(input);
    const wrap = h('div', {});

    // verdict
    wrap.append(h('div', { class: 'result-meta' },
      types.length ? h('span', {}, 'Found ', h('span', { class: 'result-count' }, types.length + ' functional element' + (types.length === 1 ? '' : 's'))) : h('span', { class: 'result-count' }, 'No functional elements'),
      types.length ? [...new Set(types.map(([ti]) => PLDATA.TOKENS[ti].cat))].map(c =>
        h('span', { class: 'badge', style: 'margin-left:4px' }, CAT_NAME[c])) : h('span', { class: 'result-filters' }, 'this looks like inert data in most contexts')));

    // highlighted payload
    const codeEl = h('div', { class: 'card card-pad xray-wrap' });
    let pos = 0;
    const pushPlain = txt => { if (txt) codeEl.append(document.createTextNode(txt)); };
    for (const s of spans) {
      pushPlain(input.slice(pos, s.start));
      codeEl.append(h('span', {
        class: 'xray-hl ' + CAT_CLASS[PLDATA.TOKENS[s.ti].cat],
        title: PLDATA.TOKENS[s.ti].name,
        onclick: () => {
          const el = document.getElementById('tok-' + s.ti);
          if (el) el.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }
      }, s.match));
      pos = s.end;
    }
    pushPlain(input.slice(pos));
    wrap.append(codeEl);
    if (!types.length) {
      wrap.append(h('div', { class: 'pb-expect', style: 'margin-top:12px' }, icon('info', 14),
        h('span', {}, 'No known meta-characters matched. If this string lands in an HTML or script context, it is harmless decoration... unless the context itself transforms it. Check the Context Lab for how the sink decides.')));
      return wrap;
    }

    // token cards
    wrap.append(h('div', { class: 'panel-title', style: 'margin-top:18px' }, icon('layers', 14), 'Element by element'));
    types.forEach(([ti, matches]) => {
      const t = PLDATA.TOKENS[ti];
      wrap.append(h('div', { class: 'card card-pad token-detail', id: 'tok-' + ti },
        h('div', { class: 'token-head' },
          h('span', { class: 'token-match ' + CAT_CLASS[t.cat] }, matches[0].slice(0, 42)),
          h('span', { class: 'badge' }, CAT_NAME[t.cat]),
          matches.length > 1 ? h('span', { class: 'dim small' }, '+' + (matches.length - 1) + ' more') : null),
        h('div', { class: 'token-what' }, h('b', {}, t.name + ': '), t.what),
        h('div', { class: 'token-grid' },
          h('div', { class: 'token-box' }, h('h5', {}, 'Why it matters'), h('p', {}, t.why)),
          t.bypass ? h('div', { class: 'token-box' }, h('h5', {}, 'If it is filtered'), h('p', {}, t.bypass)) : null)));
    });
    return wrap;
  }

  function contextDetail(c) {
    return h('div', { class: 'card card-pad playbook-card' },
      h('div', { class: 'panel-head' },
        h('span', { class: 'panel-title' }, icon('crosshair', 14), c.name),
        h('span', { class: 'badge amber' }, 'breakout: ' + c.breakout)),
      h('div', { class: 'sink-demo' }, c.snippet.split('{INJ}')[0],
        h('span', { class: 'inj' }, 'your input'), c.snippet.split('{INJ}')[1] || ''),
      h('div', { style: 'display:flex;flex-direction:column;gap:10px;margin-top:14px' },
        h('div', {},
          h('div', { class: 'err-sec-title' }, icon('zap', 13), 'Minimal payload'),
          h('div', { class: 'cmd-line' }, h('span', { class: 'cmd-text' }, c.minPayload), SL.copyBtn(c.minPayload)),
          h('div', { class: 'cmd-why' }, 'Copy-paste ready for this exact context.')),
        h('div', {},
          h('div', { class: 'err-sec-title' }, icon('brain', 13), 'Why it works'),
          h('div', { class: 'err-list' }, h('div', {}, c.why))),
        h('div', {},
          h('div', { class: 'err-sec-title' }, icon('trending', 13), 'Escalation'),
          h('div', { class: 'err-list' }, h('div', {}, c.escalate))),
        h('div', { class: 'pb-warn' }, icon('shield', 14), h('span', {}, 'When it does not work: ' + c.blocked))));
  }

  function contextsView() {
    const sel = PLDATA.CONTEXTS.find(c => c.id === state.ctxId) || PLDATA.CONTEXTS[0];
    return h('div', {},
      h('div', { class: 'context-grid' },
        PLDATA.CONTEXTS.map(c => h('button', {
          class: 'context-card' + (c.id === sel.id ? ' active' : ''),
          onclick: () => { state.ctxId = c.id; render(); }
        },
          h('span', { class: 'context-name' }, c.name),
          h('span', { class: 'context-snippet' }, c.snippet.replace(/{INJ}/, '...')),
          h('span', { class: 'context-break' }, 'breakout: ' + c.breakout.split('(')[0].trim())))),
      h('div', { style: 'margin-top:14px' }, contextDetail(sel)));
  }

  function methodView() {
    return h('div', {},
      PLDATA.METHOD.map((m, i) => h('div', { class: 'method-step' },
        h('div', { class: 'method-rail' },
          h('span', { class: 'method-num' }, String(i + 1)),
          h('span', { class: 'method-line' })),
        h('div', { class: 'method-body' },
          h('div', { class: 'method-title' }, icon(m.icon, 15), m.title),
          h('div', { class: 'method-goal' }, m.goal),
          h('div', { class: 'method-content' },
            m.probe ? h('div', { class: 'probe-box' },
              h('span', { class: 'dim small nowrap' }, 'probe:'),
              h('span', { class: 'probe-text' }, m.probe),
              SL.copyBtn(m.probe)) : null,
            m.interp ? h('div', { class: 'card', style: 'overflow:hidden' },
              h('table', { class: 'interp-table' },
                h('thead', {}, h('tr', {}, h('th', {}, 'What you observe'), h('th', {}, 'What it means'))),
                h('tbody', {}, m.interp.map(r => h('tr', {}, h('td', {}, r[0]), h('td', {}, r[1])))))) : null,
            h('div', { class: 'card card-pad' },
              h('div', { class: 'err-list' }, m.items.map(it => h('div', {}, h('span', { class: 'num' }, '›'), it)))),
            m.lesson ? h('div', { class: 'pb-expect' }, icon('brain', 14), h('span', {}, m.lesson)) : null)))));
  }

  function diagView() {
    return h('div', {},
      PLDATA.DIAGNOSTICS.map(d => h('div', { class: 'card card-pad diag-card' },
        h('div', { class: 'diag-symptom' }, icon('alert', 15), d.symptom),
        h('div', { class: 'token-grid', style: 'margin-top:10px' },
          h('div', { class: 'token-box' }, h('h5', {}, 'Likely cause'), h('p', {}, d.cause)),
          h('div', { class: 'token-box' }, h('h5', {}, 'Confirm it'), h('p', {}, d.confirm)),
          h('div', { class: 'token-box' }, h('h5', {}, 'The fix'), h('p', {}, d.fix))))));
  }

  /* ================= MAIN RENDER ================= */

  const EXAMPLES = [
    { label: 'URL-encoded XSS', v: '%22%3E%3Csvg%20onload%3Dalert%281%29%3E' },
    { label: 'Double URL-encoded', v: '%2522%253E%253Csvg%2520onload%253Dalert%25281%2529%253E' },
    { label: 'Base64 XSS', v: 'PGltZyBzcmM9eCBvbmVycm9yPWFsZXJ0KDEpPg==' },
    { label: 'HTML entities', v: '&lt;svg onload=alert&#40;1&#41;&gt;' },
    { label: 'JS escapes', v: '\\x3c\\x73\\x76\\x67\\x20\\x6f\\x6e\\x6c\\x6f\\x61\\x64\\x3d\\x61\\x6c\\x65\\x72\\x74\\x28\\x31\\x29\\x3e' },
    { label: 'charcode array', v: 'String.fromCharCode(60,115,118,103,32,111,110,108,111,97,100,61,97,108,101,114,116,40,49,41,62)' },
    { label: 'JWT token', v: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c' },
    { label: 'hex payload', v: '3c737667206f6e6c6f61643d616c6572742831293e' }
  ];

  let rootEl = null;

  function decodeTab(main) {
    main.innerHTML = '';
    const ta = h('textarea', {
      class: 'code-input', spellcheck: false, rows: 6,
      placeholder: 'Paste an encoded or obfuscated payload...\n\nAuto-detected: URL encoding (single or layered), Base64, Base32, hex, HTML entities, JS escapes (\\xNN, \\uNNNN), octal, charcode arrays, JWT, gzip-wrapped data. ROT13 and reversed are manual toggles below.'
    });
    ta.value = state.dec.input;
    const rot = h('input', { type: 'checkbox' }); rot.checked = state.dec.rot13;
    const rev = h('input', { type: 'checkbox' }); rev.checked = state.dec.reverse;

    const run = async () => {
      state.dec.input = ta.value;
      state.dec.rot13 = rot.checked;
      state.dec.reverse = rev.checked;
      if (!ta.value.trim()) { state.dec.layers = null; state.dec.final = ''; paint(); return; }
      state.dec.busy = true; paint();
      try {
        const res = await decodeAll(ta.value);
        state.dec.layers = res.layers;
        state.dec.final = res.final;
        state.dec.err = null;
      } catch (e) { state.dec.err = e.message; state.dec.layers = null; }
      state.dec.busy = false;
      paint();
    };

    const out = h('div', { id: 'decOut' });
    const paint = () => {
      out.innerHTML = '';
      if (state.dec.err) { out.append(h('div', { class: 'pb-warn' }, icon('alert', 14), state.dec.err)); return; }
      if (state.dec.busy) { out.append(h('p', { class: 'empty-note' }, 'Decoding...')); return; }
      if (state.dec.layers) out.append(layerTree(state.dec.layers, state.dec.final, state.dec.input));
    };

    ta.addEventListener('input', SL.debounce(run, 400));
    ta.addEventListener('keydown', e => { if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') run(); });
    rot.addEventListener('change', run);
    rev.addEventListener('change', run);

    main.append(
      h('div', { class: 'card card-pad', style: 'margin-bottom:14px' },
        h('div', { class: 'panel-head' },
          h('span', { class: 'panel-title' }, icon('layers', 14), 'Layered decoder'),
          h('button', { class: 'btn primary small', onclick: run }, icon('zap', 13), 'Decode')),
        ta,
        h('div', { style: 'display:flex;gap:16px;margin-top:10px;flex-wrap:wrap;align-items:center' },
          h('label', { class: 'check-row small' }, rot, 'also try ROT13'),
          h('label', { class: 'check-row small' }, rev, 'also try reversed'),
          h('span', { class: 'dim small' }, 'Ctrl+Enter decodes')),
        h('div', { class: 'example-row', style: 'margin-top:10px' },
          h('span', { style: 'font-size:10px;text-transform:uppercase;letter-spacing:.08em;color:var(--text-3);font-weight:600;margin-right:2px' }, 'Examples:'),
          EXAMPLES.map(ex => h('button', {
            class: 'example-chip', onclick: () => {
              ta.value = ex.v;
              run();
            }
          }, ex.label)))),
      out);
  }

  function xrayTab(main) {
    main.innerHTML = '';
    const ta = h('textarea', {
      class: 'code-input', spellcheck: false, rows: 5,
      placeholder: 'Paste a payload to dissect... e.g. "><svg onload=alert(document.domain)>'
    });
    ta.value = state.xray.input;
    const out = h('div');
    const run = () => { state.xray.input = ta.value; out.innerHTML = ''; out.append(xrayResult()); };
    ta.addEventListener('input', SL.debounce(run, 350));
    main.append(
      h('div', { class: 'card card-pad', style: 'margin-bottom:14px' },
        h('div', { class: 'panel-head' },
          h('span', { class: 'panel-title' }, icon('search-code', 14), 'Payload X-ray'),
          h('button', { class: 'btn primary small', onclick: run }, icon('zap', 13), 'Analyze')),
        ta,
        h('p', { class: 'hint' }, 'Splits the payload into its functional elements: breakouts, tags, event handlers, schemes, injection markers. Each element comes with what it does, why it works syntactically, and the bypass variants if it gets filtered.')),
      out);
    run();
  }

  function render() {
    if (!rootEl) return;
    const tabs = [['decode', 'Decode', 'layers'], ['xray', 'X-ray', 'search-code'], ['contexts', 'Context Lab', 'crosshair'], ['method', 'Method', 'book'], ['diag', 'When it fails', 'stethoscope']];
    const tabBar = rootEl.querySelector('#plTabs');
    if (tabBar) {
      tabBar.innerHTML = '';
      tabs.forEach(([id, label, ic]) => tabBar.append(h('button', {
        class: 'tab' + (state.tab === id ? ' active' : ''),
        onclick: () => { state.tab = id; render(); }
      }, icon(ic, 13), label)));
    }
    const main = rootEl.querySelector('#plMain');
    if (!main) return;
    main.innerHTML = '';
    if (state.tab === 'decode') decodeTab(main);
    else if (state.tab === 'xray') xrayTab(main);
    else if (state.tab === 'contexts') main.append(contextsView());
    else if (state.tab === 'method') main.append(methodView());
    else main.append(diagView());
  }

  function view() {
    rootEl = h('div', { class: 'view' },
      SL.sectionTitle('code', 'Decoder'),
      h('p', { class: 'section-sub' },
        'Paste anything encoded and peel it layer by layer, then X-ray a payload to see why each part works, which injection context it targets, and what to change when it fails.'),
      h('div', { class: 'tab-row', id: 'plTabs' }),
      h('div', { id: 'plMain' }));
    render();
    return rootEl;
  }

  return {
    view,
    _decodeOnce: decodeOnce,
    _decodeAll: decodeAll,
    _xray: xrayScan,
    _test: { rot13, decodeEntities, decodeJsEscapes, b64ToBytes }
  };
})();
