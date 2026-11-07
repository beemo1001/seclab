/* ============================================================
   CyberFlow · shared brand script
   Brand mark, suite switcher, toast. Keep the three copies
   identical (source of truth: community-sites/_shared).
   ============================================================ */
window.CF = (function () {
  'use strict';

  // Public URLs of the three tools. Local dev servers map to ports 4101-4103.
  var SUITE = [
    { id: 'bountyflow', name: 'BountyFlow', port: 4101, url: 'https://beemo1001.github.io/bountyflow/',
      desc: 'Every bug bounty program, analyzed. New programs daily.',
      icon: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4"/><path d="M12 3v3M12 18v3M3 12h3M18 12h3"/>' },
    { id: 'seclab', name: 'SecLab', port: 4102, url: 'https://beemo1001.github.io/seclab/',
      desc: 'Decoders, assembly annotator and Linux error reference.',
      icon: '<path d="M10 2v7.31L4.2 19.1A2 2 0 0 0 5.9 22h12.2a2 2 0 0 0 1.7-2.9L14 9.31V2"/><path d="M8.5 2h7M7 16h10"/>' },
    { id: 'hackgrid', name: 'HackGrid', port: 4103, url: 'https://beemo1001.github.io/hackrange/',
      desc: 'Hands-on hacking labs that run in your browser.',
      icon: '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><path d="M14 17.5h7M17.5 14v7"/>' }
  ];
  var local = /^(localhost|127\.0\.0\.1)$/.test(location.hostname);
  function hrefFor(s) { return local ? 'http://' + location.hostname + ':' + s.port + '/' : s.url; }

  // The CyberFlow "D": five nested crimson stripes, as in the logo.
  function markSVG(cls) {
    var paths = '';
    [14, 11, 8, 5, 2].forEach(function (r) {
      var top = 16 - r, bot = 16 + r;
      paths += '<path d="M2 ' + top + 'H16A' + r + ' ' + r + ' 0 0 1 16 ' + bot + 'H2"/>';
    });
    return '<svg class="' + (cls || 'cf-mark') + '" viewBox="0 0 32 32" fill="none" stroke="#e0243a" stroke-width="1.7" aria-hidden="true">' + paths + '</svg>';
  }

  function svgIcon(inner, size) {
    return '<svg class="ic" width="' + (size || 18) + '" height="' + (size || 18) + '" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + inner + '</svg>';
  }

  // Fill every [data-cf-mark] and build the suite switcher.
  function initChrome(current) {
    document.querySelectorAll('[data-cf-mark]').forEach(function (el) { el.outerHTML = markSVG(el.getAttribute('data-cf-mark') || 'cf-mark'); });

    var host = document.getElementById('cfSuite');
    if (host) {
      host.className = 'cf-suite';
      var items = SUITE.map(function (s) {
        return '<a href="' + hrefFor(s) + '"' + (s.id === current ? ' class="current"' : '') + '>' + svgIcon(s.icon, 18) +
          '<div><b>' + s.name + '</b><span>' + s.desc + '</span></div></a>';
      }).join('');
      host.innerHTML =
        '<button class="cf-suite-btn" type="button" aria-haspopup="true" aria-expanded="false">' +
        svgIcon('<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>', 15) +
        '<span class="lbl">CyberFlow tools</span></button>' +
        '<div class="cf-suite-menu" role="menu"><div class="label">CyberFlow toolkit</div>' + items + '</div>';
      var btn = host.querySelector('button');
      btn.addEventListener('click', function (e) {
        e.stopPropagation();
        var open = host.classList.toggle('open');
        btn.setAttribute('aria-expanded', open);
      });
      document.addEventListener('click', function (e) { if (!host.contains(e.target)) host.classList.remove('open'); });
    }

    var foot = document.getElementById('cfFooterLinks');
    if (foot) foot.innerHTML = SUITE.map(function (s) { return '<a href="' + hrefFor(s) + '">' + s.name + '</a>'; }).join('');

    // Close any open .pop when clicking outside it or pressing Escape.
    document.addEventListener('click', function (e) {
      document.querySelectorAll('.pop.open').forEach(function (p) { if (!p.contains(e.target)) p.classList.remove('open'); });
    });
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape') document.querySelectorAll('.pop.open, .cf-suite.open').forEach(function (p) { p.classList.remove('open'); });
    });
  }

  var toastTimer;
  function toast(msg) {
    var t = document.querySelector('.cf-toast');
    if (!t) { t = document.createElement('div'); t.className = 'cf-toast'; t.setAttribute('role', 'status'); document.body.appendChild(t); }
    t.textContent = msg;
    t.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { t.classList.remove('show'); }, 2200);
  }

  function copy(text, label) {
    var done = function () { toast((label || 'Copied') + ' to clipboard'); };
    if (navigator.clipboard && window.isSecureContext) return navigator.clipboard.writeText(text).then(done, fallback);
    fallback();
    function fallback() {
      var ta = document.createElement('textarea');
      ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
      document.body.appendChild(ta); ta.select();
      try { document.execCommand('copy'); done(); } catch (e) { toast('Copy failed'); }
      ta.remove();
    }
  }

  // Boot overlay shared by all three sites.
  function boot(name) {
    var el = document.createElement('div');
    el.className = 'cf-boot';
    el.innerHTML = '<div class="cf-boot-inner">' + markSVG('cf-mark') +
      '<div class="cf-boot-word">' + name + '</div>' +
      '<div class="cf-boot-bar"><div class="cf-boot-fill"></div></div>' +
      '<div class="cf-boot-status">starting</div></div>';
    document.body.appendChild(el);
    return {
      step: function (msg, pct) {
        el.querySelector('.cf-boot-status').textContent = msg;
        if (pct != null) el.querySelector('.cf-boot-fill').style.width = pct + '%';
      },
      done: function () { el.classList.add('done'); setTimeout(function () { el.remove(); }, 400); }
    };
  }

  return { SUITE: SUITE, markSVG: markSVG, initChrome: initChrome, toast: toast, copy: copy, boot: boot, hrefFor: hrefFor };
})();
