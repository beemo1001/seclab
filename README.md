# SecLab

The student security field kit: three tools that teach you to fish instead of handing you a fish. Same family, same philosophy and same design language as [BountyFlow](https://pages.github.com/) (the bug bounty aggregator): free forever, no APIs, no keys, no telemetry, everything runs 100% in your browser.

## The three tools

**Assembly Annotator** (`#/asm`)
Paste assembly from a pwn challenge, objdump -d or gdb. Every single line gets a plain-English explanation, plus pwn context:
- x86, x86-64 and ARM64 (AArch64), Intel or AT&T syntax (AT&T is detected, converted and explained)
- Function prologues and epilogues, frame sizes, calling conventions (System V AMD64, i386 cdecl, AAPCS64)
- Syscall resolution with argument registers, for all three architectures (syscall, svc, int 0x80)
- Security findings: stack canary detection, PIE vs non-PIE addressing, dangerous libc calls (gets, strcpy, system...), watch-list calls (printf, read, memcpy) with the exact question to ask about each
- ROP gadget detection (pop rdi ; ret, leave ; ret, syscall ; ret) straight from pasted gadget lists
- ASCII constants decoded on the spot ("this immediate spells /bin//sh")
- A student next-steps playbook and the full ABI reference table

**Linux Error Reference** (`#/linux`)
Sixty of the errors every Linux user meets. Each entry: what it really means, why it happens, diagnosis commands you run yourself (each explained), the actual fix, prevention, and a brain tip that teaches the deeper lesson.
- Smart search: paste the exact error, a fragment, an exit code (137) or an errno (13). Typos tolerated.
- Output scanner: paste a whole block of terminal output and it finds every recognized error, line by line.
- The errno table (1 to 116), all 31 signals, exit codes, and a decoder: type 143, learn it is SIGTERM.
- Ten categories: filesystem, permissions, execution, processes and signals, networking, SSH, packages, compilation, shell scripting, Docker.

**Payload Lab** (`#/payload`)
Not a cheat sheet. A systematic approach to understanding web applications at a fundamental level.
- **Decode**: layer-peeling decoder for URL encoding (single or layered), Base64, Base32, hex, HTML entities, JS escapes, octal, charcode arrays, JWT and gzip-wrapped data, with ROT13 and reversed as manual toggles. Every layer explains WHY attackers use that encoding.
- **X-ray**: splits any payload into its functional elements (breakouts, tags, event handlers, schemes, injection markers) and explains what each does, why it works syntactically, and the bypass variants if it gets filtered.
- **Context Lab**: the grammar of all 11 injection contexts (HTML body, three attribute flavors, URL attributes, three JS string flavors, template literals, code blocks, HTML comments, CSS) with the breakout, the minimal payload and the reasoning for each.
- **Method**: the 7-step systematic approach: map inputs, send the canary, read the reflection like a blueprint, classify the defense, craft the minimal payload, escalate with intent, adapt and document.
- **When it fails**: 14 diagnosed payload failures ("works in Repeater but not the browser", "tags appear but nothing executes") with the likely cause, how to confirm it, and the fix.

## Deploy on GitHub Pages (2 minutes)

Same procedure as BountyFlow:

1. Create a public repository on GitHub (for example `seclab`).
2. Upload everything in this folder to the `main` branch (git push, or drag and drop via the web uploader).
3. Repo `Settings` -> `Pages` -> Source: `Deploy from a branch`, branch `main`, folder `/ (root)` -> `Save`.
4. Your site goes live at `https://YOURUSERNAME.github.io/seclab/`.

No build step, no dependencies, no configuration. The `.nojekyll` file is already included.

## File structure

```
index.html          the app shell (header, router mount, footer)
css/styles.css      the full design system
js/core.js          DOM helper, icon system, clipboard, toasts
js/app.js           boot screen, hash router, home view
js/asm-data.js      instructions, registers, syscalls, ABI, examples
js/asm.js           the annotator engine + view
js/errors-data.js   60 error entries, errno, signals, exit codes
js/errors.js        search engine, scanner, reference tables + view
js/payload-data.js  contexts, functional tokens, diagnostics, method
js/payload.js       decoder engine, X-ray engine + views
logo.svg            the SecLab mark (radar ring + terminal cursor)
```

## Design notes

- Design system: "Security Intelligence Platform", identical tokens to BountyFlow. IBM Plex Sans for UI, IBM Plex Mono for data, deep blue-black surfaces, one blue accent, rose reserved for the brand mark and critical signals.
- Everything is client-side. Open the folder on disk, host it anywhere, print it to PDF: no network calls except the optional Google Fonts stylesheet (with a system font fallback when offline).
- Educational tool. Only test systems you are authorized to test. Stay in scope. Hack ethically.
