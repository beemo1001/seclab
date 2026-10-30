/* ============================================================
   SecLab · asm.js
   Assembly Annotator engine + view.
   Parses raw asm, objdump or gdb output (x86 / x86-64, Intel or
   AT&T syntax, plus ARM64), annotates every line in plain English,
   and extracts security findings a student can act on.
   ============================================================ */

const SLAsm = (() => {
  'use strict';
  const { h, icon } = SL;

  /* ---------------- tiny helpers ---------------- */
  const seg = (t, c) => ({ t, c });
  const isImm = s => /^-?(0x[0-9a-f]+|\d+)$/i.test((s || '').trim());
  const parseImm = s => { const v = (s || '').trim().replace(/^\+/, '').replace(/^#/, ''); return /^-?0x/i.test(v) ? parseInt(v, 16) : parseInt(v, 10); };

  const X64_ARG = { rdi: 1, rsi: 2, rdx: 3, rcx: 4, r8: 5, r9: 6 };
  const X64_SCARG = { rdi: 1, rsi: 2, rdx: 3, r10: 4, r8: 5, r9: 6 };
  const ARM_ARG = r => (/^[xw]([0-7])$/.test(r) ? +RegExp.$1 + 1 : 0);
  const ARM_SCARG = r => (/^[xw]([0-5])$/.test(r) ? +RegExp.$1 + 1 : 0);

  const REVERSE_OPS = new Set(['mov', 'movabs', 'movzx', 'movsx', 'movsxd', 'lea', 'cmp', 'add', 'sub', 'adc', 'sbb', 'and', 'or', 'xor', 'test', 'shl', 'sal', 'shr', 'sar', 'rol', 'ror', 'imul']);
  const WRITES_FIRST = new Set(['mov', 'movabs', 'movzx', 'movsx', 'movsxd', 'lea', 'pop', 'add', 'sub', 'inc', 'dec', 'neg', 'imul', 'and', 'or', 'xor', 'not', 'shl', 'sal', 'shr', 'sar', 'rol', 'ror', 'adr', 'adrp', 'ldr', 'ldrb', 'ldrh', 'ldrsw', 'ldp', 'movz', 'movk', 'movn', 'lsl', 'lsr', 'asr', 'sdiv', 'udiv', 'mul', 'madd', 'adds', 'subs', 'ands']);

  function splitOps(s) {
    const out = []; let depth = 0, cur = '', inStr = false;
    for (const ch of s) {
      if (ch === '"') inStr = !inStr;
      if (!inStr) {
        if (ch === '[' || ch === '(') depth++;
        if (ch === ']' || ch === ')') depth--;
        if (ch === ',' && depth <= 0) { out.push(cur.trim()); cur = ''; continue; }
      }
      cur += ch;
    }
    if (cur.trim()) out.push(cur.trim());
    return out.filter(Boolean);
  }

  /* ---------------- AT&T -> Intel ---------------- */
  function attOperand(op) {
    op = op.trim();
    if (op.startsWith('*')) op = op.slice(1).trim();
    if (op.startsWith('$')) return op.slice(1);
    if (op.startsWith('%')) return op.slice(1);
    const m = /^(-?(?:0x[0-9a-f]+|\d+)?)\(%([a-z0-9]+)(?:,%([a-z0-9]+)(?:,(\d+))?)?\)$/i.exec(op);
    if (m) {
      const [, disp, base, idx, scale] = m;
      let inner = base;
      if (idx) inner += '+' + idx + (scale && scale !== '1' ? '*' + scale : '');
      if (disp && disp !== '0') inner += disp.startsWith('-') ? disp : '+' + disp;
      return '[' + inner + ']';
    }
    return op;
  }

  function attToIntel(mn, ops) {
    let m = mn.toLowerCase();
    const widen = /^(mov)(s|z)(bw|bl|wl|bq|wq|lq)$/.exec(m);
    if (widen) {
      m = 'mov' + (widen[2] === 's' ? (widen[3] === 'lq' ? 'sxd' : 'sx') : 'zx');
    } else if (m === 'movabsq') m = 'movabs';
    else {
      const old = /^(movzbl|movzwl|movsbl|movswl|movsbw|movzbw|movsbq|movswq|movslq|movzbq|movzwq)$/.exec(m);
      if (old) m = m.indexOf('movslq') === 0 ? 'movsxd' : (m[3] === 's' ? 'movsx' : 'movzx');
      else {
        const fams = ['mov', 'add', 'sub', 'cmp', 'and', 'or', 'xor', 'test', 'push', 'pop', 'inc', 'dec', 'neg', 'not', 'shl', 'shr', 'sar', 'rol', 'ror', 'imul', 'mul', 'idiv', 'div', 'adc', 'sbb', 'lea', 'call', 'jmp', 'ret', 'leave', 'nop', 'xchg'];
        for (const f of fams) {
          if (m.startsWith(f) && m.length === f.length + 1 && /^[bwlq]$/.test(m.slice(f.length))) { m = f; break; }
        }
      }
    }
    if (ops.length === 2 && REVERSE_OPS.has(m)) ops = [ops[1], ops[0]];
    return { mn: m, ops: ops.map(attOperand) };
  }

  /* ---------------- pre-pass: gadget listing lines ("pop rdi ; ret") ---------------- */
  function instructionLike(s) {
    s = s.trim().replace(/^0x[0-9a-f]+:\s*/i, '');
    if (!s) return false;
    const toks = s.split(/\s+/);
    const t = toks[0].toLowerCase();
    if (ASMDATA.X86[t] || ASMDATA.ARM64[t]) return true;
    if (/^(j)(e|z|ne|nz|g|ge|l|le|a|ae|b|be|s|ns|o|no|p|np|nle|nl|nge|ng|nbe|nb|nae|na|c|nc|pe|po)$/.test(t)) return true;
    if (t.startsWith('b.') && t.length > 2) return true;
    if (/^set[a-z]{1,3}$/.test(t) || /^cmov[a-z]{1,3}$/.test(t)) return true;
    if (/^(rep|repe|repz|repne|repnz)$/.test(t) && toks.length > 1) return instructionLike(toks.slice(1).join(' '));
    return false;
  }

  function prePass(lines) {
    const flat = [];
    for (const raw of lines) {
      if (raw.includes(';')) {
        const segs = raw.split(';');
        const tail = segs.slice(1).map(s => s.trim()).filter(Boolean);
        if (tail.length && tail.every(instructionLike)) {
          const addrM = raw.match(/0x[0-9a-f]+:/i);
          segs.forEach((s, k) => {
            const t = s.trim();
            if (!t) return;
            flat.push(k === 0 ? t : (addrM ? addrM[0] + ' ' + t : t));
          });
          continue;
        }
      }
      flat.push(raw);
    }
    return flat;
  }

  /* ---------------- line parsing ---------------- */
  function rawArchGuess(lines) {
    let arm = 0, x86 = 0;
    for (const l of lines) {
      if (/\b(stp|ldp|adrp|blr|cbz|cbnz|svc|eor|orr|lsl|lsr|asr|uxtw|sxtw)\b|\[sp,?\s*#-?|\bw(2[5-9]|3[01])\b|\bx(1[6-9]|2[0-9]|30)\b/i.test(l)) arm++;
      if (/\b(rax|rbx|rcx|rdx|rsi|rdi|rsp|rbp|rip|eax|ebx|ecx|edx|esi|edi|esp|ebp|eip|syscall|endbr64|pushq|popq|movabs)\b|%\w/.test(l)) x86++;
    }
    return arm > x86 ? 'arm64' : 'x86';
  }

  function parseLine(raw, idx, archHint) {
    const armHint = archHint === 'arm64';
    const rec = { idx, raw, kind: 'empty', mn: null, ops: [], comment: '', att: false, symbol: null };
    let s = raw;

    if (!s || !s.trim()) return rec;
    s = s.replace(/^\s*=>\s*/, '');

    // gdb "0x401187 <+10>: mov ..." and objdump "  401187: ..."
    const odM = /^\s*[0-9a-f]{4,}:\s*(.*)$/i.exec(s);
    if (odM && /^\s*[0-9a-f]{4,}:\s/.test(s)) s = odM[1];
    else {
      const gdbM = /^\s*0x[0-9a-f]+\s*(?:<[^>]*>)?\s*(?:\+\d+)?:\s*(.*)$/i.exec(s);
      if (gdbM) s = gdbM[1];
    }
    s = s.replace(/^\s+/, '');

    // strip byte columns (objdump)
    const bytesM = /^((?:[0-9a-fA-F]{2}\s+){1,16})(?=[a-z.]|\s*$)/.exec(s);
    if (bytesM) s = s.slice(bytesM[0].length);
    if (!s.trim()) { rec.kind = 'bytes'; return rec; }

    // objdump function header
    const fh = /^\s*[0-9a-f]{6,}\s+<(.+)>\s*:?\s*$/.exec(s) || /^\s*<(.+)>\s*:\s*$/.exec(s);
    if (fh) { rec.kind = 'func'; rec.name = fh[1]; return rec; }
    if (/^\s*(Dump of assembler|Disassembly of section|End of assembler dump)/.test(s)) { rec.kind = 'junk'; return rec; }

    // comment split. '#' is a comment in x86 tooling but an immediate
    // prefix on ARM64, so the rule depends on the architecture.
    let code = s, comment = '';
    const cPats = armHint ? [/(^|\s)\/\//, /(^|\s);/] : [/(^|\s)#/, /(^|\s);/, /(^|\s)\/\//];
    const findComment = txt => {
      let best = -1;
      for (const p of cPats) { const m = p.exec(txt); if (m && (best === -1 || m.index + m[1].length < best)) best = m.index + m[1].length; }
      return best;
    };
    const cIdx = findComment(code);
    if (cIdx > -1) { comment = code.slice(cIdx).replace(/^[#;/]+ ?/, '').trim(); code = code.slice(0, cIdx).trim(); }
    rec.comment = comment;
    if (!code) { rec.kind = comment ? 'comment' : 'empty'; return rec; }

    // directive
    const firstTok = code.split(/\s+/)[0];
    const mnLower = firstTok.toLowerCase();
    if (/^[.\w]+$/.test(firstTok)) {
      if (mnLower in ASMDATA.DIRECTIVES && !ASMDATA.X86[mnLower] && !ASMDATA.ARM64[mnLower]) {
        rec.kind = 'directive'; rec.mn = mnLower; rec.rest = code.slice(firstTok.length).trim();
        return rec;
      }
      if (firstTok.startsWith('.') && !(code.match(/:/) && /^\.L/.test(firstTok))) {
        rec.kind = 'directive'; rec.mn = mnLower; rec.rest = code.slice(firstTok.length).trim();
        return rec;
      }
    }

    // label
    const labM = /^([.A-Za-z_@$][\w.$]*)\s*:\s*(.*)$/.exec(code);
    if (labM) {
      rec.name = labM[1];
      if (labM[2].trim()) { rec.kind = 'label+ins'; rec.ins = labM[2].trim(); }
      else rec.kind = 'label';
      return rec;
    }

    // instruction
    rec.kind = 'ins';
    let mn = mnLower, rest = code.slice(firstTok.length).trim();
    if (/^(rep|repe|repz|repne|repnz|lock|data16|addr32)$/.test(mn) && rest) {
      rec.prefix = mn;
      const parts = rest.split(/\s+/);
      mn = parts[0].toLowerCase();
      rest = rest.slice(parts[0].length).trim();
    }
    const symM = /<([^>]+)>/.exec(rest);
    if (symM) rec.symbol = symM[1];
    let ops = splitOps(rest);
    const attMn = /^(mov|movabs|add|sub|cmp|and|or|xor|test|push|pop|inc|dec|neg|not|shl|shr|sar|rol|ror|imul|mul|idiv|div|adc|sbb|lea|call|jmp|ret|leave|xchg|nop|loop)[bwlq]$/.test(mn) && !ASMDATA.X86[mn];
    rec.att = /%[a-z0-9]/i.test(rest) || /(^|[\s,])\$/i.test(rest) || attMn;
    if (rec.att) { const conv = attToIntel(mn, ops); mn = conv.mn; ops = conv.ops; }
    ops = ops.map(o => o.replace(/\s*<[^>]*>/g, '').trim()).filter(Boolean);
    rec.mn = mn; rec.ops = ops;
    return rec;
  }

  /* ---------------- arch detection ---------------- */
  function detectArch(P) {
    let arm = 0, att = 0, bits32 = 0, bits64 = 0;
    for (const p of P) {
      if (p.att) att++;
      const r = p.raw || '';
      if (/\b(stp|ldp|adrp|blr|cbz|cbnz|svc|lsl|lsr|asr|eor|adr)\b/.test(r)) arm++;
      if (/\be(sp|bp|ax|bx|cx|dx|si|di)\b|%e[a-z]{2}\b/.test(r)) bits32++;
      if (/\br(sp|bp|ax|bx|cx|dx|si|di|8|9|1[0-5])\b|%r[a-z0-9]{1,3}\b/.test(r)) bits64++;
    }
    if (arm > 0 && arm >= Math.max(bits32, bits64)) return { arm64: true, att: false, label: 'ARM64 (AArch64)' };
    const bits = bits32 > bits64 ? 32 : 64;
    return { arm64: false, bits, att: att > 0, label: (bits === 32 ? 'x86 32-bit' : 'x86-64') + (att > 0 ? ' (AT&T input, shown as Intel)' : ', Intel syntax') };
  }

  /* ---------------- annotation engine ---------------- */
  function annotateAll(rawLines) {
    const D = ASMDATA;
    const lines = prePass(rawLines);
    const hint = rawArchGuess(lines);
    const P = lines.map((l, i) => parseLine(l, i, hint));
    const arch = detectArch(P);

    const findings = {
      arch, canary: false, pie: null, frames: [], syscalls: {}, calls: {}, watch: [],
      unsafe: [], gadgets: [], strings: [], counts: { ins: 0, funcs: 0 }
    };
    const rows = [];

    let lastSys = null;   // last value written to rax / eax / x8
    let canaryRead = false;

    const annotateDirective = (p, note) => {
      const dd = D.DIRECTIVES[p.mn] || 'Assembler directive: metadata for the assembler, not a machine instruction.';
      note.push(dd);
      if (/string|asciz|ascii|\bdb\b|\bdecl\b/.test(p.mn) && p.rest) {
        const sm = /"([^"]*)"/.exec(p.rest);
        if (sm) { note.push(' Defines the string ', seg('"' + sm[1] + '"', 'green')); findings.strings.push(sm[1]); }
      }
      if ((p.mn === 'times' || p.mn === 'db') && /0x90|\b90h\b/i.test(p.rest || '')) note.push(seg(' That is a NOP sled.', 'amber'));
    };

    const p2Annotate = (p, i, note, tags) => {
      const mn = p.mn, ops = p.ops, raw = p.raw;
      findings.counts.ins++;
      const destClean = (ops[0] || '').replace(/^(?:qword|dword|word|byte)\s+ptr\s+/i, '').trim();

      // ----- jcc / setcc / cmovcc / b.cond -----
      let cond = null;
      if (/^j[a-z]+$/.test(mn) && !/^(jmp|jcxz|jecxz)$/.test(mn)) cond = [mn.slice(1), 'Jump if '];
      else if (/^set[a-z]{1,3}$/.test(mn)) cond = [mn.slice(3), 'Store 1 in the byte operand if '];
      else if (/^cmov[a-z]{1,3}$/.test(mn)) cond = [mn.slice(4), 'Copy only if '];
      else if (arch.arm64 && /^b\.[a-z]+$/.test(mn)) cond = [mn.slice(2), 'Branch if '];
      if (cond) {
        note.push(cond[1] + seg(D.CC[cond[0]] || cond[0], 'amber') + '. The flags come from the last cmp, test, adds or subs.');
        return;
      }

      // ----- syscalls -----
      if (mn === 'syscall' || (arch.arm64 && mn === 'svc') || (mn === 'int' && /0x80|^80$/i.test(ops[0] || ''))) {
        const isInt80 = mn === 'int';
        const table = isInt80 ? D.SC_I386 : (arch.arm64 ? D.SC_ARM64 : D.SC_X64);
        if (lastSys != null && table[lastSys]) {
          note.push(seg('Kernel call: ', 'cyan'), 'syscall ' + lastSys + ' = ', seg(table[lastSys], 'green') + '.');
          findings.syscalls[lastSys] = table[lastSys];
        } else if (lastSys != null) {
          note.push('Kernel call number ' + lastSys + ' is not in the local table. Look it up with: man 2 syscalls.');
        } else {
          note.push(seg('Kernel call. ', 'cyan'), 'The number rides in rax (x86-64), eax (int 0x80) or x8 (ARM64), set by an earlier instruction.');
        }
        if (isInt80) note.push(' Legacy 32-bit entry: arguments in ebx, ecx, edx, esi, edi.');
        else if (arch.arm64) note.push(' Arguments in x0 to x5, return and error code in x0.');
        else note.push(' Arguments in rdi, rsi, rdx, r10, r8, r9 (note r10, not rcx). Return and error code land in rax.');
        return;
      }

      // ----- track writes to the syscall-number register -----
      if (WRITES_FIRST.has(mn) && ops.length >= 1) {
        const canon = arch.arm64 ? D.armReg(destClean.toLowerCase()) : (D.SUBREG[destClean.toLowerCase()] || destClean.toLowerCase());
        if (arch.arm64 && /^(x8|w8)$/.test(canon)) {
          const src = (ops[1] || '').replace('#', '');
          if (isImm(src)) lastSys = parseImm(src);
        } else if (!arch.arm64 && /^(rax|eax|al)$/.test(canon)) {
          if (mn === 'xor' && (ops[1] || '').toLowerCase().replace(/%(e?ax|al)/, '') === '' && (ops[1] || '').replace('%', '').toLowerCase() === canon) lastSys = 0;
          else if (mn === 'xor' && (ops[1] || '').toLowerCase().replace('%', '') === destClean.toLowerCase()) lastSys = 0;
          else if (mn === 'pop') { /* set by the push lookahead */ }
          else if (ops[1] && isImm(ops[1])) lastSys = parseImm(ops[1]);
          else lastSys = null;
        }
      }
      if (mn === 'push' && ops[0] && isImm(ops[0])) {
        for (let j = i + 1; j < Math.min(i + 4, P.length); j++) {
          const q = P[j];
          if (q.kind !== 'ins') { if (q.kind === 'label' || q.kind === 'func') break; continue; }
          if (q.mn === 'pop' && /^(rax|eax|x8|w8)$/i.test(q.ops[0] || '')) lastSys = parseImm(ops[0]);
          break;
        }
      }
      if (mn === 'call' || mn === 'bl' || mn === 'ret') lastSys = null;

      // ----- base description -----
      const db = arch.arm64 ? (D.ARM64[mn] || D.X86[mn]) : (D.X86[mn] || D.ARM64[mn]);
      if (db) {
        note.push(db.d);
        if (db.n) note.push(' ' + db.n);
      } else {
        note.push('Not in the local knowledge base. Look it up on felixcloutier.com/x86 (x86) or in the ARM instruction reference.');
      }

      // ----- contextual enhancements -----
      if (/fs:0x28/i.test(raw)) {
        if (mn === 'mov' || mn === 'movabs') {
          note.push(' ', seg('Stack canary read: ', 'red'), 'this random per-run value guards the saved return address.');
          findings.canary = true; canaryRead = true; tags.push('canary');
        } else {
          note.push(' ', seg('Canary check: ', 'red'), 'if the stored copy differs from the real one, the process aborts instead of returning.');
          findings.canary = true;
        }
      }
      if (canaryRead && mn === 'mov' && /-0*8\s*\]|#-8\b/.test(ops[0] || '')) {
        note.push(' ', seg('Stashing the canary at the frame top. ', 'amber'), 'The epilogue verifies it before returning.');
      }

      if (mn === 'call' || (arch.arm64 && mn === 'bl')) {
        let name = p.symbol;
        if (!name && ops[0] && !isImm(ops[0]) && !/^(\[|[xw]\d|r[a-z0-9]+)$/i.test(ops[0])) name = ops[0];
        if (name) {
          const clean = name.replace(/@plt.*/i, '').replace(/@GLIBC.*/i, '');
          findings.calls[clean] = (findings.calls[clean] || 0) + 1;
          if (/plt/i.test(name)) note.push(' Reached through the ', seg('PLT', 'cyan'), ' (the dynamic linker trampoline for library functions).');
          if (/__stack_chk_fail/i.test(clean)) {
            note.push(' ', seg('The canary check failed and the program deliberately crashes here. ', 'red'), 'This is what kills naive stack overflows in protected binaries.');
          } else if (D.UNSAFE_LIBC[clean]) {
            note.push(' ', seg('DANGER: ' + D.UNSAFE_LIBC[clean], 'red'));
            findings.unsafe.push(clean); tags.push('unsafe');
          } else if (D.WATCH_LIBC[clean]) {
            note.push(' ', seg('Check this: ' + D.WATCH_LIBC[clean], 'amber'));
            findings.watch.push(clean); tags.push('watch');
          }
        }
      }
      if (mn === 'blr' || (mn === 'call' && ops[0] && /^(r[a-z0-9]+|[xw]\d+)$/i.test(ops[0]))) {
        note.push(' ', seg('Indirect call through a register: ', 'amber'), 'control that register and you control execution.');
      }
      if (arch.arm64 && (mn === 'br' || mn === 'ret') && /x(16|17|30)/i.test(raw)) {
        note.push(' ', seg('Return / jump address comes from the link register or PLT scratch: ', 'amber'), 'a corrupted saved x30 turns this into arbitrary control.');
      }

      // argument setup before a call
      if (WRITES_FIRST.has(mn) && ops.length >= 2 && (mn === 'mov' || mn === 'lea' || mn === 'movz' || mn === 'movk' || mn === 'movzx' || mn === 'movsx')) {
        const canon = arch.arm64 ? D.armReg(destClean.toLowerCase()) : (D.SUBREG[destClean.toLowerCase()] || destClean.toLowerCase());
        const argn = arch.arm64 ? (ARM_ARG(canon) || ARM_SCARG(canon)) : (X64_ARG[canon] || X64_SCARG[canon]);
        if (argn) {
          for (let j = i + 1; j < Math.min(i + 7, P.length); j++) {
            const q = P[j];
            if (q.kind !== 'ins') { if (q.kind === 'label' || q.kind === 'func') break; continue; }
            if (q.mn === 'call' || q.mn === 'bl' || q.mn === 'syscall' || q.mn === 'svc') {
              const isSc = q.mn === 'syscall' || q.mn === 'svc';
              const n2 = arch.arm64 ? (isSc ? ARM_SCARG(canon) : ARM_ARG(canon)) : (isSc ? X64_SCARG[canon] : X64_ARG[canon]);
              note.push(' Sets ', seg('argument ' + n2, 'amber'), ' for the ' + (isSc ? 'syscall' : 'call') + ' below.');
              break;
            }
            if (WRITES_FIRST.has(q.mn)) {
              const qd = (q.ops[0] || '').replace(/^(?:qword|dword|word|byte)\s+ptr\s+/i, '').trim();
              const qc = arch.arm64 ? D.armReg(qd.toLowerCase()) : (D.SUBREG[qd.toLowerCase()] || qd.toLowerCase());
              if (qc === canon) break;
            }
          }
        }
      }

      if (/rip[+-]/i.test(raw) && (mn === 'lea' || mn === 'mov' || mn === 'call')) {
        note.push(' ', seg('RIP-relative addressing: ', 'cyan'), 'the binary is position independent (PIE), addresses are computed at runtime.');
        findings.pie = true;
      } else if (!arch.arm64 && arch.bits === 64 && (mn === 'lea' || mn === 'mov') && /0x[0-9a-f]{5,}/i.test(raw) && findings.pie !== true) {
        note.push(' Absolute address: typical of a ', seg('non-PIE', 'amber'), ' binary (fixed load address, gadgets can be hardcoded).');
        findings.pie = false;
      }
      if (mn === 'adrp') { note.push(' ', seg('PIE-style addressing on ARM64.', 'cyan')); findings.pie = true; }

      if (mn === 'sub' && /^(rsp|esp|sp)$/i.test(ops[0] || '') && ops[1] && isImm(ops[1].replace('#', ''))) {
        const n = parseImm(ops[1]);
        findings.frames.push(n);
        note.push(' ', seg('Frame size: ' + n + ' bytes', 'amber') + '. Locals live below rbp; the saved rbp sits at [rbp] and the return address at [rbp+8].');
      }
      if (mn === 'lea' && /rbp|ebp|x29/i.test(ops[1] || '') && /-/.test(ops[1] || '')) {
        note.push(' Points at a ', seg('local variable / buffer', 'cyan'), ' inside this frame.');
      }

      // immediates: ASCII decoding (BigInt: these constants exceed Number.MAX_SAFE_INTEGER)
      for (const o of ops.slice(0, 2)) {
        const oo = (o || '').replace('#', '');
        const hexM = /^0x([0-9a-f]+)$/i.exec(oo);
        if (hexM && hexM[1].length >= 8 && hexM[1].length <= 16) {
          let v = BigInt('0x' + hexM[1]);
          const bytes = [];
          while (v > 0n && bytes.length < 9) { bytes.push(Number(v & 0xffn)); v >>= 8n; }
          if (bytes.length >= 4 && bytes.every(b => b >= 0x20 && b < 0x7f)) {
            const txt = bytes.map(b => String.fromCharCode(b)).join('');
            note.push(' The constant spells ', seg('"' + txt + '"', 'green'), ' in little-endian bytes: a string built in registers.');
            findings.strings.push(txt);
          }
        }
      }

      if (mn === 'push' && /^(rbp|ebp|x29)$/i.test(ops[0] || '')) {
        const nxt = P[i + 1];
        if (nxt && nxt.kind === 'ins' && nxt.mn === 'mov' && /^(rbp|rsp|sp)$/i.test((nxt.ops[0] || '').replace(/^(?:qword|dword|word|byte)\s+ptr\s+/i, ''))) {
          note.push(' ', seg('Function prologue starts here.', 'cyan'));
        }
      }
      if (mn === 'leave') {
        const nxt = P[i + 1];
        if (nxt && nxt.kind === 'ins' && nxt.mn === 'ret') note.push(' ', seg('Standard epilogue: ', 'cyan'), 'leave restores rsp and rbp, the next ret pops the saved return address.');
      }
      if (mn === 'xor' && ops.length === 2 && (ops[0] || '').toLowerCase() === (ops[1] || '').toLowerCase() && /^(r|e|x|w)[a-z0-9]{1,3}$/i.test(ops[0] || '')) {
        note.push(' ', seg('Zeroing idiom.', 'amber'));
      }
      if ((mn === 'idiv' || mn === 'div') && !arch.arm64) note.push(' Remember: rdx:rax is the dividend, a cdq / cqo above prepared the high half.');
      if (p.prefix && /^movs/.test(mn)) note.push(' With rep this is a one-instruction ', seg('memcpy', 'cyan'), ' of rcx elements.');
      if (p.prefix && /^stos/.test(mn)) note.push(' With rep this is a one-instruction ', seg('memset', 'cyan'), ' of rcx elements.');
      if (p.prefix && /^scas/.test(mn)) note.push(' repne scasb is how ', seg('strlen', 'cyan'), ' is written: scan until the NUL byte.');
      if (mn === 'stp' && /x29|x30|fp|lr/i.test(ops[0] || '')) note.push(' ', seg('ARM64 prologue: ', 'cyan'), 'saves the frame pointer and return address while allocating the frame.');
      if (mn === 'ldp' && /x29|x30|fp|lr/i.test(ops[0] || '')) note.push(' ', seg('ARM64 epilogue: ', 'cyan'), 'restores the frame pointer and return address.');
    };

    // main pass
    for (let i = 0; i < P.length; i++) {
      const p = P[i];
      const note = [];
      const tags = [];

      if (p.kind === 'func') {
        findings.counts.funcs++;
        note.push('Function ', seg(p.name, 'cyan'), ': where the disassembler says this function begins.');
        lastSys = null;
        rows.push({ p, note, tags });
        continue;
      }
      if (p.kind === 'label') {
        note.push('Label ', seg(p.name, 'cyan'), ': a jump target or function name, not an instruction.');
        rows.push({ p, note, tags });
        continue;
      }
      if (p.kind === 'label+ins') {
        note.push('Label ', seg(p.name, 'cyan'), ':');
        const sub = parseLine(p.ins, i, hint);
        if (sub.kind === 'ins') { p2Annotate(sub, i, note, tags); rows.push({ p: sub, note, tags }); }
        else if (sub.kind === 'directive') { annotateDirective(sub, note); rows.push({ p: sub, note, tags }); }
        else rows.push({ p, note, tags });
        continue;
      }
      if (p.kind === 'directive') { annotateDirective(p, note); rows.push({ p, note, tags }); continue; }
      if (p.kind === 'comment') { note.push('Comment: context for the human, does nothing at runtime.'); rows.push({ p, note, tags }); continue; }
      if (p.kind !== 'ins') { rows.push({ p, note, tags }); continue; }
      p2Annotate(p, i, note, tags);
      rows.push({ p, note, tags });
    }

    // gadget detection
    for (let i = 0; i < P.length; i++) {
      const a = P[i]; if (a.kind !== 'ins') continue;
      const seq = [a];
      for (let j = i + 1; j < P.length && seq.length < 3; j++) {
        const q = P[j];
        if (q.kind === 'label' || q.kind === 'func') break;
        if (q.kind !== 'ins') continue;
        seq.push(q); break;
      }
      const m1 = seq[0].mn, m2 = seq[1] && seq[1].mn, m3 = seq[2] && seq[2].mn;
      if (m1 === 'pop' && m2 === 'ret') {
        a.gadget = 'pop ' + (seq[0].ops[0] || '') + ' ; ret';
      } else if (m1 === 'leave' && m2 === 'ret') {
        a.gadget = 'leave ; ret';
      } else if (m1 === 'syscall' && m2 === 'ret') {
        a.gadget = 'syscall ; ret';
      } else if (m1 === 'pop' && m2 === 'pop' && m3 === 'ret') {
        a.gadget = 'pop ' + (seq[0].ops[0] || '') + ' ; pop ' + (seq[1].ops[0] || '') + ' ; ret';
      }
      if (a.gadget) findings.gadgets.push(a.gadget);
    }
    findings.gadgets = [...new Set(findings.gadgets)];

    return { rows, findings };
  }

  /* ---------------- syntax highlighting (on reconstructed code) ---------------- */
  function codeText(p) {
    if (p.kind === 'ins') {
      return (p.prefix ? p.prefix + ' ' : '') + p.mn + (p.ops.length ? ' ' + p.ops.join(', ') : '') +
        (p.symbol ? ' <' + p.symbol + '>' : '') + (p.comment ? '   # ' + p.comment : '');
    }
    if (p.kind === 'directive') return p.mn + (p.rest ? ' ' + p.rest : '') + (p.comment ? '   # ' + p.comment : '');
    if (p.kind === 'label') return p.name + ':' + (p.comment ? '   # ' + p.comment : '');
    if (p.kind === 'label+ins') return p.name + ': ' + p.ins;
    if (p.kind === 'func') return p.name + ':';
    if (p.kind === 'comment') return '# ' + p.comment;
    return '';
  }

  function highlight(p, arch) {
    const esc = SL.esc;
    const text = codeText(p);
    if (!text) return '&nbsp;';
    const parts = text.split(/   # /);
    let code = esc(parts[0]);
    const cmt = parts[1] ? '<span class="tk-cmt"># ' + esc(parts[1]) + '</span>' : '';

    code = code.replace(/&lt;([^&]*)&gt;/g, '&lt;<span class="tk-sym">$1</span>&gt;');
    code = code.replace(/(&quot;[^&]*?&quot;|"[^"]*")/g, '<span class="tk-str">$1</span>');
    // mnemonic (plus optional rep prefix)
    code = code.replace(/^((?:rep|repe|repz|repne|repnz|lock)\s+)?([a-z][a-z0-9.]*)/i,
      (m, pfx, mn) => (pfx ? '<span class="tk-mn">' + pfx.trim() + '</span> ' : '') + '<span class="tk-mn">' + mn + '</span>');
    // memory brackets
    code = code.replace(/\[[^\]]*\]/g, m => '<span class="tk-mem">' + m + '</span>');
    // registers
    if (arch.arm64) {
      code = code.replace(/(^|[\s,\[+])(x\d{1,2}|w\d{1,2}|sp|xzr|wzr|fp|lr)(?=$|[\s,\]\)+])/g,
        (m, pre, r) => pre + '<span class="tk-reg">' + r + '</span>');
    } else {
      code = code.replace(/(^|[\s,\[+%])(r\d{1,2}[dwb]?|r[a-z]{2}[dwb]?|e[a-z]{2}|[a-d][lh]|[asd]i|[sb]p|rip|[asd]s|fs|gs)(?=$|[\s,\]\)+*])/gi,
        (m, pre, r) => (/^(e?(ax|bx|cx|dx|si|di|sp|bp|ip)|[a-d][lh]|r[a-z0-9]{1,3}[dwb]?|[asd]i|[sb]p|rip|fs|gs)$/i.test(r) ? pre + '<span class="tk-reg">' + r + '</span>' : m));
    }
    // immediates
    code = code.replace(/(^|[\s,\[])(\$?)(-?(?:0x[0-9a-f]+|\d+))(?=$|[\s,\]\)])/gi,
      (m, pre, d, n) => pre + d + '<span class="tk-imm">' + n + '</span>');
    return code + (cmt ? '  ' + cmt : '');
  }

  /* ---------------- view ---------------- */
  const state = { input: '', onlyNotes: false };

  function renderNote(parts) {
    const wrap = SL.h('span');
    for (const part of parts || []) {
      if (part == null) continue;
      if (typeof part === 'string') wrap.append(part);
      else wrap.append(SL.h('span', { class: 'why-' + part.c }, part.t));
    }
    return wrap;
  }

  function findingsCards(f) {
    const cards = [];
    const mk = (title, iconName, tint, body) => cards.push(SL.h('div', { class: 'card find-card' },
      SL.h('div', { class: 'find-head' }, SL.h('span', { class: 'find-title' }, icon(iconName, 14), title), SL.h('span', { class: 'badge ' + tint }, tint === 'red' ? 'danger' : 'info')),
      SL.h('div', { class: 'find-body' }, body)));

    mk('Architecture', 'cpu', 'blue', [
      SL.h('span', {}, 'Detected: ' + f.arch.label + '.'),
      SL.h('span', {}, f.counts.ins + ' instructions parsed' + (f.counts.funcs ? ', ' + f.counts.funcs + ' function header' + (f.counts.funcs > 1 ? 's' : '') : '') + '.'),
      SL.h('span', { class: 'dim' }, 'The calling convention card below the listing tells you where arguments live.')
    ]);

    mk('Stack canary', f.canary ? 'shield-check' : 'shield-x', f.canary ? 'green' : 'amber', [
      f.canary
        ? SL.h('span', {}, 'Present (fs:0x28 pattern). A plain stack overflow trips the canary and aborts before ret, so you need a leak or a different bug class first.')
        : SL.h('span', {}, 'Not observed in this listing. If the code writes unbounded data into locals, an overflow can reach the saved return address directly.'),
      SL.h('span', { class: 'dim' }, 'Confirm with: checksec --file=binary')
    ]);

    mk('PIE / addressing', 'crosshair', 'blue', [
      f.pie === true
        ? SL.h('span', {}, 'RIP-relative (or ADRP) addressing found: likely PIE. Addresses change per run, so leak a pointer before building a ROP chain.')
        : f.pie === false
          ? SL.h('span', {}, 'Absolute addresses (like 0x401xxx) found: non-PIE. The load address is fixed and gadget addresses can be hardcoded.')
          : SL.h('span', {}, 'No addressing evidence in this snippet.'),
      SL.h('span', { class: 'dim' }, 'NX cannot be judged from disassembly: checksec reports it.')
    ]);

    const scKeys = Object.keys(f.syscalls);
    if (scKeys.length) mk('Syscalls used', 'zap', 'violet',
      scKeys.map(k => SL.h('div', { class: 'find-row' },
        SL.h('span', { class: 'find-k mono' }, '#' + k),
        SL.h('span', { class: 'find-v mono' }, f.syscalls[k]))));

    const callKeys = Object.keys(f.calls);
    if (callKeys.length) mk('Library calls', 'external', 'cyan',
      callKeys.map(k => SL.h('div', { class: 'find-row' },
        SL.h('span', { class: 'find-k mono' }, k),
        SL.h('span', { class: 'find-v' },
          f.unsafe.includes(k) ? 'danger: ' + (ASMDATA.UNSAFE_LIBC[k] || '').split('.')[0]
            : f.watch.includes(k) ? 'verify: ' + (ASMDATA.WATCH_LIBC[k] || '').split('.')[0]
              : 'external function'))));

    if (f.gadgets.length) mk('ROP gadgets', 'puzzle', 'red',
      f.gadgets.map(g => SL.h('div', { class: 'find-row' },
        SL.h('span', { class: 'find-v mono' }, g),
        SL.h('span', { class: 'find-k' }, g.startsWith('pop rdi') ? 'the most wanted gadget' : 'chainable'))));

    if (f.strings.length) mk('Strings found', 'search-code', 'green',
      f.strings.map(s => SL.h('div', { class: 'find-row' },
        SL.h('span', { class: 'find-v mono' }, '"' + s + '"'))));

    return cards;
  }

  function playbookCard(f) {
    const steps = [];
    if (f.unsafe.length) {
      steps.push(['Understand the bug', 'The listing calls ' + f.unsafe.join(', ') + '. That is the entry point: find how input reaches it and what bounds, if any, apply.']);
      steps.push(['Size the overflow', 'Compare the frame size (' + (f.frames.length ? Math.max(...f.frames) + ' bytes' : 'unknown') + ') with the bound actually enforced on input. The gap is your padding to the saved return address.']);
    }
    if (f.canary) steps.push(['Deal with the canary', 'Options: leak it with a format string or an off-by-one, corrupt only up to a pointer below it, or find a bug that triggers after the check.']);
    else if (f.unsafe.length) steps.push(['No canary detected', 'A straight overflow can reach the return address. Point it at a win function (ret2win) or a ROP chain.']);
    if (f.watch.length) steps.push(['Verify the amber calls', 'For ' + f.watch.join(', ') + ': is the size bound correct, is the format string constant?']);
    if (f.pie) steps.push(['Beat PIE', 'Leak a code pointer first (a GOT entry via puts, a %p in a format string) to compute the load base, then reuse the chain.']);
    if (f.gadgets.length) steps.push(['Chain the gadgets', 'Gadgets found here: ' + f.gadgets.slice(0, 4).join(', ') + '. Order them so argument registers receive your values right before the call or syscall.']);
    steps.push(['Verify with tooling', 'checksec for mitigations, gdb with pwndbg or gef to watch the overwrite land, ROPgadget to farm gadgets, cyclic (pwntools) to find the exact offset to the return address.']);

    return SL.h('div', { class: 'card card-pad playbook-card', style: 'margin-top:16px' },
      SL.h('div', { class: 'pb-title' }, icon('grad-cap', 14), 'Student next steps'),
      ...steps.map((s, i) => SL.h('div', { class: 'pb-item' },
        SL.h('span', { class: 'pb-step' }, (i + 1) + '. ' + s[0]),
        SL.h('span', { class: 'pb-desc' }, s[1]))));
  }

  function abiCard(arch) {
    const key = arch.arm64 ? 'arm64' : (arch.bits === 32 ? 'i386' : 'x64');
    const abi = ASMDATA.ABI[key];
    return SL.h('div', { class: 'card card-pad', style: 'margin-top:16px' },
      SL.h('div', { class: 'panel-title' }, icon('book', 14), 'Calling convention: ' + abi.title),
      SL.h('div', { class: 'scroll-y', style: 'margin-top:10px' },
        SL.h('table', { class: 'ref-table' },
          SL.h('thead', {}, SL.h('tr', {}, SL.h('th', {}, 'Register'), SL.h('th', {}, 'Role'), SL.h('th', {}, 'Callee saves'))),
          SL.h('tbody', {}, abi.rows.map(r => SL.h('tr', {},
            SL.h('td', { class: 'mono' }, r[0]), SL.h('td', {}, r[1]), SL.h('td', { class: 'dim' }, r[2])))))),
      SL.h('p', { class: 'hint', style: 'margin-top:10px' }, abi.note));
  }

  function view() {
    const ta = SL.h('textarea', {
      class: 'code-input', spellcheck: false, rows: 14,
      placeholder: 'Paste assembly here...\n\nWorks with:\n- raw asm source (NASM, GAS)\n- objdump -d output (addresses, bytes, <symbols> handled)\n- gdb disassembly listings\n- x86 / x86-64 in Intel or AT&T syntax, ARM64 (AArch64)\n- ROP gadget lists (pop rdi ; ret)\n\nOr load an example below.',
      oninput: SL.debounce(() => { state.input = ta.value; run(); }, 450)
    });
    ta.addEventListener('keydown', e => { if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { state.input = ta.value; run(); } });

    const outEl = SL.h('div');
    const onlyToggle = SL.h('input', { type: 'checkbox', onchange: () => { state.onlyNotes = onlyToggle.checked; run(); } });

    const run = () => {
      outEl.innerHTML = '';
      const src = state.input.trim();
      if (!src) {
        outEl.append(SL.h('div', { class: 'card card-pad empty-state' },
          SL.h('div', { class: 'big-icon' }, icon('cpu', 24)),
          SL.h('h3', {}, 'Nothing to annotate yet'),
          SL.h('p', { class: 'dim' }, 'Paste assembly on the left or load a worked example. Every line gets a plain-English explanation plus pwn context: prologues, canaries, syscalls, ROP gadgets and dangerous library calls.')));
        return;
      }
      let res;
      try { res = annotateAll(src.split(/\r?\n/)); }
      catch (e) {
        outEl.append(SL.h('div', { class: 'card card-pad' },
          SL.h('div', { class: 'diag-symptom' }, icon('alert', 15), 'Parse error: ' + e.message)));
        return;
      }
      const f = res.findings;

      outEl.append(
        SL.h('div', { class: 'panel-title' }, icon('activity', 14), 'Findings'),
        SL.h('div', { class: 'find-grid', style: 'margin-bottom:16px' }, ...findingsCards(f)));

      const MAX = 420;
      let rows = res.rows;
      if (state.onlyNotes) rows = rows.filter(r => (r.note && r.note.length) || r.p.gadget || r.p.kind === 'func');
      const shown = rows.slice(0, MAX);

      const tbody = SL.h('tbody');
      shown.forEach((r, i) => {
        const p = r.p;
        const cls = p.kind === 'func' || p.kind === 'label' ? 'asm-label-row'
          : p.kind === 'directive' || p.kind === 'comment' ? 'asm-directive-row'
            : (r.tags.includes('unsafe') || r.tags.includes('canary')) ? 'asm-flag-row' : '';
        tbody.append(SL.h('tr', { class: cls },
          SL.h('td', { class: 'asm-ln' }, String(i + 1)),
          SL.h('td', { class: 'asm-code', html: highlight(p, f.arch) }),
          SL.h('td', { class: 'asm-note' },
            renderNote(r.note),
            p.gadget ? SL.h('span', { class: 'why-red' }, ' ROP gadget: ' + p.gadget) : null)));
      });

      outEl.append(SL.h('div', { class: 'card', style: 'overflow:hidden' },
        SL.h('div', { class: 'panel-head', style: 'padding:14px 16px 4px' },
          SL.h('span', { class: 'panel-title' }, icon('list', 14), 'Annotated listing'),
          SL.h('label', { class: 'check-row small' }, onlyToggle, 'Only lines with notes')),
        SL.h('div', { class: 'scroll-y', style: 'max-height:640px' },
          SL.h('table', { class: 'asm-table' },
            SL.h('thead', {}, SL.h('tr', {},
              SL.h('th', {}, '#'), SL.h('th', {}, 'Code'), SL.h('th', {}, 'What it does / why it matters'))),
            tbody))));
      if (rows.length > MAX) outEl.append(SL.h('p', { class: 'empty-note' }, 'Showing the first ' + MAX + ' of ' + rows.length + ' lines.'));
      outEl.append(playbookCard(f), abiCard(f.arch));
    };

    const loadExample = ex => { ta.value = ex.code; state.input = ex.code; run(); };

    return SL.h('div', { class: 'view' },
      SL.sectionTitle('cpu', 'Assembly Annotator'),
      SL.h('p', { class: 'section-sub' }, 'Paste assembly from a pwn challenge, a class exercise or objdump. Every line gets a plain-English explanation, and the engine flags what matters for exploitation: stack canaries, syscalls, unsafe library calls, ROP gadgets, PIE addressing and frame sizes. Nothing leaves your browser.'),
      SL.h('div', { class: 'workbench' },
        SL.h('div', { class: 'workbench-col' },
          SL.h('div', { class: 'card card-pad' },
            SL.h('div', { class: 'panel-head' },
              SL.h('span', { class: 'panel-title' }, icon('terminal', 14), 'Input'),
              SL.h('button', { class: 'btn primary small', onclick: () => { state.input = ta.value; run(); } }, icon('zap', 13), 'Annotate')),
            ta,
            SL.h('div', { class: 'example-row', style: 'margin-top:10px' },
              SL.h('span', { style: 'font-size:10px;text-transform:uppercase;letter-spacing:.08em;color:var(--text-3);font-weight:600;margin-right:2px' }, 'Examples:'),
              ...ASMDATA.EXAMPLES.map(ex => SL.h('button', { class: 'example-chip', onclick: () => loadExample(ex) }, ex.label))),
            SL.h('p', { class: 'hint' }, 'Ctrl+Enter annotates. Accepts raw asm, objdump -d output (address and byte columns are stripped automatically), gdb listings and ROP gadget dumps. AT&T syntax is detected, converted and explained.')),
          SL.h('div', { class: 'card card-pad' },
            SL.h('div', { class: 'panel-title' }, icon('book', 14), 'How to read a function'),
            SL.h('div', { class: 'pb-item', style: 'margin-top:10px' },
              SL.h('span', { class: 'pb-step' }, '1. Prologue'),
              SL.h('span', { class: 'pb-desc' }, 'push rbp ; mov rbp, rsp ; sub rsp, N. N is the frame size: locals live below rbp, the saved return address sits at rbp+8.')),
            SL.h('div', { class: 'pb-item' },
              SL.h('span', { class: 'pb-step' }, '2. Body'),
              SL.h('span', { class: 'pb-desc' }, 'Argument registers get loaded before calls (rdi, rsi, rdx... on x86-64; x0 to x7 on ARM64). Watch for unbounded reads and writes into [rbp-...] buffers.')),
            SL.h('div', { class: 'pb-item' },
              SL.h('span', { class: 'pb-step' }, '3. Epilogue'),
              SL.h('span', { class: 'pb-desc' }, 'leave ; ret (or pop rbp ; ret) restores the frame and pops the return address. Corrupt that saved address and you own rip.')),
            SL.h('div', { class: 'pb-item' },
              SL.h('span', { class: 'pb-step' }, '4. Exploit path'),
              SL.h('span', { class: 'pb-desc' }, 'Canary present? Leak it. PIE on? Leak a pointer. Neither? Overflow straight to the return address and chain gadgets.')))),
        SL.h('div', { class: 'workbench-col' }, outEl)));
  }

  return { view, _annotateAll: annotateAll, _parseLine: parseLine };
})();
