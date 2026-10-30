/* ============================================================
   SecLab · asm-data.js
   Knowledge base for the Assembly Annotator.
   x86 / x86-64 (Intel + AT&T) and ARM64 (AArch64).
   Written for students: plain English, pwn context included.
   ============================================================ */

const ASMDATA = (() => {
  'use strict';

  /* ---------- condition codes (shared by jcc / setcc / cmovcc / b.cond) ---------- */
  const CC = {
    'e': 'equal', 'z': 'equal (zero flag set)',
    'ne': 'not equal', 'nz': 'not equal (zero flag clear)',
    'g': 'greater (signed)', 'nle': 'greater (signed)',
    'ge': 'greater or equal (signed)', 'nl': 'greater or equal (signed)',
    'l': 'less (signed)', 'nge': 'less (signed)',
    'le': 'less or equal (signed)', 'ng': 'less or equal (signed)',
    'a': 'above (unsigned)', 'nbe': 'above (unsigned)',
    'ae': 'above or equal (unsigned)', 'nb': 'above or equal (unsigned)', 'nc': 'no carry (above or equal)',
    'b': 'below (unsigned)', 'nae': 'below (unsigned)', 'c': 'carry set (below)',
    'be': 'below or equal (unsigned)', 'na': 'below or equal (unsigned)',
    's': 'sign flag set (result negative)', 'ns': 'sign flag clear (result non-negative)',
    'o': 'overflow flag set (signed overflow)', 'no': 'overflow flag clear',
    'p': 'parity even', 'pe': 'parity even', 'np': 'parity odd', 'po': 'parity odd',
    'hs': 'above or equal (unsigned, ARM64 alias)', 'lo': 'below (unsigned, ARM64 alias)',
    'mi': 'negative (ARM64 alias)', 'pl': 'non-negative (ARM64 alias)',
    'vs': 'overflow set (ARM64 alias)', 'vc': 'overflow clear (ARM64 alias)',
    'al': 'always (unconditional, ARM64)'
  };

  /* ---------- x86 / x86-64 instructions (Intel syntax names) ---------- */
  /* d = plain-English description, n = extra note (context, ABI, pwn) */
  const X86 = {
    'mov': { c: 'data', d: 'Copy the source into the destination. The destination is overwritten, the source keeps its value.', n: 'Moving a register into itself (mov rax, rax) is a common NOP-sled filler.' },
    'movabs': { c: 'data', d: 'Move a full 64-bit immediate into a register.', n: 'Shellcode uses this to push 8 ASCII bytes of a path in one instruction.' },
    'movzx': { c: 'data', d: 'Copy a small value into a wider register and fill the top bits with zeros (unsigned widen).' },
    'movsx': { c: 'data', d: 'Copy a small value into a wider register and copy the sign bit into the top (signed widen).' },
    'movsxd': { c: 'data', d: 'Sign-extend a 32-bit value into a full 64-bit register. Emitted when int meets long.' },
    'lea': { c: 'data', d: 'Compute an address without touching memory. lea rax, [rbp-0x20] means rax = rbp minus 0x20.', n: 'Also abused for arithmetic: lea rax, [rax+rax*2] multiplies by 3 with no flags changed.' },
    'xchg': { c: 'data', d: 'Swap the two operands.' },
    'push': { c: 'stack', d: 'Grow the stack by 8 bytes (rsp -= 8) and store the value at the new top.', n: 'The saved values live at [rsp], [rsp+8], ... until popped.' },
    'pop': { c: 'stack', d: 'Read the value at the top of the stack into the register and shrink the stack by 8 (rsp += 8).', n: 'pop followed by ret is a ROP gadget: it loads a register with attacker data, then returns.' },
    'pusha': { c: 'stack', d: 'Push all general-purpose registers (32-bit idiom).' },
    'popa': { c: 'stack', d: 'Pop all general-purpose registers (32-bit idiom).' },
    'pushf': { c: 'stack', d: 'Push the flags register onto the stack.' },
    'popf': { c: 'stack', d: 'Pop the flags register off the stack.' },
    'cbw': { c: 'data', d: 'Sign-extend al into ax.' },
    'cwde': { c: 'data', d: 'Sign-extend ax into eax.' },
    'cdqe': { c: 'data', d: 'Sign-extend eax into rax.' },
    'cwd': { c: 'data', d: 'Sign-extend ax into dx:ax to prepare for 16-bit idiv.' },
    'cdq': { c: 'data', d: 'Sign-extend eax into edx:eax to prepare for idiv.' },
    'cqo': { c: 'data', d: 'Sign-extend rax into rdx:rax to prepare for 64-bit idiv.' },
    'add': { c: 'arith', d: 'dst = dst + src. Updates the arithmetic flags.' },
    'sub': { c: 'arith', d: 'dst = dst minus src. Updates the arithmetic flags. cmp is a sub that throws the result away.' },
    'adc': { c: 'arith', d: 'Add with carry: dst = dst + src + carry flag. Used for big-number arithmetic.' },
    'sbb': { c: 'arith', d: 'Subtract with borrow. Big-number arithmetic.' },
    'inc': { c: 'arith', d: 'dst = dst + 1. Sets flags (except carry).' },
    'dec': { c: 'arith', d: 'dst = dst minus 1. Sets flags (except carry).' },
    'neg': { c: 'arith', d: 'dst = minus dst (two-complement negation).' },
    'imul': { c: 'arith', d: 'Signed multiply. Two-operand form: dst = dst * src, low half kept.' },
    'mul': { c: 'arith', d: 'Unsigned multiply of rax by the operand; full result in rdx:rax.' },
    'idiv': { c: 'arith', d: 'Signed divide of rdx:rax by the operand. Quotient in rax, remainder in rdx.', n: 'A zero or overflow here raises SIGFPE (integer divide error).' },
    'div': { c: 'arith', d: 'Unsigned divide of rdx:rax by the operand.' },
    'cmp': { c: 'logic', d: 'Subtract src from dst and throw the result away: only the flags survive. The next conditional jump reads them.' },
    'test': { c: 'logic', d: 'Bitwise AND of the two operands, result discarded, flags kept. test rax, rax is the idiomatic zero / nonzero check.' },
    'and': { c: 'logic', d: 'dst = dst AND src, bit by bit. Used for masking.' },
    'or': { c: 'logic', d: 'dst = dst OR src, bit by bit. Used for combining flag bits.' },
    'xor': { c: 'logic', d: 'dst = dst XOR src, bit by bit.', n: 'xor reg, reg is the classic zeroing idiom: shorter encoding than mov reg, 0. xor with a key is also the core of shellcode encoders.' },
    'not': { c: 'logic', d: 'Flip every bit of the operand (bitwise NOT).' },
    'shl': { c: 'logic', d: 'Shift bits left. Each position multiplies by 2: shl rax, 3 means rax * 8.' },
    'sal': { c: 'logic', d: 'Shift arithmetic left (same as shl).' },
    'shr': { c: 'logic', d: 'Shift bits right, filling with zeros (unsigned divide by powers of 2).' },
    'sar': { c: 'logic', d: 'Shift bits right, copying the sign bit (signed divide by powers of 2).' },
    'rol': { c: 'logic', d: 'Rotate bits left: bits leaving the top re-enter at the bottom.' },
    'ror': { c: 'logic', d: 'Rotate bits right.' },
    'jmp': { c: 'flow', d: 'Unconditional jump: rip = target.' },
    'call': { c: 'flow', d: 'Push the address of the next instruction (the return address), then jump to the target.', n: 'Overwriting the saved return address between a call and its ret is the classic stack overflow.' },
    'ret': { c: 'flow', d: 'Pop the return address into rip and jump there.', n: 'If you control the top of the stack here, you control execution. This single instruction is what ROP chains pivot on.' },
    'leave': { c: 'flow', d: 'Tear down the frame: rsp = rbp, then pop rbp. Shorthand for the standard epilogue.' },
    'enter': { c: 'flow', d: 'Build a stack frame (compilers use push rbp + mov rbp, rsp instead).' },
    'loop': { c: 'flow', d: 'Decrement rcx and jump back if it is not zero.' },
    'nop': { c: 'flow', d: 'Do nothing. Padding, alignment, or a patch placeholder.', n: 'Long runs of NOPs (a NOP sled) let injected code survive imprecise landings.' },
    'endbr64': { c: 'flow', d: 'Intel CET marker: this address is a legal indirect-branch target. Hardening from modern compilers.', n: 'Not a security boundary for your exploits: ignore it unless studying CET itself.' },
    'endbr32': { c: 'flow', d: '32-bit Intel CET indirect-branch marker.' },
    'ud2': { c: 'flow', d: 'Trigger an illegal-instruction trap. The compiler emits this for unreachable code (after noreturn calls).' },
    'hlt': { c: 'flow', d: 'Halt the CPU until the next interrupt (kernel only).' },
    'int': { c: 'sys', d: 'Software interrupt. int 0x80 is the legacy 32-bit Linux syscall entry: number in eax, args in ebx, ecx, edx, esi, edi.', n: 'On 64-bit systems int 0x80 still works for 32-bit programs and is common in shellcodes.' },
    'int3': { c: 'sys', d: 'Debug breakpoint trap (what gdb uses under the hood).' },
    'syscall': { c: 'sys', d: 'The 64-bit Linux kernel entry. Number in rax; arguments in rdi, rsi, rdx, r10, r8, r9.', n: 'Note the 4th argument uses r10, not rcx: the kernel clobbers rcx and r11.' },
    'sysenter': { c: 'sys', d: 'Fast 32-bit syscall entry (replaced by syscall on 64-bit).' },
    'rdtsc': { c: 'sys', d: 'Read the timestamp counter into edx:eax. Timing attacks and shellcode alignment.' },
    'cpuid': { c: 'sys', d: 'CPU identification: vendor, features. Also acts as a barrier.' },
    'movsb': { c: 'string', d: 'Copy one byte from [rsi] to [rdi] and advance both pointers.' },
    'movsw': { c: 'string', d: 'Copy one 16-bit word from [rsi] to [rdi] and advance both.' },
    'movsd': { c: 'string', d: 'Copy one 32-bit dword from [rsi] to [rdi] and advance both.' },
    'movsq': { c: 'string', d: 'Copy one 64-bit qword from [rsi] to [rdi] and advance both.' },
    'stosb': { c: 'string', d: 'Store al at [rdi] and advance. With rep this is memset.' },
    'stosd': { c: 'string', d: 'Store eax at [rdi] and advance.' },
    'stosq': { c: 'string', d: 'Store rax at [rdi] and advance.' },
    'lodsb': { c: 'string', d: 'Load the byte at [rsi] into al and advance.' },
    'lodsd': { c: 'string', d: 'Load the dword at [rsi] into eax and advance.' },
    'scasb': { c: 'string', d: 'Compare al with the byte at [rdi] and advance. repne scasb is how strlen is written in assembly.' },
    'scasd': { c: 'string', d: 'Compare eax with the dword at [rdi] and advance.' },
    'cmpsb': { c: 'string', d: 'Compare bytes at [rsi] and [rdi], advance both. repz cmpsb is memcmp.' },
    'rep': { c: 'string', d: 'Repeat the string instruction that follows, using rcx as the counter.', n: 'rep movsb with rcq (sic) rcx set is memcpy; rep stosb is memset.' },
    'repe': { c: 'string', d: 'Repeat while the zero flag says equal and rcx is not zero.' },
    'repz': { c: 'string', d: 'Repeat while equal (same as repe).' },
    'repne': { c: 'string', d: 'Repeat while not equal and rcx is not zero.' },
    'repnz': { c: 'string', d: 'Repeat while not equal (same as repne).' },
    'cld': { c: 'string', d: 'Clear the direction flag: string operations walk forward (up).' },
    'std': { c: 'string', d: 'Set the direction flag: string operations walk backward.' },
    'in': { c: 'io', d: 'Read from an I/O port (kernel / driver land).' },
    'out': { c: 'io', d: 'Write to an I/O port.' },
    /* SSE / common compiler output */
    'movdqa': { c: 'sse', d: 'Move 128 bits between xmm registers and aligned memory.' },
    'movdqu': { c: 'sse', d: 'Move 128 bits, no alignment requirement (struct copies, string ops).' },
    'movaps': { c: 'sse', d: 'Move 128 bits of packed floats, aligned.' },
    'movups': { c: 'sse', d: 'Move 128 bits of packed floats, unaligned.' },
    'pxor': { c: 'sse', d: 'Bitwise XOR of xmm registers. pxor xmm0, xmm0 zeroes a vector register.' },
    'cvtsi2sd': { c: 'sse', d: 'Convert an integer to a double (int to float bridge).' },
    'cvttsd2si': { c: 'sse', d: 'Convert a double to an integer with truncation.' },
    'movsd': { c: 'sse', d: 'Move a scalar double (the bottom 64 bits of an xmm register).' },
    'movss': { c: 'sse', d: 'Move a scalar float (the bottom 32 bits of an xmm register).' },
    'addsd': { c: 'sse', d: 'Add two scalar doubles.' },
    'mulsd': { c: 'sse', d: 'Multiply two scalar doubles.' },
    'divsd': { c: 'sse', d: 'Divide two scalar doubles.' },
    'ucomisd': { c: 'sse', d: 'Compare two scalar doubles and set flags (the float version of cmp).' },
    'xorps': { c: 'sse', d: 'XOR packed floats (zeroing idiom for floats).' }
  };

  /* ---------- ARM64 / AArch64 instructions ---------- */
  const ARM64 = {
    'mov': { c: 'data', d: 'Copy a register or a small immediate (w = 32-bit, x = 64-bit form).' },
    'movz': { c: 'data', d: 'Load a 16-bit immediate into a register, zero-extending the rest.', n: 'movz + movk pairs build 64-bit constants like a "/bin/sh" string in two instructions.' },
    'movk': { c: 'data', d: 'Insert a 16-bit immediate into a chosen lane, keeping the other bits.' },
    'movn': { c: 'data', d: 'Load the bitwise NOT of a 16-bit immediate (quick way to get -1).' },
    'add': { c: 'arith', d: 'dst = src1 + src2 (register, immediate or shifted register).' },
    'adds': { c: 'arith', d: 'Add and set the flags. The s suffix is what makes later b.cond work.' },
    'sub': { c: 'arith', d: 'dst = src1 minus src2.' },
    'subs': { c: 'arith', d: 'Subtract and set the flags.' },
    'cmp': { c: 'arith', d: 'Compare: alias of subs with the zero register. Only flags change.' },
    'cmn': { c: 'arith', d: 'Compare negative: alias of adds with the zero register.' },
    'mul': { c: 'arith', d: 'Multiply two registers.' },
    'madd': { c: 'arith', d: 'Multiply and add: dst = a + b * c in one instruction.' },
    'sdiv': { c: 'arith', d: 'Signed integer division.' },
    'udiv': { c: 'arith', d: 'Unsigned integer division.' },
    'and': { c: 'logic', d: 'Bitwise AND (sets flags in the ands form).' },
    'ands': { c: 'logic', d: 'Bitwise AND and set flags.' },
    'orr': { c: 'logic', d: 'Bitwise OR (how immediates and masks get combined).' },
    'eor': { c: 'logic', d: 'Bitwise XOR (ARM64 spelling of xor).' },
    'lsl': { c: 'logic', d: 'Logical shift left (multiply by powers of 2).' },
    'lsr': { c: 'logic', d: 'Logical shift right (unsigned divide by powers of 2).' },
    'asr': { c: 'logic', d: 'Arithmetic shift right (signed divide by powers of 2).' },
    'ldr': { c: 'mem', d: 'Load from memory: ldr x0, [sp, #8] reads 8 bytes at sp + 8 into x0.' },
    'ldrb': { c: 'mem', d: 'Load a byte, zero-extended.' },
    'ldrh': { c: 'mem', d: 'Load a halfword (2 bytes).' },
    'ldrsw': { c: 'mem', d: 'Load a 32-bit value, sign-extended to 64 bits.' },
    'str': { c: 'mem', d: 'Store a register to memory.' },
    'strb': { c: 'mem', d: 'Store the low byte of a register.' },
    'strh': { c: 'mem', d: 'Store the low halfword.' },
    'ldp': { c: 'mem', d: 'Load a pair of registers from memory.', n: 'ldp x29, x30, [sp], #16 is half of the classic ARM64 epilogue.' },
    'stp': { c: 'mem', d: 'Store a pair of registers to memory.', n: 'stp x29, x30, [sp, #-16]! is the classic ARM64 prologue: save frame pointer and link register while allocating the frame.' },
    'b': { c: 'flow', d: 'Unconditional branch (jump).' },
    'bl': { c: 'flow', d: 'Branch with link: the ARM64 call. The return address lands in x30 (LR).' },
    'blr': { c: 'flow', d: 'Branch with link to a register: an indirect call through a function pointer.', n: 'If you control the register, you control execution: the ARM64 equivalent of call rax.' },
    'br': { c: 'flow', d: 'Branch to a register: an indirect jump.', n: 'ROP and ret2libc pivot on this.' },
    'ret': { c: 'flow', d: 'Return: jump to the address in x30 (LR) by default.', n: 'Overwrite the saved x30 on the stack and you control the return: the ARM64 stack overflow target.' },
    'cbz': { c: 'flow', d: 'Compare with zero and branch if zero: a short if (x == 0).' },
    'cbnz': { c: 'flow', d: 'Compare with zero and branch if not zero.' },
    'tbz': { c: 'flow', d: 'Test a single bit and branch if it is zero.' },
    'tbnz': { c: 'flow', d: 'Test a single bit and branch if it is one.' },
    'adr': { c: 'data', d: 'Compute the address of a nearby label into a register.' },
    'adrp': { c: 'data', d: 'Load the 4KB-aligned page address of a label; the next add adds the offset.', n: 'adrp + add is the ARM64 version of RIP-relative addressing: a PIE indicator.' },
    'svc': { c: 'sys', d: 'Supervisor call: the ARM64 syscall instruction (svc #0). Number in x8, arguments in x0 to x5.' },
    'msr': { c: 'sys', d: 'Write a system register (privileged or per-thread state).' },
    'mrs': { c: 'sys', d: 'Read a system register. mrs x0, tpidr_el0 reads the thread pointer, where glibc keeps the stack canary on ARM64.' },
    'nop': { c: 'flow', d: 'Do nothing.' },
    'paciasp': { c: 'flow', d: 'Sign the return address with a PAC key (pointer authentication, ARM64 hardening).' },
    'autiasp': { c: 'flow', d: 'Authenticate the signed return address before ret (pointer authentication).' },
    'pacibsp': { c: 'flow', d: 'Sign the return address with the B key (pointer authentication).' },
    'btijmp': { c: 'flow', d: 'Branch target identification marker (ARM64 CET equivalent).' }
  };

  /* ---------- register knowledge ---------- */
  const REG_X64 = {
    rax: 'Return value. Also the syscall number holder.', rdi: '1st argument. Syscall arg 1.', rsi: '2nd argument. Syscall arg 2.',
    rdx: '3rd argument. Syscall arg 3.', rcx: '4th argument in the C ABI. NOT the 4th syscall argument (that is r10).',
    r8: '5th argument. Syscall arg 5.', r9: '6th argument. Syscall arg 6.', r10: '4th syscall argument. Scratch in the C ABI.',
    r11: 'Scratch register (the kernel also clobbers it on syscall).', rsp: 'Stack pointer. Points at the return address during ret.',
    rbp: 'Frame pointer. Callee-saved. Locals live at negative offsets from it.', rbx: 'Callee-saved: a function must restore it before returning.',
    r12: 'Callee-saved.', r13: 'Callee-saved.', r14: 'Callee-saved.', r15: 'Callee-saved.'
  };
  const REG_I386 = {
    eax: 'Return value. Also the int 0x80 syscall number.', ebx: 'Callee-saved. int 0x80 syscall arg 1.', ecx: 'Scratch. int 0x80 arg 3.',
    edx: 'Scratch. int 0x80 arg 2.', esi: 'Callee-saved. int 0x80 arg 5.', edi: 'Callee-saved. int 0x80 arg 4.',
    esp: 'Stack pointer.', ebp: 'Frame pointer.'
  };
  const REG_ARM64 = {
    x0: '1st argument and return value.', x1: '2nd argument.', x2: '3rd argument.', x3: '4th argument.', x4: '5th argument.',
    x5: '6th argument.', x6: '7th argument.', x7: '8th argument.', x8: 'Syscall number (also indirect return slot).',
    x9: 'Scratch (local temporaries).', x10: 'Scratch.', x11: 'Scratch.', x12: 'Scratch.', x13: 'Scratch.', x14: 'Scratch.', x15: 'Scratch.',
    x16: 'IP0: intra-procedure scratch, PLT veneers use it.', x17: 'IP1: PLT scratch.', x18: 'Platform register (TLS / shadow call stack). Never use.',
    x29: 'Frame pointer (FP).', x30: 'Link register (LR): the return address. The stack overflow target on ARM64.',
    sp: 'Stack pointer.', xzr: 'The hardwired zero register (reads as 0, writes vanish).', wzr: '32-bit zero register.'
  };

  /* map any sub-register to its 64-bit family (x86) */
  const SUBREG = (() => {
    const m = {};
    ['ax', 'bx', 'cx', 'dx', 'sp', 'bp', 'si', 'di'].forEach(r => {
      const R = 'r' + r;                       // rax, rbx, ...
      m[r] = R; m['e' + r] = R; m[R] = R;      // ax, eax, rax -> rax
    });
    ['al', 'bl', 'cl', 'dl'].forEach(r => m[r] = 'r' + r[0] + 'x');
    ['ah', 'bh', 'ch', 'dh'].forEach(r => m[r] = 'r' + r[0] + 'x');
    ['sil', 'dil', 'spl', 'bpl'].forEach(r => m[r] = 'r' + r.slice(0, -1));
    for (let i = 8; i <= 15; i++) {
      m['r' + i] = 'r' + i; m['r' + i + 'd'] = 'r' + i; m['r' + i + 'w'] = 'r' + i; m['r' + i + 'b'] = 'r' + i;
    }
    return m;
  })();

  /* arm64 sub-register: wN -> xN */
  const armReg = r => (/^w(\d+)$/.exec(r) ? 'x' + RegExp.$1 : r);

  /* ---------- Linux syscall tables ---------- */
  const SC_X64 = {
    0: 'read(fd, buf, count)', 1: 'write(fd, buf, count)', 2: 'open(path, flags, mode)', 3: 'close(fd)',
    4: 'stat(path, statbuf)', 5: 'fstat(fd, statbuf)', 6: 'lstat(path, statbuf)', 7: 'poll(fds, n, timeout)',
    8: 'lseek(fd, offset, whence)', 9: 'mmap(addr, len, prot, flags, fd, off)', 10: 'mprotect(addr, len, prot)',
    11: 'munmap(addr, len)', 12: 'brk(addr)  // grow the heap', 13: 'rt_sigaction(...)', 16: 'ioctl(fd, req, arg)',
    17: 'pread64(...)', 21: 'access(path, mode)  // does the file exist / is it readable', 22: 'pipe(fds)',
    32: 'dup(oldfd)', 33: 'dup2(oldfd, newfd)', 35: 'nanosleep(req, rem)', 39: 'getpid()',
    41: 'socket(domain, type, protocol)', 42: 'connect(fd, addr, len)', 43: 'accept(fd, addr, len)',
    44: 'sendto(fd, buf, len, flags, addr, alen)', 45: 'recvfrom(...)', 49: 'bind(fd, addr, len)', 50: 'listen(fd, backlog)',
    56: 'clone(flags, ...)', 57: 'fork()', 58: 'vfork()', 59: 'execve(path, argv, envp)',
    60: 'exit(code)', 61: 'wait4(pid, status, options, rusage)', 62: 'kill(pid, sig)', 63: 'uname(buf)',
    72: 'fcntl(fd, cmd, arg)', 78: 'getdents(fd, buf, len)  // list directory entries', 79: 'getcwd(buf, size)',
    80: 'chdir(path)', 83: 'mkdir(path, mode)', 84: 'rmdir(path)', 87: 'unlink(path)', 88: 'rename(old, new)',
    89: 'readlink(path, buf, size)', 90: 'chmod(path, mode)', 92: 'chown(path, uid, gid)',
    96: 'gettimeofday(tv, tz)', 101: 'ptrace(req, pid, addr, data)  // what debuggers use', 102: 'getuid()',
    105: 'setuid(uid)', 106: 'setgid(gid)', 110: 'getppid()', 113: 'settimeofday(tv, tz)',
    165: 'mount(...)', 166: 'umount(...)', 186: 'gettid()',
    218: 'set_tid_address(...)', 231: 'exit_group(code)  // what libc exit() really calls', 232: 'epoll_wait(...)',
    257: 'openat(dirfd, path, flags, mode)', 262: 'newfstatat(...)', 263: 'unlinkat(dirfd, path, flags)',
    302: 'prlimit64(...)', 318: 'getrandom(buf, len, flags)'
  };

  const SC_I386 = {
    1: 'exit(code)', 2: 'fork()', 3: 'read(fd, buf, count)', 4: 'write(fd, buf, count)',
    5: 'open(path, flags, mode)', 6: 'close(fd)', 7: 'waitpid(pid, status, options)', 8: 'creat(path, mode)',
    10: 'unlink(path)', 11: 'execve(path, argv, envp)', 12: 'chdir(path)', 13: 'time(t)',
    20: 'getpid()', 24: 'getuid()', 33: 'access(path, mode)', 37: 'kill(pid, sig)',
    41: 'dup(fd)', 41.5: null, 42: 'pipe(fds)', 45: 'brk(addr)', 47: 'getgid()',
    54: 'ioctl(fd, req, arg)', 63: 'dup2(oldfd, newfd)', 65: 'getppid()', 75: 'setrlimit(...)',
    85: 'readlink(path, buf, size)', 90: 'chmod(path, mode)', 91: 'fchmod(fd, mode)', 92: 'chown(path, uid, gid)',
    106: 'stat(path, buf)', 120: 'clone(flags, ...)', 122: 'uname(buf)', 125: 'mprotect(addr, len, prot)',
    140: '_llseek(...)', 141: 'getdents(fd, buf, len)', 145: 'readv(...)', 146: 'writev(...)',
    183: 'getcwd(buf, size)', 192: 'mmap2(addr, len, prot, flags, fd, pgoff)', 194: 'ftruncate64(...)',
    195: 'stat64(path, buf)', 197: 'fstat64(fd, buf)', 224: 'getdents64(fd, buf, len)', 252: 'exit_group(code)'
  };
  delete SC_I386[41.5];

  const SC_ARM64 = {
    17: 'getcwd(buf, size)', 21: 'ioctl(fd, req, arg)', 24: 'dup3(oldfd, newfd, flags)', 29: 'ioctl(...)',
    34: 'mkdirat(dirfd, path, mode)', 35: 'unlinkat(dirfd, path, flags)', 40: 'mount(...)', 48: 'faccessat(...)',
    49: 'chdir(path)', 56: 'openat(dirfd, path, flags, mode)', 57: 'close(fd)', 59: 'pipe2(fds, flags)',
    62: 'lseek(fd, off, whence)', 63: 'read(fd, buf, count)', 64: 'write(fd, buf, count)',
    65: 'readv(...)', 66: 'writev(...)', 67: 'pread64(...)', 68: 'pwrite64(...)', 78: 'readlinkat(...)',
    79: 'newfstatat(...)', 80: 'fstat(fd, buf)', 93: 'exit(code)', 94: 'exit_group(code)',
    96: 'set_tid_address(...)', 98: 'futex(...)', 129: 'kill(pid, sig)', 131: 'tgkill(...)',
    160: 'uname(buf)', 167: 'prctl(...)', 172: 'getpid()', 173: 'getppid()', 174: 'getuid()',
    175: 'geteuid()', 176: 'getgid()', 198: 'socket(domain, type, protocol)', 203: 'connect(fd, addr, len)',
    206: 'sendto(fd, buf, len, flags, addr, alen)', 207: 'recvfrom(...)', 214: 'brk(addr)',
    215: 'munmap(addr, len)', 220: 'clone(flags, ...)', 221: 'execve(path, argv, envp)',
    222: 'mmap(addr, len, prot, flags, fd, off)', 226: 'mprotect(addr, len, prot)',
    260: 'wait4(pid, status, options, rusage)', 281: 'execveat(...)', 291: 'stat(...) asm-generic name for newfstatat family'
  };

  /* ---------- dangerous libc calls (red = always a problem) ---------- */
  const UNSAFE_LIBC = {
    'gets': 'gets() has NO length limit. Every call is an automatic stack overflow (removed from modern libc, still seen in old challenges).',
    'strcpy': 'strcpy() copies until a NUL byte: if the source is longer than the destination buffer, it overflows.',
    'strcat': 'strcat() appends with no bound check: same overflow risk as strcpy.',
    'sprintf': 'sprintf() writes into a buffer with no size limit. Also a format-string risk when the format is attacker-controlled.',
    'vsprintf': 'Same as sprintf via a va_list.',
    'scanf': 'scanf("%s") reads unbounded input into the buffer. Use a width like %31s.',
    'fscanf': 'Same unbounded %s risk as scanf.',
    'system': 'system() runs a command through /bin/sh. Control the argument and you have instant RCE.',
    'popen': 'popen() runs a command and pipes it: same as system plus I/O.',
    'alloca': 'alloca() allocates on the stack with no free; large sizes smash frames.'
  };

  /* ---------- context-dependent calls (amber = verify before trusting) ---------- */
  const WATCH_LIBC = {
    'printf': 'printf() is fine with a fixed format string. If user input is the FIRST argument, that is a format string bug (read/write memory with %x, %p, %n).',
    'fprintf': 'Same format-string rule as printf: the format must be a constant.',
    'read': 'read(fd, buf, n): compare n with the size of the destination buffer. read into a stack buffer with a large n is an overflow.',
    'memcpy': 'memcpy(dst, src, n): fine unless n is bigger than dst.',
    'execve': 'execve() replaces the process. Normal in shells; if you control its arguments in a target, that is full RCE.',
    '__isoc99_scanf': 'scanf() from modern glibc: same unbounded %s risk as scanf.',
    'snprintf': 'snprintf() is bounded (safer sibling of sprintf): check the bound matches the buffer.'
  };

  /* ---------- ABI quick references ---------- */
  const ABI = {
    x64: {
      title: 'System V AMD64 (Linux, macOS)',
      rows: [
        ['rdi', '1st argument', 'no'], ['rsi', '2nd argument', 'no'], ['rdx', '3rd argument', 'no'],
        ['rcx', '4th argument (C ABI)', 'no'], ['r8', '5th argument', 'no'], ['r9', '6th argument', 'no'],
        ['rax', 'return value', 'no'], ['r10', '4th syscall argument', 'no'],
        ['rsp', 'stack pointer', 'must'], ['rbp', 'frame pointer', 'must'],
        ['rbx, r12, r13, r14, r15', 'callee-saved scratch', 'must']
      ],
      note: 'The first 6 integer/pointer arguments ride in registers; the 7th and beyond are pushed on the stack at [rsp+8] and up at the moment of call. Floats go in xmm0 to xmm7.'
    },
    i386: {
      title: 'i386 cdecl (32-bit Linux)',
      rows: [['eax', 'return value', 'no'], ['ecx, edx', 'scratch', 'no'], ['ebx, esi, edi', 'callee-saved', 'must'], ['esp', 'stack pointer', 'must'], ['ebp', 'frame pointer', 'must']],
      note: 'ALL arguments are pushed on the stack, right to left. At function entry, [esp+4] is arg 1, [esp+8] is arg 2. The caller cleans the stack.'
    },
    arm64: {
      title: 'AAPCS64 (ARM64 / AArch64)',
      rows: [
        ['x0 to x7', 'arguments 1 to 8', 'no'], ['x0', 'return value', 'no'], ['x8', 'syscall number', 'no'],
        ['x9 to x15', 'scratch (caller-saved)', 'no'], ['x16, x17', 'PLT / veneer scratch (IP0, IP1)', 'no'],
        ['x18', 'platform register: never touch', 'must'], ['x29', 'frame pointer (FP)', 'must'],
        ['x30', 'link register (LR): return address', 'must'], ['sp', 'stack pointer', 'must']
      ],
      note: 'The first 8 arguments fit in registers. There is no dedicated link register push in the ABI: the prologue decides whether to spill x30. If a leaf function calls nothing, it can skip saving x30 entirely, which is why small ARM64 functions have no frame.'
    }
  };

  /* ---------- worked examples ---------- */
  const EXAMPLES = [
    {
      id: 'ret2win',
      label: 'Overflow classic (no canary)',
      code:
`vuln:
    push    rbp
    mov     rbp, rsp
    sub     rsp, 0x40
    lea     rax, [rbp-0x40]
    mov     rsi, rax
    lea     rdi, [rip+0xe8a]        # "%s"
    mov     eax, 0
    call    printf@plt
    lea     rax, [rbp-0x40]
    mov     rdi, rax
    mov     eax, 0
    call    gets@plt                # the bug: unbounded read
    nop
    leave
    ret`
    },
    {
      id: 'canary',
      label: 'Canary + PIE (objdump)',
      code:
`0000000000401187 <main>:
  401187:  f3 0f 1e fa             endbr64
  40118b:  55                      push   rbp
  40118c:  48 89 e5                mov    rbp,rsp
  40118f:  48 83 ec 50             sub    rsp,0x50
  401193:  64 48 8b 04 25 28 00    mov    rax,QWORD PTR fs:0x28
  40119a:  00 00
  40119c:  48 89 45 f8             mov    QWORD PTR [rbp-0x8],rax
  4011a0:  48 8d 3d e9 0e 00 00    lea    rdi,[rip+0xee9]
  4011a7:  e8 e4 fe ff ff          call   401090 <printf@plt>
  4011ac:  b8 00 00 00 00          mov    eax,0x0
  4011b1:  48 8b 55 f8             mov    rdx,QWORD PTR [rbp-0x8]
  4011b5:  64 48 33 14 25 28 00    xor    rdx,QWORD PTR fs:0x28
  4011bc:  00 00
  4011be:  74 05                   je     4011c5 <main+0x3e>
  4011c0:  e8 4b 0f 00 00          call   402110 <__stack_chk_fail@plt>
  4011c5:  c9                      leave
  4011c6:  c3                      ret`
    },
    {
      id: 'helloworld',
      label: 'Hello world (raw syscalls)',
      code:
`global _start
section .text
_start:
    mov     rax, 1                  ; sys_write
    mov     rdi, 1                  ; fd = stdout
    lea     rsi, [rel msg]
    mov     rdx, 13                 ; length
    syscall
    mov     rax, 60                 ; sys_exit
    xor     rdi, rdi
    syscall

section .rodata
msg:    db      "hello pwn! ", 10`
    },
    {
      id: 'shellcode',
      label: 'execve("/bin//sh") shellcode',
      code:
`    xor     rdx, rdx                ; arg3 = NULL
    push    rdx                     ; string terminator
    movabs  rax, 0x68732f2f6e69622f ; "/bin//sh"
    push    rax
    mov     rdi, rsp                ; arg1 = pointer to the string
    xor     rsi, rsi                ; arg2 = NULL
    push    59
    pop     rax                     ; rax = 59 (execve)
    syscall`
    },
    {
      id: 'int80',
      label: '32-bit int 0x80 shellcode',
      code:
`    xor     eax, eax
    push    eax                     ; NUL terminator
    push    0x68732f2f              ; "//sh"
    push    0x6e69622f              ; "/nib"
    mov     ebx, esp                ; path
    mov     al, 11                  ; sys_execve
    xor     ecx, ecx                ; argv
    xor     edx, edx                ; envp
    int     0x80`
    },
    {
      id: 'rop',
      label: 'ROP gadgets',
      code:
`0x00000000004012f3: pop rdi ; ret
0x00000000004012f0: pop rsi ; pop r15 ; ret
0x000000000040101a: ret
0x00000000004011d2: leave ; ret
0x0000000000401040: syscall
0x0000000000401041: ret`
    },
    {
      id: 'arm64',
      label: 'ARM64 function + syscall',
      code:
`fun:
    stp     x29, x30, [sp, #-32]!
    mov     x29, sp
    mov     w8, #64                 ; sys_write
    mov     x0, #1                  ; fd = stdout
    adr     x1, msg
    mov     x2, #12                 ; length
    svc     #0
    ldp     x29, x30, [sp], #32
    ret`
    }
  ];

  /* ---------- assembler directives we understand ---------- */
  const DIRECTIVES = {
    '.text': 'The code section: executable bytes live here.',
    '.data': 'Initialized writable data.',
    '.rodata': 'Read-only data: strings and constants. Writing here faults.',
    '.bss': 'Uninitialized data: zero bytes at load, no file size.',
    '.globl': 'Export this symbol so the linker (and other files) can see it.',
    '.global': 'Export this symbol so the linker can see it (alternate spelling).',
    '.string': 'Define a NUL-terminated string constant.',
    '.asciz': 'Define a NUL-terminated string constant (same as .string).',
    '.ascii': 'Define raw string bytes WITHOUT the terminating NUL.',
    '.byte': 'Define constant bytes.',
    '.word': 'Define 2-byte constants.',
    '.long': 'Define 4-byte constants.',
    '.quad': 'Define 8-byte constants.',
    '.short': 'Define 2-byte constants.',
    '.section': 'Switch to (or create) a section.',
    '.type': 'Symbol metadata (function vs object).',
    '.size': 'Symbol size metadata. Ignore when reading.',
    '.align': 'Pad to an alignment boundary.',
    '.balign': 'Pad to an alignment boundary.',
    '.equ': 'Define an assembly-time constant.',
    '.extern': 'Declare a symbol defined in another file.',
    '.cfi_startproc': 'Call-frame debugging metadata start. Safe to ignore.',
    '.cfi_endproc': 'Call-frame debugging metadata end. Safe to ignore.',
    '.cfi_def_cfa_offset': 'Call-frame debugging metadata. Safe to ignore.',
    '.cfi_offset': 'Call-frame debugging metadata. Safe to ignore.',
    '.intel_syntax': 'Switch disassembly to Intel syntax.',
    '.att_syntax': 'Switch disassembly to AT&T syntax.',
    'section': 'Switch section (NASM spelling, no dot).',
    'global': 'Export a symbol (NASM spelling).',
    'db': 'Define bytes (NASM). db "text", 10 stores the string plus a newline.',
    'dw': 'Define words (NASM).',
    'dd': 'Define dwords (NASM).',
    'dq': 'Define qwords (NASM).',
    'equ': 'Define a constant (NASM).',
    'times': 'Repeat a definition: times 90 db 0x90 is a NOP sled.'
  };

  return { CC, X86, ARM64, REG_X64, REG_I386, REG_ARM64, SUBREG, armReg, SC_X64, SC_I386, SC_ARM64, UNSAFE_LIBC, WATCH_LIBC, ABI, EXAMPLES, DIRECTIVES };
})();
