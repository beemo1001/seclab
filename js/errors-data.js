/* ============================================================
   SecLab · errors-data.js
   The Linux Error Reference knowledge base.
   Every entry explains what the error MEANS, why it happens,
   how to diagnose it yourself, and how to fix it for real.
   The goal is diagnosis skill, not copy-paste commands.
   ============================================================ */

const ERRDB = (() => {
  'use strict';

  const CATS = [
    { id: 'files', name: 'Filesystem & Paths', icon: 'hard-drive' },
    { id: 'perms', name: 'Permissions & Identity', icon: 'lock' },
    { id: 'exec', name: 'Execution & Binaries', icon: 'zap' },
    { id: 'proc', name: 'Processes & Signals', icon: 'activity' },
    { id: 'net', name: 'Networking', icon: 'network' },
    { id: 'ssh', name: 'SSH & Remote', icon: 'key' },
    { id: 'pkg', name: 'Packages (apt/dpkg)', icon: 'package' },
    { id: 'build', name: 'Compilation & Toolchain', icon: 'compile' },
    { id: 'shell', name: 'Shell & Scripting', icon: 'terminal' },
    { id: 'docker', name: 'Docker & Containers', icon: 'box' }
  ];

  const ERRORS = [
    /* ================= FILESYSTEM ================= */
    {
      id: 'enoent', err: 'No such file or directory', errno: 2, cat: 'files',
      aka: ['cannot find the file', 'file not found', 'no such file or directory (os error 2)'],
      meaning: 'The kernel looked up a path and it does not exist. Either the path is wrong, the file was moved or deleted, or something the file depends on (like an interpreter or a directory in the path) is missing.',
      causes: [
        'A typo in the path, or the wrong working directory (relative paths depend on where you run the command from)',
        'The file was deleted or renamed after something started using it',
        'A script points at an interpreter that is not installed (see the bad interpreter entry)',
        'The path contains a space or special character that the shell split into two arguments',
        'You are inside a container or chroot and the path exists only on the host'
      ],
      diagnose: [
        { cmd: 'ls -la /full/path/to/file', why: 'Checks the file exists right now, with permissions, and reveals typos' },
        { cmd: 'pwd && realpath relative/path', why: 'Shows where you actually are and where the relative path really points' },
        { cmd: 'ls -la $(dirname /full/path)', why: 'Verifies every directory in the path exists and is searchable (x permission)' }
      ],
      fix: [
        'Use the absolute path, or cd into the directory that contains the file',
        'If the file should exist, find it: find / -name "filename" 2>/dev/null',
        'If a script fails, check its first line (the shebang) actually points at an installed interpreter',
        'Quote paths with spaces: use "/home/me/my folder/file" instead of /home/me/my folder/file'
      ],
      prevent: 'In scripts, check before use: if [ ! -f "$FILE" ]; then echo "missing: $FILE" >&2; exit 1; fi',
      related: ['bad-interpreter', 'missing-so', 'spaces-path'],
      tip: 'Run with strace -e openat ./program 2>&1 | grep ENOENT to see exactly WHICH path the program tried to open. This turns a mystery into a fact in five seconds.'
    },
    {
      id: 'eacces', err: 'Permission denied', errno: 13, cat: 'perms',
      aka: ['access denied', 'permission denied (13)', 'cannot create', 'cannot open', 'cannot remove', 'cannot write', 'cannot read'],
      meaning: 'The file exists, you found it, but the kernel says you are not allowed to do what you asked: read it, write it, execute it, or enter a directory on the way to it.',
      causes: [
        'The rwx bits do not include you: you are neither the owner, nor in the group, nor covered by "other"',
        'You can read a directory but not write to it (or the reverse)',
        'Trying to execute a file that has no execute bit',
        'Read-only mounted filesystem (see the read-only entry)',
        'SELinux or AppArmor blocking access beyond the classic bits'
      ],
      diagnose: [
        { cmd: 'ls -la /path/to/file', why: 'Shows owner, group and the rwx bits' },
        { cmd: 'id', why: 'Shows who you are and which groups you belong to' },
        { cmd: 'namei -l /full/path/to/file', why: 'Lists permissions of EVERY component along the path: the blocked step jumps out' },
        { cmd: 'getenforce', why: 'Tells you if SELinux is enforcing (Enforcing) on systems that use it' }
      ],
      fix: [
        'Your own file without write: chmod u+w file',
        'Someone else\'s file: you need sudo (for the change) or the owner to fix permissions',
        'To execute: chmod +x program (only for things that are actually executable)',
        'Directory you cannot enter: chmod +x on the directory (the x bit on a directory means "may traverse")',
        'SELinux denials: check ausearch -m avc -ts recent for the real reason'
      ],
      prevent: 'Never chmod 777 to "fix" permissions: that is opening the door for every user on the machine. Grant the minimum bit that makes the operation work.',
      related: ['script-not-executable', 'erofs', 'not-in-sudoers', 'lowport'],
      tip: 'Read permission r lets you see contents, x on directories lets you pass through, w lets you change. For "open a file inside a folder" you need x on every folder in the path, not r. That is why namei -l is the fastest diagnosis.'
    },
    {
      id: 'eexist', err: 'File exists', errno: 17, cat: 'files',
      aka: ['cannot create file', 'already exists'],
      meaning: 'You asked to create something that must be unique (a file, a directory, a symlink, a lock) and it is already there. The kernel refuses to silently overwrite.',
      causes: [
        'mkdir on a directory that already exists',
        'ln (hard link) or a lock file created twice',
        'O_CREAT | O_EXCL open calls: an atomic "create only if new" pattern',
        'A previous run of your program crashed and left its lock or output behind'
      ],
      diagnose: [
        { cmd: 'ls -la /path/to/thing', why: 'Confirm it exists and see its age: is it from a crashed run?' },
        { cmd: 'lsof /path/to/thing', why: 'Check if another live process still holds it' }
      ],
      fix: [
        'If the old file is junk: remove it first, or use mkdir -p / ln -f where appropriate',
        'If it is a lock: your program should detect the stale lock and recover, not blindly delete it',
        'In code: open with O_EXCL and handle EEXIST as a normal case, not an error'
      ],
      prevent: 'Treat EEXIST as a signal about state, not a failure: it usually means a previous run did not clean up.',
      related: ['enoent'],
      tip: 'mkdir -p dir creates parents and stays silent if the directory exists. It is almost always what scripts should use instead of mkdir.'
    },
    {
      id: 'eisdir', err: 'Is a directory', errno: 21, cat: 'files',
      aka: ['read: is a directory'],
      meaning: 'You tried to use a directory as if it were a file: cat it, write to it, or pass it where a file path was expected.',
      causes: [
        'cat myfolder instead of cat myfile',
        'cp file dir/ newname (a stray space makes the destination a directory plus a second argument)',
        'A glob expanded to a directory: cat * when a subfolder exists',
        'Passing a directory to a program that opens files with write mode'
      ],
      diagnose: [
        { cmd: 'file /path/to/thing', why: 'Definitively says directory, symlink, text, ELF, and more' },
        { cmd: 'ls -lad /path/to/thing', why: 'The d in the permission column means directory' }
      ],
      fix: [
        'Point the command at a file inside the directory',
        'For globs: use find /path -maxdepth 1 -type f instead of * when you only want files',
        'In scripts, guard with [ -f "$x" ] && ... or [ -d "$x" ]'
      ],
      prevent: 'The file command plus -f / -d tests in scripts kill this whole class of mistakes.',
      related: ['enotdir'],
      tip: 'The companion error is ENOTDIR (Not a directory): you treated a FILE like a folder, for example ls file.txt/sub. The pair tells you which side of the path you got wrong.'
    },
    {
      id: 'enotdir', err: 'Not a directory', errno: 20, cat: 'files',
      aka: ['not a directory'],
      meaning: 'A component in the middle of your path is a file, not a folder. The kernel walked the path, hit a plain file, and was asked to keep walking through it.',
      causes: [
        'A typo: /etc/passwd/extra treats the file passwd as a folder',
        'A missing slash between a filename and the next part',
        'A path variable that contains a filename when a directory was expected'
      ],
      diagnose: [
        { cmd: 'namei -l /full/path', why: 'Walks each component and shows exactly which one is a file' }
      ],
      fix: [
        'Find the component that should be a directory and correct the path',
        'If a variable builds the path: echo "$BASE/$SUB" to see the real string'
      ],
      prevent: 'Build paths with variables, not string concatenation across many lines, and echo them while debugging.',
      related: ['eisdir', 'enoent'],
      tip: 'ENOTDIR almost always means "there is a typo or a missing separator somewhere before this point in the path". namei finds it instantly.'
    },
    {
      id: 'enospc', err: 'No space left on device', errno: 28, cat: 'files',
      aka: ['disk full', 'cannot write: no space left'],
      meaning: 'The filesystem is full (or you hit a quota): writes fail immediately. On Linux this often happens when INODES run out even with free space, so the two variants look identical from the error text.',
      causes: [
        'The disk is genuinely full: logs, caches, docker images, core dumps',
        'Out of inodes: millions of tiny files (sessions, cache shards, maildirs)',
        'A filesystem quota for your user is exceeded (df shows space, quota says no)',
        'A size-limited tmpfs (/tmp) or a small container layer'
      ],
      diagnose: [
        { cmd: 'df -h', why: 'Human-readable space per filesystem: look for 100% Use%' },
        { cmd: 'df -i', why: 'Inode usage: IUse% at 100% with free space is the tiny-files scenario' },
        { cmd: 'sudo du -xh --max-depth=2 / | sort -rh | head -20', why: 'Finds the biggest directories from the root, staying on one filesystem' },
        { cmd: 'quota -s 2>/dev/null || sudo repquota -a | head', why: 'Shows user quotas on systems that use them' }
      ],
      fix: [
        'Clear the biggest offender: usually journal logs (sudo journalctl --vacuum-size=200M), apt cache (sudo apt clean), or docker (docker system prune)',
        'Inode exhaustion: find the tiny-file flood with sudo find / -xdev -type f | sed "s|.*/||" | cut -c1-40 | sort | uniq -c | sort -rn | head, then clean that tree',
        'Never fix by deleting things you cannot name: identify first, then delete',
        'Grow the disk or move data if this is chronic'
      ],
      prevent: 'Set up log rotation (logrotate), monitor with a df alert, and cap docker log sizes in /etc/docker/daemon.json.',
      related: ['erofs'],
      tip: 'A sudden full disk on a server that "was fine yesterday" is very often a runaway log: check the newest huge files with sudo find / -xdev -type f -size +500M -printf "%TY-%Tm-%Td %s %p\\n" | sort.'
    },
    {
      id: 'erofs', err: 'Read-only file system', errno: 30, cat: 'files',
      aka: ['read-only filesystem', 'cannot write, filesystem is read only'],
      meaning: 'The filesystem is mounted read-only, so every write fails no matter what the file permissions say. Linux also remounts the root filesystem read-only on purpose when it detects serious corruption: that is a protection, not just an annoyance.',
      causes: [
        'The filesystem was mounted with the ro option',
        'The kernel remounted it read-only after filesystem errors (dmesg will show them)',
        'A dirty NTFS or ext4 disk after an unclean shutdown, waiting for a check',
        'Snapshot or recovery boot environments are read-only by design',
        'Physical write-protect: SD card lock, damaged eMMC'
      ],
      diagnose: [
        { cmd: 'mount | grep -E "^/dev" ', why: 'Shows the ro / rw option per filesystem' },
        { cmd: 'findmnt -no OPTIONS /', why: 'Clean view of the root filesystem options' },
        { cmd: 'dmesg | grep -iE "error|read-only|remount" | tail -20', why: 'Shows WHY the kernel dropped to read-only (I/O errors, corruption)' }
      ],
      fix: [
        'Simple remount: sudo mount -o remount,rw / (only if dmesg shows no hardware errors)',
        'ext4 issues: unmount and run fsck from a live system: e2fsck -f /dev/sdXN (never on a mounted fs)',
        'NTFS from Linux: run ntfsfix /dev/sdXN or boot Windows and run chkdsk',
        'If dmesg shows the disk is failing: copy data off first, remounting rw can be the last write it ever does'
      ],
      prevent: 'Clean shutdowns, healthy disks, and a UPS for machines that write precious data.',
      related: ['enospc', 'eacces'],
      tip: 'The kernel remounting the root read-only is a five-alarm signal: it means journaling detected corruption. Back up before repairing, and read dmesg before forcing anything rw.'
    },
    {
      id: 'emfile', err: 'Too many open files', errno: 24, cat: 'files',
      aka: ['too many open files', 'file descriptor limit', 'emfile'],
      meaning: 'The process hit its open-file (file descriptor) limit. Every open file, socket, pipe and terminal counts as one descriptor.',
      causes: [
        'A long-running process (database, proxy, Java app) opening files or sockets without closing them: a leak',
        'System-wide limits reached (fs.file-max)',
        'Services under real load with defaults tuned for laptops (1024 is the classic soft limit)'
      ],
      diagnose: [
        { cmd: 'ulimit -n', why: 'Your current soft limit for open files' },
        { cmd: 'cat /proc/<PID>/limits | grep "open files"', why: 'The actual limits of the running process' },
        { cmd: 'ls /proc/<PID>/fd | wc -l', why: 'How many descriptors it holds right now: if this grows over hours, it is a leak' },
        { cmd: 'sudo lsof -p <PID> | awk "{print \$4}" | sort | uniq -c | sort -rn | head', why: 'Which descriptors dominate (files, sockets, pipes)' }
      ],
      fix: [
        'Raise the limit for a service: in its systemd unit add LimitNOFILE=65535 then systemctl daemon-reload and restart',
        'For a shell: ulimit -n 65535 (soft limit, up to the hard limit)',
        'The real fix for a leak is in the code: every open needs a close (or use RAII / with blocks)',
        'System wide ceiling: sysctl fs.file-max'
      ],
      prevent: 'Default LimitNOFILE for services that matter, and descriptor-count monitoring on long-lived processes.',
      related: ['enoent'],
      tip: 'Watch the trend, not the number: ls /proc/PID/fd | wc -l every hour. Flat and high is a tuning problem. Climbing forever is a bug in the program.'
    },
    {
      id: 'enametoolong', err: 'File name too long', errno: 36, cat: 'files',
      aka: ['file name too long', 'path too long'],
      meaning: 'A single path component or the whole path exceeded the filesystem limits (255 bytes per name on ext4, 4096 per path). Deleting such files also fails with the same error, which is how students first meet it.',
      causes: [
        'A script or program built a name in a loop (name = name + "_backup" each run)',
        'Recursion that repeats a directory into itself',
        'Extracting archives with hostile or broken paths'
      ],
      diagnose: [
        { cmd: 'echo "$FILE" | wc -c', why: 'How long the path actually is' }
      ],
      fix: [
        'To delete a too-long path, shrink it from the top: rename the deepest reachable directory to one character (mv "$(repeat)" a), then remove',
        'Or delete by inode: find . -inum <NUM> -delete',
        'In code, cap generated names and hash long suffixes instead of appending forever'
      ],
      prevent: 'Never build names by endless appending; keep a counter or a date, not a growing string.',
      related: ['enoent'],
      tip: 'The famous rm trick: if rm says the name is too long, cd as deep as possible and mv the offender to "a". Two hops of mv shrink any path enough to delete it.'
    },
    {
      id: 'ebusy', err: 'Device or resource busy', errno: 16, cat: 'files',
      aka: ['target is busy', 'resource busy'],
      meaning: 'You asked to unmount, remove or modify something the kernel cannot take away while it is in use: a process holds a file open inside the mount, or the device is mid-operation.',
      causes: [
        'umount while a shell sits inside the directory or a process reads a file there',
        'A deleted-but-open file keeps the filesystem "busy"',
        'Removing a module or network interface in active use'
      ],
      diagnose: [
        { cmd: 'lsof +D /mnt/point', why: 'Which processes are using files under the mount (slow but thorough)' },
        { cmd: 'fuser -vm /mnt/point', why: 'Compact view of processes holding the mount' }
      ],
      fix: [
        'Close the shells and stop the processes listed, then retry',
        'Lazy unmount as a last resort: umount -l (detaches now, cleans up when the last user exits)',
        'For "will this disk ever be free": fuser -km /mnt/point kills the users (careful: that is a kill, not a close)'
      ],
      prevent: 'Before unmounting: check your own shell is not inside the mount, and stop services using it.',
      related: ['erofs'],
      tip: 'Half the time the process holding the mount is your own terminal, cd-ed into the mount point. fuser -vm tells you in one line.'
    },

    /* ================= PERMISSIONS ================= */
    {
      id: 'script-not-executable', err: 'Permission denied (running a script you just wrote)', errno: 13, cat: 'perms',
      aka: ['cannot execute: permission denied', 'permission denied .sh'],
      meaning: 'You tried to run ./script.sh and Linux refused. Unlike a missing file, here the file exists: it simply does not have the execute bit set, or its interpreter cannot be executed.',
      causes: [
        'Fresh scripts have mode 644 (rw-r--r--): readable, not executable',
        'The file came from another filesystem or archive that dropped the x bit',
        'A Windows-mounted drive (NTFS, FAT) with no Unix permission support',
        'The shebang interpreter itself is not executable'
      ],
      diagnose: [
        { cmd: 'ls -l ./script.sh', why: 'Look for the x in the permission triplet' },
        { cmd: 'head -1 ./script.sh', why: 'Verify the shebang points at a real interpreter (/bin/bash, /usr/bin/env python3)' }
      ],
      fix: [
        'chmod +x ./script.sh then run it again',
        'Or invoke through the interpreter without the x bit: bash script.sh, python3 script.py',
        'On Windows-mounted disks: set fmask/dmask options in the mount, or run via interpreter'
      ],
      prevent: 'Remember the pattern: source files are data (no x), things you run are programs (x). Copying from a browser or chat usually drops x.',
      related: ['eacces', 'cmdnotfound'],
      tip: 'chmod +x is for things YOU wrote or trust from a known source. Do not reflexively chmod +x anything that refuses to run: read it first, especially downloads.'
    },
    {
      id: 'not-in-sudoers', err: 'user is not in the sudoers file. This incident will be reported.', errno: null, cat: 'perms',
      aka: ['sudoers', 'sudo permission denied', 'not in the sudo group'],
      meaning: 'Your user is not allowed to use sudo on this machine. The scary sentence is a joke from the original sudo authors: the "report" goes to the auth log, not to a person.',
      causes: [
        'The user was never added to the sudo (or wheel) group',
        'On a fresh server you are logged in as a different user than you think',
        'The sudoers file is broken and sudo refuses everyone (worst case)'
      ],
      diagnose: [
        { cmd: 'id && groups', why: 'Are you in sudo / wheel?' },
        { cmd: 'sudo -l', why: 'Lists exactly which commands you may run with sudo, if any' }
      ],
      fix: [
        'From an administrator session or root console: usermod -aG sudo username (or -aG wheel on RHEL family), then log out and back in',
        'If sudoers syntax broke: pkexec visudo or boot to recovery mode and visudo there',
        'Cloud servers: use the provider\'s serial console / rescue mode to fix group membership'
      ],
      prevent: 'Add yourself to the admin group at user creation time. On Ubuntu: adduser mary && usermod -aG sudo mary.',
      related: ['eacces', 'passwd-token'],
      tip: 'Group changes only apply to NEW logins. Logging out and back in (not just closing the terminal window) is the step everyone forgets.'
    },
    {
      id: 'eperm', err: 'Operation not permitted', errno: 1, cat: 'perms',
      aka: ['operation not permitted', 'eperm'],
      meaning: 'The kernel itself refuses the operation, no matter the file permissions. This is stronger than EACCES: you are trying to do something only certain privileged contexts may do (change file ownership, alter kernel state, send signals to other users\' processes).',
      causes: [
        'chown / mount / raw socket operations as a normal user',
        'kill a process owned by another user',
        'Immutable flag set on a file (chattr +i): even root cannot delete until it is cleared',
        'Container without the needed capability (CAP_NET_ADMIN, CAP_SYS_ADMIN...)'
      ],
      diagnose: [
        { cmd: 'lsattr file', why: 'Look for the i (immutable) attribute' },
        { cmd: 'grep Cap /proc/self/status', why: 'See the capabilities your process actually holds' }
      ],
      fix: [
        'Immutable file: sudo chattr -i file (then it behaves normally)',
        'Privileged operation: run it with sudo, or delegate a specific capability to the binary (setcap) instead of running everything as root',
        'In containers: add the specific capability with docker run --cap-add, not --privileged'
      ],
      prevent: 'Understand the rule: EACCES is file permission bits. EPERM is kernel policy. Different causes, different fixes.',
      related: ['eacces'],
      tip: 'Deleting a file as root and still getting denied? lsattr it: the immutable flag is the classic hidden reason, and chattr -i fixes it in one command.'
    },
    {
      id: 'passwd-token', err: 'Authentication token manipulation error', errno: null, cat: 'perms',
      aka: ['passwd authentication token', 'cannot change password'],
      meaning: 'passwd could read your intent but could not write the new password data. The "token" is the stored credential material in /etc/shadow, and something prevented updating it.',
      causes: [
        'A filesystem mounted read-only (see the read-only entry)',
        'Permissions or ownership wrong on /etc/shadow or /etc/passwd',
        'Trying to set a password that fails the policy checks in a confusing way',
        'PAM misconfiguration'
      ],
      diagnose: [
        { cmd: 'ls -l /etc/passwd /etc/shadow /etc/pam.d/passwd', why: 'The shadow file must be root-owned and not world-readable' },
        { cmd: 'mount | grep -w /', why: 'Is the root filesystem rw?' }
      ],
      fix: [
        'Read-only root: fix the mount first (the password is the symptom, not the disease)',
        'Permissions: sudo chown root:shadow /etc/shadow && sudo chmod 640 /etc/shadow',
        'Then retry: sudo passwd username'
      ],
      prevent: 'Do not hand-edit /etc/shadow; use passwd, chpasswd or usermod which lock correctly.',
      related: ['erofs', 'not-in-sudoers'],
      tip: 'This error after "filesystem went read-only" is extremely common. Check mount before blaming PAM.'
    },
    {
      id: 'readonly-var', err: 'readonly variable (bash)', errno: null, cat: 'shell',
      aka: ['cannot modify readonly variable', 'bash readonly'],
      meaning: 'Your script tried to assign to a shell variable that was marked readonly. The whole point of readonly is to make assignment fail loudly, so this error is the shell doing its job.',
      causes: [
        'Trying to reassign PATH, UID, EUID, PPID or another shell-managed variable',
        'A sourced file declared readonly and your script assigns later',
        'Two tools both "own" the same variable name'
      ],
      diagnose: [
        { cmd: 'readonly -p | grep -w VARNAME', why: 'Proves which variable is readonly and where it was declared' }
      ],
      fix: [
        'Use a different variable name (MY_PATH instead of PATH)',
        'If you sourced something that locked a name you need: that is a design smell, rename your variable',
        'In subshells, readonly vars still leak in: run the conflicting code in a fresh shell instead of sourcing it'
      ],
      prevent: 'In scripts, prefix your internal variables (PREFIX_ or _) to avoid collisions with shell-managed names.',
      related: ['bad-substitution'],
      tip: 'PATH, UID, EUID, PPID, RANDOM, SECONDS are protected for a reason: breaking them would corrupt the shell itself. Assigning to UID is not a privilege escalation, it is an error.'
    },

    /* ================= EXECUTION ================= */
    {
      id: 'cmdnotfound', err: 'command not found', errno: null, cat: 'exec',
      aka: ['xyz: command not found', '127'],
      meaning: 'The shell searched every directory in PATH and found nothing with that name. The command exit code for this is 127.',
      causes: [
        'Typo, or the command is not installed',
        'Installed but not in PATH (a local bin folder, a tool installed with pip --user, nvm, cargo...)',
        'The executable is in the current directory but you typed name instead of ./name',
        'PATH is broken (empty, overwritten, or the script runs with a minimal environment like cron)',
        'Alias or function exists in your interactive shell but not in the script'
      ],
      diagnose: [
        { cmd: 'type -a name', why: 'Tells you if the shell knows it as alias, function, builtin or binary, and where' },
        { cmd: 'echo $PATH', why: 'A broken PATH is visible instantly: empty, or missing /usr/bin' },
        { cmd: 'find / -name "name" -type f 2>/dev/null', why: 'Brute force: is it anywhere on disk?' }
      ],
      fix: [
        'Install the package, or add its bin directory to PATH: export PATH="$HOME/.local/bin:$PATH"',
        'In the current directory: run it as ./name (the shell does not search . for security reasons)',
        'For cron and systemd services: always use absolute paths, they do not inherit your PATH',
        'For scripts: set PATH explicitly at the top'
      ],
      prevent: 'Scripts that run anywhere start with #!/usr/bin/env bash and set PATH for the tools they need. It is the difference between "works on my machine" and works.',
      related: ['script-not-executable', 'enoexec', 'syntax-unexpected'],
      tip: 'The security rule behind the annoyance: PATH intentionally excludes the current directory so a malicious "ls" in a shared folder cannot hijack your commands. That is why ./name is required.'
    },
    {
      id: 'enoexec', err: 'cannot execute binary file: Exec format error', errno: 8, cat: 'exec',
      aka: ['exec format error', 'cannot execute binary file'],
      meaning: 'The kernel looked at the file, saw the execute bit, opened it, and then could not recognize a format it knows how to run. Architecture mismatch is the number one cause.',
      causes: [
        'ARM binary on an x86 machine, or x86-64 binary on a 32-bit-only system',
        'A Mach-O (macOS) or Windows PE executable on Linux',
        'A script missing its shebang entirely',
        'A file with a corrupted or stripped header (a download that is actually an HTML error page)'
      ],
      diagnose: [
        { cmd: 'file ./program', why: 'Says the exact format and architecture: ELF 64-bit x86-64, ARM aarch64, Mach-O, PE, or "data"' },
        { cmd: 'uname -m', why: 'Your machine architecture (x86_64, aarch64)' }
      ],
      fix: [
        'Architecture mismatch: get or compile a build for your architecture',
        'Cross-architecture on demand: install qemu-user-static and run through the emulator, or use docker --platform linux/amd64',
        'Shebang missing: add #!/usr/bin/env bash as the first line',
        'Broken download: re-download and verify the checksum, file said it all along'
      ],
      prevent: 'Run file on every downloaded binary before executing it. It answers architecture, format, statically or dynamically linked, and corrupted, all in one line.',
      related: ['cmdnotfound', 'bad-interpreter', 'segfault'],
      tip: 'binfmt_misc plus qemu-user-static is the classic trick: after installing it, Linux transparently runs ARM binaries on x86. Very handy for router firmware and IoT challenges.'
    },
    {
      id: 'bad-interpreter', err: 'bad interpreter: No such file or directory (or /usr/bin/env: python\r)', errno: 2, cat: 'exec',
      aka: ['bad interpreter', 'env: python\\r', 'CRLF shebang', '$\'\\r\': command not found'],
      meaning: 'The script exists, is executable, but its FIRST line (the shebang) is broken: it names an interpreter that is missing, or the line secretly ends with a Windows carriage return so the kernel literally searches for a program called "python\\r".',
      causes: [
        'The script was written or edited on Windows: CRLF line endings poison the shebang',
        'The interpreter name in the shebang does not exist (python vs python3 on modern systems)',
        'The shebang line is not the first line (a comment or empty line above it)'
      ],
      diagnose: [
        { cmd: 'head -1 script | od -c | head -2', why: 'Shows the raw bytes: a \\r before \\n proves Windows line endings' },
        { cmd: 'which python3 && ls -l /usr/bin/env', why: 'Verify the interpreter the shebang points at exists' }
      ],
      fix: [
        'Convert line endings: sed -i "s/\\r$//" script (or dos2unix script)',
        'Fix the interpreter: #!/usr/bin/env python3 is the portable form',
        'Configure your editor to save LF, and .gitattributes with *.sh text eol=lf to stop it coming back'
      ],
      prevent: 'One line in .gitattributes (*.sh text eol=lf) permanently ends this class of bug for teams that mix Windows and Linux.',
      related: ['enoent', 'cmdnotfound', 'spaces-path'],
      tip: 'The \\r character is invisible in every normal view, which is what makes it legendary. od -c, cat -A or grep -c $\'\\r\' file make it visible. If a script misbehaves after editing on Windows, this is the first suspect.'
    },
    {
      id: 'missing-so', err: 'error while loading shared libraries: libfoo.so: cannot open shared object file', errno: 2, cat: 'exec',
      aka: ['cannot open shared object file', 'shared libraries', 'ld.so'],
      meaning: 'The program is fine, but a library it was linked against is not found at startup. The dynamic linker (ld.so) walks its search path and reports the first missing library.',
      causes: [
        'The library is genuinely not installed',
        'It is installed in a non-standard directory the linker does not search (common with /usr/local, hand-built, or conda software)',
        'The cache at /etc/ld.so.cache is stale after installing libraries',
        'A version mismatch: the program wants libfoo.so.2 and only libfoo.so.3 exists'
      ],
      diagnose: [
        { cmd: 'ldd ./program | grep "not found"', why: 'Lists every missing library, not just the first' },
        { cmd: 'find / -name "libfoo*" 2>/dev/null', why: 'Is the library on disk at all, and in which version?' },
        { cmd: 'ldconfig -p | grep libfoo', why: 'What the linker cache currently knows' }
      ],
      fix: [
        'Install the library package (name usually contains the version number: libssl3, libxml2)',
        'Custom location: put the directory in /etc/ld.so.conf.d/mylibs.conf then sudo ldconfig',
        'Quick test without system changes: LD_LIBRARY_PATH=/opt/myapp/lib ./program',
        'Version mismatch: install the specific older version the binary wants, or rebuild against the new one'
      ],
      prevent: 'When shipping binaries, either link statically, bundle your libraries and ship a wrapper script setting LD_LIBRARY_PATH, or use patchelf to bake in an rpath.',
      related: ['enoexec', 'undefined-ref'],
      tip: 'ldd ./binary is the universal first move for any binary startup problem: it lists every library with full paths, and "not found" lines point straight at the missing package.'
    },
    {
      id: 'undefined-symbol-runtime', err: 'symbol lookup error: undefined symbol', errno: null, cat: 'exec',
      aka: ['symbol lookup error', 'undefined symbol at runtime'],
      meaning: 'The program and its libraries loaded, but when it called a function, the dynamic linker could not find that symbol in any loaded object. Usually a version mix: the binary was built against a newer library than the one it found at runtime.',
      causes: [
        'Two versions of the same library installed, and the older one is picked first',
        'LD_LIBRARY_PATH or rpath pointing at a different (older) copy',
        'A plugin loading into a host that does not export a symbol the plugin expects'
      ],
      diagnose: [
        { cmd: 'ldd ./program', why: 'Which copy of each library actually gets loaded' },
        { cmd: 'LD_DEBUG=libs ./program 2>&1 | head -40', why: 'Watch the linker search live: paths and versions' },
        { cmd: 'nm -D /path/to/libfoo.so | grep symbol_name', why: 'Check whether the loaded library really exports the symbol' }
      ],
      fix: [
        'Make sure the version you built against is the one found first (fix paths or rpath)',
        'Rebuild the software against the installed library versions',
        'For plugins: verify the host binary was built with the needed symbols exported (-rdynamic / --export-dynamic)'
      ],
      prevent: 'Pin library versions in build environments, and avoid mixing distro packages with hand-built ones in the same prefix.',
      related: ['missing-so', 'undefined-ref'],
      tip: 'LD_DEBUG=libs is x-ray vision for dynamic linking: it prints every directory searched and every decision made. Pipe to a file, it is chatty.'
    },
    {
      id: 'spaces-path', err: 'No such file or directory (path with spaces or special characters)', errno: 2, cat: 'shell',
      aka: ['path with spaces', 'too many arguments', 'argument list'],
      meaning: 'The file is right there, but the shell split its name into pieces at every space. "my file.txt" became two arguments, "my" and "file.txt", and neither exists.',
      causes: [
        'Unquoted variable or path expansion: cat my file.txt',
        'for f in $(ls) style loops, which tear filenames apart at spaces',
        'Filenames with spaces, tabs, newlines, or glob characters (* ? [ ])'
      ],
      diagnose: [
        { cmd: 'printf "[%s]\\n" $VAR', why: 'Shows how the shell sees the value: brackets make word splits visible' },
        { cmd: 'ls -Q', why: 'Quotes the names so spaces become obvious' }
      ],
      fix: [
        'Quote everything: cat "my file.txt", cp "$SRC" "$DST"',
        'Iterate safely: for f in ./*.txt; do ... "$f" ...; done (never for f in $(ls))',
        'Newlines in filenames: use find . -print0 | while IFS= read -r -d "" f; do ... "$f"; done'
      ],
      prevent: 'The habit that prevents the whole class: every variable expansion gets double quotes, every time, even when you are sure there are no spaces.',
      related: ['enoent', 'unary-expected', 'syntax-unexpected'],
      tip: 'for f in $(ls) is the classic bug: it looks professional and breaks on the first space. The glob form for f in ./*.txt is shorter, safer AND handles no-match better (with nullglob).'
    },
    {
      id: 'syntax-unexpected', err: 'syntax error near unexpected token', errno: null, cat: 'shell',
      aka: ['syntax error near unexpected token', 'unexpected token (', 'unexpected end of file'],
      meaning: 'bash parsed your command as far as it could and then hit a character that cannot legally appear there. The token in the message is the first thing the parser could not digest, which is usually a clue about what is missing BEFORE it.',
      causes: [
        'A missing space: if[$x = 1] is invalid, [ is a command and needs a space after it',
        'Missing quote, bracket or fi/done keyword somewhere before the reported token',
        'CRLF line endings turning do and then into do\\r',
        'Using bash syntax ([[, arrays, function) while running with sh, which is a stricter shell'
      ],
      diagnose: [
        { cmd: 'bash -n script.sh', why: 'Syntax-checks the whole script without running a single line: fastest way to find the real line number' },
        { cmd: 'head -1 script.sh', why: 'Is it #!/bin/bash or #!/bin/sh? Arrays and [[ require bash' },
        { cmd: 'grep -n $\'\\r\' script.sh', why: 'Windows line endings break keywords invisibly' }
      ],
      fix: [
        'Run bash -n, go to the reported line, and look BEFORE the token: the mistake is usually a missing quote or keyword earlier',
        'Missing space after [ : [ "$x" = 1 ] with spaces on both sides of every bracket',
        'dos2unix or sed -i "s/\\r$//" for CRLF',
        'Switch the shebang to bash, or write portable sh syntax'
      ],
      prevent: 'bash -n script.sh is a one-second lint step: run it before executing anything non-trivial, and after every edit.',
      related: ['bad-interpreter', 'unary-expected', 'spaces-path'],
      tip: 'Unexpected end of file means the parser reached the bottom while a quote or block was still open. Count your fi, done, } and quotes from the top; the mismatch is always the last thing you edited.'
    },
    {
      id: 'unary-expected', err: '[: =: unary operator expected', errno: null, cat: 'shell',
      aka: ['unary operator expected', 'binary operator expected', '[: too many arguments'],
      meaning: 'The test command [ received the wrong number of words. Almost always an unquoted empty variable: [ $X = yes ] with X empty becomes [ = yes ], and = is then read as a file operator.',
      causes: [
        'Empty or unset variable, unquoted, inside [ ]',
        'A variable containing multiple words, unquoted',
        'A missing argument before the operator'
      ],
      diagnose: [
        { cmd: 'echo "X=[$X]"', why: 'Brackets reveal empty values and spaces instantly' },
        { cmd: 'set -u', why: 'Makes unset variables a hard error instead of silent emptiness' }
      ],
      fix: [
        'Quote it: [ "$X" = yes ] (the single most important habit in shell scripting)',
        'Prefer [[ "$X" == yes ]] in bash: it parses before expansion and tolerates unquoted empties',
        'Default empty variables: X="${X:-}"'
      ],
      prevent: 'Double-quote every expansion in tests. The [[ ]] form in bash is a deliberate safety upgrade.',
      related: ['spaces-path', 'syntax-unexpected'],
      tip: 'Rule of thumb: the difference between [ and [[ is that [[ is a keyword parsed by bash itself, so empty unquoted variables cannot explode into extra words. In POSIX sh you must quote.'
    },
    {
      id: 'bad-substitution', err: 'bad substitution', errno: null, cat: 'shell',
      aka: ['bad substitution', 'unsupported substitution'],
      meaning: 'You used a parameter expansion the running shell does not understand. Usually bash-only syntax executed by sh (dash on Ubuntu and Debian).',
      causes: [
        'Substring or search expansions (${var:0:5}, ${var%pattern}) in a POSIX sh script',
        'A typo in the expansion: ${var^^} style features outside bash',
        'Running a bash script with sh script.sh'
      ],
      diagnose: [
        { cmd: 'head -1 script.sh && ls -l /bin/sh', why: 'Check the shebang and what sh really is on this system' },
        { cmd: 'readlink -f /bin/sh', why: 'On Ubuntu it is dash, not bash: this is the most common surprise' }
      ],
      fix: [
        'Run bash scripts with bash: ./script.sh with shebang #!/usr/bin/env bash, or bash script.sh',
        'Or rewrite the expansion in POSIX form (case statements instead of ${var^^})'
      ],
      prevent: 'Pick one: either commit to bash (shebang #!/usr/bin/env bash) or write strict POSIX sh. Mixing them is where this error breeds.',
      related: ['syntax-unexpected', 'readonly-var'],
      tip: 'Ubuntu and Debian made /bin/sh = dash for speed. The price: every bashism in a #!/bin/sh script explodes with bad substitution or syntax errors. readlink -f /bin/sh tells you which shell you are really getting.'
    },

    /* ================= PROCESSES & SIGNALS ================= */
    {
      id: 'segfault', err: 'Segmentation fault', errno: null, cat: 'proc',
      aka: ['segfault', 'segmentation fault (core dumped)', 'SIGSEGV', 'exit 139'],
      meaning: 'The process touched memory it is not allowed to touch: read or write past the end of a buffer, jumped to an address that is not mapped, dereferenced a wild or NULL pointer. The kernel delivers SIGSEGV and the process dies. Exit code 139 = 128 + 11.',
      causes: [
        'Buffer overflow: writing past the end of an array on the stack or heap',
        'NULL or uninitialized pointer dereference',
        'Use-after-free: touching memory after free()',
        'Stack exhaustion from runaway recursion (also reported as segfault)',
        'Misaligned or wrong-architecture code execution (jumping into data)'
      ],
      diagnose: [
        { cmd: 'ulimit -c unlimited && ./program', why: 'Enable core dumps so the crash leaves evidence' },
        { cmd: 'gdb ./program core -ex bt -ex quit', why: 'Backtrace shows the exact line where it died' },
        { cmd: 'valgrind ./program 2>&1 | head -40', why: 'Catches the invalid read/write even if it does not crash this run' },
        { cmd: 'gcc -g -fsanitize=address program.c && ./a.out', why: 'AddressSanitizer prints the exact overflow with a pretty diagram' }
      ],
      fix: [
        'Find the offending access with ASan or valgrind, then fix the bounds / pointer logic in the code',
        'Recursion: add a depth limit or convert to iteration',
        'Third-party binary: check for a newer version, or report with the backtrace'
      ],
      prevent: 'Compile test builds with -fsanitize=address,undefined. It finds memory bugs the moment they happen instead of 500 crashes later.',
      related: ['sigbus', 'sigill', 'coredump', 'sigfpe'],
      tip: 'For a security student: a segfault is not just a crash, it is information. It means you CAN reach past the boundary: the difference between a crash and an exploit is usually only precision. That is the entire starting point of pwn.'
    },
    {
      id: 'sigbus', err: 'Bus error', errno: null, cat: 'proc',
      aka: ['bus error', 'SIGBUS', 'exit 135'],
      meaning: 'The memory address was VALID, but the access itself was physically impossible: misaligned access, or a mapped file whose backing storage disappeared. SIGSEGV says "no such memory". SIGBUS says "memory exists, hardware refuses".',
      causes: [
        'Unaligned access on strict architectures (ARM, SPARC): reading a 4-byte int from an odd address',
        'mmap-ed file truncated by another process while mapped (SIGBUS_PAGE_FAULT)',
        'Hardware or filesystem corruption'
      ],
      diagnose: [
        { cmd: 'gdb ./program core -ex bt', why: 'The faulting instruction is usually a single vector or pointer cast' },
        { cmd: 'file core 2>/dev/null; coredumpctl info 2>/dev/null', why: 'Confirm which signal actually fired' }
      ],
      fix: [
        'Alignment: use memcpy to load misaligned data instead of a pointer cast, or align your buffers',
        'Truncated mmap: hold the file lock while it is mapped, or handle the size change',
        'x86 tolerates misalignment (slowly), which is why code that worked on a PC dies on a Raspberry Pi or phone'
      ],
      prevent: 'Never cast a char* buffer to int*/struct* and dereference: that is exactly the pattern that works on x86 and SIGBUS-es on ARM.',
      related: ['segfault', 'sigill'],
      tip: 'If a program runs on x86 and bus-errors on ARM, misaligned access is guilty until proven innocent. Look for pointer casts on packed or network data.'
    },
    {
      id: 'sigill', err: 'Illegal instruction', errno: null, cat: 'proc',
      aka: ['illegal instruction', 'SIGILL', 'exit 132', 'core dumped'],
      meaning: 'The CPU tried to execute an instruction it does not implement. The program counter landed somewhere invalid, or the binary uses newer instructions than this CPU has.',
      causes: [
        'Jumping into data (a corrupted function pointer, a missing executable permission on memory with NX enforced)',
        'Binary compiled with instructions the CPU lacks (AVX-512 on an old chip, ARM NEON on a core without it)',
        'ud2 instructions the compiler inserted for undefined behavior paths'
      ],
      diagnose: [
        { cmd: 'gdb ./program core -ex "x/i $pc" -ex bt', why: 'Disassemble the exact instruction pointer at crash time' },
        { cmd: 'grep -o "avx2\\|avx512" /proc/cpuinfo | sort -u', why: 'Check which SIMD extensions your CPU actually has' }
      ],
      fix: [
        'For CPU features: rebuild targeting an older baseline (-march=x86-64, or -mno-avx512f)',
        'For control-flow corruption: this is a real bug, debug with ASan or gdb'
      ],
      prevent: 'Distribute binaries built for a conservative baseline, and gate optimized code paths on runtime CPU detection like OpenSSL does.',
      related: ['segfault', 'sigbus', 'enoexec'],
      tip: 'SIGILL with a garbage instruction pointer usually means execution jumped into non-code memory: that is a control-flow hijack in progress, the same event a stack overflow produces right before ret2win works.'
    },
    {
      id: 'sigkill-oom', err: 'Killed (or process disappears with exit 137)', errno: null, cat: 'proc',
      aka: ['killed', 'sigkill', 'oom', 'exit 137', 'out of memory', 'std::bad_alloc', 'terminate called after throwing', 'what(): std::bad_alloc'],
      meaning: 'Something sent SIGKILL, which cannot be caught or ignored. Exit 137 = 128 + 9. On servers the usual sender is the kernel OOM killer, which executes a process when memory pressure becomes critical.',
      causes: [
        'Out of memory: the kernel OOM killer chose this process (it picks by a badness score, often the biggest consumer)',
        'Docker / Kubernetes memory limits: exceeding the cgroup limit triggers an OOM kill inside the container',
        'An admin, a supervisor like systemd (OOMPolicy), or a manual kill -9'
      ],
      diagnose: [
        { cmd: 'sudo dmesg | grep -i "killed process" | tail -5', why: 'The kernel logs every OOM kill with the culprit and the score' },
        { cmd: 'journalctl -k --since "1 hour ago" | grep -i oom', why: 'Same evidence, journald flavor' },
        { cmd: 'docker inspect <ctr> --format "{{.State.OOMKilled}}"', why: 'Definitive answer for containers: true means the cgroup limit fired' }
      ],
      fix: [
        'Memory leak: measure first (heaptrack, massif, py-spy for Python), then fix the retention',
        'Legitimately big workload: raise the machine or container memory, or stream data instead of loading it whole',
        'Accidental OOM (loading a 4GB file into RAM): rewrite to process in chunks'
      ],
      prevent: 'Set container limits BELOW the host memory, monitor RSS trends, and treat a slow RSS climb as a bug to fix this week, not someday.',
      related: ['sigterm', 'enospc'],
      tip: 'A process that dies without any error message is the signature of SIGKILL: no handler can run, so nothing gets printed. If your program died silently, suspect the OOM killer and read dmesg before blaming the code.'
    },
    {
      id: 'sigterm', err: 'Terminated (SIGTERM) / exit 143', errno: null, cat: 'proc',
      aka: ['terminated', 'SIGTERM', 'exit 143', '15'],
      meaning: 'A polite request to shut down: SIGTERM can be caught, so well-behaved programs use it to close files, flush buffers and exit cleanly. Exit 143 = 128 + 15. systemd, docker stop, Kubernetes and Ctrl-less daemons all speak SIGTERM first.',
      causes: [
        'Service manager stopping or restarting the service',
        'docker stop (SIGTERM, then SIGKILL after the grace period, default 10s)',
        'Your own scripts using kill without -9 (which is the correct default!)'
      ],
      diagnose: [
        { cmd: 'systemctl status myservice', why: 'Shows the last stop reason and signal' },
        { cmd: 'journalctl -u myservice -n 50', why: 'Did the process log a graceful shutdown or vanish mid-sentence?' }
      ],
      fix: [
        'If your program vanished without flushing: install a SIGTERM handler and flush, or set proper shutdown hooks',
        'docker stop timing out then killing: the app ignores SIGTERM, add a handler (or signal:stop_grace_period tuning)'
      ],
      prevent: 'Always try SIGTERM first and SIGKILL as the last resort: kill -9 gives the process no chance to flush files or release locks, which is how you corrupt data.',
      related: ['sigkill-oom'],
      tip: 'The ladder is: SIGTERM (please leave), wait, then SIGKILL (removed by force). kill -9 as a first move is how databases get corrupted: the engine never got to roll back its journal.'
    },
    {
      id: 'coredump', err: '(core dumped)', errno: null, cat: 'proc',
      aka: ['core dumped', 'core file', 'where is the core'],
      meaning: 'The kernel wrote the process memory image to a file at crash time. A core is a full snapshot: registers, stack, heap, loaded libraries. With it, gdb can replay the crash moment exactly.',
      causes: [
        'Any fatal signal (SEGV, ABRT, ILL) with core dumps enabled produces one'
      ],
      diagnose: [
        { cmd: 'ulimit -c', why: '0 means core dumps are disabled in this shell: that is the default on most desktops' },
        { cmd: 'cat /proc/sys/kernel/core_pattern', why: 'Where cores go: a path, a pipe to a handler, or systemd-coredump' },
        { cmd: 'coredumpctl list | tail -5', why: 'On systemd machines cores live in the journal, not in files' },
        { cmd: 'coredumpctl gdb', why: 'Opens the newest core straight in gdb with the right binary' }
      ],
      fix: [
        'Enable for your session: ulimit -c unlimited',
        'Set a stable location: echo "/tmp/core.%e.%p" | sudo tee /proc/sys/kernel/core_pattern',
        'Read it: gdb ./program /tmp/core.1234 then bt'
      ],
      prevent: 'Nothing to prevent: cores are gifts. The only mistake is leaving them disabled while debugging crashes.',
      related: ['segfault', 'sigill'],
      tip: 'A core file plus gdb gives you the exact stack of a crash that happened at 3am on a server you cannot reproduce on. coredumpctl gdb is the modern one-liner for it.'
    },
    {
      id: 'zombie', err: 'Zombie / defunct process', errno: null, cat: 'proc',
      aka: ['defunct', 'zombie process', 'Z state'],
      meaning: 'The child process already died, but its entry stays in the process table because the parent has not called wait() yet. A zombie holds no memory or files, only its PID and exit status. It is a receipt waiting to be collected.',
      causes: [
        'Parent forgot to wait() on children (the actual bug is in the parent)',
        'Parent is busy or blocked and collects children slowly',
        'A daemon design that deliberately reaps periodically'
      ],
      diagnose: [
        { cmd: 'ps aux | awk "\$8 ~ /Z/"', why: 'Lists zombies with their parents' },
        { cmd: 'ps -o ppid= -p <zombie_pid>', why: 'Find the guilty parent' }
      ],
      fix: [
        'One or two zombies: harmless, they vanish when the parent exits or reaps',
        'Growing count: fix the parent code (waitpid in a loop, or SIGCHLD handler with wait)',
        'Quick shell trick: the parent reaps all children on SIGCHLD in many runtimes: kill -CHLD <parent_pid>'
      ],
      prevent: 'Every fork() needs a matching wait(): that is the contract. In C, install a SIGCHLD handler that loops waitpid(-1, NULL, WNOHANG).',
      related: ['sigterm', 'ebusy'],
      tip: 'You cannot kill a zombie with kill -9 because it is already dead; there is nothing to signal. The fix is always aimed at the parent, never at the zombie.'
    },
    {
      id: 'sigttin', err: 'Stopped (tty output) / process stops in background', errno: null, cat: 'proc',
      aka: ['stopped', 'SIGTTIN', 'SIGTTOU', 'suspended tty'],
      meaning: 'A background job tried to read from (or write to) the terminal that no longer belongs to it, so the kernel stopped it with SIGTTIN / SIGTTOU. It sits frozen until you bring it back.',
      causes: [
        'Running an interactive program with & (sudo vim file &, a prompt in the background)',
        'Pressing Ctrl+S in a terminal (that is XOFF: output flow control, the cousin everyone hits)',
        'Piping a program that insists on reading stdin and gets EOF confusion'
      ],
      diagnose: [
        { cmd: 'jobs -l', why: 'Shows stopped jobs with their numbers and states' }
      ],
      fix: [
        'Resume in the foreground: fg %1',
        'Keep it running in the background while detaching input: myprogram < /dev/null > out.log 2>&1 &',
        'Ctrl+S freeze: press Ctrl+Q to resume the terminal itself (this one surprises everyone at least once)'
      ],
      prevent: 'For daemons: nohup, setsid, disown, or a proper systemd unit. For terminal flow control: know that Ctrl+Q unfreezes what Ctrl+S froze.',
      related: ['sigterm'],
      tip: 'A terminal that suddenly ignores everything is usually Ctrl+S (XOFF) pressed by accident. Ctrl+Q revives it. It looks like a frozen machine but it is just flow control.'
    },
    {
      id: 'sigfpe', err: 'Floating point exception (but you divided integers)', errno: null, cat: 'proc',
      aka: ['floating point exception', 'SIGFPE', 'integer division by zero'],
      meaning: 'Despite the name, in C this almost always means INTEGER division by zero. The FPU proper handles float division by zero gracefully (returns inf); the integer divide unit raises SIGFPE and kills the process.',
      causes: [
        'x / y with y == 0 (integers)',
        'x % 0 modulo zero',
        'Integer overflow on INT_MIN / -1 (the one case that traps even without zero)'
      ],
      diagnose: [
        { cmd: 'gdb ./program core -ex bt', why: 'Points at the exact division line' }
      ],
      fix: [
        'Guard the denominator: if (y != 0) q = x / y; else handle it',
        'Check for INT_MIN / -1 if you parse extreme values'
      ],
      prevent: 'Every division whose denominator comes from outside (user, file, network) gets a guard. Zero is a legal input.',
      related: ['segfault'],
      tip: 'The name is historical: SIGFPE covers the whole arithmetic-error family. If your C program dies with "Floating point exception" and there is no float in sight, look for an integer division by zero.'
    },

    /* ================= NETWORKING ================= */
    {
      id: 'econnrefused', err: 'Connection refused', errno: 111, cat: 'net',
      aka: ['connection refused', 'refused', 'curl (7)'],
      meaning: 'The network path was fine, the target machine answered, and it said "nothing is listening on that port". Refused is actually good news: you reached the host; the service just is not there.',
      causes: [
        'The service is not running (crashed, stopped, not installed)',
        'The service listens on a different port than you typed',
        'The service binds 127.0.0.1 only, and you connected from outside',
        'A firewall REJECT rule (as opposed to DROP: reject answers with refused, drop causes timeout)'
      ],
      diagnose: [
        { cmd: 'ss -tlnp | grep -E ":PORT\\b"', why: 'Is anything listening on that port, on which address? The p shows the process (as root)' },
        { cmd: 'curl -v telnet://host:port', why: 'A quick human-readable reachability probe' },
        { cmd: 'nc -vz host port', why: 'Classic port check: prints open or refused' }
      ],
      fix: [
        'Start the service, or fix the port number',
        'Bind to the right address: 0.0.0.0 to listen on all interfaces (and know the security trade-off), 127.0.0.1 for local only',
        'Container world: the app listens inside the container but you forgot -p 8080:80 to publish it',
        'Firewall: allow the port (ufw allow 8080) or stop rejecting it'
      ],
      prevent: 'The habit: after starting any network service, ss -tlnp to confirm WHERE it listens before wondering why clients cannot connect.',
      related: ['etimedout', 'ehostunreach', 'ssh-refused', 'docker-daemon'],
      tip: 'Refused vs timeout is the single most useful network diagnostic you get for free: refused means "host reached, port closed" (fix the service), timeout means "host never answered" (fix routing, firewall or IP).'
    },
    {
      id: 'etimedout', err: 'Connection timed out', errno: 110, cat: 'net',
      aka: ['timeout', 'connection timed out', 'curl (28)'],
      meaning: 'You sent packets and nothing came back for the whole timeout period. The host is unreachable, dropping your packets, or just too slow. Contrast with refused: there you got an answer, here you got silence.',
      causes: [
        'Wrong IP address, or the host is down',
        'A firewall DROP rule (dropped packets vanish: the client waits and times out)',
        'Routing problems: no route, broken VPN, wrong subnet',
        'The service is overloaded and cannot answer in time',
        'Cloud security groups (AWS, Azure) default to DROP: the classic silent timeout'
      ],
      diagnose: [
        { cmd: 'ping -c 3 host', why: 'Layer 3 reachability (note: some servers block ping while serving fine)' },
        { cmd: 'ip route get TARGET_IP', why: 'Which interface and gateway the kernel would use' },
        { cmd: 'traceroute -T -p PORT host', why: 'TCP traceroute to the actual port: shows where the silence begins' }
      ],
      fix: [
        'Verify the IP (is that DNS record stale?), then fix routing or the firewall rule',
        'Cloud: add the port to the security group / network security group',
        'Overloaded service: check load, connections, logs'
      ],
      prevent: 'When deploying: know which firewalls exist on the path (host firewall, cloud security group, network ACL) and check all three when something is silent.',
      related: ['econnrefused', 'ehostunreach', 'dns'],
      tip: 'DROP vs REJECT is the mental model: REJECT answers "no" (you get refused instantly), DROP ignores you (you wait and time out). Security groups are DROP by design, which is why cloud timeouts are so common.'
    },
    {
      id: 'ehostunreach', err: 'No route to host', errno: 113, cat: 'net',
      aka: ['no route to host', 'host unreachable'],
      meaning: 'The kernel knows the destination is not reachable right now: it got an explicit unreachable message from a router, or the local routing table has no idea where to send the packet.',
      causes: [
        'The host is on a network you have no route to (wrong VPN, missing route)',
        'The target firewall sends reject-with-host-unreachable (nftables REJECT icmp-host-unreachable)',
        'The local interface is down or has no IP',
        'Container or VM network not attached'
      ],
      diagnose: [
        { cmd: 'ip route', why: 'What routes exist and which one matches the target' },
        { cmd: 'ip addr', why: 'Is your interface up with the expected address?' },
        { cmd: 'ping -c 2 gateway_ip', why: 'Can you even reach your own gateway?' }
      ],
      fix: [
        'Fix the route: connect the VPN, add the route, fix the interface config',
        'Firewall-induced: change the REJECT type or allow the traffic',
        'Containers: check the network is attached and the bridge is up'
      ],
      prevent: 'Understand your network layers: interface up, IP assigned, route present, gateway reachable. ip addr, ip route, ping gw is the 30-second trio.',
      related: ['etimedout', 'enetunreach', 'dns'],
      tip: 'No route to host usually appears IMMEDIATELY (the kernel or a router answered now), while timeout means waiting in silence. Immediate errors are routing facts; slow errors are firewalls dropping.'
    },
    {
      id: 'enetunreach', err: 'Network is unreachable', errno: 101, cat: 'net',
      aka: ['network unreachable', 'sendto: network unreachable'],
      meaning: 'The local routing table has no route at all for the destination network. Subtle difference from host unreachable: here the kernel itself refuses to even try sending.',
      causes: [
        'No default gateway and no matching subnet route',
        'Interface down at send time',
        'IPv6 asked for but no IPv6 connectivity (very common: a hostname resolves an AAAA record, your network has no v6)'
      ],
      diagnose: [
        { cmd: 'ip route show default', why: 'Is there a default route at all?' },
        { cmd: 'curl -4 -v URL vs curl -6 -v URL', why: 'Separates v4 and v6 to expose the missing stack' }
      ],
      fix: [
        'Add or repair the default route / interface',
        'IPv6 ghost network: prefer -4 for tools, or fix v6 properly, and disable v6 in apps that mishandle it'
      ],
      prevent: 'When a host has AAAA records but your site lacks IPv6, expect this error from any dual-stack client. Test both explicitly.',
      related: ['ehostunreach', 'dns'],
      tip: 'Half of modern "network unreachable" cases are IPv6: DNS happily hands out AAAA records, the app tries them first, and the LAN has no v6. curl -4 or ping -4 settles it instantly.'
    },
    {
      id: 'dns', err: 'Name or service not known / Could not resolve host', errno: null, cat: 'net',
      aka: ['could not resolve host', 'name or service not known', 'temporary failure in name resolution', 'NXDOMAIN'],
      meaning: 'The hostname could not be translated to an IP. The failure can be in your resolver config, the network to the resolver, or the name itself (typo, or the record genuinely does not exist).',
      causes: [
        'Typo in the hostname',
        'No DNS servers configured, or /etc/resolv.conf points at an unreachable resolver',
        'The local resolver cache or systemd-resolved is wedged',
        'A search domain assumption: host works inside the company network but not outside (host.company.internal)',
        'The record really does not exist (NXDOMAIN)'
      ],
      diagnose: [
        { cmd: 'getent hosts hostname', why: 'Uses the same resolution path as real programs (nsswitch), unlike ping' },
        { cmd: 'resolvectl status | head -20', why: 'Which resolvers are active and their last errors' },
        { cmd: 'dig @1.1.1.1 hostname +short', why: 'Asks a public resolver directly: separates local config from global truth' }
      ],
      fix: [
        'Typo: fix the name (and check for trailing dots or spaces, especially in configs)',
        'Resolver unreachable: fix /etc/resolv.conf (nameserver 1.1.1.1) or restart systemd-resolved',
        'Internal-only names: use the FQDN, connect the VPN, or add the search domain',
        'Stale record: wait for TTL or fix it at your DNS provider'
      ],
      prevent: 'Use dig +trace when DNS behaves strangely: it walks the delegation chain and shows exactly which layer lies.',
      related: ['etimedout', 'apt-host'],
      tip: 'dig @1.1.1.1 name is the sharpest DNS tool: it bypasses every local caching and config layer. If public DNS knows the name but getent does not, your local resolver is the problem, not the internet.'
    },
    {
      id: 'eaddrinuse', err: 'Address already in use', errno: 98, cat: 'net',
      aka: ['address already in use', 'port already in use', 'EADDRINUSE'],
      meaning: 'You tried to bind a port that another socket already holds. Exactly one listener per address:port pair.',
      causes: [
        'A previous instance of your server is still running (the number one cause)',
        'A crashed process left an orphan, or systemd restarted the old one in parallel',
        'TIME_WAIT sockets blocking a bind without SO_REUSEADDR'
      ],
      diagnose: [
        { cmd: 'ss -tlnp | grep :PORT', why: 'Who holds the port right now (run as root for process names)' },
        { cmd: 'sudo lsof -i :PORT', why: 'The classic alternative view with user and PID' },
        { cmd: 'ps -fp <PID>', why: 'What the holder actually is before you kill anything' }
      ],
      fix: [
        'Stop the old instance properly (systemctl stop, or kill <PID>), then start yours',
        'Do not reflexively kill: the holder might be nginx serving production',
        'For quick dev toggles, SO_REUSEADDR in your server code solves the TIME_WAIT flavor',
        'Different port: run the new instance on 8081 while 8080 is busy'
      ],
      prevent: 'One service per port, managed by a supervisor. In dev, make your shutdown path actually close the listening socket.',
      related: ['econnrefused'],
      tip: 'SO_REUSEADDR (setsockopt before bind) is the reason a server can restart instantly after dying. Without it, TIME_WAIT sockets block the port for about a minute and everyone relearns this error.'
    },
    {
      id: 'lowport', err: 'Permission denied (binding a port below 1024)', errno: 13, cat: 'net',
      aka: ['bind: permission denied', 'cannot bind port 80', 'privileged port'],
      meaning: 'Ports below 1024 are privileged: only root (or a process with the right capability) may bind them. Your normal user trying to run a web server on port 80 hits exactly this.',
      causes: [
        'Binding 80, 443, 22, 53... as a non-root user',
        'A container without CAP_NET_BIND_SERVICE'
      ],
      diagnose: [
        { cmd: 'id', why: 'Confirm you are not root' },
        { cmd: 'ss -tlnp | grep :80', why: 'Also check nobody else holds it (that would be EADDRINUSE instead)' }
      ],
      fix: [
        'Proper: run the app on a high port (8080) and put a reverse proxy (nginx, caddy) or systemd socket activation in front for the low port',
        'Linux capability: sudo setcap cap_net_bind_service=+ep ./myserver (no root needed afterwards)',
        'Containers: docker run --cap-add NET_BIND_SERVICE',
        'Quick and dirty: sudo ./server (know that the whole process then runs as root)'
      ],
      prevent: 'The privilege split exists so random users cannot impersonate system services (HTTP on 80, DNS on 53). Design around it, do not fight it.',
      related: ['eacces', 'eaddrinuse'],
      tip: 'setcap cap_net_bind_service=+ep gives one binary the right to bind low ports without running as root. It is the clean middle ground every self-hosted admin should know.'
    },
    {
      id: 'econnreset', err: 'Connection reset by peer', errno: 104, cat: 'net',
      aka: ['connection reset by peer', 'ECONNRESET', 'connection was reset'],
      meaning: 'The other end sent a TCP RST: the connection is gone now. Either the remote process closed abruptly (crash, killed), or something between you actively refused the established flow.',
      causes: [
        'The server process crashed or was restarted mid-conversation',
        'A load balancer or WAF killed the connection (idle timeout, request too big, policy)',
        'You kept reading/writing after the peer closed half the connection',
        'Firewall state table lost the flow (common after failovers) and answers RST'
      ],
      diagnose: [
        { cmd: 'dmesg | tail -5', why: 'On the server: did something OOM or segfault at that moment?' },
        { cmd: 'curl -v --max-time 10 URL', why: 'Reproduce and see exactly which byte the reset lands on' },
        { cmd: 'journalctl -u app --since "10 min ago"', why: 'Server-side logs for the same window' }
      ],
      fix: [
        'Server crashing: fix the crash (see the segfault and OOM entries)',
        'Idle timeout: send keepalives or heartbeats',
        'Request too big for a proxy: raise the limit or stream the upload',
        'Client side: treat resets as a fact of network life and retry idempotent requests'
      ],
      prevent: 'Long-lived connections need keepalives and reconnect logic: resets are guaranteed to happen eventually.',
      related: ['etimedout', 'econnrefused', 'ssh-closed'],
      tip: 'Reset vs clean close: a graceful close is FIN (orderly, buffers flushed). A reset is RST (data in flight is discarded). A server that resets instead of closing cleanly usually crashed or was killed.'
    },
    {
      id: 'apt-host', err: 'Could not resolve host (apt update)', errno: null, cat: 'pkg',
      aka: ['apt could not resolve', 'temporary failure resolving', 'err:1 http://...'],
      meaning: 'apt cannot reach the DNS system, so every repository URL fails at the name step. This is a network or resolver problem, not a package problem: fix DNS and apt works again.',
      causes: [
        'No internet or broken DNS on the machine',
        'DNS works in the browser but not for apt (proxy env differences, IPv6 preference)',
        'A VM or container with no working resolver'
      ],
      diagnose: [
        { cmd: 'dig archive.ubuntu.com +short', why: 'Can the system resolve at all?' },
        { cmd: 'curl -sI http://archive.ubuntu.com | head -3', why: 'Direct reachability to the repo' }
      ],
      fix: [
        'Fix DNS: /etc/resolv.conf or netplan / NetworkManager config, then dig again until it answers',
        'Broken IPv6 only: force apt to IPv4 with echo \'Acquire::ForceIPv4 "true";\' | sudo tee /etc/apt/apt.conf.d/99force-ipv4',
        'Corporate proxy: configure apt to use it (Acquire::http::Proxy)'
      ],
      prevent: 'Snapshot VMs before network changes, and keep one known-good resolv.conf backed up.',
      related: ['dns', 'unable-locate', 'apt-404'],
      tip: 'apt and browsers use the same resolver but different paths (proxies, IPv6, timeouts). When the browser works and apt does not, compare with dig and curl, not with "but the internet works".'
    },
    {
      id: 'unable-locate', err: 'E: Unable to locate package', errno: null, cat: 'pkg',
      aka: ['unable to locate package', 'no installation candidate'],
      meaning: 'apt has never heard of the package. Either the name is wrong, or your package index is missing, stale, or the package lives in a repository you have not enabled.',
      causes: [
        'Typo in the package name, or the name differs between distros (apache2 vs httpd)',
        'The package index has not been downloaded yet: fresh system, no apt update',
        'The package is in universe / multiverse / EPEL, not enabled',
        'The package genuinely does not exist for your distro or release'
      ],
      diagnose: [
        { cmd: 'sudo apt update', why: 'Refresh the index first: fixes the majority of cases on fresh systems' },
        { cmd: 'apt search keyword', why: 'Find the real name by searching, not guessing' },
        { cmd: 'apt-cache policy packagename', why: 'Shows which repository would provide it, if any' },
        { cmd: 'cat /etc/os-release', why: 'Distro and release: names differ across families and versions' }
      ],
      fix: [
        'Enable the extra repository: Ubuntu universe/multiverse via add-apt-repository, RHEL family via EPEL (dnf install epel-release)',
        'Correct name found via apt search: install that',
        'Not packaged: use the upstream project, a PPA, Flatpak, or build it, in that order of preference'
      ],
      prevent: 'On Debian family systems, universe is where half of everything lives: add-apt-repository universe once and most of these errors disappear.',
      related: ['apt-host', 'apt-404', 'unmet'],
      tip: 'Same software, different names: Apache is apache2 on Debian family and httpd on RHEL family. apt search / dnf search beats memorizing both columns.'
    },
    {
      id: 'unmet', err: 'Unmet dependencies / The following packages have unmet dependencies', errno: null, cat: 'pkg',
      aka: ['unmet dependencies', 'held broken packages', 'dependency is not satisfiable'],
      meaning: 'apt solved the dependency graph and found no valid installation: something you already have (or insist on installing) conflicts with what the new package needs.',
      causes: [
        'A pinned or held package blocks the version the new one needs',
        'Mixed repositories (stable + testing, or third-party) offering incompatible versions',
        'A partially upgraded system (packages from the previous release still installed)',
        'Manually installed .deb files whose dependencies are not in any enabled repo'
      ],
      diagnose: [
        { cmd: 'apt-get check', why: 'Confirms broken dependencies exist right now' },
        { cmd: 'apt-mark showhold', why: 'Lists held packages that pin versions' },
        { cmd: 'apt-cache policy conflicting-package', why: 'Shows candidate versions and which repo each comes from' }
      ],
      fix: [
        'Let apt fix it: sudo apt --fix-broken install',
        'Unhold the blocker: sudo apt-mark unhold package',
        'Read the conflict as a story: package A wants libfoo3, you offer libfoo2: decide which side moves',
        'Chronic mixing: pick ONE release channel and stick to it; that solves 90% of these forever'
      ],
      prevent: 'Never mix distro releases (stable + testing) casually. For one newer package, prefer backports, containers, or a dedicated VM over Franken-repos.',
      related: ['unable-locate', 'dpkg-interrupted', 'gpg'],
      tip: 'Unmet dependencies is apt being honest about math: the version graph has no solution. Read the package names in the message: they tell you exactly which two repos disagree.'
    },
    {
      id: 'dpkg-interrupted', err: 'E: dpkg was interrupted, you must manually run dpkg --configure -a', errno: null, cat: 'pkg',
      aka: ['dpkg was interrupted', 'dpkg --configure -a'],
      meaning: 'A package installation was cut off mid-flight (crash, power loss, Ctrl+C at the wrong moment) and dpkg left packages in a half-configured state. It refuses further work until you finish or clean up the pending configuration.',
      causes: [
        'A crash, reboot or Ctrl+C during apt upgrade',
        'A package maintainer script hung and was killed',
        'Disk full during unpacking (see the no-space entry)'
      ],
      diagnose: [
        { cmd: 'sudo dpkg --audit', why: 'Lists packages in a non-clean state' },
        { cmd: 'df -h /', why: 'Rule out the full disk that often caused the interruption' }
      ],
      fix: [
        'Run the command it suggests: sudo dpkg --configure -a (finishes pending configuration)',
        'Then sudo apt --fix-broken install and a full sudo apt update && sudo apt upgrade',
        'If a maintainer script keeps hanging: inspect /var/lib/dpkg/info/package.postinst before forcing anything'
      ],
      prevent: 'Do not Ctrl+C package operations: queue them instead. And keep enough free disk that upgrades never hit ENOSPC mid-unpack.',
      related: ['unmet', 'enospc'],
      tip: 'dpkg stores its pending state under /var/lib/dpkg: updates and lock files included. --configure -a walks the half-finished list and completes it in order. If it fails, dpkg --audit names the exact stuck package.'
    },
    {
      id: 'gpg', err: 'GPG error: NO_PUBKEY / The repository is not signed', errno: null, cat: 'pkg',
      aka: ['no_pubkey', 'gpg error', 'repository is not signed', 'inrelease is not valid yet'],
      meaning: 'apt verifies every repository index with GPG signatures. It found a repository whose signing key it does not have (or a signature it cannot verify), and refuses to use that repository.',
      causes: [
        'A third-party repository added without its signing key',
        'The vendor rotated their signing key (happens to everyone eventually)',
        'Clock skew on the machine making signatures look invalid',
        'A typo in the sources.list entry producing garbage responses (an HTML error page instead of an index)'
      ],
      diagnose: [
        { cmd: 'date', why: 'Wrong clock invalidates good signatures: check this first' },
        { cmd: 'sudo apt-get update 2>&1 | grep -B2 NO_PUBKEY', why: 'Shows the exact missing key ID' }
      ],
      fix: [
        'Trusted vendor path: download the key to /etc/apt/keyrings/ and reference it in the sources file (the modern signed-by form)',
        'Key rotation: remove the old key, import the new one from the vendor over HTTPS',
        'Never disable signature checking (allow-insecure) to make the error go away: that turns apt into an arbitrary code installer'
      ],
      prevent: 'Add repositories the modern way: a keyring file in /etc/apt/keyrings plus a sources entry with signed-by=. It survives key rotation cleanly.',
      related: ['unable-locate', 'apt-404'],
      tip: 'The key ID in the NO_PUBKEY message is the actual answer: fetch that exact key from the vendor over HTTPS. Random keyserver copies of "the same" ID are a supply-chain risk.'
    },
    {
      id: 'apt-404', err: '404 Not Found on repository index (apt update)', errno: null, cat: 'pkg',
      aka: ['404 not found', 'err:20 index file failed to download', 'does not have a release file'],
      meaning: 'The repository URL you have configured points at files that no longer exist there. The most common cause by far: your distro release reached end of life and the mirrors moved it to the archive.',
      causes: [
        'End-of-life release: mirrors delete old releases (Ubuntu moves them to old-releases.ubuntu.com)',
        'A third-party repository that changed its URL structure or died',
        'A typo in the sources.list line'
      ],
      diagnose: [
        { cmd: 'lsb_release -sc', why: 'Your release codename: is it still supported?' },
        { cmd: 'curl -sI http://archive.ubuntu.com/ubuntu/dists/CODENAME/Release | head -1', why: 'Check whether the index exists at the configured URL' }
      ],
      fix: [
        'EOL Ubuntu: point sources.list at old-releases.ubuntu.com (and expect no security updates: plan the upgrade)',
        'Third-party repo: check the project page for the new URL, update the sources entry',
        'Typo: fix the line, then apt update'
      ],
      prevent: 'Upgrade before end of life. A distro past EOL silently accumulates these errors until nothing installs.',
      related: ['unable-locate', 'apt-host'],
      tip: 'When every apt update line turns 404 at once, it is never 12 simultaneous typos: your release moved. Check the codename first, then rewrite sources.list once.'
    },
    {
      id: 'undefined-ref', err: 'undefined reference to `foo\' (linker)', errno: null, cat: 'build',
      aka: ['undefined reference', 'ld returned 1 exit status', 'linker error'],
      meaning: 'The compiler finished every file, but at link time something was DECLARED and USED yet never DEFINED. The linker has all your object files and libraries and still cannot find a body for that symbol.',
      causes: [
        'You declared a function (header or prototype) and called it, but forgot to write or compile its definition',
        'The definition exists in another .c file you forgot to compile or link',
        'Missing library on the link line: -lm for math, -lpthread for threads',
        'C++ name mangling: defining the function in C++ while the declaration expects C (or the reverse)',
        'A static member or extern variable declared but never defined'
      ],
      diagnose: [
        { cmd: 'nm myobj.o | grep foo', why: 'U means undefined (wanted), T means defined (provided): see which side is missing' },
        { cmd: 'g++ -v ... 2>&1 | tail -3', why: 'The exact final link command, libraries included' }
      ],
      fix: [
        'Compile all sources together: gcc main.c utils.c -o app',
        'Add the library: gcc main.c -lm (order matters: libraries AFTER the sources that need them)',
        'C/C++ mismatch: wrap the declaration in extern "C" in C++ code, or fix the header guards',
        'For a missing static member: add the definition line in exactly one .cpp file'
      ],
      prevent: 'Build systems (CMake, make) exist so you never hand-type file lists. The moment a project has three files, generate the build.',
      related: ['no-header', 'no-lib', 'mult-def', 'undefined-symbol-runtime'],
      tip: 'Compile order is the silent killer: gcc main.c -lm fails if main.c uses sqrt, because the linker processes -lm before it knows main needs it. Libraries always go last on the command line.'
    },
    {
      id: 'no-header', err: 'fatal error: foo.h: No such file or directory (compiler)', errno: 2, cat: 'build',
      aka: ['fatal error header', 'no such file or directory .h', 'include error'],
      meaning: 'The preprocessor cannot find a header you #included. Note the difference from the linker: this fails BEFORE compilation, on the very first pass over the text.',
      causes: [
        'Header name typo, or wrong <> vs "" usage',
        'The library is installed for running but not for compiling: you need the -dev / -devel package',
        'The header lives in a non-standard include directory without -I pointing at it'
      ],
      diagnose: [
        { cmd: 'find /usr -name "foo.h" 2>/dev/null', why: 'Is the header anywhere on the system?' },
        { cmd: 'apt list --installed 2>/dev/null | grep -i libfoo', why: 'Check for the runtime package without its -dev twin' }
      ],
      fix: [
        'Install the development package: sudo apt install libfoo-dev (Debian family) or dnf install libfoo-devel (RHEL family)',
        'Custom location: gcc -I/opt/foo/include ...',
        'Your own headers: use quotes #include "myfile.h" for same-directory includes'
      ],
      prevent: 'The runtime package (libssl3) lets you RUN programs. The -dev package (libssl-dev) lets you COMPILE against them. Two different jobs, two different packages.',
      related: ['no-lib', 'undefined-ref'],
      tip: 'libfoo vs libfoo-dev is the single most common C compilation confusion: the error message says a header is missing, the fix is installing a package with a completely different suffix.'
    },
    {
      id: 'no-lib', err: 'cannot find -lfoo (linker)', errno: 2, cat: 'build',
      aka: ['cannot find -l', 'ld cannot find library'],
      meaning: 'The linker was told to link library foo (via -lfoo) and could not find a libfoo.so or libfoo.a in any of its search paths.',
      causes: [
        'The library is not installed (or only the -dev metadata is missing, which actually contains the .so link)',
        'The library is in a non-standard directory without -L',
        'The name is slightly different: -lfoo vs -lfoo2 (versioned library names)'
      ],
      diagnose: [
        { cmd: 'ldconfig -p | grep libfoo', why: 'What linker-visible libraries exist' },
        { cmd: 'find / -name "libfoo*" 2>/dev/null', why: 'Find every copy on disk' }
      ],
      fix: [
        'Install the dev package for the library',
        'Custom path: gcc ... -L/opt/foo/lib -Wl,-rpath,/opt/foo/lib (rpath so it ALSO runs later)',
        'Versioned name: check the actual filename (libfoo.so.2) and install the matching unversioned symlink package'
      ],
      prevent: 'Header not found is a compile-time problem (-dev provides headers). cannot find -l is link time (-dev provides the .so). Runtime not found is ld.so territory. Three different stages, one package family.',
      related: ['no-header', 'missing-so', 'undefined-ref'],
      tip: '-L tells the linker where to LOOK at build time, -Wl,-rpath tells the runtime loader where to look EVERY time you run the binary. Forgetting rpath is why things link fine and then fail to start.'
    },
    {
      id: 'mult-def', err: 'multiple definition of `foo\'', errno: null, cat: 'build',
      aka: ['multiple definition', 'first defined here'],
      meaning: 'The linker found the same symbol defined in more than one object file. Since GCC 10, this also fires for globals and constants that used to slip through as "common symbols": the compiler became stricter, old code did not change.',
      causes: [
        'A function or global variable defined in a header that multiple .c files include',
        'Defining (not just declaring) things in headers: the header is pasted into every includer',
        'Old C code relying on GCC 9 common-symbol tolerance, compiled with GCC 10+'
      ],
      diagnose: [
        { cmd: 'nm fileA.o fileB.o | grep " T foo"', why: 'See the symbol defined in both objects' }
      ],
      fix: [
        'Functions in headers: mark them inline, or move the body to a .c file and keep only the prototype in the header',
        'Globals in headers: declare with extern in the header, define once in exactly one .c file',
        'Const tables: static const in the header (each translation unit gets its private copy, which is fine)'
      ],
      prevent: 'The golden header rule: headers DECLARE, source files DEFINE. internal extern + one definition. Violations used to be warnings; now they are errors.',
      related: ['undefined-ref'],
      tip: 'The GCC 10 change surprised everyone: -fno-common became the default, and decades of header-defined globals became multiple-definition errors overnight. Same code, stricter toolchain.'
    },
    {
      id: 'fpic', err: 'relocation R_X86_64_32 against ... can not be used when making a shared object; recompile with -fPIC', errno: null, cat: 'build',
      aka: ['recompile with -fpic', 'relocation error', 'cannot be used when making a shared object'],
      meaning: 'You are building a shared library (.so) from object files that contain absolute, non-position-independent code. Shared libraries can be loaded at any address, so every piece of code inside them must be position independent.',
      causes: [
        'Object files compiled without -fPIC then linked into a .so',
        'Mixing prebuilt static libraries (compiled without -fPIC) into your shared library',
        'Assembly files with absolute addressing inside a shared object'
      ],
      diagnose: [
        { cmd: 'readelf -r object.o | head', why: 'Shows the relocations; R_X86_64_32 types are the non-PIC ones' }
      ],
      fix: [
        'Recompile everything that goes into the .so with -fPIC (and -fPIE is the sibling for executables)',
        'Prebuilt static lib without PIC: get a -fPIC build from upstream, or compile it yourself',
        'Assembly: rewrite absolute references as RIP-relative (the same PIE lesson from the ASM Annotator)'
      ],
      prevent: 'Build scripts for libraries: put -fPIC in CFLAGS from the start. Retrofitting it later is this exact error.',
      related: ['no-lib', 'mult-def'],
      tip: 'The same idea powers exploitation: -fPIC/-fPIE means no absolute addresses, which is why PIE binaries need an address leak before ROP. Compile-time flag, runtime exploit path.'
    },
    {
      id: 'implicit-decl', err: 'warning: implicit declaration of function (C)', errno: null, cat: 'build',
      aka: ['implicit declaration', 'incompatible implicit declaration'],
      meaning: 'You called a function the compiler has never seen declared. Old C silently assumed it returns int and takes whatever you passed. Since C99 this is a warning, and modern compilers (GCC 14+) make it a hard error.',
      causes: [
        'Missing #include for the function\'s header (very common: malloc without stdlib.h)',
        'A typo in the function name',
        'Your own function defined AFTER its first call without a prototype'
      ],
      diagnose: [
        { cmd: 'man 3 functionname', why: 'The SYNOPSIS section names the exact header to include' }
      ],
      fix: [
        'Add the include the man page specifies',
        'Declare your own functions before first use, or reorder definitions',
        'Fix typos: an implicit declaration of "prinf" is really a missing printf'
      ],
      prevent: 'Compile with -Wall -Wextra and treat warnings as errors early (-Werror=implicit-function-declaration): the mismatch the compiler flags here is a real bug waiting to corrupt the stack.',
      related: ['no-header', 'undefined-ref'],
      tip: 'Implicit declarations are dangerous precisely because the call still compiles: the compiler guesses the argument conventions. On 64-bit systems, a pointer passed through a guessed int return is how stack corruption begins.'
    },
    {
      id: 'docker-sock', err: 'permission denied while trying to connect to the Docker daemon socket', errno: 13, cat: 'docker',
      aka: ['docker.sock permission denied', 'got permission denied while trying to connect'],
      meaning: 'The docker CLI talks to the daemon through the Unix socket /var/run/docker.sock, and your user has no permission on it. The socket acts like a root-equivalent door: whoever can speak to it controls the daemon.',
      causes: [
        'Your user is not in the docker group',
        'The docker group genuinely grants root-equivalent power: on hardened systems it is deliberately not granted'
      ],
      diagnose: [
        { cmd: 'ls -l /var/run/docker.sock', why: 'See the owning group (usually docker)' },
        { cmd: 'id | grep -o docker || echo "not in docker group"', why: 'Confirm the membership' }
      ],
      fix: [
        'sudo usermod -aG docker $USER then log out and back in (group changes need a new login)',
        'Or use sudo docker for one-off commands',
        'Rootless mode is the proper fix for untrusted users: it runs the daemon under your account'
      ],
      prevent: 'Know what you grant: docker group membership = root on the host, because you can mount / as a volume. Treat it like sudo, not like a convenience.',
      related: ['eacces', 'docker-daemon'],
      tip: 'docker run -v /:/host -it ubuntu chroot /host is why docker group equals root. Only add people you would trust with the root password.'
    },
    {
      id: 'docker-daemon', err: 'Cannot connect to the Docker daemon. Is the docker daemon running?', errno: 2, cat: 'docker',
      aka: ['cannot connect to the docker daemon', 'is the docker daemon running'],
      meaning: 'The CLI cannot reach the docker daemon at all. Either the daemon is not running, or the CLI is talking to the wrong place (wrong socket, wrong host, wrong context).',
      causes: [
        'The docker service is stopped or failed to start',
        'On WSL or minimal systems: the daemon was never started',
        'DOCKER_HOST environment variable pointing elsewhere',
        'A docker context switch left the CLI aimed at a dead remote'
      ],
      diagnose: [
        { cmd: 'systemctl status docker', why: 'Is the daemon up, and if not, why (journal link included)' },
        { cmd: 'echo $DOCKER_HOST; docker context ls', why: 'Where is the CLI actually pointed?' },
        { cmd: 'sudo journalctl -u docker --since "10 min ago" | tail -20', why: 'Startup failure reasons live here' }
      ],
      fix: [
        'sudo systemctl start docker (and enable for boot)',
        'WSL without systemd: start it manually with sudo service docker start or dockerd',
        'Clear a stale remote: unset DOCKER_HOST and docker context use default'
      ],
      prevent: 'On dedicated docker hosts: systemctl enable docker. On WSL: know whether your distro has systemd enabled (/etc/wsl.conf).',
      related: ['docker-sock', 'econnrefused'],
      tip: 'The CLI and the daemon are separate programs: the CLI is a client, the socket is the network, dockerd is the server. Every docker error is about one of the three, and naming them correctly makes the fix obvious.'
    },
    {
      id: 'ssh-publickey', err: 'Permission denied (publickey)', errno: null, cat: 'ssh',
      aka: ['permission denied publickey', 'publickey password', 'ssh key rejected'],
      meaning: 'The server offered publickey authentication, your client offered keys, and none were accepted. Either the server does not have your public key, or your key material has a problem (permissions, path, passphrase).',
      causes: [
        'Your public key is not in the server\'s ~/.ssh/authorized_keys (or it has a typo)',
        'Wrong key offered: ssh tries only the default keys unless told otherwise',
        'Permissions block the key: ~/.ssh or the key file too open (ssh refuses silently)',
        'Home directory or authorized_keys owned by the wrong user on the server',
        'The server only accepts publickey (PasswordAuthentication no) and your key never got installed'
      ],
      diagnose: [
        { cmd: 'ssh -v user@host 2>&1 | grep -iE "offering|denied|identity"', why: 'Verbose mode shows every key offered and each rejection' },
        { cmd: 'ls -ld ~/.ssh ~/.ssh/id_* ~/.ssh/authorized_keys 2>/dev/null', why: 'Client side: permissions must be strict (700 dir, 600 keys)' }
      ],
      fix: [
        'Install the key properly: ssh-copy-id user@host (handles permissions and the file format in one shot)',
        'Offer the right key explicitly: ssh -i ~/.ssh/mykey user@host',
        'Fix server-side perms: chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys (and ownership: chown -R user:user ~/.ssh)',
        'Read the server log when you have console access: /var/log/auth.log shows exactly why each key was refused'
      ],
      prevent: 'ssh-copy-id once, and add the key explicitly in ~/.ssh/config (IdentityFile + Host alias) so the right key is always offered.',
      related: ['ssh-refused', 'ssh-hostkey', 'ssh-toomany'],
      tip: 'Run ssh -v and read the "Offering public key" lines: you see every key tried, in order. If your key never appears in the list, the problem is client-side before the network was even involved.'
    },
    {
      id: 'ssh-refused', err: 'ssh: connect to host ... port 22: Connection refused', errno: 111, cat: 'ssh',
      aka: ['port 22 connection refused', 'ssh connection refused'],
      meaning: 'The host answered but nothing is listening on port 22 (or whatever port you targeted). Same mechanics as any connection refused: the machine is reachable, the SSH service is not there.',
      causes: [
        'sshd not installed or not running on the target',
        'The server listens on a non-standard port (2222, 22222)',
        'The port forward maps a different port: -p 2222 for the CLI',
        'Cloud firewall rejecting port 22 while allowing others'
      ],
      diagnose: [
        { cmd: 'ssh -p 2222 user@host', why: 'Try the common alternative ports' },
        { cmd: 'nmap -p 22,2222,22222 host', why: 'Scan the usual suspects in one pass' },
        { cmd: 'ssh -G host | grep -i port', why: 'Check what port your own config thinks it should use' }
      ],
      fix: [
        'On the server (console access): install and start openssh-server, systemctl enable --now ssh',
        'Non-standard port: use ssh -p PORT or set Port in ~/.ssh/config',
        'Check the cloud security group actually allows your IP on the SSH port'
      ],
      prevent: 'When provisioning servers, make SSH working a boot-time guarantee: cloud-init or your config manager installs and enables sshd before anything else.',
      related: ['econnrefused', 'ssh-publickey'],
      tip: 'Your ~/.ssh/config can pin the port once: Host mybox / HostName 1.2.3.4 / Port 2222 / User admin. Then ssh mybox just works, no flags to remember.'
    },
    {
      id: 'ssh-hostkey', err: 'Host key verification failed / REMOTE HOST IDENTIFICATION HAS CHANGED', errno: null, cat: 'ssh',
      aka: ['host key verification failed', 'host identification has changed', 'man in the middle'],
      meaning: 'The fingerprint of the server no longer matches what you recorded in known_hosts. Either the server was legitimately rebuilt, or someone is actually impersonating it. SSH refuses by design and makes you decide.',
      causes: [
        'Server rebuilt, reinstalled, or its host keys regenerated (the common case)',
        'The IP or hostname now points at a different machine (DHCP reuse, cloud IP recycling)',
        'A genuine man in the middle (rare, but this error is your only warning)',
        'Load balancer in front of several servers with different keys'
      ],
      diagnose: [
        { cmd: 'ssh-keygen -F hostname', why: 'See what fingerprint you previously recorded' },
        { cmd: 'ssh-keyscan hostname 2>/dev/null | ssh-keygen -lf -', why: 'What the server presents NOW: compare, and verify out of band if it matters' }
      ],
      fix: [
        'If you KNOW the server changed (rebuild, new instance): remove the stale entry with ssh-keygen -R hostname, then reconnect and accept the new key',
        'If you did not expect a change: stop and verify through another channel (provider console) before accepting anything',
        'Never blindly accept: the warning exists exactly for the case where accepting is the wrong move'
      ],
      prevent: 'After rebuilding a server, expect this error on first connect and clear it deliberately. For fleets, distribute host keys or use verified first-connect procedures (cloud-init fingerprints).',
      related: ['ssh-publickey', 'ssh-closed'],
      tip: 'TOFU (trust on first use) is the SSH model: the first connection is trusted blindly, every later one is verified. That is why "just delete known_hosts" must be a decision, never a reflex.'
    },
    {
      id: 'ssh-closed', err: 'Connection closed by remote host / Connection reset', errno: null, cat: 'ssh',
      aka: ['connection closed by remote host', 'connection reset by peer ssh'],
      meaning: 'The SSH connection was established, then the other side (or a middlebox) cut it. The handshake data is what separates an early close (pre-auth policy) from a mid-session drop (network or daemon).',
      causes: [
        'fail2ban or sshd policy closed the connection (too many attempts, MaxStartups)',
        'sshd crashed or was restarted while you were connected',
        'Idle timeout on a firewall or NAT gateway dropping long-silent flows',
        'The daemon closing connections before auth (DenyUsers, or a broken PAM config)'
      ],
      diagnose: [
        { cmd: 'ssh -v user@host 2>&1 | tail -15', why: 'The last exchanged messages show how far the handshake got' },
        { cmd: 'sudo journalctl -u ssh --since "15 min ago"', why: 'Server-side truth: bans, crashes, restarts' }
      ],
      fix: [
        'Banned: wait out the ban or get the admin to clear it, then use keys so attempts stop failing',
        'Idle drops: keepalives, ServerAliveInterval 60 in ~/.ssh/config',
        'Daemon crashes: read the journal, fix the config error it names'
      ],
      prevent: 'Set Client-side keepalives on every long-lived SSH session, and switch to publickey auth so fail2ban never notices you.',
      related: ['econnreset', 'ssh-publickey', 'ssh-toomany'],
      tip: 'Closed BEFORE any prompt = policy or config. Closed AFTER login = network or daemon. One glance at where it died in ssh -v output tells you which world to debug.'
    },
    {
      id: 'ssh-toomany', err: 'Too many authentication failures', errno: null, cat: 'ssh',
      aka: ['too many authentication failures', 'max auth tries'],
      meaning: 'Your client offered too many keys before the server lost patience (default MaxAuthTries 6). Every identity the agent holds gets offered, so a full agent can exhaust the budget before the right key is tried.',
      causes: [
        'ssh-agent loaded with many keys, all offered automatically',
        'IdentitiesOnly not set, so ssh guesses through every default key'
      ],
      diagnose: [
        { cmd: 'ssh-add -l', why: 'How many identities your agent offers' }
      ],
      fix: [
        'Point at the one key: ssh -o IdentitiesOnly=yes -i ~/.ssh/the_right_key user@host',
        'Make it permanent in ~/.ssh/config: IdentitiesOnly yes under the Host block',
        'Or unload keys you no longer need from the agent'
      ],
      prevent: 'The ~/.ssh/config Host block with User, IdentityFile and IdentitiesOnly yes removes this entire class: one host, one key, no guessing.',
      related: ['ssh-publickey', 'ssh-closed'],
      tip: 'The counterintuitive part: the failure is caused by having TOO MANY keys, and ssh tries them in its own order. IdentitiesOnly=yes makes the client offer exactly what you said, and nothing else.'
    }
  ];

  /* ---------- errno table (Linux generic, the classic 1-40 plus network notables) ---------- */
  const ERRNO = [
    [1, 'EPERM', 'Operation not permitted (kernel policy, not file bits)'],
    [2, 'ENOENT', 'No such file or directory'],
    [3, 'ESRCH', 'No such process'],
    [4, 'EINTR', 'Interrupted system call (a signal arrived mid-call)'],
    [5, 'EIO', 'I/O error (hardware trouble)'],
    [9, 'EBADF', 'Bad file descriptor (using a closed fd)'],
    [11, 'EAGAIN', 'Resource temporarily unavailable (would block; EWOULDBLOCK)'],
    [12, 'ENOMEM', 'Out of memory'],
    [13, 'EACCES', 'Permission denied (file permission bits)'],
    [14, 'EFAULT', 'Bad address (kernel could not access your pointer)'],
    [16, 'EBUSY', 'Device or resource busy'],
    [17, 'EEXIST', 'File exists'],
    [19, 'ENODEV', 'No such device'],
    [20, 'ENOTDIR', 'Not a directory'],
    [21, 'EISDIR', 'Is a directory'],
    [22, 'EINVAL', 'Invalid argument (the catch-all for bad inputs)'],
    [24, 'EMFILE', 'Too many open files (per-process limit)'],
    [26, 'ETXTBSY', 'Text file busy (writing to a running executable)'],
    [28, 'ENOSPC', 'No space left on device'],
    [30, 'EROFS', 'Read-only file system'],
    [31, 'EMLINK', 'Too many links'],
    [32, 'EPIPE', 'Broken pipe'],
    [36, 'ENAMETOOLONG', 'File name too long'],
    [39, 'ENOTEMPTY', 'Directory not empty'],
    [40, 'ELOOP', 'Too many levels of symbolic links (symlink cycle)'],
    [61, 'ENODATA', 'No data available'],
    [75, 'EOVERFLOW', 'Value too large for defined data type'],
    [84, 'EILSEQ', 'Invalid byte sequence (encoding trouble)'],
    [95, 'EOPNOTSUPP', 'Operation not supported'],
    [98, 'EADDRINUSE', 'Address already in use'],
    [99, 'EADDRNOTAVAIL', 'Cannot assign requested address'],
    [100, 'ENETDOWN', 'Network is down'],
    [101, 'ENETUNREACH', 'Network is unreachable'],
    [104, 'ECONNRESET', 'Connection reset by peer'],
    [110, 'ETIMEDOUT', 'Connection timed out'],
    [111, 'ECONNREFUSED', 'Connection refused'],
    [113, 'EHOSTUNREACH', 'No route to host'],
    [114, 'EALREADY', 'Operation already in progress'],
    [115, 'EINPROGRESS', 'Operation now in progress'],
    [116, 'ESTALE', 'Stale file handle (NFS classic)']
  ];

  /* ---------- signals ---------- */
  const SIGNALS = [
    [1, 'SIGHUP', 'Hangup: terminal closed, or daemons reload config on it'],
    [2, 'SIGINT', 'Interrupt: what Ctrl+C sends (catchable)'],
    [3, 'SIGQUIT', 'Quit: Ctrl+\\, dumps core on the way out'],
    [4, 'SIGILL', 'Illegal instruction: jumped to garbage or unsupported CPU op'],
    [5, 'SIGTRAP', 'Trace / breakpoint trap (debuggers live here)'],
    [6, 'SIGABRT', 'Abort: assert() and glibc heap corruption call this'],
    [7, 'SIGBUS', 'Bus error: misaligned access or truncated mmap'],
    [8, 'SIGFPE', 'Arithmetic error: integer division by zero in C'],
    [9, 'SIGKILL', 'Kill: cannot be caught, blocked or ignored (the nuke)'],
    [10, 'SIGUSR1', 'User-defined 1 (apps repurpose it)'],
    [11, 'SIGSEGV', 'Segmentation fault: invalid memory access'],
    [12, 'SIGUSR2', 'User-defined 2'],
    [13, 'SIGPIPE', 'Writing to a pipe nobody reads (the head closes early case)'],
    [14, 'SIGALRM', 'Alarm clock: alarm() and timeouts'],
    [15, 'SIGTERM', 'Termination: the polite shutdown request'],
    [16, 'SIGSTKFLT', 'Stack fault (x86 historical)'],
    [17, 'SIGCHLD', 'Child stopped or exited (reap with wait)'],
    [18, 'SIGCONT', 'Continue: resume a stopped process'],
    [19, 'SIGSTOP', 'Stop: cannot be caught, pause a process'],
    [20, 'SIGTSTP', 'Terminal stop: what Ctrl+Z sends'],
    [21, 'SIGTTIN', 'Background read from terminal: kernel stops the job'],
    [22, 'SIGTTOU', 'Background write to terminal'],
    [23, 'SIGURG', 'Urgent data on socket'],
    [24, 'SIGXCPU', 'CPU time limit exceeded'],
    [25, 'SIGXFSZ', 'File size limit exceeded'],
    [26, 'SIGVTALRM', 'Virtual alarm (process CPU time)'],
    [27, 'SIGPROF', 'Profiling alarm'],
    [28, 'SIGWINCH', 'Window resized (terminals handle it)'],
    [29, 'SIGIO', 'Asynchronous I/O possible'],
    [30, 'SIGPWR', 'Power failure (UPS drivers)'],
    [31, 'SIGSYS', 'Bad system call (seccomp blocks land here)']
  ];

  /* ---------- exit codes ---------- */
  const EXITCODES = [
    [0, 'Success: the command did its job'],
    [1, 'General failure: the catch-all error'],
    [2, 'Misuse of shell builtin (bad options, syntax in builtins)'],
    [126, 'Command found but not executable (permission or format)'],
    [127, 'Command not found'],
    [128, 'Invalid argument to exit (exit takes 0 to 255)'],
    [130, '128 + SIGINT(2): terminated by Ctrl+C'],
    [137, '128 + SIGKILL(9): killed (very often the OOM killer)'],
    [143, '128 + SIGTERM(15): terminated politely (systemd, docker stop)']
  ];

  /* ---------- trigger phrases: raw-substring boosts for confusable errors ---------- */
  const TRIG = {
    'bad-interpreter': ['bad interpreter', 'env:', '\\r', 'crlf', 'badinterpreter'],
    'spaces-path': ['too many arguments', 'argument list'],
    enoexec: ['exec format error', 'cannot execute binary file'],
    'missing-so': ['shared libraries', 'shared object'],
    'undefined-ref': ['undefined reference'],
    segfault: ['segmentation fault', 'segfault'],
    sigbus: ['bus error'],
    sigill: ['illegal instruction'],
    'sigkill-oom': ['killed', 'oom', '137'],
    eaddrinuse: ['already in use'],
    'readonly-var': ['readonly variable'],
    'bad-substitution': ['bad substitution'],
    'unary-expected': ['unary operator'],
    'docker-sock': ['docker.sock'],
    'docker-daemon': ['cannot connect to the docker daemon'],
    gpg: ['no_pubkey', 'not signed', 'gpg error'],
    'dpkg-interrupted': ['dpkg was interrupted'],
    unmet: ['unmet dependencies', 'held broken'],
    'ssh-publickey': ['publickey'],
    'ssh-hostkey': ['host key verification', 'host identification has changed'],
    'implicit-decl': ['implicit declaration'],
    'no-header': ['fatal error', '.h:'],
    'script-not-executable': ['chmod', './script', 'script.sh', 'running a script', 'cannot execute: permission', './', '.sh'],
    fpic: ['recompile with -fpic', 'making a shared object'],
    'mult-def': ['multiple definition'],
    'no-lib': ['cannot find -l'],
    econnrefused: ['connection refused'],
    etimedout: ['timed out', 'timeout'],
    ehostunreach: ['no route to host'],
    enetunreach: ['network is unreachable'],
    dns: ['could not resolve host', 'name or service not known', 'name resolution'],
    econnreset: ['reset by peer', 'connection was reset'],
    lowport: ['bind: permission denied', 'cannot bind'],
    cmdnotfound: ['command not found'],
    emfile: ['too many open files'],
    enospc: ['no space left on device'],
    erofs: ['read-only file system', 'read only file system'],
    'unable-locate': ['unable to locate package'],
    'apt-host': ['could not resolve', 'temporary failure resolving'],
    'syntax-unexpected': ['unexpected token', 'unexpected end of file'],
    'ssh-toomany': ['too many authentication failures'],
    sigterm: ['terminated'],
    coredump: ['core dumped'],
    zombie: ['defunct', 'zombie'],
    'undefined-symbol-runtime': ['symbol lookup error'],
    sigfpe: ['floating point exception'],
    'passwd-token': ['authentication token manipulation']
  };
  ERRORS.forEach(e => { if (TRIG[e.id]) e.trig = TRIG[e.id]; });

  return { CATS, ERRORS, ERRNO, SIGNALS, EXITCODES };
})();
