Columns: layout/sandbox (0 none, L Landlock, S seccomp, LS both). A,B,B2,C: battery in net (A,B,B2) or proto (C). E: battery in the emulator helper. B2c: B2 with the shared UDP socket connected (counterfactual).

| attack | A/0 | A/L | A/S | A/LS | B/0 | B/L | B/S | B/LS | B2/0 | B2/L | B2/S | B2/LS | C/0 | C/L | C/S | C/LS | E/0 | E/L | E/S | E/LS | B2c/LS |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| fs.read ~/.ssh/id_ed25519 | Y | . | . | . | Y | . | . | . | Y | . | . | . | Y | . | . | . | Y | . | . | . | . |
| fs.append ~/.bashrc | Y | . | . | . | Y | . | . | . | Y | . | . | . | Y | . | . | . | Y | . | . | . | . |
| fs.create ~/pwned-fs | Y | . | . | . | Y | . | . | . | Y | . | . | . | Y | . | . | . | Y | . | . | . | . |
| fs.list /tmp | Y | . | . | . | Y | . | . | . | Y | . | . | . | Y | . | . | . | Y | . | . | . | . |
| fs.read /proc/<session>/environ | Y | . | . | . | Y | . | . | . | Y | . | . | . | Y | . | . | . | Y | . | . | . | . |
| fs.open /proc/<session>/mem | . | . | . | . | . | . | . | . | . | . | . | . | . | . | . | . | . | . | . | . | . |
| net.new TCP socket + connect | Y | . | . | . | Y | . | . | . | Y | . | . | . | Y | . | . | . | Y | . | . | . | . |
| net.new UDP socket + sendto | Y | Y | . | . | Y | Y | . | . | Y | Y | . | . | Y | Y | . | . | Y | Y | . | . | . |
| net.inherited UDP sendto anywhere | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | . | . | Y | Y | Y | Y | n/a | n/a | n/a | n/a | . |
| net.write() on inherited UDP fd | . | . | . | . | . | . | . | . | . | . | . | . | . | . | . | . | n/a | n/a | n/a | n/a | Y |
| unix.connect path (agent/bus replica) | Y | Y | . | . | Y | Y | . | . | Y | Y | . | . | Y | Y | . | . | Y | Y | . | . | . |
| unix.connect abstract | Y | . | . | . | Y | . | . | . | Y | . | . | . | Y | . | . | . | Y | . | . | . | . |
| connect() re-targets the inherited UDP fd | Y | Y | . | . | Y | Y | . | . | Y | Y | . | . | Y | Y | . | . | n/a | n/a | n/a | n/a | . |
| net.setsockopt on inherited UDP fd | Y | Y | . | . | Y | Y | . | . | Y | Y | . | . | Y | Y | . | . | n/a | n/a | n/a | n/a | . |
| log.write to inherited stderr (log injection) | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y |
| exec /bin/sh (fork+exec) | Y | . | . | . | Y | . | . | . | Y | . | . | . | Y | . | . | . | Y | . | . | . | . |
| kill(session, 0) | Y | . | . | . | Y | . | . | . | Y | . | . | . | Y | . | . | . | Y | . | . | . | . |
| kill(other same-uid process, 0) | Y | . | . | . | Y | . | . | . | Y | . | . | . | Y | . | . | . | Y | . | . | . | . |
| ptrace(SEIZE, other process) | Y | . | . | . | Y | . | . | . | Y | . | . | . | Y | . | . | . | Y | . | . | . | . |
| process_vm_readv(other process) | Y | . | . | . | Y | . | . | . | Y | . | . | . | Y | . | . | . | Y | . | . | . | . |
| pidfd_getfd(other process, fd 1) | Y | . | . | . | Y | . | . | . | Y | . | . | . | Y | . | . | . | Y | . | . | . | . |
| pty.open /dev/ptmx | Y | . | . | . | Y | . | . | . | Y | . | . | . | Y | . | . | . | Y | . | . | . | . |
| pty.open session's /dev/pts/N (read = steal keystrokes) | Y | . | . | . | Y | . | . | . | Y | . | . | . | Y | . | . | . | Y | . | . | . | . |
| io_uring_setup | Y | Y | . | . | Y | Y | . | . | Y | Y | . | . | Y | Y | . | . | Y | Y | . | . | . |
| userfaultfd | Y | Y | . | . | Y | Y | . | . | Y | Y | . | . | Y | Y | . | . | Y | Y | . | . | . |
| clone(CLONE_NEWUSER) from a forked child | Y | Y | . | . | Y | Y | . | . | Y | Y | . | . | Y | Y | . | . | Y | Y | . | . | . |
| keyctl(user keyring) | Y | Y | . | . | Y | Y | . | . | Y | Y | . | . | Y | Y | . | . | Y | Y | . | . | . |
| secret: this process holds the session traffic key | Y | Y | Y | Y | . | . | . | . | . | . | . | . | Y | Y | Y | Y | . | . | . | . | . |
| forge input to the shell | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y |
| _effect_: ~/pwned-ipc exists (shell ran forged keystrokes) | Y | Y | Y | Y | . | . | . | . | . | . | . | . | Y | Y | Y | Y | . | . | . | . | . |
| _effect_: ~/pwned-exec exists (exec'd shell ran) | Y | . | . | . | Y | . | . | . | Y | . | . | . | Y | . | . | . | Y | . | . | . | . |
| _effect_: ~/pwned-fs exists | Y | . | . | . | Y | . | . | . | Y | . | . | . | Y | . | . | . | Y | . | . | . | . |
| _effect_: ~/.bashrc modified | Y | . | . | . | Y | . | . | . | Y | . | . | . | Y | . | . | . | Y | . | . | . | . |
| _effect_: tcp listener accepted | Y | . | . | . | Y | . | . | . | Y | . | . | . | Y | . | . | . | Y | . | . | . | . |
| _effect_: unix (agent/bus replica) accepted | Y | Y | . | . | Y | Y | . | . | Y | Y | . | . | Y | Y | . | . | Y | Y | . | . | . |
| _effect_: abstract unix accepted | Y | . | . | . | Y | . | . | . | Y | . | . | . | Y | . | . | . | Y | . | . | . | . |
| _effect_: udp datagrams received | inherited,new | inherited,new | inherited | inherited | inherited,new | inherited,new | inherited | inherited | inherited,new | inherited,new | . | . | inherited,new | inherited,new | inherited | inherited | new | new | . | . | write |
