# S4: privilege separation without root (O4)

Spike code: `spikes/s4-privsep/` (module `mosey.spike/s4-privsep`, Go 1.27.3,
`CGO_ENABLED=0`, only `golang.org/x/sys`). Raw evidence: `data/` next to this
file. Every number below names the artifact it comes from. The machine was
Linux 6.18.60 (x86-64, 24 CPUs). During the second pass other spikes were
running and load average was about 25, so treat latency numbers as noisy
upper bounds.

This document covers both passes. The first pass committed code and some
data but no FINDINGS. The second pass answered an adversarial review (see
§7), re-ran every measurement against the real multi-process server, and
moved the first pass's raw data to `data/first-pass/`. Where a first-pass
claim had no artifact and could not be reproduced, it is withdrawn and the
text says so.

## 1. Recommendation (short)

1. **Use layout C** (built in the second pass), not O4 as written:
   - **spawner**: unsandboxed and tiny. It binds the UDP port, opens ptys,
     forks login shells (D14), spawns the helpers, and passes each pty
     master to `proto` over SCM_RIGHTS. It never reads the network and
     never holds a key.
   - **proto**: Landlock plus seccomp, `KILL_PROCESS`. It owns the UDP
     socket (recv and send), the keys, AEAD, roaming and all protocol
     parsing, and reads and writes the pty masters it was given.
   - **emu**: Landlock plus seccomp. It runs the D9 VT parser. It holds no
     key and no pty, and can type into the shell only through a strict
     reply grammar that proto (or the session) enforces.
2. **Be honest about what the sandbox buys.** A process that holds a pty
   master or the traffic key *is* the user. A compromised proto typed
   `touch ~/pwned-ipc` into the shell under every sandbox setting (red team,
   row "pwned-ipc", C/LS). For proto, Landlock and seccomp are defence in
   depth against confused-deputy and logic bugs, which are the likely bug
   class in Go. They do not contain code execution. **The emulator helper is
   the one place where the sandbox actually contains an attacker.** It also
   parses the most attacker-reachable input: anything that reaches the
   screen. Spend the hardening effort there.
3. **Roaming must use path validation**, not Mosh's "latest authentic
   source" rule. That rule lets whoever labels datagrams (a compromised
   network process, or any on-path attacker) redirect all server output to a
   victim. This was measured, see §3.7.
4. **Install seccomp with TSYNC** after start-up, with a per-role allow-list
   of 43 to 47 instructions, `PR_SET_DUMPABLE=0` first, and a
   supervisor. Pre-runtime installation works too (two ways, §3.2), but it
   buys little and costs a lot.
5. **Use Landlock through `x/sys/unix` directly**, about 150 lines, with no
   go-landlock dependency. Landlock alone is not enough: UDP, pathname unix
   sockets, io_uring, userfaultfd, user namespaces and keyctl all need
   seccomp (§3.6).
6. **macOS**: the process split carries over. Seatbelt (`sandbox_init`)
   can be called from a cgo-free Go binary, but it is deprecated and was
   never run here (§3.11). Dan decides.

## 2. What was built

One static binary re-executes itself into roles (`cmd/mosey-spike`).

| layout | processes | who holds key | who holds pty | who sends UDP |
|---|---|---|---|---|
| A (O4 as written) | session (pty, shell) + **net** (UDP, AEAD) + emu | net | session | net |
| B | session (pty, AEAD, key) + **net** (packet pump) + emu | session | session | net (session says where) |
| B2 | as B, but net is receive-only (`net-recvonly` policy) | session | session | session (shared socket) |
| **C** | **spawner** (pty, shells) + **proto** (UDP, AEAD, key) + emu | proto | spawner opens, proto uses (SCM_RIGHTS) | proto |

All layouts use the same toy wire format (`wire.go`). It is not a protocol
proposal. Packets are AES-256-GCM over `dir||seq`, with a 64-packet replay
window that is updated only after authentication. The first plaintext byte
is a frame type (data, path challenge, path response). The IPC is
`SOCK_SEQPACKET` socketpairs, so message boundaries come for free and there
are no length fields to parse.

`sandbox/` holds Landlock (`landlock_linux.go`, ABI-probed,
`syscall.AllThreadsSyscall` because 6.18 has no `LANDLOCK_RESTRICT_SELF_TSYNC`)
and a hand-assembled cBPF allow-list compiler (`seccomp.go`). The compiler
checks arch and x32, allows clone only with `CLONE_THREAD`, and maps
`clone3` to ENOSYS and `prctl` to EINVAL so the runtime falls back
gracefully. It is unit-tested by a small BPF interpreter
(`seccomp_test.go`) for amd64 and arm64.

## 3. Measurements

### 3.1 Landlock

- ABI 7 on 6.18. Handled: all fs rights (`0xffff`), TCP bind and connect,
  and scoped abstract-unix and signal. Not available on this kernel, so
  probed and reported absent: UDP rights and `FS_RESOLVE_UNIX`. Install
  time over 22 installs (red-team logs): min 151 µs, p50 1.1 ms, max
  9.0 ms (`data/redteam/rt-table.md` comments).
- The go-landlock dependency is not worth it. The deny-everything ruleset
  this design needs is about 150 lines of `x/sys` (`sandbox/landlock_linux.go`).
  go-landlock's value is path rules and best-effort ABI handling, and no
  role here needs a path. This keeps D19 intact.

### 3.2 seccomp: when to install it (TSYNC vs pre-runtime)

All three methods work in all four layouts under `KILL`
(`data/install-methods.log`, smoke test per layout × method):

| method | how | result | cost |
|---|---|---|---|
| **TSYNC** (recommended) | `prctl(NO_NEW_PRIVS)` + `seccomp(SET_MODE_FILTER, TSYNC)` after start-up and fd set-up | all threads filtered (4–5 at install). Install p50 202 µs, range 79 µs–1.2 ms over 48 installs | start-up code (ours, before any network input) is unfiltered |
| prethread | the parent installs a broad filter on one locked OS thread and forks the child from it, so the child image starts filtered (`/proc/self/status`: `seccomp=2 filters=1` at main) | works | the thread must never exit, because `Pdeathsig` fires on the parent *thread* (measured: the child was SIGKILLed when the spawner goroutine returned). Filters stack, so the inherited filter must be a superset of every role's later policy (measured: built from NetPolicy, proto died at its first `recvmsg`). Anything the child does before its own sandbox must be in it (measured: proto died on `fsync` from `os.Stdout.Sync()`) |
| entry stub | `-ldflags=-E main.prestart`: about 30 instructions of assembly per arch that install a linker-initialised filter before `_rt0_*` | works for `net`/`emu` (`seccomp=2 filters=1` at main) | per-arch assembly; matches roles by argv string (proto not added: C/entry-stub shows proto `seccomp=0`); the filter must include all runtime start-up syscalls (`StartupExtras`), so it is broad |

Pre-runtime installation only protects our own start-up code, which reads
no network input. So the extra machinery buys nothing against the threat
model. Use TSYNC.

### 3.3 Allow-lists (what each role may call)

Method: `strace -ff` of the real B2 and C servers, unsandboxed, with every
sandboxed role churning the runtime for 20 s (GC, FreeOSMemory, stack
growth, async preemption, timers, goroutine bursts) under client traffic
(`scripts/discover.sh` → `data/discover/*.syscalls`). The first pass's
amd64 traces and its qemu-aarch64 arm64 trace are in `data/first-pass/`.
The policy (`sandbox/policy.go`) now contains only syscalls observed in
some trace, minus start-up-only calls (which run before the filter), plus
two explained exceptions:

- `exit` is kept without observation. It is how an M ends when a goroutine
  exits while locked to its thread (`runtime.exitThread`,
  `src/runtime/sys_linux_*.s`).
- `pread64` only appears when cgroup `cpu.max` exists, i.e. under a CPU
  quota. Go ≥ 1.25 `updatemaxprocs` re-reads it from sysmon
  (`data/pread64-systemd.trace`). **The unconstrained strace runs missed
  it**, so strace in a shell alone is not a sufficient method. It was found
  by a KILL soak under systemd `CPUQuota`.

Removed from the first version because they were never observed:
`mprotect, clock_nanosleep, epoll_pwait2, epoll_wait, pipe2, recvmmsg,
sendmmsg, sendmsg`, `getrandom` (net and emu), `recvmsg` (net), and
`getsockname/getpeername/getsockopt/eventfd2/epoll_create1` (start-up only).
`pipe2` is still needed in the *prethread spawn* policy, where
`exec.Cmd.Start` uses it.

| policy | role | extras over the runtime set | cBPF insns (amd64) |
|---|---|---|---|
| `net` | net in A, B | recvfrom, sendto | 45 |
| `net-recvonly` | net in B2 | recvfrom | 44 |
| `emu` | emulator helper | none (`read`/`write` on its seqpacket) | 43 |
| `proto` | proto in C | recvfrom, sendto, recvmsg (SCM_RIGHTS), getrandom (observed: 2 calls) | 47 |

The runtime set is `mmap munmap madvise clone(CLONE_THREAD only) futex
sched_yield nanosleep gettid getpid tgkill sigaltstack rt_sigaction
rt_sigprocmask rt_sigreturn exit exit_group sched_getaffinity pread64
epoll_pwait epoll_ctl clock_gettime fcntl close read write`, plus
`clone3`→ENOSYS and `prctl`→EINVAL.

**arm64 is not verified on a real kernel.** The arm64 filter is checked by
the BPF interpreter test, and the syscall set comes from a qemu-user strace
of the single-process soak (`data/first-pass/arm64-soak.syscalls`). It
builds, but the KILL policy never ran on arm64 hardware. Do not ship
`KILL_PROCESS` on linux/arm64 until a real-hardware soak passes.

### 3.4 Soaks: the real server, production policies, KILL

`scripts/soak-server.sh`: four concurrent 600 s runs
(`data/soak600-real/*.log`). Each ran the real multi-process server with
`net-recvonly`/`proto`/`emu` under `SECCOMP_RET_KILL_PROCESS`, every
sandboxed role churning the runtime for the full 600 s, and `client-load`
running a command printing about 1 KB every 50 ms through every hop.

| run | mode | output received | empty 10 s windows | sandboxed deaths |
|---|---|---|---|---|
| shell-B2 | plain child, `GOMAXPROCS` churn | 14.51 MB | 0 | 0 |
| shell-C | same | 14.49 MB | 0 | 0 |
| systemd-B2 | `systemd-run --user`, `CPUQuota=200%` (`cpu.max=200000 100000` recorded), no GOMAXPROCS calls so `pread64` runs throughout | 14.50 MB | 0 | 0 |
| systemd-C | same | 14.53 MB | 0 | 0 |

The first pass said its systemd soak ran at `CPUQuota=400%`. The committed
script and logs never recorded a quota, so that claim is withdrawn. The
quota is now printed in each log.

### 3.5 Counterfactuals (`data/counterfactuals/`)

- **Drop `pread64`, KILL, systemd CPUQuota=200%, B2 server.** With an idle
  runtime, net and emu died with SIGSYS after **60.0 s** (two runs:
  60.008 s, 60.407 s). With the runtime churning, net died after
  **1.08–1.19 s** (six respawns), and once after 7 ms. The supervisor
  respawned it with backoff of 50 ms, 100, 200, 400, 800 and 1600 ms.
  So the idle re-read interval is about 60 s and the busy one about 1 s.
  A missing syscall can stay hidden for a minute.
- **Core dumps.** The same SIGSYS with `PR_SET_DUMPABLE` left at 1 gave two
  core dumps in systemd-coredump (`coredumpctl`: SIGSYS, `present`, about
  100 KB each). With `DUMPABLE=0` there were none. A process holding keys
  must set it before anything else.
- **B2 with the shared socket connected** (red-team cell `B2c`): the
  receive-only net process sent a datagram with plain `write(2)`. See §3.6.

### 3.6 Red team: a compromised process

`scripts/redteam.py` gives the compromised process a battery of raw
syscalls run *inside* it after its sandbox (attacker code execution).
Targets are harness replicas: a fake HOME and key, a TCP and UDP listener,
a pathname unix socket standing in for `$SSH_AUTH_SOCK` and the user bus,
an abstract socket, and a same-uid sleeper that opted out of Yama. Layouts
A, B, B2 and C run the battery in net or proto; **E** runs it in the
emulator helper; **B2c** is the connected-socket counterfactual. The action
is ERRNO, so every row is reached; `data/redteam/killcheck.log` shows the
first forbidden call under KILL kills the process. Full matrix:
`data/redteam/rt-summary.md` (compact) and `rt-table.md` with
`results.json` (details). Excerpt, Y = attack worked:

| attack | none | Landlock only | seccomp only | both |
|---|---|---|---|---|
| read/write/create files, list dirs, /proc/<pid>/environ | Y | . | . | . |
| new TCP connect | Y | . | . | . |
| new UDP socket + sendto | Y | **Y** | . | . |
| pathname unix connect (agent/bus replica) | Y | **Y** (no RESOLVE_UNIX on 6.18) | . | . |
| exec /bin/sh, kill, ptrace, process_vm_readv, pidfd_getfd | Y | . | . | . |
| open /dev/ptmx or the session's pts | Y | . | . | . |
| io_uring_setup, userfaultfd, keyctl | Y | **Y** | . | . |
| clone(CLONE_NEWUSER) (fixed test, see §7) | Y | **Y** (child ran in a new userns) | . | . |
| sendto anywhere on the *inherited* UDP socket | Y in A, B, C; B2 only without seccomp | | | |
| log line injection on inherited stderr | Y everywhere | | | |

By role, with both sandboxes on:

- **A** (net holds the key): forged keystrokes ran in the shell (`pwned-ipc`).
- **B, B2** (net is a pump): no key and no forgery (the zero-tag forged
  packet was dropped). But the net process *labels source addresses*. See
  §3.7.
- **C** (proto): every escape is denied, *and* the shell ran the
  attacker's command, because proto holds the pty master. It can also send
  UDP anywhere from its socket.
- **E** (emulator): every escape is denied, and both forged replies
  (`touch …\n` and `ESC[24;80R` followed by a command and CR) were
  rejected by the session's reply grammar (`session: emu reply DENIED`
  lines in the log). `pwned-ipc` was not created. The grammar
  (`reply.go`, `reply_test.go`) accepts exactly one CPR, DA1, DA2 or
  DSR-OK reply per message, with no CR, LF or other C0 control. So it can
  never submit a line. It could still insert harmless CSI text into a line
  being edited; a vi-mode readline is the worst case.
- **B2c**: B2's no-send property depends on an invariant: the session must
  never `connect()` the shared UDP socket. The net filter keeps `write`
  (it writes IPC with it), and the connected socket turned `write` into a
  send path. The session now asserts this at start-up (`getpeername` must
  return ENOTCONN). A related finding: a compromised net with no seccomp
  that connects the shared socket leaves it connected for the *respawned*
  net, because the file description is shared.

### 3.7 Address relabelling and replay (layouts B and B2)

`scripts/relabel.py` runs a modified net process
(`MOSEY_SPIKE_REDTEAM=relabel`, sandbox on, KILL). It relays honestly,
then (1) replays the first genuine packet 300 ms later and (2) from 1.5 s
on relabels every genuine client packet as coming from a victim (a UDP
replica). In B it also diverts sends meant for the victim to the real
client. `data/redteam/relabel.md`:

| layout | roaming | client got post-relabel output (of 10) | datagrams to victim | bytes to victim | replayed command ran |
|---|---|---|---|---|---|
| B2 | trust (Mosh rule) | **0** | **25** | 1049 | 1× |
| B2 | validate | 10 | 6 (challenges only, rate-limited) | 252 | 1× |
| B | trust | 10 | 0 | 0 | 1× |
| B | validate | 10 | 0 | 0 | 1× |

- With Mosh's rule, a compromised net redirects all session output to an
  arbitrary host, so B2 does not stop it reaching arbitrary hosts. The
  first pass's "zero datagrams left the net process" was literally true
  and misleading. **A compromised net process is an on-path attacker**: it
  can drop, delay, reorder, replay (rejected by the window) and relabel.
- **validate** (`roam.go`, QUIC-style path validation, RFC 9000 §8.2):
  an authenticated packet from a new address does not move the peer. A
  sealed 16-byte challenge goes to the new address, at most 1 per 250 ms
  per address and 4/s overall, and the peer moves only on an authenticated
  echo labelled with that address. In B2 this held: the client kept
  working, and the victim got 6 × 42-byte challenges in response to the
  relabelled ~50-byte client packets. That is an amplification below 1.
- **In B, validation is defeated.** The session's final peer was the
  victim (`switches=2` with `validate`), because net carries the challenge
  and delivers it to the real client, whose answer it relabels. B's net
  can redirect anything anyway. The victim saw 0 bytes only because this
  attacker chose to divert to the client.
- In C there is no relabelling process. The kernel labels the source. So
  validation guards only against real on-path attackers, which Mosh's rule
  also exposes.
- Replay: the replayed first packet's command ran once in every row, so
  the window works. (The first pass claimed replay rejection without
  testing it. It is now tested.)

### 3.8 Crashes and supervision (`data/netcrash.log`)

Under client load, observed every 500 ms:

- **B2**: the net process was killed with SIGKILL at 5 s and SIGSYS at
  10 s. The supervisor respawned it 50.5 ms after EOF each time, with the
  inherited socket. **No empty 500 ms window.** The session state (keys,
  roaming, pty) lives in the session. (`kill -SYS` from outside shows as
  exit 2, because the Go runtime handles a sent SIGSYS; a real seccomp
  kill shows as `signal: bad system call`, §3.5.)
- **C**: proto was killed at 5 s. **The session's network is gone** (29
  empty windows to the end). The shell survived, because the spawner keeps
  a reference to the pty master. A real server must bring the client back
  through D8 resume: SSH in, the spawner starts a new proto for the same
  pty, and the session rekeys.
- Policy implemented (`netSupervisor`): backoff from 50 ms doubling to 5 s,
  reset by a good packet, at most 10 starts per 60 s, then give up. Blast
  radius: one net or proto per server, and one server per session (as with
  mosh-server).
- The emu helper is not supervised in the spike. In the pread64
  counterfactual it died alongside net and left the screen frozen. It needs
  the same supervisor, and a respawn costs a full redraw.

### 3.9 Cost of the split

- SOCK_SEQPACKET round trip, 1200 B, to a sandboxed child: p50 6.0–6.1 µs,
  p99 17.5–19.9 µs, the same with and without the sandbox (3 runs each,
  `data/bench.log`). The first pass's "9–12 µs / 39.5 µs" had no artifact
  and is superseded.
- Per-syscall filter cost (getpid through the 45-insn filter): −60 to
  +25 ns over 5 runs, which is within noise on this loaded machine
  (`data/bench.log`). The first pass's "−244 to +59 ns" is superseded.
- Keystroke→echo through the whole server (client → UDP → net/proto →
  session → pty → shell echo → emu → back), 3000 keystrokes × 3 interleaved
  rounds × 2 runs, load average about 25 (`data/rtt-run*.log`): p50 114 µs
  to 305 µs for every layout, and the ordering between layouts changes
  from round to round. **The difference between layouts is below noise and
  about 100× smaller than D11's 8 ms output-collection delay.** C has one
  IPC hop fewer than B and B2 on the input path.
- SCM_RIGHTS hand-over of a pty master to a sandboxed proto: 6–37 µs.

### 3.10 systemd --user and sshd

- Transient `systemd-run --user` units (prefix `mosey-spike-`, cleaned up)
  run every layout with the sandbox. The four soak units above all
  survived. Landlock, NO_NEW_PRIVS and seccomp need no privileges.
- From an sshd login (`scripts/sshd-login.sh`, `data/sshd-login.log`): a
  throwaway unprivileged sshd on 127.0.0.1 with its own keys, never the
  system sshd or `~/.ssh`. Both B2 and C start, detach with `setsid -f`,
  survive the ssh exit, and serve the client ("SSHD LOGIN OK").
  `systemd-run --user` from that login fails without `XDG_RUNTIME_DIR`,
  and works once it is set to `/run/user/$UID`. Caveat: this sshd ran
  without PAM as the same user, so there was no logind session; a real PAM
  login normally sets `XDG_RUNTIME_DIR`.

### 3.11 macOS (research and compile only, nothing run)

- `sandbox_init(3)` can be reached from a `CGO_ENABLED=0` binary the same
  way `x/sys/unix` reaches libSystem: `//go:cgo_import_dynamic` plus an
  assembly trampoline (`seatbelt/`). It builds for darwin/arm64 and amd64.
  The built-in `pure-computation` profile (no fs, no network, no IPC
  lookups; open fds keep working) matches proto and emu. OpenSSH's
  `sandbox-darwin.c` uses it for its pre-auth child.
- The whole API is deprecated. An OpenSSH mailing-list post
  (openssh-unix-dev, August 2026, "sandbox-darwin.c: sandbox.h is
  deprecated") quotes the current man page: these profiles "must not be
  used when building against macOS SDK >= 27.0. Processes opting into them
  will be killed". Go 1.27.3 writes `LC_BUILD_VERSION minos=13.0 sdk=26.2`
  into its Mach-O (`data/machover.log`), so today the kill would not
  trigger. A later Go that bumps the declared SDK would start killing our
  processes. This could not be checked against Apple's own copy of the page.
- Whether `sendto` on a pre-opened UDP socket survives `pure-computation`
  (roaming needs it) is unknown. `cmd/seatbelt-probe` tests exactly this
  and needs a Mac.

## 4. Which code parses attacker input, and where it runs

| input | reachable by | A | B / B2 | C |
|---|---|---|---|---|
| datagram receipt, length check | anyone on the network | net (sandboxed) | net (sandboxed, about 15 lines, no content parsing) | proto (sandboxed) |
| IPC framing net→session | the net process | session | session (unsandboxed) | none (no net process) |
| AEAD open, replay window, frame type, roaming | anyone (pre-auth: header + stdlib AEAD) | net | **session (unsandboxed)** | proto (sandboxed) |
| post-auth: SSP, channels, agent forwarding, resume (future) | key holders only | session | **session (unsandboxed)** | proto (sandboxed) |
| VT parsing of terminal output (D9) | **anyone who gets bytes onto the screen** (cat a file, curl, a git log) | emu (sandboxed) | emu (sandboxed) | emu (sandboxed) |
| emu replies into the pty | the emu process | (not built) | session filter | proto filter |
| spawn requests | proto | | | spawner (must be a tiny fixed grammar) |

With D6 (PSK over SSH), pre-auth parsing is a fixed header plus the
standard library's AEAD. B2's sandboxed net process covers almost none of
the parsing, and everything above the datagram runs unsandboxed in the
session. C moves all of that into a sandboxed process. In C only the spawn
grammar is unsandboxed, and only proto can reach it.

## 5. Recommended layout and rules

1. **Layout C.** Spawner, proto and emu as in §1. One proto and one emu
   per server; one server per session.
2. proto's policy is `proto` (47 insns). It also needs, argument-filtered:
   `ioctl(TIOCSWINSZ)` on pty masters (window size; not built), and
   `accept4` on a listening socket the spawner creates and passes, for
   agent forwarding (D15; not built).
3. emu's policy is `emu` (43 insns). proto enforces the reply grammar, and
   emu gets a supervisor and a full redraw on respawn.
4. Order of set-up in every sandboxed role: wrap the inherited fds, then
   `PR_SET_DUMPABLE=0`, then Landlock deny-all (abstract-unix and signal
   scoping), then seccomp TSYNC with `KILL_PROCESS`, then read input.
5. Roaming uses path validation (§3.7). Dan decides, because it touches S1.
6. CI gate: a KILL soak of the real server under `CPUQuota` (so `pread64`
   runs) for at least 120 s (idle re-read is about 60 s) per Go upgrade and
   per arch. Run it on arm64 hardware before arm64 ships with KILL.
7. If B2 is chosen instead: assert the never-connect invariant, or give net
   its own socket, and use path validation.

## 6. Open questions for Dan

See `decisions_for_dan` in the spike result. In short: layout (C, or B2,
or C plus a receive-only pump); roaming validation and its latency
trade-off; KILL vs ERRNO for production; macOS (deprecated Seatbelt or
nothing); and how arm64 KILL gets verified.

## 7. Review response

| # | review point | response |
|---|---|---|
| 1, 8 (major) | In B and B2 net chooses where replies go via the address label; no relabel test | **Accepted and fixed.** The comment is corrected (`netproc.go`). A relabel and replay red team was added (§3.7): under Mosh's rule, B2 sent 25 datagrams of session output to the victim and the client got nothing. Path validation (`roam.go`) was implemented and fixed it for B2 (6 rate-limited 42 B challenges, client unaffected). In B it is shown to be defeated. A compromised net is described as an on-path attacker. The option of "the session reads the source address from its own recvmsg" was not built: if the session also read the socket, net would have nothing to do. C gets the same effect, because the kernel labels the source. |
| 2, 9 (major) | B2 leaves the session, which holds all parsing, unsandboxed; the OpenSSH-shaped split was never built | **Accepted and built.** Layout C (§2) was red-teamed in all 4 sandbox settings, soaked 2 × 600 s under KILL, benchmarked, and supervision-tested. The parsing table is §4. "Can't be sandboxed" only applies to the process that execs shells, as the reviewer said. Result: C sandboxes all protocol parsing at no measurable latency cost. It does not contain code execution in proto, because the pty master is the user; the red team shows this. The recommendation changed from B2 to C. |
| 3 (major) | "net handles DoS cookies" contradicts net being receive-only | **Accepted.** In B2 every pre-auth reply must come from the session, so each spoofed handshake costs the unsandboxed session work. In C proto does both receive and reply in one sandboxed process, so the contradiction goes away. The cookie, if S1 needs one (D6 PSK may make it unnecessary), lives in proto. The DoS budget is S1's to size. |
| 4 (minor) | the recommended configuration was never soaked under KILL | **Fixed.** Four 600 s soaks of the real B2 and C servers with `net-recvonly`/`proto`/`emu` under KILL: shell with GOMAXPROCS churn, and systemd with CPUQuota=200% and no churn. 0 deaths. (§3.4) |
| 5, 12 (minor) | the allow-list has unobserved entries; pread64 missed by strace | **Fixed.** The policy is observed-only plus `exit` (with a runtime source path). The removed list is in the code. The strace miss of `pread64` is stated (§3.3). The pread64 kill counterfactual and coredump on/off logs are committed (§3.5). The kill time is **60 s idle / 1.1 s busy**; the first pass reported only the busy case. |
| 6, 15 (minor) | the unshare(CLONE_NEWUSER) row is a false negative | **Fixed.** It is replaced by raw `clone(CLONE_NEWUSER\|SIGCHLD)` from a forked child. Under no sandbox and under Landlock only, the child ran in a new user namespace (exit 42). seccomp blocks it. It is listed among the Landlock-only gaps (§3.6). |
| 7, 16 (minor) | B2 relies on the shared socket never being connected | **Measured and guarded.** The B2c counterfactual shows `write` becomes a send path. The session asserts ENOTCONN at start-up. The invariant is written in `NetRecvOnlyPolicy` and §5. Also found: connect state survives net respawns. C has no shared socket. |
| 8 (minor) | no recovery when net dies | **Fixed for B and B2** (supervisor, §3.8): 50 ms respawn, no visible gap under load. For C, a proto death loses the network until D8 resume; this was measured and is stated. emu supervision is not built; this is stated. |
| 10 (major) | missing artifacts and missing FINDINGS | **Fixed.** This file exists. Every number cites `data/`. First-pass claims without artifacts were re-measured (IPC, seccomp bench, TSYNC timings, pread64, coredump, install methods, sshd, machover) or withdrawn (CPUQuota=400%). Old data is in `data/first-pass/`. |
| 11 (minor) | arm64 never ran under KILL on a real kernel | **Accepted.** Labelled unverified (§3.3), with a gate before shipping (§5.6). No arm64 hardware was available to this spike. |
| 13 (minor) | replay not tested; no window | **Fixed.** There is now a 64-packet window (updated after auth, so reordering is accepted). The relabel red team replays a genuine packet, and its command ran once. |
| 14 (minor) | the emu sandbox and the reply grammar were not exercised | **Fixed.** The battery runs inside emu (cell E, 4 settings) and `EmuPolicy` lost sendto/sendmsg (never observed). The reply grammar is built (`reply.go`), unit-tested against forged streams, and red-teamed: forged replies were DENIED and `pwned-ipc` was not created. |

A harness bug found and fixed along the way: the red-team net process
ended with a bare `select {}`. Go reports that as a deadlock and exits 2,
so the new supervisor respawned net and the battery ran repeatedly. The
second run inherited the socket the first run had connected. Net now
sleeps forever after the battery, and the published matrix comes from the
fixed run.

## 8. Challenges to locked decisions

None. D9 (server-side emulation) holds up better for this work: the
emulator is the one role where the sandbox truly contains an attacker. Its
query replies need the grammar in §3.6. That adds to D9 rather than
challenging it.

## 9. Not done / bounded

- arm64 KILL on real hardware, and Seatbelt on a Mac (no hardware).
- `ioctl(TIOCSWINSZ)` and `accept4` (agent forwarding) in the proto policy:
  named, not built.
- emu supervision; spawner→proto protocol for *new* sessions and for D8
  resume (one pty was handed over once).
- Soaks were 600 s, four of them, on one kernel (6.18.60). The latency
  numbers come from a machine shared with other spikes at load average
  about 25.
- The toy wire format is not S1's protocol. Roaming validation is a
  prototype with fixed constants (250 ms per address, 4/s, 8 pending).
