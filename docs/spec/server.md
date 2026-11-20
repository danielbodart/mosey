# Server: roles, IPC, sandbox

This is the spec for `mosey --serve`: layout C of S4 (D22). It says which
processes the server runs, what each one holds, every message they send
each other, byte by byte, the grammar proto holds emu's replies to, the
sandbox each role runs in and the order it is entered, how the roles are
supervised, the KILL soak CI gate, and what the platform layer leaves
for macOS. The code in `internal/server`, `internal/ipc`, `internal/pty`,
`internal/sandbox` and `cmd/mosey/server.go` is written from it.

PLAN §2 is locked; where this spec cites a decision, the decision wins.
Where the architecture interfaces must change to match it, §11 lists the
change; nothing here is in force against another owner's package until
it is agreed and `architecture.md` updated in the same commit.

**Provenance tags.** Every constant says where it comes from:

| tag | meaning |
|---|---|
| [Dnn] | a locked decision in PLAN §2 |
| [S4 §x], [S2 §x] | measured in that spike; the section of its FINDINGS.md |
| [RFC nnnn], [mosh(1)], [kernel ABI] | a published standard, man page or the Linux user-space ABI |
| [derived] | our own choice, with the reasoning next to it; to be confirmed by the test named |

Clean room (PLAN §4): nothing here comes from Mosh's source. The port
range comes from Mosh's man page; everything else is S2, S4, an RFC or
ours.

---

## 1. Roles

One `mosey --serve` per session. mosey is one binary (D7): every role is
the same file, re-executed with a flag. A plain word never selects a role
(`mosey server` connects to a host called server).

| argv | role | sandboxed | lives |
|---|---|---|---|
| `mosey --serve` | **launcher**: ssh's child. Reads the client's line, starts the spawner, relays the credential line, exits | no | seconds |
| `mosey --serve=spawner` | **spawner**: binds UDP, opens the pty, starts the shell, starts and supervises proto and emu | no | the session |
| `mosey --serve=proto` | **proto**: keys, UDP, transport, SSP, every protocol parser, the pty master, the reply grammar | Landlock + seccomp | the session |
| `mosey --serve=emu` | **emu**: tuios.dev/vt and nothing else | Landlock + seccomp | until it dies; restarted |
| `mosey --serve=protocol` | prints the bootstrap line version and the handshake protocol, `1 1` (D7's probe asks `~/.local/bin/mosey`, `bootstrap.md` §4.7.2) | no | instant |
| `mosey --serve=install HASH SIZE TEMP` | installs the uploaded copy it is running from as `~/.local/bin/mosey` (D7, `bootstrap.md` §4.7.7) | no | instant |
| `mosey --serve=list` | **lister**: reads every session's greeting (§2.6) and prints one line each (`bootstrap.md` §9.4) | no | instant |

Any other `--serve=` value prints `mosey --serve: unknown role` and exits
2 (already in `cmd/mosey/server.go`).

### 1.1 Why a launcher

The spawner has to outlive the ssh command, and ssh does not exit until
the process it started has exited and every copy of its stdout and
stderr pipes is closed. The process ssh starts cannot simply detach:
sshd makes the remote command's shell a session leader, and the shell
execs a simple command in place, so `mosey --serve` is itself a session
leader and `setsid(2)` fails with EPERM [kernel ABI]. S4 detached with
`setsid -f`, which forks (S4 §3.10). Go cannot fork without exec, so the
fork is an exec: the launcher starts `mosey --serve=spawner` in a new
session and exits once the credential is out. The spawner is then the
parent of proto, emu and the shell for the whole session, which matters
because `Pdeathsig` fires when the *parent* goes (S4 §3.2).

### 1.2 What each role holds, and what its compromise costs

| role | holds | parses (attacker-reachable) | if compromised |
|---|---|---|---|
| launcher | ssh's stdin, stdout, stderr | the `ClientLine` (from whoever controls the ssh session: the user) | nothing an ssh login does not already give |
| spawner | the pty master (its own reference), the shell's pid, the children's pids, the log file | the `ClientLine` again; proto's messages (§3.4); the roles' stderr lines (§6.4); on the attach socket, the attach protocol (§2.8) | the user. It is never reachable from the network or from emu directly; only proto can reach its parser, and only with three fixed layouts |
| proto | the session's keys, the UDP socket, the pty master, its IPC sockets | every datagram (pre-auth: a fixed header and stdlib AEAD; post-auth: SSP, the screen and input diffs), emu's messages, the spawner's messages | **the user**: it holds the pty master and can type into the shell (S4 §3.6, row C). The sandbox is defence in depth against logic bugs, not containment |
| emu | its IPC socket, its stderr pipe | everything that reaches the screen (D9): the most attacker-reachable input mosey has | **contained** (S4 §3.6, row E): no file, no socket, no pty, no key, and no signal to any other process. The last holds on every kernel, with or without Landlock: seccomp alone denies `kill`, and filters `tgkill` to emu's own pid and `fcntl` to commands that cannot arm `O_ASYNC` (§6.3). It can feed proto screen diffs, which proto validates with the same decoder the client uses, and replies, which proto filters through §4. Worst case: wrong pixels on screen, a blank screen for a while (§5.2), and a few tokens of harmless reply-shaped text in a line being edited (§4.1, S4 §3.6) |

The spawner never reads the network and never holds a key after proto
mints it (it sees the credential line on its way to stdout, which is
D20's threat model: SSH need only be authentic).

---

## 2. Life of a session

### 2.1 Bootstrap (launcher and spawner)

Numbers in brackets are the timeouts of §8.

```
ssh ──stdin──► launcher                       spawner                proto             emu
                │ read ClientLine [T1]
                │ parse (bootstrap.ParseClientLine)
                │ socketpair B; start spawner (setsid) with B on fd 3
                │──ClientLine──────────────────►│
                │                               │ parse again
                │                               │ open log; bind UDP; open pty
                │                               │ start emu; limit its memory (§6.3)
                │                               │ start proto
                │                               │──Start{fds: udp, pty}──►│
                │                               │──EmuLink{fd, gen 1}────►│
                │                               │                         │ wrap fds
                │                               │                         │ sandbox.Enter
                │                               │                         │──Init──────►│ (emu: sandboxed
                │                               │                         │◄─Update─────│  before reading)
                │                               │                         │ mint credential
                │                               │◄──Credential{line}──────│
                │                               │ validate line [T3]
                │                               │ start the shell
                │◄──Ready{line}─────────────────│
 ssh ◄─stdout───│ print the line; exit 0        │ close B
```

0. **Launcher and spawner are not dumpable.** Each calls
   `prctl(PR_SET_DUMPABLE, 0)` (`nocore.NotDumpable`) first, before the
   credential line passes through it, so the user's other processes
   cannot read it from them and a crash leaves no core of it
   (`threat-model.md` §4.10). Neither sets `RLIMIT_CORE`: an rlimit is
   inherited across `exec`, and the login shell keeps the user's own
   core-dump settings; `DUMPABLE` is reset by `execve`, so the shell is
   untouched by it. proto and emu do both (§6.1).
1. **Launcher reads the line.** Stdin to EOF, at most `MaxClientLine`
   + 1 bytes, within T1; it must be exactly one line (`bootstrap.md`
   §4.4). `bootstrap.ParseClientLine` decides validity, then the
   protocol version and the reserved fields are checked (`bootstrap.md`
   §6.2, §6.4); the line carries no software version. Any failure is one line on
   stderr, the matching `MOSEY-ERROR` line (`line`, `version` or
   `unsupported`) on stdout, and exit 1; nothing else has started.
   When it is to start a session and the line has a `dir`, the launcher
   checks, before starting anything, that it names a directory
   (`bootstrap.md` §9.2.3); if not, the same with code `dir`.
2. **Launcher starts the spawner**: `exec.Cmd{Path: Self, Args: [Self,
   "--serve=spawner"]}` (`Self` is `/proc/self/exe` on Linux, §2.3), `SysProcAttr{Setsid: true}`, stdin and stdout
   `/dev/null`, stderr `/dev/null` (the spawner opens its own log; it
   must hold no copy of ssh's pipes, or ssh would wait for it), one
   extra file: its end of a seqpacket socketpair B, as fd 3. Environment:
   the launcher's own, unchanged (the spawner needs `SSH_CONNECTION`,
   `HOME`, `SHELL`, `XDG_*`, `PATH`). No `Pdeathsig`: the spawner must
   outlive the launcher.
3. **Launcher sends `ClientLine`** (0x40) on B and waits up to T2 for
   `Ready` (0x41) or `Failed` (0x42). `Ready`: write the line to stdout
   exactly as received (the spawner has already validated it) in one
   write, exit 0. `Failed`: write `mosey --serve: <text>` to stderr and
   `MOSEY-ERROR <proto> internal -` to stdout, exit 1. EOF, any other
   message or T2 expiring: the same, with the text `the server did not
   start`. In every failure case the launcher SIGKILLs the spawner
   before exiting, so nothing is left running (`bootstrap.md` §4.4).
4. **Spawner.** In this order, each failure being `Failed{text}` to the
   launcher, the teardown of §2.4 for whatever has started, and exit 1:
   1. Wrap fd 3 as an `ipc.Conn`; receive `ClientLine` within T2; parse
      it again (the spawner trusts no other process's parse). Clamp the
      size with `screen.ClampSize`.
   2. `chdir("/")` so the spawner pins no mount, ignore SIGHUP and
      SIGPIPE, and open the session log (§6.4).
   3. Bind the UDP socket (§2.2).
   4. Open the pty at the clamped size (`pty.Open`).
   5. Start emu (§2.3) and limit its memory (§6.3). If `RLIMIT_DATA`
      cannot be set on it, kill it and fail: mosey never runs an emu
      with no memory bound.
   6. Start proto (§2.3). Send `Start` with the UDP socket and the pty
      master, then `EmuLink` (generation 1) with proto's end of the emu
      socketpair. Close the spawner's copies of the UDP socket and of
      the emu socket: the spawner never touches the network or emu's
      traffic (S4 §1).
   7. Wait up to T3 for `Credential` (0x30). Validate it (§3.4). An
      `Exit` instead carries proto's reason for `Failed`.
   8. Make the session directory and the attach socket (§2.6), now that
      the credential has named the session, and, if the `ClientLine`
      says `!agent=yes`, the agent socket (§2.7). A failure is logged; the
      session goes on, not resumable or without an agent.
   9. Start the login shell on the pty's slave (§2.5), then close the
      slave. The shell starts this late so a failure earlier leaves no
      shell behind, and so its start-up overlaps the client's handshake
      (except with a `type`, whose `Ready` waits for the shell's first
      output, below). If the line has a `type`, wait for proto's `FirstOutput`
      and then for the pty to stop echoing, or `TypeWait` (2 s), whichever
      comes first, then write its text and
      one CR to the pty master, in one write (`bootstrap.md` §9.2.3); a
      failure is logged and the session goes on.
   10. Send `Ready{line}` to the launcher and close B. From here on the
      launcher's fate does not matter.
   11. Supervise (§5) and serve the attach socket until the session ends
       (§2.4).

### 2.2 The UDP socket

- **Address** (`bootstrap.md` §4.4, §6.3). The *advertised* address is
  the third field of `SSH_CONNECTION`, parsed with `netip.ParseAddr`,
  unmapped and with any zone dropped: the address the client's ssh
  reached. The spawner binds to it, so replies leave from the address
  the client sends to on a multihomed host; this is Mosh's default,
  `--bind-server=ssh` [mosh(1)]. When there is no usable
  `SSH_CONNECTION` (absent, or not four fields) there is no advertised
  address (the line carries `-`) and the spawner binds the wildcard
  `[::]`, dual-stack, falling back to `0.0.0.0` on a host without IPv6.
  A link-local IPv6 address is advertised but cannot be bound without
  its zone, so the spawner binds `[::]` for it. `Spawner.BindAddr`
  overrides both, for tests.
- **Port.** The first free port from `FirstPort` to `LastPort`
  (60000–61000 [mosh(1)], so a firewall opened for Mosh lets mosey
  through), trying each in order: `EADDRINUSE` moves to the next, any
  other error stops. None free: `Failed{"no free UDP port in
  60000-61000"}`. Sequential is enough: a credential is needed to talk
  to the port, so its predictability costs nothing.
- **Shape.** `socket(AF_INET|AF_INET6, SOCK_DGRAM|SOCK_CLOEXEC, 0)`,
  bound, **never connected** (proto sends with `sendto` to whatever
  address path validation has settled on, D21), blocking mode is
  proto's business once wrapped. No socket options in slice 1.
- The advertised address (or none) and the bound port go to proto in
  `Start`, so proto can write them into the credential line, and the
  spawner checks the line carries exactly them (§3.4).

### 2.3 Starting proto and emu

Both are started the same way:

- `Path`: `Spawner.Self`, which on Linux is `/proc/self/exe`, never the
  file's path: D7 replaces `~/.local/bin/mosey` in place when a client
  of another protocol needs it (`bootstrap.md` §4.7.7), and a running
  session that restarts emu, or a session started a moment before the
  rename, must exec its own binary, not the new file at the old path.
  `Args: [Self-path, "--serve=proto"]` or `"--serve=emu"`, the path
  (`os.Executable()`) as argv[0], so `ps` and the tests still see which
  file it came from. Elsewhere (no server yet, D22) `Self` is
  `os.Executable()`.
- `Env: []string{}`: no `HOME`, no `SSH_AUTH_SOCK`, no bus address,
  nothing a confused role could follow (S4 `childEnv`). A `soak` build
  (§9) passes `MOSEY_SOAK_*` and nothing else.
- stdin and stdout `/dev/null`; stderr the write end of a pipe the
  spawner reads (§6.4); `ExtraFiles`: exactly one, the role's seqpacket
  socket, which arrives as fd 3 (`ipcFD` in `cmd/mosey/server.go`).
- `SysProcAttr{Pdeathsig: SIGKILL}` (Linux), so a spawner that is
  SIGKILLed takes its roles with it. `Pdeathsig` fires when the thread
  that forked the child exits, not the process (S4 §3.2, measured), so
  every child, including each emu restart, is started from one
  goroutine that has called `runtime.LockOSThread` and never returns
  while the spawner runs. EOF on the role's socket is the primary way a
  role learns its parent is gone; `Pdeathsig` is the backstop.
- Socketpairs are `socketpair(AF_UNIX,
  SOCK_SEQPACKET|SOCK_CLOEXEC|SOCK_NONBLOCK, 0)` (`ipc.Pair`): CLOEXEC on
  both ends, so nothing leaks into the shell; `ExtraFiles` clears CLOEXEC
  on the child's copy only. Non-blocking so the receiving end can be
  wrapped as a pollable `os.File`, which is what lets proto put a
  deadline on E (T4) when it wraps a new E inside its sandbox (§3.6).
  The spawner keeps proto's end of each E as a bare fd number and never
  wraps it in an `os.File`, because `(*os.File).Fd` would switch it back
  to blocking mode.

Two pairs: **C** (control) spawner↔proto, and **E** (emulator)
proto↔emu, which the spawner creates and hands out, one end to emu at
exec and the other to proto in `EmuLink`. A new E is made for every emu
generation.

### 2.4 How a session ends

| trigger | who sees it | what happens |
|---|---|---|
| the shell exits | spawner (`wait4`) | the spawner closes the agent and attach sockets at once, as the teardown does, so the session is no longer listed and a plain `mosey DEST` cannot pick an ending session to resume; then `ShellExit{status}` to proto, which drains the pty until EIO or T5, at full speed (the hold of `screen.md` §2.5 ends with the shell, so D8 R4's "any exit of the shell ends the session" holds; a flood the shell's last program left unread may then be cut with a marker), lets SSP deliver the final screen (until the client acks it, or T6), tells the client the session is over with `Conn.End(EndShellExited)` (`transport.md` §8.4) and sends `Exit{ShellExited}`. If no client has attached yet, which is the rule for a quick command (`mosey HOST ls`, `bootstrap.md` §9.2.3: it can end before the client has read its credential), proto first waits for the first client, within the no-client bound below, so that client is shown the final screen and told, rather than dialling a session already gone |
| no client ever confirms a credential | proto | once every credential it minted has expired unconfirmed (`handshake.CredentialTTL`, 30 s [D20], from the last one minted) with no client ever attached, nothing can connect, so `Exit{NoClient}` |
| the client detaches | proto (`transport.Ended`, or its connection failing) | **the session does not end** (D8, `bootstrap.md` §9.3): proto closes that connection, tells the spawner (`Detached`) and waits for a resume |
| the client falls silent | proto (nothing authentic from it for `SilentAfter`, 15 s, `bootstrap.md` §9.2) | **the session does not end**: proto keeps the connection, since the client may be in a dead spot, stops holding the program back (`screen.md` §2.5), and tells the spawner `Detached`, so a plain `mosey DEST` may take it (D8 R1); when the client is heard again proto says `Attached` again |
| detached for `IdleTimeout` (7 days, D8 R4) | spawner (a timer from the last `Detached`, stopped by each `Attached`) | the spawner hangs the shell up: SIGHUP to the shell's pid and to the pty's foreground process group (`TIOCGPGRP` on its master), as a hangup does; the shell's exit is then the first row. If the shell has not exited `HangupGrace` (10 s) later, the teardown below |
| `mosey -kill NAME` | spawner (`Hangup` on the attach socket, §2.6) | as the idle timeout |
| local `mosey -close-if-idle` on `SIGHUP`/`SIGTERM` | spawner (`HangupIfIdle` on the attach socket, §2.6) | if the requesting credential still holds the session (or was its last holder, with no takeover in flight) and the shell is idle (foreground process group is the shell's pid and no other process in `/proc` shares its session id), as the idle timeout; otherwise nothing, and the session stays alive. Any error in the idle check fails safe and keeps the session alive |
| another client attaches | proto (`Listener.Accept`) | **the session does not end**: the listener revokes the old connection (D26, `transport.md` §8.3) and proto serves the new one |
| emu's restart budget is spent | spawner (§5.2) | **the session does not end.** The spawner pauses restarts for `EmuCooldown`, tells proto (`EmuPaused`), and tries again; the shell and proto live on. An emu failure never ends a session (§5.2) |
| proto exits or dies | spawner (`wait4`) | the session ends: with proto gone nothing holds the keys or the screen, and the resume slice does not restart it (§5.4). The spawner's own reference to the pty master is kept for a later slice that does |
| SIGTERM or SIGINT to the spawner | spawner | as for proto exiting |

Teardown, always in this order, by the spawner, and only for the
triggers above (nothing emu does is one of them):

1. If proto is alive: close C (proto treats EOF on C as "end now"),
   wait up to T7, then SIGKILL it.
2. Close the spawner's pty master. With proto gone it is the last
   master reference, so the kernel hangs the terminal up and sends
   SIGHUP (and SIGCONT) to the shell's session, as when a modem
   disconnects [kernel ABI, tty hangup]. Wait up to T8 for the shell,
   then SIGKILL the shell's pid (only its pid: a job the user
   deliberately detached with `nohup` or `setsid` survives, as it does
   after an ssh logout).
3. Close emu's E if the spawner still holds a copy (it does not after
   step 4.6 of §2.1; proto's copy closed with proto), wait up to T9 for
   emu, then SIGKILL it. Remove its scope unit if one was made (§6.3).
4. Log the end (reason, codes, how long it ran) and exit 0, or 1 if the
   session ended on an error.

### 2.5 The login shell (D14)

- **Which shell.** `$SHELL` if it is an absolute path to an executable
  file. sshd sets it from the password database through NSS, which a
  `CGO_ENABLED=0` binary cannot query, so it is the only way to see an
  LDAP or sssd user's shell. Else the shell field of the current uid's
  line in `/etc/passwd`, parsed by the spawner (Go's `os/user` does not
  expose it). Else `/bin/sh`.
- **Directory.** The home directory: `$HOME`, else the passwd home,
  else `/`. If the `ClientLine` has a `dir` (`bootstrap.md` §9.2.3), that
  directory instead: as it is if absolute, else joined to the home
  directory. One that is not a directory fails the start.
- **argv[0]** is `-` plus the shell's base name, the login-shell
  convention (S4 `startShell`).
- **A command.** If the `ClientLine` has a `cmd` (`bootstrap.md` §9.2.3),
  the same shell, argv[0], directory and environment, with the arguments
  `-c` and the command's text as one argument: `-bash -c 'claude'`. The
  text goes to `exec` as it is, so the user's shell is the only one that
  reads it (Dan, 2026-11-16: as `ssh HOST COMMAND`). The spawner keeps
  the text for the greeting (§2.6), never for running it again.
- **Process.** `SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}`,
  stdin, stdout and stderr all the slave. No `Pdeathsig`: the shell
  belongs to the user, and teardown hangs it up instead (§2.4).
- **Environment.** The spawner's own environment (sshd's, so
  `SSH_CONNECTION`, `SSH_CLIENT`, `USER`, `LOGNAME`, `PATH`, `MAIL` are
  as an ssh login has them), with these changes:
  - `SSH_TTY` removed: it names no tty of this session.
  - `SSH_AUTH_SOCK` removed: sshd's socket dies with the bootstrap
    connection (`bootstrap.md` §4.4). If the agent socket was made (§2.7)
    it is set to that socket's path instead.
  - `TERM=xterm-256color`, whatever the client sent [derived]: the
    shell's programs talk to the server's emulator, not to the client's
    terminal (D9, `bootstrap.md` §6.2), and tuios emulates an xterm with
    256 colours and truecolor. The client's own `TERM` is for the
    client's renderer.
  - `COLORTERM` as the client sent it, or unset: whether truecolor is
    worth emitting depends on what the user's terminal can show
    (§11, item 9).
  - The locale variables (`LANG`, `LANGUAGE`, `LC_*`) from the
    `ClientLine`, replacing any of the same name.
  - **Hopping** (D7, `bootstrap.md` §4.7.9): if the spawner's binary is
    `$HOME/.local/bin/mosey` (the same file, by device and inode, as
    `/proc/self/exe` when the shell starts), and no `mosey` is on the
    environment's `PATH`, `PATH` gets `$HOME/.local/bin` put first, so
    `mosey otherhost` in the session finds it. A `PATH` that already has
    a `mosey` (`~/.local/bin` itself, say), a server anywhere else
    (Nix's, a package's, `-remote`'s), or a `~/.local/bin` that breaks
    the installer's rules (`bootstrap.md` §4.7.2: a symlink, not the
    user's, or it, `~/.local` or the home writable by group or others,
    which `-remote` would otherwise skip) leaves `PATH` as it is. A login
    profile that assigns `PATH` outright undoes this; the stock Debian,
    Ubuntu and Fedora profiles then add `~/.local/bin` back themselves,
    and NixOS needs mosey from Nix (`bootstrap.md` §4.7.9).
  The spawner re-checks each `ClientLine` variable against
  `bootstrap.md` §6.2's names and its `vchar` alphabet, 1–64 bytes,
  whatever the parser accepted. Anything else is dropped and logged.
- The slave is closed in the spawner straight after `Start` returns.

### 2.6 The attach socket (D8)

The local channel D8 resumes through (`transport.md` §8.1,
`bootstrap.md` §9.2). It belongs to the **spawner**: proto, under Landlock
deny-all, cannot create a filesystem socket and must not be made able to,
since it holds the keys.

- **Where.** `R/mosey/SID-HEX/attach.sock`, where `R` is
  `$XDG_RUNTIME_DIR` if it is set and absolute, else `os.TempDir()` (so
  `$TMPDIR`, else `/tmp`) with `mosey-UID` in place of `mosey`, and
  `SID-HEX` the session id in 32 lower-case hex digits. Under `/tmp` the
  directory name carries the uid so users do not collide [derived:
  `bootstrap.md` §8's capture directory rule].
- **Checks.** The spawner makes `R/mosey` (mode 0700) if it is absent,
  then checks with `lstat` that it is a directory, not a symlink, owned by
  its uid, with no group or other permission bits; anything else and it
  makes no socket. It then makes `SID-HEX` (0700, `mkdir` failing on one
  that exists), and binds a `SOCK_SEQPACKET` unix socket at
  `attach.sock.tmp`, listens, sets it 0600 and renames it to
  `attach.sock`, so a socket at the final name is always one that accepts.
  A launcher or lister makes the same check of `R/mosey` and of
  `SID-HEX` before it connects, so it never follows a symlink planted by
  someone else into their socket.
- **When.** After proto's first `Credential` has been validated (it names
  the SID), before `Ready`. A failure to make it is logged and the session
  goes on, not resumable.
- **Peer check.** On every accepted connection the spawner reads
  `SO_PEERCRED` and closes the connection, unanswered, unless the uid is
  its own [S1 `resume.go`]. The directory's mode already keeps other users
  out; this is defence in depth.
- **The exchange.** Spawner → peer: the greeting (`bootstrap.md` §9.2.1),
  one message, not an IPC message. Peer → spawner, within T2: `ClientLine`
  (0x40), a resume, answered by `Ready` (0x41) or `Failed` (0x42), then
  close; or `Hangup` (0x43, `mosey -kill`), answered by the hangup of
  §2.4 and then close, with nothing sent; or `HangupIfIdle` (0x44, local
  `mosey -close-if-idle`), which hangs the shell up only if the
  requesting credential still holds (or last held) the session and the
  shell is idle (§2.4), and then closes with nothing sent; or nothing (a
  lister closes).
  All of it is the stable attach protocol (§2.8).
  The spawner reads with `recvmsg` and closes any fd that arrives, as on B
  (§3.1).
- **What the spawner checks** of the `ClientLine`: it parses
  (`bootstrap.ParseClientLine`, whole and canonical), it is
  `resume:SID`, or a reconnect's `resume:SID:CREDID` (the launcher has
  chosen, under its lock, and checked any holder, `bootstrap.md` §9.2;
  CREDID only labels the hold, §9.2.2), its SID is the session's, and
  its public key is an X-Wing key (`agent` may be either: the
  resuming client's own bootstrap triggered its own bind, and whether its
  connection carries the agent is the hello's business, `agent.md` §4.1)
  (`handshake.CheckPublicKey`). Then it sends proto `Resume` and waits up
  to T3 for the `Credential`, which it checks as in §3.4, and also that
  its `sid` is the session's. Once it has sent `Ready` the greeting
  says `attached`, held by that credential, for `handshake.CredentialTTL`
  unless an `Attached` or `Detached` comes first (`bootstrap.md` §9.2
  "The lock").
- **The name.** The spawner takes the session's name from its first
  `ClientLine`, which the launcher has made `new:NAME`; a first line
  without a name is refused. The name is in every greeting and in the
  log; proto never needs it, but the credential line carries it, so
  `Start` gives it to proto to print (§3.3).
- **The command.** Likewise the first `ClientLine`'s `cmd`, if it has
  one, is the session's for life and goes in every greeting as its
  optional `cmd` (`bootstrap.md` §9.2.1), so a plain `mosey DEST CMD`
  can find the session again and `-list` can show it (PLAN D8, option
  C). A greeting is read whole, as one message of at most
  `MaxSessionLine` (2048 bytes).
- **Bounds.** At most `MaxAttachConns` = 4 connections are served at once
  [choice: a resume takes milliseconds; more are closed at once]; resumes
  reach proto one at a time, in order.
- **Teardown** (§2.4) removes the socket and its directory first, so a
  resume never reaches a session that is ending; when the shell exits it
  goes even sooner, before proto is told (§2.4's first row), because the
  client hears the session is over before proto's `Exit` reaches the
  spawner.

### 2.7 The agent socket (D25)

`R/mosey/SID-HEX/agent.sock`, beside `attach.sock`, belonging to the
spawner for the same reason: proto cannot make or accept on a filesystem
socket. `agent.md` §4 is its full rule; in short:

- made, after the attach socket, only when the session's first
  `ClientLine` says `!agent=yes`; `SOCK_STREAM`, bound at
  `agent.sock.tmp`, listening, mode 0600, renamed to `agent.sock`;
- the shell's `SSH_AUTH_SOCK` (§2.5) is its path;
- each accepted connection's `SO_PEERCRED` uid must be the spawner's own
  or root's, as sshd's forwarded socket admits root (`agent.md` §4.1);
  then the spawner sends it to proto as `AgentConn` (§3.3) and closes its
  own copy;
- removed at teardown (§2.4), before anything else, and just before
  `attach.sock`, so that closing the attach socket can then remove the
  session directory, which must be empty by then.

### 2.8 The attach protocol (D8 V1)

D8 V1: client and server of different mosey versions is normal. After
the host's mosey is upgraded (by Nix, or by replacing the binary), a
launcher of the new binary attaches a session the old one runs, and that
session goes on running its own binary; an upgrade takes effect on new
sessions. There is no live upgrade (Dan, 2026-11-15). This rests on one
promise: **what crosses the attach socket is stable.** The launcher or
lister that connects and the spawner that answers may be any two
releases that speak the same attach protocol.

**The stability promise.** The attach protocol is the greeting
(`bootstrap.md` §9.2.1) and the messages that follow it on an attach
socket: `ClientLine` (0x40), `Ready` (0x41), `Failed` (0x42),
`Hangup` (0x43) and `HangupIfIdle` (0x44) (§3.3), with §3.1's framing (one seqpacket message each,
type byte first). This is **attach protocol 1** (`bootstrap.AttachProtocol`,
reset from 2 by Dan, 2026-11-17); the greeting's `aproto` says which one
number a session's spawner speaks, and a launcher attaches it only if it
is its own, as the handshake does with its own number (`transport.md`
§3.6). There is no range, and the number names only the envelope
(`versioning.md` §5): the greeting's grammar and mandatory fields, and
this framing. What the messages carry is open:

- `ClientLine`, `Ready` and the greeting carry lines of
  `bootstrap.md` §6.1's grammar, which gain fields without a new number
  (`versioning.md` §6).
- **New message types** come from 0x45 to 0x4F, and bit 3 of the type
  says whether a peer that does not know one may ignore it
  (`versioning.md` §3):

  | types | an unknown one | why |
  |---|---|---|
  | 0x40–0x47 | refused: the receiver closes the connection, as for a malformed message | critical, like the five defined here: each asks for or answers an action (attach, hang up); an older spawner that does not know `HangupIfIdle` (0x44) closes the connection and leaves the session detached |
  | 0x48–0x4F | skipped, unread, and the receiver goes on waiting for what it was waiting for, within the same deadline | may be ignored: for a message that only adds something, such as a hint the spawner may log |

  A receiver skips at most 4 such messages on one connection [choice: no
  exchange needs more], each within §3.1's `MaxMessage`, and refuses
  the connection at the fifth; it reads nothing of them, so they change
  nothing.

A message type is critical or not by its number, which fixes it once
for every message of the type. The four defined are all critical and
mandatory to understand: a spawner that ignored `Hangup` would leave a
session the user ended running, and a launcher that ignored `Failed`
would wait out its deadline. Every other IPC type (§3.2) is private to one build: a
spawner only ever exchanges them with its own proto and emu, and a
launcher with the spawner it started from its own file, so they stay
closed (`versioning.md` §5: an unknown one is refused).

A launcher takes a session of any mosey version (`bootstrap.md` §9.2
step 5) and attaches it as §2.6 says: it sends the session's spawner the
line, and prints the credential line the session's own proto mints.
Nothing compares software versions. A session whose greeting does not
parse is not chosen. One whose `aproto` is another number, or whose
greeting has a critical field this launcher does not know, is not taken
by `auto`; `name:NAME` or `resume:SID` naming it fails with
`MOSEY-ERROR 1 !code=attach detail=P-N` (or `!code=unsupported
detail=KEY`) and, on stderr, `session NAME speaks attach protocol P;
this mosey speaks N`.

### 2.9 Root at the far keyboard (`screen.md` §4.8)

The client marks the user's tab as root while the process at the far
keyboard runs as uid 0 (Dan, 2026-11-16; `screen.md` §8.8). Only the
spawner can tell: it holds a reference to the pty master and is not
sandboxed, while proto, which also holds the master, is under Landlock
deny-all and cannot open `/proc`.

- **The measurement** is `pty.ForegroundRoot(master)`: `TIOCGPGRP` on the
  master gives the foreground process group, and the `Uid:` line of
  `/proc/<pgid>/status` the effective uid of its leader [Linux proc(5)];
  root is that uid being 0. Any failure (no foreground group, the leader
  gone, `/proc` hidden, a line that does not parse) is "not root". The
  status file is bounded: at most 4 KiB is read. On anything but Linux
  it returns `errors.ErrUnsupported`, and the spawner never sends `Root`.
- **When.** Every `RootPoll` (500 ms) while a client is attached, and at
  once when one attaches; never while the session is detached, since
  nobody would be told [derived: the tab is read at a glance, and half a
  second after `sudo -i` is prompt; each sample is one ioctl and one
  small file read, microseconds, so two a second cost nothing that
  matters]. Not on output: only proto sees output, and telling the
  spawner of each read would be an IPC message per frame to save at
  most half a second. A `sudo cmd` shorter than the tick may not show,
  and `sudo` waiting for its password counts as root, since it is the
  set-uid process at the keyboard.
- **Sending.** The spawner sends `Root` (§3.3) only when the measurement
  differs from what it last sent, and proto starts from false, so the
  first message is always a rise.
- **Proto** keeps the last value and sets `Grid.Root` on every screen it
  publishes, as it sets `EchoOff` (`screen.md` §7.2); a `Root` that
  changes the value publishes at once. A grid from emu with `Root` set is
  a violation (`screen.md` §7.3).

---

## 3. IPC

### 3.1 Transport

- **Sockets.** `AF_UNIX`, `SOCK_SEQPACKET`, made with `socketpair(2)`:
  the kernel keeps message boundaries and delivers in order, so a
  message is one `send` and one `recv` and there is no length field to
  parse (S4 §2). macOS needs another framing (§10).
- **Sizes.** No message is longer than `MaxMessage` = 65536 bytes
  [derived: well under the default `net.core.wmem_default` of 212992,
  which bounds one seqpacket message, so no tuning is needed on any
  host]. A receiver reads into a buffer of `MaxMessage + 1` bytes. With
  `recvmsg` it refuses any message flagged `MSG_TRUNC` or `MSG_CTRUNC`;
  with `read` it refuses one that fills the whole buffer.
- **File descriptors** travel with `SCM_RIGHTS`, on the spawner's
  messages only. Proto and emu cannot send any (their seccomp policies
  have no `sendmsg`). A receiver that expects none uses `read(2)`, and
  the kernel discards and closes any fds that came with the message
  [kernel ABI]; one that may get fds uses `recvmsg` and closes every fd
  of any message it refuses. A message that must carry fds and arrives
  with a different number is refused.
- **Who reads with what.** spawner: `recvmsg` on B, C and the attach
  socket (closes any fds: none are allowed in). proto: `recvmsg` on C
  (Start, EmuLink and AgentConn carry fds), `read` on E. emu: `read` on
  E. launcher: `read` on B and on the attach socket.
- **Encoding.** Byte 0 is the type. Integers are unsigned big-endian
  unless marked `i32` (two's complement, big-endian). Each type has one
  fixed layout; a message is valid only if its length is exactly the
  layout's (or within the stated range for the one trailing variable
  field), every field is within its stated range, and reserved bits are
  zero. Anything else is refused whole.
- **Directions.** Each `ipc.Conn` is made for one peer and accepts only
  that peer's types (§3.2): the spawner never even parses an `Update`.
  A type from the wrong peer is refused like any malformed message.
- **Refusal** is a protocol violation by the peer, never a skip: §5.3
  says what each role does about one.

### 3.2 Types

| type | name | from → to | fds |
|---|---|---|---|
| 0x01 | Start | spawner → proto | 2 |
| 0x02 | EmuLink | spawner → proto | 1 |
| 0x03 | ShellExit | spawner → proto | 0 |
| 0x04 | AgentConn | spawner → proto | 1 |
| 0x05 | Resume | spawner → proto | 0 |
| 0x06 | EmuPaused | spawner → proto | 0 |
| 0x07 | Root | spawner → proto | 0 |
| 0x10 | Init | proto → emu | 0 |
| 0x11 | Output | proto → emu | 0 |
| 0x12 | Resize | proto → emu | 0 |
| 0x13 | Flush | proto → emu | 0 |
| 0x20 | Update | emu → proto | 0 |
| 0x21 | Replies | emu → proto | 0 |
| 0x30 | Credential | proto → spawner | 0 |
| 0x31 | Exit | proto → spawner | 0 |
| 0x32 | KillEmu | proto → spawner | 0 |
| 0x33 | Attached | proto → spawner | 0 |
| 0x34 | Detached | proto → spawner | 0 |
| 0x35 | FirstOutput | proto → spawner | 0 |
| 0x40 | ClientLine | launcher → spawner | 0 |
| 0x41 | Ready | spawner → launcher | 0 |
| 0x42 | Failed | spawner → launcher | 0 |
| 0x43 | Hangup | launcher (`--serve=kill`) → spawner | 0 |
| 0x44 | HangupIfIdle | launcher (local `-close-if-idle`) → spawner | 0 |

The high nibble names the direction, so a stray message is easy to spot
in a trace. Unlisted types are refused, but for 0x48–0x4F on an attach
socket, which are skipped (§2.8). **0x40 to 0x4F are the attach
protocol** and are open as §2.8 says; on an attach socket the
"launcher" end is whoever connected (a launcher or a lister) and the
"spawner" end the session. Everything else is private to one build, and
closed by design: proto and emu are always started from the spawner's
own image, `/proc/self/exe` (§2.3), so there is no peer of another
release to tolerate, and every unknown type, field or bit is refused as
a violation (§5.3), since the peer is the less trusted side
(`versioning.md` §5).

### 3.3 Layouts

Offsets and lengths in bytes.

**0x01 Start** (spawner → proto). Exactly the first message on C.

| off | len | field | valid |
|---|---|---|---|
| 0 | 1 | type 0x01 | |
| 1 | 1 | flags | 0 |
| 2 | 2 | cols | 1..`screen.MaxCols` |
| 4 | 2 | rows | 1..`screen.MaxRows` |
| 6 | 2 | port | 1..65535, the bound port |
| 8 | 1 | family | 0 (no advertised address: the line's `-`), 4 or 6 |
| 9 | 0, 4 or 16 | advertised address | §2.2; unmapped, not unspecified, no zone |
| 9, 13 or 25 | 1216 | client public key | the X-Wing encapsulation key from the `ClientLine` [D20]; its length is `handshake`'s constant |
| 1225, 1229 or 1241 | 1 + n | session name | its length n, 1..32, then the `sname` (`bootstrap.md` §6.2), which proto puts in every credential line it mints (§2.6 "The name") |

Length 1227..1274. fds: exactly 2, `[0]` the UDP socket, `[1]`
the pty master.

**0x02 EmuLink** (spawner → proto). Once straight after `Start`, then
once per emu restart.

| off | len | field | valid |
|---|---|---|---|
| 0 | 1 | type 0x02 | |
| 1 | 4 | generation | 1 for the first; each later one exactly the previous + 1 |
| 5 | 1 | reason the previous emu ended | 0 first start, 1 exited, 2 killed by a signal, 3 over its memory limit, 4 killed at proto's request |
| 6 | 4 | status (i32) | exit code ≥ 0, or −signal; 0 when reason is 0 |

Length 10. fds: exactly 1, proto's end of the new E.

**0x03 ShellExit** (spawner → proto): type, then status (i32: exit code
≥ 0 or −signal). Length 5.

**0x04 AgentConn** (spawner → proto): type only. Length 1. fds: exactly
1, a connected `SOCK_STREAM` unix socket accepted on the agent socket
(§2.7), in non-blocking mode, so proto wraps it with `os.NewFile` inside
its sandbox as it does each E (§3.6). Any number, at any time after
`Start`. Proto serves or closes it (`agent.md` §4.2); it never answers.

**0x05 Resume** (spawner → proto): type, then the resuming client's
X-Wing public key, exactly 1216 bytes (as in `Start`). Length 1217. Proto
mints a credential for its own session id bound to that key (TTL, cap of
2 unused per session, `transport.md` §8.1) and answers with exactly one
`Credential`. The spawner has checked the key, so a key `Mint` refuses is
a bug: proto logs it and ends the session with `Exit{Error}`.

**0x06 EmuPaused** (spawner → proto): type, then seconds (2),
1..3600: emu's restart budget is spent and no emu will start for this
long (§5.2). Length 3. Proto stays "emu down" (§3.6) and tells the
client the screen is unavailable (§11, item 7); the next `EmuLink` ends
the pause.

**0x07 Root** (spawner → proto): type, then one byte, 0 (not root) or 1
(root): the far keyboard's process, as §2.9 measured it. Length 2. Any
number, at any time after `Start`; any other byte is malformed.

**0x10 Init** (proto → emu). Exactly the first message on each E.

| off | len | field | valid |
|---|---|---|---|
| 0 | 1 | type 0x10 | |
| 1 | 2 | cols | 1..`screen.MaxCols` |
| 3 | 2 | rows | 1..`screen.MaxRows` |
| 5 | 4 | scrollback cells | 1..`emu.DefaultScrollbackCells` × 10 (D23's budget is 1e6; the cap leaves room for the configurable clamp) |
| 9 | 4 | foreground (`screen.Color`) | a valid `screen.Color` (`screen.md`) |
| 13 | 4 | background | as above |
| 17 | 64 | palette: 16 × `screen.Color` | as above |

Length 81. The colours are what emu answers OSC 10, 11 and 4 with
(S2: fish, vim and Claude Code adapt to them). Slice 1's `ClientLine`
carries no colours, so proto sends `screen.DefaultColor` throughout
until `bootstrap.md` adds them (§11, item 6).

**0x11 Output** (proto → emu): type, then 1..`MaxOutput` bytes of
program output. `MaxOutput` = 16384 [derived: proto reads the pty in
16 KiB chunks; a larger write is split across requests]. Length
2..16385.

**0x12 Resize** (proto → emu): type, cols (2), rows (2), both in range
as for `Init`. Length 5.

**0x13 Flush** (proto → emu): type only. Length 1. A request with no
output, answered like any other (no `Replies`, then the diff), which
proto sends when its `SyncHold` timer fires after a held answer, so a
program that opens synchronised output and never closes it frees its
screen (`screen.md` §6.3). Its allowance is 0.

**0x20 Update** (emu → proto): one fragment of a screen diff.

| off | len | field | valid |
|---|---|---|---|
| 0 | 1 | type 0x20 | |
| 1 | 1 | flags | bit 0 MORE: another fragment follows; bit 1 HELD: emu's snapshot is held under synchronised output (`screen.md` §6.3), only on a fragment with MORE clear; bits 2–7 zero |
| 2 | 0..65534 | fragment | |

A diff is the concatenation of a run of fragments ending in one with
MORE clear. Proto refuses the run as soon as its total passes
`screen.MaxDiff`, 48 MiB (`screen.md` §5.12), so proto's reassembly
buffer for one diff is at most 64 MiB, and decodes the whole diff with
`Grid.Apply` only once it is complete. The diff is in the client's own
format (`screen.md`), relative to the grid after the previous complete
`Update` on this E, the first on each E (the answer to `Init`) being
relative to `screen.NewGrid(cols, rows)` at `Init`'s size (`screen.md`
§7.1, §7.3), so a SIZE op crosses the boundary only in an answer to
`Resize`.

**0x21 Replies** (emu → proto): type, then 1..`MaxReplies` bytes: the
emulator's answers to this request's output, as tuios queued them, as
one or more tokens back to back (§4.1). `MaxReplies` = 4096 [derived:
tuios' longest single answers, a full DA1 or an XTGETTCAP, are tens to
hundreds of bytes; S2 measured legitimate reply traffic at tens of
bytes]. An emu with more queued than this for one request drops it all
and logs the count; no well-behaved program reaches it. How many of the
tokens proto passes on is bounded by the request's reply allowance
(§4.1), not by this byte limit.

**0x30 Credential** (proto → spawner): type, then the credential line,
1..`MaxCredentialLine` bytes including its final `\n`.
`MaxCredentialLine` = 2048 [`bootstrap.md` §6.3: the longest line is
1806 bytes].

**0x31 Exit** (proto → spawner): type; code (1): 1 ShellExited, 3
NoClient, 5 Error (2 was ClientClosed and is refused since the resume
slice: a client leaving never ends a session, `bootstrap.md` §9.3; 4 is
unassigned and refused: an emu failure never ends a session, §5.2); then
0..200 bytes of
reason, each 0x20–0x7E. Length 2..202. The spawner logs it; before the
`Ready`, it becomes the `Failed` text.

**0x32 KillEmu** (proto → spawner): type; generation (4); why (1): 1
deadline (T4 passed with a request outstanding), 2 violation (§5.3).
Length 6. A generation other than the current one is ignored (the
request crossed a restart), not refused.

**0x33 Attached** (proto → spawner): type; the credential id (8) the
connection was made with; family (1): 0 (the client's address is not yet
validated), 4 or 6; then for 4 or 6 the address (4 or 16 bytes, unmapped,
not unspecified) and the port (2, not 0). Length 10, 16 or 28. Proto sends
it each time a client confirms a credential, with the connection's
validated address if it has one, and again when a client it had reported
silent (§2.4) is heard. It is what the greeting's `attached`, `since`,
`peer` and `holder` say (§2.6). The spawner keeps a
backstop of `handshake.CredentialTTL` + 10 s from the `Ready`, restarted by
each `Resume` it forwards (`bootstrap.md` §4.5): if no `Attached` has
come by then it ends the session itself, so a proto that hangs before its
own `Exit{NoClient}` leaves no shell running for nobody. The first
`Attached` stops the backstop for good.

**0x34 Detached** (proto → spawner): type only. Length 1. Proto sends it
when the attached connection ends with no other taking its place: the
client's END (`detached`), or the connection or its SSP failing; and when
the attached client has been silent for `SilentAfter` (§2.4). The greeting
says `detached` from then until the next `Attached`, and the spawner's
idle timer runs from it.

**0x35 FirstOutput** (proto → spawner): type only. Length 1. Proto's
pty reader sends it once, after its first read of the master that
returns bytes: the shell has written something, its prompt as a rule,
so the spawner may type a `type`'s text without it showing twice
(`bootstrap.md` §9.2.3). Proto sends it whether or not there is text to
type: proto never sees the `ClientLine`. Only proto reads the master, so
it is the one that can tell; the spawner reading it too would take
output from the emulator.

**0x40 ClientLine** (launcher → spawner): type, then the line as read
from stdin including its `\n`, 1..`MaxClientLine` bytes.
`MaxClientLine` = 8192 [`bootstrap.md` §6.2].

**0x41 Ready** (spawner → launcher): type, then the credential line,
as `Credential`.

**0x42 Failed** (spawner → launcher): type, then 1..512 bytes, each
0x20–0x7E.

**0x43 Hangup** (launcher → spawner, on the attach socket only): type
only. Length 1. `mosey -kill` (`bootstrap.md` §9.5): the spawner hangs the
shell up as for the idle timeout (§2.4) and closes the connection.

**0x44 HangupIfIdle** (launcher → spawner, on the attach socket only):
type, then credential id (8). Length 9. Local `mosey -close-if-idle`
(`bootstrap.md` §2.2): if the session is still held by that credential
(or was last held by it, with no takeover in flight) and the shell is
idle (`pty.SessionIdle`: foreground process group is the shell's pid and
no other process in `/proc` has `sid == shell_pid`), the spawner hangs
the shell up as for the idle timeout (§2.4). Otherwise it does nothing.
Either way it closes the connection with nothing sent. Any error in the
idle check fails safe and keeps the session alive.

### 3.4 What the spawner accepts from proto

The spawner is unsandboxed, so its parser of proto's messages is the
one place a compromised proto could reach further. It accepts exactly:

- `Credential`, once before T3 at bootstrap, and afterwards once for each
  `Resume` outstanding (§2.6) and only then; each only if
  `bootstrap.ParseCredentialLine` accepts it, its `addr` is exactly the
  advertised address (or none, the field absent) and its `port` the bound port,
  and `bootstrap.MarshalCredentialLine`
  of the parse is byte for byte the line received (so what reaches
  stdout is canonical printable ASCII and nothing else).
- `Exit`, at most once.
- `KillEmu`, any number, at most one per emu generation acted on.
- `Attached` and `Detached`, any number (each is a fixed layout and
  changes only what the greeting says).
- `FirstOutput`, any number: only the first before `Ready` does anything
  (it ends the wait to type a `type`'s text early, which `TypeWait`
  would end anyway), and every later one is ignored.

Anything else (another type, a second `Credential`, a malformed
message, any fd) is a violation: the spawner logs it, SIGKILLs proto,
and ends the session (§2.4). The spawner reads C in a goroutine of its
own and never blocks its supervision loop on proto.

### 3.5 The emu protocol, as a state machine

Strictly request and response, one request outstanding at a time. Proto
is the only one who asks.

```
proto, per E:                            emu:
  Start ──send Init──► Waiting             Fresh ──Init──► Ready
  Idle ──send Output|Resize|Flush──► Waiting
                                         Ready ──Output|Resize|Flush──► Ready
  Waiting:                                   (each answered with
    Replies (only before the first           [Replies] Update…Update(last))
      Update fragment, at most once)
    Update with MORE ──► stay Waiting
    Update without MORE ──► apply ──► Idle
  any emu message in Idle ──► violation
```

- emu answers every request with at most one `Replies`, then a run of
  `Update` fragments ending with MORE clear (which may be one fragment
  holding an empty diff). It processes requests in order and never
  speaks unasked.
- emu refuses (logs on stderr and exits 1) a first message other than
  `Init`, a second `Init`, or any malformed message: proto is more
  trusted than emu, so this only ever fires on a bug.
- proto treats as a **violation** (§5.3): an emu message while Idle, a
  second `Replies`, `Replies` after an `Update` fragment, a diff over
  `screen.MaxDiff`, a diff `Grid.Apply` refuses, a complete diff after
  which the mirror has a non-zero `EchoOff`, `EchoAck`, `EchoApplied`,
  `Rebuilt`, `InputConsumed` or `Root` (fields that are proto's alone, `screen.md` §7.3; the check runs on a
  copy, so the mirror is unchanged when it fails), a `Replies` whose
  bytes do not split under §4.1, or any malformed message. Tokens over
  the request's reply allowance (§4.1) are not a violation: they are
  dropped and counted, because an honest emu answering a program that
  asked many questions at once can exceed it.
- proto waits at most T4 for a response to complete. Past it, it sends
  `KillEmu{why: deadline}`.

### 3.6 The emulator over IPC

Proto's production `emu.Emulator` is a client of §3.5. `server.Session`
cannot tell it from the in-process one, which is what lets the
end-to-end tests run the whole server on netsim without forking.

- It keeps a **mirror** `*screen.Grid`, the result of every `Update`
  applied with `Grid.Apply`, which validates against the bounds and the
  D9/D27 allow-list before changing anything. So one fuzzed decoder
  guards both the client against the server and proto against emu.
- `Write(p)`: split `p` into `Output` requests of at most `MaxOutput`
  and run each to completion. `Resize(c, r)`: one `Resize` request.
  `Snapshot(g)`: copy the mirror into `g`, with proto's own counters and
  proto's own history (`screen.md` §7.2: emu's history lines, renumbered
  into the session's numbering, which a rebuild does not restart).
  `TakeReplies()`: the replies
  that passed §4, concatenated, and forget them. `Close()`: close E.
- Its methods return no error (the interface has none). While emu is
  down (between a violation, death or `KillEmu` and the next
  `EmuLink`, including an `EmuPaused` cool-down), `Write` and `Resize`
  block until the new emu has answered its `Init`, or the session ends;
  output that was in flight when emu died is dropped, not resent (§5.2
  says how the screen recovers). Keystrokes do not wait for emu: the pty
  writer (§4.3) runs on, so the user can still interrupt a program while
  the screen is down.
  `Write` blocking is what applies back-pressure: proto stops reading
  the pty, so a program can only produce output as fast as it is parsed
  (S2, "the cost limits itself").
- **Wrapping a new E inside the sandbox.** Every E after generation 1
  arrives after `sandbox.Enter`, so the way it is wrapped must use only
  syscalls proto's policy allows. The fd comes from `recvmsg` with
  `MSG_CMSG_CLOEXEC`. Proto then calls `fcntl(F_GETFL)` and
  `fcntl(F_SETFL, flags|O_NONBLOCK)` (both allowed: `O_ASYNC` stays
  clear, §6.3), so it never depends on the spawner having made the pair
  non-blocking, then `os.NewFile`, which costs one more `F_GETFL` and an
  `epoll_ctl` to register the fd with the poller. The result is pollable,
  so `SetReadDeadline` works and T4 can be enforced. Never
  `net.FileConn`: it calls `getsockopt(SO_TYPE)`, `getsockname` and
  `getpeername`, none of which the policy has, so under `Kill` it would
  kill proto on the first emu restart. Generation 1's E is wrapped the
  same way, so one code path is tested by every restart test.
- On a new `EmuLink`: close the old E, wrap the new one, reset the
  mirror to `screen.NewGrid(cols, rows)` at the current size, send
  `Init` with that size and the colours, and apply its `Update` to that
  fresh grid
  (`screen.md` §7.3). For every generation after the first, proto then:
  - increments its own `Rebuilt.Seq` (`screen.md` §7.2) and sets
    `Rebuilt.Reason` from the `EmuLink` reason, mapped to `screen.md`'s
    codes: 3 (over its memory limit) → 1 (memory); 1 (exited) and 2
    (killed by a signal, which includes a seccomp SIGSYS) → 2 (panic or
    exit); 4 (killed at proto's request) → 2 if proto asked because of
    a violation (a refused update), 3 (other) if because of the T4
    deadline. This is how the client learns of the rebuild, including
    D23's memory notice;
  - makes the shell's foreground program repaint (§5.2, "Redraw").

  The next `Snapshot` differs from what the client holds, so SSP sends
  the client the change as it would any other.

---

## 4. The reply grammar

Some programs ask the terminal questions (cursor position, device
attributes, background colour) and read the answers from their input.
The emulator answers, so emu's answers must be typed into the pty. That
is exactly the capability an attacker who owns emu wants (S4 §3.6). So
proto, not emu, decides what reaches the pty: only complete answers of
the shapes below, each on its own, none containing a byte that a line
editor acts on as a control. In particular there is never a CR, LF or
any other C0 control other than ESC as an introducer and the string
terminator, so a reply can never submit a command line. What a
compromised emu can still do is insert reply-shaped text into a line
being edited; a vi-mode readline is the worst case (S4 §3.6), and the
small alphabet below keeps that to digits, a few punctuation marks and
the final letters of the shapes.

### 4.1 Splitting

`Replies` is split into tokens, left to right. Each token is one of:

- **CSI**: `ESC [`, then bytes 0x30–0x3F (parameters), then 0x20–0x2F
  (intermediates), then one final byte 0x40–0x7E.
- **OSC**: `ESC ]`, then bytes 0x20–0x7E, then `ESC \` or BEL (0x07).
- **DCS**: `ESC P`, then bytes 0x20–0x7E, then `ESC \`.

Each token is at most `MaxReplyToken` = 256 bytes [derived: the longest
legitimate one, an XTGETTCAP answer, is under 100]. If the bytes do not
split exactly into such tokens (a byte outside them, an unterminated
string, an over-long token, an empty message), the whole `Replies` is a
violation: tuios never produces that, so emu is broken or hostile.

**The reply allowance.** A `Replies` may hold several tokens, because a
program often asks several questions in one write (a CPR and a DA1
together, say) and tuios answers them all in that request. But emu is
not trusted to say how many questions there were, so proto bounds it
from the bytes it sent, which it can see:

- Every query has an introducer: `ESC [`, `ESC ]` or `ESC P`, or a C1
  form of one (a byte 0x9B, 0x9D or 0x90, which also covers their UTF-8
  encodings `C2 9B`, `C2 9D`, `C2 90`). Proto counts introducers in each
  `Output`, counting an `ESC` that ends one `Output` with a `[`, `]` or
  `P` that starts the next, so a query cut across two requests is still
  counted.
- A request's **allowance** is the number of introducers in its own
  `Output` plus those in the `Output` before it on this E (a query whose
  final byte lands in the next request is answered there), capped at
  `MaxReplyTokens` = 8 [derived: the most answers a program asks for in
  one write that we know of is vim's start-up probe, a handful; to be
  confirmed by `TestReplyAllowanceCoversRealPrograms`, §12, not yet
  written]. A `Resize`
  or `Init` request's allowance is 0: tuios answers nothing to either.
- Proto runs the tokens through §4.2 in order; each one it accepts uses
  one unit of allowance, and once it is used up the rest are dropped and
  counted, not queued. An `Output` with no introducer, after one with
  none, gets no reply at all, so a compromised emu cannot add text on
  ordinary output.

So the most a compromised emu can type per request is `MaxReplyTokens`
allow-listed tokens, and only on requests whose output held escape
sequences; the threat model's "exactly one reply per message" (R9) is
replaced by this bound (Review notes, item 5).

### 4.2 The allow-list

A token that splits but is not on this list is dropped on its own,
counted, and logged at most once a minute per shape [derived]. A
legitimate program that asks something new costs only that answer, and
the list grows by a reviewed commit. `P` is 1–5 decimal digits with no
leading zero (or the single digit `0` where 0 is meaningful), `H` is 2–4
hex digits `[0-9a-fA-F]`, and `ST` is `ESC \` or BEL where the query
allowed BEL (OSC only).

| answer to | shape |
|---|---|
| CPR (`CSI 6 n`) | `CSI P ; P R` |
| DECXCPR (`CSI ? 6 n`) | `CSI ? P ; P R` or `CSI ? P ; P ; P R` |
| DSR status (`CSI 5 n`, `CSI ? 5 n`) | `CSI 0 n`, `CSI ? 0 n` |
| colour-scheme query (`CSI ? 996 n`) | `CSI ? 997 ; 1 n`, `CSI ? 997 ; 2 n` |
| DA1 (`CSI c`) | `CSI ? P (; P){0,15} c` |
| DA2 (`CSI > c`) | `CSI > P ; P ; P c` |
| DECRQM (`CSI ? Pd $ p`, `CSI Pd $ p`) | `CSI ? P ; [0-4] $ y`, `CSI P ; [0-4] $ y` |
| XTWINOPS reports (`CSI 14/16/18 t`) | `CSI 4 ; P ; P t`, `CSI 6 ; P ; P t`, `CSI 8 ; P ; P t` |
| XTSMGRAPHICS (`CSI ? Pi ; Pa ; Pv S`) | `CSI ? [12] ; [0-3] ; P S` (emu runs with graphics off, so it answers "not supported", S2) |
| modifyOtherKeys query (`CSI ? 4 m`) | `CSI > 4 ; [0-2] m` |
| kitty keyboard query (`CSI ? u`) | `CSI ? P u` |
| OSC 10, 11, 12 queries | `OSC (10|11|12) ; rgb: H / H / H ST` |
| OSC 4 query | `OSC 4 ; P ; rgb: H / H / H ST`, the index 0–255 |
| program-status query (`OSC 7501 ; ?`) | `OSC 7501 ; ? ST` |
| DECRQSS (`DCS $ q … ST`) | `DCS 0 $ r ESC \`, or `DCS 1 $ r V ESC \`, where V is 1–64 bytes of `[0-9;:]` followed by one of `m`, `r`, `s`, ` q` |
| XTGETTCAP (`DCS + q … ST`) | `DCS 0 + r ESC \`, or `DCS 1 + r X ESC \` or `DCS 1 + r X = X ESC \`, where X is 2–128 hex digits of even length |
| DA3 (`CSI = c`) | `DCS ! | 8 hex digits ESC \` |
| XTVERSION (`CSI > q`) | `DCS > | N ESC \`, where N is **exactly** the name proto's own build gives emu (`emu.XTVersion`; same binary, so proto knows it) |

Never on the list, whatever emu says: OSC 52 (clipboard reads are never
passed, D27), any APC (kitty graphics is off), DCS other than the four
above, and anything containing a byte outside 0x20–0x7E between the
introducer and the terminator.

`server.ValidReply(b)` is true exactly when `b` is one token on this
list. `server.SplitReplies(b) (tokens [][]byte, err error)` (§11, item
3) is §4.1's splitting. The allowance (§4.1) is applied to its result
by the IPC emulator (§3.6), which is what sees the `Output` bytes; not
by `ValidReply`, which judges one token.

### 4.3 The path to the pty

S2 measured the naive design (one goroutine reads output, parses it and
writes replies before reading again) deadlocking in 0.1–0.2 s against a
program that never reads its input. So:

- The goroutine that reads the pty never writes to it.
- Accepted replies go into a **bounded queue** of `ReplyQueue` = 64 KiB
  [S2, reply flood]; one that would overflow it is dropped and counted.
- One **writer** goroutine writes the pty. Keystrokes from the client
  share it and go ahead of replies [S2].
- **Keystrokes have no queue of their own, and are never dropped.** The
  client's input stream (`ssp.md` §10.1) is the queue: the writer takes
  the events of `Since(applied)` one at a time, writes a key event's
  bytes to the pty (or applies a resize event, §7), and only when the
  write has returned in full does `Session` advance `applied`. So at
  most one event, at most `MaxKeyEvent` = 4096 bytes, is ever between
  the stream and the pty. A program that never reads its input fills
  the kernel's line-discipline buffer (about 4 KiB), the writer's
  `write` then blocks (parked on the poller; closing the master at the
  session's end releases it), and `applied` stops. Since
  `Grid.InputConsumed` follows `applied`, the client stops reading its
  terminal within a round trip and the rest of the paste waits in the
  user's terminal (`ssp.md` §10.1, "Input flow control is by
  consumption"). With an honest client, the stream is then at most
  about 112 KiB past `applied`, inside `RetainBytes` (256 KiB), so
  `Since(applied)` never overruns. A stalled pty is therefore not a
  bug: it is the bounded stall the flow control is built for. Only a
  client that ignores `InputConsumed` can push the stream past
  `RetainBytes`; `Session` then ends the connection with
  `ssp.ErrProtocol` as `ssp.md` says, and nothing is skipped silently.
  Replies queued meanwhile wait behind the blocked write, within
  `ReplyQueue`, and overflow is dropped and counted as above.
- A resize event queued behind unread keystrokes waits with them, so a
  program that reads no input also sees no resize until it does; it is
  the order `ssp.md` requires (events in order), and the stall ends when
  the program reads or exits.

---

## 5. Supervision

### 5.1 What the spawner watches

The spawner's loop waits on: the shell's exit, proto's exit, emu's
exit, a message on C, SIGTERM/SIGINT, and T3 while bootstrapping. Every
child exit is logged with its role, pid, generation, how long it lived,
and its status in words (`exit 2`, `signal: bad system call`, `signal:
killed`): the soak (§9) and a person both read these.

### 5.2 emu restarts

emu is restarted when it exits for any reason while the session lives:
a crash or panic (a tuios bug, D23 "a panic also means rebuild"), a
seccomp kill (SIGSYS, from a missing syscall under KILL), the memory
limit (§6.3), or `KillEmu`.

- **Reason.** Exit status 0 or ≥ 1: "exited"; a signal: "killed by a
  signal"; following a `KillEmu`: "killed at proto's request". Either of
  two signs makes it "over its memory limit" instead: the emu's scope's
  `memory.events` shows its `oom_kill` count went up, or the status is
  exit 2 and some line of the emu's stderr since it started begins with
  `fatal error: out of memory` or `fatal error: runtime: out of memory`
  (how Go's runtime dies when `RLIMIT_DATA` refuses it memory; the
  goroutine traceback that follows means the *last* line never matches,
  so the spawner checks each line as it reads it and remembers a match
  for that generation). This is only a classification for the client's
  notice: emu can forge the line, and gains nothing by doing so, since
  every reason is handled alike.
- **Backoff and budget** [S4 §3.8, its `netSupervisor`]: wait 50 ms
  before the first restart, doubling each time to at most 5 s; the wait
  goes back to 50 ms once an emu has lived 60 s. At most 10 starts in
  any 60 s.
- **When the budget is spent, the session goes on.** A start that would
  be the eleventh in 60 s is not made. The spawner sends proto
  `EmuPaused{EmuCooldown}`, logs it, and starts nothing for
  `EmuCooldown` = 60 s [derived: the length of the budget window];
  then it forgets the start history, resets the backoff to 50 ms and
  starts emu again. This repeats for as long as emu keeps failing. The
  shell, the pty and proto are never touched: the user can still type
  (§3.6), for example Ctrl-C to the program printing whatever is
  crashing emu, and the session ends only for the triggers of §2.4.
  Why: anyone who can get bytes onto the screen (a line in a log the
  user follows with `tail -f`, a chat message in a TUI) can repeat a
  byte sequence that crashes, hangs or over-allocates emu at will, and a
  SIGWINCH repaint replays it; the backoff before an eleventh start sums
  to about 21 s. If that ended the session it would be a remote kill of
  the user's shell by T4. D23 says to rebuild, never to end the session.
  What the attacker gets instead is a blank or frozen screen, which they
  could cause anyway by printing garbage.
- **Restart.** New E pair, start emu with one end (from the locked
  thread, §2.3), limit its memory (§6.3; a failure to set `RLIMIT_DATA`
  is a failed start: kill that emu and count it against the budget),
  send proto `EmuLink` with the next generation, the reason and the
  status, close the spawner's copy of proto's end.
- **Redraw.** The new emu's screen starts blank, so the shell's
  foreground program must repaint. **Proto** does it, after the new
  emu's first `Update` is applied, with a size change and back, the one
  mechanism `screen.md` §7.3 also names: through the normal resize path
  (§7, emulator first, then the pty) it sets the size to (cols, rows−1),
  or (cols, rows+1) when rows is 1, and at once back to (cols, rows).
  The kernel sends SIGWINCH to the foreground process group on each real
  change [kernel ABI, `TIOCSWINSZ`], so programs that ignore a SIGWINCH
  whose size has not changed (curses' `resizeterm` to the same size is a
  no-op) still repaint; the signals usually coalesce and the program
  reads the final size, so any repaint at the passing size is
  overwritten. Proto has the `ioctl(TIOCSWINSZ)` it needs on the master
  (§6.3) and sends no signal itself; the spawner sends none either.
- **The client** learns of every rebuild from `Rebuilt.Seq` and
  `Rebuilt.Reason` (§3.6, `screen.md` §7.3), which is D23's notice when
  the reason is memory. A pause (`EmuPaused`) is told to the client by
  §11, item 7's notice frame.

### 5.3 Violations

| who sees it | what | then |
|---|---|---|
| proto, from emu | anything in §3.5's violation list | log it (type and length, never the bytes), stop reading E, send `KillEmu{why: violation}`, carry on as "emu down" (§3.6). A compromised emu stays compromised; a fresh one parses from scratch |
| proto, from the spawner | a malformed message on C | log and exit 1 (the spawner is more trusted than proto; this is a bug) |
| emu, from proto | §3.5 | log and exit 1; the spawner restarts it |
| spawner, from proto | §3.4 | log, SIGKILL proto, end the session |
| spawner or launcher, on B | a malformed message | log or print, exit 1 |

A violation never changes state before it is detected: every message is
validated whole before it is acted on (CLAUDE.md, "hostile input is
validated in full").

### 5.4 proto

Proto is not restarted: its death ends the session (§2.4). S4 measured
it (§3.8: proto killed, the network gone for good, the shell alive
because the spawner holds the master). Restarting it would need the
spawner to keep the UDP socket, a `Start` flag for an existing pty, a
fresh emu and a repaint, and gains only the case of proto crashing; the
resume slice leaves it for later (`threat-model.md` R17). D8's resume
brings back a client that went away, not a proto that died.

---

## 6. Sandbox

### 6.1 Order of set-up

Each sandboxed role, in this order, with nothing in between [S4 §5.4,
plus §2.1 above]:

**proto** (`server.RunProto`):

1. `prctl(PR_SET_DUMPABLE, 0)`, first of all, before anything holds a
   key: with it left at 1, a seccomp kill writes a core dump holding the
   keys (S4 §3.5: two cores in systemd-coredump; none with it at 0).
   This also stops the user's other processes from ptracing proto or
   reading its memory. `RLIMIT_CORE` goes to 0 at the same time
   (`nocore.Process`, `threat-model.md` §4.10): proto starts no child to
   inherit it.
2. Check fd 3 is a `SOCK_SEQPACKET` socket (`getsockopt(SO_TYPE)`), wrap
   it as C.
3. Receive `Start` (T3), then `EmuLink`. Wrap the UDP socket
   (`net.FilePacketConn`) and the pty master (`os.NewFile`) now:
   `net.FilePacketConn` costs `getsockopt(SO_TYPE)`, `getsockname` and
   `getpeername`, which the policy does not allow (S4 §3.3: start-up
   only). E is wrapped the way every later E is (§3.6), with only
   `fcntl(F_GETFL/F_SETFL)` and `epoll_ctl`, which the policy does
   allow; doing generation 1 the same way means the post-sandbox path is
   the one every session uses.
4. `sandbox.Enter(sandbox.Proto, action, params)`: DUMPABLE=0 again
   (idempotent), `NO_NEW_PRIVS` on every thread, Landlock deny-all, then
   seccomp with TSYNC.
5. Only now: send `Init`, wait for its `Update`, mint the credential,
   send `Credential`, run the `Session`.

**emu** (`server.RunEmu`):

1. `prctl(PR_SET_DUMPABLE, 0)` and `RLIMIT_CORE` 0 (`nocore.Process`).
2. Check fd 3 is a `SOCK_SEQPACKET` socket, wrap it as E. (Its memory
   limit was set by the spawner before proto got E, §6.3.)
3. Build nothing that needs a syscall outside its policy later: the
   tuios emulator is made after `Init` arrives, inside the sandbox, so
   any syscall it makes is one the soak sees.
4. `sandbox.Enter(sandbox.Emu, action, params)`.
5. Only now read E.

`sandbox.Enter` does, in order, the same order in §6.2:

1. `PR_SET_DUMPABLE` 0;
2. `PR_SET_NO_NEW_PRIVS` on every thread (`AllThreadsSyscall`);
   `landlock_restrict_self` returns EPERM without it (or
   `CAP_SYS_ADMIN`), and seccomp needs it too [kernel ABI];
3. Landlock (§6.2);
4. seccomp (§6.3) with `SECCOMP_FILTER_FLAG_TSYNC`. A non-zero return
   from the TSYNC call is the id of a thread that could not be
   synchronised and is an error.

**Failure.** On Linux, every error is fatal, the role exits 1 and the
session does not start (or, for emu, the start fails and counts against
the budget, §5.2), with **one** exception: the Landlock version probe
(`landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)`)
returning 0, or failing with ENOSYS (kernel older than 5.13) or
EOPNOTSUPP (Landlock built but not among the active LSMs). That alone
is logged as a warning, and the role carries on with seccomp alone,
which on its own stopped every attack in S4's battery (S4 §3.6, column
"seccomp only"), and with this spec's argument rules contains signals
too (§6.3). Once the probe has reported an ABI ≥ 1, any error from
`landlock_create_ruleset` or `landlock_restrict_self` is fatal, bar the
two probes §6.2 expects to fail where a feature is missing (an optional
right offered one at a time, and the `RESTRICT_SELF_TSYNC` flag), where
EINVAL means "not supported" and the next step is the fallback §6.2
names; and so is any error from `prctl`. Fatal, because it means the sandbox the kernel advertises did not
turn on, and carrying on would run seccomp-only silently. On other
systems `Enter` returns `errors.ErrUnsupported` (§10).

**Action** (`sandbox.Action`), chosen per architecture by the binary,
never by the environment in a release build:

| arch | releases | development builds only |
|---|---|---|
| amd64 | `Kill`, always [D22] | `Kill` (since the soak job, §9, is in `ci.yml`) |
| arm64 | `Kill`, since CI run 43626969195 soaked it (`Errno` before) [D22] | as releases |

D22 locks `Kill` on amd64; it gives no amd64 `Errno` allowance, and
this spec proposes none. Because every green commit is a release (D10),
the gate is mechanical: `TestReleaseAction`, part of `check`, fails
unless the action compiled in for amd64 is `Kill`, and `release` needs
`check` and `kill-soak` (§9).

`Errno` returns EPERM. The architecture and x32 checks (§6.3) kill
whatever the action: a filter that cannot even read the syscall number
right has nothing to fall back on.

### 6.2 Landlock

Through `golang.org/x/sys/unix` directly, no go-landlock (S4 §3.1,
D19). The ruleset handles every right the kernel knows and adds **no
rules**, so everything handled is denied:

| ABI | handled |
|---|---|
| 1 | every filesystem right of v1 (execute, read and write files, read dirs, remove, make every node type) |
| 2 | + `REFER` |
| 3 | + `TRUNCATE` |
| 4 | + `NET_BIND_TCP`, `NET_CONNECT_TCP` |
| 5 | + `FS_IOCTL_DEV` |
| 6 | + scoped `ABSTRACT_UNIX_SOCKET` and `SIGNAL` |
| any | + `NET_BIND_UDP`, `NET_CONNECT_SEND_UDP` and `FS_RESOLVE_UNIX` if the kernel accepts a ruleset with each, probed one at a time (none did on 6.18, S4 §3.1) |

- The ABI comes from `landlock_create_ruleset(NULL, 0,
  LANDLOCK_CREATE_RULESET_VERSION)`. The attribute struct passed is the
  three-`u64` prefix (`handled_access_fs`, `handled_access_net`,
  `scoped`) with its own size, which every ABI accepts (S4).
- `NO_NEW_PRIVS` is set on every thread first, through
  `syscall.AllThreadsSyscall` (Go, `CGO_ENABLED=0` only, which D1
  guarantees): without it `landlock_restrict_self` fails with EPERM.
  Then `landlock_restrict_self` is applied to every thread: with
  `LANDLOCK_RESTRICT_SELF_TSYNC` where the kernel accepts it, else
  through `AllThreadsSyscall` the same way. Any error here is fatal
  (§6.1, "Failure").
- Landlock checks access when a file is opened, so fds opened before
  (the pty master, the sockets) keep working, including `ioctl` on the
  pty master under `FS_IOCTL_DEV`. A test proves it (§12).
- What Landlock does not stop on a 6.18 kernel, and seccomp must: a new
  UDP socket and `sendto`, connecting a pathname unix socket (sshd's
  agent or the user bus), `io_uring_setup`, `userfaultfd`, `keyctl`, and
  `clone(CLONE_NEWUSER)` (S4 §3.6). It is defence in depth.

### 6.3 seccomp

**Compiler** (`sandbox.Compile`). Classic BPF, hand-assembled from a
list of syscall names; small enough that an assembler buys nothing
(S4). The program, in order:

1. Load `arch` (offset 4 of `struct seccomp_data`); not the target's
   `AUDIT_ARCH_*`: `KILL_PROCESS`.
2. Load `nr` (offset 0). On amd64, `nr ≥ 0x40000000` (the x32 bit):
   `KILL_PROCESS`.
3. `clone`: allowed only if `args[0]` has `CLONE_THREAD` (0x00010000):
   new threads, never new processes; otherwise the policy's default
   action.
4. **Argument rules.** Each compares only the low 32 bits of an
   argument (`args[i]` is at offset 16 + 8i, little-endian on both
   targets, so the low half is the word at that offset), and each sends
   a call that does not match to the policy's default action.
   - `ioctl`, proto only: allowed only if `args[0]` is the pty master's
     fd and `args[1]` is `TCGETS` (0x5401) or `TIOCSWINSZ` (0x5414),
     the same numbers on amd64 and arm64 [kernel ABI, asm-generic
     ioctls]. The kernel takes both arguments as `unsigned int`, so the
     high halves cannot change what it does [kernel ABI, `ioctl(2)`].
     The fd number is known only after `Start`, which is why proto's
     filter is compiled after the fds are wrapped.
   - `tgkill`, both roles: allowed only if the low 32 bits of `args[0]`
     (the tgid) equal the role's own pid, `Params.Pid`, which
     `Enter` takes from `getpid()` when it compiles the filter;
     otherwise the default. The Go runtime only ever signals its own
     threads (preemption, signal forwarding, `raise` on a crash), so
     this costs it nothing, and `tgkill(victim, victim, SIGKILL)` at
     another process of the user's is refused on every kernel, Landlock
     or not. The kernel takes the tgid as a `pid_t`, so the high half
     cannot change which process is named [kernel ABI, `tgkill(2)`].
   - `fcntl`, both roles: allowed only if the low 32 bits of `args[1]`
     (the command) are `F_GETFD` (1), `F_SETFD` (2),
     `F_GETFL` (3) or `F_DUPFD_CLOEXEC` (1030), or are `F_SETFL` (4)
     **and** the low 32 bits of `args[2]` have `O_ASYNC`
     (0x2000) clear; otherwise the default. The numbers are the same on
     amd64 and arm64 [kernel ABI, asm-generic `fcntl.h`], and the
     kernel takes the command and `F_SETFL`'s flags as `unsigned int`
     [kernel ABI, `fcntl(2)`]. This shuts the other signal route:
     `F_SETOWN` (8), `F_SETOWN_EX` (15) and `F_SETSIG` (10) are not on
     the list, and `O_ASYNC` cannot be set, so emu cannot make the
     kernel signal a victim each time its IPC fd becomes readable. These
     are the commands the runtime and `os` use after start-up (`F_GETFL`
     and `F_SETFL` for non-blocking mode, `F_DUPFD_CLOEXEC` for dup,
     `F_SETFD` for close-on-exec); the discovery procedure below
     confirms the list from the real roles' traces.
5. `clone3`: `ERRNO(ENOSYS)`, so the runtime falls back to `clone`;
   `prctl`: `ERRNO(EINVAL)`, because Go ≥ 1.25 names its mappings with
   `prctl(PR_SET_VMA)` and stops for good on EINVAL, where a kill would
   crash any kernel with `CONFIG_ANON_VMA_NAME` (S4 `policy.go`).
6. One `JEQ` per allowed syscall, sorted by number, to a shared
   `RET ALLOW`.
7. Default: the action (§6.1).

Jump offsets are 8 bits, so the compiler refuses a list that would need
a longer jump. Syscall numbers for both targets come from a table
generated from the pinned `golang.org/x/sys` (its
`zsysnum_linux_amd64.go` and `zsysnum_linux_arm64.go`), committed, and
checked by a test against `unix.SYS_*` on the host's architecture. A
name a target lacks (`open` on arm64) is an error at compile time, not a
silent skip: the policies list only names both have.

**Policies** (`sandbox.PolicyFor`). The runtime set, from S4's traces of
Go 1.27 with `CGO_ENABLED=0` after start-up (S4 §3.3):

```
mmap munmap madvise
clone(CLONE_THREAD) futex sched_yield nanosleep gettid getpid
tgkill(own pid)
sigaltstack rt_sigaction rt_sigprocmask rt_sigreturn
exit exit_group
sched_getaffinity pread64
epoll_pwait epoll_ctl
clock_gettime
fcntl(F_GETFD, F_SETFD, F_GETFL, F_DUPFD_CLOEXEC, F_SETFL without O_ASYNC)
close read write
clone3 → ENOSYS, prctl → EINVAL
```

Every name with an argument in brackets is allowed only under the rule
of step 4; none of the runtime set goes out unfiltered if it can reach
another process.

`exit` was never observed but is how a thread ends when a goroutine
exits locked to it (`runtime.exitThread`); `pread64` appears only under a
CPU quota, where Go's `updatemaxprocs` re-reads the cgroup's `cpu.max`
(about every 60 s idle, every second busy), which is why strace without
a quota missed it and only a soak under `CPUQuota` found it (S4 §3.3,
§3.5).

| role | adds | why |
|---|---|---|
| emu | nothing | it reads and writes E with `read` and `write` |
| proto | `recvfrom`, `sendto` | the UDP socket (`ReadFromUDPAddrPort`, `WriteToUDPAddrPort`). The transport must use these two calls and not `ReadMsgUDP`/`WriteMsgUDP` without a policy change: `recvmsg` is allowed for C, `sendmsg` is not |
| | `recvmsg` | `EmuLink` with its fd, after the sandbox is on |
| | `getrandom` | `crypto/rand`: the credential, the handshake, rekeys, path challenges |
| | `ioctl` (argument rule, step 4) | `TCGETS` for the echo-off bit (D12), `TIOCSWINSZ` for the window size and the repaint after a rebuild (§5.2) |

Absent from both, on purpose: `socket`, `socketpair`, `connect`, `bind`,
`listen`, `accept4`, `open`/`openat`, `execve`, `fork`/`vfork`,
`ptrace`, `process_vm_*`, `pidfd_*`, `kill`, `io_uring_*`,
`userfaultfd`, `keyctl`, `unshare`, `setns`, `sendmsg`, `mprotect`.
The agent slice adds nothing: the spawner accepts agent connections and
passes each to proto (§2.7, `AgentConn`), so proto never needs `accept4`,
which S4 §5.2 had expected it to.

**S4's list was traced from a stand-in.** Its emu was a toy, not tuios,
and its proto ran a toy wire format, not B3, SSP and flate. So before
slice 1 turns `Kill` on, the lists are re-derived from the real roles by
the discovery procedure: build with `-tags soak`, run each role under
`strace -ff` with the filter's default action set to `SECCOMP_RET_LOG`
(allowed and logged; only a `soak` build can choose it) through the
soak's load (§9) once unconstrained and once under `CPUQuota=200%`, and
take, per role, every syscall a thread made after its `seccomp(2)` call.
The policy is that set plus `exit`, and any difference from the list
above is recorded in this section with the trace that showed it.

**Memory** (D23). Two limits on emu, because tuios stores OSC 8 links by
value with no ceiling (S2: 2 KiB links cost about 2.2 KB per history
cell, gigabytes at the clamp):

- **cgroup**, when the user has a systemd user manager: after starting
  emu, the spawner moves it into a transient scope with `busctl --user
  --timeout=2 call org.freedesktop.systemd1 /org/freedesktop/systemd1
  org.freedesktop.systemd1.Manager StartTransientUnit
  'ssa(sv)a(sa(sv))' mosey-emu-<spawner pid>-<generation>.scope fail 4
  PIDs au 1 <pid> MemoryMax t 536870912 MemorySwapMax t 0 CollectMode s
  inactive-or-failed 0`. 512 MiB is D23's `MemoryMax`; `MemorySwapMax=0`
  [derived] so swap cannot postpone the limit. busctl, not a D-Bus
  library (D19). Before handing proto the new E the spawner waits for
  the call to return, so emu has parsed nothing outside its scope. No
  `busctl`, no `XDG_RUNTIME_DIR`, or a failed call: logged once, and the
  session carries on with the second limit alone (S4 §3.10: a login
  without PAM has no user manager).
- **`RLIMIT_DATA`** of 1 GiB, soft and hard, set **by the spawner** on
  the new emu with `prlimit64(pid, RLIMIT_DATA, …)` straight after
  starting it, before the scope call and before proto gets E, so emu
  has read nothing when it takes effect. The spawner is unsandboxed and
  of the same uid, which is all `prlimit64` on another process needs
  [kernel ABI, `prlimit(2)`]; emu cannot raise it again (no
  `CAP_SYS_RESOURCE`, and neither `prlimit64` nor `setrlimit` is in its
  policy). [derived: twice `MemoryMax`, because it counts private
  writable mappings, which run ahead of what a cgroup charges.] Go's
  runtime fails an allocation past it with `fatal error: out of
  memory` and exit 2, which the spawner classifies as a memory death
  (§5.2). It works with no systemd and on any Linux. Whether 1 GiB
  leaves tuios enough at the clamp (S2: about 86 MiB for both screens at
  1000x500) and still stops S2's link flood is for
  `TestEmuMemoryLimitRestartsEmu` (§12), which is **not yet written**:
  until it is, that is untested.
- **No emu runs unbounded** (threat-model.md §4.8). `RLIMIT_DATA` is
  the limit every host has, so it is required, not best effort: if
  `prlimit64` fails, the spawner SIGKILLs that emu before proto ever
  gets its E. For generation 1 that fails the session before it
  starts, with `Failed{"cannot limit the emulator's memory"}` (§2.1
  step 4.5), so the user is told why; for a restart it is a failed
  start, counted against the budget (§5.2), because by then the session
  is the user's and an emu failure never ends it. Setting the limit
  from the spawner rather than in emu means no message or exit code
  from emu, which a compromised emu could forge, decides whether a
  limit is in force.

proto gets neither: it holds no unbounded structure an attacker
controls (every buffer it fills from the network or emu has a bound
above), and a memory death of proto ends the session.

### 6.4 Logs

Each session has one log, `${XDG_STATE_HOME:-$HOME/.local/state}/mosey/serve-<UTC
time, RFC 3339 basic>-<spawner pid>.log`, made by the spawner: directory
0700, file 0600, `O_CREAT|O_EXCL|O_NOFOLLOW|O_APPEND`. It does not exist
before step 2 of §2.1, so earlier failures reach the user through
`Failed` and ssh's stderr only.

- The spawner writes its own `log/slog` text records there.
- Each role's stderr is a pipe to the spawner, which reads it a line at a
  time (at most `MaxLogLine` = 4096 bytes; a longer line is cut and
  marked), replaces every byte outside 0x20–0x7E with `?`, and writes it
  with a prefix naming the role, pid and generation the spawner knows
  the pipe belongs to. A compromised role cannot pass its lines off as
  another's or write control bytes to the file (S4 §3.6: "log line
  injection on inherited stderr", every role).
- The whole file is capped at `MaxLog` = 1 MiB per session [derived];
  past it one "log truncated" line is written and the rest is dropped,
  so neither a network attacker (rejected packets are logged) nor a
  hostile program can fill the disk through it. Proto and emu also
  rate-limit their own repeated lines (at most one per kind a minute).
- At start the spawner removes its own `serve-*.log` files in that
  directory older than 7 days [derived].

---

## 7. proto's main loop, briefly

`server.Session.Run` (architecture §3) does the work; what matters here
is its threads of control and the ordering rules the IPC imposes:

- **pty reader**: reads the master in chunks of up to 16 KiB, calls
  `Emulator.Write`, then reads `Terminal.EchoOff` (`TCGETS`) and hands
  `Emulator.Snapshot` plus the echo-off bit to SSP. It never writes the
  pty (§4.3). EIO on the read means every slave fd has closed. After its
  first read that returns bytes it sends the spawner `FirstOutput`.
  **It is where the program is held back** (`screen.md` §2.5, Dan
  2026-11-16): proto alone reads the master, and proto alone sees SSP's
  acknowledgement, so neither emu nor the spawner takes part. While a
  client is attached and heard (attached, not silent for `SilentAfter`,
  and the shell not yet exited), before each read it compares the
  history of the screen it last published with the acknowledged one
  (`Endpoint.Acked`); while a quarter of the window or more is
  unacknowledged it waits for `Endpoint.AckedChanged`, a change of
  listener or the end, and then reads at most a quarter of the window
  in bytes. A hold that has gone `SilentAfter` without the
  acknowledgement advancing lifts until it does, since a client whose
  heartbeats arrive but which hears nothing is in a dead spot too. Otherwise it reads whole chunks. The writer is never held,
  so keystrokes, Ctrl-C among them, and resizes reach the pty while the
  reader waits; the screen meanwhile is the last state read, which SSP
  keeps sending, and an emu rebuild is unaffected (it renumbers
  nothing, §5.2).
- **pty writer**: keystrokes first, then replies (§4.3). It keeps the
  echo ack's write log, reads the echo-off bit before each key event and
  publishes if it changed, and arms the 50 ms echo-ack publish
  (`prediction.md` §3.1).
- **resize**: a resize from the client is clamped (`screen.ClampSize`),
  given to `Emulator.Resize` **first**, then to the pty with
  `TIOCSWINSZ`. The kernel's SIGWINCH makes the program repaint at the
  new size, and that output must reach an emulator already at it
  [derived].
- **network**: the transport listener and SSP endpoint (their specs).
- **C reader**: `EmuLink`, `EmuPaused`, `AgentConn`, `ShellExit` and `Root`
  from the spawner; EOF ends the session at once.

---

## 8. Constants

| name | value | where | provenance |
|---|---|---|---|
| UDP port range | 60000–61000 | spawner | [mosh(1)] |
| bind address | `SSH_CONNECTION` server address | spawner | [mosh(1), `--bind-server=ssh`] |
| `MaxMessage` | 65536 B | ipc | [derived: < `wmem_default` 212992] |
| `MaxOutput` | 16384 B | ipc | [derived] |
| `MaxReplies` | 4096 B | ipc | [derived from S2] |
| `MaxReplyToken` | 256 B | server | [derived] |
| `MaxReplyTokens`: reply allowance per request | introducers in this `Output` and the one before, at most 8 | server | [derived; `TestReplyAllowanceCoversRealPrograms`, not yet written] |
| `screen.MaxDiff`: one `Update` run, reassembled | 64 MiB | proto | [`screen.md` §5.12] |
| `ReplyQueue` | 64 KiB, drop when full | server | [S2, reply flood] |
| `MaxClientLine` | 8192 B | ipc, bootstrap | [`bootstrap.md` §6.2] |
| `MaxCredentialLine` | 2048 B | ipc, bootstrap | [`bootstrap.md` §6.3] |
| T1: launcher reads the `ClientLine` | 30 s | launcher | [`bootstrap.md` §4.4: `handshake.CredentialTTL`] |
| T2: launcher waits for `Ready` | 15 s | launcher, spawner | [derived] |
| T3: spawner waits for `Credential`; proto waits for `Start` | 10 s | spawner, proto | [derived] |
| T4: one emu request | 30 s | proto | [derived: S2 measured about 3 ms per REP, so 16 KiB of REP storm costs seconds; 30 s is far past any honest request and still ends a hang] |
| T5: drain after the shell exits | until EIO, at most 1 s | proto | [derived] |
| T6: final screen delivery | until acked, at most 3 s | proto | [derived: D11's heartbeat] |
| T7: proto after C closes | 2 s | spawner | [derived] |
| T8: shell after hangup | 5 s | spawner | [derived] |
| T9: emu after E closes | 1 s | spawner | [derived] |
| `MaxAttachConns`: attach-socket connections served at once | 4 | spawner | [choice] §2.6 |
| greeting deadline (launcher, lister) | 2 s | launcher | [choice] `bootstrap.md` §11 |
| `SilentAfter`: a silent client counts as detached | 15 s | proto | [D] `bootstrap.md` §9.2: five 3 s heartbeats (D11) |
| `IdleTimeout`: a detached session is hung up | 7 days | spawner | [D] Dan, D8 R4 |
| `HangupGrace`: SIGHUP, then the teardown | 10 s | spawner | [choice] `bootstrap.md` §9.3 |
| `TypeWait`: the most a `type` waits for the shell's first output and its tty to stop echoing | 2 s | spawner | [choice] `bootstrap.md` §9.2.3 |
| `echoPoll`: how often that wait looks at the tty's echo bit | 10 ms | spawner | [choice] `bootstrap.md` §9.2.3 |
| `RootPoll`: how often the foreground's uid is sampled while a client is attached | 500 ms | spawner | [derived] §2.9 |
| a resume's hold on the greeting | `handshake.CredentialTTL`, 30 s | spawner | [derived] `bootstrap.md` §9.2 |
| emu restart backoff | 50 ms, ×2, ≤ 5 s; reset after 60 s alive | spawner | [S4 §3.8] |
| emu restart budget | 10 per 60 s | spawner | [S4 §3.8] |
| `EmuCooldown`: pause once the budget is spent | 60 s, then a fresh budget; never ends the session | spawner | [derived: the budget window; §5.2] |
| emu `MemoryMax` | 512 MiB | spawner | [D23] |
| emu `MemorySwapMax` | 0 | spawner | [derived] |
| emu `RLIMIT_DATA` | 1 GiB, set by `prlimit64`, required | spawner | [derived; `TestEmuMemoryLimitRestartsEmu`, not yet written] |
| scrollback budget | 1,000,000 cells | proto → emu (`Init`) | [D23] |
| `MaxLog` | 1 MiB per session | spawner | [derived] |
| `MaxLogLine` | 4096 B | spawner | [derived] |
| log retention | 7 days | spawner | [derived] |
| soak length | ≥ 150 s | CI | [D22 ≥ 120 s; derived: + one 120 s rekey, D20] |
| soak quota | `CPUQuota=200%` | CI | [S4 §3.4] |

---

## 9. The KILL soak (CI gate, D22)

A missing syscall stays hidden until the runtime happens to make it:
S4 dropped `pread64` and saw nothing for **60 s** idle, then a SIGSYS
(S4 §3.5). Unit tests cannot find that; only the real roles running long
enough, under the conditions that trigger the rare paths, can.

**What runs.** `scripts/soak.sh --scope DURATION`, as the CI job
`kill-soak` (as built, the test binary is `internal/server`'s, running
`TestKillSoak` and `TestEmuKillSoak`, which CI runs on a runner each per
architecture with `--test NAME`, and the scope uses the runner's
user through `setpriv`; without `--scope` it runs as it is, for a
workstation):

1. Build `mosey` with `-tags soak` and the e2e test binary
   (`go test -c ./internal/e2e`). The `soak` tag adds only two things,
   neither of which touches a policy: a goroutine in proto and emu that
   churns the runtime after `Enter` (garbage collection,
   `debug.FreeOSMemory`, deep stack growth, bursts of goroutines,
   timers), as S4's soaks did; and reading `MOSEY_SOAK_ACTION`
   (`kill`, `errno` or `log`) so arm64 can be soaked under `Kill` before
   its default changes. A release build has neither.
2. Run the test binary in a transient scope with a CPU quota, as the
   runner's user: `sudo systemd-run --scope --quiet -p CPUQuota=200% --
   setpriv --reuid=$(id -u) --regid=$(id -g) --init-groups --
   env MOSEY_SOAK=150s MOSEY_SOAK_BIN=… MOSEY_SOAK_ACTION=kill
   e2e.test -test.run '^TestKillSoak$' -test.timeout 10m`. The quota
   makes `cpu.max` exist, so `pread64` runs throughout; the server
   itself is unprivileged.
3. `TestKillSoak` (skipped unless `MOSEY_SOAK` is set) starts `mosey
   --serve` directly, writing the `ClientLine` to its stdin and reading
   the credential from its stdout (no sshd needed), and drives a
   `client.Session` over loopback UDP with a fake terminal. The shell is
   `/bin/sh` running, for the whole run: about 1 KB of output every
   50 ms (S4's load), a cursor-position query every second (exercises
   the reply path and §4), a resize every 5 s (exercises `TIOCSWINSZ`
   and `TCGETS`), and keystrokes every 100 ms.

**It passes when**, and fails otherwise:

- `cpu.max` of the scope is not `max` (logged; proves the quota held);
- no role died before teardown: the session log has no child-exit line
  for proto or emu, and no emu restart;
- the client received output in every 10 s window, and an answer to
  every cursor-position query;
- at least one rekey completed (`transport.Rekeyed`, D20's 120 s);
- the session ended cleanly when the test exited the shell.

**When.** On every push and pull request, on `ubuntu-latest` (amd64)
and `ubuntu-24.04-arm` (arm64 hardware), so every Go upgrade (a
`mise.toml` or `go.mod` change), every dependency bump and every policy
change is soaked on both architectures before it can release; `release`
needs it. About three minutes per architecture. A weekly scheduled run
as well [derived], because runner kernels change underneath us.

**Turning `Kill` on.** amd64 switches to `Kill` in the commit that adds
the job, once it is green; before that commit no build is releasable,
because `TestReleaseAction` fails in the `release` job (§6.1), so D22's
"KILL on amd64" holds for every release. arm64 switched in a later
commit, citing CI run 43626969195: 150 s under `MOSEY_SOAK_ACTION=kill`
on ubuntu-24.04-arm with a CPU quota, no role killed (D22).

---

## 10. Platform layer and macOS

Linux-only mechanisms live in `_linux.go` files behind portable
functions; the `_other.go` files return `errors.ErrUnsupported`, and
the whole tree builds and vets for darwin (`mise run lint`). macOS is
parked, not ruled out (D22): nothing above this layer may assume Linux.

| mechanism | Linux (slice 1) | macOS (later; nothing here may prevent it) |
|---|---|---|
| pty | `/dev/ptmx`, `TIOCSPTLCK`, `TIOCGPTN`, `TCGETS`, `TIOCSWINSZ` | `/dev/ptmx` with `TIOCPTYGRANT`, `TIOCPTYUNLK`, `TIOCPTYGNAME`; `TIOCGETA` for termios; `TIOCSWINSZ` |
| IPC framing | `SOCK_SEQPACKET` socketpair | macOS has no `AF_UNIX` `SOCK_SEQPACKET` (to verify on a Mac), and its `SOCK_DGRAM` caps a message at `net.local.dgram.maxdgram` (2 KiB by default). So: `SOCK_STREAM` with a 4-byte big-endian length before each message, bounded by `MaxMessage` before any allocation. The message layouts of §3.3 do not change; the length prefix is the one new thing to fuzz |
| fd passing | `SCM_RIGHTS` | the same |
| parent death | `Pdeathsig` (`SysProcAttr` field is Linux-only: it must stay in a `_linux.go` file) | EOF on the IPC socket only |
| sandbox | Landlock + seccomp + `PR_SET_DUMPABLE` | Seatbelt `sandbox_init` with the `pure-computation` profile, reachable from a `CGO_ENABLED=0` binary through `//go:cgo_import_dynamic` and an assembly trampoline (S4 §3.11, built and compiled for both Mac architectures, never run). `ptrace(PT_DENY_ATTACH)` in place of DUMPABLE. Open: whether `sendto` on the inherited UDP socket survives `pure-computation` (roaming needs it; `cmd/seatbelt-probe` tests exactly this); and the API is deprecated, with profiles reported to kill processes built against SDK ≥ 27 (S4 §3.11). Dan decides before a macOS server ships |
| emu memory limit | cgroup scope + `RLIMIT_DATA` | `RLIMIT_DATA` is not enforced for `mmap` on macOS, and there are no cgroups: unsolved, and required before a macOS server ships (D23) |
| syscall policy test | BPF interpreter, any host | not applicable |

Until then `mosey --serve` on macOS prints `mosey --serve: the server
runs on Linux only for now` and exits 1 (from `pty.Open`'s
`ErrUnsupported`), so the client can say so. The client runs on macOS
from slice 1.

---

## 11. Interface changes this spec needs

Not yet agreed; each is for server-proc (or the owner named) to settle
and record in `architecture.md`:

1. **Roles.** `cmd/mosey/server.go`: `--serve` becomes the launcher and a
   new `--serve=spawner` role is the spawner (§1.1). `server.Spawner.Run`
   becomes the launcher's main; the spawner's main is new (for example
   `server.RunSpawner(ctx, ipcFD)`), and `Spawner` gains `BindAddr` for
   tests.
2. **ipc messages.** `Start` gains `Flags`, `Addr` and `Port`; new
   `EmuLink{Generation, Reason, Status, Conn *os.File}`, `ShellExit`,
   `EmuPaused{Seconds}`, `KillEmu`, `Init{Cols, Rows, ScrollbackCells, Foreground,
   Background, Palette}`, `ClientLine`, `Ready`, `Failed`; `Update`
   gains `More`; `Exit` gains a `Code` (4 unassigned, §3.3). Message ints become fixed-width
   types (`uint16` for sizes) so `Marshal` cannot be handed a value its
   layout cannot hold.
3. **ipc.Conn** is made for one peer (`NewConn(f, peer)`), so `Recv`
   refuses the other directions' types, and it reads with `read` or
   `recvmsg` as §3.1 says. **server** gains `SplitReplies` beside
   `ValidReply`.
4. **sandbox.Policy** needs argument rules (§6.3 step 4): proto's
   `ioctl` (fd and request), and in both roles `tgkill` (`args[0]` is
   the role's own pid) and `fcntl` (the command list, and `F_SETFL`
   only with `O_ASYNC` clear). `Compile` needs the fd number and the
   pid, so `Enter` takes them (for example `Enter(role, action,
   Params{PTY: fd, Pid: pid})`, with `Enter` filling `Pid` from
   `getpid()` when it is zero, and tests passing another to the
   interpreter). `PolicyFor`'s `Policy` gains the `clone3`/`prctl` errno
   answers explicitly rather than hiding them in `Compile`. `sandbox`
   also gains `TestReleaseAction` (§6.1) and, for the live battery only,
   a test-only way to enter seccomp without Landlock (§12), not
   reachable from the binary.
5. **screen** (screen owner): nothing new. `screen.MaxDiff` is 64 MiB (48 MiB before the scrollback slice)
   (`screen.md` §5.12), and proto uses it as is to bound `Update`
   reassembly, so proto's buffer for one diff is up to 64 MiB (§3.3);
   `Grid.Rebuilt` (`screen.md` §11, item 1) is what §3.6 sets.
6. **bootstrap** (bootstrap-client): the `ClientLine` should carry the
   client terminal's foreground, background and 16-colour palette, so
   emu answers colour queries with what the user sees (S2); until then
   `Init` sends `DefaultColor`.
7. **Session end and notices** (ssp or crypto-transport). *The session
   end is done at integration:* the END frame, `0x0A` with a reason byte,
   `Conn.End` and the `Ended` event (`transport.md` §8.4); proto sends it
   when the shell exits and ends the session on the client's. The
   `EmuPaused` notice is still open. As first written: nothing in the
   interfaces lets proto tell the client "the shell exited" (so it exits
   at once, not on a timeout), or lets the client tell proto "I quit"
   (`Exit{ClientClosed}`), or tells the client "the screen is
   unavailable for N seconds" during an `EmuPaused` cool-down (§5.2). A
   sealed close frame kind (the next free `transport.Kind`, 0x0A) with
   a reason byte would cover the first two; the pause notice could ride
   a notice frame or a `screen.Grid` field, for `screen.md`'s owner to
   choose. D23's rebuild notice itself needs nothing new: it is
   `Grid.Rebuilt` (§3.6).
8. **emu** (screen owner): `emu.XTVersion`, the exact XTVERSION name,
   so proto can pin it (§4.2); and emu's tuios set-up must turn kitty
   graphics and sixel off (S2), which §4.2's list assumes.
9. **COLORTERM** (screen owner): if `render` maps truecolor down to what
   the local terminal shows, the shell could always get
   `COLORTERM=truecolor`; until that is settled the client's value is
   passed through (§2.5).

---

## 12. Tests

Every package has unit tests; every parser of input from another
process has a fuzz target, run locally for at least a few minutes before
it lands, with the duration and exec count in the commit message.

**resume** (§2.6; `internal/server`)
- The attach socket: made under a checked 0700 directory; refused under
  a directory with group or other bits, owned by someone else, or a
  symlink; a peer of another uid is closed unanswered (where the test can
  be another uid; otherwise the check's function is tested alone).
- A resume through the socket, with stub proto: greeting, `ClientLine`,
  `Resume` forwarded, `Credential` checked (a different `sid`,
  `addr`, `port` or `name` is a violation), `Ready` returned. A wrong
  SID, `new` or a bad key is `Failed`, and proto never hears of it.
- A lister that closes after the greeting changes nothing.
- The greeting follows `Attached` and `Detached`, says `attached` held by
  a resume's credential until its TTL (a reconnect's hold naming the
  reconnecting client's credential), and carries the name.
- `Hangup` and the idle timeout (short, injected) send the shell SIGHUP;
  the idle clock, on virtual time, runs only while detached, and an
  attach stops it.
- The launcher's choice (`bootstrap.md` §9.2): `auto` takes the newest
  detached and never an attached one, else starts a named session; `name`
  takes NAME whatever its state, else starts it; `new` always starts; R3's
  holder rule gives `session`, `taken` or the session; generated names
  never clash.
- The launcher's attach-protocol rule (§2.8): a session of any mosey
  version is attached as it is, running its own binary; one of another
  attach protocol is passed over by `auto`, refused with `attach` by
  `name` and `resume`, and keeps its name from a new session.
- Hopping (§2.5): `PATH` gets `~/.local/bin` first only when the
  binary is `~/.local/bin/mosey`, `PATH` has no `mosey`, and the
  directory keeps the installer's rules.
- `Session`: a client silent for `SilentAfter` is reported `Detached`
  and, when heard again, `Attached`, without losing its connection.
- `Session` (in process, netsim, synctest): a client vanishes without
  END and a new one attaches with a second credential for the same SID:
  the new one gets the whole screen and its keys reach the shell, the old
  one is revoked. A client that ends with END leaves the session running,
  and a later one resumes it. The shell exiting while nobody is attached
  ends the session. A session never attached still ends with `NoClient`.

**ipc**
- `Marshal` then `Parse` round-trips every type at its bounds.
- Each type is refused at length ± 1, with each field one past its
  range, with reserved bits set, from the wrong peer, and with the wrong
  number of fds (and every fd of a refused message is closed: count
  open fds before and after).
- A message of `MaxMessage + 1` bytes is refused, not truncated.
- `FuzzParse` per peer: never panics; whatever it accepts re-marshals to
  the same bytes.

**server**
- `ValidReply` accepts one of each shape in §4.2, built by tuios itself
  (feed each query to `emu.New` and take the answer), so the list and
  the emulator cannot drift apart.
- `ValidReply` and `SplitReplies` refuse S4's forged set (`touch …\n`; a
  valid reply followed by `\n`, by a command and CR; a bracketed-paste
  wrapper; OSC 52; DECRQSS with a C0 in it; a wrong final byte; an over-long number; the
  empty string) and anything with a byte outside 0x20–0x7E between
  introducer and terminator.
- The reply allowance (§4.1), on the IPC emulator with a fake emu: an
  `Output` with no introducer, after one with none, passes no token at
  all; two valid tokens run together after an `Output` with one
  introducer pass one and count one dropped; nine valid tokens after an
  `Output` with twenty introducers pass `MaxReplyTokens` (8); a query
  split as `ESC` | `[6n` across two `Output`s, and as `ESC [6` | `n`,
  is answered; a `Resize` gets none. Dropped tokens are not violations
  and never reach the reply queue.
- `TestReplyAllowanceCoversRealPrograms` (**not yet written**): the
  start-up query bursts of
  vim, fish, neovim and Claude Code, recorded once into testdata, fed
  through tuios and the allowance: every answer reaches the reply
  queue. If one does not, `MaxReplyTokens` is raised with the recording
  as its provenance.
- `FuzzSplitReplies`: never panics; on success the tokens concatenate to
  the input and no token holds a C0 byte other than its leading ESC and
  its terminator; every token `ValidReply` accepts matches the list.
- The emu protocol: with a fake emu, each item of §3.5's violation list
  produces `KillEmu{violation}` and changes neither the mirror grid nor
  the reply queue; a silent emu produces `KillEmu{deadline}` after T4
  (synctest).
- §3.5's proto-owned fields: a fake emu whose complete diff sets
  `EchoOff`, `EchoAck`, `EchoApplied` or `Rebuilt` gets
  `KillEmu{violation}`, and the
  mirror is unchanged.
- Restart: a fake spawner sends a new `EmuLink`; the mirror is reset
  to a blank grid at the current size and the new emu's first diff
  applies from it; the next
  `Snapshot` is the new emu's screen with `Rebuilt.Seq` one higher and
  `Rebuilt.Reason` mapped as §3.6 says for each `EmuLink` reason and
  each `KillEmu` why; `Write` blocked across the gap resumes; and the
  pty sees the size go to (cols, rows−1) and back (rows+1 at one row),
  emulator first each time.
- Supervision (spawner, with stub roles that exit on cue; synctest for
  the clock): backoff 50, 100, 200 … 5000 ms; reset after 60 s alive;
  the eleventh start in 60 s is not made, proto gets
  `EmuPaused{60}`, nothing starts for 60 s, then emu starts again with a
  fresh budget; through all of it the stub shell is never signalled and
  the session never ends. A stub emu that writes `fatal error: out of
  memory` followed by 200 lines of traceback and exits 2 is classified
  "over its memory limit"; one that exits 2 without the line is
  "exited". A `prlimit64` that fails (a test hook) at generation 1 fails
  the session with its reason, and at a later generation counts as a
  failed start.
- Input to a program that never reads it (`internal/server`, on netsim
  under synctest, the in-process emulator, a pty whose slave program
  sleeps and never reads stdin): the client types 1 MiB. `applied`
  stops once the line discipline's buffer is full; `InputConsumed`
  stops with it; the client stops reading within a round trip; the
  server's input stream never exceeds `RetainBytes` past `applied`; no
  `ErrProtocol`, nothing dropped; memory stays bounded. When the
  program starts reading, all 1 MiB arrives in order.
- The spawner's §3.4 checks: a credential line with another port or
  address, a non-canonical line, a second `Credential`, any fd: proto is
  killed and the session ends.
- `FuzzLogLine`: the stderr line sanitiser never emits a byte outside
  0x20–0x7E or more than `MaxLogLine`.
- The hold (`screen.md` §2.5): it is a quarter of the window at the
  screen's width, and a client new to the session lacks the window and
  no more. End to end over netsim (`internal/e2e/holdback_test.go`):
  `seq 5000` and `seq 20000` while the client listens reach the local
  scrollback whole on every profile; a client silent past `SilentAfter`
  releases the program and prints one marker for exactly the gap, and so
  does a client that only the server's datagrams fail to reach; a
  client that leaves mid-flood releases it at once; Ctrl-C during a flood
  gives the prompt back within an answer's time plus two hold cycles on
  a slow link.

**sandbox**
- `Compile` for amd64 and arm64, run through a BPF interpreter in the
  test on any host: every policy syscall allowed; a syscall off the
  list gets the action; the wrong arch and (amd64) the x32 bit kill;
  `clone` with and without `CLONE_THREAD`; `clone3` → ENOSYS;
  `prctl` → EINVAL; `ioctl` allowed only for the master fd with
  `TCGETS` or `TIOCSWINSZ`, refused for another fd, another request, or
  the right request with junk in the high 32 bits of a different
  argument; `tgkill` allowed with `args[0]` the compiled-in pid (with
  and without junk in its high 32 bits), and given the action for any
  other pid; `fcntl` allowed for `F_GETFD`, `F_SETFD`, `F_GETFL`,
  `F_DUPFD_CLOEXEC` and `F_SETFL` without `O_ASYNC`, and given the
  action for `F_SETFL` with `O_ASYNC`, `F_SETOWN`, `F_SETOWN_EX`,
  `F_SETSIG` and an unknown command; the jump-length refusal.
- `TestReleaseAction`: the action compiled in for amd64 is `Kill`
  (§6.1), checked in every run of `check`.
- `FuzzCompile`: random syscall numbers and arguments through the
  interpreter agree with a plain-Go reference of the same policy.
- The generated syscall table agrees with `unix.SYS_*` on the host.
- Live, Linux, in a re-executed child of the test binary (skipped where
  seccomp or Landlock is unavailable): after `Enter(Emu, Errno)`,
  `socket`, `openat`, `kill`, `execve` and `ptrace` fail with EPERM and
  the runtime keeps working (GC, goroutines, timers); after
  `Enter(Emu, Kill)` the first `socket` kills the child with SIGSYS and
  leaves no core; Landlock alone denies `openat` of a file in a temp
  dir; `ioctl(TIOCSWINSZ)` on a pty master opened before `Enter(Proto,
  …)` still works (`TestResizeAfterSandbox`).
- `TestLandlockInForceAfterEnter`: whenever the version probe reports
  ABI ≥ 1, a child runs the full `Enter` sequence (DUMPABLE,
  `NO_NEW_PRIVS`, Landlock, seccomp) with a test-only policy that is the
  role's plus `openat`, then opens a file in a temp dir: it must fail
  with EACCES, which only Landlock gives (seccomp would give EPERM or
  SIGSYS), and the parent must see `NoNewPrivs: 1` and `Seccomp: 2`
  in the child's `/proc/<pid>/status` (the child itself cannot open
  it, which is the point). Without this, a Landlock that silently did not turn on
  would pass every other test, because the real policies also deny
  `openat`.
- No signals out, Landlock disabled: the child enters seccomp only (the
  test-only hook of §11, item 4) under `Errno` and then `Kill`, and the
  test watches a sibling process it started that counts the signals it
  gets. `tgkill(sibling, sibling, SIGUSR1)` fails (EPERM, or SIGSYS
  under `Kill`); `fcntl(E, F_SETOWN, sibling)`, `F_SETSIG` and
  `F_SETFL|O_ASYNC` each fail; the peer then writes to E, and the
  sibling has counted no signal. The runtime's own preemption still
  works (a busy loop is preempted: `tgkill` at its own pid is allowed).
- `TestRestartUnderKill`: proto under `Enter(Proto, Kill)` receives a
  second `EmuLink` after its sandbox is on, wraps it (§3.6), sets a read
  deadline, completes `Init`, and does not die of SIGSYS.

**pty**
- `Open` at a size, `SetSize`, and reading it back from the slave.
- `EchoOff` follows the slave's termios (set `!ECHO && ICANON` on the
  slave, read it through the master), and is false in raw mode.
- A login shell starts with the pty as its controlling terminal, as a
  session leader, with `argv[0]` starting with `-`.
- An interrupt typed on a fresh pty (ISIG without NOFLSH) discards the
  output not yet read but for at most 4 KiB, and a writer blocks once a
  bounded amount waits (`screen.md` §2.5 rests on both).

**The roles, together** (Linux; `internal/server` or `internal/e2e`)
- `TestServeBootstrap`: run `mosey --serve` from a built binary, write
  a `ClientLine`, read one credential line, see the launcher exit while
  the spawner lives on, then connect and get a prompt.
- `TestEmuMemoryLimitRestartsEmu` (**not yet written**; R18 in the
  threat model says so): S2's 2 KiB-link flood at the clamp
  kills emu through `RLIMIT_DATA` (and through the cgroup where a user
  manager exists), emu is restarted, the session goes on.
- `TestCompromisedEmuCannotTypeIntoTheShell` (**not yet written**): an
  emu built with a test hook sends S4's forged replies; no file appears,
  and the forged messages are logged as refused. Until it is, the fake
  emu's `TestTheReplyAllowanceBoundsWhatEmuCanType` and
  `TestForgedRepliesAreRefused` cover proto's side.
- `TestKillSoak` (§9), skipped unless `MOSEY_SOAK` is set.
- Before the transport exists, three tests cover what they can without
  it: `TestTheEmuRoleRunsTuiosUnderKill` runs the real emu role (tuios)
  under its `Kill` policy in a copy of the test binary and drives it
  through the IPC emulator; `TestEmuKillSoak` does the same for
  `MOSEY_SOAK`, with the soak build's runtime churn; and
  `TestTheSpawnerRunsASessionAndRebuildsEmu` runs the launcher, the real
  spawner and emu, and a stand-in proto that holds no key, through the
  bootstrap, a shell command, an emu kill and restart, and the
  teardown.

---

## Review notes

Answers to the review of this spec. Items 1 and 6, and 3 and 7, raised
the same defect twice and share an answer.

1. **`tgkill` and `fcntl` went out unfiltered** (critical; also item
   6). *Fixed.* §6.3 step 4 now compiles argument rules in both roles:
   `tgkill` only when the low 32 bits of `args[0]` are the role's own
   pid (compiled in from `getpid()`), and `fcntl` only for `F_GETFD`,
   `F_SETFD`, `F_GETFL`, `F_DUPFD_CLOEXEC`, and `F_SETFL` with `O_ASYNC`
   clear, as threat-model.md §4.11 requires. The runtime set marks both.
   §11 item 4 asks for both rules and the pid parameter. §12 adds them to
   the BPF interpreter tests and adds a live test with Landlock off:
   `tgkill` at a sibling, and `F_SETOWN` + `F_SETSIG` + `O_ASYNC`, under
   `Errno` and `Kill`. §1.2 and §5.2 no longer lean on Landlock: §1.2
   says why emu cannot signal on any kernel, and §5.2 no longer has
   anyone send a signal (see item 10).
2. **Landlock before `NO_NEW_PRIVS`** (major). *Fixed.* §6.1 and §6.2
   now give one order: DUMPABLE, then `NO_NEW_PRIVS` on every thread,
   then Landlock, then seccomp. Under "Failure", the only non-fatal
   Landlock outcome is the version probe reporting 0, ENOSYS or
   EOPNOTSUPP. Any error after a positive ABI is fatal, except the two
   feature probes that are expected to return EINVAL.
   `TestLandlockInForceAfterEnter` checks that Landlock is really in
   force after `Enter`, using EACCES, which only Landlock returns.
3. **amd64 `Errno` presented as settled** (major; also item 7).
   *Fixed.* §6.1's Action table now follows D22: releases on amd64 run
   `Kill`, always, and an amd64 `Errno` build is development-only. The
   gate is mechanical, because under D10 every green commit is a
   release: `release` runs `TestReleaseAction`, which fails unless the
   amd64 action is `Kill`. Until the soak lands, nothing is released and
   slice 1 is not done. No amendment to D22 is proposed. §9 says the
   same.
4. **The restart budget made emu crashes a remote kill of the shell**
   (major). *Fixed, as the review suggests.* When the budget is spent,
   the spawner sends proto a new `EmuPaused` message (0x06), pauses for
   `EmuCooldown` (60 s), then starts again with a fresh budget,
   repeating for as long as emu keeps failing. The shell, the pty and
   proto are never touched, and keystrokes still reach the pty, so the
   user can Ctrl-C the program that is feeding emu the crash. `Exit`
   code 4 (`EmuFailed`) is retired, and §2.4's teardown now names only
   the triggers that can end a session. The client gets a "screen
   unavailable" notice through §11 item 7. threat-model.md §4.11
   ("Supervision … then the session ends") still says the old thing and
   needs its owner to update it.
5. **Several reply tokens per message vs "exactly one reply"** (major).
   *Fixed, with the second option.* One reply per message would drop
   real answers: programs send several queries in one write, and tuios
   answers them all in one request. §4.1 now bounds the tokens proto
   passes on by what proto itself sent. A request's allowance is the
   number of CSI/OSC/DCS introducers (7-bit or C1) in its `Output` plus
   the one before it, so a query split across two requests still
   counts, and it is capped at `MaxReplyTokens` = 8. An `Output` with no
   introducer after one with none gets nothing. Tokens over the
   allowance are dropped and counted, not treated as violations, because
   an honest emu can exceed it. §12 replaces "two replies where one is
   expected" with allowance tests, plus a recorded-programs test that
   sets the cap's provenance. threat-model.md R9 and §4.11's "exactly
   one reply per message" need their owner to change to this bound.
   This spec cannot edit them.
6. See item 1.
7. See item 3.
8. **Unread keystrokes were bounded by neither spec** (major). *Fixed:
   server.md owns it* (§4.3). Keystrokes have no queue of their own.
   The writer takes one event at a time from `Since(applied)`, and
   `applied` advances only when the pty has taken the whole event, so
   at most `MaxKeyEvent` bytes are ever between the stream and the pty.
   A pty that does not drain holds `applied`, `InputConsumed` holds with
   it, and the client stops reading its terminal. With an honest client
   the stream stays about 112 KiB past `applied`, inside `RetainBytes`.
   A stalled program is therefore the bounded stall the flow control is
   designed for, not a bug. Only a client that ignores `InputConsumed`
   overruns, and then gets `ssp.ErrProtocol`. ssp.md §10.1 has since
   been revised to say the same: `applied` holds while a write blocks,
   and an overrun is the peer's fault, not a reported bug of ours. §12
   adds the test with a program that never reads stdin while the client
   types 1 MiB.
9. **Wrapping fds under the sandbox** (major). *Fixed.* The §6.1
   sentence is corrected: only `net.FilePacketConn` needs syscalls the
   policy lacks, so only the UDP socket must be wrapped before `Enter`.
   §3.6 now says exactly how each E is wrapped inside the sandbox:
   `recvmsg` with `MSG_CMSG_CLOEXEC`, `fcntl(F_GETFL)`, then
   `fcntl(F_SETFL, |O_NONBLOCK)`, then `os.NewFile`, which uses
   `epoll_ctl`, so the fd is pollable and T4's deadline works. Never
   `net.FileConn`. All of these are allowed by the new `fcntl` rule.
   §2.3 makes the pairs `SOCK_NONBLOCK` and keeps the spawner from ever
   calling `Fd()` on proto's end. Generation 1 uses the same path.
   `TestRestartUnderKill` covers a restart under `Enter(Proto, Kill)`.
10. **Rebuild behaviour contradicted screen.md §7.3** (major). *Fixed:
    aligned with screen.md.* The mirror resets to version 0 on every
    `EmuLink`, and each E's first `Update` is relative to version 0
    (§3.3, §3.6). Proto increments `Rebuilt.Seq` and maps the `EmuLink`
    reason, and for `KillEmu` its own reason, onto screen.md's codes
    1/2/3 (§3.6). §3.5's violation list now includes a non-zero
    `EchoOff`, `EchoAck` or `Rebuilt`, checked on a copy. The repaint is
    the single mechanism screen.md names, a size change and back, done
    by proto through its filtered `TIOCSWINSZ`. The spawner's bare
    `kill(-pgrp, SIGWINCH)` is gone, and with it `TIOCGPGRP` (§5.2,
    §10). §11 item 5 is replaced: `MaxDiff` is screen.md's 48 MiB, and
    proto's reassembly buffer is up to 64 MiB.
11. **Missing no-memory-bound rule, and OOM detection on the last
    line** (major). *Fixed, slightly differently from the suggested
    fix.* `RLIMIT_DATA` is now set by the spawner with `prlimit64` on
    the new emu before proto gets its E, not by emu on itself. If emu
    were the one to report that the limit could not be set, the report
    would be an exit code, which a compromised emu could forge to end
    the session (item 4). If `prlimit64` fails, that emu is killed
    before it reads anything. At generation 1 the session fails with a
    stated reason; later, it counts as a failed start (§6.3, §2.1 step
    4.5, §5.2). So mosey never runs an emu with no memory bound, and the
    rule is stricter than threat-model.md §4.8's "neither limit", since
    `RLIMIT_DATA` is always required. The OOM check now scans every
    stderr line of that generation for `fatal error: out of memory` (or
    `fatal error: runtime: out of memory`), not the last line. It is
    stated to be only a classification, because emu can forge it.
    threat-model.md §4.8's "set by emu on itself" needs its owner to
    change to "set by the spawner".
