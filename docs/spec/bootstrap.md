# Bootstrap: starting a session over SSH

Owner: **bootstrap-client**. Packages: `internal/bootstrap`, `internal/client`
(its bootstrap half), `cmd/mosey/main.go`. The server half of each step
lives in `internal/server` and is specified in `server.md`; this document
says what the server must do *as seen from the SSH channel*.

Decisions implemented here: D6 (start over SSH with the user's config), D7
(one binary, version check, auto-upload hook), D8 (resume hook), D20 (B3:
one-shot keys over stdin and stdout), D25 (agent bind capture hook), D26
(exclusive attach). They are locked; where this text and PLAN.md disagree,
PLAN.md wins and this file is the bug.

Provenance tags on constants: **[S1]**, **[S3]**, **[S4]** are our spikes'
measurements or choices (see `docs/spikes/<id>/FINDINGS.md`); **[ssh]** is
black-box behaviour of OpenSSH 10.6p1 or its man pages (`ssh(1)`,
`ssh_config(5)`, `PROTOCOL.agent`), checked on dan-desktop on 2026-11-14;
**[mosh-man]** is the Mosh man page; **[shells]** is black-box behaviour of
the shells named, checked on dan-desktop on 2026-11-14 (bash as `/bin/sh`,
tcsh 6.24.16, fish 4.7.1, nushell 0.112.2, zsh from nixpkgs); **[derived]**
is worked out here, with the working; **[choice]** is ours, untuned. No
Mosh source was consulted, and none may be.

Roles (D7, `server.md` §1): **launcher** is `mosey --serve`, the process
ssh starts; **spawner** is `mosey --serve=spawner`, the detached,
unsandboxed owner of the session; **proto** and **emu** are
`--serve=proto` and `--serve=emu`. Every one of them is the same `mosey`
file.

---

## 1. What the bootstrap is for

SSH does three jobs and then gets out of the way:

1. It authenticates the user to the host and the host to the user, with the
   user's own keys, agent, `known_hosts` and `~/.ssh/config` (D6).
2. It starts the server: `mosey --serve` on the far host.
3. It carries two lines: the client's one-shot X-Wing public key up stdin,
   and a credential down stdout (D20, B3).

B3 needs SSH to be **authentic, not confidential**: a recorder, `script(1)`
or a bastion log that captures both lines cannot use them to impersonate
either side ([S1] §5, ProVerif `b3_stdout_leak`,
`TestB3LeakedStdoutCannotImpersonate`). Nothing in either line is secret in
the sense that matters. The PSK is in the clear on purpose: it is defence in
depth and the key of the msg1 DoS filter, not an authenticator.

After the credential line, ssh exits. The session lives on in the detached
server; nothing about it depends on the SSH connection again until a resume
(§9).

```
client                         ssh / sshd                         far host
------                         ----------                         --------
key := NewOneShotKey()
ssh -G ...                (local only: resolve config)
spawn ssh ... DEST "exec /bin/sh -c 'exec mosey --serve'"
write ClientLine, close stdin ────────────────────────────────►  launcher reads stdin to EOF
                                                                  check line, version
forward ssh stderr (filtered)  ◄── prompts, banners, errors ──    launcher starts spawner (setsid);
                                                                  spawner: UDP, pty, emu, proto
                                                                  proto mints credential;
                                                                  spawner checks it, starts shell
read stdout up to the line    ◄──────────── MOSEY-CONNECT ...     launcher prints it, exits 0
                                   ssh exits
check addr (§7.2)
transport.Dial(addr:port) ════════ UDP msg1/msg2/confirm ═══════► proto
                                   (no confirm in 30 s: session ends, §4.5)
enter raw mode, run Session
```

---

## 2. The command line the client accepts

```
mosey [-remote PATH] [-upload ask|yes|no] [-ssh PROGRAM] [-A | -a] [-r | -r=SESSION | -list] [-- SSH-OPTION...] DESTINATION
```

- `DESTINATION` is passed to ssh unchanged: `host`, `user@host`, an alias
  from `~/.ssh/config`, or `ssh://user@host:port`. It must be non-empty, at
  most 1024 bytes, must not start with `-`, and must not contain bytes below
  0x21 or 0x7F (ssh would read a space as the start of the command). Anything
  else is a usage error (exit 2).
- `-remote PATH` is the remote mosey binary (§4.2). Without it the client
  looks for its own version and copies it over if it is missing (D7,
  §4.7).
- `-upload ask|yes|no` is what to do when the far host has no mosey of
  this version (§4.7.5). Default `ask`. Any other value is a usage error.
- `-ssh PROGRAM` is the local ssh. Default `ssh`, found on `PATH`. Tests
  point it at a fake (§12).
- `-A` and `-a` are ssh's own flags (D25): force agent forwarding on or off.
  They may be given as mosey flags or among the SSH options; the last one
  given wins, as in ssh ([ssh]: `ssh -A -a` resolves to `forwardagent no`,
  `ssh -a -A` to `yes`).
- `-r` resumes the user's one session on DESTINATION; `-r=SESSION`
  resumes that one, named by its 32 hex digits; `-list` lists the
  sessions there and exits (§9.2, §9.4). They exclude each other.
- `SSH-OPTION`s after `--` are filtered (§2.1) and passed to both ssh
  invocations.

Every plain word belongs to the client (D7): `mosey server` connects to a
host called `server`. Server mode is only ever the flag `--serve` as
`os.Args[1]`.

### 2.1 Which ssh options pass through

The SSH options are parsed with ssh's getopt rules: clusters (`-4vC`),
attached arguments (`-p2222`, `-oUser=x`) and separate ones (`-p 2222`). The
parser emits them normalised: one flag per argument, and each argument-taking
option as two arguments (`-p`, `2222`).

| Kind | Letters | What happens |
|---|---|---|
| Flags passed through | `4 6 C K k q v x` | to `ssh -G` and the bootstrap ssh |
| Options with an argument, passed through | `B b c E F I i J l m o P p` | same |
| Consumed by mosey | `A a` | decide agent forwarding (§5); passed to `ssh -G` only, never to the bootstrap ssh |
| Everything else | e.g. `t T N n f s G V O W M S L R D X Y g e w Q y` | refused: `mosey: ssh option -X can't be used for the bootstrap`, exit 2 |

Why refuse rather than ignore: each refused option either breaks the
two-line protocol (`-t` gives a pty that echoes and turns LF into CRLF; `-n`
and `-f` take stdin away; `-N`, `-s`, `-W`, `-G`, `-O` run no command) or
does nothing useful for a session that ssh leaves after a second (`-L`,
`-R`, `-D`, `-X`, `-M`, `-S`). Saying so is kinder than a session that
silently lacks the forward the user asked for. A bare word or a second `--`
among the SSH options is a usage error. An option missing its argument is a
usage error.

`-A`, `-T` and `-t` must be filtered by mosey, not overridden with `-o`:
[ssh] the flags win over any `-o` whatever the order (`ssh -o
ForwardAgent=no -A` and `ssh -A -o ForwardAgent=no` both resolve to
`forwardagent yes`; `-t -o RequestTTY=no` resolves to `requesttty true`).

---

## 3. Resolving the user's config: `ssh -G`

Before the bootstrap the client runs, with no stdin and a 10 s deadline
[choice]:

```
PROGRAM -G USER-OPTIONS... [-A|-a] -- DESTINATION
```

`USER-OPTIONS` are the filtered options of §2.1, and the agent flag is the
last of `-A`/`-a` the user gave, if any. Its stdout is read up to 256 KiB
[choice; a typical config prints about 3 KiB]; more is an error. Each line is
`keyword SP value`; keywords are lower case [ssh]. A keyword may repeat
(`identityfile`, `sendenv`); the client keeps every value in order. A
non-zero exit is fatal and the client prints ssh's stderr (filtered as in
§6.5): it is how a typo in `~/.ssh/config` or a bad `-o` surfaces ([ssh]:
`-o Bogus=1` exits 255 with `Bad configuration option: bogus`).

`ssh -G` makes no connection. It may run `Match exec` commands, which ssh
will run again for the real connection; that is the user's config doing what
it says.

The client uses these keywords:

| Keyword | Used for | Slice |
|---|---|---|
| `forwardagent` | the agent decision (§5) | value computed and logged in 1; acted on in the agent slice |
| `identityagent` | which socket `ForwardAgent yes` forwards (§5) | agent slice |
| `hostname`, `port`, `hostkeyalias`, `userknownhostsfile`, `globalknownhostsfile` | pinning a captured bind to `known_hosts` (§8) | agent slice |
| `hostname` | UDP address fallback (§7.2) | 1 |
| `proxyjump`, `proxycommand` | the note that UDP does not follow a proxy (§7.2) | 1 |
| `sessiontype`, `stdinnull`, `forkafterauthentication` | whether this ssh knows these keywords, so the bootstrap may force them (§4.1) | 1 |

`ssh -G` prints `sessiontype`, `stdinnull` and `forkafterauthentication`
whenever the ssh supports them (OpenSSH 8.7 and later) [ssh]. Their presence
is the client's feature test: no version string parsing.

The parsed result is a value type (`bootstrap.Config`) so that tests build it
by hand.

---

## 4. Starting the server

### 4.1 The ssh command

```
PROGRAM -T
        -o ControlMaster=no -o ControlPath=none -o ControlPersist=no
        -o ForwardAgent=no                     (agent slice: =CAPTURE-SOCKET)
        -o ForwardX11=no -o ClearAllForwardings=yes -o Tunnel=no
        -o PermitLocalCommand=no -o EscapeChar=none
        -o RemoteCommand=none
        [-o SessionType=default -o StdinNull=no -o ForkAfterAuthentication=no]
        USER-OPTIONS...
        -- DESTINATION "exec /bin/sh -c 'exec SERVER --serve'"
```

(`--serve=list` in place of `--serve` for `mosey -list`, §9.4; with no
`-remote`, the script is §4.7.2's probe, which runs the same flag.)

- **Ours come first, so ours win.** For `-o` the first value obtained is
  used, and command-line options are read before any config file [ssh;
  `ssh_config(5)`; checked: `-o ControlMaster=no -o ControlMaster=auto`
  resolves to `controlmaster false`]. The user's `-o` and config cannot undo
  them; the flags that could (`-A`, `-t`) never reach this ssh (§2.1).
- **`ControlMaster=no`, `ControlPath=none`, `ControlPersist=no`.** Always a
  fresh connection. A multiplexed session has no key exchange of its own, so
  there is no session-bind to capture, and the agent trigger would reach the
  master's agent, not the capture socket ([S3] E12, E12b). Cost: about
  108 ms on loopback, once per start or resume ([S3]: mux 9.8 ms, fresh
  117.8 ms median, n=10).
- **`-T`.** No pty: the bootstrap is two lines of protocol, and a pty would
  echo stdin and rewrite LF as CRLF. The flag form is used because it beats
  a config `RequestTTY force` [ssh].
- **`ForwardAgent=no`** in slice 1. The agent slice replaces `no` with the
  capture socket path (§8). Never the user's real agent: the bootstrap's
  agent channel exists only to make ssh send its bind.
- **`ForwardX11=no`, `ClearAllForwardings=yes`, `Tunnel=no`.** A config
  `LocalForward` would collide with the user's interactive ssh to the same
  host, and an `ExitOnForwardFailure` would then kill the bootstrap; X11
  and tun forwarding would give the far host a way back to the client
  (threat-model §4.9, which requires all three).
- **`PermitLocalCommand=no`, `EscapeChar=none`.** A config `LocalCommand`
  must not run or write to our terminal; no escape processing on a pipe.
- **`RemoteCommand=none`.** A config `RemoteCommand` together with a
  command on the line is an error in ssh; `none` clears it [ssh: with
  `-o RemoteCommand=none`, `ssh -G` prints no `remotecommand`]. Needs
  OpenSSH 7.6 or later; an older ssh fails with `Bad configuration option`,
  which the client reports.
- **`SessionType`, `StdinNull`, `ForkAfterAuthentication`** are added only
  when `ssh -G` showed the ssh knows them (§3): a config `SessionType none`
  or `StdinNull yes` would otherwise break the bootstrap, and an older ssh
  rejects the unknown keyword.
- **`--`** ends ssh's options, so a destination can never be read as one
  (it is also checked in §2).

The remote command is **one argument**, `exec /bin/sh -c 'exec SERVER
--serve'`. sshd hands it to the user's login shell with `-c`, so it is
shell text.

**Why the `/bin/sh` wrapper.** The client spots a missing server by its
exit status (§4.2), and only a POSIX shell gives a fixed one. Run directly,
a missing command exits 127 under sh, bash and fish, but **1** under tcsh
(`Command not found.`) and nushell (`nu::shell::external_command`), and a
non-executable file exits 1 under tcsh [shells]. Through the wrapper all of
them exit 127 for a missing file and 126 for one that will not run, because
the status is `/bin/sh`'s [shells: checked under bash, tcsh, fish, nushell
and zsh]. The outer `exec` keeps the user's shell out of the process tree;
the inner `exec` makes the launcher the process sshd waits for. The cost is
one `/bin/sh` exec, about a millisecond. A host with no `/bin/sh` is not a
host mosey supports.

To make quoting unnecessary in every outer shell (sh, bash, zsh, fish, csh,
nu: each takes `'…'` as a literal and `exec` as a builtin [shells]), and so
that the text inside the single quotes needs no quoting for `/bin/sh`
either, `SERVER` is restricted:

```
server = [ "~/" ] 1*pathchar          ; at most 256 bytes
pathchar = ALPHA / DIGIT / "." / "_" / "/" / "+" / "-"
```

and must not start with `-`. A `-remote` outside this is a usage error. The
leading `~/` is left for the remote `/bin/sh` to expand (it is the start of
a word in its script, and the outer shell sees it only inside quotes),
which is what D7's `~/.cache/mosey/<version>/mosey` needs [shells: checked
under each outer shell above]. `--serve` must be the binary's first
argument: `cmd/mosey` tests only `os.Args[1]`.

### 4.2 Where the server binary comes from

Two ways, chosen by whether the user named one:

- **`-remote PATH` given.** That file and nothing else, run with the
  §4.1 command exactly as slice 1 had it. No probe, no upload: the user
  has said where mosey is. A missing or unrunnable file is reported from
  `/bin/sh`'s exit status: 127 for a command it cannot find and 126 for one
  it cannot run (POSIX), which the §4.1 wrapper makes hold whatever the
  user's login shell is [shells]. ssh exits with the remote command's
  status, and the client reports 126 or 127 with no protocol line as
  `ErrNoServer` (§10). A launcher never exits 126 or 127 itself (its
  failures are exit 1, §4.4), so the two cannot be confused. A server of
  another version refuses with `MOSEY-ERROR ... version` (§6.4), and the
  client says so.
- **No `-remote` (the default): D7.** The remote command becomes §4.7's
  probe, which runs `~/.cache/mosey/<V>/mosey` or `mosey` on the remote
  `PATH`, whichever says it is this client's version `V`, and otherwise
  prints the remote's platform; the client then copies a matching build
  over, with the user's consent, and starts again once (§4.7). The two
  lines of §6 do not change. `mosey --serve=version`, reserved in slice 1,
  is what the probe asks each candidate.

### 4.3 The client's process handling

- **No core dumps.** Before the one-shot X-Wing key exists, and so before
  anything else holds a secret, the client makes itself leave no core
  and unreadable by the user's other processes (`internal/nocore`,
  `threat-model.md` §4.10): on Linux `prctl(PR_SET_DUMPABLE, 0)` and
  `RLIMIT_CORE` 0, on darwin `RLIMIT_CORE` 0. The client holds the PSK,
  the transport keys and the roots for the whole session, and a core of
  it would undo forward secrecy (D8). ssh inherits the rlimit, which costs
  it nothing; `execve` resets `DUMPABLE` for it. If either call fails the
  client stops before it starts ssh.
- **ssh's stdin** is a pipe. The client writes the ClientLine in one write
  as soon as ssh has started (before authentication: the line is at most
  4 KiB and a pipe holds 64 KiB, so the write cannot block), then closes it.
  ssh delivers the line and then EOF to the remote command.
- **ssh's stdout** is a pipe read by `ReadCredential` (§6.5). Never shown.
- **ssh's stderr** is a pipe the client copies to its own stderr through the
  filter of §6.5 until the credential line arrives. After the line it still
  passes through the same filter, and then goes only to the client's log
  file (§7.4), never to the terminal, which is about to be in raw mode
  under the session's screen. It is not inherited: ssh relays the remote's stderr and the server's
  banner, and D9 says no remote escape sequence reaches the local terminal.
  ssh's prompts (passwords, passphrases, host-key confirmation) are not on
  stderr; ssh opens `/dev/tty` for them, which is why they still work.
- **The local terminal stays cooked** until `transport.Dial` has succeeded
  (§7.3). ssh's password prompt reads a line from `/dev/tty`; in raw mode
  Enter sends CR, not LF, and the prompt never ends.
- **Signals.** Until raw mode, Ctrl-C is a SIGINT to the foreground process
  group, which is both mosey and ssh, and mosey dies with its defaults:
  nothing *local* needs restoring yet. SIGTERM and SIGHUP cancel the
  context, which kills ssh (`exec.CommandContext`). The far side may by
  then have started a session; the client does nothing about it, because
  §4.5 guarantees a session nobody connects to ends by itself.
- **After the line**, ssh should exit within a round trip (the launcher has
  exited and closed its fds, §4.4). The client does not wait for it before
  dialling. It reaps ssh in the background: if ssh has not exited 10 s after
  the line [S3: the capture deadline], SIGTERM, then SIGKILL 1 s later. A
  non-zero exit after a valid line is logged, not fatal. The agent slice
  must wait for ssh's exit before reading the capture result (§8), but not
  before dialling.

### 4.4 The server's side, as SSH sees it

What happens on the far host, in order, and which role does it. The
messages between launcher and spawner are `server.md` §2.1 and §3.3
(`ClientLine` 0x40, `Ready` 0x41, `Failed` 0x42, on the socketpair B);
the timeouts T1–T3 are `server.md` §8.

1. **Launcher.** Read stdin **to EOF**, at most 4097 bytes, within T1 =
   30 s [derived: `handshake.CredentialTTL`; the client writes the line
   before authentication, so it is there when the command starts]. Stdin
   must be exactly one ClientLine: one LF, at the end, then EOF. Anything
   else is `MOSEY-ERROR ... line`.
2. **Launcher.** Parse it (§6.2). Check the protocol version, then the
   software version (§6.4). Check the reserved fields (§6.2: `attach`,
   `agent`). Then start the spawner, `mosey --serve=spawner`, as a new
   process with `Setsid`, stdio on `/dev/null` and B as fd 3, send it
   `ClientLine` (0x40), and wait up to T2 = 15 s for `Ready` or `Failed`.
3. **Spawner** (`server.md` §2.1 step 4). Parse the line again, bind UDP,
   open the pty at the line's size (clamped by `screen.ClampSize`), start
   emu and proto, and have proto mint a credential (D20: TTL 30 s, at most
   2 unused per session). Proto returns it as `Credential` (0x30), within
   T3 = 10 s [choice]. **The spawner checks every field it owns**: the
   line must parse (`ParseCredentialLine`), re-marshal to the same bytes,
   and carry exactly the spawner's own advertised `addr` (or `-`), its own
   bound `port` and its own `swver` (`server.md` §3.4). Proto chooses only
   `credid`, `sessionid`, `psk` and `public`, the four things it alone
   knows; a compromised or buggy proto cannot choose where the client
   sends UDP or what version it claims. Only then does the spawner start
   the login shell with the line's environment (§6.2), and send `Ready`
   (0x41) with the line.
4. **Launcher.** Write the line from `Ready` to stdout in **one** write.
5. **Launcher. Detach.** No process of the session may keep fds 0, 1 or 2
   of the SSH session open, and the process ssh started must **exit 0**.
   sshd sends the exit status and closes the channel only when the command
   has exited, so a session process that merely closed its stdio would hold
   ssh open. The process sshd started is usually a session leader already
   (sshd makes the login shell one, and the shells `exec` down to the
   launcher, §4.1), so it cannot `setsid` itself: that is why the spawner
   is a separate process started with `Setsid` in step 2 ([S4] §3.10 did
   this with `setsid -f`; [S3]'s `moseys` with `SysProcAttr{Setsid: true}`
   and a pipe for the line). See open question 5.
6. **Launcher.** Before it exits, human-readable errors go to stderr,
   prefixed `mosey --serve: `, and are what the user reads. The spawner
   never writes to ssh's pipes; it logs to its session log (`server.md`
   §6.4).

On any failure in steps 1 to 3: one line on stderr saying what, one
`MOSEY-ERROR` line on stdout, exit 1, and nothing left running (the
launcher SIGKILLs a spawner that has not sent `Ready`, `server.md` §2.1
step 3). If step 4's write fails (ssh has gone: `EPIPE`), the launcher
sends SIGTERM to the spawner, which tears the session down (`server.md`
§2.4), and exits 1.

**Bind address.** The spawner binds UDP in 60000–61000 [mosh-man: the
documented range, so firewall rules written for Mosh admit mosey] on the
server address from `SSH_CONNECTION` when there is one, so replies leave
from the address the client is sending to on a multi-homed host, and on the
wildcard address otherwise (`server.md` §2.2). **Requirement on
`server.md` §2.2:** when that address is loopback, the spawner advertises it
but binds the wildcard, as it already does for link-local. SSH reached over
a local forward or tunnel shows a loopback `SSH_CONNECTION`, the client then
falls back to `hostname` (§7.2), and a socket bound to 127.0.0.1 would never
see its packets. Likewise the spawner advertises `-`, never an address the
client must refuse (§6.3: unspecified, multicast, limited broadcast).

### 4.5 A session nobody connects to

**Requirement.** A `new` session whose credentials all expire
unconfirmed ends by itself: once every credential proto minted for it has
passed `handshake.CredentialTTL` (30 s, D20) without a confirmed
transport, proto sends `Exit{NoClient}` and the spawner runs its teardown
(`server.md` §2.4: close C, hang up the pty so the shell gets SIGHUP,
SIGKILL the shell's pid, proto and emu after their grace periods, exit).
So a bootstrap that never finishes (UDP blocked, Ctrl-C after the line,
the client crashing, the launcher's write failing) leaves nothing running
for longer than about 30 s plus the teardown's grace periods.

**Requirement on `server.md`** (a backstop, not yet there): the spawner
also ends the session if proto has not told it of a first confirmation
within CredentialTTL + 10 s [choice: a margin for the teardown and clock
granularity] of `Ready`. This needs one more proto → spawner message
(`Attached`, no payload); without it, a proto that hangs before
confirmation holds a shell forever. Until server.md adds it, proto's
`NoClient` is the only rule, and it is the one the e2e test of §12 checks.

The shell is still started *before* the first confirmation, at step 3,
on purpose: its start-up (rc files, often hundreds of milliseconds)
overlaps the client's handshake. Starting it later would not protect
anything: the user's rc files have already run once for the same SSH login,
since sshd ran `SHELL -c` to start the launcher (§6.5 exists because rc
files print), and that login is the user. See the review notes (§15).

**Environment for the shell.** sshd's `SSH_AUTH_SOCK` (if any) dies with
the bootstrap connection, so the spawner never passes it to the shell; the
agent slice gives the shell mosey's own socket instead. Other session
variables are `server.md`'s concern.

**Known hazard (not ours to fix in slice 1).** With systemd-logind's
`KillUserProcesses=yes` the detached session is killed when the SSH login
ends, as Mosh's server is. [S4] §3.10 ran it under `systemd-run --user`,
which survives; adopting that is a later decision (open question 8).

### 4.6 Release assets: the files D7's upload sends

D7 sends the client's own file when the remote runs the client's OS and
architecture. When it does not (a Mac client, a Linux server), the client
fetches the release of **its own version** for the remote's platform. That
needs the file's name to be computable from three things the client
already knows, so it is fixed here, and `ci.yml`'s release job produces
exactly this [choice]:

- **Where.** Every release is a GitHub Release on
  `github.com/danielbodart/mosey`, made by CI from a green trunk commit
  (D10), tagged `v<V>`, where `V` is `scripts/version.sh`'s
  `MAJOR.COMMITS.RUN` and is byte-for-byte what `mosey -version` prints for
  every binary in it: each is stamped from `scripts/version.sh` run on the
  same commit in the same CI run. Before publishing, the release job runs
  the linux/amd64 binary and checks it prints `V`, and checks that each
  of the others, which it cannot run, contains `V`'s bytes.
- **The binaries.** One asset per platform, named
  `mosey-<V>-<os>-<arch>`, with `os` ∈ {`linux`, `darwin`} and `arch` ∈
  {`amd64`, `arm64`}: Go's `GOOS` and `GOARCH` names, so the client's own
  is `runtime.GOOS` and `runtime.GOARCH`. Each is the bare static
  executable `scripts/build.sh` made (CGO off, `-trimpath`, linux with
  `GOEXPERIMENT=runtimesecret`, D1, D20), not an archive.
- **The checksums.** One asset named `SHA256SUMS`, in `sha256sum(1)`'s
  text format: per binary, 64 lower-case hex digits, two spaces, the
  asset's name, a newline, sorted by name.
- **So** the binary for `os/arch` at version `V` is
  `https://github.com/danielbodart/mosey/releases/download/v<V>/mosey-<V>-<os>-<arch>`
  and its hash is the line of
  `https://github.com/danielbodart/mosey/releases/download/v<V>/SHA256SUMS`
  whose second field is that name.

Why bare files: the hash in `SHA256SUMS` is then the hash of the very
bytes the client sends and the remote installs at
`~/.cache/mosey/<V>/mosey`, so one hash is checked on download, after the
copy, and against a file already there; and the client needs no archive
parser for a file from the network [derived]. Why the version in the name:
a downloaded file says what it is, and two versions can sit in one
directory without one overwriting the other.

Mapping the remote's `uname -s` and `uname -m` to `os` and `arch`
(`Linux` → `linux`, `Darwin` → `darwin`, `x86_64` → `amd64`, `aarch64`
and `arm64` → `arm64`; anything else has no asset) is the auto-upload
slice's, as is the download itself. `SHA256SUMS` comes over HTTPS from
the same release, so it catches corruption and a wrong file, not a
compromised GitHub account or CI; whether releases are also signed is
§14 question C. A client of a development build (`dev`, or a local
build's timestamp patch) has no release, so it can upload only itself.

### 4.7 Auto-upload (D7)

D7: if the far host has no mosey of the client's version, the client copies
over a matching static build, hash-checked, installed to
`~/.cache/mosey/<V>/mosey`, asking the first time, and never replacing a file
someone else owns. `V` is the client's own version, exactly as it sends it in
`swver` (§6.2). This section is the whole of it; nothing here changes the two
lines of §6 or what a server does once it is running.

```
client                                                     far host
------                                                     --------
ssh … "PROBE"   + ClientLine  ──────────────────────────►  ~/.cache/mosey/V/mosey --serve=version = V ?  exec it --serve
                                                           mosey --serve=version = V ?                  exec it --serve
                              ◄──────── MOSEY-PROBE 1 Linux x86_64      (neither: say what this host is)
ask the user (first time per host)
pick the binary: our own file, or the release asset, SHA-256 checked
ssh … "UPLOAD"  + the binary  ──────────────────────────►  mktemp in ~/.cache/mosey; cat; run it as
                                                           --serve=install V HASH SIZE TEMP: checks, hash, rename
                              ◄──────── exit 0
ssh … "PROBE"   + ClientLine  ──────────────────────────►  ~/.cache/mosey/V/mosey --serve   (as §4.4)
```

#### 4.7.1 When it applies

Only when the user gave no `-remote` (§4.2), and only if `V` can name a
directory: a valid `swver` (§6.1) other than `.` and `..`. Every `swver`
byte is a `pathchar` (§4.1), so `~/.cache/mosey/V/mosey` needs no quoting
anywhere. A version that cannot (none that `scripts/version.sh` or the
flake makes) runs slice 1's `mosey --serve`, with no probe and no upload,
and the log says why.

**The probe and the roles.** Every command that runs a server role probes:
`mosey DEST` (the launcher, `--serve`), `mosey -r DEST` (the launcher
again, with a resume ClientLine) and `mosey -list DEST` (`--serve=list`,
§9.4). The probe runs the matching binary with that command's flag, so a
host whose only mosey is the one D7 put in `~/.cache/mosey/V/` is found by
all three. **Only `mosey DEST` uploads.** When the probe answers
`MOSEY-PROBE`:

| Command | What the client does |
|---|---|
| `mosey DEST` | §4.7.3–§4.7.8: ask, copy, start again |
| `mosey -r DEST`, `mosey -r=SID DEST` | nothing is copied: `mosey: no mosey V on DEST, so no session of it to resume: a session started by another version is resumed with that version's mosey`, exit 1. A session runs the version that started it (§9.2 step 5), so a copy of `V` could never serve a session that `V` did not start, and a host with no `V` has no session of `V`. |
| `mosey -list DEST` | nothing is copied: `mosey: no mosey V on DEST, so no sessions of it: mosey DEST starts one, copying mosey there`, exit 1. Listing is not a reason to install anything. |

Sessions of an older version on a host that has none of `V` are listed and
resumed by that version's client, as §9.2 step 5 already says for a host
that has both.

`~/.cache` is literal: the remote's `XDG_CACHE_HOME` is not consulted. The
probe, the upload and the installer must agree on one path without a round
trip to ask, and D7 names this one.

#### 4.7.2 The probe

The remote command (one argument, as §4.1, `V` substituted):

```
exec /bin/sh -c 'v=V; for m in "$HOME/.cache/mosey/$v/mosey" mosey; do if [ "$("$m" --serve=version </dev/null 2>/dev/null)" = "$v" ]; then exec "$m" FLAG; fi; done; s=$(uname -s 2>/dev/null); a=$(uname -m 2>/dev/null); echo "MOSEY-PROBE 1 ${s:-unknown} ${a:-unknown}"'
```

- **The cache first**, then `mosey` on the remote `PATH`. Each candidate is
  asked its version by running `--serve=version` (server.md §1), with stdin
  on `/dev/null` (the ClientLine waiting on stdin is for the launcher, and
  a program that is not mosey must not eat it) and stderr dropped (`sh:
  mosey: not found` is the normal case). The first that prints exactly `V`
  is exec'd with `FLAG`, the command's own (§4.7.1: `--serve` for the
  launcher, which reads the ClientLine as in §4.4, or `--serve=list`). A file
  in the cache is asked too rather than trusted for its path: it may be a
  half-written copy from a crashed upload, or another build of the same
  version string (two `dev` builds).
- **Neither:** one `MOSEY-PROBE` line on stdout, then exit 0. The probe
  never exits 126 or 127, so `ErrNoServer` from an exit status means only
  what it meant in slice 1.
- **Quoting.** The text inside the single quotes has no `'`, no `\` (fish
  reads `\'` and `\\` inside single quotes), no `!` and no newline (csh
  refuses a newline inside quotes), so every login shell of §4.1 passes it
  to `/bin/sh` unchanged [shells: run under each in §12's test].
- **Cost.** In the everyday case one exec of `/bin/sh` and one or two of
  `mosey --serve=version` (a Go binary's start, a few milliseconds) on top
  of slice 1's command; no extra round trip.

**The probe line**, read by `ReadCredential` (§6.5) like the other lines of
ours and fuzzed with them:

```
probe-line = "MOSEY-PROBE" SP proto SP sysname SP machine LF
proto      = decimal                 ; must be Version
sysname    = 1*64(%x21-7E)           ; uname -s, or "unknown"
machine    = 1*64(%x21-7E)           ; uname -m, or "unknown"
```

At most 148 bytes [derived: 11 + 1 + 5 + 1 + 64 + 1 + 64 + LF];
**`MaxProbeLine` = 160**. Canonical as §6.1 asks. `ReadCredential` returns
it as a `*NoServerError` (`errors.Is(err, ErrNoServer)`) carrying the two
fields. A `uname` that prints a space or something longer gives a line that
does not parse, which is `ErrBadLine`: a host that odd has no release asset
anyway.

The far side chooses these fields, and a hostile one can claim any
platform. All it gains is which public build the client sends it.

#### 4.7.3 The remote's platform

| `uname -s` | os | | `uname -m` | arch |
|---|---|---|---|---|
| `Linux` | `linux` | | `x86_64`, `amd64` | `amd64` |
| `Darwin` | `darwin` | | `aarch64`, `arm64` | `arm64` |

Exact, case-sensitive matches [derived from uname(1) on Linux and macOS].
Anything else: `mosey: DEST is SYSNAME MACHINE, which mosey has no build
for`. A `darwin` remote, though there is a darwin build, is refused with
`mosey: the mosey server runs on Linux only for now, and DEST is Darwin`:
the server's roles return `ErrUnsupported` there (D22, `server.md`), so
copying 10 MB over to be told so would waste the user's time. That check
goes when a macOS server lands.

#### 4.7.4 Which file is sent

- **Same os and arch as the client:** the client's own file, the very bytes
  it is running (D7: "the copy sent over is the very file the client
  runs"). On Linux it is read through `/proc/self/exe`, which is the running
  image even if a package upgrade has replaced the path since; elsewhere
  through `os.Executable`. A non-dumpable process may open its own
  `/proc/self/exe` (the kernel lets a process inspect itself), so §4.3's
  `PR_SET_DUMPABLE 0` does not get in the way. Read whole, at most
  `MaxBinary` = 128 MiB [choice; a release is about 10 MB], and hashed as
  read. No network.
- **Otherwise:** the release asset of §4.6 for **exactly `V`** and the
  remote's os/arch. Only a release version has one: `V` must match
  `MAJOR.MINOR.PATCH` with each part a decimal of at most 9 digits, no
  leading zero, and `PATCH` ≥ 1 (CI's run number) [derived from
  `scripts/version.sh`: a local build's patch is a 14-digit timestamp, the
  flake's version says `unstable`, a plain `go build` says `dev`]. Anything
  else is a development build: `mosey: this is a development build (V) and
  DEST is OS/ARCH, which it cannot copy itself to: build mosey for OS/ARCH
  and pass -remote, or put it at ~/.cache/mosey/V/mosey there`.

  The download: `SHA256SUMS` first, then the binary, both from
  `https://github.com/danielbodart/mosey/releases/download/v<V>/`. HTTPS
  only, redirects included (a redirect to anything but `https` is
  refused); GitHub redirects release downloads to its object store. The
  whole fetch has a deadline of 5 minutes [choice: 10 MB at 300 kbit/s].
  `SHA256SUMS` is read up to 64 KiB, the binary up to `MaxBinary`; more is
  an error. `SHA256SUMS` is parsed strictly (`ParseSums`, fuzzed): every
  line exactly 64 lower-case hex digits, two spaces, a name of
  1 to 256 `pathchar`s other than `/`, LF; a name at most once; the asset's name must be there.
  The binary's SHA-256 must equal that line's, and its length must be
  non-zero, **before** anything is sent to the far host. A 404 on either
  file: `mosey: there is no release vV on GitHub to fetch mosey for
  OS/ARCH from`. Any other failure, offline included: `mosey: fetching
  mosey V for OS/ARCH from GITHUB-URL: ERR`, followed by the same advice as
  for a development build. Nothing is cached locally; a second host of the
  same platform downloads again (§14 question D).

  What this proves: the bytes are the ones the release lists, so
  corruption and a wrong file are caught. It does not prove that CI made
  them (§4.6, §14 question C).

The SHA-256 of what is sent, and its length, go to the far host on the
upload's command line (§4.7.6), and the installer refuses anything else.

#### 4.7.5 Consent

`-upload` says what happens when the probe finds nothing:

| `-upload` | |
|---|---|
| `ask` (default) | if this host is remembered, go on; else ask; `y` or `yes` (any case) goes on and remembers the host; anything else, or end of input, is no |
| `yes` | go on without asking; remember nothing |
| `no` | never copy: `mosey: DEST has no mosey V: install it there, or run without -upload=no` |

**The question**, on stderr while the terminal is still cooked (§4.3),
after the probe's ssh has exited, so no ssh is reading `/dev/tty`:

```
mosey: DEST has no mosey V. Copy this one (OS/ARCH, N.N MB) to ~/.cache/mosey/V/ there? [y/N] 
mosey: DEST has no mosey V. Download mosey V for OS/ARCH from GitHub and copy it to ~/.cache/mosey/V/ there? [y/N] 
```

(the first for the client's own platform, the second for another, which is
asked before anything is downloaded), and the answer is one line read from the terminal, at most 64 bytes
counted. Every field in it is the client's own (the destination as typed,
its version, the platform mapped through §4.7.3), never a remote string.

**The first time** is per `user@hostname:port` as `ssh -G` resolved them
(§3; `user`, `hostname` and `port`), so an alias and its target are one
host, and two accounts on one host are two. Not per version: under D10
every commit is a release, and a question at each upgrade would teach
people to type `y` without reading. A remembered host is a line in
`$XDG_STATE_HOME/mosey/upload-hosts` (else `~/.local/state/mosey/`),
beside the log (§7.4): the file is 0600 in a 0700 directory, at most
1 MiB, one key per line, rewritten whole through a temporary file and a
rename. A key holds only bytes 0x21–0x7E and is at most 1100 bytes; a
host whose key cannot be written is asked each time. Failing to read or
write the file is logged, and the host is asked again next time; it never
stops a session. The state directory, not the config one: the client
writes it, and a home-manager user's `~/.config` may be read-only.

The prompt goes through an interface (`client.Options.Ask`) so tests
answer it. `cmd/mosey` reads the answer from the terminal it already
requires (§4.3: stdin and stdout must be one).

#### 4.7.6 The upload

The same ssh as §4.1, every option the same (one fresh connection, nothing
forwarded), with this remote command (`V`, `HASH` as 64 lower-case hex
digits, `SIZE` in decimal):

```
exec /bin/sh -c 'umask 077; d="$HOME/.cache/mosey"; mkdir -p "$d" || exit 1; t=$(mktemp "$d/.upload.XXXXXXXX") || exit 1; cat >"$t" && chmod 700 "$t" && "$t" --serve=install V HASH SIZE "$t"; s=$?; rm -f "$t"; exit $s'
```

- **stdin is the binary**, written whole and then closed; nothing else.
  ssh's stdout is drained (at most 64 KiB, then discarded: rc files
  print). ssh's stderr goes to the user through §6.5's filter, which is
  how the installer's refusals are read.
- **`umask 077`**: every directory and file the shell makes is the user's
  alone. **`mktemp`** creates the file with `O_EXCL`, so the shell never
  writes through a name someone planted [mktemp(1): GNU coreutils,
  busybox and macOS all create mode 0600 with `O_EXCL`]. The temporary file
  sits in `~/.cache/mosey`, not `/tmp`: `/tmp` is often `noexec`, and the
  rename into place must stay on one filesystem.
- **The copy installs itself.** The shell runs the uploaded file as
  `--serve=install` (§4.7.7). Running it proves it runs on that host, and
  the checks are Go's, not whatever `sha256sum` or `shasum` the host has
  (macOS has no `sha256sum`). A copy cut short in transit does not start
  (its ELF segments run past the end of the file) and so installs nothing;
  one that starts hashes its own file through the descriptor it checks,
  and refuses any byte that differs.
- **`rm -f "$t"`** after the installer, whatever it said: after a success
  the name is gone already (renamed), after anything else the partial
  file goes. `exit $s` passes the installer's status to ssh.

ssh's exit status:

| Status | Meaning | Client says (exit 1) |
|---|---|---|
| 0 | installed | `mosey: copied mosey V to DEST` and goes on (§4.7.8) |
| 126 | the copy would not run | `mosey: the copy of mosey would not run on DEST: is ~/.cache on a filesystem mounted noexec?` |
| 255 | ssh failed | `mosey: ssh to DEST failed` |
| other | refused or failed; stderr has said why | `mosey: copying mosey to DEST failed (exit N; see above)` |

#### 4.7.7 The installer: `mosey --serve=install V HASH SIZE TEMP`

A server role (`server.md` §1) that runs once, from the uploaded file, and
is the only code that writes the cache. It is not sandboxed (it must write
the user's home) and reads nothing from the network. In order:

1. **Arguments.** Exactly four. `V` a `swver` that §4.7.1 accepts; `HASH`
   64 lower-case hex digits; `SIZE` a decimal from 1 to `MaxBinary`;
   `TEMP` exactly `$HOME/.cache/mosey/.upload.` followed by 1 to 64
   `pathchar`s other than `/`. `HOME` must be absolute. Anything else:
   refused.
2. **Home.** `open($HOME, O_DIRECTORY)`, following symlinks (a home under
   `/home → /usr/home` is ordinary). It must be owned by the user or root
   and writable by neither group nor others: sshd's own `StrictModes` rule
   for the home directory [sshd_config(5)].
3. **`~/.cache`.** Created 0700 if absent. Opened relative to the home's
   descriptor, **following a symlink** here only: a `~/.cache` that is a
   link to another disk is common and is the user's own doing. What it
   resolves to must be a directory owned by the user and writable by
   neither group nor others.
4. **`~/.cache/mosey`** and **`~/.cache/mosey/V`**. Each created 0700 if
   absent, then opened relative to its parent's descriptor with
   `O_NOFOLLOW | O_DIRECTORY`: a symlink is refused (`ELOOP` or
   `ENOTDIR`), so nothing planted can send the install elsewhere. Each must
   be owned by the user and writable by neither group nor others.
5. **The upload.** `TEMP`'s last component, opened relative to
   `~/.cache/mosey` with `O_NOFOLLOW`: a regular file, owned by the user,
   one link, exactly `SIZE` bytes, and SHA-256 equal to `HASH`, all read
   through that one descriptor. On a mismatch it is unlinked and the
   installer refuses.
6. **What is there now.** `fstatat(V-dir, "mosey", AT_SYMLINK_NOFOLLOW)`:
   absent is fine; a regular file owned by the user is replaced; a
   symlink, a directory, anything else, or **a file owned by anyone else**
   is refused and left exactly as it is (D7: never replaces a file someone
   else owns).
7. **Install.** `fchmod 0700`, `fsync` and `fstat` on the upload, then
   `renameat(~/.cache/mosey, TEMP, V-dir, "mosey")`, atomic within the
   filesystem. `rename(2)` takes names, so TEMP is looked up again here:
   `fstatat(V-dir, "mosey", AT_SYMLINK_NOFOLLOW)` must then show the
   device and inode of the descriptor that was hashed, or the file is
   unlinked and the installer refuses. Then `fsync` of the version
   directory. A session running
   from the file it replaces is unaffected: its spawner re-executes
   `/proc/self/exe` (`server.md`, threat-model §4.11).

Every step works through the descriptors of the step before
(`openat`, `mkdirat`, `fstatat`, `renameat`), so no directory is looked up
twice and no symlink can redirect a step. The one name looked up twice is
TEMP, by the rename, inside `~/.cache/mosey`, which only the user can
write; step 7's inode check catches a swap there after the fact. Exit 0 and nothing
on stdout on success; on any refusal one line on stderr,
`mosey --serve=install: WHAT`, naming the path and the rule, and exit 1.

Other users: the cache is under the user's home and every directory in it
is the user's alone, so another user can neither plant nor replace a file
there. The same user can (threat-model T12), which is why the copy is never
a trust anchor (S7 §10, threat-model §4.13).

Old versions are not removed (§14 question E).

#### 4.7.8 Starting again

After a 0 exit the client runs §4.1 once more with the probe, the same
config and the **same** ClientLine: its one-shot key was never used, since
no launcher read the first line, and the key is public anyway (B3 needs
SSH authentic, not confidential). If this second probe also says
`MOSEY-PROBE`, the client stops: `mosey: copied mosey V to DEST, but it is
still not found there` (no loop). Anything else proceeds or fails exactly
as a first attempt would.

#### 4.7.9 Costs and failures

The first session at a new version costs three SSH logins (probe, upload,
start) instead of one, and one prompt the first time ever per host; every
later session at that version, one login. A user with a key that asks for
a touch per login touches three times, once per upgrade per host.

| Situation | What happens |
|---|---|
| offline, same platform | nothing needs the network: the copy is the client's own file |
| offline, other platform | §4.7.4's fetch error and the advice to copy it by hand |
| development build, other platform | §4.7.4's message, before any download |
| no consent | `mosey: not copying mosey to DEST` |
| `~/.cache/mosey` is a symlink, or a version directory or the file is someone else's | the installer refuses (stderr says which), exit 1 |
| `~/.cache` on a `noexec` mount | upload exit 126, §4.7.6 |
| the probe line does not parse | `ErrBadLine`, as for any malformed line of ours |
| a `-remote` was given | none of this: §4.2 |


---

## 5. Agent forwarding: the decision (D25)

Whether to forward follows ssh's own config, with `-A`/`-a` on top, and is
read from the `forwardagent` that `ssh -G` printed (§3), which already
reflects the flags with ssh's own precedence:

| `forwardagent` | Socket to forward |
|---|---|
| `no` | none: agent off |
| `yes` | `identityagent` if set and not `none` or `SSH_AUTH_SOCK`; else `$SSH_AUTH_SOCK`; empty means agent off (to be verified against OpenSSH in the agent slice's harness, [S3] exercised `IdentityAgent`) |
| starts with `$` | the environment variable it names ([ssh]: printed verbatim, e.g. `$FOO`); unset or empty means agent off |
| anything else | that path ([ssh]: `ssh -G` has already expanded `~`) |

Slice 1 computes this (a pure function of `Config` and the environment,
unit tested) and logs it at debug level, but always runs the bootstrap with
`ForwardAgent=no`, sends `agent=no` in the ClientLine, and leaves
`ChannelAgent` out of its Hello.

---

## 6. The two lines

### 6.1 Common rules

- Both lines are **printable ASCII**: fields of bytes 0x21–0x7E, separated
  by exactly one space (0x20), ending in exactly one LF (0x0A). No CR, no
  leading or trailing space, no empty field, no tab.
- **Binary fields** are base64url without padding (RFC 4648 §5), decoded
  strictly (`base64.RawURLEncoding.Strict()`: unused trailing bits must be
  zero), and must decode to exactly the stated length. Why base64url: no
  `+` or `/`, so nothing a shell, a log viewer or a recorder might mangle.
- **Decimal fields** are `0` or a non-zero digit followed by digits: no
  sign, no leading zero.
- **The first two fields are frozen forever**: a magic word, then the
  bootstrap protocol version (`bootstrap.Version`, now `1`). Any version of
  mosey can therefore tell a line it cannot read from a line that is not
  its own, and the `MOSEY-ERROR` grammar in full, its size bound included,
  is frozen too, so a client of any version can read any server's refusal
  (§6.4).
- **Canonical.** A parser accepts a line only if marshalling what it parsed
  gives back the same bytes. The fuzz targets check exactly this (§12).
- **Strict versioning.** A v1 parser refuses any ClientLine or
  CredentialLine whose version field is not `1`, before reading the rest,
  with an error that carries the number it saw (`*VersionError`, §10.1).
  The ErrorLine is the exception: its parser accepts any `proto`, since its
  whole grammar is frozen. A new field or a new value means a new version. Fields marked
  *reserved* below have a grammar now so a later slice can start accepting
  values without changing the grammar; a v1 server refuses them with
  `unsupported`.

```
SP      = %x20
LF      = %x0A
dec     = "0" / (%x31-39 *DIGIT)
b64(n)  = base64url, no padding, of exactly n bytes
swver   = 1*64( ALPHA / DIGIT / "." / "_" / "+" / "-" )   ; "dev" or "0.123.20261114"
```

### 6.2 ClientLine: client → server, on ssh's stdin

```
client-line = "MOSEY-CLIENT" SP proto SP swver SP attach SP agent
              SP cols SP rows SP env SP public LF
proto   = dec                       ; = 1
attach  = "new" / "resume:" b64(16) ; resume: §9.2; all-zero SID = AnySession
agent   = "no" / "yes"              ; yes is reserved (D25)
cols    = dec                       ; 1..65535
rows    = dec                       ; 1..65535
env     = "-" / var *("," var)      ; names strictly ascending (byte order), no repeats
var     = name "=" 1*64vchar
name    = "COLORTERM" / "LANG" / "LANGUAGE" / "LC_ADDRESS" / "LC_ALL"
        / "LC_COLLATE" / "LC_CTYPE" / "LC_IDENTIFICATION" / "LC_MEASUREMENT"
        / "LC_MESSAGES" / "LC_MONETARY" / "LC_NAME" / "LC_NUMERIC"
        / "LC_PAPER" / "LC_TELEPHONE" / "LC_TIME" / "TERM"
vchar   = ALPHA / DIGIT / "." / "_" / "@" / ":" / "+" / "-"
public  = b64(1216)                 ; 1622 characters
```

| Field | Meaning |
|---|---|
| `proto` | `bootstrap.Version` |
| `swver` | the client's software version (`main.version`), for D7's equality check (§6.4) |
| `attach` | `new`: start a session. `resume:SID`: attach to session SID, or with the all-zero SID (`AnySession`) to the user's one session (D8, §9.2) |
| `agent` | whether the client will forward an agent (D25). The server needs it at spawn time to give the shell an `SSH_AUTH_SOCK` and to trigger ssh's bind (§8). Slice 1 sends `no`; a v1 server answers `yes` with `unsupported agent` |
| `cols`, `rows` | the client terminal's size; a terminal that reports 0 is sent as 80×24. The server clamps it (D23, `screen.ClampSize`). The client sends its size again as the first userinput event after connecting, in case it changed during the bootstrap |
| `env` | the client's locale and terminal variables, from the allow-list only. A variable that is unset, empty, longer than 64 bytes or holds a byte outside `vchar` is left out (logged at debug), never escaped. The server gives the locale variables to the shell; what it does with `TERM` and `COLORTERM` is `server.md`'s (the shell's `TERM` describes the server's emulator, not the client's terminal) |
| `public` | the client's one-shot X-Wing encapsulation key, `OneShotKey.PublicKey()`, 1216 bytes [S1, measured from `crypto/hpke`] |

Size: at most 3027 bytes [derived: the fixed fields and their 8 spaces come
to 1749 with a 64-byte swver and a resume attach; env at most 1277 (156
bytes of names, 17 × 65 for `=` and value, 16 commas); LF 1]. **`MaxClientLine` = 4096**
[derived: the next power of two, so the server's read bound is fixed and
generous].

Why not pass the environment as ssh `SendEnv`: sshd's `AcceptEnv` decides
what arrives, differently on every host, and the values arrive in the
environment of a process the server cannot validate first. On the line, the
grammar is ours and the parser is fuzzed.

Example (key shortened):

```
MOSEY-CLIENT 1 0.214.20261114093012 new no 211 58 COLORTERM=truecolor,LANG=en_GB.UTF-8,TERM=xterm-256color nW3b…Qe8
```

### 6.3 CredentialLine: server → client, on ssh's stdout

```
cred-line = "MOSEY-CONNECT" SP proto SP swver SP addr SP port
            SP credid SP sessionid SP psk SP public LF
addr      = "-" / ipv4 / ipv6       ; netip.Addr.String() form, no zone, never 4-in-6;
                                    ; not unspecified, multicast or 255.255.255.255
port      = dec                     ; 1..65535
credid    = b64(8)                  ; 11 characters
sessionid = b64(16)                 ; 22 characters
psk       = b64(32)                 ; 43 characters
public    = b64(1216)               ; 1622 characters
```

| Field | Meaning |
|---|---|
| `swver` | the server's software version (the spawner's own); equal to the client's by §6.4, sent so a mismatch can never pass silently and for the log |
| `addr` | the server's address as SSH reached it: the third field of `SSH_CONNECTION`, parsed with `netip.ParseAddr`, unmapped (`Unmap`) and with any zone dropped. `-` if there is no `SSH_CONNECTION`, it does not parse as four fields, or the address is one the grammar forbids. Set by the spawner from its own environment; proto must copy it exactly (§4.4 step 3) |
| `port` | the UDP port the spawner bound; likewise the spawner's, checked |
| `credid` | `handshake.Credential.ID` [S1: 8 bytes, our choice] |
| `sessionid` | `Credential.SessionID`, 16 bytes; names the session for resume (D8) and the logs |
| `psk` | `Credential.PSK`, 32 bytes [S1] |
| `public` | `Credential.ServerPublic`, the server's one-shot X-Wing key, 1216 bytes [S1] |

The parser is canonical, so `addr` must be exactly what `netip.Addr.String()`
gives for an unmapped, zone-free address: `::ffff:192.0.2.1`, `fe80::1%eth0`
and `0192.0.2.1` are refused. It also refuses, as `ErrBadLine`, any address
no server can legitimately have reached SSH on (threat-model §4.9): the
unspecified `0.0.0.0` and `::` (`IsUnspecified`), multicast `224.0.0.0/4`
and `ff00::/8` (`IsMulticast`), and the limited broadcast
`255.255.255.255`. These are properties of the address alone, so they
belong to the grammar and the fuzzer; the checks that need the client's own
interfaces or config are §7.2's.

Size: at most 1829 bytes [derived: 13 + 1 + 64 + 39 (longest IPv6 text) +
5 + 11 + 22 + 43 + 1622, 8 spaces, LF]. **`MaxCredentialLine` = 2048**
[derived].

The client turns it into a `handshake.Credential` (ID, SessionID, PSK,
ServerPublic) and a UDP destination (§7.2). `bootstrap` does not import
`handshake` (architecture §1); `internal/client` does the conversion.

### 6.4 ErrorLine: server → client, on ssh's stdout

```
error-line = "MOSEY-ERROR" SP eproto SP code SP detail LF
eproto     = "0" / (%x31-39 0*4DIGIT)    ; 0..99999, any version, no leading zero
code       = 1*16(%x61-7A)               ; a lower-case word
detail     = "-" / swver
```

This grammar, **and its bound `MaxErrorLine` = 128 bytes**, is frozen in
full, for every version: a v7 client must be able to read a v1 server's
refusal, and no future server may send a longer one. It freezes the
*shape* of each field, not a list of values: `code` is any lower-case word
of 1 to 16 letters, so a later version can add a code and an older client
still parses the line. The longest line is 100 bytes [derived:
`MOSEY-ERROR` 11 + SP + 5 digits + SP + 16 letters + SP + 64-byte swver +
LF]; 128 leaves room and is the bound the client enforces.

A client reading a code it does not know treats it as `internal` (the
generic message below, with the code shown in it). The codes v1 defines:

| Code | When | `detail` | Client says (exit 1) |
|---|---|---|---|
| `line` | the stdin line is malformed or not alone | `-` | `mosey: the server could not read this client's request: a bug, please report it` |
| `version` | the ClientLine's `proto` is not the server's, **or** its `swver` is not byte-for-byte the server's (for a resume, the session's, §9.2 step 5) | the server's (or session's) `swver` | new: `mosey: the remote mosey is version D, this is V: install V there or pass -remote` (D7 slice: upload, retry once). Resume: `mosey: the session runs version D; this is V: resume it with mosey D, or end it from a new session` |
| `unsupported` | a reserved value (`agent=yes`) the server does not yet accept | `agent` | `mosey: the remote mosey can't do F yet` |
| `session` | `resume:SID` names no session of this user that answers, or `AnySession` finds none (§9.2) | `-` | `mosey: no session to resume on DEST` |
| `ambiguous` | `AnySession` finds more than one session (§9.2) | their count | `mosey: N sessions on DEST: name one with -r=SESSION (mosey -list DEST shows them)` |
| `internal` | the server failed to start the session; stderr says why | `-` | `mosey: the server failed to start (see above)` |
| any other word | a later server's code | any | `mosey: the server refused: CODE (see above)` |

**Versions must be equal** (D7, D10): "the wrong version" in D7 means "not
this one", so the check is string equality, not a compatibility range. With
auto-upload it costs nothing; until then a user installs the matching
build. Two plain `go build`s are both `dev` and pass, which is what a
developer wants.

**Whose version.** For `new`, the launcher compares the ClientLine with
its own version, and the spawner it starts is the same file. For a resume
(§9.2) the check is against **the session's** version, which the session's
spawner reports over `attach.sock`, not the launcher's: the proto that will
mint the credential and speak the transport is the session's, and an
equal launcher in front of an old session proves nothing. A mismatch is
`MOSEY-ERROR 1 version SESSIONVER`, and the client, having asked for a
resume, does not answer it with an upload (§9.2).

The protocol version is checked first; the server sends its own `proto` in
the ErrorLine, and the client prints both numbers when they differ.

### 6.5 Reading stdout: `ReadCredential`

The remote login shell may print before the server runs: bash reads
`~/.bashrc` for a command run by sshd, and rc files print. `ReadCredential`
therefore:

1. Reads lines. A line that starts with `MOSEY-` is a **protocol line** and
   must parse as a CredentialLine, an ErrorLine or a ProbeLine (§4.7.2);
   if it does not, that is
   fatal (`ErrBadLine`), never skipped. No lookalike may be taken for
   ours, nor a malformed line of ours be stepped over to a later one.
2. Skips every other line, counting its bytes. More than
   **`MaxPreamble` = 64 KiB** [choice: well above any motd-like rc noise]
   of skipped bytes in total is fatal (`ErrNoLine`).
3. A protocol line longer than its maximum (2048 for CONNECT, 128 for
   ERROR, 160 for PROBE) is fatal. A skipped line may be any length; it counts against
   `MaxPreamble`.
4. Returns at the first protocol line; it reads nothing past its LF.
   (Afterwards, the client drains stdout to EOF in the background, at most
   another 64 KiB, then closes the pipe.)
5. EOF before a protocol line: `ErrNoLine`, as a `*NoLineError` carrying
   the kept tail (below), which the client maps to a message by ssh's exit
   status (§10).

An ErrorLine is returned as a `*RemoteError`, a ProbeLine as a
`*NoServerError`; a CredentialLine as the value (§10.1).

It never reads more than `MaxPreamble + MaxCredentialLine` bytes.

The last 1 KiB of skipped lines is kept and, on `ErrNoLine`, shown to the
user through the stderr filter below, because "no line" usually means the
server printed an error the user needs to see (a shell's `command not
found` goes to stderr, but a broken wrapper may print to stdout).

**The stderr filter** (D9: no remote control sequence reaches the local
terminal): bytes pass if they are LF, TAB, 0x20–0x7E, or part of a valid
UTF-8 sequence for a rune that `unicode.IsPrint` accepts and that is not a
bidi control (U+061C, U+200E–U+200F, U+202A–U+202E, U+2066–U+2069; D27's
set). Every other byte is written as `\xHH`; CR is `\r`. Lines longer than
1024 bytes are cut and end in `…`. The same filter guards §6.5's skipped
output, the `ssh -G` stderr of §3, and ssh's stderr after the line on its
way to the log file (§7.4): every byte from ssh reaches every sink through
it.

---

## 7. From the line to the session

### 7.1 States

```
          ┌────────────┐ ssh -G fails / timeout
 start ──►│ Resolving  │──────────────────────────────────────────► Failed
          └─────┬──────┘
                │ Config
          ┌─────▼──────┐ ssh will not start
          │ Spawning   │──────────────────────────────────────────► Failed
          └─────┬──────┘
                │ started: write ClientLine, close stdin
          ┌─────▼──────┐ ErrorLine ─────────────► Failed(code)    (D7 slice: version on a new attach → Uploading)
          │ AwaitLine  │ EOF / bound / bad line ► Failed(ssh exit status)
          └─────┬──────┘ ctx done ──────────────► Failed(cancelled), ssh killed
                │ CredentialLine (ssh stderr now goes to the log file; reap ssh in background)
          ┌─────▼──────┐ no usable address (§7.2) ► Failed(ErrBadAddr)
          │ Dialling   │ 30 s without msg2 ─────► Failed(no UDP)
          └─────┬──────┘
                │ *transport.Conn; key.Wipe()
          ┌─────▼──────┐ shell exits ───────────► Done (exit 0)
          │ Session    │ Revoked ───────────────► TakenOver (exit 3)
          └────────────┘ signal / terminal EOF ─► Detached (END detached; exit 0, §9.3)
```

Every arrow out of a state releases what that state held: ssh is killed and
reaped, the capture socket (agent slice) closed and unlinked, the one-shot
key wiped, the terminal restored.

### 7.2 The UDP address

The `addr` comes from the far host, which under T5 may be hostile, so the
client takes it only if it passes the rules below (threat-model §4.9). In
order:

1. The line's `addr`, if not `-` and **usable**.
2. Else the addresses `hostname` from `ssh -G` resolves to locally
   (`net.DefaultResolver`; a literal address is its own result), the first
   one that is **usable**.
3. Else fail with `ErrBadAddr`: `mosey: don't know where to send UDP for
   DEST` (followed, if `addr` was refused, by `(the server said ADDR, which
   is RULE)`).

An address is **usable** unless one of these holds:

| Rule | Why | Source |
|---|---|---|
| unspecified (`0.0.0.0`, `::`) | "send to this host", never a server | grammar (§6.3) for `addr`; checked here for `hostname`'s results |
| multicast (`224.0.0.0/4`, `ff00::/8`) | would spray every listener on the segment | same |
| IPv4 limited broadcast `255.255.255.255` | same | same |
| the directed broadcast of one of the client's own IPv4 interfaces (the last address of a prefix of length 30 or less, from `net.InterfaceAddrs`) | the only subnet broadcast the client can recognise, and the one that would reach its neighbours | here |
| loopback (`127.0.0.0/8`, `::1`) while the **destination is not loopback** | sshd reached over a local forward or tunnel (a `ProxyCommand` to socat or cloudflared, a container port mapping) reports a loopback `SSH_CONNECTION`; sending there reaches the client's own host | here |
| link-local (`fe80::/10`) with no zone the client can supply | the server's zone means nothing here | here: usable only if `hostname` parses as the same address *with* a zone, which is then used |

The **destination is loopback** when every address `hostname` resolves to
is loopback (`localhost`, `127.0.0.1`, `::1`, the test harnesses). So a
loopback `addr` is used when the user really did ssh to their own host,
and otherwise skipped in favour of `hostname`; server.md binds the wildcard
for a loopback `SSH_CONNECTION` (§4.4) so that fallback is reachable.

A refused `addr` that is not a grammar violation (rows 4–6) is not fatal by
itself: it is logged (warn) and the client goes on to `hostname`. A
grammar violation is `ErrBadLine` before §7.2 runs, because no honest server
sends one. `hostname`'s results are the user's own config and DNS, so a
refused one is skipped, not reported as hostile.

The rules are a pure function, `ChooseAddr` (§10.1), with the resolver and
the interface list injected, so the unit tests and the fuzzer reach every
row without a network.

If `ssh -G` shows a `proxyjump` or `proxycommand`, the client prints a
one-line notice on stderr, before Dial while the terminal is still cooked
(and logs it), that UDP goes straight to ADDR:PORT, not through the proxy. Via a jump host,
`SSH_CONNECTION` holds the address the jump host reached, which the client
may not be able to reach at all; Mosh's man page documents the same
problem and offers a choice of address sources [mosh-man,
`--experimental-remote-ip`]. Choosing among them is a later flag (open
question 6); slice 1 tries `addr` and, if the handshake times out, says
which address it tried.

The client's socket is `net.ListenUDP` on the wildcard address of the
chosen address's family, unconnected, so roaming (D21) needs no new socket.

### 7.3 Dialling and the terminal

`transport.Dial(ctx, pc, addr:port, cred, key, log)` with a deadline of
**30 s** [derived: `handshake.CredentialTTL`; after it the credential is
dead on the server anyway]. On timeout: `mosey: no reply from ADDR:PORT
over UDP: is UDP port PORT open?` (the classic firewall case). Then
`key.Wipe()` either way.

Only after Dial succeeds does the client put the terminal in raw mode and
start `client.Session` (§4.3: ssh's prompts need a cooked terminal). The
Hello it sends: `Version` = the hello version, `Channels` = `{Terminal}`
(plus `Agent` in the agent slice when §5 says on and §8 captured a bind),
`Attach` = `Exclusive` (D26: the only mode in v1).

### 7.4 The client's log

**The client's log is never the terminal.** Once raw mode starts the
terminal belongs to the session's screen, and anything else written there
(a log line, ssh's late stderr, the reaper's notes of §4.3) would corrupt
it; before raw mode, what the user must read is printed as a message by
`cmd/mosey` (§10), not logged.

- The log is a file, `$XDG_STATE_HOME/mosey/client.log` (default
  `~/.local/state/mosey/client.log`), directory 0700, file 0600, opened
  for append before the bootstrap starts. At 1 MiB [choice] it is renamed
  to `client.log.1` (replacing any older one) and a new file started, so
  it never grows without bound.
- If it cannot be opened, the log is discarded (`slog.DiscardHandler`) and
  the client says so once on stderr, before raw mode. It never falls back
  to stderr.
- Everything from ssh that reaches the log has been through the §6.5
  filter first, and every log line is one line (the text handler quotes
  values).
- `cmd/mosey/main.go` today builds its logger on `os.Stderr`; that must
  change to this rule when the bootstrap lands (listed in §15).

---

## 8. Bind capture (D25, agent slice)

Slice 1 implements none of this; it reserves `SSH.AgentCapture`, the
`agent` field and `ChannelAgent`. The design is S3's option (a′), whose
hardening is required, not optional ([S3] recommendation 1–5).

**Client.**

1. If §5 says on: make a directory with mode 0700 (under
   `$XDG_RUNTIME_DIR/mosey/`, else `os.TempDir()/mosey-UID/`, checked to be
   ours and 0700), and listen on `cap-HEX.sock` in it, `HEX` 16 random
   bytes, socket mode 0600, unlinked on close.
2. Run the bootstrap ssh with `-o ForwardAgent=PATH`, send `agent=yes`.
3. After `cmd.Start`, tell the capture the only acceptable peer: ssh's pid
   and our uid.
4. The capture is a strict state machine on **one** connection (the
   listener closes on the first accept, so a second agent channel from the
   server cannot reach it), with a 10 s deadline [S3]:

   ```
   Accept ─ SO_PEERCRED pid≠ssh or uid≠ours ─────────────────► NoBind
     │
   Frame1: SSH_AGENTC_EXTENSION (27) "session-bind@openssh.com"
           hostkey, session-id, signature, is_forwarding=1;
           signature verifies over session-id with hostkey
     │ else ─────────────────────────────────────────────────► NoBind
     │ reply SSH_AGENT_SUCCESS (6)
   Frame2: SSH_AGENTC_REQUEST_IDENTITIES (11), length 1
     │ else: reply SSH_AGENT_FAILURE (5) ────────────────────► NoBind
     │ reply SSH_AGENT_IDENTITIES_ANSWER (12) with 0 keys
   EOF ─────────────────────────────────────────────────────► Bound
     │ any further frame ─────────────────────────────────────► NoBind
   ```

   Message numbers and the bind's fields are from OpenSSH's
   `PROTOCOL.agent` [ssh]. Frame 1 is ssh's own; everything after it comes
   from the server, which can mint a valid bind for any host it reaches
   ([S3] E11, the critical review finding), hence "anything else means no
   bind at all".
5. Read the result **after ssh has exited** (so the server controls no
   timer) and pin the bind's host key to `known_hosts`: it must be a key
   that the files `userknownhostsfile` and `globalknownhostsfile` from
   `ssh -G` list for `hostkeyalias` if set, else `hostname`, at `port`
   (hashed entries included; `x/crypto/ssh/knownhosts`). Certificates
   (`@cert-authority`) are not handled yet ([S3] did not exercise them):
   no bind.
6. **NoBind means agent off**: the session goes on, the client says why on
   stderr, leaves `ChannelAgent` out of its Hello, and refuses any agent
   channel the server opens anyway ([S3] E7, E7b).
7. **Bound**: the bind is replayed with `is_forwarding=1` at the head of
   every mosey agent channel, before any frame from the server.

**Server.** With `agent=yes` and `SSH_AUTH_SOCK` set by sshd, the launcher,
before printing the CredentialLine, triggers ssh's bind: connect to
`SSH_AUTH_SOCK`, send `SSH_AGENTC_REQUEST_IDENTITIES`, read one reply frame
(at most 256 KiB), close; deadline 5 s [choice]. It is the open that makes
ssh connect to the capture socket and send its bind ([S3]: the trigger
took 0.82 ms). With no `SSH_AUTH_SOCK` (the host has
`AllowAgentForwarding no`) it skips the trigger; the client sees no
connection, so NoBind, and carries on without the agent ([S3] E7).

Measured cost of capture over a plain bootstrap: about 5 ms on loopback
[S3].

**How quoin knows it is inside a mosey session.** [S3] recommendation 6
has quoin-sudo treat a detached mosey session as remote, and quoin 0331bf1
does so by finding an ancestor whose comm is `mosey-server`. D7 removed
that name: the client and every server role are now the one file `mosey`,
so every one of them has comm `mosey`, and no process may be called
`mosey-server`. The comm alone cannot tell the local client from the far
spawner, so 0331bf1 no longer matches anything.

The marker is the spawner's **argv**: `/proc/PID/cmdline` of the
session's spawner is exactly `mosey` (any path), then `--serve=spawner`.
The spawner is the parent of the login shell (`server.md` §2.5), so a
`sudo` inside the session finds it as an ancestor; the local client's
argv[1] is never a `--serve` flag (§2). mosey's side of the contract:
the spawner's argv[1] stays exactly `--serve=spawner`, and the spawner
never rewrites its argv or comm. **Requirement on the quoin branch**
(D28 hand-off, `docs/mosey-integration.md`): replace 0331bf1's comm match
with "an ancestor running as the user whose comm is `mosey` and whose
argv[1] is `--serve=spawner`". A forged argv grants nothing a forged comm
did not, for the reason [S3] gives: remote mode's approval is a signature
any process that reaches the forwarded agent could already ask for. If
open question 8 puts the session under `systemd-run --user`, the spawner
is still the shell's parent, so the rule holds.

---

## 9. Exclusive attach and resume (D26, D8)

### 9.1 Exclusive attach (D26)

Every Hello in v1 says `Attach = Exclusive`. When a transport of a session
is **confirmed** (the first authentic transport packet, which also consumes
the credential, D20), the server revokes every other transport of that
session: each is sent `KindRevoked` with the new client's address and the
time, and its keys are wiped. The last client to confirm wins. Other unused
credentials of the session are not cancelled; they expire by their TTL
(30 s), and if one is confirmed it takes over in turn: each came from an
SSH login, and each SSH login is the user.

For a `new` attach there is nothing to revoke. The kicked client, on the
`transport.Revoked` event, restores the terminal and prints

```
mosey: session taken over from ADDR:PORT at 2026-11-14T09:30:12+00:00
```

(`By` as `netip.AddrPort.String()`, `At` in the client's local zone as
RFC 3339 to the second), then exits with status 3. It does not reconnect:
this is the "cut off a stolen client" property of D26.

**The limit of that message.** The kicked client learns why only from a
REVOKED frame, and the server keeps those for the tombstone's 60 s
(`transport.md` §8.3). A client that sends nothing in that minute, a
laptop asleep while the session is resumed from a phone, wakes to
silence: its keys are gone on the server, so it probes on a stale screen
and never prints the message. Its keys are useless to anyone either way,
so the cut-off itself holds; only the explanation is lost. A longer-lived
signal is open question D (§14).

### 9.2 Resume (D8)

Resume is a new SSH login and a new handshake whose credential is vouched
for by that login; nothing transport- or crypto-related is ever kept on
disk, by either side (D8; [S1] §1.4). It covers a client that is gone: a
reboot, a crash, a closed terminal, a laptop left behind, another device.
A dead spot *within* one client's life needs no resume: the transport keeps
its keys through any outage and the path follows the client (D21), so the
same client carries on once packets flow again (`transport.md` §7).

**The client's command line** [choice: the simplest that covers a reboot
and a second device without the client keeping state]:

| Command | ClientLine `attach` | Server picks |
|---|---|---|
| `mosey DEST` | `new` | a new session, always, as Mosh does: a plain `mosey DEST` never takes over anything |
| `mosey -r DEST` | `resume:` + 22 `A`s (the all-zero SID, **`AnySession`**) | the user's one session on that host; none is `session`, several is `ambiguous` (below) |
| `mosey -r=SID DEST` | `resume:SID` | session SID, given as its 32 hex digits (as `-list` shows them) |
| `mosey -list DEST` | none: runs `mosey --serve=list` (§9.4) | |

The all-zero SID is never drawn for a session (proto redraws it; the
chance is 2^-128), so `AnySession` is a value of §6.2's grammar, not a
new grammar. The client keeps no list of sessions: the server's is the
only one, so a second device sees exactly what the first would.

1. **Client.** It bootstraps exactly as §4–§7 with a fresh one-shot key
   and `attach=resume:SID`. Its `cols`/`rows` are its own terminal's.
2. **Launcher.** It checks the protocol version and the reserved `agent`
   field as for `new`, but **not** its own `swver` (step 5). It finds the
   session's attach socket, `R/mosey/SID-HEX/attach.sock` (`server.md`
   §2.6 says what `R` is and how the directory is checked), and connects.
   For `AnySession` it connects to every `R/mosey/*/attach.sock` and keeps
   those that answer with a greeting: none is `MOSEY-ERROR 1 session -`,
   more than one is `MOSEY-ERROR 1 ambiguous N` (N their count, in
   decimal), exactly one is the session. A named SID with no socket, or
   one that does not answer, is `MOSEY-ERROR 1 session -`.
3. **Spawner.** The session's spawner owns the socket. It checks the
   peer's uid with `SO_PEERCRED` [S1 `resume.go`], sends its greeting
   (§9.2.1), and reads the launcher's `ClientLine` (0x40). It parses it
   again (it trusts no other process's parse), checks `swver` against its
   own and the SID against its own (or `AnySession`), and checks the
   client's public key is an X-Wing key. It forwards the key to proto
   (`Resume`, 0x05), and proto mints a credential for the **same SID**
   with the usual TTL (30 s) and cap (2 unused, the oldest evicted and
   logged). The credential comes back as `Credential` (0x30); the spawner
   checks it as at bootstrap (§4.4 step 3), and that its `sessionid` is
   the session's, and sends it to the launcher in `Ready` (0x41), which
   prints it exactly as for `new`. Any failure is `Failed` (0x42), which
   the launcher turns into `MOSEY-ERROR 1 internal -`.
4. **Handshake and takeover** as §7 and §9.1: on confirmation every other
   transport of the session is revoked, and its client exits saying so.
5. **Versions** (§6.4 "Whose version"). The first thing the spawner sends
   is its greeting, whose first two fields are frozen (§9.2.1); the
   launcher compares the ClientLine's `swver` with the session's and, on
   a mismatch, prints `MOSEY-ERROR 1 version SESSIONVER` and exits 1
   without sending anything. The client, having asked for a resume, does
   not upload (§6.4).

   **An upgraded client and an old session** (§14 question A, decided
   [choice]): an upgrade ends resumability. The client says `the session
   runs version SESSIONVER; this is V: resume it with mosey SESSIONVER, or
   end it from a new session`, and keeps no old builds. Keeping old
   client builds locally would make a client that runs code nobody is
   using any more the one that holds the keys, for a case that ends at
   the session's next `exit`. Listed for Dan.
6. **The size** in the ClientLine is not applied by the spawner (an
   unconfirmed attach must change nothing). The client sends its size as
   the first input event once connected (§6.2), which resizes the pty and
   emu when the transport is confirmed, through the one resize path.
7. **The screen** starts from scratch on the new connection: SSP state is
   per transport (`ssp.md` §1.3), so the new client receives the whole
   current screen as its first diff.
8. **If proto has died** the session is over (`server.md` §2.4): the
   spawner tears it down, so its socket is gone and a resume finds no
   session. Restarting proto on the same pty ([S4] §3.8) is left for a
   later slice; see `server.md` §5.4.

#### 9.2.1 The greeting

The first message the spawner sends on an attach socket, one seqpacket
message of printable ASCII (§6.1's rules), **not** an IPC message:

```
session-line = "MOSEY-SESSION" SP swver SP sessionid SP started SP state
               SP since SP peer LF
sessionid    = b64(16)
started      = dec              ; unix seconds the session started
state        = "new" / "attached" / "detached"
since        = dec              ; unix seconds of the last change of state
peer         = "-" / addrport   ; netip.AddrPort.String() of the last attached
                                ; client, unmapped, no zone; "-" if none known
```

`new` is a session no client has attached to yet; `attached` one whose
last client is (as far as the server knows: a client that vanished
without saying so still counts) attached; `detached` one whose last
client said it was leaving, or whose connection failed.

**The first two fields are frozen forever** (`MOSEY-SESSION` and
`swver`), so a launcher of any version can read any session's version:
`SessionLineVersion` reads only those, accepting anything printable after
the second space. The rest is this version's, parsed by `ParseSessionLine`
only when the versions are equal. Both parsers are canonical and fuzzed.
`MaxSessionLine` = 256 bytes [derived: the longest line is 13 + 64 + 22 +
20 + 8 + 20 + 47 + 6 spaces + LF = 201].

### 9.3 How long a session lives

[choice, listed for Dan] **A session lives until its shell exits.**

| The session | Ends when |
|---|---|
| has never had a client | every credential minted for it has expired unconfirmed (§4.5: 30 s after the last one), or the spawner's backstop fires |
| has had a client | its shell exits; or the spawner is signalled; or proto dies (§9.2 step 8). **Never** because its client went away |

A client that goes away says so if it can: on a signal (SIGTERM, SIGHUP:
a closed terminal, a logout, a shutdown) or the end of its terminal's
input, it sends END with reason `detached` (`transport.md` §8.4), puts the
terminal back, prints

```
mosey: detached from session SID-HEX; resume with: mosey -r=SID-HEX DEST
```

and exits 0. The server marks the session `detached` and keeps it. A client
that cannot say so (power loss, a crash, a network that never comes back)
leaves the session `attached` to a connection nobody holds, which the next
resume revokes.

There is **no idle timeout** for a detached session, as there is none for
Mosh's server or a tmux session: a session is resumable for as long as its
shell runs, and `exit` in the shell is how it ends. `mosey -list` (§9.4)
shows what is still running. The hazards of §4.5 ("Known hazard") apply
unchanged: with logind's `KillUserProcesses=yes` the session dies with the
SSH login that started it.

### 9.4 Listing sessions

`mosey -list DEST` runs `mosey --serve=list` over the bootstrap's own ssh
command (§4.1, its last argument `exec /bin/sh -c 'exec SERVER
--serve=list'`, or with no `-remote` §4.7.2's probe running
`--serve=list`, which finds the copy in `~/.cache/mosey/V/`), with stdin
closed. A probe that answers `MOSEY-PROBE` is reported as §4.7.1 says,
not shown as a list, and nothing is copied. The
server connects to every attach socket as the launcher does for
`AnySession`, reads each greeting, and prints one line per session that
answered, oldest first, then exits 0:

```
SESSION                           STATE     SINCE                 PEER                 VERSION
0f3a…(32 hex digits)              detached  2026-11-14T09:30:12Z  192.0.2.7:50123      0.214.20261114
```

or `no sessions`. The text is for people: the client does not parse it,
it copies ssh's stdout to its own through the §6.5 filter (D9), so a
hostile server can print only harmless text. The client then adds
`resume one with: mosey -r=SESSION DEST`.

A lister sends no ClientLine; the spawner sees the connection close after
its greeting and does nothing.

---

## 10. Errors the client reports

| Situation | Message | Exit |
|---|---|---|
| usage (§2) | the usage text | 2 |
| `ssh -G` fails | filtered stderr of `ssh -G`, then `mosey: ssh -G DEST failed` | 1 |
| ssh cannot start | `mosey: running PROGRAM: ERR` | 1 |
| `ErrNoLine`, ssh exit 255 | (ssh has already said why on stderr) `mosey: ssh to DEST failed` | 1 |
| `ErrNoLine`, ssh exit 126/127 (`ErrNoServer`, with `-remote`) | `mosey: no mosey at SERVER on DEST: install it there or pass -remote` | 1 |
| ProbeLine (`ErrNoServer`, no `-remote`) | the upload of §4.7, and its messages; for `-r` and `-list`, §4.7.1's messages and no upload | 1 |
| `ErrNoLine`, other exit | `mosey: the remote mosey exited with status N` | 1 |
| `ErrBadLine` | `mosey: DEST sent a malformed mosey line` | 1 |
| `ErrBadAddr` | §7.2 | 1 |
| ErrorLine | per §6.4 | 1 |
| Dial timeout | §7.3 | 1 |
| taken over | §9.1 | 3 |
| detached (a signal, or the terminal's input ended) | §9.3 | 0 |
| `-list` | the server's list (§9.4), filtered | 0, or 1 if ssh failed |
| shell exited | none | 0 |

Errors are values (§10.1), matched with `errors.Is`/`errors.As` in
`client.Run`; only `cmd/mosey` prints and exits.

### 10.1 The Go interface of `internal/bootstrap`

This replaces the stubs in `internal/bootstrap/*.go` and architecture.md
§5's one-line summary of the package; both must be brought in line in the
commit that implements it (§15). `bootstrap` imports neither `handshake`
nor `transport`.

```go
const (
	Version           = 1
	MaxClientLine     = 4096
	MaxCredentialLine = 2048
	MaxErrorLine      = 128 // frozen with the ErrorLine grammar
	MaxPreamble       = 64 << 10
)

// ClientLine is §6.2. Marshal always writes proto = Version.
type ClientLine struct {
	SoftwareVersion string            // swver
	Resume          bool              // attach: false = "new"
	SessionID       [16]byte          // attach = resume:SID, when Resume
	Agent           bool              // agent
	Cols, Rows      uint16            // 1..65535
	Env             map[string]string // allow-listed names only; Marshal sorts
	Public          []byte            // 1216 bytes
}

// CredentialLine is §6.3. Marshal always writes proto = Version.
type CredentialLine struct {
	SoftwareVersion string
	Addr            netip.Addr // the zero Addr is "-"
	Port            uint16
	CredentialID    [8]byte
	SessionID       [16]byte
	PSK             [32]byte
	Public          []byte // 1216 bytes
}

// ErrorLine is §6.4; Detail "" is "-".
type ErrorLine struct {
	Proto  int
	Code   string
	Detail string
}

const (
	CodeLine        = "line"
	CodeVersion     = "version"
	CodeUnsupported = "unsupported"
	CodeSession     = "session"
	CodeAmbiguous   = "ambiguous"
	CodeInternal    = "internal"
)

// AnySession is the SessionID of a resume that asks for the user's one
// session (§9.2); no session is ever given it.
var AnySession [16]byte

// SessionLine is §9.2.1, the spawner's greeting on its attach socket.
type SessionLine struct {
	SoftwareVersion string
	SessionID       [16]byte
	Started         time.Time // to the second
	State           SessionState // New, Attached, Detached
	Since           time.Time
	Peer            netip.AddrPort // the zero AddrPort is "-"
}

const MaxSessionLine = 256

func MarshalSessionLine(SessionLine) []byte
func ParseSessionLine([]byte) (SessionLine, error)
// SessionLineVersion reads only the frozen fields: any version's greeting.
func SessionLineVersion([]byte) (string, error)

func MarshalClientLine(ClientLine) []byte
func ParseClientLine([]byte) (ClientLine, error)
func MarshalCredentialLine(CredentialLine) []byte
func ParseCredentialLine([]byte) (CredentialLine, error)
func MarshalErrorLine(ErrorLine) []byte
func ParseErrorLine([]byte) (ErrorLine, error)

// ReadCredential is §6.5. On an ErrorLine it returns *RemoteError; on a
// ProbeLine, *NoServerError; on EOF or MaxPreamble, *NoLineError; on a
// bad protocol line, ErrBadLine.
func ReadCredential(r io.Reader) (CredentialLine, error)

// ProbeLine is §4.7.2: what the probe prints when no mosey of this
// version is there. Marshal always writes proto = Version.
type ProbeLine struct {
	System  string // uname -s
	Machine string // uname -m
}

func MarshalProbeLine(ProbeLine) []byte
func ParseProbeLine([]byte) (ProbeLine, error)

// NoServerError is the probe's answer; errors.Is(err, ErrNoServer).
type NoServerError struct{ Probe ProbeLine }

// Platform maps a probe to Go's os and arch (§4.7.3).
func Platform(p ProbeLine) (goos, goarch string, ok bool)
// IsRelease says whether v has a GitHub Release (§4.7.4).
func IsRelease(v string) bool
// AssetName is §4.6's mosey-V-OS-ARCH.
func AssetName(v, goos, goarch string) string
// ParseSums finds name's hash in a SHA256SUMS file (§4.6, §4.7.4).
func ParseSums(sums []byte, name string) ([32]byte, error)
// CanUpload is §4.7.1's rule on V; CachePath is ~/.cache/mosey/V/mosey.
func CanUpload(v string) bool
func CachePath(v string) string

var (
	ErrBadLine  = errors.New("bootstrap: malformed mosey line")
	ErrNoLine   = errors.New("bootstrap: no mosey line")
	ErrNoServer = errors.New("bootstrap: no mosey on the far host")
	ErrBadAddr  = errors.New("bootstrap: no usable UDP address")
)

// VersionError is a line whose proto is not Version; errors.Is(err,
// ErrBadLine) is true.
type VersionError struct{ Got int }

// RemoteError is a server's ErrorLine.
type RemoteError struct{ ErrorLine }

// NoLineError is ErrNoLine (errors.Is) with the last 1 KiB of skipped
// stdout, unfiltered; whoever shows it passes it through Sanitize.
type NoLineError struct {
	Tail     []byte
	Overflow bool // MaxPreamble was reached, rather than EOF
}

// Sanitize is the §6.5 filter, as a writer that filters into w.
func Sanitize(w io.Writer) io.WriteCloser // Close flushes a rune split across Writes

// SSHOptions is §2.1: the user's options, normalised, and the last -A/-a.
type SSHOptions struct {
	Args  []string
	Agent byte // 0, 'A' or 'a'
}

func ParseSSHOptions(args []string) (SSHOptions, error)

// Config is §3: ssh -G's keywords, each with every value in order.
type Config map[string][]string

func ParseConfig(out []byte) (Config, error)
func (c Config) Get(keyword string) string // the first value, or ""

// SSH is how the client runs the system ssh for a bootstrap.
type SSH struct {
	Program      string // "ssh" looks it up on PATH
	Destination  string
	Options      SSHOptions
	Server       string // the remote mosey binary, §4.1's charset; "" is §4.7's probe
	Version      string // this client's swver, for the probe (§4.7.2)
	AgentCapture string // agent slice; "" is ForwardAgent=no
	Role         string // "" runs --serve; "list" runs --serve=list (§9.4)
}

func (s SSH) Check() error // §2 and §4.1: destination and Server rules
func (s SSH) Resolve(ctx context.Context) (Config, error) // runs ssh -G
func (s SSH) Command(ctx context.Context, c Config) *exec.Cmd
// UploadCommand is §4.7.6's ssh, which reads the binary on stdin.
func (s SSH) UploadCommand(ctx context.Context, c Config, hash [32]byte, size int64) *exec.Cmd

// AgentSocket is §5: the socket to forward, or ok false for agent off.
func AgentSocket(c Config, getenv func(string) string) (path string, ok bool)

// ChooseAddr is §7.2.
func ChooseAddr(ctx context.Context, line CredentialLine, c Config,
	lookup func(ctx context.Context, host string) ([]netip.Addr, error),
	local []netip.Prefix) (netip.Addr, error)
```

`ReadCredential` returns `ErrNoServer` only as a `*NoServerError`, for a
ProbeLine; `client.Run` also wraps a `*NoLineError` in it when ssh exited
126 or 127 (§4.2, §10).

The installer of §4.7.7 is `internal/install` (`install.Run(args,
getenv, uid) error`), a server-side package the client never imports.

The implementation adds, beside the above: `*UsageError` (what
`ParseSSHOptions` and `SSH.Check` return; exit 2), `*ResolveError` (ssh
-G's failure, carrying its bounded stderr for §10's message),
`*AddrError` (`ErrBadAddr` with the refused `addr`, its rule and any
lookup error, for §7.2's message), `Config.Has` (the keyword test of §3),
`ClientEnv` (§6.2's env from the environment, naming what it left out),
`SSH.RemoteCommand` (§4.1's one argument), `ExitStatus`, `EnvNames`,
`ValidServer`, `ValidSoftwareVersion`, `ValidEnvValue`, the field sizes
(`PublicKeySize` and so on), `TailSize`, `MaxSanitizedLine` and
`MaxConfig`. `Sanitize` returns an `io.WriteCloser` rather than an
`io.Writer`: a rune split across two writes is held for the next, and
`Close` writes any held bytes escaped.

---

## 11. Constants

| Name | Value | Provenance |
|---|---|---|
| `bootstrap.Version` | 1 | ours |
| `MaxClientLine` | 4096 B | [derived] §6.2: at most 3027 B used |
| `MaxCredentialLine` | 2048 B | [derived] §6.3: at most 1829 B used |
| `MaxErrorLine` | 128 B, frozen | [derived] §6.4: at most 100 B used |
| Session with no confirmed credential | ends after `handshake.CredentialTTL` (30 s) | [derived] §4.5 |
| Spawner backstop (requirement on server.md) | CredentialTTL + 10 s | [choice] §4.5 |
| Client log rotation | 1 MiB, one old file | [choice] §7.4 |
| `MaxPreamble` | 64 KiB | [choice] |
| `MaxProbeLine` | 160 B | [derived] §4.7.2: at most 148 B used |
| `MaxBinary` (upload, download, installer) | 128 MiB | [choice]; a release is about 10 MB |
| `SHA256SUMS` read bound | 64 KiB | [choice]; four lines today |
| Release fetch deadline | 5 min | [choice] §4.7.4 |
| Consent answer bound | 64 B | [choice] |
| `upload-hosts` file bound, key bound | 1 MiB, 1100 B | [choice] §4.7.5 |
| Release version parts | at most 9 digits each, patch ≥ 1 | [derived] §4.7.4, `scripts/version.sh` |
| Env value length | 1–64 B | [choice]; keeps §6.2's bound |
| `-remote` length | 1–256 B | [choice] |
| X-Wing public key | 1216 B (1622 base64url chars) | [S1] measured from `crypto/hpke` |
| Credential ID, session ID, PSK | 8, 16, 32 B | [S1]; `internal/handshake` |
| Server stdin deadline | 30 s | [derived] = `handshake.CredentialTTL` |
| proto credential deadline | 10 s | [choice] |
| `ssh -G` deadline, output bound | 10 s, 256 KiB | [choice] |
| ssh exit wait after the line | 10 s, then SIGTERM, then SIGKILL after 1 s | [S3] capture deadline |
| launcher waits for `Ready` (T2) | 15 s | `server.md` §8 |
| Dial deadline | 30 s | [derived] = `handshake.CredentialTTL` |
| Capture deadline | 10 s | [S3] |
| Agent trigger deadline, reply bound | 5 s, 256 KiB | [choice] |
| UDP port range | 60000–61000 | [mosh-man] |
| Fresh SSH connection over a mux | about +108 ms, loopback | [S3] E12 |
| Default size when the terminal says 0 | 80×24 | [choice]; the VT100's |
| stderr filter line cut | 1024 B | [choice] |
| Taken-over exit status | 3 | ours |
| `MaxSessionLine` | 256 B | [derived] §9.2.1: at most 201 B used |
| Greeting deadline (launcher, lister) | 2 s per socket | [choice]: the spawner answers at once; a hung one is skipped, not waited on |
| Detached session lifetime | until its shell exits | [choice] §9.3 |

---

## 12. Tests

**Unit, `internal/bootstrap`:**

- Marshal/Parse round trips for both lines and the error line, including
  maxima (64-byte swver, every env name at 64 bytes, longest IPv6).
- Each rule of §6.1 broken once: CR, double space, trailing space, padding,
  non-zero trailing bits, wrong decoded length, leading zero, `0` cols,
  65536, unknown env name, unsorted or repeated names, `::ffff:` and zoned
  addresses, `0.0.0.0`, `::`, `224.0.0.1`, `ff02::1` and `255.255.255.255`
  as `addr`, a wrong version (error carries the number), a missing or extra
  field.
- ErrorLine: every v1 code; an unknown 16-letter code parses (and maps to
  `internal` in the client); a 17-letter code, an upper-case code, a
  6-digit or zero-led `eproto`, and a line over 128 bytes are refused; a
  `proto` other than 1 is accepted.
- `ChooseAddr`, each row of §7.2's table with an injected resolver and
  interface list: a usable `addr`; a loopback `addr` with a non-loopback
  `hostname` (falls back), and with `localhost` (kept); a local directed
  broadcast (falls back); link-local with and without a zoned `hostname`;
  `-` with a `hostname` resolving to `[::, 224.0.0.1, 192.0.2.7]` (picks
  the last); nothing usable (`ErrBadAddr`).
- `ReadCredential`: noise then the line; the line first; a `MOSEY-` line
  that does not parse; noise over `MaxPreamble`; one skipped line longer than
  `MaxPreamble`; EOF; a protocol line over its maximum; a reader that
  returns one byte at a time; and that it never reads past the LF (a reader
  that fails if read beyond).
- ssh option filter: every letter in §2.1's table; clusters, attached and
  separate arguments; `-A`/`-a` ordering; refused letters; missing argument.
- `SSH.Command`: the exact argv for a given `Config`, with and without the
  8.7 keywords, its last element exactly `exec /bin/sh -c 'exec SERVER
  --serve'`; `-remote` charset; a destination starting with `-`.
- The remote command under each outer shell that is installed (sh, bash,
  zsh, fish, tcsh, nu; each skipped if absent): a missing `SERVER` exits
  127, a non-executable one 126, and `~/` expands.
- The stderr filter: every C0 and C1 byte, ESC sequences, bidi controls,
  invalid UTF-8, a long line; output never contains a byte below 0x20 but
  LF and TAB, nor 0x7F.
- The agent decision table of §5.
- The probe and the upload command (§4.7) under each outer shell that is
  installed, as for §4.1: the probe execs a cached or `PATH` mosey that
  says `V`, skips one that says anything else, and prints a ProbeLine
  that parses when there is none; the upload command installs through a
  stand-in installer and removes its temporary file.
- `Platform`, `IsRelease`, `AssetName` and `ParseSums`, each row and rule.

**Unit, `internal/install`:** a fresh install; replacing the user's own
older file; refusing, and leaving untouched, a `~/.cache/mosey` or version
directory that is a symlink, a file that is a symlink, a directory or
someone else's (the "user" is a field, so a test can play another uid), a
group- or world-writable directory, a size or hash mismatch (the upload is
removed), a `TEMP` outside `~/.cache/mosey`, a relative `HOME`.

**Unit, `internal/client`:** the consent table of §4.7.5 and the
remembered-hosts file; the release fetch against a local HTTPS server:
the right asset is chosen, a hash mismatch, a missing asset, a 404, an
oversized body and an `http` redirect are each refused before any upload.

**Fuzz** (each run locally for at least a few minutes before it lands,
durations in the commit message; 10 s each in CI):

- `FuzzParseClientLine`, `FuzzParseCredentialLine`, `FuzzParseErrorLine`:
  no panic; anything accepted re-marshals to the identical bytes; no
  accepted CredentialLine has an unspecified, multicast or limited
  broadcast `addr`.
- `FuzzChooseAddr`: no panic; the result, if any, breaks no row of §7.2.
- `FuzzReadCredential`: no panic; at most `MaxPreamble + MaxCredentialLine`
  bytes read; the result, if any, re-marshals to a line present in the
  input.
- `FuzzSSHOptions`: no panic; any accepted argv, re-parsed, gives the same
  normalised argv, and never contains a refused letter.
- `FuzzSanitize`: the stderr filter's output invariant.
- `FuzzParseProbeLine`: as the other lines; `FuzzReadCredential` covers
  probe lines too.
- `FuzzParseSums`: no panic; a hash it returns is that of a line of the
  input naming exactly that name; anything accepted has no line outside
  the grammar.
- `FuzzParseSessionLine`: no panic; anything accepted re-marshals to the
  identical bytes; `SessionLineVersion` agrees with it on every line it
  accepts, and never panics on any input.

**End to end, `internal/e2e`:**

- **Fake ssh, always runs.** `SSH.Program` is a test helper binary that
  takes ssh's argv, checks it is the §4.1 shape, and runs the remote command
  with `sh -c` locally, with `SSH_CONNECTION="127.0.0.1 1 127.0.0.1 22"`.
  With the real `mosey` built by the test: the line exchange, the version
  check (a second build with another `-X main.version`), `-remote` to a
  missing file (exit 127), a server that prints rc noise before the line,
  and that the fake ssh exits once the line is out while the session lives
  on (detach, §4.4 step 5; asserted as "exits", with the test's own
  timeout, never a measured duration, D18).
- **Abandoned session** (§4.5). The fake ssh delivers the line and the
  client never dials. The spawner, proto, emu and shell (found by the
  session's pids from the spawner's log) must all be gone, and the pty
  hung up, after CredentialTTL plus the teardown's grace periods. Run
  with the server's clock under the test's control where the server
  allows it; otherwise asserted as "gone", within the test's own timeout,
  never as a measured duration (D18).
- **Non-loopback address.** If the test host has a non-loopback,
  non-link-local address (skipped cleanly otherwise): with
  `SSH_CONNECTION` naming it, the client dials it; with a loopback
  `SSH_CONNECTION` and the fake `ssh -G` printing that address as
  `hostname`, the client falls back to it and still connects (which
  needs the wildcard bind of §4.4).
- **Real sshd, skipped cleanly if absent.** A throwaway unprivileged sshd on
  127.0.0.1 with throwaway host and user keys, its own `known_hosts`, a
  throwaway agent, and an `ssh_config` given with `-F`, as
  `spikes/s3-agent-bind/harness` does. Never the system sshd, `~/.ssh`,
  the user's agent, or a live service. Runs the real binaries over loopback
  UDP to an interactive shell and back.
- **Resume through real sshd** (§9.2), same harness, with sshd's
  `SetEnv XDG_RUNTIME_DIR=` a throwaway directory so the attach sockets
  live under the test: a first client starts a session and sets a shell
  variable; a second (`-r`) takes it over, sees the variable's value
  echoed by the same shell, and the first exits 3 saying it was taken
  over; the second, sent SIGHUP, detaches (exit 0) and the session stays
  (`-list` shows it `detached`); a third (`-r=SID`) resumes it and ends it
  with `exit`, after which nothing of the session is running.
- **Auto-upload through the real sshd** (§4.7), with the remote's `HOME`
  a temporary directory (the throwaway sshd's `SetEnv HOME=`), no
  `-remote`, and a version nothing on the remote `PATH` can have: the
  client asks, is told `y`, copies itself, and ends with a working
  session and `~/.cache/mosey/V/mosey` byte-for-byte the client's file;
  a second client of another version upgrades beside it; a cached file
  of the wrong version is replaced; and a `~/.cache/mosey` that is a
  symlink is refused with nothing written through it.
- **NixOS VM** (`tests/install.nix`, CI's `vm-install`): a host with no
  mosey gets one by consent and runs the session from the cache; a
  second run asks nothing.
- The netsim end-to-end test starts at `client.Session` and does not involve
  ssh at all; this document's part is that a `CredentialLine` round-tripped
  through Marshal/Parse yields the `handshake.Credential` it is given.

---

## 13. Threats this part answers

| Threat | Answer |
|---|---|
| stdout recorded or leaked (recorder, bastion) | B3: the line does not let anyone impersonate either side ([S1] `b3_stdout_leak`); the PSK only filters DoS |
| a hostile or compromised remote writes control sequences to stdout or stderr | stdout is parsed, never shown; stderr and skipped lines pass the filter (§6.5), D9 |
| a hostile remote sends a huge or endless stdout | `MaxPreamble`, line maxima, ssh killed 10 s after the line |
| the stdin line attacks the unsandboxed spawner | fixed grammar, 4 KiB read bound, 30 s deadline, fuzzed, canonical |
| a hostile remote injects a session-bind after ssh's (agent slice) | §8's state machine: anything after ssh's own bind means no bind ([S3] E11) |
| a live ControlMaster carries the bootstrap | always a fresh connection ([S3] E12, E12b) |
| the user's config undoes a bootstrap option | ours come first; flags that beat `-o` are filtered (§2.1, §4.1) |
| version skew between client and server | exact equality, refused before anything starts (§6.4, D7) |
| a stolen client keeps the session | exclusive attach on any new confirmed login (§9.1, D26) |
| a hostile remote steers the client's UDP at a broadcast, multicast or local address | grammar refuses unspecified, multicast, limited broadcast; §7.2 refuses local directed broadcast and loopback for a non-loopback destination (threat-model §4.9) |
| a compromised proto chooses where the client sends UDP | the spawner checks `addr`, `port`, `swver` against its own (§4.4 step 3) |
| failed bootstraps pile up detached shells | a session with no confirmed credential ends after CredentialTTL (§4.5) |
| late remote bytes corrupt the session screen | ssh's stderr after the line goes, filtered, only to the log file (§7.4) |
| a planted symlink or another user's file redirects the auto-upload's install (D7) | the installer works through `O_NOFOLLOW` descriptors below `~/.cache`, checks owner and mode at every level, and never replaces what is not the user's (§4.7.7) |
| a corrupt, cut-short or substituted binary is installed (D7) | the installer checks the length and SHA-256 the client computed or read from `SHA256SUMS` before the rename (§4.7.4, §4.7.7) |
| a hostile remote lies about its platform | it chooses which public build it is sent, nothing more (§4.7.2) |

---

## 14. Open in this document

A. **An upgraded client and an old session.** *Decided by the resume
   slice* (§9.2 step 5): an upgrade ends resumability, with a message
   naming both versions. Dan may still prefer keeping old client builds.

B. **The spawner's confirmation backstop** (§4.5): the `Attached`
   message and the CredentialTTL + 10 s rule are a requirement this
   document places on `server.md`, which has yet to take it up.

C. **Signed releases** (§4.6): `SHA256SUMS` is only as trustworthy as
   the GitHub release it comes from. Signing it (an SSH signature from a
   key CI holds, or Sigstore's keyless signing of the workflow) would let
   the client check that CI made it. The auto-upload slice, the first to
   download anything, checks `SHA256SUMS` only (§4.7.4) and leaves this
   open for Dan.

D. **A local cache of downloaded releases** (§4.7.4). Each host of a
   foreign platform downloads the release again; keeping it under
   `$XDG_CACHE_HOME/mosey/` would save that, at the cost of one more
   file the client must re-verify before trusting.

E. **Old versions in `~/.cache/mosey`** (§4.7.7). Under D10 each upgrade
   leaves about 10 MB per host. Removing a version is safe for running
   sessions (they run `/proc/self/exe`), but a resume from an old client
   (question A) would then upload that version again, so pruning waits
   for the resume slice's answer to A.

D. **Telling a client taken over long ago** (§9.1). [listed for Dan] The
   REVOKED frames last 60 s, so a client asleep through a takeover never
   learns of it. One answer: a tombstone that lasts as long as the
   session, keyed by the old indices, its frames sealed under the old
   receive keys before they are erased; the cost is a few hundred bytes
   per takeover for the session's life, and a bound on how many are kept.

---

## 15. Review notes

Answers to the review of 2026-11-14. Changes to other files that these
answers need are listed under **Elsewhere**; this revision edits only
this file.

1. **Orphaned sessions (major). Fixed.** New §4.5 states the requirement:
   a `new` session with no confirmed credential ends after CredentialTTL,
   by proto's `Exit{NoClient}` and the spawner's teardown (hang-up, then
   SIGKILL of shell, proto and emu), which `server.md` §2.4 already
   specifies; §4.5 adds a spawner-side backstop as a requirement on
   server.md (question B). §4.3 now says the client relies on this after a
   Ctrl-C, §4.4 makes a failed stdout write SIGTERM the spawner, and §12
   adds the abandoned-session e2e test. *Rebutted in part:* deferring the
   shell to the first confirmation. The shell's rc files are not run "for
   a client that never proved it holds sk_C": they run for the SSH login,
   which already ran them once to start the launcher, and that login is
   the user. Starting the shell early overlaps its start-up with the
   handshake; deferring it buys nothing B3 needs.
2. **Unspecified, multicast and broadcast addresses (major). Fixed.**
   §6.3's grammar refuses unspecified, multicast and `255.255.255.255`
   (`ErrBadLine`, fuzzed); §7.2's table refuses the client's own directed
   broadcasts and applies every rule to `hostname`'s results too. Unit,
   fuzz (`FuzzChooseAddr`) and e2e cases are in §12.
3. **Who writes `addr`, `port`, `swver` (major). Fixed, by a different
   route.** Proto still sends the whole line in `Credential` (0x30), as
   `server.md` §3.3 fixes the layout, but the spawner now checks all three
   against its own state, not only that the line parses (§4.4 step 3;
   `server.md` §3.4 already checks `addr` and `port`, `swver` is new).
   The effect is the reviewer's: proto chooses only the four fields it
   alone knows, and a line whose routing fields differ from the spawner's
   never reaches stdout. Rebuilding the line in the spawner from four
   fields would also work; checking is the smaller change to a layout
   already specified and fuzzed. *Elsewhere:* `server.md` §3.4 adds the
   `swver` check.
4. **Resume and exact versions (major). Fixed, with an open question.**
   §6.4 "Whose version" and §9.2 step 6: a resume is checked against the
   session's version, which the spawner reports first on `attach.sock`,
   whose first message is frozen across versions; a `version` refusal on
   a resume does not trigger an upload. What an upgraded client does is
   §14 question A, for the resume slice.
5. **Loopback `addr` and the threat-model requirement (major). Fixed.**
   §7.2: a loopback `addr` is skipped unless the destination itself
   resolves only to loopback, and the client falls back to `hostname`.
   Because that fallback must reach the server, §4.4 adds a requirement on
   `server.md` §2.2 to bind the wildcard for a loopback `SSH_CONNECTION`,
   as it does for link-local. §12 adds unit cases and a non-loopback e2e
   case; the plain fake-ssh test keeps its loopback `SSH_CONNECTION`,
   which is now correct because its `hostname` is loopback too.
   *Elsewhere:* `server.md` §2.2.
6. **ErrorLine grammar (major). Fixed.** §6.4 freezes the shape:
   `eproto` is 1 to 5 digits, `code` any lower-case word of 1 to 16
   letters, and `MaxErrorLine` = 128 is part of the frozen grammar (the
   longest line is 100 bytes). Unknown codes parse and map to `internal`;
   §6.1 notes the ErrorLine parser accepts any `proto`.
7. **Launcher and spawner vs architecture.md (major). Fixed here;
   architecture.md is elsewhere.** The roles are named in the header and
   each step of §4.4 says which role does it, citing `server.md` §2.1 and
   the messages 0x40, 0x41, 0x42 and T1–T3. *Elsewhere:* architecture.md
   §1 and §2 must name the launcher (`mosey --serve`) and the spawner
   (`mosey --serve=spawner`) and drop "the spawner detaches with setsid";
   `server.md` §11 item 1 already lists this, and it lands with
   `cmd/mosey/server.go`'s new role in one commit.
8. **The Go interface (major). Fixed here; stubs and architecture.md are
   elsewhere.** New §10.1 gives every exported type, signature and error,
   including `ErrorLine`, `Config`, `SSH.Resolve`, `Command(ctx, Config)`,
   `*RemoteError`, `*NoLineError{Tail, Overflow}`, `*VersionError`,
   `ErrBadAddr`, `Sanitize` and `ChooseAddr`. *Elsewhere:* the stubs in
   `internal/bootstrap/` and architecture.md §5 change in the same commit,
   per architecture.md's own rule; this revision was limited to this
   file.
9. **Where the client logs (major). Fixed.** New §7.4: the log is a file
   under `$XDG_STATE_HOME/mosey/`, else discarded, never stderr; ssh's
   stderr after the line passes the §6.5 filter and goes only there; the
   proxy note of §7.2 is a message printed before raw mode. *Elsewhere:*
   `cmd/mosey/main.go`'s `os.Stderr` handler changes when the bootstrap
   lands.
10. **Exit 127 under csh and nu (major). Fixed, and checked.** Confirmed
    [shells]: tcsh 6.24.16 and nushell 0.112.2 exit 1 for a missing
    command (tcsh also 1 for a non-executable file); fish 4.7.1 exits 127.
    §4.1 now runs the server through `exec /bin/sh -c 'exec SERVER
    --serve'`, under which all of them exit 127 (and 126), checked under
    bash, tcsh, fish, nushell and zsh, with `~/` still expanded. §4.1's
    charset already needs no quoting inside the single quotes. §12 tests
    each installed shell.
11. **quoin and the `mosey-server` comm (major). Fixed as a requirement
    on quoin.** §8 now says 0331bf1's comm match is dead under D7, and
    that the marker is the spawner's argv (`--serve=spawner`), which
    mosey promises not to change or rewrite. Setting the comm to
    `mosey-server` with `PR_SET_NAME`, as the review suggests, is not
    taken: D7 as now settled says no process is named `mosey-server`.
    *Elsewhere:* the quoin branch (D28 hand-off) replaces the comm match.
