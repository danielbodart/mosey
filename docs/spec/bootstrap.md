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
mosey [-remote PATH] [-ssh PROGRAM] [-A | -a] [-- SSH-OPTION...] DESTINATION
```

- `DESTINATION` is passed to ssh unchanged: `host`, `user@host`, an alias
  from `~/.ssh/config`, or `ssh://user@host:port`. It must be non-empty, at
  most 1024 bytes, must not start with `-`, and must not contain bytes below
  0x21 or 0x7F (ssh would read a space as the start of the command). Anything
  else is a usage error (exit 2).
- `-remote PATH` is the remote mosey binary (§4.2). Default `mosey`.
- `-ssh PROGRAM` is the local ssh. Default `ssh`, found on `PATH`. Tests
  point it at a fake (§12).
- `-A` and `-a` are ssh's own flags (D25): force agent forwarding on or off.
  They may be given as mosey flags or among the SSH options; the last one
  given wins, as in ssh ([ssh]: `ssh -A -a` resolves to `forwardagent no`,
  `ssh -a -A` to `yes`).
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
        -o ForwardX11=no -o ClearAllForwardings=yes
        -o PermitLocalCommand=no -o EscapeChar=none
        -o RemoteCommand=none
        [-o SessionType=default -o StdinNull=no -o ForkAfterAuthentication=no]
        USER-OPTIONS...
        -- DESTINATION "exec /bin/sh -c 'exec SERVER --serve'"
```

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
- **`ForwardX11=no`, `ClearAllForwardings=yes`.** A config `LocalForward`
  would collide with the user's interactive ssh to the same host, and an
  `ExitOnForwardFailure` would then kill the bootstrap.
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

Slice 1: `mosey` on the remote `PATH`, or `-remote PATH`. A non-interactive
SSH session's `PATH` is often shorter than an interactive one's (no
`~/.local/bin`); `-remote` is the answer until D7.

D7 (auto-upload slice) changes only the remote command and adds a step after
a failure; the two lines in §6 do not change. Its hooks:

- **Missing binary.** `/bin/sh`'s exit status for a command it cannot find
  is 127, and 126 for one it cannot run (POSIX); the §4.1 wrapper makes
  this hold whatever the user's login shell is [shells]. ssh exits with the
  remote command's status. The client reports exit 127 or 126 with no
  protocol line as `ErrNoServer` (§10); D7 answers it with an upload and
  one retry. A launcher never exits 126 or 127 itself (its failures are
  exit 1, §4.4), so the two cannot be confused.
- **Wrong version.** The server refuses a client of another version with
  `MOSEY-ERROR ... version` before starting anything (§6.4). D7 answers that
  the same way.
- **`mosey --serve=version`** prints the server's version and exits, for a
  probe that wants to ask before uploading. Reserved; slice 1 does not call
  it.

### 4.3 The client's process handling

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
attach  = "new" / "resume:" b64(16) ; resume is reserved (D8)
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
| `attach` | `new`: start a session. `resume:SID`: attach to session SID (D8, §9); a v1 server answers `MOSEY-ERROR 1 unsupported attach` |
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
| `version` | the ClientLine's `proto` is not the server's, **or** its `swver` is not byte-for-byte the server's | the server's `swver` | `mosey: the remote mosey is version D, this is V: install V there or pass -remote` (D7 slice: upload, retry once) |
| `unsupported` | a reserved value (`resume:…`, `agent=yes`) the server does not yet accept | `attach` or `agent` | `mosey: the remote mosey can't do F yet` |
| `session` | `resume:SID` names no session of this user (§9) | `-` | `mosey: no session to resume` |
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
   must parse as a CredentialLine or an ErrorLine; if it does not, that is
   fatal (`ErrBadLine`), never skipped. No lookalike may be taken for
   ours, nor a malformed line of ours be stepped over to a later one.
2. Skips every other line, counting its bytes. More than
   **`MaxPreamble` = 64 KiB** [choice: well above any motd-like rc noise]
   of skipped bytes in total is fatal (`ErrNoLine`).
3. A protocol line longer than its maximum (2048 for CONNECT, 128 for
   ERROR) is fatal. A skipped line may be any length; it counts against
   `MaxPreamble`.
4. Returns at the first protocol line; it reads nothing past its LF.
   (Afterwards, the client drains stdout to EOF in the background, at most
   another 64 KiB, then closes the pipe.)
5. EOF before a protocol line: `ErrNoLine`, as a `*NoLineError` carrying
   the kept tail (below), which the client maps to a message by ssh's exit
   status (§10).

An ErrorLine is returned as a `*RemoteError`; a CredentialLine as the
value (§10.1).

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
          └────────────┘ ctx done / user quits ─► Done
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

### 9.2 Resume (D8, later slice)

Reserved now: `attach = resume:SID` in the ClientLine, the `session` error,
`Credential.SessionID`, and `Listener` routing by credential, not process.

Resume is a new SSH login and a new handshake whose credential is vouched
for by that login; nothing transport- or crypto-related is ever kept on
disk, by either side (D8; [S1] §1.4).

1. **Client.** It knows the session ID from the CredentialLine. It may keep
   it, with the destination, in `$XDG_STATE_HOME/mosey/` (never a key,
   counter or PSK). It bootstraps exactly as §4–§7 with a fresh one-shot
   key and `attach=resume:SID`. Which events start a resume (a user flag, a
   restart, long silence after the server lost its keys) is the resume
   slice's to decide.
2. **Server.** The launcher reads the line, finds the session's
   attach socket (`$XDG_RUNTIME_DIR/mosey/SID-HEX/attach.sock`, in a 0700
   directory owned by the user; the same checks as the capture directory),
   and connects. The session's spawner (unsandboxed, owns the socket)
   checks `SO_PEERCRED` uid equals its own [S1 `resume.go`], forwards the
   client's key and size to proto over IPC, and proto mints a credential in
   the session's `handshake.Credentials` (TTL 30 s, at most 2 unused, the
   oldest evicted and logged). The line comes back the same way and is
   printed exactly as for `new`. No such session, or a foreign uid: `MOSEY-ERROR
   1 session -`.
3. **Handshake and takeover** as §7 and §9.1: on confirmation the old
   transport is revoked.
4. **If proto died** (its keys with it, [S4] §3.8), the spawner starts a new
   proto on the same pty and a resume brings the client back; emu sends a
   full redraw.
5. The ClientLine's `cols`/`rows` apply on attach: the server resizes the
   pty and emu when the transport is confirmed, not before (an unconfirmed
   attach must change nothing).
6. **Versions** (§6.4 "Whose version"). The launcher skips its own
   `swver` check for a resume. The first thing the session's spawner sends
   on `attach.sock` is its version; the launcher compares the ClientLine's
   `swver` with that, and on a mismatch prints `MOSEY-ERROR 1 version
   SESSIONVER` and exits 1 without forwarding anything. **The
   `attach.sock` grammar is frozen across versions** from the resume
   slice on, at least its first message (`MOSEY-SESSION SP swver LF`, the
   §6.1 rules), so a launcher of any version can read any session's
   version. A client that asked for a resume and gets `version` does not
   upload (that would install its own version, which still would not
   match the session).

   What an upgraded client does about an old session is **open** (§14,
   question A): either it keeps old client builds locally (as D7 keeps
   server builds remotely, under `~/.cache/mosey/<version>/`) and resumes
   with the build that matches, or an upgrade ends resumability and the
   user is told `the session runs SESSIONVER; this is V`. Under D10 every
   green commit ships, so this is a daily case, not an edge one; the
   resume slice must decide before it ships.

---

## 10. Errors the client reports

| Situation | Message | Exit |
|---|---|---|
| usage (§2) | the usage text | 2 |
| `ssh -G` fails | filtered stderr of `ssh -G`, then `mosey: ssh -G DEST failed` | 1 |
| ssh cannot start | `mosey: running PROGRAM: ERR` | 1 |
| `ErrNoLine`, ssh exit 255 | (ssh has already said why on stderr) `mosey: ssh to DEST failed` | 1 |
| `ErrNoLine`, ssh exit 126/127 (`ErrNoServer`) | `mosey: no mosey at SERVER on DEST: install it there or pass -remote` | 1 |
| `ErrNoLine`, other exit | `mosey: the remote mosey exited with status N` | 1 |
| `ErrBadLine` | `mosey: DEST sent a malformed mosey line` | 1 |
| `ErrBadAddr` | §7.2 | 1 |
| ErrorLine | per §6.4 | 1 |
| Dial timeout | §7.3 | 1 |
| taken over | §9.1 | 3 |
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
	CodeInternal    = "internal"
)

func MarshalClientLine(ClientLine) []byte
func ParseClientLine([]byte) (ClientLine, error)
func MarshalCredentialLine(CredentialLine) []byte
func ParseCredentialLine([]byte) (CredentialLine, error)
func MarshalErrorLine(ErrorLine) []byte
func ParseErrorLine([]byte) (ErrorLine, error)

// ReadCredential is §6.5. On an ErrorLine it returns *RemoteError; on
// EOF or MaxPreamble, *NoLineError; on a bad protocol line, ErrBadLine.
func ReadCredential(r io.Reader) (CredentialLine, error)

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
func Sanitize(w io.Writer) io.Writer

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
	Server       string // the remote mosey binary, §4.1's charset
	AgentCapture string // agent slice; "" is ForwardAgent=no
}

func (s SSH) Check() error // §2 and §4.1: destination and Server rules
func (s SSH) Resolve(ctx context.Context) (Config, error) // runs ssh -G
func (s SSH) Command(ctx context.Context, c Config) *exec.Cmd

// AgentSocket is §5: the socket to forward, or ok false for agent off.
func AgentSocket(c Config, getenv func(string) string) (path string, ok bool)

// ChooseAddr is §7.2.
func ChooseAddr(ctx context.Context, line CredentialLine, c Config,
	lookup func(ctx context.Context, host string) ([]netip.Addr, error),
	local []netip.Prefix) (netip.Addr, error)
```

`ErrNoServer` is not returned by `ReadCredential`: `client.Run` wraps a
`*NoLineError` in it when ssh exited 126 or 127 (§4.2, §10).

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

---

## 14. Open in this document

A. **An upgraded client and an old session** (§9.2 step 6): keep old
   client builds locally and resume with the matching one, or let an
   upgrade end resumability. For the resume slice; it does not affect
   slice 1.

B. **The spawner's confirmation backstop** (§4.5): the `Attached`
   message and the CredentialTTL + 10 s rule are a requirement this
   document places on `server.md`, which has yet to take it up.

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
