# Bootstrap: starting a session over SSH

Owner: **bootstrap-client**. Packages: `internal/bootstrap`, `internal/client`
(its bootstrap half), `cmd/mosey/main.go`. The server half of each step
lives in `internal/server` and is specified in `server.md`; this document
says what the server must do *as seen from the SSH channel*.

Decisions implemented here: D6 (start over SSH with the user's config), D7
(one binary, auto-upload where the host has none), D8 (resume; its stable
protocol, V1, in §6 and §9.2), D20 (B3:
one-shot keys over stdin and stdout), D25 (agent bind capture, §8; the channel it feeds is `agent.md`), D26
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
either side ([S1] §5, ProVerif `b3_stdout_leak`, S1's
`TestB3LeakedStdoutCannotImpersonate`; in mosey
`TestALeakedCredentialLineCannotImpersonateTheClient`). Nothing in either line is secret in
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
mosey [-remote PATH] [-upload ask|yes|no] [-ssh PROGRAM] [-A | -a] [-s NAME | -new | -list | -kill NAME] [-dir DIR] [-type TEXT] [-close-if-idle] [-- SSH-OPTION...] [DESTINATION [COMMAND [ARG...]]]
```

The words are read in that order, and each part ends where the next
begins: mosey's own flags, Go's `flag` rules, up to the first word that
is not one of them or up to `--`; after a `--`, ssh's options, by ssh's
getopt rules (§2.1), up to the first word that is neither an option nor
an option's value; then `DESTINATION`, the first such word; then
everything after it, untouched, is the command. So mosey never reads the
command's own flags (`mosey far ls -la`), and the ssh options always come
before the destination, after `--` (`mosey -s work -- -p 2222 far
claude`), which is where they went before commands existed.

No `DESTINATION`, or a `DESTINATION` of `localhost` (any case), is this
machine, and no ssh is run (§2.2): `mosey` alone resumes or starts a
session here, and `mosey -list` lists the sessions here, as tmux does
[D: Dan, 2026-11-18, reversing 2026-11-16's "this machine is asked for
by name": tmux works this way, and spelling out `localhost` was a
chore]. A COMMAND needs a `DESTINATION` before it, as the first plain
word is always the destination. `-h` and `-help` print the usage on
stdout and exit 0.

- `DESTINATION` is passed to ssh unchanged: `host`, `user@host`, an alias
  from `~/.ssh/config`, or `ssh://user@host:port`. It must be at
  most 1024 bytes, must not start with `-`, and must not contain bytes below
  0x21 or 0x7F (ssh would read a space as the start of the command). Anything
  else is a usage error (exit 2). Only the exact word `localhost` is this
  machine without ssh: `127.0.0.1`, `::1`, `me@localhost` and an ssh
  alias for this host all go through ssh, as any other host does, so the
  ssh path can still be run against this machine.
- `-remote PATH` is the remote mosey binary (§4.2). Without it the client
  uses whatever mosey the host has, and copies itself over only if there
  is none it can use (D7, §4.7).
- `-upload ask|yes|no` is what to do when the far host has no mosey it
  can use (§4.7.5). Default `ask`. Any other value is a usage error.
- `-ssh PROGRAM` is the local ssh. Default `ssh`, found on `PATH`. Tests
  point it at a fake (§12).
- `-A` and `-a` are ssh's own flags (D25): force agent forwarding on or off.
  They may be given as mosey flags or among the SSH options; the last one
  given wins, as in ssh ([ssh]: `ssh -A -a` resolves to `forwardagent no`,
  `ssh -a -A` to `yes`).
- With none of the next four, `mosey DESTINATION` resumes the user's
  most recently detached session there that was started without a
  command, or starts a new one if none is detached (D8 R1, §9.2); with a
  `COMMAND`, the most recently detached one started with that command
  (below). There is no resume flag.
- `-s NAME` attaches to the session called NAME, taking it over if
  another client has it (D26), and starts it under that name if there is
  none (D8 R2). NAME is §6.2's `sname`: 1 to 32 letters, digits, `-`,
  `_` and `.`, starting with a letter or digit; anything else is a usage
  error.
- `-new` always starts a new session, with a generated name.
- `-list` lists the sessions there and exits (§9.4); `-kill NAME` ends
  session NAME (§9.5). The four exclude each other. The old `-r` and
  `-r=SESSION` are gone: `-s` replaces them.
- `-dir DIR` and `-type TEXT` say how a session starts (§9.2.3): its
  login shell starts in DIR, relative to the remote `$HOME` unless it is
  absolute, and TEXT is typed into it, followed by Enter. They apply only
  when the command **creates** a session: a plain `mosey DEST` that finds
  none detached, `-new`, or `-s NAME` when there is no session NAME. When
  it resumes or takes over an existing session they are ignored, without
  an error. DIR is 1 to 1024 bytes of UTF-8 with no control character;
  TEXT is 1 to 1024 bytes of UTF-8 with no control character but tab
  (§6.2's `dirtext` and `typetext`); anything else, or either one with
  `-list` or `-kill`, is a usage error. An empty value is the same as
  leaving the flag out. They replace what a tmux user does with
  `tmux new-session -c DIR` and then `tmux send-keys TEXT Enter`, so a
  session can open in a project and start a program there, and leave the
  user in that directory's shell, with their whole `PATH`, when the
  program exits.
- `-close-if-idle` is for local sessions only (§2.2; a usage error with
  any other `DESTINATION`, or with `-list` or `-kill`). When the client
  receives `SIGHUP` or `SIGTERM` or its terminal closes while attached
  (a read that ends with EOF or fails with `EIO`, the hangup a closed
  window gives, which often arrives before its `SIGHUP`; or the terminal
  refusing raw mode just after Dial, a window closed during start-up),
  it connects to the session's attach socket and sends `HangupIfIdle`
  with its current credential id (`server.md` §2.4, §2.6) before exiting
  cleanly: if the shell is idle at its prompt with no other processes in
  the session and no other client has taken over, the spawner ends the
  session; otherwise the session stays alive and detached.
- `SSH-OPTION`s after `--` are filtered (§2.1) and passed to both ssh
  invocations.
- `COMMAND [ARG...]`, the words after `DESTINATION`, are a command to run
  in place of the interactive shell, as `ssh DEST COMMAND` runs one (Dan,
  2026-11-16: `mosey dan-desktop claude` should end, and leave the
  terminal, when claude does). They are joined with single spaces, as
  ssh joins them, and the result is run by the user's shell as `SHELL -c
  TEXT`, so quoting and expansion are that shell's (§9.2.3). The command
  runs on the session's pty, in DIR if `-dir` is given; when it exits the
  session ends, and the client exits as it does when a shell exits. Like
  `-dir`, it is run only when a session is **created**. A plain `mosey
  DEST COMMAND` is R1 keyed by the command (PLAN D8, Dan, 2026-11-16,
  option C: closing the window on `mosey dan-desktop claude` and running
  it again should "connect back to the same one and resume it and not
  create another instance if there's one there"): it resumes the most
  recently detached session that was started with exactly that text,
  byte for byte, and otherwise starts a new one running it, with a
  generated name. It never takes an attached session, so a second window
  running the same line gets a second instance. The match is on the
  command alone: `-dir`, as on any resume, is ignored, and two sessions
  of one program in two directories are told apart with `-s NAME`
  [D: the command is what the user sees and names; a directory given
  relative to a home would have to be resolved to be compared, and a
  plain `mosey DEST -dir X` without a command does not match on it
  either]. `-s NAME DEST COMMAND` starts NAME running the command if
  there is no session NAME, and otherwise takes NAME over as it is; if
  NAME was not started with that very command it says so on stderr
  (`mosey: session NAME was already running, so the command was not
  run`). A session started with a command is an ordinary named session:
  it can be detached, listed (with its command), taken over and killed.
  The joined text is 1 to 1024 bytes of
  UTF-8 with no control character but tab (§6.2's `cmdtext`); anything
  else, a command with `-type` (both say what to run, and typing into a
  command is not what `-type` means), or with `-list` or `-kill`, is a
  usage error.
- `-completion bash|zsh|fish` prints that shell's completion script on
  stdout and exits 0, starting nothing and needing no `DESTINATION`, as
  `-version` does; any other shell, or none, is a usage error [D: Dan,
  2026-11-16: `mosey d<TAB>` should offer the hosts `ssh d<TAB>` does].
  The scripts hand `DESTINATION` to the shell's own ssh host completion,
  and get mosey's flags from the flag set the client parses with, so
  they cannot drift from it. TAB never runs ssh: `-s` and `-kill`
  complete from `mosey -list localhost`, and only when `DESTINATION` is
  `localhost` or not yet typed.

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

### 2.2 No `DESTINATION`, or `localhost`: this machine

`mosey`, `mosey -s NAME`, `mosey -new`, `mosey -list` and `mosey -kill
NAME`, each with or without `localhost` after it, act on this user's
sessions on the machine the client runs on, with no ssh at all: mosey as
a local terminal multiplexer, as tmux is, and an end-to-end test that
needs no sshd [D: Dan, 2026-11-16; no `DESTINATION` again, Dan,
2026-11-18]. A hint for this machine names no host (`mosey -s NAME`).
The word `localhost` is compared without regard to case, and nothing else
(no `user@`, no address, no alias) is taken as this machine.

**The local launcher.** Where §4.1 runs `ssh ... -- DEST "exec /bin/sh -c
'exec mosey --serve'"`, the client runs the server binary itself, as
`SERVER --serve` (or `--serve=list`, or `--serve=kill NAME`), with no shell
between: `SERVER` is `-remote`'s path if given, otherwise the client's own
file (`os.Executable`). Its stdin, stdout and stderr are what ssh's would
have been, and everything else is unchanged: the ClientLine up stdin, the
CredentialLine (or ErrorLine) down stdout through `ReadCredential`, its
stderr through the §6.5 filter, then the handshake, SSP, prediction,
resume and R3. There is nothing for SSH to vouch for (D6): the client
started the server itself, as the same user.

What is skipped, because it is all about ssh: `ssh -G` (`Resolve` returns
a config holding only `hostname 127.0.0.1`, for §7.2), §2.1's options,
§4.7's probe and upload, §8's bind capture and `BatchMode`. A path given
to `-remote` here is run as it is, so it needs none of §4.1's quoting
rules; a bare name is looked up on the client's `PATH`.

**The same sessions.** The launcher, its spawner and the attach sockets
(`R/mosey/SID-HEX/attach.sock`, `server.md` §2.6) are exactly those of an
ssh login to this host, so a session started locally is listed by `mosey
-list THISHOST` from elsewhere and can be taken with `mosey -s NAME
THISHOST` (D26), and one started over ssh can be taken here. Two
consequences follow:

- The launcher gets the client's environment, less `SSH_CONNECTION`,
  `SSH_CLIENT`, `SSH_TTY` and `SSH_AUTH_SOCK`: this is not an ssh login,
  even when the client itself runs inside one. With no `SSH_CONNECTION`
  the spawner advertises no address and binds the wildcard (`server.md`
  §2.2), so a client from another network can still reach a session
  started here; the local client finds it on `127.0.0.1` (§7.2's fallback,
  loopback being allowed since the destination is loopback). A session
  that was started over ssh advertises the address that login reached, and
  the local client sends there. The shell inherits the rest of the
  client's environment, as under tmux, where under ssh it would have
  sshd's.
- A local `-dir` is relative to `$HOME`, as over ssh, not to the client's
  working directory.

**The agent.** There is no ssh, so no session-bind to capture (§8), and no
far host for one to name: the shell is a process of the same user on the
same machine as the agent, and could open its socket directly. So the
shell gets the agent the client has, through the session's own agent
socket (`agent.md` §4.1), with nothing replayed (`agent.Forwarder.Unbound`):
each connection reaches the agent as any local process's does. The socket
forwarded is the client's `SSH_AUTH_SOCK`; with none, the agent is off.
`-a` turns it off; `-A` with no `SSH_AUTH_SOCK` says `mosey: not forwarding
the agent: SSH_AUTH_SOCK is not set`. Since the shell's socket is the
session's, not the client's, the agent follows whichever client is
attached: one taken over ssh with `-A` gets that client's agent, bound as
§8 says, and one taken back here gets this terminal's again.

**Flags that need ssh.** `-upload` and `-ssh` say how to reach a host or
what to copy to it, and ssh options after `--` are for an ssh there is
not; on this machine they are a usage error (`mosey: -upload has no
use with localhost, which runs without ssh`), not silently ignored. `-A`, `-a`, `-remote`, `-predict`, `-dir`, `-type`, `-close-if-idle`
and the session flags mean what they mean over ssh (`-close-if-idle` is
local only).

**Messages** name `localhost` where they name `DEST` (`no sessions on
localhost`, `work is not a directory on localhost`), but a hint names no
host, as this machine is the default (`resume it with: mosey -s NAME`).
A launcher that prints no
line is named with its status (`SERVER exited with status N and no mosey
line`), and one that cannot be run with `running SERVER: ERR`.

No protocol number changes: the lines, the hello and the greeting are as
over ssh.

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
| `forwardagent` | the agent decision (§5) | agent slice |
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
        -o ForwardAgent=no | =CAPTURE-SOCKET    (§5, §8)
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
- **`ForwardAgent=no`**, or the capture socket's path when §5 says the
  agent is on (§8). Never the user's real agent: the bootstrap's agent
  channel exists only to make ssh send its bind.
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
which is what D7's `~/.local/bin/mosey` needs [shells: checked
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
  any mosey version serves the client as its own would (D8 V1); one of
  another protocol fails the bootstrap with one line naming both numbers
  (§6.4), and is never replaced: the user named it.
- **No `-remote` (the default): D7.** The remote command becomes §4.7's
  probe, which runs `mosey` on the remote `PATH`, of whatever version, or
  else `~/.local/bin/mosey` if it speaks the client's protocol, and
  otherwise prints the remote's platform; the client then copies a build
  over, with the user's consent, and starts again once (§4.7). The lines
  of §6 do not change. `mosey --serve=protocol` is what the probe asks
  `~/.local/bin/mosey`.

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
  non-zero exit after a valid line is logged, not fatal. With the agent
  on, the client waits for the capture's final state before dialling,
  because the Hello depends on it (§7.3, §8 step 5): that state is final
  at the capture connection's EOF, which the launcher's trigger causes
  before the line is printed, or at ssh's exit if no connection came.

### 4.4 The server's side, as SSH sees it

What happens on the far host, in order, and which role does it. The
messages between launcher and spawner are `server.md` §2.1 and §3.3
(`ClientLine` 0x40, `Ready` 0x41, `Failed` 0x42, on the socketpair B);
the timeouts T1–T3 are `server.md` §8.

1. **Launcher.** Read stdin **to EOF**, at most 8193 bytes, within T1 =
   30 s [derived: `handshake.CredentialTTL`; the client writes the line
   before authentication, so it is there when the command starts]. Stdin
   must be exactly one ClientLine: one LF, at the end, then EOF. Anything
   else is `MOSEY-ERROR 1 !code=line`.
2. **Launcher.** Parse it (§6.2), which checks the line's protocol
   number (§6.4) and refuses a critical field it does not know with
   `unsupported` (§6.2); no software version is sent or compared (D8 V1). Then
   start the spawner, `mosey --serve=spawner`, as a new
   process with `Setsid`, stdio on `/dev/null` and B as fd 3, send it
   `ClientLine` (0x40), and wait up to T2 = 15 s for `Ready` or `Failed`.
3. **Spawner** (`server.md` §2.1 step 4). Parse the line again, bind UDP,
   open the pty at the line's size (clamped by `screen.ClampSize`), start
   emu and proto, and have proto mint a credential (D20: TTL 30 s, at most
   2 unused per session). Proto returns it as `Credential` (0x30), within
   T3 = 10 s [choice]. **The spawner checks every field it owns**: the
   line must parse (`ParseCredentialLine`), re-marshal to the same bytes,
   and carry exactly the spawner's own advertised `addr` (or none), its own
   bound `port` and the session's `name` (`server.md` §3.4). Proto chooses
   only `credid`, `sid`, `psk` and `public`, the four things it
   alone knows; a compromised or buggy proto cannot choose where the
   client sends UDP. Only then does the spawner start
   the login shell with the line's environment (§6.2), type a `type`'s
   text once the shell has written its first output (§9.2.3), and send
   `Ready` (0x41) with the line.
4. **Launcher.** If the line says `!agent=yes` and sshd set
   `SSH_AUTH_SOCK`, trigger ssh's bind (§8, "Server"). Then write the line
   from `Ready` to stdout in **one** write.
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
overlaps the client's handshake (except with a `type`, whose `Ready`
waits for the shell's first output, §9.2.3). Starting it later would not protect
anything: the user's rc files have already run once for the same SSH login,
since sshd ran `SHELL -c` to start the launcher (§6.5 exists because rc
files print), and that login is the user. See the review notes (§15).

**Environment for the shell.** sshd's `SSH_AUTH_SOCK` (if any) dies with
the bootstrap connection, so the spawner never passes it to the shell; with
`!agent=yes` the shell gets mosey's own socket instead (`agent.md` §4.1). Other session
variables are `server.md`'s concern.

**Known hazard (fixed where the user lingers).** With systemd-logind's
`KillUserProcesses=yes` the detached session is killed when the SSH login
ends, as Mosh's server is. [S4] §3.10 ran it under `systemd-run --user`,
which survives. Decided (2026-11-23): the spawner moves itself into a
scope in the user's manager, `mosey-session-<pid>.scope`, whenever that
manager lives at least as long as the login (`server.md` §2.1 step 4.2):
for an ssh login, only when the user lingers (`loginctl enable-linger`),
since otherwise the manager stops soon after the login ends and would take
the session with it. So with linger a session survives
`KillUserProcesses=yes`; without it the hazard stands, and enabling
linger is the user's remedy. mosey does not enable linger itself: it keeps
the user's whole manager running from boot.

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
  {`amd64`, `arm64`}, and `android-arm64` (D10 as amended 2026-11-22; no
  `android-amd64`, which Go links only with cgo): Go's `GOOS` and `GOARCH` names, so the client's own
  is `runtime.GOOS` and `runtime.GOARCH`. Each is the bare static
  executable `scripts/build.sh` made (CGO off, `-trimpath`, linux with
  `GOEXPERIMENT=runtimesecret`, D1, D20), not an archive.
- **The checksums.** One asset named `SHA256SUMS`, in `sha256sum(1)`'s
  text format: per binary, 64 lower-case hex digits, two spaces, the
  asset's name, a newline, sorted by name. It lists the binaries only.
- **The build attestations** (S1, D7 as amended 2026-11-15, and again
  the same day: client-side checking removed). Not release assets: the
  release job attests each binary alone with
  `actions/attest-build-provenance`, which makes a Sigstore bundle (a DSSE
  envelope holding an in-toto statement of SLSA provenance v1,
  `https://slsa.dev/provenance/v1`, whose one subject is the binary, by
  its file name `mosey-<V>-<os>-<arch>` and its SHA-256; a short-lived
  Fulcio certificate whose subject alternative name is the workflow
  `https://github.com/danielbodart/mosey/.github/workflows/ci.yml@refs/heads/trunk`
  and whose OIDC issuer is `https://token.actions.githubusercontent.com`;
  and the Rekor entry that logged it) and stores it with the repository's
  attestations, on the public-good Sigstore instance (the repository is
  public). They are for a person to check a download by hand, with `gh
  attestation verify FILE --repo danielbodart/mosey`; the client does not
  fetch or check them (§4.7.4, §14 question C).
- **So** the binary for `os/arch` at version `V` is
  `https://github.com/danielbodart/mosey/releases/download/v<V>/mosey-<V>-<os>-<arch>`
  and its hash is the line of
  `https://github.com/danielbodart/mosey/releases/download/v<V>/SHA256SUMS`
  whose second field is that name.
- **The tag's commit, and `nix/release.json`** (Dan, 2026-11-15). The
  tag `v<V>` does not name the released trunk commit but a commit of its
  own, made by `github-actions[bot]`, whose one parent is that trunk
  commit and which adds one file, `nix/release.json`:
  `{"version": V, "assets": {SYSTEM: {"url": …, "hash": "sha256-<SRI>"}}}`
  for the Nix systems `x86_64-linux`, `aarch64-linux`, `x86_64-darwin`
  and `aarch64-darwin` (`linux-amd64`, `linux-arm64`, `darwin-amd64`,
  `darwin-arm64`), each URL the asset above and each hash its
  `SHA256SUMS` line in SRI form (`scripts/release-json.sh`). Only the tag
  is pushed; no branch has the commit. `flake.nix`'s package is that
  asset, fetched and installed as `bin/mosey` with version `V`, so
  `github:danielbodart/mosey/v<V>` gives the release's own binary (a
  flake sees its commit, never its tag, so the version has to be in the
  tree); on trunk there is no file and no package. The last release
  before a commit is the newest tag whose parent (or, for the tags made
  before this, whose own commit) is its ancestor
  (`scripts/last-release.sh`), and `scripts/release-due.sh` diffs from
  that parent.

**How the release job makes them.** After laying the binaries out and
checking their versions, it attests each binary in a step of its own
(`actions/attest-build-provenance`; every action in every workflow is
pinned by commit, because the release job holds the OIDC token that
signs as this repository's release workflow, the identity `gh attestation
verify --repo danielbodart/mosey` trusts, and attests what the build job
made; `scripts/actions-pinned.sh` refuses a tag). Only then is the
release created. A failure at any of these steps fails the job, so no
release is ever published with an unattested binary. Nor is one left
half-made by a newer push: that cancels the older run's testing, but
once its release job has started, the cancellation lets it finish
(`ci.yml`'s concurrency), and releases queue behind one another.

Why bare files: the hash in `SHA256SUMS` is then the hash of the very
bytes the client sends and the remote installs at
`~/.local/bin/mosey`, so one hash is checked on download, after the
copy, and against a file already there; and the client needs no archive
parser for a file from the network [derived]. Why the version in the name:
a downloaded file says what it is.

Mapping the remote's `uname -s` and `uname -m` to `os` and `arch`
(`Linux` → `linux`, `Darwin` → `darwin`, `x86_64` → `amd64`, `aarch64`
and `arm64` → `arm64`; anything else has no asset) is the auto-upload
slice's, as is the download itself. An Android host says `Linux`, so it
is sent `linux-<arch>`, which runs there; the `android-arm64` asset is
for a person installing a client on a phone, and an Android client,
whose `runtime.GOOS` is `android`, never sends itself to a `linux` host. `SHA256SUMS` comes over HTTPS from
the same release, so it catches corruption and a wrong file, not a
compromised GitHub account or CI; the client checking the build
attestation too is §14 question C, parked. A client of a development build (`dev`, or a local build's timestamp
patch) has no release, so it can upload only itself.

### 4.7 Auto-upload (D7)

D7, as Dan amended it on 2026-11-15: **the client installs itself only
where the host has no mosey it can use.** It uses whatever mosey the host
has, of whatever version. Upgrading is done by Nix or by replacing the
binary, never by the client while it moves between hosts; the next session
on that host runs the new binary.

The host's mosey is, in order: `mosey` on the remote `PATH`; otherwise the
single file `~/.local/bin/mosey`, asked for by its path, since the
non-login `ssh host cmd` that runs the probe may not have `~/.local/bin`
on `PATH`. When there is neither, or `~/.local/bin/mosey` (found either
way) speaks another protocol than the client (§4.7.2), the client copies
a static build to `~/.local/bin/mosey`, hash-checked, asking the first
time, never replacing a file someone else owns (Dan, 2026-11-16: "On a
protocol mismatch, mosey replaces that file after asking"). A `mosey` on
`PATH` anywhere else is never replaced. Nothing here changes the lines of
§6 or what a server does once it is running.

Why `~/.local/bin` (Dan, 2026-11-16, closing §14 question G): it is the
one directory the stock login profiles already put on `PATH` when it
exists (Debian's and Ubuntu's `~/.profile`, Fedora's `~/.bashrc`; the
XDG Base Directory spec names it for user executables), so a session
served from it can hop on with no rc file edited (§4.7.9).

```
client                                                     far host
------                                                     --------
ssh … "PROBE"   + ClientLine  ──────────────────────────►  mosey on PATH, not ~/.local/bin/mosey? exec it --serve
                                                           else ~/.local/bin/mosey, if its
                                                             --serve=protocol is the client's?    exec it --serve
                              ◄──────── MOSEY-PROBE 1 machine=x86_64 system=Linux   (neither: say what this host is)
ask the user (first time per host)
pick the binary: our own file, or the release asset, SHA-256 checked
ssh … "UPLOAD"  + the binary  ──────────────────────────►  mktemp in ~/.local/bin; cat; run it as
                                                           --serve=install HASH SIZE TEMP: checks, hash, rename
                              ◄──────── exit 0
ssh … "PROBE"   + ClientLine  ──────────────────────────►  ~/.local/bin/mosey --serve   (as §4.4)
```

#### 4.7.1 When it applies

Only when the user gave no `-remote` (§4.2).

**The probe and the roles.** Every command that runs a server role probes:
`mosey DEST`, `mosey -s NAME DEST` and `mosey -new DEST` (the launcher,
`--serve`, each with its own ClientLine `attach`, §9.2), R3's background
reconnect (the launcher again), `mosey -list DEST` (`--serve=list`, §9.4)
and `mosey -kill NAME DEST` (`--serve=kill`, §9.5). The probe runs the
host's mosey with that command's flag, so a host whose only mosey is the
one D7 put in `~/.local/bin/` is found by all of them. **Only the three
that the user typed to get a session upload.** When the probe answers
`MOSEY-PROBE`:

| Command | What the client does |
|---|---|
| `mosey DEST`, `mosey -s NAME DEST`, `mosey -new DEST` | §4.7.3–§4.7.8: ask, copy, start again |
| R3's background reconnect (§9.2.2) | nothing is copied and nothing is asked (D8 R3): the attempt fails, is logged, and is tried again after the backoff |
| `mosey -list DEST`, `mosey -kill NAME DEST` | nothing is copied: `mosey: no mosey on DEST, so no sessions: mosey DEST starts one, copying mosey there`, exit 1. Listing or ending is not a reason to install anything. |

`~/.local/bin` is literal: nothing in the remote's environment moves it.
The probe, the upload and the installer must agree on one path without a
round trip to ask, and D7 names this one.

#### 4.7.2 The probe

The remote command (one argument, as §4.1; `B H` is the client's
`--serve=protocol` answer, `bootstrap.Version` and `handshake.ProtocolVersion`,
now `1 1`):

```
exec /bin/sh -c 'b="$HOME/.local/bin"; f="$b/mosey"; p=$(command -v mosey 2>/dev/null); case $p in "$f"|"") ;; *) exec mosey FLAG;; esac; w=; for d in "$HOME/" "$HOME/.local/" "$b/"; do case $(ls -ld "$d" 2>/dev/null) in ?????w*|????????w*|"") w=1;; esac; done; if test -h "$b" || test -h "$f" || test -n "$w"; then :; elif test -O "$HOME/.local" && test -O "$b" && test -O "$f"; then if [ "$("$f" --serve=protocol </dev/null 2>/dev/null)" = "B H" ]; then exec "$f" FLAG; fi; p=; fi; if [ -n "$p" ]; then exec "$f" FLAG; fi; s=$(uname -s 2>/dev/null); a=$(uname -m 2>/dev/null); echo "MOSEY-PROBE 1 machine=${a:-unknown} system=${s:-unknown}"'
```

- **`PATH` first** (Dan, 2026-11-15). A `mosey` on the remote `PATH`
  other than `~/.local/bin/mosey` is exec'd with `FLAG`, the command's
  own (§4.7.1: `--serve` for the launcher, which reads the ClientLine as
  in §4.4, or `--serve=list`), as it is: it was put there by Nix, a
  package or the user, and upgrading it is theirs. It is not asked
  anything first. If it speaks another protocol, the bootstrap line or
  the handshake says so and the client fails with one line naming both
  numbers (§6.4, `transport.md` §3.6); it never replaces a file it did
  not install. "Other than" is the path `command -v` printed compared,
  as a string, with `$HOME/.local/bin/mosey`: what `PATH` resolved to,
  not what a link points at. A spelling that differs (a `HOME` with a
  trailing slash, or `PATH` naming the directory with one) therefore
  makes `~/.local/bin/mosey` count as another `PATH` mosey: exec'd as it
  is, and one of another protocol is reported, not replaced. That is
  accepted for its simplicity, and pinned by a test.
- **Otherwise `~/.local/bin/mosey`**, whether `PATH` found it or not
  (Dan, 2026-11-16: the file mosey installs is the one it may replace),
  under the installer's rules (§4.7.7): neither `~/.local/bin` nor the
  file is a symlink (`test -h`); they and `~/.local` (which may be one)
  are the user's (`test -O`, which follows a link); and neither the
  home, `~/.local` nor `~/.local/bin` may be written by its group or
  others (the group and other `w` of `ls -ld`'s mode string, which POSIX
  fixes and is the one portable way `/bin/sh` has to read a mode; a
  directory `ls` cannot read counts as writable). So the probe never
  asks a file from a place the installer would refuse to write, and
  nobody but the user (or root) can swap the file between the checks and
  the exec. It is asked `--serve=protocol` (server.md §1), with stdin on
  `/dev/null` (the ClientLine waiting on stdin is the launcher's) and
  stderr dropped, and exec'd only if it prints exactly the client's own
  answer. Its software version does not matter: a copy left by an older
  client that speaks the same protocol is used as it is. One that
  answers anything else gets the `MOSEY-PROBE` line, so the client
  offers to replace it (§4.7.5, §4.7.7), even when `PATH` found it.
- **A `~/.local/bin/mosey` on `PATH` that fails those rules** (a
  symlink, say, which the user made and mosey never would) is exec'd as
  it is, as any other `PATH` mosey is: the installer would refuse to
  replace it, so offering to would only fail, and the user's `PATH`
  chose it. Not on `PATH`, it is not run at all, as before.
- **`--serve=protocol`** prints one line, the bootstrap line version
  (§6.1) and the handshake protocol (`transport.md` §2.3), as decimals
  separated by a space: `1 1` now. It is the one thing every mosey answers
  the same way for ever (D8 V1), and since each number names only its
  layer's envelope (`versioning.md` §5), a copy of any later release
  answers the same until an envelope changes. The attach protocol (§9.2.1) is not in
  it: that is spoken between server binaries on one host, never by the
  client.
- **Neither:** one `MOSEY-PROBE` line on stdout, then exit 0. It does not
  say whether a `~/.local/bin/mosey` was there that the probe could not
  use: the install is the same either way (the installer replaces the user's own
  regular file and names what it refuses, §4.7.7), and one question
  covers both (§4.7.5). The probe never exits 126 or 127 itself, so
  `ErrNoServer` from an exit status means only what it meant in slice 1.
- **`command -v` and `test -O`.** `command -v` is POSIX. `test -O` is not,
  but dash, bash, BusyBox ash and the BSD and macOS `/bin/sh` all have it;
  a `/bin/sh` without it makes the test false, so `~/.local/bin/mosey`
  is not asked (but is exec'd if `PATH` found it, as above) and
  otherwise the client offers to copy, and the installer then says why
  it cannot.
- **Quoting.** The text inside the single quotes has no `'`, no `\` (fish
  reads `\'` and `\\` inside single quotes), no `!` and no newline (csh
  refuses a newline inside quotes), so every login shell of §4.1 passes it
  to `/bin/sh` unchanged [shells: run under each in §12's test].
- **Cost.** With a `mosey` on `PATH` elsewhere, one exec of `/bin/sh`
  on top of slice 1's command; otherwise three of `ls` and, with a
  `~/.local/bin/mosey`, one of `mosey --serve=protocol` (a Go binary's
  start, a few milliseconds). No extra round trip.

**The probe line**, read by `ReadCredential` (§6.5) like the other lines of
ours and fuzzed with them:

```
probe-line = "MOSEY-PROBE" SP "1" *(SP field) LF     ; §6.1, fields in key order
```

| Field | Value | Mandatory | Critical | Why critical or not |
|---|---|---|---|---|
| `machine` | `1*64(%x21-7E)`: `uname -m`, or `unknown` | mandatory | no | it describes the host; a wrong one gets a build that does not run, never a wrong action |
| `system` | `1*64(%x21-7E)`: `uname -s`, or `unknown` | mandatory | no | as `machine` |

At most 163 bytes [derived: 11, SP, 5 digits, ` machine=` 9 and 64,
` system=` 8 and 64, LF]; **`MaxProbeLine` = 256** [choice: room for
fields a later release adds]. Canonical as §6.1 asks. The shell prints
the fields in key order itself, so the script stays the one line above. `ReadCredential` returns
it as a `*NoServerError` (`errors.Is(err, ErrNoServer)`) carrying the
fields. A `uname` that prints a space or something longer gives a line
that does not parse, which is `ErrBadLine`: a host that odd has no release
asset anyway.

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
- **Otherwise:** the release asset of §4.6 for the client's **own
  version `V`** and the remote's os/arch (Dan: "we're gonna download it
  from GitHub, and we've asked the user"). Only a release version has
  one: `V` must match `MAJOR.MINOR.PATCH` with each part a decimal of at
  most 9 digits, no leading zero, and `PATCH` ≥ 1 (CI's run number)
  [derived from `scripts/version.sh`: a local build's patch is a 14-digit
  timestamp, a plain `go build` says `dev`; the flake installs a release's
  binary, so its version is a release's]. Anything else is a development
  build: `mosey: this is a development build (V) and DEST is OS/ARCH,
  which it cannot copy itself to: build mosey for OS/ARCH and put it at
  ~/.local/bin/mosey there, or pass -remote`.

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
  them: the release's build attestation (§4.6) would, but the client does
  not check it (§14 question C, parked: sigstore-go, which did, doubled
  the binary and was removed).

The SHA-256 of what is sent, and its length, go to the far host on the
upload's command line (§4.7.6), and the installer refuses anything else.

#### 4.7.5 Consent

`-upload` says what happens when the probe finds nothing it can use:

| `-upload` | |
|---|---|
| `ask` (default) | if this host is remembered, go on; else ask; `y` or `yes` (any case) goes on and remembers the host; anything else, or end of input, is no |
| `yes` | go on without asking; remember nothing |
| `no` | never copy: `mosey: DEST has no mosey: install it there, or run without -upload=no` |

**The question**, on stderr while the terminal is still cooked (§4.3),
after the probe's ssh has exited, so no ssh is reading `/dev/tty`:

```
mosey: DEST has no mosey this one can use. Copy this one (OS/ARCH, N.N MB) to ~/.local/bin/ there? [y/N] 
mosey: DEST has no mosey this one can use. Download mosey V for OS/ARCH from GitHub and copy it to ~/.local/bin/ there? [y/N] 
```

(the first for the client's own platform, the second for another, which is
asked before anything is downloaded). The same question covers a host
with no mosey at all and one whose `~/.local/bin/mosey` the probe could
not use, which the install replaces (§4.7.7).
The answer is one line read from the terminal, at most 64 bytes counted.
Every field in it is the client's own (the destination as typed, its
version, the platform mapped through §4.7.3), never a remote string.

**The first time** is per `user@hostname:port` as `ssh -G` resolved them
(§3; `user`, `hostname` and `port`), so an alias and its target are one
host, and two accounts on one host are two. Not per version. A remembered
host is a line in `$XDG_STATE_HOME/mosey/upload-hosts` (else
`~/.local/state/mosey/`), beside the log (§7.4): the file is 0600 in a
0700 directory, at most 1 MiB, one key per line, rewritten whole through a
temporary file and a rename. A key holds only bytes 0x21–0x7E and is at
most 1100 bytes; a host whose key cannot be written is asked each time.
Failing to read or write the file is logged, and the host is asked again
next time; it never stops a session. The state directory, not the config
one: the client writes it, and a home-manager user's `~/.config` may be
read-only.

The prompt goes through an interface (`client.Options.Ask`) so tests
answer it. `cmd/mosey` reads the answer from the terminal it already
requires (§4.3: stdin and stdout must be one).

#### 4.7.6 The upload

The same ssh as §4.1, every option the same (one fresh connection, nothing
forwarded), with this remote command (`HASH` as 64 lower-case hex digits,
`SIZE` in decimal):

```
exec /bin/sh -c 'umask 077; d="$HOME/.local/bin"; mkdir -p "$d" || exit 1; t=$(mktemp "$d/.upload.XXXXXXXX") || exit 1; cat >"$t" && chmod 700 "$t" && "$t" --serve=install HASH SIZE "$t"; s=$?; rm -f "$t"; exit $s'
```

- **stdin is the binary**, written whole and then closed; nothing else.
  ssh's stdout is drained (at most 64 KiB, then discarded: rc files
  print). ssh's stderr goes to the user through §6.5's filter, which is
  how the installer's refusals are read.
- **`umask 077`**: every directory and file the shell makes is the user's
  alone, `~/.local` and `~/.local/bin` included when they are missing.
  A `~/.local/bin` made here reaches `PATH` at the user's next login,
  when the profile sees it exists (§4.7.9); the session's own login
  shell starts after the install, so it is one of those. **`mktemp`**
  creates the file with `O_EXCL`, so the shell never writes through a
  name someone planted [mktemp(1): GNU coreutils,
  busybox and macOS all create mode 0600 with `O_EXCL`]. The temporary file
  sits in `~/.local/bin`, not `/tmp`: `/tmp` is often `noexec`, and the
  rename into place must stay on one filesystem. Its name starts with a
  dot and lives only while the installer runs.
- **The copy installs itself.** The shell runs the uploaded file as
  `--serve=install` (§4.7.7). Running it proves it runs on that host, and
  the checks are Go's, not whatever `sha256sum` or `shasum` the host has
  (macOS has no `sha256sum`). A copy cut short in transit does not start
  (its ELF segments run past the end of the file) and so installs nothing;
  one that starts hashes its own file through the descriptor it checks,
  and refuses any byte that differs. That catches a copy damaged in transit or
  left half-written by a crash. It does not catch one replaced on the far
  host by something running as the user, which could make the installer
  say anything: the check runs on the far side, by the file it checks, and
  the client never checks what is installed (T12, threat-model §4.13).
- **`rm -f "$t"`** after the installer, whatever it said: after a success
  the name is gone already (renamed), after anything else the partial
  file goes. `exit $s` passes the installer's status to ssh.

ssh's exit status:

| Status | Meaning | Client says (exit 1) |
|---|---|---|
| 0 | installed | `mosey: copied mosey to DEST` and goes on (§4.7.8) |
| 126 | the copy would not run | `mosey: the copy of mosey would not run on DEST: is ~/.local/bin on a filesystem mounted noexec?` |
| 255 | ssh failed | `mosey: ssh to DEST failed` |
| other | refused or failed; stderr has said why | `mosey: copying mosey to DEST failed (exit N; see above)` |

#### 4.7.7 The installer: `mosey --serve=install HASH SIZE TEMP`

A server role (`server.md` §1) that runs once, from the uploaded file, and
is the only code that writes `~/.local/bin/mosey`. It is not sandboxed
(it must write the user's home) and reads nothing from the network. In order:

1. **Arguments.** Exactly three. `HASH` 64 lower-case hex digits; `SIZE`
   a decimal from 1 to `MaxBinary`; `TEMP` exactly
   `$HOME/.local/bin/.upload.` followed by 1 to 64 `pathchar`s other
   than `/`. `HOME` must be absolute. Anything else: refused.
2. **Home.** `open($HOME, O_DIRECTORY)`, following symlinks (a home under
   `/home → /usr/home` is ordinary). It must be owned by the user or root
   and writable by neither group nor others: sshd's own `StrictModes` rule
   for the home directory [sshd_config(5)].
3. **`~/.local`.** Created 0700 if absent. Opened relative to the home's
   descriptor, **following a symlink** here only: a `~/.local` that is a
   link to another disk is the user's own doing. What it resolves to
   must be a directory owned by the user and writable by neither group
   nor others.
4. **`~/.local/bin`.** Created 0700 if absent, then opened relative to
   its parent's descriptor with `O_NOFOLLOW | O_DIRECTORY`: a symlink is
   refused (`ELOOP` or `ENOTDIR`), so nothing planted can send the
   install elsewhere. It must be owned by the user and writable by
   neither group nor others; the usual 0755 is fine.
5. **The upload.** `TEMP`'s last component, opened relative to
   `~/.local/bin` with `O_NOFOLLOW`: a regular file, owned by the user,
   one link, exactly `SIZE` bytes, and SHA-256 equal to `HASH`, all read
   through that one descriptor. On a mismatch it is unlinked and the
   installer refuses.
6. **What is there now.** `fstatat(~/.local/bin, "mosey",
   AT_SYMLINK_NOFOLLOW)`: absent is fine; a regular file owned by the user
   is replaced (§4.7.2: one that speaks another protocol); a symlink, a
   directory, anything else, or **a file owned by anyone else** is refused
   and left exactly as it is (D7: never replaces a file someone else
   owns).
7. **Install.** `fchmod 0700`, `fsync` and `fstat` on the upload, then
   `renameat(~/.local/bin, TEMP, ~/.local/bin, "mosey")`, atomic
   within the filesystem. `rename(2)` takes names, so TEMP is looked up
   again here: `fstatat(~/.local/bin, "mosey", AT_SYMLINK_NOFOLLOW)`
   must then show the device and inode of the descriptor that was
   hashed, or the file is unlinked and the installer refuses. Then
   `fsync` of `~/.local/bin`. A session running from the file it
   replaces is unaffected: its processes keep the old file open, and its
   spawner re-executes its roles through `/proc/self/exe`, never by path
   (`server.md` §2.3, threat-model §4.11), so they are the old binary too.

Every step works through the descriptors of the step before
(`openat`, `mkdirat`, `fstatat`, `renameat`), so no directory is looked up
twice and no symlink can redirect a step. The one name looked up twice is
TEMP, by the rename, inside `~/.local/bin`, which only the user can
write; step 7's inode check catches a swap there after the fact. Exit 0 and nothing
on stdout on success; on any refusal one line on stderr,
`mosey --serve=install: WHAT`, naming the path and the rule, and exit 1.

Other users: `~/.local/bin` is under the user's home and every directory
on the way is the user's alone, so another user can neither plant nor
replace a file there. The same user can (threat-model T12), which is why the copy is never
a trust anchor (S7 §10, threat-model §4.13).

#### 4.7.8 Starting again

After a 0 exit the client runs §4.1 once more with the probe, the same
config and the **same** ClientLine: its one-shot key was never used, since
no launcher read the first line, and the key is public anyway (B3 needs
SSH authentic, not confidential). If this second probe also says
`MOSEY-PROBE`, the client stops: `mosey: copied mosey to DEST, but it is
still not found there` (no loop). Anything else proceeds or fails exactly
as a first attempt would.

#### 4.7.9 Hopping on

`mosey otherhost` typed inside a session finds a mosey to carry on with
(D7: "a host can hop on with it") wherever the login profile puts
`~/.local/bin` on `PATH`, which the stock profiles do when the directory
exists: Debian's and Ubuntu's `~/.profile`, Fedora's `~/.bashrc` (Dan,
2026-11-16, closing §14 question G). No rc file is edited. A
`~/.local/bin` that the install itself made is there before the session's
login shell starts (§4.7.8 starts again after the install), so that
shell's profile sees it; any other shell already open on the host sees
it at its next login.

As well, a session whose server is `~/.local/bin/mosey`, on a host whose
spawner `PATH` lacks `~/.local/bin`, gets it put first on its login
shell's `PATH` (`server.md` §2.5). That covers a shell whose profile adds
to `PATH` without naming `~/.local/bin`; a profile that sets `PATH`
outright (Debian's `/etc/profile`, NixOS's `set-environment`) undoes it,
and on Debian `~/.profile` then adds `~/.local/bin` back.

**NixOS needs mosey from Nix** to hop on: no stock NixOS profile puts
`~/.local/bin` on `PATH`. Hopping is proven by §12's e2e test for a shell
whose profile keeps `PATH`; `tests/install.nix` covers the install only.

#### 4.7.10 Costs and failures

The first session on a host with no mosey costs three SSH logins (probe,
upload, start) instead of one, and one prompt the first time ever per
host; every later session, one login, whichever client version runs it.
Upgrading the client does not touch the host: a host keeps the mosey it
has until Nix, a package or the user replaces it, or, for
`~/.local/bin/mosey`, until a client of another protocol replaces it.

| Situation | What happens |
|---|---|
| offline, same platform | nothing needs the network: the copy is the client's own file |
| offline, other platform | §4.7.4's fetch error and the advice to copy it by hand |
| development build, other platform | §4.7.4's message, before any download |
| no consent | `mosey: not copying mosey to DEST` |
| `mosey` on `PATH`, not `~/.local/bin/mosey`, of another protocol | `mosey: DEST's mosey speaks protocol P; this mosey speaks N` (§6.4), exit 1; nothing is copied |
| `~/.local/bin/mosey` of another protocol, on `PATH` or not | the question of §4.7.5, then the install replaces it |
| `~/.local/bin` is a symlink, or `~/.local/bin/mosey` is a symlink or someone else's | the installer refuses (stderr says which), exit 1 |
| `~/.local/bin` on a `noexec` mount | upload exit 126, §4.7.6 |
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
| `yes` | `identityagent` if it names a socket (or `$VAR`); `$SSH_AUTH_SOCK` if it is unset or `SSH_AUTH_SOCK`; agent off if it is `none`, or the socket is empty [ssh: checked black-box against OpenSSH 10.6p1 by `TestForwardAgentYesForwardsTheIdentityAgent`: `IdentityAgent none` with `ForwardAgent yes` forwards nothing] |
| starts with `$` | the environment variable it names ([ssh]: printed verbatim, e.g. `$FOO`); unset or empty means agent off |
| anything else | that path ([ssh]: `ssh -G` has already expanded `~`) |

It is a pure function of `Config` and the environment (`AgentSocket`, unit
tested). A session on this machine, with no ssh, decides otherwise (§2.2).
Off: the bootstrap runs with `ForwardAgent=no`, the ClientLine says
no `!agent` field, and the Hello has no `ChannelAgent`. On: §8, and `agent.md`.

---

## 6. The lines

### 6.1 Common rules

Every line of this document, and the attach socket's greeting (§9.2.1),
is in the one grammar of `versioning.md` §6: a tag, a protocol number,
then `key=value` fields in ascending key order, a `!` before the key of
a critical one, ending in one LF. That section is normative; in short:

```
line   = tag SP number *(SP field) LF
field  = ["!"] key "=" value         ; key: a-z first, then a-z 0-9 -, 1..16 bytes
value  = 1*(%x21-7E)                 ; printable ASCII, no space
```

- **The tag and the number are frozen for ever** as the first two words,
  so any version of mosey can tell a line it cannot read from a line that
  is not its own, and name the number it saw. The number is the
  bootstrap protocol's, `bootstrap.Version`, now **1**, on every line of
  this section and on the ProbeLine and ListLine (§4.7.2, §9.4); the
  greeting carries the attach protocol's instead (§9.2.1). The
  ErrorLine's grammar, its bound included, is frozen in full, so a
  client of any version can read any server's refusal (§6.4).
- **Must-ignore, critical marked** (`versioning.md` §2, §3). A field the
  parser does not know is dropped before anything is decided, unless
  its key has a `!`, which refuses the line. Each line's table below
  says, for every field, whether it is mandatory and whether it is
  critical, and why; a known field must carry exactly that marking. A
  missing mandatory field refuses the line.
- **Absent, never `-`.** A field with nothing to say is left out: no
  `-` placeholders, no empty values. A boolean is `yes` or absent.
- **Binary values** are base64url without padding (RFC 4648 §5), decoded
  strictly (`base64.RawURLEncoding.Strict()`: unused trailing bits must
  be zero), and must decode to exactly the stated length. Why base64url:
  no `+` or `/`, so nothing a shell, a log viewer or a recorder might
  mangle.
- **Decimal values** are `0` or a non-zero digit followed by digits: no
  sign, no leading zero.
- **Canonical.** A parser accepts a line only if marshalling what it
  parsed gives back the same bytes with the unknown fields left out. The
  fuzz targets check exactly this, and that an unknown field without
  `!` changes nothing while one with `!` is refused (§12).
- **One number, strictly** (D8 V1). Each build speaks exactly one line
  number. Its parser refuses any ClientLine, CredentialLine, ProbeLine
  or ListLine whose number is another, before reading the rest, with an
  error that carries the number it saw (`*VersionError`, §10.1). The
  ErrorLine is the exception: its parser accepts any number, since its
  whole grammar is frozen. There is no range and no fallback: a mismatch
  fails the bootstrap with one line naming both numbers (§6.4).
- **Stable** (D8 V1, `versioning.md` §5). The number names the grammar
  above and each line's mandatory fields, nothing more. A new field is
  optional, and is critical or not by `versioning.md` §3; a new value
  of a known field is a new field, or a feature (`versioning.md` §4).
  Neither changes the number. No line carries a software version, and
  nothing compares one (Dan, 2026-11-15: "when I use SSH I don't really
  worry about the version stuff").

```
dec     = "0" / (%x31-39 *DIGIT)
b64(n)  = base64url, no padding, of exactly n bytes
word    = 1*64( ALPHA / DIGIT / "." / "_" / "+" / "-" )
```

### 6.2 ClientLine: client → server, on ssh's stdin

```
client-line = "MOSEY-CLIENT" SP "1" *(SP field) LF     ; fields in key order
```

| Field | Value | Mandatory | Critical | Why critical or not |
|---|---|---|---|---|
| `!agent` | `yes`; absent for no | optional | yes | it instructs: the server makes the agent socket and triggers ssh's bind (D25, §8). Ignored, the shell would get no agent and the client would learn it only at its capture's deadline (§8) |
| `!attach` | `attach` below | mandatory | yes | it selects which session, and `resume:SID:CREDID` restricts the takeover to a session still held by CREDID (§9.2.2) |
| `!cmd` | `b64text` of a `cmdtext` | optional | yes | it instructs: run this in place of the shell, and `auto` matches on it (§9.2). Ignored, the user would get a shell, or a detached session that runs something else |
| `cols` | `dec`, 1..65535 | mandatory | no | it describes the client's terminal; the server clamps it, and the client sends its size again as its first event |
| `!dir` | `b64text` of a `dirtext` | optional | yes | it instructs: start here. Ignored, what the user types next would run in another directory |
| `env` | `var *("," var)` | optional | no | it describes the client's locale and terminal; a server that dropped it would give the shell the default locale |
| `!public` | `b64(1216)` | mandatory | yes | it authenticates: the client's one-shot X-Wing key (D20) |
| `rows` | `dec`, 1..65535 | mandatory | no | as `cols` |
| `!type` | `b64text` of a `typetext` | optional | yes | it instructs: type this into the new shell. Ignored, the session would start without what the user asked to run |

```
attach  = "auto"                    ; R1: the newest detached session started with this cmd (or none), else a new one (§9.2)
        / "new"                     ; -new: a new session with a generated name
        / "name:" sname             ; -s NAME: NAME, taken over if attached, else started
        / "new:" sname              ; launcher → spawner only: start a session called sname
        / "resume:" b64(16)         ; launcher → attach socket: take over session SID
          [":" b64(8)]              ; R3: ... only if it is detached or held by this credential
sname   = (ALPHA / DIGIT) 0*31(ALPHA / DIGIT / "-" / "_" / ".")
var     = name "=" 1*64vchar        ; names strictly ascending (byte order), no repeats
name    = "COLORTERM" / "LANG" / "LANGUAGE" / "LC_ADDRESS" / "LC_ALL"
        / "LC_COLLATE" / "LC_CTYPE" / "LC_IDENTIFICATION" / "LC_MEASUREMENT"
        / "LC_MESSAGES" / "LC_MONETARY" / "LC_NAME" / "LC_NUMERIC"
        / "LC_PAPER" / "LC_TELEPHONE" / "LC_TIME" / "TERM"
vchar   = ALPHA / DIGIT / "." / "_" / "@" / ":" / "+" / "-"
b64text = base64url, no padding, of 1..1024 bytes
dirtext = 1..1024 bytes of UTF-8, no control character (Unicode Cc)
typetext = 1..1024 bytes of UTF-8, no control character (Unicode Cc) but TAB
cmdtext = typetext
fgtext  = 1..48 bytes of UTF-8, no control character (Unicode Cc)
cwdtext = 1..192 bytes of UTF-8, no control character (Unicode Cc)
```

| Field | Meaning |
|---|---|
| `attach` | which session (D8, §9.2): `auto` for a plain `mosey DEST` or `mosey DEST COMMAND`, `new` for `-new`, `name:NAME` for `-s NAME`, and `resume:SID:CREDID` for R3's background reconnect, naming the session and the credential this client last held it with. `new:NAME` and `resume:SID` are what the launcher, having chosen, hands the session's spawner (§9.2), with a reconnect's CREDID kept (§9.2.2); a launcher refuses `new:NAME` from a client with `line`. The all-zero SID is refused: no session has it |
| `agent` | whether the client will forward an agent (D25). The server needs it at spawn time to give the shell an `SSH_AUTH_SOCK` (`agent.md` §4.1) and, for `new` and resume alike, to trigger ssh's bind (§8) |
| `cols`, `rows` | the client terminal's size; a terminal that reports 0 is sent as 80×24. The server clamps it (D23, `screen.ClampSize`). The client sends its size again as the first userinput event after connecting, in case it changed during the bootstrap |
| `env` | the client's locale and terminal variables, from the allow-list only. A variable that is unset, empty, longer than 64 bytes or holds a byte outside `vchar` is left out (logged at debug), never escaped; with none, the field is absent. The server gives the locale variables to the shell; what it does with `TERM` and `COLORTERM` is `server.md`'s (the shell's `TERM` describes the server's emulator, not the client's terminal) |
| `dir` | `-dir`: the directory a new session's login shell starts in, relative to the remote `$HOME` unless absolute (§9.2.3). Absent: the shell starts in `$HOME` (`server.md` §2.5). Only a session the line creates uses it |
| `type` | `-type`: the text typed into a new session's pty once its shell has started, followed by Enter (§9.2.3). Only a session the line creates uses it |
| `cmd` | the command after `DESTINATION` (§2), joined with spaces, run as `SHELL -c CMD` in place of the interactive shell (§9.2.3). Only a session the line creates runs it; with `auto` it is also what the launcher matches a detached session on (§9.2). A line with `cmd` and `type` is refused (`line`) |
| `public` | the client's one-shot X-Wing encapsulation key, `OneShotKey.PublicKey()`, 1216 bytes [S1, measured from `crypto/hpke`] |

`dir`, `type` and `cmd` are base64url because a path or a command holds
spaces, and §6.1 keeps every value free of them; base64url keeps the line
printable ASCII whatever the user typed, and its strict decoding keeps
the line canonical. The text inside is still checked: valid UTF-8 (Go's
`utf8.Valid`) and no rune for which `unicode.IsControl` holds, but TAB in
`type` and `cmd`. So a `-dir` cannot smuggle a NUL or a newline into a
path, and a `-type` cannot carry an Enter of its own (a second command),
an ESC (a line editor's key binding) or a Ctrl-C [choice: one line of
ordinary text, with tab kept because a user may type it]. The bound is
1024 bytes each [choice: `PATH_MAX` on macOS, so any of our platforms can
name the directory; for `type`, a quarter of the 4096 bytes termios(3)
says a canonical-mode line holds, so the text and its Enter always arrive
as one line the shell can read; for `cmd`, a command a user types on one
line].
The check keeps out control characters, not the line editor: what is
left arrives as if the user typed it, so a TAB starts completion in bash
and zsh, and where readline's `convert-meta` is on (bash's default in a C
or 8-bit locale) a byte of 0x80 or above is read as a Meta chord. The
text is the user's own, so that is what typing it would do anyway.

**A server that does not know a critical field** (one from a later
release, say) refuses the line with `MOSEY-ERROR 1 !code=unsupported
detail=KEY` (§6.4), and the client says `mosey: DEST's mosey can't do KEY
yet`: a server never starts a session without doing what the line asked.

Size: at most 5756 bytes [derived: `MOSEY-CLIENT 1` 14; ` !agent=yes` 11;
` !attach=` and the longest attach, `resume:SID:CREDID` at 41, 50;
` cols=` and ` rows=` 11 each; ` !dir=` 1372 (the base64url of 1024
bytes is 1366); ` env=` 1282 (at most 1277: 156 bytes of names, 17 × 65
for `=` and value, 16 commas); ` !public=` 1631; then either ` !type=`
1373 or ` !cmd=` 1372, never both; LF 1]. **`MaxClientLine` = 8192**
[derived: the next power of two, so the server's read bound is fixed and
generous, and over 2 KiB is left for fields a later release adds].

Why not pass the environment as ssh `SendEnv`: sshd's `AcceptEnv` decides
what arrives, differently on every host, and the values arrive in the
environment of a process the server cannot validate first. On the line, the
grammar is ours and the parser is fuzzed.

Example (key shortened; `c3Jj` is `-dir src`):

```
MOSEY-CLIENT 1 !attach=new cols=211 !dir=c3Jj env=COLORTERM=truecolor,LANG=en_GB.UTF-8,TERM=xterm-256color !public=nW3b…Qe8 rows=58
```

### 6.3 CredentialLine: server → client, on ssh's stdout

```
cred-line = "MOSEY-CONNECT" SP "1" *(SP field) LF     ; fields in key order
```

| Field | Value | Mandatory | Critical | Why critical or not |
|---|---|---|---|---|
| `!addr` | `ipv4 / ipv6`, below; absent for none | optional | yes | it selects where the client sends its UDP (§7.2) |
| `!credid` | `b64(8)` | mandatory | yes | it authenticates: `handshake.Credential.ID` [S1: 8 bytes, our choice] |
| `existing` | `yes`; absent otherwise | optional | no | it describes what happened: the command was not run, and the client says so. The attach is the same either way |
| `name` | `sname` (§6.2), 1..32 | mandatory | no | it names the session to the user; nothing is decided by it (R3 resumes by `sid`, §9.2.2) |
| `!port` | `dec`, 1..65535 | mandatory | yes | it selects where the client sends its UDP |
| `!psk` | `b64(32)` | mandatory | yes | it authenticates: `Credential.PSK` [S1] |
| `!public` | `b64(1216)` | mandatory | yes | it authenticates: `Credential.ServerPublic`, the server's one-shot X-Wing key [S1] |
| `!sid` | `b64(16)` | mandatory | yes | it selects: `Credential.SessionID`, the session the handshake binds (`transport.md` §3.4), named for resume (D8) and in the logs |

```
ipv4 / ipv6   ; netip.Addr.String() form, no zone, never 4-in-6;
              ; not unspecified, multicast or 255.255.255.255
```

| Field | Meaning |
|---|---|
| `addr` | the server's address as SSH reached it: the third field of `SSH_CONNECTION`, parsed with `netip.ParseAddr`, unmapped (`Unmap`) and with any zone dropped. Absent if there is no `SSH_CONNECTION`, it does not parse as four fields, or the address is one the grammar forbids. Set by the spawner from its own environment; proto must copy it exactly (§4.4 step 3) |
| `port` | the UDP port the spawner bound; likewise the spawner's, checked |
| `name` | the session's name (D8 R2): the one the user gave with `-s`, or the one the launcher generated. The client shows it and keeps it, in memory only, for R3. Its grammar is letters, digits and `-_.`, so it is safe to print as it is |
| `existing` | present only in answer to a ClientLine with a `cmd`, when the line took a session that was already running and was not started with that `cmd`, so the command was not run (§9.2.3: `name:NAME` only, since `auto` takes only a session started with the same `cmd`); the client says so |

The parser is canonical, so `addr` must be exactly what `netip.Addr.String()`
gives for an unmapped, zone-free address: `::ffff:192.0.2.1`, `fe80::1%eth0`
and `0192.0.2.1` are refused. It also refuses, as `ErrBadLine`, any address
no server can legitimately have reached SSH on (threat-model §4.9): the
unspecified `0.0.0.0` and `::` (`IsUnspecified`), multicast `224.0.0.0/4`
and `ff00::/8` (`IsMulticast`), and the limited broadcast
`255.255.255.255`. These are properties of the address alone, so they
belong to the grammar and the fuzzer; the checks that need the client's own
interfaces or config are §7.2's.

Size: at most 1853 bytes [derived: `MOSEY-CONNECT 1` 15; ` !addr=` and
the longest IPv6 text, 39, 46; ` !credid=` 20; ` existing=yes` 13;
` name=` 38; ` !port=` 12; ` !psk=` 49; ` !public=` 1631; ` !sid=` 28;
LF 1]. **`MaxCredentialLine` = 2048** [derived: the next power of two].

The client turns it into a `handshake.Credential` (ID, SessionID, PSK,
ServerPublic) and a UDP destination (§7.2). `bootstrap` does not import
`handshake` (architecture §1); `internal/client` does the conversion.

### 6.4 ErrorLine: server → client, on ssh's stdout

```
error-line = "MOSEY-ERROR" SP number *(SP field) LF   ; number: 0..99999, any
```

| Field | Value | Mandatory | Critical | Why critical or not |
|---|---|---|---|---|
| `!code` | `1*16(%x61-7A)`, a lower-case word | mandatory | yes | it decides what the client does: which message, which exit status, whether R3 stops retrying (§9.2.2) |
| `detail` | `word` | optional | no | it fills in the message: a field's name, two numbers, a time |

This grammar, **and its bound `MaxErrorLine` = 256 bytes**, is frozen in
full, for every number: a client of any version must be able to read any
server's refusal, and no server may send a longer one. It freezes the
*shape*, not a list of values: `code` is any lower-case word of 1 to 16
letters, so a later version can add a code and an older client still
parses the line, and a later field is skipped as any unknown field is.
The longest line of the two fields is 112 bytes [derived: `MOSEY-ERROR`
11, SP, 5 digits, ` !code=` 7 and 16 letters, ` detail=` 8 and a 64-byte
word, LF]; 256 [choice] leaves room for fields a later release adds.

A client reading a code it does not know treats it as `internal` (the
generic message below, with the code shown in it). The codes defined so
far:

| Code | When | `detail` | Client says (exit 1) |
|---|---|---|---|
| `line` | the stdin line is malformed or not alone | absent | `mosey: the server could not read this client's request: a bug, please report it` |
| `version` | the ClientLine's number is not the server's line number (§6.1) | absent | `mosey: DEST's mosey speaks protocol P; this mosey speaks N`, P being the ErrorLine's number. A CredentialLine or ProbeLine of another number (`*VersionError`) gets the same message |
| `attach` | `name:NAME` or `resume:SID…` names a session whose spawner speaks another attach protocol (§9.2.1), which this launcher cannot attach | `P-N`: that spawner's attach protocol, then the launcher's | `mosey: session NAME on DEST speaks attach protocol P; DEST's mosey speaks N`, from the detail alone, so it names both numbers even where the launcher's stderr is not shown (R3's reconnect logs it); `-kill` says the same |
| `unsupported` | the ClientLine has a critical field this server does not know (§6.2), or a value of one it does not yet accept | the field's key | `mosey: DEST's mosey can't do F yet` |
| `session` | `resume:SID…` names no session of this user that answers (§9.2) | absent | R3's reconnect (§9.2.2): `mosey: session NAME on DEST has ended: its shell exited, or the host restarted` |
| `taken` | R3's `resume:SID:CREDID` finds its session held by another credential than CREDID: another client has taken it over (§9.2.2, D26) | when that client attached, in unix seconds | `mosey: session NAME taken over by another client at TIME` (exit 3, as §9.1) |
| `dir` | the line would create a session and its `dir` is not a directory the launcher can reach (§9.2.3); no session was started | absent | `mosey: DIR is not a directory on DEST, so no session was started`, DIR as the user gave it |
| `internal` | the server failed to start the session; stderr says why | absent | `mosey: the server failed to start (see above)` |
| any other word | a later server's code | any | `mosey: the server refused: CODE (see above)` |

An ErrorLine with an unknown critical field is refused like any other
line of ours that does not parse (§6.5): the client still fails, saying
the server's answer was malformed.

**No software versions** (D8 V1, as amended by Dan on 2026-11-15 and
2026-11-17). Client and server of different mosey versions is normal and
must work: no line carries a software version and nothing compares one.
What two builds must agree on is one protocol number per layer, and it
names only that layer's envelope (`versioning.md` §5): the bootstrap
lines' here (§6.1), the handshake's (`transport.md` §2.3, §3.6) and,
between server binaries on one host, the attach protocol's (§9.2.1).
Each is checked for equality, and a mismatch fails with one line naming
both numbers. Everything else is an element a receiver either knows or
skips, or refuses because it is critical. D7 uses whatever mosey the
host has (§4.7); the host's mosey is upgraded by Nix or by replacing the
binary, and new sessions use it. A session of an older binary goes on
running that binary until it ends. There is no live upgrade (Dan,
2026-11-15).

The ErrorLine carries the server's own number, which is how the client
names the server's.

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
3. A protocol line longer than its maximum (2048 for CONNECT, 256 for
   ERROR, 256 for PROBE) is fatal. A skipped line may be any length; it counts against
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
          ┌─────▼──────┐ ErrorLine ─────────────► Failed(code)    (D7: a ProbeLine on a new attach → Uploading)
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
| loopback (`127.0.0.0/8`, `::1`) while the **destination is not loopback** | sshd reached over a local forward or tunnel (a `ProxyCommand` to socat or cloudflared, a container port mapping) reports a loopback `SSH_CONNECTION`; sending there reaches the client's own host | here |
| link-local (`fe80::/10`) with no zone the client can supply | the server's zone means nothing here | here: usable only if `hostname` parses as the same address *with* a zone, which is then used |

The **destination is loopback** when every address `hostname` resolves to
is loopback (`localhost`, `127.0.0.1`, `::1`, the test harnesses). So a
loopback `addr` is used when the user really did ssh to their own host,
and otherwise skipped in favour of `hostname`; server.md binds the wildcard
for a loopback `SSH_CONNECTION` (§4.4) so that fallback is reachable.

A refused `addr` that is not a grammar violation (rows 4–5) is not fatal by
itself: it is logged (warn) and the client goes on to `hostname`. A
grammar violation is `ErrBadLine` before §7.2 runs, because no honest server
sends one. `hostname`'s results are the user's own config and DNS, so a
refused one is skipped, not reported as hostile.

The rules are a pure function, `ChooseAddr` (§10.1), with the resolver
injected, so the unit tests and the fuzzer reach every row without a
network.

A **directed broadcast** of one of the client's own subnets (`10.0.0.255`
on `10.0.0.0/24`) is not in the table: the kernel refuses it. Linux and
macOS fail a send to any address their routing table marks as broadcast
with `EACCES` unless the socket set `SO_BROADCAST` [Linux ip(7), BSD
`ip_output`]. Go's `net` sets it on every IPv4 UDP socket [M: Go 1.27,
a send to the desktop's `10.0.0.255` went out], so the client clears it
on its socket (below), and a hostile `addr`
naming one fails the handshake's first send instead of reaching the
neighbours. The client once checked this itself, from `net.InterfaceAddrs`
on every attach and reconnect; that is a netlink dump under the kernel's
global `rtnl_lock`, which a misbehaving network driver held for 5–25 s at
a time on Dan's desktop [M, 21 November 2026], leaving every new terminal
blank for as long, to duplicate a rule the kernel already enforces. A test
(`TestTheKernelRefusesALocalDirectedBroadcast`) sends to one from the
client's own kind of socket, so a platform without the rule fails loudly.

If `ssh -G` shows a `proxyjump` or `proxycommand`, the client prints a
one-line notice on stderr, before Dial while the terminal is still cooked
(and logs it), that UDP goes straight to ADDR:PORT, not through the proxy. Via a jump host,
`SSH_CONNECTION` holds the address the jump host reached, which the client
may not be able to reach at all; Mosh's man page documents the same
problem and offers a choice of address sources [mosh-man,
`--experimental-remote-ip`]. Choosing among them is a later flag (open
question 6); slice 1 tries `addr` and, if the handshake times out, says
which address it tried.

The client's socket is bound to the wildcard address of the chosen
address's family, unconnected, so roaming (D21) needs no new socket. An
IPv4 one has `SO_BROADCAST` cleared, which is what makes the kernel refuse
a directed broadcast (above).

### 7.3 Dialling and the terminal

`transport.Dial(ctx, pc, addr:port, cred, key, log)` with a deadline of
**30 s** [derived: `handshake.CredentialTTL`; after it the credential is
dead on the server anyway]. On timeout: `mosey: no reply from ADDR:PORT
over UDP: is UDP port PORT open?` (the classic firewall case). Then
`key.Wipe()` either way.

Only after Dial succeeds does the client put the terminal in raw mode and
start `client.Session` (§4.3: ssh's prompts need a cooked terminal). A
client told to go (`SIGHUP`, `SIGTERM`) before Dial does not start it: a
handshake begun then could leave the server holding a client that never
speaks until `SilentAfter`. If raw mode fails after Dial, the client
leaves as any detach does (§2's `-close-if-idle`, then END), never by
just closing the connection. The
Hello it sends: `Protocol` = `handshake.ProtocolVersion`, `Channels` = `{Terminal}`,
plus `Agent` when §5 says on and §8 captured and pinned a bind, `Attach` =
`Exclusive` (D26: the only mode in v1). So with the agent on, Dial waits
for the capture's final state (§4.3), which costs nothing when the bind
came (it was in before the line) and at most until ssh exits when it did
not.

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

## 8. Bind capture (D25)

The design is S3's option (a′), whose hardening is required, not optional
([S3] recommendation 1–5). The state machine's exact rules, the pin's and
the replay's are `agent.md` §2 and §3; this section is the procedure.

**Client.**

1. If §5 says on: make a directory with mode 0700 (under
   `$XDG_RUNTIME_DIR/mosey/`, else `os.TempDir()/mosey-UID/`, checked to be
   ours and 0700), and listen on `cap-HEX.sock` in it, `HEX` 16 random
   bytes, socket mode 0600, unlinked on close.
2. Run the bootstrap ssh with `-o ForwardAgent=PATH`, send `!agent=yes`.
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
5. Read the result once it is **final**: at EOF on the one connection
   (nothing more can arrive on it, and nothing can connect), or when ssh
   has exited with no connection made, or at the deadline. The server
   controls no timer that matters: holding the connection open past the
   deadline is NoBind. Then pin the bind's host key to `known_hosts`: it
   must be a key
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

**Server.** With `!agent=yes` and `SSH_AUTH_SOCK` set by sshd, the launcher,
before printing the CredentialLine, triggers ssh's bind: connect to
`SSH_AUTH_SOCK`, send `SSH_AGENTC_REQUEST_IDENTITIES`, read one reply frame
(at most 256 KiB), close; deadline 5 s [choice]. A failure is logged and
otherwise ignored: the client then sees NoBind. It is the open that makes
ssh connect to the capture socket and send its bind ([S3]: the trigger
took 0.82 ms). With no `SSH_AUTH_SOCK` (the host has
`AllowAgentForwarding no`) it skips the trigger; the client sees no
connection, so NoBind, and carries on without the agent ([S3] E7).

Measured cost of capture over a plain bootstrap: about 5 ms on loopback
[S3].

**How a program can tell it is inside a mosey session.** mosey is one
file (D7), so the client and every server role have comm `mosey`, and the
comm alone cannot tell the local client from the far spawner. The
spawner's **argv** can: `/proc/PID/cmdline` of the session's spawner is
exactly `mosey` (any path), then `--serve=spawner`. The spawner is the
parent of the login shell (`server.md` §2.5), so a program inside the
session finds it as an ancestor; the local client's argv[1] is never a
`--serve` flag (§2). This describes the process shape as built; it is
not a promise to any tool that it stays so (D28), and what a tool does
with it is the tool's own affair. A forged argv proves nothing, since any
process of the user's can set its own.

---

## 9. Sessions: exclusive attach, resume, names, lifetime (D26, D8)

### 9.1 Exclusive attach (D26)

Every Hello in v1 says `Attach = Exclusive`. When a transport of a session
is **confirmed** (the first authentic transport packet, which also consumes
the credential, D20), the server revokes every other transport of that
session: each is sent `KindRevoked` with the new client's address and the
time, and its keys are wiped. The last client to confirm wins. Other unused
credentials of the session are not cancelled; they expire by their TTL
(30 s), and if one is confirmed it takes over in turn: each came from an
SSH login, and each SSH login is the user.

Which commands may take over is §9.2's: only `mosey -s NAME DEST`, and
R3's reconnect of a session its own client still holds (§9.2.2). A plain
`mosey DEST` never takes an attached session (D8 R1, D26).

For a `new` attach there is nothing to revoke. The kicked client, on the
`transport.Revoked` event, restores the terminal and prints

```
mosey: session taken over from ADDR:PORT at 2026-11-14T09:30:12+00:00
```

(`By` as `netip.AddrPort.String()`, `At` in the client's local zone as
RFC 3339 to the second), then exits with status 3. It does not reconnect:
this is the "cut off a stolen client" property of D26.

**The limit of that message.** The kicked client learns of it from a
REVOKED frame, and the server keeps those for the tombstone's 60 s
(`transport.md` §8.3). A client that sends nothing in that minute, a
laptop asleep while the session is resumed from a phone, wakes to
silence. Its keys are useless to anyone either way, so the cut-off itself
holds. Since the sessions slice it still learns why: after `ReconnectAfter`
of silence it tries to reconnect (§9.2.2), the launcher answers `taken`
because another credential holds the session, and the client prints
`mosey: session NAME taken over by another client at TIME` and exits 3.
That message lacks the address, which the ErrorLine's frozen grammar
cannot carry (§6.4).

### 9.2 Resume and names (D8 R1, R2)

Resume is a new SSH login and a new handshake whose credential is vouched
for by that login; nothing transport- or crypto-related is ever kept on
disk, by either side (D8; [S1] §1.4). It covers a client that is gone: a
reboot, a crash, a closed terminal, a laptop left behind, another device.
A dead spot *within* one client's life is roaming's: the transport keeps
its keys through any outage and the path follows the client (D21), so the
same client carries on once packets flow again (`transport.md` §7); only
when that cannot work does the running client resume (§9.2.2).

**Session state lives only on the remote host** (D8). The client keeps no
list of sessions and no id on disk: the greetings of §9.2.1 are the only
record, so a second device sees exactly what the first would.

**Names** (D8 R2). Every session has one, `sname` (§6.2): 1 to 32
letters, digits, `-`, `_` and `.`, starting with a letter or digit,
compared byte for byte. It is the user's, given with `-s NAME`, or
generated by the launcher as `ADJECTIVE-NOUN` from two word lists of 64
of mosey's own (`server.GenerateName`), so 4096 names: a draw that
clashes with a session that answers is drawn again, up to 32 times, after
which the name gets `-` and four hex digits [choice]. The name travels in
the CredentialLine (§6.3), so the client can say it, and in the greeting
(§9.2.1), so a launcher can find it.

**The commands** (D8 R1, R2):

| Command | ClientLine `attach` | What the launcher does, holding the lock |
|---|---|---|
| `mosey DEST` | `auto`, no `cmd` | of the sessions the launcher can attach (step 5: any version's, if their attach protocol is this launcher's) that are `detached` (below) and whose greeting has no `cmd` (§9.2.1: started without a command, `-type` and `-dir` ones included), the one with the newest `since`, taken with `resume:SID`; if there is none, a new session with a generated name, `new:NAME`. It never takes a session that is `new` or `attached`, nor one running a command |
| `mosey DEST COMMAND` | `auto` with `cmd` | as `mosey DEST`, but of the sessions whose greeting's `cmd` is the line's, byte for byte (§9.2.3; PLAN D8, option C); if there is none, a new session with a generated name running the command |
| `mosey -s NAME DEST` | `name:NAME` | session NAME (step 5: of any version; one of another attach protocol is `MOSEY-ERROR 1 !code=attach detail=P-N`), whatever its state, with `resume:SID`: a takeover if it is attached (D26); if there is no session NAME, a new one called NAME, `new:NAME` |
| `mosey -new DEST` | `new` | a new session with a generated name, `new:NAME` |
| R3's reconnect | `resume:SID:CREDID` | §9.2.2 |
| `mosey -list DEST` | none: `--serve=list` (§9.4) | |
| `mosey -kill NAME DEST` | none: `--serve=kill NAME` (§9.5) | |

Each row that can start a session (`auto`, `name:NAME`, `new`) uses the
line's `dir`, `type` and `cmd` only when it does start one (§9.2.3); a
row that takes an existing session ignores them, but for `auto`'s match
on `cmd`.

**What counts as detached.** A greeting says `detached` when its last
client said it was leaving (END `detached`, §9.3), when that client's
connection failed, or when proto has heard nothing authentic from it for
**`SilentAfter` = 15 s** [D: five of D11's 3 s heartbeats, the same
interval after which the client itself stops relying on roaming alone,
§9.2.2]. The last is what lets R1 give a session back after the client's
machine crashed, lost power or rebooted without a word: by the time it
runs `mosey DEST` again the session reads `detached`. A silent client that
is heard again (the dead spot ended) is `attached` again with no resume;
if a plain `mosey DEST` from elsewhere took the session meanwhile, the
returning client finds itself revoked (§9.1). The greeting's `since` is
the moment of the last change, so "most recently detached" is the newest
`since` among the detached.

**The lock.** Choosing and starting are one step per host and user: the
launcher takes an exclusive `flock` on `R/mosey/lock` (made `0600` with
`O_NOFOLLOW` in `R/mosey`, which is checked first as `server.md` §2.6
says) before it reads any greeting, and holds it until it has the
credential line or has failed. Waiting for it is bounded by T2 (15 s), and
`flock` lets go when its holder exits, so a launcher that dies leaves no
lock behind. Two `mosey DEST` started together, a terminal restoring its
tabs, therefore never choose the same detached session, and two
`-s NAME` never start two sessions called NAME. A launcher that took a
session has its spawner's word that a credential is out for it: from
then until that credential's TTL (30 s) has passed, the greeting says
`attached` with that credential as its holder (§9.2.1) even before its
client confirms, so the next launcher does not choose it too. If nobody
confirms in that time the greeting says again what it said before.

The steps:

1. **Client.** It bootstraps exactly as §4–§7 with a fresh one-shot key and
   its `attach`. Its `cols`/`rows` are its own terminal's.
2. **Launcher.** It checks the protocol number as for any line, and
   triggers ssh's bind before printing the line (§4.4 step 4, §8) when
   `!agent=yes`, so a resuming client captures its own bind from its own
   SSH login. It takes the lock, connects to every `R/mosey/*/attach.sock`
   (`server.md` §2.6 says what `R` is and how the directories are
   checked), keeps those that answer with a greeting within 2 s, and
   chooses as the table says. To start a session it rewrites the line's
   `attach` as `new:NAME` and goes on as §4.4 does, starting a spawner of
   its own. To take one it closes every other connection, rewrites the
   line's `attach` as `resume:SID` (a reconnect keeps its CREDID,
   `resume:SID:CREDID`, §9.2.2) and sends it to that session's spawner.
   A `new:NAME` or the all-zero SID from a client is `MOSEY-ERROR 1 !code=line`.
3. **Spawner.** The session's spawner owns the socket. It checks the
   peer's uid with `SO_PEERCRED` [S1 `resume.go`], sends its greeting
   (§9.2.1), and reads the launcher's `ClientLine` (0x40). It parses it
   again (it trusts no other process's parse) and checks it is
   `resume:SID` or `resume:SID:CREDID` for its own SID, and that the
   client's public key is an X-Wing key. It forwards the key to proto
   (`Resume`, 0x05), and proto mints a credential for the **same SID**
   with the usual TTL (30 s) and cap (2 unused, the oldest evicted and
   logged). The credential comes back as `Credential` (0x30); the spawner
   checks it as at bootstrap (§4.4 step 3), and that its `sid` is
   the session's, marks the session held by it (the lock paragraph above)
   and sends it to the launcher in `Ready` (0x41), which prints it exactly
   as for a new session. Any failure is `Failed` (0x42), which the
   launcher turns into `MOSEY-ERROR 1 !code=internal`.
4. **Handshake and takeover** as §7 and §9.1: on confirmation every other
   transport of the session is revoked, and its client exits saying so.
5. **Versions** (D8 V1). Every session's greeting is in the stable
   form of §9.2.1, which every launcher reads in full, so a launcher
   chooses among the sessions of every mosey version alike: after the
   host's mosey is upgraded, a plain `mosey DEST` takes its detached
   session back, and `-s NAME` finds NAME, whichever binary runs it. No
   software version is compared: the launcher attaches the session as
   steps 2–4 say, through the attach protocol (`server.md` §2.8), and the
   session goes on running its own binary, so an upgrade takes effect on
   new sessions. The client and the session's proto then check their
   handshake protocol (`transport.md` §2.3). A session whose greeting does
   not parse is not chosen. One whose attach protocol is not this
   launcher's is never taken by `auto` (it is listed by `-list`, so the
   user can see it); `name:NAME` or `resume:SID` naming it is refused with
   `MOSEY-ERROR 1 !code=attach detail=P-N`, P its spawner's number and N the
   launcher's, and the launcher's stderr says `session NAME speaks attach protocol P; this mosey speaks
   N`. One whose greeting has a critical field this launcher does not
   know (§9.2.1) is treated the same way, but refused with
   `MOSEY-ERROR 1 !code=unsupported detail=KEY`, so the client says
   which field this host's mosey cannot honour. Either way its name
   stays taken: a new session is never given it.
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
message in §6.1's grammar, **not** an IPC message:

```
session-line = "MOSEY-SESSION" SP aproto *(SP field) LF   ; fields in key order
aproto       = dec              ; the attach protocol the spawner speaks,
                                ; 1..255; "1" now
```

| Field | Value | Mandatory | Critical | Why critical or not |
|---|---|---|---|---|
| `!cmd` | `b64text` (§6.2): the command the session was started with | optional | yes | it selects: `auto` takes only a session started with its own command (§9.2). A launcher that ignored it would resume a running command for a plain `mosey DEST` |
| `cwd` | `b64text` of a `cwdtext` (§6.2): the foreground program's working directory | optional | no | it describes, for `-list` |
| `fg` | `b64text` of an `fgtext` (§6.2): the foreground program's name | optional | no | it describes, for `-list` |
| `!holder` | `b64(8)`: the credential id that holds the session | optional | yes | it restricts: R3 takes a session back only if this is its own credential (§9.2.2). Ignored, a reconnect could take a session from whoever took it over |
| `!name` | `sname` (§6.2) | mandatory | yes | it selects: `-s NAME` and `-kill NAME` find the session by it |
| `peer` | `addrport`: `netip.AddrPort.String()` of the last attached client, unmapped, no zone | optional | no | it describes, for the takeover message |
| `!sid` | `b64(16)` | mandatory | yes | it selects: the session a resume names (`resume:SID`) |
| `since` | `dec`: unix seconds of the last change of state | mandatory | no | it describes; R1 orders detached sessions by it, but never takes one it would not otherwise take |
| `started` | `dec`: unix seconds the session started | mandatory | no | it describes |
| `!state` | `new` / `attached` / `detached` | mandatory | yes | it restricts: `auto` takes only a detached session, and never steals an attached one (D8 R1) |

`new` is a session no client has attached to yet; `attached` one whose
client is attached, or for which a resume's credential is out and not yet
expired (§9.2 "The lock"); `detached` one whose last client said it was
leaving, whose connection failed, or which proto has not heard from for
`SilentAfter` (§9.2). `holder` is the id of the credential the attached
connection was made with, or the one the pending resume was minted with,
except that a reconnect's pending resume names the CREDID the reconnecting
client gave (§9.2.2), and absent when the session is `new` or `detached`.
A credential id is not
secret: it travels in the clear in msg1 (`transport.md` §3.4), and only
the user's own processes can read a greeting. R3 uses it to tell "still
held by me" from "held by someone else" (§9.2.2). `cmd` is the `cmd`
of the ClientLine that created the session, exactly as it came (§6.2,
§9.2.3), for as long as the session lives; `auto` matches on it (§9.2)
and `-list` shows it (§9.4).

`fg` and `cwd` say what the user would find at the session's keyboard,
read afresh for each greeting so `-list` can tell sessions apart. The
program is the leader of the pty's foreground process group (TIOCGPGRP
on the master): the shell at its prompt, or the job it gave the terminal
to, such as an editor or `claude`, whether typed at the prompt or the
session's command. Should that leader be gone or unreadable, the shell
stands in. Its name is argv[0]'s base name less a login shell's `-`,
which is the name a program gives itself (a Nix-wrapped `claude` has comm
`.claude-unwrapp` but argv[0] `claude` [M] /proc on NixOS, 2026-11-18),
else its comm; its directory is where `/proc/PID/cwd` points, the user's
home written `~` as a prompt writes it. Both are read as the user, who
owns the processes; one that is not readable (a `sudo` job's directory)
is left out. The spawner fits each to its grammar: every byte that is not
UTF-8 and every control character as `?`, cut on a rune boundary with
`…`, a directory at its start so its end shows. Each is absent when
unknown, and both outside Linux.

**Stable** (D8 V1, `versioning.md` §5). `aproto` is the one number of the
attach protocol (`server.md` §2.8, the greeting and the messages that
follow it) the session's spawner speaks, and names only its envelope:
§6.1's grammar, the greeting's mandatory fields and the framing of the
messages. A later release adds a field to the greeting as any line gains
one, so `ParseSessionLine` reads the greeting of any session of the same
number. A launcher attaches a session only if `aproto` equals its own
`bootstrap.AttachProtocol` (§9.2 step 5). No software version is in it.
The parser is canonical and fuzzed. A greeting with a critical field this
launcher does not know is one it cannot judge: the session is not chosen
by `auto`, and `name:NAME` or `resume:SID` naming it is refused as for
another attach protocol, with `attach` and its own number on both sides.

`MaxSessionLine` = 2048 bytes [derived: the longest greeting is 1917
bytes: `MOSEY-SESSION` and 5 digits 19; ` !cmd=` 1372; ` cwd=` 261;
` fg=` 68; ` !holder=` 20;
` !name=` 39; ` peer=` and 47, 53; ` !sid=` 28; ` since=` and
` started=` with the 12-digit bound on the times, 19 and 21; ` !state=`
and `detached`, 16; LF; then the next power of two]. A seqpacket message
of that size fits any socket buffer the kernel gives.

#### 9.2.2 Reconnect (D8 R3)

While the client runs, a dead spot is ridden out by roaming (D21). Roaming
cannot help when the server's half of the transport is gone or never
hears the client again: a NAT or firewall that drops the UDP flow for good while SSH still works, or a
laptop asleep past the server's tombstone. So the client also resumes its
own session, in the background, and never asks the user anything:

- **When.** Once no authentic packet has arrived for **`ReconnectAfter` =
  15 s** [D: five of D11's 3 s heartbeats; the server's `SilentAfter` is
  the same, so each side gives up on the other at about the same moment],
  the client starts trying, while it goes on sending on the old transport.
- **Each try** is a whole bootstrap (§4–§7) with a fresh one-shot key and
  `attach = resume:SID:CREDID`: SID the session's, CREDID the credential
  its current transport was made with. Its ssh runs with `-o
  BatchMode=yes` (ssh_config(5): no passphrase, password or host-key
  question is put; a login that would need one fails), in a session of its
  own (`setsid`), so neither it nor anything it starts (a `ProxyCommand`,
  a `ProxyJump`'s inner ssh, which does not inherit `-o BatchMode`, a
  `KnownHostsCommand`) has the user's terminal to open as `/dev/tty`, and
  with `SSH_ASKPASS_REQUIRE=never` (ssh(1)), so none asks through a
  graphical askpass instead; its stderr goes to
  the client's log and never to the screen, nothing is copied over
  (§4.7.1), and the agent's bind is captured afresh, so the new transport
  forwards this login's agent. For a session on this machine (§2.2) a
  try runs the local launcher again, with no ssh and so nothing to ask. A
  try that has not dialled within
  `ReconnectTry` = 60 s [D: twice the 30 s credential TTL, the longest a
  healthy try can need] is abandoned.
- **Backoff.** The first try starts at 15 s of silence; after a failed try
  the next waits 2 s, doubling to at most 60 s [D: a try is one SSH
  login; 60 s keeps a day-long outage to about 1440 of them, and puts a
  working session at most a minute after the network returns when
  roaming cannot]. It starts from 2 s again once the session hears from
  the server.
- **What the user sees.** Nothing is asked, but nothing is hidden either:
  from the first try until the server is heard again or the new transport
  is in, the screen's top row is replaced, in reverse video, by `mosey: no
  contact for DURATION; reconnecting`, followed after a failed
  try by ` (last try: REASON)`, REASON the failure's first line in
  printable ASCII, at most 120 bytes [choice: a line's worth; the log has
  it whole], since it may carry what ssh said. DURATION is kept current
  each second. A try that can never work (a host that wants a password,
  which `BatchMode` refuses) so shows its reason rather than a screen that
  has simply stopped [choice: R3 says to ask nothing, not to say nothing;
  tries continue as below, since the user may fix the cause, say by
  adding the key to the agent, without restarting the client]. The row is
  part of what is drawn, not of the session's screen: the server never
  sees it, and the renderer's diff puts the row back when it goes.
- **The launcher's answer** to `resume:SID:CREDID`, under the lock: no
  session SID that answers is `MOSEY-ERROR 1 !code=session`. A session that is
  `detached`, or whose `holder` is CREDID, is taken as §9.2 step 2 says:
  the second case is a path broken one way only (the server still hears
  the client, so it never went `detached`), and the takeover revokes this
  client's own old transport. A session any other credential holds is
  `MOSEY-ERROR 1 !code=taken detail=SINCE`, SINCE its greeting's `since`. The
  launcher passes CREDID on to the spawner, and while the credential it
  mints is out the greeting's `holder` is CREDID, not the new one: the
  hold is that client's. Otherwise a try dropped at the swap (below)
  would leave the session held by a credential nobody will use, and if
  the path went quiet again within its 30 s, the same client's next try
  would read `taken` and exit, though nobody took the session.
- **The swap.** Before it dials, the try checks the old transport is still
  silent: if anything authentic has arrived since the try began, roaming
  has won, the try is dropped and its credential expires unused (30 s,
  §4.5). Otherwise it dials. The confirmation revokes the old transport
  (D26), and a REVOKED arriving on it while this client's own dial is in
  flight is not a takeover: the client waits for its dial, and only if
  that fails exits as §9.1 says. On success the terminal stays raw and the
  screen stays up; the new transport's SSP starts from scratch, so its
  first frame is the whole screen; prediction starts afresh; the size goes
  as the first input event again. Keystrokes typed during the silence that
  the server had not acknowledged are dropped [choice: the old proto may
  or may not have written them to the pty, and sending them again could
  type them twice].
- **How it ends.** `session`: the client restores the terminal, prints
  `mosey: session NAME on DEST has ended: its shell exited, or the host
  restarted` and exits 1 [choice: it cannot tell which]. `taken`: `mosey:
  session NAME taken over by another client at TIME` and exit 3, as
  §9.1. Every other failure (ssh exiting 255, a timeout, no mosey of this
  version, `internal`, a handshake that does not complete) is logged and
  tried again after the backoff.
- **Open (PLAN O15), a placeholder awaiting Dan.** Until he decides, a
  try never takes a session another client holds: D26 says only an
  explicit `-s` takes over, and a stolen laptop that wakes must not take
  its session back. The other answer, a try that takes over as `-s`
  does, is one switch in the launcher (`reconnectTakesBack` in
  `internal/server/choose.go`), and both settings are tested. A try names
  its session by SID, not by name, so it never attaches a newer session
  that reused the name after the old one ended; that this meets R3's "by
  name" is also Dan's to confirm.

#### 9.2.3 How a new session starts: `-dir`, `-type` and a command

`-dir DIR` and `-type TEXT` (§2) travel as the ClientLine's `dir` and
`type` (§6.2). They are what a session is started with, never what it is
attached with: a tmux user's `tmux new-session -c DIR` followed by
`tmux send-keys TEXT Enter`, without tmux (Dan, 2026-11-15).

- **Only on creation.** The launcher uses them (and `cmd`, below) only when §9.2's table has
  it start a session (`new:NAME`): a plain `mosey DEST` with no session
  detached, `-new`, or `-s NAME` with no session NAME. When it takes an
  existing session they are ignored, with no error and no message: the
  `resume:SID` line it sends that session's spawner has `dir` and `type`
  set to `-`. A reconnect (§9.2.2) sends `-` for both. So
  `mosey -s work -dir src -type 'claude' DEST` is a command a user can
  repeat: the first run makes the session, every later one returns to it.
- **The directory.** The launcher resolves `dir`: an absolute path is
  used as it is; any other is joined to the home directory the shell
  would start in (`server.md` §2.5: `$HOME`, else the passwd home, else
  `/`), and cleaned (`filepath.Join`). It must then name a directory the
  launcher can `stat` (symlinks followed). Before it starts a spawner,
  holding the lock, the launcher checks this; if it fails the launcher
  starts nothing, writes `the directory DIR is not one: ERR` on stderr and
  `MOSEY-ERROR 1 !code=dir` on stdout, and the client says `mosey: DIR is not
  a directory on DEST, so no session was started` and exits 1 (§6.4). The
  spawner resolves the same `dir` the same way and starts the login shell
  there (`server.md` §2.5); should it have gone in between, starting the
  shell fails and the session with it (`Failed`, `internal`).
- **The text.** Once the login shell has started and has written its
  first output to the pty (its prompt, as a rule), the spawner writes
  `type`'s text and then one CR (0x0D, what a terminal's Enter key sends)
  into the pty master, in one write, as a person who waited for the
  prompt would type it (Dan, 2026-11-16). Proto reads the master, so it
  is proto that sees the first output: its pty reader sends the spawner
  `FirstOutput` (`server.md` §3.3) after its first read that returns
  bytes, and the spawner waits for that and then for the tty to stop
  echoing (below), for at most `TypeWait` = 2 s in all
  [choice: far longer than an ordinary shell takes to draw its first
  prompt, short enough that a shell which prints nothing, or rc files
  that take longer, only delay the text, never lose it]. When `TypeWait`
  passes first, it types anyway, and the text is then typeahead: it
  sits in the tty's input queue until the shell reads its first line,
  and the tty echoes it when it arrives, so it may show twice, once
  before the prompt and once after it. Waiting fixes exactly that: typed
  ahead, bash 5 (NixOS, through the e2e test's throwaway sshd,
  2026-11-16) showed `echo hi`, then `PROMPT$ echo hi`, then `hi`
  [shells]; typed after the prompt it shows `PROMPT$ echo hi` once.
  The first output is not always the prompt: a login shell's profile
  can write first (a window title, say), and readline turns the tty's
  `ECHO` off only just before it draws the prompt ([M] strace of bash
  5.3, 2026-11-16). Typed in between, the text showed twice on CI's
  Ubuntu runner. So after `FirstOutput` the spawner also waits until the
  slave's termios, read through the master, has `ECHO` off, looking
  every 10 ms [choice]; a line editor (readline, zle, fish) turns it off
  to read keys itself. A shell with no line editor (dash) leaves it on
  for good and gets the text when `TypeWait` passes, which costs it up
  to 2 s and no second echo: the tty's is its only one. The
  tty's `ICRNL` turns the CR into the newline that ends the line. This
  is what `tmux send-keys TEXT Enter` sends: the keys, as if typed. A
  prompt is not proof the shell is reading, so a program the rc files
  run that reads the terminal after printing something (a prompt for a
  passphrase, say) gets the text instead of the shell. The text is typed
  into the shell, never run by the server: it is the user's own command,
  with the user's own `PATH` and aliases, and when it exits the user is
  at that shell's prompt in DIR. It is written before the spawner sends
  `Ready`, so it always comes before anything the client types; the
  price is that a line with a `type` has its `Ready`, and so its
  credential, wait for the shell's first output (at most `TypeWait`,
  well inside T2), where a line without one does not. A failed write is
  logged and the session goes on.
- **The command.** A line with a `cmd` (§2, §6.2) starts the session
  running the command instead of an interactive shell: the spawner runs
  the shell `server.md` §2.5 picks as `SHELL -c CMD`, with the same
  argv[0] (`-` and its base name, so it is a login shell and reads the
  same profile, and so has the same `PATH`, as the interactive one; ssh
  runs its command with a non-login shell, but there sshd's own login
  set the environment up, where here the spawner's environment is a
  non-interactive ssh command's), the same environment and the same
  directory, `dir` included. `CMD` is the text as it came, one argument
  to `exec`: the server puts it through no shell but that one and
  interpolates it into nothing. When the shell exits the session ends
  as any session whose shell exits does (§9.3): proto sends END and the
  client exits 0. The command's exit status is not passed on: END's
  body is one reason byte (`transport.md` §8.4), and carrying the
  status would change that frame, and so the handshake's protocol
  number, and have proto wait for the spawner's `ShellExit` after the
  pty's EOF, which it does not now. A `cmd` is run only by a session the
  line creates; the `resume:SID` line for a session that is taken has no
  `cmd`, as it has no `dir` or `type`.
- **Returning to a command** (PLAN D8, Dan, 2026-11-16, option C). The
  spawner keeps the `cmd` its session was created with and puts it in
  every greeting (§9.2.1). A plain `mosey DEST CMD` is sent as `auto`
  with the `cmd`, and the launcher takes the most recently detached
  session whose greeting has that same `cmd`, compared byte for byte,
  or starts a new one running it (§9.2's table). So closing the window
  on `mosey dan-desktop claude` and running it again returns to that
  claude, and a second window while the first is attached gets a
  second claude. A plain `mosey DEST` with no `cmd` takes only a
  session whose greeting has none, so it never drops the user into a
  detached program, and `mosey DEST CMD` never into a detached shell.
  The key is the command alone (§2): `-dir`, and `-type` for a shell,
  only say how a session starts.
- **Saying a command was not run.** When a line with a `cmd` takes a
  session whose greeting's `cmd` is not that one (`name:NAME` with NAME
  running something else, or a shell), the launcher adds `existing` to
  the credential line it passes on (§6.3), and the client prints `mosey:
  session NAME was already running, so the command was not run` on
  stderr before the screen goes up. `-s NAME DEST CMD` returning to a
  NAME it started with that same `cmd` says nothing, as `auto` never
  does: that command is the one running. The launcher adds `existing`
  to no line in answer to one without a `cmd`, so no older client sees
  it.

### 9.3 How long a session lives (D8 R4)

| The session | Ends when |
|---|---|
| has never had a client | every credential minted for it has expired unconfirmed (§4.5: 30 s after the last one), or the spawner's backstop fires |
| has had a client | its shell exits: `exit`, Ctrl-D, or anything else that ends it; or `mosey -kill NAME DEST` (§9.5); or it has been `detached` for **`IdleTimeout` = 7 days** [D, Dan 2026-11-15]; or the spawner is signalled; or proto dies (§9.2 step 8). **Never** because its client went away |

`-kill` and the idle timeout hang the shell up: the spawner sends SIGHUP
to the shell and to the pty's foreground process group, as a hangup does
[kernel ABI, tty hangup], and the shell's exit then ends the session the
usual way (`server.md` §2.4), so an attached client is told (END
`shell exited`) and exits 0. A shell that ignores SIGHUP is hung up for
good after `HangupGrace` = 10 s [choice]: the teardown closes the last pty
master, then SIGKILLs it after T8.

The idle time counts from the moment the session became `detached`
(§9.2), and each attach resets it. **Configurability** (PLAN O14): it is a
constant. A per-session value would need a ClientLine field and a host
one a server config file, neither of them cheap; `SpawnerConfig` has a
field for tests.

There is **no detach key**: whatever the user types goes to the shell.
A client that goes away says so if it can: on a signal (SIGTERM, SIGHUP:
a closed terminal, a logout, a shutdown) or the end of its terminal's
input, it sends END with reason `detached` (`transport.md` §8.4), puts the
terminal back, prints

```
mosey: detached from session NAME; resume it with: mosey -s NAME DEST
```

and exits 0. The server marks the session `detached` and keeps it. A
client that cannot say so (power loss, a crash, a network that never comes
back) leaves the session `attached` until proto has heard nothing for
`SilentAfter`, and then `detached`, so the next plain `mosey DEST` takes
it (§9.2).

The hazards of §4.5 ("Known hazard") apply: with logind's
`KillUserProcesses=yes` the session dies with the SSH login that started
it, unless the user lingers.

### 9.4 Listing sessions

`mosey -list DEST` runs `mosey --serve=list` over the bootstrap's own ssh
command (§4.1, its last argument `exec /bin/sh -c 'exec SERVER
--serve=list'`, or with no `-remote` §4.7.2's probe running
`--serve=list`, which finds the host's mosey, `PATH`'s or
`~/.local/bin/mosey`), with stdin
closed. A probe that answers `MOSEY-PROBE` is reported as §4.7.1 says,
not shown as a list, and nothing is copied. The server connects to every
attach socket as the launcher does (without the lock: it chooses
nothing), reads each greeting, prints one line per session that answered,
oldest first, and exits 0:

```
list-line = "MOSEY-LIST" SP "1" *(SP field) LF     ; §6.1, fields in key order
```

| Field | Value | Mandatory | Critical | Why critical or not |
|---|---|---|---|---|
| `cmd` | `b64text` (§6.2): the greeting's `cmd` | optional | no | the list is only shown: every field describes |
| `cwd` | `b64text` of a `cwdtext`: the greeting's `cwd` | optional | no | as `cmd` |
| `fg` | `b64text` of an `fgtext`: the greeting's `fg` | optional | no | as `cmd` |
| `name` | `sname` | mandatory | no | as `cmd` |
| `peer` | `addrport`: the greeting's `peer` | optional | no | as `cmd` |
| `since` | `dec`: unix seconds of the last change of state | mandatory | no | as `cmd` |
| `state` | `new` / `attached` / `detached` | mandatory | no | as `cmd` |

The number is the bootstrap lines' (§6.1), checked like theirs.

The client reads ssh's stdout (at most 2 MiB [derived: `MaxListed` ×
`MaxListLine`]), skips anything that is
not a `MOSEY-` line (a login shell's chatter, §6.5), and parses each
`MOSEY-LIST` line with `ParseListLine`: canonical, at most `MaxListLine` =
2048 bytes [derived: `MOSEY-LIST` and 5 digits 16; ` cmd=` 1371;
` cwd=` 261; ` fg=` 68; ` name=` 38; ` peer=` 53; ` since=` 19; ` state=` and
`detached` 15; LF; 1842 in all; then the next power of two],
and fuzzed, since a hostile server writes it. At most `MaxListed` = 1024
lines are shown [choice]; a line that does not parse is not shown, and
the client says how many it dropped. Every field but `cmd` is from a
grammar of printable ASCII with no space; `cmd` decodes to a `cmdtext`
(valid UTF-8, no control character but tab), checked by the parser, and
the client shows it with every rune that is not printable
(`unicode.IsPrint` false: tab, format characters such as the bidi
overrides, non-ASCII spaces) as `?`, and cut to 60 runes with `…` after
[choice: one terminal line beside the other columns; the full text is
the user's own and in their shell history]. So the table the client lays
out itself cannot carry an escape sequence, nor reorder what it shows
(D9). It is the last column, shown only when some session has a command,
and empty for one that has none. `peer` is shown as `PEER` (the IP
address without port, for attached sessions only), and `fg` and `cwd` are
shown as `RUNNING` cut to 16 runes and `DIR` cut to its last 32 runes
with `…` before [choice: a program's name whole and enough of a path's
end to tell sessions apart, so a row stays one line], each a column only
when some session has it, so an older server's list lays out as before:

```
NAME         STATE     SINCE                      PEER        RUNNING  DIR               COMMAND
quiet-heron  detached  2026-11-14T09:30:12+00:00              bash     ~
brave-otter  attached  2026-11-16T15:02:40+00:00  100.64.1.2  claude   ~/Projects/mosey  claude
```

`SINCE` is in the client's local zone, as §9.1's times are. With no line it prints `no sessions on DEST` (`on localhost` for this machine, §2.2).

A lister sends no ClientLine; the spawner sees the connection close after
its greeting and does nothing.

### 9.5 Ending a session

`mosey -kill NAME DEST` runs `mosey --serve=kill NAME` like `-list` (the
name is an `sname`, which needs no quoting in any shell, §4.1). The server
finds the session called NAME among those that answer, as `-list` does,
and after its greeting sends it `Hangup` (0x43, `server.md` §2.6); the
spawner hangs the shell up (§9.3), and closes the connection once it has
sent the signals. The server prints nothing and exits 0, and the client
says `mosey: ended session NAME on DEST`. With no session called NAME the
server prints `MOSEY-ERROR 1 !code=session` and exits 1, and the client says
`mosey: no session called NAME on DEST` and exits 1. Any other failure is
reported as `-list`'s are.

---

## 10. Errors the client reports

| Situation | Message | Exit |
|---|---|---|
| usage (§2) | the usage text | 2 |
| `ssh -G` fails | filtered stderr of `ssh -G`, then `mosey: ssh -G DEST failed` | 1 |
| ssh cannot start | `mosey: running PROGRAM: ERR` | 1 |
| `ErrNoLine`, ssh exit 255 | (ssh has already said why on stderr) `mosey: ssh to DEST failed` | 1 |
| `ErrNoLine`, ssh exit 126/127 (`ErrNoServer`, with `-remote`) | `mosey: no mosey at SERVER on DEST: install it there or pass -remote` | 1 |
| `*VersionError`, or ErrorLine `version` (any server: `PATH`'s, `-remote`'s, or `~/.local/bin/mosey`) | `mosey: DEST's mosey speaks protocol P; this mosey speaks N` (§6.4) | 1 |
| the handshake's `*IncompatibleVersionError` | `mosey: DEST's mosey speaks handshake protocol P; this mosey speaks N` (`transport.md` §3.6) | 1 |
| ProbeLine (`ErrNoServer`, no `-remote`) | the upload of §4.7, and its messages; for `-list` and `-kill`, §4.7.1's messages and no upload; for R3's reconnect, a log line and another try | 1 |
| `ErrNoLine`, other exit | `mosey: the remote mosey exited with status N` | 1 |
| `ErrBadLine` | `mosey: DEST sent a malformed mosey line` | 1 |
| ErrorLine `unsupported` | `mosey: DEST's mosey can't do F yet` (§6.4) | 1 |
| `ErrBadAddr` | §7.2 | 1 |
| ErrorLine | per §6.4 | 1 |
| Dial timeout | §7.3 | 1 |
| taken over (REVOKED, or R3's `taken`) | §9.1, §9.2.2 | 3 |
| R3's reconnect finds no session | §9.2.2 | 1 |
| detached (a signal, or the terminal's input ended) | §9.3 | 0 |
| `-list` | the table of §9.4, laid out by the client | 0, or 1 if ssh failed |
| `-kill` | §9.5 | 0, or 1 if there is no such session or ssh failed |
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
	MaxClientLine     = 8192
	MaxCredentialLine = 2048
	MaxErrorLine      = 256 // frozen with the ErrorLine grammar
	MaxPreamble       = 64 << 10
)

// ClientLine is §6.2. Marshal always writes the number Version.
type ClientLine struct {
	Attach          Attach            // AttachNew (the zero value), AttachAuto, AttachName, AttachResume
	Name            string            // "name:NAME", or "new:NAME" ("" is plain "new")
	SessionID       [16]byte          // "resume:SID"
	Holder          [8]byte           // "resume:SID:CREDID", when HasHolder (R3)
	HasHolder       bool
	Agent           bool              // !agent=yes; false is absent
	Cols, Rows      uint16            // 1..65535
	Env             map[string]string // allow-listed names only; Marshal sorts
	Dir, Type       string            // !dir, !type: "" is absent (§6.2, §9.2.3)
	Public          []byte            // 1216 bytes
	Command         string            // !cmd: "" is absent (§6.2, §9.2.3)
}

// CredentialLine is §6.3. Marshal always writes the number Version.
type CredentialLine struct {
	Addr            netip.Addr // the zero Addr is absent
	Port            uint16
	CredentialID    [8]byte
	SessionID       [16]byte
	Name            string // sname
	PSK             [32]byte
	Public          []byte // 1216 bytes
	Existing        bool   // existing=yes: a cmd was not run (§9.2.3)
}

// ValidSessionName is §6.2's sname.
func ValidSessionName(string) bool

// ValidDir and ValidType are §6.2's dirtext and typetext.
func ValidDir(string) bool
func ValidType(string) bool

// ErrorLine is §6.4; Detail "" is absent.
type ErrorLine struct {
	Proto  int
	Code   string
	Detail string
}

const (
	CodeLine        = "line"
	CodeVersion     = "version"
	CodeAttach      = "attach" // the session's attach protocol is not this launcher's (§9.2 step 5)
	CodeUnsupported = "unsupported"
	CodeSession     = "session"
	CodeTaken       = "taken" // R3: another credential holds the session (§9.2.2)
	CodeInternal    = "internal"
	CodeDir         = "dir"
)

// CriticalError is a line with a critical field this build does not
// know (§6.1, versioning.md §3); errors.Is(err, ErrBadLine) holds. Key
// is the field's key, without its "!".
type CriticalError struct{ Key string }

// SessionLine is §9.2.1, the spawner's greeting on its attach socket.
type SessionLine struct {
	// AttachProtocol is the attach protocol the session's spawner speaks
	// (server.md §2.8), 1..255.
	AttachProtocol  int
	SessionID       [16]byte
	Name            string
	Started         time.Time // to the second
	State           SessionState // New, Attached, Detached
	Since           time.Time
	Peer            netip.AddrPort // the zero AddrPort is absent
	Holder          [8]byte        // HasHolder false is absent
	Command         string         // !cmd; "" is absent (§9.2.3)
	Foreground, Cwd string         // fg, cwd; "" is absent
	HasHolder       bool
	// Unknown is the key of a critical field this build does not know;
	// ParseSessionLine sets it beside a *CriticalError, so the launcher
	// can name the session it will not attach (§9.2 step 5).
	Unknown         string
}

const (
	MaxSessionLine = 2048
	AttachProtocol = 1 // this build's attach protocol (§9.2.1)
)

// ListLine is §9.4: one session as --serve=list prints it, and the
// client parses it.
type ListLine struct {
	Name    string
	State   SessionState
	Since   time.Time
	Command string // cmd; "" is absent
	Foreground, Cwd string // fg, cwd; "" is absent
}

const (
	MaxListLine = 2048
	MaxListed   = 1024
)

func MarshalListLine(ListLine) []byte
func ParseListLine([]byte) (ListLine, error)

func MarshalSessionLine(SessionLine) []byte
func ParseSessionLine([]byte) (SessionLine, error)

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

// ProbeLine is §4.7.2: what the probe prints when the host has no mosey
// it can use. Marshal always writes the number Version.
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
// InstallPath is ~/.local/bin/mosey (§4.7), as the remote /bin/sh
// expands it.
const InstallPath = "~/.local/bin/mosey"
// ProtocolAnswer is what `mosey --serve=protocol` prints (§4.7.2), LF
// excluded: the bootstrap line version and the handshake protocol.
func ProtocolAnswer(handshakeProtocol int) string

var (
	ErrBadLine  = errors.New("bootstrap: malformed mosey line")
	ErrNoLine   = errors.New("bootstrap: no mosey line")
	ErrNoServer = errors.New("bootstrap: no mosey on the far host")
	ErrBadAddr  = errors.New("bootstrap: no usable UDP address")
)

// VersionError is a line whose number is not Version; errors.Is(err,
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
	Protocol     string // ProtocolAnswer: what the probe asks ~/.local/bin/mosey (§4.7.2)
	AgentCapture string // the capture socket (§8); "" is ForwardAgent=no
	Role         string // "" runs --serve; "list" --serve=list (§9.4); "kill" --serve=kill RoleArg (§9.5)
	RoleArg      string // kill's session name, an sname
	Batch        bool   // -o BatchMode=yes: R3's background reconnect never asks (§9.2.2)
}

func (s SSH) Check() error // §2 and §4.1: destination and Server rules
func (s SSH) Local() bool  // Destination localhost: this machine, with no ssh (§2.2)
func (s SSH) Resolve(ctx context.Context) (Config, error) // runs ssh -G; locally LocalConfig()
func (s SSH) Command(ctx context.Context, c Config) *exec.Cmd // locally the server itself (§2.2)
// UploadCommand is §4.7.6's ssh, which reads the binary on stdin.
func (s SSH) UploadCommand(ctx context.Context, c Config, hash [32]byte, size int64) *exec.Cmd

// AgentSocket is §5: the socket to forward, or ok false for agent off.
func AgentSocket(c Config, getenv func(string) string) (path string, ok bool)

// ChooseAddr is §7.2.
func ChooseAddr(ctx context.Context, line CredentialLine, c Config,
	lookup func(ctx context.Context, host string) ([]netip.Addr, error)) (netip.Addr, error)
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
`ValidServer`, `ValidEnvValue`, the field sizes
(`PublicKeySize` and so on), `TailSize`, `MaxSanitizedLine` and
`MaxConfig`. `Sanitize` returns an `io.WriteCloser` rather than an
`io.Writer`: a rune split across two writes is held for the next, and
`Close` writes any held bytes escaped.

---

## 11. Constants

| Name | Value | Provenance |
|---|---|---|
| `bootstrap.Version` | 1 | ours (§6.1, `versioning.md` §5: the number names the lines' envelope only; reset from 2 by Dan, 2026-11-17) |
| `MaxFields` (any line) | 32 | [choice] `versioning.md` §6 |
| `MaxClientLine` | 8192 B | [derived] §6.2: at most 5756 B used |
| `-dir`, `-type` length | 1–1024 B each | [choice] §6.2: macOS `PATH_MAX`; a quarter of termios(3)'s 4096-byte canonical line |
| `MaxCredentialLine` | 2048 B | [derived] §6.3: at most 1853 B used |
| `MaxErrorLine` | 256 B, frozen | [choice] §6.4: at most 112 B used by its two fields |
| Session with no confirmed credential | ends after `handshake.CredentialTTL` (30 s) | [derived] §4.5 |
| Spawner backstop (requirement on server.md) | CredentialTTL + 10 s | [choice] §4.5 |
| Client log rotation | 1 MiB, one old file | [choice] §7.4 |
| `MaxPreamble` | 64 KiB | [choice] |
| `MaxProbeLine` | 256 B | [choice] §4.7.2: at most 163 B used |
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
| `MaxSessionLine` | 2048 B | [derived] §9.2.1: at most 1917 B used |
| `MaxForeground`, `MaxCwd` | 48 B, 192 B | [choice] §9.2.1: a program's name; a path's tail, the greeting under `MaxSessionLine` |
| `bootstrap.AttachProtocol` | 1 | ours (§9.2.1, `server.md` §2.8, `versioning.md` §5: reset from 2 by Dan, 2026-11-17) |
| Greeting deadline (launcher, lister) | 2 s per socket | [choice]: the spawner answers at once; a hung one is skipped, not waited on |
| Session name (`sname`) | 1–32 B of letters, digits, `-_.` | [choice] §6.2: safe unquoted in any shell and on any terminal |
| Generated name | `ADJECTIVE-NOUN`, 64 × 64 words; 32 draws, then `-` and 4 hex digits | [choice] §9.2 |
| Launcher lock wait | T2, 15 s | [derived] §9.2 |
| `SilentAfter` (server: a silent client counts as detached) | 15 s | [D] §9.2: five 3 s heartbeats (D11) |
| `ReconnectAfter` (client: R3 starts) | 15 s | [D] §9.2.2: the same five heartbeats (PLAN O13) |
| R3 backoff | 2 s, doubling, at most 60 s | [D] §9.2.2 (PLAN O13) |
| `ReconnectTry` (one R3 try, to the dial) | 60 s | [D] §9.2.2: twice the credential TTL |
| `IdleTimeout` (a detached session's shell is hung up) | 7 days | [D] Dan, 2026-11-15 (D8 R4); a constant (PLAN O14) |
| `HangupGrace` (SIGHUP, then the teardown) | 10 s | [choice] §9.3 |
| `MaxListLine`, `MaxListed` | 2048 B, 1024 lines | [derived] §9.4: at most 1842 B used; [choice] |
| R3: no session | exit 1 | [choice] §9.2.2 |

---

## 12. Tests

**Unit, `internal/bootstrap`:**

- Marshal/Parse round trips for both lines and the error line, including
  maxima (every env name at 64 bytes, longest IPv6, a 1024-byte `dir`
  and `type`).
- `dir` and `type`: a 1025-byte text, a NUL, an LF, a CR, an ESC, a DEL,
  a C1 control, invalid UTF-8 and a padded or non-canonical base64url
  field are each refused; a tab is accepted in `type` and refused in
  `dir`; spaces and non-ASCII letters are accepted in both.
- Each rule of §6.1 broken once: CR, double space, trailing space, padding,
  non-zero trailing bits, wrong decoded length, leading zero, `0` cols,
  65536, unknown env name, unsorted or repeated names, `::ffff:` and zoned
  addresses, `0.0.0.0`, `::`, `224.0.0.1`, `ff02::1` and `255.255.255.255`
  as `addr`, a wrong number (error carries the number), a missing
  mandatory field, keys out of order or repeated (`!k=` beside `k=`
  too), an empty value, a key outside the grammar, a known field with the
  wrong `!` marking, and more than `MaxFields` fields.
- Must-ignore (`versioning.md` §7), on every line: an unknown field
  without `!` parses to exactly what the line without it does; an
  unknown field with `!` is refused as a `*CriticalError` naming it.
- ErrorLine: every code; an unknown 16-letter code parses (and maps to
  `internal` in the client); a 17-letter code, an upper-case code, a
  6-digit or zero-led number, and a line over 256 bytes are refused; a
  number other than 1 is accepted.
- `ChooseAddr`, each row of §7.2's table with an injected resolver: a
  usable `addr`; a loopback `addr` with a non-loopback `hostname` (falls
  back), and with `localhost` (kept); a subnet broadcast (taken: the
  kernel refuses it, §7.2); link-local with and without a zoned `hostname`;
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
  installed, as for §4.1: the probe execs a `PATH` mosey elsewhere
  whatever it says, prefers it to `~/.local/bin/mosey`, execs a
  `~/.local/bin/mosey` that answers the client's protocol, on `PATH` or
  not, skips one that answers anything else (`other`), on `PATH` or not,
  skips a symlinked one or a symlinked `~/.local/bin` off `PATH` and
  execs it as it is on `PATH`, and prints a ProbeLine that parses when
  there is none (`none`); the upload command installs
  through a stand-in installer and removes its temporary file.
- `Platform`, `IsRelease`, `AssetName` and `ParseSums`, each row and rule.

**Unit, `internal/install`:** a fresh install; replacing the user's own
older file; refusing, and leaving untouched, a `~/.local/bin` that is a
symlink, a file that is a symlink, a directory or
someone else's (the "user" is a field, so a test can play another uid), a
group- or world-writable directory, a size or hash mismatch (the upload is
removed), a `TEMP` outside `~/.local/bin`, a relative `HOME`; a
missing `~/.local` and `~/.local/bin` are made 0700.

**Unit, `internal/client`:** the consent table of §4.7.5 and the
remembered-hosts file; the release fetch against a local HTTPS server:
the right asset is chosen, a hash mismatch, a missing asset, a 404, an
oversized body and an `http` redirect are each refused before any upload.
With `localhost` (§2.2): the server stand-in is run with no ssh and
no `ssh -G`, as `--serve`, `--serve=list` or `--serve=kill NAME`, without
the client's `SSH_CONNECTION` or `SSH_AUTH_SOCK`; the agent decision of
§2.2 for each of `-A`, `-a` and neither, with and without
`SSH_AUTH_SOCK`; R3's try resumes on loopback with the agent unbound; and
the messages name `localhost` and the hints name no host. In
`cmd/mosey`, every session command parses with `localhost`, in any case,
or with no `DESTINATION`, as this machine, and `127.0.0.1`, `::1` and
`me@localhost` as hosts for ssh; `-upload`, `-ssh` or ssh options on this
machine are a usage error; `-h` is the usage, exit 0.
The words after `DESTINATION` are the command, joined with spaces, with
their own flags untouched (`far ls -la`), with ssh options before the
destination after `--`; a command keeps a plain `mosey DEST` `auto`, with the `cmd`; a
command with `-type`, `-list` or `-kill`, or outside `cmdtext`, is a
usage error.

**Fuzz** (each run locally for at least a few minutes before it lands,
durations in the commit message; 10 s each in CI):

- Every line's fuzz target (`FuzzParseClientLine`,
  `FuzzParseCredentialLine`, `FuzzParseErrorLine`, `FuzzParseProbeLine`,
  `FuzzParseSessionLine`, `FuzzParseListLine`) also checks
  `versioning.md` §7: for whatever it accepts, the same line with an
  unknown field added without `!` parses to the same value, and with `!`
  is refused naming the key.
- `FuzzParseClientLine`, `FuzzParseCredentialLine`, `FuzzParseErrorLine`:
  no panic; anything accepted re-marshals to the identical bytes less its
  unknown fields; no
  accepted CredentialLine has an unspecified, multicast or limited
  broadcast `addr`; no accepted ClientLine has a `dir`, `type` or `cmd`
  outside `dirtext`, `typetext` and `cmdtext` (§6.2), checked against a
  reference written out rune by rune in the test, and the seeds include
  lines with and without `cmd`, and credential lines with and without
  `existing`.
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
  identical bytes less its unknown fields, and its `cmd`, if any, is a
  `cmdtext`, its `fg` an `fgtext` and its `cwd` a `cwdtext`; seeds with and
  without each.
- `FuzzParseListLine`: no panic; anything accepted re-marshals to the
  identical bytes less its unknown fields, every field but `cmd` is
  printable ASCII with no space, and `cmd` is a `cmdtext`, `fg` an
  `fgtext` and `cwd` a `cwdtext`; seeds with and without each;
  `FuzzReadList` for the whole of `-list`'s output: at most
  `MaxListed` rows, none longer than its fields allow.
- `FuzzListCommand` (`internal/client`): what `-list` shows of any
  string is at most 60 runes and `…`, every one printable
  (`unicode.IsPrint`).
- `FuzzFitText` (`internal/server`): what the spawner makes of any
  name or path is valid UTF-8 within its bound and an `fgtext` and
  `cwdtext`, and one already within them is unchanged.

**End to end, `internal/e2e`:**

- **This machine, no ssh** (§2.2; no sshd needed, so it always runs on
  Linux). The real binary with `localhost`, its `HOME`,
  `XDG_RUNTIME_DIR` and `SHELL` the test's own: a session starts and
  predicts (`-predict always`), detaches on SIGHUP with a hint naming
  `localhost`, is listed detached, and is reattached by `-s NAME` with its shell's
  state; `-dir` of no directory starts nothing, then starts there;
  `-kill` ends a session; a throwaway agent is the shell's unless `-a`.
  With the throwaway sshd as well, a session started locally is listed
  over ssh and taken over by `-s NAME HOST`.
  A command, `mosey localhost sh -c 'echo ran-$((6*7)); exit 3'`, shows
  its output and the client exits when it does, with status 0 (§9.2.3);
  `-s NAME localhost CMD` with NAME running says the command was not
  run, and attaches. Returning to a command
  (`TestALocalCommandIsReturnedToAfterADetachAndNeverMixedWithAShell`):
  `mosey localhost sh`, detached, is listed with its command, and the
  same line run again returns to it, its shell's state intact, though a
  shell session was detached since; while that one is attached a second
  `mosey localhost sh` gets a new session; a plain `mosey localhost`
  never takes the detached command session, nor `mosey localhost sh` the
  detached shell, which a plain `mosey localhost` then does take.
  `choose`'s unit tests (`internal/server`) cover the same rule, and that
  `existing` is added only when the taken session's `cmd` differs.

- **Fake ssh, always runs.** `SSH.Program` is a test helper binary that
  takes ssh's argv, checks it is the §4.1 shape, and runs the remote command
  with `sh -c` locally, with `SSH_CONNECTION="127.0.0.1 1 127.0.0.1 22"`.
  With the real `mosey` built by the test: the line exchange, a server of
  another version (a second build with another `-X main.version`) that
  serves the client all the same (D8 V1), a server of another protocol
  (a stand-in that answers `MOSEY-ERROR 3 !code=version`) refused with §6.4's
  line, `-remote` to a
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
- **Sessions through real sshd** (§9), same harness, with sshd's
  `SetEnv XDG_RUNTIME_DIR=` a throwaway directory so the attach sockets
  live under the test (`TestSessionsThroughRealSSH`): a first plain client
  starts a session and sets a shell variable; a second plain client, the
  first still attached, gets a new session of its own; the first, sent
  SIGHUP, detaches and says its name; a third plain client resumes that
  session (the variable is still set); `-s NAME` takes it over and the
  third exits 3; `-new` starts a third session; `-list` shows every name
  and state; `-kill NAME` ends one, whose client exits 0; and `exit` in
  the last ends it, after which nothing of it is running.
- **Start options through real sshd** (§9.2.3), same harness
  (`TestDirAndTypeStartASessionAndAreIgnoredOnResume`): `-s work -dir
  sub -type 'echo hi'` creates session `work` whose shell is in
  `$HOME/sub` and whose screen shows `hi` as a line of output; after it
  detaches, `-s work -dir other -type …` resumes it, still in `$HOME/sub`
  (`other` does not exist, and nothing is typed); `-new -dir missing` is
  refused with §6.4's `dir` message, exit 1, and starts no session.
  With bash as the login shell (`TestTypedTextShowsOnceAfterTheFirstPrompt`,
  skipped without bash), `-type 'echo typed-once'` shows the typed line
  once, right after the first prompt, then its output.
- **Reconnect, R3** (§9.2.2), on netsim in virtual time
  (`TestAClientWhosePathDiesReconnectsByItselfAndKeepsItsScreen`,
  `TestAReconnectThatFindsTheSessionGoneOrTakenEndsTheClient`), the
  server's silence rule (`TestASilentClientCountsAsDetachedUntilItIsHeardAgain`),
  and the client loop's tries, backoff and swap under synctest with fakes
  (`internal/client`, `reconnect_test.go`).
- **The idle timeout and `-kill`** (§9.3, §9.5), with an injected short
  `IdleTimeout`, on the spawner with a stub proto
  (`TestADetachedSessionIsHungUpAfterTheIdleTimeoutAndAnAttachStopsTheClock`,
  `TestKillHangsTheShellUp`, `internal/server`).
- **Auto-upload through the real sshd** (§4.7), with the remote's `HOME`
  a temporary directory and its `PATH` the test's own (the throwaway
  sshd's `SetEnv HOME= PATH=`), and no `-remote`: on a host with no
  mosey the client asks, is told `y`, copies itself, and ends with a
  working session and `~/.local/bin/mosey` byte-for-byte the client's
  file, whose shell finds `mosey` in `~/.local/bin` (§4.7.9); a client
  of another version then uses that copy as it is and copies nothing; a
  `~/.local/bin/mosey` of another protocol is replaced, whether or not
  `PATH` names `~/.local/bin`; a `mosey` elsewhere on `PATH` of
  another version is used as it is, and one of another protocol fails
  with §6.4's line and nothing is copied; and a `~/.local/bin/mosey` that
  is a symlink, or a `~/.local/bin` that is one, is refused with nothing
  written through it.
- **NixOS VM** (`tests/install.nix`, CI's `vm-install`): a host with no
  mosey gets one by consent and runs the session from
  `~/.local/bin/mosey`; a second run asks nothing.
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
| the stdin line attacks the unsandboxed spawner | one grammar, `MaxClientLine` read bound, at most `MaxFields` fields, 30 s deadline, fuzzed, canonical; an unknown field is dropped before anything acts on the line, and one marked critical refuses it |
| a field that restricts or instructs is silently ignored by an older peer (`versioning.md` §3) | every such field is critical (`!`), so a peer that does not know it refuses the line rather than acting without it; each line's table says which fields are and why (§6.2–§6.4, §4.7.2, §9.2.1, §9.4) |
| a hostile remote injects a session-bind after ssh's | §8's state machine: anything after ssh's own bind means no bind ([S3] E11) |
| a live ControlMaster carries the bootstrap | always a fresh connection ([S3] E12, E12b) |
| the user's config undoes a bootstrap option | ours come first; flags that beat `-o` are filtered (§2.1, §4.1) |
| version skew between client and server | normal (D8 V1): no software version is compared; the lines' number and the handshake's protocol name only their envelopes (`versioning.md` §5) and are each checked for equality, the latter inside the authenticated handshake (`transport.md` §3.6), so no one on the path can make two builds disagree about it; a session runs the binary that started it until it ends (§9.2 step 5, `server.md` §2.8) |
| a stolen client keeps the session | exclusive attach on any new confirmed login (§9.1, D26); its background reconnect never takes back a session another credential holds (§9.2.2) |
| a hostile server prints escape sequences in `-list`'s names | the client parses each list line against a grammar of printable ASCII and lays out the table itself (§9.4, fuzzed) |
| a hostile server sends a name that is not an `sname` | the CredentialLine refuses it (§6.3), so the client never prints one |
| a hostile remote steers the client's UDP at a broadcast, multicast or local address | grammar refuses unspecified, multicast, limited broadcast; §7.2 refuses local directed broadcast and loopback for a non-loopback destination (threat-model §4.9) |
| a compromised proto chooses where the client sends UDP | the spawner checks `addr`, `port` and `name` against its own (§4.4 step 3) |
| failed bootstraps pile up detached shells | a session with no confirmed credential ends after CredentialTTL (§4.5) |
| late remote bytes corrupt the session screen | ssh's stderr after the line goes, filtered, only to the log file (§7.4) |
| a planted symlink or another user's file redirects the auto-upload's install (D7) | the installer works through `O_NOFOLLOW` descriptors below `~/.local`, checks owner and mode at every level, and never replaces what is not the user's (§4.7.7) |
| a corrupt, cut-short or substituted binary is installed (D7) | the installer checks the length and SHA-256 the client computed or read from `SHA256SUMS` before the rename (§4.7.4, §4.7.7) |
| a compromised GitHub release, CDN or account serves another binary with a matching `SHA256SUMS` (D7) | **not covered by the client** (§14 question C, parked): the release job attests every binary (§4.6), so a person can catch it with `gh attestation verify`, but the client checks only `SHA256SUMS` |
| a hostile remote lies about its platform | it chooses which public build it is sent, nothing more (§4.7.2) |

---

## 14. Open in this document

A. **An upgraded client and an old session.** *Closed by D8 V1* (§9.2
   step 5): a launcher of any version attaches a session of any version
   with its attach protocol, which goes on running its own binary; an
   upgrade takes effect on new sessions.

B. **The spawner's confirmation backstop** (§4.5): the `Attached`
   message and the CredentialTTL + 10 s rule are a requirement this
   document places on `server.md`, which has yet to take it up.

C. **Signed releases** (§4.6). *Parked (Dan, 2026-11-15; D7 as amended,
   PLAN O16).* CI attests every binary with
   `actions/attest-build-provenance` (GitHub OIDC and Sigstore, no
   long-lived key), and GitHub stores the attestations, so a person can
   check a download with `gh attestation verify FILE --repo
   danielbodart/mosey`. The client checked them for a while with
   sigstore-go, which doubled the binary (9.9 to 21 MB) and brought about
   65 modules, so it was removed; the client checks `SHA256SUMS` only
   (§4.7.4). To revisit with a small verifier; no large dependency.

D. **A local cache of downloaded releases** (§4.7.4). Each host of a
   foreign platform downloads the release again; keeping it under
   `$XDG_CACHE_HOME/mosey/` would save that, at the cost of one more
   file the client must re-verify before trusting.

E. **Old versions of the installed copy.** *Closed by D7 as amended
   2026-11-15*: there is one file, `~/.local/bin/mosey`, replaced only
   when it speaks another protocol, so nothing piles up.

D. **Telling a client taken over long ago** (§9.1). *Answered by the
   sessions slice*: R3's reconnect hears `taken` from the launcher and
   says so (§9.2.2), without the address.

F. **A background reconnect that finds its session held by another
   client** (PLAN O15, §9.2.2). For Dan: it exits as taken over today;
   it could take the session back as `-s` does.

G. **Hopping through a login profile that sets `PATH`** (§4.7.9).
   *Closed by Dan, 2026-11-16*: mosey installs to `~/.local/bin/mosey`,
   which the stock login profiles put on `PATH` (Debian and Ubuntu
   `~/.profile`, Fedora `~/.bashrc`), so hopping works there with no rc
   file edited. NixOS needs mosey from Nix.

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
   §14 question A, for the resume slice. *Superseded by D8 V1:* nothing
   compares software versions any more, and a launcher attaches a session
   of any version as it is (§6.4, §9.2 step 5).
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
11. **Telling a mosey session by its processes, and the `mosey-server`
    comm (major).** §8 says that under D7 no process is named
    `mosey-server`, and that the spawner's argv (`--serve=spawner`) is
    what marks a session as built. Setting
    the comm to `mosey-server` with `PR_SET_NAME`, as the review
    suggests, is not taken: D7 as settled says no process has that name.
    Since D28's amendment (2026-11-15) this describes the current process
    shape only, with no promise to any tool that it stays so.
