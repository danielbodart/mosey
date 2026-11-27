# Bootstrap: start a session over SSH

Owner: **bootstrap-client**. Packages: `internal/bootstrap`, `internal/client`
(its bootstrap half), `cmd/mosey/main.go`. The server half of each step is
in `internal/server`, and `server.md` specifies it. This document says what
the server must do *as seen from the SSH channel*.

This document implements these decisions:

- D6: start over SSH with the user's config.
- D7: one binary, and auto-upload where the host has none.
- D8: resume. Its stable protocol, V1, is in §6 and §9.2.
- D20 (B3): one-shot keys over stdin and stdout.
- D25: agent bind capture, §8. The channel it feeds is in `agent.md`.
- D26: exclusive attach.

These decisions are locked. If this text and PLAN.md disagree, PLAN.md is
correct and this file has the bug.

Provenance tags on constants:

- **[S1]**, **[S3]**, **[S4]**: measurements or choices from our spikes
  (see `docs/spikes/<id>/FINDINGS.md`).
- **[ssh]**: black-box behaviour of OpenSSH 10.6p1, or its man pages
  (`ssh(1)`, `ssh_config(5)`, `PROTOCOL.agent`). Checked on dan-desktop on
  2026-11-14.
- **[mosh-man]**: the Mosh man page.
- **[shells]**: black-box behaviour of the named shells, checked on
  dan-desktop on 2026-11-14. The shells are bash as `/bin/sh`, tcsh
  6.24.16, fish 4.7.1, nushell 0.112.2 and zsh from nixpkgs.
- **[derived]**: calculated here. The calculation is shown.
- **[choice]**: our choice, not tuned.

We did not read Mosh source code, and nobody may read it.

Roles (D7, `server.md` §1):

- **launcher** is `mosey --serve`. ssh starts this process.
- **spawner** is `mosey --serve=spawner`. It is detached, has no sandbox,
  and owns the session.
- **proto** and **emu** are `--serve=proto` and `--serve=emu`.

All of these roles are the same `mosey` file.

---

## 1. What the bootstrap is for

SSH does three jobs. Then it has no more part in the session:

1. It authenticates the user to the host and the host to the user. It uses
   the user's own keys, agent, `known_hosts` and `~/.ssh/config` (D6).
2. It starts the server: `mosey --serve` on the far host.
3. It carries two lines. The client's one-shot X-Wing public key goes up
   stdin. A credential comes down stdout (D20, B3).

B3 needs SSH to be **authentic, not confidential**. A recorder, `script(1)`
or a bastion log can capture both lines. It cannot use them to impersonate
either side ([S1] §5, ProVerif `b3_stdout_leak`, S1's
`TestB3LeakedStdoutCannotImpersonate`; in mosey
`TestALeakedCredentialLineCannotImpersonateTheClient`). Neither line
contains a secret in the sense that matters. The PSK is in the clear on
purpose. It is defence in depth and the key of the msg1 DoS filter. It is
not an authenticator.

After the credential line, ssh exits. The session continues in the
detached server. The session does not use the SSH connection again until
a resume (§9).

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

The client reads the words in this order. Each part ends where the next
part starts:

1. mosey's own flags, by Go's `flag` rules. They end at the first word
   that is not one of them, or at `--`.
2. After a `--`, ssh's options, by ssh's getopt rules (§2.1). They end at
   the first word that is not an option or an option's value.
3. `DESTINATION`: the first such word.
4. The command: all words after `DESTINATION`, not changed.

Thus mosey never reads the flags of the command (`mosey far ls -la`). The
ssh options always come before the destination, after `--` (`mosey -s
work -- -p 2222 far claude`). That is where they went before commands
existed.

No `DESTINATION`, or a `DESTINATION` of `localhost` (any case), means this
machine. Then the client runs no ssh (§2.2). `mosey` alone resumes or
starts a session here. `mosey -list` lists the sessions here. tmux works
the same way [D: Dan, 2026-11-18, reversing 2026-11-16's "this machine is
asked for by name": tmux works this way, and spelling out `localhost` was a
chore]. A COMMAND needs a `DESTINATION` before it, because the first plain
word is always the destination. `-h` and `-help` print the usage on stdout
and exit 0.

- `DESTINATION` goes to ssh without change. It can be `host`,
  `user@host`, an alias from `~/.ssh/config`, or `ssh://user@host:port`.
  It has these limits:
  - It is at most 1024 bytes.
  - It does not start with `-`.
  - It contains no bytes below 0x21 and no 0x7F. (ssh reads a space as
    the start of the command.)

  Any other value is a usage error (exit 2). Only the exact word
  `localhost` means this machine without ssh. `127.0.0.1`, `::1`,
  `me@localhost` and an ssh alias for this host all go through ssh, as
  other hosts do. Thus you can still test the ssh path against this
  machine.
- `-remote PATH` is the remote mosey binary (§4.2). Without it, the client
  uses the mosey that the host has. The client copies itself to the host
  only if the host has no usable mosey (D7, §4.7).
- `-upload ask|yes|no` says what to do when the far host has no usable
  mosey (§4.7.5). The default is `ask`. Any other value is a usage error.
- `-ssh PROGRAM` is the local ssh. The default is `ssh`, found on `PATH`.
  Tests set it to a fake (§12).
- `-A` and `-a` are ssh's own flags (D25). They force agent forwarding on
  or off. You can give them as mosey flags or among the SSH options. The
  last one given wins, as in ssh ([ssh]: `ssh -A -a` resolves to
  `forwardagent no`, and `ssh -a -A` to `yes`).
- Without any of the next four flags, `mosey DESTINATION` resumes the
  user's most recently detached session there that started without a
  command. If no such session is detached, it starts a new one (D8 R1,
  §9.2). With a `COMMAND`, it resumes the most recently detached session
  that started with that command (see below). There is no resume flag.
- `-s NAME` attaches to the session with the name NAME. If another client
  has the session, this client takes it over (D26). If there is no session
  NAME, it starts one with that name (D8 R2). NAME is the `sname` of §6.2:
  1 to 32 letters, digits, `-`, `_` and `.`, and the first character is a
  letter or digit. Any other NAME is a usage error.
- `-new` always starts a new session, with a generated name.
- `-list` lists the sessions there and exits (§9.4). `-kill NAME` ends
  session NAME (§9.5). Only one of these four flags is allowed at a time.
  The old `-r` and `-r=SESSION` are removed: `-s` replaces them.
- `-dir DIR` and `-type TEXT` say how a session starts (§9.2.3). Its login
  shell starts in DIR. DIR is relative to the remote `$HOME`, unless DIR is
  absolute. The client types TEXT into the shell, followed by Enter.
  - These flags apply only when the command **creates** a session. That
    is a plain `mosey DEST` that finds no detached session, `-new`, or
    `-s NAME` when there is no session NAME.
  - When the command resumes or takes over an existing session, the
    client ignores these flags and gives no error.
  - DIR is 1 to 1024 bytes of UTF-8 with no control character. TEXT is 1
    to 1024 bytes of UTF-8 with no control character except tab. These are
    the `dirtext` and `typetext` of §6.2.
  - Any other value is a usage error. Either flag with `-list` or `-kill`
    is also a usage error.
  - An empty value is the same as no flag.

  These flags replace what a tmux user does with `tmux new-session -c DIR`
  and then `tmux send-keys TEXT Enter`. Thus a session can open in a
  project and start a program there. When the program exits, the user
  stays in the shell in that directory, with their full `PATH`.
- `-close-if-idle` is for local sessions only (§2.2). With any other
  `DESTINATION`, or with `-list` or `-kill`, it is a usage error. The
  flag has an effect when one of these events occurs while the client is
  attached:
  - The client receives `SIGHUP` or `SIGTERM`.
  - Its terminal closes. A read ends with EOF or fails with `EIO`. This is
    the hangup that a closed window gives, and it often arrives before its
    `SIGHUP`.
  - The terminal refuses raw mode just after Dial. This is a window closed
    during start-up.

  Then the client connects to the attach socket of the session. It sends
  `HangupIfIdle` with its current credential id (`server.md` §2.4, §2.6).
  Then it exits cleanly. The spawner ends the session if all of these are
  true:
  - The shell is idle at its prompt.
  - There are no other processes in the session.
  - No other client has taken over.

  If not, the session stays alive and detached.
- The client filters the `SSH-OPTION`s after `--` (§2.1). It gives them to
  both ssh invocations.
- `COMMAND [ARG...]`, the words after `DESTINATION`, are a command. It runs
  in place of the interactive shell, as `ssh DEST COMMAND` runs one (Dan,
  2026-11-16: `mosey dan-desktop claude` should end, and leave the
  terminal, when claude does).
  - The client joins the words with single spaces, as ssh does. The
    user's shell runs the result as `SHELL -c TEXT`. Thus quoting and
    expansion are those of that shell (§9.2.3).
  - The command runs on the pty of the session, in DIR if `-dir` is given.
    When the command exits, the session ends. Then the client exits as it
    does when a shell exits.
  - As with `-dir`, the command runs only when a session is **created**.
  - A plain `mosey DEST COMMAND` is R1 keyed by the command (PLAN D8, Dan,
    2026-11-16, option C: closing the window on `mosey dan-desktop claude`
    and running it again should "connect back to the same one and resume
    it and not create another instance if there's one there"). It resumes
    the most recently detached session that started with exactly that
    text, byte for byte. If there is none, it starts a new session that
    runs the command, with a generated name.
  - It never takes an attached session. Thus a second window that runs the
    same line gets a second instance.
  - The match uses only the command. As on any resume, the client ignores
    `-dir`. To keep apart two sessions of one program in two directories,
    use `-s NAME` [D: the command is what the user sees and names; a
    directory given relative to a home would have to be resolved to be
    compared, and a plain `mosey DEST -dir X` without a command does not
    match on it either].
  - `-s NAME DEST COMMAND` starts NAME with the command if there is no
    session NAME. If session NAME exists, the client takes it over without
    change. If NAME did not start with that exact command, the client
    writes this on stderr: `mosey: session NAME was already running, so
    the command was not run`.
  - A session that starts with a command is a usual named session. You can
    detach it, list it (with its command), take it over and kill it.
  - The joined text is 1 to 1024 bytes of UTF-8 with no control character
    except tab (the `cmdtext` of §6.2). These are usage errors:
    - any other text;
    - a command with `-type` (both say what to run, and typing into a
      command is not what `-type` means);
    - a command with `-list` or `-kill`.
- `-completion bash|zsh|fish` prints the completion script for that shell
  on stdout and exits 0. It starts nothing and needs no `DESTINATION`, as
  `-version` does. Any other shell, or no shell, is a usage error [D: Dan,
  2026-11-16: `mosey d<TAB>` should offer the hosts `ssh d<TAB>` does].
  - The scripts give `DESTINATION` to the ssh host completion of the
    shell.
  - The scripts get mosey's flags from the flag set that the client parses
    with. Thus the two cannot become different.
  - TAB never runs ssh. `-s` and `-kill` complete from `mosey -list
    localhost`. They do this only when `DESTINATION` is `localhost` or not
    yet typed.

Every plain word belongs to the client (D7). `mosey server` connects to a
host with the name `server`. Server mode is always and only the flag
`--serve` as `os.Args[1]`.

### 2.1 Which ssh options pass through

The client parses the SSH options with ssh's getopt rules. It accepts
clusters (`-4vC`), attached arguments (`-p2222`, `-oUser=x`) and separate
arguments (`-p 2222`). The parser gives them in a normal form: one flag per
argument, and each option with an argument as two arguments (`-p`,
`2222`).

| Kind | Letters | What happens |
|---|---|---|
| Flags passed through | `4 6 C K k q v x` | to `ssh -G` and the bootstrap ssh |
| Options with an argument, passed through | `B b c E F I i J l m o P p` | same |
| Used by mosey | `A a` | decide agent forwarding (§5); passed to `ssh -G` only, never to the bootstrap ssh |
| All other letters | e.g. `t T N n f s G V O W M S L R D X Y g e w Q y` | refused: `mosey: ssh option -X can't be used for the bootstrap`, exit 2 |

Why the client refuses these options and does not ignore them: each
refused option does one of two things.

- It breaks the two-line protocol. `-t` gives a pty that echoes and
  changes LF to CRLF. `-n` and `-f` take stdin away. `-N`, `-s`, `-W`,
  `-G` and `-O` run no command.
- It does nothing useful, because ssh leaves the session after a second
  (`-L`, `-R`, `-D`, `-X`, `-M`, `-S`).

An error message is better for the user than a session that silently does
not have the forward the user asked for. These are also usage errors:

- a bare word among the SSH options;
- a second `--` among the SSH options;
- an option without its argument.

mosey must filter `-A`, `-T` and `-t`. It must not override them with
`-o`. [ssh] The flags win over any `-o`, in any order. `ssh -o
ForwardAgent=no -A` and `ssh -A -o ForwardAgent=no` both resolve to
`forwardagent yes`. `-t -o RequestTTY=no` resolves to `requesttty true`.

### 2.2 No `DESTINATION`, or `localhost`: this machine

These commands act on the sessions of this user on the machine where the
client runs, with no ssh: `mosey`, `mosey -s NAME`, `mosey -new`, `mosey
-list` and `mosey -kill NAME`, each with or without `localhost` after it.
Thus mosey is a local terminal multiplexer, as tmux is. It also gives an
end-to-end test that needs no sshd [D: Dan, 2026-11-16; no `DESTINATION`
again, Dan, 2026-11-18]. A hint for this machine names no host (`mosey -s
NAME`). The client compares the word `localhost` without regard to case.
No other word means this machine: no `user@`, no address and no alias.

**The local launcher.** §4.1 runs `ssh ... -- DEST "exec /bin/sh -c
'exec mosey --serve'"`. In its place, the client runs the server binary
itself, as `SERVER --serve` (or `--serve=list`, or `--serve=kill NAME`).
There is no shell between them. `SERVER` is the path from `-remote` if
given. If not, it is the file of the client (`os.Executable`). Its stdin,
stdout and stderr are the ones that ssh would have had. All other steps
are the same:

- the ClientLine up stdin;
- the CredentialLine (or ErrorLine) down stdout, through `ReadCredential`;
- its stderr through the §6.5 filter;
- then the handshake, SSP, prediction, resume and R3.

SSP uses its local timing when the client dials a loopback address, as it
does for a session that started here (`ssp.md` §6.2.1).

There is nothing for SSH to vouch for (D6). The client started the server
itself, as the same user.

The client skips these steps, because they all concern ssh:

- `ssh -G`. `Resolve` returns a config that holds only `hostname
  127.0.0.1`, for §7.2.
- The options of §2.1.
- The probe and upload of §4.7.
- The bind capture and `BatchMode` of §8.

The client runs a path given to `-remote` as it is. Thus the path needs
none of the quoting rules of §4.1. The client looks up a bare name on its
`PATH`.

**The same sessions.** The launcher, its spawner and the attach sockets
(`R/mosey/SID-HEX/attach.sock`, `server.md` §2.6) are exactly those of an
ssh login to this host. Thus `mosey -list THISHOST` from a different host
lists a session that started locally. `mosey -s NAME THISHOST` can take it
(D26). Also, you can take a session here that started over ssh. This has
two results:

- The launcher gets the environment of the client, minus `SSH_CONNECTION`,
  `SSH_CLIENT`, `SSH_TTY` and `SSH_AUTH_SOCK`. This is not an ssh login,
  even when the client itself runs inside one.
  - With no `SSH_CONNECTION`, the spawner advertises no address and binds
    the wildcard (`server.md` §2.2). Thus a client from a different
    network can still reach a session that started here.
  - The local client finds the session on `127.0.0.1` (the fallback of
    §7.2). Loopback is allowed because the destination is loopback.
  - A session that started over ssh advertises the address that the
    login reached. The local client sends to that address.
  - The shell gets the remaining environment of the client, as under
    tmux. Under ssh, it gets the environment of sshd.
- A local `-dir` is relative to `$HOME`, as over ssh. It is not relative
  to the working directory of the client. With no `-dir`, a new local
  session starts in the working directory of the client (§9.2.4).

**The agent.** There is no ssh, so there is no session-bind to capture
(§8). Also, there is no far host for a bind to name. The shell is a
process of the same user on the same machine as the agent, and it could
open the agent socket directly. Thus the shell gets the agent that the
client has, through the agent socket of the session (`agent.md` §4.1). The
client replays nothing (`agent.Forwarder.Unbound`). Each connection
reaches the agent as the connection of any local process does.

- The forwarded socket is the `SSH_AUTH_SOCK` of the client. With none,
  the agent is off.
- `-a` turns the agent off.
- `-A` with no `SSH_AUTH_SOCK` writes `mosey: not forwarding the agent:
  SSH_AUTH_SOCK is not set`.

The socket of the shell belongs to the session, not to the client. Thus
the agent follows the attached client. A client that takes the session
over ssh with `-A` gives its agent, bound as §8 says. A client that takes
it back here gives the agent of this terminal again.

**Flags that need ssh.** `-upload` and `-ssh` say how to reach a host or
what to copy to it. The ssh options after `--` are for an ssh that does
not exist here. On this machine these are usage errors (`mosey: -upload
has no use with localhost, which runs without ssh`). The client does not
silently ignore them. `-A`, `-a`, `-remote`, `-predict`, `-dir`, `-type`,
`-close-if-idle` and the session flags have the same meaning as over ssh
(`-close-if-idle` is local only).

**Messages** name `localhost` where they otherwise name `DEST` (`no
sessions on localhost`, `work is not a directory on localhost`). But a
hint names no host, because this machine is the default (`resume it with:
mosey -s NAME`). If the launcher prints no line, the message gives its
status (`SERVER exited with status N and no mosey line`). If the launcher
cannot run, the message is `running SERVER: ERR`.

No protocol number changes. The lines, the hello and the greeting are the
same as over ssh.

---

## 3. Resolve the user's config: `ssh -G`

Before the bootstrap, the client runs this command, with no stdin and a
10 s deadline [choice]:

```
PROGRAM -G USER-OPTIONS... [-A|-a] -- DESTINATION
```

`USER-OPTIONS` are the filtered options of §2.1. The agent flag is the
last of `-A`/`-a` that the user gave, if any.

- The client reads stdout up to 256 KiB [choice; a typical config prints
  about 3 KiB]. More output is an error.
- Each line is `keyword SP value`. Keywords are lower case [ssh].
- A keyword can occur more than once (`identityfile`, `sendenv`). The
  client keeps every value, in order.
- A non-zero exit is fatal. The client prints the stderr of ssh, filtered
  as in §6.5. This is how a typo in `~/.ssh/config` or a bad `-o` becomes
  visible ([ssh]: `-o Bogus=1` exits 255 with `Bad configuration option:
  bogus`).

`ssh -G` makes no connection. It can run `Match exec` commands, and ssh
runs them again for the real connection. That is the config of the user
doing what it says.

The client uses these keywords:

| Keyword | Used for | Slice |
|---|---|---|
| `forwardagent` | the agent decision (§5) | agent slice |
| `identityagent` | the socket that `ForwardAgent yes` forwards (§5) | agent slice |
| `hostname`, `port`, `hostkeyalias`, `userknownhostsfile`, `globalknownhostsfile` | pin a captured bind to `known_hosts` (§8) | agent slice |
| `hostname` | UDP address fallback (§7.2) | 1 |
| `proxyjump`, `proxycommand` | the note that UDP does not follow a proxy (§7.2) | 1 |
| `sessiontype`, `stdinnull`, `forkafterauthentication` | whether this ssh knows these keywords, so the bootstrap can force them (§4.1) | 1 |

`ssh -G` prints `sessiontype`, `stdinnull` and `forkafterauthentication`
when the ssh supports them (OpenSSH 8.7 and later) [ssh]. The client uses
their presence as its feature test. It does not parse a version string.

The parsed result is a value type (`bootstrap.Config`), so that tests can
make it by hand.

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

(For `mosey -list`, `--serve=list` replaces `--serve`, §9.4. With no
`-remote`, the script is §4.7.2's probe, which runs the same flag.)

- **Ours come first, so ours win.** For `-o`, ssh uses the first value it
  gets. ssh reads command-line options before any config file [ssh;
  `ssh_config(5)`; checked: `-o ControlMaster=no -o ControlMaster=auto`
  resolves to `controlmaster false`]. The user's `-o` and config cannot
  undo our options. The flags that could (`-A`, `-t`) never reach this ssh
  (§2.1).
- **`ControlMaster=no`, `ControlPath=none`, `ControlPersist=no`.** The
  connection is always a fresh one. A multiplexed session has no key
  exchange of its own. Thus it has no session-bind to capture, and the
  agent trigger goes to the master's agent, not to the capture socket
  ([S3] E12, E12b). The cost is about 108 ms on loopback, once per start
  or resume ([S3]: mux 9.8 ms, fresh 117.8 ms median, n=10).
- **`-T`.** No pty. The bootstrap is two lines of protocol, and a pty
  echoes stdin and changes LF to CRLF. We use the flag form because it
  overrides a config `RequestTTY force` [ssh].
- **`ForwardAgent=no`**, or the capture socket's path when §5 says the
  agent is on (§8). Never the user's real agent. The bootstrap's agent
  channel exists only to make ssh send its bind.
- **`ForwardX11=no`, `ClearAllForwardings=yes`, `Tunnel=no`.** A config
  `LocalForward` would collide with the user's interactive ssh to the same
  host. An `ExitOnForwardFailure` would then kill the bootstrap. X11 and
  tun forwarding would give the far host a path back to the client
  (threat-model §4.9, which requires all three).
- **`PermitLocalCommand=no`, `EscapeChar=none`.** A config `LocalCommand`
  must not run or write to our terminal. A pipe gets no escape processing.
- **`RemoteCommand=none`.** In ssh, a config `RemoteCommand` together with
  a command on the line is an error. `none` clears it [ssh: with
  `-o RemoteCommand=none`, `ssh -G` prints no `remotecommand`]. This needs
  OpenSSH 7.6 or later. An older ssh fails with `Bad configuration option`,
  and the client reports it.
- **`SessionType`, `StdinNull`, `ForkAfterAuthentication`.** The client
  adds these only when `ssh -G` showed that the ssh knows them (§3).
  Without them, a config `SessionType none` or `StdinNull yes` would break
  the bootstrap. An older ssh rejects the unknown keyword.
- **`--`** ends ssh's options, so ssh can never read a destination as an
  option (§2 also checks it).

The remote command is **one argument**, `exec /bin/sh -c 'exec SERVER
--serve'`. sshd gives it to the user's login shell with `-c`, so it is
shell text.

**Why the `/bin/sh` wrapper.** The client finds a missing server by its
exit status (§4.2). Only a POSIX shell gives a fixed status. Without the
wrapper, a missing command exits 127 under sh, bash and fish. But it exits
**1** under tcsh (`Command not found.`) and nushell
(`nu::shell::external_command`). Under tcsh, a non-executable file also
exits 1 [shells].

Through the wrapper, all of them exit 127 for a missing file and 126 for
a file that does not run. This is because the status is `/bin/sh`'s
[shells: checked under bash, tcsh, fish, nushell and zsh]. The outer
`exec` keeps the user's shell out of the process tree. The inner `exec`
makes the launcher the process that sshd waits for. The cost is one
`/bin/sh` exec, about a millisecond. mosey does not support a host with no
`/bin/sh`.

`SERVER` is restricted, for two reasons. First, no outer shell then needs
quoting (sh, bash, zsh, fish, csh, nu: each takes `'…'` as a literal and
`exec` as a builtin [shells]). Second, the text inside the single quotes
then needs no quoting for `/bin/sh` either:

```
server = [ "~/" ] 1*pathchar          ; at most 256 bytes
pathchar = ALPHA / DIGIT / "." / "_" / "/" / "+" / "-"
```

`SERVER` must not start with `-`. A `-remote` outside this grammar is a
usage error. The remote `/bin/sh` expands the leading `~/`: it is the
start of a word in that script, and the outer shell sees it only inside
quotes. D7's `~/.local/bin/mosey` needs this [shells: checked under each
outer shell above]. `--serve` must be the binary's first argument, because
`cmd/mosey` tests only `os.Args[1]`.

### 4.2 Where the server binary comes from

There are two ways. The choice depends on whether the user named a
binary:

- **`-remote PATH` given.** The client uses that file and nothing else. It
  runs the §4.1 command exactly as slice 1 had it. There is no probe and no
  upload, because the user has said where mosey is.

  The client reports a missing or unrunnable file from `/bin/sh`'s exit
  status. That is 127 for a command `/bin/sh` cannot find and 126 for one
  it cannot run (POSIX). The §4.1 wrapper makes this true for every login
  shell of the user [shells]. ssh exits with the remote command's status.
  The client reports 126 or 127 with no protocol line as `ErrNoServer`
  (§10). A launcher never exits 126 or 127 itself (its failures are exit 1,
  §4.4), so the two cannot be confused.

  A server of any mosey version serves the client as the client's own
  version would (D8 V1). A server of another protocol fails the bootstrap
  with one line that names both numbers (§6.4). The client never replaces
  it, because the user named it.
- **No `-remote` (the default): D7.** The remote command becomes §4.7's
  probe. The probe runs `mosey` on the remote `PATH`, of any version. Else
  it runs `~/.local/bin/mosey` if that file speaks the client's protocol.
  Otherwise it prints the remote's platform. The client then copies a build
  to the host, with the user's consent, and starts again once (§4.7). The
  lines of §6 do not change. The probe asks `~/.local/bin/mosey` with
  `mosey --serve=protocol`.

### 4.3 The client's process handling

- **No core dumps.** The client makes itself leave no core, and makes
  itself unreadable by the user's other processes (`internal/nocore`,
  `threat-model.md` §4.10). It does this before the one-shot X-Wing key
  exists, so before anything else holds a secret. On Linux it sets
  `prctl(PR_SET_DUMPABLE, 0)` and `RLIMIT_CORE` 0. On darwin it sets
  `RLIMIT_CORE` 0.

  The reason: the client holds the PSK, the transport keys and the roots
  for the whole session. A core of it would undo forward secrecy (D8). ssh
  inherits the rlimit, which costs ssh nothing. `execve` resets `DUMPABLE`
  for ssh. If either call fails, the client stops before it starts ssh.
- **ssh's stdin** is a pipe. The client writes the ClientLine in one write
  as soon as ssh has started, then closes the pipe. The write occurs before
  authentication. It cannot block: the line is at most 4 KiB and a pipe
  holds 64 KiB. ssh delivers the line and then EOF to the remote command.
- **ssh's stdout** is a pipe that `ReadCredential` reads (§6.5). It is
  never shown.
- **ssh's stderr** is a pipe. Until the credential line arrives, the client
  copies it to its own stderr through the filter of §6.5. After the line,
  it still goes through the same filter, but then only to the client's log
  file (§7.4). It never goes to the terminal, which is about to be in raw
  mode under the session's screen.

  ssh's stderr is not inherited. ssh relays the remote's stderr and the
  server's banner, and D9 says no remote escape sequence reaches the local
  terminal. ssh's prompts (passwords, passphrases, host-key confirmation)
  are not on stderr. ssh opens `/dev/tty` for them, which is why they
  still work.
- **The local terminal stays cooked** until `transport.Dial` succeeds
  (§7.3). ssh's password prompt reads a line from `/dev/tty`. In raw mode,
  Enter sends CR, not LF, and the prompt never ends.
- **Signals.** Until raw mode, Ctrl-C is a SIGINT to the foreground process
  group, which is both mosey and ssh. mosey dies with its default action,
  because nothing *local* needs restoring yet. SIGTERM and SIGHUP cancel
  the context, which kills ssh (`exec.CommandContext`). By then the far
  side can have started a session. The client does nothing about it,
  because §4.5 guarantees that a session nobody connects to ends by itself.
- **After the line**, ssh should exit within a round trip, because the
  launcher has exited and closed its fds (§4.4). The client does not wait
  for ssh before it dials. It reaps ssh in the background. If ssh has not
  exited 10 s after the line [S3: the capture deadline], the client sends
  SIGTERM, then SIGKILL 1 s later. A non-zero exit after a valid line is
  logged, not fatal.

  With the agent on, the client waits for the capture's final state before
  it dials, because the Hello depends on it (§7.3, §8 step 5). That state
  is final at the capture connection's EOF, or at ssh's exit if no
  connection came. The launcher's trigger causes that EOF before the line
  is printed.

### 4.4 The server's side, as SSH sees it

This section gives the steps on the far host, in order, and the role that
does each step. The messages between launcher and spawner are in
`server.md` §2.1 and §3.3 (`ClientLine` 0x40, `Ready` 0x41, `Failed` 0x42,
on the socketpair B). The timeouts T1–T3 are in `server.md` §8.

1. **Launcher.** Read stdin **to EOF**, at most 8193 bytes, within T1 =
   30 s [derived: `handshake.CredentialTTL`; the client writes the line
   before authentication, so it is there when the command starts]. Stdin
   must be exactly one ClientLine: one LF, at the end, then EOF. Anything
   else is `MOSEY-ERROR 1 !code=line`.
2. **Launcher.** Parse the line (§6.2). The parse checks the line's
   protocol number (§6.4). It refuses a critical field that it does not
   know with `unsupported` (§6.2). No software version is sent or compared
   (D8 V1). Then start the spawner, `mosey --serve=spawner`, as a new
   process with `Setsid`, stdio on `/dev/null` and B as fd 3. Send it
   `ClientLine` (0x40). Wait up to T2 = 15 s for `Ready` or `Failed`.
3. **Spawner** (`server.md` §2.1 step 4). The spawner does these steps:
   - Parse the line again, bind UDP, and open the pty at the line's size
     (clamped by `screen.ClampSize`).
   - Start emu and proto. Proto mints a credential (D20: TTL 30 s, at most
     2 unused per session). Proto returns it as `Credential` (0x30),
     within T3 = 10 s [choice].
   - **Check every field that the spawner owns.** The line must parse
     (`ParseCredentialLine`) and re-marshal to the same bytes. It must
     carry exactly the spawner's own advertised `addr` (or none), its own
     bound `port` and the session's `name` (`server.md` §3.4). Proto
     chooses only `credid`, `sid`, `psk` and `public`, the four things
     that only proto knows. Thus a compromised or buggy proto cannot
     choose where the client sends UDP.
   - Only then start the login shell with the line's environment (§6.2).
     Type a `type`'s text when the shell has written its first output
     (§9.2.3). Send `Ready` (0x41) with the line.
4. **Launcher.** If the line says `!agent=yes` and sshd set
   `SSH_AUTH_SOCK`, trigger ssh's bind (§8, "Server"). Then write the line
   from `Ready` to stdout in **one** write.
5. **Launcher. Detach.** No process of the session may keep fds 0, 1 or 2
   of the SSH session open. The process that ssh started must **exit 0**.
   sshd sends the exit status and closes the channel only when the command
   has exited. Thus a session process that only closed its stdio would
   hold ssh open.

   The process that sshd started is usually a session leader already.
   sshd makes the login shell one, and the shells `exec` down to the
   launcher (§4.1). So it cannot `setsid` itself. That is why the spawner
   is a separate process, started with `Setsid` in step 2 ([S4] §3.10 did
   this with `setsid -f`; [S3]'s `moseys` with `SysProcAttr{Setsid: true}`
   and a pipe for the line). See open question 5.
6. **Launcher.** Before it exits, the launcher writes human-readable
   errors to stderr, prefixed `mosey --serve: `. These are what the user
   reads. The spawner never writes to ssh's pipes. It logs to its session
   log (`server.md` §6.4).

On any failure in steps 1 to 3, the launcher:

- writes one line on stderr that says what failed;
- writes one `MOSEY-ERROR` line on stdout;
- exits 1, and leaves nothing running. It SIGKILLs a spawner that has not
  sent `Ready` (`server.md` §2.1 step 3).

If step 4's write fails (ssh has gone: `EPIPE`), the launcher sends
SIGTERM to the spawner and exits 1. The spawner then tears the session
down (`server.md` §2.4).

**Bind address.** The spawner binds UDP in 60000–61000 [mosh-man: the
documented range, so firewall rules written for Mosh admit mosey]. It
binds on the server address from `SSH_CONNECTION` when there is one. On a
multi-homed host, replies then leave from the address that the client
sends to. Otherwise it binds the wildcard address (`server.md` §2.2).

**Requirement on `server.md` §2.2:** when that address is loopback, the
spawner advertises it but binds the wildcard. It already does this for
link-local. SSH reached over a local forward or tunnel shows a loopback
`SSH_CONNECTION`. The client then falls back to `hostname` (§7.2), and a
socket bound to 127.0.0.1 would never see its packets. In the same way,
the spawner advertises `-`, never an address that the client must refuse
(§6.3: unspecified, multicast, limited broadcast).

### 4.5 A session nobody connects to

**Requirement.** A `new` session whose credentials all expire unconfirmed
ends by itself. The condition is that every credential that proto minted
for it has passed `handshake.CredentialTTL` (30 s, D20) without a
confirmed transport. Then proto sends `Exit{NoClient}`, and the spawner
runs its teardown (`server.md` §2.4). The teardown closes C and hangs up
the pty, so the shell gets SIGHUP. After their grace periods, it SIGKILLs
the shell's pid, proto and emu, then exits.

So a bootstrap that never finishes leaves nothing running for longer than
about 30 s plus the teardown's grace periods. Examples are UDP blocked,
Ctrl-C after the line, a client crash, or a failed write by the launcher.

**Requirement on `server.md`** (a backstop, not yet there): the spawner
also ends the session if proto has not told it of a first confirmation
within CredentialTTL + 10 s of `Ready` [choice: a margin for the teardown
and clock granularity]. This needs one more proto → spawner message
(`Attached`, no payload). Without it, a proto that hangs before
confirmation holds a shell forever. Until server.md adds it, proto's
`NoClient` is the only rule. The e2e test of §12 checks that rule.

The shell starts *before* the first confirmation, at step 3, on purpose.
Its start-up (rc files, often hundreds of milliseconds) overlaps the
client's handshake. The exception is a `type`, whose `Ready` waits for the
shell's first output (§9.2.3). A later start would not protect anything.
The user's rc files have already run once for the same SSH login, because
sshd ran `SHELL -c` to start the launcher (§6.5 exists because rc files
print). And that login is the user. See the review notes (§15).

**Environment for the shell.** sshd's `SSH_AUTH_SOCK` (if any) dies with
the bootstrap connection. So the spawner never passes it to the shell.
With `!agent=yes`, the shell gets mosey's own socket instead (`agent.md`
§4.1). Other session variables are `server.md`'s concern.

**Known hazard (fixed where the user lingers).** With systemd-logind's
`KillUserProcesses=yes`, the detached session is killed when the SSH
login ends, as Mosh's server is. [S4] §3.10 ran it under
`systemd-run --user`, which survives. Decided (2026-11-23): the spawner
moves itself into a scope in the user's manager,
`mosey-session-<pid>.scope`. It does this whenever that manager lives at
least as long as the login (`server.md` §2.1 step 4.2). For an ssh login,
that is only when the user lingers (`loginctl enable-linger`). Otherwise
the manager stops soon after the login ends and would take the session
with it.

So with linger, a session survives `KillUserProcesses=yes`. Without
linger, the hazard stays, and the user's remedy is to enable linger.
mosey does not enable linger itself, because linger keeps the user's whole
manager running from boot.

### 4.6 Release assets: the files D7's upload sends

D7 sends the client's own file when the remote runs the client's OS and
architecture. When it does not (a Mac client, a Linux server), the client
fetches the release of **its own version** for the remote's platform. For
that, the client must compute the file's name from three things that it
already knows. So this section fixes the name, and `ci.yml`'s release job
produces exactly this [choice]:

- **Where.** Every release is a GitHub Release on
  `github.com/danielbodart/mosey`. CI makes it from a green trunk commit
  (D10) and tags it `v<V>`. `V` is `scripts/version.sh`'s
  `MAJOR.COMMITS.RUN`. It is byte-for-byte what `mosey -version` prints for
  every binary in the release. This is because each binary is stamped from
  `scripts/version.sh` run on the same commit in the same CI run. Before it
  publishes, the release job runs the linux/amd64 binary and checks that it
  prints `V`. It cannot run the others, so it checks that each of them
  contains `V`'s bytes.
- **The binaries.** One asset per platform, named
  `mosey-<V>-<os>-<arch>`, with `os` ∈ {`linux`, `darwin`} and `arch` ∈
  {`amd64`, `arm64`}, and `android-arm64` (D10 as amended 2026-11-22).
  There is no `android-amd64`, because Go links it only with cgo. The names
  are Go's `GOOS` and `GOARCH` names, so the client's own is `runtime.GOOS`
  and `runtime.GOARCH`. Each is the bare static executable that
  `scripts/build.sh` made (CGO off, `-trimpath`, linux with
  `GOEXPERIMENT=runtimesecret`, D1, D20), not an archive.
- **The checksums.** One asset named `SHA256SUMS`, in `sha256sum(1)`'s
  text format. Per binary, it has 64 lower-case hex digits, two spaces,
  the asset's name and a newline. The lines are sorted by name. It lists
  the binaries only.
- **The build attestations** (S1, D7 as amended 2026-11-15, and again the
  same day: client-side checking removed). These are not release assets.
  The release job attests each binary alone with
  `actions/attest-build-provenance`. This makes a Sigstore bundle, which
  holds:
  - a DSSE envelope with an in-toto statement of SLSA provenance v1,
    `https://slsa.dev/provenance/v1`. Its one subject is the binary, by its
    file name `mosey-<V>-<os>-<arch>` and its SHA-256.
  - a short-lived Fulcio certificate. Its subject alternative name is the
    workflow
    `https://github.com/danielbodart/mosey/.github/workflows/ci.yml@refs/heads/trunk`,
    and its OIDC issuer is `https://token.actions.githubusercontent.com`.
  - the Rekor entry that logged it.

  The job stores the bundle with the repository's attestations, on the
  public-good Sigstore instance (the repository is public). The
  attestations are for a person who checks a download by hand, with `gh
  attestation verify FILE --repo danielbodart/mosey`. The client does not
  fetch or check them (§4.7.4, §14 question C).
- **So** the binary for `os/arch` at version `V` is
  `https://github.com/danielbodart/mosey/releases/download/v<V>/mosey-<V>-<os>-<arch>`.
  Its hash is the line of
  `https://github.com/danielbodart/mosey/releases/download/v<V>/SHA256SUMS`
  whose second field is that name.
- **The tag's commit, and `nix/release.json`** (Dan, 2026-11-15). The tag
  `v<V>` does not name the released trunk commit. It names a commit of its
  own, made by `github-actions[bot]`. That commit's one parent is the
  trunk commit, and it adds one file, `nix/release.json`:
  `{"version": V, "assets": {SYSTEM: {"url": …, "hash": "sha256-<SRI>"}}}`.
  The file has an entry for each of the Nix systems `x86_64-linux`,
  `aarch64-linux`, `x86_64-darwin` and `aarch64-darwin` (`linux-amd64`,
  `linux-arm64`, `darwin-amd64`, `darwin-arm64`). Each URL is the asset
  above. Each hash is its `SHA256SUMS` line in SRI form
  (`scripts/release-json.sh`). Only the tag is pushed; no branch has the
  commit.

  `flake.nix`'s package is that asset, fetched and installed as
  `bin/mosey` with version `V`. So `github:danielbodart/mosey/v<V>` gives
  the release's own binary. A flake sees its commit, never its tag, so the
  version must be in the tree. On trunk there is no file and no package.
  The last release before a commit is the newest tag whose parent is an
  ancestor of that commit (`scripts/last-release.sh`). For the tags made
  before this, the tag's own commit must be the ancestor.
  `scripts/release-due.sh` diffs from that parent.

**How the release job makes them.** The job lays out the binaries and
checks their versions. Then it attests each binary in a separate step
(`actions/attest-build-provenance`). Every action in every workflow is
pinned by commit, and `scripts/actions-pinned.sh` refuses a tag. The
reason: the release job holds the OIDC token that signs as this
repository's release workflow. That is the identity that `gh attestation
verify --repo danielbodart/mosey` trusts, and the job attests what the
build job made.

Only then does the job create the release. A failure at any of these
steps fails the job, so no release is ever published with an unattested
binary. A newer push also does not leave a release half-made. The push
cancels the older run's testing. But when that run's release job has
started, the cancellation lets it finish (`ci.yml`'s concurrency), and
releases queue behind one another.

Why bare files: then the hash in `SHA256SUMS` is the hash of the exact
bytes that the client sends and the remote installs at
`~/.local/bin/mosey`. So one hash is checked on download, after the copy,
and against a file already there. Also, the client needs no archive parser
for a file from the network [derived]. Why the version in the name: a
downloaded file says what it is.

The auto-upload slice owns the map from the remote's `uname -s` and
`uname -m` to `os` and `arch`, and also the download. The map is `Linux`
→ `linux`, `Darwin` → `darwin`, `Android` → `android`, `x86_64` →
`amd64`, `aarch64` and `arm64` → `arm64`. Anything else has no asset.
There is no `android-amd64` asset.

An Android host says `Linux` to `uname -s`, so the probe asks
`uname -o` too, and sends `Android` when that says `Android`. The
`linux-<arch>` build does not run in Termux (Dan's phone, 2026-11-27).
Termux runs every program through Android's linker, and the linker loads
only a position-independent program (ELF type `ET_DYN`). The linux build
is static, of type `ET_EXEC`, so the upload fails with
`unexpected e_type: 2`. The android build is position-independent.

An Android client, whose `runtime.GOOS` is `android`, never sends itself
to a `linux` host.

`SHA256SUMS` comes over HTTPS from the same release. So it catches
corruption and a wrong file, but not a compromised GitHub account or CI.
A client check of the build attestation too is §14 question C, parked. A
client of a development build (`dev`, or a local build's timestamp patch)
has no release, so it can upload only itself.

### 4.7 Auto-upload (D7)

D7, as Dan amended it on 2026-11-15: **the client installs itself only
where the host has no mosey it can use.** It uses any mosey that the host
has, of any version. Nix or a replacement of the binary does the upgrade.
The client never upgrades a host while it moves between hosts. The next
session on that host runs the new binary.

The host's mosey is, in this order:

1. `mosey` on the remote `PATH`.
2. Otherwise the single file `~/.local/bin/mosey`, asked for by its path.
   The non-login `ssh host cmd` that runs the probe may not have
   `~/.local/bin` on `PATH`.

The client copies a static build to `~/.local/bin/mosey` in two cases.
Either there is no host mosey, or `~/.local/bin/mosey` (found either way)
speaks another protocol than the client (§4.7.2). The copy is
hash-checked. The client asks the first time. It never replaces a file
that someone else owns (Dan, 2026-11-16: "On a protocol mismatch, mosey
replaces that file after asking"). A `mosey` on `PATH` anywhere else is
never replaced. Nothing here changes the lines of §6 or what a server does
when it runs.

Why `~/.local/bin` (Dan, 2026-11-16, closing §14 question G): it is the
one directory that the stock login profiles already put on `PATH` when it
exists. These are Debian's and Ubuntu's `~/.profile` and Fedora's
`~/.bashrc`; the XDG Base Directory spec names it for user executables.
So a session served from it can hop on with no rc file edited (§4.7.9).

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

**The probe and the roles.** Every command that runs a server role
probes:

- `mosey DEST`, `mosey -s NAME DEST` and `mosey -new DEST` (the launcher,
  `--serve`, each with its own ClientLine `attach`, §9.2);
- R3's background reconnect (the launcher again);
- `mosey -list DEST` (`--serve=list`, §9.4);
- `mosey -kill NAME DEST` (`--serve=kill`, §9.5).

The probe runs the host's mosey with the flag of that command. So all of
them find a host whose only mosey is the one that D7 put in
`~/.local/bin/`. **Only the three that the user typed to get a session
upload.** When the probe answers `MOSEY-PROBE`:

| Command | What the client does |
|---|---|
| `mosey DEST`, `mosey -s NAME DEST`, `mosey -new DEST` | §4.7.3–§4.7.8: ask, copy, start again |
| R3's background reconnect (§9.2.2) | it copies nothing and asks nothing (D8 R3). The attempt fails, is logged, and is tried again after the backoff |
| `mosey -list DEST`, `mosey -kill NAME DEST` | it copies nothing: `mosey: no mosey on DEST, so no sessions: mosey DEST starts one, copying mosey there`, exit 1. To list or end sessions is not a reason to install anything. |

`~/.local/bin` is literal: nothing in the remote's environment moves it.
The probe, the upload and the installer must agree on one path without a
round trip to ask, and D7 names this path.

#### 4.7.2 The probe

The remote command is one argument, as in §4.1. `B H` is the client's
`--serve=protocol` answer, `bootstrap.Version` and
`handshake.ProtocolVersion`, now `1 1`:

```
exec /bin/sh -c 'b="$HOME/.local/bin"; f="$b/mosey"; p=$(command -v mosey 2>/dev/null); case $p in "$f"|"") ;; *) exec mosey FLAG;; esac; w=; for d in "$HOME/" "$HOME/.local/" "$b/"; do case $(ls -ld "$d" 2>/dev/null) in ?????w*|????????w*|"") w=1;; esac; done; if test -h "$b" || test -h "$f" || test -n "$w"; then :; elif test -O "$HOME/.local" && test -O "$b" && test -O "$f"; then if [ "$("$f" --serve=protocol </dev/null 2>/dev/null)" = "B H" ]; then exec "$f" FLAG; fi; p=; fi; if [ -n "$p" ]; then exec "$f" FLAG; fi; s=$(uname -s 2>/dev/null); case $(uname -o 2>/dev/null) in Android) s=Android;; esac; a=$(uname -m 2>/dev/null); echo "MOSEY-PROBE 1 machine=${a:-unknown} system=${s:-unknown}"'
```

- **`PATH` first** (Dan, 2026-11-15). The probe execs a `mosey` on the
  remote `PATH` other than `~/.local/bin/mosey` as it is, with `FLAG`.
  `FLAG` is the command's own (§4.7.1): `--serve` for the launcher, which
  reads the ClientLine as in §4.4, or `--serve=list`. Nix, a package or the
  user put that file there, and its upgrade is their job. The probe asks it
  nothing first. If it speaks another protocol, the bootstrap line or the
  handshake says so. The client then fails with one line that names both
  numbers (§6.4, `transport.md` §3.6). It never replaces a file that it did
  not install.

  "Other than" compares, as strings, the path that `command -v` printed
  with `$HOME/.local/bin/mosey`. This is what `PATH` resolved to, not what
  a link points at. So a different spelling makes `~/.local/bin/mosey`
  count as another `PATH` mosey. Examples are a `HOME` with a trailing
  slash, or a `PATH` that names the directory with one. The probe then
  execs that file as it is, and the client reports one of another protocol
  and does not replace it. We accept this for its simplicity, and a test
  pins it.
- **Otherwise `~/.local/bin/mosey`**, whether `PATH` found it or not
  (Dan, 2026-11-16: the file mosey installs is the one it may replace).
  The probe applies the installer's rules (§4.7.7):
  - Neither `~/.local/bin` nor the file is a symlink (`test -h`).
  - They and `~/.local` (which may be a symlink) are the user's
    (`test -O`, which follows a link).
  - The group and others must not have write access to the home,
    `~/.local` or `~/.local/bin`. The probe reads the group and other `w`
    of `ls -ld`'s mode string. POSIX fixes this string, and it is the one
    portable way for `/bin/sh` to read a mode. A directory that `ls` cannot
    read counts as writable.

  So the probe never asks a file from a place that the installer would
  refuse to write. And nobody but the user (or root) can swap the file
  between the checks and the exec. The probe asks the file
  `--serve=protocol` (server.md §1), with stdin on `/dev/null` and stderr
  dropped. (The ClientLine that waits on stdin is the launcher's.) The
  probe execs the file only if it prints exactly the client's own answer.

  Its software version does not matter. A copy from an older client that
  speaks the same protocol is used as it is. A file that gives any other
  answer gets the `MOSEY-PROBE` line, so the client offers to replace it
  (§4.7.5, §4.7.7), even when `PATH` found it.
- **A `~/.local/bin/mosey` on `PATH` that fails those rules** is exec'd as
  it is, as any other `PATH` mosey is. An example is a symlink, which the
  user made and mosey never would. The installer would refuse to replace
  it, so an offer to replace it would only fail. Also, the user's `PATH`
  chose it. If it is not on `PATH`, the probe does not run it at all, as
  before.
- **`--serve=protocol`** prints one line: the bootstrap line version
  (§6.1) and the handshake protocol (`transport.md` §2.3), as decimals with
  a space between them. That is `1 1` now. Every mosey answers it the same
  way for ever (D8 V1). Each number names only its layer's envelope
  (`versioning.md` §5). So a copy of any later release gives the same
  answer until an envelope changes. The attach protocol (§9.2.1) is not in
  it, because only server binaries on one host speak it, never the client.
- **Neither:** one `MOSEY-PROBE` line on stdout, then exit 0. The line does
  not say whether a `~/.local/bin/mosey` was there that the probe could not
  use. The install is the same either way: the installer replaces the
  user's own regular file and names what it refuses (§4.7.7). One question
  covers both (§4.7.5). The probe never exits 126 or 127 itself. So
  `ErrNoServer` from an exit status means only what it meant in slice 1.
- **`command -v` and `test -O`.** `command -v` is POSIX. `test -O` is not,
  but dash, bash, BusyBox ash and the BSD and macOS `/bin/sh` all have it.
  With a `/bin/sh` that does not have it, the test is false. Then the probe
  does not ask `~/.local/bin/mosey`, but execs it if `PATH` found it, as
  above. Otherwise the client offers to copy, and the installer then says
  why it cannot.
- **Quoting.** The text inside the single quotes has no `'`, no `\`, no
  `!` and no newline. fish reads `\'` and `\\` inside single quotes, and
  csh refuses a newline inside quotes. So every login shell of §4.1 passes
  the text to `/bin/sh` unchanged [shells: run under each in §12's test].
- **Cost.** With a `mosey` on `PATH` elsewhere: one exec of `/bin/sh` more
  than slice 1's command. Otherwise: three execs of `ls` and, with a
  `~/.local/bin/mosey`, one of `mosey --serve=protocol` (a Go binary's
  start, a few milliseconds). No extra round trip.

**The probe line.** `ReadCredential` (§6.5) reads it like our other lines,
and it is fuzzed with them:

```
probe-line = "MOSEY-PROBE" SP "1" *(SP field) LF     ; §6.1, fields in key order
```

| Field | Value | Mandatory | Critical | Why critical or not |
|---|---|---|---|---|
| `machine` | `1*64(%x21-7E)`: `uname -m`, or `unknown` | mandatory | no | it describes the host. A wrong one gets a build that does not run, never a wrong action |
| `system` | `1*64(%x21-7E)`: `uname -s`, `Android` if `uname -o` says `Android`, or `unknown` | mandatory | no | as `machine` |

At most 163 bytes [derived: 11, SP, 5 digits, ` machine=` 9 and 64,
` system=` 8 and 64, LF]; **`MaxProbeLine` = 256** [choice: room for
fields a later release adds]. The line is canonical as §6.1 asks. The
shell itself prints the fields in key order, so the script stays the one
line above. `ReadCredential` returns the line as a `*NoServerError`
(`errors.Is(err, ErrNoServer)`) that carries the fields. If `uname` prints
a space or something longer, the line does not parse, and the result is
`ErrBadLine`. A host that odd has no release asset anyway.

The far side chooses these fields, and a hostile one can claim any
platform. All it gets is the choice of which public build the client sends
it.

#### 4.7.3 The remote's platform

| `uname -s` | os | | `uname -m` | arch |
|---|---|---|---|---|
| `Linux` | `linux` | | `x86_64`, `amd64` | `amd64` |
| `Darwin` | `darwin` | | `aarch64`, `arm64` | `arm64` |
| `Android` | `android` | | | |

The matches are exact and case-sensitive [derived from uname(1) on Linux
and macOS]. `Android` comes from `uname -o` (§4.7.2) and takes `arm64`
only. For anything else: `mosey: DEST is SYSNAME MACHINE, which mosey has no build
for`. The client refuses a `darwin` remote, though there is a darwin
build, with
`mosey: the mosey server runs on Linux only for now, and DEST is Darwin`.
The server's roles return `ErrUnsupported` there (D22, `server.md`). So a
copy of 10 MB to the host, only to get that error, would waste the user's
time. This check goes when a macOS server lands. An `android` remote
runs the server, because the Android kernel is Linux.

#### 4.7.4 Which file is sent

- **Same os and arch as the client:** the client sends its own file, the
  exact bytes that it runs (D7: "the copy sent over is the very file the
  client runs"). On Linux the client reads it through `/proc/self/exe`.
  That is the running image, even if a package upgrade has replaced the
  path since. On other systems it reads through `os.Executable`. A
  non-dumpable process may open its own `/proc/self/exe` (the kernel lets
  a process inspect itself). So §4.3's `PR_SET_DUMPABLE 0` does not stop
  it.

  The client reads the file whole, at most `MaxBinary` = 128 MiB [choice;
  a release is about 10 MB], and hashes it as it reads. No network.
- **Otherwise:** the client sends the release asset of §4.6 for its **own
  version `V`** and the remote's os/arch (Dan: "we're gonna download it
  from GitHub, and we've asked the user"). Only a release version has an
  asset. `V` must match `MAJOR.MINOR.PATCH`, with these conditions on the
  parts:
  - each part is a decimal of at most 9 digits, with no leading zero;
  - `PATCH` ≥ 1 (CI's run number).

  [derived from `scripts/version.sh`: a local build's patch is a 14-digit
  timestamp, a plain `go build` says `dev`; the flake installs a release's
  binary, so its version is a release's]. Anything else is a development
  build: `mosey: this is a development build (V) and DEST is OS/ARCH,
  which it cannot copy itself to: build mosey for OS/ARCH and put it at
  ~/.local/bin/mosey there, or pass -remote`.

  The download gets `SHA256SUMS` first, then the binary, both from
  `https://github.com/danielbodart/mosey/releases/download/v<V>/`. The
  rules are:
  - HTTPS only, redirects included. A redirect to anything but `https` is
    refused. GitHub redirects release downloads to its object store.
  - The whole fetch has a deadline of 5 minutes [choice: 10 MB at
    300 kbit/s].
  - The client reads `SHA256SUMS` up to 64 KiB, and the binary up to
    `MaxBinary`. More is an error.
  - `SHA256SUMS` is parsed strictly (`ParseSums`, fuzzed). Every line is
    exactly 64 lower-case hex digits, two spaces, a name of 1 to 256
    `pathchar`s other than `/`, and LF. A name occurs at most once. The
    asset's name must be there.
  - The binary's SHA-256 must equal that line's, and its length must be
    non-zero, **before** the client sends anything to the far host.
  - A 404 on either file: `mosey: there is no release vV on GitHub to fetch mosey for
    OS/ARCH from`.
  - Any other failure, offline included: `mosey: fetching
    mosey V for OS/ARCH from GITHUB-URL: ERR`, followed by the same advice
    as for a development build.
  - Nothing is cached locally. A second host of the same platform
    downloads again (§14 question D).

  What this proves: the bytes are the ones that the release lists. So it
  catches corruption and a wrong file. It does not prove that CI made
  them. The release's build attestation (§4.6) would prove that, but the
  client does not check it (§14 question C, parked: sigstore-go, which did
  check it, doubled the binary and was removed).

The SHA-256 of what the client sends, and its length, go to the far host
on the upload's command line (§4.7.6). The installer refuses anything
else.

#### 4.7.5 Consent

`-upload` sets what happens when the probe finds no mosey that it can
use:

| `-upload` | |
|---|---|
| `ask` (default) | if this host is remembered, go on. Else ask. `y` or `yes` (any case) goes on and remembers the host. Anything else, or end of input, is no |
| `yes` | go on and do not ask. Remember nothing |
| `no` | never copy: `mosey: DEST has no mosey: install it there, or run without -upload=no` |

**The question** goes on stderr while the terminal is still cooked
(§4.3). It comes after the probe's ssh has exited, so no ssh reads
`/dev/tty`:

```
mosey: DEST has no mosey this one can use. Copy this one (OS/ARCH, N.N MB) to ~/.local/bin/ there? [y/N] 
mosey: DEST has no mosey this one can use. Download mosey V for OS/ARCH from GitHub and copy it to ~/.local/bin/ there? [y/N] 
```

The first question is for the client's own platform. The second is for
another platform, and the client asks it before it downloads anything.
The same question covers a host with no mosey at all and a host whose
`~/.local/bin/mosey` the probe could not use. The install replaces that
file (§4.7.7). The answer is one line read from the terminal, at most
64 bytes counted. Every field in the question is the client's own (the
destination as typed, its version, the platform mapped through §4.7.3),
never a remote string.

**The first time** is per `user@hostname:port`, as `ssh -G` resolved them
(§3; `user`, `hostname` and `port`). So an alias and its target are one
host, and two accounts on one host are two. It is not per version. A
remembered host is a line in `$XDG_STATE_HOME/mosey/upload-hosts` (else
`~/.local/state/mosey/`), beside the log (§7.4). The file:

- is 0600 in a 0700 directory, at most 1 MiB;
- has one key per line;
- is rewritten whole through a temporary file and a rename.

A key holds only bytes 0x21–0x7E and is at most 1100 bytes. The client
asks each time for a host whose key it cannot write. If the client cannot
read or write the file, it logs the failure and asks for that host again
next time. This never stops a session. The file is in the state
directory, not the config directory, because the client writes it. Also,
a home-manager user's `~/.config` can be read-only.

The prompt goes through an interface (`client.Options.Ask`), so tests can
answer it. `cmd/mosey` reads the answer from the terminal that it already
requires (§4.3: stdin and stdout must be one).

#### 4.7.6 The upload

The upload uses the same ssh as §4.1, with every option the same (one
fresh connection, nothing forwarded). Its remote command is this (`HASH`
as 64 lower-case hex digits, `SIZE` in decimal):

```
exec /bin/sh -c 'umask 077; d="$HOME/.local/bin"; mkdir -p "$d" || exit 1; t=$(mktemp "$d/.upload.XXXXXXXX") || exit 1; cat >"$t" && chmod 700 "$t" && "$t" --serve=install HASH SIZE "$t"; s=$?; rm -f "$t"; exit $s'
```

- **stdin is the binary**, written whole and then closed. Nothing else
  goes on stdin. The client drains ssh's stdout (at most 64 KiB, then
  discarded), because rc files print. ssh's stderr goes to the user
  through §6.5's filter. That is how the user reads the installer's
  refusals.
- **`umask 077`**: every directory and file that the shell makes is the
  user's alone. This includes `~/.local` and `~/.local/bin` when they are
  missing. A `~/.local/bin` made here gets on `PATH` at the user's next
  login, when the profile sees that it exists (§4.7.9). The session's own
  login shell starts after the install, so it is one of those logins.

  **`mktemp`** creates the file with `O_EXCL`, so the shell never writes
  through a name that someone planted [mktemp(1): GNU coreutils, busybox
  and macOS all create mode 0600 with `O_EXCL`]. The temporary file is in
  `~/.local/bin`, not `/tmp`. `/tmp` is often `noexec`, and the rename into
  place must stay on one filesystem. The file's name starts with a dot,
  and the file exists only while the installer runs.
- **The copy installs itself.** The shell runs the uploaded file as
  `--serve=install` (§4.7.7). This proves that the file runs on that host.
  Also, the checks are Go's, not those of the host's `sha256sum` or
  `shasum` (macOS has no `sha256sum`). A copy cut short in transit does
  not start, because its ELF segments run past the end of the file. So it
  installs nothing. A copy that starts hashes its own file through the
  descriptor that it checks, and refuses any byte that differs.

  This catches a copy damaged in transit or left half-written by a crash.
  It does not catch a copy that a process which runs as the user replaced
  on the far host. Such a process could make the installer say anything.
  The check runs on the far side, by the file that it checks, and the
  client never checks what is installed (T12, threat-model §4.13).
- **`rm -f "$t"`** runs after the installer, whatever its result. After a
  success the name is already gone (renamed). After any other result, the
  partial file goes. `exit $s` passes the installer's status to ssh.

ssh's exit status:

| Status | Meaning | Client says (exit 1) |
|---|---|---|
| 0 | installed | `mosey: copied mosey to DEST` and goes on (§4.7.8) |
| 126 | the copy did not run | `mosey: the copy of mosey would not run on DEST: is ~/.local/bin on a filesystem mounted noexec?` |
| 255 | ssh failed | `mosey: ssh to DEST failed` |
| other | refused or failed; stderr has said why | `mosey: copying mosey to DEST failed (exit N; see above)` |

#### 4.7.7 The installer: `mosey --serve=install HASH SIZE TEMP`

The installer is a server role (`server.md` §1) that runs once, from the
uploaded file. It is the only code that writes `~/.local/bin/mosey`. It is
not sandboxed, because it must write the user's home. It reads nothing
from the network. It does these steps in order:

1. **Arguments.** Exactly three. `HASH` is 64 lower-case hex digits.
   `SIZE` is a decimal from 1 to `MaxBinary`. `TEMP` is exactly
   `$HOME/.local/bin/.upload.` followed by 1 to 64 `pathchar`s other than
   `/`. `HOME` must be absolute. The installer refuses anything else.
2. **Home.** `open($HOME, O_DIRECTORY)`, which follows symlinks (a home
   under `/home → /usr/home` is ordinary). The home must be owned by the
   user or root. Neither the group nor others may have write access to
   it. This is sshd's own `StrictModes` rule for the home directory
   [sshd_config(5)].
3. **`~/.local`.** Created 0700 if absent. The installer opens it relative
   to the home's descriptor. It **follows a symlink** at this step only: a
   `~/.local` that is a link to another disk is the user's own choice. It
   must resolve to a directory owned by the user. Neither the group nor
   others may have write access to it.
4. **`~/.local/bin`.** Created 0700 if absent. Then the installer opens it
   relative to its parent's descriptor with `O_NOFOLLOW | O_DIRECTORY`. So
   it refuses a symlink (`ELOOP` or `ENOTDIR`), and nothing planted can
   send the install to another place. It must be owned by the user, and
   neither the group nor others may have write access to it. The usual
   0755 is fine.
5. **The upload.** The installer opens `TEMP`'s last component relative to
   `~/.local/bin` with `O_NOFOLLOW`. Through that one descriptor, it checks
   that the upload:
   - is a regular file, owned by the user, with one link;
   - is exactly `SIZE` bytes;
   - has a SHA-256 equal to `HASH`.

   On a mismatch, the installer unlinks the file and refuses.
6. **What is there now.** `fstatat(~/.local/bin, "mosey",
   AT_SYMLINK_NOFOLLOW)`. If nothing is there, that is fine. A regular
   file owned by the user is replaced (§4.7.2: one that speaks another
   protocol). The installer refuses all else and leaves it exactly as it
   is: a symlink, a directory, any other type, or **a file owned by anyone
   else** (D7: never replaces a file someone else owns).
7. **Install.** `fchmod 0700`, `fsync` and `fstat` on the upload. Then
   `renameat(~/.local/bin, TEMP, ~/.local/bin, "mosey")`, which is atomic
   within the filesystem. `rename(2)` takes names, so the rename looks up
   TEMP again. Then `fstatat(~/.local/bin, "mosey", AT_SYMLINK_NOFOLLOW)`
   must show the device and inode of the descriptor that was hashed. If
   not, the installer unlinks the file and refuses. Then `fsync` of
   `~/.local/bin`.

   A session that runs from the replaced file is not affected. Its
   processes keep the old file open. Its spawner re-executes its roles
   through `/proc/self/exe`, never by path (`server.md` §2.3,
   threat-model §4.11), so they are the old binary too.

Every step works through the descriptors of the step before (`openat`,
`mkdirat`, `fstatat`, `renameat`). So no directory is looked up twice, and
no symlink can redirect a step. The one name looked up twice is TEMP, by
the rename, inside `~/.local/bin`, which only the user can write. Step 7's
inode check catches a swap there after the fact. On success: exit 0 and
nothing on stdout. On any refusal: one line on stderr,
`mosey --serve=install: WHAT`, which names the path and the rule, and
exit 1.

Other users: `~/.local/bin` is under the user's home, and every directory
on the path to it is the user's alone. So another user can neither plant
nor replace a file there. The same user can (threat-model T12). That is
why the copy is never a trust anchor (S7 §10, threat-model §4.13).

#### 4.7.8 Starting again

After a 0 exit, the client runs §4.1 once more, with the probe, the same
config and the **same** ClientLine. Its one-shot key was never used,
because no launcher read the first line. Also, the key is public: B3
needs SSH to be authentic, not confidential. If this second probe also
says `MOSEY-PROBE`, the client stops: `mosey: copied mosey to DEST, but it is
still not found there` (no loop). Any other result proceeds or fails
exactly as a first attempt would.

#### 4.7.9 Hopping on

`mosey otherhost` typed inside a session finds a mosey to continue with
(D7: "a host can hop on with it"). This works wherever the login profile
puts `~/.local/bin` on `PATH`. The stock profiles do this when the
directory exists: Debian's and Ubuntu's `~/.profile`, Fedora's
`~/.bashrc` (Dan, 2026-11-16, closing §14 question G). No rc file is
edited. A `~/.local/bin` that the install made is there before the
session's login shell starts (§4.7.8 starts again after the install). So
that shell's profile sees it. Any other shell already open on the host
sees it at its next login.

Also, consider a session whose server is `~/.local/bin/mosey`, on a host
whose spawner `PATH` does not have `~/.local/bin`. Its login shell gets
`~/.local/bin` first on its `PATH` (`server.md` §2.5). This covers a shell
whose profile adds to `PATH` but does not name `~/.local/bin`. A profile
that sets `PATH` outright undoes it (Debian's `/etc/profile`, NixOS's
`set-environment`). On Debian, `~/.profile` then adds `~/.local/bin`
back.

**NixOS needs mosey from Nix** to hop on, because no stock NixOS profile
puts `~/.local/bin` on `PATH`. §12's e2e test proves hopping for a shell
whose profile keeps `PATH`. `tests/install.nix` covers only the install.

#### 4.7.10 Costs and failures

The first session on a host with no mosey costs three SSH logins (probe,
upload, start) in place of one. It also costs one prompt, the first time
ever per host. Every later session costs one login, whichever client
version runs it. A client upgrade does not touch the host. A host keeps
its mosey until Nix, a package or the user replaces it. For
`~/.local/bin/mosey`, a client of another protocol can also replace it.

| Situation | What happens |
|---|---|
| offline, same platform | nothing needs the network: the copy is the client's own file |
| offline, other platform | §4.7.4's fetch error and the advice to copy it by hand |
| development build, other platform | §4.7.4's message, before any download |
| no consent | `mosey: not copying mosey to DEST` |
| `mosey` on `PATH`, not `~/.local/bin/mosey`, of another protocol | `mosey: DEST's mosey speaks protocol P; this mosey speaks N` (§6.4), exit 1. Nothing is copied |
| `~/.local/bin/mosey` of another protocol, on `PATH` or not | the question of §4.7.5, then the install replaces it |
| `~/.local/bin` is a symlink, or `~/.local/bin/mosey` is a symlink or someone else's | the installer refuses (stderr says which), exit 1 |
| `~/.local/bin` on a `noexec` mount | upload exit 126, §4.7.6 |
| the probe line does not parse | `ErrBadLine`, as for any malformed line of ours |
| a `-remote` was given | none of this: §4.2 |

---

## 5. Agent forwarding: the decision (D25)

The decision to forward follows ssh's own config, with `-A`/`-a` on top.
The client reads it from the `forwardagent` that `ssh -G` printed (§3).
That value already includes the flags, with ssh's own precedence:

| `forwardagent` | Socket to forward |
|---|---|
| `no` | none: agent off |
| `yes` | `identityagent` if it names a socket (or `$VAR`). `$SSH_AUTH_SOCK` if it is unset or `SSH_AUTH_SOCK`. Agent off if it is `none`, or if the socket is empty [ssh: checked black-box against OpenSSH 10.6p1 by `TestForwardAgentYesForwardsTheIdentityAgent`: `IdentityAgent none` with `ForwardAgent yes` forwards nothing] |
| starts with `$` | the environment variable it names ([ssh]: printed verbatim, e.g. `$FOO`). Unset or empty means agent off |
| anything else | that path ([ssh]: `ssh -G` has already expanded `~`) |

It is a pure function of `Config` and the environment (`AgentSocket`, unit
tested). A session on this machine, with no ssh, decides differently
(§2.2). When off, the bootstrap runs with `ForwardAgent=no`, the ClientLine
has no `!agent` field, and the Hello has no `ChannelAgent`. When on, see §8
and `agent.md`.

---

## 6. The lines

### 6.1 Common rules

Every line in this document uses the one grammar of `versioning.md` §6.
The attach socket's greeting (§9.2.1) uses it too. A line is a tag, a
protocol number, then `key=value` fields in ascending key order. A `!`
comes before the key of a critical field. The line ends in one LF. That
section is normative. In short:

```
line   = tag SP number *(SP field) LF
field  = ["!"] key "=" value         ; key: a-z first, then a-z 0-9 -, 1..16 bytes
value  = 1*(%x21-7E)                 ; printable ASCII, no space
```

- **The tag and the number are frozen for ever** as the first two words.
  Thus any version of mosey can tell a line it cannot read from a line
  that is not its own, and it can name the number it saw. The number is
  the bootstrap protocol's, `bootstrap.Version`, now **1**. It is on every
  line of this section, and on the ProbeLine and ListLine (§4.7.2, §9.4).
  The greeting carries the attach protocol's number instead (§9.2.1). The
  ErrorLine's grammar, with its bound, is frozen in full. Thus a client of
  any version can read any server's refusal (§6.4).
- **Must-ignore, critical marked** (`versioning.md` §2, §3). The parser
  drops a field it does not know before it decides anything. The
  exception is a field whose key has a `!`: that field refuses the line.
  The table for each line below gives, for every field, whether it is
  mandatory, whether it is critical, and why. A known field must carry
  exactly that marking. A missing mandatory field refuses the line.
- **Absent, never `-`.** Leave out a field that has nothing to say. Do not
  use `-` placeholders or empty values. A boolean is `yes` or absent.
- **Binary values** are base64url without padding (RFC 4648 §5). The
  decoding is strict (`base64.RawURLEncoding.Strict()`: unused trailing
  bits must be zero). The value must decode to exactly the stated length.
  The reason for base64url: it has no `+` or `/`, so a shell, a log viewer
  or a recorder cannot mangle it.
- **Decimal values** are `0`, or a non-zero digit followed by digits. They
  have no sign and no leading zero.
- **Canonical.** A parser accepts a line only if it marshals what it
  parsed back to the same bytes, with the unknown fields left out. The
  fuzz targets check exactly this. They also check that an unknown field
  without `!` changes nothing, and that one with `!` refuses the line
  (§12).
- **One number, strictly** (D8 V1). Each build speaks exactly one line
  number. Its parser refuses any ClientLine, CredentialLine, ProbeLine or
  ListLine with another number, before it reads the rest. The error
  carries the number it saw (`*VersionError`, §10.1). The ErrorLine is the
  exception: its parser accepts any number, because its whole grammar is
  frozen. There is no range and no fallback. A mismatch fails the
  bootstrap with one line that names both numbers (§6.4).
- **Stable** (D8 V1, `versioning.md` §5). The number names the grammar
  above and the mandatory fields of each line, and nothing more. A new
  field is optional, and `versioning.md` §3 decides if it is critical. A
  new value of a known field is a new field, or a feature
  (`versioning.md` §4). Neither changes the number. No line carries a
  software version, and nothing compares one (Dan, 2026-11-15: "when I use
  SSH I don't really worry about the version stuff").

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
| `!agent` | `yes`; absent for no | optional | yes | it instructs: the server makes the agent socket and triggers ssh's bind (D25, §8). If ignored, the shell gets no agent, and the client learns this only at its capture's deadline (§8) |
| `!attach` | `attach` below | mandatory | yes | it selects the session. `resume:SID:CREDID` restricts the takeover to a session that CREDID still holds (§9.2.2) |
| `!cmd` | `b64text` of a `cmdtext` | optional | yes | it instructs: run this in place of the shell. `auto` matches on it (§9.2). If ignored, the user gets a shell, or a detached session that runs something else |
| `cols` | `dec`, 1..65535 | mandatory | no | it describes the client's terminal. The server clamps it, and the client sends its size again as its first event |
| `!dir` | `b64text` of a `dirtext` | optional | yes | it instructs: start here. If ignored, the next command the user types runs in another directory |
| `env` | `var *("," var)` | optional | no | it describes the client's locale and terminal. A server that dropped it gives the shell the default locale |
| `host` | `hostname` | optional | no | it describes the client's machine, for the takeover message and `-list` (§9.1, §9.4). A server that dropped it shows the client's address alone |
| `!public` | `b64(1216)` | mandatory | yes | it authenticates: the client's one-shot X-Wing key (D20) |
| `rows` | `dec`, 1..65535 | mandatory | no | as `cols` |
| `!type` | `b64text` of a `typetext` | optional | yes | it instructs: type this into the new shell. If ignored, the session starts without what the user asked to run |

```
attach  = "auto"                    ; R1: the newest detached session started with this cmd (or none), else a new one (§9.2)
        / "new"                     ; -new: a new session with a generated name
        / "name:" sname             ; -s NAME: NAME, taken over if attached, else started
        / "new:" sname              ; launcher → spawner only: start a session called sname
        / "resume:" b64(16)         ; launcher → attach socket: take over session SID
          [":" b64(8)]              ; R3: ... only if it is detached or held by this credential
sname   = (ALPHA / DIGIT) 0*31(ALPHA / DIGIT / "-" / "_" / ".")
var     = ename "=" 1*64vchar       ; names strictly ascending (byte order), no repeats
ename   = UPALPHA 0*31(UPALPHA / DIGIT / "_")   ; a name not in the list below is skipped
name    = "COLORTERM" / "LANG" / "LANGUAGE" / "LC_ADDRESS" / "LC_ALL"
        / "LC_COLLATE" / "LC_CTYPE" / "LC_IDENTIFICATION" / "LC_MEASUREMENT"
        / "LC_MESSAGES" / "LC_MONETARY" / "LC_NAME" / "LC_NUMERIC"
        / "LC_PAPER" / "LC_TELEPHONE" / "LC_TIME" / "TERM" / "VTE_VERSION"
UPALPHA = %x41-5A                   ; A-Z
vchar   = ALPHA / DIGIT / "." / "_" / "@" / ":" / "+" / "-"
b64text = base64url, no padding, of 1..1024 bytes
dirtext = 1..1024 bytes of UTF-8, no control character (Unicode Cc)
typetext = 1..1024 bytes of UTF-8, no control character (Unicode Cc) but TAB
cmdtext = typetext
fgtext  = 1..48 bytes of UTF-8, no control character (Unicode Cc)
cwdtext = 1..192 bytes of UTF-8, no control character (Unicode Cc)
hostname = label *("." label)       ; 1..63 bytes in all (RFC 1123 §2.1)
label   = (ALPHA / DIGIT) [*(ALPHA / DIGIT / "-") (ALPHA / DIGIT)]
```

| Field | Meaning |
|---|---|
| `attach` | which session (D8, §9.2). `auto` for a plain `mosey DEST` or `mosey DEST COMMAND`. `new` for `-new`. `name:NAME` for `-s NAME`. `resume:SID:CREDID` for R3's background reconnect: it names the session and the credential this client last held it with. `new:NAME` and `resume:SID` are what the launcher hands the session's spawner after it chooses (§9.2). A reconnect's CREDID stays (§9.2.2). A launcher refuses `new:NAME` from a client with `line`. The all-zero SID is refused: no session has it |
| `agent` | whether the client will forward an agent (D25). The server needs it at spawn time to give the shell an `SSH_AUTH_SOCK` (`agent.md` §4.1). For `new` and resume alike, the server also needs it to trigger ssh's bind (§8) |
| `cols`, `rows` | the size of the client's terminal. A terminal that reports 0 is sent as 80×24. The server clamps it (D23, `screen.ClampSize`). The client sends its size again as the first userinput event after it connects, in case the size changed during the bootstrap |
| `env` | the client's locale and terminal variables, from the allow-list (`name`) only. A variable is left out (logged at debug), never escaped, if it is unset, empty, longer than 64 bytes, or holds a byte outside `vchar`. If no variable remains, the field is absent. The server gives the locale variables to the shell. `server.md` defines what the server does with `TERM`, `COLORTERM` and `VTE_VERSION` (the shell's `TERM` describes the server's emulator, not the client's terminal). **An entry whose `ename` is not in the list is skipped**, as an unknown field is (`versioning.md` §2). It must still be a valid `var` in its place in the order, so it is bounded. The line is canonical without it. Thus a later client can add a variable, and an older server gives the shell the rest [D: Dan, 2026-11-27] |
| `dir` | `-dir`: the directory where a new session's login shell starts. It is relative to the remote `$HOME` unless absolute (§9.2.3). If absent, the shell starts in `$HOME` (`server.md` §2.5). Only a session that the line creates uses it |
| `type` | `-type`: the text typed into a new session's pty after its shell starts, followed by Enter (§9.2.3). Only a session that the line creates uses it |
| `cmd` | the command after `DESTINATION` (§2), joined with spaces. It runs as `SHELL -c CMD` in place of the interactive shell (§9.2.3). Only a session that the line creates runs it. With `auto`, the launcher also matches a detached session on it (§9.2). A line with `cmd` and `type` is refused (`line`) |
| `host` | the name that the client claims for its own machine (`hostname.Own`). It is `os.Hostname()` if that is a `hostname`. Else it is the first label, if that is one. Else the field is absent. The server keeps it with the attached client, next to the address it observed (§9.2.1). The name is a claim and the address is an observation, so mosey never shows the name without the address (§9.1, §9.4). **A `host` that is not a `hostname` is dropped**, as if absent, and the line is canonical without it. It never refuses the line, because the field only describes [D: Dan, 2026-11-27]. The bound is 63 bytes [D: one DNS label (RFC 1035 §2.3.4), so a first label always fits] |
| `public` | the client's one-shot X-Wing encapsulation key, `OneShotKey.PublicKey()`, 1216 bytes [S1, measured from `crypto/hpke`] |

`dir`, `type` and `cmd` are base64url because a path or a command holds
spaces, and §6.1 keeps every value free of spaces. base64url keeps the
line printable ASCII, whatever the user typed. Its strict decoding keeps
the line canonical. The parser still checks the text inside. It must be
valid UTF-8 (Go's `utf8.Valid`), with no rune for which `unicode.IsControl`
holds, but TAB is allowed in `type` and `cmd`. Thus a `-dir` cannot
smuggle a NUL or a newline into a path. A `-type` cannot carry its own
Enter (a second command), an ESC (a line editor's key binding) or a
Ctrl-C [choice: one line of ordinary text, with tab kept because a user
may type it].

The bound is 1024 bytes each [choice: `PATH_MAX` on macOS, so any of our
platforms can name the directory; for `type`, a quarter of the 4096 bytes
termios(3) says a canonical-mode line holds, so the text and its Enter
always arrive as one line the shell can read; for `cmd`, a command a user
types on one line].

The check keeps out control characters, not the line editor. The rest
arrives as if the user typed it. Thus a TAB starts completion in bash and
zsh. Where readline's `convert-meta` is on (bash's default in a C or 8-bit
locale), the shell reads a byte of 0x80 or above as a Meta chord. The
text is the user's own, so to type it would have the same result.

**A server that does not know a critical field** (for example, one from a
later release) refuses the line with `MOSEY-ERROR 1 !code=unsupported detail=KEY`
(§6.4). The client says `mosey: DEST's mosey can't do KEY yet`. A server
never starts a session without doing what the line asked.

Size: at most 5902 bytes from this build [derived: `MOSEY-CLIENT 1` 14; ` !agent=yes` 11;
` !attach=` and the longest attach, `resume:SID:CREDID` at 41, 50;
` cols=` and ` rows=` 11 each; ` !dir=` 1372 (the base64url of 1024
bytes is 1366); ` env=` 1359 (at most 1354: 167 bytes of names, 18 × 65
for `=` and value, 17 commas); ` host=` 69; ` !public=` 1631; then either ` !type=`
1373 or ` !cmd=` 1372, never both; LF 1]. **`MaxClientLine` = 8192**
[derived: the next power of two, so the server's read bound is fixed and
generous, and over 2 KiB is left for fields a later release adds].

Why not pass the environment with ssh `SendEnv`? sshd's `AcceptEnv`
decides what arrives, and it is different on every host. Also, the values
arrive in the environment of a process, and the server cannot validate
them first. On the line, the grammar is ours and the parser is fuzzed.

Example (key shortened; `c3Jj` is `-dir src`):

```
MOSEY-CLIENT 1 !attach=new cols=211 !dir=c3Jj env=COLORTERM=truecolor,LANG=en_GB.UTF-8,TERM=xterm-256color host=blade !public=nW3b…Qe8 rows=58
```

### 6.3 CredentialLine: server → client, on ssh's stdout

```
cred-line = "MOSEY-CONNECT" SP "1" *(SP field) LF     ; fields in key order
```

| Field | Value | Mandatory | Critical | Why critical or not |
|---|---|---|---|---|
| `!addr` | `ipv4 / ipv6`, below; absent for none | optional | yes | it selects where the client sends its UDP (§7.2) |
| `!credid` | `b64(8)` | mandatory | yes | it authenticates: `handshake.Credential.ID` [S1: 8 bytes, our choice] |
| `existing` | `yes`; absent otherwise | optional | no | it describes what happened: the command was not run, and the client says so. The attach is the same in both cases |
| `name` | `sname` (§6.2), 1..32 | mandatory | no | it names the session to the user. Nothing depends on it (R3 resumes by `sid`, §9.2.2) |
| `!port` | `dec`, 1..65535 | mandatory | yes | it selects where the client sends its UDP |
| `!psk` | `b64(32)` | mandatory | yes | it authenticates: `Credential.PSK` [S1] |
| `!public` | `b64(1216)` | mandatory | yes | it authenticates: `Credential.ServerPublic`, the server's one-shot X-Wing key [S1] |
| `!sid` | `b64(16)` | mandatory | yes | it selects: `Credential.SessionID`, the session the handshake binds (`transport.md` §3.4). It is named for resume (D8) and in the logs |

```
ipv4 / ipv6   ; netip.Addr.String() form, no zone, never 4-in-6;
              ; not unspecified, multicast or 255.255.255.255
```

| Field | Meaning |
|---|---|
| `addr` | the server's address as SSH reached it. This is the third field of `SSH_CONNECTION`, parsed with `netip.ParseAddr`, unmapped (`Unmap`), with any zone dropped. It is absent if there is no `SSH_CONNECTION`, if that does not parse as four fields, or if the grammar forbids the address. The spawner sets it from its own environment. proto must copy it exactly (§4.4 step 3) |
| `port` | the UDP port that the spawner bound. This value is also the spawner's, and it is checked |
| `name` | the session's name (D8 R2): the name the user gave with `-s`, or the name the launcher generated. The client shows it and keeps it, in memory only, for R3. Its grammar is letters, digits and `-_.`, so it is safe to print as it is |
| `existing` | present only in answer to a ClientLine with a `cmd`. It means that the line took a session that was already running and was not started with that `cmd`, so the command was not run. This occurs with `name:NAME` only, because `auto` takes only a session started with the same `cmd` (§9.2.3). The client says so |

The parser is canonical. Thus `addr` must be exactly what
`netip.Addr.String()` gives for an unmapped, zone-free address.
`::ffff:192.0.2.1`, `fe80::1%eth0` and `0192.0.2.1` are refused. The
parser also refuses, as `ErrBadLine`, any address on which no server can
legitimately have reached SSH (threat-model §4.9):

- the unspecified `0.0.0.0` and `::` (`IsUnspecified`),
- multicast `224.0.0.0/4` and `ff00::/8` (`IsMulticast`),
- the limited broadcast `255.255.255.255`.

These are properties of the address alone, so they belong to the grammar
and the fuzzer. The checks that need the client's own interfaces or
config are in §7.2.

Size: at most 1853 bytes [derived: `MOSEY-CONNECT 1` 15; ` !addr=` and
the longest IPv6 text, 39, 46; ` !credid=` 20; ` existing=yes` 13;
` name=` 38; ` !port=` 12; ` !psk=` 49; ` !public=` 1631; ` !sid=` 28;
LF 1]. **`MaxCredentialLine` = 2048** [derived: the next power of two].

The client turns it into a `handshake.Credential` (ID, SessionID, PSK,
ServerPublic) and a UDP destination (§7.2). `bootstrap` does not import
`handshake` (architecture §1). `internal/client` does the conversion.

### 6.4 ErrorLine: server → client, on ssh's stdout

```
error-line = "MOSEY-ERROR" SP number *(SP field) LF   ; number: 0..99999, any
```

| Field | Value | Mandatory | Critical | Why critical or not |
|---|---|---|---|---|
| `!code` | `1*16(%x61-7A)`, a lower-case word | mandatory | yes | it decides what the client does: which message, which exit status, and whether R3 stops its tries (§9.2.2) |
| `detail` | `word` | optional | no | it fills in the message: a field's name, two numbers, a time |

This grammar, **and its bound `MaxErrorLine` = 256 bytes**, is frozen in
full, for every number. A client of any version must be able to read any
server's refusal, and no server may send a longer one. It freezes the
*shape*, not a list of values. `code` is any lower-case word of 1 to 16
letters. Thus a later version can add a code, and an older client still
parses the line. A client skips a later field as it skips any unknown
field.

The longest line with the two fields is 112 bytes [derived: `MOSEY-ERROR`
11, SP, 5 digits, ` !code=` 7 and 16 letters, ` detail=` 8 and a 64-byte
word, LF]. 256 [choice] leaves room for fields that a later release adds.

A client that reads a code it does not know treats it as `internal` (the
generic message below, with the code in it). The codes defined so far:

| Code | When | `detail` | Client says (exit 1) |
|---|---|---|---|
| `line` | the stdin line is malformed or not alone | absent | `mosey: the server could not read this client's request: a bug, please report it` |
| `version` | the ClientLine's number is not the server's line number (§6.1) | absent | `mosey: DEST's mosey speaks protocol P; this mosey speaks N`, where P is the ErrorLine's number. A CredentialLine or ProbeLine with another number (`*VersionError`) gets the same message |
| `attach` | `name:NAME` or `resume:SID…` names a session whose spawner speaks another attach protocol (§9.2.1), which this launcher cannot attach | `P-N`: that spawner's attach protocol, then the launcher's | `mosey: session NAME on DEST speaks attach protocol P; DEST's mosey speaks N`. The client makes it from the detail alone, so it names both numbers even where the launcher's stderr is not shown (R3's reconnect logs it). `-kill` says the same |
| `unsupported` | the ClientLine has a critical field this server does not know (§6.2), or a value of one it does not yet accept | the field's key | `mosey: DEST's mosey can't do F yet` |
| `session` | `resume:SID…` names no session of this user that answers (§9.2) | absent | R3's reconnect (§9.2.2): `mosey: session NAME on DEST has ended: its shell exited, or the host restarted` |
| `taken` | R3's `resume:SID:CREDID` finds its session held by a credential other than CREDID: another client took it over (§9.2.2, D26) | the time that client attached, in unix seconds | `mosey: session NAME taken over by another client at TIME` (exit 3, as §9.1) |
| `dir` | the line would create a session, and its `dir` is not a directory the launcher can reach (§9.2.3). No session was started | absent | `mosey: DIR is not a directory on DEST, so no session was started`, with DIR as the user gave it |
| `internal` | the server failed to start the session; stderr says why | absent | `mosey: the server failed to start (see above)` |
| any other word | a later server's code | any | `mosey: the server refused: CODE (see above)` |

An ErrorLine with an unknown critical field is refused like any other
line of ours that does not parse (§6.5). The client still fails, and says
that the server's answer was malformed.

**No software versions** (D8 V1, as amended by Dan on 2026-11-15 and
2026-11-17). A client and a server of different mosey versions is normal
and must work. No line carries a software version, and nothing compares
one. Two builds must agree on one protocol number per layer. That number
names only the envelope of its layer (`versioning.md` §5):

- the number of the bootstrap lines, here (§6.1),
- the number of the handshake (`transport.md` §2.3, §3.6),
- between server binaries on one host, the number of the attach protocol
  (§9.2.1).

Each number is checked for equality. A mismatch fails with one line that
names both numbers. Every other element is one that a receiver knows,
skips, or refuses because it is critical.

D7 uses the mosey that the host has (§4.7). Nix, or a replacement of the
binary, upgrades the host's mosey, and new sessions use it. A session of
an older binary continues to run that binary until it ends. There is no
live upgrade (Dan, 2026-11-15).

The ErrorLine carries the server's own number. This is how the client
names the server's number.

### 6.5 Reading stdout: `ReadCredential`

The remote login shell can print before the server runs. bash reads
`~/.bashrc` for a command that sshd runs, and rc files print. Thus
`ReadCredential` does these steps:

1. It reads lines. A line that starts with `MOSEY-` is a **protocol
   line**. It must parse as a CredentialLine, an ErrorLine or a ProbeLine
   (§4.7.2). If it does not, that is fatal (`ErrBadLine`), never skipped.
   No lookalike can be taken for ours. No malformed line of ours can be
   stepped over to a later one.
2. It skips every other line and counts its bytes. More than
   **`MaxPreamble` = 64 KiB** [choice: well above any motd-like rc noise]
   of skipped bytes in total is fatal (`ErrNoLine`).
3. A protocol line longer than its maximum (2048 for CONNECT, 256 for
   ERROR, 256 for PROBE) is fatal. A skipped line can be any length. It
   counts against `MaxPreamble`.
4. It returns at the first protocol line. It reads nothing past the LF of
   that line. (After this, the client drains stdout to EOF in the
   background, at most another 64 KiB, then closes the pipe.)
5. EOF before a protocol line is `ErrNoLine`, as a `*NoLineError` that
   carries the kept tail (below). The client maps it to a message by
   ssh's exit status (§10).

It returns an ErrorLine as a `*RemoteError` and a ProbeLine as a
`*NoServerError`. It returns a CredentialLine as the value (§10.1).

It never reads more than `MaxPreamble + MaxCredentialLine` bytes.

It keeps the last 1 KiB of skipped lines. On `ErrNoLine`, it shows them to
the user through the stderr filter below. The reason: "no line" usually
means that the server printed an error that the user needs to see. (A
shell's `command not found` goes to stderr, but a broken wrapper can
print to stdout.)

**The stderr filter** (D9: no remote control sequence reaches the local
terminal). A byte passes if it is LF, TAB or 0x20–0x7E. A byte also passes
if it is part of a valid UTF-8 sequence for a rune that `unicode.IsPrint`
accepts. That rune must not be a bidi control (U+061C, U+200E–U+200F,
U+202A–U+202E, U+2066–U+2069; D27's set). Every other byte is written as
`\xHH`. CR is `\r`. Lines longer than 1024 bytes are cut and end in `…`.
The same filter guards:

- the skipped output of §6.5,
- the `ssh -G` stderr of §3,
- ssh's stderr after the line, on its way to the log file (§7.4).

Every byte from ssh goes through this filter to every sink.

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

Each arrow out of a state releases what that state held:

- ssh is killed and reaped,
- the capture socket (agent slice) is closed and unlinked,
- the one-shot key is wiped,
- the terminal is restored.

### 7.2 The UDP address

The `addr` comes from the far host, which can be hostile under T5. Thus
the client takes it only if it passes the rules below (threat-model §4.9).
In order:

1. The line's `addr`, if not `-` and **usable**.
2. Else the first **usable** address of those that `hostname` from
   `ssh -G` resolves to locally (`net.DefaultResolver`; a literal address
   is its own result).
3. Else fail with `ErrBadAddr`: `mosey: don't know where to send UDP for DEST`.
   If `addr` was refused, the message continues with
   `(the server said ADDR, which is RULE)`.

An address is **usable** unless one of these is true:

| Rule | Why | Source |
|---|---|---|
| unspecified (`0.0.0.0`, `::`) | "send to this host", never a server | grammar (§6.3) for `addr`; checked here for `hostname`'s results |
| multicast (`224.0.0.0/4`, `ff00::/8`) | it would spray every listener on the segment | same |
| IPv4 limited broadcast `255.255.255.255` | same | same |
| loopback (`127.0.0.0/8`, `::1`) while the **destination is not loopback** | sshd reached over a local forward or tunnel (a `ProxyCommand` to socat or cloudflared, a container port mapping) reports a loopback `SSH_CONNECTION`. A send there reaches the client's own host | here |
| link-local (`fe80::/10`) with no zone the client can supply | the server's zone has no meaning here | here: usable only if `hostname` parses as the same address *with* a zone. The client then uses that address |

The **destination is loopback** when every address that `hostname`
resolves to is loopback (`localhost`, `127.0.0.1`, `::1`, the test
harnesses). Thus the client uses a loopback `addr` when the user really
did ssh to their own host. Otherwise it skips the `addr` and uses
`hostname`. server.md binds the wildcard for a loopback `SSH_CONNECTION`
(§4.4), so that this fallback is reachable.

A refused `addr` that is not a grammar violation (rows 4–5) is not fatal
by itself. The client logs it (warn) and continues to `hostname`. A
grammar violation is `ErrBadLine` before §7.2 runs, because no honest
server sends one. `hostname`'s results come from the user's own config
and DNS. Thus the client skips a refused one, and does not report it as
hostile.

The rules are a pure function, `ChooseAddr` (§10.1), with the resolver
injected. Thus the unit tests and the fuzzer reach every row without a
network.

A **directed broadcast** of one of the client's own subnets (`10.0.0.255`
on `10.0.0.0/24`) is not in the table, because the kernel refuses it.
Linux and macOS fail with `EACCES` a send to any address that their
routing table marks as broadcast, unless the socket set `SO_BROADCAST`
[Linux ip(7), BSD `ip_output`]. Go's `net` sets it on every IPv4 UDP
socket [M: Go 1.27, a send to the desktop's `10.0.0.255` went out]. Thus
the client clears it on its socket (below). A hostile `addr` that names a
directed broadcast then fails the handshake's first send, and does not
reach the neighbours.

The client once did this check itself, from `net.InterfaceAddrs`, on each
attach and reconnect. That is a netlink dump under the kernel's global
`rtnl_lock`. On Dan's desktop, a misbehaving network driver held that
lock for 5–25 s at a time [M, 21 November 2026]. Every new terminal
stayed blank for that long, only to duplicate a rule that the kernel
already enforces. A test (`TestTheKernelRefusesALocalDirectedBroadcast`)
sends to one from the client's own kind of socket. Thus a platform
without the rule fails loudly.

If `ssh -G` shows a `proxyjump` or `proxycommand`, the client prints a
one-line notice on stderr, and logs it. The notice says that UDP goes
straight to ADDR:PORT, not through the proxy. The client prints it before
Dial, while the terminal is still cooked. Through a jump host,
`SSH_CONNECTION` holds the address that the jump host reached. The client
possibly cannot reach that address at all. Mosh's man page documents the
same problem and offers a choice of address sources [mosh-man,
`--experimental-remote-ip`]. A choice among them is a later flag (open
question 6). Slice 1 tries `addr`. If the handshake times out, the client
says which address it tried.

The client binds its socket to the wildcard address of the chosen
address's family, unconnected. Thus roaming (D21) needs no new socket. An
IPv4 socket has `SO_BROADCAST` cleared. This makes the kernel refuse a
directed broadcast (above).

### 7.3 Dialling and the terminal

The client calls `transport.Dial(ctx, pc, addr:port, cred, key, log)` with
a deadline of **30 s** [derived: `handshake.CredentialTTL`; after it the
credential is dead on the server anyway]. On timeout, it says
`mosey: no reply from ADDR:PORT over UDP: is UDP port PORT open?` (the
classic firewall case). Then it calls `key.Wipe()`, in both cases.

The client puts the terminal in raw mode and starts `client.Session` only
after Dial succeeds (§4.3: ssh's prompts need a cooked terminal). If the
client is told to go (`SIGHUP`, `SIGTERM`) before Dial, it does not start
Dial. A handshake begun then could leave the server holding a client that
never speaks until `SilentAfter`. If raw mode fails after Dial, the client
leaves as any detach does (§2's `-close-if-idle`, then END). It never
only closes the connection.

The Hello that the client sends:

- `Protocol` = `handshake.ProtocolVersion`,
- `Channels` = `{Terminal}`, plus `Agent` when §5 says on and §8 captured
  and pinned a bind,
- `Attach` = `Exclusive` (D26: the only mode in v1).

Thus, with the agent on, Dial waits for the capture's final state (§4.3).
This costs nothing when the bind came (it was in before the line). When
the bind did not come, it costs at most the time until ssh exits.

### 7.4 The client's log

**The client's log is never the terminal.** After raw mode starts, the
terminal belongs to the session's screen. Anything else written there
would corrupt it: a log line, ssh's late stderr, or the reaper's notes of
§4.3. Before raw mode, `cmd/mosey` prints what the user must read as a
message (§10). It does not log it.

- The log is a file, `$XDG_STATE_HOME/mosey/client.log` (default
  `~/.local/state/mosey/client.log`). The directory is 0700 and the file
  is 0600. The client opens it for append before the bootstrap starts.
  At 1 MiB [choice], the client renames it to `client.log.1` (and
  replaces any older one) and starts a new file. Thus it never grows
  without bound.
- If the client cannot open it, the log is discarded
  (`slog.DiscardHandler`), and the client says so once on stderr, before
  raw mode. It never falls back to stderr.
- Everything from ssh that reaches the log goes through the §6.5 filter
  first. Every log line is one line (the text handler quotes values).
- `cmd/mosey/main.go` today builds its logger on `os.Stderr`. That must
  change to this rule when the bootstrap lands (listed in §15).

---

## 8. Bind capture (D25)

The design is S3's option (a′). Its hardening is required, not optional
([S3] recommendation 1–5). `agent.md` §2 and §3 give the exact rules of
the state machine, the pin and the replay. This section gives the
procedure.

**Client.**

1. If §5 says on, make a directory with mode 0700. Put it under
   `$XDG_RUNTIME_DIR/mosey/`, else under `os.TempDir()/mosey-UID/`. Check
   that it is ours and 0700. Listen on `cap-HEX.sock` in it, where `HEX`
   is 16 random bytes. The socket mode is 0600. Unlink the socket on
   close.
2. Run the bootstrap ssh with `-o ForwardAgent=PATH`. Send `!agent=yes`.
3. After `cmd.Start`, tell the capture the only acceptable peer: ssh's pid
   and our uid.
4. The capture is a strict state machine on **one** connection, with a
   10 s deadline [S3]. The listener closes on the first accept, so a
   second agent channel from the server cannot reach it.

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

   OpenSSH's `PROTOCOL.agent` [ssh] gives the message numbers and the
   bind's fields. Frame 1 is ssh's own. Everything after it comes from the
   server, which can mint a valid bind for any host it reaches ([S3] E11,
   the critical review finding). Hence "anything else means no bind at
   all".
5. Read the result when it is **final**. It is final at one of these:
   - EOF on the one connection (nothing more can arrive on it, and
     nothing can connect),
   - ssh has exited with no connection made,
   - the deadline.

   The server controls no timer that matters: a connection held open past
   the deadline is NoBind. Then pin the bind's host key to `known_hosts`.
   It must be a key that the files `userknownhostsfile` and
   `globalknownhostsfile` from `ssh -G` list for `hostkeyalias` if set,
   else for `hostname`, at `port`. Hashed entries are included
   (`x/crypto/ssh/knownhosts`). Certificates (`@cert-authority`) are not
   handled yet ([S3] did not exercise them): they give no bind.
6. **NoBind means agent off.** The session continues. The client says why
   on stderr and leaves `ChannelAgent` out of its Hello. It refuses any
   agent channel that the server opens anyway ([S3] E7, E7b).
7. **Bound**: replay the bind with `is_forwarding=1` at the head of every
   mosey agent channel, before any frame from the server.

**Server.** With `!agent=yes` and `SSH_AUTH_SOCK` set by sshd, the
launcher triggers ssh's bind before it prints the CredentialLine. To do
this, it:

1. connects to `SSH_AUTH_SOCK`,
2. sends `SSH_AGENTC_REQUEST_IDENTITIES`,
3. reads one reply frame (at most 256 KiB),
4. closes.

The deadline is 5 s [choice]. The launcher logs a failure and otherwise
ignores it: the client then sees NoBind. The open makes ssh connect to
the capture socket and send its bind ([S3]: the trigger took 0.82 ms).
With no `SSH_AUTH_SOCK` (the host has `AllowAgentForwarding no`), the
launcher skips the trigger. The client then sees no connection, so
NoBind, and continues without the agent ([S3] E7).

Measured cost of capture over a plain bootstrap: about 5 ms on loopback
[S3].

**How a program can tell it is inside a mosey session.** mosey is one
file (D7). Thus the client and every server role have comm `mosey`, and
the comm alone cannot tell the local client from the far spawner. The
spawner's **argv** can. `/proc/PID/cmdline` of the session's spawner is
exactly `mosey` (any path), then `--serve=spawner`. The spawner is the
parent of the login shell (`server.md` §2.5), so a program inside the
session finds it as an ancestor. The local client's argv[1] is never a
`--serve` flag (§2).

This describes the process shape as built. It is not a promise to any
tool that the shape stays so (D28). What a tool does with it is the
tool's own affair. A forged argv proves nothing, because any process of
the user's can set its own.

---

## 9. Sessions: exclusive attach, resume, names, lifetime (D26, D8)

### 9.1 Exclusive attach (D26)

Every Hello in v1 says `Attach = Exclusive`. A transport of a session is
**confirmed** at its first authentic transport packet, which also
consumes the credential (D20). At that point, the server revokes every
other transport of that session. It sends each one `KindRevoked` with the
new client's address and the time, and wipes its keys. The last client to
confirm wins.

The server does not cancel other unused credentials of the session. They
expire by their TTL (30 s). If one is confirmed, it takes over in turn:
each came from an SSH login, and each SSH login is the user.

§9.2 says which commands can take over: only `mosey -s NAME DEST`, and
R3's reconnect of a session that its own client still holds (§9.2.2). A
plain `mosey DEST` never takes an attached session (D8 R1, D26).

For a `new` attach there is nothing to revoke. On the `transport.Revoked`
event, the kicked client restores the terminal and prints:

```
mosey: session taken over from ADDR at 2026-11-14T09:30:12+00:00
mosey: session taken over from NAME (ADDR) at 2026-11-14T09:30:12+00:00
```

ADDR is the address of `By`, without the port: the port tells the user
nothing [D: Dan, 2026-11-27]. An IPv4 ADDR shows in full. An IPv6 ADDR
starts as its RFC 5952 form. If that form writes four groups or fewer,
ADDR is that form: `2001:db8::1` stays as it is. Otherwise ADDR is the
form up to the end of its 2nd written group, `…`, and the form from the
start of its 2nd-last written group. That is four groups, as in IPv4 [D:
Dan, 2026-11-27]. The first two groups give the network, and the last two
tell hosts apart. The cut works on the text, so a `::` in a kept part
stays and no collapsed zero comes back:

| RFC 5952 form | ADDR |
|---|---|
| `2a02:c7c:5a1b:e600:5e1f:9aff:fe3b:12cd` | `2a02:c7c…fe3b:12cd` |
| `fe80::5e1f:9aff:fe3b:12cd` | `fe80::5e1f…fe3b:12cd` |
| `2001:db8:0:1:2::` | `2001:db8…1:2::` |

The cut form is at most 21 characters. The log keeps the full address.
`At` is in the client's local zone,
as RFC 3339 to the second. The second form is for a new client that
claimed a name (§6.2 `host`; `transport.md` §8.3). NAME is that claim and
ADDR is the address the server observed, without the port. The name
tells the user which machine took the session, and the address tells
them where it came from. A loopback ADDR shows the same way: it says
that the new client runs on the session's own host [D: Dan, 2026-11-27].
mosey never shows the name without the address, because nothing checks
the name. Then it exits with status 3. It does not
reconnect: this is the "cut off a stolen client" property of D26.

**The limit of that message.** The kicked client learns of the takeover
from a REVOKED frame. The server keeps those frames for the tombstone's
60 s (`transport.md` §8.3). A client that sends nothing in that minute
wakes to silence. An example is a laptop that sleeps while the user
resumes the session from a phone. Its keys are useless to anyone in both
cases, so the cut-off itself holds.

Since the sessions slice, the client still learns why. After
`ReconnectAfter` of silence, it tries to reconnect (§9.2.2). The launcher
answers `taken`, because another credential holds the session. The
client prints `mosey: session NAME taken over by another client at TIME`
and exits 3. That message has no address, because the ErrorLine's frozen
grammar cannot carry it (§6.4).

### 9.2 Resume and names (D8 R1, R2)

Resume is a new SSH login and a new handshake. That login vouches for the
handshake's credential. Neither side ever keeps transport or crypto state
on disk (D8; [S1] §1.4). Resume is for a client that is gone: a reboot,
a crash, a closed terminal, a laptop left behind, another device.

A dead spot *within* the life of one client is for roaming. The transport
keeps its keys through any outage, and the path follows the client (D21).
Thus the same client continues when packets flow again
(`transport.md` §7). Only when that cannot work does the running client
resume (§9.2.2).

**Session state lives only on the remote host** (D8). The client keeps no
list of sessions and no id on disk. The greetings of §9.2.1 are the only
record. Thus a second device sees exactly what the first device would
see.

**Names** (D8 R2). Every session has one, `sname` (§6.2). A name is 1 to
32 letters, digits, `-`, `_` and `.`, and starts with a letter or digit.
Names are compared byte for byte. The user gives the name with
`-s NAME`, or the launcher generates it as `ADJECTIVE-NOUN`. The launcher
uses two word lists of 64 words of mosey's own (`server.GenerateName`),
so there are 4096 names. If a draw clashes with a session that answers,
the launcher draws again, up to 32 times.

After that, the name gets `-` and four hex digits [choice]. The name
travels in the CredentialLine (§6.3), so the client can say it. It also
travels in the greeting (§9.2.1), so a launcher can find it.

**The commands** (D8 R1, R2):

| Command | ClientLine `attach` | What the launcher does, while it holds the lock |
|---|---|---|
| `mosey DEST` | `auto`, no `cmd` | It looks at the sessions that the launcher can attach (step 5: of any version, if their attach protocol is this launcher's). Of those, it uses the ones that are `detached` (below) and whose greeting has no `cmd` (§9.2.1: started without a command, `-type` and `-dir` ones included). It takes the one with the newest `since`, with `resume:SID`. If there is none, it starts a new session with a generated name, `new:NAME`. It never takes a session that is `new` or `attached`, or one that runs a command |
| `mosey DEST COMMAND` | `auto` with `cmd` | as `mosey DEST`, but from the sessions whose greeting's `cmd` is the line's, byte for byte (§9.2.3; PLAN D8, option C). If there is none, a new session with a generated name that runs the command |
| `mosey -s NAME DEST` | `name:NAME` | session NAME, whatever its state, with `resume:SID` (step 5: of any version; one of another attach protocol is `MOSEY-ERROR 1 !code=attach detail=P-N`). This is a takeover if it is attached (D26). If there is no session NAME, a new one called NAME, `new:NAME` |
| `mosey -new DEST` | `new` | a new session with a generated name, `new:NAME` |
| R3's reconnect | `resume:SID:CREDID` | §9.2.2 |
| `mosey -list DEST` | none: `--serve=list` (§9.4) | |
| `mosey -kill NAME DEST` | none: `--serve=kill NAME` (§9.5) | |

Each row that can start a session (`auto`, `name:NAME`, `new`) uses the
line's `dir`, `type` and `cmd` only when it does start one (§9.2.3). A
row that takes an existing session ignores them, except for the match of
`auto` on `cmd`.

**What counts as detached.** A greeting says `detached` when one of these
is true:

- its last client said it was leaving (END `detached`, §9.3),
- that client's connection failed,
- proto has heard nothing authentic from that client for
  **`SilentAfter` = 15 s** [D: five of D11's 3 s heartbeats, the same
  interval after which the client itself stops relying on roaming alone,
  §9.2.2].

The last condition lets R1 give a session back after the client's
machine crashed, lost power or rebooted without a word. When the user
runs `mosey DEST` again, the session reads `detached`. A silent client
that is heard again (the dead spot ended) is `attached` again with no
resume. If a plain `mosey DEST` from elsewhere took the session in the
meantime, the returning client finds itself revoked (§9.1). The
greeting's `since` is the moment of the last change. Thus "most recently
detached" is the newest `since` among the detached sessions.

**The lock.** Choosing and starting are one step per host and user. The
launcher takes an exclusive `flock` on `R/mosey/lock` before it reads any
greeting. The lock file is made `0600` with `O_NOFOLLOW` in `R/mosey`,
and `R/mosey` is checked first as `server.md` §2.6 says. The launcher
holds the lock until it has the credential line or has failed. T2 (15 s)
bounds the wait for the lock. `flock` releases the lock when its holder
exits, so a launcher that dies leaves no lock behind.

Thus two `mosey DEST` started together (a terminal that restores its
tabs) never choose the same detached session. Two `-s NAME` never start
two sessions called NAME. A launcher that took a session has its
spawner's word that a credential is out for it. From then until that
credential's TTL (30 s) has passed, the greeting says `attached`, with
that credential as its holder (§9.2.1), even before its client confirms.
Thus the next launcher does not choose it too. If nobody confirms in that
time, the greeting again says what it said before.

The steps:

1. **Client.** It bootstraps exactly as §4–§7, with a fresh one-shot key
   and its `attach`. Its `cols`/`rows` are those of its own terminal.
2. **Launcher.**
   - It checks the protocol number as for any line.
   - When `!agent=yes`, it triggers ssh's bind before it prints the line
     (§4.4 step 4, §8). Thus a resuming client captures its own bind from
     its own SSH login.
   - It takes the lock and connects to every `R/mosey/*/attach.sock`
     (`server.md` §2.6 says what `R` is and how the directories are
     checked).
   - It keeps those that answer with a greeting within 2 s, and chooses as
     the table says.
   - To start a session, it rewrites the line's `attach` as `new:NAME` and
     continues as §4.4 does. It starts a spawner of its own.
   - To take a session, it closes every other connection. It rewrites the
     line's `attach` as `resume:SID` (a reconnect keeps its CREDID,
     `resume:SID:CREDID`, §9.2.2). It sends the line to that session's
     spawner.
   - A `new:NAME` or the all-zero SID from a client gets
     `MOSEY-ERROR 1 !code=line`.
3. **Spawner.** The session's spawner owns the socket. It:
   - checks the peer's uid with `SO_PEERCRED` [S1 `resume.go`],
   - sends its greeting (§9.2.1),
   - reads the launcher's `ClientLine` (0x40),
   - parses it again (it trusts no parse from another process),
   - checks that it is `resume:SID` or `resume:SID:CREDID` for its own
     SID, and that the client's public key is an X-Wing key,
   - forwards the key to proto (`Resume`, 0x05).

   Then proto mints a credential for the **same SID**, with the usual TTL
   (30 s) and cap (2 unused; proto evicts and logs the oldest). The
   credential comes back as `Credential` (0x30). The spawner checks it as
   at bootstrap (§4.4 step 3), and checks that its `sid` is the session's.
   The spawner marks the session as held by that credential (see the lock
   paragraph above).

   The spawner sends the credential to the launcher in `Ready` (0x41).
   The launcher prints it exactly as for a new session. Any failure is
   `Failed` (0x42), which the launcher turns into
   `MOSEY-ERROR 1 !code=internal`.
4. **Handshake and takeover** as §7 and §9.1. On confirmation, the server
   revokes every other transport of the session. The client of each one
   exits and says so.
5. **Versions** (D8 V1). Every session's greeting has the stable form of
   §9.2.1, and every launcher reads it in full. Thus a launcher chooses
   among the sessions of every mosey version alike. After an upgrade of
   the host's mosey, a plain `mosey DEST` takes its detached session back.
   `-s NAME` finds NAME, whichever binary runs it. No software version is
   compared.

   The launcher attaches the session as steps 2–4 say, through the attach
   protocol (`server.md` §2.8). The session continues to run its own
   binary, so an upgrade takes effect on new sessions. The client and the
   session's proto then check their handshake protocol
   (`transport.md` §2.3).

   A session whose greeting does not parse is not chosen. For a session
   whose attach protocol is not this launcher's:
   - `auto` never takes it. (`-list` lists it, so the user can see it.)
   - If `name:NAME` or `resume:SID` names it, the launcher refuses with
     `MOSEY-ERROR 1 !code=attach detail=P-N`. P is its spawner's number
     and N the launcher's. The launcher's stderr says
     `session NAME speaks attach protocol P; this mosey speaks N`.

   The launcher treats in the same way a session whose greeting has a
   critical field that this launcher does not know (§9.2.1). But it
   refuses with `MOSEY-ERROR 1 !code=unsupported detail=KEY`, so the
   client says which field this host's mosey cannot honour. In both
   cases, the session's name stays taken: a new session never gets it.
6. **The size** in the ClientLine is not applied by the spawner, because
   an unconfirmed attach must change nothing. The client sends its size
   as the first input event after it connects (§6.2). When the transport
   is confirmed, that event resizes the pty and emu, through the one
   resize path.
7. **The screen** starts from scratch on the new connection. SSP state is
   per transport (`ssp.md` §1.3), so the new client receives the whole
   current screen as its first diff.
8. **If proto has died**, the session is over (`server.md` §2.4). The
   spawner tears it down, so its socket is gone and a resume finds no
   session. A restart of proto on the same pty ([S4] §3.8) is left for a
   later slice; see `server.md` §5.4.

#### 9.2.1 The greeting

The greeting is the first message that the spawner sends on an attach
socket. It is one seqpacket message in §6.1's grammar, **not** an IPC
message:

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
| `!holder` | `b64(8)`: the credential id that holds the session | optional | yes | it restricts: R3 takes a session back only if this is its own credential (§9.2.2). If ignored, a reconnect could take a session from whoever took it over |
| `!name` | `sname` (§6.2) | mandatory | yes | it selects: `-s NAME` and `-kill NAME` find the session by it |
| `peer` | `addrport`: `netip.AddrPort.String()` of the last attached client, unmapped, no zone | optional | no | it describes, for the takeover message |
| `peer-host` | `hostname` (§6.2): the name that the last attached client claimed (its `host`) | optional | no | it describes, for `-list`. It is present only with `peer`. A launcher that drops it loses only the name |
| `!sid` | `b64(16)` | mandatory | yes | it selects: the session a resume names (`resume:SID`) |
| `since` | `dec`: unix seconds of the last change of state | mandatory | no | it describes. R1 orders detached sessions by it, but never takes one it would not otherwise take |
| `started` | `dec`: unix seconds the session started | mandatory | no | it describes |
| `!state` | `new` / `attached` / `detached` | mandatory | yes | it restricts: `auto` takes only a detached session, and never steals an attached one (D8 R1) |

The states:

- `new`: no client has attached to the session yet.
- `attached`: the session's client is attached, or a resume's credential
  for it is out and not yet expired (§9.2 "The lock").
- `detached`: the session's last client said it was leaving, its
  connection failed, or proto has not heard from it for `SilentAfter`
  (§9.2).

`holder` is the id of the credential that made the attached connection,
or of the credential that proto minted for the pending resume. The
exception: a reconnect's pending resume names the CREDID that the
reconnecting client gave (§9.2.2). `holder` is absent when the session is
`new` or `detached`. A credential id is not secret. It travels in the
clear in msg1 (`transport.md` §3.4), and only the user's own processes
can read a greeting. R3 uses it to tell "still held by me" from "held by
someone else" (§9.2.2).

`peer-host` is the `host` of the ClientLine whose credential made the
attached connection. Proto learns it with the client's key (`server.md`
§3.3 `Start`, `Resume`) and reports it with the address (`Attached`).
A `peer-host` without a `peer`, or one that is not a `hostname`, is
dropped as if absent. The greeting is canonical without it, and the
launcher reads the rest of the greeting as usual.

`cmd` is the `cmd` of the ClientLine that created the session, exactly as
it came (§6.2, §9.2.3). It stays for the life of the session. `auto`
matches on it (§9.2) and `-list` shows it (§9.4).

`fg` and `cwd` tell what the user would find at the session's keyboard.
The spawner reads them afresh for each greeting, so `-list` can tell
sessions apart. The program is the leader of the pty's foreground process
group (TIOCGPGRP on the master). This is the shell at its prompt, or the
job that the shell gave the terminal to, such as an editor or `claude`.
The job can be typed at the prompt or be the session's command. If that
leader is gone or unreadable, the shell stands in.

The program's name is argv[0]'s base name, less a login shell's `-`. This
is the name a program gives itself (a Nix-wrapped `claude` has comm
`.claude-unwrapp` but argv[0] `claude` [M] /proc on NixOS, 2026-11-18).
Else the name is its comm. Its directory is where `/proc/PID/cwd` points,
with the user's home written `~`, as a prompt writes it. The spawner
reads both as the user, who owns the processes. A value that is not
readable (a `sudo` job's directory) is left out.

The spawner fits each value to its grammar:

- every byte that is not UTF-8, and every control character, becomes `?`,
- the value is cut on a rune boundary with `…`,
- a directory is cut at its start, so its end shows.

Each is absent when unknown. Both are absent outside Linux.

**Stable** (D8 V1, `versioning.md` §5). `aproto` is the one number of the
attach protocol that the session's spawner speaks (`server.md` §2.8: the
greeting and the messages after it). It names only the envelope: §6.1's
grammar, the greeting's mandatory fields and the framing of the messages.
A later release adds a field to the greeting as any line gains one. Thus
`ParseSessionLine` reads the greeting of any session with the same
number. A launcher attaches a session only if `aproto` equals its own
`bootstrap.AttachProtocol` (§9.2 step 5). The greeting holds no software
version.

The parser is canonical and fuzzed. A greeting with a critical field that
this launcher does not know is one that it cannot judge. `auto` does not
choose that session. If `name:NAME` or `resume:SID` names it, the
launcher refuses as for another attach protocol, with `attach` and its
own number on both sides.

`MaxSessionLine` = 2048 bytes [derived: the longest greeting is 1991
bytes: `MOSEY-SESSION` and 5 digits 19; ` !cmd=` 1372; ` cwd=` 261;
` fg=` 68; ` !holder=` 20;
` !name=` 39; ` peer=` and 47, 53; ` peer-host=` and 63, 74; ` !sid=` 28; ` since=` and
` started=` with the 12-digit bound on the times, 19 and 21; ` !state=`
and `detached`, 16; LF; then the next power of two]. A seqpacket message
of that size fits any socket buffer that the kernel gives.

#### 9.2.2 Reconnect (D8 R3)

While the client runs, roaming (D21) rides out a dead spot. Roaming
cannot help when the server's half of the transport is gone, or never
hears the client again. Examples are a NAT or firewall that drops the UDP
flow for good while SSH still works, or a laptop asleep past the server's
tombstone. Thus the client also resumes its own session, in the
background, and never asks the user anything:

- **When.** When no authentic packet has arrived for
  **`ReconnectAfter` = 15 s** [D: five of D11's 3 s heartbeats; the
  server's `SilentAfter` is the same, so each side gives up on the other
  at about the same moment], the client starts its tries. It continues to
  send on the old transport.
- **Each try** is a whole bootstrap (§4–§7) with a fresh one-shot key and
  `attach = resume:SID:CREDID`. SID is the session's. CREDID is the
  credential that its current transport was made with. The try's ssh
  runs:
  - with `-o BatchMode=yes` (ssh_config(5): ssh asks no passphrase,
    password or host-key question; a login that needs one fails),
  - in a session of its own (`setsid`), so neither ssh nor anything it
    starts has the user's terminal to open as `/dev/tty`. This includes a
    `ProxyCommand`, a `ProxyJump`'s inner ssh (which does not inherit
    `-o BatchMode`), and a `KnownHostsCommand`,
  - with `SSH_ASKPASS_REQUIRE=never` (ssh(1)), so none of them asks
    through a graphical askpass instead.

  Its stderr goes to the client's log, never to the screen. Nothing is
  copied over (§4.7.1). The agent's bind is captured afresh, so the new
  transport forwards this login's agent. For a session on this machine
  (§2.2), a try runs the local launcher again, with no ssh, so there is
  nothing to ask. A try that has not dialled within `ReconnectTry` = 60 s
  [D: twice the 30 s credential TTL, the longest a healthy try can need]
  is abandoned.
- **Backoff.** The first try starts at 15 s of silence. After a failed
  try, the next waits 2 s, doubling to at most 60 s [D: a try is one SSH
  login; 60 s keeps a day-long outage to about 1440 of them, and puts a
  working session at most a minute after the network returns when
  roaming cannot]. The wait starts from 2 s again when the session hears
  from the server.
- **What the user sees.** Nothing is asked, but nothing is hidden either.
  From the first try until the server is heard again or the new transport
  is in, a status replaces the screen's top row, in reverse video:
  `mosey: no contact for DURATION; reconnecting`. After a failed try,
  ` (last try: REASON)` follows. REASON is the first line of the failure,
  in printable ASCII, at most 120 bytes [choice: a line's worth; the log
  has it whole], because it can carry what ssh said. DURATION is kept
  current each second.

  Thus a try that can never work (a host that wants a password, which
  `BatchMode` refuses) shows its reason, and not a screen that has
  stopped [choice: R3 says to ask nothing, not to say nothing; tries
  continue as below, since the user may fix the cause, say by adding the
  key to the agent, without restarting the client]. The row is part of
  what is drawn, not part of the session's screen. The server never sees
  it, and the renderer's diff puts the row back when it goes.
- **The launcher's answer** to `resume:SID:CREDID`, under the lock:
  - If no session SID answers, the answer is `MOSEY-ERROR 1 !code=session`.
  - A session that is `detached`, or whose `holder` is CREDID, is taken
    as §9.2 step 2 says. The second case is a path broken in one
    direction only: the server still hears the client, so the session
    never went `detached`. The takeover revokes this client's own old
    transport.
  - A session that any other credential holds gets
    `MOSEY-ERROR 1 !code=taken detail=SINCE`, where SINCE is its
    greeting's `since`.

  The launcher passes CREDID on to the spawner. While the credential that
  proto mints is out, the greeting's `holder` is CREDID, not the new one:
  the hold is that client's. Otherwise a try dropped at the swap (below)
  would leave the session held by a credential that nobody will use. If
  the path then went quiet again within its 30 s, the same client's next
  try would read `taken` and exit, though nobody took the session.
- **The swap.** Before it dials, the try checks that the old transport is
  still silent. If anything authentic has arrived since the try began,
  roaming has won. The try is dropped and its credential expires unused
  (30 s, §4.5). Otherwise the try dials. The confirmation revokes the old
  transport (D26). A REVOKED that arrives on the old transport while this
  client's own dial is in flight is not a takeover. The client waits for
  its dial, and exits as §9.1 says only if the dial fails.

  On success:
  - the terminal stays raw and the screen stays up,
  - the new transport's SSP starts from scratch, so its first frame is
    the whole screen,
  - prediction starts afresh,
  - the size goes as the first input event again.

  Keystrokes typed during the silence that the server had not
  acknowledged are dropped [choice: the old proto may or may not have
  written them to the pty, and sending them again could type them
  twice].
- **How it ends.** On `session`, the client restores the terminal, prints
  `mosey: session NAME on DEST has ended: its shell exited, or the host restarted`
  and exits 1 [choice: it cannot tell which]. On `taken`, it prints
  `mosey: session NAME taken over by another client at TIME` and exits 3,
  as §9.1 says. The client logs every other failure and tries again after
  the backoff. These failures include ssh that exits 255, a timeout, no
  mosey of this version, `internal`, and a handshake that does not
  complete.
- **Open (PLAN O15), a placeholder until Dan decides.** Until he decides,
  a try never takes a session that another client holds. D26 says only an
  explicit `-s` takes over, and a stolen laptop that wakes must not take
  its session back. The other answer is a try that takes over as `-s`
  does. That is one switch in the launcher (`reconnectTakesBack` in
  `internal/server/choose.go`), and both settings are tested. A try names
  its session by SID, not by name. Thus it never attaches a newer session
  that reused the name after the old one ended. Dan must also confirm
  that this meets R3's "by name".
#### 9.2.3 How a new session starts: `-dir`, `-type` and a command

`-dir DIR` and `-type TEXT` (§2) travel as the ClientLine's `dir` and
`type` (§6.2). They set how a session starts. They never change how a
client attaches to a session. They do what a tmux user does with
`tmux new-session -c DIR` and then `tmux send-keys TEXT Enter`, but
without tmux (Dan, 2026-11-15).

- **Only on creation.** The launcher uses them (and `cmd`, below) only
  when §9.2's table makes it start a session (`new:NAME`). This occurs
  for:
  - a plain `mosey DEST` when no session is detached;
  - `-new`;
  - `-s NAME` when no session NAME exists.

  When the launcher takes an existing session, it ignores them, with no
  error and no message. The `resume:SID` line that it sends to that
  session's spawner has `dir` and `type` set to `-`. A reconnect
  (§9.2.2) sends `-` for both. Thus a user can repeat the command
  `mosey -s work -dir src -type 'claude' DEST`. The first run makes the
  session, and each later run returns to it.
- **The directory.** The launcher resolves `dir`:
  - It uses an absolute path as it is.
  - It joins any other path to the home directory that the shell starts
    in (`server.md` §2.5: `$HOME`, else the passwd home, else `/`). Then
    it cleans the result (`filepath.Join`).

  The result must name a directory that the launcher can `stat`, with
  symlinks followed. The launcher checks this while it holds the lock,
  before it starts a spawner. If the check fails:
  - the launcher starts nothing;
  - the launcher writes `the directory DIR is not one: ERR` on stderr and
  `MOSEY-ERROR 1 !code=dir` on stdout;
  - the client says `mosey: DIR is not
  a directory on DEST, so no session was started` and exits 1 (§6.4).

  The spawner resolves the same `dir` in the same way, and starts the
  login shell there (`server.md` §2.5). If the directory goes away
  between the check and the start, the shell does not start. The session
  then fails with it (`Failed`, `internal`).
- **The text.** The spawner waits until the login shell starts and
  writes its first output to the pty (usually its prompt). Then the
  spawner writes `type`'s text and one CR into the pty master, in one
  write. CR is 0x0D, which a terminal's Enter key sends. A person who
  waits for the prompt types the text in this way (Dan, 2026-11-16).

  Proto reads the master, so proto sees the first output. After its
  first read that returns bytes, its pty reader sends the spawner
  `FirstOutput` (`server.md` §3.3). The spawner waits for that, and then
  for the tty to stop echoing (below). It waits for at most `TypeWait` =
  2 s in total [choice: far longer than an ordinary shell needs to draw
  its first prompt; short enough that a shell which prints nothing, or
  slow rc files, only delay the text and never lose it].

  If `TypeWait` passes first, the spawner types the text anyway. The
  text is then typeahead. It stays in the tty's input queue until the
  shell reads its first line. The tty echoes it when it arrives, so it
  can show twice: once before the prompt and once after it. The wait
  prevents exactly that. Typed ahead, bash 5 (NixOS, through the e2e
  test's throwaway sshd, 2026-11-16) showed `echo hi`, then
  `PROMPT$ echo hi`, then `hi` [shells]. Typed after the prompt, the
  text shows `PROMPT$ echo hi` once.

  The first output is not always the prompt. A login shell's profile can
  write first (for example, a window title). Readline turns the tty's
  `ECHO` off only immediately before it draws the prompt ([M] strace of
  bash 5.3, 2026-11-16). Text typed between these two points showed
  twice on CI's Ubuntu runner. So after `FirstOutput`, the spawner also
  waits until the slave's termios has `ECHO` off. It reads the termios
  through the master, and looks every 10 ms [choice].

  A line editor (readline, zle, fish) turns this flag off to read keys
  itself. A shell with no line editor (dash) leaves the flag on
  permanently. That shell gets the text when `TypeWait` passes. This
  costs it up to 2 s, but gives no second echo, because the tty's echo
  is its only echo.

  The tty's `ICRNL` turns the CR into the newline that ends the line.
  This is what `tmux send-keys TEXT Enter` sends: the keys, as if typed.
  A prompt does not prove that the shell reads. The rc files can run a
  program that prints something and then reads the terminal (for
  example, a passphrase prompt). That program then gets the text
  instead of the shell.

  The text is typed into the shell. The server never runs it. It is the
  user's own command, with the user's own `PATH` and aliases. When it
  exits, the user is at that shell's prompt in DIR. The spawner writes
  the text before it sends `Ready`, so the text always comes before
  anything the client types. This has a cost. For a line with a `type`,
  `Ready`, and thus the credential, waits for the shell's first output
  (at most `TypeWait`, well inside T2). For a line without a `type`,
  there is no wait. If the write fails, the spawner logs it and the
  session continues.
- **The command.** A line with a `cmd` (§2, §6.2) starts the session
  with the command instead of an interactive shell. The spawner runs the
  shell that `server.md` §2.5 picks as `SHELL -c CMD`. It uses:
  - the same argv[0] (`-` and its base name);
  - the same environment;
  - the same directory, `dir` included.

  With that argv[0], the shell is a login shell. Thus it reads the same
  profile as the interactive shell, and has the same `PATH`. ssh runs
  its command with a non-login shell, but there sshd's own login sets
  up the environment. Here, the spawner's environment is that of a
  non-interactive ssh command.

  `CMD` is the text as it came, one argument to `exec`. The server puts
  it through no shell other than that one, and interpolates it into
  nothing. When the shell exits, the session ends as any session whose
  shell exits does (§9.3). Proto sends END and the client exits 0.

  The command's exit status is not passed on. END's body is one reason
  byte (`transport.md` §8.4). To carry the status would change that
  frame, and so the handshake's protocol number. It would also make
  proto wait for the spawner's `ShellExit` after the pty's EOF, which
  proto does not do now. Only a session that the line creates runs a
  `cmd`. The `resume:SID` line for a session that the launcher takes has
  no `cmd`, as it has no `dir` or `type`.
- **Returning to a command** (PLAN D8, Dan, 2026-11-16, option C). The
  spawner keeps the `cmd` that its session was created with. It puts
  that `cmd` in every greeting (§9.2.1). The client sends a plain
  `mosey DEST CMD` as `auto` with the `cmd`. The launcher takes the most
  recently detached session whose greeting has that same `cmd`, compared
  byte for byte. If there is none, it starts a new session that runs the
  command (§9.2's table).

  So when the user closes the window on `mosey dan-desktop claude` and
  runs it again, it returns to that claude. A second window, while the
  first is attached, gets a second claude. A plain `mosey DEST` with no
  `cmd` takes only a session whose greeting has no `cmd`. Thus it never
  puts the user into a detached program, and `mosey DEST CMD` never puts
  the user into a detached shell. The key is the command alone (§2).
  `-dir`, and `-type` for a shell, only set how a session starts.
- **Saying a command was not run.** A line with a `cmd` can take a
  session whose greeting has a different `cmd`. This occurs for
  `name:NAME` when NAME runs something else, or runs a shell. Then the
  launcher adds `existing` to the credential line it passes on (§6.3).
  The client then prints `mosey:
  session NAME was already running, so the command was not run` on
  stderr before the screen goes up. `-s NAME DEST CMD` says nothing when
  it returns to a NAME that it started with that same `cmd`. `auto`
  never says it either. In both cases, that command is the one that
  runs. The launcher adds `existing` to no line in answer to a line
  without a `cmd`, so no older client sees it.

#### 9.2.4 The implicit directory: where the terminal started the client

A terminal that opens a new window or tab "here" starts its command in
the directory of the tab it came from. It knows that directory from OSC 7
(`screen.md` §4.7). GNOME Console does this for Ctrl+Shift+N and
Ctrl+Shift+T ([M] Console 50.0 source, `kgx-window.c` `new_activated`,
read 2026-11-26). If the command is mosey, the directory is the client's
working directory. A session that starts in `$HOME` loses it.

- **Local.** The destination is this machine (§2.2), and the command
  has no `-dir`. Then the client sends its own working directory as
  `dir`. This is tmux's rule: `new-session` starts in the client's
  directory unless `-c` gives another [D: Dan, 2026-11-26]. The client
  uses `os.Getwd`, which gives `$PWD` if `$PWD` names the same
  directory. Thus a path through a symlink stays as the shell showed it.
  If `os.Getwd` fails, or `ValidDir` refuses the result, the client
  sends no `dir`. As with any `dir`, it applies only when the line
  creates a session (§9.2.3). `-list` and `-kill` send none.
- **Remote: `MOSEY_FROM`.** A window that shows a remote session has an
  OSC 7 URI whose host is the remote one. The terminal starts the new
  client in a local directory, so the client cannot know the host. A
  terminal that wants the new window on the same host sets
  `MOSEY_FROM` in the new child's environment. The value is the OSC 7
  URI of the tab it came from, `file://HOST/PATH` [D: Dan, 2026-11-26:
  an environment variable, which no other command takes as an
  argument]. No standard carries this. ssh reads no destination from
  its environment, and VTE ignores iTerm2's `OSC 1337 ; RemoteHost`
  ([M] VTE 0.84.1 `vteseq.cc`). The client reads the variable and
  removes it from its own environment before anything else. Thus no
  session's shell, no ssh and no later mosey gets it. It applies only
  if all of these are true. Otherwise the client ignores it.
  1. The client is the leader of its session (`getsid(0)` is its own
     pid). A terminal starts its command in this way. A shell starts a
     command in a process group of the shell's own session. Thus a
     `MOSEY_FROM` that a plain shell kept in its environment never
     changes a `mosey` typed there.
  2. The command has no DESTINATION, no `-dir`, and no `-list` or
     `-kill`.
  3. `ParseFrom` accepts the value: the scheme `file` (any case), then
     `//`, then a host, then a path that starts with `/`. The host is
     empty, or a hostname: 1 to 253 bytes of dot-separated labels. Each
     label is 1 to 63 letters, digits and `-`, and does not start or
     end with `-`. So a host never starts with `-`, and the remote
     shell, which writes the host, cannot give ssh an option. The path
     percent-decodes (RFC 3986 §2.1) to a `ValidDir`. A `?` or `#`,
     which starts a query or a fragment, is refused.
  4. The host is not this machine. It is not empty, not `localhost`,
     and its first label is not that of `os.Hostname()`, compared
     without regard to case. A host that is this machine gives the
     local rule above, from the working directory.

  Then the client acts as if HOST is its DESTINATION and the path is
  its `-dir`, implicit. Its other flags apply to HOST: `-new`, `-s`,
  `-A`, `-remote` and ssh options after `--`. The client ignores
  `-close-if-idle`, and does not refuse it, because it is for local
  sessions only. The host is the remote's hostname, as its shell wrote
  it. It is not the destination that the user typed: it has no `user@`,
  port or ssh alias. Thus a remote can choose the host that the next
  new window logs in to. The terminal's title bar shows that directory
  and host before the user opens the window, and ssh still checks the
  host key [D: Dan, 2026-11-26].
- **Implicit, so never an error.** The launcher refuses a `-dir` that
  the user typed if it names no directory (§9.2.3). A directory that the
  client chose is not the user's mistake. So if the launcher answers
  `!code=dir` to such a line, the client starts once more. It sends the
  same line without its `dir`, and the shell starts in home. The
  launcher's stderr line about the directory still shows. The client
  sends the same one-shot key again, as in §4.7.8. This is safe: the
  launcher started nothing, so nothing was sealed to the key, and the
  key is public anyway. Over ssh this is a second ssh login. It occurs
  only when the directory is gone, or when the name HOST reaches a
  different machine from the one whose shell wrote it.

### 9.3 How long a session lives (D8 R4)

| The session | Ends when |
|---|---|
| has never had a client | every credential minted for it has expired unconfirmed (§4.5: 30 s after the last one), or the spawner's backstop fires |
| has had a client | its shell exits: `exit`, Ctrl-D, or anything else that ends it; or `mosey -kill NAME DEST` (§9.5); or it has been `detached` for **`IdleTimeout` = 7 days** [D, Dan 2026-11-15]; or the spawner is signalled; or proto dies (§9.2 step 8). **Never** because its client went away |

`-kill` and the idle timeout hang up the shell. The spawner sends SIGHUP
to the shell and to the pty's foreground process group, as a hangup does
[kernel ABI, tty hangup]. The shell's exit then ends the session in the
usual way (`server.md` §2.4). So an attached client gets END
`shell exited` and exits 0. If a shell ignores SIGHUP, the spawner hangs
it up permanently after `HangupGrace` = 10 s [choice]. The teardown
closes the last pty master, then sends SIGKILL to the shell after T8.

The idle time starts when the session becomes `detached` (§9.2). Each
attach resets it. **Configurability** (PLAN O14): it is a constant. A
per-session value needs a ClientLine field, and a per-host value needs a
server config file. Neither is cheap. `SpawnerConfig` has a field for
tests.

There is **no detach key**: all that the user types goes to the shell.
A client that goes away tells the server if it can. It does this on a
signal (SIGTERM, SIGHUP: a closed terminal, a logout, a shutdown), or
at the end of its terminal's input. It sends END with reason `detached`
(`transport.md` §8.4), puts the terminal back, and prints:

```
mosey: detached from session NAME; resume it with: mosey -s NAME DEST
```

Then it exits 0. The server marks the session `detached` and keeps it.
Some clients cannot tell the server (power loss, a crash, a network that
never comes back). Such a client leaves the session `attached` until
proto has heard nothing for `SilentAfter`. Then the session becomes
`detached`, so the next plain `mosey DEST` takes it (§9.2).

The hazards of §4.5 ("Known hazard") apply. With logind's
`KillUserProcesses=yes`, the session dies with the SSH login that
started it, unless the user lingers.

### 9.4 Listing sessions

`mosey -list DEST` runs `mosey --serve=list` with stdin closed. It runs
it over the bootstrap's own ssh command, as follows:

- With `-remote`, the ssh command is that of §4.1, with its last
  argument `exec /bin/sh -c 'exec SERVER
--serve=list'`.
- With no `-remote`, §4.7.2's probe runs `--serve=list`. The probe finds
  the host's mosey: `PATH`'s or `~/.local/bin/mosey`.

If the probe answers `MOSEY-PROBE`, the client reports it as §4.7.1
says. It does not show it as a list, and copies nothing. The server
connects to each attach socket as the launcher does, but without the
lock, because it chooses nothing. It reads each greeting and prints one
line for each session that answered, oldest first. Then it exits 0:

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
| `peer-host` | `hostname` (§6.2): the greeting's `peer-host`, only with `peer` | optional | no | as `cmd` |
| `since` | `dec`: unix seconds of the last change of state | mandatory | no | as `cmd` |
| `state` | `new` / `attached` / `detached` | mandatory | no | as `cmd` |

The number is that of the bootstrap lines (§6.1). The client checks it
as it checks theirs.

The client reads ssh's stdout, at most 2 MiB [derived: `MaxListed` ×
`MaxListLine`]. It skips each line that is not a `MOSEY-` line (a login
shell's chatter, §6.5). It parses each `MOSEY-LIST` line with
`ParseListLine`. The parser is canonical and accepts at most
`MaxListLine` = 2048 bytes [derived: `MOSEY-LIST` and 5 digits 16;
` cmd=` 1371; ` cwd=` 261; ` fg=` 68; ` name=` 38; ` peer=` 53;
` peer-host=` 74; ` since=` 19; ` state=` and `detached` 15; LF; 1916
in all; then the next power of two]. The parser is fuzzed, because a hostile server
writes the line. The client shows at most `MaxListed` = 1024 lines
[choice]. It does not show a line that does not parse, and it says how
many lines it dropped.

Every field except `cmd` comes from a grammar of printable ASCII with no
space. `cmd` decodes to a `cmdtext` (valid UTF-8, no control character
except tab), which the parser checks. The client shows `cmd` with each
rune that is not printable as `?`. These are the runes with
`unicode.IsPrint` false: tab, format characters such as the bidi
overrides, and non-ASCII spaces. The client cuts `cmd` to 60 runes with
`…` after [choice: one terminal line beside the other columns; the full
text is the user's own and in their shell history]. So the table that
the client lays out itself cannot carry an escape sequence, and cannot
reorder what it shows (D9).

The command is the last column. It shows only when a session has a
command, and is empty for a session that has none. The client shows
`peer` as `PEER`: the IP address without port, shortened as in §9.1,
for attached sessions only. With a `peer-host`, `PEER` is `NAME (ADDR)`, as in §9.1, loopback
included. A `peer-host` that is not a `hostname`, or one with no `peer`,
is dropped as in §9.2.1: the row stays. It shows `fg` as `RUNNING`, cut to 16 runes, and `cwd` as `DIR`,
cut to its last 32 runes with `…` before [choice: a program's name whole
and enough of a path's end to tell sessions apart, so a row stays one
line]. Each is a column only when a session has it, so an older server's
list lays out as before:

```
NAME         STATE     SINCE                      PEER                RUNNING  DIR               COMMAND
quiet-heron  detached  2026-11-14T09:30:12+00:00                      bash     ~
brave-otter  attached  2026-11-16T15:02:40+00:00  blade (100.64.1.2)  claude   ~/Projects/mosey  claude
```

`SINCE` is in the client's local zone, as §9.1's times are. If there is
no line, the client prints `no sessions on DEST` (`on localhost` for this
machine, §2.2).

A lister sends no ClientLine. The spawner sees the connection close
after its greeting, and does nothing.

### 9.5 Ending a session

`mosey -kill NAME DEST` runs `mosey --serve=kill NAME` in the same way
as `-list`. The name is an `sname`, which needs no quotes in any shell
(§4.1). The server finds the session called NAME among those that
answer, as `-list` does. After the session's greeting, the server sends
it `Hangup` (0x43, `server.md` §2.6). The spawner hangs up the shell
(§9.3), and closes the connection after it sends the signals.

The server prints nothing and exits 0. The client says
`mosey: ended session NAME on DEST`. If no session is called NAME, the
server prints `MOSEY-ERROR 1 !code=session` and exits 1. The client then
says `mosey: no session called NAME on DEST` and exits 1. The client
reports any other failure as it does for `-list`.

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

Errors are values (§10.1). `client.Run` matches them with
`errors.Is`/`errors.As`. Only `cmd/mosey` prints and exits.

### 10.1 The Go interface of `internal/bootstrap`

This replaces the stubs in `internal/bootstrap/*.go` and the one-line
summary of the package in architecture.md §5. The commit that implements
it must bring both in line (§15). `bootstrap` imports neither
`handshake` nor `transport`.

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
	Host            string            // host: "" is absent; a bad one is dropped (§6.2)
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
	PeerHost        string         // peer-host; "" is absent, and it needs Peer
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
	Peer     netip.AddrPort // the zero AddrPort is absent
	PeerHost string         // peer-host; "" is absent, and it needs Peer
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
ProbeLine. `client.Run` also wraps a `*NoLineError` in it when ssh
exited 126 or 127 (§4.2, §10).

The installer of §4.7.7 is `internal/install` (`install.Run(args,
getenv, uid) error`). It is a server-side package, and the client never
imports it.

The implementation also adds these items:

- `*UsageError`: what `ParseSSHOptions` and `SSH.Check` return (exit 2).
- `*ResolveError`: the failure of ssh -G. It carries the bounded stderr
  for §10's message.
- `*AddrError`: `ErrBadAddr` with the refused `addr`, its rule and any
  lookup error, for §7.2's message.
- `Config.Has`: the keyword test of §3.
- `ClientEnv`: §6.2's env from the environment. It names what it left
  out.
- `SSH.RemoteCommand`: §4.1's one argument.
- `ExitStatus`, `EnvNames`, `ValidServer` and `ValidEnvValue`.
- The field sizes (`PublicKeySize` and so on), `TailSize`,
  `MaxSanitizedLine` and `MaxConfig`.

`Sanitize` returns an `io.WriteCloser`, not an `io.Writer`. It holds a
rune that is split across two writes for the next write. `Close` writes
any held bytes, escaped.

---

## 11. Constants

| Name | Value | Provenance |
|---|---|---|
| `bootstrap.Version` | 1 | ours (§6.1, `versioning.md` §5: the number names the lines' envelope only; reset from 2 by Dan, 2026-11-17) |
| `MaxFields` (any line) | 32 | [choice] `versioning.md` §6 |
| `MaxClientLine` | 8192 B | [derived] §6.2: at most 5902 B used |
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
| `MaxSessionLine` | 2048 B | [derived] §9.2.1: at most 1991 B used |
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
| `MaxListLine`, `MaxListed` | 2048 B, 1024 lines | [derived] §9.4: at most 1916 B used; [choice] |
| `hostname.Max` | 63 B | [D] §6.2 `host`: one DNS label (RFC 1035 §2.3.4) |
| R3: no session | exit 1 | [choice] §9.2.2 |

---

## 12. Tests

**Unit, `internal/bootstrap`:**

- Marshal/Parse round trips for the two lines and the error line. These
  include the maxima: every env name at 64 bytes, the longest IPv6, and a
  1024-byte `dir` and `type`.
- `dir` and `type`: the parser refuses each of these: a 1025-byte text, a
  NUL, an LF, a CR, an ESC, a DEL, a C1 control, invalid UTF-8, and a
  padded or non-canonical base64url field. `type` accepts a tab and `dir`
  refuses it. Both accept spaces and non-ASCII letters.
- Each rule of §6.1, broken one time:
  - CR, double space, trailing space, padding, non-zero trailing bits,
    wrong decoded length, leading zero, `0` cols, 65536.
  - An env name that is not an `ename`, and unsorted or repeated names,
    known or not. An unknown `ename` is skipped, and the rest applies.
  - `::ffff:` and zoned addresses, and `0.0.0.0`, `::`, `224.0.0.1`,
    `ff02::1` and `255.255.255.255` as `addr`.
  - A wrong number (the error carries the number).
  - A missing mandatory field.
  - Keys out of order or repeated (also `!k=` beside `k=`).
  - An empty value, a key outside the grammar, and a known field with the
    wrong `!` marking.
  - More than `MaxFields` fields.
- A `host` or `peer-host` that is not a `hostname` (64 bytes, a leading
  or trailing `-`, an `_`, an empty label), and a `peer-host` with no
  `peer`: each is dropped, and the line parses as the line without it.
  Marshal never writes one.
- Must-ignore (`versioning.md` §7), on every line. An unknown field
  without `!` parses to exactly the same result as the line without it.
  An unknown field with `!` is refused as a `*CriticalError` that names it.
- ErrorLine: every code. An unknown 16-letter code parses, and the client
  maps it to `internal`. The parser refuses a 17-letter code, an
  upper-case code, a 6-digit or zero-led number, and a line over 256
  bytes. It accepts a number other than 1.
- `ChooseAddr`, each row of §7.2's table, with an injected resolver:
  - A usable `addr`.
  - A loopback `addr` with a non-loopback `hostname` (falls back), and
    with `localhost` (kept).
  - A subnet broadcast (taken: the kernel refuses it, §7.2).
  - Link-local, with and without a zoned `hostname`.
  - `-` with a `hostname` that resolves to `[::, 224.0.0.1, 192.0.2.7]`
    (picks the last).
  - Nothing usable (`ErrBadAddr`).
- `ReadCredential`:
  - Noise, then the line. The line first.
  - A `MOSEY-` line that does not parse.
  - Noise over `MaxPreamble`. One skipped line longer than `MaxPreamble`.
  - EOF. A protocol line over its maximum.
  - A reader that returns one byte at a time.
  - It never reads past the LF (a reader that fails on a read beyond it).
- ssh option filter: every letter in §2.1's table; clusters, and attached
  and separate arguments; `-A`/`-a` order; refused letters; a missing
  argument.
- `SSH.Command`: the exact argv for a given `Config`, with and without
  the 8.7 keywords. Its last element is exactly `exec /bin/sh -c 'exec SERVER
  --serve'`. Also the `-remote` charset, and a destination that starts
  with `-`.
- The remote command under each installed outer shell: sh, bash, zsh,
  fish, tcsh, nu. The test skips each shell that is absent. A missing
  `SERVER` exits 127, a non-executable one exits 126, and `~/` expands.
- The stderr filter: every C0 and C1 byte, ESC sequences, bidi controls,
  invalid UTF-8, a long line. The output never contains a byte below 0x20
  other than LF and TAB, and never 0x7F.
- The agent decision table of §5.
- The probe and the upload command (§4.7), under each installed outer
  shell, as for §4.1. The probe:
  - execs a `PATH` mosey elsewhere, whatever it says, and prefers it to
    `~/.local/bin/mosey`;
  - execs a `~/.local/bin/mosey` that answers the client's protocol, on
    `PATH` or not;
  - skips one that answers anything else (`other`), on `PATH` or not;
  - skips a symlinked one, or a symlinked `~/.local/bin`, off `PATH`, and
    execs it as it is on `PATH`;
  - prints a ProbeLine that parses when there is none (`none`).

  The upload command installs through a stand-in installer and removes its
  temporary file.
- `Platform`, `IsRelease`, `AssetName` and `ParseSums`: each row and rule.

**Unit, `internal/install`:**

- A fresh install.
- It replaces the user's own older file.
- It refuses each of these, and leaves it untouched:
  - a `~/.local/bin` that is a symlink;
  - a file that is a symlink;
  - a directory;
  - someone else's file (the "user" is a field, so a test can play
    another uid);
  - a group- or world-writable directory;
  - a size or hash mismatch (the installer removes the upload);
  - a `TEMP` outside `~/.local/bin`;
  - a relative `HOME`.
- It makes a missing `~/.local` and `~/.local/bin` with mode 0700.

**Unit, `internal/client`:**

- The consent table of §4.7.5, and the remembered-hosts file.
- The release fetch against a local HTTPS server. The client chooses the
  right asset. It refuses each of these before any upload: a hash
  mismatch, a missing asset, a 404, an oversized body and an `http`
  redirect.
- With `localhost` (§2.2):
  - The client runs the server stand-in with no ssh and no `ssh -G`, as
    `--serve`, `--serve=list` or `--serve=kill NAME`. The stand-in does
    not get the client's `SSH_CONNECTION` or `SSH_AUTH_SOCK`.
  - The agent decision of §2.2 for each of `-A`, `-a` and neither, with
    and without `SSH_AUTH_SOCK`.
  - R3's try resumes on loopback with the agent unbound.
  - The messages name `localhost`, and the hints name no host.

In `cmd/mosey`:

- Every session command parses `localhost` in any case, or no
  `DESTINATION`, as this machine. It parses `127.0.0.1`, `::1` and
  `me@localhost` as hosts for ssh.
- `-upload`, `-ssh` or ssh options on this machine are a usage error.
- `-h` is the usage, exit 0.
- The words after `DESTINATION` are the command, joined with spaces.
  Their own flags stay untouched (`far ls -la`). ssh options go before the
  destination, after `--`.
- A command keeps a plain `mosey DEST` `auto`, with the `cmd`.
- A command with `-type`, `-list` or `-kill`, or outside `cmdtext`, is a
  usage error.

**Fuzz.** Run each target locally for at least a few minutes before it
lands. Put the durations in the commit message. CI runs each for 10 s.

- Every line's fuzz target (`FuzzParseClientLine`,
  `FuzzParseCredentialLine`, `FuzzParseErrorLine`, `FuzzParseProbeLine`,
  `FuzzParseSessionLine`, `FuzzParseListLine`) also checks
  `versioning.md` §7. For each line it accepts, the same line with an
  unknown field added without `!` parses to the same value. With `!`, the
  parser refuses it and names the key.
- `FuzzParseClientLine`, `FuzzParseCredentialLine`, `FuzzParseErrorLine`:
  - No panic.
  - Each accepted line re-marshals to the identical bytes, less its
    unknown fields.
  - No accepted CredentialLine has an unspecified, multicast or limited
    broadcast `addr`.
  - No accepted ClientLine has a `dir`, `type` or `cmd` outside `dirtext`,
    `typetext` and `cmdtext` (§6.2). A reference in the test, written out
    rune by rune, checks this.
  - The seeds include lines with and without `cmd`, and credential lines
    with and without `existing`.
  - No accepted ClientLine has a `host` that is not a `hostname`. A
    line with a bad `host` re-marshals to the line without it. A
    reference in the test, a regular expression and the 63-byte bound,
    checks this.
- `FuzzChooseAddr`: no panic. The result, if any, breaks no row of §7.2.
- `FuzzReadCredential`: no panic. It reads at most
  `MaxPreamble + MaxCredentialLine` bytes. The result, if any, re-marshals
  to a line that is in the input.
- `FuzzSSHOptions`: no panic. Each accepted argv, parsed again, gives the
  same normalised argv. It never contains a refused letter.
- `FuzzSanitize`: the output invariant of the stderr filter.
- `FuzzParseProbeLine`: as for the other lines. `FuzzReadCredential`
  covers probe lines too.
- `FuzzParseSums`: no panic. Each hash it returns is the hash of an input
  line that names exactly that name. Nothing it accepts has a line outside
  the grammar.
- `FuzzParseSessionLine`: no panic. Each accepted line re-marshals to the
  identical bytes, less its unknown fields. Its `cmd`, if any, is a
  `cmdtext`, its `fg` an `fgtext` and its `cwd` a `cwdtext`. The seeds
  include lines with and without each. Its `peer-host`, if any, is a
  `hostname` beside a `peer`. A bad one is dropped, and the line
  re-marshals to the line without it.
- `FuzzParseListLine`: as `FuzzParseSessionLine` for `peer-host`.
- `FuzzParseListLine`: no panic. Each accepted line re-marshals to the
  identical bytes, less its unknown fields. Every field other than `cmd`
  is printable ASCII with no space. `cmd` is a `cmdtext`, `fg` an
  `fgtext` and `cwd` a `cwdtext`. The seeds include lines with and without
  each. `FuzzReadList` covers all of `-list`'s output: at most
  `MaxListed` rows, and no row longer than its fields allow.
- `FuzzListCommand` (`internal/client`): for any string, `-list` shows
  at most 60 runes and `…`, and each is printable
  (`unicode.IsPrint`).
- `FuzzFitText` (`internal/server`): for any name or path, the spawner
  makes valid UTF-8 within its bound, and an `fgtext` and
  `cwdtext`. It does not change one that is already within them.

**End to end, `internal/e2e`:**

- **This machine, no ssh** (§2.2). This test needs no sshd, so it always
  runs on Linux. It runs the real binary with `localhost`, and with the
  test's own `HOME`,
  `XDG_RUNTIME_DIR` and `SHELL`.
  - A session starts and predicts (`-predict always`).
  - On SIGHUP it detaches, with a hint that names `localhost`.
  - `-list` shows it as detached. `-s NAME` attaches it again, with its
    shell's state.
  - `-dir` of no directory starts nothing. Then it starts there.
  - `-kill` ends a session.
  - A throwaway agent is the shell's agent, unless `-a`.
  - With the throwaway sshd as well, `-list` over ssh shows a session that
    started locally, and `-s NAME HOST` takes it over.
  - A command, `mosey localhost sh -c 'echo ran-$((6*7)); exit 3'`, shows
    its output. The client exits when the command does, with status 0
    (§9.2.3).
  - `-s NAME localhost CMD`, with NAME running, says that it did not run
    the command, and attaches.
  - Return to a command
    (`TestALocalCommandIsReturnedToAfterADetachAndNeverMixedWithAShell`).
    `mosey localhost sh`, detached, shows in the list with its command.
    The same line, run again, returns to it with its shell's state intact,
    though a shell session detached after it. While that one is attached,
    a second `mosey localhost sh` gets a new session. A plain
    `mosey localhost` never takes the detached command session.
    `mosey localhost sh` never takes the detached shell; a plain
    `mosey localhost` then takes it.
  - The unit tests of `choose` (`internal/server`) cover the same rule.
    They also check that the server adds `existing` only when the `cmd` of
    the taken session is different.

- **Fake ssh, always runs.** `SSH.Program` is a test helper binary. It
  takes ssh's argv, checks that it has the §4.1 shape, and runs the remote
  command locally with `sh -c`, with
  `SSH_CONNECTION="127.0.0.1 1 127.0.0.1 22"`. The test builds the real
  `mosey` and checks these:
  - The line exchange.
  - A server of another version (a second build with another
    `-X main.version`) serves the client all the same (D8 V1).
  - The client refuses a server of another protocol (a stand-in that
    answers `MOSEY-ERROR 3 !code=version`) with §6.4's line.
  - `-remote` to a missing file (exit 127).
  - A server that prints rc noise before the line.
  - The fake ssh exits when the line is out, and the session continues
    (detach, §4.4 step 5). The test asserts "exits", with its own
    timeout, and never a measured duration (D18).
- **Abandoned session** (§4.5). The fake ssh delivers the line, and the
  client never dials. The test finds the session's pids from the
  spawner's log. The spawner, proto, emu and shell MUST all be gone, and
  the pty hung up, after CredentialTTL plus the grace periods of the
  teardown. Where the server allows it, the test controls the server's
  clock. Otherwise it asserts "gone" within its own timeout, never as a
  measured duration (D18).
- **Non-loopback address.** This needs a non-loopback, non-link-local
  address on the test host. If there is none, the test skips cleanly.
  - With `SSH_CONNECTION` naming that address, the client dials it.
  - With a loopback `SSH_CONNECTION`, and the fake `ssh -G` printing that
    address as `hostname`, the client falls back to it and still connects.
    This needs the wildcard bind of §4.4.
- **Real sshd, skipped cleanly if absent.** This uses a throwaway
  unprivileged sshd on 127.0.0.1, with throwaway host and user keys, its
  own `known_hosts`, a throwaway agent, and an `ssh_config` given with
  `-F`, as `spikes/s3-agent-bind/harness` does. It never uses the system
  sshd, `~/.ssh`, the user's agent, or a live service. It runs the real
  binaries over loopback UDP to an interactive shell and back.
- **Sessions through real sshd** (§9), same harness
  (`TestSessionsThroughRealSSH`). sshd's `SetEnv XDG_RUNTIME_DIR=` is a
  throwaway directory, so the attach sockets are under the test.
  1. A first plain client starts a session and sets a shell variable.
  2. A second plain client, while the first is still attached, gets a new
     session of its own.
  3. The first client gets SIGHUP. It detaches and says its name.
  4. A third plain client resumes that session (the variable is still
     set).
  5. `-s NAME` takes it over, and the third client exits 3.
  6. `-new` starts a third session.
  7. `-list` shows every name and state.
  8. `-kill NAME` ends one session, and its client exits 0.
  9. `exit` in the last session ends it. After that, nothing of it runs.
- **The implicit directory** (§9.2.4). `parseArgs` gets the origin, so
  the rules are table tests (`cmd/mosey`):
  - With no `-dir`, a local session gets the working directory.
  - `MOSEY_FROM` names the host and directory only for a session leader
    with no DESTINATION, `-dir`, `-list` or `-kill`. It does so only for
    another host.
  - `FuzzParseFrom` holds that an accepted host is a hostname, and an
    accepted directory is an absolute `ValidDir`. The URI, made again,
    parses the same.

  End to end:
  - A local client started in `~/proj/sub` gets a shell there. One given
    `-dir other` gets `~/other`
    (`TestANewLocalSessionStartsInTheClientsDirectory`).
  - Through the real sshd, Console's command with `MOSEY_FROM` gets a
    shell in that directory on that host. `MOSEY_FROM` is not in the
    shell's environment. A directory that is gone gives a shell in home,
    through the retry
    (`TestMoseyFromOpensANewSessionOnTheTabsHostInItsDirectory`).
- **Start options through real sshd** (§9.2.3), same harness
  (`TestDirAndTypeStartASessionAndAreIgnoredOnResume`):
  - `-s work -dir sub -type 'echo hi'` creates session `work`. Its shell
    is in `$HOME/sub`, and its screen shows `hi` as a line of output.
  - After it detaches, `-s work -dir other -type …` resumes it, still in
    `$HOME/sub`. (`other` does not exist, and nothing is typed.)
  - The client refuses `-new -dir missing` with §6.4's `dir` message,
    exit 1, and starts no session.
  - With bash as the login shell
    (`TestTypedTextShowsOnceAfterTheFirstPrompt`, skipped without bash),
    `-type 'echo typed-once'` shows the typed line one time, immediately
    after the first prompt, then its output.
- **Reconnect, R3** (§9.2.2). These run on netsim in virtual time
  (`TestAClientWhosePathDiesReconnectsByItselfAndKeepsItsScreen`,
  `TestAReconnectThatFindsTheSessionGoneOrTakenEndsTheClient`). Also the
  server's silence rule
  (`TestASilentClientCountsAsDetachedUntilItIsHeardAgain`). Also the
  tries, backoff and swap of the client loop, under synctest with fakes
  (`internal/client`, `reconnect_test.go`).
- **The idle timeout and `-kill`** (§9.3, §9.5). These use an injected
  short `IdleTimeout`, on the spawner with a stub proto
  (`TestADetachedSessionIsHungUpAfterTheIdleTimeoutAndAnAttachStopsTheClock`,
  `TestKillHangsTheShellUp`, `internal/server`).
- **Auto-upload through the real sshd** (§4.7). The remote's `HOME` is a
  temporary directory and its `PATH` is the test's own (the throwaway
  sshd's `SetEnv HOME= PATH=`). There is no `-remote`.
  - On a host with no mosey, the client asks and gets `y`. It copies
    itself and ends with a working session. `~/.local/bin/mosey` is
    byte-for-byte the client's file. The session's shell finds `mosey` in
    `~/.local/bin` (§4.7.9).
  - A client of another version then uses that copy as it is, and copies
    nothing.
  - The client replaces a `~/.local/bin/mosey` of another protocol,
    whether or not `PATH` names `~/.local/bin`.
  - The client uses a `mosey` elsewhere on `PATH` of another version as
    it is. One of another protocol fails with §6.4's line, and the client
    copies nothing.
  - The client refuses a `~/.local/bin/mosey` that is a symlink, or a
    `~/.local/bin` that is one, and writes nothing through it.
- **NixOS VM** (`tests/install.nix`, CI's `vm-install`): a host with no
  mosey gets one by consent, and runs the session from
  `~/.local/bin/mosey`. A second run asks nothing.
- The netsim end-to-end test starts at `client.Session` and does not use
  ssh. This document's part of it: a `CredentialLine`, round-tripped
  through Marshal/Parse, gives the `handshake.Credential` it got.

---

## 13. Threats this part answers

| Threat | Answer |
|---|---|
| Someone records or leaks stdout (recorder, bastion) | B3: the line does not let anyone impersonate either side ([S1] `b3_stdout_leak`). The PSK only filters DoS |
| A hostile or compromised remote writes control sequences to stdout or stderr | The client parses stdout and never shows it. stderr and skipped lines go through the filter (§6.5), D9 |
| A hostile remote sends a very large or endless stdout | `MaxPreamble`, line maxima, and the client kills ssh 10 s after the line |
| The stdin line attacks the unsandboxed spawner | One grammar, `MaxClientLine` read bound, at most `MaxFields` fields, 30 s deadline, fuzzed, canonical. The spawner drops an unknown field before anything acts on the line. An unknown field marked critical makes it refuse the line |
| An older peer silently ignores a field that restricts or instructs (`versioning.md` §3) | Every such field is critical (`!`). A peer that does not know the field refuses the line, and does not act without it. Each line's table says which fields are critical and why (§6.2–§6.4, §4.7.2, §9.2.1, §9.4) |
| A hostile remote injects a session-bind after ssh's | §8's state machine: anything after ssh's own bind means no bind ([S3] E11) |
| A live ControlMaster carries the bootstrap | Always a fresh connection ([S3] E12, E12b) |
| The user's config undoes a bootstrap option | Our options come first. The client filters flags that beat `-o` (§2.1, §4.1) |
| Version skew between client and server | Normal (D8 V1). Nothing compares software versions. The lines' number and the handshake's protocol name only their envelopes (`versioning.md` §5). Each is checked for equality. The handshake checks its protocol inside the authenticated handshake (`transport.md` §3.6), so no one on the path can make two builds disagree about it. A session runs the binary that started it until it ends (§9.2 step 5, `server.md` §2.8) |
| A stolen client keeps the session | Exclusive attach on each new confirmed login (§9.1, D26). Its background reconnect never takes back a session that another credential holds (§9.2.2) |
| A hostile server prints escape sequences in `-list`'s names | The client parses each list line against a grammar of printable ASCII, and makes the table layout itself (§9.4, fuzzed) |
| A hostile server sends a name that is not an `sname` | The CredentialLine refuses it (§6.3), so the client never prints one |
| A hostile remote steers the client's UDP at a broadcast, multicast or local address | The grammar refuses unspecified, multicast and limited broadcast. §7.2 refuses local directed broadcast, and loopback for a non-loopback destination (threat-model §4.9) |
| A compromised proto chooses where the client sends UDP | The spawner checks `addr`, `port` and `name` against its own (§4.4 step 3) |
| Failed bootstraps pile up detached shells | A session with no confirmed credential ends after CredentialTTL (§4.5) |
| Late remote bytes corrupt the session screen | ssh's stderr after the line goes, filtered, only to the log file (§7.4) |
| A planted symlink or another user's file redirects the install of the auto-upload (D7) | The installer works through `O_NOFOLLOW` descriptors below `~/.local`. It checks owner and mode at every level. It never replaces what is not the user's (§4.7.7) |
| The installer installs a corrupt, cut-short or substituted binary (D7) | Before the rename, the installer checks the length and SHA-256 that the client computed or read from `SHA256SUMS` (§4.7.4, §4.7.7) |
| A compromised GitHub release, CDN or account serves another binary with a matching `SHA256SUMS` (D7) | **The client does not cover this** (§14 question C, parked). The release job attests every binary (§4.6), so a person can find it with `gh attestation verify`. The client checks only `SHA256SUMS` |
| A hostile remote lies about its platform | It chooses which public build it gets, and nothing more (§4.7.2) |

---

## 14. Open in this document

A. **An upgraded client and an old session.** *Closed by D8 V1* (§9.2
   step 5). A launcher of any version attaches a session of any version
   with its attach protocol. The session continues to run its own binary.
   An upgrade has an effect on new sessions only.

B. **The spawner's confirmation backstop** (§4.5). The `Attached`
   message and the CredentialTTL + 10 s rule are a requirement that this
   document puts on `server.md`. `server.md` does not yet include it.

C. **Signed releases** (§4.6). *Parked (Dan, 2026-11-15; D7 as amended,
   PLAN O16).* CI attests every binary with
   `actions/attest-build-provenance` (GitHub OIDC and Sigstore, no
   long-lived key). GitHub keeps the attestations, so a person can check
   a download with `gh attestation verify FILE --repo
   danielbodart/mosey`. For a time, the client checked them with
   sigstore-go. That doubled the binary (9.9 to 21 MB) and added about
   65 modules, so we removed it. The client checks only `SHA256SUMS`
   (§4.7.4). Revisit this with a small verifier, and no large dependency.

D. **A local cache of downloaded releases** (§4.7.4). Each host of a
   foreign platform downloads the release again. A cache under
   `$XDG_CACHE_HOME/mosey/` prevents that. The cost is one more file that
   the client must verify again before it trusts it.

E. **Old versions of the installed copy.** *Closed by D7 as amended
   2026-11-15.* There is one file, `~/.local/bin/mosey`. The client
   replaces it only when it speaks another protocol, so old copies do not
   pile up.

D. **Telling a client taken over long ago** (§9.1). *Answered by the
   sessions slice.* R3's reconnect gets `taken` from the launcher and
   says so (§9.2.2), without the address.

F. **A background reconnect that finds its session held by another
   client** (PLAN O15, §9.2.2). For Dan: today it exits as taken over. The
   other option: it takes the session back, as `-s` does.

G. **Hopping through a login profile that sets `PATH`** (§4.7.9).
   *Closed by Dan, 2026-11-16.* mosey installs to `~/.local/bin/mosey`.
   The stock login profiles put that on `PATH` (Debian and Ubuntu
   `~/.profile`, Fedora `~/.bashrc`). So hopping works there, and no rc
   file needs an edit. NixOS needs mosey from Nix.

---

## 15. Review notes

These are the answers to the review of 2026-11-14. **Elsewhere** lists
the changes to other files that these answers need. This revision edits
only this file.

1. **Orphaned sessions (major). Fixed.** New §4.5 gives the requirement.
   A `new` session with no confirmed credential ends after CredentialTTL.
   Proto's `Exit{NoClient}` and the spawner's teardown end it: hang-up,
   then SIGKILL of shell, proto and emu. `server.md` §2.4 already
   specifies this. §4.5 adds a spawner-side backstop as a requirement on
   server.md (question B). §4.3 now says that the client relies on this
   after a Ctrl-C. In §4.4, a failed stdout write sends SIGTERM to the
   spawner. §12 adds the abandoned-session e2e test.
   *Rebutted in part:* the proposal to defer the shell to the first
   confirmation. The shell's rc files do not run "for a client that never
   proved it holds sk_C". They run for the SSH login, which already ran
   them one time to start the launcher, and that login is the user. An
   early shell start overlaps its start-up with the handshake. To defer
   it gives nothing that B3 needs.
2. **Unspecified, multicast and broadcast addresses (major). Fixed.**
   §6.3's grammar refuses unspecified, multicast and `255.255.255.255`
   (`ErrBadLine`, fuzzed). §7.2's table refuses the client's own directed
   broadcasts. It applies every rule to the results of `hostname` too.
   §12 has the unit, fuzz (`FuzzChooseAddr`) and e2e cases.
3. **Who writes `addr`, `port`, `swver` (major). Fixed, by a different
   route.** Proto still sends the whole line in `Credential` (0x30),
   because `server.md` §3.3 fixes the layout. But the spawner now checks
   all three against its own state, not only that the line parses (§4.4
   step 3). `server.md` §3.4 already checks `addr` and `port`; `swver` is
   new. The effect is what the reviewer asked for. Proto chooses only the
   four fields that only it knows. A line whose routing fields are
   different from the spawner's never gets to stdout. The spawner can
   also rebuild the line from four fields. A check is the smaller change
   to a layout that is already specified and fuzzed. *Elsewhere:*
   `server.md` §3.4 adds the `swver` check.
4. **Resume and exact versions (major). Fixed, with an open question.**
   §6.4 "Whose version" and §9.2 step 6: a resume is checked against the
   session's version. The spawner reports this first on `attach.sock`,
   whose first message is frozen across versions. A `version` refusal on
   a resume does not start an upload. What an upgraded client does is
   §14 question A, for the resume slice. *Superseded by D8 V1:* nothing
   compares software versions now. A launcher attaches a session of any
   version as it is (§6.4, §9.2 step 5).
5. **Loopback `addr` and the threat-model requirement (major). Fixed.**
   §7.2: the client skips a loopback `addr`, unless the destination
   itself resolves only to loopback. The client then falls back to
   `hostname`. That fallback must get to the server. So §4.4 adds a
   requirement on `server.md` §2.2: bind the wildcard for a loopback
   `SSH_CONNECTION`, as for link-local. §12 adds unit cases and a
   non-loopback e2e case. The plain fake-ssh test keeps its loopback
   `SSH_CONNECTION`. This is now correct, because its `hostname` is
   loopback too.
   *Elsewhere:* `server.md` §2.2.
6. **ErrorLine grammar (major). Fixed.** §6.4 freezes the shape:
   - `eproto` is 1 to 5 digits.
   - `code` is any lower-case word of 1 to 16 letters.
   - `MaxErrorLine` = 128 is part of the frozen grammar (the longest line
     is 100 bytes).

   Unknown codes parse and map to `internal`. §6.1 says that the
   ErrorLine parser accepts any `proto`.
7. **Launcher and spawner vs architecture.md (major). Fixed here;
   architecture.md is elsewhere.** The header names the roles. Each step
   of §4.4 says which role does it, and cites `server.md` §2.1 and the
   messages 0x40, 0x41, 0x42 and T1–T3. *Elsewhere:* architecture.md §1
   and §2 must name the launcher (`mosey --serve`) and the spawner
   (`mosey --serve=spawner`). They must remove "the spawner detaches with
   setsid". `server.md` §11 item 1 already lists this. It lands in one
   commit with the new role of `cmd/mosey/server.go`.
8. **The Go interface (major). Fixed here; stubs and architecture.md are
   elsewhere.** New §10.1 gives every exported type, signature and error.
   These include `ErrorLine`, `Config`, `SSH.Resolve`,
   `Command(ctx, Config)`, `*RemoteError`, `*NoLineError{Tail, Overflow}`,
   `*VersionError`, `ErrBadAddr`, `Sanitize` and `ChooseAddr`.
   *Elsewhere:* the stubs in `internal/bootstrap/` and architecture.md §5
   change in the same commit, as architecture.md's own rule says. This
   revision changed only this file.
9. **Where the client logs (major). Fixed.** New §7.4:
   - The log is a file under `$XDG_STATE_HOME/mosey/`. If there is no
     such directory, the client discards the log. It never logs to
     stderr.
   - ssh's stderr after the line goes through the §6.5 filter, and goes
     only to the log.
   - The proxy note of §7.2 is a message that the client prints before
     raw mode.

   *Elsewhere:* the `os.Stderr` handler of `cmd/mosey/main.go` changes
   when the bootstrap lands.
10. **Exit 127 under csh and nu (major). Fixed, and checked.** Confirmed
    [shells]: tcsh 6.24.16 and nushell 0.112.2 exit 1 for a missing
    command. tcsh also exits 1 for a non-executable file. fish 4.7.1
    exits 127. §4.1 now runs the server through `exec /bin/sh -c 'exec SERVER
    --serve'`. Under this, all of them exit 127 (and 126). We checked this
    under bash, tcsh, fish, nushell and zsh, and `~/` still expands.
    §4.1's charset already needs no quoting inside the single quotes. §12
    tests each installed shell.
11. **How to identify a mosey session by its processes, and the
    `mosey-server` comm (major).** §8 says that under D7 no process has
    the name `mosey-server`. The spawner's argv (`--serve=spawner`) marks
    a session as built. The review suggests to set the comm to
    `mosey-server` with `PR_SET_NAME`. We do not do this: D7 as settled
    says that no process has that name. Since D28's amendment
    (2026-11-15), this describes only the current process shape. It does
    not promise any tool that the shape stays the same.
