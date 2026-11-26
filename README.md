<p align="center"><img src="logo.png" alt="mosey" width="600"></p>

# mosey

<!-- This file is in Simplified Technical English (ASD-STE100): short
sentences, active voice, one meaning for each word (Dan, 2026-11-18). -->

mosey is a remote terminal for bad networks. It is also a simple
replacement for tmux. It moves between networks and it stays usable on
links that lose packets. Your sessions continue to run until you return
to them, from this computer or from a different one.

> To *mosey* is to walk slowly and easily.

**Status: in daily use.** The design is complete ([PLAN.md](PLAN.md)).
The specifications are in [docs/spec/](docs/spec). Each commit that
passes all tests is a release (refer to [Installing](#installing)).

## Quick start

mosey does two jobs with one command:

- The job of Mosh: a terminal on a different computer that continues to
  operate on a bad network.
- The simple half of the job of tmux: sessions that continue to run when
  you close the window. You return to a session by its name.

The two jobs use the same sessions. Thus you can start a session at your
desk and continue it on your laptop. You must install mosey on your
computer (refer to [Installing](#installing)). If a host does not have
mosey, mosey copies itself to that host.

**Like Mosh: a remote shell that does not stop.**

```sh
mosey dan-desktop              # Log in with your ssh. Return to your last detached shell there, or start a new one.
mosey dan-desktop claude       # Run claude, not a shell. mosey stops when claude stops. Run it again to return to a detached claude.
```

You can change the wifi, close the laptop or go through a tunnel. The
worst result is that the screen stops for some time. It continues when
the network returns. Your typing shows immediately, also on a slow link.
If mosey gets no data from the host for 15 s, it logs in again in the
background.

**Like tmux: named sessions that continue after you close the window.**

```sh
mosey -s work                  # Attach to the session "work" on this computer. If it does not exist, make it. mosey does not use ssh.
mosey -list                    # Show the sessions on this computer.
mosey -kill work               # Stop the session "work".
```

To detach, close the terminal window. There is no detach key. To return,
run `mosey -s work` again. The lines that moved off the screen go into
the scrollback of your terminal. Thus the mouse wheel and search operate
as usual. To stop the session, type `exit` in its shell.

**The two jobs together: one session, all your devices.**

```sh
mosey -s work                                     # At the desk.
mosey -s work dan-desktop                         # Later, on the laptop: take "work" from the desk.
mosey -s ai -dir Projects/x dan-desktop claude    # Run claude in ~/Projects/x. The first time, mosey starts it. After that, mosey returns to it.
```

`-s NAME` attaches to the session NAME, or makes it if it does not
exist. If a different client is attached to NAME, mosey disconnects that
client. `mosey HOST` without `-s` never takes a session that is attached
to a different client. Thus a second terminal gets its own session. Your
ssh-agent goes to the client that is attached.

mosey does not have panes, windows or a status bar. For these, use the
tabs and splits of your terminal. mosey has one session in each window.
The server operates only on Linux.

For all the commands, refer to [Using it](#using-it).

## What it is

You use `ssh` to log in to a computer from a laptop. Then the wifi stops,
you go through a tunnel, the laptop sleeps, or you change from your home
wifi to your phone. The session stops or it closes. In 2012,
[Mosh](https://mosh.org) solved much of this problem:

- It uses UDP. Thus it continues to operate when the network changes.
- It sends the *screen*, not a stream of bytes.
- It shows your typing immediately on your computer. Thus it feels fast
  also on a slow link.

But the last release of Mosh was in 2022. Its cryptography is from 2012.
It has no scrollback. You cannot return to a session from a different
device without tmux.

mosey uses the ideas of Mosh. It is new code in Go. We wrote it from the
Mosh paper and from public specifications. Like Mosh, it starts with
your usual `ssh`, your configuration, your keys and your agent. These
are its goals:

- **You can return to a session.** You can attach again after a network
  problem, after a reboot or from a different device. When you attach,
  mosey disconnects the old client. Thus a stolen laptop loses access.
- **Modern security.**
  - The handshake is post-quantum and hybrid (X-Wing: ML-KEM-768 and
    X25519). It has forward secrecy, new keys at intervals and roaming
    that an attacker cannot replay.
  - A copy of an SSH log line does not give an attacker your session.
  - ProVerif checks the designs.
  - When you type, the two ends send a packet each 20 ms, with cover
    packets between your keys. Each packet is 64 bytes or more. Thus a
    person who monitors the network cannot see when you push each key,
    or the size of most keys. OpenSSH's `ObscureKeystrokeTiming` does the
    same for SSH.
  - It cannot hide when a series of keys starts or stops. It cannot
    hide keys that collect while the network is stopped.
- **The terminal is isolated.** The terminal emulator operates on the
  server, in its own Landlock and seccomp sandbox. It sends structured
  screen changes to your computer. Your terminal never reads escape
  sequences from the remote host. Thus a full class of terminal attacks
  cannot occur.
- **Fast where it is important.**
  - It uses the timing of Mosh for the screen state.
  - We tuned retransmission and outage probes on a network simulator.
    The simulator replays recorded traces from cellular networks, trains
    and hotel wifi.
  - Its local echo operates with modern shells (zsh autosuggestions,
    syntax highlighting, fish). In replays of recorded sessions at a
    100 ms round trip, approximately 72% of keys show immediately. 0.1%
    are incorrect. It never showed a key of a password.
- **Scrollback in your terminal, without tmux.**
  - Lines that move off the remote screen go into the scrollback of your
    terminal. The mouse wheel, search and selection operate as usual.
    There is no scroll mode.
  - When you attach or return, mosey first shows one screen of the lines
    above the screen.
  - Full-screen programs (vim, less) use the alternate screen of your
    terminal. They keep no history, as on a local computer.
  - When your client is connected, a large output (for example `cat` of
    a big file) waits for the client, as with ssh. Thus all the lines
    arrive. mosey keeps only some hundred lines in its queue, thus
    Ctrl-C stops the program quickly.
  - When you are detached, or your client sent no data for 15 s, the
    program continues. The server keeps the newest 1000 lines. If more
    lines moved off the screen, the client shows one line
    `… N lines not shown`.
- **No installation on the host.** If the host does not have mosey,
  `mosey host` copies its own static binary to the host. One binary is
  the client and the server. Thus you can go to a different host from
  there.
- **Agent forwarding for constrained agents.** mosey replays the
  `session-bind` that OpenSSH made. Thus destination-constrained keys
  (`ssh-add -h`) operate as they do with `ssh -A`.
- **A release for each commit.** Each commit on trunk that passes all
  tests is a release, for linux and darwin on amd64 and arm64, and for
  android on arm64.

mosey is clean-room: it contains no Mosh code. The rules are in
[PLAN.md](PLAN.md#4-clean-room-rules-d3).

## Installing

Each commit on `trunk` that passes all tests and changes the code, the
Go toolchain or the build is a
[GitHub Release](https://github.com/danielbodart/mosey/releases). The tag
is `v<version>`. The release has one static binary for each platform and
their checksums. Each binary also has a GitHub build attestation:

```sh
V=0.123.456   # The version of a release, without the v.
curl -fLO "https://github.com/danielbodart/mosey/releases/download/v$V/mosey-$V-linux-amd64"
curl -fLO "https://github.com/danielbodart/mosey/releases/download/v$V/SHA256SUMS"
sha256sum --ignore-missing -c SHA256SUMS
gh attestation verify "mosey-$V-linux-amd64" --repo danielbodart/mosey
install -m 0755 "mosey-$V-linux-amd64" ~/.local/bin/mosey
```

- `sha256sum -c` shows that the file is the file in the `SHA256SUMS` of
  the release.
- `gh attestation verify` shows that the release workflow of mosey on
  GitHub Actions built the file. CI attests each binary through GitHub
  and Sigstore. There is no signing key that can leak. GitHub keeps the
  attestations.
- When mosey downloads a release, it checks only `SHA256SUMS` (refer to
  [Zero install](#zero-install)). You check the attestation manually.

The platforms are `linux-amd64`, `linux-arm64`, `darwin-amd64`,
`darwin-arm64` and `android-arm64`. Use `android-arm64` on a phone, in a
terminal app such as Termux, with its `openssh` package. The names do not change
([docs/spec/bootstrap.md §4.6](docs/spec/bootstrap.md)). mosey downloads
these files itself when it copies itself to a host of a different
platform.

With Nix, use a release tag:

- `nix run github:danielbodart/mosey/v<V> -- HOST`, or
- `inputs.mosey.url = "github:danielbodart/mosey/v<V>"` and the package
  `packages.<system>.mosey` of the flake.

The package is the binary of that release. Nix gets it with the hash in
`nix/release.json` of the tag. Nix does not build it from source. Thus it
is the file that `SHA256SUMS` and the attestation identify. Trunk has no
package, because trunk has no release. Always use a tag. The package
installs the shell completions below for bash, zsh and fish.

On NixOS, use the NixOS module of the flake:

```nix
imports = [ inputs.mosey.nixosModules.default ];
programs.mosey.enable = true;
```

- `programs.mosey.enable` installs mosey and opens UDP 60000-61000 in the
  firewall, as `programs.mosh.enable` does. It changes nothing else.
- `programs.mosey.openFirewall = false;` keeps the ports closed.
- `programs.mosey.gnome.searchProvider.enable = true;` shows your
  sessions in GNOME Shell search. It is off by default. Refer to
  [gnome-search-provider/README.md](gnome-search-provider/README.md).

### Shell completion

`mosey -completion bash|zsh|fish` writes a completion script for that
shell. Then:

- `mosey d<TAB>` shows the hosts that `ssh d<TAB>` shows, and
  `localhost`. These are the `Host` entries of your ssh configuration,
  known hosts and `user@host`.
- The flags and their values complete.
- `-s` and `-kill` complete with your sessions on this computer. They
  never complete with the sessions of a different host, because TAB
  does not run ssh.
- The words after the host complete as a command.

```sh
source <(mosey -completion bash)          # In ~/.bashrc.
source <(mosey -completion zsh)           # In ~/.zshrc, after compinit.
mosey -completion fish | source           # In ~/.config/fish/config.fish.
```

The hosts come from the ssh completion of the shell:

- bash: the known-hosts function of bash-completion. Without
  bash-completion, the `Host` lines of `~/.ssh/config` and of the files
  that it includes.
- zsh: `_ssh`.
- fish: the host list of fish.

## Using it

If the host has no mosey, mosey copies itself to the host the first time
(refer to [Zero install](#zero-install)). Then:

```sh
mosey host                 # Return to your last detached shell session on host, or start a new one.
mosey -s NAME host         # Attach to the session NAME and take it. If it does not exist, make it.
mosey -new host            # Start a new session with a generated name.
mosey -list host           # Show your sessions on host: name, attached or detached, since when, and the command.
mosey -kill NAME host      # Stop the session NAME. Its shell gets SIGHUP.
mosey -s work -dir src/app -type 'claude' host
                           # Make the session work in ~/src/app and run claude in it. Later, return to it.
mosey host claude          # Return to your detached claude on host, or start a new one. mosey stops when claude stops.
mosey -s work -- -p 2222 host claude
                           # Put the ssh options after --, before the host.
```

### A command after the host

A command after the host runs in place of your shell, as with `ssh host
command`:

- mosey joins the words with spaces. Your shell runs them with `-c`.
  Thus `mosey host ls -la` gives `-la` to `ls`, and your shell does the
  quoting.
- When the command stops, the session stops and mosey stops. The exit
  status of mosey is 0. mosey does not give the exit status of the
  command.
- If you close the window, the command continues, detached.
  `mosey host COMMAND` returns to your last detached session that started
  with exactly that command. If there is no such session, it starts a new
  one. It never takes a session that is attached. Thus a second window
  gets a second session.
- `mosey host` does the same for shells. It returns only to a detached
  shell, never to a detached program.
- `-dir` sets the directory of a new session. mosey does not use it to
  find a session. To keep two sessions of one program separate, give
  them names with `-s`.
- `mosey -s NAME host COMMAND` starts NAME with the command. If NAME
  exists, mosey takes it as it is. If NAME runs a different command,
  mosey tells you.
- `mosey -list host` shows the command of each session.
- You cannot use `-type` and a command together.

### This computer

With no host, mosey uses this computer, without ssh, as tmux does:

- `mosey`, `mosey -s work`, `mosey -new`, `mosey -list`, `mosey -kill
  NAME` and `mosey -s work -dir Projects/x -type claude` operate as
  above, on this computer.
- `localhost` after these commands has the same result.
- `mosey thishost` finds the same sessions through ssh. Thus you can
  start a session at your desk, take it on your laptop with `mosey -s
  work thishost`, and take it back at the desk with `mosey -s work`.
- The shell starts with your environment, as with tmux. It gets your
  agent (`SSH_AUTH_SOCK`), but not with `-a`.
- mosey refuses `-upload`, `-ssh` and ssh options here, because there is
  no ssh.
- A command needs a host before it: `mosey localhost htop`.
- `-close-if-idle` stops a local session when you close the terminal
  window, if the shell is at its prompt with no running or background
  jobs. If a command runs or a job is in the background, the session
  detaches as usual. mosey refuses `-close-if-idle` for remote hosts.
- Only the word `localhost` is this computer. `mosey 127.0.0.1` and
  `mosey me@localhost` log in through ssh, as for all other hosts.

Refer to [docs/spec/bootstrap.md §2.2](docs/spec/bootstrap.md).

### How a session starts

`-dir` and `-type` set how a new session starts:

- The shell starts in the directory of `-dir`. A relative directory is
  relative to your home directory on the host.
- On this computer, with no `-dir`, the shell starts in the directory
  where you started mosey, as with tmux. Thus a new terminal window
  opens in the directory of the window that you opened it from. If that
  directory does not exist, the shell starts in your home directory.
- mosey types the text of `-type` into the shell, then Enter. This is
  the same as `tmux new-session -c DIR` and `tmux send-keys TEXT Enter`.
- mosey types the text after the shell shows its prompt, or after 2
  seconds if the shell shows nothing. Thus the text shows one time, as
  if you typed it.
- These flags apply only when mosey makes the session. When mosey
  returns to a session, it ignores them. Thus the same command returns
  you to the session.
- When the program stops, you are at a shell in that directory, with
  your full `PATH`.

### Session names

`mosey host` without `-s` never takes a session that is attached to a
different client. Thus a second terminal to the same host gets its own
session. Each session has a name. If you do not give a name, mosey
generates one, for example `quiet-heron`. Only the host keeps the list
of sessions. Your computer keeps no record of them. Thus a different
device sees the same sessions.

### When a session stops

**A session stops only when its shell stops.** These actions stop the
session:

- `exit` or Ctrl-D in the **remote** shell, or a different action that
  stops that shell.
- `mosey -kill NAME host`.
- Closing the terminal of a local `mosey -close-if-idle` session when
  the shell is idle, with no running or background jobs.

**Events on your computer (the client) only detach the session.** These
events do not change the session. The session waits on the host:

- You close the terminal window.
- You log out of your laptop.
- Your laptop sleeps, reboots, crashes or loses its network.

**A host that shuts down or logs you out stops its sessions.** The
server gets SIGTERM and stops the session at once: the shell gets a
hangup, as at the end of an ssh login. A session that you start over ssh
stays alive after that ssh login stops. On a host with
`KillUserProcesses=yes` in `logind.conf`, it stays alive only if you
enable linger (`loginctl enable-linger`). mosey does not enable linger.

There is no detach key. To detach, close the terminal of the client. To
return, run `mosey host` again, from this computer or from a different
one. If a client stops without a message, the host thinks that it is
detached after 15 seconds with no data from it.

### When the network stops

The client waits through a network problem without help. If it gets no
data from the host for 15 seconds, it also logs in again through ssh in
the background:

- It does not ask you questions, because ssh runs in batch mode.
- It uses the new connection and keeps your screen as it was.
- It tries again, at intervals from 2 seconds to 1 minute. It stops when
  it gets the session again, or when it finds that the session stopped.
  Then it tells you the result.
- While it tries, the top line of the screen shows how long the host
  was silent and why the last try failed. Thus, if batch mode cannot log
  in to the host (for example, the host asks for a password or a second
  factor), you see the cause. The line goes away when data from the host
  arrives again.

If a session stays detached for 7 days, mosey stops it. Its shell gets
SIGHUP.

### When a different client takes a session

When you take a session with `-s`, mosey disconnects all other attached
clients and erases their keys:

- If that client is awake in the next minute, it stops. It tells you who
  took the session and when.
- If that client sleeps, it finds out when it tries to connect again. It
  stops and tells you that a different client took the session.
- It never takes the session back itself.

mosey never writes secrets to disk. Each return is a new SSH login and a
new handshake. Refer to [docs/spec/bootstrap.md §9](docs/spec/bootstrap.md).

### Versions

**The protocol is important, not the version.** As with ssh, a client
and a host with different versions of mosey operate together. mosey does
not compare versions. They share a protocol number. That number is the
promise of stability. If the mosey on the host uses a different protocol,
mosey tells you in one line and stops:

```
HOST's mosey speaks protocol 2; this mosey speaks 1
```

To upgrade the mosey on the host, use Nix or replace the binary. Sessions
that you start after the upgrade use the new binary. A session that runs
continues with the binary that started it.

### Agent forwarding

mosey forwards your ssh-agent in the same conditions as `ssh`:

- Your `~/.ssh/config` has `ForwardAgent yes` (or a socket path) for the
  host, or
- you use `-A`.
- `-a` stops forwarding.

All agents that use the protocol operate with mosey: the `ssh-agent` of
OpenSSH, gpg-agent, 1Password and agents that use a TPM.

On the host, `SSH_AUTH_SOCK` is the socket of mosey. Each connection to
it goes to your agent, as with `ssh -A`. First it sends the
`session-bind` that OpenSSH made for the login that mosey started. Thus
keys with destination constraints (`ssh-add -h`) operate for the hosts
that you permitted, and for no others.

If mosey cannot get that bind, it tells you one time and continues
without the agent. This occurs when:

- the host has `AllowAgentForwarding no`, or
- the host key is not in your `known_hosts`.

After you return to a session, the agent is the agent of the device that
returned.

mosey has no code for a specific agent. It forwards the agent as `ssh -A`
does. The extension messages of an agent go through without change.
Refer to [docs/spec/agent.md](docs/spec/agent.md).

### Predictive echo

On a slow link, mosey shows your typing before the server echoes it, as
Mosh does:

- If the screen of the server is different from a guess, mosey removes
  the guess.
- It guesses only some keys: letters, backspace, left and right.
- It hides each new series of guesses until the server confirms one.
- When the round trip is long, it underlines the guesses that the server
  did not confirm.
- At a password prompt, it guesses but shows nothing. The server sends
  nothing for each key.
- For this, the prompt must stop echo on the pty of mosey. Thus this
  protection does not apply in tmux, screen, or ssh or mosey in a
  session. There, only the cover packets hide when you type.

The `-predict` values:

- `adaptive` (the default): show guesses when the round trip is
  approximately 40 ms or more.
- `always`: always show guesses.
- `never`: never show guesses.

Refer to [docs/spec/prediction.md](docs/spec/prediction.md).

## Zero install

The server is the same `mosey` binary. For each connection, `mosey HOST`
uses the mosey that the host has, of all versions. It looks for:

1. `mosey` on the `PATH`, then
2. `~/.local/bin/mosey`.

It looks in the same ssh login that starts the session. If it finds no
mosey, or `~/.local/bin/mosey` uses a different protocol, it asks one
time for each host:

```
mosey: HOST has no mosey this one can use. Copy this one (linux/amd64, 9.8 MB) to ~/.local/bin/ there? [y/N]
```

Then it copies its own file through ssh:

- If the host is a different platform (for example, a Mac client and a
  Linux server), mosey downloads the release of its own version for
  that platform from GitHub.
- It checks that file against the `SHA256SUMS` of the release before it
  sends it. If the file is not correct, mosey refuses it.
- mosey does not check the build attestation. You can check it manually
  with `gh attestation verify` (refer to [Installing](#installing)).

On the host, the copy installs itself:

- It checks its length and its SHA-256.
- It does not follow a symlink below `~/.local`.
- It does not replace a file that is not yours.
- It renames itself into its location.

Then the session starts. In the session, `mosey otherhost` finds the same
copy. Thus you can go to a different host from there. `~/.local/bin` is
on the `PATH` where the login profile puts it there (Debian, Ubuntu,
Fedora). mosey does not change rc files. On NixOS, install mosey with Nix
to go to other hosts: the flake's NixOS module does this
(`programs.mosey.enable`, see below).

The client never upgrades the mosey on a host. It replaces only
`~/.local/bin/mosey`, and only if that file uses a different protocol.
It asks first. mosey uses a `mosey` in a different location on the
`PATH`, or a binary from `-remote`, as it is.

- `-upload=yes` copies without a question. `-upload=no` never copies.
- `-remote PATH` runs that binary on the host and copies nothing.
- A development build (`dev`, or a local build) can copy only itself.
  Thus it can copy only to a host of its own platform.
- At this time, the server operates only on Linux.

For the details and the threats that this does and does not stop, refer
to [docs/spec/bootstrap.md §4.7](docs/spec/bootstrap.md) and
[docs/threat-model.md §4.13](docs/threat-model.md).

## Building

With [mise](https://mise.jdx.dev):

```sh
mise run check    # gofmt, vet, tests, shellcheck, actionlint.
mise run build    # The static mosey binary for linux and darwin, amd64 and arm64, and android/arm64.
mise run race     # The tests with the race detector. This needs a C compiler.
```

If you have Nix but not mise, `nix develop` gives a shell with the tools.
The flake does not build mosey. Its package is the binary of a release
(refer to [Installing](#installing)).

To run the VM test of the installation on binaries that you built, make
them the release of the flake, as CI does:

1. `mise run build`.
2. `scripts/release-assets.sh V rel`. `V` is the version of the binaries.
3. `scripts/nix-local-release.sh V rel`.
4. `nix build .#checks.x86_64-linux.vm-install`.
5. Unstage `nix/release.json`.

CI does all of that for each push. It also runs:

- each fuzz target for 10 seconds, in four shards,
- the slow tests,
- 150-second soak tests of the server with its seccomp `KILL` policy on
  amd64 and arm64.

A release needs all jobs to pass. A newer push to trunk cancels the tests
of the older run. It never cancels a release that is in progress. The
newer run releases the commits of the older run with its own. Each night,
each fuzz target runs for 5 minutes on its own runner. If a fuzz target
finds a crash, CI keeps it as an artifact. Commit it as a regression seed.

## License

Apache-2.0. [DEPENDENCIES.md](DEPENDENCIES.md) lists the dependencies and
the reason for each one.
