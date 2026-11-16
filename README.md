<p align="center"><img src="logo.png" alt="mosey" width="600"></p>

# mosey

A remote terminal for bad networks, and a simple stand-in for tmux. It
roams between networks, stays usable on lossy links, and keeps your
sessions running until you come back to them, from this machine or
another.

> To *mosey* is to wander along at an easy pace.

**Status: in daily use.** The design is settled ([PLAN.md](PLAN.md)) and
the specs are written ([docs/spec/](docs/spec)). Every green commit is
released (see [Installing](#installing)).

## Quick start

mosey is one command for two jobs: Mosh's (a terminal on another machine
that survives bad networks) and the simple half of tmux's (sessions that
keep running when you close the window, and that you pick up again by
name). The same sessions serve both, so you can start one at your desk
and carry on from your laptop. You need mosey on your machine (see
[Installing](#installing)); it copies itself to a host that lacks it.

**Like Mosh: a remote shell that doesn't die.**

```sh
mosey dan-desktop              # log in with your own ssh; resume your last detached session there, or start one
mosey dan-desktop claude       # run a program instead of a shell; mosey exits when it does
```

Change wifi, close the laptop lid, go through a tunnel: at worst the
screen freezes, and it carries on when the network comes back. Your typing
shows up at once even on a slow link. If the host has been silent for
15 s, mosey logs in again by itself in the background.

**Like tmux: named sessions that outlive the window.**

```sh
mosey -s work localhost        # attach to "work" on this machine, or create it; no ssh involved
mosey -list localhost          # what's running here
mosey -kill work localhost     # end it
```

Close the terminal window to detach; there is no detach key. Run `mosey
-s work localhost` again and you're back where you left off, with the
lines that scrolled past printed into your terminal's own scrollback, so
the mouse wheel and search just work. Typing `exit` in the shell ends the
session.

**Both at once: one session, any device.**

```sh
mosey -s work localhost                           # at the desk
mosey -s work dan-desktop                         # later, from the laptop: takes "work" over
mosey -s ai -dir Projects/x dan-desktop claude    # claude in ~/Projects/x: started the first time, returned to after
```

`-s NAME` is create-or-attach: the first time, it starts NAME; every time
after, it takes you back, cutting off any other client still attached.
Plain `mosey HOST` never takes a session that's attached elsewhere, so a
second terminal gets a session of its own. Your ssh-agent follows
whichever client is attached.

What it doesn't do: panes, windows or a status bar. Use your terminal's
own tabs and splits for those; mosey is one session per window. The
server side runs on Linux.

The full reference is [Using it](#using-it).

## What it is

You `ssh` into a box from a laptop. Then the wifi drops, you go through a
tunnel, the laptop sleeps, or you hop from home wifi to your phone's
hotspot, and the session freezes or dies. [Mosh](https://mosh.org) fixed
much of this in 2012:

- it runs over UDP, so it survives a change of network;
- it syncs the *screen* rather than a byte stream;
- it echoes your typing locally, so it feels instant even on a slow link.

But Mosh's last release was in 2022, its crypto dates from 2012, it has
no scrollback, and a session can't be picked up again from another
device without tmux.

mosey is inspired by Mosh, written from scratch in Go from the Mosh paper
and public specifications. It starts over your normal `ssh`, with your own
config, keys and agent, exactly as Mosh does. It aims to be:

- **Resumable.** Reattach after a dead spot, a reboot, or from another
  device. Attaching kicks off the old client, so a stolen laptop is cut off.
- **Secure by modern standards.** It uses a post-quantum hybrid handshake
  (X-Wing: ML-KEM-768 plus X25519), forward secrecy, rekeying, and
  replay-proof roaming. A leaked SSH log line doesn't hand anyone your
  session. The designs are checked with ProVerif. While you type, both
  ends send on a fixed 20 ms tick with cover traffic between your keys,
  every packet padded to at least 64 bytes, which hides the timing of
  keys within a run of typing, and most of their sizes, from someone
  watching the network, as OpenSSH's `ObscureKeystrokeTiming` does for
  SSH. It can't hide when a run starts or stops, or keys that pile up
  while the network stalls.
- **Isolated from the terminal.** The terminal emulator runs on the server,
  inside its own Landlock and seccomp sandbox, and sends your machine
  structured screen diffs. Your local terminal never parses escape
  sequences from the remote host, which shuts off a whole class of terminal
  exploits.
- **Fast where it counts.** It keeps Mosh's state-sync timing, with
  retransmission and outage probing tuned on a deterministic network
  simulator against replayed cellular, train and hotel-wifi traces. Its
  predictive local echo copes with modern shells (zsh autosuggestions,
  syntax highlighting, fish): replaying recorded sessions, about 72% of
  keystrokes appear instantly at a 100 ms round trip and 0.1% are wrong,
  and no password key was ever shown.
- **Scrollback in your own terminal, so no tmux needed for it.** Lines
  that scroll off the remote screen are printed into your terminal's own
  scrollback, so the mouse wheel, search and selection work as they do
  locally, with no scroll mode to learn. When you attach or resume, one
  screenful of the lines that scrolled off just above the screen comes
  first, as many as your terminal has rows; full-screen programs (vim,
  less) use your terminal's alternate screen and leave no history, as
  they would locally. While your client is connected, a flood such as
  `cat` of a big file waits for it, as under ssh, so every line arrives;
  only a few hundred lines are ever queued, so Ctrl-C still brings the
  prompt back promptly. While you are detached, or your client has been
  silent for 15 s, the program runs on and the server keeps the newest
  1000 lines; when more than that scrolled past, the client prints one
  `… N lines not shown` line for the gap and carries on.
- **Zero install.** `mosey host` copies its own static binary across when
  the host doesn't have it. One binary is both client and server, so you can
  hop onwards from there.
- **Agent forwarding that works with constrained agents.** It replays the
  `session-bind` that OpenSSH itself made, so destination-constrained keys
  (`ssh-add -h`) behave exactly as they do under `ssh -A`.
- **Released on every commit.** Trunk-based development: every green
  commit is a release, for linux and darwin on amd64 and arm64.

mosey is clean-room: it contains no Mosh code. The rules
are in [PLAN.md](PLAN.md#4-clean-room-rules-d3).

## Installing

Every green commit on `trunk` that changes the code, the Go toolchain or
the build is a
[GitHub Release](https://github.com/danielbodart/mosey/releases), tagged
`v<version>`, with one static binary per platform and their checksums.
Each binary also has a GitHub build attestation:

```sh
V=0.123.456   # a release's version, without the v
curl -fLO "https://github.com/danielbodart/mosey/releases/download/v$V/mosey-$V-linux-amd64"
curl -fLO "https://github.com/danielbodart/mosey/releases/download/v$V/SHA256SUMS"
sha256sum --ignore-missing -c SHA256SUMS
gh attestation verify "mosey-$V-linux-amd64" --repo danielbodart/mosey
install -m 0755 "mosey-$V-linux-amd64" ~/.local/bin/mosey
```

`sha256sum -c` shows the file is the one the release's `SHA256SUMS`
lists. `gh attestation verify` shows it was built by mosey's own release
workflow on GitHub Actions: CI attests every binary through GitHub and
Sigstore (no signing key to leak), and GitHub keeps the attestations.
mosey itself checks only `SHA256SUMS` when it downloads a release (see
[Zero install](#zero-install)); the attestation is for you to check by
hand.

The platforms are `linux-amd64`, `linux-arm64`, `darwin-amd64` and
`darwin-arm64`. The names are fixed
([docs/spec/bootstrap.md §4.6](docs/spec/bootstrap.md)), because mosey
fetches them itself to copy the right one onto a host of another
platform.

With Nix, pin a release tag: `nix run github:danielbodart/mosey/v<V> --
HOST`, or `inputs.mosey.url = "github:danielbodart/mosey/v<V>"` and the
flake's `packages.<system>.mosey`. The package is that release's own
binary, fetched by the hash in the tag's `nix/release.json`, not a build
from source, so it is the file `SHA256SUMS` and the attestation vouch for.
Trunk has no package (no release, no file): always pin a tag.

## Using it

mosey copies itself over the first time if the host has no mosey at all
(see [Zero install](#zero-install)). Then:

```sh
mosey host                 # resume your most recently detached session on host, or start a new one
mosey -s NAME host         # attach to the session called NAME, taking it over; create it if missing
mosey -new host            # always start a fresh session, with a generated name
mosey -list host           # your sessions on host: name, attached or detached, since when
mosey -kill NAME host      # end the session called NAME (its shell gets SIGHUP)
mosey -s work -dir src/app -type 'claude' host
                           # create session work in ~/src/app running claude; later, just go back to it
mosey host claude          # a new session running claude instead of a shell; it and mosey end when claude does
mosey -s work -- -p 2222 host claude
                           # ssh's own options go after --, before the host
```

**A command after the host** runs in place of your shell, as `ssh host
command` would: the words are joined with spaces and run by your shell's
`-c`, so `mosey host ls -la` passes `-la` to `ls`, and quoting is your
shell's. When the command exits, the session ends and mosey exits (with
status 0: the command's own status is not passed back). It only ever
starts a session: plain `mosey host COMMAND` always starts a new one, and
`mosey -s NAME host COMMAND` runs it only if NAME isn't running already;
if it is, mosey says so and takes NAME over as it is. The session is an
ordinary one while it runs: you can detach, list, take over and kill it.
`-dir` sets where it runs; `-type` and a command exclude each other.

**`localhost` is this machine**, with no ssh at all: `mosey localhost`,
`mosey -s work localhost`, `mosey -new localhost`, `mosey -list
localhost`, `mosey -kill NAME localhost` and `mosey -s work -dir
Projects/x -type claude localhost` work as above, on the machine you're
at, the way you'd use tmux. These are the very sessions `mosey thishost`
finds over ssh, so one you started at your desk can be taken from your
laptop with `mosey -s work thishost`, and taken back by `mosey -s work
localhost` at the desk. The shell starts with your environment, as under
tmux, and has your agent (`SSH_AUTH_SOCK`) unless you pass `-a`.
`-upload`, `-ssh` and ssh options are for ssh, and are refused here.
Only the word `localhost` means this: `mosey 127.0.0.1` or `mosey
me@localhost` logs in over ssh as to any other host. `mosey` on its own
just prints the usage.
([docs/spec/bootstrap.md §2.2](docs/spec/bootstrap.md))

`-dir` and `-type` say how a session starts: its shell starts in that
directory (relative to your home there), and the text is typed into it,
followed by Enter, as `tmux new-session -c DIR` and `tmux send-keys TEXT
Enter` would. The text is typed once the shell has printed its prompt
(or after 2 seconds if it prints nothing), so it shows once, as if you had
typed it. They only apply when the command creates the session; when
it resumes one they are ignored, so the same command takes you back.
When the program exits you are at a shell in that directory, with your
whole `PATH`.

Plain `mosey host` never takes over a session that is attached somewhere
else, so a second terminal to the same host gets a session of its own.
Every session has a name; one you didn't name gets a generated one, such
as `quiet-heron`. The list of sessions lives only on the host: your
machine keeps no record of them, so another device sees the same ones.

**A session ends only when its shell does.** Typing `exit` or Ctrl-D in
the **remote** shell, or anything else that ends that shell, ends the
session, and `mosey -kill NAME host` ends it from outside.

**Everything that happens on your own machine, the client, only
detaches.** Closing the terminal window, logging out of your laptop,
putting it to sleep, rebooting it, or it crashing or losing its network:
none of these touch the session, which waits on the host. There is no
detach key; closing the client's terminal is how you detach. The next
plain `mosey host`, from this machine or another, picks the session up
again (a client that vanished without a word counts as detached once the
host has heard nothing from it for 15 seconds).

While the client runs it rides out a dead spot by itself. If it hears
nothing from the host for 15 seconds, it also logs in again over ssh in
the background, without asking you anything (ssh runs in batch mode),
and swaps the new connection in with your screen as it was; it keeps
trying, from every 2 seconds up to once a minute, until it gets the
session back or finds it has ended, and then exits saying so. While it
tries, the top line of the screen says how long the host has been silent
and why the last try failed, so a host batch mode can't log in to (one
that wants a password or a second factor) shows you why rather than
leaving the screen frozen; the line goes once the host is heard again. A
session left detached for 7 days is ended (its shell gets SIGHUP).

Taking a session over with `-s` cuts off any client still attached and
wipes its keys. If that client is awake within a minute, it exits saying
who took over and when; one that was asleep finds out when it tries to
reconnect, and exits saying the session was taken over. It never takes
the session back by itself. Nothing secret is ever saved to disk: each
resume is a fresh SSH login and a fresh handshake
([docs/spec/bootstrap.md §9](docs/spec/bootstrap.md)).

**Versions don't matter; the protocol does.** As with ssh, a client and
a host of different mosey versions work together: nothing compares
versions. What they share is a protocol number, which is the stability
promise; if the host's mosey speaks another one, mosey says so in one
line (`HOST's mosey speaks protocol 2; this mosey speaks 1`) and stops.
Upgrade the host's mosey with Nix or by replacing the binary; sessions
you start after that use it, and one already running goes on with the
binary that started it.

### Agent forwarding

mosey forwards your ssh-agent exactly when `ssh` would: when your
`~/.ssh/config` says `ForwardAgent yes` (or a socket path) for the host,
or when you pass `-A`; `-a` turns it off. Any agent that speaks the
protocol works: OpenSSH's `ssh-agent`, gpg-agent, 1Password, a TPM-backed
agent. On the
host, `SSH_AUTH_SOCK` points at mosey's own socket, and every connection to
it reaches your agent as it would under `ssh -A`, starting with the
`session-bind` OpenSSH made for the login mosey started over, so keys you
added with destination constraints (`ssh-add -h`) work for exactly the
hops you allowed. If that bind can't be had (the host has
`AllowAgentForwarding no`, or its host key isn't in your `known_hosts`),
mosey says so once and carries on without the agent. After a resume the
agent is the resuming device's.

mosey has no code for any particular agent: it forwards the agent as
`ssh -A` does, and an agent's own extension messages pass through
untouched. Details: [docs/spec/agent.md](docs/spec/agent.md).

### Predictive echo

On a slow link mosey shows what you type before the server has echoed it,
as Mosh does, and takes back any guess the server's screen disagrees
with. It guesses only what it can (letters, backspace, left and right),
starts each run of guesses hidden until the server confirms one, and
underlines guesses not yet confirmed once the round trip is long enough
to notice. At a password prompt it guesses and keeps nothing, and the
server sends nothing per key; that needs the prompt to turn echo off on
mosey's own pty, so it does not hold inside tmux, screen, or a nested ssh
or mosey session, where only chaff hides your typing rhythm.
`-predict adaptive` (the default) shows guesses from a round trip of about
40 ms, `-predict always` always, `-predict never` never. Details:
[docs/spec/prediction.md](docs/spec/prediction.md).

## Zero install

The server is the same `mosey` binary. On each connection `mosey HOST`
uses whatever mosey the host has, of any version: `mosey` on its `PATH`,
or else `~/.local/bin/mosey`, found in the same ssh login that starts
the session. Only if there is neither, or `~/.local/bin/mosey` speaks
another protocol, does it ask, once per host:

```
mosey: HOST has no mosey this one can use. Copy this one (linux/amd64, 9.8 MB) to ~/.local/bin/ there? [y/N]
```

and copies its own file over ssh. If the host is another platform (a Mac
client, a Linux server) it downloads its own version's release for that
platform from GitHub instead, and checks it against the release's
`SHA256SUMS` before sending it; it refuses a binary that does not match.
(It does not check the release's build attestation itself; that is for
`gh attestation verify`, by hand, as in [Installing](#installing).) On
the host the copy installs itself: it
checks its own length and SHA-256, refuses to follow a symlink below
`~/.local` or to replace a file that isn't yours, and renames itself into
place. Then the session starts, and in it `mosey otherhost` finds that
same copy, so you can hop on: `~/.local/bin` is on `PATH` wherever the
login profile puts it there (Debian, Ubuntu, Fedora), with no rc file
edited. On NixOS, install mosey with Nix to hop on. The client never
upgrades a host's mosey: it replaces only `~/.local/bin/mosey`, and only
if that speaks another protocol (asking as before). A `mosey` elsewhere
on `PATH`, or one given with `-remote`, is used as it is.

- `-upload=yes` copies without asking; `-upload=no` never copies.
- `-remote PATH` runs that binary on the host instead, and copies nothing.
- A development build (`dev`, or a local build) can copy only itself, so
  only to a host of its own platform.
- The server runs on Linux for now.

The details, and what this does and doesn't protect against, are in
[docs/spec/bootstrap.md §4.7](docs/spec/bootstrap.md) and
[docs/threat-model.md §4.13](docs/threat-model.md).

## Building

With [mise](https://mise.jdx.dev):

```sh
mise run check    # gofmt, vet, tests, shellcheck, actionlint
mise run build    # the static mosey binary for linux and darwin, amd64 and arm64
mise run race     # the tests under the race detector (needs a C compiler)
```

and `nix develop` for a shell with the tools if you have Nix but not
mise. The flake does not build mosey: its package is a release's binary
(see [Installing](#installing)). To run the VM test of the install path on
binaries you built, make them the flake's release, as CI does:
`mise run build`, `scripts/release-assets.sh V rel` with `V` what they say
they are, `scripts/nix-local-release.sh V rel`, then
`nix build .#checks.x86_64-linux.vm-install` (and unstage
`nix/release.json` after).

CI runs all of that on every push, plus 10 seconds of every fuzz target
(in four shards), the slow tests, and 150-second soaks of the server
under its seccomp `KILL` policy on amd64 and arm64. A release needs every
job green. A newer push to trunk cancels the older run's testing, never a
release in progress, and releases its commits with its own. Every night,
each fuzz target runs for 5 minutes on a runner of its own, and a crash
is kept as an artifact to commit as a regression seed.

## License

Apache-2.0. [DEPENDENCIES.md](DEPENDENCIES.md) lists the dependencies and
why each one is there.
