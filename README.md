<p align="center"><img src="logo.png" alt="mosey" width="600"></p>

# mosey

A remote terminal for bad networks. It roams between networks, stays usable
on lossy links and picks up where it left off.

> To *mosey* is to wander along at an easy pace.

**Status: pre-alpha. Don't rely on it yet.** The design is settled
([PLAN.md](PLAN.md)) and the specs are written ([docs/spec/](docs/spec)).
The first slice works: `mosey HOST` bootstraps over your `ssh` and gives
you an interactive shell over encrypted UDP, with the emulator sandboxed on
the server, and copies itself to a host that doesn't have it (see
[Zero install](#zero-install)). Sessions survive the client: a later
`mosey HOST` picks a detached one up again, from here or another device,
every session has a name you can attach to with `-s`, and a client that
loses its server for a while logs in again by itself to get its session
back (see [Using it](#using-it)), and your ssh-agent comes along when your ssh config
forwards it (see [Agent forwarding](#agent-forwarding)). Client and host
need not run the same version, and a newer mosey takes a running session
over in place, so upgrading never costs a session. While you type,
both ends send cover traffic on a fixed tick, which hides the timing of
keys within a run of typing (see [What it is](#what-it-is)). On a slow
link your typing shows up at once, before the server echoes it (see
[Predictive echo](#predictive-echo)). Every green commit is already
released (see [Installing](#installing)).

## What it is

You `ssh` into a box from a laptop. Then the wifi drops, you go through a
tunnel, the laptop sleeps, or you hop from home wifi to your phone's
hotspot, and the session freezes or dies. [Mosh](https://mosh.org) fixed
much of this in 2012:

- it runs over UDP, so it survives a change of network;
- it syncs the *screen* rather than a byte stream;
- it echoes your typing locally, so it feels instant even on a slow link.

But Mosh's last release was in 2022, its crypto dates from 2012, and a
session can't be picked up again from another device without tmux.

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
platform. With Nix, `nix run github:danielbodart/mosey -- HOST`, or the
flake's `packages.<system>.mosey`.

## Using it

mosey copies itself over the first time if the host has none of its
version (see [Zero install](#zero-install)). Then:

```sh
mosey host                 # resume your most recently detached session on host, or start a new one
mosey -s NAME host         # attach to the session called NAME, taking it over; create it if missing
mosey -new host            # always start a fresh session, with a generated name
mosey -list host           # your sessions on host: name, attached or detached, since when, version
mosey -kill NAME host      # end the session called NAME (its shell gets SIGHUP)
```

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

**Upgrading mosey never costs you a session.** A client and a host of
different mosey versions work together: they agree on a protocol version
both speak, and nothing refuses another version. When a newer mosey
resumes a session that an older one started, it takes the session over
in place: the old server hands the newer one its terminal and screen and
exits, and your shell keeps running, the same process with everything in
it, now served by the new code, so a security fix reaches sessions that
were already running. Upgrades only go forward: an older client attaches
a newer session as it is. (Sessions started before this release can't
be handed over; they stay resumable by their own version until their
shell exits, and a plain `mosey HOST` that passes over one says so,
naming the session and the version that can resume or end it.)

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
looks on the host for
`~/.cache/mosey/<version>/mosey`, then `mosey` on its `PATH`, in the same
ssh login that starts the session. If neither is this version, it asks
once per host:

```
mosey: HOST has no mosey 0.123.456. Copy this one (linux/amd64, 9.8 MB) to ~/.cache/mosey/0.123.456/ there? [y/N]
```

and copies its own file over ssh. If the host is another platform (a Mac
client, a Linux server) it downloads its own version's release for that
platform from GitHub instead, and checks it against the release's
`SHA256SUMS` before sending it; it refuses a binary that does not match.
(It does not check the release's build attestation itself; that is for
`gh attestation verify`, by hand, as in [Installing](#installing).) On
the host the copy installs itself: it
checks its own length and SHA-256, refuses to follow a symlink below
`~/.cache` or to replace a file that isn't yours, and renames itself into
place. Then the session starts. Copying its own version over is how a
newer client brings its fixes to a host; a server of another version
would also work (see above), and `-remote` uses whatever it is given.

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

or with Nix: `nix build` for the package, `nix flake check` for the
package and the VM test of the install path, and `nix develop` for a shell
with the tools (the tests and the lint are `mise run check`'s).

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
