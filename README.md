<p align="center"><img src="logo.png" alt="mosey" width="600"></p>

# mosey

A remote terminal for bad networks. It roams between networks, stays usable
on lossy links and picks up where it left off.

> To *mosey* is to wander along at an easy pace.

**Status: pre-alpha. Don't rely on it yet.** The design is settled
([PLAN.md](PLAN.md)) and the specs are written ([docs/spec/](docs/spec)).
The first slice works: `mosey HOST` bootstraps over your `ssh` and gives
you an interactive shell over encrypted UDP, with the emulator sandboxed on
the server. For now `mosey` must already be on the host (`-remote PATH`
names it otherwise). Resume, agent forwarding, predictive echo and copying
the binary across are the next slices. Every green commit is already
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
session can't be picked up again from another device without tmux

mosey is inspired by Mosh, written from scratch in Go from the Mosh paper
and public specifications. It starts over your normal `ssh`, with your own
config, keys and agent, exactly as Mosh does. It aims to be:

- **Resumable.** Reattach after a dead spot, a reboot, or from another
  device. Attaching kicks off the old client, so a stolen laptop is cut off.
- **Secure by modern standards.** It uses a post-quantum hybrid handshake
  (X-Wing: ML-KEM-768 plus X25519), forward secrecy, rekeying, and
  replay-proof roaming. A leaked SSH log line doesn't hand anyone your
  session. The designs are checked with ProVerif.
- **Isolated from the terminal.** The terminal emulator runs on the server,
  inside its own Landlock and seccomp sandbox, and sends your machine
  structured screen diffs. Your local terminal never parses escape
  sequences from the remote host, which shuts off a whole class of terminal
  exploits.
- **Fast where it counts.** It keeps Mosh's state-sync timing, with
  retransmission and outage probing tuned on a deterministic network
  simulator against replayed cellular, train and hotel-wifi traces. Its
  predictive local echo copes with modern shells (zsh autosuggestions,
  syntax highlighting, fish): 80% of keystrokes appear instantly, 0.1% are
  wrong.
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
`v<version>`, with one static binary per platform and their checksums:

```sh
V=0.123.456   # a release's version, without the v
curl -fLO "https://github.com/danielbodart/mosey/releases/download/v$V/mosey-$V-linux-amd64"
curl -fLO "https://github.com/danielbodart/mosey/releases/download/v$V/SHA256SUMS"
sha256sum --ignore-missing -c SHA256SUMS
install -m 0755 "mosey-$V-linux-amd64" ~/.local/bin/mosey
```

The platforms are `linux-amd64`, `linux-arm64`, `darwin-amd64` and
`darwin-arm64`. The names are fixed
([docs/spec/bootstrap.md §4.6](docs/spec/bootstrap.md)), because mosey
will fetch them itself to copy the right one onto a host of another
platform. With Nix, `nix run github:danielbodart/mosey -- HOST`, or the
flake's `packages.<system>.mosey`.

## Using it

mosey needs the same `mosey` binary on both ends for now (copying it over
by itself comes later). Then:

```sh
mosey host                 # a new session: a login shell on host, over UDP
mosey -r host              # resume your session on host, from here or another device
mosey -r=SESSION host      # resume a particular one, when you have several
mosey -list host           # your sessions on host, and whether anyone is attached
```

A session lives until its shell exits. Closing the terminal, logging out or
rebooting only detaches the client, and the session waits on the server for
`mosey -r`. Resuming takes the session over: any client still attached is
cut off and its keys are wiped. If it is awake within a minute of that, it
exits saying who took over and when; one asleep longer (a closed laptop)
is still cut off, but wakes to a session that never answers, with no word
why.
Nothing secret is ever saved to disk: each resume is a fresh SSH login and
a fresh handshake ([docs/spec/bootstrap.md §9](docs/spec/bootstrap.md)).
A client that just loses its network for a while needs none of this: it
carries on by itself when packets flow again.

## Building

With [mise](https://mise.jdx.dev):

```sh
mise run check    # gofmt, vet, tests, shellcheck, actionlint
mise run build    # the static mosey binary for linux and darwin, amd64 and arm64
mise run race     # the tests under the race detector (needs a C compiler)
```

or with Nix: `nix build` for the package, `nix flake check` for the tests,
the VM test and the lint, and `nix develop` for a shell with the tools.

CI runs all of that on every push, plus a fuzz smoke test of every parser,
the slow tests, and a 150-second soak of the server under its seccomp
`KILL` policy on amd64 and arm64. A release needs every job green.

## License

Apache-2.0. [DEPENDENCIES.md](DEPENDENCIES.md) lists the dependencies and
why each one is there.
