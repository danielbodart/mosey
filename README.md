# mosey

A remote terminal for bad networks. It roams between networks, stays usable
on lossy links and picks up where it left off.

> To *mosey* is to wander along at an easy pace.

**Status: pre-alpha. It doesn't work yet.** The design is settled
([PLAN.md](PLAN.md)), the research spikes are done
([docs/spikes/](docs/spikes)), the specs are written
([docs/spec/](docs/spec)), and the first slice, an interactive shell end to
end, is being built. Don't use it for anything yet.

## What it is

You `ssh` into a box from a laptop. Then the wifi drops, you go through a
tunnel, the laptop sleeps, or you hop from home wifi to your phone's
hotspot, and the session freezes or dies. [Mosh](https://mosh.org) fixed
much of this in 2012:

- it runs over UDP, so it survives a change of network;
- it syncs the *screen* rather than a byte stream;
- it echoes your typing locally, so it feels instant even on a slow link.

But Mosh's last release was in 2022, its crypto dates from 2012, and a
session can't be picked up again from another device.

mosey is a successor to Mosh, written from scratch in Go from the Mosh paper
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

mosey is clean-room: it contains no Mosh code (Mosh is GPLv3). The rules
are in [PLAN.md](PLAN.md#4-clean-room-rules-d3).

## Building

With [mise](https://mise.jdx.dev):

```sh
mise run check    # lint and test
mise run build    # the static mosey binary for linux and darwin, amd64 and arm64
```

## License

Apache-2.0. [DEPENDENCIES.md](DEPENDENCIES.md) lists the dependencies and
why each one is there.
