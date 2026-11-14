# mosey

A remote terminal for bad networks: it roams between them, stays usable on
lossy links and picks up where it left off.

> To *mosey* is to wander along at an easy pace.

mosey is a successor to [Mosh](https://mosh.org), written from scratch in Go
from the Mosh paper and public specifications. It starts over SSH as Mosh
does, copies its own server across if the host lacks it, runs the terminal
emulator on the server so your real terminal never parses remote escape
sequences, and resumes sessions after a dead spot, a reboot or a change of
device. Every commit to trunk is a release.

**Status: pre-alpha.** It doesn't work yet. The design is settled
([PLAN.md](PLAN.md)), the spikes are done (`docs/spikes/`), and the first
slice, an interactive shell end to end, is being built
([docs/spec/architecture.md](docs/spec/architecture.md)). Don't use it for
anything.

## Building

With [mise](https://mise.jdx.dev):

```sh
mise run check    # lint and test
mise run build    # the static mosey binary for linux and darwin, amd64 and arm64
```

## License

Apache-2.0. mosey contains no code from Mosh (GPLv3); see the clean-room rules
in [PLAN.md](PLAN.md#4-clean-room-rules-d3). Dependencies and why each is
there: [DEPENDENCIES.md](DEPENDENCIES.md).
