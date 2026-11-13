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

**Status: planning.** See [PLAN.md](PLAN.md). There is no code yet.

## License

Apache-2.0. mosey contains no code from Mosh (GPLv3); see the clean-room rules
in [PLAN.md](PLAN.md#4-clean-room-rules-d3).
