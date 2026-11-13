# Spike S6: prediction harness (a record, not production)

These directories hold the code. Findings are in
`docs/spikes/s6-prediction/FINDINGS.md`, and the spec is in
`docs/spikes/s6-prediction/prediction-spec.md`.

| Path | What |
|---|---|
| `screen/` | A structured cell grid. It stands in for the client's view under D9 (no VT parser). |
| `predict/` | The prediction engine, implemented from the spec, with unit tests and `FuzzEngine` |
| `trace/` | The trace file format: gzip'd JSON with timestamped key/output events and de-duplicated screens |
| `cmd/record/` | Drives a program in a pty with a scripted human-like typist, and records screens via `charmbracelet/x/vt` |
| `cmd/faketui/` | An Ink-style TUI that stands in for Claude Code. It never calls a model. |
| `cmd/replay/` | Replays traces under network profiles and predictor variants, and prints Markdown tables |
| `cmd/tracedump/` | Lists the keys in a trace, and shows the screens around a given key |
| `sim/` | A small discrete-event network and SSP-sender model. It is not S5's simulator. |
| `scripts/record-all.sh` | Builds the sandbox (fake HOME, rc files, history) and records every scenario in parallel |
| `traces/` | The recorded traces used for FINDINGS |

To reproduce:

    scripts/record-all.sh <scratch> <scratch>/traces 3        # about 7 min of wall clock, in parallel
    go run ./cmd/replay -traces traces -seeds 3 -variants all

Dependencies, used by the spike only:

- `charmbracelet/x/vt`: the recording-side emulator. It is a terminal emulator we did not write, so D19 allows it.
- `creack/pty`
- `rivo/uniseg`: grapheme segmentation and width in the predictor.
- `golang.org/x/term`
