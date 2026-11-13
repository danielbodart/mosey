# Spike S2: terminal emulator on the server

A record, not production code. Findings: `docs/spikes/s2-terminal/FINDINGS.md`.

| path | what |
|---|---|
| `emu/` | one small interface (`emu.Emulator`) over every candidate: tuios.dev/vt (pure Go), tuios' libghostty-vt backend (build tag `ghostty`), `ghosttyd` (libghostty read directly through go.mitchellh.com/libghostty, no tuios code: the independent oracle; build tag `ghostty`), charmbracelet/x/vt, gitpod-io/xterm-go, cfoust/cy/pkg/emu |
| `internal/ptyrun/` | runs a program on a pty whose screen is a candidate emulator (replies go back to the program) |
| `cmd/vttest-drive`, `cmd/vtcompare` | drive vttest identically against each candidate and tmux, score screens |
| `cmd/apprec`, `cmd/appreplay` | record vim/less/htop/zsh/fish(/claude) once, replay the identical bytes into each candidate |
| `fuzz/` | `go test -fuzz` targets per candidate, recover mode, triage, saved reproducers in `fuzz/crashers/`; `FuzzTuiosClamp` (resizes up to the clamp, heap invariant) |
| `cmd/hostile` | hostile-input battery with a watchdog (time, RSS) per child process |
| `cmd/perf` | per-session RSS and parse throughput |
| `celldiff/`, `cmd/diffbench` | prototype structured cell-diff encoding (D9) with a client that has no VT parser; `allow.go` is the D9 allow-list; `hostile_test.go` has the decoder probes, `FuzzApply` and `FuzzRoundTrip` |
| `cmd/memworst` | worst-case memory per tuios session by width, scrollback and cell kind (`scripts/memworst.sh`) |
| `cmd/replyflood` | pty-backed query flood from a program that never reads stdin: naive vs split reply path |
| `cmd/boundary` | in-process vs helper-process (SOCK_SEQPACKET socketpair) cost |
| `scripts/` | how everything was run (`build-libghostty.sh`, `build.sh`, `fuzz-all.sh`, `fuzz-recover.sh`, `vttest-all.sh`, `apps.sh`, `score.sh`, `bench-all.sh`, `deps.sh`, `triage.sh`; after the review: `fuzz-review.sh`, `bench-review.sh`, `memworst.sh`, `deccolm-screens.py`) |
| `fixtures/` | Unicode torture file and a Go source file for vim/less; `fixtures/rec/` holds the vim, less, zsh, fish and Unicode recordings (raw.bin + events.json + the live screens) so the replays can be rerun: `appreplay -rec fixtures/rec -out <dir>` |

Build (the `ghostty` tag needs libghostty-vt; everything else is pure Go):

    scripts/build-libghostty.sh /tmp/x            # ~1 min, zig 0.16.0 via mise
    LIBGHOSTTY_PREFIX=/tmp/x/ghostty-out scripts/build.sh /tmp/x/bin

Pure Go only: `mise exec go@1.27.3 -- go test ./emu ./celldiff ./fuzz`.
