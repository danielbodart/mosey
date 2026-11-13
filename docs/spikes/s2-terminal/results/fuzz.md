# Fuzzing

Harness: `spikes/s2-terminal/fuzz/fuzz_test.go`. One `go test -fuzz` target
per candidate; the input is program output, with `0xFF b1 b2` meaning
"resize to (1+b1%200) x (1+b2%100)". After every write or resize it checks:
no panic, cursor inside the screen, every cell readable with width <= 2, and
the whole input done within 3 s of wall time. 17 seed inputs (huge CSI
parameters, REP, sixel, kitty graphics, OSC 8/52, DEC line drawing, grapheme
clusters, DECCOLM, resize).

Run on dan-desktop (24 CPUs, shared with the other spikes: load average
13-58 during the runs), Go 1.27.3, `-parallel 3` per target, each target in
its own `systemd-run --user --scope` unit (`mosey-spike-fuzz-*`) capped at
6 GiB, all five at once.

## Phase 1: plain `go test -fuzz`, 20 minutes, stop at first failure

| target | wall time | execs | coverage entries | result |
|---|---|---|---|---|
| tuios (pure Go) | 20m00s | 4,910,023 | 882 | **no failures** |
| libghostty-vt (via tuios' cgo backend) | 20m00s | 1,158,595 | 549 | **no failures** (coverage guidance only sees the Go side) |
| charm x/vt | 98 s | 69,922 | 128 | hang: `x ESC[2147483600000047b` (REP with a huge count) |
| xterm-go | 31 s | - | - | panic in `BufferLine.SetCellFromCodepoint`: wide character after a resize to 3 columns |
| cy/pkg/emu | 1.3 s | - | - | panic in `State.OscDispatch`: `ESC ] ; ESC` |

Before fuzzing even started, the seed `x ESC[2147483647b` (REP INT_MAX) took
**23.5 s of CPU** in xterm-go and was taken out of its corpus so its fuzzer
could run at all.

## Phase 2: recover mode, 20 minutes of fuzzing per failing target

`MOSEY_FUZZ_RECOVER=<file>`: panics and invariant failures are recorded and
fuzzing continues; a hang (which go's fuzzer cannot survive) ends the round,
its reproducer is moved to `fuzz/crashers/`, and a new round starts until
1200 s have been spent (round time includes recompiling, ~10 s each).

| target | rounds (hangs) | distinct failure sites after triage (`scripts/triage.sh`, `TestCrashers`) |
|---|---|---|
| charm | 6 (5 hangs) | **REP count not capped**: 5 reproducers, all `x ESC[<10-19 digits>b`, each still running after 15 s standalone. **Cursor outside the screen** after DECCOLM + resize to width 1 (`cursor 4,0 outside 1x92`). |
| xterm-go | 1 | **1 panic site** (`BufferLine.SetCellFromCodepoint`, index out of range) reached by 12 different inputs: wide characters at narrow widths. Plus the REP INT_MAX CPU burn above. |
| cy | 12 (11 "hangs") | **3 panic sites**: `OscDispatch` (`ESC ] BEL` is enough), `insertBlanks` and `deleteChars` (integer overflow of a 20-digit parameter into a negative slice bound). **3 real hangs** (still running after 15 s standalone): CHT/CBT/CSI with 18-51-digit counts (`ESC[555555555555555555Z`, `ESC[10000000000000000000000000I`). The other 8 "hangs" complete in < 2 ms standalone; the fuzz worker died for another reason (cy writes every unknown sequence to stdout with `fmt.Printf`, and it links `sasha-s/go-deadlock`). Not counted. |

Reproducers: `spikes/s2-terminal/fuzz/crashers/<Target>/`.

## What this says

- tuios and libghostty survived 20 minutes each with no finding. That is a
  weak lower bound (Dan's plan asked for hours; see "not done"), but the
  other three fell over in 1-100 seconds, which separates the field.
- The libghostty run exercises the C library through cgo without coverage
  guidance for the Zig code. Upstream ships AFL++ harnesses for libghostty-vt
  (`test/fuzz-libghostty`: `osc`, `parser`, `stream` targets) at the pinned
  commit; running those for hours is the meaningful test of that backend and
  was not done here.
