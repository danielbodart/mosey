# S2 findings: the terminal emulator on the server (O3)

Spike run on dan-desktop on 2026-11-13. Code is in `spikes/s2-terminal/`
(its README maps it). Raw tables are in `docs/spikes/s2-terminal/results/`.

## Recommendation

**Use `tuios.dev/vt` with its pure-Go backend, behind a small mosey-owned
interface, in the sandboxed session process. Keep its libghostty-vt backend
as a test oracle in CI, not as the shipping default.** Pin the version.
Contribute the items below upstream, and be ready to fork (it's MIT) if
upstream stalls.

tuios was the only pure-Go candidate that survived every test:

- No fuzz finding in 20 minutes (4.9 M execs).
- Passed every hostile-input case that a remote program can trigger.
- Matched libghostty on 41 of 42 core vttest screens and 40 of 42 screens
  from real programs (vim, less, htop, zsh, fish, Claude Code).
- Parses at about 45-60 MB/s.
- Holds an 80x24 session with 10,000 lines of scrollback in about 1.2 MiB.
- Has by far the richest API for D9: scrollback, modes, hooks for title,
  OSC 52 and OSC 8, synchronized updates, a non-blocking reply queue and a
  full-state snapshot.

Its weaknesses are organisational. The module is four weeks old and one
person writes most of it.

libghostty is the most correct emulator and the fastest parser, but:

- It's Zig called through cgo. Zig isn't memory-safe in release builds, and
  cgo makes D1's static builds harder.
- It uses about 6x the memory per session.
- Its Go bindings say "no API stability yet".

charm x/vt, xterm-go and cy all failed within two minutes of fuzzing.

## What was compared

| candidate | what it is | licence | version tested |
|---|---|---|---|
| **tuios** `tuios.dev/vt` | Pure Go. Started as a copy of charm x/vt and was extracted from the tuios multiplexer. | MIT | v0.3.2 (2026-10-26) |
| **ghostty** libghostty-vt, through tuios' `ghostty` build tag (cgo, `go.mitchellh.com/libghostty`) | Ghostty's Zig terminal core, as a C library | MIT | ghostty 27e8b3fa, bindings 2026-09-20 |
| **charm** `github.com/charmbracelet/x/vt` | Charm's pure-Go emulator, tuios' ancestor | MIT | main @ 27ecf3e4 (2026-11-01) |
| **xtermgo** `github.com/gitpod-io/xterm-go` | Pure-Go port of xterm.js' headless core, with no dependencies | MIT | main @ dae5128c (2026-09-07) |
| **cy** `github.com/cfoust/cy/pkg/emu` | Pure Go, descended from st and vt10x, part of the cy multiplexer | MIT | v1.12.1 |

Looked at but not tested:

- `hinshun/vt10x`: last changed in 2023, one rune per cell, and cy's ancestor.
- `tonistiigi/vt100` and `xyproto/vt100`: toys.
- `danielgatis/go-vte`: a parser only.
- `mitchellh/go-libghostty` used directly: the same library as the ghostty
  column, without tuios' API.
- `phroun/purfecterm`: GUI widgets.
- `instagrim-dev/htgo`: a separate process, not a library.

Web searches found no other credible Go emulator.

Every candidate sits behind `spikes/s2-terminal/emu.Emulator` (write, resize,
cell at, cursor, replies, title). mosey's own seam should have this shape.

## Results

### Correctness: vttest (`results/vttest.md`, screens in `results/vttest-screens/`)

The test drove vttest 2.7 (20251205) through a pty with the same script for
every emulator: pick a menu, press RETURN until the main menu returns, and
save each screen. tmux was run too, as an independent oracle. That gave 71
screens from menus 1, 2, 3, 4, 6.3-6.5, 7, 8 and 11.5-11.7.

None of these emulators is ground truth, so I read each disagreement by hand
against what vttest says the screen should show:

- **libghostty was right every time I checked**, so it's the reference.
- tmux is a poor oracle here. `capture-pane` returns DEC line-drawing
  characters as ASCII (`qqq` for `───`), and tmux ignores DECCOLM.
- 13 screens run in 132-column mode (DECCOLM). Every candidate except
  libghostty mishandles at least one of them: none clears the screen on
  DECCOLM as a VT100 does. mosey shouldn't let the remote side resize the
  client anyway (tmux doesn't), so these screens are scored separately.
- Menus 6 (reports) and 7 (VT52) differ for legitimate reasons and aren't
  scored. Each emulator identifies itself differently, and vttest shows the
  menu 3 submenu only to VT220-class terminals.

There are 42 core screens (menus 1, 2, 4, 8 and 11.5-11.7, without DECCOLM):

| | screens identical to libghostty | rows identical |
|---|---|---|
| tuios | **41/42** | 99.4% |
| xtermgo | 41/42 | 99.4% |
| cy | 35/42 | 96.0% |
| tmux (capture) | 36/42 | 95.2% |
| charm | 32/42 | 93.8% |

- tuios' one miss (screen 1.03) is DECCOLM not clearing the screen.
- charm fails the very first screen (the cursor-movement box, 1.01), insert
  mode (IRM, 8.03) and scrolling regions.
- cy fails IRM and DEC double-size lines.

### Correctness: real programs (`results/apps.md`)

`cmd/apprec` ran each program on a pty with libghostty answering its queries,
and saved the exact bytes and the checkpoints. `cmd/appreplay` then fed the
same bytes to every candidate. The programs:

- **vim**: syntax colours, vsplit, inserting CJK, an emoji with a skin tone,
  a combining accent and a flag, resize, horizontal scroll.
- **less**.
- **htop**: tree view, setup screen, resize to 132x43.
- **zsh**: colour prompt with RPROMPT, OSC 8, OSC 2, truecolour, a 3000-line
  scroll, resize.
- **fish 4.7**: its own prompt and terminal queries.
- **claude** (Claude Code's TUI): start, arrow keys, resizes.
- **A Unicode torture file**: ZWJ families, flags, VS15/16, Devanagari, Thai,
  Hangul jamo, wide characters at the right margin, tabs.

| | screens identical to libghostty (out of 42) | rows identical |
|---|---|---|
| tuios | **40** | 99.8% |
| xtermgo | 33 | 96.0% |
| charm | 29 | 84.8% |
| cy | 29 | 84.1% |

- Both of tuios' differences are vim's insert line with `👍🏽 é`. vim and the
  emulator disagree on cluster widths, and tuios agrees with vim where
  libghostty leaves gaps. Neither is wrong; it's the usual width-table
  problem (see "Notes for D9").
- charm draws Claude Code's logo wrongly (`Claude CodClaude█Code`), loses
  `漢字` when fish redraws its command line, and drops a combining accent.
- cy has no grapheme clusters at all, just one rune per cell. It drops or
  splits combining marks, ZWJ sequences, VS16 and Indic conjuncts.
- xtermgo doesn't compose e + ZWSP + combining mark, and misses some vim
  redraws.

### Fuzzing (`results/fuzz.md`)

Each candidate got 20 minutes of `go test -fuzz` with 3 workers. The checks
were: no panic, cursor on screen, every cell readable, and under 3 s per
input. Each candidate that failed then got another 20 minutes in recover
mode, which records failures and keeps going.

| | result |
|---|---|
| tuios | **0 findings** in 4,910,023 execs |
| ghostty | **0 findings** in 1,158,595 execs (but coverage guidance doesn't see inside the Zig code) |
| charm | Hang after 98 s: **the REP count (`CSI n b`) isn't capped**. 5 reproducers, all still running after 15 s. A resize also left the cursor outside the screen. |
| xtermgo | Panic after 31 s: a wide character after a resize (12 inputs, 1 site). REP INT_MAX also burns 23 s of CPU and 4 GiB. |
| cy | Panic after 1.3 s: **`ESC ] BEL` crashes it**. Two more panics (integer overflow in ICH and DCH) and 3 hangs (CHT/CBT with huge counts). It also prints every unknown sequence to stdout. |

Twenty minutes is far short of the hours the plan asks for (see "Not done").
It still separates the field: three of the five candidates failed within two
minutes.

### Hostile input (`results/hostile.md`)

24 cases, each emulator in its own child process with a watchdog (30 s,
4 GiB RSS), GOMAXPROCS=2. Every candidate drains replies after each write,
as a server would. Full table in the results file; the cases that separate
them:

| case | ghostty | tuios | charm | xtermgo | cy |
|---|---|---|---|---|---|
| CUP/ICH/DCH/IL/DL/ECH/SU/SD/CHT/CBT with 2^31-1 and 20-digit params, x10k | ok 0.1 s | ok 0.0 s | ok 0.3 s | **hang** (killed at 30 s, still in the first write) | **hang** |
| `x` + REP 2^31-1 | ok | ok | ok | **OOM** (4 GiB in 3.6 s) | ok |
| `x` + REP with a 19-digit count | ok | ok | **hang** | ok | ok |
| REP 65535, 10k times | ok 2.3 s | ok 0.9 s | **hang** | ok 8.6 s | ok |
| sixel declaring 30000x30000 / 60000 px tall | ok | ok | ok | ok | ok |
| kitty image declaring 100000x100000, 64 MiB payload | ok 14 MiB | ok 14 MiB | ok | ok | ok |
| OSC 2 never terminated, 256 MiB | ok 25 MiB | ok 30 MiB | ok | ok 63 MiB | ok but **1,118 MiB** |
| 1 M distinct OSC 8 links | ok 28 MiB | ok 89 MiB | ok 215 MiB | **1.5 GiB and 1.2 MB/s**, killed | ok 106 MiB |
| 1 M combining marks on one base | ok | ok | ok | **hang** | ok |
| 16 M distinct truecolour cells | ok 45 MiB | ok 33 MiB | ok 215 MiB | ok | ok but **1.7 GiB** |
| 1 GiB of 200-column lines (scrollback) | 7.4 s (145 MB/s) | 21.2 s (51 MB/s) | killed, 3 MB/s | 15.7 s | killed, 20 MB/s |
| 1 M alt-screen enter/leave | **killed, 0.3 MB/s** (≈14k toggles/s) | ok 0.9 s | ok 10.3 s | ok 10.9 s | ok 5.1 s |
| mode 2026 opened and never closed, 10 MiB | ok | ok | ok 13.2 s | ok | ok |
| 100k resizes 1x1..300x100 with output | ok 9.5 s | ok 4.8 s | ok 23.1 s | **panic** | ok 11.1 s |
| resize to 5000x5000 and back, x20 (host-controlled) | ok 14 MiB | **2.9 GiB** | **OOM** | 305 MiB | 2.9 GiB |

- **tuios passed every case a remote program can trigger.** Its one bad
  number is the host-controlled 5000x5000 resize (about 112 bytes per cell);
  mosey must clamp the client's requested size whatever emulator it uses.
- **libghostty** passed everything but is slow at alt-screen toggling
  (a program can burn its own session's CPU; the helper's CPU limit
  contains it).
- charm, xterm-go and cy each have at least one remotely triggerable hang,
  OOM or panic.

### Memory and CPU per session (`results/perf.md`)

Each candidate ran in its own child process, so RSS includes C allocations.

| | RSS, fresh 80x24 session | RSS after 10k coloured lines (scrollback 10,000) | plain text MB/s | SGR-heavy MB/s | recorded programs MB/s |
|---|---|---|---|---|---|
| ghostty | 60 KiB | 7,550 KiB | 112.6 | 105.0 | 25.5 |
| tuios | **44 KiB** | **1,177 KiB** | 60.9 | 45.2 | **44.8** |
| xtermgo | 79 KiB | 12,655 KiB | 48.4 | 65.6 | 31.9 |
| cy | 120 KiB | 48,926 KiB | 15.5 | 19.0 | 18.5 |
| charm | 498 KiB | 58,688 KiB | 2.7 | 3.2 | 1.7 |

- Each child had GOMAXPROCS=1. Other spikes shared the machine (load
  average 12-13), so treat throughput as ±20%.
- An idle session costs no CPU in any of them, because none runs timers.
- At these rates, a 1 Gbit/s flood of output costs tuios about a quarter of
  a core.
- libghostty's scrollback is about 6x bigger than tuios', because it keeps
  whole pages where tuios packs its history.

### Maintenance and supply chain

| | age and releases | activity (12 months) | people | bus factor | non-stdlib modules |
|---|---|---|---|---|---|
| tuios | Module first tagged 2026-10-15; 5 tags in 11 days; v0 API | 37 commits to `vt/` since it was extracted. The tuios repo is very active (pushed today). | Gaurav-Gosain wrote 26 of the 37; three others wrote 11 | **1** | 16, all MIT or BSD. See below. |
| ghostty | Ghostty 1.x. The libghostty-vt C API is new in 2026; the Go bindings say "no API stability yet". | 1,326 commits to `src/terminal` | Many: mitchellh 1,016, then more than 30 others | High | None in Go beyond the bindings. The C library needs only libc, but **building it needs cgo and zig**. |
| charm | v0.1.0 tagged 2026-10-12 | 19 commits | Charm (a company); mostly dependabot lately | Medium | 16, the same family as tuios |
| xtermgo | Untagged, created 2026-03 | 60 commits | **56 by `ona-automations` (an AI agent), 4 by a human** | Low | **0** |
| cy | Part of cy v1.12 | 23 commits to `pkg/emu`, the last in 2026-03 | cfoust | 1 | 5, including `sasha-s/go-deadlock` |

tuios' 16 modules are ultraviolet, x/ansi, uniseg, displaywidth, uax29,
runewidth, colorful, progstatus, x/sync and x/sys, plus **six terminal-I/O
packages that a headless emulator never calls**: x/term, x/termios,
x/windows, cancelreader, terminfo and colorprofile.

All the licences are MIT, BSD or Apache-2.0, so all are compatible with
mosey's Apache-2.0. Keep the MIT notices in the binary's licence bundle.

### What D9 needs from the emulator, and who has it

| need | tuios | ghostty (lib) | charm | xtermgo | cy |
|---|---|---|---|---|---|
| cells with grapheme clusters, width, style, link | yes (`CellAt`, `uv.Cell`) | yes (render state, grid refs) | yes | yes | no clusters |
| damage tracking (dirty rows) | **no** (only `ScrollbackGeneration`) | **yes** (row dirty flags in the render state) | yes (`Touched`) | yes (`OnRender` row range) | yes (`Changes`) |
| scrollback access, for O5's lazy native scrollback | **best**: `ScrollbackRows`, `ScrollbackText`, `CopyScrollback`, soft-wrap and padding flags, a generation counter | viewport scrolling and the formatter | basic | buffer lines | `History()` |
| cursor position, visibility, style | yes | yes | yes | yes | yes |
| input modes the client must mirror (DECCKM, bracketed paste, mouse, focus, kitty keyboard, modifyOtherKeys) | yes, a method for each | yes | partial | `Modes()` | partial |
| title (OSC 0/2) | callback | callback | callback | event | getter |
| OSC 52 clipboard | `ClipboardSet` and `ClipboardQuery` callbacks. A query is answered empty unless the host says otherwise. | `WithClipboardWrite/Read` | **none** | none built in (you register a handler) | none |
| OSC 8 links | per cell | per cell | per cell | per cell | none |
| synchronized update (mode 2026) | `SyncUpdate()`, with a cap on how long it holds | `WithRenderHold` | partial | no | `WriteSync` |
| replies to the program | `TakeResponses()`, non-blocking | a write-pty callback | **a blocking `io.Pipe`: any Write that triggers a reply deadlocks unless something is reading** | event | writer |
| answering colour queries with the *client's* colours | `SetReportColors`, `SetThemeColors` | colour-scheme API | no | events | no |
| graphics | Parses kitty and sixel, has passthrough hooks, and `SetKittyFilesElsewhere` refuses file-path uploads | kitty | no | no | kitty (partial) |
| full-state snapshot and restore | `tuios.dev/vt/snapshot` (gob or JSON, packed) | formatter "extras" | no | serialize addon (as escape sequences) | no |
| hard caps on sizes an attacker controls | grapheme cluster ≤ 64 bytes, title stack 10, sequence data 4 MiB, sixel limits | explicit options (`MaxScrollbackBytes`, `ContinuationMaxBytes`, `UnknownMaxBytes`, `KittyClipboardWriteMaxBytes`) | few | few | few |

tuios was built for exactly mosey's shape. Its README lists "keep a pane's
screen in a server and send it to a client that attaches later" as a use,
and it has switches for a daemon and client split (`SetKittyUploadAnswers`,
`SetKittyFilesElsewhere`).

### The cell-diff prototype (`celldiff/`, `results/celldiff.md`)

The wire format has a handful of ops: resize, scroll up n rows, define a
style, replace a run of cells in a row, cursor, and title. Styles are
interned to small ids, and rows are compared by a cached 64-bit hash. The
client applies the ops to a cell grid and **has no VT parser**.

Two checks confirm the client's frame equals the server's after every diff:

- a 3,000-step randomised round trip (resizes, scrolling, wide and combining
  characters, OSC 8, titles);
- a replay of every recorded program.

The recordings have no timing, so a frame was taken every 1 KiB of output.
Real SSP frames, 20-250 ms apart, coalesce far more.

| stream | raw bytes | diff bytes | diff bytes, each frame deflated | mean time to snapshot and diff (tuios) |
|---|---|---|---|---|
| zsh session | 23,259 | 16,652 | 6,713 | 122 µs |
| vim | 14,865 | 19,299 | 7,580 | 104 µs |
| htop | 34,849 | 48,139 | 13,383 | 238 µs |
| claude | 6,021 | 7,896 | 2,543 | 136 µs |
| `seq 1 100000` | 688,895 | 199,877 | 69,115 | 109 µs |
| 200x60 full-screen redraw, 500 times | 3,252,000 | 1,629,772 | 446,253 | 612 µs |

- Deflating each frame with the stdlib's `compress/flate` cuts the diff
  bytes to between a half and a third. That's an input for O8.
- Detecting scrolls by row hash makes `seq`-style output cheap: one `U n` op
  plus the new rows.
- Reading every cell through the API dominates the snapshot cost (about
  50 ns per cell, unoptimised). With dirty-row tracking, the cost would be
  proportional to the rows that changed. That's the main thing to add
  upstream.
- A keystroke echo is an 11-byte diff.

### The cost of the helper-process boundary (`results/boundary.md`)

One round is: some input arrives, the emulator consumes the program's
output, and a diff goes out. In-process, that's a function call. The helper
variant is a separate process on a `SOCK_SEQPACKET` socketpair, which is what
O4's split would use. Each workload ran 20,000 rounds (1,000 for the 200x60
case):

| workload (tuios) | in-process p50 / p99 | helper p50 / p99 | added at p50 | CPU per round, in-process / helper |
|---|---|---|---|---|
| keystroke echo (11-byte diff) | 94.5 / 223.6 µs | 121.7 / 247.0 µs | **+27 µs** | 113 / 133 µs |
| one line of output (75 B) | 112.2 / 247.5 µs | 118.2 / 261.8 µs | +6 µs | 150 / 160 µs |
| 200x60 redraw (3.2 KB diff) | 715 / 1,099 µs | 881 / 1,188 µs | +166 µs | 890 / 963 µs |

The boundary adds tens of microseconds per frame. Against SSP's 8 ms
collection window and frames at least 20 ms apart, that's **noise**.

The results file has the same numbers for libghostty. It is about 1.4-1.8x
slower per round than tuios here, because reading cells through cgo costs
more than the parsing does.

**Run the emulator in the sandboxed helper either way**, as O3 proposed.

## What to contribute upstream (tuios.dev/vt)

1. **Damage tracking** on the `Terminal` interface: per-row dirty flags or a
   per-row generation number, on both backends. libghostty already has
   dirty rows in its render state. This turns a read of the whole screen
   every frame into a read of only what changed.
2. **The ghostty backend loses background-colour erase.** After
   `ESC[42m ESC[K`, the pure backend and every other candidate report a green
   background on the erased cells, but tuios' ghostty `CellAt` reports the
   default colour (`emu/bce_test.go`). libghostty stores these as
   background-only cells, and the binding drops them. This also means my
   attribute comparisons against the ghostty column under-count tuios on
   htop.
3. **DECCOLM** should clear the screen and home the cursor (vttest 1.3).
   There should also be an option never to change the column count, which
   is what mosey wants.
4. **A size guard on resize.** 5000x5000 cost 2.9 GiB in tuios, about
   112 bytes per cell. mosey will clamp the client's size anyway, but the
   library should refuse absurd sizes.
5. **A smaller dependency tree.** The headless emulator pulls in six
   terminal-I/O modules through ultraviolet (x/term, x/termios, x/windows,
   cancelreader, terminfo, colorprofile). Fix it with either a leaf package
   in ultraviolet for `Cell`, `Style` and `Link`, or types that tuios owns.
6. Our fuzz invariants and seeds (`fuzz/fuzz_test.go`) as extra fuzz targets,
   and the hostile-input battery as a benchmark suite.
7. Faster scrollback: 51 MB/s when flooding 200-column lines, against
   libghostty's 145 MB/s. Profile the path that pushes lines into history.

Courtesy bug reports for the other emulators, which mosey doesn't need:

- charm: the REP hang and the blocking reply pipe.
- xterm-go: the REP CPU burn and the wide-character panic.
- cy: the OSC panic and the integer overflows.

## Notes for D9 (not decisions)

- **The server decides widths.** Programs, the server emulator and the
  user's real terminal can each use a different width table (the vim and
  emoji case above). The client should place each run of cells with
  explicit cursor positioning. If it relies on the local terminal to
  advance the cursor by the same width, one disagreement shifts the rest of
  the row. The server emulator should turn on mode 2027 (grapheme
  clustering).
- **The server emulator answers queries, not the user's terminal.** fish,
  vim and Claude Code ask for the background colour (OSC 11), the device
  attributes and kitty-keyboard support, and adapt to the answers. The
  handshake must carry the client terminal's colours, palette and supported
  features so the server can answer truthfully (in tuios: `SetReportColors`,
  `SetThemeColors`, `DisableKittyKeyboardProtocol`).
- **Input modes travel in the diff.** How the client encodes keys and mouse
  events depends on modes that the remote program sets: DECCKM, bracketed
  paste, mouse tracking, focus events and the kitty keyboard flags. They
  belong in the state; the prototype's `M` op is a placeholder for them.
- **Synchronized output (mode 2026) is a natural frame boundary.** The
  server shouldn't send a frame while a synchronized update is open, up to a
  cap, as tuios does.
- **Graphics (sixel, kitty) can't be expressed as cells.** In v1, the server
  should answer "not supported" when a program asks, and it must refuse
  kitty uploads that name a file (tuios: `SetKittyFilesElsewhere(true)`).
- **Large frames need fragmenting.** A full 200x60 repaint is tens of KB of
  diff, so frames bigger than one 1280-byte datagram must be split across
  datagrams. (Mosh fragments too; see the paper, §2.)

## Challenges to locked decisions

None. The evidence supports three locked decisions:

- **D9**: server-side emulation, with a client that has no VT parser.
- **D19**: an existing emulator is good enough, and nothing here needs us to
  write our own.
- **D1**: the recommended backend is pure Go, so static builds stay simple.
  libghostty would have made D1 harder, though not impossible.

## Not done, bounded or unmeasured

- Fuzzing ran for 20 minutes per candidate on a shared machine, plus another
  20 in recover mode for the three that failed. The plan asks for hours.
  libghostty's own AFL++ harnesses (`test/fuzz-libghostty`) weren't run.
- There was no real xterm or VT hardware to act as an oracle. libghostty was
  the reference, after I checked the disagreements by hand.
- The app recordings have no timing, so the diff sizes use a fixed 1 KiB
  frame rather than SSP's timing. S5 can redo this with the simulator.
- Throughput and latency were measured while other spikes loaded the machine
  (load average 12-58). The numbers are comparative, not absolute.
- The claude recording ran Dan's real `claude` wrapper. HOME pointed at a
  scratch directory, but the wrapper still found the account and showed the
  logged-in TUI. The script only opened it, pressed Down twice and Ctrl-C
  twice, and sent no prompt. Recording claude is now opt-in (`-only claude`),
  and the htop and claude recordings aren't committed.
- Sixel and kitty images weren't tested for correctness, only for resource
  limits.
- The emulator wasn't tested under Landlock or seccomp; that's S4.
