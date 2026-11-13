# S2 findings: the terminal emulator on the server (O3)

Spike run on dan-desktop on 2026-11-13, then revised the same evening after
an adversarial review (see "Review response" at the end, which says what
changed and why). Code is in `spikes/s2-terminal/` (its README maps it). Raw
tables are in `docs/spikes/s2-terminal/results/`.

## Recommendation

**Use `tuios.dev/vt` with its pure-Go backend, behind a small mosey-owned
interface, in the sandboxed session process. Keep libghostty-vt as a test
oracle in CI, read directly through `go.mitchellh.com/libghostty` (not
through tuios' binding), and not as the shipping default.** Pin the version.
Contribute the items below upstream, and be ready to fork (it's MIT) if
upstream stalls.

Why tuios:

- It is the only pure-Go candidate with no fuzz finding: 20 minutes (4.9 M
  execs) in the first run, and 20 minutes (2.5 M execs) with no finding in a second run with resizes
  up to the client clamp and a heap invariant.
- No crash, hang or unbounded growth from any hostile input a remote program
  can send at 80x24, apart from OSC 8 link storage (below). At the 1000x500
  clamp it has no crash or hang, but some cases are slow (REP 65535
  repeated costs about 3 ms of CPU per 8-byte sequence) and, like most
  candidates, it has no hard memory ceiling of its own.
- Against libghostty read directly (no tuios code in the path), it matches
  36 of 36 core vttest screens, and 40 of 42 screens from real programs on
  text and on attributes. Its only misses are the vim emoji line, a
  width-table disagreement.
- It has by far the richest API for D9: scrollback, modes, hooks for title,
  OSC 52 and OSC 8, synchronized updates, a non-blocking reply queue and a
  full-state snapshot.

Parse speed is **not** a reason to prefer it over xterm-go. Rerun three times on a nearly idle machine, xterm-go parses plain and SGR-heavy text faster than tuios (84 and 87 MB per CPU-second, against 75 and 73), while tuios is about twice as fast on the recorded-program mix (71 against 34). libghostty is fastest on plain text (144).
tuios wins on robustness and API, not speed.

What mosey must add around it, whichever emulator ships (new since the
review, all measured below):

1. **A size clamp on the client's window size**, applied before the
   emulator's `Resize`: proposed 1000 x 500.
2. **A scrollback budget in cells, not lines.** tuios caps lines only, and
   a remote program can make one history cell cost about 100 bytes (64-byte
   clusters, distinct colours), or the length of an OSC 8 URI, which tuios
   accepts up to 4 MiB. Proposed: lines = min(10,000, 1,000,000 / cols).
3. **A memory cgroup on the session helper** (`MemoryMax`, proposed
   512 MiB), because item 2 doesn't bound links until tuios caps URI length
   upstream.
4. **A reply path that cannot deadlock**: the reader of the pty never
   writes to it; replies go to a bounded queue with a drop policy.
5. **The D9 allow-list** for title, OSC 8 and cell text, enforced on the
   server and re-checked by the client, and a client decoder that treats
   every diff as hostile (now fuzzed: 15 minutes, 2.4 M execs, no finding after one fix).

Its weaknesses are organisational. The module is four weeks old and one
person writes most of it.

libghostty is the most correct emulator and bounds memory best (its
hyperlink storage stays at tens of MiB where tuios' grows without limit),
but:

- It's Zig called through cgo. Zig isn't memory-safe in release builds, and
  cgo makes D1's static builds harder.
- It uses about 6x the memory per session on ordinary output.
- At the clamp size it is slow at alt-screen toggling and at grapheme
  clusters (both degraded, below).
- Its Go bindings say "no API stability yet".
- It hasn't been meaningfully fuzzed here (see "Fuzzing").

charm x/vt, xterm-go and cy all failed within two minutes of fuzzing.

## What was compared

| candidate | what it is | licence | version tested |
|---|---|---|---|
| **tuios** `tuios.dev/vt` | Pure Go. Started as a copy of charm x/vt and was extracted from the tuios multiplexer. | MIT | v0.3.2 (2026-10-26) |
| **ghostty** libghostty-vt, through tuios' `ghostty` build tag (cgo, `go.mitchellh.com/libghostty`) | Ghostty's Zig terminal core, as a C library, read through tuios' binding (which keeps a tuios grid alongside) | MIT | ghostty 27e8b3fa, bindings 2026-09-20 |
| **ghosttyd**: the same library, read directly | `emu/ghosttyd.go` reads libghostty's render state through `go.mitchellh.com/libghostty`, with no tuios code. Added after the review as an independent oracle. | MIT | same |
| **charm** `github.com/charmbracelet/x/vt` | Charm's pure-Go emulator, tuios' ancestor | MIT | main @ 27ecf3e4 (2026-11-01) |
| **xtermgo** `github.com/gitpod-io/xterm-go` | Pure-Go port of xterm.js' headless core, with no dependencies | MIT | main @ dae5128c (2026-09-07) |
| **cy** `github.com/cfoust/cy/pkg/emu` | Pure Go, descended from st and vt10x, part of the cy multiplexer | MIT | v1.12.1 |

Looked at but not tested:

- `hinshun/vt10x`: last changed in 2023, one rune per cell, and cy's ancestor.
- `tonistiigi/vt100` and `xyproto/vt100`: toys.
- `danielgatis/go-vte`: a parser only.
- `phroun/purfecterm`: GUI widgets.
- `instagrim-dev/htgo`: a separate process, not a library.

Web searches found no other credible Go emulator.

Every candidate sits behind `spikes/s2-terminal/emu.Emulator` (write, resize,
cell at, cursor, replies, title). mosey's own seam should have this shape.

## Results

### Correctness: vttest (`results/vttest.md`, screens in `results/vttest-screens/`)

The test drove vttest 2.7 (20251205) through a pty with the same script for
every emulator: pick a menu, press RETURN until the main menu returns, and
save each screen. That gave 70 screens from menus 1, 2, 3, 4, 6.3-6.5, 7, 8
and 11.5-11.7. All seven runs (five candidates, ghosttyd and tmux) were
redone together after the review.

**The oracles.** None of these is ground truth. There are three references,
independent of each other:

- **ghosttyd**, libghostty read directly. This is the primary reference.
- **tmux** (`capture-pane`), a third implementation. It's a poor oracle for
  some screens: it returns DEC line-drawing characters as ASCII (`qqq` for
  `───`) and ignores DECCOLM.
- **xterm-go**, which shares no code with tuios or libghostty.

The first version used tuios' own libghostty binding as the only
reference. That isn't independent of tuios: the binding keeps a tuios grid
alongside libghostty's, is read through the same cell-extraction code, and
drops background-colour-erase cells. On vttest's core screens the two
readings of libghostty agree on every screen, so the core scores didn't
move. On the program replays they differ (next section).

**Which screens count.** Menus 6 (reports) and 7 (VT52) differ for
legitimate reasons and aren't scored. Each emulator identifies itself
differently, and vttest shows the menu 3 submenu only to VT220-class
terminals. Screens that depend on DECCOLM (132-column mode) are scored
separately, because mosey shouldn't let the remote side resize the client
(tmux doesn't either). Which screens those are is now decided by **what
vttest sent** (`scripts/deccolm-screens.py`): a screen counts as DECCOLM if
the byte stream had asked for 132 columns at capture time, or had changed
the column mode since the previous screen. The first version used the
reference's mode at capture time, which left screen 1.03 in the core set.
On that screen vttest switches back to 80 columns, so DECCOLM's clear
decides what it shows.

That leaves 36 core screens (menus 1, 2, 4, 8 and 11.5-11.7, without the 19
DECCOLM screens):

| | = ghosttyd | = tuios' binding | = tmux | attributes = ghosttyd |
|---|---|---|---|---|
| tuios | **36/36** | 36/36 | 32/36 | 36/36 |
| xtermgo | 36/36 | 36/36 | 32/36 | 36/36 |
| cy | 31/36 | 31/36 | 31/36 | 36/36 |
| charm | 29/36 | 29/36 | 26/36 | 36/36 |
| tmux | 32/36 | 32/36 | 36/36 | - |

- The four screens where every emulator differs from tmux come from tmux's
  capture limits.
- charm fails the very first screen (the cursor-movement box, 1.01), insert
  mode (IRM) and scrolling regions. cy fails IRM and DEC double-size lines.
- On the 19 DECCOLM screens, only libghostty clears the screen and homes
  the cursor as a VT100 does. Against ghosttyd: tuios 9/19, xterm-go 9/19,
  cy 8/19, charm 7/19.
- Under the old rule the core set was 42 screens and tuios scored 41/42.
  That table is kept at the end of `results/vttest.md`.

### Correctness: real programs (`results/apps.md`, `results/apps-replay/`)

`cmd/apprec` ran each program on a pty with tuios' libghostty binding
answering its queries, and saved the exact bytes and the checkpoints.
`cmd/appreplay` then fed the same bytes to every candidate. Because one
emulator's answers shaped the streams, this compares how each emulator
draws the same bytes, not how each would have steered the program. The
programs:

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

The vim, less, zsh, fish and Unicode recordings are committed in
`spikes/s2-terminal/fixtures/rec/` (the only personal data in them is the
user and host name in the prompt), along with every emulator's replayed
screens. The htop recording (the machine's process list) and the claude
recording (an account's TUI) are not, so the 11 htop and claude screens
can't be reproduced from the repo.

Against **ghosttyd** (libghostty read directly), out of 42 screens:

| | text: screens | text: rows | attributes: screens | attributes: rows |
|---|---|---|---|---|
| tuios | **40** | 99.8% | **40** | 99.7% |
| xtermgo | 33 | 96.0% | 36 | 98.7% |
| charm | 29 | 84.8% | 35 | 98.4% |
| cy | 29 | 84.1% | 25 | 94.7% |
| tuios' binding of libghostty | 42 | 100% | 37 | 98.1% |

- **tuios' attribute score was 35/42 against its own binding, and is 40/42
  against libghostty read directly.** The five htop screens that every
  candidate "failed" were caused by the binding's background-colour-erase
  bug. `emu/bce_test.go` now shows ghosttyd reporting the green background
  that the binding drops.
- Both of tuios' differences are vim's insert line with `👍🏽 é`. vim and the
  emulator disagree on cluster widths, and tuios agrees with vim where
  libghostty leaves gaps. Neither is wrong; it's the usual width-table
  problem (see "Notes for D9").
- Against xterm-go, which shares no code with tuios or libghostty, tuios
  matches 33/42 screens on text and 36/42 on attributes. The differences
  are xterm-go's own (below) and vim's emoji line.
- charm draws Claude Code's logo wrongly (`Claude CodClaude█Code`), loses
  `漢字` when fish redraws its command line, and drops a combining accent.
- cy has no grapheme clusters at all, just one rune per cell. It drops or
  splits combining marks, ZWJ sequences, VS16 and Indic conjuncts.
- xterm-go doesn't compose e + ZWSP + combining mark, and misses some vim
  redraws.

### Fuzzing (`results/fuzz.md`)

First run: each candidate got 20 minutes of `go test -fuzz` with 3 workers.
The checks were: no panic, cursor on screen, every cell readable, and under
3 s per input. Each candidate that failed then got another 20 minutes in
recover mode, which records failures and keeps going.

| | result |
|---|---|
| tuios | **0 findings** in 4,910,023 execs |
| libghostty | 0 findings in 1,158,595 execs, but **not meaningfully fuzzed**: coverage guidance doesn't see inside the Zig code, so the inputs were close to random. Its own AFL++ harnesses weren't run. |
| charm | Hang after 98 s: **the REP count (`CSI n b`) isn't capped**. 5 reproducers, all still running after 15 s. A resize also left the cursor outside the screen. |
| xtermgo | Panic after 31 s: a wide character after a resize (12 inputs, 1 site). REP INT_MAX also burns 23 s of CPU and 4 GiB. |
| cy | Panic after 1.3 s: **`ESC ] BEL` crashes it**. Two more panics (integer overflow in ICH and DCH) and 3 hangs (CHT/CBT with huge counts). It also prints every unknown sequence to stdout. |

The first run capped resizes at 200x100 and had no memory invariant, so it
said nothing about memory or about larger windows. These targets were
added after the review (`scripts/fuzz-review.sh`). Each ran in a
`mosey-spike-fuzz-*` scope with a 4 GiB cap and `-parallel 3`, alongside
other spikes' fuzzers (load 25-35):

| target | what it checks | time | execs | result |
|---|---|---|---|---|
| `FuzzTuiosClamp` | tuios, with resizes anywhere up to 1000x500; the heap after GC every 256 inputs must stay under 384 MiB | 20 min | 2,512,051 | **no finding** |
| `FuzzApply` | the cell-diff client decoder, given arbitrary bytes while it holds a real frame. An error must leave the state unchanged, success must leave every bound intact, and the heap must stay under 768 MiB | 15 min | 2,404,217 | **no finding**. An earlier run found one bug in its first second (see the review response), which was fixed before this run. |
| `FuzzRoundTrip` | arbitrary program output into tuios at a fuzzed size up to the clamp, a resize, and a diff after each half. The client must accept the server's diffs and end up identical, with every bound intact | 15 min | 977,967 | **no finding** |

Twenty minutes is far short of the hours the plan asks for (see "Not done").
It still separates the field: three of the five candidates failed within two
minutes.

### Hostile input (`results/hostile.md`, `results/hostile-clamp.md`)

The battery now has 28 cases. Each emulator runs in its own child process
with a watchdog (30 s, 4 GiB RSS) and GOMAXPROCS=2. Every candidate drains
replies after each write. (What happens to those replies on a real pty is
covered in the next section.)

**Scoring rule.**

- *ok*: finishes in reasonable time and memory.
- *degraded*: a finite slowdown, or a large but bounded allocation, that
  stays inside the one session. The helper's CPU and memory limits contain
  it, and the program only hurts its own session.
- *fail*: a crash, unbounded work (still running when killed, with no sign
  of finishing), or memory growth the emulator never stops.

The first version scored two similar cases differently. Under this rule,
libghostty's alt-screen toggling is **degraded** (about 14,000 toggles/s,
so the 1 M-toggle case was killed at 30 s, but each toggle finishes).
charm's REP hang is a **fail** (one REP with a 19-digit count never
returns).

At 80x24 (the first run), these are the cases that separate them:

| case | ghostty | tuios | charm | xtermgo | cy |
|---|---|---|---|---|---|
| CUP/ICH/DCH/IL/DL/ECH/SU/SD/CHT/CBT with 2^31-1 and 20-digit params, x10k | ok 0.1 s | ok 0.0 s | ok 0.3 s | **fail** (killed at 30 s, still in the first write) | **fail** |
| `x` + REP 2^31-1 | ok | ok | ok | **fail** (OOM: 4 GiB in 3.6 s) | ok |
| `x` + REP with a 19-digit count | ok | ok | **fail** (hang) | ok | ok |
| REP 65535, 10k times | ok 2.3 s | ok 0.9 s | **fail** | degraded 8.6 s | ok |
| sixel declaring 30000x30000 / 60000 px tall | ok | ok | ok | ok | ok |
| kitty image declaring 100000x100000, 64 MiB payload | ok 14 MiB | ok 14 MiB | ok | ok | ok |
| OSC 2 never terminated, 256 MiB | ok 25 MiB | ok 30 MiB | ok | ok 63 MiB | degraded **1,118 MiB** |
| 1 M distinct OSC 8 links | ok 28 MiB | ok 89 MiB | degraded 215 MiB | **fail** (1.5 GiB and 1.2 MB/s, killed) | ok 106 MiB |
| 1 M combining marks on one base | ok | ok | ok | **fail** (hang) | ok |
| 16 M distinct truecolour cells | ok 45 MiB | ok 33 MiB | degraded 215 MiB | ok | degraded **1.7 GiB** |
| 1 GiB of 200-column lines (scrollback) | ok 7.4 s | ok 21.2 s | degraded (killed, 3 MB/s) | ok 15.7 s | degraded (killed, 20 MB/s) |
| 1 M alt-screen enter/leave | **degraded** (killed at 30 s, ≈14k toggles/s) | ok 0.9 s | ok 10.3 s | ok 10.9 s | ok 5.1 s |
| mode 2026 opened and never closed, 10 MiB | ok | ok | ok 13.2 s | ok | ok |
| 100k resizes 1x1..300x100 with output | ok 9.5 s | ok 4.8 s | ok 23.1 s | **fail** (panic) | ok 11.1 s |
| resize to 5000x5000 and back, x20 | ok 14 MiB | degraded 2.9 GiB | **fail** (OOM) | 305 MiB | degraded 2.9 GiB |

The first version called the 5000x5000 resize "host-controlled". It isn't:
in mosey the window size comes from the remote client, an authenticated
but untrusted peer. So mosey now clamps it on the server before `Resize`
(`celldiff.ClampSize`, 1000 x 500), and the battery was rerun with the
session at that size, for tuios and libghostty, with four new cases:

| case, at 1000x500 | libghostty (tuios' binding) | tuios |
|---|---|---|
| everything that was ok at 80x24 except the rows below | ok | ok |
| REP 65535, 10k times | ok 1.0 s | **degraded**: killed at 30 s with 9,794 of 10,000 done (about 3 ms of CPU per 8-byte sequence) |
| 1 GiB of 200-column lines | ok 7.3 s | **degraded**: 13 MB/s, killed at 30 s (51 MB/s at 80x24) |
| 1 M alt-screen enter/leave | **degraded**: 2 writes in 30 s (each toggle clears 500k cells) | ok 3.5 s |
| 16 M distinct truecolour cells | ok 166 MiB | ok 377 MiB |
| new: resize to the clamp and back x20, both screens written | ok 20 MiB | ok 86 MiB |
| new: 2,000 resizes between 1x1 and 1000x500 with output | ok 1.0 s | ok 0.4 s |
| new: 12,000 lines of 63-byte clusters, distinct colours | **degraded**: 4 MB/s, killed at 30 s, 373 MiB | **degraded**: 7.9 MB/s, killed at 30 s, 606 MiB and growing toward ~1 GiB at the 10,000-line cap |
| new: a distinct 2 KiB OSC 8 URI on every cell, 512 MiB sent | ok 97 MiB | **degraded**: 790 MiB, growing with what is sent (see "Worst-case memory") |
| resize to 5000x5000 (now prevented by the clamp) | ok 13 MiB | 2.9 GiB |

The four new cases at 80x24, all candidates: xterm-go **crashes**
(panic) on the clamp-sized resize storm; charm takes 315 MiB for it; at
80x24 the 2 KiB-link case costs tuios 896 MiB, charm 779 MiB and xterm-go
1,188 MiB, while libghostty and cy stay at about 40 MiB.

So at the clamp tuios has no crash, hang or failure, but three cases are
degraded: two are CPU (a program can make its own session slow, about 3 ms
per REP or 13 MB/s for scrolling) and the cluster and link cases are memory
the emulator doesn't bound by itself. The cell budget for history and the
helper's cgroup are what bound them (next sections). libghostty is degraded
on alt-screen toggling and clusters, and bounded on memory.

### The reply path back to the program (`results/replyflood.md`)

Many queries (DSR/CPR, DA, OSC 11) need a reply written back into the pty.
`cmd/replyflood` runs a child on a raw-mode pty that writes 64 MiB of
queries and text and **never reads its stdin**. That sets up the classic
deadlock:

| server design | result (3 runs each) |
|---|---|
| naive: one goroutine reads output, parses it, and writes the replies to the pty before reading again | **deadlock in 0.1-0.2 s**. About 18 KiB of replies fill the child's input queue, the write blocks, nothing reads the output, and the child blocks writing. |
| split: the reader never writes. Replies go to a 64 KiB bounded queue, drained by a separate writer goroutine; overflow is dropped and counted | **completes**: all 64 MiB consumed in 6.4-7.3 s (on a loaded machine), 17-19 KiB of replies delivered, about 53 MiB dropped, at most 64 KiB queued, heap 2-4 MiB |

tuios' own reply queue (`TakeResponses`) is capped at 4 MiB and drops the
overflow silently. The review measured exactly 4,194,302 bytes queued after
137 MiB of queries. With the split design that cap is never reached,
because mosey drains the queue after every `Write`. The requirement is
recorded in "Notes for D9".

### Worst-case memory per session (`results/memworst.md`)

The first version quoted 1.2 MiB for an 80x24 session with 10,000 lines of
history. That's real, but it's the cheapest kind of cell, and a remote
program chooses what each cell costs. `cmd/memworst` writes full-width
lines in which every cell is as expensive as it can make it, and measures
the Go heap per history cell (tuios pure-Go, 2,000 lines, 80 to 1,000
columns):

| what each cell holds | bytes per history cell | 10,000 lines at 80 cols | at 200 cols | at 1,000 cols |
|---|---|---|---|---|
| one ASCII byte, default style | 4.5-5.1 | 4 MiB | 9.5 MiB | 46 MiB |
| one byte, distinct truecolour fg+bg, 3 attributes | 17-20 | 15 MiB | 37 MiB | 187 MiB |
| 63-byte grapheme cluster (tuios' cap is 64), distinct colour | **86-101** | 69 MiB | 172 MiB | **963 MiB** |
| distinct 256-byte OSC 8 URI | 276-345 | 230 MiB | 580 MiB | 2.8 GiB |
| distinct 2 KiB OSC 8 URI | **2,155-2,229** | 1.7 GiB | 4.2 GiB | **21 GiB** |

The per-cell column was measured over 2,000 lines. The 10,000-line columns
are that cost times cols x 10,000, so they are derived, not measured. With
a single 4,000,000-byte URI per cell, memory reached 2.9 GiB after 8 lines
of 80 cells, in 38 s.

What this means:

- **Without links**, the worst case is about **100 bytes per history cell**
  (the 64-byte cluster cap plus overhead), so memory ≈ 100 B x cols x
  scrollback lines. At the clamp width that's about 1 GiB for 10,000 lines.
  The budget therefore has to be in cells. With lines = min(10,000,
  1,000,000 / cols), history costs at most about 100 MiB at any width:
  10,000 lines up to 100 columns, 1,000 lines at 1,000 columns.
- **With links, tuios has no ceiling today.** It stores each cell's URI by
  value and accepts URIs up to its 4 MiB sequence cap, so memory grows at
  about the rate the program sends (1-2x), up to the line cap. libghostty
  doesn't have this problem: the same 200x60 run with 2 KiB links stayed at
  44 MiB RSS. The fix belongs upstream (cap the URI length, intern URIs, or
  a byte budget for history). Until then the helper's memory cgroup is the
  only thing that contains it. A session that hits its cgroup limit is
  killed, but it can't take the server or other users' sessions with it.
- **The screen itself** at the clamp costs tuios about 86 MiB RSS with both
  the main and the alternate screen written (libghostty: 20 MiB).
- A per-session budget of about 512 MiB (`MemoryMax` on the session helper)
  covers both screens, 100 MiB of history and the diff server's own frames
  at the clamp, with room to spare. That number is a proposal for Dan (see
  the decisions).

### Memory and CPU per session (`results/perf.md`)

Each candidate ran in its own child process, so RSS includes C allocations.
After the review this was rerun three times per candidate on a nearly
idle machine, interleaved, reporting the median and range. Wall-clock MB/s on a shared machine moves with load, so
the table now also gives MB per CPU-second (user + sys of the whole
process, so GC counts), which is much steadier:

| | RSS, fresh 80x24 session | RSS after 10k coloured lines (scrollback 10,000) | plain text, MB per CPU-s | SGR-heavy, MB per CPU-s | recorded programs, MB per CPU-s |
|---|---|---|---|---|---|
| ghostty | 63 KiB | 7,553 KiB | 144.1 [139.8-152.0] | 128.6 [127.8-134.2] | 33.5 [33.4-34.5] |
| tuios | 44 KiB | 1,178 KiB | 74.8 [74.5-75.3] | 72.9 [71.8-73.0] | 70.7 [70.2-71.0] |
| charm | 498 KiB | 58,661 KiB | 3.1 [3.1-3.1] | 3.9 [3.9-3.9] | 2.2 [2.2-2.2] |
| xtermgo | 79 KiB | 12,654 KiB | 84.1 [83.8-84.9] | 87.5 [87.4-87.5] | 33.7 [33.6-33.8] |
| cy | 120 KiB | 48,946 KiB | 16.5 [15.9-16.8] | 20.1 [19.2-20.3] | 19.4 [18.6-19.4] |

Wall-clock MB/s (in `results/perf.md`) agreed with the CPU rates to within 1% this time.

- Each child had GOMAXPROCS=1. The load average was 4.6 at the start and
  2.7 at the end. The first version ran at load 13-39, which cut its
  numbers by 15-35% and, by accident, ranked tuios ahead of xterm-go on
  plain text.
- An idle session costs no CPU in any of them, because none runs timers.
- **Correction:** the first version said a 1 Gbit/s flood of output costs
  tuios "about a quarter of a core". That was wrong by about 7x. 1 Gbit/s
  is 125 MB/s; at 71-75 MB per CPU-second that is 1.7-1.8 cores, or
  about a sixth of a core per 100 Mbit/s. Grapheme-heavy output is far
  slower: the 63-byte-cluster lines in `memworst` ran at about 9 MB/s
  (measured under load), which is about 14 cores per Gbit/s.
- The cost limits itself. A program can only write as fast as the session
  process reads the pty, so a single-threaded session uses at most one
  core, and a slow parse slows the program down rather than building a
  queue. The helper's CPU limit (O4) is about fairness between sessions,
  not about bounding a queue. A 100% `CPUQuota` per session holds a flood
  to about 75 MB/s of plain output.
- libghostty's scrollback is about 6x bigger than tuios' on ordinary
  output, because it keeps whole pages where tuios packs its history.

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
| title (OSC 0/2) | callback (passes C1 controls and DEL through; see the allow-list) | callback | callback | event | getter |
| OSC 52 clipboard | `ClipboardSet` and `ClipboardQuery` callbacks. A query is answered empty unless the host says otherwise. | `WithClipboardWrite/Read` | **none** | none built in (you register a handler) | none |
| OSC 8 links | per cell, stored by value, no length cap below 4 MiB | per cell, bounded storage | per cell | per cell | none |
| synchronized update (mode 2026) | `SyncUpdate()`, with a cap on how long it holds | `WithRenderHold` | partial | no | `WriteSync` |
| replies to the program | `TakeResponses()`, non-blocking, capped at 4 MiB with a silent drop | a write-pty callback | **a blocking `io.Pipe`: any Write that triggers a reply deadlocks unless something is reading** | event | writer |
| answering colour queries with the *client's* colours | `SetReportColors`, `SetThemeColors` | colour-scheme API | no | events | no |
| graphics | Parses kitty and sixel, has passthrough hooks, and `SetKittyFilesElsewhere` refuses file-path uploads | kitty | no | no | kitty (partial) |
| full-state snapshot and restore | `tuios.dev/vt/snapshot` (gob or JSON, packed) | formatter "extras" | no | serialize addon (as escape sequences) | no |
| hard caps on sizes an attacker controls | grapheme cluster ≤ 64 bytes, title stack 10, sequence data 4 MiB, sixel limits; **scrollback capped in lines only** | explicit options (`MaxScrollbackBytes`, `ContinuationMaxBytes`, `UnknownMaxBytes`, `KittyClipboardWriteMaxBytes`) | few | few | few |

tuios was built for exactly mosey's shape. Its README lists "keep a pane's
screen in a server and send it to a client that attaches later" as a use,
and it has switches for a daemon and client split (`SetKittyUploadAnswers`,
`SetKittyFilesElsewhere`).

### The cell-diff prototype (`celldiff/`, `results/celldiff.md`)

The wire format has a handful of ops: reset styles, define a style, resize,
scroll up n rows, replace a run of cells in a row, cursor, and title.
Styles are interned to small ids, and rows are compared by a cached 64-bit
hash. The client applies the ops to a cell grid and **has no VT parser**.

**Hardened after the review.** The first version's decoder crashed on
malformed input: the review found five panics, and a truncated frame that
was accepted as success. The `FuzzApply` target had never been run. Now:

- Every varint is bounded before it becomes an int: rows and columns
  against the current frame, run lengths against the row, cell text to
  64 bytes, style ids to the defined table, the cursor to the screen.
- Ops before the first resize are refused, a zero-length run is refused
  (it was an infinite loop), and a truncated diff is an error.
- The whole diff is parsed and validated before any of it is applied, so
  after any error the client state is exactly as it was.
- Style ids are dense (a new id must equal the table size). The table is
  capped at 65,536 styles and 1 MiB of link text on both ends, and the
  server resets both tables when they are three-quarters full (op `X`,
  which also blanks the client's cells). A program that shows more than
  65,535 distinct styles at once gets the default style on the rest.
- `celldiff/hostile_test.go` replays every probe from the review, plus
  about twenty more, and checks that each is refused without changing the
  state. The fuzzing table above has the `FuzzApply` and `FuzzRoundTrip`
  results.

**The allow-list (D9).** `celldiff/allow.go`. The server enforces it in
`Snapshot`, and the client checks it again in `Apply`:

| field | rule |
|---|---|
| title | valid UTF-8; C0, DEL and C1 (U+0080-U+009F) removed; at most 256 bytes, cut on a rune boundary |
| OSC 8 URI | printable ASCII only (no controls or spaces; IRIs must be percent-encoded); at most 2048 bytes; scheme `http`, `https` or `mailto`. Otherwise the link is dropped and the text kept. |
| cell text | valid UTF-8, no C0, DEL or C1, at most 64 bytes; otherwise U+FFFD |

tuios keeps C1 controls and DEL in titles. All three of the review's probes
(`"a\u009d0;evil\u009cb"`, `"a\u009b2Jb"`, `"a\x7fb"`) reached the old
prototype's title unchanged. They are now tests on both sides
(`TestAllowListServer`, `TestApplyHostile`).

Three checks confirm that the client's frame equals the server's after
every diff: a 3,000-step randomised round trip, `FuzzRoundTrip`, and a
replay of every recorded program.

**Diff size against raw bytes, for every stream.** The recordings have no
timing, so a frame was taken every 1 KiB of output. Real SSP frames, 20-250
ms apart, coalesce far more. These ratios are only an input for S5 to redo
with its simulator's frame timing, and O8 should take its numbers from that
rerun, not from here.

| stream | raw bytes | diff bytes | diff/raw | diff bytes, each frame deflated | mean time to snapshot and diff (tuios), median [range] of 3 runs |
|---|---|---|---|---|---|
| claude | 6,021 | 7,896 | **1.31** | 2,543 | 160 µs [148-204] |
| fish | 2,646 | 1,438 | **0.54** | 763 | 138 µs [138-187] |
| htop | 34,849 | 48,139 | **1.38** | 13,383 | 238 µs [229-272] |
| less | 8,908 | 9,945 | **1.12** | 4,070 | 162 µs [142-171] |
| synth-seq100k | 688,895 | 199,877 | **0.29** | 69,115 | 96 µs [96-113] |
| synth-top200x60 | 3,252,000 | 1,629,772 | **0.50** | 446,253 | 574 µs [573-579] |
| unicode | 1,073 | 1,684 | **1.57** | 1,003 | 122 µs [95-147] |
| vim | 14,865 | 19,299 | **1.30** | 7,580 | 115 µs [107-148] |
| zsh | 23,259 | 16,652 | **0.72** | 6,713 | 98 µs [92-122] |

The deflated column compresses the diffs only; the raw stream would compress too, so it is not a like-for-like ratio. Diff sizes didn't change when the decoder and allow-list were hardened.

- For **most real-program streams the diff is larger than the raw bytes**
  at this cadence: claude, htop, less, the Unicode file and vim come out
  1.1-1.6x. Only fish, zsh and the synthetic floods come out smaller. A
  program that repaints a little at a time sends only a few bytes per
  change, while a cell diff restates whole runs. Coalescing at SSP frame
  rates should change this, but that hasn't been measured yet.
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
case), three times each on a nearly idle machine (load average about 2), median of the three:

| workload (tuios) | in-process p50 / p99 | helper p50 / p99 | added at p50 (each run) | CPU per round, in-process / helper |
|---|---|---|---|---|
| keystroke echo (11-byte diff) | 89 / 223 µs | 95 / 227 µs | **+6 µs** (5, 6, 6) | 112 / 122 µs |
| one line of output (75 B) | 95 / 243 µs | 102 / 263 µs | **+7 µs** (7, 8, 6) | 148 / 160 µs |
| 200x60 redraw (3.2 KB diff) | 670 / 1170 µs | 695 / 1245 µs | **+24 µs** (28, 24, 24) | 878 / 926 µs |

The first version measured +27 / +6 / +166 µs at p50 with the machine at load 12-37; on a quiet machine the boundary costs less.

The boundary adds 6-28 µs per round at the median. Against SSP's 8 ms
collection window and frames at least 20 ms apart, that's **noise**.
libghostty is about 1.3-1.8x slower per round than tuios here, because
reading cells through cgo costs more than the parsing does.

**Run the emulator in the sandboxed helper either way**, as O3 proposed.

## What to contribute upstream (tuios.dev/vt)

1. **Bound history memory.** Cap the OSC 8 URI length (2 KiB is generous),
   intern URIs instead of storing one per cell, and offer a history budget
   in bytes or cells as well as lines. Today a program can make one history
   cell cost as much as the URI it sends, up to 4 MiB.
2. **Damage tracking** on the `Terminal` interface: per-row dirty flags or a
   per-row generation number, on both backends. libghostty already has
   dirty rows in its render state. This turns a read of the whole screen
   every frame into a read of only what changed.
3. **The ghostty backend loses background-colour erase.** After
   `ESC[42m ESC[K`, the pure backend, every other candidate and libghostty
   read directly all report a green background on the erased cells, but
   tuios' ghostty `CellAt` reports the default colour (`emu/bce_test.go`).
   libghostty stores these as background-only cells, and the binding drops
   them.
4. **Strip C0, C1 and DEL from titles**, including what `Title` callbacks
   receive. mosey filters anyway, but other hosts re-emit titles too.
5. **Make full-screen scrolling cheaper at large sizes.** At 1000x500, REP
   65535 repeated costs about 3 ms per sequence (0.1 ms at 80x24), and a
   flood of lines runs at 13 MB/s (51 MB/s at 80x24). The cost looks
   proportional to the screen size. libghostty did the REP case in a
   thirtieth of the time.
6. **DECCOLM** should clear the screen and home the cursor (vttest 1.3).
   There should also be an option never to change the column count, which
   is what mosey wants.
7. **A size guard on resize.** 5000x5000 cost 2.9 GiB in tuios, about
   112 bytes per cell. mosey clamps the client's size anyway, but the
   library should refuse absurd sizes.
8. **Say when replies are dropped.** `TakeResponses` silently drops
   everything past 4 MiB; a counter or a callback would let a host log it.
9. **A smaller dependency tree.** The headless emulator pulls in six
   terminal-I/O modules through ultraviolet (x/term, x/termios, x/windows,
   cancelreader, terminfo, colorprofile). Fix it with either a leaf package
   in ultraviolet for `Cell`, `Style` and `Link`, or types that tuios owns.
10. Our fuzz invariants and seeds (`fuzz/fuzz_test.go`, `fuzz/clamp_test.go`)
    as extra fuzz targets, and the hostile-input battery as a benchmark
    suite.
11. Faster scrollback: 51 MB/s when flooding 200-column lines, against
    libghostty's 145 MB/s. Profile the path that pushes lines into history.

Courtesy bug reports for the other emulators, which mosey doesn't need:

- charm: the REP hang and the blocking reply pipe.
- xterm-go: the REP CPU burn, the wide-character panic, and the panic in
  the clamp-sized resize storm.
- cy: the OSC panic and the integer overflows.

## Notes for D9 (not decisions)

- **The window size is untrusted input.** Clamp the client's requested
  size on the server before the emulator's `Resize` (proposed 1000 x 500),
  and refuse larger sizes in the client decoder too.
- **Budget history in cells.** On every resize, set tuios' line cap from
  the width: lines = min(10,000, cell budget / cols), with a proposed
  budget of 1,000,000 cells (about 100 MiB worst case without links).
- **Put the session helper in a memory cgroup** (`MemoryMax`, proposed
  512 MiB) and give it a CPU quota. Until tuios bounds link storage, the
  cgroup is the only ceiling on what OSC 8 links can cost. This is a
  requirement on O4's helper, not an option.
- **The reply path must not block the reader.** Replies to the program go
  through a bounded queue to a separate writer. 64 KiB is plenty, because a
  well-behaved program's replies are tens of bytes. When the program isn't
  reading, replies are dropped and counted. Keystrokes from the client
  share the writer and go ahead of replies. A program that never reads its
  input can then stall only its own input, never the output path.
- **The allow-list** is the table in the cell-diff section, and both ends
  enforce it. Whether to allow `file:` links, bidi controls in titles
  (U+202A-U+202E, U+2066-U+2069) and OSC 52 are open questions for Dan.
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
  belong in the state; the prototype doesn't carry them yet.
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

- **D9**: server-side emulation, with a client that has no VT parser. The
  review's findings (a crashing decoder, an unfiltered title) were bugs in
  this prototype, not in the decision. They show why D9's allow-list has
  to be specified and tested on both ends.
- **D19**: an existing emulator is good enough, and nothing here needs us to
  write our own.
- **D1**: the recommended backend is pure Go, so static builds stay simple.
  libghostty would have made D1 harder, though not impossible.

## Not done, bounded or unmeasured

- Fuzzing ran for 20 minutes per candidate on a shared machine, plus
  another 20 in recover mode for the three that failed, plus the three
  review targets above. The plan asks for hours. libghostty's own AFL++
  harnesses (`test/fuzz-libghostty`) weren't run, so libghostty counts as
  not meaningfully fuzzed.
- There was no real xterm or VT hardware to act as an oracle. The
  references are libghostty read directly, tmux and xterm-go. They are
  independent of each other, but none of them is ground truth.
- The app recordings were made with tuios' libghostty binding answering
  queries. They weren't re-recorded with ghosttyd answering.
- The app recordings have no timing, so the diff sizes use a fixed 1 KiB
  frame rather than SSP's timing. S5 can redo this with the simulator.
- The machine was never idle. Other spikes' fuzzers kept the load average
  between 12 and 58 for every run, including the reruns. Throughput is now
  reported as the median and range of several runs, with CPU-time rates
  beside wall-clock ones, but absolute numbers would be higher on an idle
  machine.
- The worst-case memory table measured 2,000 history lines and derives the
  10,000-line columns linearly.
- The hostile battery at the clamp size was run for tuios and libghostty
  only. The four new cases were also run at 80x24 for every candidate.
- The claude recording ran Dan's real `claude` wrapper. HOME pointed at a
  scratch directory, but the wrapper still found the account and showed the
  logged-in TUI. The script only opened it, pressed Down twice and Ctrl-C
  twice, and sent no prompt. Recording claude is now opt-in (`-only claude`).
  The htop and claude recordings are not committed; vim, less, zsh, fish
  and the Unicode file are.
- Sixel and kitty images weren't tested for correctness, only for resource
  limits.
- The emulator wasn't tested under Landlock or seccomp; that's S4.
- The allow-list doesn't yet decide on bidi controls in titles, `file:`
  links or OSC 52.

## Review response

An adversarial review raised 13 issues. Each is listed below with what was
done about it.

1. **(major) The client decoder crashed on malformed input, and `FuzzApply`
   had never run.** Fixed. `Apply` was rewritten (see "The cell-diff
   prototype"), and every probe from the review is now a test that must be
   refused without changing state. On its first run, `FuzzApply` found one
   more bug within a second: an `X` (style reset) left cells pointing at
   styles that no longer existed. `X` now blanks the cells too, and the
   input is kept as a regression seed (`celldiff/testdata/fuzz/FuzzApply/`).
   After the fix it ran for 15 minutes (2.4 M execs) with no finding.
2. **(major) No allow-list on the title; C1 controls reached the client.**
   Fixed. The allow-list is specified and enforced on both ends (table
   above), and it covers OSC 8 schemes and cell text too. The review's
   probes are tests on both sides. The comment that claimed the title was
   "already allow-listed" is gone.
3. **(major) The 1.2 MiB per session figure came from cheap 80x24 cells.**
   Fixed. The new section "Worst-case memory per session" measures about
   100 B per history cell without links, and no ceiling with links (each
   cell costs up to its URI's length). It proposes a clamp (1000 x 500), a
   cell budget for history and a 512 MiB cgroup limit, with the reasoning,
   and the hostile battery was rerun at the clamp. The recommendation now
   says tuios has no hard memory ceiling of its own, and that libghostty
   bounds link storage better.
4. **(minor) The reply path was never tested on a pty.** Fixed.
   `cmd/replyflood` shows the naive design deadlocking in 0.2 s and the
   split design with a bounded queue completing. The requirement is in the
   D9 notes, and tuios' silent 4 MiB drop is on the upstream list.
5. **(minor) Fuzz invariants didn't cover memory or sizes above 200x100.**
   Fixed. `FuzzTuiosClamp` resizes up to the clamp and checks the heap, and
   libghostty is now described as not meaningfully fuzzed.
6. **(minor) The window size is not host-controlled.** Agreed and fixed:
   it's input from an untrusted peer. The server clamps it
   (`celldiff.ClampSize`, 1000 x 500) before `Resize`, and the client
   refuses larger sizes. It used to accept 4096 x 4096.
7. **(major) "1 Gbit/s costs a quarter of a core" was wrong by about 7x.**
   Corrected in the perf section (1.7-1.8 cores per Gbit/s, from
   CPU-time measurements). It now also explains why the per-session CPU
   cap is about fairness rather than about queueing.
8. **(major) The libghostty reference ran through tuios' own adapter.**
   Fixed. `ghosttyd` reads libghostty's render state directly, with no
   tuios code, and vttest and every app replay were re-scored against it.
   The vttest core scores didn't change. tuios' attribute score on the
   apps went from 35/42 to 40/42, because the five htop "misses" were the
   binding's background-colour-erase bug. Text and attribute scores are
   now reported side by side, with xterm-go as a second independent
   comparison. The recordings themselves were still made with the binding
   answering queries, and the text says so where it matters.
9. **(major) No program recordings were committed.** Fixed for vim, less,
   zsh, fish and the Unicode file (`spikes/s2-terminal/fixtures/rec/`, with
   the replayed screens in `results/apps-replay/`). The htop recording
   (process list) and the claude recording (an account's TUI) are
   deliberately not committed, and the text now says which numbers can't be
   reproduced from the repo.
10. **(minor) The tuios vs xterm-go speed ranking was a load artefact.**
    Agreed. perf, boundary and the cell-diff timings were rerun with
    repetitions, interleaved, reporting the median and range, and the perf
    table adds CPU-time rates. On a nearly idle machine, xterm-go is faster than tuios on plain and SGR-heavy text (84 and 87 against 75 and 73 MB per CPU-second), and tuios is twice as fast on the recorded programs (71 against 34). Parse speed is no longer listed
    as a reason for tuios.
11. **(minor) Hostile timeouts were scored inconsistently.** Fixed. The
    scoring rule (ok / degraded / fail) is stated, and libghostty's
    alt-screen case is marked degraded.
12. **(minor) The cell-diff summary picked favourable streams.** Fixed.
    Every stream's diff/raw is in the table, the text says most real
    programs come out larger than raw at this cadence, and it says O8
    should wait for S5's rerun with SSP timing.
13. **(minor) The vttest core set kept m1-03, although it depends on
    DECCOLM.** Fixed. DECCOLM screens are now chosen from what vttest sent
    (`scripts/deccolm-screens.py`), which moves 19 screens out of the core
    set (the old rule moved 13). Restated core score: tuios 36/36.
