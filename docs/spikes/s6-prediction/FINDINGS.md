# Spike S6: predictive local echo, findings

Spike record for PLAN D12. The spec is in `prediction-spec.md` and the code
in `spikes/s6-prediction/`. Raw tables are in `results/` (one file per
network profile, plus `heldout.md`). Every number below was measured by the
replay harness on recorded traces, unless it is marked *black-box*. Nothing
was taken from Mosh source (PLAN §4).

## 0. Summary

- **Headline** (9 traces, 3 network seeds; "instant" means the right glyph
  and cursor were on screen at the keystroke):

  | Profile | paper + strict choices | paper, permissive | mosey (gate) | mosey + rebase |
  |---|---|---|---|---|
  | LAN 5 ms | 42.8 % / 0.4 % wrong | 54.0 % / 2.4 % | **79.8 % / 0.1 %** | 79.8 % / 0.1 % |
  | Wi-Fi 30 ms, 1 % loss | 42.3 % / 0.5 % | 53.3 % / 3.3 % | 79.0 % / 0.1 % | 79.1 % / 0.1 % |
  | Transatlantic 100 ms | 41.1 % / 1.3 % | 51.2 % / 6.3 % | 76.6 % / 0.1 % | 76.9 % / 0.1 % |
  | 100 ms, 29 % loss | 39.0 % / 1.4 % | 48.7 % / 8.4 % | 73.4 % / 0.2 % | 74.0 % / 0.2 % |
  | Train 250 ms ±150, 10 % burst loss | 23.5 % / 0.3 % | 26.7 % / 10.9 % | 47.2 % / 0.4 % | **62.9 % / 0.4 %** |
  | EV-DO 450 ms ±100, 1 % loss | 20.8 % / 0.3 % | 22.9 % / 10.1 % | 41.2 % / 0.3 % | **62.4 % / 0.3 %** |

  Of mosey's instant keystrokes, 4.3–4.7 % of all keys (5.2–5.6 % with
  rebase) were **row-stale**: the typed glyph and cursor were right, but
  some other cell on the cursor row was not yet what the application would
  draw (§4.3). Counting those as not instant, mosey is 75.5 % at 5 ms and
  72.1 % at 100 ms.
- **Recommendation:** the `mosey` design with **rebase** recovery. It keeps
  the paper's epochs and server echo ack and adds the changes in §4.2.
  Rebase is the one item that goes past D12's "not game-style" wording
  (decision 2).
- The review found real problems. All are now fixed and measured:
  - a password glyph could be drawn in the clear at fish's masked prompt
    (§5);
  - the colour heuristic for autosuggestions failed completely on a
    non-default theme (§7);
  - the paper's echo-ack-only frame tags password keystrokes on the wire
    (§6);
  - the replay was nondeterministic.

  The first draft's display thresholds had no derivation. They were
  replaced by a black-box measurement of `mosh-client` (§3).

## 1. What was built

| Piece | What |
|---|---|
| `predict/` | The engine, written from the spec, with three recovery modes (blind, gate, rebase), unit tests and `FuzzEngine`. |
| `cmd/record/` | Drives a real program in a pty with a scripted typist: log-normal gaps, typos fixed with backspace, word pauses, IME-style commits for CJK and emoji. It records every pty read as a screen via `charmbracelet/x/vt`, a third-party emulator that D19 allows. It also records the pty's termios echo-off state (`tcgetattr` on the master) and faketui's own insertion point. |
| `cmd/faketui/` | An Ink-style TUI (box, placeholder, slash menu, streamed reply) with a drawn or a real cursor. It reports its true insertion point as a private OSC, which the recorder strips. |
| `sim/` | A discrete-event network and SSP sender model with deterministic seeds (§2). |
| `cmd/replay/` | Runs traces × profiles × variants and prints the tables in `results/`. |
| `cmd/moshprobe/`, `scripts/moshprobe.sh` | A black-box sweep of the installed `mosh-client` (§3). |
| `cmd/ghosteval/`, `cmd/cursorcheck/` | Measure the decoration and cursor heuristics against ground truth (§7, §8). |

The traces are in `spikes/s6-prediction/traces/`, recorded on 2026-11-13
with 3 script rounds, 9,544 keystrokes in total:

- bash;
- zsh-plain;
- zsh-full (zsh-autosuggestions, zsh-syntax-highlighting, right prompt,
  transient prompt);
- fish (defaults plus right prompt and transient prompt);
- vim;
- less;
- real **Claude Code** v2.1.319;
- faketui with a drawn cursor;
- faketui with a real cursor.

The shell script covers typing, typos, backspace, left/right editing, Tab
completion (unique, ambiguous, and fish's pager), history recall,
Ctrl-U/Ctrl-C, accepting suggestions with Right, a line that wraps, wide
characters and emoji, and a `read -s` password prompt. The held-out traces
in `traces-heldout/` are zsh and fish with Solarized true-colour themes.
They were not used for tuning before §7.

Claude Code was run with a sandbox HOME and a dummy API key. The script
only edits text in the prompt box and **never presses Enter**, so nothing
was sent to a model. It still started up signed in as Dan's account
("Claude Max" in its header), because the binary found credentials outside
the sandbox HOME.

## 2. Method, and what the simulator approximates

For each keystroke the replay asks two questions. At the moment of the key,
did the client draw a prediction for it? And did that prediction (glyph
cells and cursor) match the screen the application settled on before the
next key? That gives the paper's two metrics:

- **instant**: shown and right;
- **wrong**: shown and not right.

**Time to correct** is how long a wrong glyph stayed on screen. **Visible
kills** counts, per run, refutations of an epoch that was on screen.

The cursor is judged against the terminal cursor. For faketui it is judged
against the application's own insertion point. It is never judged against
the engine's reverse-cell heuristic; the first draft did that, which was
circular.

The network model is the spike's own, because S5's simulator was not
available. It has:

- a fixed base RTT, split evenly between the two directions;
- uniform jitter;
- i.i.d. or Gilbert-Elliott loss;
- an SSP sender with D11's constants: frame interval SRTT/2 clamped to
  20–250 ms, 8 ms collection, 100 ms delayed ack, RFC 6298 RTO with a 50 ms
  floor.

The server's echo ack follows the paper's 50 ms rule.

Approximations:

1. **Open loop.** The application is not re-run. When a key reaches the
   simulated server late, the recorded screens that followed that key are
   replayed with the same relative timing. A real application would behave
   differently in two cases:
   - keys arrive in a batch, so it draws one redraw instead of several;
   - it redraws asynchronously; zsh-autosuggestions and fish compute
     suggestions in the background.

   So the replay is accurate for what the client is shown, but not for how
   the application would have behaved under that delivery. A live check was
   **not done** (feeding the real program keys at the simulated delivery
   times and comparing screens).
2. Keys are delivered one event per keystroke, as the typist wrote them.
   Real terminals sometimes coalesce reads.
3. There is no reordering, no MTU effect, and no outage longer than a loss
   burst.
4. The SRTT given to the engine is fixed per profile.
5. The tables use `DisplayAlways`, so every keystroke counts.

The replay is now **deterministic**. The old variation came from iterating
a Go map of predictions; the engine now iterates in (seq, row, column)
order. Three runs of `paper-strict,mosey` on EV-DO gave byte-identical
output (same md5), and `sim/sim_test.go` asserts it.

## 3. Display thresholds: a black-box measurement of mosh-client

The paper gives no numbers for when predictions are shown or underlined.
The first draft used 30 ms and 80 ms with no derivation. A reviewer pointed
out that they may have been recalled from Mosh's source, so they were
removed and measured instead.

`scripts/moshprobe.sh` runs the test like this:

- run `mosh-server` and `mosh-client` on loopback, inside a throwaway user
  and network namespace (`unshare -rn`);
- add `tc netem delay D` on `lo`, so RTT = 2D;
- after a 4 s warm-up, type 25 letters 400 ms apart;
- watch the client's screen through a vt emulator. A glyph that appears in
  less than one RTT was predicted.

| netem RTT (ms) | 4–32 | 34 | 36 | 38 | 40–90 | 92 | 94 | 96 | 98 | 100–150 |
|---|---|---|---|---|---|---|---|---|---|---|
| keys predicted /25 | 0 | 13* | 1, 15* | 25* | 25 | 25 | 25 | 25 | 25 | 25 |
| keys underlined /25 | 0 | 0 | 0 | 0 | 0 | 15* | 16* | 19* | 25* | 25 |

(*) These runs were taken while a fuzzer loaded the CPU. The load adds a
few ms to mosh's RTT estimate and moves the transition down by about 2 ms.
Without prediction, echo took RTT + ~10 ms (45.6 ms at 36 ms). The partial
counts show mosh's estimate hovering at its threshold. Hysteresis was not
probed.

So mosh-client starts showing predictions at a netem RTT of about 36–40 ms
and underlines them from about 92–100 ms. Mosh's internal SRTT cannot be
observed, so these figures are netem RTTs, not mosh's own thresholds.
Mosey's defaults are now **show at SRTT ≥ 38 ms, underline at ≥ 95 ms**.
`Mosey()` labels them with this provenance, and they are no longer in the
paper baselines. They should be re-tuned against S5's SRTT estimator. The
sweeps took about 7 min for 21 delays, then about 2.5 min for 7 more.

## 4. Results

### 4.1 Ablations (all traces, three seeds)

Each row changes one thing from `mosey`. Each cell gives
instant % / wrong % / row-stale % / visible kills per run.

| Variant | 100 ms | 450 ms (EV-DO) |
|---|---|---|
| `mosey` | 76.6 / 0.1 / 4.5 / 15 | 41.2 / 0.3 / 4.5 / 5 |
| `+rebase` | 76.9 / 0.1 / 4.5 / 14 | 62.4 / 0.3 / 5.6 / 8 |
| `-blind` (paper's background predictions) | 76.6 / 0.1 / 4.5 / 15 | 43.3 / 0.5 / 4.6 / 13 |
| `-decoration` (no autosuggestion handling) | 56.5 / 3.5 / 0.1 / 238 | 25.1 / 10.6 / 0.8 / 83 |
| `+ghostcolour` (colour heuristic as well) | 77.3 / 0.1 / 4.5 / 13 | 41.2 / 0.3 / 4.5 / 5 |
| `-stylebreak+ghostcolour` (the first draft's design) | 77.5 / 0.1 / 3.0 / 11 | 41.4 / 0.1 / 3.2 / 2 |
| `-shiftrow` (whole-row ICH shift) | 41.9 / 0.2 / 0.1 / 216 | 22.6 / 0.0 / 0.3 / 10 |
| `-shiftnone` (cursor cell only) | 75.1 / 0.4 / 6.5 / 27 | 40.7 / 0.3 / 5.1 / 4 |
| `+stylestrict` (rendition must match) | 59.1 / 0.1 / 2.2 / 84 | 26.3 / 0.1 / 1.4 / 8 |
| `-horizon` | 76.6 / 0.1 / 4.5 / 18 | 41.2 / 0.3 / 4.5 / 38 |
| `+wrap` (predict across the margin) | 76.7 / 0.4 / 4.5 / 29 | 41.3 / 0.5 / 4.5 / 13 |
| `-wide` | 73.8 / 0.1 / 4.4 / 15 | 38.3 / 0.3 / 4.4 / 5 |
| `-bsguard` | 76.7 / 0.2 / 4.5 / 18 | 41.2 / 0.3 / 4.5 / 5 |
| `-fakecursor` | 71.4 / 0.1 / 4.3 / 12 | 39.0 / 0.3 / 4.5 / 4 |
| `-informative` (any match confirms) | 78.7 / 0.2 / 4.6 / 44 | 41.4 / 0.3 / 4.5 / 10 |
| `+bsconfirm` | 77.0 / 0.2 / 4.5 / 18 | 41.2 / 0.3 / 4.5 / 7 |
| `-echooff` | same as `mosey` on these traces (§5) | same |

Neither paper baseline is "the paper's design"; each resolves the paper's
silences a different way:

- **`paper-strict`** ("paper + strict choices") adds two choices the paper
  never makes: rendition must match to confirm, and the whole row shifts.
- **`paper-permissive`** goes the other way: glyph-only confirmation,
  text-run shift, blind recovery, and any match confirms.

On bash, zsh-plain and vim, which resemble the 2012 traces, the permissive
reading gets 76–79 % instant / 0.3–0.4 % wrong at 100 ms. That is close to
the paper's 70 % / 0.9 %. Its 6.3 % aggregate wrong rate comes from:

- autosuggestions: 13.7 % wrong in fish, 19.7 % in zsh-full;
- the TUI with a real cursor: 1.6 % wrong (14.5 % at 450 ms).

### 4.2 What changed from the paper, and why (each is an ablation above)

- **Decoration rule** (§7). Without it, autosuggestions make 10.6 % of keys
  wrong at 450 ms.
- **Glyph-only confirmation.** Syntax highlighting recolours words as they
  are typed, so requiring a rendition match drops instant from 76.6 % to
  59.1 %.
- **Text-run shift**, ending at 3 blanks or at a decoration. Shifting the
  whole row drops instant to 41.9 %.
- **Informative-only confirmation.** Only a typed glyph that changes its
  cell can confirm an epoch. Without this rule visible kills triple
  (15 → 44), and a password glyph leaks at fish's prompt (§5).
- **Gate or rebase recovery**, instead of blind background prediction.
  Blind roughly doubles visible kills on long links.
- **Ack horizon**, restated as the review asked. It does not change instant
  or wrong on any profile. What it does: after Enter (or another
  unpredictable key), a frame can arrive showing a redrawn line. Without
  the horizon, that frame judges predictions that were already correct as
  wrong, and they flicker off. Visible kills without and with it:

  | Profile | without | with |
  |---|---|---|
  | 450 ms | 38 | 5 |
  | train | 55 | 9 |
  | 100 ms with 29 % loss | 59 | 17 |
  | 100 ms | 18 | 15 |
  | LAN | 11 | 10 |

  At 450 ms the removed kills come from bash (7), zsh-plain (6), zsh-full
  (10), fish (10) and Claude Code (3). The effect is not specific to
  transient prompts, as the first draft claimed.
- **No prediction across the right margin.** Allowing it adds wrong
  predictions (0.1 → 0.4 %) and gains nothing.
- **Wide characters.** Predicting them adds about 3 points on these traces,
  which contain CJK and emoji.

### 4.3 Row-stale

A row-stale keystroke has the typed glyph and cursor right, but some other
cell on the cursor row is not yet what the application will draw. Cases
seen:

- a mid-line insert in a syntax-highlighted line, where the shift stops at
  the next differently-coloured token;
- an autosuggestion suffix the shell is about to change;
- Claude Code's prompt row: 17–18 % of its keys. The cause was not
  diagnosed further.

The user sees the right glyph at the cursor, and old text further along the
row until the frame arrives. The headline counts row-stale keys as instant,
because the paper's metric is about the typed key. Both figures are in §0,
and every table has a `row-stale` column.

### 4.4 Recovery: gate vs rebase

Gate and rebase predict the same keys when the RTT is shorter than the gap
between keys. On long links, gate stops predicting after every
unpredictable key until a frame shows that the server has every key, and a
fast typist never pauses that long. Rebase fixes this. Instant at 450 ms:

| Trace | gate | rebase |
|---|---|---|
| All | 41.2 % | 62.4 % |
| vim | 2.1 % | 52.9 % |
| less | 0 % | 17.5 % |
| faketui | 36 % | 77 % |
| Claude Code | 60 % | 76 % |

On the train profile, instant rises from 47.2 % to 62.9 %. Wrong does not
change (0.3 % and 0.4 %). Rebase never replays a log with holes: if an
input was evicted from the log, or was a paste or an echo-off key, it falls
back to gate.

### 4.5 Time to correct

Mosey makes too few wrong predictions for a good sample. At 100 ms the
median is 164 ms (35 wrong keys in 32 correction events). At 450 ms the
median is 225 ms and the p95 765 ms (69 keys in 61 events). The permissive
paper baseline makes many more wrong predictions, and they are corrected by
the same mechanism. In this table, n counts wrong keystrokes and events
counts distinct corrections:

| Profile | median / p95 ms | n keys / events |
|---|---|---|
| LAN 5 ms | 63 / 64 | 571 / 568 |
| Wi-Fi 30 ms | 101 / 114 | 791 / 769 |
| 100 ms | 161 / 220 | 1535 / 1466 |
| 100 ms, 29 % loss | 158 / 395 | 2043 / 1932 |
| Train 250 ms | 212 / 629 | 2635 / 2525 |
| EV-DO 450 ms | 216 / 800 | 2454 / 2310 |

On links up to 100 ms, the median is about **RTT + 60 ms**: the 50 ms
echo-ack wait plus collection and pacing. On long links the median is
*less* than one RTT, because the refuting frame is usually already in
flight when the wrong glyph is drawn. The p95 is about RTT + 350 ms. The
first draft's "one round trip plus 50 ms (456 ms)" rested on about 4 events
and is withdrawn.

## 5. Passwords

Two protections, measured separately:

1. **The echo-off bit.** The recorder showed that on Linux, `tcgetattr` on
   a pty master reports the slave's `ECHO` and `ICANON` flags. The bit is
   `!ECHO && ICANON`.
   - bash and zsh `read -s` (52 and 46 keys in the traces) run in canonical
     mode with echo off, like passwd, sudo and ssh prompts. The bit covers
     them.
   - vim, readline and Ink clear ICANON, so the bit does not disable
     prediction in them.
   - fish's `read -s` runs in raw mode and draws `●`, so the bit does
     **not** cover it (45 keys).
2. **The epoch rules.** Tentative epochs are hidden, and only a typed glyph
   can confirm an epoch.

Results, as secret keys shown / secret keys (counting non-blank predicted
cells only, 3 seeds):

- **`mosey`, `mosey+rebase` and every other variant with the informative
  rule: 0 / 555 on every profile.** `sim/sim_test.go` asserts this for
  bash, zsh-plain, zsh-full and fish at 5 ms, at 100 ms with 29 % loss, and
  at 450 ms, for both gate and rebase.
- **`mosey+bsconfirm` and `mosey-informative`: 3–11 / 555, all in fish.**
  This was a real leak, and the first draft had it. In those variants a
  backspace can confirm an epoch:
  1. the user presses backspace to remove a `●`, which empties a cell;
  2. the server's frame shows the emptied cell, so the prediction matches
     and confirms the epoch;
  3. the next password letter is then drawn in the clear for about one
     round trip.

  The first draft never noticed, because it had no password metric and its
  zsh traces had a bug (see below). Fixed: backspace no longer confirms an
  epoch.
- **`-echooff`: no change on these traces.** The bit guards against a
  coincidence that did not happen in them: something else drawing the
  predicted glyph at the cursor. `TestEchoOffCoincidentalMatch` builds that
  case: type-ahead at a no-echo prompt, then `wall` writes the same letter.
  Without the bit, the next password key is drawn; with it, nothing is.
  While echo-off is set the engine also logs nothing, so rebase never
  replays password bytes.

**Scenario bug found.** In the first draft's zsh traces, `read -s -p 'pw: '`
failed with "-p: no coprocess", because zsh expects the prompt after `?`.
The "password" was typed at a normal prompt and run as a command. The zsh
traces were re-recorded with `read -s 'pw?pw: '`.

Not covered: a password field that a raw-mode TUI draws itself, with no mask
and no echo. There the epoch rules are the only protection.

## 6. Keystroke timing (D4 threat model)

About 50 ms after each keystroke, the paper's server sends an extra frame
to report a new echo ack, even when the screen has not changed. An on-path
observer can match these replies to the client's keystrokes, including at
no-echo prompts (Song et al. 2001; this is also the reason for OpenSSH 9.5's
`ObscureKeystrokeTiming`). Measured echo-ack-only frames per run-set of 9
traces, with those sent while echo-off in brackets:

| Server mode | frames at 100 ms (echo-off) | instant at 5 / 30 / 100 / 450 ms |
|---|---|---|
| extra frame (paper) | 7669 (129) | 79.8 / 79.0 / 76.6 / 41.2 |
| no extra frame while echo-off (**adopted**) | 7549 (9) | 79.8 / 79.3 / 76.9 / 41.2 |
| piggyback only (no extra frames at all) | 1 (0) | 72.8 / 72.5 / 71.0 / 41.5 |

The 9 remaining echo-off frames are sent at the edges of the prompt, where
the state changes.

- Suppressing the extra frames while echo-off costs nothing.
- Dropping them altogether costs 5–7 points of instant on links up to
  100 ms: after a pause, the first keys' epoch has to wait for the next
  screen change to be confirmed.

Neither option hides client-to-server timing, because D11 sends every
keystroke as its own datagram. Hiding that needs chaff in SSP: packets at a
fixed interval while the user types, as OpenSSH 9.5 does. S5 should measure
it. See decision 1.

## 7. Modern shells: what breaks prediction, and the fixes

| Feature | What breaks | Fix | Evidence |
|---|---|---|---|
| Autosuggestions (zsh-autosuggestions, fish) | A naive insert shifts the grey suggestion right while the shell keeps it in place, so the epoch dies, or garbage is shown once it is confirmed. Right-arrow accepts the suggestion instead of moving the cursor. | Decoration rule (spec §8.1): the shifted run stops at a change of rendition. Right-arrow is unpredictable over a decoration. A predicted blank that meets a new suggestion is dropped, not judged. | `-decoration`: 10.6 % wrong at 450 ms (fish 28 %, zsh-full 20 %). |
| Syntax highlighting | Every word changes colour as it is typed, so a rendition-strict check refutes the epoch. | Glyph-only confirmation. | `+stylestrict` at 100 ms: fish 77 → 17 %, zsh-full 72 → 35 % instant. |
| Right prompts | A whole-row shift pushes the clock or user@host along. | Text-run shift, ending at 3 blanks or at a decoration. | `-shiftrow`: 41.9 % instant. |
| Transient prompts | Enter rewrites the finished line. | Enter starts a new epoch. The ack horizon drops predictions for the old line without counting them wrong. | §4.2. |
| fish pager, zsh menu-select, Tab | The completion UI redraws everything. | Tab and arrows are unpredictable; gate or rebase restarts prediction afterwards. | Wrong ≤ 0.8 % in fish with `mosey`. |
| Masked password prompt (fish) | Backspace confirms the epoch, and the next letter leaks. | Only typed glyphs confirm. | §5. |
| Soft-wrapped input boxes (Claude Code) | The app wraps a word onto the next line before the right margin. | Not fixed. It is also the paper's main error source. | 18 of 1,770 Claude Code keys at 100 ms (§8). |

**Held-out result.** The first draft detected autosuggestions by colour: a
cell counted as a suggestion if it was faint, palette 8 or 238–246, or a
true-colour grey with spread < 24.

- On the default-colour traces, `ghosteval` scores it 100 % precision and
  recall. (Ground truth there is palette 8, which also includes the right
  prompt.)
- On the Solarized held-out traces (autosuggestion `#586e75`, spread 29),
  its **recall is 0 %**.
- Replaying that design on the held-out traces gives 17.5 % instant /
  9.9 % wrong at 100 ms, and 4.1 % / 23.7 % at 450 ms.

The rendition-change rule replaced it. On the held-out traces it gets
75.9 % / 0.1 % at 100 ms and 43.9 % / 0.4 % at 450 ms. On the development
traces it costs about 1 point of instant and 1.5 points of row-stale
compared with the colour rule (§4.1).

**Caveat:** the rule was designed *after* seeing the held-out failure, so
these traces are no longer an unbiased test of it. The fallback, if the
rule fails on some future theme, is the cursor-cell-only model
(`-shiftnone`). It needs no decoration detection and gets 71.7 % / 0.3 % at
100 ms and 42.5 % / 0.4 % at 450 ms on the held-out traces. Dan's own
dotfiles were not recorded.

A more principled fix would lean on standards instead of heuristics. Shells
already mark prompt and input regions with OSC 133 (FinalTerm semantic
prompts). A small extension that marks "suggestion text" would let the
server's emulator tag those cells as non-input in the structured diff (D9).
That needs patches to zsh-autosuggestions and fish, so it is an open
question here, not a recommendation.

## 8. TUIs and Claude Code

- **Real Claude Code** (v2.1.319; 590 keys per run, 3 seeds):
  - It **hides the terminal cursor but parks it at the insertion point** on
    every redraw, and it draws **no reverse-video cursor cell**.
    `cursorcheck` found no lone reverse cell on any of the 590 settled
    screens, and the hidden cursor followed Left, Right and inserts.
  - So mosey predicts from the hidden terminal cursor, and the drawn-cursor
    heuristic plays no part: `-fakecursor` gives identical Claude Code
    numbers.
  - Results: 83.4 % instant / 1.0 % wrong at 100 ms; 60.2 % / 1.4 % at
    450 ms, or 75.9 % instant with rebase.
  - The wrong keys come from word-wrap inside the input box: the box wraps
    before column 80, and we predicted at column 79. Row-stale is 17–18 %.
- **faketui with a drawn cursor**, the first draft's only TUI:
  - The reverse-cell heuristic agreed with the application's own insertion
    point on **471 of 488** keys.
  - Judged against the app's truth instead of the heuristic: 86.3 % instant
    / 0.5 % wrong at 100 ms with the heuristic, 0 % instant without it.
  - This shows that the heuristic works on a TUI written to fit it. It says
    nothing about real applications.
- **Recommendation**, revised from the first draft: predict from the
  terminal cursor whether or not it is visible. Keep the drawn-cursor
  heuristic as a fallback, off by default, until a real application needs
  it (decision 4).

## 9. Hostile input and resource limits

- **Paste.** Bracketed paste is now unpredictable, however many reads it
  arrives in (`TestBracketedPaste`). The 64-byte rule is a performance
  limit, not a security control. The first draft's security rationale is
  withdrawn: predicting a paste never changes what the server runs.
- **Input log.** Input is now copied into the log; the first draft aliased
  the caller's buffer (`TestLogCopiesInput`). Entries are zeroed on
  eviction, and nothing is logged while echo-off. Rebase never replays a log
  with holes (`TestRebaseLogOverflow`).
- **Instrumentation.** The `Predicted` map grew by one entry per keystroke,
  forever; it is now a ring of 1024. The set of confirmed epochs is pruned
  to the epochs still live.
- **Display rule.** It now uses the exact set of confirmed epochs, not a
  high-water mark (`TestExactConfirmedEpochs`).
- **Complexity.** The visual cursor is computed once per frame, not on
  every key. The corrected bound: O(W·H) per frame, plus O(W) per predicted
  key, plus a rebase replay of at most 512 inputs per founding frame.
- **Width table.** Spec §9 now says that the server names a fixed version
  identifier inside the authenticated handshake. No table is sent.
- **`FuzzEngine`** was rewritten to cover what the review said it missed:
  - screen sizes from 1×1 to 120×40, and resizes;
  - hostile or decreasing echo acks and received counts;
  - reverse-video and grey cells;
  - the echo-off bit;
  - a pending cap small enough to bind.

  It asserts bounds on cells, cursor, pending predictions, the log, bumps
  and confirmed epochs, and that no displayed cell belongs to an
  unconfirmed epoch. It ran twice and passed both times:
  - 10 min, 6.10 M executions on 24 workers, before the decoration and
    backspace changes;
  - 3 min, 1.74 M executions on 4 workers, after them.

  Not covered: wide glyphs in the server's cells, and CPU time per call.

## 10. Review response

| # | Issue | Response |
|---|---|---|
| 1 | Echo-ack frames leak keystroke timing (major) | **Fixed and measured.** Spec §12 adds a threat model. Echo-ack-only frames are suppressed while echo-off, at no cost (129 → 9 per run-set). Piggyback-only is measured (−5 to −7 points instant) and left to Dan. Chaff goes to S5 (§6). |
| 2 | Password safety rests on statistics (major) | **Fixed.** An echo-off bit from termios: nothing predicted or logged while it is set. A unit test for type-ahead plus a coincidental match, and a replay assertion over every recorded `read -s` segment. The new metric found a **real leak** at fish's masked prompt, now fixed (§5). A zsh scenario bug was found and the zsh traces re-recorded. |
| 3 | Log aliases the caller's buffer and holds passwords | **Fixed** (§9). |
| 4 | Rebase over a missing log entry | **Fixed**: falls back to gate (§9). |
| 5 | Fuzz claim overstated | **Fixed.** The fuzzer was extended as proposed and re-run. The remaining gaps are stated in spec §10. |
| 6 | `predictedSeqs` unbounded | **Fixed**: a ring of 1024. |
| 7 | O(row width) claim false | **Fixed**: the visual cursor is cached per frame, and the claim corrected. |
| 8 | 64-byte paste rule presented as security | **Fixed.** Bracketed paste is handled explicitly, and the rule is described as a performance limit only. |
| 9 | Display rule is a high-water mark | **Fixed**: an exact set, with a test. |
| 10 | Width table unbounded and unauthenticated | **Fixed in the spec**: a version identifier from a fixed set, inside the authenticated transcript. |
| 11 | FINDINGS.md missing (major) | This document. |
| 12 | Thresholds may come from Mosh source (major) | **Agreed; replaced** by a black-box measurement of `mosh-client` (§3). The new defaults are 38 / 95 ms, and they are no longer in the paper baselines. |
| 13 | Drawn-cursor result circular; no real Claude Code (major) | **Fixed.** The cursor is judged against the app's own insertion point; the heuristic agreed with it on 471/488 keys. **Real Claude Code was recorded.** It parks the hidden terminal cursor at the insertion point and draws no reverse cell, so it does not need the heuristic. The claim that drawn-cursor tracking is "required" is withdrawn (§8). |
| 14 | Row-stale hidden (major) | **Reported** in the headline, in every table and in §4.3, with instant excluding row-stale. |
| 15 | Ack horizon attributed to transient prompts | **Restated**, with the per-trace breakdown (§4.2). |
| 16 | Time to correct from about 4 events | **Withdrawn and re-measured**, with n on every figure (§4.5). |
| 17 | Informative rule has no ablation | **Added** the `InformativeOnly` flag and the `mosey-informative` and `mosey+bsconfirm` ablations (§4.1, §5). |
| 18 | Paper baseline mislabelled | **Renamed** `paper-strict` ("paper + strict choices"), and **added** `paper-permissive`. The informative rule and the thresholds are removed from both. |
| 19 | Heuristics tuned and scored on the same traces | **Held-out traces recorded.** The colour heuristic failed on them (0 % recall) and the decoration rule replaced it. §7 notes that the held-out set is now spent. Dan's dotfiles were not recorded. |
| 20 | Replay nondeterministic | **Fixed** with sorted iteration; verified, and covered by a test. |
| 21 | Open-loop replay undisclosed | **Documented** (§2). A live closed-loop check was not done. |

## 11. Decisions for Dan

1. **Echo-ack-only frames.** Options:
   - (a) suppress them only while echo-off: adopted, and free;
   - (b) piggyback only: instant 5–7 points lower on links up to 100 ms,
     but it removes the reply tag everywhere;
   - (c) (a) plus SSP chaff while typing, measured by S5.

   Recommend **(c)**.
2. **Rebase recovery.** It goes past D12's "not game-style" wording: on
   each new frame it re-predicts the keys not yet acknowledged, like
   client-side reconciliation in games. It gains 15–21 points of instant on
   long links and costs nothing measurable. Recommend **adopt**.
3. **Autosuggestion handling.** Options:
   - (a) the rendition-change rule: adopted, independent of the colour
     theme, but designed after the held-out failure;
   - (b) cursor cell only: the simplest, about 1.5 points lower instant,
     with more row-stale;
   - (c) an OSC 133 extension that marks suggestion text, with patches to
     zsh-autosuggestions and fish.

   Recommend **(a) now, and (c) later as a standards proposal**.
4. **Drawn-cursor heuristic.** Real Claude Code does not need it. Recommend
   **off by default**, kept as a fallback.
5. **Echo-off bit in the frame format** (D9/D11 schema). Recommend **yes**.
   It is one bit, which the server reads with `tcgetattr`.

## 12. Challenges to locked decisions

- **D12** ("not game-style prediction"): §4.4 has the measured case for
  rebase. It is raised as decision 2, not overridden.
- **D11** (every keystroke sent at once), together with **D4** (the public
  internet): per-keystroke datagrams leak typing timing, whatever prediction
  does. Prediction's own amplifier, the echo-ack frame at no-echo prompts,
  is removed (§6). The rest needs chaff in SSP, which D11 as written does
  not include.

## 13. Not done, or bounded

- A live, closed-loop replay check of the open-loop approximation.
- Traces with Dan's own dotfiles, or with themes other than Solarized.
- Hysteresis in mosh-client's thresholds, and thresholds measured against
  S5's SRTT.
- S5's simulator: this spike used its own simple model, with no
  reordering, no outages and no Mahimahi traces.
- Wide glyphs in fuzzed server cells.
- The cause of Claude Code's 17–18 % row-stale.
