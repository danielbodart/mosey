# Prediction: predictive local echo

This is the specification `internal/predict`, the client's use of it, and
the server's echo ack are written from. It says in our own words what the
Mosh paper describes about speculative local echo, amended by PLAN D12 and
by what spike S6 measured on modern shells. Nothing here comes from Mosh's
source code, which no one working on mosey reads (PLAN §4).

Owner: **prediction**. Status: the prediction slice. A change to a rule,
a constant or the wire fields of §3 is a change to this file first, then
to the code.

## 0. Sources and notation

| Tag | Meaning |
|---|---|
| [P §x] | Winstein & Balakrishnan, *Mosh: An Interactive Remote Shell for Mobile Clients*, USENIX ATC 2012, section x. §2 is the overview of the display, §3.2 speculative local echo, §4 the evaluation |
| [S6 §x] | our own measurement, `docs/spikes/s6-prediction/FINDINGS.md` section x: 9 recorded traces (9,544 keys: bash, zsh, zsh with autosuggestions and highlighting, fish, vim, less, Claude Code, two Ink-style TUIs) replayed over a simulated network |
| [M S6 §3] | S6's black-box measurement of the installed `mosh-client` |
| [M] | our own measurement in this slice, §14 |
| [D] | decided here, with the reason beside it |
| Dn | PLAN.md §2 decision |

Where this spec differs from S6's draft (`docs/spikes/s6-prediction/
prediction-spec.md`), §15 says how and why.

## 1. What it is for, and the rule it keeps

Over a long or lossy path, a keystroke's echo takes a round trip. The
paper's answer [P §3.2] is for the client to guess the echo of keys whose
effect is easy to predict, draw the guess at once, and check each guess
against the server's screen when it arrives, taking it back if it was
wrong.

The rule prediction must keep is D9's: **the client never parses remote
output.** Every prediction comes from bytes the local user typed, and is
judged only against structured cells the server sent (`screen.md`). A
predicted cell is drawn by the client's own renderer, through the same
allow-list checks as any other cell (`screen.md` §8.4). The server is
authenticated (D20), so a server that lies can only make its own user's
predictions wrong; it can never make the client draw anything it did not
already draw (§12).

## 2. Model

The client holds the newest **frame**: the `screen.Grid` SSP delivered,
with its cells, cursor and the three prediction fields of §3. On top of it,
`predict.Engine` keeps:

- **cell predictions**: (row, column, expected cell, event number, epoch,
  informative);
- **cursor predictions**: (row, column, event number, epoch).

What the user sees is the frame, then every *displayed* cell prediction
over it, then the newest displayed cursor prediction (§11).

**Event numbers.** Every keystroke read and every resize is an event of
the client's input stream (`ssp.md` §10.1), and the stream numbers them
already. An event's **number** is the stream's `Len()` just after it was
appended, so the first event is 1 and "event n has reached the server" is
`n ≤` the server's count of events [D: reuses SSP's numbering, so no new
counter crosses the wire]. One terminal read is one event, and may hold
several keys (a fast typist, or a terminal that coalesces): they share the
number. A read longer than `userinput.MaxKeyEvent` becomes several events;
it is over the paste limit anyway (§12).

## 3. What the server tells the client

Each frame carries three prediction fields, all set by proto, never by
emu (`screen.md` §7.3):

- **`EchoAck`** [P §3.2]: the number of the newest event the pty has had
  for **at least 50 ms**. Its effects, if the program echoes, should be on
  this screen. The 50 ms wait is the paper's, and is on the server so that
  network jitter never enters the judgement: a timeout on the client
  would either flicker under jitter or leave mistakes up too long
  [P §3.2].
- **`EchoApplied`** [D]: how many events the pty had taken when this
  screen was taken. Called *R* below. It says which keys the screen can
  reflect at all, for the ack horizon (§7), the cursor judgement (§7) and
  rebase (§8). `EchoAck ≤ EchoApplied` always.
- **`EchoOff`** [D12]: `!ECHO && ICANON` on the pty, read through the
  master with `TCGETS` (on Linux the master reports the slave's termios
  [M S6 §5]). That is a canonical-mode prompt that does not echo:
  `passwd`, `sudo`, ssh's password prompt, `read -s`. Programs in raw mode
  (vim, readline, Ink) clear `ICANON` too, so they are not caught by it.

**Wire.** The three travel in `screen.md`'s ECHO op, extended by this
slice to `flags`, `ack`, `ahead`, with `EchoApplied = ack + ahead`
(`screen.md` §5.6). Sending the difference costs one byte in the usual
case, and makes `EchoAck ≤ EchoApplied` hold by construction.

### 3.1 The server's rules

proto's `Session` (`server.md` §7) keeps, per attached client:

1. **The write log.** Each time the pty writer finishes writing an event
   (keys, or a resize applied), it notes `(applied, now)`. The log keeps
   only entries younger than 50 ms plus the newest older one, and at most
   `EchoLogCap` = 64 entries; when it is full, the newest entry's count is
   raised in place, which only makes the echo ack later [D: bounds memory
   under a paste without ever acking early].
2. **The echo ack.** On every publish, `EchoAck` is the count of the
   newest log entry at least 50 ms old, unless the pty has echo off (rule
   4).
3. **The echo-ack frame.** 50 ms after an event is written, proto
   publishes (rule 2 then advances the ack). That frame differs from the
   last one only by its echo ack when the program echoed nothing, which is
   the paper's extra frame [P §3.2]. It is what confirms an epoch after a
   pause when nothing else changed: without it, instant drops 5–7 points
   on links up to 100 ms [M S6 §6].
4. **No echo-ack-only frames while echo is off** (D11, D12). While the pty
   has echo off, `EchoAck` keeps its last value, so a version that differs
   only in its echo ack can't arise and SSP has nothing to send. At a
   password prompt the server then sends nothing per keystroke. S6
   measured this at no cost to prediction (129 such frames down to 9 per
   run-set, all at the edges of prompts) [M S6 §6]. While chaffing it is a
   second line of defence (`ssp.md` §9.1.3).
5. **`EchoApplied` rides along.** On each publish it is set to the
   writer's `applied`, *unless* the new grid would equal the last one
   published but for `EchoApplied`; then it keeps the old value. So it
   never causes a frame of its own: no frame per keystroke at a prompt
   that echoes nothing [D]. A frame it rides on was going anyway.
6. **Echo-off is read when it matters.** proto reads the bit on every
   publish, and also just before writing each key event to the pty: a
   program that turns echo off and prints its prompt in the same write
   may have changed termios after the screen was taken, and nothing else
   would publish until it next prints. If the bit differs from the one
   last published, proto publishes before writing the key [D].

All of this is per connection, like `applied` (`ssp.md` §1.3): a new
client's stream starts at 0, and so do its log, `EchoAck` and
`EchoApplied`.

## 4. Epochs and confirmation [P §3.2; refinements ours]

- Predictions are made in **epochs**. Within one epoch the guesses stand
  or fall together.
- A new epoch starts **tentative**: its predictions are made, but not
  drawn.
- When the server's screen bears out one of an epoch's predictions, the
  epoch is **confirmed**: its outstanding predictions are drawn at once,
  and so is every later prediction in it.
- A key that may change how the program echoes, or whose effect is hard
  to guess, **starts a new epoch** (it "bumps" the epoch). The paper names
  arrow keys and control characters [P §3.2]; our list is §5.

This is what makes vi safe: after `Esc`, the keys of normal mode are never
drawn, because their epoch is never confirmed.

**Only an informative prediction confirms** [S6 §4.2, §5]. A prediction is
informative if it is the glyph the user just typed and differs from what
the frame showed in that cell. Cells that merely shifted, cells the
prediction left as they were, and anything a backspace or an arrow
predicts can refute an epoch but never confirm one. Two measured reasons:

- In vim's normal mode a blank shifted onto a blank "confirmed" a
  nonsense epoch, which was then drawn: allowing any match to confirm
  tripled visible mistakes (15 to 44 per run-set at 100 ms) [M S6 §4.1].
- At fish's masked `read -s` prompt (raw mode, drawing `●`), a backspace
  that emptied a cell confirmed the epoch, and the next password letter
  was drawn in the clear for about a round trip: 3–11 of 555 password keys
  shown. With backspace never confirming: 0 of 555 [M S6 §5].

The client keeps the **exact set** of confirmed epochs, not a high-water
mark, so confirming epoch 5 never reveals leftovers of an unconfirmed
epoch 4 [S6 §9]. The set is pruned to epochs some live prediction still
belongs to.

The client has **no timers** of its own for judging [P §3.2].

## 5. Which keys are predicted [P §3.2 for the principle; table ours]

| Input (bytes as the terminal sends them) | Prediction |
|---|---|
| a printable character of width 1 or 2 (§10) | the glyph at the cursor; the text run to its right shifts right by its width (§6); the cursor advances by its width |
| backspace (DEL `0x7f` or BS `0x08`) | the cursor moves back over one glyph (two cells for a wide one); the text run right of the old cursor shifts left; the vacated cells at its end become blank |
| left arrow (`ESC [ D` or `ESC O D`) | the cursor moves back over one glyph |
| right arrow (`ESC [ C` or `ESC O C`) | the cursor moves forward over one glyph, only over the user's own text (§9.1) |
| anything else: CR, LF, Tab, up and down, Home, End, Delete, any other control or escape sequence, function keys, mouse reports, pastes | not predicted; **bumps the epoch** |

The engine also refuses, and bumps, when:

- the glyph would reach the row's last column, or not fit: wrapping is
  unpredictable, and word-wrap was the paper's main source of errors
  [P §4]. Predicting across the margin added wrong predictions (0.1% to
  0.4%) and gained nothing [M S6 §4.1];
- the shift would push a non-blank cell off the row;
- the cursor is on the right half of a wide glyph;
- backspace or left would move before the column where typing began on
  this row, as far as the engine has seen (protects a prompt) [S6 §4.1,
  `-bsguard`];
- any limit of §12 is reached.

One event may hold several keys; they are predicted in order, and the
first unpredictable one bumps and ends the event's predictions.

## 6. The shift model [ours; S6 §4.2]

The paper says a program echoes "at the current cursor location" [P
§3.2], and nothing about the text right of it. Ours is the **text-run**
model:

- Inserting shifts right only the run of text starting at the cursor. The
  run ends at **3 consecutive blanks** [D, S6: protects right prompts] or
  at a **decoration** (§9.1).
- Deleting is the mirror image.
- Cells past the run are not predicted, so they keep the frame's value.

Shifting the whole row (terminal ICH/DCH) breaks on right prompts, box
borders and autosuggestions: 41.9% instant against 76.6% at 100 ms.
Overwriting only the cursor cell is wrong mid-line: 75.1% and 0.4% wrong
[M S6 §4.1].

A predicted glyph is drawn in the rendition of the nearest glyph to its
left on the row, without reverse video or a link [ours]. **Glyphs are
compared by text and width only, never rendition** [S6 §4.2]: syntax
highlighters recolour a word as it is typed, and requiring the rendition
to match drops instant from 76.6% to 59.1% [M S6 §4.1]. A colour that
changes after confirmation comes with the server's next frame.

## 7. Judging a frame [P §3.2; refinements ours]

When a frame arrives, the client takes `A = min(EchoAck, last)` and
`R = min(EchoApplied, last)`, where `last` is the number of its own newest
event, and `A = min(A, R)`: a server can't vouch for more than it
received, and a hostile one is held to what was sent [D, §12].

1. **Size.** If the frame's size differs from the last, every prediction
   is dropped unjudged and a new tentative epoch begins.
2. **Echo off.** If the frame has `EchoOff` and the last did not, every
   prediction is dropped unjudged and a new epoch begins.
3. **Cells.** Each cell prediction with event number `n ≤ A`, in order of
   (number, row, column):
   - **Ack horizon** [ours, S6 §4.2]: if an event that bumped the epoch
     has a number in `[n, R]`, the frame shows the program's response to
     that later key too (a redrawn line after Enter, a transient prompt),
     so it can't judge this prediction. A bump at `n` itself counts: an
     event stops predicting at its first unpredictable key, so every
     prediction it made came before that key (one read of `ls` and Enter
     together, say) [D: S6 had one key per event and never met this]. It is dropped, neither right nor
     wrong. Without the horizon, frames after Enter judge correct
     predictions against a redrawn line and they flicker off: visible
     mistakes at 450 ms fall from 38 to 5 with it [M S6 §4.2].
   - **Decoration over a blank**: if the prediction is a blank and the
     frame has a decoration there (§9.1), the shell drew a new suggestion
     where the user's text ended. That fits what was typed but is no
     evidence for it: dropped.
   - **Match** (same text and width): removed, since the frame now shows
     it. If it was informative, its epoch is confirmed.
   - **Mismatch**: the epoch is refuted (step 5).
4. **Cursor.** Each cursor prediction with `n ≤ A` is judged only when
   `n == R` and no bump lies in `[n, R]`; older ones have been overtaken
   by later keys the server already has, and are dropped. A position that
   differs from the frame's cursor refutes the epoch; one that matches
   **does not confirm** it, since vi's `l` moves the cursor exactly as a
   typed letter would [S6 §5].
5. **Refutation.** Every prediction is dropped, drawn or not, and a new
   tentative epoch begins. If any of the epoch's predictions were drawn,
   the user sees them replaced by the server's truth: the paper's wrong
   guesses "removed within an RTT" [P §2]. The engine counts these
   (`Stats.Refuted`, `Stats.VisiblyWrong`).

## 8. Recovering: rebase [D12 as amended; S6 §4.4]

After a bump or a refutation the engine no longer knows the cursor
position the program will report. The paper keeps predicting "in the
background" from what it last believed [P §3.2]; S6 measured that to make
mistakes that later confirm by coincidence (`-blind`: visible mistakes
doubled at 450 ms) [M S6 §4.1]. D12 adopts **rebase**:

- After a bump or a refutation the engine is **unfounded**: it logs keys,
  but predicts none.
- On each frame, while unfounded and echo is on:
  - if `R ≥ last`, the server has every key and the frame is a fresh
    base: the engine is founded again;
  - otherwise, if `R ≥` the newest bump and the log holds every event in
    `(R, last]`, the engine starts a fresh tentative epoch and predicts
    those events again, in order, on top of this frame; it is founded
    unless one of them bumps;
  - otherwise (an event in the gap was a paste, a resize, longer than the
    log keeps, or typed while echo was off) it waits as above, which S6
    calls the gate.
- Epochs, the echo ack and confirmation work as before. Only the base of
  the tentative predictions is recomputed.

Rebase gains 15–21 points of instant on long links and changes wrong by
nothing measurable: 62.4% against 41.2% instant at 450 ms, 62.9% against
47.2% on the train profile [M S6 §4.4]. It is the one place D12 goes past
the paper's "not game-style" wording, and D12 adopts it.

## 9. Modern shells and TUIs [ours]

### 9.1 Decorations: autosuggestions, right prompts, placeholders

A non-blank cell is a **decoration** if its rendition differs from the
rendition of the nearest non-blank cell to its left on the same row.
Autosuggestions (zsh-autosuggestions, fish), right prompts and placeholder
text are drawn in a different rendition from the user's text, whatever the
colour theme. Right of the cursor, a decoration:

- ends the shifted run (§6), so typing at the end of the input predicts
  only the typed cell; when the typed glyph matches the suggestion, the
  stale suffix still on screen is what the shell draws anyway;
- makes **right arrow unpredictable** when the cell under the cursor is
  blank or in a rendition other than the text being edited, because there
  right accepts the suggestion;
- is never judged against a predicted blank (§7 step 3).

Without it, autosuggestions make 10.6% of keys wrong at 450 ms (fish 28%,
zsh-full 20%) [M S6 §4.1]. S6's first rule detected suggestions by colour
and failed completely on a Solarized theme (0% recall); this rule was
designed after seeing that, so S6's held-out traces no longer test it
fairly [S6 §7]. The fallback, if it fails on some theme, is the
cursor-cell-only model, which needs no detection [S6 §7].

A cost: mid-line in a syntax-highlighted line, the shift stops at the next
differently-coloured token, so the rest of the row is stale (not wrong)
until the frame. S6 counts such keys as *row-stale*: 4.3–5.6% of keys
[M S6 §0, §4.3].

### 9.2 Right prompts, transient prompts, completion menus

The 3-blank end of a run and the decoration rule stop inserts from
pushing a right prompt along. Enter bumps the epoch; the ack horizon (§7)
then drops predictions a transient prompt's redraw can no longer judge.
Tab and the arrow keys bump, so fish's pager and zsh's menu selection are
never predicted; rebase picks prediction up again afterwards.

### 9.3 Hidden and drawn cursors

Predictions start from the **terminal cursor, even when it is hidden**.
Claude Code hides it but parks it at the insertion point on every redraw,
and draws no reverse-video cell [M S6 §8]. A heuristic that takes a lone
reverse-video cell as a drawn cursor helped only a TUI written to fit it;
D12 turns it off by default, and this slice does not build it [D: no real
program needs it yet; S6 §8].

## 10. Wide characters and widths [ours; Mosh PR #1410 was the motivation]

A wrong width would put every later prediction on the row in the wrong
place, so the client predicts only what it can measure the way the
server's emulator does.

- **Single-code-point characters only.** The client path may depend only
  on the standard library and `golang.org/x/*` (`screen.md` §9), so it has
  no grapheme-cluster segmenter. A character is predicted only if it is
  one code point and the next code point in the event does not join it.
  Anything that combines or joins bumps: combining marks (Unicode
  categories Mn, Me, Mc), zero-width joiners and non-joiners, variation
  selectors, emoji modifiers, regional indicators, Hangul conjoining
  jamo, and any other format character (Cf). So do C0 and C1 controls,
  explicit bidi controls, and strong right-to-left scripts (Hebrew,
  Arabic and the blocks around them: where they land is the terminal's
  bidi policy) [S6 §9].
- **Width** comes from Unicode's East Asian Width property, read from
  `golang.org/x/text/width`: Wide and Fullwidth are 2; Narrow, Halfwidth
  and Neutral are 1; **Ambiguous is not predicted**, since terminals
  disagree on it. Code points not yet assigned are not predicted.
- **Agreement with the server.** The client and the server are the same
  build (D7), so the tables never skew between versions, only between the
  two libraries. A test in `internal/emu` writes every code point the
  client would predict (152,580 of them) into the server's emulator and
  compares the cell it gets (`TestPredictionWidthsAgreeWithTheEmulator`).
  They agree on every one [M], so there is no list of exceptions; if a
  library update makes them differ, the test names the code points and
  they are excluded. A disagreement the test could not see costs a wrong
  prediction, corrected within a round trip, never a safety problem.
- A width-2 glyph takes its cell plus a continuation cell. Backspace and
  the arrows step over both.

Predicting wide characters adds about 3 points of instant on S6's traces,
which include CJK and emoji [M S6 §4.1].

## 11. Display

### 11.1 When predictions are drawn [P §2; thresholds M S6 §3]

`-predict` chooses, with the names `mosh(1)` documents for its own
option:

- **`adaptive`** (the default): draw predictions only while SSP's smoothed
  RTT is at least **38 ms**; on a faster path the server's echo is quick
  enough. Underline them while it is at least **95 ms**.
- **`always`**: draw them whatever the RTT, underlining from 95 ms.
- **`never`**: draw nothing. The engine still runs, so switching costs
  nothing, but nothing it predicts is shown.

The paper gives no numbers. These were measured black-box on the
installed `mosh-client` over `tc netem` [M S6 §3]: it starts drawing
predictions at a round trip of about 36–40 ms and underlining them from
about 92–100 ms. They are netem round trips, since mosh's own estimator
can't be seen; ours (`ssp.md` §7) sits a few ms above the path's.

Whether drawn or not, predictions are made and judged the same way, so
the epoch state is ready the moment the RTT crosses the threshold.

### 11.2 Underlining [P §2]

Above the underline threshold, every predicted cell drawn is underlined:
the user can see what the server has not yet confirmed, and the line
trails the cursor and vanishes as frames arrive [P §2]. A predicted
cell's other underline styles are replaced by the plain underline
(`screen.md` G6).

### 11.3 How it is drawn

`Engine.Overlay()` returns the grid to draw: the frame itself when
nothing is displayed, or a clone with the displayed predictions written
into it and the cursor moved to the newest displayed cursor prediction
(its visibility and shape stay the frame's). The renderer draws it like
any other grid (`screen.md` §8). The overlay keeps `screen.md` §2.2's
invariants: wherever a predicted cell overwrites half of a wide
character, the other half becomes a blank of its style, and a
continuation cell always carries its wide character's style. A test
checks `Grid.Valid` on every overlay the fuzz target produces.

The client draws on every key it reads, every frame, and every local
resize.

## 12. Hostile input and limits [ours]

Predictions come only from the local user's bytes. The server's frames
are authenticated but still hostile in the D4 sense: a compromised proto
can send any grid that passes `Apply`. Bounds:

| Limit | Value | Why |
|---|---|---|
| `MaxEventBytes` | 64 bytes; a longer event bumps | **Performance only**: one event is never worth more than a row of predictions. Not a security control: predicting a paste never changes what the server runs [S6 §9] |
| Bracketed paste | everything from `ESC [ 200 ~` to `ESC [ 201 ~` bumps, across any number of events | Pastes are not keystrokes [S6 §9] |
| `MaxPending` | 1024 cell predictions; past it, the next key bumps | memory and CPU while the server is stalled [S6 §9] |
| cursor predictions | at most 1024; the oldest 512 are dropped past it | they are judged only at `n == R`, so old ones are dead anyway |
| bumps remembered | at most 1024; the oldest half dropped past it, and with them every prediction made at or before the newest bump dropped, unjudged | the horizon and rebase look only at recent ones; a prediction whose horizon is forgotten can't be judged |
| `LogSize` | the last 512 events, copied (never the caller's buffer), zeroed when evicted, and all of it when a frame turns echo off; nothing logged while echo is off, and no event over `MaxEventBytes` | bounded replay; no password bytes held [S6 §9] |
| `EchoAck`, `EchoApplied` | clamped to the client's own `last`, and `A ≤ R` | a server can't make the engine judge keys it never had, nor rebase from a future it invents |
| frame size | whatever `Apply` admits (D23: 1000 × 500) | the engine's work per frame is bounded below, not by the size |
| work | per frame O(P log P) for P ≤ 1024 predictions, O(W) per predicted key, and a rebase of at most 512 events | no quadratic behaviour on a long row [S6 §9] |
| cells written | only printable code points that passed §10, `screen.ValidCluster`, or blanks | the client draws only glyphs it chose |

A hostile server can at most make predictions wrong (they are removed when
refuted), keep them tentative (never drawn), or confirm an epoch by
drawing what the user typed, which shows the user their own keys sooner.
It can't make the client draw anything the user did not type, and it can't
make it keep more than the bounds above.

`FuzzEngine` drives the engine with arbitrary keys and arbitrary frames:
sizes from 1 × 1 up, resizes, wide characters and decorations in the
server's cells, echo acks and applied counts that jump, fall or exceed
what was sent, and the echo-off bit. It asserts: every overlay passes
`Grid.Valid` and draws its cursor inside the grid; the bounds above hold;
no drawn cell belongs to an epoch that was never confirmed; and nothing
is drawn while the last frame had echo off.

## 13. Threat model

### 13.1 Passwords

Two protections, measured separately on 555 password keys [M S6 §5]:

1. **The echo-off bit.** While the newest frame has `EchoOff`, the engine
   neither predicts nor logs input, and entering echo-off drops every
   prediction. It covers `read -s` in bash and zsh, `passwd`, `sudo` and
   ssh, which all run in canonical mode with echo off. It does not cover
   fish's `read -s`, which runs in raw mode and draws `●`.
2. **The epoch rules.** Tentative epochs are never drawn, and only a
   typed glyph that changes its cell confirms one (§4).

Together: 0 of 555 password keys drawn, at every profile, with rebase or
without; with backspace allowed to confirm, 3–11 of 555, all at fish's
prompt [M S6 §5]. The bit guards against a coincidence the traces never
hit: something else drawing the typed glyph at the predicted cell during
type-ahead at a no-echo prompt (`wall`, say). A unit test builds that case
(`TestEchoOffStopsPredictionEvenWhenTheScreenMatches`).

**Not covered:** a password field that a raw-mode TUI draws itself, with
no mask: there the epoch rules alone protect it, statistically.

The first key typed at a no-echo prompt may be predicted before the frame
with the bit arrives; it is tentative, so not drawn unless confirmed, and
the frame with the bit drops it (§3.1 rule 6 makes that frame prompt).

### 13.2 Keystroke timing

D11 sends each keystroke in its own datagram, so an on-path observer sees
input timing (Song, Wagner and Tian, USENIX Security 2001); chaff hides it
within a run of typing (`ssp.md` §9.1, threat model R2). Prediction adds
one thing that would undo that at the worst place: the paper's
echo-ack-only frame, sent about 50 ms after a key even when nothing was
echoed, which at a no-echo prompt names each password key in the server's
direction. §3.1 rule 4 removes it while echo is off; rule 5 makes sure
`EchoApplied` does not bring it back.

### 13.3 What prediction keeps in memory

The input log (§12) holds the bytes of at most the last 512 events, never
those typed while echo was off, and zeroes each entry when it leaves. The
start of a password typed before the echo-off frame arrived is logged
like any key, so the frame that turns echo off zeroes the whole log.
Rebase does not run while echo is off, and if echo comes back on before
the server has every key, the missing entries are a hole and rebase
waits for the server (§8), which costs one round trip of prediction.

## 14. Measurements [M]

`internal/predict`'s replay test replays S6's recorded traces
(`spikes/s6-prediction/traces/*.json.gz`, read as data, never imported)
through the engine over a small discrete-event model of the path and of
the server's rules in §3.1. Its model of the network is S6's (§2 there):
open-loop, a fixed base RTT split evenly, uniform jitter, i.i.d. or
Gilbert-Elliott loss, D11's frame interval and collection time. "Instant"
means a key whose prediction, glyph and cursor, was drawn at the moment
of the key and matched the screen the program settled on before the next
key; "wrong" a key whose drawn prediction did not.

`MOSEY_PREDICT_REPORT=1 go test ./internal/predict -run TestReplay -v`
prints the tables below (12 s); without the variable the test replays
bash at 100 and 450 ms and asserts floors (65% and 45% instant, at most
1% wrong) and that no password key is drawn, so CI stays quick.

### 14.1 Results (9 traces, 9,544 keys, 3 seeds; this slice's engine)

Instant / wrong, as a percentage of all keys:

| trace | LAN 5 ms | Wi-Fi 30 ms, 1% | 100 ms | 100 ms, 29% | train 250 ms | EV-DO 450 ms |
|---|---|---|---|---|---|---|
| bash | 81.0 / 0.00 | 79.7 / 0.00 | 77.6 / 0.00 | 74.3 / 0.00 | 61.3 / 0.00 | 59.2 / 0.00 |
| Claude Code | 85.6 / 1.02 | 85.3 / 1.02 | 83.6 / 1.02 | 82.3 / 0.96 | 72.9 / 2.88 | 73.6 / 2.88 |
| fish | 80.0 / 0.00 | 79.6 / 0.00 | 77.1 / 0.00 | 73.6 / 0.00 | 63.8 / 0.24 | 61.6 / 0.76 |
| less | 32.1 / 0.00 | 32.1 / 0.00 | 31.4 / 0.00 | 27.3 / 0.00 | 20.9 / 0.00 | 16.1 / 0.00 |
| TUI, drawn cursor | 0.0 / 0.00 | 0.0 / 0.00 | 0.0 / 0.00 | 0.0 / 0.00 | 0.0 / 0.00 | 0.0 / 0.00 |
| TUI, real cursor | 84.6 / 0.00 | 83.5 / 0.00 | 81.6 / 0.00 | 79.0 / 0.00 | 71.3 / 0.00 | 69.8 / 0.00 |
| vim | 71.5 / 0.00 | 70.7 / 0.00 | 69.0 / 0.00 | 64.6 / 0.00 | 54.7 / 0.00 | 53.0 / 0.00 |
| zsh, full | 75.8 / 0.14 | 74.8 / 0.14 | 72.7 / 0.21 | 65.5 / 0.21 | 54.1 / 0.30 | 52.2 / 0.30 |
| zsh, plain | 82.2 / 0.00 | 81.4 / 0.00 | 79.7 / 0.00 | 77.1 / 0.00 | 66.9 / 0.00 | 65.7 / 0.00 |
| **all** | **74.1 / 0.10** | **73.4 / 0.10** | **71.5 / 0.11** | **67.8 / 0.11** | **57.9 / 0.30** | **56.4 / 0.40** |

Row-stale (§9.1) was 4.0–5.7% of keys. **Password keys drawn: 0 of 555
on every profile.** Echo-ack-only frames sent while echo was off: 0.

Against S6's targets (79.8% instant and 0.1% wrong on the LAN, 62.4% at
450 ms with rebase): wrong is on target, and the difference in instant is
the drawn-cursor TUI, which S6's figures predicted with the heuristic D12
turns off. S6's ablation without it gave 71.4% at 100 ms [M S6 §4.1];
this engine gives 71.5%. Claude Code's wrong predictions are S6's too:
its input box wraps a word before the margin [M S6 §8].

End to end (`internal/e2e`, netsim under synctest, 400 ms round trip): a
key is on the user's screen before any virtual time passes, and a wrong
guess is taken back 660 ms after it was typed, the round trip plus the
50 ms echo-ack wait plus the server's frame pacing.

## 15. Where this differs from S6's draft

- **R comes with the frame.** S6's draft took *R* from SSP's ack of the
  client's stream. That ack is sent with whatever datagram goes next, so
  it can be newer than the screen it travels with: keys the program has
  not yet echoed would then be skipped by rebase. S6's own simulator gave
  each frame the server's count at the time of the screen, which is what
  `EchoApplied` carries [D].
- **No width-table identifier in the handshake.** Client and server are
  one build (D7); the agreement test of §10 replaces the identifier.
- **Single code points only.** No grapheme segmenter on the client path
  (§10).
- **No drawn-cursor heuristic** (§9.3).
- **Gate is not a mode.** Rebase falls back to it when the log has holes;
  blind recovery is not built.

## 16. Interfaces

- `screen.Grid.EchoApplied` (`uint64`), carried in ECHO as `ahead`
  (`screen.md` §5.6), compared by `Equal`, zero in emu's mirror
  (`screen.md` §7.3).
- `internal/predict`: `New(Config)`, `Engine.Key(n, bytes)`,
  `Engine.Skip(n)`, `Engine.Frame(grid)`, `Engine.SetRTT(d)`,
  `Engine.Overlay()`, `Engine.Stats()`; `Width(r)`; `Mode` (`Adaptive`,
  `Always`, `Never`) and `ParseMode`.
- `client.Session.Predict` and `client.Options.Predict`: the mode, from
  `mosey -predict`.
- `server.Session`: the write log and the rules of §3.1.
