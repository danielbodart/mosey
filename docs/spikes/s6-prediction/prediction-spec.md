# Predictive local echo: specification (spike S6 draft)

Status: spike draft, written for PLAN D12. It becomes `docs/spec/prediction.md`
once Dan settles the open points in `FINDINGS.md`.

**Provenance.** This spec was written from the Mosh paper only (Winstein &
Balakrishnan, *Mosh: An Interactive Remote Shell for Mobile Clients*, USENIX
ATC 2012, mainly §2 "Terminal emulation" and §3.2 "Speculative local echo"),
plus our own design. No Mosh source code was read. Each rule below is tagged:

- **[paper §x]**: the idea is stated in the paper. The wording here is ours.
- **[ours]**: our design, either where the paper says nothing or where we
  improve on it. Numbers marked *chosen* are our own, picked for the spike, and
  were not measured from Mosh.

## 1. Model

The client holds the latest **server frame**: a structured grid of cells (glyph,
width, rendition), the cursor position and visibility, as delivered by SSP
(D9). The client has no VT parser. On top of that frame it keeps a set of
**predictions**:

- a *cell prediction*: (row, column, expected cell, input sequence number, epoch,
  informative flag);
- a *cursor prediction*: (row, column, sequence number, epoch).

The client draws the server frame, then the displayed predictions over it, then
the predicted cursor.

Each user input event (one keystroke, or one IME commit) gets the next
**input sequence number**. These are the numbers SSP already uses for the
client-to-server stream.

## 2. What the server tells the client [paper §3.2]

Each server frame carries two numbers and one bit:

- **echo ack**: the latest input that the server handed to the application
  **at least 50 ms ago**. Its effects should therefore appear in this frame.
  The 50 ms server-side timeout comes from the paper [paper §3.2]. The
  paper's reason: a client-side timeout either flickers under jitter or leaves
  mistakes on screen too long. With the server-side timeout, network jitter
  has no effect on how a prediction is judged.
- **received** [ours]: the latest input the server has received at all.
  SSP's acknowledgement of the client's state already carries this number;
  prediction reuses it (§5, §7).
- **echo-off** [ours]: the pty's line discipline has `ECHO` clear and
  `ICANON` set, read by the server with `tcgetattr` on the pty master (on
  Linux the master reports the slave's termios; measured in this spike).
  This is a canonical-mode prompt that does not echo: `passwd`, `sudo`,
  `ssh` password prompts, `read -s`. While the last frame had echo-off set,
  the client **neither predicts nor logs** input, and entering echo-off kills
  every outstanding prediction. Raw-mode applications (vim, readline, Ink)
  clear `ECHO` too but also clear `ICANON`, so they are not affected. A
  password field drawn by a raw-mode TUI is *not* covered by this bit; there
  the epoch rule (§3) is the only protection.

The paper says the server sends an extra frame about 50 ms after a keystroke
to report a new echo ack even if the screen has not changed [paper §3.2].
That frame tags keystrokes for an on-path observer (§12). Mosey sends **no
echo-ack-only frames while echo-off is set**, and whether to drop them
altogether is a decision for Dan (FINDINGS §6, measured there).

## 3. Epochs [paper §3.2]

- Predictions are made in **epochs**. Within one epoch the predictions are
  either all right or all wrong.
- A new epoch starts **tentative**. Its predictions are made in the
  background and are not drawn.
- When any prediction in an epoch is **confirmed**, the epoch becomes
  displayed: its outstanding predictions appear immediately, and so does every
  later prediction in that epoch.
- Keys that may change whether the application echoes, or that are otherwise
  hard to predict, **start a new epoch**. The paper names up/down arrows and
  control characters. Our list is in §4.

This is what makes vi (insert vs normal mode) safe: the first keystrokes
after a mode change are never shown until the server shows that it echoes.
For no-echo prompts the epoch rule is a *second* line of defence only. It is
statistical: a tentative epoch is confirmed if anything draws the predicted
glyph at the predicted cell (another process writing to the tty, `wall`,
type-ahead). The first line is the echo-off bit (§2), which stops prediction
and logging outright (unit test `TestEchoOffCoincidentalMatch` shows the
leak without it; FINDINGS §5 measures `read -s` segments).

## 4. Which keys are predicted [paper §3.2 for the principle; table is ours]

| Input | Prediction |
|---|---|
| Printable grapheme cluster of width 1 or 2 | Glyph at the cursor. Text to the right shifts by the glyph's width (insert model, §6). Cursor advances by the width. |
| Backspace (DEL 0x7f or BS 0x08) | Cursor moves back one glyph (two cells for a wide glyph). Text to the right shifts left. The vacated cell becomes blank. |
| Left arrow (CSI D / SS3 D) | Cursor moves back one glyph. |
| Right arrow (CSI C / SS3 C) | Cursor moves forward one glyph, but only over real text (§8.1). |
| Anything else: CR/LF, Tab, Up/Down, Home/End, Delete, Ctrl-anything, Esc, function keys, mouse, pastes | Not predicted. **New epoch.** |

The engine also refuses to predict, and starts a new epoch instead, when
[ours]:

- the glyph would not fit on the row. Wrapping is unpredictable: the paper
  says most of Mosh's errors (0.9 % of keys) came from word-wrap [paper §4];
- the insert would push non-blank text past the right margin;
- the cursor sits on the right half of a wide glyph;
- the glyph is a combining mark, zero-width, or wider than 2 (§9);
- any limit in §10 is reached.

## 5. Judging predictions [paper §3.2; refinements ours]

When a frame arrives with echo ack `A` and received `R`:

1. Each cell prediction with sequence number ≤ `A` is compared with the
   frame's cell at its position.
   - **Ack horizon** [ours]: if an unpredictable key (one that started a new
     epoch) with sequence number in `(seq, R]` has reached the server, the
     frame can no longer judge this prediction. Example: you type `ls` and
     press Enter, and the transient prompt redraws the line. The prediction
     is dropped without counting as right or wrong, and the frame's truth
     shows through.
   - On a **match**, the prediction is removed (the frame now shows it). If
     it was *informative*, its epoch is confirmed. The client keeps the
     **exact set** of confirmed epochs, not a high-water mark: confirming
     epoch 5 never reveals leftover predictions of an unconfirmed epoch 4.
   - On a **mismatch**, the epoch is refuted (step 3).
2. A cursor prediction with sequence number ≤ `A` is judged only if its
   sequence number is exactly `R`. Older ones have been overtaken by later
   keys. A mismatch refutes the epoch. A match **does not confirm**
   [ours]: vi's `l` moves the cursor exactly as a typed letter would.
3. **Refutation**: every prediction is removed, displayed or not. The epoch
   counter is incremented, so the new epoch is tentative. If the refuted
   prediction was on screen, this counts as a visible misprediction. The user
   sees the wrong glyphs replaced by the server's truth. The paper calls this
   being "removed within an RTT" [paper §2, §4].

**Informative predictions** [ours]. Only the glyph the user just typed
counts as evidence, and only if it differs from what the server already
showed in that cell. Cells that merely shifted, cells the prediction left
unchanged, and the cell a backspace emptied can refute an epoch but cannot
confirm one. Two measured reasons. In vim's normal mode, a blank shifted
onto a blank "confirmed" a nonsense epoch, which was then shown (ablation
`mosey-informative`: visible kills 15 → 44 at 100 ms, all traces). And at fish's
masked `read -s` prompt (raw mode, draws `●`), a backspace that emptied a
cell confirmed the epoch and the next password glyph was drawn in the
clear for about one round trip (ablation `mosey+bsconfirm`: 6–11 password
keys displayed per 555; 0 with the rule). FINDINGS §5.

The client has **no timers** of its own for judging [paper §3.2].

## 6. Shift model [ours]

The paper says applications "echo the key at the current cursor location or
not" [paper §3.2] but does not say what happens to text right of the cursor.
We use the **text-run insert model**:

- Inserting shifts right only the contiguous text run from the cursor. The
  run ends at 3 consecutive blanks (*chosen*; this protects right prompts)
  or at a decoration (§8.1).
- Deleting is the mirror image of inserting.
- Cells beyond the run are not predicted, so they keep the server's last
  value.

Rejected alternatives, measured in FINDINGS: shifting the whole row
(terminal ICH/DCH semantics) breaks against right prompts, box borders and
autosuggestions. Overwriting only the cursor cell is wrong in mid-line
inserts.

Glyphs are compared by text and width only, not by rendition [ours]. A
predicted glyph is drawn with the rendition of its left neighbour.
Syntax highlighters recolour the word as you type (`ech` red, then `echo` green), so judging by rendition refutes almost
every epoch in zsh with zsh-syntax-highlighting and in fish (FINDINGS
§4, `mosey+stylestrict`). A colour change after confirmation is cosmetic and comes from the
server's frame.

## 7. Recovering after losing track [ours; goes beyond the paper]

After a refutation or an unpredictable key, the client no longer knows where
the cursor is. The paper says only that new predictions are made "in the
background". We define three recovery modes and measured all of them:

- **blind**: keep predicting from the last belief (the literal reading of
  the paper). These predictions build on a stale cursor and usually fail
  silently. Sometimes they *coincidentally* match and confirm a wrong epoch.
- **gate**: stop predicting until a frame shows `R == latest sequence
  number`, meaning the server has every key and the base is fresh. This is
  safe, but a user who keeps typing (vi: `i` then a sentence) gets no
  prediction until they pause for an RTT.
- **rebase**: when a frame arrives at or after the unpredictable key
  (`R ≥ last bump`), or at a refutation, re-predict the inputs in
  `(R, latest]` from the client's input log, on top of the new frame, in a
  fresh tentative epoch. Epochs, echo ack and confirmation are unchanged.
  Only the base of the tentative predictions is recomputed. If any input in
  `(R, latest]` is missing from the log (evicted after 512 inputs, a paste,
  or typed while echo-off), rebase is not attempted and the client behaves
  as **gate** until `R == latest`.

Recommended: **rebase** (FINDINGS §4). It is the one place this spec
reaches past D12's "not game-style" wording, so it is flagged for Dan.

## 8. Modern shells and TUIs [ours]

### 8.1 Decorations: autosuggestions, right prompts, placeholders

A non-blank cell is a **decoration** if its rendition differs from the
rendition of the nearest glyph to its left on the same row (the text being
edited). Autosuggestions (zsh-autosuggestions, fish), right prompts and
placeholder text are drawn in a different rendition from the user's text
whatever the colour theme. This rule is colour-independent. Decorations
right of the cursor:

- end the shifted text run, so typing at the end of the input predicts only
  the typed cell. When the typed glyph matches the suggestion, the stale
  suffix still on screen is what the shell draws anyway;
- make Right-arrow unpredictable when the cell under the cursor is a
  decoration or blank, because Right accepts the suggestion;
- if a predicted blank (from a backspace) meets a decoration in the server
  frame, the prediction is dropped, not judged wrong: the shell drew a new
  suggestion there.

The first draft used a colour rule instead ("ghost": faint, palette 8 or
238–246, or a true-colour grey with max−min < 24). It was tuned on the
spike's own default-colour traces and **failed on held-out Solarized
traces** (recall 0 %; FINDINGS §7). The rendition-change rule was designed
after that failure, so the held-out traces are no longer strictly held out
for it; FINDINGS §7 states this. The colour rule may be kept as an
additional signal (`GhostAware`); it adds nothing measurable.

Known cost: in a syntax-highlighted line, a mid-line insert stops the shift
at the next differently-coloured token, so the rest of the line is stale
(not wrong) until the server's frame. Row-stale is reported in FINDINGS.

### 8.2 Hidden and drawn cursors (Ink/React TUIs)

Predictions start from the terminal cursor **even when it is hidden**. Real
Claude Code (v2.1.319, recorded in this spike) hides the terminal cursor
but parks it at the insertion point on every redraw, and draws no
reverse-video cell; the hidden cursor is the right base (FINDINGS §8).

Optional fallback for TUIs that draw their own cursor and leave the
terminal cursor elsewhere: if the cursor is hidden and exactly one isolated
reverse-video cell is on screen, that cell is the **visual cursor**. On the
spike's own faketui it agreed with the application's real insertion point on
471 of 488 keys. No real application in the traces needs it, so it is not
part of the recommended default until one does.

### 8.3 Right prompts and transient prompts

The 3-blank run terminator and the decoration rule stop inserts from
pushing a right prompt. A transient prompt rewrites the finished line on
Enter; Enter starts a new epoch. The ack horizon (§5) is not specific to
transient prompts: it removes the flicker of already-correct predictions
that a frame arriving after Enter (or any unpredictable key) would
otherwise judge against a redrawn line. Measured effect: visible kills fall
from 38 to 5 (evdo, 450 ms), 55 to 9 (train) and 59 to 17 (100 ms + 29 %
loss), across bash and zsh-plain as well as zsh-full and fish; on links of
100 ms and less without loss it changes nothing measurable. Instant and
wrong rates are identical with and without it (FINDINGS §4).

### 8.4 Completion pagers and menus

Tab and the arrow keys are unpredictable (§4). Tab, then a printable key,
in fish's pager or zsh's menu-select is caught by the gate or rebase step
after the bump.

## 9. Wide characters and grapheme clusters [ours; Mosh PR #1410 was the motivation]

- The input is segmented into grapheme clusters (UAX #29). One prediction is
  made per cluster.
- The width of a cluster is computed by **the same width function as the
  server's emulator**. In production the server names a width-table
  **version identifier** from a fixed set compiled into the client (e.g.
  "unicode-16.0+mosey-1"), inside the authenticated handshake transcript. A
  client that does not know the identifier does not predict wide or
  ambiguous-width clusters. We do not send width tables over the wire; if a
  future version must, the table is size-capped (a few KB of ranges) and
  carried inside the authenticated transcript, so a peer can only make its
  own user's predictions wrong, never consume unbounded client memory. If
  the two sides disagree, every wide glyph is a misprediction (visible, then
  corrected within an RTT), not a safety problem.
- A width-2 cluster takes its own cell plus a continuation cell (width 0).
  Backspace and arrow keys step over both.
- These are not predicted, and start a new epoch instead: combining or
  zero-width clusters typed alone, clusters wider than 2, clusters with
  explicit bidi controls, and strong right-to-left scripts. The terminal's
  bidi policy decides where those land.

## 10. Hostile-input and resource limits [ours]

Predictions come only from the local user's own bytes, and they are judged
only against structured cells. Even so:

| Limit | Value (*chosen*) | Why |
|---|---|---|
| Input event size | 64 bytes, else unpredictable | **Performance only**: one event is never worth more than a row of predictions. It is not a security control: a paste of ≤ 64 bytes, or one split over several reads, passes it. |
| Bracketed paste | everything from `ESC[200~` to `ESC[201~` is unpredictable, across any number of input events | Pastes are not keystrokes; predicting them gains nothing. This is not a security boundary either: predicting a paste never changes what the server runs. |
| Grapheme cluster | ≤ 32 bytes, ≤ 8 code points | Zalgo text and pathological clusters |
| Outstanding cell predictions | ≤ 1024 | Memory and CPU bound while the server is stalled |
| Input log for rebase | the last 512 inputs, copied (never aliasing the caller's buffer), zeroed on eviction, nothing logged while echo-off | Bounded replay cost; no password bytes held |
| C0/C1 controls, bidi controls | Never placed in a predicted cell | The client draws only printable glyphs it chose |
| Work | O(W·H) per frame (judging, visual cursor), O(W) per predicted key, plus a rebase replay of at most 512 inputs per founding frame | No quadratic behaviour on a long row. The visual cursor is computed once per frame, not per key. |

A fuzz target (`FuzzEngine`) drives all three recovery modes with arbitrary
keys and an arbitrary server: screen sizes 1×1 to 120×40, resizes, echo acks
and received counts that jump, decrease or exceed what was sent, reverse
and ghost-styled cells, and the echo-off bit. It asserts: drawn cells and
cursor in bounds; pending cells ≤ cap + W; log ≤ 512; bounded cursor,
bump and confirmed-epoch state; and that **no displayed cell belongs to an
epoch without a confirmation**. Not covered: wide glyphs in the server's
cells (only ASCII is echoed back), CPU time per call, and a server that
lies consistently (echoes what was typed but runs something else). That
last one is outside the threat model: the server is authenticated.

## 11. Display policy [paper §2; thresholds from a black-box measurement]

- **adaptive** (default): draw predictions only when SRTT is at or above a
  show threshold; below it, server echo is quick enough.
- **Underline** unconfirmed predictions above a second, higher threshold.
  The paper describes the underline trailing the cursor and vanishing as
  responses arrive [paper §2].

Provenance of the thresholds. The paper gives no numbers. The first draft
of this spec used 30 ms and 80 ms with no derivation; a reviewer flagged
that these may have been recalled from Mosh's source, so they were removed
and re-derived as a **black-box measurement** of the installed `mosh-client`
(`scripts/moshprobe.sh`: loopback inside a throwaway user+network namespace,
`tc netem` delay, slow typing, a vt emulator watching the client's screen).
Results are in FINDINGS §3. They are expressed as the netem round trip,
since mosh's internal SRTT estimator is not observable; our own SRTT
(SSP, D11) will sit a few ms above the netem RTT. Mosey's defaults are set
from that measurement and should be re-tuned against S5's SRTT estimator.
- `always` / `never` for users, matching mosh's documented `--predict`
  option names (mosh(1) man page).

The spike measured with `always`, so the metrics cover every keystroke.

## 12. Threat model: keystroke timing [ours]

SSP (D11) sends each keystroke in its own datagram, so an on-path observer
already sees the timing of client-to-server packets; under D4 (public
internet) this is in scope. Inter-keystroke timing leaks information about
what is typed, including password length and, statistically, content (Song,
Wagner, Tian, *Timing Analysis of Keystrokes and Timing Attacks on SSH*,
USENIX Security 2001). OpenSSH 9.5 added `ObscureKeystrokeTiming` (chaff
packets at a fixed interval while typing) for this reason.

Prediction adds one thing on top: the paper's **echo-ack-only frame**. When
a keystroke produces no screen change (a no-echo prompt), the server would
still send a frame ~50 ms later. That reply distinguishes keystrokes from
heartbeats and acks in the server-to-client direction too, and it is
exactly the case where the content is a password. Options, measured in
FINDINGS §6:

1. **No echo-ack-only frames while echo-off** (adopted). Costs nothing
   visible: nothing is predicted at a no-echo prompt anyway.
2. **Piggyback only**: the echo ack rides only on frames already due
   (screen change, retransmission, heartbeat). Removes the tag everywhere.
   Cost: tentative epochs confirm later.
3. **Chaff**: while input is active, send client-to-server packets at a
   fixed interval (e.g. every 20 ms) and keep the server's reply cadence
   fixed, as OpenSSH 9.5 does. Hides timing in both directions at a
   bandwidth cost. This belongs to SSP (D11), not prediction, and is for S5
   to measure.

Options 1 and 2 only stop prediction from making the leak worse. The
underlying leak from per-keystroke datagrams needs option 3.
