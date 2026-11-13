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

Each server frame carries two numbers:

- **echo ack**: the latest input that the server handed to the application
  **at least 50 ms ago**. Its effects should therefore appear in this frame.
  The 50 ms server-side timeout comes from the paper [paper §3.2]. The
  paper's reason: a client-side timeout either flickers under jitter or leaves
  mistakes on screen too long. With the server-side timeout, network jitter
  has no effect on how a prediction is judged.
- **received** [ours]: the latest input the server has received at all.
  SSP's acknowledgement of the client's state already carries this number;
  prediction reuses it (§5, §7).

To report a new echo ack, the server sends an extra frame about 50 ms after
a keystroke even if the screen has not changed [paper §3.2].

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

This is what makes vi (insert vs normal mode) and `passwd` (no echo after
Enter) safe. The first keystrokes after a mode change are never shown until
the server shows that it echoes.

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
     it was *informative*, its epoch is confirmed.
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

**Informative predictions** [ours]. Only the cell the user just changed
counts as evidence: the typed glyph, or the cell a backspace emptied, and
only if it differs from what the server already showed there. Cells that
merely shifted, or that the prediction left unchanged, can refute an epoch
but cannot confirm one. Without this rule the spike measured false
confirmations in vim's normal mode: a blank shifted onto a blank "confirmed"
a nonsense epoch, which was then shown. See FINDINGS §4.2.

The client has **no timers** of its own for judging [paper §3.2].

## 6. Shift model [ours]

The paper says applications "echo the key at the current cursor location or
not" [paper §3.2] but does not say what happens to text right of the cursor.
We use the **text-run insert model**:

- Inserting shifts right only the contiguous text run from the cursor. The
  run ends at 3 consecutive blanks (*chosen*; this protects right prompts)
  or at ghost text (§8.1).
- Deleting is the mirror image of inserting.
- Cells beyond the run are not predicted, so they keep the server's last
  value.

Rejected alternatives, measured in FINDINGS: shifting the whole row
(terminal ICH/DCH semantics) breaks against right prompts, box borders and
autosuggestions. Overwriting only the cursor cell is wrong in mid-line
inserts.

Glyphs are compared by text and width only, not by rendition [ours]. A
predicted glyph is drawn with the rendition of its left neighbour, unless
that neighbour is ghost text. Syntax highlighters recolour the word as you
type (`ech` red, then `echo` green), so judging by rendition refutes almost
every epoch in zsh with zsh-syntax-highlighting and in fish (FINDINGS
§4.1). A colour change after confirmation is cosmetic and comes from the
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
  Only the base of the tentative predictions is recomputed.

Recommended: **rebase** (FINDINGS §5). It is the one place this spec
reaches past D12's "not game-style" wording, so it is flagged for Dan.

## 8. Modern shells and TUIs [ours]

### 8.1 Ghost text (zsh-autosuggestions, fish autosuggestions, placeholders)

A cell is **ghost** if it is non-blank and faint (SGR 2), or if its
foreground is a dark grey: palette 8 or 238–246, or a true-colour grey with
max−min < 24 and max between 0x40 and 0xA0. This is a heuristic (*chosen*).
Ghost text right of the cursor:

- is never shifted. Typing over it predicts only the typed cell. When the
  typed glyph matches the suggestion, the stale ghost suffix still on screen
  is exactly what the shell will draw;
- makes Right-arrow unpredictable, because Right accepts the suggestion;
- is never used as the rendition for a predicted glyph.

### 8.2 Drawn cursors (Ink/React TUIs, e.g. Claude Code's style)

If the terminal cursor is hidden and exactly one isolated reverse-video cell
is on screen, that cell is the **visual cursor**. Predictions start from it,
and cursor predictions are judged against it. A reverse cell that sits on
placeholder (ghost) text counts as ghost.

### 8.3 Right prompts and transient prompts

The 3-blank run terminator stops inserts from pushing a right prompt. A
transient prompt rewrites the finished line on Enter. Enter starts a new
epoch, and the ack horizon (§5) drops predictions from the old line without
calling them wrong.

### 8.4 Completion pagers and menus

Tab and the arrow keys are unpredictable (§4). Tab, then a printable key,
in fish's pager or zsh's menu-select is caught by the gate or rebase step
after the bump.

## 9. Wide characters and grapheme clusters [ours; Mosh PR #1410 was the motivation]

- The input is segmented into grapheme clusters (UAX #29). One prediction is
  made per cluster.
- The width of a cluster is computed by **the same width function as the
  server's emulator**. In production the server announces its width table or
  version in the handshake, and the client uses that table. If the two
  disagree, every wide glyph is a misprediction.
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
| Input event size | 64 bytes, else treated as a paste: unpredictable | Pasted text from a hostile web page should never be "echoed" ahead of the server. A paste also has no keystroke rhythm to hide. |
| Grapheme cluster | ≤ 32 bytes, ≤ 8 code points | Zalgo text and pathological clusters |
| Outstanding cell predictions | ≤ 1024 | Memory and CPU bound while the server is stalled |
| Input log for rebase | the last 512 inputs | Bounded replay cost |
| C0/C1 controls, bidi controls | Never placed in a predicted cell | The client draws only printable glyphs it chose |
| Work per keystroke | O(row width) | No quadratic behaviour on a long row |

A fuzz target (`FuzzEngine`) checks that all three recovery modes stay in
bounds on arbitrary input and frame streams.

## 11. Display policy [paper §2; thresholds chosen]

- **adaptive** (default): draw predictions only when SRTT ≥ 30 ms
  (*chosen*). Below that, echo from the server is quick enough to be
  invisible.
- **Underline** unconfirmed predictions when SRTT > 80 ms (*chosen*). The
  paper describes the underline trailing the cursor and vanishing as
  responses arrive [paper §2].
- `always` / `never` for users, matching mosh's documented `--predict`
  option names (mosh(1) man page).

The spike measured with `always`, so the metrics cover every keystroke.
