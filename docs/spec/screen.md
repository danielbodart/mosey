# Screen: the terminal model, the cell-diff format and the allow-list

Owner: **screen** (`internal/screen`, `internal/render`, `internal/emu`).
Slice 1. Written before the code, as PLAN §4 and §6 ask, and the code is
written from it.

This document covers:

- the screen model (`screen.Grid`) and its invariants;
- the cell-diff wire format (O11);
- the D9/D27 allow-list and the D23 bounds;
- what the server's emulator must do to fill a Grid;
- what the client's renderer must do to draw one;
- what the client must never do.

PLAN §2 (D1–D28) is locked. Where this document cites a decision, the
decision wins. Where it needs an interface that `internal/` does not have
yet, §11 lists the change. The code is not edited from here.

**Provenance of constants.** Every number carries one of these tags:

| tag | meaning |
|---|---|
| [D*n*] | a locked decision in PLAN §2 |
| [paper §*x*] | Winstein & Balakrishnan, USENIX ATC 2012 |
| [measured S2] / [measured S5] | the spike findings in `docs/spikes/` |
| [measured here] | counted for this spec from files committed in the repo (the method is given) |
| [RFC *n*] / [ECMA-48] / [xterm] | a published standard, or xterm's documented control sequences (ctlseqs) |
| [derived] | our own choice; the reasoning sits next to it |

Nothing here is taken from Mosh's source (PLAN §4). The diff format is new
and mosey's own. Mosh's only part in it is the idea, from the paper, that
the server-to-client object is the screen and that intermediate screens may
be skipped [paper §2, §2.3].

---

## 1. The rule this all serves (D9)

The server runs the terminal emulator. The client receives structured
cells and draws them with escape sequences it writes itself. **The client
never parses a remote escape sequence.** It has no VT parser on any path
that bytes from the network can reach. Only four kinds of remote-chosen
bytes are ever written to the user's real terminal:

1. cell text: grapheme clusters that passed the allow-list (§4.2);
2. the window title, through the allow-list (§4.1);
3. OSC 8 link URIs, through the allow-list (§4.3);
4. OSC 52 clipboard data, which the client base64-encodes itself, so it
   never reaches the terminal raw (§4.4).

Every other byte the client writes comes from a fixed table in
`internal/render` (§8.2), with numbers formatted by the client.

Kinds 1 and 2 reach the terminal as UTF-8 only when the local locale's
codeset is UTF-8. Otherwise every non-ASCII character is written as `?`
(§8.3). A terminal that is not in UTF-8 mode can read the continuation
bytes 0x80–0x9F inside ordinary UTF-8 as C1 controls (`threat-model.md`
§4.7).

The allow-list is enforced at both ends [D23]. The server sanitises: its
emulator snapshot replaces or drops anything outside the list. The client
re-checks: `Grid.Apply` refuses a whole diff that breaks the list. The
same `Apply` also guards proto against a compromised emu (§7.3), so one
fuzzed decoder protects both boundaries.

## 2. The screen model

### 2.1 Fields

`screen.Grid` (`internal/screen/grid.go`) holds:

| field | meaning | on the wire (§5) |
|---|---|---|
| cells | `cols × rows` of `Cell{Text, Width, Style}` | SIZE, row and cell ops |
| `Cursor` | `X`, `Y`, `Visible`, `Shape` | CURSOR / HERE, CURSTYLE |
| `Title` | the window title (OSC 0/2), allow-listed | TITLE |
| `Modes` | input modes the client mirrors (§8.5) | MODES |
| `EchoOff` | `!ECHO && ICANON` on the pty [D12] | ECHO |
| `EchoAck` | newest keystroke the program has had for 50 ms [paper §3.2]; used by prediction, a later slice | ECHO |
| `Clipboard` | latest OSC 52 write, `{Seq, Data}` [D27] | CLIP |
| `Bell` | count of bells | BELL |
| `Rebuilt` (proposed, §11 item 1) | `{Seq, Reason}`: the emulator was rebuilt [D23] | REBUILT |

`Style` is `{Fg, Bg, Underline Color; Attrs; Link string}`. `Color` is
`DefaultColor` (0), `Palette(i)` (`1<<24 | i`) or `RGB(r,g,b)`
(`2<<24 | r<<16 | g<<8 | b`). `Attrs` are the ten bits defined in
`grid.go`, from `Bold` (bit 0) to `Strikethrough` (bit 9).

### 2.2 Invariants

Every Grid that `Apply` returns, and every Grid that an emulator's
`Snapshot` produces, satisfies all of these. `Apply` checks the ones a diff
can break (§5.8). Tests check all of them through `Grid.Valid` (§11
item 4).

- **G1, size.** `1 ≤ cols ≤ MaxCols` and `1 ≤ rows ≤ MaxRows`. The single
  exception is version 0 (§2.3), which is 0 × 0.
- **G2, widths.** Every cell's `Width` is 0, 1 or 2.
  - A cell has `Width` 0 if and only if the cell to its left in the same
    row has `Width` 2.
  - A `Width`-2 cell is never in the last column.
- **G3, continuation cells.** A `Width`-0 cell has `Text == ""` and the
  same `Style` as the `Width`-2 cell before it.
- **G4, text.**
  - A `Width`-1 cell's `Text` is either `""` (a blank) or a valid cluster
    (§4.2).
  - A `Width`-2 cell's `Text` is a valid cluster and is never empty.
  - `Text` is never `" "` (a single space). Blanks are `""`, so two grids
    that draw the same compare equal (§2.4).
- **G5, links.** Every `Style.Link` is `""` or a valid link (§4.3). Across
  the whole grid, there are at most `MaxLinks` distinct non-empty links,
  and their total length is at most `MaxLinkBytes`.
- **G6, style.**
  - Each `Color` is one of the three forms in §2.1, and no other bits are
    set.
  - `Attrs` has no bit above 9.
  - At most one of `Underlined`, `DoubleUnderline` and `CurlyUnderline` is
    set. They are one underline style, not three flags.
- **G7, cursor.**
  - `0 ≤ X < cols` and `0 ≤ Y < rows`. The emulator's "pending wrap"
    column, one past the last, is clamped to `cols − 1`.
  - `Shape` is in 0..6 (DECSCUSR [xterm]).
- **G8, the rest.**
  - `ValidTitle(Title)`.
  - `len(Clipboard.Data) ≤ MaxClipboard`.
  - `Modes` fields are within their enums: `Mouse` 0..3, `MouseEncoding`
    0..1, and `KittyKeyboard` 0..31 (the five progressive-enhancement
    flags).
  - `Rebuilt.Reason` is in 0..3.

### 2.3 Version 0

SSP starts both ends at version 0, "the empty object both sides know"
(`ssp.NewEndpoint`). For the screen, version 0 is `NewGrid(0, 0)`. It has:

- no cells;
- every field at its zero value: cursor at (0,0) and *not* visible, shape
  0, empty title, zero modes, zero counters, no clipboard.

A 0 × 0 grid is valid only as version 0. No diff may target 0 × 0 (SIZE
refuses 0, §5.6). `NewGrid(cols, rows)` for any other size gives blank
cells and zero values in every other field. The emulator's first snapshot
then sets `Visible` and whatever else it needs, and the first diff carries
the change.

### 2.4 Equality, clones, resizing

- **`Equal`** compares everything listed in §2.1:
  - the size and every cell's `Text`, `Width` and `Style`;
  - `Cursor`, `Title`, `Modes`, `EchoOff` and `EchoAck`;
  - `Clipboard.Seq` together with `Clipboard.Data` (byte-equal);
  - `Bell` and `Rebuilt`.

  Equal grids draw the same and drive input the same. `Diff(g, g)` is
  always empty, and an empty diff is valid and changes nothing.
- **`Clone`** is deep, but rows may be shared copy-on-write. This note is
  not normative, but it matters. SSP clones every version it keeps, and a
  full copy at the clamp is 500,000 cells, about 28 MB at 56 bytes per
  `Cell` (a Go-struct estimate [derived]). Sharing immutable row slices
  makes a clone cost one slice of row pointers.
- **Fitting a row to width `C`** (used by `Resize`, SIZE, ROWS and SCROLL):
  1. Keep cells `0..min(len, C)−1`.
  2. If cell `C−1` now has `Width` 2, replace it with a blank of the same
     `Style`. Its continuation fell off the edge, and G2 must hold.
  3. Pad to `C` with default blanks (`Cell{Text: "", Width: 1}`).
- **`Resize(cols, rows)`**:
  - keeps rows `0..min(R, rows)−1`, each fitted to `cols`;
  - fills any new rows with default blanks;
  - clamps the cursor into the new bounds.

  It never reflows. The emulator decides what a resize does to the content
  (`grid.go`), and the next diff carries the outcome.

## 3. Bounds

| constant | value | provenance | enforced where |
|---|---|---|---|
| `MaxCols` × `MaxRows` | 1000 × 500 | [D23]; S2 measured 2.9 GiB in tuios at 5000 × 5000 [measured S2] | server: `ClampSize` before the pty and the emulator; client: SIZE |
| scrollback lines | `min(10000, ScrollbackCells / cols)` | [D23]; worst case about 100 B per history cell without links [measured S2] | emu, on every `Resize` |
| `ScrollbackCells` | 1,000,000 | [D23] | emu (`emu.DefaultScrollbackCells`) |
| emu `MemoryMax` | 512 MiB | [D23], [measured S2] | spawner's cgroup for emu (`server.md`) |
| `MaxCluster` | 64 bytes | tuios' own cluster cap [measured S2] | both ends, §4.2 |
| `MaxTitle` | 256 bytes, cut on a rune boundary | [derived]: far longer than any useful title, and the cap S2's allow-list used | both ends, §4.1 |
| `MaxLink` | 2048 bytes | [D27] | both ends, §4.3 |
| `MaxLinks` | 4096 distinct links per grid | [derived]: a full 1000 × 500 screen of `ls --hyperlink` names stays under it; it bounds client memory, which tuios does not (S2 measured link storage growing without limit) | both ends, G5 |
| `MaxLinkBytes` | 1 MiB of distinct link text per grid | [derived]: matches S2's link-table cap [measured S2]; 4096 × 2048 would be 8 MiB, more than a screen needs | both ends, G5 |
| `MaxClipboard` | 64 KiB of decoded data | [derived]: [D27] asks for a cap and leaves the value to this spec. 64 KiB covers a long yank, and its 87 KiB of base64 is a few dozen datagrams. A larger write is dropped whole, never truncated: a truncated paste is a different paste | emu drops; client: CLIP |
| `MaxDiff` | 48 MiB | [derived] §5.12 | `Apply` (a longer diff is refused unread), `ssp.Config.MaxRemoteBytes`, the IPC `Update` |
| cells written per diff | `2 × cols × rows` | [derived]: an encoder writes each cell at most once, plus one erase pass; this bounds the decoder's work, not only the diff's length | `Apply`, §5.8 |
| reply queue | 64 KiB, drop and count | [measured S2]: the naive design deadlocked in 0.2 s; a 64 KiB bounded queue completed | emu / proto (`server.md`) |
| `SyncHold` | 200 ms | [derived]: longer than any well-behaved synchronised frame, short enough that a program that never closes mode 2026 freezes its screen only briefly | emu holds its snapshot; proto's timer asks for it again (§6.3) |

A window size from the client is untrusted input, even though the client
is authenticated [measured S2]. The server applies `ClampSize` (to
`[1, MaxCols] × [1, MaxRows]`) before the pty's `TIOCSWINSZ` and before
`Emulator.Resize`. The client's decoder refuses a SIZE outside the same
range.

## 4. The allow-list (D9, D27)

Each rule has two halves:

- a **Sanitize** function, run by the server's emulator snapshot, which
  repairs or drops;
- a **Valid** test, run by the client inside `Apply`, which refuses the
  whole diff.

`ValidX(s)` is defined as `SanitizeX(s) == s`, so the two halves cannot
drift apart. The functions live in `internal/screen/allow.go`.

The **forbidden code points**, used below, are:

| set | code points | why |
|---|---|---|
| C0 | U+0000–U+001F | terminal controls (ECMA-48) |
| DEL | U+007F | |
| C1 | U+0080–U+009F | 8-bit controls: U+009B is CSI, U+009D is OSC. S2's review got `"a\u009d0;evil\u009cb"` into a title [measured S2] |
| bidi embedding, override and isolate | U+202A–U+202E, U+2066–U+2069 | they reorder the text that follows them in a terminal that does bidi (Trojan Source, CVE-2021-42574) |
| bidi marks | U+061C, U+200E, U+200F | stateless. Stripped from titles [D27]; allowed in cells (§4.2) |
| line and paragraph separators | U+2028, U+2029 | [derived]: some renderers break lines on them; nothing legitimate needs them in a terminal |

### 4.1 Title (OSC 0, OSC 2)

`SanitizeTitle(s)`:

1. Drop invalid UTF-8 byte by byte (`utf8.DecodeRuneInString`, rune error
   with size 1).
2. Drop every forbidden code point, including all the bidi marks [D27].
3. If the result is longer than `MaxTitle` bytes, cut it at the last rune
   boundary at or before `MaxTitle`.

An empty title is valid and means "no title". OSC 1 (the icon name) is
ignored. The title stack (XTWINOPS 22/23) is the emulator's business; only
its current title is in the Grid.

### 4.2 Cell text

The **server decides grapheme clusters and widths** [measured S2: programs,
emulators and local terminals use different width tables]. The client
never segments text or measures widths. A valid cluster is:

- valid UTF-8, 1 to `MaxCluster` bytes;
- no C0, DEL, C1, bidi embedding/override/isolate, U+2028 or U+2029.

The bidi marks U+061C, U+200E and U+200F *are* allowed in cells. They are
stateless, they appear in real text, and each run of cells is placed by an
explicit cursor move (§8.3), so they can't move text across cells.

`SanitizeCluster(s)` returns `s` if it is valid, and U+FFFD (`"�"`)
otherwise. The cell keeps its width, so the layout does not shift.

### 4.3 OSC 8 hyperlinks

`SanitizeLink(uri)` returns `uri` unchanged if all of these hold, and `""`
otherwise:

1. `1 ≤ len(uri) ≤ MaxLink` [D27].
2. Every byte is printable ASCII, 0x21–0x7E. There are no spaces or
   controls, and IRIs must be percent-encoded. This also rules out ESC,
   BEL and ST inside the URI.
3. The bytes before the first `:` match `http`, `https` or `mailto`, ASCII
   case-insensitively (RFC 3986 §3.1: schemes are case-insensitive) [D27],
   and at least one byte follows the `:`.

When a link is dropped, the cell keeps its text and loses the link.
OSC 8's `id=` parameter is not carried. The client writes links without
one (§8.4). `file:`, `javascript:`, `data:`, `ssh:` and every other scheme
are refused [D27].

The server admits links into a snapshot in reading order (row by row, left
to right). A link not seen before is admitted only while G5's budget
(`MaxLinks`, `MaxLinkBytes`) allows it. A cell whose link is refused keeps
its text with `Link == ""`.

### 4.4 OSC 52 clipboard

- **Writes** (`OSC 52 ; <sel> ; <base64> ST`):
  - The emulator decodes the base64. If the decoded data is at most
    `MaxClipboard` bytes, it becomes `Clipboard.Data` and `Clipboard.Seq`
    goes up by one.
  - Larger writes are dropped whole and counted in the log.
  - The selection parameter is ignored. The client always writes the
    clipboard (`c`).
  - An empty write is allowed. It clears the clipboard.
  - The data may be any bytes, because the client base64-encodes them
    again before writing (§8.4).
- **Reads** (`OSC 52 ; <sel> ; ?`) are never passed on [D27]. The
  emulator answers them as tuios does by default: an empty clipboard
  [measured S2]. The client never reads the local clipboard for the
  server.

### 4.5 Never passed through

Everything not listed in §1 is consumed by the server's emulator and never
reaches the client in any form. That includes:

- DCS, APC, PM and SOS strings;
- sixel and kitty graphics (answered "unsupported"; kitty uploads that
  name a file are refused);
- OSC 4/10/11 colour queries, which the emulator answers with the client's
  colours from `emu.Options`;
- OSC 7, OSC 9, OSC 777 and OSC 133;
- DECCOLM;
- XTWINOPS resize and report requests;
- every query whose answer would come from the user's terminal.

The remote side can never resize, query or reconfigure the user's
terminal, except for the input modes the client chooses to mirror (§8.5).

## 5. The diff format (O11)

### 5.1 What went wrong before, and the design that follows

O11 says S2's prototype came out bigger than raw output at its cadence.
S5's encoder did too:

| encoder | stream | pty bytes | diff bytes | diff / pty |
|---|---|---|---|---|
| S2 prototype, a frame per 1 KiB [measured S2] | claude / htop / less / unicode / vim | 6,021 / 34,849 / 8,908 / 1,073 / 14,865 | 7,896 / 48,139 / 9,945 / 1,684 / 19,299 | 1.31 / 1.38 / 1.12 / 1.57 / 1.30 |
| S2 prototype [measured S2] | fish / zsh | 2,646 / 23,259 | 1,438 / 16,652 | 0.54 / 0.72 |
| S5 O8 encoder, SSP schedule, 120 × 40, 50 ms [measured S5, pty bytes measured here*] | less / shell / vim | 71,391 / 4,787 / 48,826 | 208,849 / 16,274 / 62,376 | **2.93 / 3.40 / 1.28** |
| S5 O8 encoder [as above] | flood | 198,973 | 1,337 | 0.007 |

\* The pty bytes are the payload lengths summed over the committed
`spikes/s5-netsim-ssp/testdata/captures/*.bin`. Each file is a sequence of
records: a big-endian u64 in µs, a big-endian u32 length, then the bytes.
S5's own table reports its diff bytes as "raw", meaning its uncompressed
diff, not pty bytes.

The causes, read from the two encoders (both are our own spike code):

1. **A length prefix on every cell** (S2). An ASCII cell cost 2 bytes,
   where the terminal pays 1.
2. **One span per row, from the first change to the last** (S2). This
   restates every unchanged cell in between.
3. **No scroll detection** (S5). In `less`, each line scrolled restated all
   40 rows; the median frame was 4,704 bytes. S2's prototype had only a
   whole-screen scroll-up.
4. **A style record at the start of every run** (S5's was the SGR string
   itself), and style definitions (S2).
5. **A fixed header on every frame**, about 10 bytes in S5. Most of the
   shell session's 323 frames were keystroke echoes, which a terminal
   gets in 1 byte.

Coalescing at SSP's frame rate helps only some of this. S5 already
coalesced, and `less` still came out at 2.93×.

The design answers each cause:

| cause | this format |
|---|---|
| 1 | Printable ASCII is 1 byte per cell, with no prefix. A non-ASCII code point is its own UTF-8 bytes. Width 2 is a mode, switched by one byte per run, not per cell. Only a cluster of several code points pays 1 byte of prefix (§5.5). |
| 2 | Any number of spans per row. The write position moves with 1–3 byte ops (SKIP, COL, NEXT, POS). |
| 3 | SCROLL (2 bytes) and ROWS map target rows to *any* rows of the base. That covers whole-screen scrolls, scroll regions, and inserted or deleted lines. COPY moves cells within or between rows, for inserted and deleted characters. |
| 4 | A pen that persists through the whole diff, changed by deltas of only the fields that change. Links are defined once per diff and referred to by index. |
| 5 | No frame header. The write position starts at the cursor. An echo is `TEXT+HERE`, 2 bytes for one character (§5.11, example 1). |

The result: a diff states each changed cell at most once, at about the
terminal's own cost for its text, with positioning and styling cheaper
than the escape sequences a program would use. §5.12 has the per-change
costs and the acceptance gate.

The diff never refers to anything the receiver doesn't hold. SSP diffs
from a version the receiver has acknowledged [paper §2.3], and every op
reads only that base and the diff's own bytes. There is no cross-diff
dictionary and no style table that outlives a diff, so a lost datagram
can't desynchronise anything.

### 5.2 Primitives

- **varint**: an unsigned LEB128, as `encoding/binary.Uvarint` reads it,
  at most 10 bytes.
  - It must be minimal: a multi-byte varint whose last byte is 0x00 is an
    error.
  - Each field has a bound. The decoded `uint64` is compared with that
    bound *before* it is converted to `int`.
  - **No check adds or multiplies a wire value.** A sum such as
    `x + n ≤ C` wraps around in `uint64`: with `x = 5` and
    `n = 2^64 − 3` it is 2, and the check passes. So every bound in §5.6
    has the wire value alone on one side, and on the other a constant or
    a difference of decoder state whose order is already known (`C − x`,
    where `x ≤ C` always holds). Products become divisions:
    `n ≤ (C − x) / W`. The forms in §5.6 are normative, and a sum of a
    wire value with anything is a bug.
- **byte**: one octet.
- **colour**: one kind byte, then its payload.

  | kind | payload | `screen.Color` |
  |---|---|---|
  | `0x00` | none | `DefaultColor` |
  | `0x01` | index byte | `Palette(index)` |
  | `0x02` | `r g b` bytes | `RGB(r, g, b)` |
  | any other | | error |

- **string**: `varint length` then that many bytes. The length bound is
  given per field.

A diff is a sequence of ops, each starting with an opcode byte. There is
no header, no trailer and no padding. An empty diff (zero bytes) is the
identity. The format is versioned by the handshake's hello, not inside
the diff: both ends run the same binary [D7]. An unknown opcode is an
error, never skipped.

### 5.3 Decoder state

`Apply(diff)` works on a scratch copy of the Grid (copy-on-write rows) and
swaps it in only after the whole diff has parsed and validated (§5.8).
State during a diff:

| state | initial value |
|---|---|
| `C, R` (size) | base size, then SIZE's if present |
| rows | base rows (or as set up by SIZE / ROWS / SCROLL) |
| `x, y` (write position) | the cursor's position after SIZE's clamp (§2.4). Always `0 ≤ x ≤ C` and `y < R` (except in version 0, where there are no cells to write). `x = C` is reached by writing the last cell of a row; every op that writes or sets the cursor there checks `x < C` first |
| pen | the default `Style{}` |
| `w` (width for single code points) | 1 |
| last character | none |
| link table | empty; index 0 means "no link" |
| phase | 0 |
| state ops seen | none |
| cells written | 0, against a budget of `2 × C × R` (at most 10⁶, so it fits in any `int`). Every write op checks `k ≤ budget − written` for the `k` cells it is about to write, before it writes any (§5.8) |

### 5.4 Opcodes

| opcode | name | arguments | phase allowed |
|---|---|---|---|
| `0x00`–`0x3F` | TEXT (short) | stream of `opcode + 1` bytes (1–64) | 2 |
| `0x40` | TEXT (long) | `varint L` (1 ≤ L ≤ bytes left), stream of L bytes | 2 |
| `0x41` | SIZE | `varint cols`, `varint rows` | 0 (first op only) |
| `0x42` | ROWS | `varint dst`, `varint src`, `varint n` | 0–1 |
| `0x43` | SCROLL | `varint n` | 0–1 |
| `0x44` | POS | `varint y`, `varint x` | 2 |
| `0x45` | COL | `varint x` | 2 |
| `0x46` | NEXT | none | 2 |
| `0x47` | SKIP | `varint n` | 2 |
| `0x48` | ERASE | `varint n` (0 = to end of row) | 2 |
| `0x49` | ERASED | none | 2 |
| `0x4A` | REPEAT | `varint n` | 2 |
| `0x4B` | COPY | `varint sy`, `varint sx`, `varint n` | 2 |
| `0x4C` | PEN | `byte flags`, then fields | 2 |
| `0x4D` | LINK | string (1..`MaxLink`) | 2 |
| `0x50` | CURSOR | `varint x`, `varint y` | 2, once* |
| `0x51` | HERE | none | 2, once* |
| `0x52` | CURSTYLE | `byte` | 2, once |
| `0x53` | TITLE | string (0..`MaxTitle`) | 2, once |
| `0x54` | MODES | 4 bytes | 2, once |
| `0x55` | ECHO | `byte flags`, `varint ack` | 2, once |
| `0x56` | BELL | `varint count` | 2, once |
| `0x57` | CLIP | `varint seq`, string (0..`MaxClipboard`) | 2, once |
| `0x58` | REBUILT | `varint seq`, `byte reason` | 2, once |
| `0x80`–`0xBF` | TEXT+HERE (short) | stream of `opcode − 0x7F` bytes (1–64), then as HERE | 2, once* |
| anything else | | | error |

\* CURSOR, HERE and TEXT+HERE all set the cursor. Together they may appear
at most once per diff.

**Phases.**

- **Phase 0** is the very start of the diff. SIZE is allowed only as the
  first op.
- **Phase 1** comes after SIZE, or at the start if there is no SIZE. ROWS
  and SCROLL are allowed here, and only here.
- **Phase 2** begins at the first op that is not SIZE, ROWS or SCROLL.
  From then on, SIZE, ROWS or SCROLL is an error.

When phase 1 ends, the row map (§5.6) is fixed. Every later op reads and
writes the rows as they stand after it.

Reserved for later slices, and errors until a spec section defines them:

- `0x59`–`0x5F`: more state;
- `0x60`–`0x6F`: scrollback, for the later lazy-scrollback work;
- `0x4E`–`0x4F`, `0x70`–`0x7F` and `0xC0`–`0xFF`.

### 5.5 The text stream

TEXT, TEXT (long) and TEXT+HERE carry a *stream*: bytes that write cells
at `(x, y)`, moving `x` along. A stream is read byte by byte:

| first byte `b` | meaning | consumes |
|---|---|---|
| `0x20` | a blank cell: `Text ""`, width 1 | 1 |
| `0x21`–`0x7E` | an ASCII cell, `Text = string(b)`, width 1. ASCII is never wide | 1 |
| `0xC2`–`0xF4` | the lead byte of one UTF-8 code point. The whole code point is one cell of width `w` | 2–4 |
| `0x01` | set `w = 1` | 1 |
| `0x02` | set `w = 2` | 1 |
| `0x03` | `n = next byte`, `2 ≤ n ≤ MaxCluster`; the next `n` bytes are one cluster, one cell of width `w` | 2 + n |
| `0x04`–`0x1F` | the next `b − 0x02` bytes (2–29) are one cluster, one cell of width `w` | 1 + (b − 2) |
| `0x00`, `0x7F`–`0xC1`, `0xF5`–`0xFF` | error | |

Rules:

- A code point read after a lead byte must decode with `utf8.DecodeRune`
  to a valid rune, with the full length available inside this op's
  stream.
- Every code point and cluster must be a valid cluster (§4.2). The client
  doesn't check that a multi-code-point cluster is *one* grapheme; the
  server decided that, and §4.2's rules are what keep it harmless.
- A stream may not end in the middle of a code point, a cluster, or the
  `0x03` length byte.
- `w` and the last character persist from op to op through the whole
  diff.
- A cell of width `W` needs `W ≤ C − x` and `W ≤ budget − written`. A
  width-2 cell writes the
  character at `x` with the pen as its style, and a continuation cell
  (`Text ""`, width 0, the same style) at `x + 1`.
- Every cell written gets the current pen as its `Style`. `x` advances by
  `W`, and the cells-written count rises by `W`.
- The last character becomes the cell's `(Text, W)`. A blank (`0x20`) is a
  last character too.

Why control bytes are free to use as markers: a valid cluster never
contains C0 (§4.2), so `0x01`–`0x1F` can't be cell text. They are bytes of
*this* format, never terminal controls. The client never writes them; it
decodes them into structured cells.

### 5.6 Op semantics and checks

Every op is checked before it changes the scratch state. Any check that
fails makes the whole diff an error (§5.9). The checks are written in the
order they run, and in a form that cannot overflow (§5.2): a wire value is
first compared with a constant or a known size, and only then used in a
subtraction from decoder state. `budget − written` below is the cells
the diff may still write (§5.3); an op that writes `k` cells checks
`k ≤ budget − written` before writing any.

**SIZE `cols rows`.**

- Requires `1 ≤ cols ≤ MaxCols` and `1 ≤ rows ≤ MaxRows`.
- The scratch grid becomes `Resize(cols, rows)` of the base (§2.4).
- `C, R` and the write position (the clamped cursor) update to match.

**ROWS `dst src n`.**

- Requires `dst < R`, `src < R₀`, `1 ≤ n`, `n ≤ R − dst` and
  `n ≤ R₀ − src`, where `R₀` is the *base's* row count before SIZE.
- Destinations must go up: each ROWS or SCROLL op's `dst` must be at or
  after the end of the previous one's range, so destinations never
  overlap. Sources may overlap, and a base row may be copied more than
  once.
- Meaning: when phase 1 ends, target row `dst + i` starts as base row
  `src + i`, fitted to `C`.
- **If any ROWS or SCROLL op is present, every target row that none of
  them names starts blank** (default style). If there are none, row `y`
  starts as base row `y`, fitted, as SIZE left it.

  So a scroll needs no op to clear the rows it uncovers, and a row that
  stays put inside a partial scroll (a status line) needs an identity
  `ROWS y y 1`.

**SCROLL `n`.** Exactly `ROWS 0 n (R − n)`, with the same checks. It
needs `1 ≤ n < R`. It is a separate op because a full-screen scroll is
the most common row move: every line of output at the bottom of a shell.

**POS `y x`.** Requires `y < R` and `x < C`. Sets the write position.

**COL `x`.** Requires `x < C`. Sets `x`; `y` is unchanged.

**NEXT.** Requires `y + 1 < R`. Sets `x = 0` and `y = y + 1`.

**SKIP `n`.** Requires `1 ≤ n` and `n ≤ C − x`. Moves `x` forward and
leaves the skipped cells as they are. It writes nothing, so it does not
count against the budget.

**ERASE `n`.**

- Requires `x < C`.
- If `n = 0`, set `m = C − x`. Otherwise require `n ≤ C − x`, and set
  `m = n`.
- Requires `m ≤ budget − written`.
- Writes `m` blanks (`Text ""`, width 1, the pen as style) and advances
  `x` by `m`. The cells-written count rises by `m`.

**ERASED.**

- Requires `x < C`, and that the extent below (`(C − x) + C × (R − y −
  1)` cells, all decoder state, at most 500,000) is at most
  `budget − written`.
- Writes blanks in the pen from `(x, y)` to the end of row `y`, and over
  every whole row below it. This is ECMA-48 ED 0's extent.
- The write position does not move. The cells-written count rises by the
  number of cells erased.

**REPEAT `n`.**

- Requires a last character, `1 ≤ n`, `n ≤ (C − x) / W` (integer
  division) and `n ≤ (budget − written) / W`, where `W` (1 or 2) is the
  last character's width.
- Writes the last character `n` more times, with the *current* pen, as
  the stream would.
- The cells-written count rises by `n × W`.

**COPY `sy sx n`.**

- Requires `sy < R₀`, `sx < C₀` (the base's size before SIZE), `1 ≤ n`,
  `n ≤ C₀ − sx`, `n ≤ C − x` and `n ≤ budget − written`.
- Writes base row `sy`'s cells `sx .. sx+n−1`, exactly as they were in
  the base, styles included, at `x .. x+n−1`. The pen is ignored, and the
  last character doesn't change.
- Advances `x` by `n`. The cells-written count rises by `n`.
- The copy may cut through a wide character. If it does, the end-of-diff
  check of G2 refuses the diff (§5.8).

**PEN `flags` fields.**

- `flags` bits:

  | bit | value | meaning |
  |---|---|---|
  | 0 | `0x01` | fg follows |
  | 1 | `0x02` | bg follows |
  | 2 | `0x04` | underline colour follows |
  | 3 | `0x08` | attrs follow |
  | 4 | `0x10` | link follows |
  | 5 | `0x20` | reset the pen to `Style{}` before applying the fields |

- Bits 6–7 must be 0, and `flags` must not be 0.
- The fields follow in bit order.
- **Colours** are as in §5.2.
- **Attrs** is a varint, at most `0x3FF`, with at most one underline bit
  set (G6).
- **Link** is a varint index, at most the number of LINK ops so far.
  0 means no link.
- Fields the flags don't name keep their current pen values.

**LINK `s`.**

- Requires `1 ≤ len(s) ≤ MaxLink` and `ValidLink(s)`.
- Appends `s` to the diff's link table. Its index is the table's new
  length (1-based).
- The diff may define at most `MaxLinks` links, totalling at most
  `MaxLinkBytes`.
- The link table belongs to this diff alone.

**CURSOR `x y`.** Requires `x < C` and `y < R`. Sets the cursor position.

**HERE.** Requires `x < C`, which also needs `C ≥ 1`. Sets the cursor to
the write position as it stands at this point in the diff.

**TEXT+HERE.** The stream is applied as for TEXT, then the op acts as
HERE.

**CURSTYLE `b`.**

- Bit 7 is `Visible`, and bits 0–2 are `Shape`, which must be 0–6
  (DECSCUSR: 0 default, 1–2 block, 3–4 underline, 5–6 bar; odd blinks)
  [xterm].
- Bits 3–6 must be 0.

**TITLE `s`.** Requires `ValidTitle(s)`. Sets `Title`.

**MODES `m0 m1 m2 m3`.**

- `m0` bits are DECCKM (0), DECKPAM (1), bracketed paste 2004 (2), focus
  events 1004 (3) and alternate screen 1049 (4). Bits 5–7 must be 0.
- `m1` = `Mouse` (0–3).
- `m2` = `MouseEncoding` (0–1).
- `m3` = `KittyKeyboard` (0–31).
- Replaces `Modes` whole.

**ECHO `flags ack`.**

- `flags` bit 0 is `EchoOff`. Bits 1–7 must be 0.
- Sets `EchoOff` and `EchoAck = ack`.

**BELL `count`.** Sets `Bell = count`. It is absolute, so it is idempotent
under SSP's resends. The client rings when the count goes up (§8.4).

**CLIP `seq s`.** Requires `len(s) ≤ MaxClipboard`. Sets
`Clipboard = {seq, copy of s}`.

**REBUILT `seq reason`.** Requires `reason ≤ 3` (0 none, 1 emu memory
limit, 2 emu panic or exit, 3 other). Sets `Rebuilt` (§11 item 1).

### 5.7 Ordering, summed up

The grammar, in EBNF:

```
diff     = [ size ] { rowmove } { op2 } ;
size     = 0x41 varint varint ;
rowmove  = 0x42 varint varint varint | 0x43 varint ;
op2      = text | pos | col | next | skip | erase | erased | repeat | copy
         | pen | link | cursor | here | textHere | curstyle | title
         | modes | echo | bell | clip | rebuilt ;
```

Along with the once-only rule in §5.4, the destination order of `rowmove`,
and the bounds above.

### 5.8 End of diff: final checks, then commit

After the last op, the decoder checks the scratch grid:

- **G2** and **G3** on every row a write op touched. Rows that only came
  through SIZE, ROWS or SCROLL were fitted from valid base rows, and
  fitting keeps G2 and G3.
- **G5** on the whole grid. An implementation should keep a reference
  count per link in the Grid, so this costs O(links changed), not
  O(cells).
- **G7**, the cursor in range.

The cells-written budget is not an end-of-diff check. It is enforced
before each write op runs (§5.5, §5.6). A decoder that counted only at
the end would already have done the work the budget exists to bound.

If every check passes, the scratch rows and fields replace the Grid's.
Otherwise the Grid is untouched. `Apply` also refuses, without reading
it, any diff longer than `MaxDiff`.

The work is bounded:

- every op consumes at least one byte;
- the cell work is at most the budget;
- the row work is at most `R` row copies.

### 5.9 Errors

`Apply` returns an error that wraps `screen.ErrInvalidDiff` (§11 item 2),
with the reason and the byte offset of the op that failed. An example:
`screen: invalid diff: TEXT cell at column 80 past width 80, op at offset
37`. On every error the Grid is exactly as it was (`Equal` to a clone
taken before).

What callers do with the error:

- **Client.** The server is authenticated, so an invalid diff means a
  bug or a compromised server. The client ends the session with "the
  server sent an invalid screen update", rather than waiting forever on
  an instruction it can't apply. That is failing closed; `ssp.md` has the
  final word on how SSP surfaces it (§11 item 9).
- **proto, applying emu's `Update`.** emu is treated as compromised: proto
  kills it, the spawner rebuilds it, and the client is told (REBUILT,
  reason 2) (§7.3).

### 5.10 Encoder (`Diff`)

Normative requirements on `g.Diff(from)`:

- **E1.** `from.Clone().Apply(g.Diff(from))` succeeds and the result is
  `Equal` to `g`, for every valid `from` and `g`, including version 0 as
  `from`.
- **E2.** `g.Diff(from)` is empty if and only if `g.Equal(from)`.
- **E3.** It writes each target cell at most once, and stays within
  `MaxDiff` and the cells-written budget for any valid `g`.
- **E4.** It is deterministic: the same inputs give the same bytes.
- **E5.** Whenever it emits SIZE, it emits CURSOR or HERE too. The decoder
  doesn't need this, but it keeps the cursor deliberate after a resize.
- **E6.** Spans start and end on character boundaries of the target: a
  span never starts on a width-0 cell, and never ends between a width-2
  cell and its continuation. With E1 this means G2 holds in the result
  without the decoder having to repair anything.

The reference algorithm below is recommended, not normative. Tests check
E1–E6, not the exact bytes.

1. **Size.** If it differs, emit SIZE.
2. **Row moves.**
   - Hash each base row (fitted to `C`) and each target row.
   - If target row `y` already equals base row `y`, it needs nothing.
   - Otherwise, find shifts: for each offset `d`, count the non-blank
     target rows `y` with `base[y + d] == target[y]`.
   - If the best `d > 0` covers rows `0 .. R−d−1` and saves bytes, emit
     SCROLL `d`.
   - Otherwise, emit ROWS for each maximal run that matches at a constant
     offset and is worth more than its 3–4 bytes. Add an identity ROWS
     for every unchanged non-blank row that a move would otherwise blank.
   - Use row moves only if they save bytes overall.
3. **Cells.**
   - For each row, compare the row as it now starts (§5.6) with the
     target, and collect the changed cells into spans that obey E6.
   - Merge two spans when restating the gap costs no more than the SKIP
     (or COL) and stream bytes it would save. For a gap of ASCII cells in
     the same style, that is a gap of up to 2 cells.
   - Within a span:
     - position with the cheapest of nothing, SKIP, COL, NEXT or POS;
     - use ERASE 0 for blanks to the end of the row, and ERASE `n` for
       runs of 3 or more blanks;
     - use REPEAT for runs of 4 or more of the same character in the
       same style;
     - use PEN with only the fields that change. Use `0x20` (reset) when
       that is shorter;
     - emit LINK the first time a link is used in this diff;
     - emit `0x01` / `0x02` only when `w` must change.
   - When everything from a point to the end of the screen is blank in
     one style, use ERASED. COPY is optional for slice 1's encoder: the
     decoder supports it from the start, so the encoder can begin using
     it (for inserted and deleted characters in shells and editors)
     without a format change.
4. **Cursor.**
   - If the target cursor is where the last TEXT op leaves the write
     position, use TEXT+HERE.
   - Otherwise, if it is where the write position stands, use HERE.
   - Otherwise use CURSOR.
5. **State.** Emit CURSTYLE, TITLE, MODES, ECHO, BELL, CLIP and REBUILT
   for each field that differs from `from`.

Snapshotting and diffing read every cell. tuios has no damage tracking
[measured S2: about 50 ns per cell]. That is about 0.1 ms at 80 × 24, and
about 25 ms at the 1000 × 500 clamp, which is more than SSP's 8 ms
collection window [D11]. This is acceptable for slice 1: it only happens
while output arrives, and a large window sends large frames anyway.
Per-row hashes cached on the Grid (invalidated on write) make step 2 and
the "unchanged row" test cheap. Damage tracking upstream is S2's
contribution item 2.

### 5.11 Examples (exact bytes)

All examples are at 80 × 24 unless a size is given. Bytes are in hex.

1. **Echo of `l`.** The cursor is at (5, 0) and moves to (6, 0).

   `80 6C`: TEXT+HERE with a 1-byte stream, `l`. 2 bytes; the terminal
   got 1.

2. **Backspace.** The cursor goes from (6, 0) to (5, 0), and cell 5
   becomes blank.

   `45 05` (COL 5), `51` (HERE), `48 01` (ERASE 1). 5 bytes; the terminal
   got `08 20 08`, 3 bytes.

3. **A line of output scrolls the screen, then a bold green `$ ` prompt.**
   The base cursor is on row 23 and moves to (2, 23).

   | bytes | op |
   |---|---|
   | `43 01` | SCROLL 1. Row 23 starts blank |
   | `45 00` | COL 0; `y` is already 23 |
   | `4C 09 01 02 01` | PEN: fg `Palette(2)`, attrs `Bold` |
   | `00 24` | TEXT `$` |
   | `50 02 17` | CURSOR (2, 23) |

   14 bytes; the terminal got `0D 0A 1B 5B 31 3B 33 32 6D 24 1B 5B 30 6D
   20`, 15 bytes.

4. **`clear`.** The base cursor is anywhere.

   `44 00 00` (POS 0 0), `51` (HERE), `49` (ERASED). 5 bytes; the terminal
   got `ESC[H ESC[2J`, 7 bytes.

5. **The first frame from version 0**, at 80 × 24: a `$ ` prompt, the
   cursor visible at (2, 0).

   | bytes | op |
   |---|---|
   | `41 50 18` | SIZE 80 24 |
   | `00 24` | TEXT `$` |
   | `50 02 00` | CURSOR (2, 0) |
   | `52 80` | CURSTYLE visible, shape 0 |

   10 bytes.

6. **`漢字` at the write position.**

   `06 02 E6 BC A2 E5 AD 97`: TEXT with a 7-byte stream: set `w = 2`, then
   U+6F22 and U+5B57. That writes 4 cells. The terminal got the same 6
   UTF-8 bytes.

7. **`é` as `e` plus U+0301** (one cluster, width 1).

   `03 05 65 CC 81`: TEXT with a 4-byte stream: a 3-byte cluster (`0x05` =
   0x02 + 3).

8. **A link on `docs`.**

   | bytes | op |
   |---|---|
   | `4D 13` + `https://example.com` | LINK, 19 bytes |
   | `4C 10 01` | PEN link 1 |
   | `03 64 6F 63 73` | TEXT `docs` |
   | `4C 10 00` | PEN link 0 |

### 5.12 Size: what it costs, the bound, the gate

**Cost per change** [derived from §5.4–§5.6; terminal costs are the usual
sequences per ECMA-48 and xterm]:

| change | this format | what a program typically sends |
|---|---|---|
| printable ASCII | 1 B per cell | 1 B |
| non-ASCII single code point | its UTF-8 (2–4 B) | the same |
| a run of wide characters | + 1 B per switch of `w` | 0 |
| a cluster of several code points | + 1 B (+ 2 B over 29 B) | 0 |
| move within a row | COL 2–3 B, SKIP 2–3 B | CHA/CUF 3–6 B |
| move to the next row | NEXT 1 B | CR LF 2 B |
| move anywhere | POS 3–5 B | CUP 4–10 B |
| style change | PEN 3–7 B for one or two fields | SGR 3–19 B |
| erase to end of line / screen | 2 B / 1 B | EL 3 B / ED 3–4 B |
| full-screen scroll | 2 B, once per frame however many lines | LF per line, or SU 3–5 B |
| scroll region / inserted lines | 4–8 B per run of rows | DECSTBM + IL/DL 6–14 B |
| echo of one key | 2 B | 1 B |
| a cell rewritten with the same content | 0 | the full cost |

Text costs the same, moves and styles cost less, and anything a program
repaints without changing costs nothing. So a diff exceeds the raw bytes
only in two cases. One is where the change itself is smaller than an op:
a single keystroke echo is 2 bytes against 1. The other is where the
program used a shift we don't encode: ICH/DCH within a row, until the
encoder uses COPY. Both are small. Every datagram already carries
transport's 30 bytes (`architecture.md` §4) plus SSP's own header, so
the 1-byte echo floor changes wire bytes by a few percent at most.

**`MaxDiff` = 48 MiB** [derived].

- The worst valid diff writes every cell of a 1000 × 500 screen with its
  own pen and its own 64-byte cluster.
- Per cell, the PEN costs 18 bytes: opcode 1, flags 1, three RGB colours
  at 4 each, attrs 2 and link 2. The TEXT costs 68 bytes: opcode 1, `w`
  switch 1, `0x03 n` 2, cluster 64.
- That is 86 B × 500,000 = 43.0 MB. Add up to 1.02 MiB of LINK ops,
  64 KiB of CLIP, and under 1 KiB for the other state ops: about
  44.2 MB.
- 48 MiB (50.3 MB) leaves room above that and is the bound SSP uses for
  `MaxRemoteBytes` [D24].

A legitimate diff at 80 × 24 is at most about 166 KB plus links. Typical
frames are tens to a few thousand bytes.

**Acceptance gate (O11).** Before the encoder lands, `internal/emu` gets a
test, `TestDiffNotBiggerThanRaw` (package `emu_test`, which may import
both `emu` and `screen`). Its corpus is copied into
`internal/emu/testdata/corpus/`. The copies are data, not code, so
production never imports `spikes/`:

- S5's committed captures `flood`, `less`, `shell` and `vim`, which have
  timing.
- S2's committed recordings `fish`, `less`, `unicode`, `vim` and `zsh`,
  which have checkpoints but no timing.

For each stream, it feeds the pty bytes to `emu.New` and takes frames on
D11's server schedule. Output collects for 8 ms after the first byte; then
a frame is taken, and frames are at least 50 ms apart. That is SRTT/2 for
a 100 ms path [D11], the same schedule S5 used. S2's recordings, which
have no timing, take a frame at every checkpoint and every 1 KiB, as S2
did. Each frame is diffed from the previous one. The test then asserts:

- for each S5 capture: Σ uncompressed diff bytes ≤ Σ pty bytes;
- over S2's five recordings together: Σ diff ≤ Σ pty. Each stream is
  logged. `unicode` is a torture file, not a typical program, so it is
  reported but not gated alone.

It also logs each stream's per-frame flate size, with SSP's 32-byte
threshold [measured S5], and records the table in this section when it
first passes.

**If the gate fails, the implementer stops and reports the numbers to the
screen owner. The format is then amended here before the code lands.** The
gate is set on *uncompressed* bytes on purpose: the format must beat raw
output on its own, so the result holds whatever O12 settles about padding.

### 5.13 Compression (D24, O12)

SSP compresses each instruction with stdlib flate before fragmenting it
[D24]. That is `ssp.md`'s, including the decompression bound, which is
`MaxDiff` here. The diff format is independent of it. On the screen side:

- **No preset dictionary built from the screen.** S5 measured the
  acknowledged screen as a dictionary to be the best compressor (0.247)
  and the leakiest. It puts the whole screen in the compressor's window,
  so a secret anywhere on screen influences the length of a frame that
  doesn't contain it [measured S5 §8]. This spec gives SSP no screen
  dictionary interface, and O12 should not add one.
- **No padding inside the diff.** Padding, if any, is SSP's (O12), applied
  to the compressed instruction, where it can be one rule for all
  objects.
- **The length side channel.** Diff lengths reveal how many cells change,
  which can echo the length of what's typed. Echo-off keeps password
  keystrokes out of the screen [D12], and chaff [D11, O10] covers timing.
  `docs/threat-model.md` carries this.

## 6. The server's emulator (`internal/emu`, D23)

### 6.1 Configuration of `emu.New`

The shipped emulator is `tuios.dev/vt`, pure Go, pinned [D23]. `New`
creates it at the clamped size and sets it up as follows. Each item is
[measured S2] unless marked otherwise.

- **Mode 2027 on.** Grapheme clustering, so clusters and widths are the
  server's.
- **Kitty file uploads refused** (`SetKittyFilesElsewhere(true)`).
  Graphics queries are answered "unsupported" (§4.5).
- **Kitty keyboard protocol disabled** in slice 1, so
  `Modes.KittyKeyboard` stays 0. The client can only mirror it if the
  user's terminal supports it, and the client line doesn't carry that yet
  (§11 item 8). The field and its byte in MODES are reserved now.
- **Colour queries** (OSC 4/10/11) are answered from `Options.Foreground`,
  `Background` and `Palette` (`SetReportColors`, `SetThemeColors`).
- **The scrollback line cap** is `min(10000, Options.ScrollbackCells /
  cols)`, set at `New` and again on every `Resize` [D23].
- **DECCOLM never changes the size.** `Snapshot` always produces the size
  of the last `Resize`. If the emulator's own size differs, the snapshot
  is fitted to it (§2.4). proto does not take this on trust: a mirror of
  any other size is a violation (§7.3).

### 6.2 `Snapshot(g)`

`Snapshot(g)` makes `g` the current screen, with the allow-list applied
(§4) and the invariants (§2.2) true:

- **Cells.**
  - Each cluster goes through `SanitizeCluster`.
  - `" "` becomes `""`.
  - Widths come from the emulator. A wide character the emulator puts in
    the last column becomes a blank (G2).
  - Continuation cells get `""` and the lead's style (G3).
  - Links go through `SanitizeLink` and then the G5 budget, in reading
    order (§4.3).
  - Colours map onto `screen.Color`, and attributes onto `Attrs`. A
    double or curly underline takes precedence over plain, so that only
    one is set (G6).
- **Cursor.** The position is clamped (G7). `Visible` and `Shape` come
  from DECTCEM and DECSCUSR.
- **Title.** `SanitizeTitle` of the emulator's current title.
- **Modes.**
  - DECCKM, DECKPAM, 2004, 1004 and 1049 map directly.
  - Mouse: 1003 gives `MouseAll`, else 1002 gives `MouseDrag`, else 1000
    gives `MouseClicks`. 9 (X10 press-only) is treated as `MouseClicks`.
  - Encoding: 1006 gives `MouseSGR`. 1005 and 1015 have no
    representation and give `MouseX10` (§11 item 10).
- **Clipboard and bell.** `Clipboard` and `Bell` are emu's own counters
  (§4.4). proto renumbers them (§7.3).
- **Left zero.** `EchoOff`, `EchoAck` and `Rebuilt` are always zero in
  emu's grid. They are proto's.

### 6.3 Behaviour

- **Synchronised output (mode 2026).** The end of the mode is a natural
  frame boundary [measured S2], so emu holds the screen while a program
  has the mode open. The hold lives in `Snapshot`, and emu still answers
  every request (`server.md` §3.5: strictly request and response, never
  unasked):
  - **Holding.** From when the program sets 2026 until it resets it, or
    until `SyncHold` (§3) has passed since it set it, whichever is first,
    `Snapshot` gives the screen as it was just before the mode was set
    and reports that it held. Over IPC, emu answers each request in that
    time with an empty diff and the HELD flag on its last `Update`
    fragment (§11 item 12).
  - **Releasing.** The first `Snapshot` after the mode closes, or after
    `SyncHold` has passed, gives the live screen, and the diff in that
    response carries everything that changed. Once `SyncHold` has passed,
    the hold is over for that opening of the mode, even if the program
    never closes it. Only a new set of 2026 starts a new hold.
  - **Who wakes it.** A program that opens 2026, draws, closes it and
    waits for input is released by the output that closed it. A program
    that opens it and never closes it writes nothing more, so nothing
    would ask emu again. So proto owns a timer: when a response comes back
    held, proto arms `SyncHold` (unless it is already armed). When it
    fires with no request outstanding, proto sends `Flush`, a request with
    no payload whose answer is an ordinary `Update` (§11 item 12). The
    in-process emulator does the same through `Snapshot`'s held result.
    The timer is proto's clock, so tests drive it under `testing/synctest`
    [D18].
  - **A hostile emu** that reports HELD on every response gains nothing:
    it costs proto one `Flush` per `SyncHold`, and emu could already
    withhold any change by sending an empty diff.
- **Replies** (DA, DSR/CPR, colour reports) go to a bounded queue of
  64 KiB. When it is full, replies are dropped and counted. The reader
  never writes to the pty (§3). proto writes the queue's contents to the
  pty only if they pass `server.ValidReply` (`server.md`).
- **Panic or memory limit.** A panic in emu is never recovered in
  production: the process dies [D23]. When emu hits its `MemoryMax`, the
  kernel kills it. Either way, the spawner starts a new emu at the
  current size and proto tells the client (§7.3).

## 7. proto and the screen (summary; `server.md` owns the details)

### 7.1 The pipeline

1. pty output goes to emu (`Output`).
2. emu replies with `Update` and `Replies`. An `Update` is a diff in this
   format, from emu's previous update to its new snapshot. The first
   `Update` of each emu generation, the answer to `Init`, is a diff from
   `screen.NewGrid(cols, rows)` at `Init`'s size, as `server.md` §3.3
   says. It is not from version 0, so a SIZE op appears at the IPC
   boundary only in the answer to a `Resize`.
3. proto applies each `Update` with `Grid.Apply` to its mirror of emu's
   grid. This is the same validating decoder the client uses.
4. proto copies the mirror into the Grid it gives SSP, with proto's own
   fields set: `EchoOff` from `pty.EchoOff`, `EchoAck`, the renumbered
   counters and `Rebuilt`.
5. SSP diffs that Grid from the client's acknowledged version [paper
   §2.3, D11].

### 7.2 Counters belong to proto

`Bell`, `Clipboard.Seq` and `Rebuilt.Seq` must never go backwards on the
client, or a new emu that starts again from 0 would silence them. So
proto keeps its own counters, and compares emu's only within one emu
generation:

- **The baseline.** Each generation starts from the mirror's fresh grid,
  `NewGrid(cols, rows)`, so emu's `Bell` and `Clipboard` start at
  `0` and `{0, nil}`. Proto compares each `Update`'s result with the
  mirror before it, in the same generation. A rebuild replaces the
  mirror and its baseline. It never counts as a change: the client's
  `Bell` and `Clipboard` stay exactly as they were, so a rebuild neither
  rings the bell nor clears the user's clipboard.
- **Bell.** When the mirror's `Bell` goes up by `d`, proto adds `d` to its
  own count.
- **Clipboard.** When the mirror's `Clipboard.Seq` goes up, by any
  amount, proto increments its own `Seq` by one and takes the data.
- **Going backwards.** Within a generation, emu's counters only rise. A
  `Bell` or `Clipboard.Seq` lower than the mirror's before the `Update`,
  or `Clipboard.Data` changed without a higher `Seq`, is a violation
  (§7.3), and proto takes nothing from that `Update`. A real emulator's
  counters never fall, so only a broken or hostile emu trips this.

### 7.3 Rebuilds and a hostile emu

proto treats emu as hostile.

- **When emu's grid oversteps.** proto kills emu and asks the spawner to
  rebuild it (`KillEmu{violation}`) if an `Update`:
  - fails `Apply`;
  - leaves the mirror with a non-zero `EchoOff`, `EchoAck` or `Rebuilt`.
    Those three fields are proto's alone;
  - leaves the mirror at a size other than the last one proto sent, in
    `Init` or `Resize`. emu's sizes are proto's to choose: a program
    can't resize (DECCOLM and XTWINOPS are ignored, §4.5), so a
    compromised emu must not either. Without this check it could turn an
    80 × 24 session into 1000 × 500 frames, about 270 times the data
    towards the client;
  - contains a SIZE op in any answer other than one to `Resize`. SIZE
    can only be the first op (§5.4), so this is a look at the diff's
    first byte. In the answer to a `Resize` a SIZE is allowed, and the
    size check above makes it match;
  - moves `Bell` or `Clipboard` backwards (§7.2).

  Every one of these is checked on the scratch result before proto's
  mirror, counters or Grid change, so a refused `Update` changes nothing.
  `server.md` §3.5's violation list must name the same cases (§11 item
  13).
- **Starting again.** After any rebuild, proto's mirror is replaced by
  `screen.NewGrid(cols, rows)` at the size sent in the new emu's `Init`,
  and the new emu's first `Update` is diffed from that grid (§7.1). Proto
  applies it to that fresh grid, not to the old mirror. The Grid proto
  gives SSP is not reset: SSP diffs the new screen from what the client
  holds, as for any other change.
- **Telling the client.** proto increments `Rebuilt.Seq`, with reason 1
  (memory), 2 (panic, exit or a refused update) or 3 (other).
- **Getting the screen back.** The new emulator is blank, so proto should
  make the shell's foreground program repaint. The cheapest reliable way
  is a SIGWINCH from a size change and back (`server.md`). Until it
  repaints, the client sees a blank screen with the cursor where the new
  emu puts it.

## 8. The client's renderer (`internal/render`)

### 8.1 Its job

`Renderer.Render(g)` makes the user's terminal show `g`, writing only what
differs from what it drew last. It keeps its own copy of the last Grid it
drew. It is the only code in the client that writes to the terminal while
a session runs. Each `Render` builds the frame in a buffer and writes it
with a single `Write`, so a frame isn't interleaved with anything else.

### 8.2 The output alphabet

`render` writes only the sequences in this table, with `n`, `r`, `c` and
`x` formatted as decimal by `strconv`. `ESC` is 0x1B, `CSI` is `ESC [`,
`OSC` is `ESC ]`, and `ST` is `ESC \` [ECMA-48, xterm].

| purpose | sequence |
|---|---|
| move | `CSI r ; c H` (1-based) |
| style | `CSI 0 ; … m`, with parameters from §8.3 |
| erase | `CSI K` (EL 0), `CSI n X` (ECH), `CSI 2 J`, used only as §8.3 allows |
| cursor | `CSI ? 25 h` / `l`, `CSI n SP q` (DECSCUSR, n 0–6) |
| frame | `CSI ? 2026 h` / `l`, only if `Capabilities.SyncUpdates` |
| screen | `CSI ? 1049 h` / `l`, `CSI ? 7 h` / `l` (DECAWM) |
| title | `OSC 2 ; <title> ST`, `CSI 22 ; 2 t` / `CSI 23 ; 2 t` (push / pop) |
| link | `OSC 8 ; ; <uri> ST`, and `OSC 8 ; ; ST` to end it |
| clipboard | `OSC 52 ; c ; <base64> ST` |
| bell | `BEL` (0x07) |
| modes | `CSI ? 1 h/l`, `ESC =` / `ESC >`, `CSI ? 2004 h/l`, `CSI ? 1004 h/l`, `CSI ? 1000 h/l`, `CSI ? 1002 h/l`, `CSI ? 1003 h/l`, `CSI ? 1006 h/l`, and `CSI = n ; 1 u` (kitty flags, only once a later slice enables them) |
| text | cell `Text` (a blank is one space, 0x20); without `Capabilities.UTF8`, `?` for any non-ASCII text (§8.3) |

There is no LF, CR, BS, HT or any other C0 apart from ESC and BEL. Line
changes are always CUP. A test checks this (§10).

### 8.3 Drawing cells

- **Placement.** Every run of cells starts with a CUP. After any cell
  whose text is not a single printable ASCII byte (0x21–0x7E) or a blank,
  the next cell gets a fresh CUP. So a disagreement between the server's
  and the local terminal's width tables shifts nothing past that cell
  [measured S2]. A width-2 cell is written as its text, and its
  continuation is skipped.
- **Non-UTF-8 terminals.** `Capabilities.UTF8` (§11 item 14) says whether
  the local locale's codeset is UTF-8. The client reads it from the
  environment, the first of `LC_ALL`, `LC_CTYPE` and `LANG` that is set
  and non-empty: it is true if the part after the `.` (before any `@`)
  is `UTF-8` or `utf8`, ignoring case. An unset locale or `C`/`POSIX`
  counts as not UTF-8 [derived: the conservative reading, and the one a
  libc would make]. When it is false:
  - every cell whose `Text` contains a byte ≥ 0x80 is written as `?`,
    and a width-2 cell as `?` followed by a space, so the layout is
    unchanged;
  - every non-ASCII rune in a title is written as `?` (§8.4).

  Links are ASCII by §4.3, and clipboard data is base64, so with
  `UTF8` false the renderer writes no byte ≥ 0x80 at all. This matters
  because UTF-8 continuation bytes include 0x80–0x9F. Read by a
  terminal not in UTF-8 mode, `ě` (`C4 9B`) contains 8-bit CSI, and
  `ě` + U+0332 (`C4 9B CC B2`) inside one cluster reads as `CSI L` to a
  parser that strips the eighth bit. The
  per-cell CUP can't help inside a cluster or a title
  (`threat-model.md` §4.7).
- **Autowrap.** `Enter` turns autowrap off (DECAWM reset). Writing the
  last column, including the bottom-right cell, then never scrolls or
  wraps.
- **Clipping.** The renderer draws `g` at the top left of the local
  terminal.
  - Cells beyond the local width or height are not drawn.
  - A width-2 cell in the local last column is drawn as a blank.
  - Local cells outside `g` are drawn blank in the default style, once,
    after a size change or `Invalidate`.
  - The renderer needs the local size for this (§11 item 5).
- **Style.**
  - Each style change is written as one `CSI 0 ; … m`, starting from a
    reset, so the local terminal never carries a pen state the renderer
    doesn't know.
  - Attributes map as: `Bold` 1, `Faint` 2, `Italic` 3, any underline 4,
    `Blink` 5, `Reverse` 7, `Invisible` 8, `Strikethrough` 9. In slice 1,
    double and curly underlines are drawn as plain 4, and the underline
    colour is not drawn. Styled underlines (`4:n`, `58`) wait for a
    capability (§11 item 11).
  - Colours:
    - `Palette(i)` for `i < 16` is 30–37 / 90–97 (fg) and 40–47 / 100–107
      (bg).
    - Other palette entries are `38;5;i` / `48;5;i`, if `Colors256`.
    - `RGB` is `38;2;r;g;b` / `48;2;r;g;b`, if `TrueColor`.
    - Without those capabilities, RGB maps to the nearest of xterm's 256
      colours, 16–255, by squared distance in sRGB. Without `Colors256`,
      any colour maps to the nearest of the 16, using xterm's default
      values for both [derived].
- **Erasing.** EL and ECH are used only for runs of blanks in the
  completely default style (default fg and bg, no attributes, no link).
  That avoids depending on the local terminal's background-colour-erase
  behaviour. Other blanks are written as spaces.
- **Invalidation.** A full redraw starts with `CSI 2 J`.

### 8.4 Everything else, once per frame, in this order

1. Begin a synchronised update, if supported. Hide the cursor.
2. Draw the cells that changed (§8.3).
3. **Links.** Only if `Capabilities.Hyperlinks`:
   - Open `OSC 8 ; ; <uri> ST` before a run whose cells carry a link,
     and close it with `OSC 8 ; ; ST` before anything that isn't linked.
   - Every link in the frame is closed before the frame's cursor
     placement.
   - Without the capability, link text is drawn plain.
4. **Title.** If `Title` changed, write `OSC 2 ; title ST`. Without
   `Capabilities.UTF8`, each non-ASCII rune of the title is written as
   `?` (§8.3).
5. **Clipboard.** If `Capabilities.Clipboard` is set and `Clipboard.Seq`
   is greater than the last one acted on, write `OSC 52 ; c ;
   base64(Data) ST`, using `encoding/base64.StdEncoding`.
   - The first grid a renderer draws only *records* its `Seq`. Attaching
     must not replay an old write into the user's clipboard.
6. **Bell.** If `Bell` went up, write one `BEL`, however many bells were
   missed. The first grid only records the count.
7. **Modes.** Mirror the input modes that changed (§8.5).
8. **Cursor.**
   - CUP to `Cursor`, clipped to the local size.
   - DECSCUSR if `Shape` changed.
   - Show the cursor if `Visible`.
9. End the synchronised update.

**Rebuilt.** If `Rebuilt.Seq` went up, the renderer reports it to its
caller. The client tells the user: "the remote screen was reset (reason)".
In slice 1 that goes to the log, and to stderr when the session ends; a
later slice may draw a banner. The first grid only records it.

**Defence in depth.** Before writing a title, link, cluster or clipboard,
the renderer checks it again with the `Valid*` functions. It drops
anything that fails, and never writes it. `Apply` already guarantees
this, but a Grid can also be built by client code (prediction, in a later
slice), not only by `Apply`.

### 8.5 Mirroring input modes

The client doesn't translate keys. It sets the user's terminal into the
modes the remote program asked for, and the terminal then produces the
bytes the program expects. The client passes those through unparsed;
local input is the user's own, not remote data (§11 item 6).

| `Modes` | written when it changes |
|---|---|
| `AppCursorKeys` | `CSI ? 1 h` / `l` |
| `AppKeypad` | `ESC =` / `ESC >` |
| `BracketedPaste` | `CSI ? 2004 h` / `l` |
| `FocusEvents` | `CSI ? 1004 h` / `l` |
| `Mouse` | reset the old mode (`CSI ? 1000/1002/1003 l`), then set the new one (`h`) unless it is `MouseOff` |
| `MouseEncoding` | `CSI ? 1006 h` / `l` |
| `KittyKeyboard` | not written in slice 1 (§6.1) |
| `AltScreen` | not mirrored. The client is always on its own alternate screen |

### 8.6 `Enter`, `Leave`, `Invalidate`

- **`Enter`** writes, in order:
  1. `CSI 22 ; 2 t` (push the title);
  2. `CSI ? 1049 h`;
  3. `CSI ? 7 l`;
  4. `CSI ? 25 l`;
  5. `CSI 2 J`.

  It then marks everything as needing a draw.
- **`Leave`** undoes everything it or any `Render` set, then restores the
  rest:
  1. `CSI 0 m`;
  2. the close of any open link;
  3. every mirrored mode back to off: mouse 1000/1002/1003/1006 `l`,
     1004 `l`, 2004 `l`, `ESC >`, `CSI ? 1 l`;
  4. `CSI 0 SP q`;
  5. `CSI ? 25 h`;
  6. `CSI ? 7 h`;
  7. `CSI ? 1049 l`;
  8. `CSI 23 ; 2 t` (pop the title).

  It is safe to call twice, and the client calls it on every exit path,
  including a signal.
- **`Invalidate`** forgets what is on the terminal. Call it after a local
  resize or a SIGCONT. The next `Render` starts with `CSI 2 J` and draws
  everything.

## 9. What the client must never do

1. **Never parse a remote escape sequence.** No package on the client's
   path imports a VT parser:
   - `internal/client`, `render`, `screen`, `terminal`, `userinput`,
     `ssp`, `transport`, `handshake` and `bootstrap` must not depend,
     directly or indirectly, on `tuios.dev/vt`, `internal/emu`, or
     `github.com/charmbracelet/x/ansi` or anything else that parses
     escape sequences;
   - a test enforces this with `go list -deps` (§10).

   mosey is one binary, so it does contain tuios, but only the server's
   emu role calls it.
2. **Never write a remote byte to the terminal except the four kinds in
   §1,** and each only after its allow-list check. Clipboard data only
   ever goes out base64-encoded. **Never write a byte ≥ 0x80 to a
   terminal whose locale codeset is not UTF-8**: non-ASCII cell text and
   title runes become `?` (§8.3).
3. **Never let the remote side resize, query or reconfigure the user's
   terminal**, beyond the input modes of §8.5. It never forwards DA, DSR,
   OSC 10/11, DECRQM, XTGETTCAP or any other query. The server's emulator
   answers those.
4. **Never read the local clipboard for the server**, and never pass an
   OSC 52 read.
5. **Never use the local terminal's idea of width to place cells.** It
   places them with explicit moves, as §8.3 says.
6. **Never apply part of a diff.** A diff is all or nothing, and an error
   leaves the Grid as it was.
7. **Never trust a size, index or length from the wire** before it is
   checked against its bound as a `uint64`, and never add or multiply a
   wire value in a bound check: compare it alone with a constant or a
   difference of known-good state (§5.2, §5.6).

## 10. Tests and fuzzing

Every package has tests. Fuzz targets run for at least a few minutes
locally before they land, with the durations and exec counts in the
commit message, and for 10 s each in CI (`mise run fuzz-smoke`)
[architecture §6].

**`internal/screen`**

- **`FuzzApply`.** Arbitrary bytes, applied to grids held in the corpus: a
  real 80 × 24 frame, version 0, and a 1000 × 500 frame. After every call:
  - on error, the grid is `Equal` to a clone taken before;
  - on success, `Grid.Valid()` holds;
  - nothing panics;
  - the heap stays under a bound, as S2's target checked.

  Seeds: every example in §5.11, S2's hostile probes, and each case in
  the list below.
- **`FuzzRoundTrip`.** Two grids built from fuzz bytes by a generator that
  only makes valid grids, including wide characters, clusters, links,
  every mode and counter, and different sizes. Check E1, E2 and E3 for
  `b.Diff(a)` applied to `a`.
- **`FuzzSanitize`.** For every `Sanitize*`: the output is `Valid*`,
  `Sanitize*` is idempotent, and `Valid*(s)` is the same as
  `Sanitize*(s) == s`.
- **Unit tests**, one per rule in §5.6 and per invariant in §2.2. Among
  them:
  - SIZE outside 1..max, and SIZE that isn't first;
  - ROWS after a cell op, overlapping destinations, and a source past
    the base;
  - a width-2 cell in the last column;
  - COPY cutting a wide character;
  - REPEAT before any TEXT;
  - a link index past the table;
  - a non-minimal varint;
  - duplicate state ops (CURSOR then TEXT+HERE);
  - the cells-written budget exceeded through ERASE 0;
  - a stream ending inside a code point;
  - C1, bidi and over-long titles, and the review's probes
    `"a\u009d0;evil\u009cb"`, `"a\u009b2Jb"` and `"a\x7fb"` [measured S2];
  - `javascript:`, `file:`, `HTTP:` (accepted) and links of 2048 and 2049
    bytes;
  - clipboards of 64 KiB and 64 KiB + 1;
  - every strict prefix of every §5.11 example. Each must either fail or
    give a valid grid, and never panic;
  - **overflow probes**, each refused without a panic and quickly: ROWS,
    SKIP, ERASE, REPEAT and COPY with `n` = 2^64 − 1, 2^64 − `x` (and
    2^64 − `dst`, − `src`, − `sx` for the ops that have them) and 2^63,
    with `x`, `dst`, `src` and `sx` both 0 and non-zero, and REPEAT with
    a width-2 last character and `n` = 2^63. These are also seeds for
    `FuzzApply`: a fuzzer is unlikely to find values within a few units
    of 2^64 on its own;
  - the budget enforced before the op: a diff whose ERASED, ERASE or
    REPEAT would pass the budget is refused before it writes.

**`internal/emu`**

- **`FuzzEmuRoundTrip`.** Program bytes and resizes up to the clamp go
  into `emu.New`. A snapshot is taken and diffed after each half, and the
  diffs are applied to a client grid. Every snapshot must satisfy
  `Valid()`, the client must end up `Equal`, and the heap must stay
  bounded. This is S2's `FuzzRoundTrip` and `FuzzTuiosClamp`, rebuilt on
  the production types.
- **`TestDiffNotBiggerThanRaw`**: the gate in §5.12.
- **The S2 hostile battery's cases** at 80 × 24 and at the clamp, as
  regression tests. Each must finish, stay bounded, and give a valid
  snapshot.
- **Allow-list tests through the emulator**: OSC 2 with C1 or bidi, OSC 8
  with `file:`, an OSC 52 write over the cap (dropped whole), an OSC 52
  read (never in the Grid), DECCOLM (no size change), and a wide
  character written at the margin.

**`internal/render`**

- **The alphabet.** Random valid grids, including hostile-but-valid
  clusters, titles and links, are rendered over random previous grids
  with every capability combination. A *test-only* recognizer then checks
  that every byte of the output belongs to §8.2's table. It reads our own
  output, never remote data.
- **Round trip through a real emulator.** `render_test` (an external test
  package) feeds the renderer's output into `tuios.dev/vt` at the same
  size and checks the result matches the Grid: cells, styles within the
  capabilities' downgrade, the cursor and the modes. This is allowed in a
  test; production `render` must not import tuios (§9).
- **Behaviour**: clipping when the local size is smaller or larger, no
  clipboard write or bell on the first grid, a single BEL for several
  bells, and `Leave` restoring every mode it set.
- **Non-UTF-8 locale.** With `Capabilities.UTF8` false, random valid
  grids (with non-ASCII clusters, wide characters and non-ASCII titles)
  render to output with no byte ≥ 0x80, and the cursor and every ASCII
  cell land where they would with `UTF8` true. A table test checks the
  locale parsing (`en_US.UTF-8`, `C.utf8`, `de_DE@euro`, `C`, `POSIX`,
  unset, and `LC_ALL` overriding `LANG`).

**`internal/server` (proto's side of §7, with a fake emu)**

- A `KillEmu` and rebuild leaves the client-facing Grid's `Bell` and
  `Clipboard` unchanged: no bell, no clipboard write.
- The rebuilt emu's first `Update`, a diff from `NewGrid(cols, rows)`
  with no SIZE, applies to the fresh mirror.
- An `Update` that leaves the mirror at another size, has SIZE in an
  answer to `Output`, or lowers `Bell` or `Clipboard.Seq`, is a
  violation and changes nothing.
- Under `testing/synctest`: a program that sets 2026, draws and then
  writes nothing gets its screen to the client `SyncHold` after it set
  the mode, through proto's `Flush`; one that closes 2026 gets it on the
  closing output, with no `Flush`.

**The import rule.** A test in `internal/client` runs `go list -deps` on
the client-path packages of §9, item 1, and fails if a forbidden package
appears.

## 11. Interface changes this spec needs

These are listed for the owners to agree. `internal/` is not edited from
here (`architecture.md`: an exported signature that another owner calls is
agreed first).

1. **`Grid.Rebuilt`** (`struct{ Seq uint64; Reason uint8 }`) and opcode
   `0x58`. D23 says "tell the client" when emu is rebuilt, and the Grid has
   no field for it. Owners: screen and server-proc.
2. **`screen.ErrInvalidDiff`**: the sentinel wrapped by every `Apply`
   error (§5.9).
3. **New constants in `allow.go`**: `MaxDiff` (48 MiB, for
   `ssp.Config.MaxRemoteBytes` and the IPC `Update`), `MaxLinks` (4096)
   and `MaxLinkBytes` (1 MiB). `SyncHold` (200 ms) belongs in `emu`, and
   the 64 KiB reply queue in `server`.
4. **`Grid.Valid() error`**, which checks §2.2. Snapshot and the tests
   need it.
5. **The renderer needs the local terminal size**: for example,
   `Renderer.Resize(cols, rows int)`, which also invalidates, or a size
   argument to `New`. `Render(g)` alone can't clip (§8.3).
6. **Key handling.** `architecture.md` §3.2 says the client "encodes keys
   for the screen's current `Modes`". With §8.5's mirroring, that encoding
   is a pass-through of the local terminal's bytes, and `render` writes
   the mode changes. The bootstrap-client owner should confirm.
7. **`NewGrid(0, 0)` is SSP version 0** (§2.3). `NewGrid`'s doc comment
   should say so, and that the zero values, with the cursor not visible,
   are the starting point.
8. **The client's keyboard capability.** The kitty keyboard protocol is
   off in slice 1 (§6.1) until `ClientLine` says whether the user's
   terminal supports it. Owner: bootstrap.
9. **What SSP does when `Apply` fails** on the client. This spec
   recommends ending the session (§5.9). `ssp.md` decides how the error
   reaches `client.Session`, since an instruction that never applies would
   otherwise be resent forever.
10. **Mouse encodings 1005 and 1015** have no `MouseEncoding` value, so
    they are sent as X10 (§6.2). Adding them changes `Modes` and the MODES
    byte's range. That is cheap now and a format change later.
11. **Styled underlines and the underline colour** are carried in the
    Grid but drawn as plain SGR 4 in slice 1 (§8.3). Drawing them needs a
    `Capabilities` field, probed from the local terminal.
12. **Synchronised output over IPC** (§6.3). Owners: screen and
    server-proc. In `server.md` §3.3 and §3.5:
    - `Update`'s flags gain bit 1, HELD, meaningful only on the last
      fragment: emu's snapshot for this answer was held under mode 2026.
    - A new request, `0x13 Flush` (proto → emu), type only, length 1. emu
      answers it like `Output`, with a run of `Update` fragments (and no
      `Replies`, since no program bytes were parsed). It counts as a
      request for T4 and for "one outstanding at a time".
    - In `internal/emu`, `Snapshot` reports whether it held, for example
      `Snapshot(g *screen.Grid) (held bool)`, so the in-process emulator
      and proto's IPC client give `server.Session` the same signal.
13. **proto's violation list** in `server.md` §3.5 gains the cases of
    §7.3: a mirror at a size other than the last `Init` or `Resize`, a
    SIZE op in an answer other than one to `Resize`, and `Bell` or
    `Clipboard` going backwards within a generation. §3.6's counter
    handling follows §7.2 (a rebuild resets the baseline and is never a
    change). Owner: server-proc.
14. **`render.Capabilities.UTF8`** (§8.3), set by the client from the
    locale. Owners: screen and bootstrap-client.

## Review notes

Answers to the review of this spec. Each issue was fixed; none was
rebutted outright, and the one optional suggestion not taken says why.

1. **Bound checks overflow in `uint64`** (§5.6 ROWS, SKIP, ERASE,
   REPEAT, COPY; raised twice). Fixed. §5.2 now forbids adding or
   multiplying a wire value in a check. Each op in §5.6 checks a wire
   value alone, first against a constant or size (`dst < R`,
   `sx < C₀`), then against a difference of state already known to be
   in order (`n ≤ R − dst`, `n ≤ C − x`, `n ≤ (C − x) / W`). §5.3 states
   the invariant `x ≤ C` that makes `C − x` safe. §9 item 7 says the same.
   §10 adds unit tests and `FuzzApply` seeds at 2^64 − 1, 2^64 − `x` and
   2^63 for all five ops.
2. **The cells-written budget was optional** (raised with item 1).
   Fixed. It is now checked before each write op, as `k ≤ budget −
   written` (§5.3, §5.5, §5.6), and §5.8 says it is not an end-of-diff
   check. ERASED's extent is computed from decoder state only.
3. **Non-ASCII to a non-UTF-8 terminal** (§8). Fixed, following
   `threat-model.md` §4.7: `Capabilities.UTF8`, read from the locale,
   and when false every non-ASCII cell becomes `?` (a width-2 cell `? `)
   and every non-ASCII title rune `?` (§1, §8.2, §8.3, §8.4, §9 item 2,
   §11 item 14). The render test checks for no byte ≥ 0x80. Refusing to
   start was rejected: it would lock out a user on a Latin-1 terminal,
   and substitution is what the threat model already promises.
4. **proto didn't check the mirror's size** (§7.3). Fixed: a mirror at
   any size other than the last `Init`/`Resize` is a violation, and a
   SIZE op is allowed only in the answer to a `Resize`. The optional
   client-side check (refuse a SIZE larger than the client recently
   asked for) was not adopted. Against a hostile server (T5) it bounds
   nothing: `MaxDiff` (48 MiB) already caps every diff whatever its size,
   since PEN ops write no cells, and a 1000 × 500 grid is within the
   clamp the client must hold anyway. Against a compromised emu (T6) the
   proto check is enough, because the client only ever sees proto's own
   re-encoded diffs. And a client check would race with resizes in
   flight, refusing legitimate frames.
5. **The base of a new emu's first `Update`** (§7.1, §7.3 against
   `server.md` §3.3, §3.6). Fixed to `server.md`'s choice:
   `NewGrid(cols, rows)` at `Init`'s size, stated in §7.1 and §7.3. SIZE
   now appears at the IPC boundary only after `Resize`. Version 0
   remains SSP's starting point between proto and the client, which is
   unaffected. §10 adds a test that the rebuilt mirror applies.
6. **A rebuild cleared the clipboard and rang the bell** (§7.2). Fixed:
   counters are compared only within a generation, a rebuild resets the
   baseline and is never a change, and a counter that falls within a
   generation is a violation. A Seq increase of any size is one new
   clipboard write. §10 adds a test that a rebuild leaves the client's
   `Bell` and `Clipboard` alone.
7. **Mode 2026 against the request/response IPC** (§6.3). Fixed as the
   review proposed: emu always answers, with an empty diff and a HELD
   flag while holding. Proto owns the `SyncHold` timer and sends a new
   `Flush` request when it fires, so a program that opens 2026 and goes
   quiet is shown after at most `SyncHold`. A new message was preferred
   to a zero-length `Output` (which `server.md` forbids, and which would
   blur "program bytes" with "poll") and to a same-size `Resize` (which
   might make the emulator do resize work). The interface changes are
   §11 item 12.
