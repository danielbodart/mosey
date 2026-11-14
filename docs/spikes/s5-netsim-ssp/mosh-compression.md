# Does mosh 1.4.0 compress before encrypting? (black-box) [M]

**Answer: yes.** Screen updates (server to client) and keystrokes (client
to server) are compressed before encryption, with an LZ77-plus-entropy
coder (DEFLATE-like). A full 80x24 screen of one repeated character costs
about 107 bytes on the wire. The same screen of random printable ASCII
costs about 1747 bytes. No padding was seen: datagram sizes take almost
every integer value. No size threshold was seen either: every update we
could produce was compressed.

Clean-room: established only from datagram sizes, the man pages, mosh.org,
the paper and `ldd` on the binaries. No Mosh source was read.

## 1. Method

`spikes/s5-netsim-ssp/cmd/moshcompress` (new, built from `cmd/moshprobe`,
FINDINGS §4) works like this:

* It runs `mosh-server new -i 127.0.0.1` with this shell:
  `stty -echo; while read -r f; do cat screens/"$f"; done`.
  Each typed line `N` makes the remote side draw the prepared file N.
* It puts a userspace UDP relay on loopback between `mosh-client` and
  `mosh-server`, with no added delay, and logs each datagram's time,
  direction and UDP payload size.
* `mosh-client` runs under `script(1)` at a fixed size, with
  `MOSH_PREDICTION_DISPLAY=never`.
* Each trial first draws a clear screen and waits 1.2 s. It then draws
  the test content, starting with `ESC[H ESC[2J`, and waits 1.2 s. All
  server-to-client (s2c) bytes in the second window are summed. Trials
  run in a random order in each repetition, and the random content is
  fresh each time.
* **Content that fills the screen** uses (rows-1) x cols characters, so
  nothing scrolls:
  * `same`: one repeated character, `a`.
  * `period37` and `period400`: a random base64 string of 37 or 400
    characters, repeated. An LZ coder compresses this. Run-length coding,
    or the terminal's own repeat-character operation, would not.
  * `words`: random words from a list of 10.
  * `half`: half `a`, half random base64.
  * `b64`: random base64, 6 bits of entropy per character.
  * `print`: random from the 94 printable ASCII characters, 6.55 bits per
    character.
* **Length sweep:** `a`*n against n random base64 characters, for n from
  1 to 1024, on an otherwise empty screen.
* **"excess"** is the window total minus the median of the `empty` trial,
  which is the keystroke ack alone. Each content window has about two s2c
  datagrams: the update, and one more about 50 ms later. So "excess" is
  roughly one whole update datagram, including its fixed framing.
* **"zlib"** is Python's `zlib.compress(level 9)` of the bytes drawn,
  less the 6-byte zlib wrapper. It is used only as a reference scale.
* **Runs:**
  * 80x24, 7 reps (seed 7).
  * 160x48, 3 reps (seed 11).
  * A typed-input run: lines of 2 to 1024 characters typed into the
    client, either `a`-runs or random base64, 5 reps, measuring
    client-to-server (c2s) bytes.

To reproduce, run from `spikes/s5-netsim-ssp`:
```
mise exec go@1.27.3 -- go run ./cmd/moshcompress -out OUT -reps 7 -settle 1200ms -seed 7
mise exec go@1.27.3 -- go run ./cmd/moshcompress -out OUT -cols 160 -rows 48 -reps 3 -settle 1200ms -seed 11
mise exec go@1.27.3 -- go run ./cmd/moshcompress -out OUT -screens=false -typed 1024 -reps 5 -settle 1s -seed 5
python3 -I cmd/moshcompress/analyse.py OUT/datagrams.csv
```
Raw CSVs and full analyses are in `results/mosh-compression/`. The
`screens/` files, about 3 MB of random text, are not committed. Without
them the zlib column prints `nan`.

## 2. Results

### 2.1 Equal-length full screens (medians; excess = bytes over the empty-trial baseline)

80x24 (1840 characters, baseline 84 B, 7 reps):

| content | s2c total | excess | excess / char | zlib-9 of drawn bytes | datagrams |
|---|---|---|---|---|---|
| same (`a`) | 191 | 107 | **0.058** | 30 | 2 |
| period37 | 348 | 264 | 0.143 | 155 | 2 |
| period400 | 551 | 467 | 0.254 | 368 | 2 |
| words | 638 | 554 | 0.301 | 466 | 2 |
| half a / half b64 | 961 | 877 | 0.477 | 774 | 2 |
| b64 | 1705 | 1621 | 0.881 | 1467 | 3 (1252 + 364 + 68) |
| print | 1831 | 1747 | **0.949** | 1598 | 3 (1252 + 498 + 82) |

160x48 (7520 characters, baseline 72 B, 3 reps):

| content | s2c total | excess | excess / char | zlib-9 | datagrams |
|---|---|---|---|---|---|
| same | 262 | 190 | **0.025** | 64 | 2 |
| period37 | 434 | 362 | 0.048 | 237 | 2 |
| period400 | 598 | 526 | 0.070 | 419 | 2 |
| words | 1671 | 1599 | 0.213 | 1423 | 3 |
| half | 3276 | 3204 | 0.426 | 2968 | 4 |
| b64 | 6150 | 6078 | 0.808 | 5801 | 6 (4 x 1252 + ...) |
| print | 6741 | 6669 | **0.887** | 6362 | 7 (5 x 1252 + ...) |

Spread across repetitions is small: typically ±10-20 B for one trial
(per-rep totals are in the analysis files).

What this shows:

* **Equal length, very different cost.** At 160x48 the incompressible
  screen costs 35x the repeated one.
* **This is LZ-class compression, not cleverness in the diff.**
  `period37`, a random 37-character string repeated, costs only 0.14 or
  0.05 B per character. Run-length coding, terminal repeat sequences and
  erase-to-end-of-line cannot do that. Back-references can.
* **There is an entropy coder too.** Random base64 costs 0.81-0.88 B per
  character, *less than one byte per character*. That is close to its
  6-bit entropy (0.75 B per character) plus overhead. The same holds for
  printable characters: 0.89-0.95 against 0.82 entropy. Plain bytes
  could not go below 1.0, so the bits are Huffman- or arithmetic-coded.
* **The ratio follows zlib throughout.** Excess minus zlib-9 of the drawn
  bytes stays at about 60-150 B (unfragmented) or 150-310 B (fragmented)
  in every row and both sizes, across ratios from 0.03 to 0.95. That
  constant is consistent with DEFLATE over the update, plus fixed
  per-datagram framing and the escape sequences that redraw the screen.
  It also fits the fact that both `mosh-server` and `mosh-client` link
  `libz.so.1` (`ldd`, zlib 1.3.2). We cannot see the exact algorithm or
  level from outside. "zlib/DEFLATE" is an inference, not an observation.
* **Compression happens before fragmentation.** Updates bigger than one
  datagram arrive as full 1252-byte UDP payloads plus a remainder. The
  fragment count follows the compressed size, not the screen size: the
  7520-character `same` screen fits in one datagram.

### 2.2 Length sweep: is there a minimum size?

80x24, median excess in bytes (7 reps; 160x48 is the same within noise):

| n chars | 1 | 2 | 4 | 8 | 16 | 32 | 64 | 128 | 256 | 512 | 1024 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `a`*n | 78 | 84 | 87 | 79 | 83 | 78 | 86 | 78 | 86 | 93 | 92 |
| b64 n | 81 | 76 | 90 | 91 | 108 | 148 | 206 | 216 | 328 | 532 | 925 |

* The `a`*n row is **flat from 1 to 1024 characters**, within ±8 B. If
  updates below some size were sent uncompressed, the row would climb by
  about 1 B per character up to that size. So any threshold lies below
  the smallest update we could make: one character plus its cursor and
  clear escapes, a few tens of bytes before compression.
* `same` and `b64` diverge from about n = 8-16. Below that, zlib itself
  gains almost nothing (zlib-9 sizes 10-17 B in both cases), and the
  ±10 B noise hides any difference. **No threshold was observed.**

### 2.3 Padding

* Datagram sizes are not quantised. In the 80x24 run, s2c datagrams take
  every size from 71 to 119 B, plus nearly every value up to 955 B.
  Repeats of one trial differ by a few bytes. The c2s keystroke
  datagrams also vary byte by byte, 60-85 B.
* The only fixed size is **1252 B**: a full fragment of a large update.
  It is a ceiling, not padding.
* The size of each datagram therefore follows the compressed length of
  the update, to within a byte. (Section 4 covers what this means.)

### 2.4 Client-to-server: typed lines are compressed too

The typed run (5 reps) sums c2s bytes over the 1 s after one write of n
characters plus a newline. The client sends about four datagrams, and the
keystrokes are repeated until acked.

| n typed | 2 | 16 | 64 | 256 | 1024 |
|---|---|---|---|---|---|
| `a`*n, c2s total | 302 | 301 | 316 | 330 | 339 |
| b64 n, c2s total | 298 | 350 | 493 | 1053 | 2811 |

A line of 1024 `a`s rides in datagrams of about 90 B. A line of 1024
random base64 characters needs about 910 B per datagram.

## 3. Documentation

* `man mosh`, `man mosh-server`, `man mosh-client` (1.4.0): no mention of
  compression, zlib or padding (`grep -i -E 'compress|zlib|pad'` finds
  nothing).
* The paper, https://mosh.org/mosh-paper.pdf (Winstein and Balakrishnan,
  USENIX ATC 2012): the text extracted with `pdftotext` has no match for
  "compress", "zlib", "padding" or "MTU". **It does not document
  compression.**
* https://mosh.org/ mentions zlib only as a build dependency, in its
  dependency table under "Building from source": "zlib zlib1g-dev". That
  is evidence of the library, not of how it is used on the wire.
* Mailing lists were not searched.

So compression is real but undocumented in the allowed sources. The only
evidence is behaviour: these measurements and the `libz` linkage.

## 4. What this means for mosey

* For wire efficiency, matching mosh means compressing the update
  payload before AEAD. On a full-screen redraw this gains 3-40x on
  typical text and is about neutral on random text. That is in line with
  the O8 offline estimate (FINDINGS §8: flate-6 at 0.35 of raw bytes
  overall).
* Mosh appears to compress **every** update with no threshold and **no
  padding**. That gives it the CRIME/BREACH length side channel described
  in FINDINGS §8, directly visible in datagram sizes (§2.3 above). The
  O8 recommendation still stands: compression opt-in, a 32-byte
  threshold, padding to 64. mosey would then be *more* conservative than
  mosh, not less.
* Fragments are 1252 B of UDP payload. That is a useful reference point
  for mosey's MTU choice.

## 5. Limits

* Loopback, one machine, no added delay or loss, and one terminal type
  (xterm-256color, `LANG=C.UTF-8`).
* "excess" includes the update's own framing. Below about 16 characters
  the bytes of the content are lost in ±10 B of noise.
* The compressor is identified only as LZ77 plus entropy coding, matching
  zlib-9 to within a constant. The level and the use of dictionaries
  across updates were not tested. Repeating an identical screen after a
  clear could test the second.
