# Spike S5: what length padding costs compressed frames

The harness code (`o8.Padme`, `o8.Typist`, `o8.ClientFrames`) is on the
spike branch `spike/s5-netsim-ssp`, commit b75f167; this note and its
results were copied to trunk when Dan decided O12 (`docs/spec/ssp.md`
§9.2).

A follow-up to FINDINGS §8 (O8). Compression is decided: always on, flate-6
per frame, no dictionary. Compression makes frame length depend on content
(CRIME/BREACH, FINDINGS §8 threat note), and the AEAD hides content, not
length. This note measures what each candidate padding policy costs in
flate's saving and in datagrams, and how much length it still leaks, for
server screen frames and for client input frames.

## 1. Summary

**Server frames:** pad frames under 64 bytes to 64 and apply Padmé to the
rest (policy 5). It costs the same as S5's "pad every frame to a multiple
of 64" (0.427 of raw against 0.430; 88% of flate's saving kept, +17% wire
bytes against unpadded flate) and makes every keystroke-echo frame one
size, but leaks less on large frames (at most 8 bits for frames up to
64 KiB against 10). Padmé alone is the cheapest (99% of the saving kept)
but leaves 12 distinct sizes among echo frames, which are the frames that
correlate with typing. A 128-byte floor costs another 13 points of the
saving and buys nothing on these captures. Datagram counts move by 4 of
585 (0.7%) for every padded policy.

**Client input frames:** the smallest fixed size covering at least 99.9%
of single-keystroke frames is **14 bytes** (the body that is padded: 1 flag
byte + the input diff). Recommend **16 bytes**: it covers 99.996%, costs
3 to 4 points more wire bytes than 14, and is a round number. Frames above
it go through Padmé: bracketed pastes (0.16% of frames), rare long
keystrokes (ZWJ emoji, up to 27 bytes) and, at RTTs of 100 ms or more,
keystrokes that pile up while the server has not acknowledged them (7-10%
of frames). The last group leaks how many keys are in flight; a 32-byte
size hides it up to 100 ms RTT for 1.48x the wire bytes of unpadded
input instead of 1.20x (§5, Q-P2).

| policy (server, six sessions, 50 ms) | bytes vs raw | flate saving kept | wire vs unpadded | datagrams @1232 | distinct sizes, echo frames (< 64 B) | distinct sizes, all frames | leak bits, M = 64 KiB |
|---|---|---|---|---|---|---|---|
| 1. none (flate-6) | 0.352 | 100% | 1.000 | 585 | 13 | 106 | 16 |
| 2. multiple of 64 (S5) | 0.430 | 88% | 1.178 | 589 | 1 | 21 | 10 |
| 3. multiple of 16 (WireGuard) | 0.362 | 98% | 1.023 | 588 | 3 | 52 | 12 |
| 4. Padmé | 0.360 | 99% | 1.020 | 589 | 12 | 40 | 8 |
| **5. < 64 B -> 64, else Padmé** | **0.427** | **88%** | **1.173** | **589** | **1** | **29** | **8** |
| 6. < 128 B -> 128, else Padmé | 0.511 | 75% | 1.365 | 589 | 1 | 27 | 8 |

## 2. Method

**Frames.** The O8 harness unchanged (FINDINGS §8): six real sessions
(`shell`, `vim`, `less`, `top`, `htop`, `flood`) replayed through
`charmbracelet/x/vt` at 120x40 on SSP's frame schedule (8 ms collection,
50 ms and 20 ms frame interval), each cell diff encoded with the spike's
structured encoding. **All six captures were used**: `top` and `htop` are
not committed, but the local copies match the SHA-256 hashes in
`spikes/s5-netsim-ssp/testdata/captures/README.md`. Results:
`results/padding-6sessions.md` (all six) and `results/padding.md`
(reproducible from the four committed ones, `go test ./o8 -run
PaddingReport -v`; the policies rank the same, §3).

**What is padded.** The "eff" size of the O8 report: 1 flag byte +
min(flate-6, raw). Without the raw fallback, always-flate costs 0.360
instead of 0.352 (stored blocks add ~5 bytes to a tiny frame), so the
fallback stays. Padding is trailing bytes inside the AEAD; the receiver
learns the true length from the body. In production the padded unit should
be the whole sealed plaintext, so that the instruction header's uvarints
(which grow as version numbers do) do not leak either [D].

**Columns.** *bytes vs raw*: padded bytes over raw unpadded diff bytes.
*Flate saving kept*: (raw - padded) / (raw - flate-6). *Wire*: padded +
49 bytes per datagram (41 datagram and fragment overhead, ~8 instruction
header; IP and UDP headers not counted, they would dilute every padding
cost further). *Datagrams @1232*: a 1232-byte UDP payload ceiling (the
IPv6 minimum MTU of 1280, RFC 8200 §5, minus 40 + 8 header bytes), so
1183 instruction bytes per datagram; S5 used 1280-byte payloads, given as
a second column in the results files. *Echo frames*: eff < 64 bytes
before padding, 435 of 536 (all from `shell`, `vim`, `less` and `flood`;
`top` and `htop` produce none). *Leak bits*: the PURBs paper's measure
(§4.2): ceil(log2 |R|), where R is the set of padded lengths the policy
can produce for lengths 1..M.

**Reproduction.** Policy 2 at S5's 1280-byte payloads gives 142272 bytes,
0.430, 583 datagrams: FINDINGS §8 exactly.

### Padmé

From Nikitin, Barman, Lueks, Underwood, Hubaux and Ford, "Reducing
Metadata Leakage from Encrypted Files and Communication with PURBs",
PoPETs 2019(4), §4.4, Algorithm 1 (arXiv:1806.03160), implemented as
printed (`o8.Padme`):

    E = floor(log2 L)         L's floating-point exponent
    S = floor(log2 E) + 1     bits needed to represent E
    z = E - S                 low bits forced to zero
    m = (1 << z) - 1
    L' = (L + m) & ~m

So the mantissa of the padded length is no longer than its exponent. For
L < 8, z <= 0 and nothing changes (L = 1 makes log2 E undefined; it is
left as is). Rounding steps: 2 bytes for 8-31, 4 for 32-63, 8 for 64-127,
16 for 128-511, 32 for 512-1023, 64 for 1024-2047, and so on; leakage is
O(log log M). Tests check the paper's Table 1 (8 -> 8, 9 -> 10, 10 -> 10),
idempotence and the overhead bound. **One discrepancy:** the paper says
the maximum overhead is +11.11% (9 -> 10), but Algorithm 1 pads 129 to
144, +11.63%; its other statement, "at most 12%", holds.

WireGuard's multiple of 16 is from the WireGuard paper (Donenfeld, NDSS
2017, §5.4.6).

## 3. Server frames

Six sessions, 50 ms frame interval (the 20 ms interval differs in the
third decimal place; both are in `results/padding-6sessions.md`). 536
frames, 331168 raw bytes, flate-6 116561.

| policy | bytes | vs raw | flate saving kept | mean pad B/frame | wire vs unpadded | datagrams @1232 | distinct sizes, echo | distinct sizes, all | leak bits M=63 | M=1183 | M=64 KiB |
|---|---|---|---|---|---|---|---|---|---|---|---|
| none | 116561 | 0.352 | 100% | 0.0 | 1.000 | 585 | 13 | 106 | 6 | 11 | 16 |
| bucket-64 | 142272 | 0.430 | 88% | 48.0 | 1.178 | 589 | 1 | 21 | 0 | 5 | 10 |
| bucket-16 (WireGuard) | 119808 | 0.362 | 98% | 6.1 | 1.023 | 588 | 3 | 52 | 2 | 7 | 12 |
| Padmé | 119278 | 0.360 | 99% | 5.1 | 1.020 | 589 | 12 | 40 | 5 | 7 | 8 |
| floor-64 + Padmé | 141440 | 0.427 | 88% | 46.4 | 1.173 | 589 | 1 | 29 | 0 | 6 | 8 |
| floor-128 + Padmé | 169360 | 0.511 | 75% | 98.5 | 1.365 | 589 | 1 | 27 | 0 | 6 | 8 |

Where the padding bytes go, by unpadded size:

| policy | 0-63 B (435 frames) | 64-127 B (2) | 128-1183 B (50) | >= 1184 B (49) |
|---|---|---|---|---|
| bucket-64 | 22551 | 84 | 1679 | 1397 |
| bucket-16 | 2551 | 20 | 351 | 325 |
| Padmé | 389 | 4 | 927 | 1397 |
| floor-64 + Padmé | 22551 | 4 | 927 | 1397 |
| floor-128 + Padmé | 50391 | 84 | 927 | 1397 |

What this shows:

* **The cost of any floor is the echo frames.** 81% of frames are under
  64 bytes, so a floor of F costs about F - 11 bytes on each (the median
  echo is ~11 bytes). Padding large frames is nearly free whichever scheme
  is used: Padmé adds 2324 bytes to 99 frames, 2% of the total.
* **Padmé alone does not hide echoes.** Below 64 bytes it rounds to 2 or
  4 bytes, leaving 12 sizes among echo frames, almost as many as no
  padding (13). Those are the frames an observer can line up with
  keystrokes: one character versus a word-wrap versus a prompt redraw.
* **Policy 5 against policy 2:** the same bytes (on 128-1183-byte frames
  Padmé adds 927 bytes where 64-byte buckets add 1679; above that they
  happen to add the same 1397),
  the same single echo size, and less leakage on large frames at the sizes
  that matter (8 bits up to 64 KiB against 10). Between 64 and 1183 bytes
  Padmé is finer than 64-byte buckets (6 bits against 5), so policy 2
  leaks less in the one-datagram range; at screen redraw sizes Padmé wins,
  and its advantage grows with M because it is O(log log M), not O(log M).
* **A 128-byte floor** would cover the echo-plus-status-line frames
  between 64 and 127 bytes, but there are 2 of them in 536 here; it
  doubles the echo cost for that.
* **Datagrams** are not the constraint: every padded policy adds 3 or 4
  datagrams of 585.
* **The four committed sessions** (`results/padding.md`) give the same
  ranking: 0.350 / 0.437 / 0.361 / 0.358 / 0.434 / 0.531 of raw, 100 / 87
  / 98 / 99 / 87 / 72% of the saving kept.
* The "distinct sizes, all frames" column is bounded by having only 536
  frames; the leak-bit columns are the fair comparison for large frames.

## 4. Client input frames

**There is no recorded client stream, so it is synthesised** [D]
(`o8.Typist`, `o8.ClientFrames`): 100 000 events per seed, three seeds, at
RTTs of 20, 100 and 300 ms (15.3 hours of typing per RTT). The model:

* Key mix (weights are judgement, not measurement): printable ASCII 86%
  (a sixth of it space), backspace 4.5%, arrows 3% (CSI and SS3 forms),
  Enter 2.5%, Tab and Ctrl keys 1% each, Esc 0.5%, Home/End/PgUp/Del 0.4%,
  modified arrows 0.2%, Alt keys 0.2%, function keys 0.1%, 2-byte UTF-8
  0.6%, 3-byte UTF-8 0.2%, 4-byte emoji 0.15%, VS16 emoji 0.05%, skin-tone
  emoji 0.03%, flags and ZWJ sequences 0.01% each, IME commits of 2-4 CJK
  characters 0.05%, SGR mouse reports at 120x40 0.2%.
* Timing: log-normal gaps with a 140 ms median; a 0.3-6 s pause after
  Enter; held-key auto-repeat (backspace or an arrow, 5-40 repeats at
  30 Hz) starting at 1% of keys; a bracketed paste at 0.2% of keys,
  log-normal around 60 bytes, capped at 16 KiB.
* Sending: SSP's client rule (`ssp-spec.md` §3): the first key after idle
  goes at once, later ones at most once per frame interval
  (clamp(RTT/2, 20 ms, 250 ms)), and every instruction carries all input
  since the version the server acknowledged; an ack arrives RTT + 8 ms
  after the send. The path is lossless; loss would only make frames
  longer.
* Encoding: per event, a uvarint length and the bytes; eff = 1 flag byte
  + min(flate-6, raw). An ASCII key is 3 bytes, an arrow 5, a 4-byte emoji
  6, a mouse report 11-15, an IME commit 8-14, a ZWJ emoji 13-27.

**Single-keystroke frames** (one event, not a paste; 487 734 frames):

| eff size <= | covered |
|---|---|
| 3 | 85.98% |
| 5 | 99.11% |
| 8 | 99.74% |
| 12 | 99.81% |
| **14** | **99.98%** |
| 16 | 99.996% |
| 27 | 100% |

The cut-off is set by mouse reports and IME commits; the keys people type
most are 3 to 5 bytes. Above 16 there are only ZWJ emoji (and, on a
screen over 99 columns or rows, a few mouse reports).

**All client frames**, padded to a fixed size with Padmé above it (wire =
padded + 49 bytes per datagram):

| RTT | policy | frames above the size: pastes / multi-key | wire vs unpadded | distinct sizes, non-paste frames |
|---|---|---|---|---|
| 20 ms | none | - | 1.000 | 15 |
| 20 ms | Padmé | - | 1.000 | 12 |
| 20 ms | fixed 14 + Padmé | 484 / 51 (0.18%) | 1.201 | 4 |
| 20 ms | **fixed 16 + Padmé** | 484 / 13 (0.17%) | **1.239** | **3** |
| 20 ms | fixed 32 + Padmé | 411 / 0 | 1.543 | 1 |
| 100 ms | none | - | 1.000 | 23 |
| 100 ms | Padmé | - | 1.003 | 16 |
| 100 ms | fixed 14 + Padmé | 484 / 27627 (9.9%) | 1.166 | 8 |
| 100 ms | **fixed 16 + Padmé** | 484 / 27251 (9.8%) | **1.199** | **7** |
| 100 ms | fixed 32 + Padmé | 417 / 0 | 1.484 | 1 |
| 100 ms | fixed 64 + Padmé | 283 / 0 | 2.069 | 1 |
| 300 ms | none | - | 1.000 | 51 |
| 300 ms | **fixed 16 + Padmé** | 495 / 15907 (7.0%) | **1.154** | **16** |
| 300 ms | fixed 32 + Padmé | 434 / 8900 (3.8%) | 1.415 | 8 |
| 300 ms | fixed 64 + Padmé | 300 / 0 | 1.954 | 1 |

What this shows:

* **The client's cost is overhead, not padding.** An unpadded keystroke
  is 3 bytes of body in a 52-byte datagram, so padding to 16 adds 24%
  of wire bytes at most, and less once IP and UDP headers are counted. In
  absolute terms, typing at 100 ms RTT sends 281 B/s unpadded, 336 B/s at
  16 bytes, 417 B/s at 32.
* **Pile-up, not long keys, is what exceeds the size.** At 100 ms RTT 41%
  of frames carry more than one key (fast typing and auto-repeat inside
  one RTT), and 10% of frames exceed 16 bytes; at 300 ms the 99.9th
  percentile of non-paste frames is 57 bytes. A frame's size then tells an
  observer roughly how many keys are unacknowledged, i.e. the typing rate
  over the last RTT. That is close to what packet timing already reveals
  (Q8 in FINDINGS §9), so it is a small extra leak, but it is the reason
  to consider 32.
* **Pastes** (0.16% of frames, around 60 bytes median, up to 16 KiB) go
  through Padmé: their size leaks at most 8 bits.
* Padmé alone is almost free on the client but leaves 12-25 distinct
  non-paste sizes.

## 5. Recommendation

* **Server: policy 5**, frames under 64 bytes padded to 64, Padmé above.
  88% of flate's saving kept, one echo size, at most 8 bits leaked per
  frame up to 64 KiB.
* **Client: a fixed 16-byte body for every input frame up to 16 bytes,
  Padmé above.** 14 is the measured 99.9% size; 16 costs 3-4 points more
  wire and covers 99.996%.
* Pad empty instructions too (acks, heartbeats, probes) to the same floor
  in each direction, so size does not tell an ack from a keystroke or an
  echo. Their cost is a few dozen bytes per RTT.
* Pad the whole sealed plaintext, not just the diff, so header uvarints do
  not leak (§2).
* Padding does nothing for timing. Keystroke timing (Q8) remains a
  separate decision for S6.

**Questions for Dan.**

Q-P1. Server floor: 64 (recommended) or 128? 128 hides echo-plus-status
      frames up to 127 bytes for 13 more points of the saving.

Q-P2. Client size: 16 (recommended), or 32, which hides key pile-up up to
      100 ms RTT for 1.48x the wire bytes of unpadded input instead of
      1.20x (417 against 336 B/s while typing)?

## 6. Limits

* The client stream is a model, not a trace; the 99.9% cut-off moves with
  the weights of mouse reports and IME commits. The CDF above is there so
  it can be read for another mix.
* 536 server frames from six sessions; the diff encoding is the spike's,
  not S2's (FINDINGS §12), so echo sizes in mosey may differ by a few
  bytes. The policy ranking does not depend on that unless typical echo
  frames exceed 64 bytes.
* Bucket sizes are rounded inside the AEAD; an attacker who can inject
  output can still push a frame across a boundary and count samples
  (FINDINGS §8). Padding blunts the compression oracle, it does not close
  it.
