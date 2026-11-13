# SSP timing: our understanding (spike S5)

This is the spike's working specification of the State Synchronization
Protocol's *transport and timing*, written in our own words from the Mosh
paper (Winstein & Balakrishnan, USENIX ATC 2012, cited as [P §x]), RFCs,
and black-box measurements of the installed `mosh` 1.4.0 binaries (cited as
[M], method in FINDINGS.md §4). Where none of these gives a value we chose
one and say why ([D] = derived/decided by us). No Mosh source code was read.

It is a spike document: `docs/spec/ssp.md` should be written later from this
plus Dan's decisions on the questions in FINDINGS.md §9. Revised after
review (FINDINGS.md §10): the security rules in §2.2, path validation in
§2.1, bounds in §2.3 and our own wire format in §2.4 are new.

## 1. Model

* Each direction synchronises one **object** from a *sender* (which owns it)
  to a *receiver* (which holds a copy). Client to server, the object is the
  user's input history; server to client, it is the screen [P §2].
* Every change to the sender's object produces a new numbered **version**.
  Version numbers are the sender's, monotonic, and start at 0 (the empty
  object both sides know) [D].
* A message is an **instruction**: "to get from version *a* to version *b*,
  apply this diff", plus the sender's acknowledgement of the reverse
  direction [P §2.3]. Applying an instruction is idempotent: if the receiver
  already holds *b*, nothing happens. That is why SSP needs no replay cache
  for *correctness* [P §2.2]; mosey still has one for security (§2.2).
* The diff is defined by the object, not by SSP. For input it carries every
  keystroke between *a* and *b*; for the screen it is whatever turns screen
  *a* into screen *b*, and intermediate screens are skipped [P §2.3].

## 2. Datagram layer

* Each datagram carries a strictly increasing **sequence number** [P §2.2],
  a millisecond-or-better **timestamp** and an optional **timestamp echo**
  [P §2.2: "every outgoing datagram contains a millisecond timestamp and an
  optional timestamp reply"]. Widths and encoding: §2.4.
* **Echo** = the most recent timestamp received from the peer, advanced by
  the time we held it before sending, so delayed acks and pacing do not
  inflate the RTT sample [P §2.2 change 2]. Each received timestamp is
  echoed at most once. There is no cut-off on how long it may be held:
  because the hold time is added, a long hold does not bias the sample [D].
  A sample over 60 s is discarded as bogus [D].
* **RTT estimation** is RFC 6298 §2 (SRTT, RTTVAR, alpha 1/8, beta 1/4,
  K = 4) on those samples. Every datagram has a unique sequence number, so
  Karn's ambiguity does not arise [P §2.2 change 1].
* **RTO** = SRTT + max(G, 4·RTTVAR), floored at **50 ms** instead of RFC
  6298's 1 s [P §2.2 change 3]. Proposed amendment (needs Dan, FINDINGS
  §9): add the peer's maximum ack delay (100 ms, §3) as QUIC's PTO does
  (RFC 9002 §6.2.1). Ceiling and backoff: §4.
* **Size**: a datagram's UDP payload is at most 1280 bytes (PLAN D5). Larger
  instructions are split into fragments; losing one fragment loses the
  instruction [D].

### 2.1 Roaming and path validation

The paper's rule is that the server sends to the source address of the
newest authentic datagram [P §2.2]. That is **not sufficient** on its own:
an on-path attacker can copy a genuine client datagram, re-send it from
another address (a victim's) so that it arrives first, and the server then
streams screen state to the victim - reflection, and a hijack of where the
output goes for as long as the attacker keeps it up (measured in FINDINGS
§6: 1.3 MB reflected from 44 kB in 90 s, and the real client stops
receiving). mosey therefore validates a new path, in the manner of QUIC
(RFC 9000 §8.2, §9.3):

1. The client needs no knowledge of the change [P §2.2 goal 4]; it just
   keeps sending.
2. When the server receives an authentic, newest datagram from an address
   other than its current peer, it makes that address the *candidate* and
   sends it a **path challenge** (a fresh random 64-bit token in an
   authenticated datagram). It repeats the challenge at most once per RTO
   while the candidate keeps sending.
3. The client answers any challenge at once with a **path response**
   carrying the token.
4. The candidate becomes the peer only on an authentic response with the
   current token. Until then the old peer keeps receiving everything, and
   the candidate may receive at most **3x** the bytes that arrived from it
   (anti-amplification, RFC 9000 §8.1), challenges included.
5. The first address is the one the handshake (S1) proved reachable.

Responding to "the peer is behind" (O7 resend-on-receive, if adopted) is
also limited to once per RTO, so a stream of small inbound datagrams cannot
draw a stream of large outbound ones even on a validated path.

### 2.2 Security ordering (no state before authentication)

* The AEAD nonce is unique per key: each direction has its **own key**
  (from the O1 KDF) **and** the sequence number's top bit is the direction
  bit, so even a key-separation bug cannot reuse a nonce across directions.
* The cleartext sequence number is AAD; every other header field
  (timestamp, echo, kind, flags) is inside the AEAD.
* Receive order is fixed: (1) replay window check on the sequence number
  (RFC 6479-style, 1024 wide), cheap and non-mutating; (2) authenticate and
  decrypt; (3) record the sequence number in the window; (4) only then
  update the high-water mark, RTT, timestamps, acks, roaming and
  instructions. A datagram that fails (1) or (2) changes nothing.

### 2.3 Resource bounds (fail closed)

Even an authenticated peer (a compromised server, say) must not be able to
exhaust the other side's memory:

* An instruction may span at most **512 fragments** (about 600 kB at the
  1280-byte payload); fragments whose index or count is out of range are
  dropped.
* At most **16** instructions are under reassembly, holding at most
  **1 MiB** in total; the oldest is evicted first.
* If O8 adopts compression, the decompressed frame is limited to a bound
  sized to the screen (rows x cols x a per-cell bound; 1 MiB in the spike)
  and an instruction that exceeds it is dropped, never truncated.

### 2.4 Wire format [D]

Our own layout, with the reason for each choice. Nothing here is taken
from Mosh; the review's clean-room check (FINDINGS §10, item 12) asked that
each field be derived independently.

| Field | Size | Why |
|---|---|---|
| seq | u64, cleartext, AAD; bit 63 = direction | Nonce for the AEAD; 2^63 per direction never wraps; the direction bit is the belt to per-direction keys' braces (§2.2). |
| flags | u8 | Kind in bits 0-2 (fragment, parity, path challenge, path response); bit 7 says an echo follows, so no sentinel value is needed. |
| ts | u32, microseconds | ms granularity would quantise a LAN RTT to 0 or 1 ms; 32 bits of µs wrap after 71 min, far beyond any RTT or hold time, and wrapping is handled by unsigned subtraction. |
| echo | u32, optional | As ts; absent (flag clear) when there is nothing to echo, which saves 4 bytes on most datagrams. |
| fragment | id u32, index u16, count u16 | An explicit count lets the receiver bound and pre-size reassembly before the last fragment arrives (§2.3) and reject inconsistent fragments; it costs one byte more than a final-flag scheme. |
| instruction | uvarint from, to, ack, floor; diff | `floor` is the oldest version the sender may still diff from (its acked version). The receiver needs it to discard old versions, because it cannot know which of its acks the sender has seen (the problem QUIC solves with "ack of ack"). |
| tag | 16 bytes | AES-GCM (stdlib) in the spike; the AEAD choice is O1. |

Per-datagram overhead is 29 bytes (seq, flags, ts, tag), 33 with an echo,
and an instruction fragment adds 8: at most 41 bytes in all.

## 3. Transport sender

State per direction (sender side): the current version `cur`; the highest
version the peer has acknowledged, `acked`; the version and time of the last
instruction sent; and the time of the last datagram of any kind.

The sender wakes at the earliest of the deadlines below and takes the first
that applies:

1. **New state** (cur differs from what we last sent). Send when *both*:
   * `now ≥ last_data_send + frame_interval`, where
     `frame_interval = clamp(SRTT/2, 20 ms, 250 ms)`. SRTT/2 keeps roughly
     one instruction in flight [P §2.3]; 20 ms is the 50 Hz cap
     [P §2.3 footnote 1]; 250 ms is the interval used in the paper's
     collection-interval analysis [P §4 Fig. 3] and PLAN D11.
   * `now ≥ first_change + collection_interval`. The **server** waits
     **8 ms** after the first change so that writes that follow each other
     closely go in one frame [P §2.3, §4]. The paper does not say what the
     **client** does with keystrokes; black-box mosh sends the first
     keystroke at once and later ones at the frame interval (FINDINGS §4),
     and the spike's baseline does the same.
2. **Retransmit**: cur has been sent but not acknowledged, and
   `now ≥ last_data_send + RTO·backoff`. Resend cur, diffed from `acked`.
3. **Delayed ack**: we received new peer state and have not acknowledged it
   within **100 ms**; send an empty instruction carrying the ack. Any data
   sent before then carries the ack instead [P §2.3].
4. **Heartbeat**: nothing sent for **3 s**; send an empty instruction. It
   lets the server learn a roamed client's address and the client warn the
   user [P §2.3].

**Diff base.** The sender diffs from `acked` by default: the receiver is
guaranteed to hold it. For the input direction that makes every datagram
carry *all* unacknowledged keystrokes, which is itself redundancy (see O7
in FINDINGS §5). Diffing optimistically from the last *sent* version saves
bytes when output is continuous; the receiver then has to wait for a
retransmit if that version was lost. The paper says only that the
instruction names its source and target [P §2.3]; the choice is [D] and
measured in FINDINGS §7 (O9).

**Floor.** Each instruction tells the receiver the oldest version the
sender will ever diff from again (`acked`), so the receiver can discard
older ones (§2.4).

## 4. Retransmission backoff and probing [D, M]

The paper names RFC 6298 [P §2.2] and does not say whether SSP doubles the
RTO on expiry (RFC 6298 §5.5) or what the ceiling is. The spike's
**baseline** doubles the RTO on each expiry with no new ack, capped at
1 s [D], and resets on an ack that advances `acked`. Black-box mosh 1.4.0
does something else (FINDINGS §4): it resends every frame interval for
about 10 s of silence, then every 3 s. With a 1 s cap, doubling versus not
doubling made no measurable difference; what matters is the **probe
cadence during an outage**, which is a cost/latency trade-off for Dan
(FINDINGS §5, outage sweep).

## 5. Receiver

* On a datagram that passes §2.2: update RTT from its echo, store its
  timestamp for our next echo, process its ack (advance `acked`, release
  versions below it), then the instruction.
* If the receiver holds the source version, apply the diff, store the new
  version, release versions below `floor`, and schedule an ack within
  100 ms. If it already holds the target, schedule an ack (the sender
  evidently missed ours). If it lacks the source, drop the instruction: the
  sender retransmits from `acked` [D].

## 6. Echo ack (affects datagram counts)

The screen object carries an **echo ack**: the newest keystroke the
application has had for at least **50 ms**, so the client can judge its
predictions without timeouts of its own. A change to it is a state change
and costs an extra frame about 50 ms after typing stops [P §3.2]. The S5 toy
screen implements it so datagram counts are realistic; prediction itself is
S6.

## 7. Constants and their provenance

| Constant | Value | Source |
|---|---|---|
| Minimum frame interval | 20 ms (50 Hz) | [P §2.3 fn. 1] |
| Frame interval | SRTT/2 | [P §2.3] |
| Maximum frame interval | 250 ms | PLAN D11; [P §4 Fig. 3] uses 250 ms |
| Server collection interval | 8 ms | [P §2.3, §4] |
| Delayed ack | 100 ms | [P §2.3] |
| Heartbeat | 3 s | [P §2.3] |
| RTO formula | RFC 6298 | [P §2.2] |
| RTO floor | 50 ms | [P §2.2] |
| Ack delay in RTO | +100 ms (proposed) | RFC 9002 §6.2.1; FINDINGS §5 |
| RTO ceiling, backoff | 1 s, doubling | [D]; compare [M] in FINDINGS §4 |
| Echo-ack delay | 50 ms | [P §3.2] |
| Max UDP payload | 1280 B | PLAN D5 |
| Timestamp | u32 µs | [D], §2.4 |
| Replay window | 1024 | [D]; RFC 6479 |
| Anti-amplification | 3x | RFC 9000 §8.1 |
| Max fragments / reassembly | 512 / 1 MiB / 16 | [D], §2.3 |
