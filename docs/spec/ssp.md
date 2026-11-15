# SSP: the State Synchronization Protocol

This is the specification `internal/ssp` and `internal/userinput` are
written from. It says in our own words what the Mosh paper describes,
amended by PLAN D11 and D24 and by what spike S5 measured, and it fixes
our own wire format. Nothing here comes from Mosh's source code, which no
one working on mosey reads (PLAN §4).

Owner: **ssp**. Status: slice 1, plus chaff (§9.1; its tick and sizes,
O10, are Dan's decision of 2026-11-15, §9.1.5). A
change to anything marked as a wire format or a constant is a change to
this file first, then to the code.

## 0. Sources and notation

Every constant and rule cites where it comes from:

| Tag | Meaning |
|---|---|
| [P §x] | Winstein & Balakrishnan, *Mosh: An Interactive Remote Shell for Mobile Clients*, USENIX ATC 2012, section x |
| [RFC n §x] | the RFC |
| [S5 §x] | our own measurement in netsim, `docs/spikes/s5-netsim-ssp/FINDINGS.md` section x (virtual time, 280 simulated hours) |
| [M] | black-box measurement of the `mosh` 1.4.0 binaries, S5 FINDINGS §4 and `docs/spikes/s5-netsim-ssp/mosh-compression.md` |
| [M S5 padding.md §x] | our own measurement of padding policies on S5's captures, `docs/spikes/s5-netsim-ssp/padding.md` section x |
| [PURBs] | Nikitin, Barman, Lueks, Underwood, Hubaux and Ford, *Reducing Metadata Leakage from Encrypted Files and Communication with PURBs*, PoPETs 2019(4), §4.4, Algorithm 1 (Padmé) |
| [D] | decided here, with the reason given beside it |
| Dn, On | PLAN.md §2 decision, §3 open item |

"Must", "must not" and "may" are used as in RFC 2119. Sizes are in bytes.
Fixed-width integers are big-endian. `uvarint` is the unsigned LEB128 of
Go's `encoding/binary.AppendUvarint`, at most 10 bytes, and **must** be in
its shortest form: a receiver re-encodes each one it reads and rejects the
datagram if the lengths differ. That makes every valid datagram have one
encoding, which the fuzz targets' round-trip invariants rely on [D].

## 1. Model

SSP keeps two copies of one object in step over a path that loses,
duplicates, delays and reorders datagrams [P §2]:

- Each direction synchronises one **object**. Its **sender** owns it and
  changes it; its **receiver** holds a copy. Client to server, the object
  is everything the user did (`userinput.Stream`); server to client, it is
  the screen (`screen.Grid`) [P §2].
- An object passes through numbered **versions**. Numbers belong to the
  sender, are `uint64`, start at 0 and only go up. Version 0 is the empty
  object both sides construct for themselves, so it never travels [D].
  A `uint64` cannot wrap in the life of a session.
- The sender tells the receiver how to move between versions with an
  **instruction**: "starting from version *from*, apply this diff and you
  have version *to*" [P §2.3]. Applying an instruction is idempotent: a
  receiver that already holds *to*, or anything newer, ignores it. That is
  why SSP itself needs no duplicate detection [P §2.2]; the transport still
  refuses replays, for security (D20).
- The object defines its own diff (`ssp.State[S].Diff`, `Apply`). SSP
  carries the bytes without looking inside. Two objects, two policies
  (D11, [P §2.3]):
  - **Input**: every keystroke matters, so a diff carries every event
    between the two versions (§10).
  - **Screen**: only the newest screen matters, so a diff is whatever turns
    screen *from* into screen *to*, and the screens in between are never
    sent.
- **Diffs start from the acknowledged version.** The sender always diffs
  from the newest version the receiver has acknowledged, `acked`, which the
  receiver is sure to hold. So every input datagram repeats every
  keystroke not yet acknowledged, which is SSP's redundancy [P §2.3].
  Diffing from the last *sent* version saved 8–12% of server bytes but
  worsened the p90 keystroke latency on high-speed rail from 577 to 732 ms,
  so mosey does not [S5 §7].
- **Versions are numbered when they are sent, not when they are made** [D].
  `Endpoint.Set` replaces the pending local object; a new number is minted
  only when the sender sends an instruction to an object that differs
  (`!Equal`) from the last one it numbered. Changes between two sends never
  get a number. This is how the server skips intermediate screens, and it
  bounds how many versions can be outstanding (§6.1).

### 1.1 Where SSP sits

```
  userinput.Stream / screen.Grid      the objects: Diff, Apply, Equal, Clone
            │
  ssp.Endpoint                        versions, instructions, acks, timers,
            │                         RTT, fragments, compression
  ssp.Datagrams (Send, Recv)          payloads ≤ Config.MaxPayload
            │
  transport.Conn                      counter, AEAD, replay window, rekey,
                                      path validation, chaff, channels
```

In the paper the datagram layer under SSP numbers, authenticates and
encrypts datagrams and follows the client's address [P §2.2]. In mosey
all of that is the transport's (`docs/spec/transport.md`): its 64-bit
counter is the sequence number and AEAD nonce, its RFC 6479 window refuses
replays, and it validates a new client address before sending to it (D21).
SSP sees only authentic payloads in some order, and never sees keys or
addresses. What remains of the paper's datagram layer, the timestamps that
measure the round-trip time [P §2.2], is SSP's and lives in the SSP header
(§3).

The transport delivers only `KindTerminal` frames to SSP; rekeys,
keepalives, path challenges and chaff never reach it (a CHAFF frame only
tells the server to chaff, §9.1.4). A rekey does
not touch SSP's state or timers.

### 1.2 Channels (D15)

One `Endpoint` synchronises one pair of objects over one `Datagrams`. The
terminal is one channel, carried in `transport.KindTerminal` frames, and
SSP datagrams carry no channel field: the transport's frame kind (and, for
later channels, the channel id prefix of `transport.KindChannel`) says
which endpoint a payload is for. A later SSP-synchronised channel gets its
own `Endpoint` over its own `Datagrams`, with `Config.MaxPayload` reduced
by the channel prefix. The agent channel (D25) is a byte stream with its
own reliability (`agent.md` §5); it does not use SSP, but pads its frames
by §9.2's rule. Which
channel types each side supports is negotiated in the handshake
(`transport.md`), not here.

### 1.3 Endpoints and transports (D26)

An `Endpoint` lives as long as the `transport.Conn` under it. A new
connection to the same session (resume, D8; takeover, D26) gets a new
`Endpoint`, and both directions start again from version 0. The server's
first instruction on it is therefore a full redraw from the empty screen.
SSP state is per transport so that a shared attach mode can come later
(D26). After a resume the server writes the new stream's events to the
pty from its event 0: the old stream's events it had written stay written,
any it had not are dropped with the old connection (they were never
acknowledged as consumed, so the old client could not have counted on
them), and `InputConsumed` counts the new stream from 0.

## 2. Roles

`Config.Role` is `Client` or `Server`. The only differences are in timing
(§6.2): the server waits to collect output before sending a new version,
and the client does not wait to collect keystrokes. Everything else,
including the wire format, is the same in both directions.

## 3. Datagram format

Each payload SSP hands to `Datagrams.Send` is one SSP datagram, at most
`Config.MaxPayload` bytes (in production `transport.MaxPayload` = 1202,
which makes the UDP payload at most 1232, D5).

```
offset  size   field
0       1      flags    bit 0 E: an echo follows
                        bit 1 F: a fragment follows
                        bit 2 P: the datagram is padded
                        bits 3-7: zero
1       4      ts       u32, the sender's clock in microseconds, mod 2^32
5       4      echo     u32, present iff E
.       1-10   ack      uvarint: the newest version of the peer's object
                        this side holds
.       4      id       u32, present iff F: which instruction
.       2      index    u16, present iff F: which fragment, from 0
.       2      count    u16, present iff F: how many fragments, >= 1
.       n      chunk    present iff F: n >= 1 bytes of the instruction
.       k+2    padding  present iff P: k zero bytes, then u16 k
```

| Field | Why it is like this |
|---|---|
| flags | One byte holds the three presence bits, so nothing needs a sentinel value [D]. Reserved bits must be zero: the two ends may be different builds (D8 V1), but any change to this layout comes with a protocol version of its own, negotiated in the handshake (`transport.md` §2.3), so under v1 an unknown bit is a protocol error rather than something to skip [D]. |
| ts | The paper puts a millisecond timestamp on every datagram [P §2.2]. Microseconds, because milliseconds would quantise a LAN round trip to 0 or 1 ms. 32 bits of microseconds wrap after 71 minutes, far beyond any round trip or hold time, and all arithmetic on them is mod 2^32 [D, S5 spec §2.4]. The clock is microseconds since the endpoint was made, read through `time` so `testing/synctest` drives it. |
| echo | The paper's optional timestamp reply [P §2.2], absent when there is nothing to echo, which saves 4 bytes on most datagrams [D]. Its value is in §7.1. |
| ack | In every datagram, not inside the instruction [D]. Acks then flow even in datagrams that carry only part of an instruction, and an instruction's bytes never depend on the ack, so a retransmission can repeat them exactly and the receiver can complete an instruction from fragments of two transmissions (§5). |
| id, index, count | An explicit count lets the receiver bound and size reassembly before the last fragment arrives, and refuse inconsistent fragments (§5) [D, S5 spec §2.4]. |
| padding | Hides the compressed length (§9.2): a sender sets P on every datagram it sends and chooses k by §9.2's rule; a receiver strips whatever step 2 below allows and does not check the sender's rule, since the peer holds the keys and could send any length it liked by other means [D]. Putting the length last means a sender can pad after it has built everything else [D]. Chaff (§9.1) is sized to the same floors. |

A datagram without F carries no instruction: it is an **ack** (delayed
ack, heartbeat or probe answer; §6.3, §6.4). After the fields its flags
announce, a datagram must have no bytes left.

**Parsing** a datagram, in this order, rejecting it (§8) at the first
failure:

1. At least 6 bytes (flags, ts, the shortest ack). Reserved flag bits zero.
2. If P: the last 2 bytes are k; `k + 2` must leave at least the 6 bytes
   of step 1 in front of it; the k bytes before the trailer must all be
   zero. Strip the `k + 2` bytes, then parse the rest.
3. ts; echo if E; ack (shortest form).
4. If F: id, index, count; `count ≥ 1`; `index < count`;
   `count ≤ MaxFragments` (§5); the chunk is the rest, and must be
   exactly `Chunk` bytes if `index < count − 1`, and 1 to `Chunk` bytes if
   `index = count − 1`. If not F: nothing may remain.

**Sizes.** The largest header is 1 + 4 + 4 + 10 + 8 = **27** bytes, and
every datagram ends in at least the 2-byte padding trailer (§9.2), so a
fragment's chunk is at most `Chunk = MaxPayload − 27 − 2` = **1173** bytes
in production [derived]. Reserving the trailer means the longest datagram
there can be still has room for P, so the padding rule never has to be
broken for lack of space. A sender fills every chunk but the last to exactly
`Chunk`, even when its own header is shorter, so the fragment boundaries of
an instruction never depend on its ack or echo (§5). Step 4 makes that a
rule a receiver checks, so a partial instruction of `count` fragments can
never hold more than `count × Chunk` bytes (§5).

What a keystroke costs on the wire, for orientation (one `a`, an echo, small
version numbers): SSP header 1 + 4 + 4 + 1 + 8 + instruction 1 + 1 + 1 +
input diff 1 + 1 + 1 + 1 + 1 + padding trailer 2 = 28 bytes of SSP, which
with the frame kind is 29 bytes of sealed plaintext, padded to 30 (§9.2);
with the transport's 13-byte clear header and 16-byte tag that is **59**
bytes of UDP payload. Mosh 1.4.0's keystroke datagrams were 60–85 bytes
[M].

## 4. Instructions

An instruction is the concatenation of its fragments' chunks, in index
order:

```
from      uvarint   the version the diff starts from; also the sender's floor
to        uvarint   the version it makes; to > from
encoding  u8        0x00 stored | 0x01 DEFLATE | 0x02 reserved | others: error
body      ...       the diff, encoded as `encoding` says, to the end
```

Its header is at most 10 + 10 + 1 = 21 bytes.

- **`from` is also the floor.** The sender only ever diffs from `acked`,
  which never goes down, so `from` is the oldest version this sender will
  ever diff from again, and the receiver may forget anything older (§7.3)
  [derived]. S5's spike format carried a separate floor field; with diffs
  always from `acked` it would always equal `from`, so it is gone.
- `to ≤ from` is a protocol error. Pure acks are datagrams without F, never
  instructions.
- `to − from > Window` (16, §6.1) is a protocol error: an honest sender
  never has more than `Window` versions outstanding past `acked`, so it
  can never make such an instruction, and the receiver relies on that to
  bound what it holds without evicting anything the sender may need
  (§7.3) [derived].
- An empty body is allowed: what an empty diff means is the object's
  business.

### 4.1 Compression (D24)

Compression is always on: the sender DEFLATEs every non-empty diff before
it fragments the instruction (D24). Mosh 1.4.0 does the same, compressing
every update with no padding and no size threshold [M,
mosh-compression.md §2].

- **Format**: raw DEFLATE (RFC 1951), no zlib or gzip wrapper, from the
  standard library's `compress/flate` at `flate.DefaultCompression` (level
  6). Level 6 cut screen bytes to 0.352 of raw at 7.6 µs to encode and
  3.3 µs to decode a frame [S5 §8].
- **Each instruction stands alone.** A fresh compressor per instruction,
  with no shared history and no preset dictionary, so losing one
  instruction never stops the next from decoding [D]. A retransmission
  reuses the bytes already made (§5), so compression runs once per
  instruction, not once per send.
- **Stored when it does not help.** If the DEFLATE output is not shorter
  than the diff, the sender sends the diff itself with encoding `0x00`;
  an empty diff is always sent stored. Compression is still always
  attempted, so this is D24's "always on", and it means a body is never
  longer than its diff. That is what lets a receiver bound an instruction
  by its decoded size (§5) [D]. No frame under 32 bytes ever compressed
  smaller in S5's captures [S5 §8], so in practice single keystrokes and
  small echoes go stored.
- **The decoder is bounded** and fails closed. It decodes into at most
  `MaxRemoteBytes` bytes and stops there: an instruction whose diff would
  be longer is a protocol error, never truncated and never applied
  [D24; S5 §8: one unbounded datagram inflated to about 1.3 MB].
  Concretely: read from a `flate.NewReader` over a `bytes.Reader` through
  `io.LimitReader(·, MaxRemoteBytes+1)`; more than `MaxRemoteBytes` bytes
  out is an error, any decode error (including `io.ErrUnexpectedEOF`) is an
  error, and bytes left in the `bytes.Reader` after the final block are an
  error. A stored body longer than `MaxRemoteBytes` is an error too.

The length side channel this opens is in §9.2 and
`docs/threat-model.md`.

## 5. Fragmentation and reassembly

An instruction longer than one chunk is split into `count =
ceil(len / Chunk)` fragments, each in its own datagram. Losing any one
loses the instruction until it is retransmitted [D, S5 spec §2]. Updates
over one datagram are rare except full-screen redraws [S5 §7], and Mosh
1.4.0 likewise fragments only after compressing [M,
mosh-compression.md §2.1].

**Pacing.** One transmission of an instruction sends its fragments in
index order, in bursts of at most **16** datagrams, one burst per frame
interval (§6.2) [D, provisional]. The first burst goes at once, so an
instruction of up to 16 fragments (about 18 kB, which covers every
120x40 redraw S5 saw) goes back to back as before. A larger one, such as a
redraw at the D23 size clamp (screen.md's `MaxDiff` is 48 MiB before
compression), goes at most 16 datagrams per 20 ms, about 7.7 Mbit/s at
the 50 Hz cap and correspondingly less as the frame interval grows with
the RTT, instead of thousands of datagrams at once into a queue that would
drop most of them. 16 is a guess with no measurement behind it; the netsim
test in §12 is what holds it, and a delivery-rate estimate can replace it
later without a format change. While a transmission is being paced out,
the sender sends no other data datagram (acks still ride on its
fragments), and `lastData` is set when its last fragment goes (§6.3).
Together with §6.3's rule that an unacknowledged multi-fragment
instruction is retransmitted under its own id rather than superseded, this
keeps a large instruction from livelocking: every retransmission fills
holes in the same partial (below), so it completes even while the screen
keeps changing.

**Ids.** Each sender numbers the instructions it makes with a `u32` id,
starting at 0 and adding 1 for each new instruction. A retransmission of
the same `(from, to)` reuses the id and the exact bytes, so a receiver
that kept a partial instruction can fill its holes from the second
transmission [D]. Any other instruction gets a new id. Ids are compared as
RFC 1982 serial numbers with a 2^31 window, so wrapping (after 2.7 years
at 50 instructions a second) needs no special case.

**Receiver bounds** (fail closed: an authenticated peer may still be
hostile, D4):

| Bound | Value | Why |
|---|---|---|
| `MaxInstruction` | `MaxRemoteBytes + 21` | The largest body is the largest diff (§4.1) plus the largest header [derived]. |
| `MaxFragments` | `ceil(MaxInstruction / Chunk)`, and at most 65535 | Both ends compute `Chunk` from the same `MaxPayload` (transport.MaxPayload, D5); a larger `count` is a protocol error [derived]. |
| partial instructions held | 4 | An honest sender has at most one multi-fragment instruction unacknowledged at a time (§6.3), and a completed one supersedes all older ids (below), so more than a few at once only happens under heavy reordering [D]. |
| bytes held in partials | `MaxPartialBytes = 2 × MaxFragments × Chunk` | Twice the most one partial can hold (§3 fixes every chunk's size, so a partial of `count ≤ MaxFragments` fragments holds at most `count × Chunk`): one maximal instruction and the start of the next, and eviction of the others always makes room for the one being filled [derived]. It is at least `2 × MaxInstruction`. S5 used 16 partials and 1 MiB total for a fixed-size toy screen [S5 §10 item 2]; ours scale with `MaxRemoteBytes`. |

**Reassembly**, for each fragment (§3 has already checked its chunk is
exactly `Chunk` bytes, or 1 to `Chunk` if it is the last):

1. If its id is not newer than the newest **completed** id, owe an ack
   (§6.4) and drop it. That instruction, or one that supersedes it, has
   already been handled, and the peer sending it again is the usual sign
   that it missed our ack: a retransmission reuses its id (above), so this
   is the only place an exact retransmission is seen [D].
2. If a partial with this id exists: a different `count` is a protocol
   error; a fragment whose index is already held is ignored (never
   replaces what is held).
3. If none exists, start one (empty).
4. **Charge** the chunk: while the bytes held in all partials plus this
   chunk would exceed `MaxPartialBytes`, or the partials would number more
   than 4, evict the partial with the oldest id **other than this one**.
   Since one partial never holds more than half of `MaxPartialBytes`, this
   always ends with room. Store the chunk.
5. When every index is held, the total length must not exceed
   `MaxInstruction` (else protocol error). Concatenate, mark the id
   completed, discard every partial with an older id, and handle the
   instruction (§7.2).

Memory is charged chunk by chunk as it is stored, never pre-allocated from
`count`, so a fragment claiming `count = 65535` costs the receiver one
chunk, and the bound holds after every fragment, which `FuzzReassembly`
checks.

## 6. The sender

### 6.1 State

| Name | Meaning |
|---|---|
| `pending` | The newest object from `Set` (the endpoint's own clone). |
| `sent[v]` | The object at every version `v` from `acked` to `latest`. |
| `latest` | The newest version number minted. |
| `acked` | The newest version the peer has acknowledged. |
| `changeAt` | When `pending` first differed from `sent[latest]`; zero when it does not. |
| `lastData` | When the last datagram carrying a fragment was sent. |
| `lastAny` | When the last datagram of any kind was sent (initially, the endpoint's creation). |
| `backoff` | Retransmission timeouts since `acked` last advanced. |
| `ackDue` | When an ack must have gone out by; zero when none is owed. |
| `instr` | The last instruction made: its `(from, to)`, id and encoded bytes. |

**The window.** At most `Window` = **16** versions are outstanding:
the sender does not mint while `latest − acked = Window` [D]. It never
forgets a version from `acked` to `latest`, so `sent` holds at most 17
objects and **every** ack the peer can send (it acks only versions it
received, all at most `latest`) names a version the sender still has.
There is no "ack for a forgotten version" case to recover from, which is
what made the earlier "forget the oldest" bound able to wedge a session
(Review notes, item 1).

Why 16: an honest peer acks within one RTT plus its 100 ms ack delay, and
the sender mints at most one version per frame interval,
`clamp(SRTT/2, 20 ms, 250 ms)`, so the versions outstanding are about
`(RTT + 100 ms) / frame interval + 1`: 8 at a 40 ms RTT, 6 at 200 ms,
9.4 at 2 s [derived]. The window is therefore reached only when acks are
being lost, or on paths with an RTT over about 3.6 s, where it limits the
sender to 16 versions per round trip. At the window the sender keeps
retransmitting `(acked → latest)` on the retransmit schedule (§6.3); each
retransmission draws an ack (§5 step 1, §7.3 step 3), and as soon as one
arrives the newest `pending` is minted. A burst of lost acks therefore
freezes the far side's view for at most about one retransmit or probe
interval after the path delivers again, never for good.

The window also bounds the receiver: every honest instruction has
`to − from ≤ Window` (§4), so the receiver holds at most 17 versions and
never has to evict one (§7.3).

### 6.2 Timing (D11)

| Quantity | Value | Source |
|---|---|---|
| frame interval | `clamp(SRTT/2, 20 ms, 250 ms)`; 20 ms before the first RTT sample | SRTT/2 keeps about one instruction in flight [P §2.3]; 20 ms is the 50 Hz cap [P §2.3, fn. 1]; 250 ms [P §4, Fig. 3] and D11; the value before a sample [D, S5] |
| collection interval, server | 8 ms after `changeAt` | so writes that follow each other closely go in one instruction [P §2.3, §4]; D11 |
| collection interval, client | 0 | the paper is silent; Mosh 1.4.0 sends the first key after idle at once (1.3 ms) and later keys of a burst at about SRTT/2 [M]; sending keys with no frame limit measured the same [S5 §7] [D] |
| delayed ack | 100 ms | [P §2.3]; D11 |
| heartbeat | 3 s since `lastAny` | [P §2.3]; Mosh 1.4.0 measured 3.00 s both ways [M]; D11 |
| RTO | §7.1 | |
| retransmit interval | `min(RTO × 2^backoff, 1 s)` | doubling per RFC 6298 §5.5, capped at 1 s: D11 as amended; doubling or not measured the same at a 1 s cap [S5 §5] |
| outage probe interval | `clamp(silence / 8, frame interval, 1 s)` once `silence ≥ 300 ms` | D11 as amended; [S5 §5, `o7-resend-prop`]; the 300 ms start was that variant's parameter and was not swept separately [S5 §5] |

`silence` is the time since the last authentic datagram from the peer
(`Stats.LastHeard`), or since the endpoint was made if nothing has arrived.
While `silence ≥ 300 ms` the outage probe interval **replaces** the
retransmit interval. Why: in S5's outage sweep the variant
`o7-resend-prop` gave median stalls of 210, 337 and 320 ms after outages
of 2, 5 and 8 s against 338, 404 and 332 ms for `rfc6298-ackdelay`
(plain doubling backoff), at 19–53 datagrams per outage against 9–37,
and matched a 1 s cadence on outages of 15 to 60 s, where Mosh's observed
"every frame interval for 10 s, then every 3 s" fell behind (411 vs
243 ms at 15 s) [S5 §5, outage sweep].

**Those numbers are not for the combination specified here.**
`o7-resend-prop` is `o7-resend` with proportional probes, and `o7-resend`
also had no backoff and resent on receive [S5 §5 variant table]. This
section keeps doubling below 300 ms of silence and rejects
resend-on-receive (below), and resend-on-receive acts exactly when the
path comes back, which is the moment the stall metric measures. The
specified combination (`rfc6298-ackdelay` plus proportional probing, no
resend-on-receive) has not been measured. Until it is, the evidence for
the probe rule is indirect: no-backoff and doubling measured the same at
a 1 s cap [S5 §5], and resend-on-receive alone did not help [S5 §5]. The
S5 outage sweep must be re-run with this combination before the rule is
final, and its numbers replace these; §12 asserts the post-outage stall
so a regression is caught either way.

A probe is an ordinary retransmission: it exists only while there is unacknowledged state. With nothing unacknowledged, an
idle side sends heartbeats only, as Mosh does during a full blackhole [M].

SSP does **not** resend because a peer datagram shows the peer is behind
(S5's "resend-on-receive"): alone it gave no gain and roughly doubled the
median stall on two of three LTE traces [S5 §5]. It does not add XOR parity
either (+18–20% client bytes for no gain, [S5 §5]).

### 6.3 What to send

The sender wakes at the earliest of: `changeAt + collection`,
`lastData + frame interval`, `lastData + retransmit interval` (when
`latest > acked`), `ackDue`, `lastAny + 3 s`; and whenever `Set` is called
or a datagram arrives. At each wake, with `now` the time:

```
if a transmission is still being paced out (§5): send its next burst
    when its frame interval is up; nothing else below runs        [data]

if pending differs from sent[latest] and changeAt is zero: changeAt = now
changed  = changeAt is not zero
mayMint  = latest - acked < Window
           and not (latest > acked and instr.to == latest
                    and instr has more than one fragment)
newDue   = changed and mayMint and now >= lastData + frameInterval
                   and now >= changeAt + collection
rexDue   = latest > acked and now >= lastData + retransmitInterval(now)

if newDue, or (rexDue and changed and mayMint):
    latest += 1; sent[latest] = clone(pending); changeAt = zero
    make the instruction (acked -> latest) with a new id; send it   [data]
    if rexDue: backoff += 1
else if rexDue:
    if instr is (acked -> latest): send instr again, same id and bytes
    else: make (acked -> latest) with a new id; send it              [data]
    backoff += 1
else if (ackDue is not zero and now >= ackDue) or now >= lastAny + 3 s:
    send an ack datagram                                             [ack]
```

- **A multi-fragment instruction is not superseded while it is
  unacknowledged** [D]. `mayMint` is false while the newest instruction
  has more than one fragment and `latest` is not yet acknowledged, so the
  retransmit branch resends it under the same id and bytes, and the
  receiver's partial fills from successive transmissions (§5) until it
  completes. Minting a new instruction instead would give it a new id and
  new bytes, the old partial's holes could never be filled, and under
  continuous output and loss a large redraw might never complete. Changes
  made meanwhile wait in `pending` and go in the next instruction, from
  the newer `acked`, which is usually far smaller. If `acked` advances to
  a version below `latest`, the retransmit branch makes a fresh
  `(acked → latest)` as before.
- A retransmission that finds a newer `pending` sends the newer version
  instead, without waiting out the server's collection interval: the
  retransmit interval is never shorter than the frame interval, so that
  limit has already passed [derived].
- Every datagram sent, data or ack, carries the current `ack` (§7.2) and,
  if one is held, the echo (§7.1); it clears `ackDue` and sets
  `lastAny = now`. A data datagram also sets `lastData = now` (for a
  fragmented instruction, when its last fragment goes).
- `Datagrams.Send` failing (including `transport.ErrBlocked` from the
  anti-amplification limit, D21) counts as a send that the path lost:
  timers advance as though it went [D]. The datagram is not retried at
  once, which is what the limit wants (transport.md).
- `Set(x)` with `x.Equal(pending)` changes nothing.

### 6.4 Acks

An ack is owed (`ackDue = now + 100 ms`, unless an earlier one is already
set) when an instruction arrives that makes a new version, and when the
peer shows it has missed our ack [P §2.3]. The peer shows that by sending
something this side has already handled or cannot use:

- any fragment of an id not newer than the newest completed id, which is
  how an exact retransmission arrives (§5 step 1);
- a completed instruction for a version this side already holds (§7.3
  step 3), which a retransmission under a new id becomes;
- a completed instruction from a version this side does not hold (§7.3
  step 4).

Any datagram that goes out before `ackDue` carries the ack instead
[P §2.3]. Because `ackDue` is only ever brought forward to 100 ms ahead, a
stream of duplicates, or every fragment of a large retransmission, draws
at most one ack per 100 ms [derived].

An ack datagram is never answered with an ack, so two idle endpoints
exchange only heartbeats.

## 7. The receiver

### 7.1 Round-trip time and RTO

**Echo.** On each authentic datagram the receiver stores its `ts` and the
local arrival time. The next datagram it sends carries
`echo = ts + hold` (mod 2^32), where `hold` is the microseconds since that
arrival; it then forgets the stored `ts`, so each one is echoed at most
once [P §2.2]. Adding the hold time means delayed acks and frame pacing do
not inflate the sample [P §2.2], so no limit on how long a timestamp may be
held is needed [D].

**Sample.** On a datagram with E, `R = (now_ts − echo) mod 2^32`
microseconds. A sample of 60 s or more is discarded as bogus [D]. Every
datagram has a fresh timestamp, so a retransmission's sample is never
ambiguous and Karn's algorithm is not needed [P §2.2].

**Estimator**, RFC 6298 §2 with α = 1/8, β = 1/4, K = 4 [P §2.2]:

- first sample: `SRTT = R`, `RTTVAR = R / 2`;
- later: `RTTVAR = 3/4·RTTVAR + 1/4·|SRTT − R|`, then
  `SRTT = 7/8·SRTT + 1/8·R`.

**RTO**:

```
RTO = max(50 ms, SRTT + max(G, 4·RTTVAR)) + MaxAckDelay
G = 1 ms; MaxAckDelay = 100 ms; before the first sample, RTO = 1 s
```

- The 50 ms floor replaces RFC 6298's 1 s [P §2.2]; D11.
- `MaxAckDelay` is the peer's 100 ms delayed ack (§6.4), added as QUIC
  adds it (RFC 9002 §6.2.1); D11 as amended. Without it the RTO fires
  before a delayed ack can arrive, which wasted 21% of server datagrams on
  a clean 40 ms path and 8–16% on the LTE traces, at no measurable gain in
  stalls [S5 §5]. The effective floor is 150 ms.
- `G` stands for timer granularity (RFC 6298 §2); 1 ms is Go's timer
  resolution on Linux in practice [D].
- 1 s before any sample is RFC 6298 §2.1's initial RTO.
- `Stats.RTO` reports this RTO, before backoff. `backoff` returns to 0
  whenever `acked` advances [D, S5 spec §4].

### 7.2 Handling a datagram

Each payload from `Datagrams.Recv`, in this order:

1. **Parse** (§3). Failure: protocol error (§8).
2. `LastHeard = now`; store `ts` for the echo; if E, take the RTT sample.
3. **Ack.** `ack > latest` is a protocol error: the peer cannot hold a
   version never sent. If `ack > acked`: `acked = ack` (`sent[ack]` is
   always kept, §6.1), forget every `sent[v]` with `v < acked`,
   `backoff = 0`. Otherwise ignore it (reordered or repeated).
4. **Fragment**, if F: reassemble (§5). If that completes an instruction,
   handle it (§7.3).

Steps 2 and 3 happen for every datagram that parses, before reassembly,
so acks and RTT samples flow even while a large instruction is incomplete.

### 7.3 Handling an instruction

The receiver keeps `held[v]`, copies of the peer's object at versions it
has reached; `newest`, the largest such `v`; and `floor`, the largest
`from` it has seen. Initially `held[0]` = the empty remote object and
`newest = floor = 0`.

1. Parse the header (§4). `to ≤ from`, `to − from > Window`, or an
   unknown encoding: protocol error.
2. `floor = max(floor, from)`. Forget every `held[v]` with `v < floor`,
   except `held[newest]` [§4, floor].
3. If `to ≤ newest`: it is old or a duplicate. Owe an ack (§6.4); stop.
4. If `held[from]` is not kept: owe an ack (§6.4) and drop it. With an
   honest peer this is only a reordered instruction from below the floor;
   the ack tells the sender `newest` within 100 ms in any case [D].
5. Decode the body (§4.1). Failure: protocol error.
6. `next = held[from].Clone()`; `next.Apply(diff)`. `Apply` validates
   everything before changing anything; failure is a protocol error.
7. `held[to] = next`, `newest = to`; forget every `held[v]` with
   `v < floor` other than `newest`. Signal `RemoteChanged` (non-blocking,
   coalescing). Owe an ack.

The ack this side sends is always `newest`. **The receiver never evicts a
version at or above the floor**, and needs no count bound to stay small
[derived]:

- *It holds every version the sender can diff from.* The sender diffs
  only from its `acked`, which is a version this side acked, so this side
  held it. This side forgets only versions below `floor`, and `floor` is
  a `from` the sender used, so it is at most the sender's `acked`, which
  never goes down. So `held[acked]` is always there, every honest
  instruction applies (or is a duplicate), and `newest` reaches the
  sender's `latest`.
- *It holds at most 17 versions.* Every version this side applied came
  from an instruction with `from ≤ floor` (step 2 raised `floor` to at
  least its `from`) and `to ≤ from + Window` (step 1), so every held
  version other than `newest` lies in `[floor, floor + Window]`, and so
  does `newest` unless it is the only one held.

A hostile peer gets no more: step 1 refuses wide instructions outright,
and the bound above uses nothing but steps 1, 2 and 7. Seventeen copies of
a screen at the D23 clamp would be large, so `screen.Grid.Clone` must
share unchanged rows between versions; that is `screen.md`'s to specify.

`Remote()` returns `held[newest].Clone()` and `newest`.

## 8. Errors

SSP fails closed. Every datagram it parses has been authenticated by the
transport, so a malformed one comes from a peer that holds the session's
keys and is broken or hostile. Rather than drop and wait for a
retransmission that would fail the same way (a silent stall), `Run` stops
and returns an error wrapping `ssp.ErrProtocol` that says which rule was
broken [D]. On the client that ends the session with that message; on the
server it closes that connection only, and the session waits for a
resume (`bootstrap.md` §9.3).

| Event | Handling |
|---|---|
| Datagram fails §3 parsing; reserved flag bit; non-shortest uvarint | protocol error |
| `ack > latest` | protocol error |
| fragment `count` > `MaxFragments`, `index ≥ count`, a non-final chunk not exactly `Chunk` bytes, a final chunk empty or over `Chunk`, `count` differing within one id, reassembled length > `MaxInstruction` | protocol error |
| instruction `to ≤ from`, `to − from > Window`, unknown encoding (including the reserved `0x02`) | protocol error |
| body decodes past `MaxRemoteBytes`, decode error, trailing bytes, stored body too long | protocol error |
| `State.Apply` fails | protocol error |
| fragment of a completed or superseded id | dropped; ack owed |
| duplicate index within a partial | ignored |
| reassembly over its bounds | oldest other partial evicted |
| instruction from a version not held; `to ≤ newest` | dropped; ack owed |
| ack not newer than `acked` | ignored |
| `Datagrams.Send` error | treated as loss (§6.3) |
| `Datagrams.Recv` error | `Run` returns it |
| `ctx` done | `Run` returns `ctx.Err()` |

A protocol error changes no state the error is about: the endpoint stops
at the first one, and `Apply` and the decoder never leave half a change
behind.

## 9. Reserved, and still open

### 9.1 Chaff (D11, O10)

D11 says that while the user types, SSP sends chaff on a fixed tick, as
OpenSSH 9.5's `ObscureKeystrokeTiming` does. Its `ssh_config(5)` entry
describes the behaviour this section adapts: while typing, keystrokes go
at fixed intervals (20 ms by default) and fake keystroke packets go "for
some time after typing ceases" (OpenSSH 9.5 release notes and
`ssh_config(5)`; nothing here is taken from its source). Without chaff the
times of the client's datagrams are the times of the user's keys, every
keystroke being a datagram (§6.2), and the server's echoes, acks and
echo-ack frames follow each key by a fixed delay, so an on-path observer
reads inter-keystroke timing off either direction, including at password
prompts (Song, Wagner and Tian, USENIX Security 2001; S6 FINDINGS §6;
threat model R2).

**What it hides.** Within a run of typing, which ticks carried a key, in
either direction. **What it does not.** That someone is typing and when a
run of typing starts (its first key goes at once, below); when it ends,
to within the random linger; gaps longer than the linger, which start a
new run; and anything that makes a datagram bigger than the chaff, such as
keys piling up unacknowledged, a paste, or the output a command prints
(R1, R2).

#### 9.1.1 The mode

Each endpoint is either **chaffing** or not. While chaffing it sends only
on its own **tick grid**, instants `start + n·T` for the tick `T`
(§9.1.5), and sends exactly one datagram per tick unless SSP has more than
one due (a burst of fragments, §5).

| | Client | Server |
|---|---|---|
| Starts or extends | on every `Set` that changes `pending` (a key or a resize; §10.1) | on every CHAFF frame from the client |
| Until | at least `now + L`, `L` drawn afresh, uniformly from [1 s, 2 s), on each input | at least `now + 1 s` |
| Chaff size (sealed plaintext) | 64, above its floor `F` of 40 (§9.2) [D, Dan 2026-11-15] | 64, its floor `F` |

- **Starting.** An endpoint that was not chaffing starts its grid at
  `now`: the input that starts the mode goes at once, as the first key
  after idle does without chaff (§6.2) [D]. Delaying it would hide nothing,
  since the first chaff gives the start of the run away just the same.
- **At each tick**, §6.3 runs as usual. Then, if it queued nothing and an
  ack is owed (`ackDue` set, even if not yet reached), the ack goes now:
  the delayed ack exists to save a datagram, and one goes this tick
  regardless [D]. If still nothing is queued, one CHAFF frame goes, of the
  side's chaff size. Every SSP datagram is padded by §9.2 as always, and
  while chaffing to at least the side's chaff size, so a keystroke, an ack
  and a chaff frame from the client are all 64 bytes on the tick grid, as
  the server's echoes, acks and chaff are. When the mode ends the client
  goes back to its floor of 40.
- **Between ticks** the endpoint receives as usual and sends nothing. A
  key typed, a screen change, an ack or retransmission falling due between
  ticks waits for the next tick, which is at most `T` away.
- **The grid holds.** After a late wake-up (a busy scheduler) the next tick
  is the first grid point after `now`; missed ticks are not made up in a
  burst [D].
- **Ending.** The mode ends at the first tick at or after `until`, which
  §6.3 handles as it would without chaff, as it does everything after.
- **Heartbeats** need nothing new: a chaffing endpoint sends far more often
  than every 3 s, and SSP's datagrams among its ticks keep `lastAny`
  current.
- **The receiver** of a CHAFF frame is the transport, which drops it after
  authenticating it. Chaff never reaches SSP's parser, its state, its RTT
  estimate or its silence clock (§6.2); the only thing it does is tell the
  server's endpoint to chaff (`Chaffer.ChaffArrived`, §9.1.4).

Why the linger is random and between 1 and 2 s [D]: a fixed linger would
put the end of the chaff exactly `L` after the last key, which is often
the Enter after a password; a random one blurs that over a second. The
1 s floor keeps every ordinary gap between keys inside one run: S5's typist
model (log-normal gaps, median 140 ms, σ 0.6; `padding.md` §4) has one
gap in 2000 over a second, while its pauses after Enter (0.3–6 s) mostly
end a run, as they should, since nothing is typed in them.

#### 9.1.2 Why the server chaffs too

The client's chaff alone hides nothing: the server answers a key and not
a chaff, with an echo 8 ms after the key arrives (§6.2), an echo-ack
frame (D12), or a delayed ack 100 ms after it (§6.4), so the observer reads
off the server's direction which client ticks carried keys. §9.1.5
measures this. So the server chaffs on its own grid while the client does,
and an echo, an echo ack or an ack is one more 64-byte datagram among the
server's ticks.

The server learns that the client is chaffing from the CHAFF frames
themselves. It does not chaff on the client's data alone, so the very
first key of a run is echoed at once, before any chaff has arrived; that
key's time is given away by the start of the client's chaff in any case.
The server lingers 1 s after the last CHAFF frame [D], which is more than
the jitter of every netsim profile but the train's delay spikes, so a
chaff frame that is late or lost does not end the server's mode in the
middle of a run.

#### 9.1.3 Prediction and echo-off (D12)

- **Chaff delays a key on the wire, not on the screen.** The client
  predicts a key the moment it reads it; only its datagram waits for the
  tick, and the confirmation waits for the server's tick too.
- **Echo off.** The client chaffs at a no-echo prompt exactly as anywhere
  else; that is where it matters most. D11's rule that the server sends no
  echo-ack-only frame while the pty has echo off still holds, and is now a
  second line of defence: while chaffing, such a frame would be a 64-byte
  datagram on the server's grid, like the chaff around it, and once the
  mode has ended it would be the one datagram that names the last key.
- **Echo acks** are screen changes like any other (§10.2) and go on the
  server's ticks while it chaffs, so they add nothing an observer can see.

#### 9.1.4 Interface

`Datagrams` that can send cover traffic also implement `ssp.Chaffer`:

```go
type Chaffer interface {
	// SendChaff sends one CHAFF frame whose sealed plaintext, frame kind
	// included, is size bytes; an error is a loss, as for Send.
	SendChaff(size int) error
	// ChaffArrived is signalled, without blocking, when a CHAFF frame
	// from the peer authenticates. One signal may stand for several.
	ChaffArrived() <-chan struct{}
}
```

An `Endpoint` whose `Datagrams` is a `Chaffer` chaffs; one whose
`Datagrams` is not (SSP's own small path in tests) behaves as §6 alone
says. `transport.Conn` implements it (`transport.md` §4.2), so production
always chaffs: it is D11, not an option. Since nothing would fail if that
link broke (the endpoint would quietly not chaff), both `internal/client`
and `internal/server` assert `var _ ssp.Chaffer = (*transport.Conn)(nil)`
at compile time, and `TestARealSessionChaffsOnTheTickGridWhileTheUserTypes`
in `internal/e2e` checks the wire of a real session for the tick grid.

#### 9.1.5 The tick (O10)

**T = 20 ms** [M]. Measured in netsim under `testing/synctest`
(`TestMeasureChaffTicks` in `internal/ssp`, run with
`MOSEY_MEASURE_CHAFF=1`; 2026-11-14), the source of every number below.

*Method.* SSP's two endpoints over every `netsim.Profiles()` profile, with
the transport's frame kind in front of every payload so that what netsim
carries is the sealed plaintext an observer sees the length of. A typist
rewritten from S5's (`padding.md` §4): log-normal gaps between keys,
median 140 ms, σ 0.6, at least 30 ms; after one key in 40, a pause of
0.3–6 s. 1500 keys on each of 3 seeds per row. The server's shell echoes a
few bytes per key (64 bytes padded, as real echoes are). Rates are per
minute of the typing session (the keys plus 3 s), not of idle time, which
costs nothing.

*The observer* sits at both ends, so sees exact send times and sizes, and
knows `T` and both chaff sizes. It marks a datagram as standing out unless
it is its side's chaff size and both its neighbours in its direction are
exactly `T` away. A key is **exposed** if the client datagram that first
carried it stands out, or the server datagram that first carried its echo
does. Without chaff every key is exposed both ways, which is the leak
Song et al. measured in SSH.

*Results* (key→echo is the time from the key to its echo on the client's
copy of the screen, without prediction):

| profile | chaff | keys exposed: all (by size; by the server) | key→echo p50 / p95 | datagrams/min, client + server | kB/min, client + server |
|---|---|---|---|---|---|
| lan | none | 100% | 9 / 9 ms | 405 + 245 | 28 + 23 |
| lan | client only, 20 ms | 100% (0%; 100%) | 18 / 27 ms | 2426 + 245 | 167 + 23 |
| lan | **20 ms** | **2.0%** (0%; 1.6%) | **30 / 40 ms** | 2430 + 2641 | 168 + 246 |
| hotel-wifi, calm | none | 100% | 52 / 89 ms | 378 + 259 | 26 + 24 |
| hotel-wifi, calm | **20 ms** | **2.4%** (0.4%; 1.5%) | **74 / 116 ms** | 2431 + 2638 | 168 + 245 |
| train, calm | none | 100% | 109 / 371 ms | 368 + 262 | 26 + 24 |
| train, calm | **20 ms** | **5.0%** (1.9%; 2.1%) | **135 / 391 ms** | 2425 + 2580 | 168 + 240 |
| hsr, calm | none | 100% | 129 / 276 ms | 365 + 258 | 25 + 24 |
| hsr, calm | **20 ms** | **4.6%** (1.6%; 2.2%) | **158 / 360 ms** | 2421 + 2568 | 167 + 239 |
| lte-driving | none | 100% | 75 / 2930 ms | 353 + 253 | 25 + 24 |
| lte-driving | **20 ms** | **12.3%** (10.3%; 1.5%) | **97 / 3887 ms** | 2424 + 2506 | 168 + 233 |

The tick against what it adds to the median key→echo over no chaff, and
what it costs, on the same profiles (lan / hotel calm / train calm / hsr
calm / lte):

| T | added p50 key→echo | keys exposed | datagrams/min, both ways | kB/min, both ways |
|---|---|---|---|---|
| 10 ms | +7 / +14 / +24 / +26 / +10 ms | 2.0 / 2.4 / 4.9 / 4.6 / 12.4% | about 10 000 | about 820 |
| **20 ms** | **+21 / +22 / +26 / +29 / +22 ms** | **2.0 / 2.4 / 5.0 / 4.6 / 12.3%** | **about 5 000** | **about 410** |
| 30 ms | +35 / +34 / +32 / +36 / +37 ms | 2.2 / 2.4 / 5.2 / 4.7 / 11.9% | about 3 400 | about 270 |
| 50 ms | +63 / +58 / +57 / +64 / +63 ms | 2.7 / 2.8 / 5.3 / 4.7 / 11.6% | about 2 000 | about 165 |

The same tick sweep on the `hotel-wifi`, `train` and `hsr` profiles **as
defined**, with netsim's per-packet delay spikes left in (re-run
2026-11-14; runs differ by a point or two, since goroutine order within a
bubble is not fixed). Each cell is keys exposed (by size), then key→echo
p50 / p95; for `lte-driving`, which has no spike model to remove, the
table above already is the profile as defined:

| T | hotel-wifi | train | hsr | lte-driving |
|---|---|---|---|---|
| none | 100%; 57 / 461 ms | 100%; 127 / 1342 ms | 100%; 274 / 684 ms | 100%; 75 / 2930 ms |
| 10 ms | 18.4% (16.4%); 452 / 933 ms | 71.6% (69.0%); 1401 / 2564 ms | 46.7% (43.7%); 765 / 1110 ms | 12.4% (10.4%); 85 / 4390 ms |
| **20 ms** | **9.0% (7.0%); 240 / 696 ms** | **50.2% (47.3%); 890 / 2164 ms** | **32.6% (29.7%); 639 / 1016 ms** | **12.2% (10.3%); 97 / 3887 ms** |
| 30 ms | 6.9% (4.9%); 140 / 611 ms | 35.9% (33.2%); 551 / 1874 ms | 21.8% (18.8%); 542 / 912 ms | 11.9% (9.9%); 113 / 3472 ms |
| 50 ms | 5.6% (3.3%); 131 / 575 ms | 25.4% (22.1%); 288 / 1553 ms | 17.4% (14.5%); 452 / 831 ms | 11.6% (9.5%); 139 / 2942 ms |
| 20 ms, client 64 B | 2.2% (0.2%); 225 / 682 ms | 6.8% (4.0%); 896 / 2215 ms | 4.0% (1.0%); 638 / 987 ms | 8.3% (6.2%); 97 / 3960 ms |

*What this shows.*

- **On the calm profiles and the LAN, hiding does not depend on the
  tick; on the spiky profiles it does, and 50 ms beats 20 ms.** Without
  delay spikes, from 10 to 50 ms the share of keys exposed is the same to
  within half a point. With netsim's spikes left in, a longer tick both
  hides more and echoes sooner: on the train as defined, 50 ms exposes
  25% of keys with a 288 ms median echo, 20 ms exposes 50% at 890 ms. On
  the LTE trace, 50 ms brings the 95th-percentile echo back to what it is
  without chaff (2.94 s), where 20 ms adds about a second. Which result
  holds on a real path depends on whether netsim's per-packet spike model
  is right (below), and that is not settled. On the calm profiles what
  is left is structural: the first key of each run of typing (about 2% of
  keys with this typist, one in 40 being followed by a pause longer than
  the linger), and keys that pile up unacknowledged until a datagram is
  over the floor (the "by size" column: under 2% on the calm profiles,
  10% on the LTE trace, whose outages hold keys for seconds).
- **The server must chaff.** With the client alone chaffing, its own
  direction exposes 2–5% of keys, but the server's echoes expose all of
  them (§9.1.2).
- **Latency grows with the tick, cost shrinks with it.** Chaff adds a key's
  wait for the client's tick and its echo's wait for the server's: about
  `T` to the median echo, a little more on paths where SSP's frame
  interval also binds.

*Why 20 ms.* On the calm profiles hiding is the same at
every candidate, so there the choice is latency against bytes. 20 ms is SSP's own minimum frame interval, the
50 Hz cap [P §2.3 fn. 1], so a chaffing end never sends faster than SSP is
already allowed to send data, and it is OpenSSH's default. It adds about
20–30 ms to the median echo, which prediction (D12) hides for the keys it
can show. 10 ms saves 2–14 ms of that for twice the datagrams. 30 ms saves
a third of the datagrams for 6–15 ms more on every key, and 50 ms makes a
LAN echo 72 ms, on top of whatever the path adds, for the keys prediction
cannot show. The cost, about 5 000
datagrams and 410 kB a minute both ways while typing (7 kB/s, 55 kbit/s),
is paid only while typing: an idle session sends no chaff
(`TestAnIdleSessionSendsNoChaff`). If netsim's spike model is right, this
reasoning is wrong for spiky paths, where 50 ms dominates 20 ms on both
hiding and latency. Dan closed O10 on 2026-11-15 at 20 ms all the same:
whether the spike model is right is a measurement still to make, not a
reason to hold the decision, and the 64-byte client chaff size (below)
takes away most of what the spiky profiles exposed by size.

*What the measurement does not settle.*

- **netsim's delay spikes are drawn per packet.** On the as-defined
  `hotel-wifi`, `train` and `hsr` profiles, chaff made keys much later
  and exposed more of them by size (the second table). Each profile delays a share of packets, and its links are FIFO, so every
  packet behind a delayed one waits too: a sender of six times the packets
  meets six times the spikes. That fits a packet's own losses; it does not
  fit bufferbloat, a queue that fills over time whoever sends. The "calm"
  rows above are those profiles with their spikes removed and everything
  else kept (`netsim.Link.Params`). That the per-packet model is an
  artefact is a hypothesis, not a measurement. Two things would settle
  it: a time-based spike model in netsim (a spike delays whatever is in
  the queue while it lasts, not a share of packets), and a black-box
  check on a real lossy path (listed in Review notes). Until one has, the
  per-packet model is unconfirmed; the tick stays 20 ms regardless (O10,
  closed by Dan on 2026-11-15).
- **The client's chaff size is 64** [D: Dan's decision of 2026-11-15,
  made from the measured train profile]. While chaffing, every client
  datagram, chaff and keystroke alike, is padded to at least 64 bytes of
  sealed plaintext, as the server's already are. On the `train` profile as
  defined, where nearly all exposure is by size, it cut the keys exposed
  by size from 50% to 7% (hsr 33 → 4%) at the same latency, for 35% more
  client bytes while typing; on the calm profiles it cut less (train calm
  1.9 → 1.3%, lte 10.3 → 6.2%). It costs nothing when idle, since an idle
  client does not chaff. When not chaffing the client's floor stays 40
  (§9.2). The tick stays 20 ms, and whether the per-packet spike model
  holds is still a measurement to make (above), not a reason to hold the
  size. The knob is `chaffing.size` (`clientChaffSize`), and the
  measurement now keeps rows at the smaller sizes for comparison
  (`client 40 B`, `client 48 B`); the 64 B row in the table above was
  measured as `client 64 B` before the default changed.

### 9.2 Compression padding and dictionary (D24, O12)

**Decision** (Dan's, which closes O12 as D24 asks the spec to [D]; the
evidence is [M S5 padding.md]):

- **No dictionary, ever.** A sender must not compress with a preset
  dictionary or with history shared between instructions; each
  instruction stands alone (§4.1). The acknowledged screen as a dictionary
  is the leakiest variant measured, and static dictionaries gained 0–3%
  [S5 §8]. Encoding `0x02` stays reserved for a codec negotiated in the
  handshake, never for a dictionary.
- **Every datagram is padded**: data, acks, heartbeats and probes alike,
  in both directions. A sender sets P (§3) on every SSP datagram and
  chooses k by the rule below.
- **The padded unit is the sealed plaintext**: what the transport
  encrypts, which is its frame kind byte (`Config.FrameOverhead` =
  `transport.FrameOverhead` = 1) followed by the whole SSP datagram,
  header and trailer included. That is the length an observer sees, less
  a constant: the UDP payload is the sealed plaintext plus the
  transport's 13-byte clear header and 16-byte tag (transport.md). Padding
  the whole of it, not just the diff, keeps the uvarints that grow with
  version numbers (ack, from, to) and the presence of the echo from
  leaking too [M S5 padding.md §2].
- **The rule.** Let *U* be the sealed plaintext length of the datagram
  with P set and k = 0 (so *U* counts the 2-byte trailer). The sender
  sends *T* bytes of sealed plaintext, k = *T* − *U*, where

  ```
  T = min(max(F, Padmé(U)), FrameOverhead + MaxPayload)
  F = 64 on the server (screen frames, echoes, acks, heartbeats to the client)
  F = 40 on the client (input frames, acks, heartbeats to the server)
  ```

  So nothing smaller than F goes out, and everything above F is rounded
  up by Padmé. While an endpoint chaffs (§9.1), F is its chaff size
  instead: 64 at both ends, so the client's 40 applies only when it is
  idle or not typing [D, Dan 2026-11-15; O12 as amended].
- **Padmé** [PURBs]: for a length L ≥ 2, E = ⌊log₂ L⌋, S = ⌊log₂ E⌋ + 1,
  z = E − S, mask = 2^z − 1, and Padmé(L) = (L + mask) with the low z bits
  cleared; Padmé(1) = 1. The padded length's mantissa is then no longer
  than its exponent: L under 8 is unchanged, and the rounding step is 2
  bytes from 8 to 31, 4 to 63, 8 to 127, 16 to 511, 32 to 1023 and 64 to
  2047. It leaks O(log log M) bits about a length up to M (8 bits up to
  64 KiB) for at most 12% overhead. (The paper's stated maximum of
  +11.11% is exceeded by its own Algorithm 1 at 129 → 144, +11.63%
  [M S5 padding.md §2]; "at most 12%" holds.)
- **The cap.** Padding never takes a datagram past the D5 limit. Padmé
  rounds 1153 to 1203 up to 1216, past `FrameOverhead + MaxPayload` =
  1203, so those are padded to exactly 1203 instead; every full fragment
  therefore goes out at the D5 maximum, a 1232-byte UDP payload. `Chunk`
  leaves room for the trailer (§3), so *U* is never over the limit and k is
  never negative.
- **Receivers do not enforce the rule.** They strip any padding §3 step 2
  allows (k bounded, the k bytes all zero, refused before any state
  changes, §8). The rule is the sender's protection of its own user; a
  peer that broke it would gain nothing it could not get by other means.
- **The residual leak is accepted** as `docs/threat-model.md` R1, owned by
  **ssp**: padding blunts the compression oracle, it does not close it.
  An on-path observer who can also put chosen output on the user's screen
  can still push a frame across a Padmé boundary with filler and count
  samples [M S5 padding.md §6]. Padding does nothing for timing; that is
  chaff (O10, §9.1).

**Why these numbers** [M S5 padding.md §1, §3, §4]. Compressed length is
a CRIME/BREACH-class side channel: the AEAD hides content, not length, and
when attacker-influenced output (a log line, a chat message, a web page in
a terminal browser) is compressed together with a secret on the same
screen, the datagram size shows whether a guess matched [S5 §8]. Mosh
1.4.0 compresses every update without padding, so its datagram sizes
follow the compressed length to within a byte [M, mosh-compression.md
§2.3]. S5 compared six policies on its six captured sessions (536 server
frames at 120x40, 331168 raw bytes, flate-6 116561):

| policy (server frames) | bytes vs raw | flate saving kept | wire vs unpadded | distinct sizes, echo frames | leak bits up to 64 KiB |
|---|---|---|---|---|---|
| none (flate-6) | 0.352 | 100% | 1.000 | 13 | 16 |
| multiple of 64 | 0.430 | 88% | 1.178 | 1 | 10 |
| multiple of 16 (WireGuard) | 0.362 | 98% | 1.023 | 3 | 12 |
| Padmé | 0.360 | 99% | 1.020 | 12 | 8 |
| **under 64 → 64, Padmé above** | **0.427** | **88%** | **1.173** | **1** | **8** |
| under 128 → 128, Padmé above | 0.511 | 75% | 1.365 | 1 | 8 |

- **The 64-byte floor is what hides echoes.** 81% of server frames are
  keystroke echoes under 64 bytes, the frames an observer can line up with
  typing. Padmé alone leaves 12 sizes among them; the floor leaves one.
  It costs the same as 64-byte buckets (88% of flate's saving kept against
  88%) but leaks less on large frames (8 bits up to 64 KiB against 10).
  A 128-byte floor costs another 13 points of the saving for 2 more
  frames in 536.
- **Padding large frames is nearly free**: Padmé adds 2324 bytes to the 99
  frames of 64 bytes or more, 2% of the total. Datagram counts move by 4
  of 585 for every padded policy.
- **The client's 16 bytes** were measured on a synthetic typist (three
  seeds, 100 000 events each, at 20, 100 and 300 ms RTT): 16 bytes of
  encoding byte plus input diff covers 99.996% of single keystrokes, and
  at 100 ms RTT costs 1.20x the wire bytes of unpadded input. What
  exceeds it is mostly keys piling up while unacknowledged, and pastes
  (0.16% of frames), which then leak at most 8 bits through Padmé.

**Why 40 on the client.** S5 measured its 16 on the encoding byte plus
the input diff alone. The rule above applies the floor to the whole sealed
plaintext, which adds the frame kind, the SSP header, the instruction's
versions and the trailer: about 24 bytes for a keystroke. A floor of 16
on the sealed plaintext therefore bound only acks and heartbeats, and a
simulated session of 300 keystrokes sent them at three sizes (26, 30 and
36). Dan chose 40, S5's 16 plus that framing, so that a keystroke goes out
at one size, as S5 intended [D]. The same session
(`TestEverySentDatagramFollowsThePaddingRuleInBothDirections`, over a
path that does not chaff) sends every client datagram, keystroke, ack and
heartbeat alike, at exactly 40, and every server echo, ack and heartbeat
at exactly 64. What exceeds 40 (keys piling up while unacknowledged,
pastes) is rounded by Padmé. While typing the client chaffs, and then its
floor is 64 (§9.1.5): one size on the tick grid, chaff included, at the
cost of 35% more client bytes while typing and nothing when idle.

### 9.3 Other hooks

- **Path MTU (O9).** `Config.MaxPayload` is the only size SSP knows. If
  DPLPMTUD raises it later, `Chunk` and `MaxFragments` follow; both ends
  must agree, which the handshake would negotiate.
- **Prediction (D12).** Needs nothing new from SSP: the echo ack and the
  echo-off bit are fields of the screen object (§10.2).

## 10. The objects

### 10.1 The client's object: `userinput.Stream`

The stream is every event the user caused, in order: keystrokes (bytes
for the pty, already encoded for the screen's modes) and window resizes.
Events are numbered from 0; `Len()` is how many were ever appended.

**Diff from `from` to `s`** (requires `from.Len() ≤ s.Len()`):

```
start   uvarint   = from.Len(): the index of the first event below
n       uvarint   = s.Len() − from.Len()
n times:
  kind  u8        0x01 keys | 0x02 resize | others: error
  keys:   len uvarint (1 .. MaxKeyEvent), then len bytes
  resize: cols uvarint (1 .. 65535), rows uvarint (1 .. 65535)
```

**Apply** to receiver `r`, validating all of it before appending anything:
`start == r.Len()` (SSP applies a diff only to the version it was made
from, so anything else is a bug or an attack); `n ≤ MaxDiffEvents`; every
kind known and every field in range and in shortest form; the whole diff
at most `MaxDiffBytes`; no bytes left over. Then append the n events.

**Equal** compares `Len()`: two streams of one session with the same
length hold the same events, because events are only ever appended.

| Constant | Value | Why |
|---|---|---|
| `MaxKeyEvent` | 4096 | `Type` splits longer input into events of at most this, so no single event is unbounded [D]. |
| `MaxPendingInput` | 64 KiB | The client stops reading its terminal while its input not yet **consumed** by the server is this many encoded bytes or more, and resumes below it (flow control, below). A huge paste therefore crosses in pieces at the speed the path and the program allow, and a diff never grows without bound [D]. Window size changes that arrive while reading is stopped are coalesced to the newest and appended when it resumes. |
| `MaxRead` | 16 KiB | The client reads its terminal with a buffer of at most this, and `Type` encodes one read (keys translated for the screen's modes, bracketed-paste markers included) into at most `2 × MaxRead` encoded bytes of events [D]. This is what makes `MaxDiffBytes` derivable. |
| `MaxDiffBytes` | 128 KiB | The most one diff may be. The client checks the condition before each read, so pending input is below `MaxPendingInput` when a read starts, and one read adds at most `2 × MaxRead` = 32 KiB plus at most one coalesced resize (7 bytes) and the diff header (20 bytes): under 96 KiB, so 128 KiB leaves a quarter spare [derived]. The server's `Config.MaxRemoteBytes` is this. |
| `ConsumedStep` | 16 KiB | How far the server's consumed index must move before the server publishes it (below) [D]. |
| `MaxDiffEvents` | 65536 | One more cap, so a diff of a byte per event cannot be costly to validate [D]. |
| `RetainBytes` | 256 KiB | A stream keeps only its newest events up to this many encoded bytes; older ones are counted, not kept. Twice `MaxDiffBytes`, so a diff from the acknowledged version never needs a forgotten event; that would be a bug, and `Diff` panics on it [D]. It also bounds how long typed bytes stay in memory. |

`Since(n)` returns the kept events from index n. The server's `Session`
reads `Since(applied)` after every `RemoteChanged` and advances `applied`
as the pty accepts each event's bytes (a pty write that blocks holds
`applied` where it is). The server writes key events to the pty and
applies resize events through `screen.ClampSize`, `pty.SetSize` and
`Emulator.Resize` (D23), in order (architecture §3.2).

**Input flow control is by consumption, not by ack** [D]. SSP acks a
version when it is received, whether or not the program is reading its
pty, so a client that throttled on acks alone would keep sending while
the program sat on a paste, and the server's stream would run past
`applied` by more than `RetainBytes`. Instead:

- **The server publishes what it has consumed.** The screen object
  carries `Grid.InputConsumed`, a stream index (§10.2). The server's
  `Session` sets it to `applied` whenever the events from the published
  value to `applied` encode to `ConsumedStep` or more, and never
  otherwise. A change to it is a screen change like any other and costs
  one frame. It moves once per 16 KiB of input, so ordinary typing almost
  never moves it on its own, and at a password prompt it adds no
  per-keystroke frame (the D11 rule in §10.2 is kept).
- **The client throttles on it.** Its pending input is the encoded size
  of its own events from `base` to `Len()`, where
  `base = min(Grid.InputConsumed, len(acked))`, `Grid.InputConsumed` is
  from the newest screen it holds, and `len(acked)` is the length of its
  stream at the version the server has acknowledged. Taking the minimum
  means a server that lies about consumption cannot make the client
  build a diff past `MaxDiffBytes` or ask `Diff` for a forgotten event:
  the diff SSP sends starts at `len(acked)` ≥ `base`, so it is no bigger
  than the pending input. (An honest server acks before it consumes, so
  `base` is `InputConsumed`.)
- **The bound that follows.** An honest server's stream is at most
  `MaxPendingInput` + `2 × MaxRead` + `ConsumedStep` + 27 bytes (under
  112 KiB) past `applied`, well inside `RetainBytes`; so is the diff SSP
  carries. When the program stops reading, the client stops reading its
  terminal within one round trip and the paste waits in the user's
  terminal, a bounded stall. When the program reads again, `applied`
  moves, `InputConsumed` follows within `ConsumedStep`, and the client
  resumes: once the server has consumed everything, `base` is within
  16 KiB of the client's `Len()`, below `MaxPendingInput`, so the client
  cannot stay stopped.
- **A client that ignores it** (hostile, D4) gains nothing: the server's
  stream keeps only `RetainBytes`, so its memory is bounded regardless,
  and if `Since(applied)` finds the first kept index above `applied`, the
  `Session` ends the connection with an error wrapping `ssp.ErrProtocol`
  ("input flow control ignored"). It is a peer's fault, never reported as
  a bug of ours, and never skipped silently.

**What the interfaces need** (changes to `internal/ssp` and
`internal/userinput` as they stand): `Endpoint.Acked() (L, uint64)`, a
clone of `sent[acked]` and its version, so `client.Session` can find
`len(acked)` (`Stats.LocalAcked` is only the number); and
`Stream.EncodedSince(n uint64) int`, the encoded size of the events from
index n to `Len()`, which a stream can keep as a running sum since it
already counts encoded bytes for `RetainBytes`.

### 10.2 The server's object: `screen.Grid`

The format of its diff, the allow-list and the bounds are `screen.md`'s.
What SSP needs from it:

- **A bound on one diff.** `screen.md` gives the largest diff the server
  can produce at the D23 size clamp; the client's `Config.MaxRemoteBytes`
  is that, and the server must never produce a bigger one.
- **Latest state only.** `Diff(from)` turns `from` into the receiver
  directly, whatever happened in between [P §2.3].
- **Echo ack** (`Grid.EchoAck`, for prediction, D12): the newest
  input event the program has had for at least **50 ms** [P §3.2]. A
  change to it is a state change and costs a frame about 50 ms after
  typing stops [P §3.2]. With it, `Grid.EchoApplied`: how many events the
  pty had taken when the screen was taken, which never causes a frame of
  its own. `prediction.md` §3.1 has the server's rules for both.
- **Input consumed** (`Grid.InputConsumed`, a `uint64` stream index):
  the input flow control of §10.1. Unlike the echo ack it is maintained
  from slice 1, because the client's reading depends on it. `screen.md`
  does not have this field yet and must add it to the object, its diff
  and its bounds; the client must treat a value above its own stream's
  `Len()` as that `Len()`.
- **Echo-off bit** (`Grid.EchoOff`, D12): `!ECHO && ICANON` on the pty,
  read with `pty.EchoOff`. It is part of the screen, so it is sent like
  any other change, in the same instruction as the screen it belongs to.
- **No echo-ack-only frames while echo is off** (D11): while `EchoOff` is
  set, the server does not advance `EchoAck`, so no version can differ
  from the last only in its echo ack, and SSP has nothing to send. At a
  password prompt the server then sends nothing per keystroke; S6
  measured this at no cost to prediction (129 such frames down to 9 per
  run-set, all at the edges of prompts) (S6 FINDINGS §6). This is the
  server `Session`'s rule, since SSP does not look inside objects.

## 11. Constants

| Constant | Value | Source |
|---|---|---|
| Max SSP datagram | `Config.MaxPayload` = transport.MaxPayload = 1202 | D5; architecture §4 |
| SSP header | 6–27 bytes | §3 [D] |
| `Chunk` | `MaxPayload − 27 − 2` = 1173 | [derived], §3 |
| Instruction header | ≤ 21 bytes | §4 [D] |
| Frame interval | `clamp(SRTT/2, 20 ms, 250 ms)`, 20 ms before a sample | [P §2.3], [P §2.3 fn. 1], [P §4 Fig. 3], D11 |
| Collection, server / client | 8 ms / 0 | [P §2.3, §4], D11 / [M], [S5 §7] |
| Delayed ack | 100 ms | [P §2.3], D11 |
| Heartbeat | 3 s | [P §2.3], [M], D11 |
| RTT estimator | RFC 6298 §2: α 1/8, β 1/4, K 4 | [P §2.2] |
| RTO floor | 50 ms | [P §2.2], D11 |
| `G` | 1 ms | RFC 6298 §2 [D] |
| `MaxAckDelay` in RTO | 100 ms (effective floor 150 ms) | RFC 9002 §6.2.1, D11, [S5 §5] |
| Initial RTO | 1 s | RFC 6298 §2.1 |
| Backoff | doubling, capped at 1 s | RFC 6298 §5.5, D11, [S5 §5] |
| Outage probing | `clamp(silence/8, frame, 1 s)` from 300 ms of silence | D11, [S5 §5] |
| Bogus RTT sample | ≥ 60 s | [D] |
| Timestamp | u32 µs | [D], §3 |
| Compression | raw DEFLATE, level 6, per instruction, stored when not smaller; no dictionary | D24, RFC 1951, [S5 §8], [M]; §9.2 |
| Padding | every datagram; sealed plaintext `min(max(F, Padmé(U)), FrameOverhead + MaxPayload)` | [D] (O12), [PURBs], [M S5 padding.md]; §9.2 |
| Padding floor `F`, server / client | 64 / 40 bytes of sealed plaintext; while chaffing, each side's chaff size (64 / 64) | [D] (O12), [M S5 padding.md §5]; 40 is S5's 16 plus a keystroke's framing (§9.2); 64 while chaffing [D, Dan 2026-11-15] (§9.1.5) |
| `FrameOverhead` | 1 (the transport's frame kind) | transport.md, §9.2 |
| Chaff tick `T` | 20 ms, both ends | [D, Dan 2026-11-15, O10 closed], [M] §9.1.5, equal to the 50 Hz cap [P §2.3 fn. 1] |
| Chaff linger, client / server | uniform 1–2 s after each input / 1 s after each CHAFF frame | [D] §9.1.1, §9.1.2 |
| Chaff size, client / server | 64 / 64 bytes of sealed plaintext | [D, Dan 2026-11-15, from the train profile: by-size exposure 50% → 7% for +35% client bytes while typing] §9.1.1, [M] §9.1.5 |
| `Window` (versions outstanding) | 16 | [D], §6.1 |
| Versions kept, sender / receiver | at most 17 / at most 17, neither evicts | [derived], §6.1, §7.3 |
| Fragment burst | 16 datagrams per frame interval | [D, provisional], §5 |
| Partials / bytes in reassembly | 4 / `MaxPartialBytes = 2 × MaxFragments × Chunk` | [D], [derived], §5 |
| `MaxInstruction` | `MaxRemoteBytes + 21` | [derived] |
| Echo ack delay | 50 ms | [P §3.2] |
| Input: `MaxKeyEvent`, `MaxPendingInput`, `MaxRead`, `MaxDiffBytes`, `MaxDiffEvents`, `RetainBytes`, `ConsumedStep` | 4096, 64 KiB, 16 KiB, 128 KiB, 65536, 256 KiB, 16 KiB | [D], [derived], §10.1 |

## 12. What the tests must show

Network behaviour runs on `internal/netsim` inside `testing/synctest`;
nothing asserts real elapsed time (D18). SSP's tests use plain netsim
sockets as `Datagrams`, so they need no transport.

**Fuzz targets** (each run locally for minutes before it lands, durations
in the commit message):

- `FuzzDatagram`: any input either parses and re-encodes to the same
  bytes, or is rejected; a rejected one changes no endpoint state.
- `FuzzReassembly`: after every fragment of any sequence, reassembly
  holds at most 4 partials and at most `MaxPartialBytes` bytes; it never
  completes an instruction it did not get every byte of, and never
  panics.
- `FuzzDecompress`: output never exceeds the limit; nothing over the limit
  is returned truncated; `decompress(compress(x)) == x` for x within it.
- `FuzzInstruction`: header parsing and §7.3 on a toy object; a rejected
  instruction leaves `held`, `newest` and `RemoteChanged` untouched.
- `userinput.FuzzApply`: a rejected diff leaves the stream as it was;
  `Apply(Diff(from))` on a clone of `from` equals the source.

**Behaviour** (synctest, with netsim's profiles where it says so):

- frames are no closer than the frame interval, and the server's first
  frame after a change waits 8 ms while the client's first key goes at once;
- an ack goes out within 100 ms of new state, or rides on data sooner;
- with the receiver's acks dropped, the sender's identical retransmission
  (same id and bytes) draws an ack within 100 ms, and a multi-fragment
  retransmission draws exactly one;
- an idle endpoint sends exactly one heartbeat per 3 s and no acks of acks;
- the RTO includes the 100 ms ack delay and the retransmit interval
  doubles to 1 s; once 300 ms silent the probe cadence follows
  `clamp(silence/8, frame, 1 s)`;
- after outages of 2, 5 and 8 s on the S5 sweep's path (70 ms RTT, 15 ms
  jitter, a key typed 0.5 s in), the median stall is at most 410 ms, the
  worst `rfc6298-ackdelay` measured [S5 §5]; when the sweep is re-run with
  §6.2's combination, its numbers replace this bound;
- **no wedge from lost acks**: under continuous server output (a new
  screen every frame interval) on a 40 ms path, drop 2, then 20,
  consecutive client datagrams; the client's screen must reach the
  server's newest within 1.5 s of the drops ending (the 1 s retransmit
  cap, a round trip and an ack delay), and the same with the
  directions swapped (continuous typing, server datagrams dropped);
- the sender never has more than `Window` versions outstanding, and the
  receiver never holds more than 17 or forgets one at or above its floor;
- the server sends only the newest screen: intermediate versions set
  within one frame interval are never numbered;
- every keystroke typed during a loss burst or an outage arrives, in
  order, exactly once, on every `netsim.Profiles()` profile;
- a fragmented instruction completes from the fragments of two
  transmissions;
- a full redraw at the D23 clamp, under continuous output, completes on
  the `lte` and `train` profiles, and no transmission sends more than 16
  fragments in one frame interval;
- **input flow control**: paste 1 MB into a server program that does not
  read its pty; the client stops reading with at most `MaxPendingInput`
  plus one read pending, the server's stream never runs more than
  `RetainBytes` past `applied`, and when the program reads, the whole
  paste arrives in order and the client resumes; a client that ignores
  `InputConsumed` ends the connection with `ErrProtocol`;
- a decompression bomb, an oversized `count` and each row of §8's table
  end `Run` with `ErrProtocol`, or are ignored, as the table says;
- every datagram SSP sends is at most `MaxPayload` bytes;
- **chaff** (§9.1): while the user types, every client datagram, SSP or
  CHAFF, leaves on the client's tick grid, one per tick, at 64 bytes of
  sealed plaintext for a single key or chaff, and before the first key and
  after the mode ends its acks and heartbeats go at its floor of 40
  (`TestTheClientPadsTo64WhileItChaffsAnd40WhenNotTyping`); the server, once chaff
  arrives, sends one datagram per tick on its own grid, at 64; a key
  waits at most one tick; the mode ends between 1 and 2 s after the last
  key on the client and 1 s after the last chaff on the server; an idle
  session sends no chaff at all, only heartbeats; an endpoint whose
  `Datagrams` is not a `Chaffer` sends exactly what it did before;
- **padding** (§9.2): Padmé matches hand-worked values, including the
  paper's Table 1; over a simulated session every datagram either side
  sends has P set and exactly the sealed length the rule gives, every
  server echo, ack and heartbeat is 64 bytes, and every full fragment is
  exactly `MaxPayload`; padding never passes the limit for any length; a
  datagram with non-zero padding or a k that reaches into the header is
  refused and changes no state (and `FuzzDatagram` covers padded
  datagrams).

## 13. Review notes

How this revision answers the review of the first draft. Items 1 and 6,
2 and 5, and 3 and 9 raised the same defect twice and share an answer.

1. **(critical) Receiver eviction could wedge a session.** Fixed, by a
   different route from the one proposed. Pinning `held[floor]` and
   `held[newest]` and evicting between them is not enough: the sender's
   `acked` is usually a version between the two (one the receiver acked
   before a newer one arrived), so evicting it drops the next instruction
   and leaves the session depending on the sender still keeping `newest`,
   which the old "forget the oldest" sender bound did not promise. Now
   neither side evicts anything the other may need: the sender stops
   minting at `Window` = 16 outstanding versions and keeps all of them
   (§6.1), so every ack names a kept version; every honest instruction
   has `to − from ≤ 16`, which the receiver enforces (§4, §7.3 step 1);
   and so the receiver holds at most 17 versions without evicting any at
   or above the floor (§7.3). Lost acks now cost at most a retransmit
   interval after the path delivers, since every retransmission draws an
   ack (item 2). §12 adds the two-dropped-datagrams test, in both
   directions. Threat-model R8 ("recovers when the path comes back")
   holds.
2. **Exact retransmissions never drew an ack.** Fixed: §5 step 1 owes an
   ack for any fragment of an id not newer than the newest completed id
   before dropping it, still at most one per 100 ms (§6.4 lists all three
   triggers). §12 adds the dropped-acks test.
3. **Input backpressure followed acks, not consumption.** Fixed in
   §10.1, here rather than in `server.md`: the server publishes
   `Grid.InputConsumed` in steps of 16 KiB, the client throttles on
   `min(InputConsumed, len(acked))`, falling behind is a bounded stall,
   and a client that ignores it ends its connection with `ErrProtocol`
   instead of being "a bug we report". This changes no ack semantics; it
   adds a field to the screen object, which `screen.md` must take up.
4. **O12 deferred in a circle.** Settled in §9.2, as D24 asks: no
   dictionary ever, the residual leak accepted as R1 with **ssp** as
   owner. (This revision said no padding in v1; Dan later decided O12
   with padding on every datagram, a 64- or 40-byte floor and Padmé
   above, from S5's `padding.md`, and §9.2 now says so.) `docs/threat-model.md`
   R1 must be changed to cite §9.2's decision (this revision edits only
   `ssp.md`).
5. Same as 2.
6. **The receiver's 8-version cap evicted the floor.** Fixed with item 1:
   there is no eviction cap; the bound is 17 by construction, which is
   the sender's 16 + 1. Dropping at step 4 now owes an ack (§7.3). §6.1's
   arithmetic is corrected (8 at 40 ms, 9.4 at 2 s), and it now only
   explains why the window is rarely reached.
7. **The partial byte bound was checked only when a partial started.**
   Fixed: §3 parsing requires non-final chunks to be exactly `Chunk` and
   the final one 1 to `Chunk` bytes (protocol error otherwise); §5 step 4
   charges every stored chunk and evicts other partials until it fits;
   the bound is `MaxPartialBytes = 2 × MaxFragments × Chunk`, which one
   partial can never fill alone.
8. **Large instructions could livelock.** Fixed: an unacknowledged
   multi-fragment instruction is retransmitted under its own id, never
   superseded (§6.3 `mayMint`), so holes fill across transmissions; and a
   transmission is paced at 16 fragments per frame interval (§5). The 16
   is a provisional guess, held by the new §12 test at the D23 clamp on
   `lte` and `train`; it should be measured in netsim before 1.0.
9. Same as 3.
10. **The client could not compute the throttle.** Fixed in §10.1: the
    interfaces need `Endpoint.Acked() (L, uint64)` and
    `Stream.EncodedSince(n) int`, and `MaxRead` = 16 KiB with a 2x
    encoding allowance makes `MaxDiffBytes` derived (under 96 KiB of
    128 KiB). `internal/ssp/ssp.go` and `internal/userinput/userinput.go`
    must grow these when slice 1 implements them.
11. **The outage evidence was for another variant.** Conceded, not
    re-run in this revision: §6.2 now says plainly that the cited numbers
    are `o7-resend-prop`, which also lacked backoff and resent on receive,
    and that the specified combination is unmeasured. §12 asserts a
    post-outage stall bound taken from what `rfc6298-ackdelay` measured,
    and the S5 sweep must be re-run with §6.2's combination before the
    probe rule is final.
12. **Other documents contradict this one.** `ssp.md`'s rules are the
    ones that hold (they scale with `MaxRemoteBytes`, where the
    threat model's 512 / 16 / 1 MiB came from S5's fixed toy screen, and
    an authenticated malformed fragment or oversized decode fails closed,
    §8). This revision may edit only `ssp.md`, so the same commit that
    lands it must also change: `docs/threat-model.md` §4.6 (fragments,
    partials and bytes as in §5 here; bad fragments and oversized decodes
    end the connection with `ErrProtocol`, not "dropped"), its constants
    table row "Fragments per instruction / instructions in reassembly /
    bytes held", its test row "out-of-range and inconsistent fragments
    are dropped", and R1 (item 4); the `Config.MaxRemoteBytes` comment in
    `internal/ssp/ssp.go` ("drops the instruction" becomes "ends `Run`
    with `ErrProtocol`"); and PLAN O12, which §9.2 closes for v1 as D24
    intended (D24 itself needs no change).

### Chaff slice (2026-11-14)

13. **Chaff measured against a per-packet spike model.** §9.1.5 found
    that netsim's `Spikes`, drawn per packet on FIFO links, punish any
    higher send rate, which made chaff look far worse on `hotel-wifi`,
    `train` and `hsr` than on the trace-driven and spike-free profiles.
    The tick was chosen on the latter ("calm" rows), with the as-defined
    numbers kept. Open: a time-based spike model in netsim, and a
    black-box run of chaff on a real lossy path, to say which is right.

