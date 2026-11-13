# SSP timing: our understanding (spike S5)

This is the spike's working specification of the State Synchronization
Protocol's *transport and timing*, written in our own words from the Mosh
paper (Winstein & Balakrishnan, USENIX ATC 2012, cited as [P §x]), RFC 6298,
and black-box measurements of the installed `mosh` 1.4.0 binaries (cited as
[M], method in FINDINGS.md §4). Where neither gives a value we chose one and
say so ([D] = derived/decided by us). No Mosh source code was read.

It is a spike document: `docs/spec/ssp.md` should be written later from this
plus Dan's decisions on the open questions in FINDINGS.md.

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
  already holds *b*, nothing happens. This is why SSP needs no replay cache
  for correctness [P §2.2] (mosey still keeps one for security, O1).
* The diff is defined by the object, not by SSP. For input it carries every
  keystroke between *a* and *b*; for the screen it is whatever turns screen
  *a* into screen *b*, and intermediate screens are skipped [P §2.3].

## 2. Datagram layer

* Each datagram carries a strictly increasing sequence number (also the AEAD
  nonce), a 16-bit millisecond **timestamp**, and an optional 16-bit
  **timestamp reply** [P §2.2]. Widths are [D].
* **Timestamp reply** = the most recent timestamp received from the peer,
  advanced by the time we held it before replying, so delayed acks do not
  inflate the RTT sample [P §2.2 change 2]. We send each reply at most once
  and drop replies we held for more than 1 s [D].
* **RTT estimation** is RFC 6298 §2 (SRTT, RTTVAR, alpha 1/8, beta 1/4,
  K = 4) on those samples. Every datagram has a unique sequence number, so
  Karn's ambiguity does not arise [P §2.2 change 1].
* **RTO** = SRTT + max(G, 4·RTTVAR), floored at **50 ms** instead of RFC
  6298's 1 s [P §2.2 change 3]. Ceiling: see §4.
* **Roaming**: the server sets its send target to the source address of any
  *authentic* datagram whose sequence number is the highest seen so far
  [P §2.2]. Nothing else is needed on the client.
* **Size**: a datagram's UDP payload is at most 1280 bytes (PLAN D5). Larger
  instructions are split into fragments; losing one fragment loses the
  instruction [D].

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
     closely go in one frame [P §2.3, §4]. Whether the **client** applies
     this or the frame interval to keystrokes is not stated by the paper:
     see §6 (black-box measurement) and the client rules there.
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
in FINDINGS). Diffing optimistically from the last *sent* version saves
bytes when output is continuous; the receiver then has to wait for a
retransmit if that version was lost. The paper says only that the
instruction names its source and target [P §2.3]; the choice is [D] and
measured in FINDINGS (O9).

**Throwaway.** Each instruction tells the receiver the oldest version the
sender will ever diff from again (`acked` in the default policy), so the
receiver can discard older ones. Needed because the receiver may already
be past `acked` when a diff from `acked` arrives [D].

## 4. Retransmission backoff [D, M]

The paper names RFC 6298 [P §2.2] and does not say whether SSP doubles the
RTO on expiry (RFC 6298 §5.5) or what the ceiling is. Black-box timings of
mosh 1.4.0 are in FINDINGS §4. The spike's **baseline** doubles the RTO on
each expiry with no new ack, capped at 1 s [D], and resets the backoff when
an ack advances `acked`. Variants are in FINDINGS (O7).

## 5. Receiver

* On an authentic datagram: update RTT from its timestamp reply, store its
  timestamp for our next reply, process its ack (advance `acked`, release
  versions below it), then the instruction.
* If the receiver holds the source version, apply the diff, store the new
  version, release versions below `throwaway`, and schedule an ack within
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
| RTO ceiling, backoff | 1 s, doubling | [D]; compare [M] in FINDINGS |
| Echo-ack delay | 50 ms | [P §3.2] |
| Max UDP payload | 1280 B | PLAN D5 |
| Timestamp width | 16 bit ms | [D] |
