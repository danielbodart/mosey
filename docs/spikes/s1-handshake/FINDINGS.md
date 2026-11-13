# S1 Handshake: findings

Spike for open question **O1**. Branch `spike/s1-handshake`, with code in
`spikes/s1-handshake/` (a record, not production code). Date 2026-11-13, on
dan-desktop (i9-12900K, 24 threads), Go 1.27.3 and ProVerif 2.05.

## TL;DR

**Recommendation: variant B1.** SSH delivers a single-use credential. It holds a
session id, a 32-byte PSK, and a fresh **X-Wing** (ML-KEM-768 + X25519) public
key that the server makes for this one handshake. The client encapsulates to that
key in msg1. The PSK authenticates both sides, and the ephemeral KEM gives
forward secrecy. There are **no long-term keys and no signatures**:

```
<- s                      (s = per-handshake X-Wing key, delivered over SSH)
...
-> psk, skem, {hello_c}   msg1: 1200 bytes  (fits the 1232-byte IPv6-safe payload)
<- {hello_s}              msg2:   54 bytes  (about 1/22 of msg1: no amplification)
```

After the handshake comes a transport with these parts:

* an explicit counter
* a receiver index that the receiver chooses
* an RFC 6479 replay window
* receive state that changes only once a packet authenticates
* roaming that follows the newest authenticated packet
* in-band hybrid rekeying (X-Wing again, chained through a one-way root key)

Resume (D8) works like this. A new SSH login gets a fresh B1 credential over an
authenticated local unix socket.

Why B1 wins:

* **It is the simplest secure design under D6.** SSH is already the root of trust
  for both ends. In A the signing keys would themselves be pinned over SSH. The
  signatures would add a round trip, CPU time and attack surface for denial of
  service, but no trust that SSH doesn't already provide.
* **Authentication is post-quantum for free.** The PSK is symmetric. A's Ed25519
  is not post-quantum, and ML-DSA-65 (public key 1952 B plus signature 3309 B)
  doesn't fit in a datagram.
* **ProVerif checks it.** All the properties we targeted hold (§3). B1 also keeps
  server authentication and the secrecy of client data **even if the PSK leaks
  before the handshake**. B2, like any pure-PSK design, loses everything in that
  case.
* **It is small and cheap.** It is about 1k lines, using the standard library
  plus `x/crypto/chacha20poly1305`. Each message fits in one datagram. The server
  spends about 0.14 ms of CPU per handshake, and it rejects garbage in about
  1.5 µs with a WireGuard-style `mac1`.
* **QUIC (quic-go) loses, as O1 predicted.** CUBIC and the pacer are hard-wired,
  and they also gate RFC 9221 DATAGRAM frames. QUIC would also mean 35.7k lines
  of dependency, a binary 2.3x the size, and 4.7x the handshake bytes.

## 1. What was built

| File | What |
|---|---|
| `hs/sym.go` | Noise `SymmetricState` (MixHash/MixKey/EncryptAndHash/Split) on `crypto/hkdf`, SHA-256 and ChaCha20-Poly1305. The KEM is `crypto/hpke` `MLKEM768X25519()` (X-Wing), used export-only as a plain KEM, with the transcript hash as HPKE `info`. **No primitive is implemented here.** |
| `hs/variant_b.go` | B1 (the server's KEM key goes over SSH) and B2 (the client sends its KEM key, i.e. Noise `NNpsk0` + HFS-style). Includes single-use credentials, a msg2 retransmission cache and the `mac1` pre-filter. |
| `hs/variant_a.go` | A: SIGMA-I over ephemeral X-Wing, with Ed25519 identities pinned over SSH |
| `hs/transport.go` | Data packets, receiver indices, roaming, in-band hybrid rekey with key confirmation, and a grace period for the previous keys |
| `hs/replay.go` | RFC 6479 ring-of-blocks anti-replay window (1984 counters), with a pure `check` and a mutating `commit` |
| `hs/resume.go` | D8 resume: unix socket in a 0700 directory, `SO_PEERCRED` uid check, fresh credentials per attach |
| `hs/*_test.go` | Tests: functional, tamper with every byte, replay, roaming, rekey, resume, latency (synctest). Also benchmarks and 9 fuzz targets. |
| `cmd/bdemo` | B1/B2 over real loopback UDP, run the same way as `quiccmp` for a like-for-like comparison |
| `quiccmp/` | quic-go v0.65.0 with RFC 9221 datagrams. It has its own `go.mod`, so the main spike has no dependencies beyond the standard library and x/crypto. |
| `proverif/` | Models of B1, B2 and A, plus compromise and sanity variants. `run.sh` writes `results.txt`. |
| `fuzz-log.txt` | Raw output of the fuzz campaign |

`go test ./hs` passes 14 tests.

### 1.1 Wire format

```
B msg1:  01 | ver | sender_idx(4) | X-Wing enc(1120) | AEAD(hello) | mac1(16)
B msg2:  02 | ver | sender_idx(4) | receiver_idx(4)  | AEAD(hello)
data:    04 | receiver_idx(4) | counter(8) | AEAD(frame_kind | body)     29 bytes overhead
reserved 05 NAT-traversal probe (O6); 06 cookie reply (only A needs it)
```

* **Data header and nonce.** The 13-byte data header is the AEAD's associated
  data, and the counter is the nonce. Each direction has its own key. Counters
  live only in memory (D8). A process that loses its counters also loses its
  keys, so a (key, nonce) pair can never repeat.
* **Receiver index.** The receiver picks it, as in WireGuard. It does three
  things:
  * It routes a packet before its source address is trusted. Roaming, NAT
    rebinding and O6 all need this.
  * It lets one socket serve many sessions.
  * It **changes on every rekey**, so a passive observer can't use it to link
    one epoch to the next.
* **Hello.** `hello` is encrypted. It carries the version, flags and the D15
  **channel types** (`terminal`, `agent@mosey`, …), and the responder answers
  with the types both sides support. The parser is strict. It rejects trailing
  bytes, duplicates, more than 16 types, names over 32 bytes, and anything
  outside `[a-z0-9.@-]`. Fuzzing checks that everything it accepts survives a
  round trip unchanged. The transport ignores unknown frame kinds, so later
  versions can add new ones.

### 1.2 Receive path (the lesson from the flynn/noise advisory)

`Session.Open` works in this order:

1. Parse the header.
2. Look up the receiver index.
3. Call `window.check(ctr)`, which is pure.
4. Open the AEAD.
5. **Only then** run `window.commit`, update the peer address, promote keys
   and handle rekey frames.

The handshake code works on a copy of the symmetric state and commits only after
the whole message authenticates, so a failed message never changes state. Tests
check this (`TestForgedPacketDoesNotAdvanceWindow`,
`TestBWrongCredentialsLeaveStateUntouched`, `TestBTamperEveryByte`), and so do
fuzz invariants (`FuzzSessionOpen`, `FuzzBServerInit*`).

### 1.3 Rekey

Either side may start a rekey after `RekeyAfterTime` (120 s in the spike, the
WireGuard value) or after `RekeyAfterMessages`. The rekey runs inside the
encrypted channel:

```
I -> R  REKEY_INIT  { new_idx_I, fresh X-Wing pk }          1250 bytes on the wire
R -> I  REKEY_RESP  { new_idx_R, enc }                      1154 bytes
keys', root' = HKDF(salt = root, ikm = ss, info = H(root, idx_I, pk) | enc | idx_R)
```

* **Switching keys.** The responder installs the new keys for receiving only.
  It switches when the first packet under them authenticates, which is key
  confirmation as in WireGuard. The initiator switches as soon as RESP arrives.
* **Old keys.** They can still decrypt for `KeepPrevFor` (10 s), and then they
  are wiped.
* **Chained root.** The root key is chained one-way. Compromising the current
  state reveals no earlier epoch, which gives forward secrecy within a session.
  The fresh KEM heals a compromise once the attacker goes passive
  (post-compromise security).
* **Collisions and losses.** If both sides start a rekey at once, the client's
  INIT wins. If a RESP is lost and the same INIT arrives again, the responder
  resends RESP from its cache. A different INIT is computed afresh from the
  unchanged root.
* **Tests and cost.** `TestRekeyByTime` and `TestRekeyCollisionAndLoss` cover
  this. A full rekey round trip costs about 0.35 to 0.55 ms of CPU.

### 1.4 Resume (D8)

`TestResumeOverLocalSocket` covers this. The steps:

1. A new SSH login runs `mosey-server attach`.
2. That process connects to the running network process at
   `$XDG_RUNTIME_DIR/mosey/…/session.sock`. The directory must be mode 0700 and
   owned by our user.
3. The network process checks that the `SO_PEERCRED` uid matches its own. A
   connection from a different uid is refused (tested).
4. It mints a **brand-new** single-use B1 credential and returns it over stdout
   and SSH.
5. The client runs an ordinary handshake, and the new transport attaches to the
   existing pty and emulator session.

No transport or crypto state ever touches disk. Each client's transport is
independent, so several clients can attach at once (O5).

### 1.5 Roaming

The peer address follows the source of the **newest** (highest-counter)
authenticated packet of the current epoch.

* A reordered old packet from the previous address doesn't move it back.
* A packet replayed from a third address is rejected before it can move it
  (`TestRoaming`).
* As in WireGuard, an attacker on the path can race a genuine packet from a
  spoofed source. The peer address then stays wrong until the next genuine
  packet arrives. That is denial of service by an on-path attacker only, never a
  loss of confidentiality.

## 2. Measurements

Method:

* **CPU per step.** `TestCostBreakdown` takes the median of 400 runs on one
  core. I ran it 3 times, and the runs agreed within 2%.
* **Loopback comparison.** `cmd/bdemo` and `quiccmp` each ran 500 handshakes
  over loopback UDP, with one echoed datagram after each, and measured CPU for
  the whole process with `getrusage`.
* **Round trips.** `TestHandshakeLatency` runs under `testing/synctest` virtual
  time with a 50 ms one-way delay. These are exact counts of protocol round
  trips, not network measurements.
* **Machine load.** Other mosey spikes were running on the machine at the same
  time (load average 11 to 30 on 24 threads). Early runs that overlapped my own
  fuzzer were up to 2x slower. Treat the absolute numbers as approximate; the
  ratios are more reliable.

### 2.1 Size and round trips

| | msg1 | msg2 | msg3 | server can send | client can send | server gets first client data |
|---|---|---|---|---|---|---|
| **B1** | **1200** | **54** | n/a | 0.5 RTT | 1 RTT | 1.5 RTT |
| B2 | 1296 (over 1280) | 1174 | n/a | 0.5 RTT | 1 RTT | 1.5 RTT |
| A (SIGMA-I) | 1222 | 1270 | 146 | **1.5 RTT** | 1 RTT | 1.5 RTT |
| QUIC (quic-go, TLS 1.3, X25519MLKEM768), handshake + 1 echoed datagram | 3892 B in 5.0 datagrams c→s | 2186 B in 4.0 datagrams s→c | | 0.5 RTT | 1 RTT | 1.5 RTT |
| rekey | INIT 1250 | RESP 1154 | | | | |

* **Hello size.** The sizes assume a hello listing 3 channel types. B2 fits D5's
  1280 bytes only with a smaller hello, and A's msg2 only just fits.
* **IPv6.** **Only B1's handshake fits in 1232 bytes, the largest UDP payload
  every IPv6 path is guaranteed to carry** (1280 − 40 − 8). The rekey INIT is
  1250 bytes, so it fits 1280 but not 1232 (decision D-2).
* **Compared with Mosh.** Mosh has no UDP handshake at all: its key arrives over
  SSH (paper and documentation). B1 adds 1 RTT before the first keystroke can go
  out, and that RTT hides behind the several RTTs the SSH bootstrap already
  takes.

### 2.2 CPU (median µs, single core)

| step | B1 | B2 | A |
|---|---|---|---|
| server: mint credential (during the SSH bootstrap) | 68 | 0.2 | n/a |
| client: build msg1 | 103 | 69 | 65 |
| server: msg1 → msg2 | 76 | 106 | 115 (**including for spoofed msg1**) |
| client: process msg2 (→ msg3) | 1.8 | 71 | 119 |
| server: process msg3 | n/a | n/a | 34 |
| **server total** | **144** | **106** | **149** |
| **client total** | **105** | **140** | **184** |
| server: reject a garbage msg1 | **1.5** (80 without `mac1`) | 1.6 | 115 |

For the whole process, both ends, over 500 handshakes, the CPU per handshake was
0.47 ms for B1, 0.40 ms for B2 and 1.22 ms for quic-go. Sealing and opening one
1 KiB transport packet takes 2.9 µs (about 350 MB/s). That code is unoptimised
and makes 7 allocations per packet.

### 2.3 Comparison with quic-go

| | mosey B1 | quic-go v0.65.0 + RFC 9221 |
|---|---|---|
| Non-std packages linked | 5 | 28 |
| Library source (non-test lines) | ~1.0k (B), ~1.2k with A | 35.7k |
| Stripped demo binary | 2.8 MB | 6.3 MB |
| Bytes for a handshake plus one echoed datagram | 1217 c→s + 85 s→c, in 2+2 datagrams | 3892 c→s + 2186 s→c, in 5+4 datagrams |
| CPU per handshake (whole process) | 0.47 ms | 1.22 ms |
| Congestion control | None: SSP owns the timing (D11) | Hard-wired CUBIC and pacer (`internal/congestion`, created unconditionally). `SendMode()` gates **all** sending on `CanSend` and `HasPacingBudget`, DATAGRAM frames included. No `Config` option turns it off, so disabling it means a fork. |
| Datagram queue | Ours | Fixed internal send queue of 32 packets, and anything over that is dropped |
| Server identity | PSK + KEM key over SSH | X.509 certificate, which would need pinning over SSH anyway |

**Verdict.** quic-go comes with streams, flow control, congestion control, TLS
and certificates. None of that is wanted under SSP, and disabling congestion
control would mean forking 35k lines.

## 3. Formal model (ProVerif 2.05, symbolic)

The models are in `spikes/s1-handshake/proverif/`. `./run.sh` runs all of them
and writes `results.txt`. Each model takes 1 to 3 s.

Assumptions:

* **Sessions.** The number of sessions is unbounded.
* **KEM.** The KEM is an ideal IND-CCA KEM, bound to the HPKE `info`. The claim
  that the hybrid is secure if either ML-KEM-768 or X25519 holds comes from the
  X-Wing combiner's own proof, not from these models.
* **SSH delivery in B.** SSH delivery is modelled as fresh names the attacker
  never learns.
* **SSH delivery in A.** The pinned keys and the session id are **chosen by the
  attacker** for each run. That puts unknown-key-share and misbinding attacks in
  scope.

| Model | Scenario | Result |
|---|---|---|
| `b1` | The PSK leaks **after** the session (phase 1) | Client authentication with **replay protection** (injective agreement on msg1): holds. Server authentication and agreement on (sid, transcript, keys), i.e. no misbinding: holds. Secrecy of data in both directions (**forward secrecy**): holds. |
| `b1_psk_leak` | The PSK leaks **before** the handshake | **Server authentication** holds, and so does **the secrecy of client→server data**, because only the server's private key (skS) can decapsulate. Client authentication and the secrecy of server→client data fail, as expected. |
| `b1_skS_leak` | Sanity check: the PSK **and** the server's per-handshake private key (skS) both leak later | Secrecy fails. **Deleting skS after msg1 is what provides forward secrecy.** |
| `b2` | The PSK leaks after the session | Everything holds. |
| `b2_psk_leak` | The PSK leaks before the handshake | **Everything fails**: a full man-in-the-middle. |
| `a` | Both signing keys leak afterwards | Client authentication (at key confirmation), server authentication, secrecy and **no misbinding**, even with pins chosen by the attacker: all hold. |
| `a_kci` | The client's signing key leaks at the start (**KCI**) | The client still authenticates the server, and its data stays secret. The server side fails, but trivially, because the attacker *is* the client. |
| `a_nomac` | Sanity check: the responder's identity goes in clear **and** msg2 is left out of the signed transcript | **The model finds a misbinding attack**, which shows it can detect one. |

A note on A. In SIGMA-I the initiator finishes before the responder, so the
client has only authenticated the server once its keys are confirmed by the
first server packet. My first model placed that check at msg3, and it failed for
exactly that reason. Tamarin 1.12 is available through nix but I didn't need it.
It, together with the existing PQNoise Tamarin models, remains the route to a
formal model before 1.0 (PLAN §6.5).

### 3.1 Properties argued, not modelled

* **KCI in B.** B has no long-term keys. A credential is consumed by the first
  valid msg1 and then wiped. If one leaks before it is used, the attacker can
  pose as the client (B1) or as either side (B2). If it leaks after use, it is
  worthless. The long-term secrets all belong to SSH.
* **Replay.**
  * msg1 credentials are single-use, so a replayed msg1 is refused, and `b1`
    proves injective agreement.
  * An identical retransmitted msg1 gets the cached msg2 and creates no new
    state.
  * The RFC 6479 window was checked against a reference model, with 200k random
    operations and 66M fuzz runs.
  * Rekey frames inherit the replay protection of the current keys.
* **Rekey FS and PCS.** Forward secrecy comes from the one-way HKDF chain plus
  wiping keys after `KeepPrevFor`. Post-compromise security only holds once the
  attacker goes passive. That is inherent to any in-band rekey. Full recovery
  means logging in over SSH again (resume).
* **Idle sessions.** While the laptop sleeps, the last epoch's keys stay in
  memory. I propose **rekey on quiet**: after N seconds without application
  traffic, rekey once, so that the keys held in memory have only protected
  rekey frames. Not implemented (D-3).
* **Misbinding in B.** The transcript binds the protocol name, the sid, the KEM
  key (B1), both indices and every byte of both messages. Each credential
  belongs to one session.
* **Denial of service.**
  * In B, `mac1` is checked before any KEM work: 1.5 µs against 80 µs without
    it (measured). msg2 is 1/22 the size of msg1, so the server can't be used
    for a reflection attack.
  * In A, msg1 is unauthenticated, so each spoofed msg1 costs the server
    115 µs and creates state. A would need WireGuard-style cookies (packet
    type `0x06`, not implemented). In the spike, a spoofed msg1 can even
    overwrite the one pending handshake.

## 4. Noise: a standard pattern or our own?

* **B is already a Noise pattern in all but name.** It uses Noise's
  `SymmetricState` plus a KEM token, as PQNoise and Noise-HFS do.
  * B2 is exactly `NNpsk0` with HFS-style `e1`/`ekem1` tokens, using X-Wing.
  * B1 has the shape of `pqNK` with `psk0`. The responder's "static" key is
    really a per-handshake key delivered over SSH, and that is the only
    non-standard part.
* **No library would help.** No Go Noise library supports KEMs or HFS.
  flynn/noise has no post-quantum support and is the subject of PLAN §7's
  advisory.
* **Recommendation.** Specify the handshake **in Noise pattern notation and
  naming** in `docs/spec/`, so that reviewers and the Noise and PQNoise tooling
  can analyse it. Implement it on the standard library, as the spike does. That
  gives the auditability of a standard pattern without the dependency.

## 5. A against B: do we need signatures when SSH vouches?

**No.** Under D6 the only way either side learns the other's long-term key is
through SSH. So A's signatures prove possession of a key whose binding SSH
already established, which is the same root of trust as the PSK. What A buys,
and why it doesn't help here:

* **Asymmetric authentication.** Irrelevant: the server runs the user's shell
  anyway.
* **KCI resistance.** B has no long-term keys to compromise in the first place.
* **Reconnecting without SSH.** That conflicts with D6 and D8 and would put
  identity keys on disk.

What A costs:

* the server's first send moves from 0.5 RTT to 1.5 RTT
* an unauthenticated msg1, which needs cookies to resist denial of service
* about 1.3 to 1.75x the CPU
* signatures that aren't post-quantum
* a msg2 that is right at the size limit
* more code to audit

## 6. Hooks for later work

* **O6 (NAT traversal).** Sessions are identified by receiver index, not by
  address. msg1 is idempotent, so the client can send it to several candidate
  addresses at once, with the candidates exchanged over SSH. The server can send
  `0x05` probes to the client's address as reported by SSH, to open its own NAT.
  Before the handshake the probes are MAC'd with the credential. After it they
  are ordinary transport frames.
* **D15 (channels).** Channel types are negotiated in `hello`. Port forwarding
  needs only a new channel-type name.
* **O2/S3 (agent forwarding, and Dan's provenance chain).** The final transcript
  hash `h` is a good channel binding, mosey's equivalent of SSH's exchange hash.
  B has no server signing key, so a statement in the style of `session-bind`
  needs one of two things. Either the SSH bootstrap's own bind is relayed over
  the SSH channel alongside the credential, or quoin gets an extension. Nothing
  in B1 rules out either option, and that question belongs to S3. A signed
  "remote provenance envelope" on the `agent@mosey` channel would be an
  extension at the channel level.

## 7. Fuzzing

`go test -fuzz` ran 9 targets, 200 s each, with `-parallel 8`, between 18:35:05
and 19:05:15. That is **30.2 min** of wall time, with **0 failures**. The raw
output is in `spikes/s1-handshake/fuzz-log.txt`.

| Target | Invariant | Execs | New corpus |
|---|---|---|---|
| FuzzParseHello | anything accepted survives a round trip unchanged | 46.5M | 42 |
| FuzzParseBCredentials | anything accepted survives a round trip unchanged | 27.9M | 4 |
| FuzzBServerInitB1 | a failure doesn't consume the credential; only the genuine msg1 succeeds | 24.1M | 2 |
| FuzzBServerInitB1FixMAC | same, with `mac1` recomputed so mutations reach the KEM, AEAD and parser | 11.0M | 11 |
| FuzzBServerInitB2FixMAC | same, for B2 | 13.5M | 7 |
| FuzzBClientResp | no msg2 from a server without the PSK is ever accepted | 37.0M | 0 |
| FuzzAHandshake | parsers for msg1, msg2 and msg3; a msg2 or msg3 not bound to this handshake is never accepted | 46.3M | 28 |
| FuzzSessionOpen | a rejected packet changes neither the window nor the peer; no forgery is accepted | 70.0M | 1 |
| FuzzReplayWindow | matches a map-based reference implementation | 66.1M | 42 |

Thirty minutes is only a smoke test. Production needs continuous fuzzing
(PLAN §6.5).

## Challenges to locked decisions

* **D5 (1280-byte payloads).** On the public internet (D4), IPv6 guarantees
  only 1280-byte packets, including the 48 bytes of IPv6 and UDP headers. That
  leaves 1232 bytes of UDP payload. A 1280-byte payload makes a 1328-byte packet,
  which can be dropped on IPv6 paths that only carry the minimum MTU. Inside
  WireGuard it's fine. B1's handshake fits in 1232 bytes, but B2's msg1 (1296)
  and the rekey INIT (1250) don't. My suggestion: payloads ≤ 1232 bytes, raised
  later by DPLPMTUD (O9). This is Dan's call (D-2).

## Provenance of constants

| Constant | Value | Source |
|---|---|---|
| Max datagram | 1280 | PLAN D5 (stated there as Mosh's; not re-verified) |
| IPv6-safe payload | 1232 | Derived: the RFC 8200 minimum MTU, minus 40 (IPv6 header) and 8 (UDP header) |
| RekeyAfterTime | 120 s | WireGuard paper (REKEY_AFTER_TIME) |
| RejectAfterMessages | 2^64 − 2^13 − 1 | WireGuard paper |
| Replay window | 1984 counters | RFC 6479 construction; we chose the size |
| KeepPrevFor, RekeyRetry | 10 s, 1 s | Our choice, untuned |
| X-Wing sizes | pk 1216, ct 1120 | Measured from `crypto/hpke` |

No Mosh source was consulted.
