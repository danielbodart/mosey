# S1 Handshake: findings

Spike for open question **O1**. Branch `spike/s1-handshake`, with code in
`spikes/s1-handshake/` (a record, not production code). Date 2026-11-13, on
dan-desktop (i9-12900K, 24 threads), Go 1.27.3 (pinned in `mise.toml`) and
ProVerif 2.05 (pinned nixpkgs revision in `proverif/run.sh`).

This is the **second version**. An adversarial review found real problems
with the first, which recommended B1. The review response is at the end
(§9). In short: B1's credential is a bearer secret on SSH stdout, so it
needs the SSH stream to stay confidential, and leaking it is remote code
execution. I added **B3**, which needs SSH only to be authentic. I fixed
the transport and resume problems the review raised, and measured or
modelled each fix.

## TL;DR

**Recommendation: variant B3** (decision **D-1** in §8 is Dan's).

* **Bootstrap.** During the SSH bootstrap, both sides make a **one-shot
  X-Wing** key (ML-KEM-768 + X25519).
  * The client writes its public key to **SSH stdin**.
  * The server prints a credential on **SSH stdout**: a credential id, a
    session id, a 32-byte PSK and its own public key.
* **Authentication.** Each side proves itself by decapsulating, so B3
  needs SSH only to be **authentic**. It does not need SSH to be
  confidential.
* **If stdout leaks.** A credential that leaks from stdout (a session
  recorder, `script(1)`, bastion logging) is **not** enough to impersonate
  the client. ProVerif model `b3_stdout_leak` checks this, and so does the
  test `TestB3LeakedStdoutCannotImpersonate`.
* **The PSK.** It stays as defence in depth, and it gives a cheap `mac1`
  DoS filter.
* **Long-term keys.** There are none, and no signatures.

```
-> s_C                         (SSH stdin: client's one-shot X-Wing pk)
<- s_S                         (SSH stdout: cred id, sid, psk, server's one-shot pk)
...
-> psk, skem_S, {hello_c}      msg1: 1208 bytes
<- skem_C, {hello_s}           msg2: 1174 bytes  (< msg1: no amplification)
-> first transport packet      key confirmation = client authentication
```

Round trips are the same as B1. The server may send at 0.5 RTT (only the
real client can read it), the client may send at 1 RTT, and the server gets
the first client data at 1.5 RTT. Both messages fit in **1232 bytes**, the
largest UDP payload every IPv6 path must carry.

Costs and fixes compared with B1:

* **Bytes.** msg2 grows from 54 to 1174 bytes. The SSH stdin line gains
  1216 bytes.
* **CPU.** Each side does one more X-Wing operation (§2.2).
* **Credential consumption.** A credential is consumed only on
  **confirmation**, not on msg1. Up to 4 unconfirmed responders can exist
  per credential, and the oldest is evicted first. So msg1s forged with a
  leaked PSK can't lock the genuine client out; only a sustained flood
  could.
* **Credential lifetime.** Credentials have a **TTL** (30 s) and a **cap**
  (2 unused per terminal session). msg1 carries a **cleartext credential
  id**, so the server finds the credential with one map lookup (under
  0.05 µs) before any MAC or KEM work.
* **Exclusive resume.** An **exclusive attach** revokes every other
  transport of the session and wipes its keys. Only that makes "log in over
  SSH again" a recovery from a stolen client.
* **Spoofed sources.** A roam to a new address, or a race from a spoofed
  source, is capped at **3x anti-amplification** until an encrypted path
  challenge validates the address (RFC 9000 §8 style).
* **Rekey.** It gained a confirming keepalive with an ack, and stale-epoch
  frames are now ignored. **A property test over 2000 random
  loss/reorder/duplication/collision schedules found two real bugs**, both
  fixed (§1.3).
* **Erasing keys.** `crypto/hpke` private keys can't be erased on demand.
  I **measured** a dropped key's seed still in process memory after two GCs
  in **20/20** trials. Built with `GOEXPERIMENT=runtimesecret` and
  `secret.Do`, it was there in **0/20** (§3.2). Without that, forward
  secrecy only holds once the GC reuses the memory.

QUIC (quic-go) still loses: its congestion control and pacer can't be
tuned without a fork, and the cost in code and bytes is large (§2.3).

## 1. What was built

| File | What |
|---|---|
| `hs/sym.go` | Noise `SymmetricState` (MixHash/MixKey/EncryptAndHash/Split) on `crypto/hkdf`, SHA-256 and ChaCha20-Poly1305. The KEM is `crypto/hpke` `MLKEM768X25519()` (X-Wing), used export-only as a plain KEM, with the transcript hash as HPKE `info`. **No primitive is implemented here.** `crypto/hpke` is **not** covered by the 2025 ToB audit (§8, D-4). |
| `hs/variant_b.go` | B1 (the server's KEM key goes over stdout), B2 (KEM-only, with the client's KEM key in msg1) and **B3** (both one-shot KEM keys over SSH). Includes credential ids, the TTL, confirmation-based consumption (B3), the msg2 retransmission cache and the `mac1` pre-filter. |
| `hs/dispatch.go` | **New.** The server's UDP demultiplexer. It does O(1) msg1 → credential lookup by credential id, enforces the TTL and the per-session cap, keeps the receiver-index table, and implements exclusive attach (revoke and wipe the other transports). |
| `hs/variant_a.go` | A: SIGMA-I over ephemeral X-Wing, with Ed25519 identities pinned over SSH |
| `hs/transport.go` | Data packets, receiver indices, and roaming with **anti-amplification and path validation**. In-band hybrid rekey with **a confirming keepalive and ack**, guards against concurrent rekeys, a guard against stale-epoch rekey frames, a grace period for the previous keys, and `Revoke`. |
| `hs/replay.go` | RFC 6479 ring-of-blocks anti-replay window (1984 counters), with a pure `check` and a mutating `commit` |
| `hs/resume.go` | D8 resume: unix socket in a 0700 directory, `SO_PEERCRED` uid check, v2 request carrying the client's one-shot key and an `exclusive` flag |
| `hs/secret_{on,off}.go` | Runs KEM key generation under `runtime/secret.Do` when built with `GOEXPERIMENT=runtimesecret` |
| `hs/*_test.go` | Functional, tamper-with-every-byte, replay, roaming, rekey, resume and latency (synctest) tests. **New:** `review_test.go` (stdout leak, dispatcher/TTL/cap, anti-amplification, idle rekey initiator, rekey interleaving property test) and `memscan_test.go` (key residue in memory). Also benchmarks and 10 fuzz targets. |
| `cmd/bdemo` | B1/B2/B3 over real loopback UDP, run the same way as `quiccmp` |
| `quiccmp/` | quic-go v0.65.0 with RFC 9221 datagrams, in its own `go.mod` |
| `proverif/` | Models of B1, B2, **B3**, A, plus compromise and sanity variants. `run.sh` (pinned) writes `results.txt`. |
| `fuzz-log.txt` | Raw output of both fuzz campaigns |

`go test ./hs` passes all 21 tests, with and without
`GOEXPERIMENT=runtimesecret`. Two of them, `CostBreakdown` and
`KEMKeyResidue`, are measurements that only run when their environment
variable is set.

### 1.1 Wire format

```
B msg1:  01 | ver | cred_id(8) | sender_idx(4) | X-Wing enc or pk | AEAD(hello) | mac1(16)
B msg2:  02 | ver | sender_idx(4) | receiver_idx(4) | [X-Wing enc (B2, B3)] | AEAD(hello)
data:    04 | receiver_idx(4) | counter(8) | AEAD(frame_kind | body)     29 bytes overhead
         frame kinds: 0 app, 1 REKEY_INIT, 2 REKEY_RESP, 3 keepalive (1 = confirm?, 0 = ack),
                      4 PATH_CHALLENGE(8), 5 PATH_RESPONSE(8); unknown kinds are ignored
reserved 05 NAT-traversal probe (O6); 06 cookie reply
```

* **Credential id.** `cred_id` is random and single-use, so it gives no
  linkability beyond the one handshake. It is in the transcript, because
  the whole header is hashed.
* **Data header and nonce.** The data header is the AEAD's associated data,
  and the counter is the nonce. Each direction has its own key. Counters
  live only in memory (D8). A process that loses its counters also loses
  its keys, so a (key, nonce) pair can never repeat.
* **Receiver index.** The receiver picks it, as in WireGuard. It routes a
  packet before its source address is trusted, it lets one socket serve
  many sessions, and it changes on every rekey so a passive observer can't
  link epochs.
* **Hello.** `hello` is encrypted. It carries the version, flags and the D15
  channel types. Its parser is strict and fuzzed for canonical round trips.

### 1.2 Receive path (the lesson from the flynn/noise advisory)

`Session.Open` works in this order:

1. Parse the header.
2. Look up the receiver index.
3. Run `window.check`, which is pure.
4. Open the AEAD.
5. **Only then** commit the window, promote keys, update the address and
   validation state, and handle frames.

The handshake code works on a copy of the symmetric state and commits only
once the whole message authenticates. Tests check this
(`TestForgedPacketDoesNotAdvanceWindow`,
`TestBWrongCredentialsLeaveStateUntouched`, `TestBTamperEveryByte`, now for
B1, B2 and B3), and so do fuzz invariants.

### 1.3 Rekey

Either side may start after `RekeyAfterTime` (120 s, the WireGuard value)
or `RekeyAfterMessages`:

```
I -> R  REKEY_INIT  { new_idx_I, fresh X-Wing pk }          1250 bytes on the wire
R -> I  REKEY_RESP  { new_idx_R, enc }                      1154 bytes
I -> R  keepalive(1) under the new keys  (retransmitted every RekeyRetry until confirmed)
R -> I  keepalive(0) under the new keys  (ack; not answered)
keys', root' = HKDF(salt = root, ikm = ss, info = H(root, idx_I, pk) | enc | idx_R)
```

* **Switching keys.**
  * The responder installs the new keys for receiving only. It switches
    when a packet under them authenticates, which is key confirmation.
  * The initiator switches when RESP arrives. It then **sends a keepalive
    straight away and keeps resending it** until it receives any packet
    under the new keys.
  * The responder answers the keepalive with a bare ack, so an idle
    responder still confirms.
* **Guards.**
  * No side starts a rekey while one is in flight in either role (`pend`,
    `next` or `awaitConfirm`).
  * A different INIT that arrives while a `next` is unconfirmed is ignored.
  * **REKEY_INIT and REKEY_RESP are acted on only under the current epoch's
    keys.**
* **The property test.** `TestRekeyInterleavingsProperty` drives two
  sessions through 2000 random schedules of 300 steps. The schedules mix
  loss (0–40%), duplication, reordering, crossing rekeys, application data
  and clock jumps, and each one then heals the network. The invariants:
  * no genuine packet ever fails authentication (a failure would mean the
    two sides derived different keys);
  * after healing, no rekey is in flight, the roots are equal, and data
    flows both ways.

  The 2000 schedules completed **12,664 rekeys**. The test found two bugs in
  the first version, both now fixed:
  1. **A stale INIT wedges the next rekey.** A delayed or duplicated
     REKEY_INIT from the previous epoch arrived after the responder had
     promoted. The responder derived a `next` from the *new* root, and the
     guard then ignored the initiator's next real INIT forever. Fix:
     rekey frames count only under `cur`.
  2. **An idle responder never confirms.** The initiator's `awaitConfirm`
     never cleared when the responder sent nothing. Fix: the keepalive
     ack.

  `TestRekeyIdleInitiatorKeepalive` covers the reviewer's specific case:
  the first keepalive is lost, the initiator stays idle past `KeepPrevFor`,
  and the retransmitted keepalive heals the session.
* **Old keys.** They are wiped after `KeepPrevFor` (10 s). The root key is
  chained one-way, which gives forward secrecy within a session.
* **Post-compromise security.** It holds only once the attacker goes
  passive (§3.1).

### 1.4 Resume (D8)

`TestResumeOverLocalSocket` covers these steps:

1. **The request.** A new SSH login runs `mosey-server attach`. The client
   has written its one-shot public key to SSH stdin. The helper forwards it
   with an `exclusive` flag over `$XDG_RUNTIME_DIR/mosey/…/session.sock`,
   which must be in a 0700 directory owned by us, with a real
   `SO_PEERCRED` uid check.
2. **Minting.** The dispatcher mints a B3 credential bound to that key, and
   the helper prints it on stdout.
3. **Attaching.** The client handshakes through the **dispatcher**, and the
   new transport is confirmed.
4. **Exclusive.** The old client's transport is revoked. Its next packet
   gets `ErrNoKey`, and its keys are wiped.

What the test does **not** cover:

* Attaching to a real pty or emulator session. That belongs to O4 and the
  session-process spike. Here the "terminal session" is just a key in the
  dispatcher.
* A real foreign-uid peer. The refusal is tested by stubbing `PeerUID`,
  because a real second uid needs root or a user namespace.

No transport or crypto state ever touches disk. Without `exclusive`,
several clients can stay attached (O5). Which mode is the default is
decision D-6.

### 1.5 Roaming and spoofed sources

The peer address follows the source of the newest authenticated packet of
the current epoch. A reordered old packet doesn't move it, and a replay from
a third address is rejected first (`TestRoaming`).

**Corrected threat description.** An attacker who can **spoof source
addresses** and see the client's packets can copy a fresh genuine packet
and win the race from any address. Before this fix, that pointed the
server's whole output stream at a third-party victim until the next genuine
packet. That is a **reflector**, not just DoS against the user. The data
stays encrypted. Now:

* **Unvalidated addresses.** A new address is *unvalidated*. Until it is
  validated, the server sends at most **3x the bytes received from it**
  (`AllowSend`, RFC 9000 §8.1's factor).
* **Path challenge.** The server sends an encrypted `PATH_CHALLENGE` there.
  Only the genuine client can answer it, and only if it really receives at
  that address.
* **Returning.** The next genuine packet from the last validated address
  returns there at once.
* **The handshake address.** In B3 (and B2) the msg1 source is validated
  by the first transport packet, since those keys depend on msg2, which
  went only to that address. Until then the server's 0.5-RTT output is
  capped at 3x msg1 (about 3.6 KB). In B1 the address needs a challenge.

`TestAntiAmplificationAndPathValidation` covers the race, the cap, the
return, and a genuine roam through challenge and response.

## 2. Measurements

Method:

* **CPU per step.** `MOSEY_COST=1 go test -run CostBreakdown` takes the
  median of 400 runs on one goroutine, measuring wall time.
* **Loopback comparison.** `cmd/bdemo -mode N` and `quiccmp` each ran 500
  handshakes over loopback UDP, with one echoed datagram after each, and
  measured CPU for the whole process with `getrusage`.
* **Round trips.** `TestHandshakeLatency` uses `testing/synctest` virtual
  time with a 50 ms one-way delay. These are exact protocol round-trip
  counts, not network measurements.
* **Machine load.** The second-round numbers come from a machine with a
  **load average of 25–32 on 24 threads** (other spikes' fuzzers). Each
  table compares variants **measured in the same run**. Absolute
  microseconds are about 1.5–2x the first round's quieter figures (B1
  server total: 144 µs in round one, 266 µs here). Trust the ratios, not
  the absolute values.

### 2.1 Size and round trips

| | msg1 | msg2 | msg3 | server can send | client can send | server gets first client data | over SSH (stdin + stdout) |
|---|---|---|---|---|---|---|---|
| B1 | 1208 | 54 | n/a | 0.5 RTT | 1 RTT | 1.5 RTT | 0 + 1273 B |
| B2 | 1304 (over 1232 and 1280) | 1174 | n/a | 0.5 RTT | 1 RTT | 1.5 RTT | 0 + 57 B |
| **B3** | **1208** | **1174** | n/a | 0.5 RTT (only the real client can read it; capped at 3x until confirmation) | 1 RTT | 1.5 RTT | **1216 + 1273 B** |
| A (SIGMA-I) | 1222 | 1270 | 146 | **1.5 RTT** | 1 RTT | 1.5 RTT | pins + sid |
| QUIC (quic-go, TLS 1.3, X25519MLKEM768), handshake + 1 echoed datagram, session tickets **not** disabled | 3905 B in 5.0 datagrams c→s | 2185 B in 4.0 datagrams s→c | | 0.5 RTT | 1 RTT | 1.5 RTT | (cert pin) |
| rekey | INIT 1250 | RESP 1154 | keepalive 31 | | | | |

* **The SSH column.** These bytes go over SSH, which is already open, and
  they add no round trip. The stdout figure is the binary size; base64
  would make it about 1.7 KB.
* **Hello size.** The sizes assume a 3-channel hello.
* **IPv6.** B1 and B3 fit in 1232 bytes. B2's msg1 and the rekey INIT
  (1250) don't (D-2).
* **What A's signatures cost.** Only the **server's first output** moves,
  by 1 RTT. The client's first send and the server's first receipt are the
  same as B's. (The first version wrongly said "adds a round trip".)
* **Compared with Mosh.** Mosh has no UDP handshake at all: its key arrives
  over SSH (paper and documentation). B adds 1 RTT before the first
  keystroke, hidden behind the SSH bootstrap's several RTTs.

### 2.2 CPU (median µs, one goroutine, one run, loaded machine)

| step | B1 | B2 | **B3** | A |
|---|---|---|---|---|
| client: make one-shot KEM key (during the SSH bootstrap) | n/a | n/a | 118 | n/a |
| server: mint credential (during the SSH bootstrap) | 121 | 0.3 | 160 | n/a |
| client: build msg1 | 190 | 158 | 241 | 171 |
| server: msg1 → msg2 | 145 | 238 | 321 | 219 (**including for spoofed msg1**) |
| client: process msg2 (→ msg3) | 3.6 | 132 | 134 | 263 |
| server: process msg3 | n/a | n/a | n/a | 59 |
| **server total** | **266** | **238** | **481** | **278** |
| **client total** | **194** | **290** | **493** | **434** |
| server: reject msg1 with bad `mac1` | 3.8 | 3.2 | 3.8 | 1.8 µs (HMAC cost) if A had a `mac1` |
| server: reject msg1 with valid `mac1` but bad AEAD (the real cost **without** a `mac1`) | 137 | 7.8 | 142 | 219 |
| dispatcher, 1000 outstanding credentials: unknown cred id | < 0.05 | | | |
| dispatcher, 1000 outstanding credentials: known id, bad `mac1` | 2.6 | | | |

Notes:

* **"Without `mac1`".** The first version's "80 µs without mac1" had no
  code path behind it. The row above now measures it: a msg1 with a valid
  `mac1` but a broken AEAD tag still costs the full decapsulation.
* **`mac1` for A.** An SSH-delivered `mac1` key would cost A about 2 µs per
  msg1, as it does B. The DoS gap between A and B in the first version came
  from leaving the filter out of A, not from SIGMA-I itself. A would still
  hold state per msg1.
* **B3 against B1.** B3 costs about 1.8x B1 on the server and 2.5x on the
  client, from one more X-Wing keygen, encapsulation and decapsulation.
  That is still under 0.5 ms per side, once per connection.
* **Transport packets.** Sealing and opening a 1 KiB transport packet took
  2.9 µs in round one. That code is unoptimised and makes 7 allocations per
  packet.

**Loopback, whole process, both ends** (`getrusage`, 500 handshakes plus an
echo, back to back under the same load):

| | B1 | **B3** | quic-go |
|---|---|---|---|
| CPU per handshake + echo, whole process (rounds 1/2/3) | 546 / 557 / 479 µs | 992 / 913 / 877 µs | 1367 / 1296 / 1261 µs |
| median | **0.55 ms** | **0.91 ms** | **1.30 ms** |
| bytes c→s / s→c on UDP (2-channel hello) | 1225 / 85 | 1225 / 1205 | 3905 / 2185 |

On this measure B3 costs about 1.7x B1 and about 0.7x quic-go. In the
first, quieter round B1 measured 0.47 ms and quic-go 1.22 ms.

### 2.3 Comparison with quic-go

The line counts in this table were all made the same way: `cloc` (via
`nix shell nixpkgs#cloc`) over the `GoFiles` of every non-standard package
in `go list -deps` of each demo binary on linux/amd64, counting code lines
only:

```
go list -deps -f '{{if not .Standard}}{{range .GoFiles}}{{$.Dir}}/{{.}}{{"\n"}}{{end}}{{end}}' ./cmd/bdemo
```

| | mosey (`hs` package incl. A) | quic-go v0.65.0 + RFC 9221 |
|---|---|---|
| Non-std packages linked | 6 (5 x/crypto and x/sys, plus `hs`) | 28 |
| Non-std code lines linked (cloc) | **3.0k**. `hs` itself is 1.6k, or 1.4k without A. | **46.9k**. quic-go itself is 23.0k. |
| Stripped demo binary | 2.8 MB | 6.4 MB |
| Bytes for a handshake plus one echoed datagram | B3: 1225 c→s + 1205 s→c, in 2+2 datagrams, plus about 2.5 KB over SSH. B1: 1225 + 85, plus 1.3 KB over SSH. | 3905 c→s + 2185 s→c, in 5+4 datagrams (`NewSessionTicket` and `HANDSHAKE_DONE` included, because session tickets weren't disabled) |
| Congestion control | None: SSP owns the timing (D11) | CUBIC and a pacer, created unconditionally. `SendMode()` gates **all** sending, DATAGRAM frames included, on `CanSend` and `HasPacingBudget`. There is no `Config` switch. The datagram send queue is fixed at 32. |
| Server identity | One-shot KEM keys + PSK over SSH | X.509 certificate, which would need pinning over SSH anyway |

The first version said "35.7k lines", which matched neither counting method.
It also overstated the congestion-control point, so here is a more careful
statement. CUBIC's initial window is 32 packets, and SSP sends a few small
frames per RTT, so **in steady state CUBIC would rarely bind**. The likely
conflict is **after loss or an outage**, when the window drops to its
minimum of 2 packets and the pacer restarts. That is exactly when SSP wants
to send a full-state frame at once. **I did not measure it.** The fair
statement is "not tunable without a fork; behaviour after an outage is
likely to fight SSP". S5's train profile could measure it if anyone wants
to reopen QUIC. Code size, binary size and handshake bytes decide the
verdict on their own.

## 3. Formal model (ProVerif 2.05, symbolic)

The models are in `spikes/s1-handshake/proverif/`. `./run.sh` (pinned) runs
all 11 of them in 20 s and writes `results.txt`.

Assumptions:

* **Sessions.** The number of sessions is unbounded.
* **KEM.** The KEM is an ideal IND-CCA KEM, bound to the HPKE `info`. The
  claim that the hybrid is secure if either component holds comes from the
  X-Wing combiner's own proof.
* **SSH in B1 and B2.** SSH delivery is **confidential** and authentic,
  modelled as names the attacker never learns.
* **SSH in B3.** SSH delivery is **authentic only**. Both public keys are
  published, and `b3_stdout_leak` publishes the PSK as well.
* **Server replication in B3.** The B3 server is **replicated** per
  credential, which models answering many msg1s and consuming the
  credential only on confirmation.
* **SSH in A.** The pins and the session id are chosen by the attacker for
  each run.

| Model | Scenario | Result |
|---|---|---|
| `b1` | The PSK leaks after the session | Client authentication with replay protection (injective, at msg1), server authentication and agreement (no misbinding), forward secrecy in both directions: **all hold** |
| `b1_psk_leak` | **The stdout line leaks before the handshake** | Server authentication and client→server secrecy hold. **Client authentication fails and server→client secrecy fails: the attacker *is* the client and drives the shell.** `TestB1LeakedStdoutIsImpersonation` shows it running. The first version presented this result as a B1 strength, which was wrong. |
| `b1_skS_leak` | Sanity check: skS leaks later too | Secrecy fails, because deleting skS is what gives forward secrecy |
| `b2` / `b2_psk_leak` | The PSK leaks after / before | All hold / **everything fails** |
| **`b3`** | The PSK leaks after the session | **Client authentication at key confirmation** (injective), server authentication and agreement, forward secrecy in both directions: **all hold**. Injective agreement *at msg1* fails by design: the replicated server answers replays. Non-injective agreement at msg1 holds. |
| **`b3_stdout_leak`** | **The whole stdout line, PSK included, is known from the start** | **Client authentication at confirmation holds, server authentication holds, and secrecy holds in both directions**, including the server's 0.5-RTT data. Only msg1 authenticity fails, which is expected: msg1 is answered but never trusted. |
| `b3_noss2_sanity` | Sanity check: like `b3_stdout_leak`, but the msg2 KEM secret is left out of the keys | Client authentication **fails** and server→client secrecy **fails**. So the model sees the attack that B3's second KEM prevents. |
| `a` | Both signing keys leak afterwards | Client authentication (at key confirmation), server authentication, secrecy and no misbinding, even with pins chosen by the attacker: all hold |
| `a_kci` | The client's signing key leaks at the start (KCI) | The client still authenticates the server, and its data stays secret. The server side fails trivially. |
| `a_nomac` | Sanity check: misbinding | The model finds the attack |

Tamarin 1.12 is available through nix but wasn't needed. It, together with
the existing PQNoise Tamarin models, remains the route to a computational
or more detailed model before 1.0 (PLAN §6.5).

### 3.1 Properties argued, not modelled

* **Rekey (no ProVerif model).** Forward secrecy comes from the one-way
  HKDF root chain plus wiping keys after `KeepPrevFor`. Post-compromise
  security holds only once the attacker goes passive, which is inherent to
  any in-band rekey. **Full recovery from a stolen or compromised client
  needs an exclusive re-attach (§1.4).** A plain resume leaves the old
  transport live, so the first version's claim that "logging in over SSH
  again" gives full recovery was wrong.
  * The state machine's *liveness and key agreement* are now checked by the
    interleaving property test (§1.3).
  * Its *secrecy* across epochs is still **argued, not modelled**. A
    ProVerif or Tamarin model of the epoch chain is still owed before
    anyone relies on it for 1.0.
* **KCI in B.** B has no long-term keys.
  * A B1 credential that leaks before use lets the attacker pose as the
    client.
  * A B3 credential that leaks before use doesn't, because `sk_C` is
    needed. It doesn't let the attacker pose as the server either, because
    `sk_S` is needed (`b3_stdout_leak`).
  * A credential that leaks after use, or after its TTL, is worthless.
* **Replay.**
  * In B1 and B2 a credential is consumed by the first valid msg1. An
    identical retransmission gets the cached msg2.
  * In B3, replays of msg1 create at most 4 unconfirmed responders. None of
    them can ever be confirmed, and each is capped at 3x anti-amplification.
  * The RFC 6479 window was checked against a reference model.
  * Rekey frames inherit the replay protection of the current keys, and
    only current-epoch rekey frames are acted on.
* **Idle sessions.** "Rekey on quiet" is still proposed and not
  implemented (D-3).
* **Misbinding in B.** The transcript binds the protocol name, the sid,
  both one-shot keys (B3), the credential id, both indices and every byte
  of both messages.
* **Denial of service.**
  * An unknown credential id is rejected in under 0.05 µs, before any MAC.
  * `mac1` costs 3–4 µs (loaded) against 137–142 µs for a decapsulation.
  * msg2 is no larger than msg1.
  * A with an SSH-keyed `mac1` would match this.

### 3.2 Erasing secrets: what the code actually does

The review was right. The forward-secrecy claims assume `sk_S`, `sk_C`,
the PSK and the root keys are **erased**, but the first version only
dropped references to the opaque `hpke.PrivateKey`. What changed:

* **What the code erases.** The PSK on consumption, on expiry and in the
  client. Both copies of the marshalled credential buffer in the resume
  path, plus `BCredentials.Wipe` for callers. The split outputs (newSession
  now takes pointers and clears the source). `resp.nextRoot` (rotate now
  takes a pointer and clears the source) and the rekey locals. All keysets
  of a revoked session.
* **What the code can't erase.** `hpke.PrivateKey` (X-Wing) has no
  zeroising API. Note also that `crypto/hpke`'s `Bytes()` hands back the
  key's **internal seed slice**, not a copy. Clearing that would erase the
  seed but not the expanded ML-KEM and X25519 keys, so it is not a fix.
  Some working copies of the symmetric state on failure paths are still
  not cleared.
* **Measured** (`MOSEY_MEMSCAN=1 go test -run KEMKeyResidue`, in
  `memscan_test.go`). The test generates an X-Wing key, drops it, runs
  `runtime.GC()` twice, and then scans every writable mapping of
  `/proc/self/mem` for its 32-byte seed. A live key acts as the positive
  control, and the needle and scan buffer sit in excluded `mmap` regions.
  Three runs each:

  | build | positive control (live key found) | dropped key's seed still in memory |
  |---|---|---|
  | default | 5/5, 5/5, 5/5 | **20/20, 20/20, 20/20** |
  | `GOEXPERIMENT=runtimesecret`, keygen inside `secret.Do` | 5/5, 5/5, 5/5 | **0/20, 0/20, 0/20** |

  The scan looks only for the seed, not the expanded keys. The default
  residue includes the stdlib's own generation-time seed buffer, because
  hpke clones the seed into the key and leaves the original unwiped.
* **The statement for the spec.** Secrets must be **erased**, not
  dereferenced. Release builds on linux/amd64 and arm64 should use
  `runtime/secret` and run the whole handshake and rekey path inside
  `secret.Do` (the spike wraps only key generation). On other platforms,
  and in default builds, the forward-secrecy claim is **"after the GC
  reuses the memory"**. `runtime/secret` is still a GOEXPERIMENT, and
  `secret.Do` erases heap allocations only when the GC finds them dead, not
  on demand (D-5). The credential TTL bounds how long an *unused* `sk_S`
  stays live.

## 4. Noise: a standard pattern or our own?

Precise naming, corrected from the first version:

* **B2** is a **KEM-only `pqNNpsk0`**: `-> psk, e_kem ; <- ekem`. It has no
  DH tokens, so it is **not** NNpsk0 plus HFS.
* **B1** is **not** a PQNoise catalogue pattern. It is a one-way KEM to an
  SSH-delivered key, plus a PSK, plus a confirmation message:
  `<- s ; ... ; -> psk, skem ; <- (no KEM)`. Calling it "pqNK" was wrong,
  because pqNK also has the initiator send `e` and the responder reply
  `ekem`. The protocol name is now `Mosey_B1_KEMpsk0_…`.
* **B3** has the **shape of pqKK minus the ephemeral tokens**:
  `-> s ; <- s ; ... ; -> psk, skem ; <- skem`. pqKK as catalogued adds
  `e`/`ekem` to get forward secrecy against later compromise of the static
  keys. B3 can leave them out because its "static" keys are one-shot and
  deleted after use, which `b3` models. **It is not a catalogue pattern, so
  existing PQNoise tooling needs a custom model**, which `proverif/b3*.pv`
  is. Real pqKKpsk0 with long-lived statics would put identity keys on
  disk, which D8 forbids.
* **No library would help.** No Go Noise library supports KEMs.
  flynn/noise has no post-quantum support and is the subject of PLAN §7's
  advisory.

**Recommendation.** Specify the handshake in Noise notation, with the exact
token sequence above and the protocol name
`Mosey_B3_KEMx2psk0_XWing_ChaChaPoly_HKDFSHA256`. Implement it on the
standard library, as the spike does. Ship the ProVerif models with the spec.

## 5. A against B: what does each trust SSH for?

The first version answered "no signatures needed" by equating A's pinned
keys with B1's PSK. That comparison was wrong, because the two designs rely
on different properties of the SSH stream:

| | What SSH must provide | If the SSH stdout leaks (recorder, `script`, bastion log, shell rc noise) |
|---|---|---|
| A (pinned public keys) | integrity only | nothing happens |
| B1 (bearer PSK) | **confidentiality** and integrity | **remote code execution**: the attacker races the client with its own msg1, gets the shell, and locks out the genuine client |
| **B3** (two one-shot KEM keys + PSK) | **integrity only** | **nothing beyond DoS**: the attacker can make PSK-valid msg1s but can't confirm them. The genuine client still completes. |

So B3 matches A's trust requirement without A's costs:

* the server's first output arrives 1 RTT earlier;
* authentication is post-quantum, where A's Ed25519 is not, and
  ML-DSA-65's 1952-byte key plus 3309-byte signature don't fit in a
  datagram;
* there are no identity keys, so no keys on disk;
* msg2 is smaller.

B3 costs about 2x B1's CPU (§2.2), 1.1 KB more on the UDP path, and 1.2 KB
more on SSH stdin. With an SSH-keyed `mac1` added, A's DoS cost would match
B's (§2.2). That is no longer a reason to choose B over A.

## 6. Hooks for later work

* **O6 (NAT traversal).** Sessions are identified by receiver index, and
  the credential id identifies a pending handshake, so neither depends on
  the address. msg1 is idempotent, so it can go to several candidate
  addresses at once. Path validation (§1.5) is the mechanism O6's
  candidate checks need anyway. `0x05` probes stay reserved.
* **D15 (channels).** Channel types are negotiated in `hello`. Port
  forwarding needs only a new channel-type name.
* **O2/S3: a requirement on S3, not an open option.** Dan's provenance
  chain over agent forwarding needs the **local** agent to verify that a
  forwarded request came through *this* mosey session, signed by the
  *remote* side. `Session.Handshake` (the final transcript hash `h`)
  exists for this.
  * **Requirement.** A remote signing key must sign a statement that
    includes mosey's `h`. That key is either the remote quoin key, or a
    per-session remote key whose public half travels with the credential
    over SSH stdout, so it is bound by the same SSH integrity that B3
    already relies on.
  * **Dropped option.** The first version also offered "relay the SSH
    bootstrap's session-bind". It doesn't work under D6. The system `ssh`
    doesn't expose the exchange hash to its caller, `sshd` doesn't export
    it to the session, a bind would cover the SSH bootstrap rather than
    mosey's `h`, and a resume uses a different SSH login.
  * **What B lacks.** Neither B1 nor B3 has a remote key that could sign
    `h`. That is the gap S3 must fill, and it is S3's decision whether the
    signer is quoin's key or a per-session one (D-9).

## 7. Fuzzing

**Campaign 1** (first version) ran 9 targets for 200 s each, with
`-parallel 8`, from 18:35:05 to 19:05:15. That is 30.2 min, with
**0 failures**. The executions add up to **342.4M**. The first version's
summary said "about 390M", which was wrong. The per-target counts are:

| Target | Invariant | Execs | New corpus |
|---|---|---|---|
| FuzzParseHello | anything accepted survives a round trip unchanged | 46.5M | 42 |
| FuzzParseBCredentials | anything accepted survives a round trip unchanged | 27.9M | 4 |
| FuzzBServerInitB1 | a failure doesn't consume the credential; only the genuine msg1 succeeds | 24.1M | 2 |
| FuzzBServerInitB1FixMAC | same, with `mac1` recomputed so mutations reach the KEM, AEAD and parser | 11.0M | 11 |
| FuzzBServerInitB2FixMAC | same, for B2 | 13.5M | 7 |
| FuzzBClientResp | no msg2 from a server without the PSK is ever accepted | 37.0M | 0 |
| FuzzAHandshake | a msg2 or msg3 not bound to this handshake is never accepted | 46.3M | 28 |
| FuzzSessionOpen | a rejected packet changes neither the window nor the peer; no forgery is accepted | 70.0M | 1 |
| FuzzReplayWindow | matches a map-based reference implementation | 66.1M | 42 |

**Campaign 2** (after the review) re-fuzzed the targets whose input format
or code changed: the credential id in msg1, B3, the new frame kinds and
address validation.

Campaign 2 ran 5 targets for 100 s each, with `-parallel 8`, from
19:29:42 to 19:38:03 (8.3 min), with **0 failures**:

| Target | Execs | New corpus |
|---|---|---|
| FuzzBServerInitB3FixMAC (new) | 24.5M | 2 |
| FuzzBServerInitB1 | 11.1M | 2 |
| FuzzParseBCredentials (B3, credential id) | 26.5M | 3 |
| FuzzBClientResp (B1/B2/B3) | 27.5M | 1 |
| FuzzSessionOpen (new frame kinds, validation) | 27.8M | 0 |

That is **117.4M** executions, and **459.8M** across both campaigns, in
38.5 min. Campaign 2 ran alongside other spikes' fuzzers.

A caveat on FuzzBServerInitB3FixMAC: its rate (224k/s on 8 workers)
means most mutations die before the KEM, either at the credential-id check
or the length check. The mutations that reach decapsulation are a minority.

The raw output of both campaigns is in `spikes/s1-handshake/fuzz-log.txt`.
This is still a smoke test, and production needs continuous fuzzing
(PLAN §6.5).

## 8. Decisions for Dan

| # | Question | Options | Recommendation |
|---|---|---|---|
| **D-1** | Which handshake? | **B3** (both one-shot KEM keys over SSH, so SSH needs only integrity). B1 (bearer PSK, so SSH must stay confidential; about half B3's CPU). A with `mac1` (SIGMA-I, Ed25519, not post-quantum, server output 1 RTT later). | **B3.** B1's failure mode, where a leaked stdout line becomes a shell for the attacker, is too sharp for a tool that will run under session recorders and bastions. |
| **D-2** | Datagram ceiling | 1280 (D5 as locked). **1232**, raised later by DPLPMTUD (O9). | **1232.** B3's handshake fits. The rekey INIT (1250) would need to lose 18 bytes, for example by carrying the new index in the header. |
| **D-3** | Rekey on quiet | After N s with no application traffic, rekey once so idle keys have only protected rekey frames. Or don't. | Yes, with N around 30 s. |
| **D-4** | KEM implementation | `crypto/hpke` X-Wing (Go 1.26+). It is **not** covered by the 2025 ToB audit, but the combiner is written by the Go team. Or `crypto/mlkem` + `crypto/ecdh` (audited) with the X-Wing combiner composed by us from `crypto/sha3`, checked against the draft's test vectors. | **`crypto/hpke`**, with the audit gap recorded and tracked. Composing the combiner ourselves is close to D19's line on writing our own crypto. Revisit if Go's next audit leaves hpke out. |
| **D-5** | Erasing secrets | Release builds with `GOEXPERIMENT=runtimesecret` and the handshake and rekey inside `secret.Do`. Or default builds, with the forward-secrecy claim weakened to "after GC reuse". | **runtimesecret on linux/amd64 and arm64** (measured: 0/20 residue against 20/20). Weaken the claim on other platforms. |
| **D-6** | Default attach mode | Shared: other transports stay, as O5's multi-client attach expects. **Exclusive**: everything else is revoked on confirmation. | **Shared by default**, to match O5, plus `--exclusive` and a command that lists the attached transports (address, last seen) and revokes them. If Dan values "a stolen laptop is cut off by default" over multi-attach, flip it. |
| **D-7** | Credential TTL and cap | TTL 30 s, cap 2 unused per terminal session (both spike choices). | Keep them, and log evictions. |
| **D-8** | Output before confirmation | Server output to an unconfirmed (B3) or unvalidated address is capped at 3x the bytes received (about 3.6 KB for msg1). | Keep 3x (RFC 9000's value). S5 should check that the first screen fits, or that SSP converges fast enough within the cap. |
| **D-9** | Who signs mosey's `h` for the provenance envelope (S3) | The remote quoin key. A per-session remote key delivered with the credential. | S3 decides, but the requirement in §6 stands either way. |

## Challenges to locked decisions

* **D5 (1280-byte payloads).** IPv6 guarantees only 1280-byte *packets*,
  which leaves 1232 bytes for a UDP payload. A 1280-byte payload can be
  dropped on IPv6 paths that only carry the minimum MTU. B3's handshake
  fits in 1232 bytes. B2's msg1 (1304) and the rekey INIT (1250) don't.
  This is Dan's call (D-2).
* **D6 ("receives the session's secret over that SSH channel")** needs one
  refinement, not a reversal. The client should also **send** a one-shot
  public key over SSH stdin. This still works with the system `ssh` and any
  `~/.ssh/config`. It means "SSH vouches" needs only SSH's integrity, not
  its confidentiality.

## Provenance of constants

| Constant | Value | Source |
|---|---|---|
| Max datagram | 1280 | PLAN D5 (stated there as Mosh's; not re-verified) |
| IPv6-safe payload | 1232 | Derived: RFC 8200 minimum MTU − 40 − 8 |
| RekeyAfterTime | 120 s | WireGuard paper (REKEY_AFTER_TIME) |
| RejectAfterMessages | 2^64 − 2^13 − 1 | WireGuard paper |
| Replay window | 1984 counters | RFC 6479 construction; we chose the size |
| KeepPrevFor, RekeyRetry | 10 s, 1 s | Our choice, untuned |
| CredentialTTL | 30 s | Our choice: SSH stdout → UDP plus retransmissions |
| Max unused credentials per session | 2 | Our choice |
| Max unconfirmed B3 responders per credential | 4 | Our choice |
| Anti-amplification factor | 3 | RFC 9000 §8.1 |
| Credential id | 8 bytes | Our choice (review suggested 8–16) |
| X-Wing sizes | pk 1216, ct 1120 | Measured from `crypto/hpke` |

No Mosh source was consulted.

## 9. Review response

Each item below is the reviewer's claim, then what I did.

1. **B1 needs SSH confidentiality, and a leaked credential means RCE
   (major). Accepted and fixed.**
   * §5 and the TL;DR are rewritten.
   * B3 was designed, implemented, modelled (`b3`, `b3_stdout_leak`, plus a
     sanity model) and tested (`TestB3LeakedStdoutCannotImpersonate`).
     `TestB1LeakedStdoutIsImpersonation` shows the B1 attack running.
   * The recommendation changed from B1 to B3, and the final choice is
     D-1.
2. **Credentials have no TTL, no cap and no id (major). Fixed.**
   * `CredentialTTL` is 30 s, checked in `HandleInit`, with
     `Dispatcher.Reap`.
   * Each terminal session has a FIFO cap of 2.
   * An 8-byte cleartext credential id in msg1 is in the transcript and
     gives O(1) dispatch, measured at under 0.05 µs with 1000 outstanding
     credentials.
   * `TestDispatcherTTLCapAndManyCredentials` runs 40 credentials on one
     dispatcher: eviction, shuffled completion, routing and TTL.
3. **Resume isn't recovery, because the old client stays attached (major).
   Fixed.**
   * The claim is corrected (§3.1).
   * An `exclusive` attach revokes every other transport and wipes its keys
     when the new transport confirms. `TestResumeOverLocalSocket` checks
     that the old client gets `ErrNoKey`.
   * The default mode is D-6.
4. **The secrets are dereferenced, not erased (minor plus major). Fixed
   where Go allows, measured, and the claim is weakened.**
   * The PSK, credential buffers, split outputs, `nextRoot` and revoked
     keysets are now cleared.
   * The `runtime/secret` experiment measured 20/20 against 0/20 residue.
   * The credential TTL bounds how long an unused `sk_S` lives.
   * The forward-secrecy claim is stated as conditional (§3.2, D-5).
5. **Rekey has no model and has an idle-initiator bug (minor). Fixed and
   property-tested.**
   * The keepalive is retransmitted until confirmed and is acked.
   * Concurrent rekeys are now refused.
   * The property test found and fixed **two further bugs**: the stale INIT
     wedge and the missing confirmation from an idle responder.
   * A ProVerif model of the epoch chain is still owed (§3.1).
6. **The provenance hook is wrong under D6 (minor). Fixed.** The bind relay
   is gone. §6 now states the requirement on S3, and `Session.Handshake`
   exposes `h`.
7. **Roaming makes the server a reflector, not just DoS (minor). Fixed.**
   The threat is described accurately. Anti-amplification (3x), an
   encrypted path challenge and response, and address validation by B3
   confirmation are implemented and tested.
8. **`crypto/hpke` is outside the ToB audit (major). Accepted.** The
   comment in `sym.go` is corrected. The alternative and the trade-off are
   D-4.
9. **The A/B comparison was tilted (minor). Accepted.**
   * A `mac1` for A was measured at 1.8 µs. A was not re-run with a full
     `mac1` path; the cost is additive.
   * "Adds a round trip" became "delays the server's first output by
     1 RTT".
   * §5 is rewritten around trust requirements.
10. **The Noise naming was wrong (minor). Fixed** (§4). The exact token
    sequences are given, B1 and B3 are stated not to be catalogue patterns,
    and B1 is renamed `KEMpsk0`.
11. **Some numbers were irreproducible (minor). Fixed.**
    * The exec total is 342.4M.
    * Line counts now use one method (cloc over `go list -deps` `GoFiles`)
      on both sides, with the command given: 3.0k against 46.9k linked, and
      23.0k for quic-go alone.
    * The 80 µs figure is replaced by a measured "valid `mac1`, bad AEAD"
      row.
12. **The quic-go congestion-control claim was unmeasured (minor).
    Accepted.** It is recast as "not tunable without a fork; behaviour
    after an outage is likely to fight SSP; not measured" (§2.3). The bytes
    sent over SSH now appear in §2.1 and §2.3, and the uncounted session
    tickets are noted.
13. **No decisions list (minor). Fixed.** §8 lists D-1 to D-9.
14. **Resume coverage was overstated, and there was no msg1 dispatch
    (minor). Fixed.** The coverage claims are narrowed to what the test
    does (§1.4), and dispatch is implemented.
15. **The toolchain and ProVerif weren't pinned (minor). Fixed.** There is
    a `mise.toml` with go 1.27.3, and `run.sh` pins nixpkgs `c56a87d8…`
    (ProVerif 2.05).
