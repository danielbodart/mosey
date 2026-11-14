# Transport: wire format, handshake, rekey and paths

This is what `internal/wire`, `internal/replay`, `internal/handshake` and
`internal/transport` are coded from. It covers every byte mosey sends over
UDP below SSP: the datagram types, the B3 handshake and its credentials,
sealed data packets and their frames, the in-band rekey with its split
INIT, path validation, revocation, the resume rekey, and what is erased
when.

It is written from spike S1 (`docs/spikes/s1-handshake/FINDINGS.md`, its
code in `spikes/s1-handshake/hs/` and its ProVerif models in
`spikes/s1-handshake/proverif/`), S5's path validation
(`docs/spikes/s5-netsim-ssp/FINDINGS.md` §6, `ssp-spec.md` §2.1) and the
locked decisions in PLAN §2, chiefly D5, D8, D15, D20, D21 and D26. Where
this document and a decision disagree, the decision wins and this document
is the bug.

Nothing here comes from Mosh's source. Mosh has no UDP handshake at all
(its key arrives over SSH, per the paper and mosh.org), so there is nothing
of it to follow; the transport is closer to WireGuard and QUIC, which are
cited where they are used.

Every constant carries its provenance:

- **[RFC n §x]**: a standard says so.
- **[WG]**: the WireGuard paper (Donenfeld, NDSS 2017), §6 timers.
- **[S1]**, **[S5]**: our spikes, measured or chosen there.
- **[derived]**: worked out here from other constants, with the working.
- **[ours]**: chosen here, untuned; netsim may move it.

The words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. Overview

```
client                                                  server (proto)
  |  ssh stdin:  ClientLine { s_C, ... }              (bootstrap.md)
  |  ssh stdout: CredentialLine { cred id, sid, psk, s_S, addr, port }
  |                                                        |
  |-- msg1  0x01: cred id, idx_C, skem_S, {hello_c}, mac1 ->|  answered, not trusted
  |<- msg2  0x02: idx_S, idx_C, skem_C, {hello_s} ----------|  0.5 RTT: server may send
  |-- data  0x04: keepalive(answer)  ---------------------->|  key confirmation:
  |<- data  0x04: keepalive(none)    -----------------------|  credential consumed,
  |                                                        |  address validated
  |<====== data 0x04: sealed frames, both ways ===========>|
  |        terminal (SSP), rekey, keepalive, path, ...      |
```

- Three datagram types are live: msg1, msg2 and data. Two more are
  reserved (§2.1).
- The handshake is two UDP messages. Each side proves itself by
  decapsulating what the other encapsulated to its one-shot key, so SSH
  needs to be authentic, not confidential (D20).
- After the handshake, everything is a data packet: a 13-byte clear header
  and one sealed frame. The frame's kind says what it is (§4.2).
- Each epoch has its own keys and receiver indices. A rekey every 120 s
  moves to the next epoch inside sealed frames, never in the clear (§6).
- The server follows the client to a new address only after the client
  answers an encrypted challenge there (§7).

The transport has no congestion control, no retransmission of terminal
payloads, no ordering and no fragmentation. SSP owns all of those (D11,
`ssp.md`). The transport retransmits only its own control messages:
msg1, the confirmation, rekey messages and path challenges.

## 2. Datagrams

### 2.1 Types

The first byte of every UDP payload, in the clear, is its type. A receiver
reads it before anything else and drops any datagram whose type it does
not expect in its current state, without reply.

| Type | Name | Direction | Size (UDP payload) | Status |
|---|---|---|---|---|
| `0x00` | | | | never assigned, so a zeroed buffer never parses |
| `0x01` | msg1 | client → server | 1170–1185 B | slice 1 |
| `0x02` | msg2 | server → client | 1150–1165 B | slice 1 |
| `0x03` | | | | reserved, unassigned |
| `0x04` | data | both | 30–1232 B | slice 1 |
| `0x05` | NAT-traversal probe | both | ≤ 1200 B | reserved for O6 |
| `0x06` | cookie reply | server → client | ≤ 1200 B | reserved for a stateless DoS cookie under load |
| `0x07`–`0xFF` | | | | reserved |

These match `transport.TypeMsg1`, `TypeMsg2`, `TypeData`, `TypeNATProbe`
and `TypeCookie`.

### 2.2 Size limits (D5)

| Limit | Value | Provenance |
|---|---|---|
| Any datagram mosey sends | ≤ **1232** B (`wire.MaxDatagram`) | [derived] RFC 8200 §5 minimum IPv6 MTU 1280 − 40 (IPv6 header) − 8 (UDP header); D5 |
| msg1, msg2, each REKEY_INIT part, REKEY_RESP, and the reserved `0x05`/`0x06` | ≤ **1200** B (`wire.MaxHandshake`) | QUIC's floor, [RFC 9000 §14.1]; D5, so DPLPMTUD [RFC 8899] can later start from a 1200-byte base with no wire change (O9) |
| Receive buffer | ≥ 1233 B | [derived] one more than the largest legal datagram, so an oversized datagram is seen as oversized rather than silently truncated |

A receiver drops any datagram over 1232 bytes, and any handshake or rekey
message over 1200, before looking further. A sender that would build a
larger one has a bug: it MUST fail rather than send.

The sizes in §2.1 and §4 are exact functions of the field sizes below and
are checked by tests. They meet D5 with room to spare: the largest
handshake message is msg1 at 1185 bytes, 15 under the limit. That settles
the open item in `architecture.md` §4 (S1's msg1 measured 1208 with a
42-byte hello; this spec's hello is at most 19 bytes, §3.6).

### 2.3 Integers and versions

- Every multi-byte integer in a datagram is **little-endian**, as in
  WireGuard, the spike and the AEAD nonce (§4.1).
- **Wire version.** msg1 and msg2 carry a version byte, `0x01` in this
  document. A receiver drops a handshake message with any other version
  without reply. Data packets carry no version: their format is the one
  the handshake agreed. The client and server are the same build (D7), so
  a mismatch means a bug or an attack, not an old peer; the bootstrap line
  carries its own version and refuses a mismatch with a message on stderr
  (`bootstrap.md`).
- **Protocol name.** The name (§3.1) is hashed into the transcript first.
  Changing any cryptographic choice changes the name, and a transcript of
  one protocol can then never match another.
- **Hello version.** The encrypted hello carries a protocol revision
  (§3.6), for feature changes within wire version 1.
- **Frame kinds** that a receiver does not know are authenticated and then
  ignored (§4.2), so later slices add frames without breaking older peers.
- **Channel types** are negotiated in the hello (D15).

## 3. The handshake (B3)

### 3.1 Name and pattern

```
Mosey_B3_KEMx2psk0_XWing_ChaChaPoly_HKDFSHA256
```

This exact string is `handshake.Protocol` (D20). In Noise notation (Noise
rev 34 §7, with PQNoise's `skem` token: "encapsulate to the peer's static
KEM key", Angel et al., CCS 2022):

```
-> s                         pre-message: the client's one-shot pk, over SSH stdin
<- s                         pre-message: the server's one-shot pk, over SSH stdout
...
-> psk, skem, {hello_c}      msg1
<- skem, {hello_s}           msg2
-> first data packet         key confirmation: the client is authenticated here
```

- **KEMx2**: two KEM encapsulations, one to each side's one-shot key.
  **psk0**: the PSK is mixed in before the first message.
- **It is not a PQNoise catalogue pattern.** It has the shape of pqKK
  without the ephemeral tokens (S1 §4). It can leave them out because its
  "static" keys are single-use and erased after the handshake (§9), which
  gives the forward secrecy ephemerals would. They are called `s` only
  because they are delivered in advance. Existing PQNoise tooling does not
  cover it; the ProVerif models in `spikes/s1-handshake/proverif/b3*.pv`
  are its model (§3.10).
- **No long-term keys exist anywhere** (D8, D20).

### 3.2 Primitives

No primitive is implemented in mosey (D19). Each is a library call:

| Name here | What | Library |
|---|---|---|
| `HASH(x)` | SHA-256 [FIPS 180-4] | `crypto/sha256` |
| `HKDF(salt, ikm, info, L)` | HKDF-Extract then HKDF-Expand with SHA-256 [RFC 5869] | `crypto/hkdf.Key(sha256.New, ikm, salt, info, L)` |
| `HMAC(k, x)` | HMAC-SHA-256 [RFC 2104] | `crypto/hmac` |
| `SEAL(k, n, ad, p)`, `OPEN(k, n, ad, c)` | ChaCha20-Poly1305 [RFC 8439 §2.8]: 32-byte key, 12-byte nonce, 16-byte tag | `golang.org/x/crypto/chacha20poly1305` |
| `NONCE(n)` | 4 zero bytes, then the 64-bit counter `n` little-endian: 12 bytes. The same layout as Noise's ChaChaPoly (Noise §12.3) | |
| `ENCAP(pk, info)` → `(enc, ss)` | HPKE base mode `SetupBaseS(pk, info)` [RFC 9180 §5.1.1] with KEM `0x647a` (X-Wing, MLKEM768-X25519; draft-connolly-cfrg-xwing-kem, id from draft-ietf-hpke-pq), KDF `0x0001` (HKDF-SHA256) and AEAD `0xFFFF` (export-only, [RFC 9180 §7.3]); then `ss = Export("mosey kem shared secret", 32)` [RFC 9180 §5.3] | `crypto/hpke`: `NewSender(pk, HKDFSHA256(), ExportOnly(), info)`, `Sender.Export` |
| `DECAP(sk, enc, info)` → `ss` | The same with `SetupBaseR` | `crypto/hpke.NewRecipient`, `Recipient.Export` |
| `KEYGEN()` | A fresh X-Wing key pair | `crypto/hpke.MLKEM768X25519().GenerateKey()` |

X-Wing sizes, measured from `crypto/hpke` [S1]:

| | Bytes |
|---|---|
| public key (`s_C`, `s_S`, a rekey key) | 1216 |
| encapsulation `enc` | 1120 |
| shared secret `ss` (our export) | 32 |

`crypto/hpke` is outside the 2025 Trail of Bits audit of Go's crypto
(`DEPENDENCIES.md`, S1 D-4). The HPKE `info` input binds each
encapsulation to the transcript so far: an `enc` lifted from one handshake
gives a different `ss` in any other.

### 3.3 Symmetric state

A Noise `SymmetricState` (Noise §5.2), expressed with RFC 5869 HKDF. Its
fields are a chaining key `ck` (32 B), a hash `h` (32 B), a cipher key `k`
(32 B) and a counter `n` (u64).

```
Initialize(name):     h = HASH(name)            # the name is 46 bytes, over 32, so it is hashed (Noise §5.2)
                      ck = h;  k unset;  n = 0
MixHash(x):           h = HASH(h || x)
MixKey(ikm):          out = HKDF(salt = ck, ikm, "mosey mixkey", 64)
                      ck = out[0:32];  k = out[32:64];  n = 0;  erase out
EncryptAndHash(p):    c = SEAL(k, NONCE(n), ad = h, p);  n = n + 1;  MixHash(c);  return c
DecryptAndHash(c):    p = OPEN(k, NONCE(n), ad = h, c)  or fail;  n = n + 1;  MixHash(c);  return p
Split():              out = HKDF(salt = ck, ikm = "", "mosey split", 96)
                      k_i2r = out[0:32];  k_r2i = out[32:64];  root = out[64:96]
                      erase out, ck, k
```

Two deliberate differences from Noise, both as the spike built and
modelled them:

- **The PSK is mixed with `MixKey`, not Noise's `MixKeyAndHash`.** The PSK
  enters `ck`, and so every later key; it does not enter `h`. The ProVerif
  models are of exactly this (`kdf_ck(proto, psk)`).
- **HKDF is RFC 5869 with a label**, rather than Noise's bare HMAC chain.
  Extract is the same (`HMAC(ck, ikm)`); Expand adds the label, which
  separates the three uses.

`Split` also yields `root`, the chaining key for the first rekey (§6).

**State is copied, not mutated, while a message is processed.** The
receiver of msg1 or msg2 works on a copy of the symmetric state and keeps
it only once the whole message has authenticated and its hello parsed. A
message that fails anywhere leaves the receiver exactly as it was (S1
§1.2, tested by `TestBWrongCredentialsLeaveStateUntouched` and
`TestBTamperEveryByte` in the spike).

### 3.4 Bootstrap inputs

Before the handshake, over SSH (`bootstrap.md` has the line formats):

1. The client runs `KEYGEN()` for its one-shot key `(sk_C, s_C)` and
   writes `s_C` (1216 B) to SSH stdin.
2. The server (proto) runs `Credentials.Mint(sid, s_C)`, which draws:

| Field | Size | How |
|---|---|---|
| `cred_id` | 8 B | `crypto/rand`; re-drawn if it collides with a live credential's [S1] |
| `sid` | 16 B | the terminal session's id: drawn once per session, shared by every credential minted for it (resume, §8) |
| `psk` | 32 B | `crypto/rand` |
| `(sk_S, s_S)` | | `KEYGEN()`, a fresh one-shot key per credential |

   and the server prints `cred_id`, `sid`, `psk` and `s_S` to SSH stdout.
3. Both sides derive the mac1 key (§3.5):
   `K_mac1 = HKDF(salt = sid, ikm = psk, "mosey mac1", 32)`.

Initial state, the same on both sides:

```
Initialize("Mosey_B3_KEMx2psk0_XWing_ChaChaPoly_HKDFSHA256")
MixHash("mosey prologue v1" || sid)        # prologue: 17 ASCII bytes, then the 16-byte sid
MixHash(s_C)                               # pre-message -> s
MixHash(s_S)                               # pre-message <- s
MixKey(psk)                                # psk0
```

### 3.5 msg1

```
offset  size   field
0       1      type = 0x01
1       1      version = 0x01
2       8      cred_id
10      4      idx_C            client's receiver index, u32 LE, nonzero (§4.3)
14      1120   enc1             ENCAP to s_S
1134    3+n+16 c1               EncryptAndHash(hello_c)      n = channel count, 1..16
1153+n  16     mac1
total   1169+n                  1170..1185 bytes
```

The client builds it:

```
hdr1 = 0x01 || 0x01 || cred_id || LE32(idx_C)
MixHash(hdr1)
(enc1, ss1) = ENCAP(s_S, info = h)         # skem
MixHash(enc1);  MixKey(ss1);  erase ss1
c1 = EncryptAndHash(hello_c)
mac1 = HMAC(K_mac1, hdr1 || enc1 || c1)[0:16]
```

- **mac1** is a cheap DoS filter in WireGuard's manner: an HMAC under a key
  only the PSK holder has, checked before any KEM work. It is outside the
  transcript and adds nothing to authentication, which the KEMs and AEAD
  provide. S1 measured a bad mac1 rejected in 3.8 µs against 142 µs for a
  decapsulation [S1 §2.2].
- **msg1 is fixed once built.** The client keeps the bytes and resends them
  unchanged; the server recognises a byte-identical resend (§3.8).
- `idx_C` is drawn fresh for each handshake.

### 3.6 Hello

Inside `c1` and `c2`, encrypted. The grammar is ours and deliberately
small, so msg1 fits in 1200 bytes:

```
offset  size  field
0       1     version     protocol revision; 1 in this document; 0 is invalid
1       1     attach      0 = exclusive (D26); 1..255 reserved
2       1     count       number of channel types, 1..16
3       count channels    channel types, one byte each, strictly increasing
```

| Channel type | Value | Status |
|---|---|---|
| terminal | `0x00` | slice 1 (`handshake.ChannelTerminal`) |
| agent | `0x01` | agent-forwarding slice (D25; `handshake.ChannelAgent`) |
| `0x02`–`0xFF` | | reserved: port forwarding and later channels (D15) |

`ParseHello` is strict: it refuses a short or long input, a count of 0 or
over 16, a version of 0, and channel types that are not strictly
increasing (which also refuses duplicates). Anything it accepts re-encodes
to the same bytes; its fuzz target checks that. It does **not** refuse
unknown channel types or attach modes: those are policy, checked by the
handshake after parsing, so that the parser stays the same as the
registry grows.

Policy:

- The **client** offers every channel type it supports, which in slice 1
  is the terminal alone, and `attach = 0`.
- The **server** refuses a msg1 whose hello lacks the terminal channel or
  asks for an attach mode it does not support. Refusing means sending
  nothing, as for any bad msg1 (§3.8); it logs at Info, because a peer
  that knows the PSK and is still wrong is a bug worth seeing.
- The **server's hello** has its own revision, the attach mode it applied
  (always the client's), and the intersection of the offered channel types
  with its own, in increasing order.
- The **client** refuses a msg2 whose hello names a channel type it did not
  offer, lacks the terminal, or has a different attach mode. That msg2
  authenticated, so the server is genuine and incompatible: Dial fails with
  an error that says so, rather than waiting.
- The session runs at the lower of the two revisions.

Since the server's channels are a subset of the client's, `hello_s` is
never longer than `hello_c`, and msg2 is always at least 20 bytes shorter
than the msg1 it answers (§3.7). The server never sends more than it
receives in the handshake.

### 3.7 msg2

```
offset  size   field
0       1      type = 0x02
1       1      version = 0x01
2       4      idx_S            server's receiver index, u32 LE, nonzero
6       4      idx_C            echoed from msg1
10      1120   enc2             ENCAP to s_C
1130    3+m+16 c2               EncryptAndHash(hello_s)      m = channel count, 1..n
total   1149+m                  1150..1165 bytes
```

The server, continuing from its copy of the state after `c1`:

```
hdr2 = 0x02 || 0x01 || LE32(idx_S) || LE32(idx_C)
MixHash(hdr2)
(enc2, ss2) = ENCAP(s_C, info = h)         # skem
MixHash(enc2);  MixKey(ss2);  erase ss2
c2 = EncryptAndHash(hello_s)
(k_i2r, k_r2i, root) = Split()
```

The client does the mirror image with `DECAP(sk_C, enc2, info = h)` and
`DecryptAndHash(c2)`, then `Split()`.

The **handshake hash** is `h` after `MixHash(c2)`, the last step before
`Split`. It is the same on both sides, never changes for the life of the
connection (a rekey does not touch it), and is what `Conn.HandshakeHash`
returns for quoin-attest to sign (D28). It binds the protocol name, the
sid, both one-shot keys, the credential id, both indices, both
encapsulations and both hellos.

`Keys` for epoch 0: on the client `Send = k_i2r`, `Recv = k_r2i`; on the
server the reverse. `LocalIndex` is the side's own index, `RemoteIndex`
the peer's, `Root = root`, `Hash = h`.

### 3.8 Processing order and the responder's state

The server's `Listener` reads every datagram on its socket. For type
`0x01` it runs these steps **in order of cost**, and a failure at any step
drops the datagram silently, counts the reason, and changes nothing:

1. **Length and header.** The length is 1170 to 1185 and the version byte
   is `0x01`.
2. **Credential lookup.** `cred_id` names a live credential: one map
   lookup, under 0.05 µs with 1000 outstanding [S1 §2.2]. An unknown id
   costs nothing more.
3. **Credential state.** It is neither consumed nor past its TTL.
4. **Resend.** If `HASH(msg1)` equals that of a msg1 this credential has
   already answered, send the cached msg2 to the source (subject to §7.2's
   budget and the address bound below) and stop. A resend creates no new
   state.
5. **mac1**, compared in constant time.
6. **KEM and AEAD**, on a copy of the credential's initial state:
   `DECAP(sk_S, enc1, h)`, `MixKey`, `DecryptAndHash(c1)`.
7. **Hello**: `ParseHello`, then the policy of §3.6.
8. **Commit.** Only now: take `idx_S` from the transport (below), build
   msg2, register `idx_S` in the receiver-index table pointing at the new
   pending handshake, cache `(HASH(msg1), msg2)` with it, and send msg2 to
   the source.

**Who draws indices.** The transport owns the receiver-index table and
`handshake` may not import `transport` (`architecture.md` §1), so the
transport draws every index and hands it in; `handshake` never draws one.
For msg1 the draw has to happen inside step 8, after the checks, because
`idx_S` is in msg2 and so in the transcript: `NewResponder` takes a
`newIndex func() uint32`, which `ReadMsg1` calls at most once, at step 8.
The transport's function draws an index that is not in the table and
**reserves** it. If `ReadMsg1` then fails anyway (say, `crypto/rand`
fails), the transport frees the reservation; if it succeeds, the
reservation becomes the pending's entry. The same rule for the others:
`NewInitiator` takes `idx_C`, `StartRekey(root, idxI)` takes `idx_I'` and
`RespondRekey(root, parts, idxR)` takes `idx_R'` (§6.4), each drawn and
reserved by the transport just before the call.

A **pending handshake** (`handshake.Pending`) is a responder that has sent
msg2 and not been confirmed. It holds the epoch-0 keys, the cached msg2,
the hello, the set of addresses msg2 was sent to (§7.3), and a reference
to its credential.

| Bound | Value | Provenance |
|---|---|---|
| Pending handshakes per credential | 4; when a fifth commits, one of the 4 **chosen uniformly at random** is evicted (keys erased, index freed) | [S1] for the 4; random rather than oldest [ours], so that forged msg1s cannot evict the genuine pending with certainty (see below) |
| Addresses a pending's msg2 is sent to | 4 distinct; a resend from a fifth is dropped | [ours] bounds the per-pending address table |
| Life of a pending handshake | no longer than its credential: when the credential reaches its TTL or is evicted by `MaxUnused` (§10.2), all its pendings are erased with it and their indices freed | D20: a credential "lives 30 s", and everything it vouches for lives no longer |

**Pendings die with their credential.** A pending is the credential's
answer to a msg1; it holds no authority of its own. So the credential's
TTL and its eviction by `MaxUnused` erase its pendings too, and a pending
never outlives the credential that `Confirm` would consume. `Confirm` is
therefore only ever called on a pending whose credential is live and
unconsumed; finding it otherwise is a bug, and the transport drops the
packet and logs at Error rather than confirm. The cost: a client whose
msg2 arrives just before the TTL has only the rest of the TTL to confirm.
Its own deadline (§3.9) is 30 s from reading the credential line, which
is after the mint, so it fails at about the same moment either way.

**A leaked credential line and pending eviction.** Whoever holds the
whole stdout line (T9) can make msg1s the server cannot tell from the
client's: that is `b3_stdout_leak`'s expected failure. Each costs the
server a decapsulation and an encapsulation (about 0.3 ms) and commits a
pending, so 4 forged msg1s arriving between the genuine msg2 and its
confirmation would, under oldest-first eviction, evict the genuine
pending for certain, and the client could not recover. Two rules stop a
handful of forgeries doing that:

- Eviction is random, so each forged msg1 evicts the genuine pending with
  probability 1/4, not 1.
- The client keeps `sk_C` and its handshake state until it is confirmed
  and resends msg1 with each confirmation resend (§3.9). An evicted
  pending's cache goes with it, so the resent msg1 is answered afresh with
  a new pending and a new msg2, which the client accepts.

To lock the client out an attacker must then keep evicting it at every
retry for the whole 30 s, a sustained stream of forged msg1s, each a KEM
pair of server CPU. That is denial of service, not impersonation: no
forged msg1 can ever be confirmed (§3.10). The reserved cookie (`0x06`)
does not help against a PSK holder; a new SSH login, which mints a fresh
credential, does.

**Confirmation** is the first data packet that opens under a pending's
keys (§5). Then, and only then:

1. The credential is **consumed**: `Responder.Confirm`. Its `psk` and
   `sk_S` are erased, every other pending of the credential is erased and
   its index freed, and later msg1s naming it are dropped at step 3. The
   credential's id stays in the table, marked consumed, until its TTL, so
   that step 3 can drop those msg1s cheaply.
2. The client's address is validated as §7.3 says.
3. The connection is returned by `Listener.Accept`. Under D26, every
   other connection of the same `sid` is revoked (§8.3).
4. The confirming packet is then handled as any data packet.

Before confirmation the server **may** send data to the client, at 0.5
RTT: only the holder of `sk_C` can read it (`b3_stdout_leak` holds
server→client secrecy). It counts against §7.2's budget. Slice 1 does not
use this: `Accept` returns only confirmed connections, and SSP starts
there.

### 3.9 The client's side

```
                    Dial
                      |
                      v
   +--------------> AWAIT_MSG2 ---- ctx done, or 30 s since the credential line ----> fail
   | resend msg1      |
   +--- timer --------+  valid msg2 (idx_C matches, DECAP, AEAD, hello policy)
                      v
   +--------------> ESTABLISHED: send keepalive(answer) at once ---- the same deadline ----> fail
   | resend keepalive |   a different valid msg2: replace the epoch-0 keys
   | and msg1         |
   +--- timer --------+  a data packet opens under the epoch-0 keys
                      v
                  CONFIRMED: Dial returns; erase sk_C and the handshake state
```

- **msg1 resends** start at 1 s and double, capped at 4 s. The 1 s is
  RFC 6298 §2.1's initial RTO and matches RFC 9002 §6.2.2's initial PTO
  with its 333 ms initial RTT [RFC]; the 4 s cap is [ours]. The handshake
  messages are 1.2 KB each, and a shorter first timer on a slow link
  would only double them.
- **The deadline** is the credential TTL, 30 s from reading the credential
  line, or `ctx`, whichever is first. The error says no answer came over
  UDP from `addr:port`, since a blocked UDP port is the usual cause.
- **A msg2 that fails** any check changes nothing: the client keeps
  waiting, so injected garbage cannot make it give up (S1 §1.2).
- A msg2 is accepted **from any source address** (§7.1).
- **Confirmation.** The client confirms by sending a data packet: a
  keepalive with "answer requested" (§4.2), sent at once. It resends it
  on the same timer as msg1 (1 s, doubling, capped at 4 s), and with each
  resend it also resends msg1, byte for byte. The client is CONFIRMED
  when any data packet opens under the epoch-0 keys, normally the
  server's keepalive(none): the server sends nothing under them before it
  has confirmed (slice 1 sends no 0.5-RTT data, §3.8; a later slice that
  does must narrow this to the keepalive(none) answer). Without the
  resends, a lost confirmation would let the pending expire, killing the
  session [S1 §1.3, the same failure as the idle rekey responder].
- **Why msg1 is resent too.** If the server has lost the pending (evicted
  by forged msg1s, §3.8), it has lost the msg2 cache with it, so the same
  msg1 is answered afresh: a new pending, a new `idx_S`, a new msg2. In
  ESTABLISHED the client accepts a msg2 that echoes its `idx_C` and
  authenticates from its retained state, replaces its epoch-0 keys and
  `idx_S` with the new ones (erasing the old), and confirms under them. A
  msg2 byte-identical to the one it already accepted (the server's cached
  answer to a resend) is ignored. A msg2 that fails a check changes
  nothing, as before.
- **Dial returns at CONFIRMED**, not at ESTABLISHED. Until then the client
  has no proof that the server holds a connection for it, and a client
  that returned earlier could send into an unknown index for ever with
  nothing to tell it so (§10.3). It costs nothing in practice: the
  server's first SSP datagram follows `Accept`, which follows
  confirmation, so it arrives with the keepalive(none) answer.
- **The deadline covers both states.** Not reaching CONFIRMED within 30 s
  of reading the credential line (or before `ctx` is done) fails Dial,
  with an error that says msg2 arrived but the server never confirmed, as
  distinct from no answer at all.
- **What the client keeps, and until when.** After building msg1 it
  needs only msg1's bytes, `sk_C` and a copy of its symmetric state after
  `c1`, so it erases `psk` and `K_mac1` then. It keeps `sk_C` and the
  state copy until CONFIRMED (or Dial fails), so that it can read a
  re-answered msg2, and erases them then (§9). `handshake.Initiator`
  supports this: `ReadMsg2` may succeed more than once, each time from
  the state after `c1`, and `Initiator.Wipe` erases it.

### 3.10 What the handshake guarantees

From the ProVerif models (`spikes/s1-handshake/proverif/`, ProVerif 2.05,
symbolic, unbounded sessions; `results.txt`). SSH is modelled as
authentic only: both public keys are given to the attacker.

| Property | `b3` (PSK leaks after) | `b3_stdout_leak` (whole stdout line, PSK included, leaks before) |
|---|---|---|
| Client authenticated to server at key confirmation (injective) | holds | **holds** |
| Server authenticated to client, key agreement, no misbinding (injective) | holds | holds |
| Secrecy of client → server data | holds (forward secret) | holds |
| Secrecy of server → client data, including 0.5-RTT | holds (forward secret) | holds |
| msg1 authentic | non-injective only: msg1 is replayable by design, since the server answers replays | **fails, as expected**: anyone with the PSK can make a msg1, which is answered but never trusted |

`b3_noss2_sanity` takes `ss2` out of the keys and the model finds the
attack, so the model can see what the second KEM prevents.

The KEM is modelled as one ideal IND-CCA KEM; that the X-Wing hybrid is
secure if either ML-KEM-768 or X25519 is comes from X-Wing's own proof.
Before 1.0 the models must be extended to the full wire (types, versions,
indices, mac1) and the rekey (§6.6), per PLAN §6.5.

## 4. Data packets

### 4.1 Layout

```
offset  size     field
0       1        type = 0x04
1       4        receiver index, u32 LE: the receiver's own index for this epoch
5       8        counter, u64 LE: the sender's packet number under this key
13      1+len    ciphertext of: kind (1 byte) || body (len bytes)
13+1+len 16      Poly1305 tag
total   30+len   len ≤ 1202
```

```
ad    = bytes 0..12 (the 13-byte clear header)
nonce = NONCE(counter)
sealed = SEAL(send key, nonce, ad, kind || body)
```

- **Overhead** is 30 bytes: 13 header, 1 kind, 16 tag
  (`transport.Overhead`). **`MaxPayload` = 1232 − 30 = 1202** [derived],
  the largest terminal payload `Conn.Send` accepts and what SSP is
  configured with (`ssp.Config.MaxPayload`).
- **One frame per packet.** There is no multiplexing of frames inside a
  packet: the parser is one byte and a body.
- **The counter is the nonce.** Each direction of each epoch has its own
  key (§3.7, §6.3), so a (key, nonce) pair repeats only if a sender reuses
  a counter. A sender starts each key's counter at 0, adds 1 for every
  packet it seals, never seals with the same counter twice, and keeps
  counters only in memory (D8). A process that loses its counters has
  lost its keys too.
- The minimum data packet is 30 bytes (an empty body). A packet under 30
  or over 1232 bytes is dropped before lookup.

### 4.2 Frame kinds

The kind is the first byte of the plaintext. These match `transport.Kind`.

| Kind | Name | Body | Packet size | Acted on under | Status |
|---|---|---|---|---|---|
| `0x00` | TERMINAL | an SSP datagram for the terminal channel, 0–1202 B (`ssp.md`) | 30–1232 | any live receive key | slice 1 |
| `0x01` | REKEY_INIT_1 | `idx_I'` (4) ‖ `pk_I[0:608]` (608) = 612 B | 642 | current epoch only | slice 1 |
| `0x02` | REKEY_INIT_2 | `idx_I'` (4) ‖ `pk_I[608:1216]` (608) = 612 B | 642 | current epoch only | slice 1 |
| `0x03` | REKEY_RESP | `idx_R'` (4) ‖ `enc` (1120) = 1124 B | 1154 | current epoch only | slice 1 |
| `0x04` | KEEPALIVE | 1 B: `0x01` = answer requested, `0x00` = no answer | 31 | any live receive key | slice 1 |
| `0x05` | PATH_CHALLENGE | 8 random bytes | 38 | any live receive key | slice 1 |
| `0x06` | PATH_RESPONSE | the 8 bytes of a challenge | 38 | any live receive key | slice 1 |
| `0x07` | CHAFF | any bytes, ignored | 30–1232 | any live receive key | reserved: D11, O10 |
| `0x08` | CHANNEL | channel id (u32 LE) ‖ datagram | ≤ 1232 | any live receive key | reserved: D15 agent and later channels; the agent slice fixes the body |
| `0x09` | REVOKED | §8.3 | 45 or 57 | any live receive key | reserved for resume (D26) |
| `0x0A`–`0xFF` | | | | | reserved |

Rules for every kind:

- **A body of the wrong length** for a known kind is ignored, after the
  packet has authenticated. The packet still counts as authentic for
  replay (it is committed) and for paths (§7).
- **An unknown kind** is ignored in the same way. That is what lets a
  later slice add kinds; it is safe because only the peer could have
  sealed it.
- **Only TERMINAL reaches SSP** through `Conn.Recv`. The transport handles
  the others itself.
- **KEEPALIVE(answer requested)** is answered with exactly one
  KEEPALIVE(none) under the receiver's *current* keys, once per received
  packet; a KEEPALIVE(none) is never answered. One 31-byte answer per
  31-byte request, so it amplifies nothing. It is used for handshake
  confirmation (§3.9), rekey confirmation (§6.4) and a local address
  change (§7.4). *This widens `frame.go`'s comment, which names only the
  rekey use.*
- **PATH_CHALLENGE** is answered with one PATH_RESPONSE carrying the same
  8 bytes, sent to the receiver's normal destination (the client always
  sends to the server's one address, §7.1). A server that receives one
  answers it too, for O6.
- **CHAFF** is accepted and dropped. Its tick and sizes are O10's.

### 4.3 Receiver indices

- Each side picks the index its peer puts on packets to it, as in
  WireGuard [WG §5.4]: a random nonzero u32, re-drawn if it equals any
  index the side currently has registered. 0 is never valid.
- **Why**: the index routes a packet to its connection and key before the
  source address is trusted (roaming, NAT rebinding, O6), lets one socket
  serve many sessions and handshakes, and is drawn afresh for every epoch
  so an observer cannot link epochs by it [S1 §1.1].
- **Who draws.** The transport draws every index and passes it into
  `handshake` (§3.8), since only it can see the table.
- **Lifetime.** An index is **reserved** when it is drawn (msg1 for
  `idx_C`, step 8 of §3.8 for `idx_S`, a rekey's start for `idx_I'`, its
  answer for `idx_R'`), gets its key set when the keys exist, and is
  freed when those keys are erased (§9), or when the call it was drawn
  for fails. Each index maps to exactly one entry: reserved, a pending
  handshake, or one key set of one connection. A packet whose index is
  reserved but has no key set yet (an initiator's `idx_I'` before its
  REKEY_RESP has arrived, say) is dropped, counted as an unknown index.
- **The server** keeps one table for its socket, covering pending
  handshakes and every connection. **The client** has one connection, but
  checks the index all the same.

## 5. Receiving a data packet

The order is fixed. It is the lesson of the flynn/noise advisory
(GHSA-g9mp-8g3h-3c5c): no state moves until the packet has authenticated.

1. **Size** is 30 to 1232 and the type is `0x04`.
2. **Index lookup.** The receiver index names a registered key set:
   a pending handshake's (server), or a connection's `cur`, `next` or
   `prev` (§6.1). Otherwise drop.
3. **Counter** is below `RejectAfterMessages` (§10).
4. **Replay check**: `replay.Window.Check(counter)` on that key set's
   window. Pure; it changes nothing.
5. **Open** the AEAD with that key set's receive key, `ad` = the header,
   `NONCE(counter)`. A failure adds 1 to the key set's failure count
   (§10) and drops; nothing else changes.
6. **Only now**, in this order:
   1. `Window.Commit(counter)`.
   2. If the key set is a pending handshake's: confirm it (§3.8).
   3. If it is `next`: promote it (§6.4).
   4. If it is `cur` and a rekey confirmation is awaited: stop awaiting
      (§6.4).
   5. Path bookkeeping (§7), with "newest" meaning this packet raised the
      window's highest counter.
   6. Act on the frame (§4.2).

A test MUST show that a rejected packet changes neither the window, the
keys, the epoch, the peer address, the amplification counters nor any
rekey or path state. That is the `transport` fuzz target's invariant too.

**Replay window**: RFC 6479's ring of bitmap blocks, 32 blocks of 64 bits,
accepting counters up to 1984 below the highest seen (one block is slack)
[RFC 6479 §2; size S1]. Any counter above the highest is new. Check and
Commit are separate calls (`internal/replay`). One window per receive key;
a new key starts with an empty window.

## 6. Rekey

### 6.1 Key sets

A connection holds up to three key sets, each with its own send key,
receive key, local and remote index, send counter, replay window and
install time:

| Key set | Used to send | Used to receive | Exists |
|---|---|---|---|
| `cur` | yes | yes | always, until the connection is closed or revoked |
| `next` | no | yes: a packet under it promotes it | on a rekey responder, between REKEY_RESP and confirmation |
| `prev` | no | yes, for `KeepPrevFor` | after a rotation, so packets in flight under the old keys still land |

Plus the `root` of the current epoch, and at most one rekey in flight
(`pend` on an initiator, the cached answer on a responder).

The epoch number counts rotations from 0 (the handshake). It is local, is
never sent, and is what `transport.Rekeyed` reports.

### 6.2 When

| Trigger | Value | Provenance |
|---|---|---|
| Client starts a rekey once `cur` is this old, checked whenever it sends | `RekeyAfter` = 120 s | [WG] REKEY_AFTER_TIME; D20 |
| Server starts one once `cur` is this old, checked whenever it sends | `RekeyAfter` + 10 s = 130 s | [ours] a backstop: the client normally goes first, so the two rarely collide, but a client that never rekeys still gets rekeyed |
| Either side, once its send counter under `cur` reaches | `RekeyAfterMessages` = 2^60 | [WG] REKEY_AFTER_MESSAGES; D20's "N packets" |

- **No rekey is triggered by idleness** (D20). The check runs when the
  side sends something, and SSP's 3 s heartbeat (D11) means a live
  connection always does.
- **`RejectAfterTime` = 180 s** [WG REJECT_AFTER_TIME]: a side never
  seals a **TERMINAL** (or, later, CHANNEL) frame under a `cur` that it
  installed this long ago. Everything the rekey and the paths need keeps
  flowing under that `cur`: REKEY_INIT, REKEY_RESP, KEEPALIVE,
  PATH_CHALLENGE, PATH_RESPONSE and REVOKED. `Conn.Send` returns
  `ErrBlocked`, which SSP treats as a loss and retries (§7.2), and the
  transport reports `RekeyOverdue{Age}` on `Conn.Events` once when the
  limit is crossed. The client tells the user as it does a screen reset
  (`screen.md` §8.4: in slice 1 the log, and stderr when the session
  ends; a later slice may draw a banner); the frozen terminal is the
  live signal. Received TERMINAL frames
  are still accepted: the limit is on what a side seals, and each side
  enforces it for itself.
- **Why it is needed.** Without it, an on-path attacker could drop only
  the rekey frames, whose sizes and timing stand out (two 642-byte
  packets back to back each `RekeyRetry`, a 1154-byte answer), and the
  epoch would live for ever while terminal traffic flowed and nothing
  noticed, silently voiding the forward-secrecy bound of
  `threat-model.md` §4.3 and R3. With it, the attack turns into a visible
  stall of the terminal, which is a denial of service such an attacker
  could cause anyway by dropping everything.
- **Why it does not break outages.** WireGuard answers a stale epoch with a
  fresh handshake; mosey can't do one without a new SSH login. It does
  not need to: the rekey frames are exempt, a rekey started during the
  outage keeps retrying (§6.4), and when packets flow again it completes
  within a round trip or two, after which TERMINAL frames resume under the
  new epoch. A long outage costs that extra round trip, nothing more.
  180 s leaves 60 s past the client's `RekeyAfter` (50 s past the
  server's) for a rekey to finish on a healthy link, where it needs about
  one RTT.
- **The bound this gives.** Terminal data sealed under one epoch spans at
  most `RejectAfterTime`, so a memory compromise (T8) exposes at most
  180 s + `KeepPrevFor` (10 s) of terminal traffic in the worst case, and
  about 120–130 s + 10 s in the normal case. `threat-model.md` §4.3
  states only the normal case; it should add the worst case (Review
  notes, R3).
- **Padding the rekey frames** is not done in v1. Their timing (a pair
  every second, once every two minutes) singles them out as surely as
  their sizes do, so padding alone would not hide them; hiding both is
  traffic shaping, which is O10's (CHAFF). The limit above is what makes
  the fingerprint harmless.
- **No new rekey starts** while one is in flight in either role: while
  `pend` exists, while `next` exists, or while a confirmation is awaited
  [S1 §1.3].

### 6.3 Derivation

The initiator I draws a fresh X-Wing key `(sk_I, pk_I)` and a new receiver
index `idx_I'`. The responder R answers with `idx_R'` and an
encapsulation. Both then compute:

```
rh   = HASH("mosey rekey v1" || root || LE32(idx_I') || pk_I)
(enc, ss) = ENCAP(pk_I, info = rh)                       # R;  I does ss = DECAP(sk_I, enc, rh)
out  = HKDF(salt = root, ikm = ss,
            info = "mosey rekey keys" || rh || enc || LE32(idx_R'), 96)
k_I→R = out[0:32];   k_R→I = out[32:64];   root' = out[64:96]
erase ss, out
```

- `root` is the current epoch's root (`Split`'s for epoch 0). It chains
  one way, so the new keys are forward secret from the old ones once the
  old root is erased (§9).
- The new keys depend on a fresh KEM exchange, so an attacker who learned
  the old keys and then **went passive** loses the session from the next
  epoch (post-compromise security against a passive attacker only, which
  is inherent to any in-band rekey [S1 §3.1]). An active attacker holding
  the keys can answer the rekey itself; recovery from that is an exclusive
  re-attach over a new SSH login (§8).
- The rekey's own transcript (`rh`, `enc`, `idx_R'`) is bound into the
  keys, and every rekey frame travels sealed under the current keys, so
  only the peer can have sent it.
- The handshake hash `h` (D28) does not change.

"Initiator" and "responder" here are rekey roles, independent of who was
client: the client's `Send` key in the new epoch is `k_I→R` if the client
started the rekey, `k_R→I` if the server did.

### 6.4 Exchange

```
I                                                          R
  REKEY_INIT_1 { idx_I', pk_I[0:608] }      sealed under cur  ->
  REKEY_INIT_2 { idx_I', pk_I[608:1216] }   sealed under cur  ->
                                           both halves with the same idx_I':
                                           derive; install next (receive only);
                                           cache the answer
                <-  REKEY_RESP { idx_R', enc }            sealed under cur
  derive; rotate: prev = cur, cur = new;
  await confirmation
  KEEPALIVE(answer requested)               sealed under the NEW cur ->
                                           opens under next: promote:
                                           prev = cur, cur = next
                <-  KEEPALIVE(none)                       sealed under the new cur
  any packet under the new cur: confirmed
```

**Why INIT is split (D20).** The INIT carries a 1216-byte public key; with
a 4-byte index and 30 bytes of framing that is 1250 bytes, over D5's 1200
[S1 §2.1]. Two halves of 642 bytes each fit, and each is sealed under the
current keys. Equal halves keep both datagrams small. Both carry `idx_I'`,
which names the INIT so the responder can pair them.

**Initiator.**

1. **Start**: the transport draws `idx_I'` and reserves it (§4.3; the
   responder's confirmation ack will use it), then
   `handshake.StartRekey(root, idxI)` runs `KEYGEN()` and builds both INIT
   parts, which are sent back to back under `cur`. Keep
   `pend = (sk_I, pk_I, idx_I')`.
2. **Resend** both parts, freshly sealed, every `RekeyRetry` (1 s [S1])
   until a REKEY_RESP is accepted. There is no give-up: a rekey in flight
   survives an outage and finishes when packets flow again.
3. **On REKEY_RESP** under `cur`, with a body of exactly 1124 bytes and a
   `pend`: `DECAP`, derive, then rotate: wipe any old `prev`, `prev = cur`
   (receive only, wiped after `KeepPrevFor`), `cur` = the new key set,
   `root = root'`, erase `pend`. A REKEY_RESP with no `pend`, or whose
   `DECAP` fails, is ignored.
4. **Confirm**: send KEEPALIVE(answer requested) under the new `cur` at
   once, and resend it every `RekeyRetry` until any packet opens under the
   new `cur`. Without the resend, an idle responder whose first keepalive
   was lost would never promote; without the answer, an idle initiator
   would never know [S1 §1.3, both found by the interleaving property
   test].

**Responder.**

1. **Collect.** An INIT part under `cur` with a 612-byte body goes into
   the one reassembly slot, keyed by its `idx_I'`. A part with a different
   `idx_I'` replaces the slot's contents. When the slot holds both halves
   of one `idx_I'`, the INIT is `(idx_I', pk_I = half1 || half2)`; the slot
   is then cleared. The slot is also cleared on every rotation. Memory is
   bounded at one slot of 1220 bytes [ours].
2. **Decide.**
   - `cur` was installed less than `RekeyMinEpochAge` (1 s) ago: ignore
     the INIT. A genuine initiator resends every `RekeyRetry`, so this
     costs it at most a second; a hostile but authenticated peer (T5
     against the client, a hostile client against proto) can then force
     at most one KEYGEN-and-ENCAP answer per second, instead of one per
     round trip (`threat-model.md` §4.3's floor).
   - Awaiting confirmation of its own rotation as an initiator: ignore the
     INIT. It finishes that first.
   - The INIT is the one it already answered (same
     `HASH(idx_I' || pk_I)`): resend the cached REKEY_RESP, freshly
     sealed, and derive nothing.
   - A different INIT while `next` is unconfirmed: ignore it.
   - It has its own `pend` (both sides started at once): **the client's
     rekey wins.** The client ignores the server's INIT; the server erases
     its `pend`, frees `idx_I'`, and answers the client's.
3. **Answer**: the transport draws and reserves `idx_R'` (§4.3), then
   `handshake.RespondRekey(root, parts, idxR)` does the `ENCAP` and
   derives (`idx_R'` is in the HKDF info, so it must be known first);
   install `next` for receiving only, cache
   `(HASH(idx_I' || pk_I), REKEY_RESP body, root')`, send REKEY_RESP under
   `cur`.
4. **Promote** on the first packet that opens under `next`: wipe any old
   `prev`, `prev = cur`, `cur = next`, `root = root'`, drop the cache.
   That first packet is normally the initiator's KEEPALIVE(answer
   requested), answered under the new `cur`.

**Only current-epoch rekey frames count.** REKEY_INIT and REKEY_RESP are
acted on only when they open under `cur`. Under `prev` they are ignored
(their counters are still committed). A delayed INIT from the previous
epoch would otherwise make the responder derive a `next` from the new
root, and its guard would then ignore the initiator's real INIT for ever
[S1 §1.3, the first bug the property test found].

### 6.5 Rekey timers and bounds

| Constant | Value | Provenance |
|---|---|---|
| `RekeyAfter` | 120 s | [WG]; D20 |
| Server's start, past `RekeyAfter` | +10 s | [ours] |
| `RekeyAfterMessages` | 2^60 | [WG] |
| `RekeyRetry` (INIT and confirmation resends) | 1 s | [S1], untuned |
| `RejectAfterTime`: no TERMINAL or CHANNEL frame is sealed under a `cur` this old | 180 s | [WG] REJECT_AFTER_TIME; §6.2 |
| `RekeyMinEpochAge`: a responder ignores an INIT under a `cur` younger than | 1 s | `threat-model.md` §4.3 (its "responder floor", [ours]) |
| `KeepPrevFor` | 10 s | [S1], untuned: long enough for packets in flight at any RTT SSP copes with |
| Reassembly slots for INIT halves | 1 | [ours] |

### 6.6 What the rekey has been checked against

- `TestRekeyInterleavingsProperty` in the spike drove 2000 random schedules
  (0–40% loss, duplication, reordering, crossing rekeys, clock jumps),
  12,664 rekeys, and checked that no genuine packet ever failed to
  authenticate and that after the network healed both roots matched, no
  rekey was in flight and data flowed both ways [S1 §1.3]. The production
  transport MUST carry an equivalent property test over netsim, extended
  to the split INIT (lose, duplicate and reorder each half separately).
- **There is no formal model of the epoch chain yet.** Its secrecy is
  argued, not modelled (S1 §3.1). A ProVerif or Tamarin model of the
  rekey is owed before 1.0 (PLAN §6.5).

## 7. Paths

### 7.1 The client

- The client sends every datagram to one address: the one from the
  credential line (or the user's override). It never changes it.
- It uses an **unconnected** UDP socket and accepts msg2 and authentic data
  packets from any source address. A multi-homed or NATed server may
  answer from an address the client did not send to, and the
  authentication, not the address, says who sent it. Junk from other
  sources costs a lookup at most.
- It sends no PATH_CHALLENGE of its own in v1; the server does not roam.

### 7.2 Anti-amplification (D21)

The server tracks, for each address it might send to but has not
validated, the bytes received from it and the bytes sent to it, counting
whole UDP payloads.

- **Only proven bytes count as received**: data packets that
  authenticated, and msg1s that passed step 6 of §3.8 or are resends of
  one that did (step 4). Garbage from a spoofed address earns no budget.
- **A send to an unvalidated address happens only if** `sent + size ≤ 3 ×
  received` [RFC 9000 §8.1]. Otherwise it is not sent. `Conn.Send` returns
  `ErrBlocked` for a terminal payload held back; SSP counts it as lost and
  sends the current state again later, which is what the limit wants.
- **Everything sent there counts**: msg2, path challenges, copies of
  terminal frames.
- **A validated address has no limit.**

### 7.3 The server's state machine (D21)

The server holds, per connection:

- `peer`: the validated address, or none.
- `cand`: at most one candidate address, with a random 8-byte `token`,
  its received and sent byte counts, the time of its last challenge and
  the current retry interval.

**At confirmation** (§3.8), let `S` be the set of addresses the pending's
msg2 was sent to, and `X` the confirming packet's source.

- If `S = {X}`: `peer = X`, validated. msg2 went only to `X`, and the
  confirming packet, which only a holder of msg2's keys can seal, came
  back from `X`: that is a round trip through `X`, as a path challenge
  would be [S1 §1.5].
- Otherwise (`X ∉ S`, or `S` has several addresses because a msg1 was
  resent or replayed from more than one): `peer` = none, and `X` becomes
  `cand` with a fresh token, its received and sent counts carried over
  from the pending's, and a PATH_CHALLENGE sent to it at once.

The confirming packet's keys show only that *someone* read msg2, not that
it was read at an address in `S`: the client accepts msg2 from any source
(§7.1), so an attacker who re-sourced the client's msg1 from a victim `V`
(making `S = {V}`) and relayed the msg2 it saw going to `V` back to the
client would, under a rule that trusted `S` alone, get `V` validated with
no limit, the very reflector D21 exists to stop. Requiring the
confirmation to come back from the one address msg2 went to means that
attacker must also spoof the confirming packet's source and win its race,
which is the residual stated under "On a PATH_RESPONSE" below.

**On each authentic data packet** under the key set that is current once
the packet has been handled (so not under `prev`), from address `Z`, that
raised the window's highest counter ("newest"):

| Case | Action |
|---|---|
| `Z == peer` | nothing |
| `Z == cand` | add the packet's size to `cand`'s received bytes |
| otherwise | `cand = Z` with a fresh token, received = the packet's size, sent = 0; send a PATH_CHALLENGE to `Z` at once |

A packet that is not the newest (reordered, or delayed while another copy
won the race) moves nothing; its frame is still handled. That is what stops
a reordered old packet dragging the server back [S1 §1.5].

**On a PATH_RESPONSE** whose 8 bytes equal `cand`'s token, compared in
constant time, **and that arrived from `cand`'s address**: `peer = cand`,
validated; `cand` = none; report `PeerChanged{From, To}`. A response with
any other token, or with the right token from any other address, is
ignored (its packet is still handled by the table above, so it may
itself make its source the new `cand`). This is stricter than QUIC, which
accepts a response on any path [RFC 9000 §8.2.3], and it is
`threat-model.md` §4.4 item 3's rule. The reason: the client answers a
challenge that reaches it from any source (§7.1), so with QUIC's rule an
attacker who re-sourced one client packet from a victim `V`, and relayed
the challenge the server then sent to `V` back to the client, would get
`V` validated by relaying alone. S4 §3.7 recorded the same relay defeating
validation in layout B.

**The residual.** An attacker who both sees what the server sends and can
spoof source addresses, and so relays the challenge to the client and
re-sources the client's response from `V`, can still validate `V`, as it
can the confirmation above. Validation cannot stop that attacker; RFC
9000 §9.3.3 makes the same concession for QUIC. It has to keep winning the
race with every client packet to keep the stream on `V`, and the genuine
client's next newest packet from its own address otherwise starts a
validation that brings the stream back. `threat-model.md` §4.4 should
record this residual (Review notes).

**Challenge resends.** While `cand` exists and has not answered, the
challenge is resent with the same token on a timer, first after 250 ms,
then doubling, capped at 1 s, each send subject to §7.2. After 10 s with no
answer `cand` is dropped. [ours, untuned: 250 ms sits above D11's
effective RTO floor of about 150 ms; the 1 s cap is D11's RTO cap. S5
found that waiting for the client's next datagram to resend a lost
challenge made the roam tail 4.3–6.2 s on the train profile (S5 §6);
D21 asks for a timer.] Netsim's roaming tests should retune these. The
transport has no RTO of its own (SSP owns RTT estimation, D11), so this
fixed schedule stands in for `threat-model.md` §4.4's "at most once per
RTO": it never resends faster than D11's RTO floor, and every resend is
inside §7.2's 3x budget whatever the timer, so the schedule cannot raise
what a victim receives. The threat model's wording should point here
(Review notes).

**Sending.** Every packet goes to `peer` if there is one. While `cand`
exists, a copy also goes to `cand` within its budget, so a client that
really has moved is not kept waiting a round trip for validation [S5,
`ssp/path.go`]. With no `peer`, packets go only to `cand`, within budget.
The old peer keeps receiving everything until the new address is
validated.

**What this stops.** An attacker who can see the client's packets and
spoof sources can copy one, re-send it from a victim's address and win the
race. Under the paper's "newest authentic source" rule that pointed the
whole screen stream at the victim: S5 measured 29x amplification (1.3 MB
for 44 kB sent) and the real client cut off. With these rules the victim
received 2.96x and the client was unaffected [S5 §6]. Such an attacker can
still deny service, as any on-path attacker can by dropping packets.

### 7.4 Local address changes

When the client learns its own address changed (netlink on Linux, D21;
`Conn.LocalAddressChanged`), it sends a KEEPALIVE(answer requested) at
once instead of waiting for SSP's next datagram, so the server sees the
new address and starts validating it. S5 measured the repair tail of a
roam at 2.2–2.5 s when an idle client waited for its 3 s heartbeat (S5 §6,
Q7). The answer, under §7.3's sending rule, reaches the new address
within its budget.

## 8. Resume (D8) and revocation (D26)

Resume is a later slice. Its wire format is fixed here so slice 1 doesn't
rule it out; nothing below is built in slice 1 except what §8.3 marks.

### 8.1 Resume is a new handshake

D8: never save transport or crypto state to disk, and rekey through an
authenticated local channel when resuming. In mosey a resume is an
ordinary B3 handshake whose credential was vouched for by a new SSH login
[S1 §1.4]. **The local channel, its socket and its messages belong to
`bootstrap.md` §9.2 and `server.md`**; this section only says what the
transport needs from them, and where the three disagree, those two win.

1. The new client (another device, or the same one after a reboot) makes a
   fresh one-shot key and bootstraps exactly as for a new session: SSH
   runs the ordinary `mosey --serve`, and the ClientLine carries `s_C`
   and `attach=resume:SID` (`bootstrap.md` §6.2, §9.2). There is no other
   flag or role (D7).
2. **The local channel** is the session's attach socket,
   `$XDG_RUNTIME_DIR/mosey/SID-HEX/attach.sock` (with `bootstrap.md` §8's
   fallback when `XDG_RUNTIME_DIR` is unset), in a 0700 directory owned
   by the user. It is owned and listened on by the session's **spawner**,
   which is unsandboxed; proto, under Landlock deny-all (D22), cannot
   create or bind a filesystem socket and must not be made able to,
   since it holds the keys. The spawner checks the connecting process's
   uid with `SO_PEERCRED` against its own and refuses any other. That is
   the authentication: the SSH login proved the user, and the kernel
   proves the connecting `mosey --serve` is that user.
3. The spawner forwards the client's `s_C` (and terminal size) to proto
   over IPC (`server.md` §3.2, the reserved `Resume` message, 0x05), and
   proto mints a fresh credential for the **same `sid`** (§3.4), bound to
   the new `s_C`, with a new `cred_id`, `psk` and `s_S`. The usual TTL and
   cap of 2 unused per session apply. The credential comes back as
   `server.md`'s `Credential` message (0x30): the whole credential line,
   address and port included, which the ssh-started `mosey --serve`
   prints exactly as for a new session.
4. The client runs §3's handshake against the same UDP port. The
   prologue binds the same `sid`, so the new connection belongs to the
   same session. **Nothing from any old connection is reused:** the keys,
   root, indices and counters are all new. That is the resume rekey.
5. On confirmation the new connection is attached and, under D26, every
   other connection of the session is revoked (§8.3). SSP starts the
   screen from scratch on the new connection (`ssp.md`).

This document defines no local wire message of its own: the attach
socket's protocol and the `Resume` IPC message are `server.md`'s and
`bootstrap.md`'s, fixed by the resume slice. What the transport requires
of them: the request carries `s_C` and asks for an exclusive attach (D26);
the answer is a whole credential line, so it carries the address and port
MOSEY-CONNECT needs; every buffer holding the PSK is erased once written
or parsed (§9); and the parsers are exact-length and fuzzed.

### 8.2 Why this is safe

- **A leaked credential line** is no more use on resume than at bootstrap
  (`b3_stdout_leak`).
- **A stolen or compromised client is cut off** only by an exclusive
  attach, which revokes it and erases its keys [S1 §3.1]. A plain rekey
  can't do that: an attacker holding the keys can answer it. D26 makes
  every attach exclusive in v1.

### 8.3 Revocation

When a connection of a session is confirmed, `Listener.Accept` revokes
every other connection of that `sid` (D26). In slice 1 a session mints
one credential, so this never fires; the code path exists and is tested.

To revoke a connection the server:

1. Seals **4 REVOKED frames** under its `cur`, with consecutive counters,
   and sends the first to its `peer` (or its `cand`, within budget) [ours:
   enough for a lossy link; see below].
2. **Erases every key** of the connection: `cur`, `next`, `prev`, `root`,
   any rekey in flight (§9).
3. Keeps a **tombstone** for 60 s [ours]: the connection's local indices
   map to the 3 remaining sealed REVOKED packets and nothing else. Each
   data packet that arrives for a tombstoned index (not opened: there is no
   key) causes the next sealed copy to be sent to that packet's source, at
   most one per 250 ms and only if it is no more than 3x the size of the
   packet that arrived (§7.2's factor).
   When the copies run out, or after 60 s, the indices are freed.

The pre-sealed copies are what let a revoked client learn why it was cut
off, despite its keys being gone straight away and a lost first copy.
They are sealed under keys only that client holds, so a third party
learns nothing from them; a spoofed packet can draw at most three of them.

REVOKED body:

```
offset  size  field
0       8     at: unix time in milliseconds, u64 LE, of the new attach
8       1     family: 4 or 6
9       4|16  address of the new client
13|25   2     port, u16 LE
total   15 or 27 B (packet 45 or 57 B)
```

The revoked client reports `transport.Revoked{By, At}`, says "session taken
over from <addr> at <time>" and exits (D26). Any other family value, or a
wrong length, is ignored like any malformed body (§4.2).

## 9. Erasing secrets

Secrets are **erased**, not dereferenced (S1 §3.2): overwritten with
`clear` on a buffer mosey owns, at the moment named. Copies are made only
where needed, and the source of a copy is cleared once the copy is made
(the spike's `newSession` and `rotate` take pointers for this).

| Secret | Who | Erased when |
|---|---|---|
| `sk_C` (client one-shot key), and the client's copy of its symmetric state after `c1` | client | CONFIRMED (§3.9), or Dial fails or is cancelled |
| `psk` | client | msg1 is built, or Dial fails |
| `psk`, `sk_S` | server | the credential is consumed (§3.8), reaches its TTL, or is evicted by the cap |
| `K_mac1` | both | with the `psk` |
| buffers holding a marshalled credential (line, IPC message, resume response) | all | as soon as written or parsed |
| `ss1`, `ss2`, HKDF outputs, the symmetric state `ck`, `k` | both | in the step that consumes them (§3.3, §3.5, §3.7); a working copy of the state that failed is cleared too |
| pending handshake keys | server | confirmation consumes another pending, eviction, or its credential reaches its TTL or is evicted (§3.8) |
| client epoch-0 keys replaced by a re-answered msg2 | client | when replaced (§3.9) |
| `sk_I` (rekey key) | rekey initiator | the REKEY_RESP is processed, or the `pend` is abandoned in a collision |
| `ss`, `out` of a rekey | both | when derived (§6.3) |
| `root` | both | replaced by `root'` at each rotation; the old one cleared |
| cached `root'` on a responder | responder | promotion, or the cache is dropped |
| `prev` keys | both | `KeepPrevFor` after rotation, or at the next rotation if sooner |
| all key sets and `root` | both | `Conn.Close`, revocation (§8.3) |
| path tokens | server | when `cand` is dropped or validated (not secret long-term, but no reason to keep) |

**What Go can't erase.** A `crypto/hpke` private key (`sk_C`, `sk_S`,
`sk_I`) has no zeroising API, and its `Bytes()` returns the internal seed
slice, so clearing that would erase the seed but not the expanded keys
(S1 §3.2). Dropping the reference is all the code can do directly.

**`runtime/secret`.** D20: linux release builds (amd64 and arm64) use
`GOEXPERIMENT=runtimesecret`, and run key generation, minting, msg1,
msg2, `StartRekey`, `RespondRekey` and `Finish` inside `secret.Do`. It
erases registers and stack when the function returns, and heap
allocations made inside it once the GC finds them dead. S1 measured a
dropped X-Wing seed still in process memory after two GCs in 20/20 trials
by default, and in 0/20 with `secret.Do` [S1 §3.2]. Keys that must outlive
the call (transport keys, the root) are copied into the connection's own
arrays and erased by the rules above.

**The claim, stated honestly.** On linux release builds, the secrets above
are erased when listed (mosey's own buffers) or once the GC reuses the
memory under `secret.Do` (library-held keys). On other platforms and
other builds, the library-held keys are erased only "once the GC reuses
the memory". The credential TTL bounds how long an unused `sk_S` lives.
Forward secrecy is only as good as this.

**Never written anywhere.** No key, PSK, root, counter or credential is
written to disk, logged, or put in an error message (D8). A `cred_id` and
`sid` are public (the id is in msg1's clear header) and MAY be logged, the
id in hex. proto runs with `PR_SET_DUMPABLE=0` (D22, `server.md`).

## 10. Limits and failures

### 10.1 Per-key limits

| Constant | Value | Provenance |
|---|---|---|
| `RejectAfterMessages`: a sender never seals with, and a receiver drops, a counter at or above | 2^64 − 2^13 − 1 | [WG] REJECT_AFTER_MESSAGES; leaves room above the replay window so a counter never wraps |
| `RekeyAfterMessages` | 2^60 | [WG] |
| Packets sealed under one ChaCha20-Poly1305 key | far under the 2^62 confidentiality limit | [RFC 9001 §6.6] |
| Failed opens under one receive key before the connection is closed | 2^36 | [RFC 9001 §6.6] integrity limit for AEAD_CHACHA20_POLY1305. Unreachable in a 120 s epoch at any real packet rate, but counting is cheap and makes the bound hold whatever the rekey does |

A send at the counter limit fails with an error rather than reusing a
nonce. With the 120 s rekey neither counter limit is reached in practice.

### 10.2 Credential limits

| Constant | Value | Provenance |
|---|---|---|
| `CredentialTTL` | 30 s from mint | [S1]: SSH stdout to UDP plus retransmissions; D20 |
| `MaxUnused` per session | 2; minting a third evicts the oldest, which is logged at Info | [S1]; D20 |
| Pending handshakes per credential | 4, a random one evicted | [S1]; random [ours], §3.8 |
| Addresses per pending | 4 | [ours] |
| Pending life | until its credential reaches its TTL or is evicted | D20; §3.8 |
| `cred_id` | 8 bytes | [S1] |

### 10.3 Handling failures

- **Nothing unauthenticated is ever answered**, except msg2 to a msg1
  that passed every check of §3.8 (or a resend of one). There are no
  error messages on the wire: an error would be either unauthenticated,
  and so forgeable, or a hint to an attacker.
- **Every drop is counted** by reason (malformed, unknown index, unknown
  credential, replay, authentication, wrong state) for tests and
  debugging, and logged at Debug at most once a second per reason, so a
  flood cannot fill the log.
- **Nothing reaches SSP** but TERMINAL payloads, `ErrBlocked` from `Send`,
  and `net.ErrClosed` after Close or revocation. Events (`PeerChanged`,
  `Rekeyed`, `RekeyOverdue`, `Revoked`) go to `Conn.Events`.
- **Fatal for a connection**: revocation, `Close`, the failure count
  reaching 2^36, or a counter reaching `RejectAfterMessages`. Everything
  else is survived. (`RejectAfterTime` is not fatal: it holds TERMINAL
  frames back and reports `RekeyOverdue` until a rekey completes, §6.2.)
- **Fatal for Dial**: not reaching CONFIRMED by the deadline of §3.9
  (whether or not a msg2 arrived; the error says which), or an authentic
  msg2 with an incompatible hello. Nothing else, since anything else could
  be forged. Because Dial returns only at CONFIRMED, a client never holds
  a connection the server has no record of: the case of a pending lost
  before confirmation is a Dial failure, not a silent hang.

### 10.4 Denial of service

| Attack | Cost to the server |
|---|---|
| Random msg1s | a map lookup, under 0.05 µs [S1] |
| msg1s with a known `cred_id`, bad mac1 | an HMAC, about 3–4 µs [S1] |
| msg1s forged with a leaked PSK | a decapsulation and an encapsulation each, about 0.3 ms [S1]; at most 4 pending per credential, evicted at random, and the client re-sends msg1 until confirmed (§3.8, §3.9), so a few forgeries per round trip only delay it. A stream kept up for the credential's whole 30 s can deny the handshake (never impersonate); a new SSH login is the answer, since the cookie (`0x06`) cannot filter a PSK holder |
| Random data packets | a map lookup; an AEAD open for a live index |
| Spoofed sources | at most 3x what the spoofer's copied packets carried (§7.2) |

msg2 is always smaller than msg1 (§3.6), so the handshake amplifies
nothing.

## 11. Tests the implementation owes

Beyond the general rules in `architecture.md` §6:

- **Known-answer transcripts.** With `testing/cryptotest.SetGlobalRandom`
  fixing the randomness, a test pins msg1, msg2, `h` and the epoch-0 keys
  byte for byte, and the same for one rekey, so a refactor cannot change
  the wire unnoticed.
- **Sizes.** msg1 with 1 and 16 channels is 1170 and 1185 bytes; msg2
  1150 to 1165; each INIT part 642; REKEY_RESP 1154; KEEPALIVE 31;
  PATH_CHALLENGE and PATH_RESPONSE 38; a full TERMINAL packet 1232. No
  handshake or rekey message over 1200.
- **Tamper every byte** of msg1, msg2 and a data packet: each is refused
  and changes no state.
- **Leaked stdout**: an attacker holding the whole credential line cannot
  complete a confirmed connection, and the genuine client still can (the
  spike's `TestB3LeakedStdoutCannotImpersonate`), including when the
  attacker sends 4 or more forged msg1s within one round trip of the
  genuine one, so the genuine pending is evicted after its msg2 went out:
  the client's msg1 resend is re-answered, it takes the new msg2 and
  confirms within the deadline.
- **Dial and confirmation**: Dial returns only at CONFIRMED; with the
  pending evicted and every resend dropped, Dial fails at the deadline
  with the "never confirmed" error; a msg2 byte-identical to the accepted
  one is ignored; a re-answered msg2 replaces the epoch-0 keys.
- **Credential life**: TTL, the cap of 2 with a logged eviction,
  consumption only on confirmation, 4 pendings with random eviction,
  resends answered from cache, and a credential's TTL or eviction erasing
  its pendings and freeing their indices.
- **Indices**: a packet to a reserved index with no key set is dropped and
  changes nothing; an index reserved for a failed `ReadMsg1` is freed.
- **Rekey property test** over netsim and synctest (§6.6), including
  collisions and the split INIT.
- **Rekey bounds**: an INIT under a `cur` younger than `RekeyMinEpochAge`
  is ignored and the genuine initiator's resend 1 s later is answered; a
  peer that sends a fresh INIT straight after every promotion gets at most
  one answer a second. With every rekey frame dropped on the path (and
  only those), TERMINAL sends return `ErrBlocked` from `RejectAfterTime`,
  `RekeyOverdue` is reported once, and when the drops stop the rekey
  completes and TERMINAL frames flow again.
- **Paths**: the S5 adversary (copy every client packet, re-source it from
  a victim, deliver it first): the victim gets at most 3x, the client is
  unaffected and the server never switches. A genuine roam validates. A
  lost challenge is resent on its timer. Confirmation with `S = {X}`, with
  `X ∉ S`, and with `S` of several addresses.
- **Relayed validation**: (a) msg1 re-sourced from a victim `V`, msg2
  relayed from `V`'s path to the client, which confirms from its own
  address: the server does not validate `V`, and `V` receives at most 3x;
  (b) a client packet re-sourced from `V`, the challenge to `V` relayed to
  the client, whose PATH_RESPONSE arrives from its own address: `V` is not
  validated.
- **Revocation**: the old client receives REVOKED, reports the address and
  time, and its later packets get at most three copies.
- **Fuzz targets** (each run for minutes locally, durations recorded):
  `ParseHello` (round trip), `Responder.ReadMsg1` with mac1 recomputed so
  mutations reach the KEM and AEAD (a failure changes nothing, only the
  genuine msg1 succeeds), `Initiator.ReadMsg2` (no msg2 from a server
  without `sk_S` is accepted), the data-packet receive path (a rejected
  packet changes nothing; no forgery is accepted), the INIT reassembly,
  and `replay.Window` against a map-based reference.

## 12. Constants

| Constant | Value | Where | Provenance |
|---|---|---|---|
| `wire.MaxDatagram` | 1232 B | §2.2 | [derived] RFC 8200 §5; D5 |
| `wire.MaxHandshake` | 1200 B | §2.2 | [RFC 9000 §14.1]; D5 |
| `transport.Overhead` | 30 B | §4.1 | [derived] 13 + 1 + 16 |
| `transport.MaxPayload` | 1202 B | §4.1 | [derived] 1232 − 30 |
| Wire version | `0x01` | §2.3 | [ours] |
| Hello revision | 1 | §3.6 | [ours] |
| Hello channel types | ≤ 16 | §3.6 | [ours]: keeps msg1 ≤ 1185 |
| X-Wing pk / enc | 1216 / 1120 B | §3.2 | [S1] measured from `crypto/hpke` |
| HPKE suite | KEM `0x647a`, KDF `0x0001`, AEAD `0xFFFF` | §3.2 | [RFC 9180]; draft-ietf-hpke-pq |
| mac1 | 16 B of HMAC-SHA-256 | §3.5 | [S1], after WireGuard's mac1 [WG §5.3] |
| `cred_id` | 8 B | §3.4 | [S1] |
| `sid` | 16 B | §3.4 | [S1] |
| `psk` | 32 B | §3.4 | [S1] |
| `CredentialTTL` | 30 s | §10.2 | [S1]; D20 |
| `MaxUnused` | 2 | §10.2 | [S1]; D20 |
| Pending per credential | 4, random eviction | §3.8 | [S1]; random [ours] |
| Addresses per pending | 4 | §3.8 | [ours] |
| Pending life | its credential's | §3.8 | D20 |
| msg1 and confirmation resend (msg1 resent with each confirmation resend) | 1 s, doubling, cap 4 s | §3.9 | [RFC 6298 §2.1], [RFC 9002 §6.2.2]; cap [ours] |
| Replay window | 1984 counters (32 × 64-bit blocks) | §5 | [RFC 6479 §2]; size [S1] |
| `RekeyAfter` | 120 s (server +10 s) | §6.2 | [WG]; D20; +10 s [ours] |
| `RekeyAfterMessages` | 2^60 | §6.2 | [WG] |
| `RejectAfterMessages` | 2^64 − 2^13 − 1 | §10.1 | [WG] |
| Failed opens per key | 2^36 | §10.1 | [RFC 9001 §6.6] |
| `RekeyRetry` | 1 s | §6.5 | [S1] |
| `RejectAfterTime` (TERMINAL and CHANNEL only) | 180 s | §6.2 | [WG] |
| `RekeyMinEpochAge` | 1 s | §6.4 | `threat-model.md` §4.3, [ours] |
| `KeepPrevFor` | 10 s | §6.5 | [S1] |
| INIT reassembly slots | 1 | §6.4 | [ours] |
| `AmplificationFactor` | 3 | §7.2 | [RFC 9000 §8.1]; D21 |
| Path challenge token | 8 B | §4.2 | [RFC 9000 §19.17] |
| Challenge resend | 250 ms, doubling, cap 1 s | §7.3 | [ours]; D11 for the floor and cap |
| Candidate abandoned after | 10 s | §7.3 | [ours] |
| REVOKED copies | 4 | §8.3 | [ours] |
| Tombstone life | 60 s | §8.3 | [ours] |

## 13. References

- PLAN.md §2: D5, D8, D11, D15, D20, D21, D22, D26, D28.
- S1: `docs/spikes/s1-handshake/FINDINGS.md`; `spikes/s1-handshake/hs/`;
  `spikes/s1-handshake/proverif/` (`b3.pv`, `b3_stdout_leak.pv`,
  `b3_noss2_sanity.pv`, `common.pvl`, `results.txt`).
- S5: `docs/spikes/s5-netsim-ssp/FINDINGS.md` §6; `ssp-spec.md` §2.1;
  `spikes/s5-netsim-ssp/ssp/path.go`.
- T. Perrin, *The Noise Protocol Framework*, revision 34 (2018).
- Angel, Dowling, Hülsing, Schwabe, Weber, *Post Quantum Noise*, ACM CCS
  2022.
- Barbosa, Connolly, Duarte, Kaiser, Schwabe, Varner, Westerbaan, *X-Wing:
  The Hybrid KEM You've Been Looking For*; draft-connolly-cfrg-xwing-kem;
  draft-ietf-hpke-pq (KEM id `0x647a`).
- J. A. Donenfeld, *WireGuard: Next Generation Kernel Network Tunnel*, NDSS
  2017.
- flynn/noise advisory GHSA-g9mp-8g3h-3c5c (state changed before
  authentication).
- RFC 2104 (HMAC), RFC 2119, RFC 5869 (HKDF), RFC 6298 (RTO), RFC 6479
  (anti-replay), RFC 8200 (IPv6), RFC 8439 (ChaCha20-Poly1305), RFC 8899
  (DPLPMTUD), RFC 9000 (QUIC: §8 address validation, §14.1 datagram size,
  §19.17 PATH_CHALLENGE), RFC 9001 §6.6 (AEAD limits), RFC 9002 §6.2
  (PTO), RFC 9180 (HPKE), RFC 4254 (SSH channels, the model for D15).

## Appendix: Review notes

Changes made in answer to the first review. Each item names the issue,
then what changed or why it stands.

1. **Confirmation validated msg2's destination even when the confirming
   packet came from elsewhere (§7.3). Fixed.** Validation at confirmation
   now needs `S = {X}`; otherwise `X` becomes `cand` and is challenged.
   An attacker who re-sources msg1 from `V` and relays msg2 to the client
   no longer gets `V` validated; it must also spoof the confirmation's
   source and win the race. Test added (§11, relayed validation (a)).
   `threat-model.md` §4.4 item 5 ("validated by the first transport
   packet") should add "if that packet comes from the address msg2 went
   to, and msg2 went to no other".
2. **PATH_RESPONSE accepted from any source (§7.3). Fixed.** It must now
   arrive from `cand`'s address, which is `threat-model.md` §4.4 item 3's
   rule; test added (§11, (b)). The residual, an attacker that both sees
   the server's output and spoofs, is stated in §7.3 and should be
   recorded in the threat model. On the resend timer, transport.md keeps
   its fixed 250 ms doubling to 1 s schedule and says why (§7.3: the
   transport has no RTO; it never resends faster than D11's RTO floor;
   the 3x budget bounds the bytes regardless). `threat-model.md` §4.4
   item 2 and its constants row "Path challenge re-send ≤ once per RTO"
   should be reworded to "on transport.md §7.3's timer (250 ms doubling to
   1 s), within the 3x budget". The optional "answer a challenge once per
   token" is **declined**: the server resends a challenge with the same
   token when the response is lost, and a client that answered only once
   would leave a genuine roam unvalidated; and the relaying attacker
   needs only one answer, so it would not raise the bar.
3. **Dropping only the rekey frames stalled rotation for ever, silently
   (§6.2). Fixed.** `RejectAfterTime` = 180 s [WG]: past it, a side seals
   no TERMINAL or CHANNEL frames (`ErrBlocked`), reports `RekeyOverdue`,
   and keeps rekeying; the rekey frames, keepalives and path frames are
   exempt, so an outage costs a round trip on return, not a new login.
   Padding is **declined for v1**: the frames' timing fingerprints them as
   well as their sizes, so hiding them is O10's traffic shaping; the limit
   is what makes the fingerprint harmless. `threat-model.md` §4.3 and R3
   should add the worst case: at most 180 s + 10 s of terminal traffic
   exposed when rekeys are being blocked, 120–130 s + 10 s normally.
4. **Four forged msg1s per round trip could evict the genuine pending
   for good (§3.8, §3.9, §10.4). Fixed.** Eviction is now random among
   the 4, and the client keeps `sk_C` and its post-`c1` state until
   CONFIRMED and resends msg1 with each confirmation resend, so a lost
   pending is re-answered with a new msg2 that the client accepts (only
   the holder of `sk_S` can make one). The "only a sustained flood" claim
   is now true and stated with its cost; §10.4 and the leaked-stdout test
   are updated. "Never evict a pending whose msg2 has gone out" was not
   taken: every committed pending has sent msg2, so it would mean never
   evicting, and 4 early forgeries would then lock the client out.
   The client now erases `psk` earlier (once msg1 is built) and `sk_C`
   one round trip later (at CONFIRMED) than before (§9).
5. **§8.1 resume contradicted D22 and `bootstrap.md` §9.2 (socket name,
   owner, uid check, entry point). Fixed.** §8.1 now defers to
   `bootstrap.md` §9.2 and `server.md`: the spawner owns
   `.../SID-HEX/attach.sock` and checks `SO_PEERCRED`; the entry point is
   plain `mosey --serve` with `attach=resume:SID`; there is no attach
   flag.
6. **No responder floor (§6.4). Fixed.** `RekeyMinEpochAge` = 1 s, the
   threat model's floor, in §6.4, §6.5, §12 and §11. At most one INIT per
   epoch was already true (a second, different INIT is ignored while
   `next` exists, and an answered one is re-sent from cache, not
   re-derived); the floor bounds epochs per second.
7. **§8.1's IPC message had no address or port, and no `XDG_RUNTIME_DIR`
   fallback. Fixed** with item 5: the `mosey-attach-v1` message is gone;
   the credential crosses the spawner–proto boundary as `server.md`'s
   `Credential` (0x30), the whole line with its port, after the reserved
   `Resume` (0x05) request; the fallback is `bootstrap.md` §8's.
8. **A never-confirmed client hung for ever (§3.9, §10.3). Fixed.** Dial
   now returns only at CONFIRMED, and not reaching it by the 30 s deadline
   fails Dial with its own error. This costs no round trip in practice:
   the server's first SSP datagram follows confirmation anyway.
9. **Index drawing was put where the table cannot be seen (§3.8, §4.3,
   §6.4). Fixed.** The transport draws and reserves every index and passes
   it in: `NewResponder(creds, hello, newIndex)` with `newIndex` called
   once at step 8, `NewInitiator(..., idxC)`, `StartRekey(root, idxI)`,
   `RespondRekey(root, parts, idxR)`. A reserved index with no key set
   drops what arrives for it. The stubs in `internal/handshake` have the
   old signatures and must follow.
10. **What a credential's TTL or eviction does to its pendings was
    undefined (§3.8, §9, §10.2). Fixed.** Pendings die with their
    credential (TTL or `MaxUnused` eviction), so a pending never outlives
    the credential `Confirm` consumes, and `Confirm` on a gone credential
    cannot happen (if it does, it is a bug: drop and log). This is the
    plain reading of D20's "lives 30 s"; the separate "30 s from msg1"
    pending life is gone. The client's own deadline starts after the mint,
    so it fails at about the same time either way.
