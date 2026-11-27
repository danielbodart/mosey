# Threat model

What mosey protects, from whom, where the trust boundaries are, what each
mechanism defends, and which risks are accepted. It grows with the slices
(PLAN §6.2). This version covers **slice 1**, **resume**, **auto-upload**,
**chaff**, **agent forwarding** and **prediction**: `mosey host` gives an interactive login
shell end to end, copying mosey to the host first if it has none (D7,
§4.13), with the user's ssh-agent forwarded over a typed channel and
OpenSSH's bind replayed when their ssh config forwards it (D25, §4.15), and
a plain `mosey host` resumes the user's most recently detached session,
and `mosey -s NAME host` takes a named one over, from wherever the user
can SSH from (§4.5); while the user types, both ends send cover traffic on a fixed
tick (§4.14); and the client draws its guess at the echo of easy keys at
once, judged against the server's cells (§4.16). Items marked **[later]** describe the
slice that brings them, so slice 1 reserves the right hooks and claims
nothing it doesn't do.

The bar is D4: **the public internet, used by other people.** Dan runs it
only inside WireGuard, but WireGuard is never the security boundary and
never an excuse for a shortcut. Every statement below assumes the attacker
can be anywhere on the path, including inside the tunnel.

PLAN §2 (D1–D28) is locked, and this document follows it. Where it states
a requirement on another spec section (`transport.md`, `ssp.md`,
`screen.md`, `server.md`, `bootstrap.md`), that section has the byte
layouts and the code is written from it; this document says which property
the layout has to keep. Where the two disagree, raise it rather than
pick one.

**Citations.** [D*n*] a locked decision in PLAN §2. [S*n* §x] a spike's
FINDINGS. [M S*n*] a number measured in that spike. [RFC *n* §x].
[paper §x] Winstein & Balakrishnan, USENIX ATC 2012. [derived] worked out
here, with the working shown. [ours] a value we chose, with the reason.

---

## 1. Assets

| # | Asset | Why it matters | Where it lives |
|---|---|---|---|
| A1 | **The user's shell on the server** (code execution as the user) | Anyone who can type into it is the user on that host: their files, keys, agent, sudo | the pty master: spawner, proto |
| A2 | **What the user types**: commands, passwords at no-echo prompts | Confidentiality of input | client memory, the network (sealed), proto, the pty |
| A3 | **What the screen shows**: program output, scrollback | Confidentiality of output (tokens, source, mail) | emu, proto's `Grid`, the network (sealed), the client's `Grid` |
| A4 | **The client host and its terminal** | A remote byte that reaches the user's real terminal emulator as a control sequence is a path to the client machine (the terminal CVE survey, dgl.cx/term) | the client process and the local tty |
| A5 | **The user's clipboard and attention** | Clipboard writes, links and titles shown locally can mislead the user | the local terminal |
| A6 | **Session secrets**: one-shot X-Wing private keys, the PSK, the handshake chaining key, the epoch root, the traffic keys, counters | Whoever holds current traffic keys can read and forge traffic; whoever holds the root can follow future epochs | client and proto memory; for the seconds of the bootstrap, the credential line in the launcher's and spawner's buffers. Never disk, core dumps included (D8, §4.10) |
| A7 | **Availability of the session** | A remote terminal that falls over is useless on a train | everywhere |
| A8 | **Third parties' bandwidth** | The server must never be a traffic reflector | proto's send path |
| A9 | **Server and client resources**: memory, CPU | One hostile program or peer must not take a host down | emu, proto, client |
| A10 | **Metadata**: that a session exists, when the user types, how much the screen changes | Traffic analysis | the wire |
| A11 | **The forwarded ssh-agent** and the session-bind captured for it (D25); the auto-uploaded binary (D7) | Signing authority: whoever can reach the forwarded agent can ask it to sign, as under `ssh -A`; the bind is what lets a destination-constrained agent judge the hop | the user's agent (client host); the bind in client memory; the agent socket (spawner), the streams (proto) |

## 2. Adversaries

| # | Adversary | Can | Cannot (by assumption) | In scope |
|---|---|---|---|---|
| T1 | **Off-path** network attacker | Send any UDP datagram to the server's port (60000–61000) or the client's, with any source address | See traffic between client and server | **Yes** |
| T2 | **On-path passive**: sniffer on Wi-Fi, an ISP, a WireGuard peer | Record every datagram, its size and time | Modify | **Yes** |
| T3 | **On-path active**: sniff and inject | T2, plus drop, delay, duplicate, reorder, rewrite, re-source a genuine datagram from another address, replay | Break ChaCha20-Poly1305, X-Wing or SHA-256 | **Yes** |
| T4 | **Hostile program output**: anyone who can get bytes onto the remote screen (`cat` a file, `curl`, `git log`, a chat client, a compromised remote program) | Send any byte sequence to emu, at any rate, at any window size the client chose; issue terminal queries | Run code on the server (unless it exploits emu: T6) | **Yes** |
| T5 | **Hostile server**: the far host is compromised, or the server binary is | Send the client any authenticated SSP state and any SSH stdout; choose the UDP address the client dials | Break SSH host authentication (that is T11) | **Yes, for the client host (A4, A5, A9).** The shell on a compromised host is already lost |
| T6 | **Compromised emu**: code execution inside the emulator via a VT parser bug | Send proto any IPC message, use any syscall the emu policy allows | — | **Yes**: this is where the sandbox really contains an attacker (S4 §1.2) |
| T7 | **Compromised proto** | Everything proto holds: keys, the UDP socket, the pty master | — | **Partly**: proto *is* the user (S4 §3.6); the sandbox is defence in depth against logic bugs, not containment |
| T8 | **Stolen client**: a laptop taken with a live session, or a client process whose memory is read | Use the live session; read current keys from memory | — | **Yes**, for limiting what it learns of the past and (with D26, [later]) cutting it off |
| T9 | **Leaked SSH stdout**: a session recorder, `script(1)`, bastion logging, shell rc noise captured somewhere | Read both bootstrap lines in full, PSK included, possibly before the client uses them | Write to the SSH channel | **Yes** (D20) |
| T10 | **Quantum harvest**: records traffic now, decrypts with a quantum computer later | T2, with a future break of X25519 and of classical SSH key exchange | Break ML-KEM-768 | **Yes** |
| T11 | **SSH broken**: a MITM that defeats SSH host authentication, or a malicious `ssh` binary | Substitute either bootstrap line | — | **No.** SSH vouches for the server (D6); B3 needs SSH to be **authentic** (D20). If SSH authentication fails, so does mosey, exactly as `ssh` itself would |
| T12 | **Same-uid code** on the client or server host | Everything the user can | — | **No**: it is the user. mosey must not make it worse (no world-readable secrets, no secrets in argv or env) |
| T13 | **Other local users** on either host | See process lists and argv; send UDP to the server's port; bind ports | Read another uid's memory, files or pipes | **Yes**, as T1 plus what `ps` shows |
| T14 | Root, the kernel, firmware, hardware side channels | Everything | — | **No** |

## 3. Trust boundaries

```
   client host                              │ network │             server host (one uid)
                                            │         │
 local tty ◄── render ◄── Grid.Apply ◄── SSP ◄─[B2]── UDP ──► proto ──[B4]──► emu
     ▲          (B6)        (B5)           │         │        │  ▲            (tuios)
     │                                     │         │        │  └──[B5]── Update (diff)
   user ──► client ──[B1: ssh stdin]──────────────────────► spawner          Replies ──[B7]──► pty
                 ◄───[B1: ssh stdout]──────────────────────     │ [B3]                          │
                                                                ├── SCM_RIGHTS: UDP + pty ──► proto
                                                                └── login shell ◄── pty ◄───────┘
```

| # | Boundary | Who is on the far side | What crosses | Trust |
|---|---|---|---|---|
| B1 | **SSH channel** (the system `ssh` and the far `sshd`) | The server host, authenticated by SSH | `ClientLine` on stdin, `CredentialLine` on stdout, ssh's stderr | **Authentic, not confidential** (D20). Both lines may leak (T9) without harm. stdout may also carry text the far host chose (motd, rc noise, a hostile host) |
| B2 | **UDP** | Anyone (T1–T3, T10, T13) before the handshake; the key holder after | handshake messages, sealed frames | Nothing is acted on before it authenticates |
| B3 | **spawner ↔ proto** (seqpacket + SCM_RIGHTS) | proto | `Start`, `EmuLink`, `AgentConn` (each with fds), `ShellExit` (spawner→proto); `Credential`, `Exit`, `KillEmu` (proto→spawner) (`server.md` §3) | proto compromise is already user compromise (T7), so this is hygiene, not containment; still parsed to a fixed grammar |
| B4 | **proto → emu** | emu | `Init`, `Output`, `Resize` | emu sees program output, which is T4's anyway |
| B5 | **emu → proto** and **server → client** | emu (T6); the server (T5) | screen diffs | **Hostile.** Both are decoded by the same validating `Grid.Apply` with the same allow-list (architecture §2), so one fuzzed decoder guards both |
| B6 | **client → local terminal** | the user's terminal emulator | escape sequences the client writes itself | The client is the only author. **No remote byte is ever passed through** (D9) |
| B7 | **emu replies → pty** | the shell and its programs | query replies | Only replies matching `server.ValidReply`'s fixed grammar |
| B9 | **The agent channel** (`agent.md`) | client side: the far host's programs (T5, and A1's holder), through proto; server side: the client | client side: stream frames, then opaque agent bytes into the user's agent; server side: the agent's answers to the shell's programs | Client side: **as `ssh -A`**: whoever is the user on the far host may use the agent, and the agent itself judges each request (its confirmations, its destination constraints, any question it asks the user). The client parses only stream frames (fuzzed) and, once per channel, the length of the bind's reply. Server side: the user's own processes, behind a 0700 directory and a uid check |
| B8 | **process metadata**: argv, environment, `/proc`, core dumps | T13 (argv), T12 (the rest) | — | No secret ever appears in argv or the environment. Every process that holds a secret (the client, the launcher, the spawner, proto, emu) suppresses core dumps before it holds one (§4.10) |

## 4. Mechanisms and what each defends

Each subsection says what the mechanism is, which adversary it stops, the
evidence, and the requirement it puts on a spec section. Constants are in
§7.

### 4.1 The B3 handshake (D20) — T1, T2, T3, T9, T10

```
-> s_C                        SSH stdin:  client's one-shot X-Wing public key (1216 B)
<- cred id, sid, psk, s_S     SSH stdout: credential id (8), session id (16), PSK (32),
                                          server's one-shot X-Wing public key (1216)
-> msg1: psk, skem_S, {hello_c}     UDP, ≤ 1200 B (D5)
<- msg2: skem_C, {hello_s}          UDP, ≤ 1200 B, and never longer than the msg1 it answers
-> first sealed transport packet    key confirmation: consumes the credential, validates the address
```

`Mosey_B3_KEMx2psk0_XWing_ChaChaPoly_HKDFSHA256`. Each side proves itself by
decapsulating what the other encapsulated to its one-shot key, so:

- **SSH only has to be authentic** (T9). The ProVerif model `b3_stdout_leak`
  publishes the entire stdout line, PSK included, from the start: client
  authentication at key confirmation, server authentication and secrecy
  in both directions (including the server's 0.5-RTT data) all hold. Only
  msg1's authenticity fails, which is by design: msg1 is answered, never
  trusted [S1 §3]. S1's `TestB3LeakedStdoutCannotImpersonate` ran the
  attack [S1 §TL;DR]; in mosey `handshake`'s
  `TestALeakedCredentialLineCannotImpersonateTheClient` and `transport`'s
  `TestALeakedCredentialLineCannotConnectAndForgeriesOnlyDelayTheClient`
  do. The sanity model `b3_noss2_sanity`, which drops msg2's KEM
  secret, finds the attack, so the model can see it [S1 §3].
- **Forward secrecy and no long-term keys.** Both KEM keys are made for one
  handshake and erased after it (§4.10). Model `b3`: with the PSK leaked
  after the session, client and server authentication, agreement and
  forward secrecy in both directions all hold [S1 §3]. Nothing is on disk
  to steal later (D8).
- **Post-quantum** (T10). X-Wing is ML-KEM-768 with X25519; its combiner is
  secure if either holds. The symmetric layer is 256-bit ChaCha20 and
  SHA-256. A harvest that later breaks X25519 *and* the SSH key exchange
  learns at most both bootstrap lines, which is T9: no harm.
- **No misbinding, no downgrade.** The transcript hashes the protocol name
  first, then the session id, both one-shot public keys, the credential id,
  both receiver indices and every byte of both messages [S1 §3.1]. There
  is no algorithm negotiation to downgrade: the protocol name fixes every
  cryptographic choice. What the hellos carry, the protocol number (D8
  V1: one number each side, which must be equal), channel types (D15),
  attach mode (D26) and features (`versioning.md` §4), is in the
  encrypted `Hello`, inside the transcript, so an on-path attacker
  cannot make the two sides disagree about it, nor strip a feature or a
  critical element from it (`transport.md` §2.3, §3.6). Client and
  server may be different releases; a pair of different protocol numbers
  fails at once, saying so, at both ends.
- **Must-ignore cannot be turned into a downgrade** (`versioning.md`).
  Every element a peer may skip is one whose loss costs at most a
  display (a tab mark, a title, a bell); everything that authenticates,
  restricts, selects or instructs is critical and refused when unknown,
  so an older peer never acts on half a message. Skipped elements are
  bounded in size and count and dropped before any state changes, and
  only an authenticated peer can send them (the bootstrap lines arrive
  over SSH, the rest inside the AEAD).
- **Off-path flooding** (T1). msg1 carries the credential id in the clear;
  an unknown id is dropped with one map lookup (< 0.05 µs with 1000
  credentials outstanding [M S1 §2.2]), before any MAC. A known id with a
  bad `mac1` (keyed by the PSK) costs 3–4 µs [M S1 §2.2]. A byte-identical
  copy of a msg1 the credential has already answered (a replay by T3, or
  the genuine client's own retransmission) is recognised by its hash
  before `mac1` and gets the cached msg2: no KEM work, no new state
  (`transport.md` §3.8 step 4). So only a sender that knows the PSK and
  makes a *distinct* msg1 reaches the ~140 µs decapsulation.
- **No amplification at the handshake.** msg2 is never longer than msg1:
  1174 B against 1200 B at most [M S1 §2.1, D5]. **Requirement on
  `transport.md`:** the hello in msg2 may not grow beyond what keeps
  `len(msg2) ≤ len(msg1)`; a test asserts it for every hello the code can
  produce. Until confirmation the server sends that address at most 3x the
  bytes it received from it (§4.4), so ~3.6 KB per msg1.
- **Credentials can't be hoarded or replayed** (T3, T9). A credential lives
  30 s, at most 2 may be unused per session (the oldest is evicted and the
  eviction logged), and it is consumed only on **confirmation**, never on
  msg1. **Requirement on `transport.md`:** a pending responder is keyed
  by `HASH(msg1)` over every byte of msg1, and an identical msg1 is
  answered from the cache **without** creating a responder, evicting one
  or touching the KEM; the client retransmits msg1 byte for byte, never
  re-encapsulating. Only distinct msg1s that pass `mac1` and decapsulate,
  which needs the PSK (T9), count toward the cap of 4 unconfirmed
  responders per credential, oldest evicted first; none can ever confirm
  [S1 §1.1, §3.1]. (S1's B3 prototype let replays fill the cap [S1 §3];
  that is the bug this requirement closes.) So a replay alone can neither
  evict the genuine responder nor cost a decapsulation, and a msg1 forged
  with a leaked PSK cannot lock out the genuine client unless it is a
  sustained flood (residual R7).

**The 1200-byte limit.** S1 measured msg1 at 1208 B with a 42-byte hello,
over D5's 1200 [M S1 §2.1]. The hello must be cut to ≤ 34 B in msg1
(architecture §4). A handshake message over 1200 B is a bug, never a
fallback: it is dropped on minimum-MTU paths (D5), and an implementation
that cannot fit stops and reports rather than exceeding it.

### 4.2 Sealed transport packets (D20) — T1, T3

```
data: type(1)=0x04 | receiver index(4) | counter(8) | AEAD_ChaCha20Poly1305(kind(1) | body) | tag(16)
      AAD = the 13-byte clear header; nonce = the counter; one key per direction
```

- **Receive order** [S1 §1.2, the flynn/noise advisory]: parse the header;
  look up the receiver index; `replay.Window.Check` (pure); open the AEAD;
  **only then** `Commit` the window, promote keys, update path state, and
  act on the frame. A packet that fails any step changes **no state at
  all**: not the window, not the peer address, not RTT, not timers.
  Evidence in the spikes: S1's `TestForgedPacketDoesNotAdvanceWindow`,
  `TestBTamperEveryByte` and `FuzzSessionOpen` (97.8M execs, 0 failures)
  [S1 §1.2, §7], and S5's `TestAuthenticateFirst`, which flips every bit
  of a datagram and checks no state moved [S5 §6]. In mosey: `transport`'s
  `TestEveryTamperedByteOfADataPacketIsRefusedAndChangesNothing`,
  `TestAPacketToAReservedIndexIsDroppedAndChangesNothing` and `FuzzReceive`
  (a refused datagram changes neither the window, the keys, the epoch,
  the peer, the amplification counters nor any rekey or path state).
- **Replay** (T3). RFC 6479 ring-of-blocks window of 1984 counters
  [S1 §8; RFC 6479], checked against a map-based reference by
  S1's `FuzzReplayWindow` (66.1M execs) [S1 §7], and in mosey by
  `replay`'s `FuzzWindow` and `TestTheWindowAgreesWithTheReferenceOnRandomSchedules`. In netsim, replaying every
  datagram 300 ms later was rejected in full with no latency cost
  [M S5 §6]; a replayed genuine command ran exactly once [M S4 §3.7].
- **Nonce uniqueness.** Each direction has its own key, the counter is the
  nonce, counters live only in memory, and a process that loses its
  counters loses its keys with them (D8) [S1 §1.1]. So no (key, nonce)
  pair repeats. A sender stops using a key before its counter reaches
  2^64 − 2^13 − 1 (WireGuard's REJECT_AFTER_MESSAGES) [S1 provenance
  table].
- **Forgery budget.** ChaCha20-Poly1305's integrity limit is 2^36 failed
  decryptions per key [RFC 9001 §6.6]. **Requirement on `transport.md`:**
  count authentication failures per receive key, and rekey (or close the
  connection) before 2^36. At D20's 120 s epochs an attacker would need
  2^36 / 120 s ≈ 5.7 × 10^8 forgeries a second to reach it [derived], so
  this is a correctness guard, not a tuning knob. The confidentiality limit
  for this AEAD exceeds 2^62 packets and is moot [RFC 9001 §6.6].
- **Unknown frame kinds are ignored** after authentication, so a later
  slice's frames (`KindChaff`, `KindChannel`, `KindRevoked`) never break an
  older peer. Ignoring is only ever done *after* authentication.
- **Linkability.** The receiver index changes every rekey, so the header
  does not link epochs [S1 §1.1]. The 5-tuple still does (R10).

### 4.3 Rekey (D20) — T8, T3

Every `RekeyAfter` (120 s, WireGuard's REKEY_AFTER_TIME; the server's
backstop is 130 s) or `RekeyAfterMessages` (2^60, WireGuard's
REKEY_AFTER_MESSAGES: D20's "N packets", `transport.md` §6.2), inside the
transport, using the same hybrid exchange chained from the current root:

```
I → R  REKEY_INIT part 1, part 2   each sealed under the current epoch, each ≤ 1200 B
R → I  REKEY_RESP                  ≤ 1200 B (measured 1154)
I → R  keepalive(1) under the new keys, resent until anything arrives under them
R → I  keepalive(0)                ack, so an idle responder still confirms
keys', root' = HKDF(salt = root, ikm = ss, info = H(root, idx_I, pk) | enc | idx_R)
```

- **Forward secrecy within a session.** The root chains one way, and old
  keys are erased `KeepPrevFor` (10 s) after the switch [S1 §1.3]. A
  memory compromise at time *t* (T8) exposes, at most, traffic sealed
  under the current epoch and the one still kept: **normally ≤
  `RekeyAfter` + `KeepPrevFor` (130 s) of traffic, and never more than
  `RejectAfterTime` + `KeepPrevFor` (190 s)** [derived], conditional on
  erasure (§4.10, R6).
- **Rekeys can be blocked, so keys have a hard lifetime.** Rekey frames
  are easy to pick out by size (two ~640 B INIT halves, then a ~1154 B
  RESP, every ~120 s [M S1 §2.1]), so a T3 can drop just those and let
  SSP through; without a limit the epoch, and with it what a later T8
  learns, would grow without bound. **Requirement on `transport.md`:**
  once `cur` is `RejectAfterTime` (180 s, WireGuard's REJECT_AFTER_TIME)
  old, a side seals nothing under it but REKEY_INIT and REKEY_RESP (no
  SSP data, heartbeats or path frames), and a receiver drops every other
  frame that opens under keys older than `RejectAfterTime` +
  `KeepPrevFor`. The session **stalls rather than closes**: in an outage
  nothing gets through anyway, and when the path comes back the rekey
  frames (resent every `RekeyRetry`) go first and data resumes under the
  new keys, so honest outages of any length still survive (the reason
  `transport.md` §6.2 gives for having no reject-after-time). Against
  the blocking T3 the cost is a stalled session, which T3 could cause
  anyway (R8), and never an unbounded epoch. The client shows the stall
  like any other loss of contact. This contradicts the current
  `transport.md` §6.2 bullet "There is no reject-after-time", which has
  to change (Review notes, item 2).
- **Only key holders can rekey.** Both INIT halves, RESP and the
  keepalives are sealed under the current keys, so T1–T3 cannot start,
  stall or steer a rekey. Rekey frames are acted on only under the
  **current** epoch's keys, which fixed the stale-INIT wedge
  [S1 §1.3, bug 1]. No side starts a rekey while one is in flight in
  either role. `TestRekeyInterleavingsProperty`: 2000 random schedules
  (0–40% loss, duplication, reordering, crossing rekeys, clock jumps),
  12,664 rekeys, no genuine packet ever failed authentication [M S1 §1.3].
- **A hostile peer can't make the other side burn CPU on rekeys.**
  **Requirement on `transport.md`:** a responder does **at most one
  encapsulation per epoch**. It caches its REKEY_RESP keyed by
  `HASH(idx_I' || pk_I)`, and a retransmitted identical INIT (the
  initiator resends every `RekeyRetry`, 1 s [S1], until a RESP arrives)
  gets the cached RESP, freshly sealed, with no KEM work; so a lost RESP
  is recovered and the epoch still advances. A different INIT while that
  answer is unconfirmed is ignored [S1 §1.3]. It ignores INITs for an
  epoch younger than a floor (1 s suggested [ours]: two encapsulations a
  second is negligible, and a genuine peer rekeys every 120 s).
  **Crossing rekeys** (both timers fire together) are settled by a fixed
  tie-break: the client's INIT wins, and the server drops its own `pend`
  and answers it (`transport.md` §6.4).
- **Post-compromise security** holds only once the attacker goes passive:
  an active attacker who holds the keys can run the rekey itself
  [S1 §3.1]. For a stolen client the answer is to cut it off (§4.5), not
  to rekey past it (R5).
- **No rekey on idleness** (D20, rejecting S1's D-3). See R3.
- The epoch chain's secrecy is argued, not modelled; a ProVerif or Tamarin
  model is owed before 1.0 [S1 §3.1, PLAN §6.5].

### 4.4 Path validation and anti-amplification (D21) — T1, T3, A8

The paper's rule, "send to the source of the newest authentic datagram"
[paper §2.2], lets an on-path attacker re-source a fresh genuine client
datagram from a victim's address so it arrives first. Measured in netsim:
**44 kB from the attacker drew 1,297 kB to the victim (29x)**, and 235 keys
were never echoed to the real client [M S5 §6]. The data stays sealed, but
the server becomes a reflector and the user is cut off. mosey follows
RFC 9000 §8 instead:

1. An authentic, newest packet from an address that is not the peer makes
   that address the **candidate**. The peer does not move.
2. proto sends the candidate a sealed `PATH_CHALLENGE` with a fresh random
   8-byte token, and **re-sends it on a timer** (at most once per RTO)
   while the candidate is unvalidated. (S5 found that waiting for the
   client's next datagram made the tail of a lost challenge 4.3–6.2 s
   [M S5 §6].)
3. The candidate becomes the peer only on an authentic `PATH_RESPONSE`
   carrying the current token, received from that address.
4. Until then the old peer keeps receiving everything, and the candidate
   receives at most **3x the bytes that came from it**, challenges
   included [RFC 9000 §8.1]. A send held back by the limit is
   `transport.ErrBlocked`, which SSP treats as a loss.
5. The address msg1 came from is validated by the first transport packet,
   because those keys depend on msg2, which went only there [S1 §1.5].

Measured with the same attack: the victim got **54.8 kB for 18.5 kB sent
(2.96x)**, the real client was unaffected and the server never switched
[M S5 §6]. In S4's real-process red team, validation held the victim to six
42-byte challenges [M S4 §3.7]. A genuine roam costs +50 to +480 ms of
repair at the median and no measurable keystroke latency [M S5 §6]; the
client sends at once when its local address changes (netlink on Linux),
so an idle client doesn't wait for its 3 s heartbeat (D21).

Layout C matters here: the kernel labels each datagram's source for proto
directly, so there is no relabelling process between the network and the
path logic. In S4's layout B a compromised packet pump defeated validation
by carrying the challenge to the real client and relabelling the answer
[S4 §3.7].

### 4.5 Resume and exclusive attach (D8, D26) — T8, T13

A new attach revokes every other transport of the session and wipes its
keys; the kicked client exits with "session taken over from <addr> at
<time>". Only this turns "SSH in again" into recovery from a stolen client
[S1 §3.1, review item 3]: `mosey -s NAME host` from any device the user
can SSH from cuts the stolen one off, and its keys are erased on the
server at once (`transport.md` §8.3). A plain `mosey host` takes only a
session that reads `detached` (`bootstrap.md` §9.2), which includes one
whose client has been silent for 15 s: a stolen laptop in a dead spot can
lose its session that way too, which is the point.

**The stolen client's own reconnect** (D8 R3, `bootstrap.md` §9.2.2). A
running client that hears nothing for 15 s resumes its session over a
fresh SSH login, by itself. That login needs whatever the user's ssh
needs (a key, an agent), so a thief with the laptop and an unlocked key
could already SSH in; what the rule adds is that the reconnect names the
credential it last held, and the launcher gives it the session only if
that credential still holds it or the session is detached. A session
taken over by `-s` is held by another credential, so the stolen client is
told `taken` and exits; it never takes the session back by itself. A
thief who runs `mosey -s NAME host` by hand can, as they could SSH in.
That a credential id is not secret does not weaken this: it is in the
clear in every msg1 (`transport.md` §3.4), but naming it only matters to
a launcher reached through an SSH login of the user.

**Names and the lock.** Session names are chosen and checked by the
launcher, which runs as the user, under an `flock` on `R/mosey/lock` in
the user's 0700 directory (the file `O_NOFOLLOW`, 0600). Another user can
neither take the lock nor see the names. A name is an `sname` (letters,
digits, `-_.`), so it is safe in the ssh command line of `-kill`, in the
greeting, the credential line and on the client's terminal.

**Lifetime.** A session ends when its shell exits, on `mosey -kill NAME`
(a `Hangup` over the attach socket, from a process of the user), or 7
days after it became detached (D8 R4); the last two send the shell SIGHUP
from the spawner, which already owned it, so no new privilege is used.
The idle timeout bounds how long a forgotten session, with whatever its
shell holds (an unlocked `sudo` timestamp, a forwarded agent socket that
no client serves), stays on a host.

The resume itself (`bootstrap.md` §9.2, `server.md` §2.6):

- **Who may resume.** Only someone who can SSH in as the user: the attach
  socket is in a 0700 directory owned by the user, checked with `lstat`
  (no symlinks, no group or other bits) by both the spawner that makes it
  and the launcher that connects, and the spawner checks the peer's uid
  with `SO_PEERCRED`. Another local user (T13) can neither reach the
  socket nor plant one the launcher would follow.
- **What a resume reuses.** Nothing secret: a new one-shot key on each
  side, a new PSK and credential, new indices and counters; only the
  session id (public) is the same. No key, counter or PSK is ever written
  to disk, by either side (D8).
- **The spawner's new input.** It now parses a `ClientLine` from any
  process of the user that connects to the socket (the same fuzzed,
  canonical parser as at bootstrap), `Hangup` (type only), and two more
  fixed-layout messages from proto (`Attached` with a credential id and an
  address, `Detached`); it forwards only an X-Wing key it has checked.
  Proto's new input is `Resume`, a fixed-length key, and `Start`'s name,
  which it only copies into the credential line the spawner checks.
- **The client's new input.** The CredentialLine's `name` (an `sname`,
  refused otherwise) and `-list`'s lines (`ParseListLine`, canonical and
  fuzzed), from which the client lays out the table itself, so a hostile
  server cannot put an escape sequence on the user's terminal through
  either (D9).
- **What a resume does not do**: it does not reach a session whose proto
  has died (R17). It does cross versions (D8 V1): any release's client
  attaches any release's session whose attach protocol the host's mosey
  speaks (`bootstrap.md` §9.2 step 5). The session goes on running the binary
  that started it, so a fix on the host reaches the sessions started after
  it, not one already running: there is no live upgrade (D8 V1, Dan,
  2026-11-15).

### 4.6 SSP bounds and compression (D11, D24) — T5, A9

SSP's parsers see only authenticated payloads, but an authenticated peer
is still not trusted with the receiver's memory. The client is protected
from a hostile server (T5) exactly as proto is from a hostile client.

- **The receiver's limits are derived from what the sender can
  legitimately produce, never set below it.** A limit smaller than the
  largest honest diff would drop that diff every time, and SSP would
  resend the same oversize diff from the acked state for ever: a T4 that
  fills the clamped screen with 64-byte random clusters would freeze the
  session. So **requirement on `screen.md` and `ssp.md`:** `screen.md`
  derives `MaxDiff` (64 MiB, `screen.md` §5.12) as the largest diff its
  encoder can emit at the D23 clamp (`MaxCols × MaxRows` cells of
  `MaxCluster` bytes plus style, link and op overhead; 500,000 × 64 B is
  32 MB of text alone [derived]); the server's encoder must never emit a
  larger one (a test builds the worst case and checks it); and the
  client's `MaxRemoteBytes`, `MaxInstruction` and decompression limit
  are that value, not a smaller one (`ssp.md` §10.2). The server's own
  limit for the client's input stream is the much smaller
  `MaxDiffBytes` (128 KiB), because input diffs are small by
  construction.
- **Fragments and reassembly** (`ssp.md` §5): at most `MaxFragments` =
  `ceil(MaxInstruction / Chunk)` fragments per instruction (about 57,200
  at 64 MiB, under the 65,535 the field allows), at most 4 instructions
  under reassembly and `MaxPartialBytes = 2 × MaxFragments × Chunk`
  bytes held in total (at least `2 × MaxInstruction`), charged chunk by
  chunk as each is stored and never set aside from a claimed count, the
  oldest other partial evicted first. A fragment whose index or count is out of range, or
  inconsistent with earlier fragments of the same instruction, is a
  protocol error. S5's 512 fragments and 1 MiB were for a fixed-size toy
  screen [S5 ssp-spec §2.3] and are not ours. The cost is that a hostile
  server (T5) can make the client hold about 128 MiB of partial
  instructions; that is bounded, and the client has nothing better to do
  with its memory for that session.
- **Decompression is bounded and fails closed** (D24). An unbounded flate
  decoder turned one 1280-byte datagram into ~1.3 MB [M S5 §8]. `ssp`'s
  `decompress` takes a limit and returns an error, **never a truncated
  result**, when the output would exceed it, and the connection ends with
  `ErrProtocol` (`ssp.md` §8): an authenticated peer that sends one is
  broken or hostile, and dropping it would only stall on the same
  retransmission. The limit is `MaxRemoteBytes` (above).
- **Apply validates before it mutates.** Every `State.Apply` (`Grid`,
  `userinput.Stream`) parses and checks the whole diff before changing
  anything, so a rejected diff leaves the state exactly as it was.
- **No state before authentication** (§4.2): RTT samples, acks,
  timestamps and the high-water mark come only from authentic datagrams.
- **Compression leaks length** (R1). See §5.
- **The history is a window, not a queue** (`screen.md` §2.5). A hostile
  or merely flooding server (T4, T5) cannot make the client hold more
  history than `HistoryLines` lines and `HistoryCells` cells: `Apply`
  refuses a diff that carries more than the window (before it allocates
  a line past it), and after every diff the client drops its oldest lines
  until both bounds hold. The server keeps the same window whatever the
  client has acknowledged, so a client that is gone or slow costs the
  server no more than the window, and a client that falls behind past it
  prints one "lines not shown" marker.
- **A listening client paces the program** (`screen.md` §2.5, Dan
  2026-11-16). While the attached client is heard, proto stops reading
  the pty once a quarter of the window is unacknowledged, so the program
  blocks in `write` until the client acknowledges, as it would under
  ssh's channel window. A hostile or broken client that keeps sending
  but never acknowledges can therefore stall the program for as long as
  it stays attached. That is accepted: the client holds the session's
  keys, which come over the user's own SSH login, so it is the user's
  own client, and it can already type anything into the shell, which is
  far worse; an ssh client can stall its programs the same way. Nobody
  else can stall it for long: an on-path attacker who drops packets
  either makes the client silent or, dropping only the server's, stops
  its acknowledgement while its heartbeats still arrive; either way,
  after `SilentAfter` (15 s) without the acknowledgement advancing the
  hold lifts and the program runs on (R8 is the denial of service it
  already had). The hold
  never holds keystrokes: they go to the pty whatever it is, so Ctrl-C
  reaches the program. A flood costs bandwidth that Mosh's
  latest-state-only rule skipped (each frame carries up to the window of
  new lines, about 80 KB at 80 columns before compression); that is
  bounded by the window and by SSP's frame rate, and keystrokes go the
  other way unaffected. What the client prints of history passes the
  same allow-list as the screen and is drawn by the renderer from cells
  (D9); the only new byte it writes is LF, at its own cursor on the last
  row (`screen.md` §8.7).

### 4.7 The client never parses remote escape sequences (D9, D27) — T4, T5, A4, A5

The server's emulator turns program output into a `screen.Grid`; SSP sends
`Grid` diffs; the client applies them to its own `Grid` and `render` draws
it with escape sequences **it writes itself**. No byte from the network,
and no byte from SSH stdout or stderr (§4.9), reaches the user's terminal
except as a validated cell, title, link or clipboard value re-encoded by
the client.

**The allow-list** (D27, S2), enforced by the server's sanitiser and
re-checked by the client's `Apply`, which **refuses** a diff that breaks it
rather than repairing it:

| Field | Rule | Bound |
|---|---|---|
| Cell text | Valid UTF-8; no C0 (U+0000–U+001F), DEL (U+007F) or C1 (U+0080–U+009F); otherwise the server substitutes U+FFFD | ≤ 64 B per cluster (`MaxCluster`, tuios' cap) |
| Cell width | 1 or 2, decided by the server; the client places runs with explicit cursor positioning so a width-table disagreement can't shift a row [S2 notes for D9] | — |
| Title | Valid UTF-8; C0, DEL, C1 and bidi controls (U+202A–U+202E, U+2066–U+2069) removed (D27); cut on a rune boundary | ≤ 256 B (`MaxTitle`) |
| OSC 8 URI | Printable ASCII only (0x21–0x7E: no controls, no space; IRIs percent-encoded); scheme `http`, `https` or `mailto`; otherwise the link is dropped and the text kept | ≤ 2048 B (`MaxLink`, D27) |
| OSC 52 clipboard | **Write only**; the server never asks the client's terminal for the clipboard, and the client never reads it (D27). The client base64-encodes the bytes itself | ≤ 64 KiB (`MaxClipboard`, ours, set in `screen.md`) |
| Window size | `ClampSize` to [1, 1000] × [1, 500] before the emulator or the pty sees it; the client refuses a diff that declares more | `MaxCols`, `MaxRows` (D23) |
| Modes | A fixed set of named input modes the client mirrors (cursor keys, keypad, bracketed paste, mouse reporting, focus events). Each maps to one fixed sequence the renderer writes; unknown bits are refused | — |

Requirements on `render` and `client`:

- **Never emit a sequence that makes the local terminal answer** (DSR,
  DA, CPR, OSC colour or clipboard queries, DECRQSS, XTGETTCAP, and the
  like). The client learns its window size from `ioctl(TIOCGWINSZ)`, never
  by asking the terminal, so no local terminal reply can be prompted into
  the input stream and forwarded to the server.
- **Non-ASCII only to a UTF-8 terminal.** Bytes 0x80–0x9F occur inside
  ordinary UTF-8 (U+00DB is `C3 9B`, and `9B` is 8-bit CSI). A terminal not
  in UTF-8 mode can act on them as C1 controls. The client renders
  non-ASCII cell text only when the local locale's codeset is UTF-8, and
  otherwise substitutes `?` [derived].
- **The client's grid is bounded** by `MaxCols × MaxRows` and by
  `screen.md`'s caps on the style and link tables (S2's prototype used
  65,536 styles and 1 MiB of link text [S2 cell-diff]). The renderer clips
  to the local window; it never trusts the remote size to fit.
- **The same decoder guards proto from emu** (B5): emu's `Update` is
  applied to proto's `Grid` with `Grid.Apply`, so a compromised emu (T6)
  can show nothing a hostile program (T4) couldn't.

Evidence: S2's hardened decoder, `FuzzApply` 15 min / 2.4M execs with no
finding after one fix, and `FuzzRoundTrip` 15 min / 0.98M execs, server
diffs always accepted and both sides identical [M S2 fuzzing]. All three
title probes from S2's review (`"a\u009d0;evil\u009cb"`, `"a\u009b2Jb"`,
`"a\x7fb"`) are tests on both sides [S2 cell-diff].

### 4.8 The emulator's bounds (D23) — T4, A9

What a remote program sends is attacker-chosen (T4), and so is the window
size (it comes from the client, an authenticated but untrusted peer).

| Bound | Value | Why |
|---|---|---|
| Window clamp | 1000 × 500, applied before `Emulator.Resize` and `pty.SetSize` | Resizing tuios to 5000 × 5000 and back cost 2.9 GiB [M S2 hostile] |
| Scrollback | `min(10000, 1e6 / cols)` lines, reset on every resize | A history cell can cost ~100 B (64-byte clusters, distinct colours), so ~1 GiB at the clamp with a line cap alone; the cell budget holds history to ~100 MiB at any width [M S2 memworst] |
| emu memory | Two limits, either enough on its own (`server.md` §6.3): a cgroup scope with `MemoryMax` 512 MiB and `MemorySwapMax` 0 where the user has a systemd user manager, and **always** `RLIMIT_DATA` 1 GiB, set by emu on itself before its sandbox and not raisable afterwards. When either is hit, emu dies, the spawner restarts it, and the client is told | tuios stores each OSC 8 URI by value, up to 4 MiB, with no ceiling of its own: a distinct 2 KiB URI per cell is ~2.2 KB per history cell [M S2 memworst]. Only these limits bound it until upstream fixes it. Many hosts have no user manager (non-systemd distributions, containers, sshd without PAM: S4 §3.10 found `systemd-run --user` fails without `XDG_RUNTIME_DIR`), so the cgroup cannot be the only bound. `RLIMIT_DATA` needs nothing but a Linux kernel; with no cgroup the bound is 1 GiB per session rather than 512 MiB (R18). **Requirement on `server.md`:** if neither limit can be set, emu does not start and the session fails with a stated reason; mosey never runs an emu with no memory bound |
| Panic | treated as "rebuild emu", never carried on | S5 hit a panic in another emulator from plain program output [S5 §8]; tuios had none in 20 + 20 min of fuzzing [M S2 fuzzing] |
| Reply queue | the pty reader never writes; replies go to a 64 KiB bounded queue drained by a separate writer, keystrokes ahead of replies; overflow dropped and counted | A program that queries and never reads deadlocked the naive design in 0.1–0.2 s; the split design consumed 64 MiB with at most 64 KiB queued [M S2 replyflood] |
| CPU | a program can slow only its own session | At the clamp, REP 65535 costs ~3 ms per 8-byte sequence; scrolling runs at 13 MB/s [M S2 hostile-clamp] |
| Graphics | sixel and kitty are answered "not supported"; kitty uploads that name a file are refused | Not expressible as cells; a file-naming upload is a read primitive [S2 notes for D9] |

### 4.9 The SSH bootstrap (D6, D20) — T5, T9, T13

- **Fresh connection.** `ssh -T -o ControlMaster=no -o ControlPath=none
  -o ForwardAgent=no` (or D25's capture socket, §4.15). A
  multiplexed connection has no key exchange of its own, and a forwarding
  master can route the bootstrap's agent traffic to the user's real agent
  [M S3 E12b].
- **No forwarding of any kind** (T5). The bootstrap needs none, and the
  user's config may turn some on: `ForwardX11` (trusted, on Debian's
  default `ForwardX11Trusted yes`, gives the far host keystroke capture
  and input injection on the client's X display: A4), `RemoteForward`
  (reaches the client's local services), `LocalForward`/`DynamicForward`,
  `Tunnel`, `LocalCommand`. **Requirement on `bootstrap.md`:** the
  bootstrap ssh also gets `-o ForwardX11=no -o ClearAllForwardings=yes
  -o PermitLocalCommand=no -o Tunnel=no`, placed before any user option
  so ours win (`ssh_config(5)`: the first value obtained is used, and the
  command line is read before any file); the user flags that would undo
  them (`-X`, `-Y`, `-L`, `-R`, `-D`, `-w`) are refused (`bootstrap.md`
  §2). With `ForwardX11=no`, `ForwardX11Trusted` has nothing to apply to,
  and `-x` adds nothing to it. A test resolves the exact command line
  with `ssh -G` against a config that turns every one of these on and
  checks the effective values.
- **Argument hygiene.** **Requirement on `bootstrap.md`:** the destination
  follows `--` so a destination beginning with `-` is never an option; the
  remote command (`<remote> --serve`) is quoted for the remote user's shell,
  since sshd runs it through that shell.
- **Lines** are printable ASCII, fields base64url without padding, one
  line each. Neither carries anything that lets a reader impersonate
  either side (T9, §4.1). The client's line carries only its public key,
  window size and `TERM`/`COLORTERM`/locale.
- **The spawner's parser.** `ParseClientLine` runs unsandboxed, but its
  input comes from someone SSH already authenticated as the user, who has
  a shell anyway (D14). So it is not a privilege boundary; it is still
  strict, canonical and fuzzed. Requirement: `Env` accepts only the names
  `TERM`, `COLORTERM`, `LANG`, `LC_*` with values of printable ASCII and
  bounded length, set through `exec.Cmd.Env`, never interpolated into a
  shell string.
- **The client's parser** (T5). `ReadCredential` skips non-credential lines
  up to a fixed byte bound and fails beyond it. **Skipped lines are never
  written raw to the local terminal** (D9); if shown at all, they are
  stripped of every C0 except tab, of DEL, ESC and C1 first. The same holds
  for the far side's stderr, which ssh relays: the client pipes ssh's
  stderr through the same sanitiser. ssh's own prompts (passwords, host
  key confirmation) go to `/dev/tty` and are unaffected.
- **The UDP address.** `CredentialLine.Addr` is chosen by the far host
  (from `SSH_CONNECTION`), so a hostile server (T5) can point the client's
  msg1 at a third party. The client retransmits msg1 with backoff and
  gives up when the credential expires (30 s), so the most it sends is a
  few dozen 1200-byte datagrams [derived]. Requirement: the client refuses
  unspecified, multicast and limited-broadcast addresses; a directed
  broadcast of the client's own subnet is refused by the kernel, since the
  client clears `SO_BROADCAST` on its socket (bootstrap.md §7.2).
- **Secrets never in argv or the environment** (T13, B8). Keys travel over
  stdin, stdout and the IPC socket only. Roles are selected by
  `--serve=proto|emu`, which carries nothing secret.

### 4.10 Erasing secrets (D20) — T8, T10

`crypto/hpke` has no API to erase an X-Wing private key, and S1 measured a
dropped key's seed still in process memory after two GCs in **20/20**
trials; built with `GOEXPERIMENT=runtimesecret` and key generation inside
`secret.Do`, **0/20** [M S1 §3.2]. So:

- **linux release builds** use `GOEXPERIMENT=runtimesecret`, with
  generation, the handshake and every rekey inside `secret.Do`;
- **elsewhere** the claim is the weaker "erased once the GC reuses the
  memory" (R6);
- every secret mosey holds in its own buffers (PSK, chaining key, roots,
  traffic keys, the marshalled credential) is overwritten when consumed,
  expired or revoked, not merely dropped [S1 §3.2]. That includes the
  launcher's and spawner's copies of the credential line, wiped as soon
  as it is written to stdout (it is harmless to leak by D20, but there is
  no reason to keep it);
- **no core dump ever holds a secret.** A crash (a panic under
  `GOTRACEBACK=crash`, a runtime abort, SIGSEGV, SIGABRT, SIGSYS) of a
  process that holds keys would otherwise write them to
  `/var/lib/systemd/coredump` or `/cores`, readable by the user, and a
  later T8 with recorded traffic (T2) would then decrypt past epochs:
  exactly what D8 and §4.3 rule out. With `DUMPABLE` at 1, a SIGSYS left
  two ~100 KB core dumps in systemd-coredump; with 0, none [M S4 §3.5].
  So **every** process that holds a secret does this first, before it
  generates, receives or reads one:
  - **Linux:** `prctl(PR_SET_DUMPABLE, 0)`, which stops the kernel
    dumping for a file or a piped `core_pattern` alike (unless root set
    `fs.suid_dumpable`, which is T14), and is reset by `execve`, so the
    login shell and ssh are untouched. proto, emu and the client also set
    `RLIMIT_CORE` to 0 (the bootstrap ssh inherits the client's, which
    costs nothing). The launcher and spawner do **not**: an rlimit is
    inherited across `exec`, and the user's login shell must keep the
    user's own core-dump settings.
  - **darwin**: `setrlimit(RLIMIT_CORE, 0)` in the client, proto and
    emu. The launcher and the spawner have no protection: macOS has no
    `PR_SET_DUMPABLE`, and the rlimit reason above applies. This is a
    known gap (`server.md` §10). The Seatbelt slice decides whether
    `PT_DENY_ATTACH` can close it.
  - **Who:** the client (`mosey host`, before its one-shot X-Wing key
    exists; a requirement on `bootstrap.md` §4.3), the launcher and
    spawner (before they read the credential line; `server.md` §2.1),
    proto and emu (already first in `server.md` §6.1).
  - The cost is that a crashed client leaves no core to debug from; Go's
    traceback on stderr is still printed, and contains no key material
    unless a key is formatted into a panic message, which code review
    forbids.
- **Swap and hibernation** can still copy key pages to disk. Go gives no
  dependable way to `mlock` or `MADV_DONTDUMP` the pages a key lands on,
  so this is accepted under R6 rather than half-solved.

### 4.11 Process layout and sandbox (D22) — T6, T7, T13

| Role | Holds | Parses | Sandbox | A compromise gets |
|---|---|---|---|---|
| launcher, spawner | the pty master (spawner; kept so the shell outlives proto); no key, but for a moment the credential line (PSK included) on its way to stdout, wiped once written (§4.10) | `ClientLine` (from the user), proto's IPC messages, and the attach protocol from the user's own processes (§4.5) | none, but `DUMPABLE=0` (§4.10): the spawner forks the login shell | the user |
| **proto** | keys, the UDP socket, the pty master | every datagram (pre-auth: header, lookup, AEAD, msg1), SSP, emu's `Update` and `Replies` | Landlock deny-all, seccomp TSYNC, `DUMPABLE=0` | **the user**: it can type into the shell (S4 red team: `pwned-ipc` created under every sandbox setting [M S4 §3.6]), and `sendto` anywhere from its socket |
| **emu** | nothing: no key, no pty, no socket but its IPC | all program output (the VT parser) | Landlock deny-all, seccomp TSYNC, `DUMPABLE=0` | its own IPC. Its diffs pass `Grid.Apply`; its replies pass `ValidReply` |

So **the emu sandbox is the one that really contains an attacker**, and it
guards the code with the most attacker-reachable input: anything that
reaches the screen [S4 §1.2]. For proto, the sandbox is defence in depth
against logic bugs, the likely bug class in Go; it does not contain code
execution (R4).

- **Setup order** [S4 §5.4]: wrap the inherited fds; `PR_SET_DUMPABLE=0`;
  Landlock deny-all (with abstract-unix and signal scoping where the
  kernel has them); seccomp with TSYNC; **then** read any input.
- **Why both.** Landlock alone let a compromised process open a new UDP
  socket and `sendto`, connect to a pathname unix socket (the agent or the
  user bus: 6.18 has no `FS_RESOLVE_UNIX`), call `io_uring_setup`,
  `userfaultfd`, `keyctl`, and create a user namespace. seccomp blocked
  every one; with both, every escape in the battery was denied, in proto
  and in emu [M S4 §3.6].
- **Policies.** Observed-only allow-lists from traces of the real roles
  under load, plus `exit` and `pread64` (re-read by the runtime under a
  CPU quota; dropping it killed a process after 60 s idle or ~1 s busy
  [M S4 §3.5]). emu: the runtime set and nothing more (43 cBPF
  instructions); proto adds `recvfrom`, `sendto`, `recvmsg` and
  `getrandom` (47) [M S4 §3.3]. `clone` only with `CLONE_THREAD`;
  `clone3` → ENOSYS and `prctl` → EINVAL so the runtime falls back.
  **Requirement on `server.md`:** proto's `ioctl` is argument-filtered to
  exactly `TIOCSWINSZ` (window size) and `TCGETS` (the echo-off bit, D12)
  on the pty master's fd; nothing else.
- **No signals out of the sandbox, on any kernel.** The runtime set
  contains `tgkill` and `fcntl`, and unfiltered either one reaches other
  processes of the same uid: `tgkill(pid, pid, SIGKILL)` kills any of
  them, and `fcntl(F_SETOWN, victim)` with `F_SETFL O_ASYNC` (and
  `F_SETSIG`) makes the kernel signal the victim whenever the IPC fd
  becomes readable. Landlock's signal scope (ABI 6, Linux 6.12) blocks
  both where the kernel has it, but D22's sandbox must contain emu on
  older kernels too, and S4's battery tested only `kill`, which the
  policy denies [S4 §3.6]. **Requirement on `server.md`:** seccomp
  argument-filters, in both roles:
  - `tgkill`: allowed only if `args[0]` (the tgid) is the process's own
    pid, a constant when the filter is compiled (the Go runtime only ever
    signals its own threads, for preemption and signal forwarding).
  - `fcntl`: allowed only for the commands the runtime and `os` use
    (`F_GETFD`, `F_SETFD`, `F_GETFL`, `F_DUPFD_CLOEXEC`, and `F_SETFL`
    with the `O_ASYNC` bit clear); `F_SETOWN`, `F_SETOWN_EX`, `F_SETSIG`
    and everything else get the policy's default action. The exact list
    is confirmed against the KILL soak's traces (`server.md` §9).
  - `ioctl(FIOASYNC)` is already impossible: emu has no `ioctl` and
    proto's is filtered as above.
  The sandbox red-team battery (§8) gains `tgkill` at a sibling process,
  and the `F_SETOWN` + `O_ASYNC` route, on a kernel with Landlock's
  signal scope disabled or absent, and checks both are denied.
- **The emu reply grammar** (B7). `ValidReply` accepts exactly one complete
  reply per message from a fixed set of templates (S4 built CPR, DA1, DA2
  and DSR-OK; colour reports may be added) whose variable parts are digits
  or hex only, ending in the template's fixed terminator. It therefore
  never contains CR, LF, or any other C0 control except as the fixed
  introducer or terminator, so it can never submit a line or raise a
  signal through the default line-discipline characters. S4's red team:
  both forged replies (`touch …\n`, and a CPR followed by a command and
  CR) were denied and the file was not created [M S4 §3.6]. Residual: R9.
- **Supervision** (`server.md` §5). The spawner supervises; proto can
  signal nobody (no `kill`, signals scoped away, `tgkill` filtered to
  itself), so it asks. emu death, panic or a hit on its memory limit
  makes the spawner restart it, with backoff from 50 ms doubling to 5 s,
  at most 10 starts per 60 s, then the session ends [S4 §3.8]. A **hung**
  emu, one that has not answered a request within T4 (30 s,
  `server.md` §8), and an emu that breaks the IPC grammar are both
  reported by proto to the spawner as `KillEmu{why}` (proto → spawner);
  the spawner kills it and restarts it the same way. Each new emu reaches
  proto as `EmuLink{fd, generation, reason}` (spawner → proto, the fd by
  SCM_RIGHTS). proto then sends the client a full redraw, and the
  spawner sends SIGWINCH to the pty's foreground process group so
  programs repaint. Tests: a silent emu produces `KillEmu{deadline}`
  after T4, and a restarted emu's first `Update` reaches the client
  (`server.md` §12).
- **Logs.** A compromised role can write any line to an inherited stderr
  (S4: "Y everywhere"). Each role's stderr is a pipe its supervisor reads
  and prefixes with the role, and every attacker-influenced string in a
  log (titles, `Exit` reasons, addresses from the wire) is quoted (`%q`),
  so no role can forge another's log line.
- **Re-exec.** The spawner re-executes its own image. **Requirement on
  `server.md`:** exec `/proc/self/exe` on Linux rather than the path
  `os.Executable` returned, so the roles are the same file the spawner
  is even if the path is replaced in between. D7 itself replaces
  `~/.local/bin/mosey` in place when a client of another protocol
  needs it (`bootstrap.md` §4.7.7), so this is also what keeps a running
  session on its own binary; against a same-uid writer it is only
  hygiene (T12).
- **seccomp's action follows D22**: KILL on amd64 and on arm64
  (`sandbox/action.go`). arm64 ran ERRNO until CI's arm64 KILL soak
  passed (run 43626969195; R13, now closed). The soak job (`server.md`
  §9) runs on both architectures for every change that could break an
  allow-list, and `TestReleaseAction` keeps the release action KILL.

### 4.12 Denial of service — T1, T3, T4

| Attack | Cost to the attacker | Cost to mosey | Bound |
|---|---|---|---|
| Random datagrams at the port | one datagram each | a length check, or one map lookup | < 0.05 µs each [M S1 §2.2] |
| msg1 with a known credential id, no PSK | needs the id (on SSH stdout: T9) | one HMAC | 3–4 µs [M S1 §2.2] |
| Replayed genuine msg1 (T3), or the client's own retransmission | sniffing the client's msg1 | one SHA-256 and a lookup; the cached msg2 resent (≤ 4 addresses, ≤ 3x each) | µs; no decapsulation, no new responder, no eviction (§4.1) |
| Distinct msg1 with the PSK (T9) | the leaked line | one decapsulation, one encapsulation, a responder | ~320 µs; ≤ 4 responders per credential; credential TTL 30 s [M S1 §2.2, §3.1] |
| Dropping only rekey frames (T3) | being on path, picking frames by size | the session stalls at `RejectAfterTime` until rekey frames pass | DoS only, as any on-path drop (R8); no epoch outlives 180 s (§4.3) |
| REKEY_INIT retransmissions by a hostile peer | holding the keys | one cached RESP resent | ≤ 1 encapsulation per epoch, epochs ≥ 1 s apart (§4.3) |
| Forged data packets | one datagram each | lookup, window check, one failed AEAD open | µs; no state change; 2^36 per key (§4.2) |
| Re-sourced genuine packets (T3) | sniffing | path challenges | ≤ 3x what the attacker sent, to the victim [M S5 §6] |
| Hostile program output (T4) | a program on the server | emu CPU and memory | the session's own; memory ≤ 512 MiB (cgroup) or 1 GiB (`RLIMIT_DATA`), never unbounded; §4.8 |
| A screen-sized diff at the clamp (T4) | a program on the server | up to `MaxDiff` (64 MiB) sent once, compressed | delivered, not dropped: the receiver's limits are derived from it (§4.6) |
| On-path drop | being on path | the session stalls | unbounded (R8) |
| Log flooding via evictions | leaked PSK | log lines | **Requirement:** eviction and rejection logs are rate-limited per session |
| A far program opening agent connections | being the user on the server | one stream each | ≤ 16 live per connection; more are closed at once (`agent.md` §4.2) |
| A hostile server stalling agent streams (T5) | holding the session | the client's buffers | ≤ 2 MiB per connection; the user's agent sees a connection that waits, as under `ssh -A` |

### 4.13 Auto-upload (D7) — T5, T12, T13, and the release channel

`bootstrap.md` §4.7. The client uses whatever mosey the host has: `mosey`
on `PATH`, else `~/.local/bin/mosey`. Only where there is neither, or
`~/.local/bin/mosey` (on `PATH` or not) speaks another protocol, does it
copy a build there (its own file, or its own version's release asset), and the copy
then runs as the user. Upgrading a host's mosey is Nix's or the user's,
never the client's.

- **What is sent** is the client's own running file, or, for another
  platform, the release asset of exactly the client's version, whose
  SHA-256 must match the release's `SHA256SUMS` before a byte goes to the
  far host (`bootstrap.md` §4.7.4). Downloads are HTTPS only, redirects
  included, size-bounded, with a deadline. **This is integrity, not
  authenticity:** a compromised GitHub account or CI, or a stolen
  release-upload token, can publish a matching `SHA256SUMS` and binary,
  including an older release's genuine binary under the current name.
  The trust placed in the download is the trust placed in the GitHub
  release, the same as a user who downloads it by hand. CI does attest
  every release binary (`bootstrap.md` §4.6: SLSA provenance signed
  through GitHub OIDC and Sigstore's public-good Fulcio and Rekor, for
  mosey's release workflow on `refs/heads/trunk`), and a person can check
  one with `gh attestation verify FILE --repo danielbodart/mosey`, but the
  client does not: sigstore-go, which did, doubled the binary and was
  removed (D7 as amended 2026-11-15; PLAN O16, `bootstrap.md` §14 C,
  parked until a small verifier). The same-platform path, which is the
  usual one, uses no network and trusts nothing but the file the user is
  already running.
- **The installer** (`mosey --serve=install`, `bootstrap.md` §4.7.7) is the
  only writer of `~/.local/bin/mosey`. It checks length and SHA-256 through
  one descriptor; the rename that follows goes by name, inside a
  directory only the user can write, and what it moved is then checked to
  be that same file (device and inode) and removed if not, so a
  cut-short, altered or swapped copy is never left installed; works
  below `~/.local` only through `O_NOFOLLOW` descriptors,
  so a planted symlink cannot redirect the write; requires every directory
  to be the user's and writable by nobody else; and never replaces a file
  that is not the user's (D7). **T13** (another local user) cannot plant
  or replace anything there. **T12** (same uid) can, as it can with any
  file the user runs: that is why the copy is never a trust anchor, for
  provenance or anything else [S7 §10].
- **The probe** runs `mosey` from the remote `PATH` as it is, as ssh
  would run any command there: the host's own install, trusted as the
  host's other programs are, except that `~/.local/bin/mosey`, the file
  the installer writes, is first asked its protocol when it is where the
  installer would have written it, so one of another protocol can be
  replaced. Off `PATH` it runs that file only where the installer would
  have written it: no symlink at `~/.local/bin` or the file, and
  both, and `~/.local`, the user's (`bootstrap.md` §4.7.2). It
  asks the copy its protocol numbers and nothing more, so it cannot tell
  a copy that T12 replaced with one that answers correctly; the
  install-time hash check is done on the far side, by the copy itself,
  and catches damage, not substitution. A server that answers with
  another protocol is refused with both numbers named, never talked to
  in a protocol it does not speak; the client replaces only
  `~/.local/bin/mosey`, the one file it writes, and only with consent.
- **Hopping.** A session served from `~/.local/bin/mosey`, on a host
  with no `mosey` on `PATH`, gets `~/.local/bin` first on its shell's
  `PATH` (`server.md` §2.5), as the stock login profiles already put it
  when it exists. The server itself checks the directory by the
  installer's rules first (no symlink, the user's, writable by nobody
  else, nor `~/.local` or the home), as the probe does, so a
  `-remote ~/.local/bin/mosey`, which skips the probe, cannot put
  commands others can write first on `PATH` either; T12 could plant
  other commands there, as it could in any directory of the user's on
  `PATH`.
- **The probe line** comes from the far host (T5). It is parsed strictly
  and fuzzed, and it chooses only which public build is sent. Nothing the
  far host says appears unfiltered in the consent question, which is made
  of the client's own values.
- **Consent.** The first copy to each `user@host:port` is asked for
  (`-upload ask`); the answer is remembered in the client's state
  directory, 0600. A user who wants nothing copied says `-upload=no`.
- **No secret** travels with the upload: its stdin is the binary, its
  argv the hash and size. The one-shot key in the ClientLine
  sent to the probe is public by design (B3), and the same line is sent
  again after the upload because no launcher ever read it.
- **Costs** to the far host: one file of at most 128 MiB, in the user's
  own quota, replaced in place rather than added to.

### 4.14 Chaff (D11, O10) — T2, T3

`ssp.md` §9.1. Without it every keystroke is its own datagram and the
server answers each one, so a passive observer reads inter-keystroke
timing off either direction, at password prompts too (R2; Song, Wagner
and Tian, USENIX Security 2001).

- **Both ends chaff while the user types.** The client from any input
  until a random 1–2 s after the last; the server while the client's
  CHAFF frames arrive, and 1 s after. A chaffing end sends exactly one
  datagram per 20 ms tick of its own grid: SSP data if due, an owed ack
  early, else a CHAFF frame of its chaff size (64 B at both ends), and
  every datagram is padded to at least that size while chaffing, so keys,
  echoes, echo acks, acks and chaff are one size on one grid. The client's
  64 B while chaffing is Dan's decision of 2026-11-15 (`ssp.md` §9.1.5);
  when not typing its floor is 40 B (§9.2). The server's half is not optional: with the client alone
  chaffing, the server's echoes named every key [M `ssp.md` §9.1.5].
- **What it hides, measured** [M `ssp.md` §9.1.5]: an observer at both
  ends, knowing the tick and the floors, picks out 2.0% of keys on the
  LAN and 2.4–5.0% on the hotel, train and HSR profiles without netsim's
  per-packet delay spikes, against 100% without chaff. What it still
  picks out is structural: the first key of each run of typing (about 2%
  with S5's typist), and keys piled up unacknowledged until a datagram is
  over the floor (10.3% on the LTE driving trace, whose outages hold keys
  for seconds). On those paths hiding was the same at every tick from 10
  to 50 ms. **With netsim's per-packet delay spikes left in** it is much
  worse and depends on the tick: at 20 ms with a 40 B client chaff size,
  9% of keys exposed on the hotel, 50% on the train and 33% on HSR,
  nearly all by size; at 50 ms, 6%, 25% and 17%. With the 64 B client
  chaff size in force since 2026-11-15 the same 20 ms runs exposed 2.2%,
  6.8% and 4.0% (8.3% on the LTE trace), for 35% more client bytes while
  typing [M `ssp.md` §9.1.5]. Whether real paths behave like the spiky or
  the calm profiles is not settled; Dan closed O10 at 20 ms regardless.
- **What an active attacker adds** (T3). By dropping or delaying the
  client's packets for a while, a T3 can hold keys unacknowledged so they
  pile up into datagrams over the floor, which stand out by size: it can
  make the "by size" leak that outages cause on the LTE trace (10%) or the
  train (47%) happen when it chooses, for example at a password prompt.
  It learns the number of keys in a pile-up only to within Padmé's
  buckets, and the attack is visible as a stall in the session.
- **What it costs**: about 20–30 ms on the median echo (less where
  prediction shows the key at once), and about 5000 datagrams and 410 kB
  a minute both ways while typing. An idle session sends no chaff.
- **What it does not hide**: that a session is active and when a run of
  typing starts; its end to within the 1–2 s linger; gaps longer than
  that, which start a new run; datagrams over the floor (keys piled up,
  pastes, a command's output); and the transport's own frames (rekeys,
  keepalives, path validation), which are not keystroke-timed (R2, R10).
- **The CHAFF frame** is authenticated like any other and then dropped;
  it never reaches SSP's parser, state or RTT estimate. Its one effect is
  to keep the server chaffing, which an active attacker (T3) cannot
  forge, and can only stop by dropping packets, which it could do anyway.

### 4.15 Agent forwarding (D25) — T5, T13, A11

What forwarding gives away is what `ssh -A` gives away, and no more: a
program running as the user on the far host can ask the user's agent to
sign while the session is attached. mosey adds the guarantees below so that
it gives away no *more*, and so that agents that judge requests (a
destination-constrained `ssh-agent`, an agent that asks the user about
each signature) see the same evidence they would under `ssh -A`.

- **Off unless asked** (D25): `forwardagent` from `ssh -G`, with `-A`/`-a`
  on top, exactly as ssh decides. The bootstrap never forwards the user's
  real agent; its agent channel reaches only the capture socket
  (`bootstrap.md` §4.1).
- **The bind is ssh's own** (T5). A hostile server can mint a valid bind
  for any host it can reach [S3 E11]. The capture takes only the first
  frame of one connection from our own ssh's pid and uid, requires exactly
  the trigger and then EOF after it, and refuses the whole capture on
  anything else (`agent.md` §2.2); the bind's host key must then be in
  the user's `known_hosts` for the destination ssh checked (§2.3). The
  injected-bind attack of [S3 E11] ends in NoBind and the agent off.
- **No trustworthy bind, no agent.** The client then offers no agent
  channel in its hello, and the transport drops every CHANNEL frame on a
  connection that negotiated only the terminal (`transport.md` §4.4): the
  server cannot open one anyway [S3 E7b].
- **Replayed at the head of every channel**, before any byte from the far
  host, on a fresh connection to the agent per channel (`agent.md` §3),
  so per-connection state in the agent (binds, constraints) sees the shape
  `ssh -A` gives it [S3 E8].
- **Opaque after the bind** (D28): the client never parses the agent
  stream, so extension messages pass through untouched and a parser bug
  cannot be reached through them. What it does parse, the stream frames,
  is bounded, validated in full before any state changes, and fuzzed
  (`FuzzParseFrame`, `FuzzCapture`).
- **Bounded** (A9): at most 16 streams per connection, 64 KiB of send and
  receive buffer each, 32 KiB in flight, windows enforced
  (`agent.md` §5.7). A far host cannot make the client buffer more than
  2 MiB, and the client's agent connection is back-pressured, not
  buffered without limit.
- **The server's socket** (T13) is in the session's 0700 directory, mode
  0600, and the spawner checks every peer's uid. Other users cannot
  reach it; the user's own processes can, which is the point.
- **proto's sandbox is unchanged.** The spawner accepts and passes each
  connection's fd; proto only reads and writes fds it was given, and its
  seccomp policy gains nothing (`server.md` §2.7, §6.3).
- **No agent-specific code** (D28, amended 2026-11-15): mosey treats
  every agent alike and has no code for any particular agent or for an
  agent's helpers on the far host. What an agent needs beyond `ssh -A`'s
  semantics it does on its own side, so nothing a particular agent ships
  widens mosey's attack surface or changes what mosey forwards.


### 4.16 Prediction (D12) — A2, T2, T5

`prediction.md`. The client draws its guess at the echo of easy keys
before the server answers, and takes it back when the server's screen
disagrees.

- **It keeps D9.** Every predicted cell comes from bytes the local user
  typed, and is judged against structured cells; the client parses no
  remote output to predict. A predicted cell is a printable code point
  that passed `screen.ValidCluster`, or a blank, and the overlay keeps
  every grid invariant (`prediction.md` §11.3), so the renderer's
  defence in depth (§4.7) sees nothing new.
- **Passwords (A2).** While the newest frame says the pty has echo off
  (`!ECHO && ICANON` on mosey's own pty, so not for a prompt inside a
  multiplexer or nested session; see the next point), the client
  predicts nothing and logs nothing, and entering it drops every
  prediction. Only a typed glyph that changes its
  cell confirms an epoch, never a backspace, so a masked prompt in raw
  mode (fish's `read -s`) doesn't reveal the next key either. Measured on
  S6's traces: 0 of 555 password keys drawn, against 3–11 when backspace
  could confirm [M S6 §5]. A password field a raw-mode TUI draws itself
  without a mask is protected only by the epoch rules, statistically.
- **Keystroke timing (T2).** The paper's echo-ack-only frame, sent about
  50 ms after a key that changed nothing on screen, would name each key at
  a no-echo prompt from the server's side. The server does not advance
  its echo ack while echo is off, and the new `EchoApplied` field rides
  only on frames that were going anyway, so at a password prompt the
  server sends nothing per key (`prediction.md` §3.1, §13.2; R2). Not
  inside tmux, screen, or a nested ssh or mosey: those keep mosey's pty
  in raw mode, so the bit is never set, the echo-ack frame goes out after
  each password key as after any other, and the client logs those keys.
  Chaff (§4.14) is the remaining defence for timing there, and the epoch
  rules for display.
- **A hostile server (T5).** It can make predictions wrong (they come
  down when refuted), keep them tentative (never drawn), or confirm an
  epoch by drawing what the user typed. It can't make the client draw
  anything the user did not type: the echo ack and applied count are
  clamped to what the client sent, and every structure the engine keeps
  is bounded (`prediction.md` §12). `FuzzEngine` checks the bounds, the
  grid invariants of every overlay, and that nothing unconfirmed or typed
  under echo-off is drawn.
- **Memory.** The input log keeps at most the last 512 key events of up
  to 64 bytes each, never those typed while echo was off, and zeroes each
  entry as it leaves; the frame that turns echo off zeroes all of it, so
  a password typed ahead of the prompt is not kept either.

## 5. Accepted residual risks

Each is a deliberate trade, with the reason and the evidence. Revisit only
with Dan.

| # | Risk | Who | Why it is accepted | Mitigation in place / planned |
|---|---|---|---|---|
| **R1** | **Compression length side channel** (CRIME/BREACH class). AEAD hides content, not length. Output the attacker influences (a log line, chat, a web page in a terminal browser) compressed in the same frame as a secret on screen lets an on-path observer test guesses by datagram size | T2 + T4 together | D24: compression is always on. Mosh 1.4.0 compresses every update with no padding [M S5 mosh-compression]. Flate cuts screen bytes to 0.35x [M S5 §8] | Per frame, never across frames. **The acknowledged screen is never a preset dictionary**: it puts the whole screen in the compressor's window, so the secret need not even be in the changed cells, and it is the leakiest variant [S5 §8]. Padding and dictionary (O12) are decided in `ssp.md` §9.2: no dictionary ever, and every SSP datagram padded on its whole sealed plaintext to at least 64 bytes from the server and 40 from the client, 64 while it chaffs (`ssp.md` §9.2), with Padmé (PURBs, PoPETs 2019) above and the D5 limit as a cap. That keeps 88% of flate's saving and makes every keystroke echo, ack and heartbeat from the server one size [M S5 padding.md]. Padding blunts the leak and does not close it: an attacker can still add filler to push a frame across a Padmé boundary and count samples, at most 8 bits per frame up to 64 KiB [M S5 padding.md]. That residual leak is accepted, owned by **ssp**; timing is chaff's (O10). A frame under 32 B never compressed smaller, so small frames go raw [M S5 §8] |
| **R2** | **Keystroke timing, what chaff leaves.** Chaff (§4.14) hides which ticks carry keys within a run of typing; an on-path observer still sees when a run starts, when it ends to within 1–2 s, gaps longer than that, and keys whose datagram grows past the floor because earlier keys are unacknowledged (2.0–5.0% of keys on the LAN and spike-free profiles as measured with a 40 B client chaff size; with the 64 B now in force, 8.3% on the LTE trace and 2–7% on the hotel, train and HSR profiles with netsim's per-packet spikes, which exposed 9–50% at 40 B; a T3 can cause pile-ups at will by stalling the path) | T2, T3 | Making every client datagram as big as the largest pile-up costs on every tick. The client pads to 64 B while chaffing (Dan, 2026-11-15; 40 B otherwise, §9.2), which cut the train profile's exposure from 50% to 7% and the LTE trace's 10.3% by size to 6.2%, for 35% more client bytes while typing [M `ssp.md` §9.1.5]; a larger size costs more on every tick for pile-ups that are rarer still | 20 ms tick both ways, random linger, server chaff, early acks on the tick so keys are acknowledged sooner; no echo-ack-only server frames while the pty has echo off (D11; prediction slice), so the end of a run does not name the last key of a password |
| **R3** | **No rekey on idleness** (D20). The keys in memory after a burst of typing protected that burst until the next 120 s rekey | T8 | Decided in D20 | Exposure is bounded by `RekeyAfter` + `KeepPrevFor` (≤ 130 s) **provided the 120 s timer runs on epoch age and fires on any send, SSP heartbeats included** (`transport.md` §6.2 does this); and, whatever an on-path attacker does to rekey frames, by `RejectAfterTime` + `KeepPrevFor` (≤ 190 s), because no data is sealed under keys older than 180 s (§4.3) |
| **R4** | **A compromised proto is the user.** It holds the pty master and the keys | T7 | Inherent: whatever reads the network and writes the pty can type into the shell (S4 red team: every layout with a key holder) | proto's pre-auth surface is a fixed header, a map lookup and the standard library's AEAD; everything else needs the keys. Every parser is fuzzed. Landlock + seccomp stop the likely Go bug class (confused deputy) from reaching files, sockets or other processes directly. It can still `sendto` anywhere from its socket: seccomp cannot filter `sockaddr` |
| **R5** | **A stolen client keeps the session until the user resumes it** from somewhere else, and a detached session lives until its shell exits: there is no idle timeout | T8 | A session is resumable for as long as its shell runs (`bootstrap.md` §9.3), as Mosh's server and tmux are | Rekey bounds what stolen keys reveal of the past (§4.3). Any resume revokes the stolen client and wipes its keys (§4.5, D26) |
| **R6** | **Erasure is "after GC reuse"** on darwin and in non-release builds; `crypto/hpke` keys can't be erased on demand | T8 | Go offers no other way. Likewise **swap and hibernation**: Go cannot pin or exclude the pages a key lands on, so a key can reach a swap device or hibernation image; an encrypted swap is the user's defence | `runtimesecret` on linux release builds (§4.10). The 30 s credential TTL bounds how long an unused one-shot key lives. Core dumps are suppressed in every process that holds a secret (§4.10) |
| **R7** | **A leaked bootstrap line plus a sustained msg1 flood** can keep the genuine client from finishing within the TTL | T9 + T1 (or T3) | A flood needs *distinct* msg1s that pass `mac1` and decapsulate, so it needs the PSK: a replay of the genuine msg1 is answered from the cache and evicts nothing (§4.1). With the leak, the worst case is DoS, never impersonation | ≤ 4 responders per credential, oldest evicted, replays never counted; confirmation-based consumption [S1 §3.1] |
| **R8** | **On-path denial of service**: a T3 that drops packets stops the session, including one that drops only rekey frames until the keys reach `RejectAfterTime` | T3 | No protocol can prevent it | SSP keeps state and recovers when the path comes back; a blocked rekey stalls the session rather than stretching the epoch (§4.3) |
| **R9** | **A compromised emu can insert harmless reply text** (a well-formed CPR or DA) into a line being edited. A vi-mode readline acting on the ESC is the worst case. A program that remaps its own termios special characters to digits could make a digit in a reply act as a control | T6 | The grammar already forbids every C0 but the fixed framing; the remaining cases need a compromised emu *and* a program in an unusual mode | Exactly one reply per message, from fixed templates [S4 §3.6] |
| **R10** | **Metadata**: the 5-tuple, the port range 60000–61000, the 3 s heartbeat and datagram sizes reveal that a mosey session exists, when it is active, and how much the screen changes | T2 | UDP state sync is the product; hiding traffic shape is out of scope | The receiver index changes each rekey, so the header doesn't link epochs [S1 §1.1] |
| **R11** | **Screen spoofing**: a hostile program can draw anything, including a fake mosey status line, a title naming another host, or link text that differs from its URI; and it can **write** the clipboard (pastejacking) | T4 | D27 allows OSC 52 writes and OSC 8 by decision; this is what any terminal does | Clipboard read never; writes capped at 64 KiB; links only http, https, mailto; title bidi controls stripped |
| **R12** | **Unvalidated addresses get up to 3x** what came from them, including the 0.5-RTT output to an unconfirmed msg1 source (~3.6 KB) | T1 spoofing | RFC 9000's factor; S5 measured 2.96x as the worst case in practice | [M S5 §6] |
| **R13** | *Closed: arm64 runs KILL since CI run 43626969195, as amd64 always did (§4.11).* Was: **seccomp in ERRNO mode** on arm64 until a real-hardware soak passes (D22): a compromised role gets EPERM and carries on probing instead of dying | T6, T7 | KILL with an incomplete allow-list kills a healthy process (a missing `pread64` hid for 60 s [M S4 §3.5]); the denials themselves are identical, so containment holds | The policy exists and is tested by the BPF interpreter for amd64 and arm64; the CI KILL soak (≥ 120 s per Go upgrade and architecture, under a CPU quota) turned KILL on, and now guards it |
| **R14** | **`crypto/hpke` is outside the 2025 Trail of Bits audit** | all | Composing X-Wing ourselves is closer to writing our own crypto (D19) | Recorded in `DEPENDENCIES.md`; part of the external review before 1.0 (PLAN §6.5) |
| **R15** | **tuios is young, mostly one author**, and has no bound on OSC 8 link storage | T4 | Best candidate by a wide margin (S2); fork if upstream stalls (D23) | Pinned; fuzzed; the emu sandbox and its memory limits (512 MiB cgroup, 1 GiB `RLIMIT_DATA`; R18) contain it; upstream fixes listed in S2 |
| **R16** | **Fuzzing so far is minutes, not hours** (S1: 38.5 min across targets; S2: 15–20 min per target) | all | Spikes, not production | Every attacker-reachable parser has a target, each run for minutes locally before it lands and 10 s in CI; continuous fuzzing before 1.0 (PLAN §6.5) |
| **R17** | **A proto that dies ends the session**: resume brings back a client that went away, not a proto that crashed, so the shell is hung up | T7, bugs | Restarting proto on the same pty is a later slice (`server.md` §5.4) | When proto exits the spawner hangs up the pty, so no unreachable shell is left running |
| **R19** | **The forwarded agent is usable by the far host** while a client with the agent is attached: any program running as the user there (or root) can ask for signatures, and can learn the public keys | T5, A1's holder | That is what agent forwarding is, under `ssh -A` too; D25 forwards only when the user's ssh config or `-A` says so | Off by default as in ssh. Agents that judge requests do so as under `ssh -A`: confirmation (`ssh-add -c`), destination constraints (`ssh-add -h`, which the replayed bind makes work [S3 E8]), any question the agent asks the user. Detaching ends every agent channel; a session started without the agent has no socket. The lengths of agent requests are padded as SSP's are (R1's rule), not hidden |
| **R18** | **Without a systemd user manager, emu's memory bound is `RLIMIT_DATA` alone**: 1 GiB per session instead of 512 MiB, counted in address space rather than charged memory, with swap not excluded | T4, T6 | Many hosts have no user manager (non-systemd distributions, containers, sshd without PAM [S4 §3.10]); refusing to run there would rule them out for no security gain, since `RLIMIT_DATA` is still a hard bound | `RLIMIT_DATA` set by emu on itself before its sandbox, not raisable (no `setrlimit`/`prlimit64` in its policy); the spawner logs once that the cgroup is missing; if neither limit can be set, emu does not start (§4.8). Whether 1 GiB stops S2's link flood is **not yet tested**: `TestEmuMemoryLimitRestartsEmu` (`server.md` §6.3, §12) is still to be written. What is tested is that the spawner recognises the out-of-memory death (`TestOutOfMemoryIsRecognisedOnAnyLineNotJustTheLast`) and rebuilds a killed emu (`TestTheSpawnerRunsASessionAndRebuildsEmu`) |

## 6. Who can do what (slice 1)

Y = can, . = cannot, given the mechanisms above.

| | Read input/output | Type into the shell | Make the server reflect traffic | Run code on the client host | Exhaust server memory | Learn when the user types |
|---|---|---|---|---|---|---|
| T1 off-path | . | . | . (≤ 3x) | . | . | . |
| T2 passive | . (lengths only: R1) | . | . | . | . | runs of typing only, not keys within them (§4.14, R2) |
| T3 active | . | . (replays rejected) | . (≤ 3x, §4.4) | . | . | as T2, plus how many keys pile up while it stalls the path (§4.14, R2) |
| T4 hostile output | its own output | . | . | . (D9) | . (cgroup or `RLIMIT_DATA`: ≤ 512 MiB or ≤ 1 GiB per session, R18; budgets) | . |
| T5 hostile server | — (it is the server) | — | — | . (D9, bounded decoder, no forwarding in the bootstrap ssh: §4.9) | — | — |
| T6 compromised emu | output only | . (reply grammar) | . | . | . (cgroup or `RLIMIT_DATA`, R18) | . |
| T7 compromised proto | **Y** | **Y** | **Y** (`sendto`) | . (D9) | — | **Y** |
| T8 stolen client | **Y** while it holds the session; from keys, ≤ 130 s of past traffic, and ≤ 190 s even if a T3 blocks rekeys (§4.3); nothing from a core dump (§4.10) | **Y** (R5) | . | — | . | — |
| T9 leaked stdout | . | . | . | . | . | . |
| T10 quantum harvest | . | — | — | — | — | — |
| T13 other local user | . | . | as T1 | . | . | . |

## 7. Constants

| Constant | Value | Provenance |
|---|---|---|
| Max UDP payload | 1232 B | [D5]; RFC 8200 minimum MTU 1280 − 40 − 8 [derived] |
| Max handshake or rekey message | 1200 B | [D5]; QUIC's floor [RFC 9000 §14] |
| msg1 hello budget | ≤ 34 B | [derived]: S1's 1208 B msg1 with a 42 B hello, less 8 [M S1 §2.1] |
| X-Wing public key / ciphertext | 1216 / 1120 B | [M S1 provenance] from `crypto/hpke` |
| Credential id / session id / PSK | 8 / 16 / 32 B | [ours, S1] |
| Credential TTL | 30 s | [D20, S1 ours]: SSH stdout to UDP plus retransmissions |
| Unused credentials per session | 2 | [D20, S1 ours] |
| Unconfirmed responders per credential | 4 | [S1 ours] |
| Replay window | 1984 counters | [RFC 6479 construction; size ours, S1] |
| RekeyAfter | 120 s | [D20]; WireGuard REKEY_AFTER_TIME |
| Server's rekey backstop | `RekeyAfter` + 10 s = 130 s | [`transport.md` §6.2, ours] |
| RekeyAfterMessages (D20's "N packets") | 2^60 | WireGuard REKEY_AFTER_MESSAGES [`transport.md` §6.2] |
| RejectAfterTime: nothing but rekey frames sealed under older keys | 180 s | WireGuard REJECT_AFTER_TIME; §4.3. `transport.RejectAfterTime`, tested by `TestBlockingOnlyTheRekeyFramesStallsTheTerminalUntilTheyGetThrough` |
| RekeyRetry (INIT and confirmation resends) | 1 s | [S1 ours, untuned] |
| Reject after messages | 2^64 − 2^13 − 1 | WireGuard REJECT_AFTER_MESSAGES [S1] |
| Forged packets per key before rekey or close | < 2^36 | [RFC 9001 §6.6] ChaCha20-Poly1305 integrity limit |
| KeepPrevFor | 10 s | [S1 ours, untuned] |
| Rekey responder floor | ≥ 1 s per epoch; ≤ 1 encapsulation per epoch | [ours, this document] |
| Anti-amplification factor | 3 | [RFC 9000 §8.1; D21] |
| Path challenge token | 8 B random | [RFC 9000 §19.17] |
| Path challenge re-send | ≤ once per RTO | [S5 ssp-spec §2.1, D21] |
| Largest screen diff (`MaxDiff`, the client's `MaxRemoteBytes` and decompression limit) | 64 MiB | [`screen.md` §5.12, derived from the clamp and the history window] |
| History window (`HistoryLines`, `HistoryCells`) | 1000 lines, 200,000 cells, at both ends and in any one diff | [D], [derived], `screen.md` §2.5, §3 |
| Largest input diff (the server's `MaxRemoteBytes`) | 128 KiB | [`ssp.md` §10.1] |
| Fragments per instruction / instructions in reassembly / bytes held | `ceil(MaxInstruction / Chunk)` (≤ 65535) / 4 / `MaxPartialBytes = 2 × MaxFragments × Chunk` | [`ssp.md` §5, derived] |
| Compression | always attempted; sent stored when DEFLATE is not shorter (in practice every frame under 32 B) | [`ssp.md` §4.1, M S5 §8] |
| Chaff tick / linger / size | 20 ms both ways / client 1–2 s random, server 1 s / 64 B both ways | [D (O10, Dan 2026-11-15), M `ssp.md` §9.1.5] / [D] / [D, Dan 2026-11-15, from the train profile, `ssp.md` §9.1.5] |
| Length padding | every SSP datagram: sealed plaintext at least 64 B (server) / 40 B (client; 64 B while it chaffs), Padmé above, capped at the D5 limit | [`ssp.md` §9.2, D (O12), M S5 padding.md] |
| Window clamp | 1000 × 500 | [D23, S2] |
| Scrollback | min(10000, 1e6 / cols) lines | [D23, M S2 memworst] |
| emu memory | 512 MiB `MemoryMax`, `MemorySwapMax` 0 (cgroup, where available); 1 GiB `RLIMIT_DATA` (always) | [D23, S2; `server.md` §6.3] |
| emu request deadline (hung emu → `KillEmu`) | 30 s (T4) | [`server.md` §8] |
| Cell cluster / title / link / clipboard | 64 B / 256 B / 2048 B / 64 KiB | tuios cap [S2] / [S2] / [D27] / [ours, `screen.md`] |
| Reply queue | 64 KiB, drop and count | [M S2 replyflood] |
| emu restart backoff | 50 ms doubling to 5 s; ≤ 10 per 60 s | [S4 §3.8, ours] |
| UDP port range | 60000–61000 | Mosh's man page, so existing firewall rules apply |

## 8. Tests that hold this model

Each property above has a test; network behaviour runs on `netsim` under
`testing/synctest` (D18), and every attacker-reachable parser has a fuzz
target (architecture §6).

| Property | Package | Test (names say what is true) |
|---|---|---|
| A rejected packet changes no state | `transport` | `FuzzReceive` invariant; a forged and a bit-flipped packet move neither the window nor the peer |
| Replay window agrees with a reference | `replay` | `FuzzWindow` against a map |
| A leaked stdout line cannot impersonate either side | `handshake` | a test that gives the attacker the whole `CredentialLine` and fails to confirm |
| msg1, msg2, rekey halves ≤ 1200 B; msg2 ≤ msg1 | `handshake`, `transport` | size assertions over every hello the code can produce |
| Re-sourced packets never move the peer; the victim gets ≤ 3x | `transport` | netsim adversary tap, as S5's redirect attack |
| Rekeys converge under loss, duplication and reordering | `transport` | an interleaving property test, as S1's |
| Credential TTL, cap and confirmation-only consumption | `handshake` | forged msg1s with the PSK don't lock out the client |
| A replayed msg1 costs nothing and evicts nothing | `transport` | netsim: an adversary tap replays the genuine msg1 many times, from its own and other addresses, between msg2 and confirmation; the genuine client still confirms, no responder is evicted, and the decapsulation counter stays at 1 |
| No data under keys past `RejectAfterTime` | `transport` | netsim adversary tap drops only REKEY_INIT/RESP frames: no data frame is sealed under keys older than 180 s, the session stalls, and resumes once the tap stops |
| A lost REKEY_RESP is recovered with one encapsulation; crossing rekeys settle on the client's | `transport` | netsim: drop the first RESP; the resent INIT gets the cached RESP and the epoch advances; both timers fire together and exactly one rekey completes |
| Decompression fails closed at its limit | `ssp` | a flate bomb is refused, not truncated |
| Reassembly bounds hold | `ssp` | `FuzzReassembly`; out-of-range and inconsistent fragments end `Run` with `ErrProtocol` (`ssp.md` §8) |
| `Apply` refuses a diff that breaks a bound or the allow-list, unchanged | `screen`, `userinput` | `FuzzApply`, the S2 title probes, a C1 in a cell |
| Server diffs always apply and agree | `screen` | Diff/Apply round trip fuzz through tuios |
| The renderer writes no query sequence and no remote byte | `render` | render hostile grids; the output contains only the renderer's own sequences |
| Hostile ssh stdout and stderr reach the terminal sanitised | `bootstrap`, `client` | `FuzzReadCredential`; an ESC in a motd line never reaches the output |
| The bootstrap ssh forwards nothing | `bootstrap` | `ssh -G` on the exact command line with a config setting `ForwardX11`, `ForwardX11Trusted`, `LocalForward`, `RemoteForward`, `DynamicForward`, `Tunnel`, `PermitLocalCommand` and `LocalCommand`: every effective value is off (skipped if no `ssh`) |
| No process holding a secret can dump core | `client`, `server` | each role checks `PR_GET_DUMPABLE` is 0 and, where required, `RLIMIT_CORE` is 0 before its first key; a forced SIGABRT of the client leaves no core |
| A worst-case screen is delivered | `ssp`, `screen`, `e2e` | the largest diff the encoder can emit at 1000 × 500 with 64-byte random clusters is ≤ `MaxDiff`, and is delivered and applied under netsim |
| emu is restarted when hung, dead or over its memory | `server` | a silent emu produces `KillEmu{deadline}` after T4; a killed one comes back through `EmuLink`; S2's link flood hits the limit under `RLIMIT_DATA` alone (**not yet tested**: see R18) |
| `ValidReply` admits only fixed templates | `server` | `FuzzSplitReplies`: no token holds a C0 byte but its leading ESC and terminator, and every token `ValidReply` accepts is one of the shapes; `TestForgedRepliesAreRefused` |
| Each role's policy allows exactly its list | `sandbox` | the BPF interpreter, amd64 and arm64 |
| emu under its sandbox cannot open, connect, exec, create sockets or signal another process | `sandbox` (linux) | a red-team battery run inside the sandboxed role, as S4's, plus `tgkill` at a sibling and `fcntl(F_SETOWN)` + `O_ASYNC`, with Landlock's signal scope off |
| A resume revokes the old client and erases its keys; the old client exits saying who took over; nothing secret is reused | `e2e`, `server` | netsim: a client vanishes and another attaches with a new credential for the same SID; the first gets `Revoked`; real sshd: `mosey -s NAME` takes over and the first exits 3 (`TestSessionsThroughRealSSH`) |
| A background reconnect never takes a session another client holds (PLAN O15's placeholder, until Dan decides) | `server`, `e2e` | the launcher's holder rule (`TestReconnectTakesItsOwnSessionAndNeverAnothers`); netsim: a reconnect told `taken` exits 3 |
| Only the user reaches the attach socket | `server` | the directory checks refuse group/other bits, a foreign owner and a symlink; a foreign uid is closed unanswered |
| A protocol mismatch fails at once, naming both numbers | `handshake`, `transport`, `bootstrap`, `server`, `e2e` | a peer of protocol 2 fails the handshake at both ends with both numbers named, in both directions; a bootstrap line of another version, a greeting of another attach protocol and a `PATH` mosey of another protocol each fail with both numbers |
| An unknown element is skipped only when it may be, and a critical one refused with nothing changed (`versioning.md`) | `bootstrap`, `handshake`, `screen`, `userinput`, `channel`, `server` | every line, the hello, the screen diff, the userinput diff and channel frames: fuzzed with unknown elements of both markings (`versioning.md` §7) |
| Chaff hides keys within a run, in both directions, and idle costs nothing | `ssp` | one client datagram per 20 ms tick, all 64 B, ending 1–2 s after the last key; the server on its own grid at 64 B; an idle session sends no chaff; on every netsim profile the server's datagrams name at most 5% of keys and the LAN's wire at most 5% (`TestChaffHidesKeysOnEveryProfile`) |
| End to end under every netsim profile | `e2e` | client and server sessions in process; real binaries over loopback through a throwaway sshd |
| Only ssh's own bind is captured | `agent` | `FuzzCapture`; the unit list of `agent.md` §7: another pid, a bind as frame 2, no forwarding flag, a bad signature, a second connection, a byte after the answer, the deadline |
| The bind is pinned to known_hosts | `agent` | plain, hashed, `[host]:port`, alias, `@revoked` and CA-only entries |
| No agent channel without a negotiated agent | `transport`, `e2e` | CHANNEL frames on a terminal-only connection never reach `RecvChannel`; `-a` and `ForwardAgent no` give the shell no `SSH_AUTH_SOCK` |
| The agent sees what `ssh -A` shows it | `e2e` | through a throwaway sshd: remote `ssh-add -l`; an onward ssh signed through the forwarded agent; `ssh-add -h A -h 'A>B'` allows the hop and a key for another hop does not; an extension message passes byte for byte |
| Agent streams stay within their bounds | `channel` | `FuzzParseFrame`, `FuzzMux`; streams under seeded loss, duplication and reordering in virtual time; windows and limits |
| Prediction draws nothing unconfirmed, nothing under echo-off, and stays bounded against any server | `predict` | `FuzzEngine`; `TestEchoOffStopsPredictionEvenWhenTheScreenMatches`; `TestBackspaceNeverConfirmsAnEpoch`; the replay of S6's traces shows 0 password keys drawn |
| No echo-ack-only frame while echo is off | `server` | `TestNoEchoAckFramesWhileEchoIsOff`: keys at an echo-off pty change neither `EchoAck` nor `EchoApplied` |

## 9. Later slices

| Slice | What it adds to this model |
|---|---|
| Prediction (D12) | Landed: §4.16 |
| Chaff (D11, O10) | Landed: §4.14, R2 |
| Auto-upload (D7) | Landed: §4.13. Release binaries carry GitHub build attestations for checking by hand; the client checking them is parked (`bootstrap.md` §14 C, PLAN O16) |
| macOS server (D22) | Seatbelt or nothing; until then the sandbox returns `ErrUnsupported` and the server says it runs unconfined |

## Review notes

Twelve review items, each fixed in the body or answered here. Several had
already been addressed in the spec sections written since this document's
first draft (`transport.md`, `ssp.md`, `screen.md`, `server.md`,
`bootstrap.md`); in those cases this document was stale, and now cites
them.

1. **Replayed msg1 evicts the genuine responder** (§4.1, R7, §4.12, §8).
   *Fixed.* The finding was right about the text and about S1's prototype.
   `transport.md` §3.5 and §3.8 step 4 already key the cache by
   `HASH(msg1)` and answer an identical msg1 from it before `mac1`, with
   no new state; §4.1 now states that as a requirement, including that
   replays never count toward the cap of 4 and that the client resends
   msg1 byte for byte. New §4.12 row and §8 test; R7 restated as needing
   the PSK (T9) plus a flood (T1 or T3).
2. **Blocked rekeys make the forward-secrecy window unbounded** (§4.3, R3,
   §6 T8, §7). *Fixed, with one change to the proposed remedy.* Added
   `RejectAfterTime` = 180 s, but past it the session **stalls** (only
   rekey frames are sealed under the old keys) rather than closes, so a
   long honest outage still survives, which is the reason `transport.md`
   §6.2 gives for having no reject-after-time. The bound is now "≤ 130 s
   normally, ≤ 190 s whatever T3 does". **This contradicts `transport.md`
   §6.2's bullet "There is no reject-after-time" and needs that spec
   changed;** raised rather than picked, as this document's preamble
   requires. N is `RekeyAfterMessages` = 2^60 (already in `transport.md`
   §6.2), now in §4.3 and §7. Padding rekey frames to the data size
   distribution is not adopted: with the stall rule, recognising them
   buys an attacker only a DoS it already had (R8, R10).
3. **The client can core-dump its keys** (A6, B8, §4.10). *Fixed.* Every
   process that holds a secret suppresses core dumps before it holds one:
   `PR_SET_DUMPABLE=0` on Linux, `RLIMIT_CORE=0` in the client, proto and
   emu and on darwin. Swap and hibernation recorded under R6; `mlock` and
   `MADV_DONTDUMP` considered and not adopted, because Go cannot place a
   key on a page it controls.
4. **`tgkill` and `fcntl` reach other processes on pre-6.12 kernels**
   (§4.11, §6 T6). *Fixed.* Requirement on `server.md` §6.3 to
   argument-filter `tgkill` to the process's own tgid and `fcntl` to the
   runtime's commands with `O_ASYNC` clear (no `F_SETOWN`, `F_SETOWN_EX`,
   `F_SETSIG`), and both attacks added to the red-team battery. *Resolved
   in code:* `internal/sandbox/bpf.go` filters both, tested by
   `TestTgkillOnlyAtTheRolesOwnPid` and
   `TestFcntlOnlyWithCommandsThatCannotArmASignal`.
5. **No memory bound without a cgroup** (§4.8, §6, §7). *Fixed:* stale
   text. `server.md` §6.3 already sets `RLIMIT_DATA` 1 GiB in emu on every
   host, with the cgroup as an extra limit where a user manager exists.
   §4.8, §6, §7 now say so; new R18 records the weaker 1 GiB bound; and a
   new requirement: if neither limit can be set, emu does not start.
   `GOMEMLIMIT` was considered and not adopted: it is a soft target the
   runtime may exceed, so it adds nothing over a hard rlimit.
6. **The bootstrap ssh inherits X11 and port forwarding** (§4.9, §6 T5).
   *Fixed:* stale text, as `bootstrap.md` §4.1 already passes
   `ForwardX11=no`, `ClearAllForwardings=yes` and `PermitLocalCommand=no`
   ahead of user options and refuses `-X`, `-Y`, `-L`, `-R`, `-D`, `-w`.
   §4.9 now states it as a T5 requirement and adds `Tunnel=no`, which
   `bootstrap.md` lacks. `-x` is not added: `-o ForwardX11=no` comes first
   and the first value wins, which `bootstrap.md` checked with `ssh -G`.
   Added the `ssh -G` test to §8.
7. **Receiver limits below the largest honest diff** (§4.6 vs §4.7/§4.8).
   *Fixed:* stale text. The 512-fragment, 1 MiB figures were S5's toy
   values. `screen.md` §5.12 derives `MaxDiff` (48 MiB) from the clamp,
   and `ssp.md` §5 and §10.2 make the client's limits that value and
   forbid the server to exceed it. §4.6 now states the rule (limits are
   derived from the sender's worst case, never set below it) and the
   real numbers, and §8 has the worst-case-screen test.
8. **No cgroup mechanism or fallback** (§4.8, §6). *Fixed* with item 5,
   which it duplicates: the mechanism (a transient scope through `busctl
   --user`) and the fallback are in `server.md` §6.3, and R18 is the
   requested R-row.
9. **emu restart and hung emu can't be built from the IPC grammar**
   (§4.11, B3). *Fixed:* stale text. `server.md` §3.2 already has
   `KillEmu` (proto → spawner) and `EmuLink` with the fd (spawner →
   proto), and §8 has T4 = 30 s. B3, B4, §4.11, §7 and §8 now match it.
10. **"At most one REKEY_INIT answered per epoch" wedges under loss**
    (§4.3). *Fixed.* Reworded to at most one encapsulation per epoch with
    the RESP cached and resent for an identical INIT, which is what
    `transport.md` §6.4 does. The crossing-rekey tie-break (the client's
    INIT wins) and `RekeyRetry` (1 s) are stated in §4.3 and §7, with a
    test in §8.
11. **Client and spawner core dumps; spawner's "no key"** (§4.10, B8,
    §4.11). *Fixed* with item 3. The launcher and spawner set
    `DUMPABLE=0` (not `RLIMIT_CORE`, which the login shell would inherit),
    their row now says they briefly hold the credential line, and they
    wipe it once written.
12. **amd64 ERRNO in slice 1 is not D22** (§4.11, R13). *Fixed.* No longer
    cited as D22: §4.11 and R13 mark it as a proposed amendment to D22
    that needs Dan's agreement, and until then an amd64 ERRNO build is a
    development build, not a release. `architecture.md` §2 and `server.md`
    §6.1 carry the same allowance and need reconciling once Dan decides.
