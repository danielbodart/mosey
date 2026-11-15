# Agent forwarding: the bind, the channel, and the stream under it

Owner: **agent** slice. Packages: `internal/channel` (the reliable byte
stream over `transport.KindChannel`), `internal/agent` (the session-bind,
the capture state machine, the known_hosts pin, the replay and the relay),
and the agent parts of `internal/client`, `internal/server` and
`internal/transport`. The bootstrap's side is `bootstrap.md` §5 and §8; the
processes and their sockets are `server.md` §2.7 and §3.3; the wire under
it is `transport.md` §4.2 and §4.4.

Decisions implemented: D15 (typed channels, negotiated in the hello), D16
(galley and quoin questions work exactly as over `ssh -A`), D17 (any agent
that speaks the protocol; no dependency on quoin), D25 (replay the bind
captured from the system ssh; agent off without a trustworthy one), D28
(extension messages pass through; a fail-closed seam for quoin-attest).
PLAN §2 is locked; where this text and PLAN disagree, PLAN wins.

Provenance tags: **[D*n*]** a locked decision; **[S3]**, **[S7]** our
spikes (`docs/spikes/`); **[ssh]** OpenSSH 10.6p1's black-box behaviour or
its documents (`ssh_config(5)`, `PROTOCOL.agent`,
draft-miller-ssh-agent); **[RFC n]**; **[derived]** worked out here;
**[choice]** ours, untuned. No Mosh source was consulted. Mosh has no agent
forwarding (PLAN §1: #696 and #1297 are open), so there is nothing of
theirs to avoid here beyond the rule itself.

---

## 1. What the user gets

`mosey host` forwards the user's agent exactly when `ssh host` would: when
`ssh -G` says `forwardagent` is on (`yes`, a socket path or `$VAR`), with
`-A` and `-a` on top (`bootstrap.md` §5). Inside the session the login
shell's `SSH_AUTH_SOCK` names a socket of mosey's, and every connection to
it is carried to the client and into the user's own agent, which then sees
what it would see under `ssh -A`:

1. **ssh's own session-bind** for the bootstrap's SSH connection, with
   `is_forwarding = 1` (§3), byte for byte as ssh sent it at the bootstrap;
2. then whatever the program on the far host sends, unchanged: requests,
   further binds from an onward `ssh`, extension messages such as
   `provenance-v00@bodar.com` [D28], and anything a later agent invents.

mosey never parses the stream after the replayed bind. Any agent that
speaks the protocol works: OpenSSH's `ssh-agent`, gpg-agent, 1Password,
KeePassXC, quoin-signer [D17]. An agent that does not know
`session-bind@openssh.com` answers it with a failure, which mosey reads and
ignores, as ssh does ([ssh]: `ssh -A` to an agent without the extension
still forwards).

The agent is off, and the session goes on without it, when the config says
no, when the server refuses forwarding (`AllowAgentForwarding no`), or when
no trustworthy bind was captured (§2.4). The client says why once on
stderr, before the screen is up.

## 2. The bind capture (client)

`bootstrap.md` §8 is the procedure; this section is the state machine's
exact rules, which `internal/agent` implements as `Capture` and fuzzes.

### 2.1 The agent wire, as far as mosey reads it

From `PROTOCOL.agent` and draft-miller-ssh-agent [ssh]:

```
frame   = uint32 length ‖ byte type ‖ body      ; length counts type+body, ≥ 1
string  = uint32 n ‖ n bytes
SSH_AGENTC_REQUEST_IDENTITIES  11   (body empty)
SSH_AGENT_IDENTITIES_ANSWER    12   uint32 nkeys ‖ nkeys × (string key, string comment)
SSH_AGENTC_EXTENSION           27   string name ‖ contents
SSH_AGENT_FAILURE               5
SSH_AGENT_SUCCESS               6
SSH_AGENT_EXTENSION_FAILURE    28
session-bind@openssh.com contents:
        string hostkey ‖ string session-id ‖ string signature ‖ bool is_forwarding
```

Integers are big-endian (the agent protocol's own rule; the transport's
little-endian rule, `transport.md` §2.3, is for mosey's own datagrams). A
`bool` is one byte, 0 or 1; anything else is malformed [ssh: RFC 4251
§5]. The signature is an SSH signature blob (`string format ‖ string
blob`) by `hostkey` over `session-id`, verified with
`golang.org/x/crypto/ssh` (D19: no crypto of ours).

mosey reads exactly two kinds of agent frame: the bind and the trigger's
`REQUEST_IDENTITIES` in the capture, and the length prefix of the one reply
to its replayed bind (§3). Nothing else is ever parsed.

### 2.2 The state machine

One connection, one pass, no going back. Every frame is read whole, with
its length checked against `MaxCaptureFrame` before any byte of its body is
read [derived: an RSA-16384 host key is 2 KiB, its signature 2 KiB, a
SHA-512 session id 64 B, so a real bind is under 5 KiB; 16 KiB is three
times that].

```
Listening ─ accept #1 ─► Peer ─ SO_PEERCRED ≠ (ssh pid, our uid) ─────► NoBind
                           │
                           ▼
                     WantBind ─ frame: type 27, name "session-bind@openssh.com",
                           │    contents parse exactly (no trailing bytes),
                           │    is_forwarding = 1, signature verifies ─┐
                           │ anything else ────────────────────────────┼──► NoBind
                           │                    reply SUCCESS ◄────────┘
                           ▼
                     WantTrigger ─ frame: type 11, length 1 ─► reply ANSWER(0 keys)
                           │ anything else: reply FAILURE ─────────────────► NoBind
                           ▼
                     WantEOF ─ EOF ─► Bound(bind frame bytes)
                           │ any byte at all ──────────────────────────────► NoBind
                           │ deadline ─────────────────────────────────────► NoBind
```

- **One connection.** The listener is closed as the first connection is
  accepted, so a second agent channel from the server cannot reach it [S3
  review, critical].
- **The peer** must be the bootstrap ssh's pid and the client's uid
  (`SO_PEERCRED`). The capture is created before ssh starts and told the
  pid after `cmd.Start`; a connection that comes first waits for it, within
  the deadline.
- **Frame 1 is ssh's**, sent before ssh relays anything of the channel's
  [ssh]. Everything after it comes from the far host, which can mint a valid
  bind for any host it can reach [S3 E11]. So the machine takes the first
  frame as the bind and refuses the whole capture if anything but the
  trigger follows: a second bind, an extension, a trailing byte.
- **Deadline** `CaptureDeadline` = 10 s from the accept to EOF [S3].
- **NoBind** carries the reason, for the log and the one line on stderr.
  It closes the connection at once, so ssh's channel closes and the
  launcher's trigger fails fast.
- **The result is final at EOF**, before ssh exits: nothing can arrive on a
  connection that has ended, and nothing can connect to a closed listener.
  The client waits for it before it dials (`bootstrap.md` §7.3), bounded by
  ssh's exit (no connection by then: NoBind) and the deadline.

`Bound` keeps the bind frame's bytes exactly as ssh sent them (length
prefix included), and the parsed host key for the pin.

### 2.3 The pin (D25)

A valid signature proves only that some host key signed some session id. The
pin ties the key to the destination: the bind's host key must be a key the
user's own `known_hosts` lists for the host ssh just checked, using
`ssh -G`'s values:

- host: `hostkeyalias` if `ssh -G` printed one, looked up bare whatever
  the port, as ssh looks an alias up [ssh: checked by the e2e harness,
  whose known_hosts names the host by its alias with no port];
- otherwise `hostname` at `port`: on port 22 looked up bare, on any other
  as `[host]:port` (`known_hosts` format, `knownhosts.Normalize`);
- files: every path in `userknownhostsfile` then `globalknownhostsfile`
  (`ssh -G` prints them expanded [ssh]); a file that does not exist is
  skipped, one that cannot be read or parsed is an error (NoBind);
- hashed entries match; `@revoked` refuses; a key listed only under
  `@cert-authority` does not match (certificates are not handled yet:
  `bootstrap.md` §14), so a host known only by its CA has no agent.

`golang.org/x/crypto/ssh/knownhosts` does the matching (D19).

### 2.4 When the agent is off

| Cause | What the client says (once, stderr, before raw mode) |
|---|---|
| `forwardagent` no, or `-a` | nothing: the user asked for none |
| §5's socket is empty (`$SSH_AUTH_SOCK` unset, `$VAR` unset) | `mosey: not forwarding the agent: SSH_AUTH_SOCK is not set` |
| the capture directory or socket cannot be made | `mosey: not forwarding the agent: <why>` |
| no connection by the time ssh exited | `mosey: not forwarding the agent: the server did not open the agent channel (is AllowAgentForwarding off there?)` |
| NoBind from §2.2 | `mosey: not forwarding the agent: <reason>` |
| the pin fails | `mosey: not forwarding the agent: the bind's host key is not in known_hosts for HOST` |
| the server's hello has no agent channel | logged only: the remote mosey forwards no agent |

With the agent off the client leaves `ChannelAgent` out of its hello, so no
agent channel can exist on the connection: the transport drops every
`CHANNEL` frame of a connection that negotiated only the terminal
(`transport.md` §4.4), which is how the client "refuses any agent channel
the server opens anyway" [S3 E7b].

## 3. The replay (client, per agent channel)

For each agent channel the server opens (§4), the client:

1. connects to the agent socket `bootstrap.md` §5 chose, within
   `AgentDialTimeout` = 5 s [choice];
2. writes the captured bind frame, byte for byte;
3. reads exactly one reply frame (length at most `MaxBindReply` = 4 KiB
   [choice: the defined replies are 1 byte]) within the same 5 s, and
   discards it whatever its type: `SUCCESS`, `FAILURE` or
   `EXTENSION_FAILURE` [ssh: ssh -A goes on after a failed bind];
4. only then accepts the channel, and relays both ways until both
   directions have ended (§5.6).

Any failure in 1–3 refuses the channel (`RESET unavailable`), and the far
program sees its connection close, as when an agent is unreachable under
`ssh -A`. A new connection to the local agent per channel is what ssh does
too [ssh], so an agent that keys state to a connection (binds, constraint
checks, quoin's per-connection chain) sees the same shape.

**Destination constraints** (`ssh-add -h`) then work as under `ssh -A`:
the agent sees the bootstrap host's bind with `is_forwarding = 1`, then an
onward ssh's own bind, and judges the hop as it would [S3 E8].

## 4. Server side

### 4.1 Where the socket lives

The login shell's `SSH_AUTH_SOCK` is `R/mosey/SID-HEX/agent.sock`: the
session directory of `server.md` §2.6, made by the **spawner**. proto is
under Landlock deny-all and seccomp, so it cannot bind, listen, accept or
connect, and must not be able to (it holds the keys). The spawner, which
already accepts on `attach.sock` in the same directory, accepts here too
and passes each accepted connection to proto as an `AgentConn` IPC message
carrying its fd (`server.md` §3.3). proto never needs `accept4`: its
policy is unchanged.

- Made only when the session's first `ClientLine` says `agent=yes`, after
  the credential has named the session and before the shell starts (the
  shell's environment needs the path). A failure is logged and the shell
  starts with no `SSH_AUTH_SOCK`, which is what `ssh` without `-A` gives.
- `SOCK_STREAM`, mode 0600, in the 0700 directory; bound at
  `agent.sock.tmp`, listening, then renamed, as `attach.sock` is.
- Every accepted connection's `SO_PEERCRED` uid must be the spawner's own
  or root's (0), or it is closed unanswered. Root is let in because
  sshd's forwarded socket admits it too (its file mode is all that guards
  it), so `sudo -E ssh-add -l` works as under `ssh -A`; root can reach the
  user's processes and files anyway [ssh]. The attach socket stays the
  user's alone (`server.md` §2.6).
- The spawner keeps nothing per connection: it accepts, checks the peer,
  sends the fd to proto and closes its own copy. The bound on live
  connections is proto's (§4.2); a connection proto refuses is closed by
  proto.
- Removed with the session directory at teardown.

A resume does not change the socket: the shell keeps its `SSH_AUTH_SOCK`
for its whole life, and each connection goes to whichever client is
attached at the time, or is refused if none is, or if that client did not
negotiate the agent. A session started with `agent=no` has no socket, and
a later `agent=yes` resume does not add one: the shell's environment was
fixed when it started [derived].

### 4.2 proto

For each `AgentConn`: if no client is attached, or the attached connection
did not negotiate `ChannelAgent`, or `MaxAgentStreams` = 16 [choice] agent
channels are already open on it, proto closes the fd. Otherwise it opens an
agent channel (§5) and relays the fd's bytes into it and the channel's
bytes out to the fd, opaque both ways, until both directions have ended or
the channel is reset. proto cannot `shutdown(2)` (not in its policy), so
when the client's direction ends proto finishes writing what it has and
then closes the fd entirely; agent requesters read replies by their
length prefix and never rely on a half-close [ssh].

When the attached connection goes (detach, takeover), its channels are
reset and their fds closed; a requester sees its connection end, as under
`ssh -A` when the connection drops.

### 4.3 The quoin-attest seam (D28)

D28's forwarder hands each agent connection to the host's attester when the
host has one, and fails closed if that hand-off fails. In mosey's layout the
spawner is the only role that may connect to a socket or pass fds outward,
so the seam is in the spawner, between accepting a connection and passing
it to proto:

- **Where the attester is**: the fixed path `AttesterSocket` =
  `/run/agent-attest/handoff.sock` [S7], never from the environment or the
  user's files, so a program of the user's cannot point a session at its
  own "attester".
- **No attester** (nothing at that path, `ENOENT` on `lstat`): plain
  forwarding, as above. This is every host without quoin [D28 §1.6].
- **An attester is present**: the connection must be handed off and the
  attester's upstream end passed to proto instead. **This slice does not
  implement the hand-off**: its wire carries `h` (`Conn.HandshakeHash`),
  which quoin has not yet fixed. So with an attester present every agent
  connection is **refused** (closed unanswered, logged once), which is the
  fail-closed half of D28 already in force. Implementing the hand-off is a
  later slice and needs no change outside `internal/server`'s
  `attest.go`.

Checked per connection, so an attester that starts or stops during a
session takes effect at the next connection.

## 5. The stream protocol (`internal/channel`)

`ssp.md` §1.2 leaves the agent channel's reliability to this slice. It is a
small, reliable, flow-controlled byte stream per channel, multiplexed over
the transport's `CHANNEL` frames, modelled on TCP's sequence-and-window
design [RFC 9293] and QUIC's stream ids [RFC 9000 §2.1], kept as simple as
agent traffic allows: requests and answers of a few hundred bytes to a few
KiB [S7: provenance statements reach 9.2 KB], rarely more than one in
flight.

### 5.1 Frame body

A `CHANNEL` frame's body (`transport.md` §4.2) is:

```
off  len  field
0    4    stream id (u32, little-endian, transport.md §2.3)
4    1    op
5    …    the op's fields, then zero padding to the body's length
```

| op | name | fields after the op | fixed part |
|---|---|---|---|
| `0x01` | OPEN | type (1, a `handshake.ChannelType`), window (4) | 10 |
| `0x02` | ACCEPT | window (4) | 9 |
| `0x03` | DATA | flags (1: bit 0 FIN, others 0), offset (8), length (2), `length` bytes | 16 + length |
| `0x04` | ACK | flags (1: bit 0 FIN received, others 0), next (8), window (4) | 18 |
| `0x05` | RESET | reason (1) | 6 |

- **Padding.** Every body is padded with zero bytes so that the sealed
  plaintext (the kind byte plus the body) is at least
  `wire.PadFloor` = 64 bytes, rounded up with Padmé above that and capped at
  `transport.MaxPayload` + 1 [`ssp.md` §9.2's rule, applied here so an
  agent request is not told apart by its exact size; derived]. The parser
  refuses a body whose bytes after the fixed part (and DATA's payload) are
  not all zero.
- **Bounds.** `offset + length` and `next` are below 2^62 [derived: no
  stream comes near it, and the bound keeps every sum in an int64]. DATA's
  `length` fits the body. A window is at most `MaxWindow` = 1 MiB
  [choice]; a larger one is a protocol error.
- **Stream ids** are chosen by the side that opens. The **server** opens
  odd ids, 1, 3, 5, …, strictly increasing; the client's even ids are
  reserved for a later channel type that the client opens (port
  forwarding, D15), so the two can never collide [RFC 9000 §2.1].
- **RESET reasons**: 1 refused (type not negotiated or not served by
  this side), 2 limit (too many streams), 3 unavailable (the local end
  could not be reached), 4 protocol (the peer broke §5's rules), 5 gone
  (no such stream), 6 aborted (the local end failed). A receiver treats
  any value the same: the stream is over.

`channel.ParseFrame` is the one parser; its fuzz target checks that
anything it accepts re-marshals to the same bytes and that every refusal
leaves the mux unchanged (§5.7).

### 5.2 Opening

The opener sends OPEN(type, its receive window), and resends it on the
RTO (§5.5) until ACCEPT or RESET arrives, or `OpenTimeout` = 30 s
[choice: above the client's 5 s agent dial with room for a lossy path]
passes. The receiver:

- answers RESET refused to an OPEN whose type it does not serve, or whose
  id has the wrong parity for the sender; RESET limit when it already has
  `MaxStreams` = 16 live streams [choice];
- otherwise makes the stream (state *Opening*) and asks its owner (the
  client's agent forwarder, §3) in the background; a resent OPEN for an
  *Opening* stream is ignored, one for an open stream is answered with
  ACCEPT again;
- sends ACCEPT(window) when the owner takes it, RESET when it refuses.

The opener sends no DATA before ACCEPT: one round trip per agent
connection, as an SSH channel open costs [RFC 4254 §5.1].

### 5.3 Sending

Each direction of a stream is a byte sequence numbered from 0. The sender
keeps every byte it has sent and not had acknowledged, at most
`SendBuffer` = 64 KiB [choice: a fat agent answer in a few windows];
writing more blocks the local reader, which is the back-pressure into the
local socket. It sends DATA covering bytes from `next-to-send` while:

- the bytes are within the peer's window: `offset + length ≤ peerNext +
  peerWindow`, from the newest ACK;
- the mux's unacknowledged bytes across all streams stay within
  `MaxInFlight` = 32 KiB [choice: a burst of at most 28 datagrams beside
  the terminal's traffic].

Each DATA carries at most `MaxData` = `transport.MaxPayload` − 16 = 1186
bytes. A local end of input is a FIN: the flag on the last DATA, or a DATA
of length 0 at the end offset.

### 5.4 Receiving

The receiver keeps `next`, the first byte it has not received, and a
buffer of bytes received and not yet written to the local end, at most
`RecvBuffer` = 64 KiB; its window is `RecvBuffer − buffered`.

- DATA with `offset ≤ next < offset + length`: the bytes from `next` on,
  up to the window, are appended; `next` advances.
- DATA wholly below `next`: a duplicate; DATA starting above `next`: out of
  order, dropped (no reassembly: the sender's go-back resend fills the
  gap, §5.5). Both are still acknowledged.
- FIN at offset `f`: the stream's end is `f`. A second FIN at another
  offset, or any byte at or past `f`, is a protocol error (RESET
  protocol). Once `next = f` and the buffer is drained, the local end is
  told (§5.6).
- Every DATA is answered at once with an ACK(next, window, FIN received if
  `next = f`): agent traffic is too sparse for delayed acks to save
  anything, and an immediate ACK keeps the RTT sample clean.
- When writing to the local end frees at least half the buffer, or opens
  a window that was below one `MaxData`, an ACK goes out unasked (a window
  update).

An ACK whose `next` is above what was sent, or that moves backwards, is a
protocol error; one that repeats is harmless.

### 5.5 Retransmission

One RTO per mux, from RFC 6298: SRTT and RTTVAR from ACKs of DATA sent
once (Karn's rule: never from a resent byte), `RTO = SRTT + 4·RTTVAR`,
initial 1 s, floor `MinRTO` = 200 ms [choice: above D11's effective
~150 ms floor, since this peer acks without delay], cap `MaxRTO` = 4 s
[choice]. When the oldest unacknowledged byte of a stream has waited an
RTO, the sender goes back: `next-to-send` = the oldest unacknowledged
byte, and the RTO doubles up to the cap. An ACK that advances resets the
doubling. The same timer resends an unanswered OPEN, and, while a peer
window of 0 holds back data, sends a DATA of length 0 at the next offset
as a probe, which the peer answers with an ACK.

There is no stall limit: a stream lives as long as the connection under
it, through outages, as an `ssh -A` channel lives as long as its TCP
connection. The connection ending (detach, takeover, the shell exiting)
ends every stream on it.

### 5.6 Closing

A stream is **done** when both directions have ended: this side's FIN is
acknowledged and the peer's FIN is received and everything before it
written out. A done stream is kept for `Linger` = 10 s [choice: several
max RTOs] answering resent DATA with ACKs, so a lost last ACK does not
leave the peer resending; at most `MaxLinger` = 64 are kept, oldest
forgotten first. A frame for an id the mux does not know (never seen, or
forgotten) is answered with RESET gone, except a RESET, which is never
answered.

- The **client** (unsandboxed) passes the peer's FIN to its agent
  connection as `shutdown(SHUT_WR)`, as ssh does with a channel EOF
  [ssh]. The **server** cannot, and closes as §4.2 says.
- `Stream.Close` before both directions ended sends RESET aborted, and
  the stream is gone at once.

### 5.7 What the mux guarantees

- A frame that does not parse, or breaks a rule above, changes no stream
  state beyond the RESET it causes; a frame that parses but names no
  stream changes nothing at all.
- Memory is bounded: `MaxStreams` × (`SendBuffer` + `RecvBuffer`) =
  2 MiB per connection, plus `MaxLinger` small records.
- Nothing waits on the peer forever while the connection is alive except a
  stream's own data, which the peer's window controls.

## 6. Constants

| Name | Value | Provenance |
|---|---|---|
| `CaptureDeadline` | 10 s | [S3] |
| `MaxCaptureFrame` | 16 KiB | [derived] §2.2 |
| `AgentDialTimeout` (connect, write the bind, read its reply) | 5 s | [choice] |
| `MaxBindReply` | 4 KiB | [choice] |
| Launcher's trigger: deadline, reply bound | 5 s, 256 KiB | `bootstrap.md` §11 |
| `MaxStreams` per connection | 16 | [choice] |
| `SendBuffer`, `RecvBuffer` per stream | 64 KiB each | [choice] |
| `MaxInFlight` per connection | 32 KiB | [choice] |
| `MaxData` | 1186 B | [derived] `transport.MaxPayload` − 16 |
| `MaxWindow` | 1 MiB | [choice] |
| Initial RTO, `MinRTO`, `MaxRTO` | 1 s, 200 ms, 4 s | [RFC 6298 §2]; [choice] |
| `OpenTimeout` | 30 s | [choice] |
| `Linger`, `MaxLinger` | 10 s, 64 | [choice] |
| Padding | sealed plaintext ≥ 64 B, Padmé above, ≤ D5 | `ssp.md` §9.2 |
| `AttesterSocket` | `/run/agent-attest/handoff.sock` | [S7] |

## 7. Tests

- `internal/agent`: the capture state machine against every refusal of
  S3's unit list (another pid, a bind as frame 2, a bind without
  forwarding, a bad signature, a second connection, the wrong order, bytes
  after the answer, the deadline) and the honest sequence; the pin against
  plain, hashed, `[host]:port`, alias, `@revoked` and `@cert-authority`
  entries; `FuzzCapture` (any byte sequence on the one connection: Bound
  only for exactly the honest sequence, and then only that bind), which
  reaches `ParseBind` through frame 1.
- `internal/channel`: `FuzzParseFrame` (round trip; padding must be zero)
  and `FuzzMux` (any frames from the peer keep every bound); streams over
  a seeded simulated path under synctest (D18; channel needs no addresses,
  so a small link rather than netsim) with loss, reordering and duplication
  deliver exactly the bytes written, in order, both ways, with many
  streams at once; windows hold a slow reader's buffer to `RecvBuffer`;
  RESETs and limits; a done stream lingers and then forgets.
- `internal/transport`: `CHANNEL` frames reach `RecvChannel` only on a
  connection that negotiated a channel type besides the terminal.
- `internal/e2e`, in process over netsim: an agent channel carries a
  request and an extension message (`provenance-v00@bodar.com`) byte for
  byte to a fake agent, which sees the replayed bind first.
- `internal/e2e`, real binaries through a throwaway sshd, with a throwaway
  `ssh-agent` and key: remote `ssh-add -l`; an ssh to a second throwaway
  sshd signed through the forwarded agent; a key added with
  `ssh-add -h A -h 'A>B'` works for the hop as under `ssh -A`, and one
  constrained to another hop does not; no `SSH_AUTH_SOCK` with
  `ForwardAgent no` or `-a`; and the session goes on with the agent off
  when the server has `AllowAgentForwarding no`.

## 8. quoin (D16, D17, D28)

mosey needs nothing from quoin and quoin needs nothing new from mosey for
plain forwarding. The contract mosey made in quoin's
`docs/mosey-integration.md` §1, item by item:

1. **The bind is OpenSSH's own**, replayed byte for byte at the head of
   every agent channel (§2, §3): done. quoin-signer's `agentsrv` reads
   `session-bind@openssh.com` as `ssh-agent` does, so it sees exactly what
   `ssh -A` would show it. The e2e test with `ssh-add -h` checks the same
   bind semantics with OpenSSH's agent, the reference quoin follows.
2. **One binary, `mosey`**; the shells' parent is the spawner, argv
   `mosey --serve=spawner` (`bootstrap.md` §8): unchanged here.
3. **Extension messages pass through**: done, and tested byte for byte
   with `provenance-v00@bodar.com` (§7).
4. **The hand-off forwarder**: the seam is in the spawner (§4.3), at the
   fixed path, never from the environment, and fails closed while an
   attester is present; the hand-off itself is not implemented yet.
5. **The session binding**: `Conn.HandshakeHash` is there; handing it to
   the attester is part of 4.
6. **Without quoin, plain forwarding**: done.

**Why there is no local test against quoin-signer itself.** It cannot run
without Dan's live setup: `quoin-signer serve` loads its keys only as
TPM-wrapped files used through `/dev/tpmrm0` (`internal/tpmkey`), takes
its listener only from systemd socket activation (`sdnotify.Listen`, a
socket named `agent`), and asks galley, a desktop prompt, about every
forwarded sign (`internal/galleyask`). Its `agentsrv.Server`, which could
take a software signer, is in quoin's `internal/` and cannot be imported
from mosey's module. A test would therefore touch the TPM, the user's
systemd units and galley, which mosey's tests must never do. What stands
in for it: spike S3 ran quoin's real `agentsrv` on frames recorded from a
mosey-relayed connection and it asked "sudo on spikeA" unchanged (quoin
8bb8de0); since then mosey relays the same bytes in the same order, which
`TestAFarProgramReachesTheUsersAgentThroughTheSession` and the `ssh-add
-h` test pin down. A quoin-side test that runs `agentsrv` with a software
key behind mosey belongs in quoin's own suite, or in the NixOS VM check
S3 asked for.
