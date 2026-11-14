# Architecture: slice 1

Slice 1 is the walking skeleton that joins the spikes: `mosey host` gives
an interactive login shell end to end. It has no prediction, resume, agent
forwarding or auto-upload; those are later slices, and the hooks for them
are reserved here so that adding them changes no wire format and no
interface below.

This document is the map six people work from at once. It says which
package does what, who owns it, how data moves between them, and where
the interfaces are. The interfaces themselves are Go: every package below
exists under `internal/` as compiling stubs with doc comments, and an
implementer replaces the `panic("TODO slice 1")` bodies. Changing an
exported signature another owner calls means agreeing it with them first
and updating this document in the same commit.

PLAN.md §2 (D1–D28) is locked. Where this document cites a decision, the
decision wins.

## 1. Packages and owners

| Package | Job | Runs in | Owner | Interface file |
|---|---|---|---|---|
| `internal/netsim` | Simulated `net.PacketConn` network under `testing/synctest`: loss, delay, jitter, reordering, MTU, outages, Mahimahi traces, adversary tap (D18) | tests only | **netsim** | `netsim.go`, `link.go`, `trace.go`, `profile.go` |
| `internal/wire` | The size limits every layer is built to (D5) | everywhere | **crypto-transport** | `wire.go` |
| `internal/replay` | RFC 6479 anti-replay window, check and commit separate | proto, client | **crypto-transport** | `replay.go` |
| `internal/handshake` | B3 handshake, one-shot X-Wing keys, credential store, hello, hybrid rekey (D20) | proto, client | **crypto-transport** | `doc.go`, `key.go`, `credential.go`, `hello.go`, `handshake.go`, `rekey.go` |
| `internal/transport` | Sealed frames over UDP: handshake driving, AEAD, replay, rekey with split INIT, path validation and anti-amplification (D21), exclusive attach (D26) | proto, client | **crypto-transport** | `doc.go`, `frame.go`, `transport.go` (`End` and the END frame added at integration) |
| `internal/ssp` | Generic State Synchronization Protocol: `State[S]`, `Endpoint`, D11 timing, fragmentation, compression (D24) | proto, client | **ssp** | `doc.go`, `ssp.go`, `endpoint.go` |
| `internal/userinput` | The client's SSP object: keystrokes and resizes | proto, client | **ssp** | `userinput.go` |
| `internal/screen` | The server's SSP object: `Grid`, the diff format (O11), the D9/D27 allow-list, the D23 bounds | proto, emu, client | **screen** | `doc.go`, `grid.go`, `diff.go`, `allow.go` |
| `internal/render` | Draws a `Grid` on the local terminal with escape sequences it writes itself | client | **screen** | `render.go` |
| `internal/emu` | The `Emulator` interface and the tuios.dev/vt implementation (D23) | emu (tests: in process) | **screen** | `emu.go`, `tuios.go` |
| `internal/pty` | Open ptys, set their size, read the echo-off bit, start the login shell (D14) | spawner, proto | **server-proc** | `pty.go`, `pty_linux.go`, `pty_other.go` |
| `internal/sandbox` | Landlock deny-all, seccomp cBPF compiler and per-role policies, `DUMPABLE=0` (D22) | proto, emu | **server-proc** | `doc.go`, `sandbox.go`, `bpf.go`, `sandbox_linux.go`, `sandbox_other.go` |
| `internal/ipc` | Seqpacket messages and SCM_RIGHTS between the roles | launcher, spawner, proto, emu | **server-proc** | `ipc.go`, `message.go` |
| `internal/server` | The four roles (launcher, spawner, proto, emu); proto's `Session`, runnable in process for tests; the emu reply grammar | all server roles | **server-proc** | `doc.go`, `proto.go`, `launcher.go`, `spawner_linux.go`, `protorole.go`, `emurole.go`, `ipcemu.go`, `reply.go` |
| `internal/bootstrap` | The SSH command line, the stdin and stdout lines (D6, D20, D25) | client, spawner | **bootstrap-client** | `doc.go`, `line.go`, `ssh.go` |
| `internal/terminal` | The client's own tty: raw mode, size, SIGWINCH | client | **bootstrap-client** | `terminal.go` |
| `internal/client` | `mosey host`: bootstrap, then `Session` (SSP + render + input) | client | **bootstrap-client** | `client.go` |
| `cmd/mosey` | The one binary: `main.go` is the client (`mosey host`), `server.go` the server (`mosey --serve`, re-executing itself as `mosey --serve=proto` and `mosey --serve=emu`; a flag, so it never collides with a host called server) | | **bootstrap-client** (`main.go`), **server-proc** (`server.go`) | `main.go`, `server.go` |
| `internal/e2e` | End-to-end tests: netsim + synctest in process, and real binaries over loopback through a throwaway sshd | tests only | **bootstrap-client** (integrator) | `doc.go` |

Each owner writes their spec section in `docs/spec/` **before** the code
(PLAN §4, §6): `transport.md` (crypto-transport), `ssp.md` (ssp),
`screen.md` (screen: the diff format and the allow-list), `server.md`
(server-proc: roles, IPC grammar, reply grammar, sandbox policies),
`bootstrap.md` (bootstrap-client: the two lines and the ssh command).
netsim is test infrastructure and needs no spec beyond its doc comments.
SSP and anything prediction-shaped is written **only** from the spec, which
cites the paper section, an RFC, or our own measurement for every constant.
S5's `docs/spikes/s5-netsim-ssp/ssp-spec.md` is the starting point for
`ssp.md`, amended by D11 and D24.

### Imports

The packages form a DAG. To keep it one, a package imports only those
above it in this list:

```
wire, replay, netsim(test-only)
handshake                       (wire)
transport                       (wire, replay, handshake)
ssp                             (wire)          -- never transport: it takes a Datagrams
userinput                       ()              -- satisfies ssp.State structurally
screen                          ()              -- satisfies ssp.State structurally
render                          (screen)
emu                             (screen)
bootstrap                       ()              -- raw bytes; never handshake
pty, sandbox, ipc               ()
terminal                        ()
server                          (all of the above but client, terminal, render)
client                          (all of the above but server, pty, sandbox, ipc, emu)
e2e                             (everything; tests only)
```

`screen` and `userinput` do not import `ssp`; the assertion that they
satisfy `ssp.State` lives in `internal/server/proto.go`. Production code
never imports `spikes/` (each spike is its own module, so it can't by
accident) and never imports `netsim`.

## 2. Processes

Layout C of S4 (D22). One `mosey --serve` per session. mosey is a single binary: the client and every server role are the same file (D7).
`mosey --serve` itself is a short-lived **launcher** (`server.md` §1.1):
the process sshd starts cannot detach, so it reads the `ClientLine`,
starts `mosey --serve=spawner` in a new session, relays the credential
line to ssh's stdout and exits, which lets ssh exit.

```
            ssh (system, user's config)
 mosey ─────────────────────────────────► mosey --serve (launcher) → mosey --serve=spawner (unsandboxed)
   │       stdin: ClientLine                   │   binds UDP, opens pty, forks login shell
   │      stdout: CredentialLine               │   re-execs itself as proto and emu
   │                                           │   SCM_RIGHTS: UDP socket + pty master → proto
   │                                           ▼
   │        UDP (B3, then sealed frames)   proto (Landlock + seccomp)
   └──────────────────────────────────────►  keys, transport, SSP, pty master,
                                             every protocol parser, reply grammar
                                               │  seqpacket
                                               ▼
                                             emu (Landlock + seccomp)
                                             tuios.dev/vt, nothing else
```

- **spawner** (`server.RunSpawner`) parses the `ClientLine` again, binds a
  UDP port in 60000–61000, opens the pty at the client's size, starts
  proto and emu, sends proto `ipc.Start` with the socket and the pty
  master, starts the login shell once proto's `ipc.Credential` line is
  in, and hands that line to the launcher (`ipc.Ready`). It never reads the
  network and never holds a key; it only parses the `ClientLine` (from the
  user, via sshd) and proto's fixed IPC grammar. It supervises: if emu dies
  it is restarted and proto sends a full redraw.
- **proto** (`server.RunProto` → `server.Session`) mints the credential
  (only proto holds keys), runs the transport listener and SSP, reads and
  writes the pty master, sets its size with `TIOCSWINSZ`, reads the
  echo-off bit, and talks to emu.
- **emu** (`server.RunEmu`) answers `Init`, `Output`, `Resize` and
  `Flush` with `Update` (a screen diff from its last update, with a HELD
  bit under synchronised output) and `Replies`.

Sandbox setup order in proto and emu (S4 §5.4): wrap the inherited fds,
`PR_SET_DUMPABLE=0`, Landlock deny-all, seccomp with TSYNC, then read
input. Slice 1 may run seccomp in ERRNO mode if the KILL soak is not ready,
but the policies exist and are tested by the BPF interpreter for amd64 and
arm64 (D22).

The proto↔emu boundary carries screen diffs in the same format the client
gets, decoded by the same validating `Grid.Apply`. So one fuzzed decoder
guards both the client against the server and proto against a compromised
emu. `server.ValidReply` is the grammar emu's replies must match before
proto writes them to the pty.

## 3. Data flow

### 3.1 Bootstrap (D6, D20)

1. `mosey host` makes a `handshake.OneShotKey` and runs
   `bootstrap.SSH.Command`: the system ssh with `-T -o ControlMaster=no -o
   ControlPath=none -o ForwardAgent=no` (D25's capture socket replaces
   `no` in a later slice), then `mosey --serve` (the remote mosey on PATH, or `-remote PATH`).
2. The client writes `bootstrap.ClientLine` (its public key, window size,
   TERM/COLORTERM/locale) to ssh's stdin.
3. The spawner parses it, sets up as in §2, and proto mints a
   `handshake.Credential` for that key: credential id, session id, PSK,
   server one-shot public key. The spawner prints it as a
   `bootstrap.CredentialLine`, with the address SSH reached (from
   `SSH_CONNECTION`) and the UDP port.
4. The client reads stdout with `bootstrap.ReadCredential`, which skips
   other lines within a bound, and converts the line to a
   `handshake.Credential`.
5. `transport.Dial` sends msg1, retransmitting until msg2. The server's
   `transport.Listener` routes msg1 by credential id to the
   `handshake.Responder`. The first transport packet from the client
   confirms the keys, consumes the credential and validates the client's
   address. `Listener.Accept` returns the connection; under D26 it revokes
   any other connection of the session.

### 3.2 Keystrokes

terminal → `client.Session` encodes keys for the screen's current `Modes`
→ `userinput.Stream.Type` → `ssp.Endpoint.Set` → SSP sends the diff from
the server's acknowledged version (every keystroke since) → transport
seals → UDP → proto's endpoint applies it to its copy of the `Stream` →
`server.Session` writes the events it has not yet applied: keys to the pty,
resizes to `pty.SetSize` (after `screen.ClampSize`) and `Emulator.Resize`.

### 3.3 Output

pty → `server.Session` → `Emulator.Write` (over IPC: `Output`, answered by
`Update` and `Replies`) → `Emulator.Snapshot` into proto's `Grid`, plus the
echo-off bit from `pty.EchoOff` → `ssp.Endpoint.Set` (the server waits 8 ms
to collect output, then sends the diff from the client's acknowledged grid
to now, skipping intermediate screens) → transport → UDP → client endpoint
`Grid.Apply` (validated) → `RemoteChanged` → `render.Renderer.Render`
draws what changed. Replies that pass `ValidReply` go to the pty.

### 3.4 Roaming (D21)

The client's address changes; it keeps sending (and calls
`Conn.LocalAddressChanged` when the OS says so, to send at once). The
server sees an authentic packet from a new address, sends it a
`PATH_CHALLENGE`, keeps sending to the old address, and allows the new one
at most 3x the bytes received from it. On the `PATH_RESPONSE` the new
address becomes the peer and `Events` reports `PeerChanged`. SSP never sees
addresses.

### 3.5 Rekey (D20)

Inside the transport, every `RekeyAfter` (120 s) or N packets, never on
idleness: two `REKEY_INIT` frames, `REKEY_RESP`, then keepalive confirm and
ack, all under the current epoch's keys. SSP is unaware.

## 4. Sizes on the wire (D5)

```
UDP payload                                    ≤ 1232  wire.MaxDatagram
  transport data packet
    clear header: type 1, receiver index 4, counter 8      13
    sealed: kind 1, body ≤ 1202, tag 16                    17 + body
  → transport.MaxPayload = 1232 − 30 = 1202    ← what ssp.Config.MaxPayload is set to
    SSP datagram: SSP's own header (timestamps, fragment) + instruction fragment
handshake msg1, msg2, REKEY_INIT halves, REKEY_RESP   ≤ 1200  wire.MaxHandshake
```

**Open item for crypto-transport (not a decision change):** S1 measured
B3's msg1 at **1208** bytes with a 42-byte hello, 8 over D5's 1200. It has
to shrink: a hello of at most 34 bytes in msg1 does it, and the hello
grammar is ours to define. If it cannot be done, stop and report rather
than exceed 1200. msg2 (1174) and REKEY_RESP (1154) fit; REKEY_INIT
(1250) is split in two as D20 says.

## 5. The interfaces, in brief

The Go files are the reference; this is the shape.

**netsim.** `New(seed)`, `NewHost`, `Connect(from, to, LinkParams)` (one
direction per link), `Host.Listen(addr) *Conn`. `*Conn` is a
`net.PacketConn` with `ReadFromAddrPort`/`WriteToAddrPort`, `Rebind` (a
roam) and `RxStats`; `Network.Rebound` tells a test of a roam, to play
netlink (D21). `Network.Tap` and `Inject` are the adversary.
`Profiles()` are the S5 fixtures (`lan`, `hotel-wifi`, `train`, `hsr`, and
`lte-driving` when its Mahimahi traces can be fetched); call it outside the
bubble. Every profile's MTU is `wire.MaxDatagram`, so a layer that sends
more finds out in every network test. Make the network inside
`synctest.Test` and close it there. Everything runs on the `time` package,
so under `synctest.Test` it is virtual time.

**transport.** `Dial(ctx, pc, addr, cred, key, log) (*Conn, error)` for the
client; `Listen(pc, creds, log)` and `Listener.Accept(ctx)` for the
server, with `Listener.Addr` and `Listener.Stats`. `*Conn` has
`Send(payload)`, `Recv(ctx)`, `Events()` (`PeerChanged`, `Rekeyed`,
`RekeyOverdue`, `Revoked`, `Ended`), `HandshakeHash()` (D28), `Peer()`,
`Stats()`, `LocalAddressChanged()`, `End(reason)` (tell the peer the
session is over, then close: `transport.md` §8.4) and `Close()`. Errors
are `ErrBlocked` (a send held back), `ErrRevoked` and `ErrEnded` (both
`net.ErrClosed`). `pc` is any `net.PacketConn`, so a
`*net.UDPConn` and a `*netsim.Conn` are interchangeable. Frame kinds are in
`frame.go`, with chaff (O10), typed channels (D15) and revocation (D26)
reserved.

**ssp.** `State[S]` (`Clone`, `Equal`, `Diff(from)`, `Apply(diff)` that
validates before mutating). `Datagrams` (`Send`, `Recv`), which
`*transport.Conn` satisfies and which SSP's own tests satisfy with a plain
netsim socket. `NewEndpoint[L, R](d, Config, local, remote)`, then `Run`
(which ends with an error wrapping `ErrProtocol` when the peer breaks the
protocol), `Set(local)`, `Remote()`, `Acked()` (the acknowledged local
version, for the client's input flow control, `ssp.md` §10.1),
`RemoteChanged()`, `Stats()`.

**userinput.** `*Stream` is an `ssp.State[*Stream]`: `Type`, `Resize`,
`Len`, `Since(n)`, and `EncodedSince(n)`, the pending input the client
throttles on (`ssp.md` §10.1).

**screen.** `*Grid` is an `ssp.State[*Grid]`: cells (`Cell`: cluster,
width, `Style`), `Cursor`, `Title`, `Modes`, and the reserved `EchoOff`
(D12), `EchoAck` (prediction), `Clipboard` (OSC 52 write, D27) and `Bell`,
plus `InputConsumed` (the client's input flow control, `ssp.md` §10.1)
and `Rebuilt` (D23's rebuild notice). `allow.go` is the allow-list and the
bounds. `render.Renderer` (`Render`, `Invalidate`, `Enter`, `Leave`,
`Resize` for the local size it clips to) draws a Grid, with the
`Capabilities` from `render.FromEnv`, the locale's UTF-8 among them.

**emu.** `Emulator` (`Write`, `Resize`, `Snapshot(*screen.Grid)`,
`TakeReplies`, `Close`), and `Holder` (`Held`) for one that holds its
screen under synchronised output; `emu.New(cols, rows, Options)` is tuios. The
server's IPC-backed Emulator implements the same interface, which is what
lets `server.Session` run in process for tests.

**server.** `Session{Listener, Terminal, Emulator, Log, Attached}.Run(ctx)`,
where `Terminal` is the pty (`Read`, `Write`, `Resize`, `EchoOff`); it
returns nil when the shell exited, `ErrNoClient` or `ErrClientClosed`.
`Launcher`, `RunSpawner`, `RunProto` and `RunEmu` are the roles' mains.

**ipc.** `Pair()`, `Conn.Send(Message)`, `Conn.Recv()`; messages, with
fixed layouts and a fuzzed `Parse` (`server.md` §3): launcher↔spawner
`ClientLine`, `Ready`, `Failed`; spawner→proto `Start`, `EmuLink`,
`ShellExit`, `EmuPaused`; proto→spawner `Credential`, `Attached`,
`KillEmu`, `Exit`; proto→emu `Init`, `Output`, `Resize`, `Flush`;
emu→proto `Update`, `Replies`.

**bootstrap.** As `bootstrap.md` §10.1: `ClientLine`, `CredentialLine`,
`ErrorLine`, their `Marshal`/`Parse`, `ReadCredential(r)`, `Sanitize`,
`ParseSSHOptions`, `Config` (from `SSH.Resolve`, which runs `ssh -G`),
`SSH.Command(ctx, Config)`, `AgentSocket` and `ChooseAddr`. The spawner
uses `ParseClientLine`, `MarshalCredentialLine` and `MarshalErrorLine`.

**terminal.** `Terminal` (`Read`, `Write`, `Size`, `Resized`, `Raw`,
`Restore`); `Open(in, out)` leaves the mode alone, since the terminal
stays cooked for ssh's prompts until the handshake is done.

**client.** `Run(ctx, Options{SSH, Version, Terminal, Stderr, Log,
Getenv})` for the binary; `Session{Conn, Server, Credential, Key,
Terminal, Log, Capabilities}.Run(ctx)` for after the bootstrap, which the
netsim end-to-end test drives; it returns nil when the server ends the
session, and otherwise tells the server with `End` before it returns.
Errors are `*Failure`,
`*TakenOverError` and `*bootstrap.UsageError`; `ExitStatus` maps them.

## 6. Tests

- **Every package has tests**, written alongside the code.
- **Network behaviour runs on netsim inside `testing/synctest`** (D18). No
  test asserts real elapsed time. A test that needs time to pass sleeps in
  the bubble, which is instant.
- **Every parser of attacker-reachable input has a `go test -fuzz` target**,
  run locally for at least a few minutes before it lands, with the
  duration and exec count recorded in the commit message. CI runs each for
  10 s (`mise run fuzz-smoke`). The targets slice 1 needs at least:
  `handshake` (msg1, msg2, hello, rekey parts), `transport` (data packet
  open: a rejected packet changes neither the window nor the peer),
  `replay` (against a map-based reference), `ssp` (datagram and fragment
  parsing, bounded decompression), `userinput` (`Apply`), `screen`
  (`Apply`, and Diff/Apply round trip), `ipc` (`Parse`), `server`
  (`ValidReply`), `bootstrap` (both lines, `ReadCredential`).
- **End to end** (`internal/e2e`): `client.Session` and `server.Session` in
  one process over netsim, with a shell-like program on a fake terminal
  and the in-process emulator, across `netsim.Profiles()`; and the real
  binaries over loopback UDP, bootstrapped through a throwaway unprivileged
  sshd on 127.0.0.1 with throwaway keys and agent, as
  `spikes/s3-agent-bind/harness` does, skipped cleanly if `sshd` is absent.

## 7. Hooks reserved for later slices

| Later | Reserved now |
|---|---|
| Resume (D8) | `Credential.SessionID`; `Listener` routes by credential, not by process; `handshake.Credentials` is per session |
| Exclusive attach (D26) | `Hello.Attach`, `transport.KindRevoked`, `transport.Revoked` event |
| Agent channel (D15, D25) | `ChannelAgent`, `transport.KindChannel`, `bootstrap.SSH.AgentCapture` |
| Provenance (D28) | `Conn.HandshakeHash` |
| Prediction (D12) | `Grid.EchoOff`, `Grid.EchoAck`, `userinput.Stream.Len` |
| Chaff (D11, O10) | `transport.KindChaff` |
| Auto-upload (D7) | `bootstrap.SSH.Server`, `bootstrap.Version` |
| NAT traversal (O6) | packet type `0x05` |
| macOS server (D22) | `pty_other.go`, `sandbox_other.go` return `ErrUnsupported` |
