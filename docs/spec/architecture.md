# Architecture

The map of mosey as built: which package does what, who owns it, how data
moves between them, and where the interfaces are. Slice 1 was the walking
skeleton that joined the spikes (`mosey host` gives an interactive login
shell end to end); resume and exclusive attach (D8, D26), agent
forwarding (D15, D25), predictive echo (D12), chaff (D11) and auto-upload
(D7) have landed on it since, each through hooks slice 1 reserved, so
none changed a wire format or an interface below it (§7). The versioning
slice (D8 V1) then made the wire and the attach socket stable across
releases, and the simplification of 2026-11-15 (Dan) left one protocol
number per layer (the bootstrap lines, the hello, the greeting), each
checked for equality, no software version anywhere on the wire, and D7
using whatever mosey the host has.

The interfaces themselves are Go, with doc comments, under `internal/`.
Changing an exported signature another owner calls means agreeing it with
them first and updating this document in the same commit.

PLAN.md §2 (D1–D28) is locked. Where this document cites a decision, the
decision wins.

## 1. Packages and owners

| Package | Job | Runs in | Owner | Interface file |
|---|---|---|---|---|
| `internal/netsim` | Simulated `net.PacketConn` network under `testing/synctest`: loss, delay, jitter, reordering, MTU, outages, Mahimahi traces, adversary tap (D18) | tests only | **netsim** | `netsim.go`, `link.go`, `trace.go`, `profile.go` |
| `internal/wire` | The size limits every layer is built to (D5), and the padding rule SSP and channel frames share (O12: `PadFloor`, `Padme`, `PaddedLen`) | everywhere | **crypto-transport** | `wire.go`, `pad.go` |
| `internal/replay` | RFC 6479 anti-replay window, check and commit separate | proto, client | **crypto-transport** | `replay.go` |
| `internal/handshake` | B3 handshake, one-shot X-Wing keys, credential store, hello, hybrid rekey (D20) | proto, client | **crypto-transport** | `doc.go`, `key.go`, `credential.go`, `hello.go`, `handshake.go`, `rekey.go` |
| `internal/transport` | Sealed frames over UDP: handshake driving, AEAD, replay, rekey with split INIT, path validation and anti-amplification (D21), exclusive attach (D26) | proto, client | **crypto-transport** | `doc.go`, `frame.go`, `transport.go` (`End` and the END frame added at integration) |
| `internal/ssp` | Generic State Synchronization Protocol: `State[S]`, `Endpoint`, D11 timing, fragmentation, compression (D24) | proto, client | **ssp** | `doc.go`, `ssp.go`, `endpoint.go` |
| `internal/channel` | Reliable, flow-controlled byte streams multiplexed over `transport.KindChannel` frames (D15; `agent.md` §5) | proto, client | **agent** | `doc.go`, `frame.go`, `mux.go`, `stream.go` |
| `internal/agent` | The session-bind, the strict bind capture and its known_hosts pin, the replay, the relay (D25; `agent.md` §2–§3) | client, launcher, proto | **agent** | `doc.go`, `bind.go`, `capture.go`, `pin.go`, `relay.go` |
| `internal/userinput` | The client's SSP object: keystrokes and resizes | proto, client | **ssp** | `userinput.go` |
| `internal/screen` | The server's SSP object: `Grid`, the diff format (O11), the D9/D27 allow-list, the D23 bounds | proto, emu, client | **screen** | `doc.go`, `grid.go`, `diff.go`, `allow.go` |
| `internal/render` | Draws a `Grid` on the local terminal with escape sequences it writes itself | client | **screen** | `render.go` |
| `internal/predict` | Predictive local echo (D12, `prediction.md`): epochs over the user's own keystrokes, judged against the server's cells, drawn as an overlay on the client's copy of the screen | client | **prediction** | `doc.go`, `engine.go`, `keys.go`, `width.go`, `overlay.go` |
| `internal/emu` | The `Emulator` interface and the tuios.dev/vt implementation (D23) | emu (tests: in process) | **screen** | `emu.go`, `tuios.go` |
| `internal/pty` | Open ptys, set their size, read the echo-off bit, start the login shell (D14) | spawner, proto | **server-proc** | `pty.go`, `pty_linux.go`, `pty_other.go` |
| `internal/sandbox` | Landlock deny-all, seccomp cBPF compiler and per-role policies, `DUMPABLE=0` (D22) | proto, emu | **server-proc** | `doc.go`, `sandbox.go`, `bpf.go`, `sandbox_linux.go`, `sandbox_other.go` |
| `internal/nocore` | `DUMPABLE=0` and `RLIMIT_CORE=0` for every process that holds a secret (threat-model.md §4.10) | client, launcher, spawner, proto, emu | **server-proc** | `doc.go`, `nocore.go` |
| `internal/ipc` | Seqpacket messages and SCM_RIGHTS between the roles | launcher, spawner, proto, emu | **server-proc** | `ipc.go`, `message.go` |
| `internal/server` | The four roles (launcher, spawner, proto, emu); proto's `Session`, runnable in process for tests; the emu reply grammar | all server roles | **server-proc** | `doc.go`, `proto.go`, `launcher.go`, `spawner_linux.go`, `startdir.go`, `protorole.go`, `emurole.go`, `ipcemu.go`, `reply.go` |
| `internal/bootstrap` | The SSH command line, the stdin and stdout lines (D6, D20, D25); D7's probe line, upload command and release rules; the local launcher of `mosey localhost` (`bootstrap.md` §2.2) | client, spawner | **bootstrap-client** | `doc.go`, `line.go`, `ssh.go`, `probe.go`, `upload.go` |
| `internal/install` | `mosey --serve=install`: puts an uploaded copy at `~/.local/bin/mosey` safely (D7, `bootstrap.md` §4.7.7) | server host (one-shot) | **bootstrap-client** | `doc.go`, `install.go`, `install_unix.go` |
| `internal/terminal` | The client's own tty: raw mode, size, SIGWINCH | client | **bootstrap-client** | `terminal.go` |
| `internal/client` | `mosey host`, or `mosey localhost` for this machine with no ssh (`bootstrap.md` §2.2): bootstrap (copying mosey over first if need be, D7), then `Session` (SSP + render + input) | client | **bootstrap-client** | `client.go`, `upload.go` |
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
channel                         (wire)          -- never transport: it takes a Datagrams too
agent                           (channel, handshake) -- the bind, capture, pin, replay, relay
userinput                       ()              -- satisfies ssp.State structurally
screen                          ()              -- satisfies ssp.State structurally
render                          (screen)
predict                         (screen; golang.org/x/text/width) -- never parses remote output (D9)
emu                             (screen)
bootstrap                       ()              -- raw bytes; never handshake
pty, sandbox, ipc, nocore       ()
install                         (bootstrap)     -- the size bound and InstallPath only
terminal                        ()
server                          (all of the above but client, terminal, render)
client                          (all of the above but server, pty, sandbox, ipc, emu)
cmd/mosey                       (client, server, install, bootstrap, terminal, nocore, predict)
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
   │                                           │   accepts on R/mosey/SID-HEX/attach.sock
   │                                           │     (a resume's launcher: ClientLine → Resume)
   │                                           │   accepts on R/mosey/SID-HEX/agent.sock
   │                                           │     (the shell's SSH_AUTH_SOCK) → AgentConn fd
   │                                           ▼
   │        UDP (B3, then sealed frames:   proto (Landlock + seccomp)
   └──────── SSP, agent channels, chaff) ►  keys, transport, SSP, channel mux,
                                             pty master, echo ack,
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
input. seccomp's action is KILL on amd64 and on arm64 (D22; arm64 was
ERRNO until its CI soak passed, run 43626969195). The KILL soak, CI's
`kill-soak` job on both architectures (server.md §9), keeps it safe across
Go upgrades and policy changes, and the policies are tested by the BPF interpreter for
amd64 and arm64.

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
Lines that scroll off the top of the primary screen ride in the same
Grid as `History`, a bounded numbered window (`screen.md` §2.5): emu
takes them from tuios' scrollback, proto renumbers them for the session,
and the renderer prints each once above its screen, into the local
terminal's own scrollback (`screen.md` §8.7), so mosey needs no tmux and
no scroll mode for history. While a client is attached and heard, proto's
pty reader holds the program back on SSP's acknowledgement
(`Endpoint.AckedChanged`), so a flood waits for the client as under ssh
and no line is cut; while nobody listens, the window keeps the newest
lines (`screen.md` §2.5).

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

### 3.6 Resume and attach (D8, D26)

Every `mosey host` bootstraps through ssh as in §3.1; its `ClientLine`
says which session (`auto`, `new`, `name:NAME`, or R3's
`resume:SID:CREDID`, `bootstrap.md` §9.2). The launcher, holding an
`flock` on `R/mosey/lock`, reads the greetings of every `attach.sock`
(`server.md` §2.6) and chooses: a new session (`choose` in `internal/server/choose.go`; the line
goes to a spawner of its own as `new:NAME`), or an existing one, whose
spawner it sends the line as `resume:SID`. The spawner checks it
and sends proto `ipc.Resume`; proto mints a new credential for the new
client's one-shot key and the line goes back up ssh as usual. The new
client's handshake carries `Hello.Attach`; when `Listener.Accept` returns
its connection, the listener revokes the old one (`KindRevoked`, the
`Revoked` event, D26), and `server.Session` makes the new connection the
one the screen goes to and keystrokes come from. SSP starts from scratch
on every connection (`ssp.md` §1.3), so the first diff is the whole screen,
and every per-connection count (`InputConsumed`, the echo ack and applied
count, §3.8) starts at 0. A client that leaves sends `End(EndDetached)`;
proto also reports a client silent for 15 s as detached (`SilentAfter`).
A session may be of any mosey version (D8 V1): the launcher attaches it
if it speaks the launcher's attach protocol, and it goes on running its
own binary. The client and the session's proto check each other's
protocol number in the handshake (one byte in each hello;
`Conn.Protocol`).
A line that creates a session may carry `-dir` and `-type`
(`bootstrap.md` §9.2.3): the launcher checks the directory before
anything starts (`CodeDir` if it is not one), and the spawner starts the
shell there (`startDir`) and types the text into the pty, followed
by Enter (`typeInto`), once proto says the shell has written its first
output (`ipc.FirstOutput`) and the tty has stopped echoing (`pty.Echoes`),
or `TypeWait` has passed. A resume drops both, so the same command goes back to
the session.
The session runs on until its shell exits, `mosey -kill` (`ipc.Hangup`)
or 7 days detached (`IdleTimeout`), the last two a SIGHUP from the
spawner. `mosey -list` reads the greetings and prints `MOSEY-LIST` lines,
which the client parses and lays out. A running client that hears nothing
for 15 s resumes its own session in the background (R3): its `loop`
swaps in the new transport, endpoint and prediction without leaving raw
mode (`client.Session.Reconnect`).

### 3.7 The agent channel (D15, D25)

At the bootstrap the client captures the session-bind ssh sends its agent
(`agent.md` §2) and pins it to `known_hosts`, and offers `ChannelAgent` in
its hello. On the server the shell's `SSH_AUTH_SOCK` is the spawner's
`agent.sock` (`server.md` §2.7, `agent.md` §4.1); each connection a program
makes there is checked (`SO_PEERCRED`) and handed to proto as an
`ipc.AgentConn` fd. proto opens a reliable stream on the attached
connection's `channel.Mux` (`KindChannel` frames, `agent.md` §5) and
relays the fd's bytes into it, opaque. The client, for each channel,
dials its own local agent, replays the captured bind, then relays
(`agent.md` §3), so the agent judges destination constraints as under
`ssh -A`. Any agent works, and mosey has no code for any particular one (D28); the client never parses
what passes. A resume brings the resuming client's own agent: the socket
path is fixed for the shell's life, and each connection goes to whichever
client is attached then.

### 3.8 Prediction (D12)

Each screen proto publishes carries `EchoAck` (the newest input event the
pty has had for 50 ms), `EchoApplied` (how many it had when the screen was
taken) and `EchoOff` (`prediction.md` §3, §3.1). proto keeps a small write
log per attached client and publishes once more 50 ms after each write,
so a confirmation reaches the client even when nothing else changed; it
sends no such frame while echo is off. The client's `predict.Engine` sees
each key event as the loop sends it and each new screen as it arrives,
and judges its guesses only against screens whose `EchoAck` covers them;
`render` draws `Overlay()`, the server's screen with the surviving
predictions on top. Nothing the server sends is parsed to predict (D9).

### 3.9 Chaff (D11)

While the user types, the client's SSP endpoint sends only on a fixed tick,
one datagram each 20 ms tick, a CHAFF frame (`Conn.SendChaff`) when it has nothing
else, and keeps on for a random 1–2 s after the last key; the server
chaffs on a tick grid of its own for a second after each CHAFF it gets
(`ChaffArrived`). Every SSP datagram is padded (§4, `ssp.md` §9.2): the
server always to at least 64 bytes of sealed plaintext, the client to at
least 40 when idle or not typing; while chaffing both ends pad every
datagram, chaff included, to at least 64 (Padmé above that; `ssp.md`
§9.1.5, O10 and O12 as Dan amended them), so an on-path observer cannot
tell which ticks carried keys. `ssp.md` §9.1 says what it hides and what
it does not.

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
`RekeyOverdue`, `Revoked`, `Ended`), `Peer()`,
`Stats()`, `Protocol()` (the version the handshake agreed, D8 V1),
`LocalAddressChanged()`, `End(reason)` (tell the peer the
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
`RemoteChanged()`, `AckedChanged()` (signalled when the peer acknowledges
a newer local version, which proto's hold waits on, `screen.md` §2.5),
`Stats()`.

**channel.** `NewMux(d, Config{Role, Accept, Log})` over a `Datagrams`
(`SendChannel`, `RecvChannel`, which `*transport.Conn` satisfies), then
`Run`, `Open(ctx, typ)` and `Live`; a `*Stream` is `Read`, `Write`,
`CloseWrite`, `Close`. `ParseFrame` and `Marshal` are the frame codec
(`agent.md` §5).

**agent.** `ParseBind`, `ListenCapture(dir)` with `Expect(pid)` and
`Result(ctx, sshExited)`, `CaptureDir`, `Pin`, `Trigger` (the launcher's),
`Forwarder{Dial, Bind, Log}` whose `Accept` is a `channel.Accept`,
`Relay` and `Serve` (proto's, one local connection over one stream).
Transport adds `DialOffering`, `Conn.Channels`, `Conn.Carries`,
`Conn.SendChannel` and `Conn.RecvChannel` (`transport.md` §4.4);
`client.Session` gains `Agent`, `server.Session` gains `AgentConn`, and
`ipc` gains `AgentConn` (0x04).

**userinput.** `*Stream` is an `ssp.State[*Stream]`: `Type`, `Resize`,
`Len`, `Since(n)`, and `EncodedSince(n)`, the pending input the client
throttles on (`ssp.md` §10.1).

**screen.** `*Grid` is an `ssp.State[*Grid]`: cells (`Cell`: cluster,
width, `Style`), `Cursor`, `Title`, `Container` and `Cwd` (OSC 666's
container mark and OSC 7's directory, `screen.md` §4.6, §4.7), `Modes`, and prediction's `EchoOff`
(D12), `EchoAck` and `EchoApplied` (`prediction.md` §3), `Clipboard` (OSC 52 write, D27) and `Bell`,
plus `InputConsumed` (the client's input flow control, `ssp.md` §10.1),
`Rebuilt` (D23's rebuild notice) and `History` (the scrollback window,
`screen.md` §2.5). `allow.go` is the allow-list and the
bounds. `render.Renderer` (`Render`, `Invalidate`, `Enter`, `Leave`,
`Resize` for the local size it clips to) draws a Grid, with the
`Capabilities` from `render.FromEnv`, the locale's UTF-8 among them.

**predict.** `New(Config{Mode})`, then `Key(n, bytes)` for each key event
(n is the stream's `Len()` after it), `Skip(n)` for a resize, `Frame(g)`
for each new screen, `SetRTT(srtt)`, and `Overlay()`, the grid the
renderer draws (`prediction.md` §16).

**emu.** `Emulator` (`Write`, `Resize`, `Snapshot(*screen.Grid)`,
`TakeReplies`, `Close`), and `Holder` (`Held`) for one that holds its
screen under synchronised output; `emu.New(cols, rows, Options)` is tuios. The
server's IPC-backed Emulator implements the same interface, which is what
lets `server.Session` run in process for tests.

**server.** `Session{Listener, Terminal, Emulator, Log, Attached,
Detached}.Run(ctx)`, where `Terminal` is the pty (`Read`, `Write`,
`Resize`, `EchoOff`); it serves one connection at a time, for as long as
the shell runs, taking each new one the listener accepts (resume, D8;
the listener has revoked the old one, D26) and outliving a client that
detaches; it returns nil when the shell exited, or `ErrNoClient` if no
client ever attached. `Minted` tells it a resume credential was minted,
which keeps a never-attached session waiting.
`Launcher`, `RunSpawner`, `RunProto` and `RunEmu` are the roles' mains.

**ipc.** `Pair()`, `Conn.Send(Message)`, `Conn.Recv()`; messages, with
fixed layouts and a fuzzed `Parse` (`server.md` §3): launcher↔spawner
`ClientLine`, `Ready`, `Failed`; spawner→proto `Start`, `EmuLink`,
`ShellExit`, `EmuPaused`, `Resume`; proto→spawner `Credential`,
`Attached{Peer}`, `Detached`, `KillEmu`, `Exit`; proto→emu `Init`,
`Output`, `Resize`, `Flush`; emu→proto `Update`, `Replies`; and the
stable attach protocol (`server.md` §2.8) `ClientLine`, `Ready`,
`Failed`, `Hangup`.

**bootstrap.** As `bootstrap.md` §10.1: `ClientLine`, `CredentialLine`,
`ErrorLine`, their `Marshal`/`Parse`, `ReadCredential(r)`, `Sanitize`,
`ParseSSHOptions`, `Config` (from `SSH.Resolve`, which runs `ssh -G`),
`SSH.Command(ctx, Config)`, `AgentSocket` and `ChooseAddr`; for D7 the
`ProbeLine`, `NoServerError`, `SSH.UploadCommand`, `Platform`,
`IsRelease`, `AssetName`, `ParseSums`, `InstallPath` and
`ProtocolAnswer`. The spawner
uses `ParseClientLine`, `MarshalCredentialLine` and `MarshalErrorLine`.
The resume slice adds `SessionLine` (the attach socket's greeting) with
`MarshalSessionLine` and `ParseSessionLine`, and
`SSH.Role` for `--serve=list`; the sessions slice adds `Attach`,
`ValidSessionName`, `ListLine` with `MarshalListLine`/`ParseListLine`,
`CodeTaken`, `SSH.RoleArg` for `--serve=kill NAME` and `SSH.Batch`, and
drops `AnySession` and `CodeAmbiguous`; the simplification of
2026-11-15 drops every `SoftwareVersion` field, `CanUpload` and
`ValidSoftwareVersion`, gives `SessionLine` one `AttachProtocol` (with
the constant `AttachProtocol`) in place of a range, and adds
`CodeAttach`; `CodeVersion` means only a line version the server cannot
read.

**terminal.** `Terminal` (`Read`, `Write`, `Size`, `Resized`, `Raw`,
`Restore`); `Open(in, out)` leaves the mode alone, since the terminal
stays cooked for ssh's prompts until the handshake is done.

**client.** `Run(ctx, Options{SSH, Version, Terminal, Stderr, Log,
Getenv, Attach, Name, Upload, Ask, Releases})` for the binary,
`List(ctx, ListOptions)` for `-list` and `Kill(ctx, KillOptions)` for
`-kill`; `Session{Conn, Server, Credential, Name, Key, Terminal, Log,
Capabilities, Reconnect}.Run(ctx)` for after the bootstrap, which the
netsim end-to-end test drives; `Reconnect`, if set, is R3's try (the
binary's runs a `Batch` bootstrap with `resume:SID:CREDID`). It returns nil
when the server ends the session, and otherwise tells the server with
`End` before it returns. Errors are `*Failure`, `*TakenOverError`,
`*DetachedError` (exit 0), `*GoneError` (R3 found no session) and
`*bootstrap.UsageError`; `ExitStatus` maps them.

## 6. Tests

- **Every package has tests**, written alongside the code.
- **Network behaviour runs on netsim inside `testing/synctest`** (D18). No
  test asserts real elapsed time. A test that needs time to pass sleeps in
  the bubble, which is instant.
- **Every parser of attacker-reachable input has a `go test -fuzz` target**,
  run locally for at least a few minutes before it lands, with the
  duration and exec count recorded in the commit message. CI runs each for
  10 s on every push (`scripts/fuzz.sh`, in shards), and for 5 minutes
  every night (`fuzz-nightly.yml`), and runs every test under `-race`
  (`mise run race`). The targets slice 1 needs at least:
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
- **The install path on NixOS VMs** (`tests/install.nix`, CI's
  `vm-install`). `flake.nix` does not build mosey: its package is a
  release's binary, named by the `nix/release.json` a release's tag adds on
  a child commit (`bootstrap.md` §4.6). CI's nix job makes the binaries its
  own build job made the flake's release (`scripts/nix-local-release.sh`),
  so the VM test runs the very file the run releases, through the same
  package a pinned tag gives.

## 7. Hooks reserved for later slices

| Later | Reserved now |
|---|---|
| Resume (D8) | **built** (resume slice; automatic and named resume, R3's reconnect, `-list`, `-kill` and the idle timeout in the sessions slice; the stable protocol, V1, in the versioning slice): the attach socket (`server.md` §2.6, §2.8), `ipc.Resume`, `bootstrap.Attach`, `client.Session.Reconnect`, `Hello`'s protocol number, `bootstrap.md` §9.2–§9.5 |
| Exclusive attach (D26) | **built** (resume slice) on `Hello.Attach`, `transport.KindRevoked`, the `Revoked` event |
| Agent channel (D15, D25) | **built** (agent slice): `agent.md`, `internal/channel`, `internal/agent`, `Conn.SendChannel`/`RecvChannel`, `ipc.AgentConn`, `server.md` §2.7 |
| Prediction (D12) | **built** (prediction slice): `prediction.md`, `internal/predict`, `Grid.EchoApplied`, the server's echo ack (`prediction.md` §3.1), `mosey -predict` |
| Chaff (D11, O10) | **built** (chaff slice; the client's 64 B chaffing floor in the dequoin slice): `ssp.Chaffer`, `transport.Conn.SendChaff` and `ChaffArrived`, `ssp.md` §9.1 |
| Auto-upload (D7) | Landed, simplified 2026-11-15 to one installed file used only where the host has no mosey, and moved 2026-11-16 to `~/.local/bin/mosey` so hopping needs no rc file: `bootstrap.md` §4.7, `internal/install`; the release job attests every binary for `gh attestation verify` by hand (`bootstrap.md` §4.6); a client-side signature check is parked (PLAN O16) |
| NAT traversal (O6) | packet type `0x05` |
| macOS server (D22) | `pty_other.go`, `sandbox_other.go` return `ErrUnsupported` |
