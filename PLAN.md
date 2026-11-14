# mosey: plan

**mosey**: to wander along at an easy pace. A remote terminal that roams
between networks, stays usable on bad links and picks up where it left off.
It's a successor to [Mosh](https://mosh.org), written from scratch in Go.

This plan was written on dan-blade on 2026-11-13, from a long research
conversation. It should be carried out on dan-desktop as a series of
workflows. **§2 lists what is decided. Don't reopen any of it without asking
Dan.** §3 lists what is still open. The spikes (§5) ran on 2026-11-13, and
their results were settled with Dan on 2026-11-14.

---

## 1. Why build it

Mosh got the idea right (UDP state sync, predicted local echo, roaming), but:

- **Releases**: 1.4.0 (Oct 2022) is still the latest tag. Fixes such as the
  CSI cell cap (#1403) and wide-character prediction (#1410) sit in open
  PRs, and agent forwarding (#696, #1297) has been open since 2015.
- **No resume**: a session belongs to one client process. Lose the laptop
  and the session is orphaned. In 2012 Mosh's author described the fix (SSH
  back in, prove identity over a unix socket, rekey) and never built it.
- **Crypto from 2012**: one static AES-128-OCB key per session, no rekeying
  and no forward secrecy.
- **No scrollback**, so everyone runs tmux inside it.

mosey's reasons to exist, in order:

1. **Every commit is a release.** Trunk-based development, and each green
   commit on trunk ships. This breaks Mosh's cycle of years between releases.
2. **Security.** Modern handshake, forward secrecy, rekeying, sandboxed
   processes, fuzzed parsers, and the bar set at the open internet.
3. **Resume.** Reattach automatically after a dead spot, a reboot, or from
   another device.
4. **The terminal is isolated.** The server runs the terminal emulator and
   the client receives structured cell diffs, so **the client never parses
   remote escape sequences.** That's stronger than Mosh, and much stronger
   than tmux with passthrough (see the terminal CVE survey, dgl.cx/term).
5. **Faster where it counts.** Mosh's proven SSP timing and prediction, plus
   the fixes upstream never merged.

## 2. Decisions (locked; last amended 2026-11-14 after the spikes)

| # | Decision | Why |
|---|---|---|
| D1 | **Go**, statically linked binaries | The GC rules out use-after-free on a network daemon. It also shares code and style with quoin, galley and gokit. |
| D2 | **License: Apache-2.0** (Dan: Apache or MIT; Apache matches gokit and zigkit) | Permissive. |
| D3 | **Clean-room implementation.** Mosh is GPLv3. | See §4 for the rules. |
| D4 | **Security bar: the public internet, used by other people.** Dan deploys it only inside WireGuard, but WireGuard is **never** the security boundary or an excuse for a shortcut. | It's a daemon reachable from the network. |
| D5 | **UDP only.** Datagrams must fit inside WireGuard. *Amended 2026-11-14:* data payloads are at most **1232 bytes** (the IPv6 minimum MTU of 1280, less the IPv6 and UDP headers). Every handshake and rekey message is at most **1200 bytes** (QUIC's floor), so DPLPMTUD can be added later with a 1200-byte base and no wire change. | A 1280-byte payload is silently dropped on minimum-MTU IPv6 paths and inside WireGuard tunnels with an MTU of 1280 (S1). |
| D6 | **Started over SSH, as Mosh is.** The client SSHes in using the system `ssh` and the user's own config, starts the server on demand, and receives the session's secret over that SSH channel. **SSH vouches for the server.** | Familiar to Mosh users, and it works with any existing SSH setup. |
| D7 | **Copy the server over automatically.** If the server binary is missing or the wrong version, the client copies over its own matching static build (hash-checked, installed to `~/.cache/mosey/<version>/`, asks the first time, never replaces a file someone else owns). Prior art: VS Code Remote-SSH, kitty's `kitten ssh`. **mosey is one binary**: `mosey host` is the client and `mosey --serve` the server (with its roles re-executed from the same file as `--serve=proto` and `--serve=emu`; a flag, so every plain word, such as a host called `server`, belongs to the client), so the copy sent over is the very file the client runs, and a host can hop on with it. A cross-architecture copy (say a Mac client, Linux server) needs the matching release for the remote platform: that is the auto-upload slice's problem. A NixOS VM test in CI covers the install path. | Nothing to install on the server first, and no version skew, which fits D10. Under D10 this is the path used every day, not an edge case (reaffirmed 2026-11-14). |
| D8 | **Resume** is a headline feature. When resuming, **rekey** through an authenticated local channel. Never save transport or crypto state to disk (saving it risks nonce reuse; Winstein, mosh-devel, July 2012). | |
| D9 | **Server-side emulation, structured diffs to the client.** The client has no VT parser. Anything deliberately passed through (title, OSC 52, OSC 8) goes through a strict allow-list. | Terminal isolation (§1.4). |
| D10 | **Trunk-based, every green commit is a release** (static binaries for linux/darwin × amd64/arm64). | §1.1 |
| D11 | **Mosh's SSP timing**, from the paper and public documentation (see §4): frame interval = SRTT/2 clamped to 20–250 ms, the server waits 8 ms to collect output, acks are delayed 100 ms, a 3 s heartbeat, RFC 6298 RTO with a 50 ms floor, and the client sends every keystroke while the server sends only the latest state. *Amended 2026-11-14 (S5):* the RTO adds the peer's maximum ack delay (RFC 9002 §6.2.1), so the effective floor is about 150 ms. The RTO doubles, capped at 1 s. During an outage, probes go out every `clamp(silence/8, frame interval, 1 s)`. While the user types, SSP sends **chaff** on a fixed tick (as OpenSSH 9.5's ObscureKeystrokeTiming does), with the tick to be measured in netsim. There are no echo-ack-only frames while the pty has echo off. | Proven in the 2012 paper's evaluation. The amendments were measured over 280 simulated hours (S5). |
| D12 | **Mosh's prediction design** (epochs, server echo-ack, underlining unconfirmed predictions), reimplemented from the paper and then improved: wide characters, limits on hostile input. *Amended 2026-11-14 (S6):*<br>• **Confirmation:** confirm on the glyph only; only an informative keystroke confirms, and backspace never does.<br>• **Inserting text:** the shifted text run stops at a change of rendition, which handles autosuggestions.<br>• **Ack horizon** for frames that arrive after an unpredictable key.<br>• **Recovery by rebase:** keys not yet acknowledged are re-applied on each frame, falling back to the gate when the log has holes, after a paste, or with echo off.<br>• **Echo-off bit:** server frames carry a bit (`!ECHO && ICANON`); while it is set the client neither predicts nor logs keys.<br>• **Drawn-cursor heuristic:** off by default. | Paper: 70% instant, 0.9% wrong. S6, on modern shells: 79.8% instant and 0.1% wrong at 5 ms; 62.4% instant at 450 ms, against 41.2% without rebase. 0 of 555 password keys shown. |
| D13 | **No multipath** (no simultaneous wifi + cellular). | A feature too far. |
| D14 | **Sessions are login shells, as with SSH.** Anything you run inside (`claude`, chase's containers) just works. There's no "session command" hook. | |
| D15 | **Typed channels from the start**, modelled on RFC 4254: the handshake negotiates which channel types each side supports. v1 has the terminal and ssh-agent forwarding. Port forwarding comes later and **must not be ruled out by the design**. A UDP datagram channel is the most useful form; for TCP you can still use `ssh -L`. | |
| D16 | **No remote-galley feature.** galley and quoin questions must work exactly as they do over `ssh -A`, through the forwarded agent. | |
| D17 | **Depend on standards, not the family tools**: ssh-agent for keys (quoin plugs in), OpenSSH `known_hosts` / `authorized_keys`, zenity-compatible prompts (galley plugs in). There's no hard dependency on quoin, galley, flong or chase. | Anyone can use it, and the family's security still arrives through those interfaces. |
| D18 | **Deterministic network tests**: a simulated `net.PacketConn` running under `testing/synctest` (virtual time), with seeded Gilbert-Elliott burst loss, delay, jitter, reordering, MTU limits, outages, and **replayed Mahimahi cellular traces**. Profiles such as `train`, `lte-driving` and `hotel-wifi` are test fixtures. Kernel netem checks are local-only, and nothing in CI asserts real elapsed time. | No manual testing on trains. |
| D19 | Minimal dependencies: the Go standard library plus `golang.org/x/*`. **Never write our own crypto or terminal emulator.** Every third-party dependency has to earn its place, and the reason goes in `DEPENDENCIES.md`. | |
| D20 | **Handshake = B3** (S1): `Mosey_B3_KEMx2psk0_XWing_ChaChaPoly_HKDFSHA256`.<br>• **Bootstrap:** each side makes a single-use X-Wing key during the SSH bootstrap; the client's goes over SSH stdin, the server's over stdout along with a PSK and a credential id.<br>• **Credentials:** a credential is consumed only when the client confirms. Each lives 30 s, at most 2 may be unused per session, and evictions are logged.<br>• **Packets:** ChaCha20-Poly1305 with an RFC 6479 replay window. Receive state changes only after a packet authenticates.<br>• **Rekey:** every 120 s or N packets, using the hybrid key exchange. REKEY_INIT is split across 2 datagrams, each sealed under the current keys. There is no rekey triggered by idleness.<br>• **Libraries:** the KEM is `crypto/hpke` X-Wing. Its audit gap is recorded in `DEPENDENCIES.md` and is part of the external review.<br>• **Erasing secrets:** linux release builds use `GOEXPERIMENT=runtimesecret`, with handshake and rekey inside `secret.Do`. Elsewhere the claim is the weaker "erased after GC reuse". | SSH only has to be authentic, not confidential: a leaked stdout line doesn't give a shell (ProVerif, plus an attack test). Post-quantum, forward secret, no long-term keys on disk. |
| D21 | **Roaming uses path validation** (RFC 9000 §8). An address that isn't validated gets at most 3x the bytes received from it, and an encrypted PATH_CHALLENGE that is re-sent on a timer. The client sends at once when its local address changes (netlink on Linux). | The paper's "newest authentic source" rule lets an on-path sniff-and-inject attacker redirect the screen stream (29x amplification, session cut off; S5). |
| D22 | **Process layout C** (S4):<br>• **spawner:** tiny and unsandboxed. Binds UDP, opens ptys, forks shells, hands pty fds over with SCM_RIGHTS.<br>• **proto:** keys, UDP, every protocol parser.<br>• **emu:** the VT parser.<br>proto and emu both run under Landlock deny-all (through `x/sys`), seccomp TSYNC (KILL on amd64; ERRNO on arm64 until a CI arm64 soak passes) and `DUMPABLE=0`. proto enforces a strict grammar on emu's replies. CI runs a KILL soak of at least 120 s for every Go upgrade and every architecture. Linux-only mechanisms sit behind a platform layer, and macOS is parked but expected (nothing may rule it out). | The emulator is the sandbox that really contains an attacker. Splitting adds no measurable latency. |
| D23 | **Terminal emulator: `tuios.dev/vt`** (pure Go, pinned) behind a mosey-owned `Emulator` interface. libghostty, read directly, is the CI oracle. Bounds:<br>• window size clamped to 1000x500 (configurable);<br>• scrollback budgeted in cells, `min(10000, 1e6/cols)` lines;<br>• emu cgroup `MemoryMax` of 512 MiB; when it is hit, tell the client and rebuild.<br>A panic also means rebuild. The reply queue is bounded. The D9 allow-list is enforced at both ends, and the client's diff decoder is fuzzed. | It is the only candidate with no fuzz finding, it has the richest API, and it scored 36/36 on vttest (S2). Fork it if upstream stalls. |
| D24 | **Compression is always on** (stdlib flate per frame, with a bounded decoder). Padding and dictionary use are settled in the spec. | Mosh 1.4.0 compresses every update with no padding (measured black-box, S5). |
| D25 | **Agent forwarding replays the bind captured from the system ssh** (S3, option a′).<br>• **Bootstrap:** the client starts a fresh `ssh -o ForwardAgent=<capture socket> -o ControlMaster=no -o ControlPath=none`.<br>• **Capture:** a strict capture state machine checks the pid and uid, then pins the bind to known_hosts.<br>• **Replay:** the bind is replayed at the start of every agent channel.<br>• **No trustworthy bind:** the agent is off.<br>Whether to forward follows ssh's own config (`ForwardAgent` from `ssh -G`, including a socket path or env var), and `-A`/`-a` override it. | quoin-signer works unchanged. Destination-constrained agents work exactly as they do with `ssh -A`. |
| D26 | **Attach is exclusive** (v1). A new attach revokes every other transport and wipes its keys; the kicked client exits with "session taken over from <addr> at <time>". The design keeps transports separate (SSP state per transport, size policy in one place, an attach-mode field reserved) so a shared mode can come later. | Simple, and it cuts off a stolen client. |
| D27 | **Terminal pass-through:**<br>• **OSC 52:** clipboard write always allowed (size-capped); read never.<br>• **OSC 8:** http, https and mailto only, at most 2048 B.<br>• **Titles:** bidi controls are stripped. | |
| D28 | **Provenance for remote approvals is a quoin feature** (`provenance-v00@bodar.com`, quoin-attest). mosey's part:<br>• it passes agent extension messages through;<br>• it hands each agent connection to quoin-attest through a keyless, fail-closed forwarder that doesn't import quoin;<br>• it exposes the handshake hash `h`, so quoin-attest can sign it.<br>Hand-off: quoin branch `mosey/s7-provenance-envelope`, `docs/mosey-integration.md`. | Works over mosey and over stock `ssh -A` (S7). |

## 3. Open

Everything from the first version of this section (O1–O9) was settled on
2026-11-14 after the spikes; see D5, D11, D12 and D20–D28. Still open:

| # | Question | Current position |
|---|---|---|
| O6 | NAT and firewall traversal (ICE/STUN over the SSH bootstrap) | After v1. B3 doesn't rule it out. |
| O9 | DPLPMTUD (RFC 8899) and ECN | After v1. Base 1200, as QUIC uses (D5). |
| O10 | Chaff tick and cost (D11) | Measure in netsim before fixing the value. Reserve the frame type now. |
| O11 | Cell-diff wire format (D9) | S2's prototype was bigger than raw output at its cadence. Redesign it in the spec, and measure it with SSP timing and compression on. |
| O12 | Compression padding and dictionary (D24) | Closed for v1 in `docs/spec/ssp.md` §9.2: no dictionary ever, no padding in v1 (it costs about 20% of the saving and only blunts the leak), the residual leak accepted as threat-model R1. Revisit padding with chaff (O10). |

## 4. Clean-room rules (D3)

- **Sources you may use**: the Mosh paper (Winstein & Balakrishnan, USENIX
  ATC 2012), mosh.org documentation and man pages, mailing-list design
  discussion, RFCs, other papers, and numbers or behaviour observed from
  black-box tests of the `mosh` binary.
- **Never read, copy, paraphrase or translate Mosh's source code**: not
  `terminaloverlay.cc`, `transportsender-impl.h`, the network code, or
  anything else. Numeric constants that the paper documents are facts and
  are fine to use. Where the paper doesn't give a value, measure Mosh as a
  black box or derive it ourselves, and note which in the spec.
- **Spec first**: `docs/spec/` describes SSP timing, prediction and framing
  in our own words, citing the paper section or RFC for each. The code is
  written from the spec.
- Each agent working on this repo is told these rules. Review checks for
  any sign of Mosh-derived code structure.

## 5. Spikes (done 2026-11-13)

All seven ran in parallel, each was adversarially reviewed and revised, and
each left `docs/spikes/<id>/FINDINGS.md` plus record code under
`spikes/<id>/`. They were S1 handshake, S2 terminal emulator, S3 agent
forwarding and session-bind, S4 privilege separation, S5 network simulator
and SSP, S6 prediction, and S7 remote-approval provenance (new, at Dan's
request). The decisions are in §2. Gaps they left:

- nothing ran on a real WAN, NAT or cellular path;
- fuzzing ran for minutes, not hours;
- no end-to-end quoin-sudo run (that needs root or a VM);
- the pieces have never run together.

## 6. Build

1. Implement in thin vertical slices on trunk, each starting with its own
   `docs/spec/` section (clean room, §4), then fuzzed, and tested against
   the S5 simulator. The first slice joins the spikes into a working whole:
   SSH bootstrap (B3 plus bind capture), the handshake, SSP over netsim and
   real UDP, layout C, tuios with cell diffs, and the client's renderer. Then
   resume, the agent channel, prediction, auto-upload, and chaff.
2. `docs/threat-model.md` grows with the slices.
3. Release pipeline (D10) from the first commit. Then use it daily, on
   trains.
4. The quoin work happens in its own session (D28).
5. Before 1.0: a formal model of the whole handshake and rekey that checks
   out, fuzzing running continuously, and an external security review
   (including `crypto/hpke`).

## 7. Sources (from the research passes)

- Winstein & Balakrishnan, *Mosh: An Interactive Remote Shell for Mobile
  Clients*, USENIX ATC 2012: https://mosh.org/mosh-paper.pdf
- Winstein, resume design, mosh-devel, July 2012:
  https://mailman.mit.edu/pipermail/mosh-devel/2012-July/000239.html
- WezTerm multiplexing (SSH bootstrap, then TLS, then automatic
  reconnect): https://wezterm.org/multiplexing.html
- tmux `resize.c` (window-size strategies with several clients):
  https://sources.debian.org/src/tmux/3.5a-3/resize.c
- Go crypto audit (Trail of Bits, 2025): https://go.dev/blog/tob-crypto-audit
- flynn/noise nonce advisory:
  https://github.com/flynn/noise/security/advisories/GHSA-g9mp-8g3h-3c5c
- PQNoise (CCS 2022): https://www.cryptojedi.org/papers/pqnoise-20220519.pdf
- Identity misbinding with raw-public-key TLS 1.3:
  https://mailarchive.ietf.org/arch/msg/tls/NaXngZTt_yTXhWGUNj85TBBdjQI/
- RFC 9221 (QUIC datagrams), RFC 4254 (SSH channels), RFC 6298 (RTO),
  RFC 6479 (anti-replay), RFC 8445 (ICE), RFC 8489 (STUN), RFC 8899
  (DPLPMTUD), RFC 9407 (Tetrys)
- Terminal emulator vulnerability survey (Leadbeater):
  https://dgl.cx/term
- tuios.dev/vt: https://pkg.go.dev/tuios.dev/vt
- go-landlock:
  https://github.com/landlock-lsm/go-landlock/blob/main/README.md
- Sprout (NSDI 2013; doesn't suit apps that don't saturate the link):
  https://www.cs.princeton.edu/courses/archive/spring21/cos563/papers/sprout.pdf
- POLYCORN (NSDI 2023, high-speed-rail LTE):
  https://www-users.cse.umn.edu/~fengqian/paper/polycorn_nsdi23.pdf
- engarde (duplicating WireGuard traffic over several links):
  https://github.com/porech/engarde
- Network simulator references: marcopolo/simnet (synctest),
  kasader/flakenet, pion/transport/vnet; Mahimahi (record and replay of
  cellular links)
- Mosh PRs: #1403 (CSI cap), #1410 (wide-character prediction), #696/#1297
  (agent forwarding), #1442 (IPv6-only)
