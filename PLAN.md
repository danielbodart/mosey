# mosey: plan

**mosey**: to wander along at an easy pace. A remote terminal that roams
between networks, stays usable on bad links and picks up where it left off.
It's a successor to [Mosh](https://mosh.org), written from scratch in Go.

This plan was written on dan-blade on 2026-11-13, from a long research
conversation. It should be carried out on dan-desktop as a series of
workflows. **§2 lists what is decided. Don't reopen any of it without asking
Dan.** §3 lists what is open: each item there is a recommendation, and the
spikes in §5 exist to settle them.

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

## 2. Decisions (locked)

| # | Decision | Why |
|---|---|---|
| D1 | **Go**, statically linked binaries | The GC rules out use-after-free on a network daemon. It also shares code and style with quoin, galley and gokit. |
| D2 | **License: Apache-2.0** (Dan: Apache or MIT; Apache matches gokit and zigkit) | Permissive. |
| D3 | **Clean-room implementation.** Mosh is GPLv3. | See §4 for the rules. |
| D4 | **Security bar: the public internet, used by other people.** Dan deploys it only inside WireGuard, but WireGuard is **never** the security boundary or an excuse for a shortcut. | It's a daemon reachable from the network. |
| D5 | **UDP only.** Datagrams must fit inside WireGuard (start at 1280-byte payloads, as Mosh does). | |
| D6 | **Started over SSH, as Mosh is.** The client SSHes in using the system `ssh` and the user's own config, starts the server on demand, and receives the session's secret over that SSH channel. **SSH vouches for the server.** | Familiar to Mosh users, and it works with any existing SSH setup. |
| D7 | **Copy the server over automatically.** If the server binary is missing or the wrong version, the client copies over its own matching static build (hash-checked, installed to `~/.cache/mosey/<version>/`, asks the first time, never replaces a file someone else owns). Prior art: VS Code Remote-SSH, kitty's `kitten ssh`. | Nothing to install on the server first, and no version skew, which fits D10. |
| D8 | **Resume** is a headline feature. When resuming, **rekey** through an authenticated local channel. Never save transport or crypto state to disk (saving it risks nonce reuse; Winstein, mosh-devel, July 2012). | |
| D9 | **Server-side emulation, structured diffs to the client.** The client has no VT parser. Anything deliberately passed through (title, OSC 52, OSC 8) goes through a strict allow-list. | Terminal isolation (§1.4). |
| D10 | **Trunk-based, every green commit is a release** (static binaries for linux/darwin × amd64/arm64). | §1.1 |
| D11 | **Mosh's SSP timing**, from the paper and public documentation (see §4): frame interval = SRTT/2 clamped to 20–250 ms, the server waits 8 ms to collect output, acks are delayed 100 ms, a 3 s heartbeat, RFC 6298 RTO with a 50 ms floor, and the client sends every keystroke while the server sends only the latest state. | Proven in the 2012 paper's evaluation. |
| D12 | **Mosh's prediction design** (epochs, server echo-ack, underlining unconfirmed predictions), reimplemented from the paper and then improved: wide characters, limits on hostile input. Not game-style prediction. | 70% of keystrokes shown instantly, 0.9% wrong (paper). |
| D13 | **No multipath** (no simultaneous wifi + cellular). | A feature too far. |
| D14 | **Sessions are login shells, as with SSH.** Anything you run inside (`claude`, chase's containers) just works. There's no "session command" hook. | |
| D15 | **Typed channels from the start**, modelled on RFC 4254: the handshake negotiates which channel types each side supports. v1 has the terminal and ssh-agent forwarding. Port forwarding comes later and **must not be ruled out by the design**. A UDP datagram channel is the most useful form; for TCP you can still use `ssh -L`. | |
| D16 | **No remote-galley feature.** galley and quoin questions must work exactly as they do over `ssh -A`, through the forwarded agent. | |
| D17 | **Depend on standards, not the family tools**: ssh-agent for keys (quoin plugs in), OpenSSH `known_hosts` / `authorized_keys`, zenity-compatible prompts (galley plugs in). There's no hard dependency on quoin, galley, flong or chase. | Anyone can use it, and the family's security still arrives through those interfaces. |
| D18 | **Deterministic network tests**: a simulated `net.PacketConn` running under `testing/synctest` (virtual time), with seeded Gilbert-Elliott burst loss, delay, jitter, reordering, MTU limits, outages, and **replayed Mahimahi cellular traces**. Profiles such as `train`, `lte-driving` and `hotel-wifi` are test fixtures. Kernel netem checks are local-only, and nothing in CI asserts real elapsed time. | No manual testing on trains. |
| D19 | Minimal dependencies: the Go standard library plus `golang.org/x/*`. **Never write our own crypto or terminal emulator.** Every third-party dependency has to earn its place, and the reason goes in `DEPENDENCIES.md`. | |

## 3. Open (recommendations, to be settled by the spikes)

| # | Question | Recommendation so far |
|---|---|---|
| O1 | **The handshake.** A custom SIGMA-style handshake on audited standard-library building blocks, or QUIC (quic-go with RFC 9221 datagrams), or Noise? | Custom SIGMA-I-style: ephemeral X25519 + ML-KEM-768 hybrid (`crypto/ecdh`, `crypto/mlkem`, `crypto/hkdf`, all covered by the 2025 Trail of Bits audit), with both long-term public keys, the role labels and both key shares in a transcript that both sides sign, and the session keys derived from that transcript. Each packet carries an explicit counter, with a replay window (RFC 6479 / WireGuard). Receive state is only updated after a packet authenticates (the lesson of flynn/noise's pre-1.0 advisory). QUIC loses because its congestion controller would override SSP's pacing and fast retransmit. **But D6 changes the problem:** when SSH vouches for the server, the handshake may just need a PSK delivered over SSH, combined with ephemeral key exchange for forward secrecy. Spike S1 decides. |
| O2 | **Agent forwarding with quoin's session-bind.** quoin's remote sudo needs OpenSSH's `session-bind@openssh.com` (host key, session id, the host key's signature). A rootless server started on demand can't sign with `/etc/ssh` host keys. **Ordinary agent forwarding works either way. Only quoin's bind-checked features are at risk.** | Options: (a) the client does the SSH bootstrap itself with `x/crypto/ssh`, holds the real (host key, exchange hash, signature) triple, and replays it as the bind for the mosey connection, which **costs `~/.ssh/config` support (ProxyJump and so on)**; (b) a per-user mosey identity vouched for by SSH, which quoin would treat as an unknown host and ask about every time, and remote sudo fails; (c) a small quoin extension that understands a mosey-specific bind. Spike S3 decides. |
| O3 | **Terminal emulator on the server.** | `tuios.dev/vt`: pure Go by default, with an optional libghostty-vt backend via cgo behind the same API, and it limits attacker-controlled sizes before allocating. It's young and only self-documented. Run the emulator in a sandboxed helper process either way. Spike S2 decides. |
| O4 | **Layout without root and privilege separation.** | A per-user server (no root), split into a **network process** (packets, crypto, handshake) and a **session process** (ptys, shells, emulator), connected by a socketpair. Landlock in both. Landlock doesn't cover UDP, so the network process needs **seccomp**, and seccomp has to apply to all of Go's runtime threads (TSYNC, or install it before the runtime starts by re-executing). Spike S4. |
| O5 | **Client UX for resuming.** | `mosey host` reattaches to the default session automatically, `mosey host:name` attaches to a named one, and `mosey ls host` lists them. No tmux-style picker. With several clients attached, the most recently active one sets the size (tmux's `latest` rule). Native scrollback comes from the server's history, fetched lazily. |
| O6 | **NAT and firewall traversal** using the SSH bootstrap as the signalling channel: both sides send UDP at the same time, so no inbound port needs opening (ICE RFC 8445, STUN RFC 8489, Tailscale's "How NAT traversal works"). | Design the handshake so this can be added. Ship it after v1. Limits: roaming needs another round of punching, and symmetric or carrier-grade NAT needs a relay. |
| O7 | **Burst-loss recovery beyond SSP.** | After an RTO, resend the *current* state straight away rather than backing off (POLYCORN, NSDI 2023, on high-speed-rail LTE). Experiment: XOR or sliding-window parity over recent keystroke frames (Tetrys / RFC 9407 ideas, Fiedler-style redundancy). No Reed-Solomon or RaptorQ dependency. Decide by benchmark (S5). |
| O8 | **Compression.** | Raw frames vs stdlib `compress/flate` vs zstd with a dictionary (`klauspost/compress`, a dependency). Decide by benchmark on real diff frames. |
| O9 | **Sending only a few datagrams.** | Recompute timing from SRTT, use DPLPMTUD (RFC 8899) later, ECN maybe. Low priority. |

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

## 5. Spikes (first workflow: run them in parallel, each in its own worktree)

Each spike ends with `docs/spikes/<id>/FINDINGS.md` (what was tried, what was
measured, and a recommendation) and code under `spikes/<id>/` that is a
record, not production code.

- **S1 Handshake.** Build the SIGMA-I + X25519/ML-KEM hybrid variant and the
  "PSK over SSH + ephemeral key exchange" variant. Model each in
  ProVerif or Tamarin, or at minimum write out its properties (key secrecy,
  forward secrecy, mutual authentication, identity misbinding, replay, key
  compromise impersonation). Compare against quic-go with RFC 9221 datagrams
  on dependencies, pacing control and complexity. Fuzz the handshake parser.
- **S2 Terminal emulator.** Compare `tuios.dev/vt`, `charmbracelet/x/vt`
  and libghostty-vt (through tuios' ghostty backend in a cgo helper) on:
  vttest coverage, fuzzing (`go test -fuzz` for N hours, crashes and hangs),
  resource limits under hostile input (huge CSI parameters, sixel, deep
  OSC), maintenance (commits, contributors, issues), dependency tree, and
  the cost of the helper process boundary.
- **S3 Agent forwarding and session-bind.** Prototype options (a)/(b)/(c)
  from O2 against a real quoin signer: does quoin's remote sudo work
  unchanged, and what does each option cost?
- **S4 Privilege separation.** Network process + session process; Landlock
  in both; seccomp with TSYNC vs installing it before the runtime starts by
  re-executing; does it run as an unprivileged systemd user service?
  Measure what still works when the network process is compromised.
- **S5 Network simulator + SSP baseline.** Build the D18 simulator first,
  since everything else depends on it. Implement SSP timing (D11) from the
  spec, then benchmark under the train profiles: keystroke-to-screen
  latency, stalls after outages, bytes sent. Try the O7 and O8 variants.
- **S6 Prediction harness.** Record your own keystroke/echo traces
  (bash, zsh with autosuggestions, fish, vim, claude). Replay them through a
  from-spec implementation of the D12 prediction under S5's profiles,
  reporting the paper's metrics: share of keystrokes shown instantly,
  wrong-prediction rate. Note what modern shell features break.

## 6. After the spikes

1. Settle O1–O8 with Dan, and update §2 and §3.
2. `docs/threat-model.md` and `docs/spec/` (wire format, handshake, SSP,
   prediction, channels, resume).
3. Implement in thin vertical slices (handshake → SSP → terminal → resume →
   agent channel → auto-upload), each fuzzed and tested against the
   simulator.
4. Release pipeline (D10) from the first commit. Then use it daily, on
   trains.
5. Before 1.0: a formal model of the handshake that checks out, fuzzing
   running continuously, and an external security review.

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
