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

## 2. Decisions (locked; last amended 2026-11-15 by Dan)

| # | Decision | Why |
|---|---|---|
| D1 | **Go**, statically linked binaries | The GC rules out use-after-free on a network daemon. It also shares code and style with quoin, galley and gokit. |
| D2 | **License: Apache-2.0** (Dan: Apache or MIT; Apache matches gokit and zigkit) | Permissive. |
| D3 | **Clean-room implementation.** Mosh is GPLv3. | See §4 for the rules. |
| D4 | **Security bar: the public internet, used by other people.** Dan deploys it only inside WireGuard, but WireGuard is **never** the security boundary or an excuse for a shortcut. | It's a daemon reachable from the network. |
| D5 | **UDP only.** Datagrams must fit inside WireGuard. *Amended 2026-11-14:* data payloads are at most **1232 bytes** (the IPv6 minimum MTU of 1280, less the IPv6 and UDP headers). Every handshake and rekey message is at most **1200 bytes** (QUIC's floor), so DPLPMTUD can be added later with a 1200-byte base and no wire change. | A 1280-byte payload is silently dropped on minimum-MTU IPv6 paths and inside WireGuard tunnels with an MTU of 1280 (S1). |
| D6 | **Started over SSH, as Mosh is.** The client SSHes in using the system `ssh` and the user's own config, starts the server on demand, and receives the session's secret over that SSH channel. **SSH vouches for the server.** | Familiar to Mosh users, and it works with any existing SSH setup. |
| D7 | **Copy the server over automatically, only where the host has none.** *Amended 2026-11-15 (Dan). Amended 2026-11-15 (Dan): sigstore-go removed as too large. Amended 2026-11-15 (Dan): use whatever mosey the host has; "keep it super simple". Amended 2026-11-16 (Dan): install to `~/.local/bin/mosey`.* The client uses whatever mosey the host has, of any version: `mosey` on the remote `PATH` first, otherwise the single file `~/.local/bin/mosey`, asked by its path (a non-login `ssh host cmd` may not have it on `PATH`). Only if there is neither does it copy over its own static build there (hash-checked, asks the first time, remembered per host, installed atomically, never replaces a file someone else owns). It never installs other versions as the user moves around: upgrading the host's mosey is done by Nix or by replacing the binary (Dan), and new sessions use it. If `~/.local/bin/mosey` speaks another protocol it is replaced, under the same consent, whether `PATH` found it or not; a `-remote` mosey, or one elsewhere on `PATH`, of another protocol fails with one line naming both numbers. Hopping on works without touching any rc file wherever the login profile puts `~/.local/bin` on `PATH` (Debian, Ubuntu, Fedora); NixOS needs mosey from Nix. A session served from `~/.local/bin/mosey`, on a host with no `mosey` on `PATH`, also gets `~/.local/bin` first on its shell's `PATH`. Prior art: VS Code Remote-SSH, kitty's `kitten ssh`. **mosey is one binary**: `mosey host` is the client and `mosey --serve` the server (with its roles re-executed from the same file as `--serve=proto` and `--serve=emu`; a flag, so every plain word, such as a host called `server`, belongs to the client), so the copy sent over is the very file the client runs, and a host can hop on with it. Versions on the two ends need not match (D8 V1, stable protocol).<br>• **Cross-platform copy** (say a Mac client, Linux server): the client fetches its own version's release asset for the remote platform from GitHub and, before uploading it, checks its SHA-256 against the release's `SHA256SUMS`. A mismatch is refused.<br>• **Release binaries carry GitHub build attestations** for checking by hand: CI attests every release binary with `actions/attest-build-provenance` (pinned by commit SHA), signed through GitHub OIDC and Sigstore with no long-lived key, and GitHub stores the attestations, so anyone can run `gh attestation verify FILE --repo danielbodart/mosey`. **Client-side signature verification is deferred** (O16): sigstore-go, which did it, doubled the binary (9.9 to 21 MB) and brought about 65 modules, and was removed.<br>A NixOS VM test in CI covers the install path. | Nothing to install on the server first. Under D10 this is the path used every day, not an edge case (reaffirmed 2026-11-14). The attestations tie a released binary to the workflow that built it, with no long-lived signing key to guard or rotate (Dan, 2026-11-15); checking them in the client waits for a verifier small enough to carry (O16). |
| D8 | **Resume is automatic** (PLAN §1 goal 3). *Amended 2026-11-15 (Dan).*<br>• **Automatic (R1):** plain `mosey HOST` resumes this user's most recently detached session on HOST if one is detached, and otherwise starts a new one. It never steals an attached session, so a second terminal to the same host gets its own. There is no resume flag.<br>• **Named sessions (R2):** every session has a name; an unnamed one gets a generated adjective-noun name. `mosey -s NAME HOST` attaches to NAME, taking it over if it is attached elsewhere (D26), and creates it if it doesn't exist. `mosey -new HOST` always starts a fresh, generated-name session. `mosey -list HOST` shows each session's name, attached or detached, and since when. `mosey -kill NAME HOST` ends one (SIGHUP to its shell). The old `-r` / `-r=SID` flags go; `-s` replaces them.<br>• **Session state lives only on the remote host.** The client keeps no session list or ids on disk.<br>• **Reconnect (R3):** while the client runs, a dead spot is ridden out by roaming (D21). If no authenticated packet has arrived for a while (interval O13), the client also retries resume of the **same** session, by name, over a fresh SSH login, in the background with backoff, never asking the user anything, until it succeeds or the session is gone. If the shell has exited, the client exits with a clear message. After a client reboot or crash, R1 gives the session back on the next plain `mosey HOST`.<br>• **Lifetime (R4):** Ctrl-D or any exit of the shell ends the session. There is **no detach key**: closing the client terminal detaches. A detached session has an idle timeout, **7 days** by default [D], after which its shell gets SIGHUP (configurability: O14).<br>• **Stable protocol (V1):** *Amended 2026-11-15 (Dan): no live upgrade. Amended 2026-11-15 (Dan): one protocol number per layer, no software versions.* "If we've got a stable protocol, why do we even need the software versions… when I use SSH I don't really worry about the version stuff." No line, greeting or hello carries a software version, and nothing compares one; `mosey -version` is for people. Each layer has **one** protocol number, versioned and documented as the stability promise: the bootstrap lines, the handshake hello and the attach greeting. Each is checked for equality, with no range and no negotiation, and a mismatch fails with one clear line naming both numbers ("dan-desktop's mosey speaks protocol 2; this mosey speaks 1"). A client and server of different mosey versions is normal and must work. A launcher attaches a session run by an older binary of the same attach protocol, which goes on serving it with its own code; an upgrade takes effect on new sessions. There is no live upgrade, and no compatibility work until mosey has users (Dan, 2026-11-15).<br>• **When resuming, rekey** through an authenticated local channel. **Never save transport or crypto state to disk** (saving it risks nonce reuse; Winstein, mosh-devel, July 2012); every resume is a fresh SSH login and a fresh handshake. | "Reattach automatically after a dead spot, a reboot, or from another device" (§1). A version lock, or a resume refused across versions, would cost the user a session for upgrading; carrying a running session to new code, or negotiating between protocol ranges, is complexity mosey does not need while it has no users (Dan, 2026-11-15). |
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
| D22 | **Process layout C** (S4):<br>• **spawner:** tiny and unsandboxed. Binds UDP, opens ptys, forks shells, hands pty fds over with SCM_RIGHTS.<br>• **proto:** keys, UDP, every protocol parser.<br>• **emu:** the VT parser.<br>proto and emu both run under Landlock deny-all (through `x/sys`), seccomp TSYNC (KILL on amd64 and arm64; arm64 was ERRNO until its CI soak passed, run 43626969195) and `DUMPABLE=0`. proto enforces a strict grammar on emu's replies. CI runs a KILL soak of at least 120 s for every Go upgrade and every architecture. Linux-only mechanisms sit behind a platform layer, and macOS is parked but expected (nothing may rule it out). | The emulator is the sandbox that really contains an attacker. Splitting adds no measurable latency. |
| D23 | **Terminal emulator: `tuios.dev/vt`** (pure Go, pinned) behind a mosey-owned `Emulator` interface. libghostty, read directly, is the CI oracle. Bounds:<br>• window size clamped to 1000x500 (configurable);<br>• scrollback budgeted in cells, `min(10000, 1e6/cols)` lines;<br>• emu cgroup `MemoryMax` of 512 MiB; when it is hit, tell the client and rebuild.<br>A panic also means rebuild. The reply queue is bounded. The D9 allow-list is enforced at both ends, and the client's diff decoder is fuzzed. | It is the only candidate with no fuzz finding, it has the richest API, and it scored 36/36 on vttest (S2). Fork it if upstream stalls. |
| D24 | **Compression is always on** (stdlib flate per frame, with a bounded decoder). Padding and dictionary use are settled in the spec (`ssp.md` §9.2). | Mosh 1.4.0 compresses every update with no padding (measured black-box, S5). |
| D25 | **Agent forwarding replays the bind captured from the system ssh** (S3, option a′).<br>• **Bootstrap:** the client starts a fresh `ssh -o ForwardAgent=<capture socket> -o ControlMaster=no -o ControlPath=none`.<br>• **Capture:** a strict capture state machine checks the pid and uid, then pins the bind to known_hosts.<br>• **Replay:** the bind is replayed at the start of every agent channel.<br>• **No trustworthy bind:** the agent is off.<br>Whether to forward follows ssh's own config (`ForwardAgent` from `ssh -G`, including a socket path or env var), and `-A`/`-a` override it. | quoin-signer works unchanged. Destination-constrained agents work exactly as they do with `ssh -A`. |
| D26 | **Attach is exclusive** (v1). *Amended 2026-11-15 (Dan).* A new attach revokes every other transport and wipes its keys; the kicked client exits with "session taken over from <addr> at <time>". Only an explicit `mosey -s NAME HOST` takes over an attached session; a plain `mosey HOST` never steals one (D8 R1) and starts its own instead. The design keeps transports separate (SSP state per transport, size policy in one place, an attach-mode field reserved) so a shared mode can come later. | Simple, and it cuts off a stolen client. |
| D27 | **Terminal pass-through:**<br>• **OSC 52:** clipboard write always allowed (size-capped); read never.<br>• **OSC 8:** http, https and mailto only, at most 2048 B.<br>• **Titles:** bidi controls are stripped. | |
| D28 | *Amended 2026-11-15 (Dan).* **Agent forwarding is orthogonal to quoin: mosey forwards the agent as ssh -A does and has no quoin-specific code; anything quoin needs it does on its side.** Each agent channel is an opaque byte stream after the replayed bind (D25), and agent extension messages pass through untouched. The quoin-attest forwarder, the attester refusal and the exported handshake hash are removed. | Dan: mosey knowing about quoin "feels wrong… this should be orthogonal… a change we need to make on the quoin side independently". Any agent works the same over mosey and over stock `ssh -A`. |

## 3. Open

Everything from the first version of this section (O1–O9) was settled on
2026-11-14 after the spikes; see D5, D11, D12 and D20–D28. Still open:

| # | Question | Current position |
|---|---|---|
| O6 | NAT and firewall traversal (ICE/STUN over the SSH bootstrap) | After v1. B3 doesn't rule it out. |
| O9 | DPLPMTUD (RFC 8899) and ECN | After v1. Base 1200, as QUIC uses (D5). |
| O10 | Chaff tick and cost (D11) | **Closed** by Dan's decision, amended 2026-11-15 (Dan), in `docs/spec/ssp.md` §9.1: the tick stays **20 ms** at both ends, the server chaffing too (without it its echoes named every key); while chaffing, **every client datagram is padded to at least 64 B** (chaff and keystrokes alike), as the server's already are. Dan chose it from the measured train profile: keys exposed by size fall from 50% to 7% for 35% more client bytes while typing, nothing when idle. On the LAN and the spike-free profiles hiding was the same at every tick from 10 to 50 ms (2.0–5.0% of keys exposed, against 100% without chaff), and 20 ms adds about 20–30 ms to the median echo. Whether netsim's per-packet delay spikes or a time-based spike model is right stays a measurement to make (a black-box check on a real lossy path), not a reason to hold the decision. |
| O11 | Cell-diff wire format (D9) | **Closed.** S2's prototype was bigger than raw output at its cadence; the redesigned format (`screen.md` §5) passed its gate, `TestDiffNotBiggerThanRaw` in `internal/emu/gate_test.go`, with SSP timing and compression on (results table in `screen.md` §5.12). |
| O12 | Compression padding and dictionary (D24) | **Closed** by Dan's decision, in `docs/spec/ssp.md` §9.2, amended 2026-11-15 (Dan) for the client's chaffing floor: no dictionary, ever; every SSP datagram (data, acks, heartbeats) is padded so its sealed plaintext is at least 64 bytes from the server, and from the client 64 while it chaffs (O10) and 40 otherwise, when idle or not typing (S5's 16 bytes of input plus a keystroke's framing, so every keystroke is one size), rounded up with Padmé (PURBs, PoPETs 2019) above that and capped at the D5 limit. If the code cannot keep the 40 B floor apart from chaffing, 64 becomes the client's floor everywhere and the spec says so. S5 measured the server rule to keep 88% of flate's saving and give every keystroke echo one size (`docs/spikes/s5-netsim-ssp/padding.md`). The residual leak is threat-model R1. |
| O13 | Reconnect interval (D8 R3) | **Closed** by the sessions slice, in `docs/spec/bootstrap.md` §9.2.2: the client starts retrying after **15 s** without an authenticated packet [D: five of D11's 3 s heartbeats], then backs off 2 s, doubling to at most 60 s [D]; each try runs ssh with `BatchMode=yes`, so it never asks the user anything. The server counts a client silent for the same 15 s as detached, so R1 takes its session after a crash or reboot. |
| O14 | Idle timeout of a detached session (D8 R4) | **Default 7 days** [D] (Dan, 2026-11-15), then SIGHUP to the shell. The sessions slice kept it a constant (`bootstrap.md` §9.3): an option would need a ClientLine field or a server config file, neither cheap. |
| O15 | A background reconnect (D8 R3) that finds its session attached elsewhere | **Open, for Dan.** A client asleep through a `-s` takeover wakes, hears nothing, and starts R3's retries by name. If a retry takes over as `-s` does, it steals the session back from whoever took it; if it attaches only a detached session, it should exit with D26's "session taken over" message. The build must not pick between these on its own. *Placeholder until Dan decides, not a decision:* the code has to do one or the other meanwhile, and does what D26's text says ("only an explicit `mosey -s NAME HOST` takes over"): a retry takes its session only if it is detached or still held by the retrying client's own credential, and otherwise exits as taken over (`bootstrap.md` §9.2.2). Dan's answer is one switch, `reconnectTakesBack` in `internal/server/choose.go`, both of whose settings are tested. Also for Dan: a retry names its session by id (and the credential it last held it with), not by name, so it can never attach a newer session that reused the name after the old one ended; R3 says "by name", and whether the id satisfies that is his to confirm. |
| O16 | Client-side release signature check (D7) | **Parked** by Dan, 2026-11-15: to revisit with a small verifier; no large dependency. sigstore-go did it and was removed as too large (it took the binary from 9.9 to 21 MB and brought about 65 modules). Meanwhile the client checks a downloaded binary against `SHA256SUMS` only, and CI's GitHub build attestations are there for `gh attestation verify` by hand. |

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
   (Done: slice 1, resume with exclusive attach, D8 and D26, auto-upload,
   D7, chaff, D11 and O10, agent forwarding, D15 and D25, and predictive
   echo, D12, and from Dan's amendments of 2026-11-15 the 64 B client
   chaff floor, O10 and O12, the removal of mosey's quoin-specific
   code, D28, GitHub build attestations on every release binary, D7
   (client-side checking of them parked, O16), and automatic and named resume with background reconnect,
   `-list`, `-kill` and the detached idle timeout, D8 R1–R4, O13 and
   O14, and the stable protocol, D8 V1, then simplified (Dan,
   2026-11-15) to one protocol number per layer and D7 using whatever
   mosey the host has, with one installed file (`~/.local/bin/mosey`
   since 2026-11-16, so hopping needs no rc file), and `-dir` and `-type` to
   start a new session in a directory with text typed into it, so a
   session can stand in for a tmux one (Dan, 2026-11-15), and lines
   that scroll off the remote screen printed into the local terminal's
   own scrollback, so mosey needs no tmux for history (Dan, 2026-11-15;
   `screen.md` §2.5 and §8.7). Next:
   Dan's call on O15.)
2. `docs/threat-model.md` grows with the slices.
3. Release pipeline (D10) from the first commit. Then use it daily, on
   trains. (Done: CI releases every green trunk commit to GitHub Releases,
   with a NixOS VM test of the install path; the race detector runs in CI.
   The flake's package is the release binary, not a source build, named by
   `nix/release.json` on a tag-only child commit, bootstrap.md §4.6: Dan,
   2026-11-15.)
4. Anything quoin needs for remote approvals over mosey is a quoin change,
   made on quoin's side in its own session; mosey has no quoin-specific code
   and waits on nothing from quoin (D28).
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
