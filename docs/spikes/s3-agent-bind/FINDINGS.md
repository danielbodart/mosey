# S3: agent forwarding and session-bind (O2)

The orchestrator wrote this file from the spike agent's structured result, because the agent's harness refused to write it. The code and results are under `spikes/s3-agent-bind/`.

## Summary and evidence

S3 (O2): ssh-agent forwarding over mosey and quoin's session-bind. This is the second revision, after adversarial review. Commits on spike/s3-agent-bind: 4f549f7, then 06055a3. The harness refused FINDINGS.md again, so the orchestrator should write docs/spikes/s3-agent-bind/FINDINGS.md from this result.

WHAT WAS BUILT (spikes/s3-agent-bind/)
- bind/: session-bind parse and verify, a strict capture agent, the relay, a cleartext-kex tap and the hop record.
- cmd/moseyc: client stand-in.
- cmd/moseys: server stand-in, installed as `mosey-server`. It starts a detached setsid session, and that session's SSH_AUTH_SOCK becomes one agent channel per connection.
- quoinchain/: quoin's own sudo/chain.zig (walk plus remote(), imported unchanged from the quoin worktree), run on the live session chain.
- harness/: two unprivileged OpenSSH 10.6p1 sshds on loopback, a throwaway stock ssh-agent, ssh_config entries for ProxyJump, ProxyCommand `ssh -W` and ControlMaster, a third host key X that a hostile server can mint binds for, and PerSourcePenalties set to no.
- No live signer, galley, TPM or ~/.ssh was touched.

OPTIONS COMPARED
- (a′) capture: run the system ssh with `-o ForwardAgent=<capture socket>`. The bootstrap opens the agent once, ssh sends its own session-bind with fwd=1, and the client replays that bind at the head of every mosey agent channel.
- (a) xcrypto: the client bootstraps with x/crypto/ssh and taps the bind triple from the cleartext key exchange.
- (b) a per-user mosey identity key.
- (c) a hop record (hop-v0@mosey.spike) sent after a real bind.
- none: no bind.

WHAT WAS MEASURED (results/run-all.txt plus one JSON per run; all loopback, 2026-11-13)
- E1–E6: a quoin-sudo-v1 sign through the session works under every option with an unconstrained stock agent.
- quoin's real agentsrv signer, replaying this run's recorded frames: for capture and xcrypto it asks "sudo on spikeA" with the signer unchanged. For identity and none it refuses without asking.
- quoin's real chain.zig on the session chain (sh → mosey-server session → systemd --user → systemd): remote() is true with quoin 0331bf1. With the trunk rule (sshd-session pair only) it is false, so sudo falls to local mode.
- E8, agent constrained with `ssh-add -h spikeA -h 'spikeA>spikeB'`: capture and xcrypto allow the onward login, as `ssh -A` does. Identity and none are denied.
- E11, hostile server injects a valid bind for host X after ssh's own. Agent: `-h spikeA -h spikeX -h 'spikeX>spikeB'`.
  - Plain `ssh -A` (control): onward login denied.
  - First prototype (legacy capture): onward-login-ok. The review's critical attack is reproduced through real ssh.
  - This revision: "protocol error: message 27 after the identities answer". No bind is taken, agent forwarding is turned off, and the onward login is denied.
- E7, server has AllowAgentForwarding no: the session now continues with agent_off=true.
- E7b, a server that ignores agent=off: the client refuses its agent channel (refused=1).
- E12, a live ControlMaster:
  - The first prototype rides the master, so there is no bind (reproduces the review's finding).
  - E12b: with a master that forwards an agent, the bootstrap's trigger reached the user's real agent, not the capture socket.
  - This revision (ControlMaster=no, ControlPath=none): works with or without a master.
  - Cost of skipping the master: mux 9.8 ms vs fresh 117.8 ms median, n=10.
- E13, ProxyCommand `ssh -W` (B via A): bind for B captured; sign OK.
- Unit tests (bind/capture_test.go):
  - Refused: an injected bind, a bind as frame 2, another pid, a bind without forwarding, the wrong frame order, a bad signature, and a second connection.
  - Taken: the honest sequence.
- Latency, interleaved, 30 rounds:
  - Run 1, quiet machine: capture 124.3 ms, none 119.6 ms, xcrypto 37.3 ms. The trigger itself took 0.82 ms.
  - Run 2, machine busy: 171.0, 154.3 and 65.6 ms.
  - So capture costs about 5 ms over a plain ssh bootstrap.
  - The ~80 ms x/crypto advantage was traced with strace of client and server. OpenSSH sets TCP_NODELAY only after authentication, so two back-to-back pre-auth writes are each held by Nagle for sshd's 40 ms delayed ACK. Go sets NODELAY by default. This is a loopback/LAN artifact of the system ssh and is not used as a decision reason. Not measured on a WAN.

QUOIN CHANGES (branch mosey/s3-agent-bind-hop, worktree /home/dan/Projects/quoin-mosey-s3)
- 8bb8de0: replay tests.
- 718c110: hop record.
- 0331bf1: chain.zig treats a mosey-server link as remote; the peer terminal leaf becomes mosey.
- e004544 (new): the hop record is rendered after the signer's own lines as "Reported by the far end, not verified:" / "<host> reports, not verified: …". It is cleaned and capped at 4000 characters, and kept out of the verified chain table and the Summary. testdata/mosey-relay.json was regenerated from this run's committed results. agentsrv and internal tests pass.

REVIEW RESPONSE (one entry per issue)
- Critical (bind replacement): fixed and measured (E11 plus unit tests).
- Major (hop text shown as verified): fixed on the quoin branch (e004544). The server now reads the requester chain via SO_PEERPIDFD plus a pidfd liveness check, and re-checks each link's start time.
- Major (pid check not enforced, ControlMaster untested): the pid/uid check is now enforced and the socket name is random (cap-<rand>.sock). E12 and E12b run with and without a master.
- Major ("all of ~/.ssh/config"): reworded. Exercised: ProxyJump, ProxyCommand ssh -W, HostKeyAlias, IdentityAgent, IdentitiesOnly, UserKnownHostsFile, StrictHostKeyChecking. Not exercised: Match exec, certificates, FIDO, GSSAPI, password prompts. ControlMaster reuse is a stated cost.
- Major (remote sudo not tested against quoin-sudo): partly fixed. The server comm is now mosey-server and quoin's real chain.zig gives remote()=true on the live chain. A real sudo with the plugin and its root gate, and a running quoin-signer daemon, were NOT run. The evidence is real OpenSSH, the real chain.zig and the real agentsrv on recorded frames.
- Minor (user-settable comm): rebutted with a caveat. Remote mode's approval is a forwarded-agent signature over a quoin-sudo-v1 message. Any user process that can reach a forwarded agent socket can already ask for that signature directly, so routing sudo to remote mode grants nothing new.
- Minor (cross-protocol signing oracle): accepted and documented. S7 must not sign hop data raw with a host key; it needs a separate key or an enforced SSHSIG namespace.
- Minor (goroutine and fd leak): fixed. One connection, deadlines, no blocking channel.
- Minor (E7 aborted the session): fixed; the session continues without the agent.
- Minor (evidence not committed): all JSONs and the throwaway keys are now committed. fixture.py reads only results/.
- Minor (unexplained 77 ms): the cause was found and the figure is dropped as a reason. The contradictory E9 block was removed.
- Not investigated: under the legacy handler the hostile server's read saw EOF after injecting, and the bootstrap then took about 10 s (the capture deadline). This does not change either result.

S7 COORDINATION
- On one agent connection the wire reads: bind(A, fwd=1) [hop(A)] bind(B) [hop(B)] … SIGN_REQUEST.
- quoin takes a hop record only when its host key matches the preceding bind's.
- A stock agent answers failure to the unknown extension and the relay carries on.
- S7's signed envelope can ride in the hop record's sig field. A session-bind proves only that the key signed some session id.

## Recommendation

Adopt (a′): capture OpenSSH's own session-bind and replay it. Under it, quoin-signer needs no change for remote sudo, and ~/.ssh/config keeps working because the system ssh does the bootstrap (D6). The hardening in this revision is required, not optional:
1. Bootstrap with `ssh -o ForwardAgent=<random 0700 capture socket> -o ControlMaster=no -o ControlPath=none`.
2. Run the capture as a strict state machine:
   - accept one connection only, and only from our ssh child's pid and uid (SO_PEERCRED);
   - the frames must be exactly session-bind with fwd=1, then REQUEST_IDENTITIES (answered with an empty list), then EOF;
   - read the result after ssh exits.
3. Pin the bind's host key to known_hosts, as `ssh -G` resolves the destination.
4. If there is no trustworthy bind, run the session with agent forwarding off, say why, and refuse any agent channel the server opens anyway.
5. Replay the bind with fwd=1 at the head of each mosey agent channel.
6. Change quoin-sudo so it treats a detached mosey session as remote (quoin 0331bf1 does this). Without that change, remote sudo inside mosey asks the far host's galley.
7. Keep option (c), the hop record, display-only and labelled "not verified" on a quoin branch until S7 provides a signature that cannot double as a session-bind.

The alternatives lose:
- (a) x/crypto loses most of ~/.ssh/config. Its speed advantage is a Nagle/delayed-ACK artifact of how the system ssh writes before login.
- (b) is refused by quoin and by destination-constrained stock agents.

## Open questions for Dan

1. **How should quoin-sudo recognise that a sudo is running inside a detached mosey session, so that it uses remote mode (forwarded-agent approval) rather than local mode (the far host's galley)?**
   - Match a link whose comm is `mosey-server`, running as the user (quoin 0331bf1, as prototyped). This ties quoin to the file name D7 installs under ~/.cache/mosey/<version>/
   - Same, plus require that the link is a session leader whose parent is the user's systemd or init
   - The mosey server registers its pid somewhere root-readable (for example via the quoin-sudo gate), and quoin checks that instead of the name
   - Leave quoin trunk unchanged, and remote sudo inside mosey asks the far host's galley
   - *Recommended:* Match the comm `mosey-server` (0331bf1), and fix the installed binary name as part of D7. Remote mode's approval is a signature from the forwarded agent over a quoin-sudo-v1 message for this host. Any process of the user's that can reach that socket can already ask for the signature directly, so a forged name grants nothing new. Session-leader checks add little, because any process can call setsid. Measured: quoin's real chain.zig returns remote()=true on the live mosey session chain with 0331bf1, and false with the trunk rule.

2. **What should the client do when the user has a live ControlMaster for the host?**
   - Always open a fresh bootstrap connection with -o ControlMaster=no -o ControlPath=none (this revision)
   - Detect a master with `ssh -O check` (or the controlpath from `ssh -G`), then fall back to no agent forwarding with a clear message
   - Offer both, and let a flag choose
   - *Recommended:* Always open a fresh bootstrap connection. A multiplexed session has no new key exchange, so there is no bind. Worse, the trigger can reach the user's real agent through the master (E12b, measured). A fresh connection costs about 108 ms on loopback (mux 9.8 ms vs fresh 117.8 ms), once per mosey start or resume.

3. **Should the hop record (who asked on the far host, shown in galley) ship before S7 can sign it, and under what name?**
   - Keep it on a quoin branch, display-only and labelled 'not verified', until S7 delivers a signed envelope (recommended)
   - Ship the unverified display to quoin trunk now
   - Drop it, and rely on S7 alone
   - *Recommended:* Keep it on a branch until S7, then pick a final name (for example hop@mosey or provenance-v1@…) and consider writing it up as an OpenSSH-style draft. Everything in the record except the host name is supplied by the far host. Even with the new 'reported, not verified' block, unsigned text in an approval prompt can help a compromised host phish an approval. S7 can carry its envelope in the record's sig field, but must not sign raw with the host key, because that signature would also be a valid session-bind.

4. **Can a spike get a VM or container where it may install quoin-sudo's plugin and run a real sudo against a throwaway quoin-signer, for the one end-to-end remote-sudo run not done here?**
   - Yes, a NixOS VM test (quoin already has VM checks)
   - No. Accept the evidence so far: real OpenSSH, real chain.zig, and the real agentsrv on recorded frames
   - *Recommended:* Yes: add a NixOS VM check during implementation, not in another spike. Every piece has been exercised except the plugin inside sudo, its root gate, and the daemon-to-galley path. Those need root.

## Not done

- docs/spikes/s3-agent-bind/FINDINGS.md was not written. The subagent harness refused the report file again. Its content is in this result, and the orchestrator must write it.
- No end-to-end run of the real quoin-sudo plugin inside sudo, its root gate, or a running quoin-signer daemon with galley. This needs root or a VM. The evidence is: real OpenSSH 10.6p1, quoin's real chain.zig on the live chain, and quoin's real agentsrv code replaying recorded frames with the test harness's synthetic laptop-side requester.
- Not measured on a WAN: neither the bootstrap latency nor the size of the Nagle/delayed-ACK stall there.
- Not exercised for (a′): host or user certificates (@cert-authority; which key ssh puts in the bind, and whether the known_hosts pin handles it), FIDO/sk keys, GSSAPI, password or keyboard-interactive prompts, Match exec, UpdateHostKeys.
- Not investigated: why the hostile server's read saw EOF after it injected a bind, and why the legacy handler then waited about 10 s.
- PeerChain needs SO_PEERPIDFD (Linux 6.5+). Without it no chain is sent. Not tested on an older kernel or on macOS.
- Timing run 2 was taken while other spikes were loading the machine. Both runs are kept and the quiet one is quoted.

## Changes to other repos

- quoin:mosey/s3-agent-bind-hop@/home/dan/Projects/quoin-mosey-s3 (8bb8de0 replay tests; 718c110 hop record; 0331bf1 chain.zig mosey-server remote + peer leaf; e004544 hop record shown as an unverified report after the signer's lines and kept out of the chain table and summary, fixture regenerated from committed spike results)
