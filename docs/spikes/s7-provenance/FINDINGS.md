# S7: provenance for remote approvals

**Question (from Dan).** When a command I run remotely needs a signature or
a sudo, the approval comes back to my own machine. Locally galley shows the
full chain of who asked. For a remote request it shows almost nothing. If we
control the remote end, can the remote quoin sign an envelope describing who
asked, send it over agent forwarding, and have the local quoin verify it and
galley show it? Ideally this would be an open standard that also works over
plain `ssh -A`.

**Answer: yes, and it works over stock `ssh -A` today.** The prototype:

- adds a new agent extension, `provenance-v00@bodar.com`;
- uses a remote **attester** key that the host's own SSH host key delegates
  to, with both signatures in stock SSHSIG format;
- runs end to end over OpenSSH 10.6p1 with one and with two forwarding
  hops, with the real quoin-signer agent code verifying and laying out the
  galley question.

mosey's own part is small and needs nothing from quoin: hand each agent
connection to the host's attester if one is there, and refuse the
connection if the hand-off fails. The draft spec is
[agent-provenance-extension.md](agent-provenance-extension.md).

**What it proves, after review (§11).** A statement proves that host `K`'s
attester says "this process tree asked for this one request". The user's
programs on the remote cannot forge the *statement*, which a ProVerif model
confirms. They *can* describe themselves misleadingly (argv, comm, cgroup),
and they can bypass the attester entirely if they can modify what the
user's own files run. Under OpenSSH they can bypass it trivially. So
`attestedHosts` on the local side is the real enforcement, under mosey as
well as under OpenSSH. The first draft overclaimed on both points.

## 1. What the local user sees today

I read quoin's `peer/`, `internal/agentsrv`, `internal/galleyask`,
`internal/sudogate`, `internal/sudomsg`, `docs/` and galley's `wire/` and
`services/`.

- **Local sign**: `peer.FromConn` reads the requester's chain from the kernel
  (`SO_PEERPIDFD`, then `/proc/<pid>/{stat,status,cmdline,cgroup}`, with the
  start time checked again after reading). It finds the anchor (the claude,
  or the tab), and galley gets a `PID | Process | Command` table:
  `claude ← git push ← ssh …`, Bash-tool commands laid out as scripts, and
  `ssh-keygen -Y sign` shown through to `git commit`.
- **Forwarded sign (`ssh -A`)**: the chain is the *local* `ssh` process,
  plus the words "forwarded" and the destination. Nothing about who on the
  remote asked. Captured from the end-to-end run in
  [e2e-questions/0-today-no-attester.json](e2e-questions/0-today-no-attester.json):
  "SSHSIG signature / key … / forwarded / SSHSIG namespace git", and a chain
  of `agentsrv.test ← ssh -p … 127.0.0.1 …`.
- **Remote sudo**: the remote gate builds `quoin-sudo-v1` with the resolved
  argv, user, runas, cwd, level and reasons. The forwarded agent signs that
  message and the gate verifies the signature over its own bytes, so what
  you approve is what runs. But galley again shows only the local ssh chain.
  The gate *has* the remote chain (`a.r`, it logs it) and does not send it.
  Also, the message's descriptive fields are unauthenticated as far as the
  local side can tell: any process on the remote that holds the forwarded
  socket could send a lookalike. It would gain nothing, because the gate
  checks the signature against its own nonce, but it could phish.

galley needs **no change**. `wire.Table` takes up to 8 columns and 64 rows,
so a `Host | PID | Process | Command` table fits.

## 2. Design

### What the signature proves, and who can forge what

| Who | Can they forge a statement? | Can they get around it? |
|---|---|---|
| Network | No: it is inside ssh or mosey's channel, and signed | No |
| User's own programs on the remote (a hostile claude) | Not the statement: the attester key belongs to another user. But they set their own argv, comm and cgroup, and can cut their ancestry by reparenting. Only pid/ppid/start/uid and exe are kernel-true, and exe needs a privileged attester | Yes, under both. Under OpenSSH at once (connect to sshd's socket). Under mosey only by modifying the user's files (replace the user-installed mosey-server, or run their own forwarder). The request then arrives **unattested**, and `attestedHosts` turns that into a warning with no grant |
| Intermediate hop's root (local→A→B) | Not B's: it can only drop it, and B then shows as unattested | — |
| Remote root, or the attester itself | **Yes, anything**, but only for requests over sessions bound to its own host key | — |
| A local same-uid program | Can't sign. A replayed statement is refused: the agent keeps every (attester, nonce) it took for 10 minutes | — |
| Another local user on the remote | Gets statements only about its own processes, under its own name (the attester checks the client's uid against the forwarder's) | Can exhaust only its own per-uid quota (64) at the attester. A failed hand-off then makes the forwarder refuse, so the worst case is failed signing, not unattested signing |

So the UI says "on desktop: **claimed by** its attester SHA256:… (delegated
by host key SHA256:… until …)". It never presents the chain as fact.

### Pieces

1. **Delegation**: `K` (the host key) signs "attester key `A` speaks for me
   from T1 to T2" as SSHSIG in its own namespace. Root makes it with stock
   `ssh-keygen -Y sign -f /etc/ssh/ssh_host_ed25519_key`, which a test
   checks. The attester never touches the host private key.
2. **Statement**: the request hash (SHA-256 of the exact agent request
   message), `K`, an optional transport session id, the time, a nonce, an
   `inner` digest for nesting, the hostname, the user, and up to 16 links
   (pid, ppid, start, uid, comm, exe, argv, cwd, cgroup, attributes such as
   `unit=`). It is RFC 4251 wire-encoded, strictly parsed, and limited in
   size. It is signed by `A` as SSHSIG, so `ssh-keygen -Y check-novalidate`
   verifies it (tested).
3. **Extension**: `SSH_AGENTC_EXTENSION "provenance-v00@bodar.com"`, sent on
   the same connection just before the request. A stock agent answers
   FAILURE and the sign goes ahead unchanged (tested against
   `x/crypto/ssh/agent`'s keyring).
4. **Binding**: the local agent accepts a statement only if its `K` is the
   host key of a *forwarded* `session-bind@openssh.com` on this connection.
   It uses each statement once, for the request whose hash it names. Nested
   statements must chain by `inner`, in the binds' order.
5. **Attester placement**: a system daemon on the remote (another user,
   ideally with its key in the TPM). It receives each client connection by
   **fd hand-off** (`SCM_RIGHTS`) from a forwarder that holds no key, reads
   the client's identity and its requests *through that fd itself*, and
   proxies to the upstream fd. An honest forwarder can lie about neither,
   but a replaced one can skip the hand-off (§11). A test shows that a
   handed-off connection still names the original client process. The
   attester reads the chain again at each sign, and it refuses (fails
   closed) when it cannot read the connector or the connector has exec'd.

### Why not the alternatives

- **Put the chain in the data to be signed** (a `quoin-sudo-v2`): this works
  only where the remote party chooses the signed bytes, as the sudo gate
  does. userauth and SSHSIG data are fixed by their protocols. Possibly
  worth doing for sudo as well, but it is not the general mechanism.
- **Unsigned claims** from the remote session (mosey-server, or a shim run
  as the user): any program of the user's there can forge them, and that is
  exactly the threat. They would be a hint at best. See decision 5.
- **Sign with the host key directly**: the daemon would need the host
  private key, so compromising it would let an attacker impersonate the
  host. A delegation gives the same check for less exposure, and it expires.
- **Sign with a mosey-server key**: mosey-server runs as the user from
  `~/.cache/mosey/<version>/` (D7), so a hostile same-uid program can
  replace it. It must not be the anchor of trust.
- **TPM quote of the attester** (real remote attestation): a later step. It
  could go in the delegation.

### Over plain OpenSSH vs mosey

| | OpenSSH `ssh -A` | mosey agent channel |
|---|---|---|
| Statements reach the local agent | yes, unchanged; measured on 10.6p1, 1 and 2 hops | yes; channel bytes are opaque |
| How the attester is put in front | a per-session shim in front of sshd's socket (profile hook) | mosey-server hands every connection to `/run/agent-attest/handoff.sock` |
| Bypass by same-uid code | trivial (sshd's socket); detected via `attestedHosts` | needs persistent tampering with the user's files (D7 puts mosey-server in `~/.cache`); detected via `attestedHosts`. Same class, higher bar |
| Hand-off failure | — | refuses the client (fail closed); plain forwarding only when the host has no attester at all, and `Required` forbids even that |
| `session` binding | empty (sshd's session id isn't visible) | mosey session id is *filled* but **not checked** by anything yet. Future work, depends on S3 option (c) |
| mosey code needed | none | ~100 lines (`spikes/s7-provenance/forwarder`), x/sys only, no quoin import (D17) |

**USP, restated.** The USP is the visibility itself: a remote approval shows
the remote process tree, attributed to a named host key, with nesting, and
it works over stock `ssh -A` as well. That is not "no bypass". mosey makes a
bypass harder than OpenSSH does (no socket to go round, a fixed hand-off
path, fail-closed). But the forwarder is the user's own binary, so a
persistent same-uid attacker can still go round it. Nothing makes a bypass
impossible unless the forwarder is root-owned and the user cannot replace
it. That would be a NixOS-installed mosey-server, against D7's per-user
copy (see decision 8).

## 3. What was built

**quoin**, branch `mosey/s7-provenance-envelope`, worktree
`/home/dan/Projects/quoin-mosey-s7-provenance`:

- `provenance/` (new, public):
  - the statement, delegation and contents wire format, with strict parsers;
  - `RequestHash`/`SignRequest`;
  - `Delegate`, `Attester.Seal` and `Open` (verify);
  - `Proxy`, the attesting agent proxy, which wraps nested statements;
  - `FromKernel`, the chain read via `peer.FromConn`, plus exe and cwd where
    readable;
  - `Hand`, `Take` and `ServeHandoff`, the SCM_RIGHTS hand-off;
  - tests (round trip, strictness, forgery and tamper, expiry, skew, stock
    ssh-keygen interop, proxy order, stock-upstream fallback, nesting,
    hand-off identity), 2 fuzz targets and benchmarks.
- `internal/agentsrv/provenance.go`:
  - the extension handler, which verifies, binds to forwarded hosts, and
    holds at most 8 statements;
  - per-request matching and nesting order;
  - the question: a Host column, each host's chain laid out by the existing
    `galleyask.ChainRows`, a "claimed by" line per hop, and the summary
    `desktop: claude ← …`;
  - the journal's `provenance` attribute;
  - `Server.AttestedHosts`, a warning with no grant when a statement is
    missing.

  Questions without statements are unchanged: every existing test passes.
  The first commit had 6 new unit tests (the original text said 7, which
  was wrong), plus `e2e_ssh_test.go`. The review commit adds 3 more (replay
  across connections, stale at consume, the exe line).
- `internal/galleyask`: `ChainTable.Columns/Monospace`, so the table can
  take a Host column.
- `cmd/quoin-signer`: the `ssh.attestedHosts` config and JSON schema.
- `projpolicy`: an exported `Signature.Check`.
- `docs/signer.md`: a short section.

**mosey**, branch `spike/s7-provenance`:

- `spikes/s7-provenance/forwarder`: mosey-server's side. It hands each
  agent connection to the attester. If the host has an attester and the
  hand-off fails, it refuses the connection. It copies plainly only when
  there is no attester and `Required` is not set. Its non-test dependencies are `golang.org/x/sys/unix` only.
  Two tests use a real `ssh-keygen -Y sign` client, quoin's `ServeHandoff`
  attester (via `replace` to the quoin worktree) and a verifying keyring
  agent at the far end of a simulated agent channel. With an attester, the
  statement's leaf is ssh-keygen's pid and its parent is the test. Without
  one, it is plain forwarding. Four more tests, added after the review,
  cover the fail-closed cases (§11).
- `spikes/s7-provenance/model/provenance.pv`: a ProVerif model (§11).

## 4. Measurements (all measured; method stated)

- **End to end over stock OpenSSH 10.6p1**
  (`QUOIN_E2E_SSHD=1 go test ./internal/agentsrv -run TestEndToEndOverStockOpenSSH`;
  the test re-runs itself under `bwrap --dev-bind / / --tmpfs ~/.ssh` and
  skips if there is no bwrap; see §11):
  - Setup: two throwaway sshds run as me on loopback, each with its own host
    key and an attester delegated by it, and quoin's real `agentsrv.Server`
    with real `peer.FromConn` as the forwarded agent. galley's answer is
    stubbed to "Allow", and the question is captured.
  - It ran inside `bwrap --tmpfs ~/.ssh` (see §6).
  - 4/4 runs passed (first round). After the review, 4/4 more passed, with
    every attested connection going through `provenance.ServeHandoff` via
    `Hand`, the path mosey would use. `ls -la --full-time ~/.ssh/agent`
    was identical before and after.
  - **What it does not cover:** the attester as another uid. That needs
    root to set up, so the attester runs as the user inside the session.
    It covers the wire, the hand-off, the binding and the display, not uid
    separation.
  - The captured questions are in `e2e-questions/`. One hop shows `here`
    plus `[127.0.0.1]:port` rows down to `ssh-keygen -Y sign -n git …`. Two
    hops show `here`, then alpha (`ssh -p … bravo`), then bravo
    (`ssh-keygen …`), in bind order.
  - Statement size. The first-round figures (7,176 bytes for a 13-link
    chain, 7,669 bytes when wrapping) came from a log I did not keep, so
    they cannot be checked. The test now logs every statement's size. In
    the post-review runs the chain hit the 16-link cap, because the test
    ran under bwrap, go test and claude: **8,357–8,731 bytes** for one hop,
    and **8,855–9,232 bytes** for alpha wrapping bravo (3 runs plus 1).
    Links past bwrap show no exe: from inside bwrap's user namespace,
    `/proc/<pid>/exe` of outside processes is unreadable. That is a live
    example of the "exe not read" case. The galley question for two hops
    was about 3.2 KB of JSON.
  - Wall time per run: one sample each, so noise-dominated, not a
    benchmark. 154–246 ms without an attester, 274–300 ms with one hop, and
    615 ms for two hops (which includes a second ssh connection).
- **Microbenchmarks** (`go test -bench`, i9-12900K): 3 runs each. First
  round, on an otherwise idle machine:

  | Benchmark | Time per op |
  |---|---|
  | Seal, 13-link chain | 0.13–0.23 ms |
  | Open (two ed25519 SSHSIG verifies plus parsing) | 0.26–0.33 ms |
  | `FromKernel`, 8-link chain, from /proc | 0.59–0.73 ms per connection |
  | A sign through the proxy, plain copy | 0.07–0.08 ms |
  | A sign through the proxy, attested (fixed chain, upstream opens it) | 0.43–0.69 ms |

  Post-review re-run (load average 12–13: other spikes were running, so
  this run is not comparable with the first; all its numbers came out
  lower anyway):

  | Benchmark | Time per op |
  |---|---|
  | Seal / Open | 0.042–0.045 / 0.12–0.13 ms |
  | `FromKernel`, 9-link chain | 0.35–0.39 ms |
  | Proxy sign, plain / attested with a fixed chain | 0.045–0.048 / 0.29–0.30 ms |
  | **Proxy sign, attested, chain read from the kernel at connect and again at this sign** (the new fail-closed path) | **0.78–0.81 ms** |

  So attesting adds about **1–1.5 ms per sign** in all, including reading
  the chain. That is negligible next to a human approval or any WAN round
  trip. An earlier run taken while fuzzing was going on was about 30%
  slower.
- **Fuzzing** (`-parallel 4`): 10 min each, no crashes.
  - `FuzzParseStatement`: 48.6 M execs. The property checked: anything that
    parses marshals back to the same bytes.
  - `FuzzOpen`: 19.1 M execs, with no panic on arbitrary contents.
  - Both started from a single seed each. 10 minutes is a smoke test, not
    the hours the plan wants for a release.

## 5. Coordination with S3 (session-bind)

S7 **depends on S3's choice**. The local agent accepts a statement only from
a host that a *forwarded* `session-bind` names, and the statement is checked
against the host key that signed the delegation.

- **S3 option (a)**: the client replays the real SSH bind. Fine. The
  statement's `K` is the real host key.
- **S3 option (b)**: a per-user mosey identity. The bind key isn't the host
  key, so statements never match. **S7 is incompatible with (b)** unless the
  delegation names the mosey identity instead.
- **S3 option (c)**: a mosey-specific bind. The same delegation mechanism
  could *be* that bind. The root-run attester, whose key the host key
  delegates to, signs the mosey session id. quoin then verifies "host key `K`
  → attester `A` → this mosey session". That gives a rootless mosey-server a
  host-vouched bind, keeps `~/.ssh/config` and ProxyJump (the SSH bootstrap
  stays the system ssh), and lets the statement's `session` field be checked
  against it. **I recommend S3 consider (c) built on this delegation.** It
  is one root-made artefact serving two uses.

## 6. Notes, black-box observations, honesty

- **OpenSSH 10.6p1, observed as a black box**:
  - agent forwarding uses an `agent-req` channel request (the server
    advertises `agent-forward` in EXT_INFO);
  - sshd puts forwarded agent sockets in **`~/.ssh/agent/`**, not in `/tmp`;
  - `IdentityAgent=none` silently disables `ForwardAgent=<path>`;
  - the client sends `session-bind@openssh.com` with is-forwarding set on
    forwarded connections. quoin saw it, otherwise no hop would be shown.
- **`~/.ssh` was touched, briefly.** Because of the `~/.ssh/agent`
  behaviour, my first two probes (before I knew about it) made the
  throwaway sshd create and remove two transient sockets in
  `/home/dan/.ssh/agent/`. The directory already existed and held an older
  socket of yours (Nov 6), which is untouched. Nothing of mine was left
  behind (checked). Every later run used `bwrap --dev-bind / / --tmpfs
  /home/dan/.ssh`. The e2e test needs that wrapper, or a disposable home,
  to be safe to run.
- No live quoin, galley, TPM or systemd unit was used. Keys were software
  keys made in temporary directories.
- Nothing from Mosh was used. This spike touches no Mosh-derived
  behaviour.

## 7. Not done

- **The remote sudo gate's statement.** The local side handles it (a test
  shows a remote sudo with the remote chain `claude ← sudo systemctl …`).
  But the gate would have to hand the Zig plugin the statement along with
  the `M` message, and the plugin would have to send the extension before
  the sign. That needs changes to `sudo/wire.zig` and `agent.zig`, which I
  did not make.
- **No production attester daemon or NixOS module.** That means the TPM
  key, the boot-time delegation oneshot and renewal timer, the
  `/run/agent-attest/handoff.sock` unit, and the OpenSSH-session shim with
  its profile hook. Only library functions and tests exist.
- **The galley "Allow" path with a real galley window was not exercised.**
  The question was captured at the `galleyask.Question` level. The table
  meets galley's validator limits by construction (4 columns, at most 64
  rows), but it was not validated by galley's JS.
- **The formal model is small.** `spikes/s7-provenance/model/provenance.pv`
  (ProVerif 2.05, 0.3 s) covers authenticity and nesting only. It does not
  model time, the nonce set, the hand-off, or the truth of a chain (§11).
- **The fuzz targets ran 10 min each, not hours.** They were not re-run
  after the review, because the parsers did not change.
- **No race detector run**: `-race` needs cgo, and there is no C toolchain
  in this environment. The new tests ran with `-count=10` (provenance) and
  `-count=3` (forwarder), all passing.
- **A privileged attester was not tried.** One with `CAP_SYS_PTRACE` could
  read every link's exe. Exe was compared and shown only where it was
  readable by the same uid.
- **Galley JS** wasn't touched, and no galley branch was needed.

## 8. Recommendation

1. Adopt the extension as drafted, with the delegated attester (pieces 1–5),
   as quoin's mechanism and a mosey USP *of visibility*. It is open (SSH
   wire, SSHSIG, stock `ssh-keygen` can make and check its signatures), and
   it works over plain `ssh -A`. Do not market it as "no bypass". Make
   `attestedHosts` the enforcement on both transports, and consider making
   it default to refuse for hosts that run mosey with a system attester
   (decision 4).
2. v1 is **display only**: a statement never makes a sign silent. Add
   `attestedHosts` as a warning and a grant-breaker.
3. mosey implements only the hand-off forwarder (no quoin import), and it
   fails closed. Reserve `/run/agent-attest/handoff.sock` as a fixed path,
   or one set only by root-owned config. **No env override**: one would let
   same-uid code redirect future sessions.
4. Move quoin's prototype into a small `quoin-attest` system daemon (TPM
   key, delegation timer) and have the sudo gate use it for remote sudo.
5. Feed §5 into S3: prefer bind option (c), built on the same delegation.

## 9. Decisions for Dan

1. **Extension name.** `provenance-v00@bodar.com` (the prototype),
   `…@quoin` (as `policy-sign@quoin`), or propose it upstream as
   `…@openssh.com`. Recommend `@bodar.com` now, because it is a domain you
   control, which is what RFC 4251 §6 asks for, and upstream later.
2. **Where the remote attester lives.** A new `quoin-attest` daemon, inside
   the remote quoin-signer, or inside the sudo gate. Recommend a new small
   daemon that the gate also uses.
3. **Display only, or should statements decide?** For example, a grant keyed
   on the remote anchor, or a remote tab treated as `terminal`, for
   `forwardedThrough` hosts. Recommend display only in v1.
4. **A missing statement from an attested host.** Warn and allow no grant
   (the prototype), or refuse. Recommend warn first, with a per-host refuse
   option later.
5. **Unsigned claims from hosts with no attester** (for example a rootless
   mosey-server alone). Recommend not showing them; the habituation risk
   outweighs what they add.
6. **Privacy.** Full argv/cwd to your own machine, or a `names` level per
   host. Recommend full by default, with `names` available.
7. **Putting the attester in front under OpenSSH.** Recommend a NixOS-module
   profile hook that starts a per-session shim when `SSH_AUTH_SOCK` is
   sshd's.
8. **Is "no bypass" worth a root-installed forwarder?** Options: (a) accept
   the same class as OpenSSH and rely on `attestedHosts` (the prototype);
   (b) a NixOS-installed, root-owned `mosey-server` on hosts with an
   attester, which D7's auto-copy would then defer to; (c) the attester
   itself owns the session's agent socket, and mosey-server hands it only
   the channel. (c) still leaves mosey-server holding the channel, so it
   is no stronger than (b). Recommend (a) now, with (b) as an option for
   managed hosts.
9. **Attester privilege.** An unprivileged system attester cannot read exe
   or cwd of the user's processes, so every name it reports is
   self-described. Options: unprivileged (the prototype), `CAP_SYS_PTRACE`
   only, or root. Recommend `CAP_SYS_PTRACE` in a hardened unit. exe is the
   one field a process cannot set, and exec detection works best with it.
10. **When the attester cannot read the connector**: refuse the sign (the
    prototype now does this), or send an attester-signed "unattributable"
    statement and let the local agent decide. Recommend refuse. The
    legitimate cases (the opener exiting while a child still signs on its
    fd) are rare, and the error is clear in the attester's log.

## 10. Challenges to locked decisions

None. Two observations only (the review sharpened the first):

- **D7** (the server is copied into `~/.cache/mosey`, writable by the user)
  means mosey-server can never be the trust anchor for provenance. The
  design accounts for this with a separate system attester. It also means
  mosey cannot promise that the attester is never bypassed, only make
  bypass harder and detectable. This is not a challenge to D7, but if Dan
  wants "no bypass" as a property, decision 8(b) needs a carve-out from
  D7 for managed hosts.
- **D16 and D17** are kept: questions still flow through the forwarded agent
  exactly as with `ssh -A`, and mosey's only addition is an optional fd
  hand-off to a well-known socket.

## 11. Review response

Two adversarial reviewers raised 14 issues. Each one below says what
changed and what was measured. quoin commit `667c5b3` is on
`mosey/s7-provenance-envelope`. The mosey changes are in this branch's
second commit.

**Critical: an unreadable peer let a sign through unattested.** *Fixed.*
`Proxy.Serve` now fails closed. A sign whose connector cannot be read is
answered `SSH_AGENT_FAILURE` and never sent upstream, whether the read
fails at hand-off or at the sign. So is a sign whose statement cannot be
sealed. Test `TestASignOnAConnectionWhoseConnectorIsGoneIsRefused`: a child
connects, passes the fd over SCM_RIGHTS and exits, the test signs on the
passed fd, the sign fails, and upstream saw 0 signs. Only an upstream that
refuses the extension (a stock agent) still gets the sign, because that is
its own choice. The USP wording is corrected (§2, spec §11).

**Major: the forwarder failed open, and a local user could force that.**
*Fixed.* `forwarder.Forward` now refuses the client whenever a hand-off
socket exists and the hand-off fails: the dial fails, the write fails, or
the attester hangs up. It pumps plainly only when nothing is at the path,
and `Required` forbids even that. On the attester side, `ServeHandoff` caps
open connections per uid at 64 (forwarder and handed-off clients counted
together), hangs up on a hand-off cut short (MSG_CTRUNC when out of fds),
and the proxy times out idle clients after 5 minutes. Upstream is not
timed, because it waits on a person. Tests:
- `TestAnAttesterThatIsThereButDownRefusesTheClient` (stale socket file);
- `TestAnAttesterThatHangsUpRefusesTheClient`;
- `TestARequiredAttesterThatIsAbsentRefusesTheClient`;
- `TestOverTheAttestersLimitTheClientIsRefused` (64 idle connections held,
  then the session's sign fails rather than going through plainly);
- `TestTheHandoffSocketLimitsEachUID` and `TestAnIdleClientIsHungUpOn`.

The "statement oracle" point is rebutted. `ServeHandoff` already refuses a
handed client whose uid differs from the forwarder's
(`peer.Cred(client).Uid != fwd.Uid`). So another user only ever gets
statements about their own processes, under their own user name, which is
true. Getting such a statement accepted by Dan's agent would also need
Dan's forwarded socket and a matching request hash.

**Major (two reviewers): "no bypass under mosey" rests on a user-replaceable
binary.** *Conceded and corrected.* mosey raises the bar: no sshd socket to
go round, no env override (dropped from recommendation 3), fail-closed. But
the forwarder is the user's own (D7), so a persistent same-uid attacker can
replace it or run its own. The claim is now "same class as the OpenSSH
shim, higher bar", in FINDINGS §2 and spec §2 and §11, with `attestedHosts`
as the enforcement on both. Spec §10's "the forwarder can lie about
neither" now says it holds only for an honest, unmodified forwarder.
Decision 8 asks whether a root-owned forwarder is worth a D7 carve-out.
The `Session` binding is marked as filled but unchecked, pending S3 (c).

**Major (two reviewers): "cannot forge a chain, read from the kernel" is
unsound.** *Conceded and corrected; display improved.* Only pid, ppid,
start and uid are kernel-true. comm, argv and the cgroup in the user's
subtree are self-set, and ancestry can be cut by reparenting. Only exe is
not self-set, and only a privileged reader can read it across uids. Spec
§2 and §11, FINDINGS §2 and the quoin package doc now say so. The question
now shows the leaf's exe and cwd ("on H: 219367 runs
/nix/store/…/bin/ssh-keygen in /home/dan", captured in the e2e JSON). When
exe is empty it says "its attester could not read what P runs: names and
arguments are as the processes set them". The journal records every
link's exe (`exes`). Test `TestTheConnectorsExeIsShownOrItsAbsenceSaid`.
Whether to make the attester privileged is decision 9.

**Major: the chain was a snapshot taken at connect.** *Fixed in part, and
the rest stated.* The proxy now reads the chain again for every sign and
refuses when the leaf differs from the hand-off snapshot. The check
(`provenance.Same`) compares pid and start (gone), exe where both reads
saw it (exec), and comm and argv. Test
`TestASignAfterTheConnectorExecsIsRefused` uses a real child that connects,
passes its fd to the parent, then execs `sleep`. The parent's sign before
the exec is attested as the child's. The one after is refused, and
upstream saw exactly 1 sign. `TestSameNoticesAnExec` covers the comparison
table. What is **not** fixed, because SO_PEERPIDFD cannot see it: while
the opener is still alive and unchanged, any process holding its fd (by
inheritance, SCM_RIGHTS or pidfd_getfd) is attributed to the opener. The
first half of that same test shows this on purpose. An exec'd program that
puts comm and argv back, under an attester that cannot read exe, also gets
through. That is the self-description limit above. The spec now says the
statement names "the process that opened the connection, read again at
each request". Cost: an attested sign with the kernel read at each sign is
0.78–0.81 ms through the proxy (benchmark `attested-kernel`).

**Major: the e2e test wrote the real ~/.ssh/agent.** *Fixed.* The test now
checks `/proc/self/mountinfo` for a tmpfs at the passwd home's `.ssh`. If
there isn't one, it re-runs itself under `bwrap --dev-bind / / --tmpfs
~/.ssh`, and it skips if there is no bwrap. It never runs sshd against the
real directory. The header comment and docs/signer.md give the command.
Four post-fix runs left `~/.ssh/agent` byte-identical in its `ls
--full-time` listing (the only entry is Dan's pre-existing socket from
Nov 6).

**Minor (two reviewers): the nonce was never checked, and "once" meant per
connection.** *Fixed.* agentsrv keeps a per-server set of (SHA-256 of
attester key and nonce) for 2×MaxSkew, and refuses a statement it has
already taken, on any connection. Pending statements are checked against
MaxSkew again when their sign arrives. Tests
`TestAStatementIsTakenOnceAcrossConnections` (re-sent on the same and on a
second connection: refused both times, and the second sign shows no
provenance) and `TestAStatementPastItsTimeWhenItsSignComesIsNotShown`. One
residual case: an agent restart clears the set (spec §11).

**Minor: claims not modelled or tested adversarially.** *Addressed.* The
adversarial tests are listed above. A ProVerif model is at
`spikes/s7-provenance/model/provenance.pv`, with its output in
`proverif.out` (ProVerif 2.05, run with `nix shell nixpkgs#proverif`, about
0.3 s). The attacker holds the network, the client's choice of request,
chain and inner statement, a signing oracle under each honest host key in
another namespace, and every key of a third host E. Results:

| Query | Result |
|---|---|
| shown for A ⇒ A's attester sealed that request and chain | **true** |
| the same, injective (each showing is a distinct sealing) | **false**, as expected: replay. The nonce set added since is tested, not modelled |
| here→A→B shown ⇒ B sealed B's chain for that request, and A sealed its own naming exactly B's statement | **true** |
| here→E→B with E compromised ⇒ B's part is still B's | **true** |
| shown for E ⇒ E's attester sealed it | **false**, as expected: a compromised host claims anything |

The model proves that the claim is authentic, not that it is true.
Fuzzing remains a 10-minute smoke test.

**Minor: the e2e test did not cover uid separation or the hand-off.** The
hand-off part is *fixed*: every attested connection in the e2e now goes
`Hand` → `ServeHandoff` → `Proxy`. The uid separation part is *stated, not
fixed*, because a second uid needs root. The test now logs each
statement's size, and §4 gives the reproduced figures and says the old
ones cannot be checked.

**Minor: test count.** *Corrected* in §3: it was 6, not 7.

**Minor: the session binding is not implemented.** *Corrected* in §2's
table and the spec §8: the prototype fills it but nothing checks it.
