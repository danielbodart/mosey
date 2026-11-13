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
connection to the host's attester if one is there. The draft spec is
[agent-provenance-extension.md](agent-provenance-extension.md).

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
| User's own programs on the remote (a hostile claude) | No: the attester key belongs to another user, and the chain is read from the kernel | Under OpenSSH, yes: connect straight to sshd's agent socket, and the request arrives **unattested**. `attestedHosts` turns that into a warning with no grant. Under mosey, no: every connection to the session's socket is handed to the attester |
| Intermediate hop's root (local→A→B) | Not B's: it can only drop it, and B then shows as unattested | — |
| Remote root, or the attester itself | **Yes, anything**, but only for requests over sessions bound to its own host key | — |
| A local same-uid program | Can't sign. Replaying a captured statement only re-describes the same request, once, within 5 minutes | — |

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
   proxies to the upstream fd. The forwarder can lie about neither. A test
   shows that a handed-off connection still names the original client
   process.

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
| Bypass by same-uid code | possible (sshd's socket); detected via `attestedHosts` | none: there is no unattested path |
| `session` binding | empty (sshd's session id isn't visible) | mosey session id, checkable against S3's bind |
| mosey code needed | none | ~100 lines (`spikes/s7-provenance/forwarder`), x/sys only, no quoin import (D17) |

**USP**: under mosey the provenance is complete. No program on the remote
can sign without it being attributed. That is something plain OpenSSH
cannot guarantee, while the same wire format still works there.

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
  7 new unit tests, plus `e2e_ssh_test.go`.
- `internal/galleyask`: `ChainTable.Columns/Monospace`, so the table can
  take a Host column.
- `cmd/quoin-signer`: the `ssh.attestedHosts` config and JSON schema.
- `projpolicy`: an exported `Signature.Check`.
- `docs/signer.md`: a short section.

**mosey**, branch `spike/s7-provenance`:

- `spikes/s7-provenance/forwarder`: mosey-server's side. It hands each
  agent connection to the attester if one is present, and otherwise copies
  it plainly. Its non-test dependencies are `golang.org/x/sys/unix` only.
  Two tests use a real `ssh-keygen -Y sign` client, quoin's `ServeHandoff`
  attester (via `replace` to the quoin worktree) and a verifying keyring
  agent at the far end of a simulated agent channel. With an attester, the
  statement's leaf is ssh-keygen's pid and its parent is the test. Without
  one, it is plain forwarding.

## 4. Measurements (all measured; method stated)

- **End to end over stock OpenSSH 10.6p1**
  (`QUOIN_E2E_SSHD=1 go test -run TestEndToEndOverStockOpenSSH`):
  - Setup: two throwaway sshds run as me on loopback, each with its own host
    key and an attester delegated by it, and quoin's real `agentsrv.Server`
    with real `peer.FromConn` as the forwarded agent. galley's answer is
    stubbed to "Allow", and the question is captured.
  - It ran inside `bwrap --tmpfs ~/.ssh` (see §6).
  - 4/4 runs passed.
  - The captured questions are in `e2e-questions/`. One hop shows `here`
    plus `[127.0.0.1]:port` rows down to `ssh-keygen -Y sign -n git …`. Two
    hops show `here`, then alpha (`ssh -p … bravo`), then bravo
    (`ssh-keygen …`), in bind order.
  - Statement size for a real 13-link chain: **7,176 bytes** for one hop;
    alpha's 7,669 bytes when it wraps bravo's. The galley question for two
    hops was 3.2 KB of JSON.
  - Wall time per run: one sample each, so noise-dominated, not a
    benchmark. 154–246 ms without an attester, 274–300 ms with one hop, and
    615 ms for two hops (which includes a second ssh connection).
- **Microbenchmarks** (`go test -bench`, i9-12900K): 3 runs each, on an
  otherwise idle machine:

  | Benchmark | Time per op |
  |---|---|
  | Seal, 13-link chain | 0.13–0.23 ms |
  | Open (two ed25519 SSHSIG verifies plus parsing) | 0.26–0.33 ms |
  | `FromKernel`, 8-link chain, from /proc | 0.59–0.73 ms per connection |
  | A sign through the proxy, plain copy | 0.07–0.08 ms |
  | A sign through the proxy, attested (fixed chain, upstream opens it) | 0.43–0.69 ms |

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
- **No formal model** (ProVerif or Tamarin) of the delegation and statement
  binding.
- **The fuzz targets ran 10 min each, not hours.**
- **Galley JS** wasn't touched, and no galley branch was needed.

## 8. Recommendation

1. Adopt the extension as drafted, with the delegated attester (pieces 1–5),
   as quoin's mechanism and a mosey USP. It is open (SSH wire, SSHSIG,
   stock `ssh-keygen` can make and check its signatures), it works over
   plain `ssh -A`, and under mosey it has no bypass.
2. v1 is **display only**: a statement never makes a sign silent. Add
   `attestedHosts` as a warning and a grant-breaker.
3. mosey implements only the hand-off forwarder (no quoin import). Reserve
   `/run/agent-attest/handoff.sock` and allow an env override.
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

## 10. Challenges to locked decisions

None. Two observations only:

- **D7** (the server is copied into `~/.cache/mosey`, writable by the user)
  means mosey-server can never be the trust anchor for provenance. The
  design accounts for this with a separate system attester.
- **D16 and D17** are kept: questions still flow through the forwarded agent
  exactly as with `ssh -A`, and mosey's only addition is an optional fd
  hand-off to a well-known socket.
