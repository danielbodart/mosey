# The ssh-agent provenance extension

`provenance-v00@bodar.com`. Draft 00, 2026-11-13. Written by mosey spike S7.
Prototyped in quoin, branch `mosey/s7-provenance-envelope`.

## Abstract

With agent forwarding, the agent on the user's machine is asked to sign
for a process on a remote host. The agent can see which forwarded session
the request came over (`session-bind@openssh.com`), but not which process
on that host asked or why. When the agent asks the user to approve the
request, the user sees "a signature, forwarded from host X". They cannot
tell whether `git push` in their terminal on X asked, or something an AI
agent on X started.

This extension lets a host's **attester** send a signed **provenance
statement** to the forwarded agent just before each signature request. The
statement names the process chain that made the request and is bound to
that one request by its hash. The attester's key is delegated by the host's
own SSH host key, so the agent can check that the statement comes from the
host the forwarded session is bound to. It then shows the user who asked,
as that host claims it.

The extension rides inside the agent protocol, so it passes through stock
OpenSSH `ssh -A` unchanged (tested with OpenSSH 10.6p1, including two
forwarding hops). Agents that do not know it refuse it as an unknown
extension, and the signature request goes ahead as before.

## 1. Conventions

The key words MUST, MUST NOT, SHOULD and MAY are as in RFC 2119. `byte`,
`uint32`, `uint64` and `string` are as in RFC 4251 §5. `SSHSIG` is OpenSSH's
`PROTOCOL.sshsig`. Agent messages and extensions are as in
draft-ietf-sshm-ssh-agent (formerly draft-miller-ssh-agent), §3.8 and §4.7.

## 2. Roles and trust

- **Agent**: holds the user's keys on the user's machine (for example
  quoin-signer). It verifies statements and shows them.
- **Host**: a machine the user's agent is forwarded to. Its SSH host key
  `K` is what `session-bind@openssh.com` binds the forwarded connection to.
- **Attester**: a process on the host that is *not* run as the user, such as
  a system daemon. It holds the attester key `A`, which `K` delegates to. It
  reads each client's process chain from the kernel and signs statements.
- **Forwarder**: whatever owns the socket that the host's `SSH_AUTH_SOCK`
  names. Under OpenSSH that is sshd plus a small per-session shim. Under
  mosey it is mosey's server. The forwarder holds no key.

**What a verified statement proves.** The holder of an attester key that
the host key `K` delegated to claims that this process chain made this one
request. The agent checks that `K` is the host the forwarded connection is
bound to. It proves nothing more:

- a host whose root, or whose attester, is compromised can claim anything.
  The agent MUST present a statement as **claimed by** the host and name the
  attester key, never as a fact.
- what the statement adds is protection against the user's *own* programs
  on that host, a hostile AI agent among them, forging the *statement*. They
  cannot read `A`, and they cannot reuse a statement for another request,
  because it is bound to the request's hash.
- it does **not** stop those programs *describing themselves* misleadingly.
  The attester reads the chain from the kernel, but only the tree (pid,
  ppid, start time, uid) is the kernel's own record. `comm`, `argv` and the
  cgroup inside the user's delegated subtree are set by the processes
  themselves (`exec -a`, argv rewriting, `PR_SET_NAME`, writing
  `cgroup.procs`), and a process can drop its ancestors by double-forking
  so that it is reparented. Only `exe` cannot be set by the process, and
  only a privileged attester (`CAP_SYS_PTRACE`) can read it for another
  user's process. A statement is therefore "process P, which says it is
  `git push`, run by this tree, asked for this request", claimed by `K`.
- it names the process that **opened** the connection (the kernel's peer),
  read again at each request. A process that is passed or inherits the
  connection's descriptor is not told apart from the one that opened it.
  The attester refuses once the opener is gone or has exec'd (§4).
- a program of the user's can still **bypass** the attester, under any
  forwarder the user can replace. See §11.

## 3. Delegation

The host's root signs a **delegation** from `K` to `A`, once, for a bounded
time. It can do this with stock tools:

    ssh-keygen -Y sign -n provenance-delegation-v00@bodar.com \
        -f /etc/ssh/ssh_host_ed25519_key delegation

The delegation's body is:

    string  "provenance-delegation-v00@bodar.com"
    string  host_key          K, as an SSH public key blob
    string  attester_key      A, as an SSH public key blob
    uint64  not_before        seconds since the epoch
    uint64  not_after         seconds since the epoch
    string  hostname          informational only

The delegation signature is an armoured SSHSIG over that body, made in
namespace `provenance-delegation-v00@bodar.com` by `K`. Hosts SHOULD keep
the validity short (days) and renew it from a timer, so that rotating or
revoking `A` needs no list of revoked keys.

## 4. Statement

    string  "provenance-v00@bodar.com"
    string  request_hash      SHA-256, see §5
    string  host_key          K; MUST equal the delegation's host_key
    string  session           opaque transport binding, or empty (§8)
    uint64  time              milliseconds since the epoch
    string  nonce             16 random bytes
    string  inner             SHA-256 of the wrapped statement's body, or empty (§7)
    string  hostname          informational
    string  user              the requesting process's user name
    uint32  n_links           at most 16
    link[n] chain             leaf (the requester) first, then each parent
    uint32  n_attrs; string[n] attrs     "name=value" or "name", at most 32

    link:
    uint32  pid
    uint32  ppid
    uint64  start             start time, clock ticks since boot (/proc/<pid>/stat field 22)
    uint32  uid
    string  comm
    string  exe               empty if the attester cannot read it
    uint32  n; string[n] argv at most 8192 bytes in all
    string  cwd               empty if the attester cannot read it
    string  cgroup            the cgroup v2 path
    uint32  n; string[n] attrs     e.g. "unit=foo.service", "truncated"

Every `string` field in a link or attribute is at most 4096 bytes. The
whole extension body (§6) is at most 64 KiB. Parsers MUST reject trailing
bytes, over-long fields and too many items. They MUST NOT try to repair a
malformed statement.

The attester MUST fill links only with what it read from the kernel itself,
for the process that is the kernel's peer of the client connection
(`SO_PEERPIDFD` on Linux). It MUST check each process's start time before
and after reading it, so that a reused pid is not reported. A field it
cannot read stays empty. A process's working directory and executable are
readable only by its owner or a privileged reader: an unprivileged system
attester leaves them empty rather than asking the client.

The attester MUST read the chain again for every request it attests, not
once per connection, and MUST compare the leaf with what it read when the
connection was handed to it: the same pid and start time, and the same
`exe` (where it can read it), `comm` and `argv`. It MUST NOT forward a sign
request it cannot attest: if the peer cannot be read (it has exited), if the
leaf has changed (it has exec'd), or if the statement cannot be sealed, the
attester answers the client `SSH_AGENT_FAILURE` and does not pass the
request on. Only an upstream agent's refusal of the extension itself lets a
request go on without a statement, because that is the upstream agent's
choice.

Defined statement attributes: `cut` (the chain did not reach pid 1),
`anchor=<pid>`, `terminal`, `session-root`, `project=<path>` (when a
project resolver vouches for it), `sudo-level=<normal|warning|danger>`.

## 5. Request hash

`request_hash` is SHA-256 over the agent request message exactly as it goes
on the wire after its `uint32` length: its type byte, then its contents. For
`SSH_AGENTC_SIGN_REQUEST` (13) that is:

    byte    13
    string  key blob
    string  data
    uint32  flags

An agent that re-encodes a parsed request MUST get the same bytes. If the
hash does not match, the statement does not apply, and the request is shown
as unattested. That is safe.

## 6. The extension message

    byte    SSH_AGENTC_EXTENSION (27)
    string  "provenance-v00@bodar.com"
    string  statement         §4
    string  statement_sig     armoured SSHSIG over statement, namespace
                              "provenance-v00@bodar.com", by A
    string  delegation        §3
    string  delegation_sig    armoured SSHSIG over delegation, namespace
                              "provenance-delegation-v00@bodar.com", by K

Replies:

- `SSH_AGENT_SUCCESS`: the agent verified the statement and holds it for its
  request.
- `SSH_AGENT_EXTENSION_FAILURE`: the agent knows the extension but refused
  this statement.
- `SSH_AGENT_FAILURE`: the agent does not know the extension.

The attester MUST send the extension on the **same agent connection**,
immediately before the request it describes, and MUST send that request
whatever the reply was.

## 7. Nesting

With `local → A → B`, B's attester sends its statement S_B and then the
request. These pass through A's ssh client, which is a client of A's
attester. A's attester MUST forward S_B unchanged. When the matching request
follows, A's attester sends its own statement S_A with
`inner = SHA-256(S_B body)`, then the request. The agent receives S_B, S_A
and the request in that order. Each statement names its host's process
chain: B's is the requester, and A's is the ssh client that carried B's
session (for example `tab ← ssh -A B`).

The agent pairs statements with the connection's forwarded session binds in
order. The outermost statement is the one no other statement wraps. Each
`inner` names the next statement in. The statements' host keys MUST be
distinct forwarded binds on the connection, in increasing bind order. A hop
whose host sent no statement is shown as unattested. If the statements do
not form one such chain, none is shown.

## 8. Binding to the session

A statement is bound to its host by `host_key`, which MUST equal the host
key of a forwarded `session-bind@openssh.com` the agent accepted on this
connection. A statement whose host is not a forwarded bind MUST be refused.
So is a statement on a connection with no forwarded bind.

`session` is for transports where the attester can see the session that
carries the agent channel. Under mosey that is the session identifier the
handshake derives. If the agent also knows that identifier (from a
mosey-specific bind, see mosey spike S3), it SHOULD require the two to be
equal. (The prototype fills `session` under mosey but no agent checks it
yet: this depends on S3 choosing a mosey bind that carries the id.) Under
OpenSSH the attester cannot see sshd's session id, so `session` is empty.
Replay is then limited by `request_hash`, `time` and the single-use rule in
§9.

## 9. Agent behaviour

1. Verify the delegation signature with `K`, check that the delegation is
   currently valid, verify the statement signature with `A`, check that the
   statement's `host_key` equals the delegation's, and check that `time` is
   within 5 minutes of the agent's clock.
2. Check `K` against the connection's forwarded binds (§8).
3. Hold at most 8 pending statements per connection, dropping the oldest.
4. When a request arrives, take the statements whose `request_hash` matches
   it and whose `time` is *still* within 5 minutes. Each statement is used
   **once per agent**: the agent keeps the (attester key, nonce) of every
   statement it took for 10 minutes and refuses one it has seen, on any
   connection.
5. Show each attested hop with the host's name from the known hosts file,
   the chain laid out as a local chain would be, and a line such as
   "claimed by its attester SHA256:… (delegated by host key SHA256:… until
   …)". Show the leaf's `exe` (and `cwd`) when present. When `exe` is empty,
   say that the names shown are the processes' own.
6. Statements SHOULD only add to what is shown. An agent MAY take them into
   its decision for hosts the user names as their own. It MUST NOT treat a
   statement from any other host as weaker evidence than no statement.
7. An agent MAY be told that a host always attests. A forwarded request from
   that host without a statement then means something on the host went
   round its attester. The agent SHOULD warn, and SHOULD NOT let a standing
   grant cover the request.

## 10. Companion interface: the hand-off socket (optional)

A forwarder that holds no key gives each client connection to the attester
over a unix socket (default `/run/agent-attest/handoff.sock`). It sends one
byte `'H'` with two file descriptors in `SCM_RIGHTS`: the client's
connection, and the attester's end of a stream socket pair whose other end
the forwarder copies to the upstream agent. From then on the attester reads
the client's requests and its kernel identity directly. The forwarder can
lie about neither, and it never parses a statement. The attester MUST
refuse a client whose uid is not the forwarder's, so a forwarder only ever
obtains statements about its own user's processes. The attester SHOULD
limit how many connections each uid holds open (the prototype: 64), and
SHOULD time out idle clients (the prototype: 5 minutes; upstream reads are
not timed, since a request waits on a person).

A forwarder MUST fail closed. If a hand-off socket exists and the hand-off
fails for any reason, the forwarder refuses the client. It forwards plainly
only when the host has no attester at all, and an administrator SHOULD be
able to forbid even that. The path is fixed or set by root-owned
configuration, never by the user's environment.

mosey's server is such a forwarder. Under OpenSSH, a per-session shim runs
in front of sshd's agent socket and sets `SSH_AUTH_SOCK` to its own socket.
Either is an *honest* forwarder only while it is unmodified: see §11.

## 11. Security considerations

- **Compromised host**: it can claim any chain, but only for requests sent
  over a session bound to its own host key. The UI says whose claim it is.
- **The user's own programs on the host**: they cannot forge or replay
  statements. They can describe themselves misleadingly (§2). And they can
  **bypass** the attester, so that their request arrives with no statement:
  - under OpenSSH, at once, by connecting to sshd's agent socket rather than
    the shim's;
  - under mosey, only by changing what the user's own files run: replacing
    the user-installed mosey-server, or starting their own forwarder. The
    hand-off path is not taken from the environment, and a failed hand-off
    refuses rather than falls back. This raises the bar from "any program at
    any time" to "a program that persists by modifying the user's files",
    but it is the same class: the forwarder is the user's, so it is not a
    trust anchor.

  The enforcement in both cases is the agent's: §9.7 makes a request with
  no statement from a host known to attest a warning that no grant covers
  (or a refusal, if the agent chooses). Nothing makes a bypass impossible
  unless the forwarder itself is root-owned and not replaceable by the user.
- **Denial of service on the host**: another local user can use up the
  attester's connections only up to the per-uid limit. A failed hand-off
  makes the forwarder refuse, so the worst outcome is that signing fails,
  never that it silently goes unattested.
- **Intermediate hops** can drop an inner host's statement, which shows that
  hop as unattested. They cannot alter it.
- **Replay** is bounded by the request hash. A userauth request contains the
  session id. An SSHSIG request contains the hash of the message. A replayed
  statement could only re-describe the same request, and the agent's
  (attester, nonce) set refuses it: each statement is shown at most once per
  agent, within the time window. An agent that restarts loses the set, so a
  statement can be shown once more for the same request within 5 minutes
  of its making.
- **Denial of service**: statements are at most 64 KiB. Each costs the agent
  two signature verifications. Agents cap pending statements per connection.
- **Downgrade**: stripping statements only removes information. The agent
  never signs on the strength of a statement it did not get.
- **Remote attestation of the attester itself** (a TPM quote that the
  attester binary is what it claims) is out of scope. A later version could
  carry one in the delegation.

## 12. Privacy considerations

A statement discloses the requesting process chain to the user's machine:
argv, working directory, cgroup and user name. Argv can contain secrets.
Every intermediate hop can read inner statements. Attesters SHOULD let an
administrator choose `full` or `names` (comm and exe only) per host. Agents
log statements, and SHOULD log a summary rather than full argv.

## 13. Naming

`bodar.com` is used under the extension naming rules of RFC 4251 §6.
If OpenSSH adopted the extension, it would become `provenance@openssh.com`,
with the delegation namespace renamed to match.
