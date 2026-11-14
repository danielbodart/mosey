# Dependencies

mosey depends on the Go standard library and `golang.org/x/*`, and on
anything else only if it earns its place (D19). Every direct dependency is
here with the reason, and so is any gap in what we know about it. Never
write our own crypto primitives or terminal emulator.

Versions are pinned in `go.mod` and `go.sum`; a bump is a commit of its
own that says why.

## Direct

### `tuios.dev/vt` v0.3.2 (MIT)

The server's terminal emulator (D23), behind mosey's own `emu.Emulator`
interface so it can be replaced or forked.

- **Why it, from S2:** the only pure-Go candidate with no fuzz finding (two
  20-minute runs); it matches libghostty, read directly, on 36 of 36 core
  vttest screens; it has the richest API for D9 (cells with clusters,
  modes, title, OSC 52 and OSC 8 hooks, a non-blocking bounded reply
  queue, a full-state snapshot); and no crash, hang or unbounded growth
  from hostile input at 80x24 apart from OSC 8 link storage.
- **What we add around it, because it lacks it:** the window clamp
  (1000x500), a scrollback budget in cells rather than lines, a 512 MiB
  memory cgroup on the emu process (its link storage is unbounded), and the
  D9 allow-list on its titles and links (it passes C1 and DEL in titles).
- **Risk:** young (weeks old at S2) and mostly one author. If upstream
  stalls, fork it (D23). Upstream contributions are listed in
  `docs/spikes/s2-terminal/FINDINGS.md`.
- **Its own dependencies** (indirect in `go.mod`): charmbracelet's
  ultraviolet, ansi, colorprofile, term and termios; clipperhouse's
  displaywidth and uax29; rivo/uniseg; mattn/go-runewidth;
  lucasb-eyer/go-colorful; muesli/cancelreader; xo/terminfo;
  tuios.dev/progstatus. `go.mitchellh.com/libghostty` is in the module
  graph for tuios' optional libghostty backend, which needs cgo; with
  `CGO_ENABLED=0` it is not compiled into either binary (`go list -deps
  ./cmd/...` does not list it). libghostty is the CI oracle, read
  directly in tests, never shipped (D23).

### `golang.org/x/crypto` v0.59.0

ChaCha20-Poly1305, the packet AEAD (D20). The standard library has it only
internally. Audited by Trail of Bits in 2025 with the rest of Go's crypto.

### `golang.org/x/sys` v0.50.0

Landlock, seccomp, `PR_SET_DUMPABLE`, SCM_RIGHTS and the pty ioctls (D22).
Landlock is used through it directly, about 150 lines, with no go-landlock
dependency (S4).

### `golang.org/x/term` v0.48.0

Raw mode and window size for the client's own terminal, on Linux and macOS.

## In the standard library, with a known gap

### `crypto/hpke`: X-Wing (ML-KEM-768 + X25519)

The handshake's and rekey's KEM (D20), used as a plain KEM.

**Audit gap:** `crypto/hpke` was not covered by Trail of Bits' 2025 audit
of Go's cryptography (go.dev/blog/tob-crypto-audit). Its X-Wing combiner is
the Go team's code. The alternative, composing the combiner ourselves from
the audited `crypto/mlkem` and `crypto/ecdh` with `crypto/sha3`, would be
writing our own crypto (D19). So we use `crypto/hpke`, record the gap here,
and include it in the external security review before 1.0 (PLAN §6.5).
Revisit if Go's next audit leaves it out again.

Also: its private keys cannot be erased on demand. On linux release builds
`GOEXPERIMENT=runtimesecret` with `runtime/secret.Do` closes that (S1 §3.2,
0/20 residue against 20/20); elsewhere forward secrecy holds only once the
GC reuses the memory.

## Test-only, not in go.mod

- **OpenSSH `sshd`** for the end-to-end bootstrap test: a throwaway
  unprivileged instance on loopback, skipped when absent.
- **Mahimahi cellular traces** (GPL-3.0 data): fetched by pinned hash for
  the lte-driving netsim profiles and git-ignored, never committed; tests
  that need them skip when they are absent. Whether CI may fetch them is
  Dan's call (S5 §9, Q6).
