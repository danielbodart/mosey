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
  colorprofile, term, termios and x/windows (ultraviolet's, compiled in
  only on Windows, which mosey never builds for); clipperhouse's
  displaywidth and uax29; rivo/uniseg; mattn/go-runewidth;
  lucasb-eyer/go-colorful; muesli/cancelreader; xo/terminfo;
  tuios.dev/progstatus; and golang.org/x/sync (ultraviolet's errgroup).
- **Named directly, at the versions tuios pins:**
  `github.com/charmbracelet/ultraviolet` and
  `github.com/charmbracelet/x/ansi`. tuios' API hands back their types
  (`uv.Cell`, `ansi.Mode`, `ansi.BasicColor`), so `internal/emu`, which
  translates tuios' cells into `screen.Grid`, has to name them. They add
  no code that tuios does not already bring, and only the emu role uses
  them: the client's path must not (D9), which `internal/client`'s and
  `internal/render`'s import tests check.
- **`go.mitchellh.com/libghostty`** is the oracle (D23): libghostty-vt
  read directly, with no tuios code in the path, compared with tuios on
  the committed recordings by `internal/emu/oracle_test.go`. It is Zig
  called through cgo, so that test is behind the `ghostty` build tag and
  runs locally only (its header says how); CI builds with
  `CGO_ENABLED=0` (D1), and neither binary compiles it in (`go list -deps
  ./cmd/...` does not list it). It is a direct requirement in `go.mod`
  only because that test imports it.

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
- **Mahimahi cellular traces** (GPL-3.0 data): fetched at test time by
  `netsim.MahimahiTrace`, from the Mahimahi repository at a pinned commit
  and checked against pinned SHA-256s, into the user's cache directory
  (`mosey-netsim/`), never into the repository; tests that need them skip
  when they cannot be had. `MOSEY_MAHIMAHI_FETCH=0` stops the fetch and
  `MOSEY_MAHIMAHI_DIR` points at a directory that already has them.
  Whether CI may fetch them is Dan's call (S5 §9, Q6); until he says no,
  it does.
