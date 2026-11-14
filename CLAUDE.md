# mosey

A clean-room Go successor to Mosh. Read `PLAN.md` first: §2 (D1–D28) is
locked. Implement it; don't reopen it. If something in it turns out to be
impossible, stop and say so rather than work around it.
`docs/spec/architecture.md` is the map of packages, owners and interfaces.

## Clean room (PLAN §4)

mosey must contain nothing derived from Mosh (GPLv3).

- **Never read, copy, paraphrase or translate Mosh source code**: not on
  GitHub, not in `/nix/store`, not in Debian sources, not anywhere. That
  includes "just checking how they did it".
- Allowed: the Mosh paper (Winstein & Balakrishnan, USENIX ATC 2012),
  mosh.org docs and man pages, mailing-list design discussion, RFCs, other
  papers, and black-box behaviour of the `mosh` binaries.
- **Spec first.** SSP, prediction and framing are written from
  `docs/spec/`, in our own words, and every constant cites the paper
  section, an RFC, or our own measurement ([M], which includes black-box
  measurements of the `mosh` binaries), decision ([D]) or arithmetic from
  other cited values ([derived]).
- Don't write our own crypto primitives or terminal emulator (D19). The
  standard library and `golang.org/x/*` are preferred; anything else is
  justified in `DEPENDENCIES.md` in the commit that adds it.

## Layout

- Production code is `cmd/` and `internal/`. **Never import from
  `spikes/`**: the spikes are records (each its own module) whose ideas and
  tested logic are ported by rewriting them cleanly, not by copying.
  Their findings are in `docs/spikes/<id>/FINDINGS.md`.
- Linux-only mechanisms (Landlock, seccomp, pty ioctls, netlink) sit in
  `_linux.go` files behind a portable function, with a `_other.go` that
  returns `errors.ErrUnsupported`. Both binaries build for darwin too;
  nothing may rule macOS out (D22).
- `CGO_ENABLED=0` always: static binaries (D1).

## Running things

Use mise, which pins Go (1.27.3) and shellcheck:

```sh
mise run check        # gofmt, vet for linux+darwin x amd64+arm64, tests, shellcheck
mise run test         # go test ./...
mise run fuzz-smoke   # every fuzz target for FUZZTIME (default 10s)
mise run build        # static binaries for all four platforms into dist/
mise exec -- go test ./internal/ssp -run TestX -v
FUZZTIME=5m scripts/fuzz.sh ./internal/screen
```

## Tests

- Every package has tests. Test names say what is true:
  `TestForgedPacketDoesNotAdvanceTheWindow`, not `TestOpen2`.
- **Network behaviour runs on `internal/netsim` inside
  `testing/synctest`** (D18): virtual time, seeded loss. Nothing in CI
  asserts real elapsed time. Production code reads time only through the
  `time` package, so the bubble controls it; don't add a clock interface.
- **Every parser of attacker-reachable input has a `go test -fuzz`
  target** with an invariant (round trip, "a rejected input changes no
  state", agreement with a reference). Before it lands, run it locally for
  at least a few minutes and put the duration and exec count in the commit
  message.
- Hostile input is validated in full before any state changes, and every
  length or index from the wire is bounded before it becomes an `int`.
- SSH end-to-end tests use a throwaway unprivileged `sshd` on 127.0.0.1
  with throwaway host and user keys and a throwaway agent, as
  `spikes/s3-agent-bind/harness` does, all under `t.TempDir()`. Skip
  cleanly when `sshd` is absent.
- **Never touch** the user's live services, `~/.ssh`, keys, agent, TPM or
  systemd units, in tests or otherwise.

## Style

As in gokit and quoin: comments explain *why*, in plain English, and cite
the decision (D-number), spike, RFC or paper section a choice comes from.
Errors are wrapped with what was being done (`fmt.Errorf("reading the
credential line: %w", err)`). Small packages with a `doc.go` that says what
the package is for and why it is shaped as it is.

## Git

Trunk-based: commit to `trunk`, in small commits that each pass
`mise run check`. Every green commit on trunk is a release (D10). Don't
rewrite history that is already on trunk.
