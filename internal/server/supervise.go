package server

import (
	"strings"
	"time"
)

// FirstPort and LastPort are the session's UDP port range, from Mosh's
// man page, so a firewall opened for Mosh lets mosey through (server.md
// §2.2).
const (
	FirstPort = 60000
	LastPort  = 61000
)

// A session's lifetime once its client has gone (D8 R4, bootstrap.md
// §9.3).
const (
	// IdleTimeout is how long a session may stay detached before its
	// shell is hung up [D: Dan, 2026-11-15]. A constant (PLAN O14).
	IdleTimeout = 7 * 24 * time.Hour
	// HangupGrace is how long a hung-up shell has to exit before the
	// teardown closes the last pty master and then kills it [choice].
	HangupGrace = 10 * time.Second
)

// emu restarts (server.md §5.2, from S4 §3.8's supervisor): wait 50 ms
// before the first restart, doubling to at most 5 s, back to 50 ms once an
// emu has lived 60 s; at most 10 starts in any 60 s. When the budget is
// spent the session goes on: the spawner pauses for EmuCooldown, then
// starts again with a fresh budget, for as long as emu keeps failing.
const (
	restartFirst    = 50 * time.Millisecond
	restartMax      = 5 * time.Second
	restartHealthy  = 60 * time.Second
	restartWindow   = 60 * time.Second
	restartBudget   = 10
	EmuCooldown     = 60 * time.Second
	emuCooldownSecs = uint16(EmuCooldown / time.Second)
)

// restarts decides when the next emu starts. It is pure bookkeeping, so
// supervision's timing is tested without processes or a clock.
type restarts struct {
	starts  []time.Time
	backoff time.Duration
}

// started records a start at t, forgetting starts that can no longer count
// against the budget, so a long session's history stays a handful.
func (r *restarts) started(t time.Time) {
	kept := r.starts[:0]
	for _, s := range r.starts {
		if t.Sub(s) < restartWindow {
			kept = append(kept, s)
		}
	}
	r.starts = append(kept, t)
}

// plan is what to do when an emu that started at born dies at now: wait
// that long and start another, or, when that start would be the eleventh
// in a window, pause for EmuCooldown (and the caller tells proto) before
// starting with a fresh budget.
func (r *restarts) plan(now, born time.Time) (wait time.Duration, pause bool) {
	switch {
	case now.Sub(born) >= restartHealthy || r.backoff == 0:
		r.backoff = restartFirst
	default:
		r.backoff = min(2*r.backoff, restartMax)
	}
	at := now.Add(r.backoff)
	recent := 0
	for _, s := range r.starts {
		if at.Sub(s) < restartWindow {
			recent++
		}
	}
	if recent >= restartBudget {
		r.starts = nil
		r.backoff = 0
		return EmuCooldown, true
	}
	return r.backoff, false
}

// outOfMemory says whether a line of emu's stderr is Go's runtime dying
// because RLIMIT_DATA refused it memory. Only a classification for the
// client's notice: emu could forge it, and gains nothing, since every
// reason is handled alike.
func outOfMemory(line string) bool {
	return strings.HasPrefix(line, "fatal error: out of memory") ||
		strings.HasPrefix(line, "fatal error: runtime: out of memory")
}
