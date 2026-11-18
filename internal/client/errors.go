package client

import (
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/danielbodart/mosey/internal/bootstrap"
)

// Failure is an error the user reads: Msg is what cmd/mosey prints after
// "mosey: ", and Err is the cause, for errors.Is and the log. Its exit
// status is 1 (bootstrap.md §10).
type Failure struct {
	Msg string
	Err error
}

func (f *Failure) Error() string { return f.Msg }
func (f *Failure) Unwrap() error { return f.Err }

func fail(err error, format string, args ...any) error {
	return &Failure{Msg: fmt.Sprintf(format, args...), Err: err}
}

// TakenOverError is the session being taken over by another client (D26):
// the server revoked this one, or R3's reconnect found another credential
// holding it (bootstrap.md §9.2.2), and it exits rather than take it back,
// which is what cuts off a stolen client. By is the zero AddrPort when the
// reconnect told it, which does not say where from; Name is the session's.
type TakenOverError struct {
	By   netip.AddrPort
	At   time.Time
	Name string
}

// takenOverTime is RFC 3339 to the second with a numeric zone, in the
// client's own zone (bootstrap.md §9.1).
const takenOverTime = "2006-01-02T15:04:05-07:00"

func (e *TakenOverError) Error() string {
	at := e.At.Local().Format(takenOverTime)
	if !e.By.IsValid() {
		return fmt.Sprintf("session %s taken over by another client at %s", e.Name, at)
	}
	return fmt.Sprintf("session taken over from %s at %s", e.By, at)
}

// DetachedError is this client going away while the session runs on (D8,
// bootstrap.md §9.3): by a signal or the end of its terminal's input. The
// server keeps the session for a resume. It exits 0.
type DetachedError struct {
	// Name is the session's (an sname, safe to print).
	Name string
	// Destination is the host as the user named it, localhost for this
	// machine (bootstrap.md §2.2), for the hint; "" leaves it out.
	Destination string
}

func (e *DetachedError) Error() string {
	msg := "detached from session " + e.Name
	switch {
	case e.Destination == "":
	case bootstrap.SSH{Destination: e.Destination}.Local():
		// This machine is mosey's default, so the hint names no host.
		msg += "; resume it with: mosey -s " + e.Name
	default:
		msg += fmt.Sprintf("; resume it with: mosey -s %s %s", e.Name, e.Destination)
	}
	return msg
}

// ErrSessionGone is R3's reconnect finding no session to resume
// (bootstrap.md §9.2.2): GoneError says so to the user.
var ErrSessionGone = errors.New("the session has ended")

// GoneError is the session found gone by R3's reconnect: its shell exited,
// or the host restarted; the client cannot tell which. It exits 1.
type GoneError struct {
	Name, Destination string
}

func (e *GoneError) Error() string {
	return fmt.Sprintf("session %s on %s has ended: its shell exited, or the host restarted", e.Name, e.Destination)
}

func (e *GoneError) Unwrap() error { return ErrSessionGone }

// Exit statuses (bootstrap.md §10).
const (
	StatusOK        = 0
	StatusFailed    = 1
	StatusUsage     = 2
	StatusTakenOver = 3
)

// ExitStatus is the status mosey exits with after err.
func ExitStatus(err error) int {
	var usage *bootstrap.UsageError
	var taken *TakenOverError
	var detached *DetachedError
	switch {
	case err == nil, errors.As(err, &detached):
		return StatusOK
	case errors.As(err, &usage):
		return StatusUsage
	case errors.As(err, &taken):
		return StatusTakenOver
	}
	return StatusFailed
}
