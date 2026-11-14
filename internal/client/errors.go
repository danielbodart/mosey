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
// the server revoked this one, and it exits rather than reconnect, which
// is what cuts off a stolen client.
type TakenOverError struct {
	By netip.AddrPort
	At time.Time
}

// takenOverTime is RFC 3339 to the second with a numeric zone, in the
// client's own zone (bootstrap.md §9.1).
const takenOverTime = "2006-01-02T15:04:05-07:00"

func (e *TakenOverError) Error() string {
	return fmt.Sprintf("session taken over from %s at %s", e.By, e.At.Local().Format(takenOverTime))
}

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
	switch {
	case err == nil:
		return StatusOK
	case errors.As(err, &usage):
		return StatusUsage
	case errors.As(err, &taken):
		return StatusTakenOver
	}
	return StatusFailed
}
