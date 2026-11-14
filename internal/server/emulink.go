package server

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/danielbodart/mosey/internal/ipc"
	"github.com/danielbodart/mosey/internal/screen"
)

// T4 bounds one emu request: S2 measured about 3 ms per REP, so 16 KiB of
// REP storm costs seconds; 30 s is far past any honest request and still
// ends a hang (server.md §8).
const T4 = 30 * time.Second

// violation is emu breaking server.md §3.5: proto kills it and starts
// afresh, never skips the message.
type violation struct{ reason string }

func (v *violation) Error() string { return "emu violated the protocol: " + v.reason }

func violated(format string, args ...any) error {
	return &violation{fmt.Sprintf(format, args...)}
}

// errDeadline is a request that did not complete within T4.
var errDeadline = errors.New("emu did not answer in time")

// answer is emu's whole response to one request.
type answer struct {
	replies []byte
	diff    []byte
	held    bool
}

// emuLink is proto's end of one emu generation's socketpair, driven
// strictly request by response (server.md §3.5): proto asks, emu answers
// with at most one Replies and then a run of Update fragments, and anything
// else is a violation.
type emuLink struct {
	conn     *ipc.Conn
	gen      uint32
	deadline time.Duration
}

func newEmuLink(f *os.File, gen uint32, deadline time.Duration) (*emuLink, error) {
	conn, err := ipc.NewConn(f, ipc.Proto, ipc.Emu)
	if err != nil {
		return nil, err
	}
	return &emuLink{conn: conn, gen: gen, deadline: deadline}, nil
}

// request sends req and collects its answer. The error is a *violation,
// errDeadline, or the connection's own (EOF when emu died).
func (l *emuLink) request(req ipc.Message) (answer, error) {
	var a answer
	if l.conn.Pending() {
		return a, violated("a message while idle")
	}
	if err := l.conn.File().SetReadDeadline(time.Now().Add(l.deadline)); err != nil {
		return a, err
	}
	if err := l.conn.Send(req); err != nil {
		return a, err
	}
	var gotReplies, gotUpdate bool
	for {
		m, err := l.conn.Recv()
		switch {
		case errors.Is(err, os.ErrDeadlineExceeded):
			return a, errDeadline
		case errors.Is(err, ipc.ErrMalformed):
			return a, violated("%v", err)
		case err != nil:
			return a, err
		}
		switch m := m.(type) {
		case ipc.Replies:
			if gotReplies || gotUpdate {
				return a, violated("Replies after %s", map[bool]string{true: "an Update", false: "Replies"}[gotUpdate])
			}
			gotReplies = true
			a.replies = m.Data
		case ipc.Update:
			gotUpdate = true
			if len(a.diff)+len(m.Fragment) > screen.MaxDiff {
				return a, violated("a diff over %d bytes", screen.MaxDiff)
			}
			a.diff = append(a.diff, m.Fragment...)
			if !m.More {
				a.held = m.Held
				return a, nil
			}
		}
	}
}

func (l *emuLink) close() { l.conn.Close() }
