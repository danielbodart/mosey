package server

import (
	"bytes"
	"errors"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/danielbodart/mosey/internal/emu"
	"github.com/danielbodart/mosey/internal/ipc"
	"github.com/danielbodart/mosey/internal/screen"
)

// sizeOp is the screen diff's SIZE opcode, which can only be a diff's first
// op (screen.md §5.4). emu's sizes are proto's to choose, so a SIZE in any
// answer but one to Resize is a violation (screen.md §7.3).
const sizeOp = 0x41

// ipcEmulator is proto's production emu.Emulator: a client of the emu
// process over IPC (server.md §3.6). server.Session cannot tell it from the
// in-process one, apart from the two things only a separate process needs:
// Flush, because emu never speaks unasked, and Changed, because a rebuilt
// emu brings a new screen without a Write.
//
// It keeps a mirror of emu's screen, the result of every Update applied with
// Grid.Apply, the same validating decoder the client uses, so one fuzzed
// decoder guards both the client against the server and proto against emu.
// What it hands out through Snapshot is the mirror with proto's own
// counters, which never go backwards across a rebuild (screen.md §7.2).
//
// It is safe for concurrent use: requests are serialised, one outstanding
// at a time, as the protocol requires.
type ipcEmulator struct {
	log *slog.Logger
	// kill asks the spawner to kill a generation (KillEmu).
	kill func(gen uint32, why ipc.KillReason)
	// repaint makes the shell's foreground program draw again after a
	// rebuild (server.md §5.2); whoever owns the resize path sets it.
	repaint  func()
	init     ipc.Init
	deadline time.Duration

	// reqMu serialises requests: one outstanding at a time.
	reqMu sync.Mutex

	mu     sync.Mutex
	up     *sync.Cond // signalled when link or closed changes
	link   *emuLink
	closed bool
	// killed is why proto asked for a generation to be killed, for the
	// Rebuilt reason when its successor arrives.
	killed  map[uint32]ipc.KillReason
	cols    int
	rows    int
	mirror  *screen.Grid
	held    bool
	allow   allowance
	replies []byte
	// Proto's own counters (screen.md §7.2).
	bell      uint64
	clipboard screen.Clipboard
	rebuilt   screen.Rebuilt
	// history is the session's history, numbered by proto: emu's lines,
	// renumbered, so a rebuild does not start the numbers again
	// (screen.md §7.2).
	history screen.History
	changed chan struct{}
	// dropped counts reply tokens over the allowance or off the list, and
	// replies over ReplyQueue.
	dropped int
}

func newIPCEmulator(cols, rows int, init ipc.Init, kill func(uint32, ipc.KillReason), log *slog.Logger) *ipcEmulator {
	e := &ipcEmulator{
		log:      log,
		kill:     kill,
		init:     init,
		deadline: T4,
		killed:   map[uint32]ipc.KillReason{},
		cols:     cols,
		rows:     rows,
		changed:  make(chan struct{}, 1),
	}
	e.up = sync.NewCond(&e.mu)
	return e
}

var (
	_ emu.Emulator = (*ipcEmulator)(nil)
	_ emu.Holder   = (*ipcEmulator)(nil)
)

// Changed is signalled whenever the mirror changes outside a request the
// Session made: a new emu's first screen.
func (e *ipcEmulator) Changed() <-chan struct{} { return e.changed }

func (e *ipcEmulator) signal() {
	select {
	case e.changed <- struct{}{}:
	default:
	}
}

// attach takes a new emu generation from an EmuLink: the old one is
// dropped, the mirror starts again from a blank grid at the current size,
// and the new emu's answer to Init is applied to it (screen.md §7.1, §7.3).
// For every generation after the first, the client is told through
// Rebuilt and the program is made to repaint (server.md §3.6). A new emu
// that fails its Init is killed like any other; attach returns an error
// only when the emulator is closed or the fd cannot be wrapped.
func (e *ipcEmulator) attach(m ipc.EmuLink) error {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		m.Conn.Close()
		return os.ErrClosed
	}
	if e.link != nil {
		// Closing it fails any request in flight on it, which releases
		// reqMu.
		e.link.close()
		e.link = nil
	}
	e.mu.Unlock()

	link, err := newEmuLink(m.Conn, m.Generation, e.deadline)
	if err != nil {
		m.Conn.Close()
		return err
	}
	e.reqMu.Lock()
	defer e.reqMu.Unlock()

	e.mu.Lock()
	cols, rows := e.cols, e.rows
	e.mu.Unlock()
	init := e.init
	init.Cols, init.Rows = uint16(cols), uint16(rows)
	a, err := link.request(init)
	if err == nil && a.replies != nil {
		err = violated("Replies to Init")
	}
	fresh := screen.NewGrid(cols, rows)
	if err == nil {
		err = check(fresh, a.diff, false, cols, rows)
	}
	if err != nil {
		e.failed(link, err)
		return nil
	}

	e.mu.Lock()
	if err := e.followHistory(screen.History{}, fresh.History); err != nil {
		e.mu.Unlock()
		e.failed(link, err)
		return nil
	}
	if m.Generation > 1 {
		e.rebuilt.Seq++
		e.rebuilt.Reason = e.reason(m)
	}
	delete(e.killed, m.Generation-1)
	e.mirror = fresh
	e.held = a.held
	e.link = link
	// The reply allowance counts the Output before this one, which the
	// old emu answered, or never did.
	e.allow = allowance{}
	e.up.Broadcast()
	e.mu.Unlock()
	e.signal()
	if m.Generation > 1 && e.repaint != nil {
		// Not under reqMu: the repaint is two Resize requests.
		go e.repaint()
	}
	return nil
}

// reason maps how the previous emu ended onto screen.md §7.3's codes
// (server.md §3.6).
func (e *ipcEmulator) reason(m ipc.EmuLink) screen.RebuiltReason {
	switch m.Reason {
	case ipc.EmuMemory:
		return screen.RebuiltMemory
	case ipc.EmuKilled:
		if e.killed[m.Generation-1] == ipc.KillDeadline {
			return screen.RebuiltOther
		}
	}
	return screen.RebuiltCrash
}

// pause records an EmuPaused: no emu until the next EmuLink. Writes wait,
// keystrokes do not (server.md §3.6).
func (e *ipcEmulator) pause(seconds uint16) {
	e.log.Warn("emu restarts paused", "seconds", seconds)
}

// failed ends a link that broke the protocol, timed out or died: proto
// stops reading it and, unless emu simply died, asks the spawner to kill it,
// carrying on "emu down" until the next EmuLink (server.md §5.3).
func (e *ipcEmulator) failed(link *emuLink, err error) {
	e.mu.Lock()
	current := e.link == link || e.link == nil
	if e.link == link {
		e.link = nil
	}
	closed := e.closed
	e.mu.Unlock()
	link.close()
	if closed || !current {
		return
	}
	var why ipc.KillReason
	var v *violation
	switch {
	case errors.As(err, &v):
		why = ipc.KillViolation
	case errors.Is(err, errDeadline):
		why = ipc.KillDeadline
	default:
		// emu died: the spawner sees it and sends the next EmuLink.
		e.log.Info("emu gone", "generation", link.gen, "err", err)
		return
	}
	// Logged by kind, never with the bytes (server.md §5.3).
	e.log.Warn("killing emu", "generation", link.gen, "why", why, "err", err)
	e.mu.Lock()
	e.killed[link.gen] = why
	e.mu.Unlock()
	e.kill(link.gen, why)
}

// do runs one request on the current emu, waiting for one while it is
// down. It returns false if the emulator was closed.
func (e *ipcEmulator) do(req ipc.Message, apply func(a answer) error) bool {
	for {
		e.mu.Lock()
		for e.link == nil && !e.closed {
			e.up.Wait()
		}
		link, closed := e.link, e.closed
		e.mu.Unlock()
		if closed {
			return false
		}
		e.reqMu.Lock()
		e.mu.Lock()
		stale := e.link != link
		e.mu.Unlock()
		if stale {
			e.reqMu.Unlock()
			continue
		}
		a, err := link.request(req)
		if err == nil {
			err = apply(a)
		}
		e.reqMu.Unlock()
		if err != nil {
			// What was in flight is dropped, not resent: the new emu's
			// screen and the repaint recover it (server.md §3.6, §5.2).
			e.failed(link, err)
		}
		return true
	}
}

// Write splits p into Output requests and runs each to completion. While
// emu is down it waits, which is the back-pressure that keeps a program's
// output to the speed it can be parsed (S2).
func (e *ipcEmulator) Write(p []byte) {
	for len(p) > 0 {
		chunk := p[:min(len(p), ipc.MaxOutput)]
		p = p[len(chunk):]
		ok := e.do(ipc.Output{Data: chunk}, func(a answer) error {
			// The allowance is counted on what was sent to the emu that
			// answered, so it is taken under reqMu, after the link is
			// settled.
			e.mu.Lock()
			allowed := e.allow.output(chunk)
			e.mu.Unlock()
			return e.take(a, allowed, nil)
		})
		if !ok {
			return
		}
	}
}

// Resize asks emu for the new size; the caller has clamped it. While emu is
// down it only records the size, which the next emu's Init carries, so a
// resize in the client's input never waits for emu and the keystrokes
// behind it reach the pty (server.md §3.6).
func (e *ipcEmulator) Resize(cols, rows int) {
	e.mu.Lock()
	e.cols, e.rows = cols, rows
	down := e.link == nil
	e.mu.Unlock()
	if down {
		return
	}
	to := &[2]int{cols, rows}
	e.do(ipc.Resize{Cols: uint16(cols), Rows: uint16(rows)}, func(a answer) error {
		if a.replies != nil {
			return violated("Replies to Resize")
		}
		return e.take(a, 0, to)
	})
}

// Flush asks emu for its screen with no new output, to release a screen
// held under synchronised output (screen.md §6.3). While emu is down there
// is nothing to release.
func (e *ipcEmulator) Flush() {
	e.mu.Lock()
	down := e.link == nil
	e.mu.Unlock()
	if down {
		return
	}
	e.do(ipc.Flush{}, func(a answer) error {
		if a.replies != nil {
			return violated("Replies to Flush")
		}
		return e.take(a, 0, nil)
	})
}

// take checks an answer whole and only then takes it: the diff onto the
// mirror, the counters onto proto's own, and the replies, up to the
// request's allowance, onto the queue. A refused answer changes nothing.
//
// resize is the size an answer to Resize must have, and nil for any other
// answer, which must keep the mirror's size. Not e.cols and e.rows: Resize
// sets those before its request can go (reqMu), so an Output answered at
// the old size while a Resize waited would otherwise read as emu breaking
// the protocol, and emu would be killed for it (the KILL soak found this).
func (e *ipcEmulator) take(a answer, allowed int, resize *[2]int) error {
	var tokens [][]byte
	if a.replies != nil {
		var err error
		if tokens, err = SplitReplies(a.replies); err != nil {
			return violated("replies: %v", err)
		}
	}
	e.mu.Lock()
	mirror := e.mirror
	e.mu.Unlock()
	cols, rows := mirror.Size()
	if resize != nil {
		cols, rows = resize[0], resize[1]
	}
	scratch := mirror.Clone()
	if err := check(scratch, a.diff, resize != nil, cols, rows); err != nil {
		return err
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	// The history first: the one take that can still refuse.
	if err := e.followHistory(mirror.History, scratch.History); err != nil {
		return err
	}
	// Counters rise only within a generation, compared with the mirror
	// before this answer (screen.md §7.2).
	e.bell += scratch.Bell - mirror.Bell
	if scratch.Clipboard.Seq > mirror.Clipboard.Seq {
		e.clipboard.Seq++
		e.clipboard.Data = bytes.Clone(scratch.Clipboard.Data)
	}
	e.mirror = scratch
	e.held = a.held
	for _, t := range tokens {
		if allowed == 0 || !ValidReply(t) {
			// Over the allowance, or not on the list: dropped on its own
			// and counted, never a violation, since an honest emu answering
			// a program that asked many questions, or something new, can
			// produce it (server.md §4.1, §4.2).
			e.dropped++
			continue
		}
		allowed--
		if len(e.replies)+len(t) > ReplyQueue {
			e.dropped++
			continue
		}
		e.replies = append(e.replies, t...)
	}
	return nil
}

// check applies diff to g, which the caller owns, and refuses it if emu
// overstepped (server.md §3.5, screen.md §7.3): a diff Apply refuses, a SIZE
// outside an answer to Resize, a grid at a size other than proto asked for,
// proto's own fields set, or counters going backwards.
func check(g *screen.Grid, diff []byte, resize bool, cols, rows int) error {
	if len(diff) > 0 && diff[0] == sizeOp && !resize {
		return violated("SIZE outside an answer to Resize")
	}
	bell, clip := g.Bell, g.Clipboard
	if err := g.Apply(diff); err != nil {
		return violated("diff refused: %v", err)
	}
	if c, r := g.Size(); c != cols || r != rows {
		return violated("screen %dx%d, not %dx%d", c, r, cols, rows)
	}
	if g.EchoOff || g.EchoAck != 0 || g.EchoApplied != 0 || g.Rebuilt != (screen.Rebuilt{}) || g.InputConsumed != 0 || g.Root {
		return violated("proto's own fields set")
	}
	if g.Bell < bell || g.Clipboard.Seq < clip.Seq ||
		(g.Clipboard.Seq == clip.Seq && !bytes.Equal(g.Clipboard.Data, clip.Data)) {
		return violated("counters went backwards")
	}
	return nil
}

// followHistory takes the lines emu's history gained from before to after
// into proto's own, renumbered (screen.md §7.2): proto's Next rises by as
// much as emu's, with a gap where emu's window lost lines. Apply already
// refused a history that went backwards; a rise that would wrap proto's
// numbering is a violation, and changes nothing. The caller holds mu.
func (e *ipcEmulator) followHistory(before, after screen.History) error {
	if after.Next <= before.Next {
		return nil
	}
	d := after.Next - before.Next
	if d > ^uint64(0)-e.history.Next {
		return violated("history numbered past 2^64")
	}
	e.history = e.history.Add(e.history.Next+d, after.Since(before.Next))
	return nil
}

// Snapshot copies the mirror into g, with proto's counters and history.
func (e *ipcEmulator) Snapshot(g *screen.Grid) { e.snapshotHeld(g) }

// Held says whether emu held its last answer under synchronised output
// (emu.Holder), so the Session arms SyncHold and Flushes when it fires.
func (e *ipcEmulator) Held() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.held
}

// snapshotHeld is Snapshot and Held under one lock, so a request that
// completes in between cannot pair one answer's screen with another's
// hold.
func (e *ipcEmulator) snapshotHeld(g *screen.Grid) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.mirror == nil {
		*g = *screen.NewGrid(e.cols, e.rows)
	} else {
		*g = *e.mirror.Clone()
	}
	g.Bell = e.bell
	g.Clipboard = screen.Clipboard{Seq: e.clipboard.Seq, Data: bytes.Clone(e.clipboard.Data)}
	g.Rebuilt = e.rebuilt
	g.History = e.history
	return e.held
}

// TakeReplies returns the replies that passed, and forgets them.
func (e *ipcEmulator) TakeReplies() []byte {
	e.mu.Lock()
	defer e.mu.Unlock()
	r := e.replies
	e.replies = nil
	return r
}

// Close ends every wait and closes the current emu's socket.
func (e *ipcEmulator) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.closed = true
	if e.link != nil {
		e.link.close()
		e.link = nil
	}
	e.up.Broadcast()
	return nil
}
