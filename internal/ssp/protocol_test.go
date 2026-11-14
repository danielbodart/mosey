package ssp

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/danielbodart/mosey/internal/userinput"
)

// script is a Datagrams that delivers a fixed list of payloads, as a
// hostile peer holding the keys would, and keeps what the endpoint sends.
type script struct {
	in   chan []byte
	mu   sync.Mutex
	sent [][]byte
}

func newScript(payloads ...[]byte) *script {
	s := &script{in: make(chan []byte, len(payloads))}
	for _, p := range payloads {
		s.in <- p
	}
	return s
}

func (s *script) Send(p []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sent = append(s.sent, bytes.Clone(p))
	return nil
}

func (s *script) Recv(ctx context.Context) ([]byte, error) {
	select {
	case p := <-s.in:
		return p, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *script) Sent() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.sent)
}

// instr is a datagram carrying a whole instruction in one fragment.
func instr(id uint32, from, to uint64, encoding byte, body []byte) []byte {
	in := appendInstruction(nil, instruction{from: from, to: to, encoding: encoding, body: body})
	return appendDatagram(nil, datagram{frag: &fragment{id: id, count: 1, chunk: in}})
}

func newClient(d Datagrams) *clientEnd {
	return NewEndpoint(d, Config{Role: Client, MaxPayload: maxPayload, FrameOverhead: frameOverhead, MaxRemoteBytes: boardLimit}, userinput.NewStream(), newBoard(""))
}

func TestABrokenPeerEndsRunWithAProtocolError(t *testing.T) {
	full := make([]byte, prodLimits.chunk)
	bomb := appendInstruction(nil, instruction{from: 0, to: 1, encoding: encodingDeflate, body: compress(make([]byte, boardLimit+1))})
	for name, c := range map[string]struct {
		payloads [][]byte
		// want is part of the error, so each case is refused for its own
		// reason and not an earlier one.
		want string
	}{
		"reserved flag":               {[][]byte{{0x08, 0, 0, 0, 0, 0}}, "reserved bit"},
		"overlong ack":                {[][]byte{{0, 0, 0, 0, 0, 0x80, 0}}, "shortest form"},
		"ack of a version never sent": {[][]byte{appendDatagram(nil, datagram{ack: 1})}, "newest sent is 0"},
		"too many fragments":          {[][]byte{appendDatagram(nil, datagram{frag: &fragment{count: uint16(prodLimits.maxFragments + 1), chunk: full}})}, "allowed"},
		"index past count":            {[][]byte{appendDatagram(nil, datagram{frag: &fragment{index: 3, count: 3, chunk: full}})}, "not below its count"},
		"short middle chunk":          {[][]byte{appendDatagram(nil, datagram{frag: &fragment{count: 3, chunk: full[1:]}})}, "fragment 0 of 3"},
		"empty last chunk":            {[][]byte{appendDatagram(nil, datagram{frag: &fragment{count: 1}})}, "last fragment"},
		"count changes": {[][]byte{
			appendDatagram(nil, datagram{frag: &fragment{id: 1, count: 3, chunk: full}}),
			appendDatagram(nil, datagram{frag: &fragment{id: 1, index: 1, count: 4, chunk: full}}),
		}, "says 4 fragments"},
		"not forward":             {[][]byte{instr(0, 0, 0, encodingStored, nil)}, "does not go forward"},
		"wider than the window":   {[][]byte{instr(0, 0, Window+1, encodingStored, nil)}, "window"},
		"reserved codec":          {[][]byte{instr(0, 0, 1, 0x02, nil)}, "encoding 0x02"},
		"decompression bomb":      {fragmentDatagrams(1, bomb), "inflates past"},
		"bytes after the stream":  {[][]byte{instr(0, 0, 1, encodingDeflate, append(compress([]byte("hello")), 0))}, "after the compressed diff"},
		"stream cut short":        {[][]byte{instr(0, 0, 1, encodingDeflate, compress([]byte("hello hello hello"))[:4])}, "cut short"},
		"diff the object refuses": {[][]byte{instr(0, 0, 1, encodingStored, []byte{0xff})}, "does not apply"},
	} {
		synctest.Test(t, func(t *testing.T) {
			e := newClient(newScript(c.payloads...))
			err := e.Run(t.Context())
			if !errors.Is(err, ErrProtocol) || !strings.Contains(err.Error(), c.want) {
				t.Errorf("%s: %v", name, err)
			}
			if b, v := e.Remote(); v != 0 || b.text != "" {
				t.Errorf("%s: the screen changed to version %d", name, v)
			}
		})
	}
}

// fragmentDatagrams is an instruction as the datagrams that carry it.
func fragmentDatagrams(id uint32, instruction []byte) [][]byte {
	var out [][]byte
	for _, f := range fragmentsOf(id, instruction, prodLimits.chunk) {
		out = append(out, appendDatagram(nil, datagram{frag: f}))
	}
	return out
}

func TestAPeerBehindIsAckedAndOtherwiseIgnored(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		first := instr(5, 0, 1, encodingStored, []byte("one"))
		s := newScript(
			first,
			// The same instruction again (its ack was lost), a duplicate
			// fragment of a partial, an old version under a new id, and
			// one from a version this side never held.
			first,
			appendDatagram(nil, datagram{frag: &fragment{id: 6, count: 2, chunk: make([]byte, prodLimits.chunk)}}),
			appendDatagram(nil, datagram{frag: &fragment{id: 6, count: 2, chunk: make([]byte, prodLimits.chunk)}}),
			instr(7, 0, 1, encodingStored, []byte("one")),
			instr(8, 3, 4, encodingStored, []byte("four")),
		)
		e := newClient(s)
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error)
		go func() { done <- e.Run(ctx) }()
		time.Sleep(time.Second)
		if b, v := e.Remote(); v != 1 || b.text != "one" {
			t.Errorf("screen %q at version %d", b.text, v)
		}
		var acks int
		for _, p := range s.Sent() {
			d, err := parseDatagram(p, prodLimits.chunk, prodLimits.maxFragments)
			if err != nil || d.frag != nil || d.ack != 1 {
				t.Errorf("sent %+v, %v", d, err)
			}
			acks++
		}
		// Everything arrived at once, so one ack answers it all.
		if acks != 1 {
			t.Errorf("%d acks", acks)
		}
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Error(err)
		}
	})
}

func TestRunReportsAFailedPath(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		broken := errors.New("socket closed")
		e := newClient(failing{broken})
		if err := e.Run(t.Context()); !errors.Is(err, broken) || errors.Is(err, ErrProtocol) {
			t.Errorf("Run: %v", err)
		}
	})
}

type failing struct{ err error }

func (f failing) Send([]byte) error                    { return f.err }
func (f failing) Recv(context.Context) ([]byte, error) { return nil, f.err }

// state is what a refused datagram or instruction must leave alone.
type state struct {
	held              []uint64
	newest, floor     uint64
	acked, latest     uint64
	lastHeard, ackDue time.Time
	echoDue           bool
	parts, partBytes  int
	changed           int
}

func snapshot(e *clientEnd) state {
	return state{
		held: slices.Sorted(maps.Keys(e.held)), newest: e.newest, floor: e.floor,
		acked: e.acked, latest: e.latest, lastHeard: e.lastHeard, ackDue: e.ackDue,
		echoDue: e.echoDue, parts: len(e.re.parts), partBytes: e.re.bytes, changed: len(e.changed),
	}
}

// fuzzClient is a client with some history: versions 1 to 3 of the
// screen received, floor 2, and a version of its own sent.
func fuzzClient() *clientEnd {
	e := newClient(newScript())
	in := userinput.NewStream()
	in.Type([]byte("k"))
	e.pending, e.latest = in, 1
	e.sent[1] = in
	e.held = map[uint64]*board{2: newBoard("two"), 3: newBoard("three")}
	e.newest, e.floor = 3, 2
	return e
}

// FuzzDatagram: any payload either parses and re-encodes to exactly the
// same bytes, or is refused, and a refused one changes nothing.
func FuzzDatagram(f *testing.F) {
	f.Add(appendDatagram(nil, datagram{ts: 1, ack: 3}))
	f.Add(appendDatagram(nil, datagram{ts: 1, echo: 5, hasEcho: true, ack: 1, padded: true, pad: 3}))
	f.Add(instr(1, 3, 4, encodingStored, []byte("four")))
	f.Add(instr(1, 2, 5, encodingDeflate, compress([]byte("five five five five"))))
	f.Add(appendDatagram(nil, datagram{frag: &fragment{count: 2, chunk: make([]byte, prodLimits.chunk)}}))
	// As senders make them (§9.2): an echo padded to the server's floor, and
	// a full fragment at MaxPayload.
	f.Add(appendDatagram(nil, datagram{ts: 1, echo: 2, hasEcho: true, ack: 3, frag: &fragment{id: 1, count: 1, chunk: []byte{3, 4, 0, 'x'}}, padded: true, pad: 38}))
	f.Add(appendDatagram(nil, datagram{ack: 1 << 63, frag: &fragment{count: 2, chunk: make([]byte, prodLimits.chunk)}, padded: true, pad: 6}))
	f.Fuzz(func(t *testing.T, p []byte) {
		d, err := parseDatagram(p, prodLimits.chunk, prodLimits.maxFragments)
		if err == nil {
			if again := appendDatagram(nil, d); !bytes.Equal(again, p) {
				t.Fatalf("re-encoded as %x", again)
			}
		}
		e := fuzzClient()
		before := snapshot(e)
		rerr := e.receive(p, time.Now())
		if err != nil {
			if rerr == nil {
				t.Fatal("the endpoint took a datagram that does not parse")
			}
			if after := snapshot(e); !equalState(before, after) {
				t.Fatalf("a refused datagram changed %+v to %+v", before, after)
			}
		}
		if rerr != nil && !errors.Is(rerr, ErrProtocol) {
			t.Fatalf("not a protocol error: %v", rerr)
		}
		checkHeld(t, e)
	})
}

// FuzzInstruction runs §7.3 on any instruction: a refused one leaves
// held, newest and RemoteChanged untouched, and whatever happens the
// receiver holds at most Window+1 versions, none below its floor but the
// newest.
func FuzzInstruction(f *testing.F) {
	f.Add(appendInstruction(nil, instruction{from: 3, to: 4, encoding: encodingStored, body: []byte("four")}))
	f.Add(appendInstruction(nil, instruction{from: 2, to: 18, encoding: encodingDeflate, body: compress([]byte("eighteen"))}))
	f.Add(appendInstruction(nil, instruction{from: 1, to: 2, encoding: encodingStored}))
	f.Add(appendInstruction(nil, instruction{from: 3, to: 4, encoding: encodingStored, body: []byte{0xff}}))
	f.Fuzz(func(t *testing.T, b []byte) {
		e := fuzzClient()
		before := snapshot(e)
		if err := e.handle(b, time.Now()); err != nil {
			if !errors.Is(err, ErrProtocol) {
				t.Fatalf("not a protocol error: %v", err)
			}
			after := snapshot(e)
			if !slices.Equal(before.held, after.held) || before.newest != after.newest || before.changed != after.changed || before.floor != after.floor {
				t.Fatalf("a refused instruction changed %+v to %+v", before, after)
			}
		}
		checkHeld(t, e)
	})
}

func checkHeld(t *testing.T, e *clientEnd) {
	t.Helper()
	if len(e.held) > Window+1 {
		t.Fatalf("holds %d versions", len(e.held))
	}
	if _, ok := e.held[e.newest]; !ok {
		t.Fatal("lost the newest version")
	}
	for v := range e.held {
		if v < e.floor && v != e.newest {
			t.Fatalf("holds %d below the floor %d", v, e.floor)
		}
	}
}

func equalState(a, b state) bool {
	return slices.Equal(a.held, b.held) && a.newest == b.newest && a.floor == b.floor &&
		a.acked == b.acked && a.latest == b.latest && a.lastHeard.Equal(b.lastHeard) &&
		a.ackDue.Equal(b.ackDue) && a.echoDue == b.echoDue && a.parts == b.parts &&
		a.partBytes == b.partBytes && a.changed == b.changed
}
