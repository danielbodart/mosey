package channel

import (
	"bytes"
	"context"
	"testing"
	"testing/synctest"
	"time"
)

// FuzzParseFrame: whatever ParseFrame accepts, Marshal writes back byte
// for byte, so there is one encoding of each frame and the padding is
// all zeros (agent.md §5.1).
func FuzzParseFrame(f *testing.F) {
	for _, fr := range []Frame{
		{Stream: 1, Op: OpOpen, Type: 1, Window: RecvBuffer},
		{Stream: 1, Op: OpAccept, Window: RecvBuffer},
		{Stream: 3, Op: OpData, Offset: 7, Data: []byte("hello"), Fin: true},
		{Stream: 3, Op: OpData, Offset: 0, Data: bytes.Repeat([]byte{0xAA}, MaxData)},
		{Stream: 5, Op: OpAck, Offset: 99, Window: 12, Fin: true},
		{Stream: 7, Op: OpReset, Reason: ReasonGone},
	} {
		f.Add(Marshal(fr))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		fr, err := ParseFrame(b)
		if err != nil {
			return
		}
		if got := Marshal(fr); !bytes.Equal(got, b) {
			t.Fatalf("parse then marshal changed the bytes:\n in %x\nout %x", b, got)
		}
	})
}

// FuzzMux: a peer that sends anything at all, after opening one stream,
// never panics the mux, never makes a stream hold more than its buffers,
// never leaves more than MaxStreams live, and a frame that does not parse
// changes nothing but the stream it names (agent.md §5.7).
func FuzzMux(f *testing.F) {
	f.Add(Marshal(Frame{Stream: 1, Op: OpData, Data: []byte("abc"), Fin: true}), Marshal(Frame{Stream: 1, Op: OpAck, Offset: 0, Window: 10}))
	f.Add(Marshal(Frame{Stream: 3, Op: OpOpen, Type: 1, Window: 5}), []byte{1, 0, 0, 0, 9})
	f.Add(Marshal(Frame{Stream: 1, Op: OpReset, Reason: ReasonAborted}), Marshal(Frame{Stream: 1, Op: OpData, Offset: 1 << 40, Data: []byte("x")}))
	f.Fuzz(func(t *testing.T, a, b []byte) {
		synctest.Test(t, func(t *testing.T) {
			streams := make(chan *Stream, MaxStreams+1)
			r := newRawPeer(Client, func(context.Context, uint8) (func(*Stream), error) {
				return func(s *Stream) { streams <- s }, nil
			})
			defer r.stop()
			r.send(t, Frame{Stream: 1, Op: OpOpen, Type: typeAgent, Window: RecvBuffer})
			s := <-streams
			go s.Write(bytes.Repeat([]byte("w"), 3*MaxData))
			for _, body := range [][]byte{a, b, a} {
				if err := r.end.SendChannel(body); err != nil {
					t.Fatal(err)
				}
				time.Sleep(time.Millisecond)
			}
			time.Sleep(10 * time.Second)
			synctest.Wait()
			r.m.mu.Lock()
			defer r.m.mu.Unlock()
			if r.m.live > MaxStreams || r.m.live < 0 {
				t.Fatalf("%d live streams", r.m.live)
			}
			for _, s := range r.m.streams {
				if len(s.rbuf) > RecvBuffer || len(s.sbuf) > SendBuffer {
					t.Fatalf("stream %d holds %d received and %d to send", s.id, len(s.rbuf), len(s.sbuf))
				}
				if s.sUna > s.sNxt || s.sNxt > s.end() || s.sNxt > s.sMax {
					t.Fatalf("stream %d: una %d nxt %d end %d max %d", s.id, s.sUna, s.sNxt, s.end(), s.sMax)
				}
			}
		})
	})
}
