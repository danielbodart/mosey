package ipc

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

// The framing of a stream socket (frame.go), driven the way Conn drives
// it, over a byte stream in memory: no socket, so it runs anywhere.

// fakeStream is a stream of bytes, with fds marked at the offsets of the
// bytes they were sent with, read in chunks no longer than chunk[i].
type fakeStream struct {
	data   []byte
	fdsAt  map[int][]int // offset -> fds sent with the byte there
	chunks []int
	read   int // bytes taken
	calls  int
}

// readInto reads at most len(p) bytes, and at most the next chunk size.
// A read stops before a byte that was sent with fds, unless that byte is
// its first, so the fds come with the read that starts at their byte, as
// a kernel gives a send's fds with its first byte. (Linux may also
// give them with a read that began on plain bytes before them [M]. The
// reader then takes them if that read is the first of its message, and
// refuses them if not: either way, one read brings one send's fds.)
func (s *fakeStream) readInto(p []byte) (int, []int) {
	n := len(p)
	if len(s.chunks) > 0 {
		c := s.chunks[s.calls%len(s.chunks)]
		if c > 0 && c < n {
			n = c
		}
	}
	s.calls++
	if rest := len(s.data) - s.read; rest < n {
		n = rest
	}
	for i := 1; i < n; i++ {
		if len(s.fdsAt[s.read+i]) > 0 {
			n = i
			break
		}
	}
	copy(p, s.data[s.read:s.read+n])
	var fds []int
	for i := s.read; i < s.read+n; i++ {
		fds = append(fds, s.fdsAt[i]...)
	}
	s.read += n
	return n, fds
}

type framedMessage struct {
	body []byte
	fds  []int
}

// drain reads messages until an error, as Conn.readFramed does.
func drain(s *fakeStream) ([]framedMessage, error) {
	var r frameReader
	buf := make([]byte, MaxMessage+1)
	var out []framedMessage
	for {
		if r.err != nil {
			return out, r.err
		}
		n, fds := s.readInto(r.next(buf))
		size, mfds, done, err := r.add(n, fds)
		if err != nil {
			return out, err
		}
		if done {
			out = append(out, framedMessage{append([]byte(nil), buf[:size]...), mfds})
		}
	}
}

func frameAll(bodies ...[]byte) []byte {
	var b []byte
	for _, body := range bodies {
		b = appendFrame(b, body)
	}
	return b
}

func TestFramedMessagesComeWholeInAnyChunking(t *testing.T) {
	bodies := [][]byte{{typeFlush}, []byte("hello"), bytes.Repeat([]byte{7}, MaxMessage), {1, 2, 3}}
	stream := frameAll(bodies...)
	for _, chunks := range [][]int{nil, {1}, {2}, {3}, {5}, {1, 4, 1}, {4097}, {65539}} {
		s := &fakeStream{data: stream, chunks: chunks}
		got, err := drain(s)
		if !errors.Is(err, io.EOF) || err != io.EOF {
			t.Errorf("chunks %v: ended with %v, want a plain io.EOF", chunks, err)
		}
		if len(got) != len(bodies) {
			t.Fatalf("chunks %v: %d messages, want %d", chunks, len(got), len(bodies))
		}
		for i := range bodies {
			if !bytes.Equal(got[i].body, bodies[i]) {
				t.Errorf("chunks %v: message %d differs", chunks, i)
			}
		}
	}
}

// Each message's fds come out with that message and no other, however the
// stream is cut, because no read crosses the end of a message.
func TestFDsStayWithTheMessageTheyWereSentWith(t *testing.T) {
	a := frameAll([]byte("first"))
	b := frameAll([]byte("second"))
	c := frameAll([]byte("third"))
	stream := append(append(append([]byte(nil), a...), b...), c...)
	fdsAt := map[int][]int{0: {10, 11}, len(a) + len(b): {12}}
	for _, chunks := range [][]int{nil, {1}, {3}, {7}, {64}} {
		got, err := drain(&fakeStream{data: stream, fdsAt: fdsAt, chunks: chunks})
		if err != io.EOF {
			t.Fatalf("chunks %v: %v", chunks, err)
		}
		want := [][]int{{10, 11}, nil, {12}}
		for i, m := range got {
			if !equalInts(m.fds, want[i]) {
				t.Errorf("chunks %v: message %d came with fds %v, want %v", chunks, i, m.fds, want[i])
			}
		}
	}
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// A length of 0, or over MaxMessage, is refused once its four bytes are
// read: not one byte of the body is read, and the refusal is final.
func TestARefusedLengthReadsNoFurtherAndIsFinal(t *testing.T) {
	for _, l := range []uint32{0, MaxMessage + 1, 1 << 31, 0xffffffff} {
		bad := binary.BigEndian.AppendUint32(nil, l)
		stream := append(frameAll([]byte("ok")), bad...)
		stream = append(stream, frameAll([]byte("after"))...)
		s := &fakeStream{data: stream, fdsAt: map[int][]int{6: {9}}, chunks: []int{1}}
		got, err := drain(s)
		if !errors.Is(err, ErrMalformed) {
			t.Fatalf("length %d: %v", l, err)
		}
		if len(got) != 1 || string(got[0].body) != "ok" {
			t.Errorf("length %d: got %d messages", l, len(got))
		}
		if s.read != 6+frameHeader {
			t.Errorf("length %d: read %d bytes, want the first message and the length only", l, s.read)
		}
	}
}

// The stream ending between messages is a plain io.EOF; ending within one
// is the peer gone as well (IsEOF), with the fds of its part handed back
// to be closed.
func TestTheStreamEndingWithinAMessageIsTheEndWithItsFDs(t *testing.T) {
	whole := frameAll([]byte("whole message"))
	for cut := 1; cut < len(whole); cut++ {
		s := &fakeStream{data: whole[:cut], fdsAt: map[int][]int{0: {5}}}
		var r frameReader
		buf := make([]byte, MaxMessage)
		var closed []int
		var err error
		for err == nil {
			n, fds := s.readInto(r.next(buf))
			var mfds []int
			_, mfds, _, err = r.add(n, fds)
			closed = append(closed, mfds...)
		}
		if err == io.EOF || !IsEOF(err) {
			t.Errorf("cut at %d: %v, want an end within a message", cut, err)
		}
		if !equalInts(closed, []int{5}) {
			t.Errorf("cut at %d: handed back fds %v", cut, closed)
		}
	}
}

func TestFramedRecordsAreBoundedBeforeTheyAreRead(t *testing.T) {
	l, r, err := streamPair()
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	defer r.Close()
	if err := writeRecord(l, []byte("greeting"), true); err != nil {
		t.Fatal(err)
	}
	if got, err := readRecord(r, 8, true); err != nil || string(got) != "greeting" {
		t.Fatalf("got %q, %v", got, err)
	}
	if err := writeRecord(l, []byte("greeting!"), true); err != nil {
		t.Fatal(err)
	}
	if _, err := readRecord(r, 8, true); !errors.Is(err, ErrMalformed) {
		t.Fatalf("a record over the bound: %v", err)
	}
}

// fds sent with a byte after the first of a message are refused: the
// sender attaches a message's fds to its first byte only, and a peer that
// sends more on later bytes could otherwise fill the receiver's fd table
// a byte at a time. Every fd that came is handed back to be closed, and
// the refusal is final.
func TestFDsAfterTheFirstReadOfAMessageAreRefusedAndHandedBack(t *testing.T) {
	stream := frameAll([]byte("hello world"), []byte("after"))
	for _, at := range []int{1, frameHeader - 1, frameHeader, frameHeader + 5, frameHeader + 10} {
		s := &fakeStream{data: stream, fdsAt: map[int][]int{0: {10}, at: {11, 12}}, chunks: []int{1}}
		var r frameReader
		buf := make([]byte, MaxMessage+1)
		var handed []int
		var err error
		for err == nil {
			n, fds := s.readInto(r.next(buf))
			var mfds []int
			var done bool
			_, mfds, done, err = r.add(n, fds)
			if done {
				t.Fatalf("fds at %d: the message was accepted", at)
			}
			handed = append(handed, mfds...)
		}
		if !errors.Is(err, ErrMalformed) {
			t.Errorf("fds at %d: %v", at, err)
		}
		if !equalInts(handed, []int{10, 11, 12}) {
			t.Errorf("fds at %d: handed back %v", at, handed)
		}
		if s.read != at+1 {
			t.Errorf("fds at %d: read %d bytes, want none past the refused read", at, s.read)
		}
		if _, fds, _, again := r.add(1, []int{13}); !errors.Is(again, ErrMalformed) || !equalInts(fds, []int{13}) {
			t.Errorf("fds at %d: after the refusal, %v and fds %v", at, again, fds)
		}
	}
}

// FuzzFrameReader drives the frame reader over any stream, cut at any
// sizes, with fds sent at any bytes (bit i of marks puts fd 1000+i at
// byte i). The invariants: what it returns agrees with a plain reading of
// the stream; it never reads past a refused length, nor past the end of
// the message it is reading; a message comes with the fds of its first
// byte only, and fds on any later byte are refused; and every fd that
// came is handed back once, with its message or with the error.
func FuzzFrameReader(f *testing.F) {
	f.Add(frameAll([]byte{1}, []byte("two")), uint8(0), []byte{0x01})
	f.Add(frameAll([]byte("abc")), uint8(1), []byte{0x02})
	f.Add([]byte{0, 0, 0, 0}, uint8(2), []byte{})
	f.Add([]byte{0, 1, 0, 1, 9}, uint8(3), []byte{0x11})
	f.Add([]byte{0, 0, 0, 3, 1}, uint8(1), []byte{0xff})
	f.Add(frameAll([]byte("ab"), []byte("cd")), uint8(0), []byte{0x41})
	f.Fuzz(func(t *testing.T, data []byte, chunk uint8, marks []byte) {
		marked := func(i int) bool { return i/8 < len(marks) && marks[i/8]>>(i%8)&1 == 1 }
		fdsAt := map[int][]int{}
		for i := range data {
			if marked(i) {
				fdsAt[i] = []int{1000 + i}
			}
		}
		s := &fakeStream{data: data, fdsAt: fdsAt, chunks: []int{int(chunk%9) + 1, int(chunk/9) + 1}}
		var r frameReader
		buf := make([]byte, MaxMessage+1)
		var got [][]byte
		var gotFDs [][]int
		var sent, handed []int
		var err error
		start := 0 // where the message being read begins
		for err == nil {
			limit := start + frameHeader
			if r.nhdr == frameHeader {
				limit += r.size
			}
			n, fds := s.readInto(r.next(buf))
			sent = append(sent, fds...)
			if s.read > limit {
				t.Fatalf("read to %d, past the message that ends at %d", s.read, limit)
			}
			var size int
			var done bool
			var mfds []int
			size, mfds, done, err = r.add(n, fds)
			handed = append(handed, mfds...)
			if done {
				got = append(got, append([]byte(nil), buf[:size]...))
				gotFDs = append(gotFDs, mfds)
				start = s.read
			}
		}
		if !equalInts(handed, sent) {
			t.Fatalf("fds %v came and %v were handed back", sent, handed)
		}
		// The reference: lengths and bodies, one after another, with fds
		// allowed at the first byte of each message only.
		var want [][]byte
		var wantFDs [][]int
		off := 0
		var wantErr error = io.EOF
		misplaced := func(from, to int) bool {
			for i := from; i < to && i < len(data); i++ {
				if marked(i) {
					return true
				}
			}
			return false
		}
	walk:
		for off < len(data) {
			if misplaced(off+1, off+frameHeader) {
				wantErr = ErrMalformed
				break
			}
			if len(data)-off < frameHeader {
				wantErr = errors.New("short length")
				break
			}
			l := binary.BigEndian.Uint32(data[off:])
			if l == 0 || l > MaxMessage {
				wantErr = ErrMalformed
				if s.read != off+frameHeader {
					t.Fatalf("read %d bytes, past the refused length that ends at %d", s.read, off+frameHeader)
				}
				break
			}
			end := off + frameHeader + int(l)
			switch {
			case misplaced(off+frameHeader, end):
				wantErr = ErrMalformed
				break walk
			case end > len(data):
				wantErr = errors.New("short body")
				break walk
			}
			want = append(want, data[off+frameHeader:end])
			wantFDs = append(wantFDs, fdsAt[off])
			off = end
		}
		if len(got) != len(want) {
			t.Fatalf("%d messages, want %d", len(got), len(want))
		}
		for i := range want {
			if !bytes.Equal(got[i], want[i]) {
				t.Fatalf("message %d is %x, want %x", i, got[i], want[i])
			}
			if !equalInts(gotFDs[i], wantFDs[i]) {
				t.Fatalf("message %d came with fds %v, want %v", i, gotFDs[i], wantFDs[i])
			}
		}
		switch {
		case wantErr == io.EOF && err != io.EOF:
			t.Fatalf("ended with %v, want io.EOF", err)
		case errors.Is(wantErr, ErrMalformed) && !errors.Is(err, ErrMalformed):
			t.Fatalf("ended with %v, want a refusal", err)
		case wantErr != io.EOF && !errors.Is(wantErr, ErrMalformed) && (err == io.EOF || !IsEOF(err)):
			t.Fatalf("ended with %v, want an end within a message", err)
		}
		// Refused or ended, the reader stays so, reads nothing more, and
		// hands back any fds it is given.
		if _, fds, _, again := r.add(1, []int{7}); again == nil || !equalInts(fds, []int{7}) {
			t.Fatalf("a reader that has stopped started again, or kept fds %v", fds)
		}
	})
}
