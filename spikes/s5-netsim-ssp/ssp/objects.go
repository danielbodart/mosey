package ssp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf8"
)

// Source is the sender's side of a synchronised object.
type Source interface {
	Version() uint64
	// Diff returns the diff that turns version from (which the source must
	// still hold) into the current version.
	Diff(from uint64) []byte
	// Release says versions below v will never be diffed from again.
	Release(v uint64)
	// Sent says the current version has been sent, so it may later be
	// diffed from and must be retained until released.
	Sent(v uint64)
}

// Sink is the receiver's copy of a synchronised object.
type Sink interface {
	Latest() uint64
	Has(v uint64) bool
	Apply(from, to uint64, diff []byte) error
	Release(v uint64)
}

// ---- Keystrokes: client -> server ----

// KeySource is the user's input history. Version = number of input bytes
// typed so far; the diff from v is every byte typed after v, so "the client
// sends every keystroke" falls out of the object [P §2.3].
type KeySource struct {
	base uint64 // version of buf[0]
	buf  []byte
}

func (k *KeySource) Version() uint64 { return k.base + uint64(len(k.buf)) }
func (k *KeySource) Type(b ...byte)  { k.buf = append(k.buf, b...) }
func (k *KeySource) Diff(from uint64) []byte {
	if from < k.base {
		panic(fmt.Sprintf("keysource: diff from released version %d < %d", from, k.base))
	}
	return append([]byte(nil), k.buf[from-k.base:]...)
}
func (k *KeySource) Sent(uint64) {}
func (k *KeySource) Release(v uint64) {
	if v > k.base && v <= k.Version() {
		k.buf = append([]byte(nil), k.buf[v-k.base:]...)
		k.base = v
	}
}

// KeySink is the server's copy. OnKeys receives each new byte once.
type KeySink struct {
	latest   uint64
	released uint64
	OnKeys   func(first uint64, keys []byte)
}

func (k *KeySink) Latest() uint64    { return k.latest }
func (k *KeySink) Has(v uint64) bool { return v <= k.latest && v >= k.released }
func (k *KeySink) Release(v uint64)  { k.released = max(k.released, min(v, k.latest)) }
func (k *KeySink) Apply(from, to uint64, diff []byte) error {
	if uint64(len(diff)) != to-from {
		return errors.New("keysink: diff length mismatch")
	}
	if to <= k.latest {
		return nil
	}
	fresh := diff[k.latest-from:]
	first := k.latest
	k.latest = to
	if k.OnKeys != nil {
		k.OnKeys(first, fresh)
	}
	return nil
}

// ---- Toy screen: server -> client ----

// Screen is a W x H character grid with a cursor and two counters:
// Applied (keystrokes whose effect is on screen: the toy's stand-in for
// "the echo is visible") and EchoAck (the newest keystroke the app has had
// for >= 50 ms, [P §3.2]).
type Screen struct {
	W, H       int
	Rows       []string
	CurR, CurC int
	Applied    uint64
	EchoAck    uint64
}

func NewScreen(w, h int) *Screen {
	s := &Screen{W: w, H: h, Rows: make([]string, h)}
	blank := string(make([]byte, 0))
	for i := range s.Rows {
		s.Rows[i] = blank
	}
	return s
}

func (s *Screen) clone() *Screen {
	c := *s
	c.Rows = append([]string(nil), s.Rows...)
	return &c
}

// Put writes text at the cursor, wrapping and scrolling.
func (s *Screen) Put(text string) {
	for _, r := range text {
		switch r {
		case '\n':
			s.newline()
			continue
		case '\r':
			s.CurC = 0
			continue
		}
		if s.CurC >= s.W {
			s.newline()
		}
		row := []rune(s.Rows[s.CurR])
		for len(row) < s.CurC {
			row = append(row, ' ')
		}
		if s.CurC < len(row) {
			row[s.CurC] = r
		} else {
			row = append(row, r)
		}
		s.Rows[s.CurR] = string(row)
		s.CurC++
	}
}

func (s *Screen) newline() {
	s.CurC = 0
	if s.CurR < s.H-1 {
		s.CurR++
		return
	}
	copy(s.Rows, s.Rows[1:])
	s.Rows[s.H-1] = ""
}

// Clear blanks the screen (a full-screen redraw follows).
func (s *Screen) Clear() {
	for i := range s.Rows {
		s.Rows[i] = ""
	}
	s.CurR, s.CurC = 0, 0
}

// diffScreens encodes old -> new as: cursor, counters, then for each
// changed row the minimal changed span.
func diffScreens(old, cur *Screen) []byte {
	b := make([]byte, 0, 64)
	b = binary.AppendUvarint(b, uint64(cur.CurR))
	b = binary.AppendUvarint(b, uint64(cur.CurC))
	b = binary.AppendUvarint(b, cur.Applied)
	b = binary.AppendUvarint(b, cur.EchoAck)
	for r := 0; r < cur.H; r++ {
		if old.Rows[r] == cur.Rows[r] {
			continue
		}
		o, n := []rune(old.Rows[r]), []rune(cur.Rows[r])
		// pad to equal length with spaces so a shorter row erases
		l := max(len(o), len(n))
		for len(o) < l {
			o = append(o, ' ')
		}
		for len(n) < l {
			n = append(n, ' ')
		}
		lo := 0
		for lo < l && o[lo] == n[lo] {
			lo++
		}
		hi := l
		for hi > lo && o[hi-1] == n[hi-1] {
			hi--
		}
		if lo == hi {
			continue
		}
		b = binary.AppendUvarint(b, uint64(r)+1)
		b = binary.AppendUvarint(b, uint64(lo))
		span := string(n[lo:hi])
		b = binary.AppendUvarint(b, uint64(len(span)))
		b = append(b, span...)
	}
	return append(b, 0)
}

func applyScreenDiff(old *Screen, d []byte) (*Screen, error) {
	s := old.clone()
	vals := make([]uint64, 4)
	for i := range vals {
		v, n := binary.Uvarint(d)
		if n <= 0 {
			return nil, errors.New("screen: bad header")
		}
		vals[i] = v
		d = d[n:]
	}
	s.CurR, s.CurC, s.Applied, s.EchoAck = int(vals[0]), int(vals[1]), vals[2], vals[3]
	for {
		r, n := binary.Uvarint(d)
		if n <= 0 {
			return nil, errors.New("screen: bad row")
		}
		d = d[n:]
		if r == 0 {
			return s, nil
		}
		col, n := binary.Uvarint(d)
		if n <= 0 {
			return nil, errors.New("screen: bad col")
		}
		d = d[n:]
		ln, n := binary.Uvarint(d)
		if n <= 0 || uint64(len(d)-n) < ln {
			return nil, errors.New("screen: bad span")
		}
		d = d[n:]
		span := []rune(string(d[:ln]))
		if !utf8.Valid(d[:ln]) {
			return nil, errors.New("screen: bad utf8")
		}
		d = d[ln:]
		row := []rune(s.Rows[r-1])
		for len(row) < int(col)+len(span) {
			row = append(row, ' ')
		}
		copy(row[col:], span)
		s.Rows[r-1] = string(row)
	}
}

// ScreenSource holds the server's screen versions.
type ScreenSource struct {
	cur      *Screen
	version  uint64
	versions map[uint64]*Screen
}

func NewScreenSource(w, h int) *ScreenSource {
	s := NewScreen(w, h)
	return &ScreenSource{cur: s, versions: map[uint64]*Screen{0: s.clone()}}
}

// Edit mutates the screen and records a new version.
func (s *ScreenSource) Edit(f func(*Screen)) {
	f(s.cur)
	s.version++
}
func (s *ScreenSource) Sent(v uint64) {
	if v == s.version {
		if _, ok := s.versions[v]; !ok {
			s.versions[v] = s.cur.clone()
		}
	}
}
func (s *ScreenSource) Current() *Screen { return s.cur }
func (s *ScreenSource) Version() uint64  { return s.version }
func (s *ScreenSource) Diff(from uint64) []byte {
	old, ok := s.versions[from]
	if !ok {
		panic(fmt.Sprintf("screensource: no version %d", from))
	}
	return diffScreens(old, s.cur)
}
func (s *ScreenSource) Release(v uint64) {
	for k := range s.versions {
		if k < v && k != s.version {
			delete(s.versions, k)
		}
	}
}

// ScreenSink is the client's copy.
type ScreenSink struct {
	latest   uint64
	versions map[uint64]*Screen
	OnScreen func(v uint64, s *Screen)
}

func NewScreenSink(w, h int) *ScreenSink {
	return &ScreenSink{versions: map[uint64]*Screen{0: NewScreen(w, h)}}
}
func (s *ScreenSink) Latest() uint64    { return s.latest }
func (s *ScreenSink) Has(v uint64) bool { _, ok := s.versions[v]; return ok }
func (s *ScreenSink) Screen() *Screen   { return s.versions[s.latest] }
func (s *ScreenSink) Release(v uint64) {
	for k := range s.versions {
		if k < v && k != s.latest {
			delete(s.versions, k)
		}
	}
}
func (s *ScreenSink) Apply(from, to uint64, diff []byte) error {
	if _, ok := s.versions[to]; ok {
		return nil
	}
	old, ok := s.versions[from]
	if !ok {
		return errors.New("screensink: missing source")
	}
	n, err := applyScreenDiff(old, diff)
	if err != nil {
		return err
	}
	s.versions[to] = n
	if to > s.latest {
		s.latest = to
		if s.OnScreen != nil {
			s.OnScreen(to, n)
		}
	}
	return nil
}
