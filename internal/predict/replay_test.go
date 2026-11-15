package predict

import (
	"compress/gzip"
	"container/heap"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/danielbodart/mosey/internal/screen"
)

// The replay of prediction.md §14: S6's recorded traces, read as data
// from spikes/s6-prediction/traces (never imported: the spikes are
// records), played through the engine over a small discrete-event model
// of the path and of the server's rules in prediction.md §3.1.

const traceDir = "../../spikes/s6-prediction/traces"

// ---- the trace format (S6's recorder; a gzip'd JSON document) ----

type rawStyle struct {
	Fg, Bg    uint32
	Attrs, UL uint8
}

type rawCell struct {
	T string   `json:"t"`
	W uint8    `json:"w"`
	S rawStyle `json:"s"`
}

type rawScreen struct {
	W, H          int
	Cells         []rawCell
	CurX, CurY    int
	CursorVisible bool
}

type rawEvent struct {
	T     int64  `json:"t"` // microseconds
	K     string `json:"k"` // "key" or "out"
	D     []byte `json:"d"`
	S     int    `json:"s"` // the screen after it
	L     string `json:"l"`
	Off   bool   `json:"eo"` // the pty had echo off after it
	Truth []int  `json:"tc"` // the program's own insertion point, if it says
}

type trace struct {
	name    string
	screens []*screen.Grid
	events  []rawEvent
}

// loadTrace reads one trace, building each screen as a clone of the one
// before with only the changed cells written, so screens share the rows
// they have in common and a trace of a thousand screens stays small.
func loadTrace(t testing.TB, path string) *trace {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Skipf("S6's traces are not here: %v", err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(zr)
	tr := &trace{name: strings.TrimSuffix(filepath.Base(path), ".json.gz")}
	expect := func(want json.Delim) {
		tok, err := dec.Token()
		if err != nil || tok != want {
			t.Fatalf("%s: want %v, got %v %v", path, want, tok, err)
		}
	}
	expect('{')
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			t.Fatal(err)
		}
		switch tok {
		case "screens":
			expect('[')
			var prev *screen.Grid
			for dec.More() {
				var rs rawScreen
				if err := dec.Decode(&rs); err != nil {
					t.Fatal(err)
				}
				prev = gridOf(rs, prev)
				tr.screens = append(tr.screens, prev)
			}
			expect(']')
		case "events":
			if err := dec.Decode(&tr.events); err != nil {
				t.Fatal(err)
			}
		default:
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				t.Fatal(err)
			}
		}
	}
	return tr
}

func colorOf(v uint32) screen.Color {
	switch {
	case v == 0:
		return screen.DefaultColor
	case v <= 256:
		return screen.Palette(uint8(v - 1))
	}
	return screen.RGB(uint8(v>>16), uint8(v>>8), uint8(v))
}

func styleOf(s rawStyle) screen.Style {
	st := screen.Style{Fg: colorOf(s.Fg), Bg: colorOf(s.Bg)}
	for bit, a := range []screen.Attrs{screen.Bold, screen.Faint, screen.Italic, screen.Blink, screen.Blink, screen.Reverse, screen.Invisible, screen.Strikethrough} {
		if s.Attrs&(1<<bit) != 0 {
			st.Attrs |= a
		}
	}
	switch s.UL {
	case 0:
	case 2:
		st.Attrs |= screen.DoubleUnderline
	case 3:
		st.Attrs |= screen.CurlyUnderline
	default:
		st.Attrs |= screen.Underlined
	}
	return st
}

func gridOf(rs rawScreen, prev *screen.Grid) *screen.Grid {
	var g *screen.Grid
	if prev != nil {
		if c, r := prev.Size(); c == rs.W && r == rs.H {
			g = prev.Clone()
		}
	}
	if g == nil {
		g = screen.NewGrid(rs.W, rs.H)
	}
	for i, rc := range rs.Cells {
		c := screen.Cell{Text: rc.T, Width: rc.W, Style: styleOf(rc.S)}
		if c.Text == " " || c.Width == 0 {
			c.Text = ""
		}
		g.SetCell(i%rs.W, i/rs.W, c)
	}
	g.Cursor = screen.Cursor{X: min(rs.CurX, rs.W-1), Y: min(rs.CurY, rs.H-1), Visible: rs.CursorVisible}
	return g
}

// ---- the path ----

// profile is a network as S6 modelled it (S6 FINDINGS §2): a base round
// trip split evenly, uniform one-way jitter, and i.i.d. or Gilbert-Elliott
// loss in each direction.
type profile struct {
	name   string
	rtt    time.Duration
	jitter time.Duration
	loss   float64
	burst  float64 // mean burst length in packets; ≤ 1 is i.i.d.
}

var profiles = []profile{
	{"lan-5ms", 5 * time.Millisecond, time.Millisecond, 0, 0},
	{"wifi-30ms-1%", 30 * time.Millisecond, 15 * time.Millisecond, 0.01, 0},
	{"transatlantic-100ms", 100 * time.Millisecond, 5 * time.Millisecond, 0, 0},
	{"100ms-29%", 100 * time.Millisecond, 0, 0.29, 0},
	{"train-250ms-burst10%", 250 * time.Millisecond, 150 * time.Millisecond, 0.10, 5},
	{"evdo-450ms", 450 * time.Millisecond, 100 * time.Millisecond, 0.01, 0},
}

// D11's constants: the server collects for 8 ms, frames go at most every
// SRTT/2 clamped to 20–250 ms, acks are delayed 100 ms.
const (
	collect  = 8 * time.Millisecond
	ackDelay = 100 * time.Millisecond
)

func (p profile) frameInterval() time.Duration {
	return min(max(p.srtt()/2, 20*time.Millisecond), 250*time.Millisecond)
}

func (p profile) srtt() time.Duration { return p.rtt + p.jitter/2 }

// rto is RFC 6298's with the profile's variance, the 50 ms floor and the
// peer's ack delay added (D11).
func (p profile) rto() time.Duration { return max(p.srtt()+2*p.jitter, 50*time.Millisecond) + ackDelay }

type lossy struct {
	rng      *rand.Rand
	p, burst float64
	bad      bool
}

func (l *lossy) lost() bool {
	switch {
	case l.p <= 0:
		return false
	case l.burst <= 1:
		return l.rng.Float64() < l.p
	}
	// Gilbert-Elliott: every packet in the bad state is lost.
	if l.bad {
		l.bad = l.rng.Float64() >= 1/l.burst
	} else {
		l.bad = l.rng.Float64() < l.p/(l.burst*(1-l.p))
	}
	return l.bad
}

// ---- the replay ----

type simEvent struct {
	at   time.Duration
	seq  int
	kind int
	n    int       // a key, or a frame's serial
	f    *simFrame // a frame arriving
	up   int       // the keys a client datagram carries
}

const (
	evKey = iota
	evUp
	evDirty
	evSend
	evDown
	evClientRTO
	evServerRTO
)

type simQueue []*simEvent

func (q simQueue) Len() int { return len(q) }
func (q simQueue) Less(i, j int) bool {
	return q[i].at < q[j].at || q[i].at == q[j].at && q[i].seq < q[j].seq
}
func (q simQueue) Swap(i, j int) { q[i], q[j] = q[j], q[i] }
func (q *simQueue) Push(x any)   { *q = append(*q, x.(*simEvent)) }
func (q *simQueue) Pop() any {
	o := *q
	x := o[len(o)-1]
	*q = o[:len(o)-1]
	return x
}

type simFrame struct {
	serial       int
	scr          int
	ack, applied uint64
	off          bool
}

// result is one replay's count, per key.
type result struct {
	keys, instant, wrong, rowStale int
	secret, secretShown            int
	echoOnlyFrames, echoOnlyOff    int
	refuted, visiblyWrong          int
}

func (r *result) add(o result) {
	r.keys += o.keys
	r.instant += o.instant
	r.wrong += o.wrong
	r.rowStale += o.rowStale
	r.secret += o.secret
	r.secretShown += o.secretShown
	r.echoOnlyFrames += o.echoOnlyFrames
	r.echoOnlyOff += o.echoOnlyOff
	r.refuted += o.refuted
	r.visiblyWrong += o.visiblyWrong
}

func pct(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return 100 * float64(a) / float64(b)
}

// replay plays tr over p with seed, the client's engine in Always mode so
// every key counts, as S6 measured.
func replay(tr *trace, p profile, seed uint64) result {
	rng := rand.New(rand.NewPCG(seed, 0x6d6f736579))
	up := &lossy{rng: rng, p: p.loss, burst: p.burst}
	down := &lossy{rng: rng, p: p.loss, burst: p.burst}
	oneWay := func() time.Duration {
		d := p.rtt / 2
		if p.jitter > 0 {
			d += time.Duration(rng.Int64N(int64(p.jitter)))
		}
		return d
	}

	// The recording: keys, and outputs with their screens.
	type out struct {
		at    time.Duration
		scr   int
		off   bool
		truth []int
	}
	var outs []out
	var keyAt []time.Duration
	var keyBytes [][]byte
	for _, ev := range tr.events {
		at := time.Duration(ev.T) * time.Microsecond
		if ev.K == "key" {
			keyAt = append(keyAt, at)
			keyBytes = append(keyBytes, ev.D)
			continue
		}
		outs = append(outs, out{at, ev.S, ev.Off, ev.Truth})
	}
	nKeys := len(keyAt)
	if nKeys == 0 {
		return result{}
	}
	// keyAt and keyBytes are 1-based from here: key k is event k.
	keyAt = append([]time.Duration{0}, keyAt...)
	keyBytes = append([][]byte{nil}, keyBytes...)
	nextKeyAt := func(k int) time.Duration {
		if k+1 <= nKeys {
			return keyAt[k+1]
		}
		return keyAt[k] + 2*time.Second
	}
	outAt := func(rho time.Duration) int { // the last output at or before rho
		return sort.Search(len(outs), func(i int) bool { return outs[i].at > rho }) - 1
	}
	screenAt := func(rho time.Duration) int {
		if i := outAt(rho); i >= 0 {
			return outs[i].scr
		}
		return 0
	}
	offAt := func(rho time.Duration) bool {
		i := outAt(rho)
		return i >= 0 && outs[i].off
	}
	truthAt := func(rho time.Duration) []int {
		for i := outAt(rho); i >= 0; i-- {
			if outs[i].truth != nil {
				return outs[i].truth
			}
		}
		return nil
	}
	// Password keys: typed with the pty's echo off, or after a `read -s`
	// line in a shell that reads it in raw mode, as S6 marked them.
	secret := make([]bool, nKeys+1)
	{
		line, pw := "", false
		for k := 1; k <= nKeys; k++ {
			b := string(keyBytes[k])
			if offAt(keyAt[k]) {
				secret[k] = true
			}
			switch b {
			case "\r":
				pw = !pw && strings.Contains(line, "read -s")
				line = ""
				continue
			case "\x03", "\x15":
				line, pw = "", false
				continue
			}
			if pw {
				secret[k] = true
			}
			line += b
		}
	}

	e := New(Config{Mode: Always})
	e.SetRTT(p.srtt())
	var res result
	res.keys = nKeys

	q := &simQueue{}
	seq := 0
	push := func(ev *simEvent) {
		seq++
		ev.seq = seq
		heap.Push(q, ev)
	}
	for k := 1; k <= nKeys; k++ {
		push(&simEvent{at: keyAt[k], kind: evKey, n: k})
	}

	// The server's side.
	var (
		srvN      int // keys written to the pty
		delivered = make([]time.Duration, nKeys+1)
		srvAck    uint64 // EchoAck as published
		serial    int    // frames sent
		srvAcked  int    // the newest frame the client acked
		lastSend  = -time.Hour
		pending   bool
		last      *simFrame
	)
	rho := func(now time.Duration) time.Duration { // the program's recorded time
		if srvN == 0 {
			return min(now, keyAt[1]-time.Microsecond)
		}
		return keyAt[srvN] + min(now-delivered[srvN], nextKeyAt(srvN)-keyAt[srvN]-time.Microsecond)
	}
	current := func(now time.Duration) *simFrame {
		r := rho(now)
		f := &simFrame{scr: screenAt(r), off: offAt(r), applied: uint64(srvN)}
		if !f.off { // rule 4: the ack stands still while echo is off
			for k := srvN; k >= 1; k-- {
				if delivered[k]+50*time.Millisecond <= now {
					srvAck = max(srvAck, uint64(k))
					break
				}
			}
		}
		f.ack = srvAck
		// Rule 5: the applied count rides only on a frame that differs.
		if last != nil && f.scr == last.scr && f.ack == last.ack && f.off == last.off {
			f.applied = last.applied
		}
		return f
	}
	dirty := func(now time.Duration) {
		if !pending {
			pending = true
			push(&simEvent{at: max(now+collect, lastSend+p.frameInterval()), kind: evSend})
		}
	}

	// The client's side.
	var (
		sent, acked int // keys sent, and acknowledged by the server
		lastUp      time.Duration
		newest      int // the newest frame seen
	)
	sendUp := func(now time.Duration) {
		lastUp = now
		if !up.lost() {
			push(&simEvent{at: now + oneWay(), kind: evUp, up: sent})
		}
	}
	secretShown := map[uint64]bool{}
	checkSecrets := func() {
		if !e.drawing() {
			return
		}
		for _, c := range e.cells {
			if _, ok := e.confirmed[c.epoch]; ok && c.n <= uint64(nKeys) && secret[c.n] && !c.cell.Blank() {
				secretShown[c.n] = true
			}
		}
	}

	settledAt := func(k int) int { return screenAt(nextKeyAt(k) - time.Microsecond) }
	for q.Len() > 0 {
		ev := heap.Pop(q).(*simEvent)
		now := ev.at
		if now > keyAt[nKeys]+30*time.Second {
			break
		}
		switch ev.kind {
		case evKey:
			k := ev.n
			e.Key(uint64(k), keyBytes[k])
			judgeKey(e, tr, k, settledAt(k), truthAt(nextKeyAt(k)-time.Microsecond), &res)
			sent = k
			sendUp(now)
			push(&simEvent{at: now + p.rto(), kind: evClientRTO})
		case evClientRTO:
			if acked < sent {
				if now-lastUp >= p.rto()-time.Microsecond {
					sendUp(now)
				}
				push(&simEvent{at: lastUp + p.rto(), kind: evClientRTO})
			}
		case evUp:
			if ev.up > srvN {
				for k := srvN + 1; k <= ev.up; k++ {
					delivered[k] = now
				}
				srvN = ev.up
				// The program's recorded outputs for the newest key, at the
				// same distance from its delivery as in the recording.
				lo, hi := keyAt[srvN], nextKeyAt(srvN)
				for i := sort.Search(len(outs), func(i int) bool { return outs[i].at >= lo }); i < len(outs) && outs[i].at < hi; i++ {
					push(&simEvent{at: now + outs[i].at - lo, kind: evDirty, n: srvN})
				}
				push(&simEvent{at: now + 50*time.Millisecond, kind: evDirty, n: srvN}) // rule 3
				dirty(now)
			}
		case evDirty:
			if ev.n == srvN {
				dirty(now)
			}
		case evSend:
			pending = false
			f := current(now)
			if last != nil && f.scr == last.scr && f.ack == last.ack && f.applied == last.applied && f.off == last.off && srvAcked >= last.serial {
				break // nothing new, and the client has the last frame
			}
			if last != nil && f.scr == last.scr && f.off == last.off && f.ack != last.ack {
				res.echoOnlyFrames++
				if f.off {
					res.echoOnlyOff++
				}
			}
			serial++
			f.serial = serial
			last, lastSend = f, now
			if !down.lost() {
				push(&simEvent{at: now + oneWay(), kind: evDown, f: f})
			}
			push(&simEvent{at: now + p.rto(), kind: evServerRTO, n: serial})
		case evServerRTO:
			if srvAcked < ev.n && serial == ev.n {
				last = nil // resend the current state
				dirty(now)
			}
		case evDown:
			f := ev.f
			if f.serial <= newest {
				break
			}
			newest = f.serial
			acked = max(acked, int(f.applied))
			g := tr.screens[f.scr].Clone()
			g.EchoAck, g.EchoApplied, g.EchoOff = f.ack, f.applied, f.off
			e.Frame(g)
			// The client's ack of the frame, simplified: the server learns of
			// it at once, so it resends only frames that were lost.
			srvAcked = max(srvAcked, f.serial)
		}
		checkSecrets()
	}
	for k := 1; k <= nKeys; k++ {
		if secret[k] {
			res.secret++
		}
	}
	res.secretShown = len(secretShown)
	s := e.Stats()
	res.refuted, res.visiblyWrong = int(s.Refuted), int(s.VisiblyWrong)
	return res
}

// judgeKey scores key k at the moment it was typed: instant if a
// prediction for it was drawn and its cells and the cursor match the
// screen the program settled on before the next key; wrong if one was
// drawn and they don't. Row-stale is an instant key whose cursor row has
// other cells not yet what the program drew (S6 FINDINGS §4.3).
func judgeKey(e *Engine, tr *trace, k, settled int, truth []int, res *result) {
	if !e.drawing() {
		return
	}
	n := uint64(k)
	want := tr.screens[settled]
	shown, wrong := false, false
	var cur *cursorPred
	for i := len(e.cursors) - 1; i >= 0; i-- {
		if _, ok := e.confirmed[e.cursors[i].epoch]; ok {
			cur = &e.cursors[i]
			break
		}
	}
	tx, ty := want.Cursor.X, want.Cursor.Y
	if truth != nil {
		tx, ty = truth[0], truth[1]
	}
	if cur != nil && cur.n == n {
		shown = true
		wrong = cur.x != tx || cur.y != ty
	}
	wc, wr := want.Size()
	for at, p := range e.cells {
		if _, ok := e.confirmed[p.epoch]; !ok || p.n != n {
			continue
		}
		shown = true
		if at.x >= wc || at.y >= wr {
			wrong = true
			continue
		}
		if got := want.Cell(at.x, at.y); !sameGlyph(got, p.cell) && !(p.cell.Blank() && decoration(want, at.x, at.y)) {
			wrong = true
		}
	}
	switch {
	case !shown:
	case wrong:
		res.wrong++
	default:
		res.instant++
		if cur != nil && cur.y < wr {
			if v := e.Overlay(); rowText(v, cur.y) != rowText(want, cur.y) {
				res.rowStale++
			}
		}
	}
}

func rowText(g *screen.Grid, y int) string {
	var b strings.Builder
	for _, c := range g.Row(y) {
		if c.Width != 0 {
			b.WriteString(c.Text)
			if c.Text == "" {
				b.WriteByte(' ')
			}
		}
	}
	return strings.TrimRight(b.String(), " ")
}

// TestReplayOfS6Traces holds the engine to S6's results on its recorded
// shells (prediction.md §14). By default it replays one trace on two
// profiles and checks floors; MOSEY_PREDICT_REPORT=1 replays every trace on
// every profile with three seeds and prints the tables.
func TestReplayOfS6Traces(t *testing.T) {
	if raceEnabled {
		t.Skip("a replay is a measurement, and minutes long under -race")
	}
	report := os.Getenv("MOSEY_PREDICT_REPORT") != ""
	files, _ := filepath.Glob(filepath.Join(traceDir, "*.json.gz"))
	if len(files) == 0 {
		t.Skip("S6's traces are not here")
	}
	slices.Sort(files)
	ps := profiles
	seeds := []uint64{1, 2, 3}
	if !report {
		files = []string{filepath.Join(traceDir, "bash.json.gz")}
		ps = []profile{profiles[2], profiles[5]}
		seeds = seeds[:1]
	}
	total := map[string]*result{}
	perTrace := map[string]map[string]*result{}
	for _, file := range files {
		tr := loadTrace(t, file)
		perTrace[tr.name] = map[string]*result{}
		for _, p := range ps {
			agg := &result{}
			for _, seed := range seeds {
				agg.add(replay(tr, p, seed))
			}
			perTrace[tr.name][p.name] = agg
			if total[p.name] == nil {
				total[p.name] = &result{}
			}
			total[p.name].add(*agg)
		}
		tr.screens = nil
	}
	for _, p := range ps {
		r := total[p.name]
		t.Logf("%-22s instant %5.1f%%  wrong %4.2f%%  row-stale %4.1f%%  password keys shown %d/%d  echo-ack-only frames %d (%d with echo off)  refuted %d (shown %d)",
			p.name, pct(r.instant, r.keys), pct(r.wrong, r.keys), pct(r.rowStale, r.keys), r.secretShown, r.secret, r.echoOnlyFrames, r.echoOnlyOff, r.refuted, r.visiblyWrong)
		if r.secretShown != 0 {
			t.Errorf("%s: %d password keys were drawn", p.name, r.secretShown)
		}
	}
	if report {
		var b strings.Builder
		fmt.Fprintf(&b, "\n| trace |")
		for _, p := range ps {
			fmt.Fprintf(&b, " %s |", p.name)
		}
		b.WriteString("\n|---|")
		for range ps {
			b.WriteString("---|")
		}
		names := make([]string, 0, len(perTrace))
		for n := range perTrace {
			names = append(names, n)
		}
		slices.Sort(names)
		for _, n := range append(names, "all") {
			fmt.Fprintf(&b, "\n| %s |", n)
			for _, p := range ps {
				r := total[p.name]
				if n != "all" {
					r = perTrace[n][p.name]
				}
				fmt.Fprintf(&b, " %.1f / %.2f |", pct(r.instant, r.keys), pct(r.wrong, r.keys))
			}
		}
		t.Log(b.String())
		return
	}
	// Floors, well below S6's own figures for bash (76–79% instant at
	// 100 ms, 0.3–0.4% wrong), so a regression fails and noise does not.
	if r := total[profiles[2].name]; pct(r.instant, r.keys) < 65 || pct(r.wrong, r.keys) > 1 {
		t.Errorf("bash at 100 ms: %.1f%% instant, %.2f%% wrong", pct(r.instant, r.keys), pct(r.wrong, r.keys))
	}
	if r := total[profiles[5].name]; pct(r.instant, r.keys) < 45 || pct(r.wrong, r.keys) > 1 {
		t.Errorf("bash at 450 ms: %.1f%% instant, %.2f%% wrong", pct(r.instant, r.keys), pct(r.wrong, r.keys))
	}
}
