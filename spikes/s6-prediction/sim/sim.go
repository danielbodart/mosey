// Package sim replays a recorded trace through the predictor over a simple
// simulated network. It is NOT the S5 simulator (that was being built in
// parallel and was not available); it is a small discrete-event model with
// fixed base RTT, uniform jitter, and i.i.d. or Gilbert-Elliott loss, plus a
// simplified SSP sender (D11 timing constants). See FINDINGS.md §2 for the
// approximations (notably: the application is replayed open-loop).
package sim

import (
	"container/heap"
	"fmt"
	"io"
	"math/rand"
	"sort"
	"strings"
	"time"

	"mosey.spike/s6-prediction/predict"
	"mosey.spike/s6-prediction/screen"
	"mosey.spike/s6-prediction/trace"
)

// Debug, when set, receives a per-event log.
var Debug io.Writer

// EchoAckMode is how the server reports a new echo ack.
type EchoAckMode int

const (
	// EchoAckExtra: send an extra frame ~50 ms after each keystroke even if
	// the screen has not changed (the paper's description).
	EchoAckExtra EchoAckMode = iota
	// EchoAckPiggyback: echo ack only rides on frames that are due anyway
	// (screen change, retransmission). No keystroke-tagged frames.
	EchoAckPiggyback
	// EchoAckExtraUnlessEchoOff: extra frames, except while the pty is at a
	// no-echo canonical prompt.
	EchoAckExtraUnlessEchoOff
)

type Options struct {
	EchoAck EchoAckMode
}

type Profile struct {
	Name     string
	RTT      time.Duration // base round trip, split evenly
	Jitter   time.Duration // extra one-way delay, uniform in [0, Jitter]
	Loss     float64       // per-packet loss probability, each direction
	BurstLen float64       // mean burst length in packets; <=1 means i.i.d.
}

// D11 constants (paper §3 / PLAN D11).
const (
	collect   = 8 * time.Millisecond
	echoDelay = 50 * time.Millisecond // paper §3.2: server-side echo-ack timeout
	ackDelay  = 100 * time.Millisecond
	minRTO    = 50 * time.Millisecond
)

func (p Profile) frameInterval() time.Duration {
	f := p.RTT / 2
	return min(max(f, 20*time.Millisecond), 250*time.Millisecond)
}

func (p Profile) rto() time.Duration {
	// RFC 6298 with SRTT≈RTT+Jitter/2 and RTTVAR≈Jitter/2; 50 ms floor (D11)
	return max(p.RTT+p.Jitter/2+2*p.Jitter, minRTO)
}

type lossy struct {
	r        *rand.Rand
	p, burst float64
	bad      bool
}

func (l *lossy) lost() bool {
	if l.p <= 0 {
		return false
	}
	if l.burst <= 1 {
		return l.r.Float64() < l.p
	}
	// Gilbert-Elliott, loss=1 in Bad, 0 in Good
	pbg := 1 / l.burst
	pgb := l.p / (l.burst * (1 - l.p))
	if l.bad {
		if l.r.Float64() < pbg {
			l.bad = false
		}
	} else if l.r.Float64() < pgb {
		l.bad = true
	}
	return l.bad
}

// ---- events -------------------------------------------------------------

type evKind int

const (
	evKey evKind = iota
	evUpArrive
	evServerDirty
	evServerSend
	evDownArrive
	evClientRTO
	evClientAck
	evServerRTO
)

type ev struct {
	at   time.Duration
	kind evKind
	n    int // key index / generation / serial
	f    *frame
	up   *upPkt
	ord  int
}

type evq []*ev

func (q evq) Len() int { return len(q) }
func (q evq) Less(i, j int) bool {
	if q[i].at != q[j].at {
		return q[i].at < q[j].at
	}
	return q[i].ord < q[j].ord
}
func (q evq) Swap(i, j int) { q[i], q[j] = q[j], q[i] }
func (q *evq) Push(x any)   { *q = append(*q, x.(*ev)) }
func (q *evq) Pop() any     { o := *q; x := o[len(o)-1]; *q = o[:len(o)-1]; return x }

type frame struct {
	serial   int
	rho      time.Duration // recorded-time position of the screen
	scr      int
	echoAck  int
	received int
	echoOff  bool
}

type upPkt struct {
	keys     int // cumulative keys 1..keys
	ackFrame int
}

// KeyResult is the per-keystroke outcome.
type KeyResult struct {
	Index         int // 1-based key number
	Label         string
	Shown         bool // a prediction for this key was visible immediately
	Wrong         bool // ...and it disagreed with the settled ground truth
	StyleOnly     bool // glyphs right, rendition differs
	RowStale      bool // shown and right, but other cells on the cursor row are stale
	Predicted     bool // engine made a (maybe background) prediction
	Effect        bool // the key visibly changed the screen in the recording
	ServerLat     time.Duration
	TimeToCorrect time.Duration // for Wrong keys
	CorrectedAt   time.Duration // sim time the wrong prediction left the screen (groups keys into events)
	Secret        bool          // typed while the pty was at a no-echo canonical prompt
	TruthCursor   bool          // ground-truth cursor came from the app (faketui marker), not the heuristic
	HeurMismatch  bool          // the reverse-cell heuristic disagreed with the app's own insertion point
	Detail        string
}

type Result struct {
	Keys          []KeyResult
	EngineKills   int
	EngineVisible int
	UpPackets     int
	DownPackets   int
	// SecretCellsShown counts (event, cell) pairs where a predicted non-blank
	// cell for a secret key was displayed; SecretKeysShown the distinct keys.
	SecretCellsShown int
	SecretKeysShown  int
	// EchoOnlyFrames: frames whose only news is a new echo ack (screen
	// unchanged): each one tags a keystroke for an on-path observer.
	// EchoOnlyFramesSecret: those sent while the pty was echo-off.
	EchoOnlyFrames       int
	EchoOnlyFramesSecret int
}

// Run replays tr under profile p with predictor config cfg.
func Run(tr *trace.Trace, p Profile, cfg predict.Config, seed int64) *Result {
	return RunOpts(tr, p, cfg, seed, Options{})
}

// RunOpts is Run with server options.
func RunOpts(tr *trace.Trace, p Profile, cfg predict.Config, seed int64, opt Options) *Result {
	r := rand.New(rand.NewSource(seed))
	upLoss := &lossy{r: r, p: p.Loss, burst: p.BurstLen}
	downLoss := &lossy{r: r, p: p.Loss, burst: p.BurstLen}
	delay := func() time.Duration {
		d := p.RTT / 2
		if p.Jitter > 0 {
			d += time.Duration(r.Int63n(int64(p.Jitter)))
		}
		return d
	}

	// recorded timeline
	type outEv struct {
		t     time.Duration
		scr   int
		eo    bool
		truth []int
	}
	var outs []outEv
	var keyT []time.Duration
	var keyB [][]byte
	var keyL []string
	secret := []bool{false}
	hasTruth := false
	for _, e := range tr.Events {
		t := time.Duration(e.T) * time.Microsecond
		if e.Kind == trace.Out {
			outs = append(outs, outEv{t, e.Screen, e.EchoOff, e.Truth})
			if e.Truth != nil {
				hasTruth = true
			}
		} else {
			keyT = append(keyT, t)
			keyB = append(keyB, e.Data)
			keyL = append(keyL, e.Label)
			secret = append(secret, e.EchoOff)
		}
	}
	N := len(keyT)
	// Password keys typed after a `read -s` line. zsh and fish implement
	// read -s in raw mode, so the pty echo-off bit misses them; mark them
	// from the script so the "never display a password cell" check covers
	// every shell, not only those the bit covers.
	{
		line, pw := "", false
		for k := 1; k <= N; k++ {
			b := string(keyB[k-1])
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
	keyT = append([]time.Duration{0}, keyT...) // 1-based
	end := time.Duration(1<<62 - 1)
	nextKeyT := func(k int) time.Duration { // recorded time of key k+1
		if k+1 <= N {
			return keyT[k+1]
		}
		return end
	}
	screenAt := func(rho time.Duration) int { // recorded screen at recorded time rho
		i := sort.Search(len(outs), func(i int) bool { return outs[i].t > rho })
		if i == 0 {
			return 0
		}
		return outs[i-1].scr
	}
	echoOffAt := func(rho time.Duration) bool {
		i := sort.Search(len(outs), func(i int) bool { return outs[i].t > rho })
		if i == 0 {
			return false
		}
		return outs[i-1].eo
	}
	truthAt := func(rho time.Duration) []int { // the app's last reported insertion point
		i := sort.Search(len(outs), func(i int) bool { return outs[i].t > rho })
		for i--; i >= 0; i-- {
			if outs[i].truth != nil {
				return outs[i].truth
			}
		}
		return nil
	}

	// per-key ground truth and first response in the recording
	settled := make([]int, N+1)
	settledTruth := make([][]int, N+1)
	respT := make([]time.Duration, N+1)
	effect := make([]bool, N+1)
	for k := 1; k <= N; k++ {
		lim := nextKeyT(k)
		if lim == end {
			lim = keyT[k] + 2*time.Second
		}
		settled[k] = screenAt(lim - time.Microsecond)
		if hasTruth {
			settledTruth[k] = truthAt(lim - time.Microsecond)
		}
		before := screenAt(keyT[k])
		i := sort.Search(len(outs), func(i int) bool { return outs[i].t > keyT[k] })
		for ; i < len(outs) && outs[i].t < lim; i++ {
			if outs[i].scr != before {
				respT[k] = outs[i].t
				effect[k] = true
				break
			}
		}
	}

	eng := predict.New(cfg, tr.Screens[screenAt(keyT[1]-time.Microsecond)])
	eng.SetRTT(p.RTT + p.Jitter/2)
	res := &Result{Keys: make([]KeyResult, N+1)}
	type watch struct {
		k     int
		at    time.Duration
		cells []predict.Shown
		cur   bool
	}
	var watches []*watch
	resolved := map[uint64]time.Duration{}
	var killTimes []time.Duration
	eng.Observer = func(e predict.Event) {
		if _, ok := resolved[e.Seq]; !ok {
			resolved[e.Seq] = e.At
		}
		if e.Outcome == predict.Wrong || e.Outcome == predict.Collateral {
			if len(killTimes) == 0 || killTimes[len(killTimes)-1] != e.At {
				killTimes = append(killTimes, e.At)
			}
		}
	}

	q := &evq{}
	ord := 0
	push := func(e *ev) { ord++; e.ord = ord; heap.Push(q, e) }
	for k := 1; k <= N; k++ {
		push(&ev{at: keyT[k], kind: evKey, n: k})
	}

	// server state
	srvN := 0                             // keys delivered
	deliver := make([]time.Duration, N+1) // delivery time of each key
	srvSerial := 0
	srvAcked := 0
	srvLastSend := -time.Hour
	srvPending := false
	var srvLastSent *frame
	rho := func(now time.Duration) time.Duration {
		if srvN == 0 {
			return min(now, keyT[1]-time.Microsecond)
		}
		return keyT[srvN] + min(now-deliver[srvN], nextKeyT(srvN)-keyT[srvN]-time.Microsecond)
	}
	echoAck := func(now time.Duration) int {
		a := 0
		for k := srvN; k >= 1; k-- {
			if deliver[k]+echoDelay <= now {
				a = k
				break
			}
		}
		return a
	}
	curFrame := func(now time.Duration) *frame {
		rh := rho(now)
		return &frame{rho: rh, scr: screenAt(rh), echoAck: echoAck(now), received: srvN, echoOff: echoOffAt(rh)}
	}
	dirty := func(now time.Duration) {
		if srvPending {
			return
		}
		srvPending = true
		at := max(now+collect, srvLastSend+p.frameInterval())
		push(&ev{at: at, kind: evServerSend})
	}

	// client state
	cliSent := 0
	cliAcked := 0
	cliLastSend := time.Duration(0)
	cliFrame := 0
	cliAckPending := false
	cliScr := screenAt(keyT[1] - time.Microsecond)
	type arrival struct {
		at  time.Duration
		rho time.Duration
	}
	var arrivals []arrival
	sendUp := func(now time.Duration, keys int) {
		res.UpPackets++
		pk := &upPkt{keys: keys, ackFrame: cliFrame}
		cliLastSend = now
		if !upLoss.lost() {
			push(&ev{at: now + delay(), kind: evUpArrive, up: pk})
		}
	}

	checkWatches := func(now time.Duration) {
		if len(watches) == 0 {
			return
		}
		cells, _, _, cseq := eng.Display()
		shownAt := map[[2]int]predict.Shown{}
		for _, c := range cells {
			shownAt[[2]int{c.X, c.Y}] = c
		}
		keep := watches[:0]
		for _, w := range watches {
			still := w.cur && cseq >= uint64(w.k)
			for _, b := range w.cells {
				if c, ok := shownAt[[2]int{b.X, b.Y}]; ok && c.Cell == b.Cell {
					still = true
				}
			}
			if still {
				keep = append(keep, w)
			} else {
				res.Keys[w.k].TimeToCorrect = now - w.at
				res.Keys[w.k].CorrectedAt = now
			}
		}
		watches = keep
	}
	anySecret := false
	for _, s := range secret {
		anySecret = anySecret || s
	}
	secretShown := map[uint64]bool{}
	checkSecrets := func() {
		if !anySecret {
			return
		}
		cells, _, _, _ := eng.Display()
		for _, c := range cells {
			// a glyph of a password key on screen; a predicted blank (backspace
			// over a mask character) reveals nothing and is not counted
			if c.Seq < uint64(len(secret)) && secret[c.Seq] && !c.Cell.Blank() {
				res.SecretCellsShown++
				secretShown[c.Seq] = true
				if Debug != nil {
					fmt.Fprintf(Debug, "SECRET shown: key %d cell (%d,%d) %q\n", c.Seq, c.X, c.Y, c.Cell.Text)
				}
			}
		}
	}
	for q.Len() > 0 {
		e := heap.Pop(q).(*ev)
		now := e.at
		if now > keyT[N]+30*time.Second {
			break // safety: nothing long after the trace matters
		}
		switch e.kind {
		case evKey:
			k := e.n
			seq := eng.Input(keyB[k-1])
			_ = seq
			kr := &res.Keys[k]
			kr.Index, kr.Label = k, keyL[k-1]
			kr.Predicted = eng.Predicted(uint64(k))
			kr.Effect = effect[k]
			cells, cx, cy, cseq := eng.Display()
			truth := tr.Screens[settled[k]]
			shown := cseq == uint64(k)
			wrong := false
			var bad []predict.Shown
			curWrong := false
			kr.Secret = secret[k]
			tx, ty := predict.VisualCursor(truth, cfg.FakeCursor)
			if tc := settledTruth[k]; tc != nil {
				// judge against the application's own insertion point, not
				// the heuristic under test
				kr.TruthCursor = true
				if hx, hy := predict.VisualCursor(truth, true); hx != tc[0] || hy != tc[1] {
					kr.HeurMismatch = true
				}
				tx, ty = tc[0], tc[1]
			}
			if shown {
				if cx != tx || cy != ty {
					wrong, curWrong = true, true
					kr.Detail += fmt.Sprintf("cursor %d,%d want %d,%d; ", cx, cy, tx, ty)
				}
			}
			for _, c := range cells {
				if c.Seq != uint64(k) {
					continue
				}
				shown = true
				t := truth.At(c.X, c.Y)
				// a predicted blank where the app then draws a suggestion or
				// other decoration is not a misprediction (colour-independent)
				if !t.SameGlyph(c.Cell) && !(c.Cell.Blank() && (predict.Ghost(t) || predict.Decoration(truth, c.X, c.Y))) {
					wrong = true
					bad = append(bad, c)
					kr.Detail += fmt.Sprintf("(%d,%d) %q want %q; ", c.X, c.Y, c.Cell.Text, t.Text)
				} else if c.Cell.Width != 0 && t.Style != c.Cell.Style {
					kr.StyleOnly = true
				}
			}
			kr.Shown, kr.Wrong = shown, wrong
			if shown && !wrong {
				// is the whole cursor row right, or are unpredicted cells stale?
				view := overlay(tr.Screens[cliScr], cells)
				if view.Row(cy) != truth.Row(cy) {
					kr.RowStale = true
				}
			}
			if wrong {
				watches = append(watches, &watch{k: k, at: now, cells: bad, cur: curWrong})
			}
			if Debug != nil {
				fmt.Fprintf(Debug, "%8.3fs key %4d %-8s %-10q pred=%v shown=%v wrong=%v %s\n", now.Seconds(), k, kr.Label, keyB[k-1], kr.Predicted, shown, wrong, kr.Detail)
			}
			cliSent = k
			sendUp(now, k)
			push(&ev{at: now + p.rto(), kind: evClientRTO, n: k})
		case evClientRTO:
			if cliAcked < cliSent && now-cliLastSend >= p.rto()-time.Microsecond {
				sendUp(now, cliSent)
				push(&ev{at: now + p.rto(), kind: evClientRTO})
			} else if cliAcked < cliSent {
				push(&ev{at: cliLastSend + p.rto(), kind: evClientRTO})
			}
		case evUpArrive:
			pk := e.up
			if pk.ackFrame > srvAcked {
				srvAcked = pk.ackFrame
			}
			if pk.keys > srvN {
				for k := srvN + 1; k <= pk.keys; k++ {
					deliver[k] = now
				}
				srvN = pk.keys
				gen := srvN
				// schedule the app's recorded outputs for this key, shifted
				lo, hi := keyT[gen], nextKeyT(gen)
				i := sort.Search(len(outs), func(i int) bool { return outs[i].t >= lo })
				for ; i < len(outs) && outs[i].t < hi; i++ {
					push(&ev{at: now + (outs[i].t - lo), kind: evServerDirty, n: gen})
				}
				switch opt.EchoAck {
				case EchoAckExtra:
					push(&ev{at: now + echoDelay, kind: evServerDirty, n: gen})
				case EchoAckExtraUnlessEchoOff:
					if !echoOffAt(rho(now)) {
						push(&ev{at: now + echoDelay, kind: evServerDirty, n: gen})
					}
				}
				dirty(now)
			}
		case evServerDirty:
			if e.n == srvN {
				dirty(now)
			}
		case evServerSend:
			srvPending = false
			f := curFrame(now)
			if srvLastSent != nil && srvAcked >= srvLastSent.serial &&
				f.scr == srvLastSent.scr && f.echoAck == srvLastSent.echoAck && f.received == srvLastSent.received {
				break // nothing new and the last frame is acknowledged
			}
			if srvLastSent != nil && f.scr == srvLastSent.scr && f.echoAck != srvLastSent.echoAck && f.received == srvLastSent.received {
				res.EchoOnlyFrames++
				if f.echoOff {
					res.EchoOnlyFramesSecret++
				}
			}
			srvSerial++
			f.serial = srvSerial
			srvLastSent = f
			srvLastSend = now
			res.DownPackets++
			if !downLoss.lost() {
				push(&ev{at: now + delay(), kind: evDownArrive, f: f})
			}
			// the client delays its acks by up to 100 ms, so the server's RTO
			// must cover RTT + ack delay or it retransmits forever (livelock
			// found in this spike: RTT 100 ms, RTO 112 ms)
			push(&ev{at: now + p.rto() + ackDelay, kind: evServerRTO, n: srvSerial})
		case evServerRTO:
			if srvAcked < e.n && srvSerial == e.n {
				// unacknowledged: resend the current state
				srvLastSent = nil
				dirty(now)
			}
		case evDownArrive:
			f := e.f
			if f.serial <= cliFrame {
				break
			}
			cliFrame = f.serial
			if f.received > cliAcked {
				cliAcked = f.received
			}
			cliScr = f.scr
			eng.FrameEx(now, tr.Screens[f.scr], predict.FrameInfo{EchoAck: uint64(f.echoAck), Received: uint64(f.received), EchoOff: f.echoOff})
			if Debug != nil {
				fmt.Fprintf(Debug, "%8.3fs frame #%d ack=%d recv=%d kills=%d pending=%d\n", now.Seconds(), f.serial, f.echoAck, f.received, eng.Kills, eng.Pending())
			}
			arrivals = append(arrivals, arrival{now, f.rho})
			if !cliAckPending {
				cliAckPending = true
				push(&ev{at: now + ackDelay, kind: evClientAck})
			}
		case evClientAck:
			cliAckPending = false
			if now-cliLastSend >= ackDelay {
				sendUp(now, cliSent)
			}
		}
		checkWatches(now)
		checkSecrets()
	}

	// server-only latency per key, and time-to-correct for wrong keys
	for k := 1; k <= N; k++ {
		kr := &res.Keys[k]
		if effect[k] {
			i := sort.Search(len(arrivals), func(i int) bool { return arrivals[i].rho >= respT[k] && arrivals[i].at >= keyT[k] })
			if i < len(arrivals) {
				kr.ServerLat = arrivals[i].at - keyT[k]
			} else {
				kr.ServerLat = -1
			}
		}
		if kr.Wrong && kr.TimeToCorrect == 0 {
			kr.TimeToCorrect = -1 // never corrected before the trace ended
		}
	}
	res.SecretKeysShown = len(secretShown)
	res.Keys = res.Keys[1:]
	res.EngineKills = eng.Kills
	res.EngineVisible = eng.VisibleWrong
	return res
}

func overlay(base *screen.Screen, cells []predict.Shown) *screen.Screen {
	v := base.Clone()
	for _, c := range cells {
		v.Set(c.X, c.Y, c.Cell)
	}
	return v
}
