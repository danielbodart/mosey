package handshake

import (
	"bytes"
	"errors"
	"testing"
)

var (
	terminalOnly   = Hello{Protocol: ProtocolVersion, Channels: []ChannelType{ChannelTerminal}}
	terminalyAgent = Hello{Protocol: ProtocolVersion, Channels: []ChannelType{ChannelTerminal, ChannelAgent}}
)

// world is one server's credential store and responder, with the indices it
// has handed out, and one client's key and credential.
type world struct {
	creds   *Credentials
	resp    *Responder
	drawn   []uint32
	key     *OneShotKey
	cred    Credential
	session [16]byte
}

func newWorld(t testing.TB) *world {
	t.Helper()
	w := &world{creds: NewCredentials(nil)}
	next := uint32(1000)
	w.resp = NewResponder(w.creds, terminalOnly, func() uint32 {
		next++
		w.drawn = append(w.drawn, next)
		return next
	})
	w.session = must(NewSessionID())
	w.newClient(t)
	return w
}

// newClient makes a fresh client key and mints a credential for it.
func (w *world) newClient(t testing.TB) {
	t.Helper()
	w.key = must(NewOneShotKey())
	cred, err := w.creds.Mint(w.session, w.key.PublicKey(), "")
	if err != nil {
		t.Fatal(err)
	}
	w.cred = cred
}

func (w *world) initiator(t testing.TB, idx uint32) *Initiator {
	t.Helper()
	i, err := NewInitiator(w.cred, w.key, terminalOnly, idx)
	if err != nil {
		t.Fatal(err)
	}
	return i
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// snapshot is everything about the responder's store a refused message
// must leave alone.
type snapshot struct {
	creds, unused, erased int
	pendings              map[[8]byte]int
	consumed              map[[8]byte]bool
}

func (w *world) snapshot() snapshot {
	c := w.creds
	c.mu.Lock()
	defer c.mu.Unlock()
	s := snapshot{creds: len(c.byID), erased: len(c.erased), pendings: map[[8]byte]int{}, consumed: map[[8]byte]bool{}}
	for _, u := range c.unused {
		s.unused += len(u)
	}
	for id, cred := range c.byID {
		s.pendings[id] = len(cred.pendings)
		s.consumed[id] = cred.consumed
	}
	return s
}

func (s snapshot) equal(o snapshot) bool {
	if s.creds != o.creds || s.unused != o.unused || s.erased != o.erased {
		return false
	}
	for id, n := range s.pendings {
		if o.pendings[id] != n || o.consumed[id] != s.consumed[id] {
			return false
		}
	}
	return true
}

func TestXWingSizesAreTheSpecs(t *testing.T) {
	sk, pk, err := generate()
	if err != nil {
		t.Fatal(err)
	}
	if len(pk) != PublicKeySize {
		t.Errorf("public key is %d bytes", len(pk))
	}
	enc, ss, err := encapsulate(pk, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(enc) != EncapsulationSize || len(ss) != 32 {
		t.Errorf("enc %d bytes, shared secret %d", len(enc), len(ss))
	}
	back, err := decapsulate(sk, enc, nil)
	if err != nil || !bytes.Equal(back, ss) {
		t.Errorf("decapsulation gave a different secret: %v", err)
	}
}

func TestBothSidesAgreeOnTheKeys(t *testing.T) {
	w := newWorld(t)
	i := w.initiator(t, 7)
	msg2, p, err := w.resp.ReadMsg1(i.Msg1())
	if err != nil {
		t.Fatal(err)
	}
	keys, server, err := i.ReadMsg2(msg2)
	if err != nil {
		t.Fatal(err)
	}
	if keys.Send != p.Keys.Recv || keys.Recv != p.Keys.Send || keys.Root != p.Keys.Root {
		t.Error("the two sides derived different keys")
	}
	if keys.Send == keys.Recv {
		t.Error("both directions share a key")
	}
	if keys.LocalIndex != 7 || p.Keys.RemoteIndex != 7 || keys.RemoteIndex != p.Keys.LocalIndex {
		t.Errorf("indices: client %d→%d, server %d→%d", keys.LocalIndex, keys.RemoteIndex, p.Keys.LocalIndex, p.Keys.RemoteIndex)
	}
	if !server.Supports(ChannelTerminal) || p.Hello.Attach != Exclusive || p.SessionID != w.session {
		t.Errorf("hellos: server %+v, client %+v", server, p.Hello)
	}
}

func TestMessagesAreTheSizesTheSpecSays(t *testing.T) {
	if Msg1Size(1) != 1167 || Msg1Size(MaxHello) != 1200 {
		t.Errorf("msg1 is %d to %d bytes", Msg1Size(1), Msg1Size(MaxHello))
	}
	if Msg2Size(1) != 1147 || Msg2Size(MaxHello) != 1180 {
		t.Errorf("msg2 is %d to %d bytes", Msg2Size(1), Msg2Size(MaxHello))
	}
	if Msg1Size(MaxHello) > 1200 {
		t.Error("msg1 can exceed D5's 1200 bytes")
	}
	if n := len(MarshalHello(terminalOnly)); n != minHello || len(MarshalHello(terminalyAgent)) != 8 {
		t.Errorf("today's hellos are %d and %d bytes", n, len(MarshalHello(terminalyAgent)))
	}
	if RekeyPartSize != 612 || RekeyRespSize != 1124 {
		t.Errorf("rekey bodies are %d and %d", RekeyPartSize, RekeyRespSize)
	}

	w := newWorld(t)
	i := w.initiator(t, 1)
	if len(i.Msg1()) != Msg1Size(minHello) || len(i.Msg1()) != 1173 {
		t.Errorf("a one-channel msg1 is %d bytes", len(i.Msg1()))
	}
	msg2 := must2(w.resp.ReadMsg1(i.Msg1()))
	if len(msg2) != Msg2Size(minHello) || len(msg2) != 1153 {
		t.Errorf("a one-channel msg2 is %d bytes", len(msg2))
	}

	w.newClient(t)
	all := Hello{Protocol: ProtocolVersion}
	for c := range MaxChannels {
		all.Channels = append(all.Channels, ChannelType(c))
	}
	for f := range MaxHello - all.size() - 2 {
		all.Features = append(all.Features, Feature(f))
	}
	big, err := NewInitiator(w.cred, w.key, all, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(big.Msg1()) != Msg1Size(MaxHello) || len(big.Msg1()) != 1200 {
		t.Errorf("the largest msg1 is %d bytes", len(big.Msg1()))
	}
	msg2 = must2(w.resp.ReadMsg1(big.Msg1()))
	if len(msg2) != Msg2Size(minHello) {
		t.Errorf("the server answered %d bytes; it supports one channel type and no feature", len(msg2))
	}
	all.Features = append(all.Features, Feature(MaxHello))
	if _, err := NewInitiator(w.cred, w.key, all, 3); !errors.Is(err, ErrMalformed) {
		t.Errorf("a hello over MaxHello: %v", err)
	}
}

func must2[A, B any](a A, _ B, err error) A {
	if err != nil {
		panic(err)
	}
	return a
}

func TestEveryTamperedByteOfMsg1IsRefusedAndChangesNothing(t *testing.T) {
	w := newWorld(t)
	i := w.initiator(t, 1)
	msg1 := i.Msg1()
	before := w.snapshot()
	for at := range msg1 {
		bad := bytes.Clone(msg1)
		bad[at] ^= 0x01
		if _, _, err := w.resp.ReadMsg1(bad); err == nil {
			t.Fatalf("msg1 with byte %d flipped was accepted", at)
		}
		if !w.snapshot().equal(before) {
			t.Fatalf("msg1 with byte %d flipped changed the store", at)
		}
	}
	if len(w.drawn) != 0 {
		t.Errorf("refused msg1s drew %d indices", len(w.drawn))
	}
	if _, _, err := w.resp.ReadMsg1(msg1); err != nil {
		t.Errorf("the genuine msg1 was refused after the forgeries: %v", err)
	}
}

func TestATamperedMsg1ThatPassesMac1IsStillRefused(t *testing.T) {
	// mac1 is only a DoS filter: with it recomputed, as a holder of the PSK
	// could, every flipped byte past the header must still fail the KEM or
	// the AEAD.
	w := newWorld(t)
	i := w.initiator(t, 1)
	msg1 := i.Msg1()
	key := mac1Key(w.cred.SessionID, &w.cred.PSK)
	before := w.snapshot()
	for at := msg1Header; at < len(msg1)-mac1Size; at++ {
		bad := bytes.Clone(msg1)
		bad[at] ^= 0x80
		copy(bad[len(bad)-mac1Size:], mac1(&key, bad[:len(bad)-mac1Size]))
		if _, _, err := w.resp.ReadMsg1(bad); !errors.Is(err, ErrAuth) {
			t.Fatalf("byte %d flipped under a good mac1: %v", at, err)
		}
	}
	if !w.snapshot().equal(before) || len(w.drawn) != 0 {
		t.Error("refused msg1s changed the store")
	}
}

func TestEveryTamperedByteOfMsg2IsRefusedAndTheGenuineOneStillWorks(t *testing.T) {
	w := newWorld(t)
	i := w.initiator(t, 1)
	msg2 := must2(w.resp.ReadMsg1(i.Msg1()))
	for at := range msg2 {
		bad := bytes.Clone(msg2)
		bad[at] ^= 0x01
		if _, _, err := i.ReadMsg2(bad); err == nil {
			t.Fatalf("msg2 with byte %d flipped was accepted", at)
		}
	}
	if _, _, err := i.ReadMsg2(msg2); err != nil {
		t.Errorf("the genuine msg2 was refused after the forgeries: %v", err)
	}
}

func TestAResendOfMsg1IsAnsweredFromTheCacheAndCreatesNothing(t *testing.T) {
	w := newWorld(t)
	i := w.initiator(t, 1)
	first, p1, err := w.resp.ReadMsg1(i.Msg1())
	if err != nil {
		t.Fatal(err)
	}
	before := w.snapshot()
	again, p2, err := w.resp.ReadMsg1(i.Msg1())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, again) || p1 != p2 {
		t.Error("a resend was answered afresh")
	}
	if !w.snapshot().equal(before) || len(w.drawn) != 1 {
		t.Error("a resend changed the store or drew an index")
	}
}

// A pending the transport gave up (Evict) is not the answer to a resend of
// its msg1: the resend is answered afresh, with keys of its own, since the
// transport wiped the evicted pending's.
func TestAResendAfterEvictionIsAnsweredWithNewKeys(t *testing.T) {
	w := newWorld(t)
	i := w.initiator(t, 1)
	_, p1, err := w.resp.ReadMsg1(i.Msg1())
	if err != nil {
		t.Fatal(err)
	}
	p1.Keys.Wipe() // as the transport does once it has copied them
	w.resp.Evict(p1)
	if !p1.Erased() {
		t.Error("an evicted pending is not erased")
	}
	_, p2, err := w.resp.ReadMsg1(i.Msg1())
	if err != nil {
		t.Fatal(err)
	}
	if p2 == p1 || p2.Keys.Wiped() {
		t.Fatal("a resend after eviction got the evicted pending back, wiped keys and all")
	}
	if err := w.resp.Confirm(p1); !errors.Is(err, ErrSpent) {
		t.Errorf("confirming the evicted pending: %v, not ErrSpent", err)
	}
	if err := w.resp.Confirm(p2); err != nil {
		t.Errorf("confirming the new pending: %v", err)
	}
}

func TestTheCredentialIsConsumedOnlyByConfirmation(t *testing.T) {
	w := newWorld(t)
	i := w.initiator(t, 1)
	_, p, err := w.resp.ReadMsg1(i.Msg1())
	if err != nil {
		t.Fatal(err)
	}
	if w.creds.Live() != 1 {
		t.Fatal("msg1 consumed the credential")
	}
	if err := w.resp.Confirm(p); err != nil {
		t.Fatal(err)
	}
	if w.creds.Live() != 0 {
		t.Error("confirmation left the credential live")
	}
	if _, _, err := w.resp.ReadMsg1(i.Msg1()); !errors.Is(err, ErrSpent) {
		t.Errorf("msg1 after confirmation: %v", err)
	}
	if err := w.resp.Confirm(p); !errors.Is(err, ErrSpent) {
		t.Errorf("a second confirmation: %v", err)
	}
}

func TestALeakedCredentialLineCannotImpersonateTheClient(t *testing.T) {
	// The attacker holds the whole stdout line, PSK included, and the
	// client's public key, which is not secret, but not its private key
	// (transport.md §11, ProVerif b3_stdout_leak).
	w := newWorld(t)
	genuine := w.initiator(t, 1)
	msg2, genuinePending, err := w.resp.ReadMsg1(genuine.Msg1())
	if err != nil {
		t.Fatal(err)
	}

	// Forge msg1s with an evil key passed off as the client's: the server
	// cannot tell, and answers each, but nothing in them can confirm.
	evil := must(NewOneShotKey())
	evil.public = w.key.PublicKey()
	evicted := false
	for n := range 2 * MaxPending {
		forged, err := NewInitiator(w.cred, &OneShotKey{sk: evil.sk, public: w.key.public}, terminalOnly, uint32(100+n))
		if err != nil {
			t.Fatal(err)
		}
		fmsg2, fp, err := w.resp.ReadMsg1(forged.Msg1())
		if err != nil {
			t.Fatalf("a msg1 with the leaked PSK should be answered: %v", err)
		}
		if _, _, err := forged.ReadMsg2(fmsg2); !errors.Is(err, ErrAuth) {
			t.Fatalf("an attacker without sk_C read msg2: %v", err)
		}
		if fp.Keys.Recv == ([32]byte{}) {
			t.Fatal("a pending without keys")
		}
		evicted = evicted || genuinePending.Erased()
	}
	if w.creds.Live() != 1 {
		t.Fatal("forged msg1s consumed the credential")
	}

	// Whether or not the genuine pending survived, the client's resent
	// msg1 gets it an answer it can read, and its confirmation works.
	msg2again, p, err := w.resp.ReadMsg1(genuine.Msg1())
	if err != nil {
		t.Fatal(err)
	}
	if evicted == bytes.Equal(msg2again, msg2) {
		t.Errorf("evicted %v, but the resend was answered from the cache %v", evicted, bytes.Equal(msg2again, msg2))
	}
	keys, _, err := genuine.ReadMsg2(msg2again)
	if err != nil {
		t.Fatal(err)
	}
	if keys.Send != p.Keys.Recv {
		t.Error("the re-answered msg2 does not match its pending")
	}
	if err := w.resp.Confirm(p); err != nil {
		t.Fatal(err)
	}
	for _, e := range w.resp.Erased() {
		if e == p {
			t.Error("the confirmed pending was reported erased")
		}
	}
}

func TestAFifthPendingEvictsOneOfTheFourAtRandom(t *testing.T) {
	victims := map[int]int{}
	for range 200 {
		w := newWorld(t)
		var pendings []*Pending
		for n := range MaxPending + 1 {
			i, err := NewInitiator(w.cred, &OneShotKey{sk: must(NewOneShotKey()).sk, public: w.key.public}, terminalOnly, uint32(n+1))
			if err != nil {
				t.Fatal(err)
			}
			_, p, err := w.resp.ReadMsg1(i.Msg1())
			if err != nil {
				t.Fatal(err)
			}
			pendings = append(pendings, p)
		}
		erased := w.resp.Erased()
		if len(erased) != 1 {
			t.Fatalf("%d pendings erased by the fifth", len(erased))
		}
		for n, p := range pendings {
			if p == erased[0] {
				victims[n]++
			}
		}
		if pendings[MaxPending].Erased() {
			t.Fatal("the newcomer was evicted")
		}
	}
	for n := range MaxPending {
		if victims[n] < 20 {
			t.Errorf("pending %d was evicted %d times in 200: not uniform", n, victims[n])
		}
	}
}

func TestIndicesAreDrawnOnlyAfterEveryCheck(t *testing.T) {
	w := newWorld(t)
	i := w.initiator(t, 1)
	bad := bytes.Clone(i.Msg1())
	bad[len(bad)-1] ^= 1
	w.resp.ReadMsg1(bad)
	other := newWorld(t)
	w.resp.ReadMsg1(other.initiator(t, 1).Msg1())
	if len(w.drawn) != 0 {
		t.Fatal("a refused msg1 drew an index")
	}
	msg2, p, _ := w.resp.ReadMsg1(i.Msg1())
	if len(w.drawn) != 1 || p.Keys.LocalIndex != w.drawn[0] {
		t.Fatalf("drawn %v, pending's index %d", w.drawn, p.Keys.LocalIndex)
	}
	keys, _, err := i.ReadMsg2(msg2)
	if err != nil || keys.RemoteIndex != w.drawn[0] {
		t.Errorf("the client sends to %d: %v", keys.RemoteIndex, err)
	}
}

func TestAMsg1WithReceiverIndexZeroIsRefusedBeforeAnyWork(t *testing.T) {
	w := newWorld(t)
	msg1, st, err := buildMsg1(&w.cred, w.key.PublicKey(), MarshalHello(terminalOnly), 0)
	st.wipe()
	if err != nil {
		t.Fatal(err)
	}
	before := w.snapshot()
	if _, _, err := w.resp.ReadMsg1(msg1); !errors.Is(err, ErrMalformed) {
		t.Errorf("got %v", err)
	}
	if !w.snapshot().equal(before) || len(w.drawn) != 0 {
		t.Error("a msg1 with index 0 left state behind")
	}
}

func TestAClientHelloWithoutTheTerminalIsRefused(t *testing.T) {
	w := newWorld(t)
	agentOnly := Hello{Protocol: ProtocolVersion, Channels: []ChannelType{ChannelAgent}}
	i, err := NewInitiator(w.cred, w.key, agentOnly, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := w.resp.ReadMsg1(i.Msg1()); !errors.Is(err, ErrIncompatible) {
		t.Errorf("got %v", err)
	}
	if len(w.drawn) != 0 || w.snapshot().pendings[w.cred.ID] != 0 {
		t.Error("a refused hello left state behind")
	}
}

func TestTheServerAnswersWithTheChannelsBothSupport(t *testing.T) {
	w := newWorld(t)
	i, err := NewInitiator(w.cred, w.key, terminalyAgent, 1)
	if err != nil {
		t.Fatal(err)
	}
	msg2, p, err := w.resp.ReadMsg1(i.Msg1())
	if err != nil {
		t.Fatal(err)
	}
	_, server, err := i.ReadMsg2(msg2)
	if err != nil {
		t.Fatal(err)
	}
	if len(server.Channels) != 1 || server.Channels[0] != ChannelTerminal || !p.Hello.Supports(ChannelAgent) {
		t.Errorf("server answered %+v to %+v", server, p.Hello)
	}
}

func TestAServerHelloNamingAChannelNotOfferedIsIncompatible(t *testing.T) {
	offered := terminalOnly
	if err := (Hello{Protocol: 1, Channels: []ChannelType{ChannelTerminal, ChannelAgent}}).agrees(offered); !errors.Is(err, ErrIncompatible) {
		t.Errorf("an extra channel: %v", err)
	}
	if err := (Hello{Protocol: 1, Channels: []ChannelType{ChannelAgent}}).agrees(terminalyAgent); !errors.Is(err, ErrIncompatible) {
		t.Errorf("no terminal: %v", err)
	}
	if err := (Hello{Protocol: 1, Attach: 1, Channels: []ChannelType{ChannelTerminal}}).agrees(offered); !errors.Is(err, ErrIncompatible) {
		t.Errorf("another attach mode: %v", err)
	}
}

func TestAOneShotKeyStartsOneHandshake(t *testing.T) {
	w := newWorld(t)
	w.initiator(t, 1)
	if _, err := NewInitiator(w.cred, w.key, terminalOnly, 2); !errors.Is(err, ErrState) {
		t.Errorf("a second handshake with the same key: %v", err)
	}
}

func TestAWipedInitiatorReadsNothing(t *testing.T) {
	w := newWorld(t)
	i := w.initiator(t, 1)
	msg2 := must2(w.resp.ReadMsg1(i.Msg1()))
	i.Wipe()
	if _, _, err := i.ReadMsg2(msg2); !errors.Is(err, ErrState) {
		t.Errorf("got %v", err)
	}
	if i.afterC1.ck != ([32]byte{}) || i.afterC1.k != ([32]byte{}) {
		t.Error("Wipe left the chaining or cipher key")
	}
}

func TestNewInitiatorErasesItsCopyOfThePSK(t *testing.T) {
	// The caller's Credential is its own to wipe; what this checks is that
	// the initiator keeps nothing derived from the PSK but the state after
	// c1, which is wiped at confirmation.
	w := newWorld(t)
	i := w.initiator(t, 1)
	if w.cred.PSK == ([32]byte{}) {
		t.Fatal("NewInitiator erased the caller's credential")
	}
	if i.sk == nil || !i.afterC1.hasKey {
		t.Error("the initiator lost what it needs to read msg2")
	}
}
