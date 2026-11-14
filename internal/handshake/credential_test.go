package handshake

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

func TestACredentialDiesAtItsTTLAndTakesItsPendingsWithIt(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newWorld(t)
		i := w.initiator(t, 1)
		_, p, err := w.resp.ReadMsg1(i.Msg1())
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(CredentialTTL - time.Millisecond)
		if p.Erased() || w.creds.Live() != 1 {
			t.Fatal("the credential died before its TTL")
		}
		time.Sleep(time.Millisecond)
		erased := w.resp.Erased()
		if len(erased) != 1 || erased[0] != p || !p.Erased() {
			t.Fatalf("at the TTL %d pendings were erased", len(erased))
		}
		if p.cred != nil || p.msg2 != nil {
			t.Error("an erased pending kept its credential or its cached answer")
		}
		if _, _, err := w.resp.ReadMsg1(i.Msg1()); !errors.Is(err, ErrUnknownCredential) {
			t.Errorf("msg1 after the TTL: %v", err)
		}
		if err := w.resp.Confirm(p); !errors.Is(err, ErrSpent) {
			t.Errorf("confirming a pending of an expired credential: %v", err)
		}
	})
}

func TestAConsumedCredentialIsRememberedUntilItsTTL(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newWorld(t)
		i := w.initiator(t, 1)
		_, p, _ := w.resp.ReadMsg1(i.Msg1())
		if err := w.resp.Confirm(p); err != nil {
			t.Fatal(err)
		}
		if _, _, err := w.resp.ReadMsg1(i.Msg1()); !errors.Is(err, ErrSpent) {
			t.Errorf("before the TTL: %v", err)
		}
		time.Sleep(CredentialTTL)
		if _, _, err := w.resp.ReadMsg1(i.Msg1()); !errors.Is(err, ErrUnknownCredential) {
			t.Errorf("after the TTL: %v", err)
		}
		if p.Erased() {
			t.Error("the TTL erased the confirmed connection's pending")
		}
	})
}

func TestAThirdUnusedCredentialEvictsTheOldestAndSaysSo(t *testing.T) {
	var logged bytes.Buffer
	creds := NewCredentials(slog.New(slog.NewTextHandler(&logged, nil)))
	resp := NewResponder(creds, terminalOnly, func() uint32 { return 1 })
	sid := must(NewSessionID())
	var keys []*OneShotKey
	var minted []Credential
	for range MaxUnused + 1 {
		k := must(NewOneShotKey())
		c, err := creds.Mint(sid, k.PublicKey())
		if err != nil {
			t.Fatal(err)
		}
		keys, minted = append(keys, k), append(minted, c)
	}
	if creds.Live() != MaxUnused {
		t.Fatalf("%d live credentials", creds.Live())
	}
	if !strings.Contains(logged.String(), "evicting an unused credential") {
		t.Errorf("the eviction was not logged: %q", logged.String())
	}
	oldest, err := NewInitiator(minted[0], keys[0], terminalOnly, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := resp.ReadMsg1(oldest.Msg1()); !errors.Is(err, ErrUnknownCredential) {
		t.Errorf("the evicted credential: %v", err)
	}
	newest, _ := NewInitiator(minted[MaxUnused], keys[MaxUnused], terminalOnly, 1)
	if _, _, err := resp.ReadMsg1(newest.Msg1()); err != nil {
		t.Errorf("the newest credential: %v", err)
	}

	// The cap is per session: another session's credentials are left alone.
	other := must(NewOneShotKey())
	if _, err := creds.Mint(must(NewSessionID()), other.PublicKey()); err != nil {
		t.Fatal(err)
	}
	if creds.Live() != MaxUnused+1 {
		t.Errorf("%d live credentials across two sessions", creds.Live())
	}
}

func TestEvictingACredentialErasesItsPendings(t *testing.T) {
	w := newWorld(t)
	i := w.initiator(t, 1)
	_, p, _ := w.resp.ReadMsg1(i.Msg1())
	for range MaxUnused {
		w.newClient(t)
	}
	erased := w.resp.Erased()
	if len(erased) != 1 || erased[0] != p || !p.Erased() {
		t.Errorf("%d pendings erased by the eviction", len(erased))
	}
}

func TestConfirmationErasesTheCredentialsOtherPendings(t *testing.T) {
	w := newWorld(t)
	var pendings []*Pending
	for n := range 3 {
		i, _ := NewInitiator(w.cred, &OneShotKey{sk: must(NewOneShotKey()).sk, public: w.key.public}, terminalOnly, uint32(n+1))
		_, p, err := w.resp.ReadMsg1(i.Msg1())
		if err != nil {
			t.Fatal(err)
		}
		pendings = append(pendings, p)
	}
	if err := w.resp.Confirm(pendings[1]); err != nil {
		t.Fatal(err)
	}
	erased := w.resp.Erased()
	if len(erased) != 2 || pendings[1].Erased() || !pendings[0].Erased() || !pendings[2].Erased() {
		t.Errorf("confirmation erased %d pendings", len(erased))
	}
	cred := pendings[1].cred
	if cred != nil {
		t.Error("the confirmed pending still points at its credential")
	}
}

func TestMintRefusesAClientKeyThatIsNotOne(t *testing.T) {
	creds := NewCredentials(nil)
	for _, k := range [][]byte{nil, make([]byte, PublicKeySize-1), make([]byte, PublicKeySize+1)} {
		if _, err := creds.Mint([16]byte{}, k); !errors.Is(err, ErrMalformed) {
			t.Errorf("a %d-byte key: %v", len(k), err)
		}
	}
	if creds.Live() != 0 {
		t.Error("a refused mint left a credential")
	}
}

// CheckPublicKey is Mint's own test of the key, so what the spawner lets
// through is exactly what proto can mint for.
func TestCheckPublicKeyAgreesWithMint(t *testing.T) {
	k, err := NewOneShotKey()
	if err != nil {
		t.Fatal(err)
	}
	defer k.Wipe()
	bad := bytes.Repeat([]byte{0xff}, PublicKeySize) // not a reduced ML-KEM key
	creds := NewCredentials(nil)
	for _, key := range [][]byte{nil, make([]byte, PublicKeySize-1), bad, k.PublicKey()} {
		_, merr := creds.Mint([16]byte{1}, key)
		if cerr := CheckPublicKey(key); (cerr == nil) != (merr == nil) {
			t.Errorf("a %d-byte key: CheckPublicKey %v, Mint %v", len(key), cerr, merr)
		}
	}
	if CheckPublicKey(k.PublicKey()) != nil {
		t.Error("a real one-shot key refused")
	}
}

func TestEachCredentialHasItsOwnIDPSKAndServerKey(t *testing.T) {
	creds := NewCredentials(nil)
	sid := must(NewSessionID())
	k := must(NewOneShotKey())
	a, _ := creds.Mint(sid, k.PublicKey())
	b, _ := creds.Mint(sid, k.PublicKey())
	if a.ID == b.ID || a.PSK == b.PSK || bytes.Equal(a.ServerPublic, b.ServerPublic) {
		t.Error("two credentials share an id, a PSK or a server key")
	}
	if a.SessionID != sid || b.SessionID != sid {
		t.Error("a credential lost its session")
	}
	a.Wipe()
	if a.PSK != ([32]byte{}) {
		t.Error("Wipe left the PSK")
	}
}
