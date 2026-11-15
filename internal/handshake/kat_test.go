package handshake

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"testing/cryptotest"
)

// transcript runs one handshake and one rekey with every random choice
// fixed, and digests every byte that goes on the wire and every key that
// comes out.
func transcript(t *testing.T) map[string]string {
	cryptotest.SetGlobalRandom(t, 0x6d6f736579)
	sid := must(NewSessionID())
	creds := NewCredentials(nil)
	resp := NewResponder(creds, terminalOnly, func() uint32 { return 0x51515151 })
	key := must(NewOneShotKey())
	cred, err := creds.Mint(sid, key.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	i, err := NewInitiator(cred, key, terminalOnly, 0xc1c1c1c1)
	if err != nil {
		t.Fatal(err)
	}
	msg2, p, err := resp.ReadMsg1(i.Msg1())
	if err != nil {
		t.Fatal(err)
	}
	keys, _, err := i.ReadMsg2(msg2)
	if err != nil {
		t.Fatal(err)
	}
	ri, parts, err := StartRekey(keys.Root, 0xc2c2c2c2)
	if err != nil {
		t.Fatal(err)
	}
	rresp, next, err := RespondRekey(p.Keys.Root, parts, 0x52525252)
	if err != nil {
		t.Fatal(err)
	}
	rkeys, err := ri.Finish(rresp)
	if err != nil {
		t.Fatal(err)
	}
	if rkeys.Recv != next.Send {
		t.Fatal("the rekey disagreed")
	}
	digest := func(b ...[]byte) string {
		d := sha256.New()
		for _, x := range b {
			d.Write(x)
		}
		return hex.EncodeToString(d.Sum(nil))[:16]
	}
	return map[string]string{
		"credential": digest(cred.ID[:], cred.PSK[:], cred.ServerPublic, key.PublicKey()),
		"msg1":       digest(i.Msg1()),
		"msg2":       digest(msg2),
		"epoch 0":    digest(keys.Send[:], keys.Recv[:], keys.Root[:]),
		"rekey init": digest(parts[0], parts[1]),
		"rekey resp": digest(rresp),
		"epoch 1":    digest(rkeys.Send[:], rkeys.Recv[:], rkeys.Root[:]),
	}
}

// TestTheWireIsPinnedByAKnownAnswerTranscript fixes the randomness and
// pins msg1, msg2, the epoch-0 keys and one rekey byte for byte
// (transport.md §11), so a refactor cannot change the wire unnoticed. If a
// change to the wire is meant, the new digests go here in the same commit
// as the spec change that explains them.
func TestTheWireIsPinnedByAKnownAnswerTranscript(t *testing.T) {
	want := map[string]string{
		"credential": "98d2879c2ea90104",
		"msg1":       "8ebb5aed30f10e95",
		"msg2":       "7f8a6faf0d8aa684",
		"epoch 0":    "799ea06560db97dc",
		"rekey init": "31e995838de0b213",
		"rekey resp": "2a1d9c38695da5b0",
		"epoch 1":    "931f5f0d66a1bfb0",
	}
	got := transcript(t)
	for name, w := range want {
		if got[name] != w {
			t.Errorf("%s: got %s, pinned %s", name, got[name], w)
		}
	}
}

func TestTheTranscriptIsDeterministicUnderAFixedRandom(t *testing.T) {
	a := transcript(t)
	b := transcript(t)
	for name := range a {
		if a[name] != b[name] {
			t.Errorf("%s differs between two runs with the same seed", name)
		}
	}
}
