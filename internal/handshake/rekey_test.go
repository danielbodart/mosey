package handshake

import (
	"bytes"
	"errors"
	"testing"
)

func rekeyRoot(t testing.TB) [32]byte {
	var root [32]byte
	copy(root[:], "a root both sides share, 32 bytes")
	return root
}

func TestARekeyGivesBothSidesTheSameNextEpoch(t *testing.T) {
	root := rekeyRoot(t)
	ri, parts, err := StartRekey(root, 11)
	if err != nil {
		t.Fatal(err)
	}
	if len(parts[0]) != RekeyPartSize || len(parts[1]) != RekeyPartSize {
		t.Fatalf("parts of %d and %d bytes", len(parts[0]), len(parts[1]))
	}
	resp, next, err := RespondRekey(root, parts, 22)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp) != RekeyRespSize {
		t.Fatalf("a response of %d bytes", len(resp))
	}
	keys, err := ri.Finish(resp)
	if err != nil {
		t.Fatal(err)
	}
	if keys.Send != next.Recv || keys.Recv != next.Send || keys.Root != next.Root {
		t.Error("the two sides derived different epochs")
	}
	if keys.Root == root || keys.Send == keys.Recv {
		t.Error("the new epoch reuses the root or shares a key between directions")
	}
	if keys.LocalIndex != 11 || keys.RemoteIndex != 22 || next.LocalIndex != 22 || next.RemoteIndex != 11 {
		t.Errorf("indices: initiator %d→%d, responder %d→%d", keys.LocalIndex, keys.RemoteIndex, next.LocalIndex, next.RemoteIndex)
	}
}

func TestARekeyFinishesOnce(t *testing.T) {
	root := rekeyRoot(t)
	ri, parts, _ := StartRekey(root, 1)
	resp, _, _ := RespondRekey(root, parts, 2)
	if _, err := ri.Finish(resp); err != nil {
		t.Fatal(err)
	}
	if _, err := ri.Finish(resp); !errors.Is(err, ErrState) {
		t.Errorf("a second Finish: %v", err)
	}
	if ri.root != ([32]byte{}) {
		t.Error("Finish left the root behind")
	}
}

func TestATamperedResponseNeverGivesTheRespondersKeys(t *testing.T) {
	// ML-KEM decapsulation rejects implicitly: a wrong enc gives a wrong
	// secret rather than an error, and a changed index only changes the
	// derivation. So a tampered response may "finish", but never with the
	// keys the responder holds. (In the transport a response is sealed
	// under the current keys, so only the peer can send one at all.)
	root := rekeyRoot(t)
	for _, at := range []int{0, 3, 4, 5, 100, 1000, 1123, RekeyRespSize - 1} {
		ri, parts, _ := StartRekey(root, 1)
		resp, next, _ := RespondRekey(root, parts, 2)
		bad := bytes.Clone(resp)
		bad[at] ^= 1
		keys, err := ri.Finish(bad)
		if err == nil && keys.Recv == next.Send {
			t.Errorf("byte %d flipped and the keys still agree", at)
		}
	}
}

func TestAMalformedResponseLeavesTheRekeyInFlight(t *testing.T) {
	root := rekeyRoot(t)
	ri, parts, _ := StartRekey(root, 1)
	resp, next, _ := RespondRekey(root, parts, 2)
	for _, bad := range [][]byte{resp[:100], append(bytes.Clone(resp), 0), append([]byte{0, 0, 0, 0}, resp[4:]...)} {
		if _, err := ri.Finish(bad); !errors.Is(err, ErrMalformed) {
			t.Errorf("a %d-byte response: %v", len(bad), err)
		}
	}
	keys, err := ri.Finish(resp)
	if err != nil || keys.Recv != next.Send {
		t.Errorf("the genuine response after the malformed ones: %v", err)
	}
}

func TestADifferentRootGivesDifferentKeys(t *testing.T) {
	root := rekeyRoot(t)
	ri, parts, _ := StartRekey(root, 1)
	other := root
	other[0] ^= 1
	resp, next, err := RespondRekey(other, parts, 2)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := ri.Finish(resp)
	if err == nil && keys.Recv == next.Send {
		t.Error("peers on different roots agreed on keys")
	}
}

func TestJoinRekeyInitRefusesMismatchedHalves(t *testing.T) {
	_, parts, _ := StartRekey(rekeyRoot(t), 5)
	for name, p := range map[string][2][]byte{
		"short first":  {parts[0][:10], parts[1]},
		"long second":  {parts[0], append(bytes.Clone(parts[1]), 0)},
		"other index":  {parts[0], append([]byte{6, 0, 0, 0}, parts[1][4:]...)},
		"index zero":   {append([]byte{0, 0, 0, 0}, parts[0][4:]...), append([]byte{0, 0, 0, 0}, parts[1][4:]...)},
		"same half x2": {parts[0], parts[0]},
	} {
		_, _, err := JoinRekeyInit(p)
		if name == "same half x2" {
			// Both carry idx 5, so the join is well formed; it is the KEM
			// that refuses the resulting key, or the keys that disagree.
			continue
		}
		if !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
	idx, pk, err := JoinRekeyInit(parts)
	if err != nil || idx != 5 || len(pk) != PublicKeySize {
		t.Errorf("the genuine halves: %d, %d bytes, %v", idx, len(pk), err)
	}
}

// FuzzRekey mutates the INIT halves and the response: whatever is
// accepted, the two sides agree only if nothing was changed.
func FuzzRekey(f *testing.F) {
	root := rekeyRoot(f)
	ri0, parts, _ := StartRekey(root, 9)
	ri0.Wipe()
	f.Add(parts[0], parts[1], uint16(0), byte(0))
	f.Fuzz(func(t *testing.T, p0, p1 []byte, at uint16, flip byte) {
		ri, genuine, err := StartRekey(root, 9)
		if err != nil {
			t.Fatal(err)
		}
		// Swap the genuine key in where the fuzzer kept the shape, so the
		// mutations reach the KEM.
		if len(p0) == RekeyPartSize && len(p1) == RekeyPartSize && bytes.Equal(p0, parts[0]) && bytes.Equal(p1, parts[1]) {
			p0, p1 = genuine[0], genuine[1]
		}
		resp, next, err := RespondRekey(root, [2][]byte{p0, p1}, 3)
		if err != nil {
			return
		}
		if len(resp) != RekeyRespSize {
			t.Fatalf("a response of %d bytes", len(resp))
		}
		mutated := int(at) < len(resp) && flip != 0
		if mutated {
			resp = bytes.Clone(resp)
			resp[int(at)] ^= flip
		}
		keys, err := ri.Finish(resp)
		if err != nil {
			return
		}
		sameInit := bytes.Equal(p0, genuine[0]) && bytes.Equal(p1, genuine[1])
		if keys.Recv == next.Send && (!sameInit || mutated) {
			t.Fatalf("keys agree after a mutation (init intact %v, response mutated %v)", sameInit, mutated)
		}
		if keys.Recv != next.Send && sameInit && !mutated {
			t.Fatal("the genuine exchange disagreed")
		}
	})
}
