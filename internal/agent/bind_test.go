package agent

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// hostKey is a throwaway ed25519 host key.
func hostKey(t testing.TB) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func appendString(b, s []byte) []byte {
	return append(binary.BigEndian.AppendUint32(b, uint32(len(s))), s...)
}

// bindFrame is a session-bind frame as ssh writes one: key's signature
// over sid, and is_forwarding as fwd.
func bindFrame(t testing.TB, key ssh.Signer, sid []byte, fwd byte) []byte {
	t.Helper()
	return bindFrameSignedBy(t, key.PublicKey(), key, sid, fwd)
}

// bindFrameSignedBy names pub as the host key but has signer sign.
func bindFrameSignedBy(t testing.TB, pub ssh.PublicKey, signer ssh.Signer, sid []byte, fwd byte) []byte {
	t.Helper()
	sig, err := signer.Sign(rand.Reader, sid)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte{msgExtension}
	body = appendString(body, []byte(SessionBindExtension))
	body = appendString(body, pub.Marshal())
	body = appendString(body, sid)
	body = appendString(body, ssh.Marshal(sig))
	body = append(body, fwd)
	return frame(body...)
}

func sid() []byte { return []byte(strings.Repeat("s", 32)) }

func TestAnHonestBindParsesAndKeepsItsBytes(t *testing.T) {
	key := hostKey(t)
	f := bindFrame(t, key, sid(), 1)
	b, err := ParseBind(f)
	if err != nil {
		t.Fatal(err)
	}
	if string(b.Frame()) != string(f) || string(b.HostKey.Marshal()) != string(key.PublicKey().Marshal()) || string(b.SessionID) != string(sid()) {
		t.Error("the bind does not keep what ssh sent")
	}
}

// Every way a bind can be wrong is refused (agent.md §2.1, §2.2).
func TestABindThatIsWrongInAnyWayIsRefused(t *testing.T) {
	key := hostKey(t)
	good := bindFrame(t, key, sid(), 1)
	badSig := bindFrameSignedBy(t, key.PublicKey(), hostKey(t), sid(), 1)
	trailing := append(append([]byte(nil), good...), 0)
	binary.BigEndian.PutUint32(trailing, uint32(len(trailing)-4))
	for name, f := range map[string][]byte{
		"not for forwarding":       bindFrame(t, key, sid(), 0),
		"is_forwarding not a bool": bindFrame(t, key, sid(), 2),
		"a bad signature":          badSig,
		"a byte after it":          trailing,
		"an empty session id":      bindFrame(t, key, nil, 1),
		"the wrong length prefix":  append(good[:len(good):len(good)], 0),
		"another message":          frame(msgRequestIdentities),
		"another extension": func() []byte {
			b := []byte{msgExtension}
			b = appendString(b, []byte("unheard-of@example.com"))
			return frame(b...)
		}(),
	} {
		if _, err := ParseBind(f); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
