package agent

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"golang.org/x/crypto/ssh"
)

// fixedBind is an honest bind from a host key fixed by its seed, so the
// fuzzer's corpus stays valid from run to run.
func fixedBind(t testing.TB) []byte {
	signer, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	return bindFrame(t, signer, sid(), 1)
}

// FuzzCapture: whatever ssh and the far host send on the capture's one
// connection, a bind is captured only for exactly ssh's honest bind, the
// trigger, and EOF, and then it is that bind byte for byte (agent.md
// §2.2). Everything else is a NoBindError, never a panic.
func FuzzCapture(f *testing.F) {
	honest := fixedBind(f)
	f.Add(append(append([]byte(nil), honest...), trigger...))
	f.Add(honest)
	f.Add(append(append(append([]byte(nil), honest...), trigger...), honest...))
	f.Add(append(append([]byte(nil), honest...), frame(msgExtension)...))
	f.Fuzz(func(t *testing.T, in []byte) {
		b, err, _ := run(in)
		if err != nil {
			if _, ok := err.(*NoBindError); !ok {
				t.Fatalf("%v is not a NoBindError", err)
			}
			return
		}
		want := append(append([]byte(nil), honest...), trigger...)
		if !bytes.Equal(in, want) || !bytes.Equal(b.Frame(), honest) {
			t.Fatalf("captured %x from %x", b.Frame(), in)
		}
	})
}
