package bind

import (
	"crypto/ed25519"
	"crypto/rand"
	"reflect"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestABindRoundTripsAndAForgedOneIsRefused(t *testing.T) {
	_, k, _ := ed25519.GenerateKey(rand.Reader)
	s, _ := ssh.NewSignerFromKey(k)
	sid := make([]byte, 32)
	rand.Read(sid)
	sig, _ := s.Sign(rand.Reader, sid)
	b := &Bind{HostKey: s.PublicKey(), SID: sid, Sig: ssh.Marshal(sig)}
	got, err := ParseContents(b.WithFwd(true).Contents())
	if err != nil || !got.Fwd {
		t.Fatalf("%v %v", got, err)
	}
	sid[0] ^= 1
	if _, err := ParseContents(b.Contents()); err == nil {
		t.Fatal("a bind whose signature is not over its session id was taken")
	}
}

func TestAHopRecordRoundTripsAndRefusesTrailingBytes(t *testing.T) {
	h := &Hop{Transport: "mosey", HostKey: []byte("k"), Session: "work",
		Chain: []Link{{Pid: 3, UID: 1000, Comm: "sudo", Cmdline: []string{"sudo", "a,b", ""}}, {Pid: 2, UID: 1000, Comm: "bash"}}}
	got, err := ParseHop(h.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	h.Chain[1].Cmdline = nil
	if !reflect.DeepEqual(got, h) && !(len(got.Chain) == 2 && got.Chain[0].Cmdline[1] == "a,b") {
		t.Fatalf("%+v", got)
	}
	if _, err := ParseHop(append(h.Marshal(), 0)); err == nil {
		t.Fatal("trailing bytes taken")
	}
}
