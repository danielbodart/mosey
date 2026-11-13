package hs

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"testing"
)

func FuzzParseHello(f *testing.F) {
	b, _ := MarshalHello(clientHello)
	f.Add(b)
	f.Add([]byte{0, 1, 0, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, in []byte) {
		h, err := ParseHello(in)
		if err != nil {
			return
		}
		out, err := MarshalHello(h)
		if err != nil || !bytes.Equal(out, in) {
			t.Fatalf("non-canonical accept: %x -> %+v -> %x %v", in, h, out, err)
		}
	})
}

func FuzzParseBCredentials(f *testing.F) {
	for _, m := range []BMode{B1ServerKEM, B2ClientKEM} {
		_, c, _ := NewBServer(m, serverHello, DefaultConfig())
		f.Add(c.Marshal())
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		c, err := ParseBCredentials(in)
		if err != nil {
			return
		}
		if !bytes.Equal(c.Marshal(), in) {
			t.Fatal("non-canonical credentials accepted")
		}
	})
}

// fuzzBServer feeds arbitrary msg1s to a live server. With fixMAC the
// fuzzer's bytes get a valid mac1 appended so mutations reach the KEM, AEAD
// and hello parsers behind the pre-filter.
func fuzzBServer(f *testing.F, mode BMode, fixMAC bool) {
	server, cred, _ := NewBServer(mode, serverHello, DefaultConfig())
	_, m1, _ := NewBClient(cred, clientHello, DefaultConfig())
	f.Add(m1)
	f.Add(m1[:len(m1)-mac1Size])
	f.Add([]byte{TypeBInit, Version})
	key := mac1Key(&cred)
	f.Fuzz(func(t *testing.T, in []byte) {
		msg := in
		if fixMAC {
			msg = append(bytes.Clone(in), mac1(key, in)...)
		}
		_, sess, _, err := server.HandleInit(msg)
		if err != nil {
			if server.consumed {
				t.Fatal("failed msg1 consumed credentials")
			}
			return
		}
		if sess != nil && !bytes.Equal(msg, m1) {
			t.Fatalf("accepted a msg1 the client never sent: %x", msg)
		}
		if server.consumed { // genuine msg1 found again: reset
			server, cred, _ = NewBServer(mode, serverHello, DefaultConfig())
			_, m1, _ = NewBClient(cred, clientHello, DefaultConfig())
			key = mac1Key(&cred)
		}
	})
}

func FuzzBServerInitB1(f *testing.F)       { fuzzBServer(f, B1ServerKEM, false) }
func FuzzBServerInitB1FixMAC(f *testing.F) { fuzzBServer(f, B1ServerKEM, true) }
func FuzzBServerInitB2FixMAC(f *testing.F) { fuzzBServer(f, B2ClientKEM, true) }

func FuzzBClientResp(f *testing.F) {
	for _, mode := range []BMode{B1ServerKEM, B2ClientKEM} {
		server, cred, _ := NewBServer(mode, serverHello, DefaultConfig())
		_, m1, _ := NewBClient(cred, clientHello, DefaultConfig())
		m2, _, _, _ := server.HandleInit(m1)
		f.Add(byte(mode), m2)
	}
	clients := map[BMode]*BClient{}
	for _, mode := range []BMode{B1ServerKEM, B2ClientKEM} {
		_, cred, _ := NewBServer(mode, serverHello, DefaultConfig())
		clients[mode], _, _ = NewBClient(cred, clientHello, DefaultConfig())
	}
	f.Fuzz(func(t *testing.T, mode byte, in []byte) {
		c := clients[BMode(mode%2+1)]
		// any msg2 here is for a different server: it must never succeed
		if _, _, err := c.HandleResp(in); err == nil {
			t.Fatal("client accepted a msg2 from a server without the PSK")
		}
	})
}

func FuzzAHandshake(f *testing.F) {
	_, ssk, _ := ed25519.GenerateKey(rand.Reader)
	_, csk, _ := ed25519.GenerateKey(rand.Reader)
	var sid [16]byte
	sidS := AIdentity{SessionID: sid, Self: ssk, Peer: csk.Public().(ed25519.PublicKey)}
	sidC := AIdentity{SessionID: sid, Self: csk, Peer: ssk.Public().(ed25519.PublicKey)}
	srv := NewAServer(sidS, serverHello, DefaultConfig())
	cli, m1, _ := NewAClient(sidC, clientHello, DefaultConfig())
	m2, _ := srv.HandleInit(m1)
	m3, _, _, _ := cli.HandleResp(m2)
	f.Add(byte(0), m1)
	f.Add(byte(1), m2)
	f.Add(byte(2), m3)
	// fresh victims that never saw the genuine messages above
	vs := NewAServer(sidS, serverHello, DefaultConfig())
	vc, vm1, _ := NewAClient(sidC, clientHello, DefaultConfig())
	vs.HandleInit(vm1)
	f.Fuzz(func(t *testing.T, which byte, in []byte) {
		switch which % 3 {
		case 0:
			NewAServer(sidS, serverHello, DefaultConfig()).HandleInit(in) // must not panic
		case 1:
			if _, _, _, err := vc.HandleResp(in); err == nil {
				t.Fatal("client accepted msg2 not bound to its msg1")
			}
		case 2:
			if _, _, err := vs.HandleFin(in); err == nil {
				t.Fatal("server accepted msg3 not bound to its msg2")
			}
		}
	})
}

func FuzzSessionOpen(f *testing.F) {
	cli, srv, _, _ := handshakeB(f, B1ServerKEM, DefaultConfig())
	for i := 0; i < 4; i++ {
		p, _ := cli.Seal([]byte("seed"))
		f.Add(p)
	}
	cli.StartRekey()
	f.Add(cli.Outbox()[0])
	f.Fuzz(func(t *testing.T, in []byte) {
		before := *srv.cur
		peer := srv.Peer
		_, err := srv.Open(in, addrB)
		if err != nil {
			if srv.cur.win != before.win || srv.Peer != peer {
				t.Fatal("receive state changed by a rejected packet")
			}
			return
		}
		// Only the seeded genuine packets can authenticate; a mutated one
		// that authenticates is a forgery.
		if len(in) >= dataHeaderSize && binary.LittleEndian.Uint64(in[5:]) > 8 {
			t.Fatalf("forged packet accepted: %x", in)
		}
	})
}

func FuzzReplayWindow(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 3})
	f.Fuzz(func(t *testing.T, in []byte) {
		var w replayWindow
		seen := map[uint64]bool{}
		var top uint64
		any := false
		for len(in) >= 4 {
			// 4-byte steps keep counters dense enough to exercise the window
			c := uint64(binary.BigEndian.Uint32(in)) % (8 * ReplayWindow)
			in = in[4:]
			want := !any || c > top || (top-c < ReplayWindow && !seen[c])
			if w.check(c) != want {
				t.Fatalf("c=%d top=%d want %v", c, top, want)
			}
			if want {
				w.commit(c)
				seen[c] = true
				if !any || c > top {
					top = c
				}
				any = true
			}
		}
	})
}
