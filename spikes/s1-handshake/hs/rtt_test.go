package hs

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"testing/synctest"
	"time"
)

// TestHandshakeLatency runs each handshake over a simulated link with a
// one-way delay of 50 ms (RTT 100 ms) in virtual time (testing/synctest, as
// D18 prescribes) and reports when each side can first send application
// data and when the server first receives client data.
func TestHandshakeLatency(t *testing.T) {
	const owd = 50 * time.Millisecond
	type result struct{ serverCanSend, clientCanSend, serverGotData time.Duration }
	run := func(name string, f func(t *testing.T, link func([]byte) []byte, start time.Time) result) {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				start := time.Now()
				link := func(p []byte) []byte { time.Sleep(owd); return p }
				r := f(t, link, start)
				t.Logf("%s: server may send at %v, client may send at %v, server receives first client data at %v (RTT=%v)",
					name, r.serverCanSend, r.clientCanSend, r.serverGotData, 2*owd)
			})
		})
	}
	for _, mode := range allB {
		run(map[BMode]string{1: "B1", 2: "B2", 3: "B3"}[mode], func(t *testing.T, link func([]byte) []byte, start time.Time) result {
			var r result
			server, cred, mk := mintB(t, mode, DefaultConfig())
			client, m1, _ := mk(cred)
			m2, srv, _, err := server.HandleInit(link(m1))
			mustT(t, err)
			r.serverCanSend = time.Since(start)
			cli, _, err := client.HandleResp(link(m2))
			mustT(t, err)
			r.clientCanSend = time.Since(start)
			p, _ := cli.Seal([]byte("k"))
			_, err = srv.Open(link(p), addrA)
			mustT(t, err)
			r.serverGotData = time.Since(start)
			return r
		})
	}
	run("A", func(t *testing.T, link func([]byte) []byte, start time.Time) result {
		var r result
		_, ssk, _ := ed25519.GenerateKey(rand.Reader)
		_, csk, _ := ed25519.GenerateKey(rand.Reader)
		var sid [16]byte
		server := NewAServer(AIdentity{SessionID: sid, Self: ssk, Peer: csk.Public().(ed25519.PublicKey)}, serverHello, DefaultConfig())
		client, m1, _ := NewAClient(AIdentity{SessionID: sid, Self: csk, Peer: ssk.Public().(ed25519.PublicKey)}, clientHello, DefaultConfig())
		m2, err := server.HandleInit(link(m1))
		mustT(t, err)
		m3, cli, _, err := client.HandleResp(link(m2))
		mustT(t, err)
		r.clientCanSend = time.Since(start)
		p, _ := cli.Seal([]byte("k")) // sent in the same flight as msg3
		m3d := link(m3)
		srv, _, err := server.HandleFin(m3d)
		mustT(t, err)
		r.serverCanSend = time.Since(start)
		_, err = srv.Open(p, addrA)
		mustT(t, err)
		r.serverGotData = time.Since(start)
		return r
	})
}
