// quiccmp runs N QUIC (quic-go, RFC 9221 datagrams enabled) handshakes over
// loopback and reports bytes/datagrams per direction, wall time and CPU per
// handshake, so they can be compared with cmd/bdemo (mosey variant B1).
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"math/big"
	"net"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"
)

type counting struct {
	net.PacketConn
	sentB, sentN atomic.Int64
}

func (c *counting) WriteTo(p []byte, a net.Addr) (int, error) {
	c.sentB.Add(int64(len(p)))
	c.sentN.Add(1)
	return c.PacketConn.WriteTo(p, a)
}

func cert() tls.Certificate {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"mosey"}}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
}

func cpu() time.Duration {
	var ru syscall.Rusage
	syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}

func main() {
	n := flag.Int("n", 200, "handshakes")
	flag.Parse()
	crt := cert()
	sconn, _ := net.ListenPacket("udp", "127.0.0.1:0")
	sc := &counting{PacketConn: sconn}
	st := &quic.Transport{Conn: sc}
	qconf := &quic.Config{EnableDatagrams: true}
	ln, err := st.Listen(&tls.Config{Certificates: []tls.Certificate{crt}, NextProtos: []string{"mosey"}}, qconf)
	if err != nil {
		panic(err)
	}
	go func() {
		for {
			c, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			go func() {
				d, err := c.ReceiveDatagram(context.Background())
				if err == nil {
					c.SendDatagram(d)
				}
			}()
		}
	}()
	var curve tls.CurveID
	var wall time.Duration
	var cb, cn, sb, sn int64
	c0 := cpu()
	for i := 0; i < *n; i++ {
		cconn, _ := net.ListenPacket("udp", "127.0.0.1:0")
		cc := &counting{PacketConn: cconn}
		ct := &quic.Transport{Conn: cc}
		s0b, s0n := sc.sentB.Load(), sc.sentN.Load()
		t0 := time.Now()
		conn, err := ct.Dial(context.Background(), sconn.LocalAddr(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"mosey"}}, qconf)
		if err != nil {
			panic(err)
		}
		conn.SendDatagram([]byte("k"))
		if _, err := conn.ReceiveDatagram(context.Background()); err != nil {
			panic(err)
		}
		wall += time.Since(t0)
		curve = conn.ConnectionState().TLS.CurveID
		// bytes up to and including the first echoed datagram
		cb += cc.sentB.Load()
		cn += cc.sentN.Load()
		sb += sc.sentB.Load() - s0b
		sn += sc.sentN.Load() - s0n
		conn.CloseWithError(0, "")
		ct.Close()
	}
	c1 := cpu()
	N := int64(*n)
	fmt.Printf("quic-go handshake+1 datagram echo, n=%d, key share %v\n", *n, curve)
	fmt.Printf("  client->server: %d bytes in %.1f datagrams (mean)\n", cb/N, float64(cn)/float64(N))
	fmt.Printf("  server->client: %d bytes in %.1f datagrams (mean)\n", sb/N, float64(sn)/float64(N))
	fmt.Printf("  wall per handshake+echo (loopback): %v\n", wall/time.Duration(N))
	fmt.Printf("  process CPU per handshake (both ends): %v\n", (c1-c0)/time.Duration(N))
}
