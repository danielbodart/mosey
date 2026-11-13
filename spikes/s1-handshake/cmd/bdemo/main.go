// bdemo runs N mosey variant-B1 handshakes over real loopback UDP sockets,
// each followed by one echoed transport datagram, and reports the same
// numbers as ../quiccmp for comparison. Credentials are handed over
// in-process (standing in for the SSH channel).
package main

import (
	"flag"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"

	"mosey.spike/s1-handshake/hs"
)

func cpu() time.Duration {
	var ru syscall.Rusage
	syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}

func main() {
	n := flag.Int("n", 200, "handshakes")
	mode := flag.Int("mode", 1, "1 = B1 (server KEM key over SSH), 2 = B2 (client KEM key in msg1)")
	flag.Parse()
	hello := hs.Hello{Proto: 1, Channels: []string{"terminal", "agent@mosey"}}
	cfg := hs.DefaultConfig()

	sconn, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	type job struct {
		srv *hs.BServer
		ack chan struct{}
	}
	jobs := make(chan job)
	go func() { // server loop
		buf := make([]byte, 2048)
		for j := range jobs {
			var sess *hs.Session
			for sess == nil {
				k, from, _ := sconn.ReadFromUDPAddrPort(buf)
				resp, s, _, err := j.srv.HandleInit(buf[:k])
				if err != nil {
					continue
				}
				sconn.WriteToUDPAddrPort(resp, from)
				sess = s
			}
			k, from, _ := sconn.ReadFromUDPAddrPort(buf)
			pt, err := sess.Open(buf[:k], from)
			if err != nil {
				panic(err)
			}
			p, _ := sess.Seal(pt)
			sconn.WriteToUDPAddrPort(p, from)
			j.ack <- struct{}{}
		}
	}()
	saddr := sconn.LocalAddr().(*net.UDPAddr).AddrPort()
	var cb, cn, sb, sn int64
	var wall time.Duration
	c0 := cpu()
	buf := make([]byte, 2048)
	for i := 0; i < *n; i++ {
		srv, cred, err := hs.NewBServer(hs.BMode(*mode), hello, cfg) // minted at SSH bootstrap
		if err != nil {
			panic(err)
		}
		ack := make(chan struct{})
		jobs <- job{srv, ack}
		cconn, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		t0 := time.Now()
		cli, m1, err := hs.NewBClient(cred, hello, cfg)
		if err != nil {
			panic(err)
		}
		cconn.WriteToUDPAddrPort(m1, saddr)
		cb += int64(len(m1))
		cn++
		k, _, _ := cconn.ReadFromUDPAddrPort(buf)
		sb += int64(k)
		sn++
		sess, _, err := cli.HandleResp(buf[:k])
		if err != nil {
			panic(err)
		}
		p, _ := sess.Seal([]byte("k"))
		cconn.WriteToUDPAddrPort(p, saddr)
		cb += int64(len(p))
		cn++
		k, _, _ = cconn.ReadFromUDPAddrPort(buf)
		sb += int64(k)
		sn++
		if _, err := sess.Open(buf[:k], netip.AddrPort{}); err != nil {
			panic(err)
		}
		wall += time.Since(t0)
		<-ack
		cconn.Close()
	}
	c1 := cpu()
	N := int64(*n)
	fmt.Printf("mosey B%d handshake+1 datagram echo, n=%d, KEM X-Wing (MLKEM768-X25519)\n", *mode, *n)
	fmt.Printf("  client->server: %d bytes in %.1f datagrams (mean)\n", cb/N, float64(cn)/float64(N))
	fmt.Printf("  server->client: %d bytes in %.1f datagrams (mean)\n", sb/N, float64(sn)/float64(N))
	fmt.Printf("  wall per handshake+echo (loopback, excl. credential minting): %v\n", wall/time.Duration(N))
	fmt.Printf("  process CPU per handshake (both ends, incl. minting): %v\n", (c1-c0)/time.Duration(N))
}
