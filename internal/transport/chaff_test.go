package transport

import (
	"context"
	"testing"
	"testing/synctest"
	"time"
)

func TestAChaffFrameIsTheSizeAskedForAndSignalsThePeerWithoutReachingRecv(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newSetup(t, 10*time.Millisecond)
		client, server, _ := s.connect(clientAddr.String())
		var sizes []int
		s.net.setTap(func(p memPacket) []memPacket {
			if p.to == serverAddr {
				sizes = append(sizes, len(p.data))
			}
			return []memPacket{p}
		})
		// 40 is the client's padding floor (ssp.md §9.2): the chaff must be
		// the size of a keystroke's sealed plaintext.
		if err := client.SendChaff(40); err != nil {
			t.Fatal(err)
		}
		select {
		case <-server.ChaffArrived():
		case <-time.After(time.Second):
			t.Fatal("the server was not told the chaff arrived")
		}
		if got := read(s.net, &sizes); len(got) != 1 || got[0] != 40+headerSize+16 {
			t.Errorf("chaff went out as %v; want one datagram of the 40-byte sealed plaintext plus %d", got, headerSize+16)
		}
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		if p, err := server.Recv(ctx); err == nil {
			t.Errorf("chaff reached Recv as %x", p)
		}
		exchange(t, client, server, "still fine")
	})
}

func TestChaffOutsideTheFrameLimitsIsRefused(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newSetup(t, 10*time.Millisecond)
		client, _, _ := s.connect(clientAddr.String())
		for _, size := range []int{0, FrameOverhead + MaxPayload + 1} {
			if err := client.SendChaff(size); err == nil {
				t.Errorf("SendChaff(%d) was sent", size)
			}
		}
		if err := client.SendChaff(FrameOverhead + MaxPayload); err != nil {
			t.Errorf("the largest chaff frame: %v", err)
		}
	})
}
