package transport

import (
	"context"
	"errors"
	"net"
	"testing"
	"testing/synctest"
	"time"
)

// The server's shell exits: End reaches the client, which reports why and
// closes with ErrEnded, and the server's own connection is closed too.
func TestEndTellsThePeerTheSessionIsOver(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newSetup(t, 20*time.Millisecond)
		client, server, _ := s.connect(clientAddr.String())
		exchange(t, client, server, "before")
		if err := server.End(EndShellExited); err != nil {
			t.Fatal(err)
		}
		if _, err := server.Recv(context.Background()); !errors.Is(err, net.ErrClosed) {
			t.Errorf("the server's Recv after End: %v", err)
		}
		synctest.Wait()
		if _, err := client.Recv(context.Background()); !errors.Is(err, ErrEnded) {
			t.Fatalf("the client's Recv: %v, not ErrEnded", err)
		}
		var got []Ended
		for _, ev := range events(client) {
			if e, ok := ev.(Ended); ok {
				got = append(got, e)
			}
		}
		if len(got) != 1 || got[0].Reason != EndShellExited {
			t.Errorf("the client reported %v", got)
		}
	})
}

// END is repeated, so a session still ends when the first copy is lost;
// the client quitting ends the server's connection the same way.
func TestEndGetsThroughWhenTheFirstCopyIsLost(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newSetup(t, 20*time.Millisecond)
		client, server, _ := s.connect(clientAddr.String())
		exchange(t, client, server, "before")
		synctest.Wait() // nothing else in flight: the next packet is END
		dropped := 0
		s.net.setTap(func(p memPacket) []memPacket {
			if p.from == clientAddr && dropped == 0 {
				dropped++
				return nil
			}
			return []memPacket{p}
		})
		if err := client.End(EndDetached); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if read(s.net, &dropped) != 1 {
			t.Fatal("the tap dropped nothing")
		}
		if _, err := server.Recv(context.Background()); !errors.Is(err, ErrEnded) {
			t.Fatalf("the server's Recv: %v, not ErrEnded", err)
		}
	})
}

// End sends its copies only while the connection is open: after Close it
// sends nothing.
func TestEndAfterCloseSendsNothing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newSetup(t, 20*time.Millisecond)
		client, server, _ := s.connect(clientAddr.String())
		exchange(t, client, server, "before")
		sent := 0
		s.net.setTap(func(p memPacket) []memPacket {
			sent++
			return []memPacket{p}
		})
		client.Close()
		if err := client.End(EndDetached); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if n := read(s.net, &sent); n != 0 {
			t.Errorf("%d packets after Close", n)
		}
	})
}
