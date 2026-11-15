package agent

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/danielbodart/mosey/internal/channel"
)

// pipeDatagrams is one end of a lossless in-memory path between two
// muxes; channel's own tests cover loss.
type pipeDatagrams struct {
	in, out chan []byte
}

func (p pipeDatagrams) SendChannel(b []byte) error {
	b = bytes.Clone(b)
	time.AfterFunc(5*time.Millisecond, func() { p.out <- b })
	return nil
}

func (p pipeDatagrams) RecvChannel(ctx context.Context) ([]byte, error) {
	select {
	case b := <-p.in:
		return b, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// muxes runs a server mux and a client mux whose agent channels the
// forwarder serves, until the test ends.
func muxes(t *testing.T, fwd *Forwarder) *channel.Mux {
	a, b := make(chan []byte, 256), make(chan []byte, 256)
	server := channel.NewMux(pipeDatagrams{in: a, out: b}, channel.Config{Role: channel.Server})
	client := channel.NewMux(pipeDatagrams{in: b, out: a}, channel.Config{Role: channel.Client, Accept: fwd.Accept})
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	for _, m := range []*channel.Mux{server, client} {
		wg.Add(1)
		go func() { defer wg.Done(); m.Run(ctx) }()
	}
	t.Cleanup(func() { cancel(); wg.Wait() })
	return server
}

func extension(name string, payload []byte) []byte {
	return frame(append(appendString([]byte{msgExtension}, []byte(name)), payload...)...)
}

// An agent channel reaches the user's agent with ssh's bind first, the
// agent's answer to the bind kept from the far program, and then every
// byte the far program sends, an extension message included, passed both
// ways untouched (agent.md §1, §3; D28).
func TestAnAgentChannelReplaysTheBindThenCarriesTheStreamUntouched(t *testing.T) {
	for _, answer := range []byte{msgSuccess, msgFailure} {
		synctest.Test(t, func(t *testing.T) {
			bind, err := ParseBind(bindFrame(t, hostKey(t), sid(), 1))
			if err != nil {
				t.Fatal(err)
			}
			agentSide, forwarded := net.Pipe()
			fwd := &Forwarder{Bind: bind, Dial: func(context.Context) (net.Conn, error) { return forwarded, nil }}
			server := muxes(t, fwd)

			request := extension("unheard-of@example.com", bytes.Repeat([]byte{0, 0xff, 0x1b, 'x'}, 3000))
			reply := frame(append([]byte{msgSuccess}, bytes.Repeat([]byte("statement"), 500)...)...)
			agentDone := make(chan error, 1)
			go func() {
				// The user's agent: the bind, then the request, exactly.
				got, err := readFrame(agentSide, MaxCaptureFrame)
				if err != nil || !bytes.Equal(got, bind.Frame()) {
					agentDone <- errors.New("the first thing the agent read is not the bind")
					return
				}
				agentSide.Write(frame(answer))
				got, err = readFrame(agentSide, 1<<20)
				if err != nil || !bytes.Equal(got, request) {
					agentDone <- errors.New("the request was changed on the way")
					return
				}
				agentSide.Write(reply)
				agentDone <- nil
				io.Copy(io.Discard, agentSide)
				agentSide.Close()
			}()

			farProgram, local := net.Pipe()
			go Serve(context.Background(), server, local, nil)
			farProgram.Write(request)
			got, err := readFrame(farProgram, 1<<20)
			if err != nil || !bytes.Equal(got, reply) {
				t.Fatalf("the far program read %d bytes (%v), not the agent's reply", len(got), err)
			}
			if err := <-agentDone; err != nil {
				t.Fatal(err)
			}
			farProgram.Close()
		})
	}
}

// An agent the client cannot reach refuses the channel, and the far
// program's connection is closed, as under ssh -A.
func TestAnUnreachableAgentClosesTheFarConnection(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		bind, _ := ParseBind(bindFrame(t, hostKey(t), sid(), 1))
		server := muxes(t, &Forwarder{Bind: bind, Dial: func(context.Context) (net.Conn, error) {
			return nil, errors.New("no agent")
		}})
		farProgram, local := net.Pipe()
		go Serve(context.Background(), server, local, nil)
		go farProgram.Write(frame(msgRequestIdentities))
		if _, err := farProgram.Read(make([]byte, 1)); err == nil {
			t.Error("the far program read something from no agent")
		}
	})
}

// A forwarder with no bind, or asked for another type, refuses.
func TestTheForwarderServesOnlyAgentChannelsWithABind(t *testing.T) {
	dial := func(context.Context) (net.Conn, error) { t.Error("dialled"); return nil, errors.New("no") }
	if _, err := (&Forwarder{Dial: dial}).Accept(context.Background(), 1); !errors.Is(err, channel.ErrRefused) {
		t.Errorf("no bind: %v", err)
	}
	bind, _ := ParseBind(bindFrame(t, hostKey(t), sid(), 1))
	if _, err := (&Forwarder{Dial: dial, Bind: bind}).Accept(context.Background(), 0); !errors.Is(err, channel.ErrRefused) {
		t.Errorf("the terminal's type: %v", err)
	}
}
