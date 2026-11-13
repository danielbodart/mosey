package bind

import (
	"fmt"
	"io"
	"net"
	"sync"
)

// Prelude is what the client sends on a fresh local agent connection before
// relaying the remote side's first byte: the replayed session-bind (and, for
// option (c), any further extensions such as a hop record). Each reply is
// read and dropped here, never passed to the remote side, which did not ask.
type Prelude struct {
	Name     string
	Contents []byte
	// Optional means an agent that answers failure (an agent that predates
	// the extension, or an unknown extension) does not stop the relay.
	Optional bool
}

// Recorder collects the exact frames the relay wrote to the agent, so the
// quoin test can replay them byte for byte against its own harness.
type Recorder struct {
	mu     sync.Mutex
	Frames [][]byte
}

func (r *Recorder) add(f []byte) {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.Frames = append(r.Frames, append([]byte(nil), f...))
	r.mu.Unlock()
}

// PreludeReply is the agent's answer to one prelude message.
type PreludeReply struct {
	Name string
	Code byte
}

// Relay connects remote (one mosey agent channel) to the agent at
// agentPath. One channel is one agent connection, so a hang-up on the
// remote side closes the agent connection and quoin withdraws its question,
// as it does when the ssh that asked exits.
func Relay(remote net.Conn, agentPath string, prelude []Prelude, rec *Recorder) ([]PreludeReply, error) {
	defer remote.Close()
	ag, err := net.Dial("unix", agentPath)
	if err != nil {
		return nil, err
	}
	defer ag.Close()
	var replies []PreludeReply
	for _, p := range prelude {
		f := ExtensionFrame(p.Name, p.Contents)
		rec.add(f[4:])
		if _, err := ag.Write(f); err != nil {
			return replies, err
		}
		r, err := ReadFrame(ag)
		if err != nil {
			return replies, err
		}
		replies = append(replies, PreludeReply{p.Name, r[0]})
		if r[0] != AgentSuccess && !p.Optional {
			return replies, fmt.Errorf("agent refused %s (reply %d)", p.Name, r[0])
		}
	}
	done := make(chan struct{})
	go func() {
		io.Copy(remote, ag)
		close(done)
	}()
	for {
		f, err := ReadFrame(remote)
		if err != nil {
			break
		}
		rec.add(f)
		if _, err := ag.Write(Frame(f)); err != nil {
			break
		}
	}
	if c, ok := ag.(*net.UnixConn); ok {
		c.CloseWrite()
	}
	<-done
	return replies, nil
}
