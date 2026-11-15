package server

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/danielbodart/mosey/internal/bootstrap"
	"github.com/danielbodart/mosey/internal/handshake"
	"github.com/danielbodart/mosey/internal/ipc"
)

// acceptBackoff is how long serveAttach waits after an accept that failed
// for a reason that may pass (EMFILE, ENFILE, ENOMEM, ECONNABORTED)
// before it tries again [choice: long enough not to spin, short beside a
// resume's ssh login].
const acceptBackoff = 100 * time.Millisecond

// serveAttach accepts on the attach socket until it closes, serving at
// most MaxAttachConns connections at once (server.md §2.6).
func (s *spawner) serveAttach() { s.acceptLoop(s.attach.Accept) }

// acceptLoop is serveAttach's loop over accept. Only a closed socket ends
// it: anything else is logged and retried, since a session whose loop had
// ended would run on with nobody able to resume it, and nobody would know
// until `mosey -r` said there was no session.
func (s *spawner) acceptLoop(accept func() (*os.File, error)) {
	for {
		f, err := accept()
		switch {
		case errors.Is(err, os.ErrClosed):
			return
		case errors.Is(err, errForeignPeer):
			s.log.Warn("refused an attach-socket connection", "err", err)
			continue
		case err != nil:
			s.log.Warn("accepting on the attach socket; trying again", "err", err)
			time.Sleep(acceptBackoff)
			continue
		}
		if s.serving.Add(1) > MaxAttachConns {
			s.serving.Add(-1)
			f.Close()
			continue
		}
		go func() {
			defer s.serving.Add(-1)
			defer f.Close()
			if err := s.serveResume(f); err != nil {
				s.log.Warn("a resume failed", "err", err)
			}
		}()
	}
}

// serveResume is one attach-socket exchange: the greeting, then, unless
// the peer is a lister that closes, a ClientLine checked in full before
// proto hears of it, and the credential proto mints for it (bootstrap.md
// §9.2 step 3).
func (s *spawner) serveResume(f *os.File) error {
	if _, err := f.Write(bootstrap.MarshalSessionLine(s.greeting())); err != nil {
		return fmt.Errorf("sending the greeting: %w", err)
	}
	conn, err := ipc.NewConn(f, ipc.Spawner, ipc.Launcher)
	if err != nil {
		return err
	}
	f.SetReadDeadline(time.Now().Add(T2))
	m, err := conn.Recv()
	if ipc.IsEOF(err) {
		return nil // a lister
	}
	if err != nil {
		return fmt.Errorf("reading the client's line: %w", err)
	}
	if _, ok := m.(ipc.Hangup); ok {
		// mosey -kill (bootstrap.md §9.5): the supervision loop hangs the
		// shell up; closing the connection says it was asked.
		select {
		case s.hangups <- struct{}{}:
		default: // one is already on its way
		}
		return nil
	}
	refuse := func(err error) error {
		conn.Send(ipc.Failed{Text: printableASCII(err.Error(), ipc.MaxFailed)})
		return err
	}
	msg, ok := m.(ipc.ClientLine)
	if !ok {
		return refuse(fmt.Errorf("the launcher sent %T", m))
	}
	cl, err := checkResumeLine(msg.Line, s.sid)
	if err != nil {
		return refuse(err)
	}
	r := resumeRequest{public: cl.Public, requester: cl.Holder, hasRequester: cl.HasHolder, reply: make(chan []byte, 1)}
	timeout := time.NewTimer(T3)
	defer timeout.Stop()
	select {
	case s.resumes <- r:
	case <-timeout.C:
		return refuse(errors.New("the session is busy"))
	}
	select {
	case line, ok := <-r.reply:
		if !ok {
			return refuse(errors.New("the session did not mint a credential"))
		}
		err := conn.Send(ipc.Ready{Line: line})
		clear(line)
		if err != nil {
			return fmt.Errorf("sending the credential: %w", err)
		}
		s.log.Info("resume: credential sent")
		return nil
	case <-timeout.C:
		// The line may still come; whoever sent it wipes it.
		go func() {
			if line, ok := <-r.reply; ok {
				clear(line)
			}
		}()
		return refuse(errors.New("the session did not answer in time"))
	}
}

// checkResumeLine is what the spawner checks of a resuming client's line
// before proto hears of it (server.md §2.6): the whole canonical parse, a
// resume of this session (the launcher chose it, and checked any holder,
// under its lock), and a key proto can mint for. A holder is only a label
// for the hold (§9.2.2): the launcher has already said whose the session
// is. The client's software version is never compared with the session's
// (D8 V1): any release's client attaches, and the handshake negotiates
// what the two speak.
func checkResumeLine(line []byte, sid [16]byte) (bootstrap.ClientLine, error) {
	cl, err := bootstrap.ParseClientLine(line)
	switch {
	case err != nil:
		return cl, fmt.Errorf("the client's line: %w", err)
	case cl.Attach != bootstrap.AttachResume:
		return cl, errors.New("a new session asked of a running one")
	case cl.SessionID != sid:
		return cl, errors.New("a resume of another session")
	}
	if err := handshake.CheckPublicKey(cl.Public); err != nil {
		return cl, err
	}
	return cl, nil
}

// checkResumed is §3.4's check of a credential minted for a resume: as at
// the bootstrap, and for this session.
func (s *spawner) checkResumed(line []byte) error {
	if err := checkCredential(line, s.advertised, s.port, s.cfg.Version, s.name); err != nil {
		return err
	}
	cl, _ := bootstrap.ParseCredentialLine(line)
	defer clear(cl.PSK[:])
	if !bytes.Equal(cl.SessionID[:], s.sid[:]) {
		return errors.New("a credential for another session")
	}
	return nil
}

// greeting is what the attach socket says first (bootstrap.md §9.2.1): what
// proto last said, unless a resume's credential is out, which holds the
// session as attached until it can no longer be confirmed.
func (s *spawner) greeting() bootstrap.SessionLine {
	s.greetMu.Lock()
	defer s.greetMu.Unlock()
	g := bootstrap.SessionLine{
		SoftwareVersion: s.cfg.Version, AttachMin: bootstrap.AttachMin, AttachMax: bootstrap.AttachMax,
		SessionID: s.sid, Name: s.name,
		Started: s.started, State: s.state, Since: s.since, Peer: s.peer,
		Holder: s.holder, HasHolder: s.hasHolder,
	}
	if time.Now().Before(s.holdUntil) {
		g.State, g.Since, g.Holder, g.HasHolder = bootstrap.SessionAttached, s.holdFrom, s.hold, true
		if s.hasHoldOwner {
			// A reconnect's hold is the reconnecting client's: if that try
			// is dropped (roaming won, §9.2.2) and the path goes quiet
			// again, the same client's next try must still find the
			// session its own, not "taken" by a credential nobody used.
			g.Holder = s.holdOwner
		}
	}
	return g
}

// setAttached records that a client holds the session with credential
// cred, from peer, for the greeting; any resume's hold is over.
func (s *spawner) setAttached(cred [8]byte, peer netip.AddrPort) {
	s.greetMu.Lock()
	defer s.greetMu.Unlock()
	s.state, s.since, s.holder, s.hasHolder = bootstrap.SessionAttached, time.Now(), cred, true
	s.holdUntil = time.Time{}
	if peer.IsValid() {
		s.peer = peer
	}
}

// setDetached records that no client holds the session. It keeps the
// last peer, so a list still says where it was.
func (s *spawner) setDetached() {
	s.greetMu.Lock()
	defer s.greetMu.Unlock()
	s.state, s.since, s.hasHolder = bootstrap.SessionDetached, time.Now(), false
	s.holdUntil = time.Time{}
}

// holdFor marks the session held by a resume's credential for that
// credential's life (bootstrap.md §9.2 "The lock"), on behalf of the
// reconnecting client whose credential was requester, if any (§9.2.2).
func (s *spawner) holdFor(cred, requester [8]byte, hasRequester bool) {
	s.greetMu.Lock()
	defer s.greetMu.Unlock()
	ttl := s.holdTTL
	if ttl == 0 {
		ttl = handshake.CredentialTTL
	}
	now := time.Now()
	s.hold, s.holdFrom, s.holdUntil = cred, now, now.Add(ttl)
	s.holdOwner, s.hasHoldOwner = requester, hasRequester
}

// serveAgent accepts on the agent socket until it closes, and passes each
// connection from this user to the supervision loop for proto, which relays
// it as an opaque byte stream, as ssh -A does (D28). Only a closed socket
// ends it.
func (s *spawner) serveAgent() {
	for {
		f, err := s.agent.Accept()
		switch {
		case errors.Is(err, os.ErrClosed):
			return
		case errors.Is(err, errForeignPeer):
			s.log.Warn("refused an agent-socket connection", "err", err)
			continue
		case err != nil:
			s.log.Warn("accepting on the agent socket; trying again", "err", err)
			time.Sleep(acceptBackoff)
			continue
		}
		select {
		case s.agentConns <- f:
		case <-s.agentDone:
			f.Close()
			return
		}
	}
}
