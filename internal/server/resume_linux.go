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
	refuse := func(err error) error {
		conn.Send(ipc.Failed{Text: printableASCII(err.Error(), ipc.MaxFailed)})
		return err
	}
	msg, ok := m.(ipc.ClientLine)
	if !ok {
		return refuse(fmt.Errorf("the launcher sent %T", m))
	}
	cl, err := checkResumeLine(msg.Line, s.cfg.Version, s.sid)
	if err != nil {
		return refuse(err)
	}
	r := resumeRequest{public: cl.Public, reply: make(chan []byte, 1)}
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
// resume of this session (or AnySession, which the launcher resolved to
// this one), this version, and a key proto can mint for.
func checkResumeLine(line []byte, version string, sid [16]byte) (bootstrap.ClientLine, error) {
	cl, err := bootstrap.ParseClientLine(line)
	switch {
	case err != nil:
		return cl, fmt.Errorf("the client's line: %w", err)
	case !cl.Resume:
		return cl, errors.New("a new session asked of a running one")
	case cl.SessionID != sid && cl.SessionID != bootstrap.AnySession:
		return cl, errors.New("a resume of another session")
	case cl.SoftwareVersion != version:
		return cl, fmt.Errorf("the client is version %s, the session %s", printableASCII(cl.SoftwareVersion, 64), version)
	}
	if err := handshake.CheckPublicKey(cl.Public); err != nil {
		return cl, err
	}
	return cl, nil
}

// checkResumed is §3.4's check of a credential minted for a resume: as at
// the bootstrap, and for this session.
func (s *spawner) checkResumed(line []byte) error {
	if err := checkCredential(line, s.advertised, s.port, s.cfg.Version); err != nil {
		return err
	}
	cl, _ := bootstrap.ParseCredentialLine(line)
	defer clear(cl.PSK[:])
	if !bytes.Equal(cl.SessionID[:], s.sid[:]) {
		return errors.New("a credential for another session")
	}
	return nil
}

// greeting is what the attach socket says first (bootstrap.md §9.2.1).
func (s *spawner) greeting() bootstrap.SessionLine {
	s.greetMu.Lock()
	defer s.greetMu.Unlock()
	return bootstrap.SessionLine{
		SoftwareVersion: s.cfg.Version, SessionID: s.sid,
		Started: s.started, State: s.state, Since: s.since, Peer: s.peer,
	}
}

// setState records what proto says of the client, for the greeting. A
// detach keeps the last peer, so a list still says where it was.
func (s *spawner) setState(st bootstrap.SessionState, peer netip.AddrPort) {
	s.greetMu.Lock()
	defer s.greetMu.Unlock()
	s.state, s.since = st, time.Now()
	if peer.IsValid() {
		s.peer = peer
	}
}

// serveAgent accepts on the agent socket until it closes, and passes each
// connection from this user to the supervision loop for proto, unless the
// host has an attester, which this mosey cannot yet hand off to: then the
// connection is refused (agent.md §4.3, fail closed). Only a closed socket
// ends it.
func (s *spawner) serveAgent() {
	warned := false
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
		if attesterPresent(AttesterSocket) {
			up, err := handOff(f)
			if err != nil {
				if !warned {
					s.log.Warn("refusing agent connections", "attester", AttesterSocket, "err", err)
					warned = true
				}
				f.Close()
				continue
			}
			f.Close()
			f = up
		}
		select {
		case s.agentConns <- f:
		case <-s.agentDone:
			f.Close()
			return
		}
	}
}
