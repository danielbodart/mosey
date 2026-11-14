package server

import (
	"errors"
	"io/fs"
	"os"
)

// The agent socket (server.md §2.7, agent.md §4): the login shell's
// SSH_AUTH_SOCK, in the session's private directory beside attach.sock,
// owned by the spawner because proto may not make, bind or accept on a
// filesystem socket. The spawner accepts each connection, checks its
// peer's uid, and hands it to proto (ipc.AgentConn), which carries it to
// the client over an agent channel.
const (
	// agentName is the socket's name in its session's directory.
	agentName = "agent.sock"
	// agentBacklog is the listen backlog [choice]: proto serves at most
	// channel.MaxStreams at once and refuses more, so a deeper queue would
	// only hold connections it will close.
	agentBacklog = 16
)

// AttesterSocket is where a host's quoin-attest takes agent connections
// handed off to it (D28; spike S7's forwarder). It is fixed, and under
// /run, which only root can write: never from the environment or the
// user's files, so a program of the user's cannot point a session at an
// "attester" of its own (agent.md §4.3).
const AttesterSocket = "/run/agent-attest/handoff.sock"

// attesterPresent says whether the host has an attester at path: anything
// there, or anything that cannot be checked, counts, so the hand-off seam
// fails closed (agent.md §4.3). Only "nothing there" is no attester.
func attesterPresent(path string) bool {
	_, err := os.Lstat(path)
	return !errors.Is(err, fs.ErrNotExist)
}

// handOff is the seam for D28's hand-off to quoin-attest: the connection,
// and the upstream end proto would then relay, go to the attester over
// AttesterSocket with SCM_RIGHTS. This slice does not implement it, since
// its wire must carry the handshake hash h (Conn.HandshakeHash), which
// quoin has not yet fixed (docs/mosey-integration.md §1.4–§1.5); so with an
// attester present every agent connection is refused, which is the
// fail-closed half of D28 already in force.
func handOff(conn *os.File) (upstream *os.File, err error) {
	return nil, errHandOffUnimplemented
}

var errHandOffUnimplemented = errors.New("this host has an attester and this mosey cannot hand agent connections to it yet; refusing")
