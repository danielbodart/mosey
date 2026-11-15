package server

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
