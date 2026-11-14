// Package agent is mosey's ssh-agent forwarding (D25; docs/spec/agent.md):
// the session-bind OpenSSH sends for the bootstrap's connection, the strict
// state machine that captures it, the known_hosts pin that ties it to the
// destination, its replay at the head of every agent channel, and the
// relay between a channel and a local agent connection.
//
// It is shaped by spike S3's option (a′): rather than speak SSH itself,
// the client lets the system ssh do the bootstrap with its agent pointed at
// a throwaway capture socket, keeps the one bind ssh sends there, and
// replays it to the user's real agent on every forwarded connection. So the
// agent sees what ssh -A would show it, destination constraints and
// quoin-signer's checks included, and the user's whole ssh config keeps
// working.
//
// After the replayed bind the stream is opaque: mosey parses no agent
// message the far host sends, so extension messages such as
// provenance-v00@bodar.com pass through untouched (D28), and any agent that
// speaks the protocol works (D17). The only agent frames this package reads
// are the capture's (fuzzed) and the length of the one reply to the bind.
package agent
