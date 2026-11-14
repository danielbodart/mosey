// Package netsim is a simulated network for tests: hosts, one-way links
// with loss, delay, jitter, reordering, MTU limits, outages and replayed
// cellular traces, and an adversary that can see, change and inject any
// packet (D18).
//
// Every socket it hands out is a net.PacketConn, so the transport and the
// whole client and server run over it unchanged. It is built to run inside
// testing/synctest: its scheduler waits on ordinary timers, which synctest
// turns into virtual time, so a twenty-minute train journey takes a
// fraction of a second and nothing in a test depends on how fast the
// machine is. Every random choice comes from a PRNG seeded by the network's
// seed, the link and the packet's sequence on that link, so a run is a
// pure function of its seeds as long as each endpoint is a single goroutine
// that depends only on what it reads and on time.Now.
//
// A network belongs to the bubble it was made in: make it inside
// synctest.Test and Close it before the test function returns, or the
// scheduler goroutine outlives the bubble and synctest reports a deadlock.
//
//	synctest.Test(t, func(t *testing.T) {
//		n := netsim.New(1)
//		defer n.Close()
//		client, server := n.NewHost("client"), n.NewHost("server")
//		n.Connect(client, server, netsim.LinkParams{Delay: 20 * time.Millisecond})
//		n.Connect(server, client, netsim.LinkParams{Delay: 20 * time.Millisecond})
//		...
//	})
//
// The scheduler waits on nothing when nothing is in flight, so a test that
// blocks forever on a read is reported by synctest as a deadlock rather than
// spinning through virtual hours.
//
// The design is spike S5's (docs/spikes/s5-netsim-ssp/FINDINGS.md §2),
// rewritten here as production test code. The ideas of a single router
// goroutine and per-link queues come from pion/transport/vnet and
// marcopolo/simnet (read, not copied); neither is a dependency, because
// neither runs under synctest with a seeded per-packet PRNG or replays
// traces.
package netsim
