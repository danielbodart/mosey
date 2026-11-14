package netsim

// Profile is a named set of network conditions for both directions of a
// client-server path, with any scripted events (outages, roams), for tests
// to run the same workload across: wired, hotel-wifi, train, hsr and the
// lte-driving traces of S5 §2.
type Profile struct {
	Name string
	// Setup connects client and server with the profile's links and
	// schedules its events. client is the socket a roam rebinds.
	Setup func(n *Network, client, server *Host, clientConn *Conn)
}

// Profiles are the fixtures every network test can range over. The ones
// that need a Mahimahi trace are left out when it is absent.
func Profiles() []Profile {
	panic("TODO slice 1")
}
