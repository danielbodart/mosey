package netsim

import (
	"errors"
	"hash/fnv"
	"math"
	"math/rand/v2"
	"net"
	"net/netip"
	"time"

	"github.com/danielbodart/mosey/internal/wire"
)

// Profile is a named set of network conditions for both directions of a
// client-server path, with any scripted events (outages, roams), for tests
// to run the same workload across: lan, hotel-wifi, train, hsr and the
// lte-driving trace of S5 §2.
type Profile struct {
	Name string
	// Source is where the profile's numbers come from: a paper, a trace,
	// or our own choice ([D]).
	Source string
	// Setup connects client and server with the profile's links and
	// schedules its events. client is the socket a roam rebinds.
	//
	// Its random choices (when the outages and roams fall) derive from the
	// network's seed, so a test sweeps them by sweeping seeds. Events are
	// scripted for the first ProfileSpan of the run; after that the links
	// keep their loss and delay but have no more outages or roams.
	Setup func(n *Network, client, server *Host, clientConn *Conn)
}

// ProfileSpan is how far into a run a profile scripts its events: longer
// than any test runs, short enough to schedule cheaply.
const ProfileSpan = 6 * time.Hour

// ProfileMTU is the MTU every profile's links have: the largest UDP payload
// mosey may send (D5, wire.MaxDatagram). A layer that sends more is caught
// in every network test, because the packet never arrives.
const ProfileMTU = wire.MaxDatagram

// LTECarriers are the carriers whose LTE driving traces LTEDriving replays.
var LTECarriers = []string{"Verizon", "TMobile", "ATT"}

// Profiles are the fixtures every network test can range over. The ones
// that need a Mahimahi trace are left out when it is absent.
//
// Call it outside the synctest bubble, since it may fetch a trace (see
// MahimahiTrace), and give each run a fresh Network.
func Profiles() []Profile {
	ps := []Profile{LAN(), HotelWifi(), Train(), HSR()}
	if p, err := LTEDriving("Verizon"); err == nil {
		ps = append(ps, p)
	}
	return ps
}

// LAN is a clean wired LAN: half a millisecond round trip, nothing lost.
// It is the control, against which every other profile's cost is measured.
func LAN() Profile {
	return Profile{
		Name:   "lan",
		Source: "control [D]",
		Setup: func(n *Network, client, server *Host, _ *Conn) {
			l := LinkParams{Delay: 250 * time.Microsecond, MTU: ProfileMTU}
			n.Connect(client, server, l)
			n.Connect(server, client, l)
		},
	}
}

// HotelWifi is a short base round trip with bufferbloat spikes from other
// guests' traffic, bursty loss from contention, the access point
// reassociating (8 s outages, two every twenty minutes on average) and the
// address changing (DHCP or a captive NAT, once every twenty minutes on
// average). Modelled [D], S5 §2.
func HotelWifi() Profile {
	return Profile{
		Name:   "hotel-wifi",
		Source: "modelled [D], S5 §2",
		Setup: func(n *Network, client, server *Host, clientConn *Conn) {
			r := n.profileRand("hotel-wifi")
			l := LinkParams{
				Delay: 15 * time.Millisecond, Jitter: 8 * time.Millisecond, JitterCap: 80 * time.Millisecond,
				MTU:    ProfileMTU,
				GE:     &GilbertElliott{MeanGood: 20 * time.Second, MeanBad: 400 * time.Millisecond, GoodLoss: 0.01, BadLoss: 0.4},
				Spikes: &DelaySpikes{P: 0.03, Min: 100 * time.Millisecond, Max: 600 * time.Millisecond},
			}
			l.Outages = poisson(r, 10*time.Minute, func() time.Duration { return 8 * time.Second })
			connect(n, client, server, l, l)
			roam(n, clientConn, poissonTimes(r, 20*time.Minute))
		},
	}
}

// Train is a commuter train on LTE: about 70 ms base round trip with
// jitter, delay spikes and long fades of bursty loss; tunnels and cuttings
// as outages (on average every two minutes, of lognormal length with a
// median of 6 s, from 1 to 45 s); and the address changing (a CGNAT or cell
// change) about every ten minutes. Modelled [D], S5 §2.
func Train() Profile {
	return Profile{
		Name:   "train",
		Source: "modelled [D], S5 §2",
		Setup: func(n *Network, client, server *Host, clientConn *Conn) {
			r := n.profileRand("train")
			l := LinkParams{
				Delay: 35 * time.Millisecond, Jitter: 15 * time.Millisecond, JitterCap: 200 * time.Millisecond,
				MTU:    ProfileMTU,
				GE:     &GilbertElliott{MeanGood: 30 * time.Second, MeanBad: 1500 * time.Millisecond, GoodLoss: 0.005, BadLoss: 0.5},
				Spikes: &DelaySpikes{P: 0.02, Min: 200 * time.Millisecond, Max: 1500 * time.Millisecond},
			}
			l.Outages = poisson(r, 2*time.Minute, func() time.Duration {
				return min(max(lognormal(r, 6*time.Second, 0.9), time.Second), 45*time.Second)
			})
			connect(n, client, server, l, l)
			var roams []time.Duration
			for t := 10 * time.Minute; t < ProfileSpan; t += 10 * time.Minute {
				roams = append(roams, t+time.Duration(r.Int64N(int64(time.Minute))))
			}
			roam(n, clientConn, roams)
		},
	}
}

// HSR is high-speed rail at 300 km/h, informed by POLYCORN (NSDI 2023): a
// handover every 5 to 10 s (its §1), of which 6% fail into a blackout of 1
// to 10 s and the rest disrupt for 30 to 100 ms (§2.3), with bursty loss
// (§4.5). The base delay, jitter and spikes were chosen [D] so the round
// trip's quartiles land near the paper's 123/185/315 ms for carrier A
// (§2.2), which TestHSRRoundTripMatchesPOLYCORN checks.
func HSR() Profile {
	return Profile{
		Name:   "hsr",
		Source: "POLYCORN-informed [D], S5 §2",
		Setup: func(n *Network, client, server *Host, _ *Conn) {
			r := n.profileRand("hsr")
			l := LinkParams{
				Delay: 45 * time.Millisecond, Jitter: 15 * time.Millisecond, JitterCap: 400 * time.Millisecond,
				MTU:    ProfileMTU,
				GE:     &GilbertElliott{MeanGood: 5 * time.Second, MeanBad: 300 * time.Millisecond, GoodLoss: 0.005, BadLoss: 0.2},
				Spikes: &DelaySpikes{P: 0.22, Min: 50 * time.Millisecond, Max: 350 * time.Millisecond},
			}
			for t := time.Duration(0); ; {
				t += time.Duration(5+r.IntN(5)) * time.Second
				if t >= ProfileSpan {
					break
				}
				d := time.Duration(30+r.IntN(70)) * time.Millisecond
				if r.Float64() < 0.06 {
					d = time.Second + time.Duration(r.Int64N(int64(9*time.Second)))
				}
				l.Outages = append(l.Outages, Window{Start: t, End: t + d})
				t += d
			}
			connect(n, client, server, l, l)
		},
	}
}

// LTEDriving replays a carrier's Mahimahi LTE driving traces, the uplink's
// for the client's link and the downlink's for the server's, with 30 ms of
// propagation after the bottleneck [D] and a 150 kB drop-tail queue [D]
// (S5 §2). The traces' own gaps of a second or more are its outages. It
// fails if the traces cannot be had (see MahimahiTrace).
func LTEDriving(carrier string) (Profile, error) {
	up, err := MahimahiTrace(carrier + "-LTE-driving.up")
	if err != nil {
		return Profile{}, err
	}
	down, err := MahimahiTrace(carrier + "-LTE-driving.down")
	if err != nil {
		return Profile{}, err
	}
	name := "lte-driving"
	if carrier != "Verizon" {
		name += "-" + carrier
	}
	link := func(t *Trace) LinkParams {
		return LinkParams{Delay: 30 * time.Millisecond, MTU: ProfileMTU, Trace: t, QueueBytes: 150_000}
	}
	return Profile{
		Name:   name,
		Source: "Mahimahi " + carrier + "-LTE-driving traces at " + mahimahiCommit[:12] + ", S5 §2",
		Setup: func(n *Network, client, server *Host, _ *Conn) {
			connect(n, client, server, link(up), link(down))
		},
	}, nil
}

func connect(n *Network, client, server *Host, up, down LinkParams) {
	n.Connect(client, server, up)
	n.Connect(server, client, down)
}

// profileRand is the stream a profile draws its events from: the network's
// seed, kept apart from every link's and every other profile's.
func (n *Network) profileRand(name string) *rand.Rand {
	h := fnv.New64a()
	h.Write([]byte(name))
	return rand.New(rand.NewPCG(mix(n.seed, h.Sum64()), 0x9f0f11e))
}

// poisson scripts outages over ProfileSpan, starting on average every mean
// apart, each as long as length says.
func poisson(r *rand.Rand, mean time.Duration, length func() time.Duration) []Window {
	var ws []Window
	for t := time.Duration(0); ; {
		t += time.Duration(r.ExpFloat64() * float64(mean))
		if t >= ProfileSpan {
			return ws
		}
		d := length()
		ws = append(ws, Window{Start: t, End: t + d})
		t += d
	}
}

// poissonTimes are instants over ProfileSpan, on average mean apart.
func poissonTimes(r *rand.Rand, mean time.Duration) []time.Duration {
	var ts []time.Duration
	for t := time.Duration(0); ; {
		t += time.Duration(r.ExpFloat64() * float64(mean))
		if t >= ProfileSpan {
			return ts
		}
		ts = append(ts, t)
	}
}

func lognormal(r *rand.Rand, median time.Duration, sigma float64) time.Duration {
	return time.Duration(math.Exp(r.NormFloat64()*sigma) * float64(median))
}

// roam schedules the client's socket to move to a new address at each of
// times, measured from the network's start.
func roam(n *Network, c *Conn, times []time.Duration) {
	if c == nil {
		return
	}
	for i, t := range times {
		n.At(n.start.Add(t), func() {
			// Should a test hold the next address already, try the ones
			// after it: a roam must not quietly not happen while the
			// socket is open.
			for k := 0; k < 1000; k++ {
				err := c.Rebind(roamAddress(c.addrPort(), i+1+k*len(times)))
				if err == nil || errors.Is(err, net.ErrClosed) {
					return
				}
			}
			panic("netsim: no free address to roam to")
		})
	}
}

// roamAddress is where a client's i'th roam takes it: a new address in the
// shared address space of RFC 6598, which carrier-grade NATs use, or in the
// IPv6 documentation prefix (RFC 3849) for an IPv6 client, with the port
// kept.
func roamAddress(from netip.AddrPort, i int) netip.AddrPort {
	if from.Addr().Is4() {
		return netip.AddrPortFrom(netip.AddrFrom4([4]byte{100, 64 + byte(i>>16&0x3f), byte(i >> 8), byte(i)}), from.Port())
	}
	a := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff}
	a[12], a[13], a[14], a[15] = byte(i>>24), byte(i>>16), byte(i>>8), byte(i)
	return netip.AddrPortFrom(netip.AddrFrom16(a), from.Port())
}

// addrPort is the socket's address now.
func (c *Conn) addrPort() netip.AddrPort {
	c.net.mu.Lock()
	defer c.net.mu.Unlock()
	return c.addr
}
