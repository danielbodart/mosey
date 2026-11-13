//go:build darwin

// seatbelt-probe: cross-compiled only. On a Mac it would apply
// pure-computation and then show what still works (to be run by Dan:
// see FINDINGS "Open questions").
package main

import (
	"fmt"
	"net"
	"os"

	"mosey.spike/s4-privsep/seatbelt"
)

func main() {
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		panic(err)
	}
	if err := seatbelt.Init(seatbelt.PureComputation); err != nil {
		fmt.Println("sandbox_init:", err)
		os.Exit(1)
	}
	_, err = os.ReadFile("/etc/hosts")
	fmt.Println("read /etc/hosts:", err)
	_, err = net.Dial("tcp", "127.0.0.1:22")
	fmt.Println("new TCP connect:", err)
	_, err = udp.WriteToUDP([]byte("x"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9})
	fmt.Println("sendto on pre-opened UDP socket (roaming needs this):", err)
}
