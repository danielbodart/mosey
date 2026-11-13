package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"
)

// runClient: client PORT KEY [idle-ms]. Sends each stdin line (+"\n") as a
// keystroke packet, prints decrypted screen bytes, exits idle-ms after stdin
// EOF with no further output.
func runClient(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("client PORT KEY [idle-ms]")
	}
	port, _ := strconv.Atoi(args[0])
	key, err := base64.StdEncoding.DecodeString(args[1])
	if err != nil {
		return err
	}
	idle := 1500 * time.Millisecond
	if len(args) > 2 {
		ms, _ := strconv.Atoi(args[2])
		idle = time.Duration(ms) * time.Millisecond
	}
	s, err := newSealer(key, dirC2S)
	if err != nil {
		return err
	}
	c, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		return err
	}
	got := make(chan struct{}, 1024)
	go func() {
		buf := make([]byte, 2048)
		for {
			n, err := c.Read(buf)
			if err != nil {
				return
			}
			pt, err := s.open(buf[:n])
			if err != nil {
				continue
			}
			os.Stdout.Write(pt)
			got <- struct{}{}
		}
	}()
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		c.Write(s.seal([]byte(sc.Text() + "\n")))
		time.Sleep(50 * time.Millisecond)
	}
	t := time.NewTimer(idle)
	for {
		select {
		case <-got:
			t.Reset(idle)
		case <-t.C:
			return nil
		}
	}
}
