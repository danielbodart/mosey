package main

import (
	"fmt"
	"os"
	"os/exec"
	"sort"
	"time"

	"mosey.spike/s4-privsep/sandbox"
)

// runBenchIPC measures the cost the process split adds per packet: a
// 1200-byte message to a sandboxed child over SOCK_SEQPACKET and back,
// through Go's netpoller on both sides (what the server does).
func runBenchIPC() error {
	ours, theirs, err := seqpacketPair("bench")
	if err != nil {
		return err
	}
	self, _ := os.Executable()
	c := exec.Command(self, "bench-ipc-child")
	c.ExtraFiles = []*os.File{theirs}
	c.Stderr = os.Stderr
	c.Env = childEnv()
	if err := c.Start(); err != nil {
		return err
	}
	theirs.Close()
	msg := make([]byte, 1200)
	buf := make([]byte, 2048)
	const warm, n = 2000, 50000
	lat := make([]time.Duration, 0, n)
	for i := 0; i < warm+n; i++ {
		t0 := time.Now()
		ours.Write(msg)
		ours.Read(buf)
		if i >= warm {
			lat = append(lat, time.Since(t0))
		}
	}
	ours.Close()
	c.Wait()
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	fmt.Printf("seqpacket round trip (1200 B, sandbox=%s): p50=%v p90=%v p99=%v p99.9=%v max=%v\n",
		env("MOSEY_SPIKE_SANDBOX", "both"), lat[n/2], lat[n*9/10], lat[n*99/100], lat[n*999/1000], lat[n-1])
	return nil
}

func runBenchIPCChild() error {
	ipc, err := ipcConn(fdUDP, "bench") // fd 3
	if err != nil {
		return err
	}
	applySandbox("bench-child", sandbox.EmuPolicy(seccompAction()))
	buf := make([]byte, 2048)
	for {
		n, err := ipc.Read(buf)
		if err != nil {
			return nil
		}
		ipc.Write(buf[:n])
	}
}
