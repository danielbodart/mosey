//go:build soak

package server

import (
	"runtime"
	"runtime/debug"
	"sync"
	"time"
)

// soakBuild passes MOSEY_SOAK_* to the roles, so a soak can pick their
// sandbox action (server.md §9). A release build passes nothing.
const soakBuild = true

// churn makes the runtime take its rare paths after the sandbox is on, as
// S4's soaks did: collections, returning memory to the OS, deep stack
// growth, bursts of goroutines, timers. A syscall missing from a policy
// stays hidden until the runtime happens to make it (S4 §3.5).
func churn() {
	go func() {
		for i := 0; ; i++ {
			var wg sync.WaitGroup
			for j := range 32 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					grow(64 + j*8)
					time.Sleep(time.Millisecond)
				}()
			}
			wg.Wait()
			garbage := make([][]byte, 0, 64)
			for range 64 {
				garbage = append(garbage, make([]byte, 32<<10))
			}
			runtime.KeepAlive(garbage)
			runtime.GC()
			if i%10 == 0 {
				debug.FreeOSMemory()
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()
}

func grow(n int) byte {
	var pad [512]byte
	pad[n%512] = byte(n)
	if n == 0 {
		return pad[0]
	}
	return grow(n-1) + pad[n%512]
}
