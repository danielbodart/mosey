//go:build linux

package hs

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"unsafe"
)

// TestKEMKeyResidue measures whether a dropped X-Wing private key's seed is
// still present anywhere in this process's writable memory after a GC.
// It scans /proc/self/mem for the 32-byte seed (needle kept masked; the
// one unmasked copy and the scan buffer are outside the scanned ranges).
// Run with MOSEY_MEMSCAN=1, with and without GOEXPERIMENT=runtimesecret.
func TestKEMKeyResidue(t *testing.T) {
	if os.Getenv("MOSEY_MEMSCAN") == "" {
		t.Skip("set MOSEY_MEMSCAN=1")
	}
	const trials = 20
	var mask [32]byte
	rand.Read(mask[:])
	scanBuf, err := syscall.Mmap(-1, 0, 1<<20, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_ANON|syscall.MAP_PRIVATE)
	mustT(t, err)
	needle, err := syscall.Mmap(-1, 0, 4096, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_ANON|syscall.MAP_PRIVATE)
	mustT(t, err)
	// positive control: a LIVE key must be found, or the scan is broken
	live := 0
	for i := 0; i < 5; i++ {
		sk, _, _ := kemGenerate()
		b, _ := sk.Bytes() // NB: crypto/hpke returns its internal seed slice, not a copy
		copy(needle, b)
		if scanFor(t, needle[:32], scanBuf, needle) {
			live++
		}
		clear(needle[:32])
		runtime.KeepAlive(sk)
	}
	if live == 0 {
		t.Fatal("positive control failed: live key not found by the scan")
	}
	found := 0
	for i := 0; i < trials; i++ {
		var masked [32]byte
		func() {
			sk, _, err := kemGenerate()
			mustT(t, err)
			secretDo(func() {
				b, _ := sk.Bytes() // internal slice: do not clear (that would erase the key's seed)
				for j := range masked {
					masked[j] = b[j] ^ mask[j]
				}
			})
			runtime.KeepAlive(sk)
		}()
		runtime.GC()
		runtime.GC()
		for j := range masked {
			needle[j] = masked[j] ^ mask[j]
		}
		if scanFor(t, needle[:32], scanBuf, needle) {
			found++
		}
		clear(needle[:32])
	}
	t.Logf("runtimesecret=%v: dropped X-Wing seed still in memory after 2x GC in %d/%d trials", secretEnabled, found, trials)
	fmt.Printf("MEMSCAN runtimesecret=%v residue=%d/%d (positive control: live key found %d/5)\n", secretEnabled, found, trials, live)
}

func scanFor(t *testing.T, pat, buf, skip []byte) bool {
	maps, err := os.Open("/proc/self/maps")
	mustT(t, err)
	defer maps.Close()
	mem, err := os.Open("/proc/self/mem")
	mustT(t, err)
	defer mem.Close()
	bufLo := uintptr(unsafe.Pointer(&buf[0]))
	skipLo := uintptr(unsafe.Pointer(&skip[0]))
	sc := bufio.NewScanner(maps)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 || !strings.HasPrefix(f[1], "rw") {
			continue
		}
		lohi := strings.SplitN(f[0], "-", 2)
		lo, _ := strconv.ParseUint(lohi[0], 16, 64)
		hi, _ := strconv.ParseUint(lohi[1], 16, 64)
		if uintptr(lo) <= bufLo && bufLo < uintptr(hi) || uintptr(lo) <= skipLo && skipLo < uintptr(hi) {
			continue
		}
		for off := lo; off < hi; off += uint64(len(buf)) - 32 {
			n := min(uint64(len(buf)), hi-off)
			k, _ := mem.ReadAt(buf[:n], int64(off))
			if k > 0 && bytes.Contains(buf[:k], pat) {
				clear(buf)
				return true
			}
			if off+n >= hi {
				break
			}
		}
	}
	clear(buf)
	return false
}
