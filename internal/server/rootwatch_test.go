package server

import (
	"errors"
	"fmt"
	"testing"
	"testing/synctest"
	"time"
)

// The root watch samples at once on an attach and every RootPoll while
// attached, sends only changes, starting from proto's false, and stops
// while detached (server.md §2.9), on virtual time.
func TestTheRootWatchSendsOnlyChangesAndOnlyWhileAttached(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var root bool
		var measured int
		var sent []bool
		w := newRootWatch(func() (bool, error) { measured++; return root, nil },
			func(r bool) error { sent = append(sent, r); return nil })
		defer w.detached()
		run := func(d time.Duration) {
			deadline := time.After(d)
			for {
				select {
				case <-w.C():
					w.sample()
				case <-deadline:
					return
				}
			}
		}
		run(10 * RootPoll)
		if measured != 0 || len(sent) != 0 {
			t.Fatalf("before any attach: %d samples, sent %v", measured, sent)
		}
		w.attached()
		if measured != 1 || len(sent) != 0 {
			t.Fatalf("an attach as the user: %d samples, sent %v", measured, sent)
		}
		root = true
		run(RootPoll + RootPoll/2)
		if want := []bool{true}; fmt.Sprint(sent) != fmt.Sprint(want) {
			t.Fatalf("sudo: sent %v, want %v", sent, want)
		}
		run(5 * RootPoll)
		if len(sent) != 1 {
			t.Fatalf("root held: sent %v", sent)
		}
		root = false
		run(RootPoll)
		if want := []bool{true, false}; fmt.Sprint(sent) != fmt.Sprint(want) {
			t.Fatalf("sudo ended: sent %v, want %v", sent, want)
		}
		w.detached()
		n := measured
		root = true
		run(10 * RootPoll)
		if measured != n || len(sent) != 2 {
			t.Fatalf("detached: %d more samples, sent %v", measured-n, sent)
		}
		// A resume samples at once, so the new client hears of root
		// without waiting for a tick.
		w.attached()
		if want := []bool{true, false, true}; fmt.Sprint(sent) != fmt.Sprint(want) {
			t.Fatalf("resumed as root: sent %v, want %v", sent, want)
		}
	})
}

// A measurement that fails is not root, and a send that fails is tried
// again at the next tick.
func TestTheRootWatchTakesAFailureAsNotRootAndRetriesAFailedSend(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var sent []bool
		w := newRootWatch(func() (bool, error) { return true, errors.New("no /proc") },
			func(r bool) error { sent = append(sent, r); return nil })
		w.attached()
		w.detached()
		if len(sent) != 0 {
			t.Fatalf("a failed measurement sent %v", sent)
		}
		fail := true
		w = newRootWatch(func() (bool, error) { return true, nil },
			func(r bool) error {
				if fail {
					return errors.New("proto busy")
				}
				sent = append(sent, r)
				return nil
			})
		defer w.detached()
		w.attached()
		fail = false
		<-w.C()
		w.sample()
		if want := []bool{true}; fmt.Sprint(sent) != fmt.Sprint(want) {
			t.Fatalf("after a failed send: sent %v, want %v", sent, want)
		}
	})
}
