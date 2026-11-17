//go:build linux

package e2e

import (
	"bytes"
	"context"
	"testing"
	"testing/synctest"

	"github.com/danielbodart/mosey/internal/client"
	"github.com/danielbodart/mosey/internal/netsim"
	"github.com/danielbodart/mosey/internal/server"
)

// mosey's own termprops, exactly as docs/spec/screen.md §8.8 gives them.
const (
	markRemote  = "\x1b]666;vte.ext.mosey.remote=dan@blade\x1b\\"
	markRoot    = "\x1b]666;vte.ext.mosey.root=1\x1b\\"
	unmarkRoot  = "\x1b]666;vte.ext.mosey.root\x1b\\"
	unmarkMosey = "\x1b]666;vte.ext.mosey.\x1b\\"
)

// startMarkedSession is startSimSession with the client marking the
// terminal remote with remote ("" for a session on this machine), and the
// server's Session handed back, so the test can play the spawner's root
// measurement (server.md §2.9) without being root.
func startMarkedSession(t *testing.T, remote string) (*simSession, *server.Session) {
	sh := newShell()
	n := newSimNet(t, netsim.HotelWifi())
	ctx, cancel := context.WithCancel(context.Background())
	cctx, quit := context.WithCancel(ctx)
	s := &simSession{
		t:       t,
		profile: "hotel-wifi",
		user:    &userTerminal{keys: make(chan []byte), resized: make(chan struct{})},
		term:    sh,
		prog:    sh,
		cc:      n.cc,
		quit:    quit,
		cancel:  cancel,
	}
	var sess *server.Session
	s.server = n.serveWith(t, ctx, sh, func(ss *server.Session) { sess = ss })
	s.client = n.connectWith(cctx, s.user, func(c *client.Session) { c.Remote = remote })
	t.Cleanup(s.end)
	return s, sess
}

// The tab's marks end to end over a lossy network (screen.md §8.8): the
// remote mark is the client's own, set on the first frame; root follows
// the server's measurement; a far-side program printing mosey's
// termprops, or a container mark, neither sets nor hides root; and the
// client's exit unsets both.
func TestTheTabIsMarkedRemoteAndRootOnlyFromWhatMoseyKnows(t *testing.T) {
	skipUntilBuilt(t, allPackages...)
	synctest.Test(t, func(t *testing.T) {
		s, sess := startMarkedSession(t, "dan@blade")
		s.wait("prompt and the remote mark", func() bool {
			b := s.user.bytes()
			return bytes.Contains(b, []byte("$")) && bytes.Contains(b, []byte(markRemote))
		})
		say := func(b string) {
			s.prog.mu.Lock()
			s.prog.print(b)
			s.prog.mu.Unlock()
		}
		// A program printing the root mark does not make the tab red.
		say("\x1b]666;vte.ext.mosey.root=1\x1b\\forged$ ")
		s.wait("the forged prompt", func() bool { return bytes.Contains(s.user.bytes(), []byte("forged$")) })
		if bytes.Contains(s.user.bytes(), []byte(markRoot)) {
			t.Fatal("a printed root mark reached the user's terminal")
		}
		// sudo: the spawner measures root, and the tab goes red.
		sess.SetRoot(true)
		s.wait("the root mark", func() bool { return bytes.Contains(s.user.bytes(), []byte(markRoot)) })
		rooted := len(s.user.bytes())
		// The far side tries to hide it, by unsetting mosey's marks and by
		// setting a container mark: the container mark arrives, and root
		// is still set.
		say("\x1b]666;vte.ext.mosey.root;vte.ext.mosey.\x1b\\\x1b]666;vte.container.name=box\x1b\\hidden$ ")
		s.wait("the container mark", func() bool {
			return bytes.Contains(s.user.bytes()[rooted:], []byte("vte.container.name=box"))
		})
		if after := s.user.bytes()[rooted:]; bytes.Contains(after, []byte(unmarkRoot)) || bytes.Contains(after, []byte(unmarkMosey)) {
			t.Fatalf("printed output unset the root mark: %q", after)
		}
		// sudo ended.
		sess.SetRoot(false)
		s.wait("root unset", func() bool { return bytes.Contains(s.user.bytes()[rooted:], []byte(unmarkRoot)) })
		s.exit()
		b := s.user.bytes()
		if bytes.Count(b, []byte(markRemote)) != 1 {
			t.Errorf("the remote mark was written %d times", bytes.Count(b, []byte(markRemote)))
		}
		if last := bytes.LastIndex(b, []byte(unmarkMosey)); last < bytes.LastIndex(b, []byte(markRemote)) {
			t.Fatalf("the client left its remote mark on the terminal: %q", b[max(0, len(b)-200):])
		}
	})
}

// A session on this machine (mosey localhost) writes no mark of mosey's
// own at all, so the tab stays local.
func TestALocalSessionLeavesTheTabUnmarked(t *testing.T) {
	skipUntilBuilt(t, allPackages...)
	synctest.Test(t, func(t *testing.T) {
		s, _ := startMarkedSession(t, "")
		s.wait("prompt", func() bool { return bytes.Contains(s.user.bytes(), []byte("$")) })
		s.exit()
		if b := s.user.bytes(); bytes.Contains(b, []byte("vte.ext.mosey")) {
			t.Fatalf("a local session marked the tab: %q", b)
		}
	})
}
