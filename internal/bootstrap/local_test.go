package bootstrap

import (
	"context"
	"errors"
	"os"
	"slices"
	"testing"
)

// With localhost there is no ssh (§2.2): the server binary is run
// directly as the launcher or a role, with no shell to quote for, so a
// path with a space is fine.
func TestLocalhostRunsTheServerHereWithNoSSH(t *testing.T) {
	s := SSH{Program: "/nonexistent/ssh", Destination: "localhost", Server: "/opt/my tools/mosey"}
	if !s.Local() || s.Probes() {
		t.Fatalf("Local %v, Probes %v", s.Local(), s.Probes())
	}
	if err := s.Check(); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		role, arg string
		want      []string
	}{
		{"", "", []string{"/opt/my tools/mosey", "--serve"}},
		{RoleList, "", []string{"/opt/my tools/mosey", "--serve=list"}},
		{RoleKill, "work", []string{"/opt/my tools/mosey", "--serve=kill", "work"}},
	} {
		s.Role, s.RoleArg = c.role, c.arg
		if got := s.Command(context.Background(), nil); !slices.Equal(got.Args, c.want) || got.Path != c.want[0] {
			t.Errorf("role %q: %q at %q, want %q", c.role, got.Args, got.Path, c.want)
		}
	}
}

// Resolve runs no ssh -G locally: the only thing the rest of the
// bootstrap needs from a config is §7.2's fallback host, which is
// loopback.
func TestALocalResolveNeedsNoSSHAndNamesLoopback(t *testing.T) {
	c, err := SSH{Program: "/nonexistent/ssh", Destination: "LOCALHOST"}.Resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if c.Get("hostname") != "127.0.0.1" || len(c) != 1 {
		t.Errorf("%v", c)
	}
}

// With no -remote the local launcher is this very binary.
func TestALocalServerIsThisBinaryUnlessNamed(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	if got := (SSH{Destination: "localhost"}).Command(context.Background(), nil); got.Path != exe || got.Err != nil {
		t.Errorf("%q (%v), want %q", got.Path, got.Err, exe)
	}
}

// The launcher is not an ssh login, so it does not see the marks of one
// the client may be running under: they would bind the session to that
// login's address, and send the trigger to the client's own agent.
func TestTheLocalLauncherDropsTheMarksOfAnSSHLogin(t *testing.T) {
	got := localEnv([]string{"HOME=/h", "SSH_CONNECTION=1 2 3 4", "SSH_CLIENT=1 2 3", "SSH_TTY=/dev/pts/1", "SSH_AUTH_SOCK=/a", "XDG_RUNTIME_DIR=/r", "SSH_AUTH_SOCKET=kept"})
	if want := []string{"HOME=/h", "XDG_RUNTIME_DIR=/r", "SSH_AUTH_SOCKET=kept"}; !slices.Equal(got, want) {
		t.Errorf("%q, want %q", got, want)
	}
}

// ssh options have no ssh to go to, and a role is still checked.
func TestALocalCommandLineIsChecked(t *testing.T) {
	var u *UsageError
	if err := (SSH{Destination: "localhost", Options: SSHOptions{Args: []string{"-v"}}}).Check(); !errors.As(err, &u) {
		t.Errorf("ssh options: %v", err)
	}
	if err := (SSH{Destination: "localhost", Role: RoleKill, RoleArg: "-x"}).Check(); !errors.As(err, &u) {
		t.Errorf("a bad session name: %v", err)
	}
}

// Only the word localhost, in any case, is this machine: an address, a
// user@ or a longer name goes through ssh, so the ssh path can be run
// against this machine too.
func TestOnlyTheWordLocalhostIsThisMachine(t *testing.T) {
	for _, d := range []string{"localhost", "Localhost", "LOCALHOST"} {
		if !(SSH{Destination: d}).Local() {
			t.Errorf("%q is not this machine", d)
		}
	}
	for _, d := range []string{"", "127.0.0.1", "::1", "me@localhost", "localhost.", "localhost:22", "ssh://localhost"} {
		if (SSH{Destination: d}).Local() {
			t.Errorf("%q is this machine", d)
		}
	}
	var u *UsageError
	if err := (SSH{}).Check(); !errors.As(err, &u) {
		t.Errorf("no destination: %v", err)
	}
}
