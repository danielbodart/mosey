package client

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/danielbodart/mosey/internal/bootstrap"
)

// localStandIn writes a `mosey` stand-in for a bootstrap with no ssh: it
// saves its arguments, environment and stdin, then prints stdout and exits
// with status.
func localStandIn(t *testing.T, dir string, stdout []byte, status string) string {
	t.Helper()
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	if err := os.WriteFile(filepath.Join(dir, "out"), stdout, 0o644); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > '" + dir + "/argv'\nenv > '" + dir + "/env'\ncat > '" + dir + "/stdin'\ncat '" + dir + "/out'\nexit " + status + "\n"
	path := filepath.Join(dir, "mosey")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func localSpawn(server string, agentFlag byte, env map[string]string, stderr *bytes.Buffer) *spawn {
	return &spawn{
		// localhost is this machine; the ssh named is never run.
		ssh:    bootstrap.SSH{Destination: "localhost", Program: "/nonexistent/ssh", Server: server, Options: bootstrap.SSHOptions{Agent: agentFlag}},
		line:   testLine(),
		stderr: stderr,
		log:    slog.New(slog.DiscardHandler),
		getenv: func(name string) string { return env[name] },
	}
}

// With localhost the bootstrap runs the server binary itself, with
// no ssh and no ssh -G, and exchanges the same two lines over its stdin
// and stdout (bootstrap.md §2.2). The launcher sees none of the marks of
// an ssh login the client itself may be running under.
func TestALocalBootstrapRunsTheServerWithNoSSH(t *testing.T) {
	t.Setenv("SSH_CONNECTION", "10.0.0.9 50000 10.0.0.5 22")
	t.Setenv("SSH_AUTH_SOCK", "/run/agent.sock")
	dir := t.TempDir()
	var stderr bytes.Buffer
	b := localSpawn(localStandIn(t, dir, credLine(), "0"), 0, nil, &stderr)
	line, cfg, err := b.run(context.Background())
	if err != nil {
		t.Fatalf("%v; stderr %q", err, stderr.String())
	}
	if line.Port != 60001 || cfg.Get("hostname") != "127.0.0.1" {
		t.Errorf("line %+v, config %v", line, cfg)
	}
	argv, _ := os.ReadFile(filepath.Join(dir, "argv"))
	if string(argv) != "--serve\n" {
		t.Errorf("the server ran with %q", argv)
	}
	stdin, _ := os.ReadFile(filepath.Join(dir, "stdin"))
	if got, err := bootstrap.ParseClientLine(stdin); err != nil || got.Dir != "src/my project" || got.Agent {
		t.Errorf("the server read %q: %v", stdin, err)
	}
	env, _ := os.ReadFile(filepath.Join(dir, "env"))
	if strings.Contains(string(env), "SSH_CONNECTION=") || strings.Contains(string(env), "SSH_AUTH_SOCK=") {
		t.Errorf("the launcher saw the client's ssh login:\n%s", env)
	}
	if b.forward != nil {
		t.Errorf("an agent with no SSH_AUTH_SOCK: %+v", b.forward)
	}
}

// Locally the shell gets the client's own agent, as a shell in this
// terminal would: the line says agent=yes and the forwarder replays no
// bind, there being no ssh to have made one. -a says no agent; -A with
// none to give says why.
func TestALocalSessionGetsThisTerminalsAgentUnlessToldNot(t *testing.T) {
	agentEnv := map[string]string{"SSH_AUTH_SOCK": "/run/user/1/agent.sock"}
	for _, c := range []struct {
		flag    byte
		env     map[string]string
		forward bool
		said    string
	}{
		{0, agentEnv, true, ""},
		{'A', agentEnv, true, ""},
		{'a', agentEnv, false, ""},
		{0, nil, false, ""},
		{'A', nil, false, "not forwarding the agent: SSH_AUTH_SOCK is not set"},
	} {
		dir := t.TempDir()
		var stderr bytes.Buffer
		b := localSpawn(localStandIn(t, dir, credLine(), "0"), c.flag, c.env, &stderr)
		if _, _, err := b.run(context.Background()); err != nil {
			t.Fatal(err)
		}
		stdin, _ := os.ReadFile(filepath.Join(dir, "stdin"))
		got, err := bootstrap.ParseClientLine(stdin)
		if err != nil || got.Agent != c.forward || (b.forward != nil) != c.forward {
			t.Errorf("-%c with %v: line agent %v, forwarder %+v, %v", c.flag, c.env, got.Agent, b.forward, err)
		}
		if c.forward && !b.forward.Unbound {
			t.Errorf("-%c: a local forwarder that would replay a bind", c.flag)
		}
		if !strings.Contains(stderr.String(), c.said) || c.said == "" && stderr.Len() > 0 {
			t.Errorf("-%c with %v said %q", c.flag, c.env, stderr.String())
		}
	}
}

// A local launcher that gives no line is named, with its status, and not
// blamed on an ssh there was none of.
func TestALocalServerThatGivesNoLineIsNamed(t *testing.T) {
	dir := t.TempDir()
	server := localStandIn(t, dir, []byte("nothing\n"), "3")
	var stderr bytes.Buffer
	_, _, err := localSpawn(server, 0, nil, &stderr).run(context.Background())
	var f *Failure
	if !errors.As(err, &f) || f.Msg != server+" exited with status 3 and no mosey line" {
		t.Errorf("%v", err)
	}
	_, _, err = localSpawn(filepath.Join(dir, "absent"), 0, nil, &stderr).run(context.Background())
	if !errors.As(err, &f) || !strings.HasPrefix(f.Msg, "running "+filepath.Join(dir, "absent")) {
		t.Errorf("a missing binary: %v", err)
	}
}

// -list, -kill and the end of a session name this machine localhost, and
// so do the commands they suggest (bootstrap.md §2.2).
func TestLocalMessagesNameLocalhost(t *testing.T) {
	dir := t.TempDir()
	server := localStandIn(t, dir, []byte("MOSEY-LIST 1 name=quiet-heron since=1794651234 state=detached\n"), "0")
	var out, errs bytes.Buffer
	if err := List(context.Background(), ListOptions{SSH: bootstrap.SSH{Destination: "localhost", Server: server}, Stdout: &out, Stderr: &errs}); err != nil {
		t.Fatal(err)
	}
	if argv, _ := os.ReadFile(filepath.Join(dir, "argv")); string(argv) != "--serve=list\n" {
		t.Errorf("list ran %q", argv)
	}
	if !strings.Contains(out.String(), "quiet-heron") || errs.String() != "attach to one with: mosey -s NAME localhost\n" {
		t.Errorf("stdout %q, stderr %q", out.String(), errs.String())
	}

	server = localStandIn(t, dir, nil, "0")
	out.Reset()
	if err := List(context.Background(), ListOptions{SSH: bootstrap.SSH{Destination: "localhost", Server: server}, Stdout: &out, Stderr: &errs}); err != nil || out.String() != "no sessions on localhost\n" {
		t.Errorf("%v: %q", err, out.String())
	}

	server = localStandIn(t, dir, []byte("MOSEY-ERROR 1 !code=session\n"), "1")
	var f *Failure
	if err := Kill(context.Background(), KillOptions{SSH: bootstrap.SSH{Destination: "localhost", Server: server}, Name: "play", Stdout: &out, Stderr: &errs}); !errors.As(err, &f) || f.Msg != "no session called play on localhost" {
		t.Errorf("a kill of nothing: %v", err)
	}
	if argv, _ := os.ReadFile(filepath.Join(dir, "argv")); string(argv) != "--serve=kill\nplay\n" {
		t.Errorf("kill ran %q", argv)
	}

	d := &DetachedError{Name: "quiet-heron", Destination: "localhost"}
	if want := "detached from session quiet-heron; resume it with: mosey -s quiet-heron localhost"; d.Error() != want {
		t.Errorf("%q", d.Error())
	}
}

// R3's try for a session on this machine (bootstrap.md §2.2, §9.2.2) runs
// the local launcher again, with no ssh, resuming the same session; a
// server that names no address is reached on loopback, and the shell
// keeps the client's agent.
func TestALocalReconnectRunsTheLauncherAgainWithNoSSH(t *testing.T) {
	sid := [16]byte{0x5e, 0x55}
	dir := t.TempDir()
	stdout := bootstrap.MarshalCredentialLine(bootstrap.CredentialLine{
		Port: 60001, CredentialID: [8]byte{9}, SessionID: sid, Name: "work", Public: bytes.Repeat([]byte{6}, bootstrap.PublicKeySize),
	})
	o := Options{
		SSH:      bootstrap.SSH{Destination: "localhost", Program: "/nonexistent/ssh", Server: localStandIn(t, dir, stdout, "0")},
		Terminal: newFakeTerm(100, 30),
		Log:      slog.New(slog.DiscardHandler),
		Getenv:   func(name string) string { return map[string]string{"SSH_AUTH_SOCK": "/run/agent.sock"}[name] },
	}
	r, err := reconnector(o, sid)(t.Context(), [8]byte{7})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Conn.Close(); r.Key.Wipe() })
	if r.Server.String() != "127.0.0.1:60001" || r.Agent == nil || !r.Agent.Unbound {
		t.Errorf("reattach to %v, agent %+v", r.Server, r.Agent)
	}
	stdin, _ := os.ReadFile(filepath.Join(dir, "stdin"))
	if cl, err := bootstrap.ParseClientLine(stdin); err != nil || cl.Attach != bootstrap.AttachResume || cl.SessionID != sid || !cl.Agent {
		t.Errorf("the server read %q: %v", stdin, err)
	}
}
