package bootstrap

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestTheBootstrapSSHCommandLineIsExact(t *testing.T) {
	s := SSH{
		Program:     "/usr/bin/ssh",
		Destination: "me@far",
		Options:     SSHOptions{Args: []string{"-p", "2222", "-v"}, Agent: 'A'},
		Server:      "~/.local/bin/dev/mosey",
	}
	base := []string{
		"/usr/bin/ssh", "-T",
		"-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", "ControlPersist=no",
		"-o", "ForwardAgent=no",
		"-o", "ForwardX11=no", "-o", "ClearAllForwardings=yes", "-o", "Tunnel=no",
		"-o", "PermitLocalCommand=no", "-o", "EscapeChar=none",
		"-o", "RemoteCommand=none",
	}
	tail := []string{"-p", "2222", "-v", "--", "me@far", "exec /bin/sh -c 'exec ~/.local/bin/dev/mosey --serve'"}

	old := s.Command(context.Background(), Config{"hostname": {"far"}})
	if want := slices.Concat(base, tail); !slices.Equal(old.Args, want) {
		t.Errorf("an ssh before 8.7:\n got %q\nwant %q", old.Args, want)
	}
	modern := s.Command(context.Background(), Config{"sessiontype": {"default"}, "stdinnull": {"no"}, "forkafterauthentication": {"no"}})
	want := slices.Concat(base, []string{"-o", "SessionType=default", "-o", "StdinNull=no", "-o", "ForkAfterAuthentication=no"}, tail)
	if !slices.Equal(modern.Args, want) {
		t.Errorf("an ssh of 8.7 or later:\n got %q\nwant %q", modern.Args, want)
	}
	// The agent flag never reaches the bootstrap ssh (§2.1): -A would beat
	// our ForwardAgent=no whatever the order.
	for _, a := range modern.Args {
		if a == "-A" || a == "-a" {
			t.Errorf("agent flag %s reached the bootstrap ssh", a)
		}
	}
	s.AgentCapture = "/run/user/1000/mosey/cap-00.sock"
	if c := s.Command(context.Background(), nil); !slices.Contains(c.Args, "ForwardAgent=/run/user/1000/mosey/cap-00.sock") {
		t.Errorf("capture socket not forwarded: %q", c.Args)
	}
}

func TestDestinationAndRemoteAreChecked(t *testing.T) {
	good := SSH{Destination: "me@far", Server: "mosey"}
	if err := good.Check(); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"", "-oProxyCommand=x", "a b", "a\tb", "a\x7fb", "a\nb", strings.Repeat("h", 1025)} {
		s := good
		s.Destination = d
		var u *UsageError
		if err := s.Check(); !errors.As(err, &u) {
			t.Errorf("destination %q: %v", d, err)
		}
	}
	for _, r := range []string{"mosey", "/usr/local/bin/mosey", "~/.local/bin/0.1+x/mosey", "bin/mosey-1.0_rc"} {
		if !ValidServer(r) {
			t.Errorf("%q refused", r)
		}
	}
	for _, r := range []string{"", "~/", "~", "-mosey", "~/-x", "mo sey", "mosey;rm", "$HOME/mosey", "'mosey'", "~user/mosey", "a\\b", strings.Repeat("m", 257)} {
		if ValidServer(r) {
			t.Errorf("%q accepted", r)
		}
	}
}

// The remote command gives /bin/sh's exit status for a missing or
// unrunnable server whatever the login shell (§4.1), and leaves ~/ for the
// remote sh to expand. Each shell that is installed is tried as sshd would
// run it: SHELL -c COMMAND.
func TestTheRemoteCommandExitsAsShSaysUnderEveryShell(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, "notexec"), []byte("#!/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "mosey"), []byte("#!/bin/sh\necho \"served $1\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	ran := 0
	for _, shell := range []string{"sh", "bash", "zsh", "fish", "tcsh", "nu"} {
		path, err := exec.LookPath(shell)
		if err != nil {
			continue
		}
		ran++
		for _, c := range []struct {
			server string
			status int
			out    string
		}{
			{"~/nothing-here", 127, ""},
			{"~/notexec", 126, ""},
			{"~/mosey", 0, "served --serve\n"},
		} {
			cmd := exec.Command(path, "-c", SSH{Server: c.server}.RemoteCommand())
			cmd.Env = []string{"HOME=" + home, "PATH=" + remotePath(t)}
			cmd.Dir = home
			out, err := cmd.Output()
			if got := ExitStatus(err); got != c.status || string(out) != c.out {
				t.Errorf("%s with %s: status %d, out %q; want %d, %q", shell, c.server, got, out, c.status, c.out)
			}
		}
	}
	if ran == 0 {
		t.Skip("no shell found")
	}
}

// ours come first so ours win: resolved by the real ssh -G against a config
// that turns every one of them the other way (threat-model §4.9).
func TestOurOptionsBeatTheUsersConfig(t *testing.T) {
	ssh, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("no ssh")
	}
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config")
	if err := os.WriteFile(cfg, []byte(`Host *
  ControlMaster auto
  ControlPath `+dir+`/cm-%C
  ControlPersist 600
  ForwardAgent yes
  ForwardX11 yes
  ForwardX11Trusted yes
  LocalForward 8080 localhost:80
  RemoteForward 9090 localhost:90
  DynamicForward 1080
  Tunnel yes
  PermitLocalCommand yes
  LocalCommand touch `+dir+`/ran
  EscapeChar ~
  RemoteCommand top
  RequestTTY force
`), 0o600); err != nil {
		t.Fatal(err)
	}
	s := SSH{Program: ssh, Destination: "far.example", Server: "mosey", Options: SSHOptions{Args: []string{"-F", cfg, "-o", "ControlMaster=yes"}}}
	c, err := s.Resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Resolve as the bootstrap ssh would, by asking ssh -G with the same
	// options in front.
	argv := s.Command(context.Background(), c).Args
	dash := slices.Index(argv, "--")
	g := exec.Command(ssh, append(append([]string{"-G"}, argv[1:dash]...), "--", "far.example")...)
	out, err := g.Output()
	if err != nil {
		t.Fatalf("ssh -G: %v", err)
	}
	got, err := ParseConfig(out)
	if err != nil {
		t.Fatal(err)
	}
	for kw, want := range map[string]string{
		"controlmaster":       "false",
		"controlpath":         "",
		"controlpersist":      "no",
		"forwardagent":        "no",
		"forwardx11":          "no",
		"clearallforwardings": "yes",
		"tunnel":              "false",
		"permitlocalcommand":  "no",
		"escapechar":          "none",
		"remotecommand":       "",
		"requesttty":          "false",
		"localforward":        "",
		"remoteforward":       "",
		"dynamicforward":      "",
	} {
		if v := got.Get(kw); v != want && !(want == "" && (v == "none" || v == "")) {
			t.Errorf("%s resolved to %q, want %q", kw, v, want)
		}
	}
}

func TestResolveReportsSSHsComplaint(t *testing.T) {
	ssh, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("no ssh")
	}
	s := SSH{Program: ssh, Destination: "far.example", Server: "mosey", Options: SSHOptions{Args: []string{"-F", "/dev/null", "-o", "Bogus=1"}}}
	_, err = s.Resolve(context.Background())
	var re *ResolveError
	if !errors.As(err, &re) || !strings.Contains(strings.ToLower(string(re.Stderr)), "bogus") {
		t.Errorf("%v", err)
	}
}

func TestResolvePassesTheUsersOptionsAndAgentFlag(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "ssh")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nprintf 'args'; printf ' %s' \"$@\"; printf '\\nhostname 192.0.2.7\\n'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	s := SSH{Program: fake, Destination: "far", Server: "mosey", Options: SSHOptions{Args: []string{"-p", "22"}, Agent: 'a'}}
	c, err := s.Resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if c.Get("args") != "-G -p 22 -a -- far" || c.Get("hostname") != "192.0.2.7" {
		t.Errorf("%v", c)
	}
}
