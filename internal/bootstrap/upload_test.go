package bootstrap

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestAProbeLineSurvivesARoundTrip(t *testing.T) {
	for _, p := range []ProbeLine{
		{"Linux", "x86_64"},
		{"unknown", "unknown"},
		{strings.Repeat("S", 64), strings.Repeat("m", 64)},
	} {
		line := MarshalProbeLine(p)
		got, err := ParseProbeLine(line)
		if err != nil || got != p {
			t.Errorf("%q: %+v %v", line, got, err)
		}
		if len(line) > MaxProbeLine {
			t.Errorf("%q is over MaxProbeLine", line)
		}
	}
	if got := string(MarshalProbeLine(ProbeLine{"Linux", "aarch64"})); got != "MOSEY-PROBE 1 machine=aarch64 system=Linux\n" {
		t.Errorf("marshalled %q", got)
	}
	// 163 with a 5-digit number (§4.7.2); 1 is one digit.
	if n := len(MarshalProbeLine(ProbeLine{strings.Repeat("S", 64), strings.Repeat("m", 64)})); n != 163-4 {
		t.Errorf("the longest probe line is %d bytes", n)
	}
}

func TestAProbeLineOutsideItsGrammarIsRefused(t *testing.T) {
	for _, line := range []string{
		"MOSEY-PROBE 1 system=Linux\n",
		"MOSEY-PROBE 1 machine=x86_64\n",
		"MOSEY-PROBE 1 Linux x86_64\n",
		"MOSEY-PROBE 1 machine=x86_64 system=Linux none\n",
		"MOSEY-PROBE 1 machine=x86_64  system=Linux\n",
		"MOSEY-PROBE 1 machine=x86_64 system=Linux \n",
		"MOSEY-PROBE 1 machine=x86_64 system=Linux",
		"MOSEY-PROBE 1 machine=x86_64 system=Linux\r\n",
		"MOSEY-PROBE 01 machine=x86_64 system=Linux\n",
		"MOSEY-PROBE 1 system=Linux machine=x86_64\n",
		"MOSEY-PROBE 1 machine=x86_64 !system=Linux\n",
		"MOSEY-PROBE 1 machine=x86_64 system=Lin\x00ux\n",
		"MOSEY-PROBE 1 machine=x86_64 system=" + strings.Repeat("S", 65) + "\n",
		"MOSEY-PROBE 1 machine=x86_64 system=\n",
	} {
		if p, err := ParseProbeLine([]byte(line)); !errors.Is(err, ErrBadLine) {
			t.Errorf("%q: %+v %v", line, p, err)
		}
	}
	var ve *VersionError
	if _, err := ParseProbeLine([]byte("MOSEY-PROBE 3 Linux x86_64\n")); !errors.As(err, &ve) || ve.Got != 3 {
		t.Errorf("another version: %v", err)
	}
}

func TestReadCredentialReturnsTheProbeAsNoServer(t *testing.T) {
	_, err := ReadCredential(strings.NewReader("Welcome\nMOSEY-PROBE 1 machine=aarch64 system=Linux\n"))
	var ns *NoServerError
	if !errors.As(err, &ns) || !errors.Is(err, ErrNoServer) || ns.Probe != (ProbeLine{"Linux", "aarch64"}) {
		t.Fatalf("%v", err)
	}
	if _, err := ReadCredential(strings.NewReader("MOSEY-PROBE 1 machine=x86 64 system=Linux\n")); !errors.Is(err, ErrBadLine) {
		t.Errorf("a probe line with a space in a field: %v", err)
	}
}

func TestEveryPlatformWithABuildIsMappedAndNoOther(t *testing.T) {
	for _, c := range []struct {
		sys, machine, os, arch string
	}{
		{"Linux", "x86_64", "linux", "amd64"},
		{"Linux", "amd64", "linux", "amd64"},
		{"Linux", "aarch64", "linux", "arm64"},
		{"Darwin", "arm64", "darwin", "arm64"},
		{"Darwin", "x86_64", "darwin", "amd64"},
	} {
		os, arch, ok := Platform(ProbeLine{System: c.sys, Machine: c.machine})
		if !ok || os != c.os || arch != c.arch {
			t.Errorf("%s %s: %s %s %v", c.sys, c.machine, os, arch, ok)
		}
	}
	for _, p := range []ProbeLine{{"linux", "x86_64"}, {"FreeBSD", "amd64"}, {"Linux", "armv7l"}, {"Linux", "riscv64"}, {"unknown", "unknown"}, {"Linux", "i686"}} {
		if os, arch, ok := Platform(p); ok {
			t.Errorf("%+v mapped to %s/%s", p, os, arch)
		}
	}
}

func TestOnlyACIVersionIsARelease(t *testing.T) {
	for _, v := range []string{"0.123.4", "1.0.1", "0.250.999999999"} {
		if !IsRelease(v) {
			t.Errorf("%q is not a release", v)
		}
	}
	for _, v := range []string{"dev", "0.123.20261114093000", "0-unstable-2026-11-14+abc1234", "0.123.0", "0.123", "0.1.2.3", "00.1.2", "0.1.2+x", "v0.1.2", "", "e2e"} {
		if IsRelease(v) {
			t.Errorf("%q is a release", v)
		}
	}
	if got := AssetName("0.1.2", "linux", "arm64"); got != "mosey-0.1.2-linux-arm64" {
		t.Errorf("asset %q", got)
	}
}

// The one installed file is a path -remote could name too, and the probe's
// protocol answer is two small decimals and nothing a script could
// misread (§4.7.2).
func TestTheInstallPathAndTheProtocolAnswerAreSafeInAScript(t *testing.T) {
	if !ValidServer(InstallPath) {
		t.Errorf("%q", InstallPath)
	}
	if got := ProtocolAnswer(1); got != "1 1" || !validProtocolAnswer(got) {
		t.Errorf("%q", got)
	}
	for _, a := range []string{"", "1", "1  1", "1 1 1", "01 1", "1 x", "1;1", "1 1'", "1000 1"} {
		if validProtocolAnswer(a) {
			t.Errorf("%q passes", a)
		}
	}
	if cmd := (SSH{Destination: "far", Protocol: "1 1; rm -rf ~"}).RemoteCommand(); strings.Contains(cmd, "rm -rf") {
		t.Errorf("the probe took a script in its protocol answer: %q", cmd)
	}
}

func TestSHA256SUMSIsReadStrictly(t *testing.T) {
	a, b := strings.Repeat("a", 64), strings.Repeat("0", 64)
	good := b + "  mosey-0.1.2-darwin-arm64\n" + a + "  mosey-0.1.2-linux-amd64\n"
	h, err := ParseSums([]byte(good), "mosey-0.1.2-linux-amd64")
	if err != nil || h != [32]byte(bytes.Repeat([]byte{0xaa}, 32)) {
		t.Fatalf("%x %v", h, err)
	}
	for _, c := range []struct{ name, sums string }{
		{"missing", b + "  mosey-0.1.2-darwin-arm64\n"},
		{"upper case", strings.ToUpper(a) + "  mosey-0.1.2-linux-amd64\n"},
		{"one space", a + " mosey-0.1.2-linux-amd64\n"},
		{"binary marker", a + " *mosey-0.1.2-linux-amd64\n"},
		{"no LF", a + "  mosey-0.1.2-linux-amd64"},
		{"CRLF", a + "  mosey-0.1.2-linux-amd64\r\n"},
		{"short hash", a[:63] + "  mosey-0.1.2-linux-amd64\n"},
		{"twice", good + a + "  mosey-0.1.2-linux-amd64\n"},
		{"a path", a + "  ../mosey-0.1.2-linux-amd64\n"},
		{"a bad line elsewhere", "junk\n" + good},
		{"empty", ""},
	} {
		if _, err := ParseSums([]byte(c.sums), "mosey-0.1.2-linux-amd64"); err == nil {
			t.Errorf("%s: accepted", c.name)
		}
	}
	if _, err := ParseSums(bytes.Repeat([]byte(good), MaxSums/len(good)+1), "x"); err == nil {
		t.Error("an oversized file was accepted")
	}
}

func TestWithoutRemoteTheBootstrapProbes(t *testing.T) {
	s := SSH{Destination: "far", Protocol: ProtocolAnswer(1)}
	if err := s.Check(); err != nil {
		t.Fatal(err)
	}
	if !s.Probes() || !strings.Contains(s.RemoteCommand(), `--serve=protocol </dev/null 2>/dev/null)" = "1 1" ]`) {
		t.Errorf("no probe: %q", s.RemoteCommand())
	}
	s = SSH{Destination: "far", Server: "/opt/mosey"}
	if s.Probes() || s.RemoteCommand() != "exec /bin/sh -c 'exec /opt/mosey --serve'" {
		t.Errorf("-remote: %q", s.RemoteCommand())
	}
}

// -list's role goes through the probe too, so a lister in ~/.local/bin is
// found (§4.7.2, §9.4), and through slice 1's and -remote's commands.
func TestTheProbeRunsTheRolesFlag(t *testing.T) {
	for _, c := range []struct {
		s    SSH
		want string
	}{
		{SSH{Destination: "far", Protocol: "1 1", Role: RoleList}, `*) exec mosey --serve=list;; esac`},
		{SSH{Destination: "far", Protocol: "1 1", Role: RoleList}, `if [ -n "$p" ]; then exec "$f" --serve=list; fi`},
		{SSH{Destination: "far", Server: "/opt/mosey", Role: RoleList}, "exec /bin/sh -c 'exec /opt/mosey --serve=list'"},
	} {
		if err := c.s.Check(); err != nil {
			t.Fatal(err)
		}
		if got := c.s.RemoteCommand(); !strings.Contains(got, c.want) {
			t.Errorf("%+v: %q", c.s, got)
		}
	}
}

// The probe and upload scripts carry nothing a login shell would read
// inside single quotes (§4.7.2): no ', no \, no !, no newline.
func TestTheScriptsNeedNoQuotingInAnyLoginShell(t *testing.T) {
	for _, cmd := range []string{
		probeCommand("1 1", "--serve"),
		probeCommand("1 1", "--serve=kill a.b_c-1"),
		uploadCommand([32]byte{1, 2}, 12345),
	} {
		inner, ok := strings.CutPrefix(cmd, "exec /bin/sh -c '")
		inner, ok2 := strings.CutSuffix(inner, "'")
		if !ok || !ok2 || strings.ContainsAny(inner, "'\\!\n") {
			t.Errorf("%q", cmd)
		}
	}
}

// shells is every login shell §4.1 names that is installed here.
func shells(t *testing.T) []string {
	t.Helper()
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	var found []string
	for _, shell := range []string{"sh", "bash", "zsh", "fish", "tcsh", "nu"} {
		if path, err := exec.LookPath(shell); err == nil {
			found = append(found, path)
		}
	}
	if len(found) == 0 {
		t.Skip("no shell found")
	}
	return found
}

// remoteTools are the commands the remote scripts and writeMosey's fakes
// run; the rest are shell builtins.
var remoteTools = []string{"uname", "cat", "ls", "mkdir", "mktemp", "chmod", "rm"}

// remotePath is the PATH the remote-command tests give their shells: dirs,
// then a directory of links to remoteTools and nothing else. The tools are
// found in the usual system directories, as an ssh login would have them,
// then this process's own PATH (Nix's build sandbox has coreutils only on
// its PATH). Linking them rather than putting those directories on PATH
// keeps the test hermetic: a host with mosey installed (NixOS puts it in
// /run/current-system/sw/bin beside coreutils) would otherwise answer the
// cases that need no mosey on PATH.
func remotePath(t *testing.T, dirs ...string) string {
	t.Helper()
	tools := t.TempDir()
	search := filepath.SplitList(strings.Join([]string{"/usr/bin", "/bin", "/run/current-system/sw/bin", os.Getenv("PATH")}, ":"))
	for _, tool := range remoteTools {
		for _, d := range search {
			p := filepath.Join(d, tool)
			if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() && fi.Mode()&0o111 != 0 {
				if err := os.Symlink(p, filepath.Join(tools, tool)); err != nil {
					t.Fatal(err)
				}
				break
			}
		}
	}
	return strings.Join(append(dirs, tools), ":")
}

// needTools skips the test when the shell cannot find a command the
// script under test runs, as the e2e tests skip without sshd.
func needTools(t *testing.T, path string, tools ...string) {
	t.Helper()
	for _, tool := range tools {
		cmd := exec.Command("/bin/sh", "-c", "command -v "+tool)
		cmd.Env = []string{"PATH=" + path}
		if cmd.Run() != nil {
			t.Skipf("%s is not on %s", tool, path)
		}
	}
}

// writeMosey is a stand-in mosey that answers --serve=protocol with
// answer and, as the launcher, says which it is and what it read on
// stdin. An answer of "" is a file that answers nothing.
func writeMosey(t *testing.T, path, answer, name string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\ncase \"$1\" in\n--serve=protocol) echo " + answer + ";;\n--serve) echo \"" + name + " read $(cat)\";;\nesac\n"
	if answer == "" {
		script = "#!/bin/sh\nexit 1\n"
	}
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
}

// The probe, as each login shell would run it (§4.7.2): a mosey elsewhere
// on PATH first, whatever it answers; else ~/.local/bin/mosey, on PATH
// or not, if it answers this client's protocol and the installer would
// have written it; else a ProbeLine that parses, exit 0, so the client
// offers to copy (and so replace a ~/.local/bin/mosey of another
// protocol, Dan 2026-11-16). A ~/.local/bin/mosey on PATH that the
// installer would refuse to replace is run as it is.
func TestTheProbeUsesWhateverMoseyTheHostHasOrSaysWhatTheHostIs(t *testing.T) {
	const ours = "1 1"
	needTools(t, remotePath(t), "uname", "cat", "ls")
	for _, shell := range shells(t) {
		for _, c := range []struct {
			name      string
			installed string // ~/.local/bin/mosey's answer; "-" for none
			path      string // the answer of a mosey elsewhere on PATH; "-" for none
			// onPath: where ~/.local/bin is on PATH: "" not at all,
			// "first" before the other mosey's directory, "last" after.
			onPath string
			served string // which ran, or "" for a probe line
			// link: "dir", ~/.local/bin is a symlink; "file", the file
			// is; or a directory ("", ".local", ".local/bin") and the
			// mode it is given after the copy is written.
			link string
			mode os.FileMode
		}{
			{"PATH", "-", ours, "", "path", "", 0},
			// Dan, 2026-11-15: whatever mosey the host has. PATH's is not
			// asked anything: a mismatch is the bootstrap's to report.
			{"PATH of another protocol", "-", "2 2", "", "path", "", 0},
			{"PATH first", ours, ours, "", "path", "", 0},
			{"PATH ahead of ~/.local/bin", "1 2", ours, "last", "path", "", 0},
			{"installed, off PATH", ours, "-", "", "installed", "", 0},
			{"installed, on PATH", ours, "-", "first", "installed", "", 0},
			{"installed, on PATH ahead of another", ours, "2 2", "first", "installed", "", 0},
			// Dan, 2026-11-16: the file mosey installs is the one it may
			// replace, however it was found.
			{"installed of another protocol, off PATH", "1 2", "-", "", "", "", 0},
			{"installed of another protocol, on PATH", "1 2", "-", "first", "", "", 0},
			{"installed of another protocol, ahead of another", "1 2", ours, "first", "", "", 0},
			{"installed that answers nothing", "", "-", "", "", "", 0},
			{"installed that answers nothing, on PATH", "", "-", "first", "", "", 0},
			// The installer's rules hold for the probe too: a place it
			// would refuse to write is not run from unless PATH chose it,
			// and then as any PATH mosey is, since it cannot be replaced.
			{"symlinked ~/.local/bin", ours, "-", "", "", "dir", 0},
			{"symlinked ~/.local/bin, PATH", ours, ours, "", "path", "dir", 0},
			{"symlinked ~/.local/bin, on PATH", "1 2", "-", "first", "installed", "dir", 0},
			{"symlinked installed file", ours, "-", "", "", "file", 0},
			{"symlinked installed file, on PATH", "1 2", "-", "first", "installed", "file", 0},
			// Nor is a directory on the way that others may write, which
			// the installer refuses too (bootstrap.md §4.7.7).
			{"~/.local/bin others may write", ours, "-", "", "", ".local/bin", 0o707},
			{"~/.local/bin its group may write", ours, "-", "", "", ".local/bin", 0o770},
			{"~/.local its group may write", ours, "-", "", "", ".local", 0o770},
			{"home its group may write", ours, "-", "", "", "", 0o770},
			{"~/.local/bin others may read", ours, "-", "", "installed", ".local/bin", 0o755},
			{"nothing", "-", "-", "", "", "", 0},
			{"nothing, ~/.local/bin on PATH", "-", "-", "first", "", "", 0},
		} {
			home, bin := t.TempDir(), t.TempDir()
			local := filepath.Join(home, ".local", "bin")
			if c.installed != "-" {
				switch c.link {
				case "dir":
					// A copy that would pass, in a directory elsewhere
					// that ~/.local/bin points at.
					elsewhere := t.TempDir()
					writeMosey(t, filepath.Join(elsewhere, "mosey"), c.installed, "installed")
					os.MkdirAll(filepath.Join(home, ".local"), 0o700)
					if err := os.Symlink(elsewhere, local); err != nil {
						t.Fatal(err)
					}
				case "file":
					real := filepath.Join(t.TempDir(), "mosey")
					writeMosey(t, real, c.installed, "installed")
					os.MkdirAll(local, 0o700)
					if err := os.Symlink(real, filepath.Join(local, "mosey")); err != nil {
						t.Fatal(err)
					}
				default:
					writeMosey(t, filepath.Join(local, "mosey"), c.installed, "installed")
					if c.mode != 0 {
						if err := os.Chmod(filepath.Join(home, c.link), c.mode); err != nil {
							t.Fatal(err)
						}
					}
				}
			}
			if c.path != "-" {
				writeMosey(t, filepath.Join(bin, "mosey"), c.path, "path")
			}
			dirs := []string{bin}
			switch c.onPath {
			case "first":
				dirs = []string{local, bin}
			case "last":
				dirs = []string{bin, local}
			}
			if (c.path != "-" || c.onPath != "") && !keepsPath(shell, bin) {
				// NixOS's /etc/zshenv, which zsh reads even with -f, sets
				// PATH afresh and hides the test's mosey; the cases that
				// need no PATH still test this shell's quoting.
				continue
			}
			cmd := exec.Command(shell, "-c", SSH{Protocol: ours}.RemoteCommand())
			cmd.Env = []string{"HOME=" + home, "PATH=" + remotePath(t, dirs...)}
			cmd.Dir = home
			cmd.Stdin = strings.NewReader("THE-LINE\n")
			out, err := cmd.Output()
			if ExitStatus(err) != 0 {
				t.Errorf("%s, %s: %v", filepath.Base(shell), c.name, err)
				continue
			}
			if c.served != "" {
				if string(out) != c.served+" read THE-LINE\n" {
					t.Errorf("%s, %s: %q", filepath.Base(shell), c.name, out)
				}
				continue
			}
			_, err = ReadCredential(bytes.NewReader(out))
			var ns *NoServerError
			if !errors.As(err, &ns) {
				t.Errorf("%s, %s: %q gives %v", filepath.Base(shell), c.name, out, err)
				continue
			}
			if _, _, ok := Platform(ns.Probe); !ok {
				t.Errorf("%s, %s: this host is not a platform: %+v", filepath.Base(shell), c.name, ns.Probe)
			}
		}
	}
}

// The probe tells ~/.local/bin/mosey on PATH from any other PATH mosey by
// comparing the path command -v printed with "$HOME/.local/bin/mosey" as
// strings (§4.7.2), so a HOME spelled with a trailing slash makes the
// installed copy look like one PATH chose elsewhere: it is exec'd as it
// is, and one of another protocol is reported with both numbers rather
// than replaced. This pins that limitation (a HOME with a trailing slash
// is rare, and the user can fix it), so a change to it is deliberate.
func TestAHomeWithATrailingSlashHidesTheInstalledCopyOnPath(t *testing.T) {
	needTools(t, remotePath(t), "uname", "cat", "ls")
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	home := t.TempDir()
	local := filepath.Join(home, ".local", "bin")
	writeMosey(t, filepath.Join(local, "mosey"), "1 2", "installed")
	cmd := exec.Command("/bin/sh", "-c", SSH{Protocol: "1 1"}.RemoteCommand())
	cmd.Env = []string{"HOME=" + home + "/", "PATH=" + remotePath(t, local)}
	cmd.Dir = home
	cmd.Stdin = strings.NewReader("THE-LINE\n")
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "installed read THE-LINE\n" {
		t.Errorf("got %q, want the installed copy exec'd as a PATH mosey", out)
	}
}

// keepsPath says whether shell -c leaves a PATH starting with bin alone.
func keepsPath(shell, bin string) bool {
	cmd := exec.Command(shell, "-c", "/bin/sh -c 'echo $PATH'")
	cmd.Env = []string{"PATH=" + bin + ":/usr/bin:/bin"}
	out, err := cmd.Output()
	return err == nil && strings.HasPrefix(string(out), bin+":")
}

// The upload script puts stdin in a mktemp file in ~/.local/bin, which it
// makes 0700 with ~/.local when they are missing, runs it
// as the installer with the hash, size and its own path, passes
// on its status, and removes the temporary file whatever happened
// (§4.7.6).
func TestTheUploadScriptRunsTheCopyAsItsInstaller(t *testing.T) {
	needTools(t, remotePath(t), "mkdir", "mktemp", "cat", "chmod", "rm")
	for _, shell := range shells(t) {
		for _, status := range []string{"0", "1"} {
			home := t.TempDir()
			copy := []byte("#!/bin/sh\necho \"$@\" > \"$HOME/args\"\nexit " + status + "\n")
			sum := sha256.Sum256(copy)
			cmd := exec.Command(shell, "-c", uploadCommand(sum, int64(len(copy))))
			cmd.Env = []string{"HOME=" + home, "PATH=" + remotePath(t)}
			cmd.Dir = home
			cmd.Stdin = bytes.NewReader(copy)
			out, err := cmd.CombinedOutput()
			if got := ExitStatus(err); got != int(status[0]-'0') {
				t.Errorf("%s: exit %d: %s", filepath.Base(shell), got, out)
				continue
			}
			args, _ := os.ReadFile(filepath.Join(home, "args"))
			f := strings.Fields(string(args))
			if len(f) != 4 || f[0] != "--serve=install" || f[1] != hexOf(sum) || f[2] != strconv.Itoa(len(copy)) ||
				!strings.HasPrefix(f[3], home+"/.local/bin/.upload.") {
				t.Errorf("%s: installer ran with %q", filepath.Base(shell), args)
			}
			if entries, _ := os.ReadDir(filepath.Join(home, ".local", "bin")); len(entries) != 0 {
				t.Errorf("%s: left %v", filepath.Base(shell), entries)
			}
			for _, d := range []string{".local", ".local/bin"} {
				if st, err := os.Stat(filepath.Join(home, d)); err != nil {
					t.Errorf("%s: ~/%s: %v", filepath.Base(shell), d, err)
				} else if st.Mode().Perm() != 0o700 {
					t.Errorf("%s: ~/%s is %v", filepath.Base(shell), d, st.Mode())
				}
			}
		}
	}
}

func hexOf(sum [32]byte) string {
	const digits = "0123456789abcdef"
	var b strings.Builder
	for _, c := range sum {
		b.WriteByte(digits[c>>4])
		b.WriteByte(digits[c&15])
	}
	return b.String()
}

func TestTheUploadSSHHasTheBootstrapsOptions(t *testing.T) {
	s := SSH{Program: "/usr/bin/ssh", Destination: "far", Protocol: "1 1", Options: SSHOptions{Args: []string{"-p", "2222"}}}
	up := s.UploadCommand(context.Background(), nil, [32]byte{}, 10)
	boot := s.Command(context.Background(), nil)
	n := len(boot.Args) - 1
	if len(up.Args) != len(boot.Args) || strings.Join(up.Args[:n], " ") != strings.Join(boot.Args[:n], " ") {
		t.Errorf("upload %q\nboot %q", up.Args, boot.Args)
	}
	if last := up.Args[n]; !strings.Contains(last, "--serve=install "+strings.Repeat("0", 64)+" 10 ") {
		t.Errorf("upload command %q", last)
	}
}
