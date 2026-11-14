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
	}
	if got := string(MarshalProbeLine(ProbeLine{"Linux", "aarch64"})); got != "MOSEY-PROBE 1 Linux aarch64\n" {
		t.Errorf("marshalled %q", got)
	}
}

func TestAProbeLineOutsideItsGrammarIsRefused(t *testing.T) {
	for _, line := range []string{
		"MOSEY-PROBE 1 Linux\n",
		"MOSEY-PROBE 1 Linux x86_64 extra\n",
		"MOSEY-PROBE 1 Linux  x86_64\n",
		"MOSEY-PROBE 1 Linux x86_64 \n",
		"MOSEY-PROBE 1 Linux x86_64",
		"MOSEY-PROBE 1 Linux x86_64\r\n",
		"MOSEY-PROBE 01 Linux x86_64\n",
		"MOSEY-PROBE 1 Lin\x00ux x86_64\n",
		"MOSEY-PROBE 1 " + strings.Repeat("S", 65) + " x86_64\n",
	} {
		if p, err := ParseProbeLine([]byte(line)); !errors.Is(err, ErrBadLine) {
			t.Errorf("%q: %+v %v", line, p, err)
		}
	}
	var ve *VersionError
	if _, err := ParseProbeLine([]byte("MOSEY-PROBE 2 Linux x86_64\n")); !errors.As(err, &ve) || ve.Got != 2 {
		t.Errorf("another version: %v", err)
	}
}

func TestReadCredentialReturnsTheProbeAsNoServer(t *testing.T) {
	_, err := ReadCredential(strings.NewReader("Welcome\nMOSEY-PROBE 1 Linux aarch64\n"))
	var ns *NoServerError
	if !errors.As(err, &ns) || !errors.Is(err, ErrNoServer) || ns.Probe != (ProbeLine{"Linux", "aarch64"}) {
		t.Fatalf("%v", err)
	}
	if _, err := ReadCredential(strings.NewReader("MOSEY-PROBE 1 Linux x86 64\n")); !errors.Is(err, ErrBadLine) {
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
		os, arch, ok := Platform(ProbeLine{c.sys, c.machine})
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

func TestOnlyAVersionThatNamesADirectoryCanBeUploaded(t *testing.T) {
	for _, v := range []string{"0.1.2", "dev", "0-unstable-2026-11-14+abc", "e2e-a"} {
		if !CanUpload(v) || !ValidServer(CachePath(v)) {
			t.Errorf("%q", v)
		}
	}
	for _, v := range []string{".", "..", "", "a/b", "a b", "a'b", strings.Repeat("v", 65)} {
		if CanUpload(v) {
			t.Errorf("%q can be uploaded", v)
		}
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
	s := SSH{Destination: "far", Version: "0.1.2"}
	if err := s.Check(); err != nil {
		t.Fatal(err)
	}
	if !s.Probes() || !strings.Contains(s.RemoteCommand(), "v=0.1.2;") {
		t.Errorf("no probe: %q", s.RemoteCommand())
	}
	s.Version = ".."
	if s.Probes() || s.RemoteCommand() != "exec /bin/sh -c 'exec mosey --serve'" {
		t.Errorf("a version that names no directory: %q", s.RemoteCommand())
	}
	s = SSH{Destination: "far", Server: "/opt/mosey", Version: "0.1.2"}
	if s.Probes() || s.RemoteCommand() != "exec /bin/sh -c 'exec /opt/mosey --serve'" {
		t.Errorf("-remote: %q", s.RemoteCommand())
	}
}

// -list's role goes through the probe too, so a lister in the cache is
// found (§4.7.2, §9.4), and through slice 1's and -remote's commands.
func TestTheProbeRunsTheRolesFlag(t *testing.T) {
	for _, c := range []struct {
		s    SSH
		want string
	}{
		{SSH{Destination: "far", Version: "0.1.2", Role: RoleList}, `then exec "$m" --serve=list; fi`},
		{SSH{Destination: "far", Version: "..", Role: RoleList}, "exec /bin/sh -c 'exec mosey --serve=list'"},
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
		probeCommand("0-unstable-2026-11-14+abc_1.x", "--serve"),
		uploadCommand("0.1.2", [32]byte{1, 2}, 12345),
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

// writeMosey is a stand-in mosey that says it is version and, as the
// launcher, says which it is and what it read on stdin.
func writeMosey(t *testing.T, path, version, name string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\ncase \"$1\" in\n--serve=version) echo " + version + ";;\n--serve) echo \"" + name + " read $(cat)\";;\nesac\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
}

// The probe runs, as each login shell would run it, whichever of the cache
// and PATH says it is this version, handing it stdin; and with neither
// prints a ProbeLine that parses and exits 0 (§4.7.2).
func TestTheProbeFindsThisVersionOrSaysWhatTheHostIs(t *testing.T) {
	const v = "0.9.1+e2e"
	for _, shell := range shells(t) {
		for _, c := range []struct {
			name   string
			cache  string // version of a mosey in ~/.cache/mosey/v, "" for none
			path   string // version of a mosey on PATH
			served string
		}{
			{"cache", v, "", "cache"},
			{"path", "", v, "path"},
			{"cache first", v, v, "cache"},
			{"wrong cache, right path", "0.9.0", v, "path"},
			{"wrong everywhere", "0.9.0", "0.8.0", ""},
			{"nothing", "", "", ""},
		} {
			home, bin := t.TempDir(), t.TempDir()
			if c.cache != "" {
				writeMosey(t, filepath.Join(home, ".cache", "mosey", v, "mosey"), c.cache, "cache")
			}
			if c.path != "" {
				writeMosey(t, filepath.Join(bin, "mosey"), c.path, "path")
			}
			if c.path != "" && !keepsPath(shell, bin) {
				// NixOS's /etc/zshenv, which zsh reads even with -f, sets
				// PATH afresh and hides the test's mosey; the cases that
				// need no PATH still test this shell's quoting.
				continue
			}
			cmd := exec.Command(shell, "-c", SSH{Version: v}.RemoteCommand())
			cmd.Env = []string{"HOME=" + home, "PATH=" + bin + ":/usr/bin:/bin:/run/current-system/sw/bin"}
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

// keepsPath says whether shell -c leaves a PATH starting with bin alone.
func keepsPath(shell, bin string) bool {
	cmd := exec.Command(shell, "-c", "/bin/sh -c 'echo $PATH'")
	cmd.Env = []string{"PATH=" + bin + ":/usr/bin:/bin"}
	out, err := cmd.Output()
	return err == nil && strings.HasPrefix(string(out), bin+":")
}

// The upload script puts stdin in a mktemp file in ~/.cache/mosey, runs it
// as the installer with the version, hash, size and its own path, passes
// on its status, and removes the temporary file whatever happened
// (§4.7.6).
func TestTheUploadScriptRunsTheCopyAsItsInstaller(t *testing.T) {
	for _, shell := range shells(t) {
		for _, status := range []string{"0", "1"} {
			home := t.TempDir()
			copy := []byte("#!/bin/sh\necho \"$@\" > \"$HOME/args\"\nexit " + status + "\n")
			sum := sha256.Sum256(copy)
			s := SSH{Version: "0.1.2", Destination: "far"}
			cmd := exec.Command(shell, "-c", uploadCommand(s.Version, sum, int64(len(copy))))
			cmd.Env = []string{"HOME=" + home, "PATH=/usr/bin:/bin:/run/current-system/sw/bin"}
			cmd.Dir = home
			cmd.Stdin = bytes.NewReader(copy)
			out, err := cmd.CombinedOutput()
			if got := ExitStatus(err); got != int(status[0]-'0') {
				t.Errorf("%s: exit %d: %s", filepath.Base(shell), got, out)
				continue
			}
			args, _ := os.ReadFile(filepath.Join(home, "args"))
			f := strings.Fields(string(args))
			if len(f) != 5 || f[0] != "--serve=install" || f[1] != "0.1.2" || f[2] != hexOf(sum) || f[3] != strconv.Itoa(len(copy)) ||
				!strings.HasPrefix(f[4], home+"/.cache/mosey/.upload.") {
				t.Errorf("%s: installer ran with %q", filepath.Base(shell), args)
			}
			if entries, _ := os.ReadDir(filepath.Join(home, ".cache", "mosey")); len(entries) != 0 {
				t.Errorf("%s: left %v", filepath.Base(shell), entries)
			}
			if st, err := os.Stat(filepath.Join(home, ".cache", "mosey")); err != nil || st.Mode().Perm() != 0o700 {
				t.Errorf("%s: ~/.cache/mosey is %v %v", filepath.Base(shell), st.Mode(), err)
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
	s := SSH{Program: "/usr/bin/ssh", Destination: "far", Version: "0.1.2", Options: SSHOptions{Args: []string{"-p", "2222"}}}
	up := s.UploadCommand(context.Background(), nil, [32]byte{}, 10)
	boot := s.Command(context.Background(), nil)
	n := len(boot.Args) - 1
	if len(up.Args) != len(boot.Args) || strings.Join(up.Args[:n], " ") != strings.Join(boot.Args[:n], " ") {
		t.Errorf("upload %q\nboot %q", up.Args, boot.Args)
	}
	if last := up.Args[n]; !strings.Contains(last, "--serve=install 0.1.2 "+strings.Repeat("0", 64)+" 10 ") {
		t.Errorf("upload command %q", last)
	}
}
