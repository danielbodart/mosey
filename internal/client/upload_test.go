package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/danielbodart/mosey/internal/bootstrap"
)

// uploadHost is a fake far host for the copier: an ssh stand-in that runs
// the remote command with /bin/sh as the login shell and HOME a directory
// of the test's, never the user's.
type uploadHost struct {
	dir, home, state string
	ssh              string
	asked            []string
	answer           string
}

func newUploadHost(t *testing.T) *uploadHost {
	t.Helper()
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	h := &uploadHost{dir: t.TempDir(), home: t.TempDir(), state: t.TempDir(), answer: "y"}
	h.ssh = filepath.Join(h.dir, "ssh")
	script := `#!/bin/sh
echo ran >> '` + h.dir + `/ran'
for last in "$@"; do :; done
HOME='` + h.home + `' exec /bin/sh -c "$last"
`
	if err := os.WriteFile(h.ssh, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return h
}

// installer is a stand-in mosey whose --serve=install puts itself where
// the real one would, so the test sees exactly the bytes that were sent.
const installer = `#!/bin/sh
[ "$1" = --serve=install ] || exit 9
mkdir -p "$HOME/.local/bin" && cp "$4" "$HOME/.local/bin/mosey"
`

func (h *uploadHost) copier(mode UploadMode, self string) *copier {
	o := Options{
		Upload: mode,
		Stderr: &bytes.Buffer{},
		Log:    slog.New(slog.DiscardHandler),
		Getenv: func(k string) string {
			if k == "XDG_STATE_HOME" {
				return h.state
			}
			return ""
		},
		Ask: func(q string) (string, error) {
			h.asked = append(h.asked, q)
			return h.answer, nil
		},
		Self: func() ([]byte, error) { return []byte(self), nil },
		// Nothing may reach the network unless a test says so.
		HTTP:    &http.Client{Transport: failTransport{}},
		Version: "0.4.2",
	}
	s := bootstrap.SSH{Program: h.ssh, Destination: "far", Protocol: probeProtocol}
	c := newCopier(o, s, bootstrap.Config{"user": {"me"}, "hostname": {"far.example"}, "port": {"22"}})
	c.goos, c.goarch = "linux", "amd64"
	return c
}

func (h *uploadHost) installed() ([]byte, error) {
	return os.ReadFile(filepath.Join(h.home, ".local", "bin", "mosey"))
}

func (h *uploadHost) sshRan() bool {
	_, err := os.Stat(filepath.Join(h.dir, "ran"))
	return err == nil
}

// toolsOnly is a PATH of links to just these tools, so a far host's
// scripts find what they need and never a mosey the machine running the
// test may have installed.
func toolsOnly(t *testing.T, tools ...string) string {
	t.Helper()
	dir := t.TempDir()
	for _, tool := range tools {
		path, err := exec.LookPath(tool)
		if err != nil {
			t.Skipf("no %s", tool)
		}
		if err := os.Symlink(path, filepath.Join(dir, tool)); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

type failTransport struct{}

func (failTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("this test allows no network")
}

var linux = bootstrap.ProbeLine{System: "Linux", Machine: "x86_64"}

func TestTheFirstCopyIsAskedForAndRemembered(t *testing.T) {
	h := newUploadHost(t)
	if err := h.copier(UploadAsk, installer).copy(context.Background(), linux); err != nil {
		t.Fatal(err)
	}
	if got, err := h.installed(); err != nil || string(got) != installer {
		t.Fatalf("installed %q %v", got, err)
	}
	if len(h.asked) != 1 || h.asked[0] != "mosey: far has no mosey this one can use. Copy this one (linux/amd64, 0.0 MB) to ~/.local/bin/ there? [y/N] " {
		t.Errorf("asked %q", h.asked)
	}
	hosts, _ := os.ReadFile(filepath.Join(h.state, "mosey", "upload-hosts"))
	if string(hosts) != "me@far.example:22\n" {
		t.Errorf("remembered %q", hosts)
	}
	// The same host again, at another version or not, is not asked.
	h.asked = nil
	if err := h.copier(UploadAsk, installer).copy(context.Background(), linux); err != nil || len(h.asked) != 0 {
		t.Errorf("second copy: asked %q, %v", h.asked, err)
	}
}

// A ~/.local/bin/mosey the probe could not use is replaced under the one
// question, which covers a host with none too; for another platform it
// names the release instead (bootstrap.md §4.7.5).
func TestAnInstalledCopyThatCannotServeIsReplacedUnderTheOneQuestion(t *testing.T) {
	h := newUploadHost(t)
	if err := os.MkdirAll(filepath.Join(h.home, ".local", "bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.home, ".local", "bin", "mosey"), []byte("a build of another protocol"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := h.copier(UploadAsk, installer).copy(context.Background(), linux); err != nil {
		t.Fatal(err)
	}
	if len(h.asked) != 1 || h.asked[0] != "mosey: far has no mosey this one can use. Copy this one (linux/amd64, 0.0 MB) to ~/.local/bin/ there? [y/N] " {
		t.Errorf("asked %q", h.asked)
	}
	if got, err := h.installed(); err != nil || string(got) != installer {
		t.Errorf("installed %q %v", got, err)
	}
	if q := question("far", "0.4.2", "linux/arm64", nil, false); q != "mosey: far has no mosey this one can use. Download mosey 0.4.2 for linux/arm64 from GitHub and copy it to ~/.local/bin/ there? [y/N] " {
		t.Errorf("for another platform: %q", q)
	}
}

func TestNoConsentMeansNothingIsCopied(t *testing.T) {
	for _, c := range []struct {
		name   string
		mode   UploadMode
		answer string
		noAsk  bool
		says   string
	}{
		{"answered no", UploadAsk, "n", false, "not copying mosey to far"},
		{"answered nothing", UploadAsk, "", false, "not copying mosey to far"},
		{"answered rubbish", UploadAsk, "yep", false, "not copying mosey to far"},
		{"-upload=no", UploadNo, "y", false, "run without -upload=no"},
		{"nobody to ask", UploadAsk, "y", true, "pass -upload=yes"},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newUploadHost(t)
			h.answer = c.answer
			cp := h.copier(c.mode, installer)
			if c.noAsk {
				cp.ask = nil
			}
			err := cp.copy(context.Background(), linux)
			if err == nil || !strings.Contains(err.Error(), c.says) {
				t.Errorf("got %v", err)
			}
			if h.sshRan() {
				t.Error("ssh ran")
			}
			if _, err := os.Stat(filepath.Join(h.state, "mosey", "upload-hosts")); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("a refusal was remembered: %v", err)
			}
		})
	}
}

func TestUploadYesNeitherAsksNorRemembers(t *testing.T) {
	h := newUploadHost(t)
	if err := h.copier(UploadYes, installer).copy(context.Background(), linux); err != nil {
		t.Fatal(err)
	}
	if len(h.asked) != 0 {
		t.Errorf("asked %q", h.asked)
	}
	if _, err := os.Stat(filepath.Join(h.state, "mosey", "upload-hosts")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("remembered: %v", err)
	}
}

func TestAHostWithNoServerBuildIsToldSo(t *testing.T) {
	for p, says := range map[bootstrap.ProbeLine]string{
		{System: "Darwin", Machine: "arm64"}:  "runs on Linux only for now, and far is Darwin",
		{System: "FreeBSD", Machine: "amd64"}: "far is FreeBSD amd64, which mosey has no build for",
		{System: "Linux", Machine: "armv7l"}:  "far is Linux armv7l, which mosey has no build for",
	} {
		h := newUploadHost(t)
		err := h.copier(UploadYes, installer).copy(context.Background(), p)
		if err == nil || !strings.Contains(err.Error(), says) || h.sshRan() {
			t.Errorf("%+v: %v (ssh ran: %v)", p, err, h.sshRan())
		}
	}
}

func TestTheInstallersRefusalReachesTheUser(t *testing.T) {
	h := newUploadHost(t)
	c := h.copier(UploadYes, "#!/bin/sh\necho 'mosey --serve=install: ~/.local/bin is a symbolic link' >&2\nexit 1\n")
	err := c.copy(context.Background(), linux)
	if err == nil || !strings.Contains(err.Error(), "copying mosey to far failed (exit 1") {
		t.Fatalf("got %v", err)
	}
	if said := c.stderr.(*bytes.Buffer).String(); !strings.Contains(said, "is a symbolic link") {
		t.Errorf("stderr %q", said)
	}
}

// release is a local HTTPS server playing GitHub's release downloads.
type release struct {
	srv   *httptest.Server
	files map[string][]byte
	hits  []string
}

func newRelease(t *testing.T, files map[string][]byte) *release {
	r := &release{files: files}
	r.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.hits = append(r.hits, req.URL.Path)
		if req.URL.Path == "/redirect/v0.4.2/SHA256SUMS" {
			http.Redirect(w, req, "http://"+req.Host+"/v0.4.2/SHA256SUMS", http.StatusFound)
			return
		}
		b, ok := r.files[req.URL.Path]
		if !ok {
			http.NotFound(w, req)
			return
		}
		w.Write(b)
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func sums(lines map[string][]byte) []byte {
	var b strings.Builder
	for name, content := range lines {
		s := sha256.Sum256(content)
		b.WriteString(hex.EncodeToString(s[:]) + "  " + name + "\n")
	}
	return []byte(b.String())
}

func (h *uploadHost) foreignCopier(r *release, base string) *copier {
	c := h.copier(UploadYes, "this client's own file, for darwin")
	c.goos, c.goarch = "darwin", "arm64"
	c.http = r.srv.Client()
	c.http.CheckRedirect = httpsOnly
	c.release = r.srv.URL + base
	return c
}

func TestAnotherPlatformGetsItsReleaseCheckedAgainstSHA256SUMS(t *testing.T) {
	h := newUploadHost(t)
	asset := []byte(installer + "# linux/amd64\n")
	r := newRelease(t, map[string][]byte{
		"/v0.4.2/mosey-0.4.2-linux-amd64": asset,
		"/v0.4.2/SHA256SUMS":              sums(map[string][]byte{"mosey-0.4.2-linux-amd64": asset, "mosey-0.4.2-darwin-arm64": []byte("x")}),
	})
	if err := h.foreignCopier(r, "").copy(context.Background(), linux); err != nil {
		t.Fatal(err)
	}
	if got, _ := h.installed(); !bytes.Equal(got, asset) {
		t.Errorf("installed %q", got)
	}
}

func TestABadReleaseIsRefusedBeforeAnythingIsSent(t *testing.T) {
	asset := []byte(installer)
	good := sums(map[string][]byte{"mosey-0.4.2-linux-amd64": asset})
	for _, c := range []struct {
		name  string
		files map[string][]byte
		base  string
		says  string
	}{
		{"hash mismatch", map[string][]byte{"/v0.4.2/mosey-0.4.2-linux-amd64": []byte("tampered"), "/v0.4.2/SHA256SUMS": good}, "", "but SHA256SUMS says"},
		{"not listed", map[string][]byte{"/v0.4.2/mosey-0.4.2-linux-amd64": asset, "/v0.4.2/SHA256SUMS": sums(map[string][]byte{"other": asset})}, "", "does not list"},
		{"no such release", map[string][]byte{}, "", "there is no release v0.4.2 on GitHub"},
		{"asset missing", map[string][]byte{"/v0.4.2/SHA256SUMS": good}, "", "there is no release v0.4.2 on GitHub"},
		{"empty", map[string][]byte{"/v0.4.2/mosey-0.4.2-linux-amd64": {}, "/v0.4.2/SHA256SUMS": sums(map[string][]byte{"mosey-0.4.2-linux-amd64": {}})}, "", "is empty"},
		{"oversized sums", map[string][]byte{"/v0.4.2/SHA256SUMS": bytes.Repeat([]byte("x"), bootstrap.MaxSums+1)}, "", "over"},
		{"redirect to http", map[string][]byte{}, "/redirect", "refusing a redirect"},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newUploadHost(t)
			r := newRelease(t, c.files)
			err := h.foreignCopier(r, c.base).copy(context.Background(), linux)
			if err == nil || !strings.Contains(err.Error(), c.says) {
				t.Errorf("got %v", err)
			}
			if h.sshRan() {
				t.Error("ssh ran")
			}
		})
	}
}

func TestADevelopmentBuildDoesNotLookForARelease(t *testing.T) {
	h := newUploadHost(t)
	r := newRelease(t, nil)
	c := h.foreignCopier(r, "")
	c.version = "0.4.20261114120000"
	err := c.copy(context.Background(), linux)
	if err == nil || !strings.Contains(err.Error(), "this is a development build (0.4.20261114120000) and far is linux/amd64") {
		t.Errorf("got %v", err)
	}
	if len(r.hits) != 0 || h.sshRan() {
		t.Errorf("fetched %q; ssh ran %v", r.hits, h.sshRan())
	}
}

func TestOfflineTheSamePlatformNeedsNoNetwork(t *testing.T) {
	// copier's HTTP fails every request: the copy is this client's own.
	h := newUploadHost(t)
	if err := h.copier(UploadYes, installer).copy(context.Background(), linux); err != nil {
		t.Fatal(err)
	}
}

func TestTheAnswerIsOneLineFromTheTerminal(t *testing.T) {
	var out bytes.Buffer
	ask := AskLine(strings.NewReader("yes\nsomething after\n"), &out)
	a, err := ask("copy? ")
	if err != nil || a != "yes" || out.String() != "copy? " || !yes(a) {
		t.Errorf("%q %v %q", a, err, out.String())
	}
	a, _ = AskLine(strings.NewReader(strings.Repeat("y", 1000)+"\n"), &out)("q")
	if len(a) != maxAnswer {
		t.Errorf("an answer of %d bytes was kept", len(a))
	}
	a, err = AskLine(strings.NewReader(""), &out)("q")
	if err != nil || yes(a) {
		t.Errorf("end of input: %q %v", a, err)
	}
	for _, s := range []string{"y", "Y", "yes", "YES", " y "} {
		if !yes(s) {
			t.Errorf("%q is not yes", s)
		}
	}
	for _, s := range []string{"", "n", "no", "yep", "ja"} {
		if yes(s) {
			t.Errorf("%q is yes", s)
		}
	}
}

func TestAHostIsRememberedByUserHostAndPort(t *testing.T) {
	c := bootstrap.Config{"user": {"me"}, "hostname": {"10.0.0.7"}, "port": {"2222"}}
	if k, ok := hostKey(c, "box"); !ok || k != "me@10.0.0.7:2222" {
		t.Errorf("%q %v", k, ok)
	}
	if _, ok := hostKey(bootstrap.Config{"user": {"m e"}, "hostname": {"x"}, "port": {"22"}}, "x"); ok {
		t.Error("a key with a space")
	}
	path := filepath.Join(t.TempDir(), "mosey", "upload-hosts")
	for _, k := range []string{"b@x:22", "a@x:22", "b@x:22"} {
		if err := remember(path, k); err != nil {
			t.Fatal(err)
		}
	}
	got, _ := os.ReadFile(path)
	if string(got) != "a@x:22\nb@x:22\n" {
		t.Errorf("file %q", got)
	}
	st, _ := os.Stat(path)
	dir, _ := os.Stat(filepath.Dir(path))
	if st.Mode().Perm() != 0o600 || dir.Mode().Perm() != 0o700 {
		t.Errorf("modes %v %v", st.Mode(), dir.Mode())
	}
	if ok, err := remembered(path, "a@x:22"); !ok || err != nil {
		t.Errorf("%v %v", ok, err)
	}
	if ok, _ := remembered(path, "c@x:22"); ok {
		t.Error("an unknown host is remembered")
	}
}

// Run answers a probe with a copy and then starts once more, running what
// it copied; if the far host still has no mosey it can use, it stops
// rather than copy again (bootstrap.md §4.7.8).
func TestRunCopiesThenStartsOnceMore(t *testing.T) {
	for _, c := range []struct {
		says string // what the copied mosey answers --serve=protocol
		want string
	}{
		{probeProtocol, "the server failed to start"},
		{"9 9", "copied mosey to far, but it is still not found there"},
	} {
		h := newUploadHost(t)
		// ssh -G answers with a config; anything else runs as the far host.
		// PATH has the tools the scripts run and no mosey, so the probe
		// finds only what was copied.
		script := `#!/bin/sh
if [ "$1" = -G ]; then printf 'hostname far.example\nuser me\nport 22\n'; exit 0; fi
echo ran >> '` + h.dir + `/ran'
for last in "$@"; do :; done
HOME='` + h.home + `' PATH='` + toolsOnly(t, "uname", "mkdir", "mktemp", "cat", "chmod", "rm", "cp", "ls") + `' exec /bin/sh -c "$last"
`
		os.WriteFile(h.ssh, []byte(script), 0o755)
		self := `#!/bin/sh
case "$1" in
--serve=install) mkdir -p "$HOME/.local/bin" && cp "$4" "$HOME/.local/bin/mosey";;
--serve=protocol) echo '` + c.says + `';;
--serve) cat >/dev/null; echo "MOSEY-ERROR 1 internal -";;
esac
`
		var stderr bytes.Buffer
		err := Run(context.Background(), Options{
			SSH:      bootstrap.SSH{Program: h.ssh, Destination: "far"},
			Version:  "0.4.2",
			Terminal: newFakeTerm(80, 24),
			Stderr:   &stderr,
			Upload:   UploadYes,
			Getenv:   func(string) string { return "" },
			Self:     func() ([]byte, error) { return []byte(self), nil },
		})
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("a copy that answers %s: %v\n%s", c.says, err, stderr.String())
		}
		ran, _ := os.ReadFile(filepath.Join(h.dir, "ran"))
		if n := strings.Count(string(ran), "ran"); n != 3 {
			t.Errorf("a copy that answers %s: ssh ran %d times, want 3 (probe, upload, start)", c.says, n)
		}
	}
}
