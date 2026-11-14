package client

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/danielbodart/mosey/internal/bootstrap"
)

// UploadMode is -upload: what to do when the far host has no mosey of
// this version (D7, bootstrap.md §4.7.5).
type UploadMode string

const (
	// UploadAsk asks the first time for each host, and remembers a yes.
	UploadAsk UploadMode = "ask"
	// UploadYes copies without asking, and remembers nothing.
	UploadYes UploadMode = "yes"
	// UploadNo never copies.
	UploadNo UploadMode = "no"
)

// ParseUploadMode reads -upload's value.
func ParseUploadMode(s string) (UploadMode, error) {
	switch m := UploadMode(s); m {
	case UploadAsk, UploadYes, UploadNo:
		return m, nil
	}
	return "", &bootstrap.UsageError{Msg: fmt.Sprintf("mosey: -upload %q: say ask, yes or no", s)}
}

// Bounds on the remembered hosts (bootstrap.md §4.7.5).
const (
	maxHostsFile = 1 << 20
	maxHostKey   = 1100
	// maxAnswer bounds the line read as the answer to the question.
	maxAnswer = 64
)

// HostsPath is where the hosts the user agreed to copy mosey to are
// remembered: beside the log, $XDG_STATE_HOME/mosey/upload-hosts. The state
// directory, not the config one, because the client writes it, and a
// home-manager user's ~/.config may be read-only.
func HostsPath(getenv func(string) string) (string, error) {
	log, err := LogPath(getenv)
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(log), "upload-hosts"), nil
}

// hostKey is how a host is remembered: user@hostname:port as ssh -G
// resolved them, so an alias and its target are one host and two accounts
// on one host are two. ok is false for a key the file cannot hold, whose
// host is then asked every time.
func hostKey(c bootstrap.Config, destination string) (string, bool) {
	host := c.Get("hostname")
	if host == "" {
		host = destination
	}
	key := c.Get("user") + "@" + host + ":" + c.Get("port")
	if len(key) > maxHostKey {
		return "", false
	}
	for i := 0; i < len(key); i++ {
		if key[i] < 0x21 || key[i] > 0x7e {
			return "", false
		}
	}
	return key, true
}

// readHosts is the remembered hosts, one per line. A missing file is no
// hosts.
func readHosts(path string) ([]string, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxHostsFile+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxHostsFile {
		return nil, fmt.Errorf("%s is over %d bytes", path, maxHostsFile)
	}
	var hosts []string
	for line := range bytes.Lines(b) {
		if h := strings.TrimSuffix(string(line), "\n"); h != "" {
			hosts = append(hosts, h)
		}
	}
	return hosts, nil
}

// remembered says whether key is a host the user has agreed to.
func remembered(path, key string) (bool, error) {
	hosts, err := readHosts(path)
	return slices.Contains(hosts, key), err
}

// remember adds key to the file, rewriting it whole through a temporary
// file and a rename, 0600 in a 0700 directory.
func remember(path, key string) error {
	hosts, err := readHosts(path)
	if err != nil {
		return err
	}
	if slices.Contains(hosts, key) {
		return nil
	}
	hosts = append(hosts, key)
	slices.Sort(hosts)
	var b bytes.Buffer
	for _, h := range hosts {
		b.WriteString(h)
		b.WriteByte('\n')
	}
	if b.Len() > maxHostsFile {
		return fmt.Errorf("%s would be over %d bytes", path, maxHostsFile)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".upload-hosts.*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b.Bytes()); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// yes is whether an answer to the question agrees: y or yes, in any case.
func yes(answer string) bool {
	a := strings.ToLower(strings.TrimSpace(answer))
	return a == "y" || a == "yes"
}

// AskLine is Options.Ask for a terminal in cooked mode: it writes the
// question to w and reads one line from r, at most maxAnswer bytes of it
// counted. End of input is an empty answer, which is no.
func AskLine(r io.Reader, w io.Writer) func(question string) (string, error) {
	return func(question string) (string, error) {
		if _, err := io.WriteString(w, question); err != nil {
			return "", err
		}
		var line []byte
		var b [1]byte
		for {
			n, err := r.Read(b[:])
			if n == 1 {
				if b[0] == '\n' {
					return string(line), nil
				}
				if len(line) < maxAnswer {
					line = append(line, b[0])
				}
			}
			if errors.Is(err, io.EOF) {
				io.WriteString(w, "\n")
				return string(line), nil
			}
			if err != nil {
				return "", err
			}
		}
	}
}
