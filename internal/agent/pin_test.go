package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func knownHostsFile(t *testing.T, lines ...string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func line(key ssh.PublicKey) string { return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))) }

// The bind's host key must be the one known_hosts lists for the host ssh
// checked (agent.md §2.3), in every form known_hosts writes it.
func TestABindIsPinnedToTheHostsKnownHostsEntry(t *testing.T) {
	key := hostKey(t).PublicKey()
	other := hostKey(t).PublicKey()
	missing := filepath.Join(t.TempDir(), "absent")
	for _, c := range []struct {
		name  string
		file  string
		host  string
		port  int
		known bool
	}{
		{"a plain entry", knownHostsFile(t, "example.org "+line(key)), "example.org", 22, true},
		{"a non-standard port", knownHostsFile(t, "[example.org]:2222 "+line(key)), "example.org", 2222, true},
		{"port 22 is not [host]:2222", knownHostsFile(t, "[example.org]:2222 "+line(key)), "example.org", 22, false},
		{"a hashed entry", knownHostsFile(t, knownhosts.HashHostname("example.org")+" "+line(key)), "example.org", 22, true},
		{"an alias", knownHostsFile(t, "my-alias "+line(key)), "my-alias", 22, true},
		{"another key for the host", knownHostsFile(t, "example.org "+line(other)), "example.org", 22, false},
		{"another host", knownHostsFile(t, "example.com "+line(key)), "example.org", 22, false},
		{"revoked", knownHostsFile(t, "example.org "+line(key), "@revoked * "+line(key)), "example.org", 22, false},
		{"known only through a CA", knownHostsFile(t, "@cert-authority *.org "+line(other)), "example.org", 22, false},
	} {
		err := Pin(key, c.host, c.port, []string{missing, c.file})
		if (err == nil) != c.known {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	if err := Pin(key, "example.org", 22, []string{missing}); err == nil {
		t.Error("pinned with no known_hosts file at all")
	}
}

func ExamplePin() {
	fmt.Println(Pin(nil, "h", 22, nil) != nil)
	// Output: true
}
