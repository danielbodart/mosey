package agent

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// Pin checks that key, a captured bind's host key, is one the user's
// known_hosts files list for host at port (agent.md §2.3): the host ssh
// just checked, by HostKeyAlias if there is one. A valid bind proves only
// that some host key signed some session id; this ties it to the
// destination. Files that do not exist are skipped; hashed entries match;
// @revoked refuses; a host known only through @cert-authority does not
// match, so it gets no agent (bootstrap.md §14).
func Pin(key ssh.PublicKey, host string, port int, files []string) error {
	var present []string
	for _, f := range files {
		if _, err := os.Stat(f); err == nil {
			present = append(present, f)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("reading %s: %w", f, err)
		}
	}
	if len(present) == 0 {
		return fmt.Errorf("no known_hosts file lists %s", host)
	}
	check, err := knownhosts.New(present...)
	if err != nil {
		return fmt.Errorf("reading known_hosts: %w", err)
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	// The remote address is not consulted when a host name is given; it
	// only has to parse.
	err = check(addr, &net.TCPAddr{IP: net.IPv4zero, Port: port}, key)
	var ke *knownhosts.KeyError
	var re *knownhosts.RevokedError
	switch {
	case err == nil:
		return nil
	case errors.As(err, &re):
		return fmt.Errorf("the bind's host key is revoked in %s", re.Revoked.Filename)
	case errors.As(err, &ke) && len(ke.Want) > 0:
		return fmt.Errorf("the bind's host key is not the one known_hosts lists for %s", knownhosts.Normalize(addr))
	case errors.As(err, &ke):
		return fmt.Errorf("the bind's host key is not in known_hosts for %s", knownhosts.Normalize(addr))
	}
	return fmt.Errorf("checking the bind's host key: %w", err)
}
