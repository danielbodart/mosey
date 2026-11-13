package bind

import (
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Link is one process in a chain read from /proc, leaf first. It is what
// the remote mosey server can see of whoever connected to the session's
// agent socket (SO_PEERCRED pid, then ppid upwards), with no privilege:
// the same quality of evidence quoin-signer has locally.
type Link struct {
	Pid, PPid int
	UID       int
	Comm      string
	Cmdline   []string
}

func (l Link) String() string {
	return fmt.Sprintf("%d %s uid=%d %q", l.Pid, l.Comm, l.UID, l.Cmdline)
}

// ReadChain walks /proc from pid up to pid 1, at most 16 links.
func ReadChain(pid int) []Link {
	var out []Link
	for i := 0; i < 16 && pid > 0; i++ {
		l, ok := readLink(pid)
		if !ok {
			break
		}
		out = append(out, l)
		if pid == 1 {
			break
		}
		pid = l.PPid
	}
	return out
}

func readLink(pid int) (Link, bool) {
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return Link{}, false
	}
	open, close := bytes.IndexByte(stat, '('), bytes.LastIndexByte(stat, ')')
	if open < 0 || close < open {
		return Link{}, false
	}
	fields := strings.Fields(string(stat[close+1:]))
	if len(fields) < 2 {
		return Link{}, false
	}
	ppid, _ := strconv.Atoi(fields[1])
	l := Link{Pid: pid, PPid: ppid, Comm: string(stat[open+1 : close])}
	if st, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid)); err == nil {
		for _, line := range strings.Split(string(st), "\n") {
			if strings.HasPrefix(line, "Uid:") {
				f := strings.Fields(line)
				if len(f) > 1 {
					l.UID, _ = strconv.Atoi(f[1])
				}
			}
		}
	}
	if cl, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid)); err == nil {
		cl = bytes.TrimSuffix(cl, []byte{0})
		if len(cl) > 0 {
			l.Cmdline = strings.Split(string(cl), "\x00")
		}
	}
	return l, true
}

// QuoinRemote is quoin-sudo's rule for remote mode (sudo/chain.zig
// `remote`, read 2026-11-13): a link named sshd-session running as the user
// whose parent is a uid-0 sshd-session. Restated here only to show what a
// mosey session's chain looks like to it.
func QuoinRemote(chain []Link, uid int) bool {
	for i := 0; i+1 < len(chain); i++ {
		l, p := chain[i], chain[i+1]
		if l.UID == uid && l.Comm == "sshd-session" && p.UID == 0 && p.Comm == "sshd-session" {
			return true
		}
	}
	return false
}
