package bind

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
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

// startTime is field 22 of /proc/<pid>/stat, counted after comm.
func startTime(stat []byte) string {
	close := bytes.LastIndexByte(stat, ')')
	if close < 0 {
		return ""
	}
	f := strings.Fields(string(stat[close+1:]))
	if len(f) < 20 {
		return ""
	}
	return f[19]
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
	// As quoin's chain.zig does: stat again, and the start time must not
	// have changed, or the pid was reused between the reads.
	again, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil || startTime(again) != startTime(stat) || startTime(stat) == "" {
		return Link{}, false
	}
	return l, true
}

// QuoinRemote restates quoin-sudo's rule for remote mode as patched on
// quoin branch mosey/s3-agent-bind-hop (0331bf1, sudo/chain.zig `remote`):
// a link named sshd-session running as the user whose parent is a uid-0
// sshd-session, or a link named mosey-server running as the user. The
// harness also runs quoin's own chain.zig (quoinchain/) on the same chain,
// which is the evidence; this is only for the record.
func QuoinRemote(chain []Link, uid int) bool {
	for i, l := range chain {
		if l.UID == uid && l.Comm == "mosey-server" {
			return true
		}
		if i+1 >= len(chain) {
			break
		}
		p := chain[i+1]
		if l.UID == uid && l.Comm == "sshd-session" && p.UID == 0 && p.Comm == "sshd-session" {
			return true
		}
	}
	return false
}

// PeerChain is the chain of the process at the other end of a unix
// connection, read so that pid reuse cannot attach another process's chain
// (review, major #2): SO_PEERPIDFD (Linux 6.5+) pins the peer as it was at
// connect(2); its pid comes from the pidfd's fdinfo; the chain is read from
// /proc; then the pidfd is polled with signal 0, and if the peer has exited
// meanwhile (so the pid may have been reused) the chain is dropped. Without
// SO_PEERPIDFD no chain is sent: an empty chain shows nothing, a wrong one
// misleads. comm and cmdline remain whatever the process set them to.
func PeerChain(c *net.UnixConn) []Link {
	raw, err := c.SyscallConn()
	if err != nil {
		return nil
	}
	pidfd := -1
	raw.Control(func(fd uintptr) {
		if v, err := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PEERPIDFD); err == nil {
			pidfd = v
		}
	})
	if pidfd < 0 {
		return nil
	}
	defer unix.Close(pidfd)
	info, err := os.ReadFile(fmt.Sprintf("/proc/self/fdinfo/%d", pidfd))
	if err != nil {
		return nil
	}
	pid := 0
	for _, line := range strings.Split(string(info), "\n") {
		if v, ok := strings.CutPrefix(line, "Pid:"); ok {
			pid, _ = strconv.Atoi(strings.TrimSpace(v))
		}
	}
	if pid <= 0 {
		return nil
	}
	chain := ReadChain(pid)
	if unix.PidfdSendSignal(pidfd, 0, nil, 0) != nil {
		return nil
	}
	return chain
}
