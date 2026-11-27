package sandbox

import (
	"fmt"
	"strconv"
)

// Profile is role's Seatbelt profile, the SBPL text that Enter gives
// sandbox_init on macOS (server.md §10 "The profiles"). It is built on any
// host, so its tests run on Linux too.
//
// Each rule is there for a measured reason [M: dan-mac, 2026-11-27]:
//
//   - (deny default) does not deny process-info*, so it is denied by name:
//     otherwise a role could read every process's arguments and path.
//   - Without the hw.ncpu read, the Go runtime's GOMAXPROCS update sees one
//     CPU and drops to 1, and a GC took up to 2.2 s.
//   - proto's UDP rules name the port of the one UDP socket it inherits.
//     The profile denies new binds and sends from new sockets, so only
//     that socket receives and sends. It may send to any address, which
//     roaming needs.
//   - TIOCSWINSZ is the one ioctl proto needs a rule for: TIOCGETA,
//     TIOCGWINSZ and FIONREAD on an inherited fd need none.
//
// Everything else the roles do (read and write, recvmsg with SCM_RIGHTS,
// kevent, the clock, the entropy) needs no rule.
func Profile(role Role, params Params) (string, error) {
	const head = "(version 1)\n(deny default)\n"
	const tail = "(allow sysctl-read (sysctl-name \"hw.ncpu\"))\n(deny process-info*)\n"
	switch role {
	case Proto:
		// The port goes into the text, so it is checked first: a port
		// out of range would make a rule for no socket, or a broken
		// profile.
		if params.UDPPort < 1 || params.UDPPort > 65535 {
			return "", fmt.Errorf("sandbox: proto's UDP port %d is not 1 to 65535", params.UDPPort)
		}
		local := "(local udp \"*:" + strconv.Itoa(params.UDPPort) + "\")"
		return head +
			"(allow network-inbound " + local + ")\n" +
			"(allow network-outbound " + local + ")\n" +
			"(allow file-ioctl (ioctl-command TIOCSWINSZ))\n" +
			tail, nil
	case Emu:
		return head + tail, nil
	}
	return "", fmt.Errorf("sandbox: no profile for role %d", role)
}
