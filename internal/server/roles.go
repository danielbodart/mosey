package server

import (
	"context"
	"io"
	"os"
)

// Spawner is the unsandboxed role; see the package doc.
type Spawner struct {
	// Stdin and Stdout are the SSH channel.
	Stdin  io.Reader
	Stdout io.Writer
	// Self is the binary to re-execute as proto and emu.
	Self string
	// FirstPort and LastPort are the UDP port range to bind in. Mosh's man
	// page documents 60000-61000; the same range means firewall rules
	// written for Mosh let mosey through.
	FirstPort, LastPort uint16
}

// Run does the bootstrap and supervises proto and emu until the shell
// exits. If emu dies it is restarted and proto sends the client a full
// redraw (S4 §5.3).
func (s *Spawner) Run(ctx context.Context) error {
	panic("TODO slice 1")
}

// RunProto is the proto role's main: it wraps the IPC fd it was started
// with, enters the sandbox, and runs a Session over IPC.
func RunProto(ctx context.Context, ipcFD *os.File) error {
	panic("TODO slice 1")
}

// RunEmu is the emu role's main: it wraps its IPC fd, enters the sandbox,
// and answers Output and Resize with Update and Replies.
func RunEmu(ctx context.Context, ipcFD *os.File) error {
	panic("TODO slice 1")
}
