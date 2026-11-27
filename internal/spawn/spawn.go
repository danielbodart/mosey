package spawn

import "os"

// Attr is the process Start starts.
type Attr struct {
	// Path is the file to execute.
	Path string
	// Args is the argument vector, argv[0] first.
	Args []string
	// Env is the whole environment.
	Env []string
	// Files are the child's fds 0, 1, 2 and up: Files[i] becomes fd i,
	// and a nil entry is /dev/null. The child inherits no other fd. As
	// with os/exec, the child gets each in blocking mode.
	Files []*os.File
	// MemoryLimitMiB, if not 0, is the memory footprint at which the
	// kernel kills the child with SIGKILL, in MiB.
	MemoryLimitMiB int
}

// Start starts the process a describes and returns it. Wait on it to
// reap it; the ProcessState's SysUsage gives the child's rusage.
func Start(a Attr) (*os.Process, error) { return start(a) }
