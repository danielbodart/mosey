package startup

import (
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
)

// Process is how this mosey was started. The zero Process is a mosey
// started directly whose file is not known: Path and Image are empty and
// Prepare changes nothing.
type Process struct {
	// Path is mosey's own file: argv[0] of a role it starts, so ps shows
	// which file that came from, and what a local session runs
	// (bootstrap.md §2.2).
	Path string
	// Image is the file to re-execute this very program from, or to read
	// it from: /proc/self/exe on Linux, the running image even if D7 has
	// replaced Path since (server.md §2.3). Empty is Path.
	Image string
	// Loader is the Android linker that started this process, or "".
	Loader string
}

// Detect is this process's Process and its arguments, program first, from
// the operating system's goos (runtime.GOOS), the running image exe
// (os.Executable, "" if unknown) and argv (os.Args). Path is "" if this
// program's file cannot be found; whoever needs it says so.
//
// The linker shows in the running image, whatever argv[0] says. A person
// who types `linker64 ./mosey` gives argv[0] "linker64", but Termux's
// termux-exec 1.x keeps mosey's own path there (Dan's phone, 2026-11-27):
// argv is [mosey, mosey, ARGS...] and only exe names the linker. argv[0]
// is still asked when exe is unknown.
func Detect(goos, exe string, argv []string) (Process, []string) {
	if goos == "android" && len(argv) >= 2 {
		loader := ""
		switch {
		case isLinker(exe):
			loader = exe
		case isLinker(argv[0]):
			loader = argv[0]
		}
		if loader != "" {
			// The linker took mosey's path as given; made absolute now,
			// while the working directory is still the one it was given
			// in.
			path, err := filepath.Abs(argv[1])
			if err != nil {
				path = ""
			}
			return Process{Path: path, Loader: loader}, argv[1:]
		}
	}
	p := Process{Path: exe}
	if goos == "linux" || goos == "android" {
		p.Image = "/proc/self/exe"
	}
	return p, argv
}

// isLinker says whether file is Android's dynamic linker, by its name.
func isLinker(file string) bool {
	switch filepath.Base(file) {
	case "linker64", "linker":
		return true
	}
	return false
}

// Executable is the file to re-execute or read this very program from:
// Image, else Path.
func (p Process) Executable() string {
	if p.Image != "" {
		return p.Image
	}
	return p.Path
}

// Prepare makes cmd, not yet started, start the way this process was:
// through the loader, if one started it, as cmd.Path's first argument.
// The linker gives the program its own path as argv[0], so a login
// shell's leading "-" (argv[0] "-bash") cannot pass through it, and is
// said with -l instead, which sh, bash, zsh and fish all take.
func (p Process) Prepare(cmd *exec.Cmd) {
	if p.Loader == "" || cmd.Err != nil {
		return
	}
	args := []string{p.Loader, cmd.Path}
	if len(cmd.Args) > 0 {
		if strings.HasPrefix(cmd.Args[0], "-") {
			args = append(args, "-l")
		}
		args = append(args, cmd.Args[1:]...)
	}
	cmd.Path, cmd.Args = p.Loader, slices.Clip(args)
}
