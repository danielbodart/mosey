package startup

import (
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
)

func TestTheAndroidLinkerIsTakenOutOfTheArguments(t *testing.T) {
	p, args := Detect("android", "", []string{"/system/bin/linker64", "/data/data/com.termux/files/home/mosey", "host"})
	if want := []string{"/data/data/com.termux/files/home/mosey", "host"}; !slices.Equal(args, want) {
		t.Errorf("args %q, want %q", args, want)
	}
	want := Process{Path: "/data/data/com.termux/files/home/mosey", Loader: "/system/bin/linker64"}
	if p != want {
		t.Errorf("got %+v, want %+v", p, want)
	}
	if p.Executable() != want.Path {
		t.Errorf("Executable is %q, not mosey's own file", p.Executable())
	}
}

// termux-exec 1.x starts mosey through the linker but keeps mosey's own
// path as argv[0] (Dan's phone, 2026-11-27); only the running image names
// the linker.
func TestTheLinkerIsFoundFromTheRunningImageWhenArgv0IsMosey(t *testing.T) {
	const linker = "/apex/com.android.runtime/bin/linker64"
	for _, argv0 := range []string{"/data/data/com.termux/files/home/.local/bin/mosey", "bin/mosey"} {
		p, args := Detect("android", linker, []string{argv0, "/data/data/com.termux/files/home/.local/bin/mosey", "--serve=protocol"})
		if want := []string{"/data/data/com.termux/files/home/.local/bin/mosey", "--serve=protocol"}; !slices.Equal(args, want) {
			t.Errorf("%s: args %q, want %q", argv0, args, want)
		}
		want := Process{Path: "/data/data/com.termux/files/home/.local/bin/mosey", Loader: linker}
		if p != want {
			t.Errorf("%s: got %+v, want %+v", argv0, p, want)
		}
	}
}

func TestARelativePathThroughTheLinkerIsMadeAbsolute(t *testing.T) {
	p, _ := Detect("android", "", []string{"/system/bin/linker64", "./mosey"})
	if !filepath.IsAbs(p.Path) || filepath.Base(p.Path) != "mosey" {
		t.Errorf("Path %q", p.Path)
	}
}

func TestAProgramStartedDirectlyKeepsItsArguments(t *testing.T) {
	for _, c := range []struct {
		goos, exe string
		argv      []string
	}{
		{"android", "/data/data/com.termux/files/home/mosey", []string{"/data/data/com.termux/files/home/mosey", "host"}},
		{"android", "/apex/com.android.runtime/bin/linker64", []string{"/system/bin/linker64"}},
		{"linux", "/usr/bin/linker64", []string{"/usr/bin/linker64", "host"}},
	} {
		p, args := Detect(c.goos, c.exe, c.argv)
		if !slices.Equal(args, c.argv) || p.Loader != "" {
			t.Errorf("%s %q: %q, loader %q", c.goos, c.argv, args, p.Loader)
		}
		if p.Path != c.exe {
			t.Errorf("%s: Path %q, not the running image %q", c.goos, p.Path, c.exe)
		}
		if p.Image != "/proc/self/exe" {
			t.Errorf("%s: Image %q, not the running image", c.goos, p.Image)
		}
	}
	if p, _ := Detect("darwin", "/usr/local/bin/mosey", []string{"mosey"}); p.Image != "" || p.Executable() != p.Path {
		t.Errorf("darwin: %+v", p)
	}
}

func TestPrepareStartsAProgramThroughTheLoader(t *testing.T) {
	p := Process{Loader: "/system/bin/linker64"}
	cmd := &exec.Cmd{Path: "/usr/bin/ssh", Args: []string{"ssh", "-G", "host"}}
	p.Prepare(cmd)
	if cmd.Path != "/system/bin/linker64" || !slices.Equal(cmd.Args, []string{"/system/bin/linker64", "/usr/bin/ssh", "-G", "host"}) {
		t.Errorf("got %s %q", cmd.Path, cmd.Args)
	}
}

func TestALoginShellThroughTheLoaderIsToldWithDashL(t *testing.T) {
	p := Process{Loader: "/system/bin/linker64"}
	cmd := &exec.Cmd{Path: "/bin/bash", Args: []string{"-bash", "-c", "ls"}}
	p.Prepare(cmd)
	if want := []string{"/system/bin/linker64", "/bin/bash", "-l", "-c", "ls"}; !slices.Equal(cmd.Args, want) {
		t.Errorf("got %q, want %q", cmd.Args, want)
	}
}

func TestPrepareWithoutALoaderChangesNothing(t *testing.T) {
	cmd := &exec.Cmd{Path: "/bin/bash", Args: []string{"-bash"}}
	Process{Path: "/x/mosey"}.Prepare(cmd)
	if cmd.Path != "/bin/bash" || !slices.Equal(cmd.Args, []string{"-bash"}) {
		t.Errorf("got %s %q", cmd.Path, cmd.Args)
	}
}
