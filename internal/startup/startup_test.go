package startup

import (
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
)

func TestTheAndroidLinkerIsTakenOutOfTheArguments(t *testing.T) {
	p, args := Detect("android", []string{"/system/bin/linker64", "/data/data/com.termux/files/home/mosey", "host"})
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

func TestARelativePathThroughTheLinkerIsMadeAbsolute(t *testing.T) {
	p, _ := Detect("android", []string{"/system/bin/linker64", "./mosey"})
	if !filepath.IsAbs(p.Path) || filepath.Base(p.Path) != "mosey" {
		t.Errorf("Path %q", p.Path)
	}
}

func TestAProgramStartedDirectlyKeepsItsArguments(t *testing.T) {
	for _, c := range []struct {
		goos string
		argv []string
	}{
		{"android", []string{"/data/data/com.termux/files/home/mosey", "host"}},
		{"android", []string{"/system/bin/linker64"}},
		{"linux", []string{"/usr/bin/linker64", "host"}},
	} {
		p, args := Detect(c.goos, c.argv)
		if !slices.Equal(args, c.argv) || p.Loader != "" {
			t.Errorf("%s %q: %q, loader %q", c.goos, c.argv, args, p.Loader)
		}
		if p.Image != "/proc/self/exe" {
			t.Errorf("%s: Image %q, not the running image", c.goos, p.Image)
		}
	}
	if p, _ := Detect("darwin", []string{"mosey"}); p.Image != "" || p.Executable() != p.Path {
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
