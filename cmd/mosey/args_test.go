package main

import (
	"slices"
	"testing"
)

func TestAndroidLinkerIsDroppedFromTheArguments(t *testing.T) {
	got := programArgs("android", []string{"/system/bin/linker64", "/data/data/com.termux/files/usr/bin/mosey", "host"})
	want := []string{"/data/data/com.termux/files/usr/bin/mosey", "host"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestArgumentsStartedDirectlyAreKept(t *testing.T) {
	for _, c := range []struct {
		goos string
		args []string
	}{
		{"android", []string{"/data/data/com.termux/files/usr/bin/mosey", "host"}},
		{"android", []string{"linker64"}},
		{"linux", []string{"/usr/bin/linker64", "host"}},
	} {
		if got := programArgs(c.goos, c.args); !slices.Equal(got, c.args) {
			t.Errorf("%s %q: got %q", c.goos, c.args, got)
		}
	}
}
