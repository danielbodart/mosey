package main

import "testing"

// Server mode is a flag so that no host name can select it: a host called
// server, or anything else without a leading dash, is the client's.
func TestServeRole(t *testing.T) {
	for _, c := range []struct {
		arg  string
		role string
		ok   bool
	}{
		{"--serve", "", true},
		{"--serve=proto", "proto", true},
		{"--serve=emu", "emu", true},
		{"server", "", false},
		{"serve", "", false},
		{"--server", "", false},
		{"-serve", "", false},
		{"user@server", "", false},
	} {
		role, ok := serveRole(c.arg)
		if role != c.role || ok != c.ok {
			t.Errorf("serveRole(%q) = %q, %v; want %q, %v", c.arg, role, ok, c.role, c.ok)
		}
	}
}
