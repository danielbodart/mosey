//go:build !linux && !darwin

package pty

// Another platform has no way written to describe a process yet (D22).
func programOf(int) Program { return Program{} }
