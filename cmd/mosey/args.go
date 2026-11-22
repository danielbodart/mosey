package main

import "path/filepath"

// programArgs is os.Args with the program first, whatever started it.
//
// On Android an app may not exec a file from its own data directory, so
// Termux (termux-exec) runs it as `/system/bin/linker64 PROGRAM ARGS...`.
// For a dynamic program the linker hides itself from argv; mosey is static
// (D1), so Go's runtime reads the kernel's argv as it is, and without this
// the client would take its own path for the host (seen in Termux,
// 2026-11-22). Only on android: elsewhere a program called linker64 is
// nothing special.
func programArgs(goos string, args []string) []string {
	if goos != "android" || len(args) < 2 {
		return args
	}
	switch filepath.Base(args[0]) {
	case "linker64", "linker":
		return args[1:]
	}
	return args
}
