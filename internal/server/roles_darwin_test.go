package server

// roleChildren are the roles a test can run in a copy of the test binary
// (main_unix_test.go). The Linux ones drive the seccomp policy; the
// Seatbelt profiles have their own tests in internal/sandbox, and the
// spawner's tests here run the real emu under its profile.
var roleChildren = map[string]func() error{}
