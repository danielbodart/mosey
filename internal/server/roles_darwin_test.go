package server

// roleChildren are the roles a test can run in a copy of the test binary
// (main_unix_test.go). The Linux ones enter the seccomp sandbox, which
// macOS does not have, so there are none here yet.
var roleChildren = map[string]func() error{}
