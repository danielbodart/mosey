package server

// roleChildren are the roles a test can run in a copy of the test binary
// (main_unix_test.go). The Linux ones enter the seccomp sandbox, which
// macOS does not have, so there are none here yet.
var roleChildren = map[string]func() error{}

// The launcher holds the server back from users on macOS until the darwin
// code has run on a Mac (spawner_darwin.go). These tests are that run, so
// they let the launcher start it.
func init() { serverRuns = true }
