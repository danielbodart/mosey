//go:build race

package server

// raceEnabled skips the tests that sandbox a copy of the test binary: the
// race detector's runtime makes syscalls the release policies rightly
// leave out, so under -race those children die of the policy, not of a bug.
const raceEnabled = true
