//go:build race

package predict

// raceEnabled skips the replay of S6's traces, a measurement that takes
// minutes under the race detector and tests no concurrency.
const raceEnabled = true
