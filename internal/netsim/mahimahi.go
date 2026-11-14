package netsim

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// The Mahimahi cellular traces S5 used, recorded with Saturator for Sprout
// (Winstein, Sivaraman and Balakrishnan, NSDI 2013) and published in the
// Mahimahi repository. That repository is GPL-3.0 and the traces carry no
// licence of their own, so they are treated as GPL-3.0 data: fetched when a
// test wants them, checked against the hashes pinned here, kept in a cache
// outside the repository, and never committed to this Apache-2.0 one.
const (
	mahimahiCommit = "f1346c38c415abfc98626dd82450f49a57033603" // 2025-02-13
	mahimahiURL    = "https://raw.githubusercontent.com/ravinet/mahimahi/" + mahimahiCommit + "/traces/"
)

// mahimahiSHA256 pins every trace MahimahiTrace will load. A file that does
// not match is refused, whether it was fetched or was already in the cache.
var mahimahiSHA256 = map[string]string{
	"ATT-LTE-driving.up":        "d58a640b9bccd131a421bff6eaf727aba324d9258b35009655bbf68e087b9b29",
	"ATT-LTE-driving.down":      "73c58f41bf7a3f0fac82810ca61307521be1cf6b77a0e98093fd340bddfd161f",
	"TMobile-LTE-driving.up":    "556620f1c11a61c7766678b08325ef4fc8d1bd774fbc98fb96854ae3d3795b61",
	"TMobile-LTE-driving.down":  "d48ff134fc29c36cc3c3dee203464246bd698f0faede42534a27b0cbe3057055",
	"Verizon-LTE-driving.up":    "669840f626966d7490a27629d4227eb2a866d40f104a6217c53b3f4b5a207d1f",
	"Verizon-LTE-driving.down":  "79f1860b7b195496d7d388d090edb3eaa9cecbbdfb489bf4a5a73d95d8c2e7ce",
	"Verizon-EVDO-driving.up":   "6055d60d234030035f59475dc1d39d99e7c2817b9fa5d485f1f0710b1aae2075",
	"Verizon-EVDO-driving.down": "60c9cd7b5d8be7d89d3807052a043f54787958f04cfd4c6c16fcdac6e2c3b9da",
}

// The environment that steers MahimahiTrace.
const (
	// EnvMahimahiDir names the directory traces are kept in, instead of
	// the user's cache directory.
	EnvMahimahiDir = "MOSEY_MAHIMAHI_DIR"
	// EnvMahimahiFetch, set to "0", stops MahimahiTrace fetching a trace it
	// does not have, for a machine with no network: tests that need one
	// then skip.
	EnvMahimahiFetch = "MOSEY_MAHIMAHI_FETCH"
)

// ErrTraceUnavailable is what MahimahiTrace's error wraps when the trace is
// not cached and could not be fetched: the cue for a test to skip. Any
// other error, such as a trace that does not match its hash, is a failure.
var ErrTraceUnavailable = errors.New("Mahimahi trace unavailable")

// maxTraceFile bounds a fetched trace: the largest S5 used is about 5 MB.
const maxTraceFile = 64 << 20

// fetchTimeout bounds one fetch in real time. It is real time only outside
// a synctest bubble; see MahimahiTrace.
const fetchTimeout = 2 * time.Minute

var mahimahi struct {
	sync.Mutex
	loaded map[string]traceResult
}

type traceResult struct {
	trace *Trace
	err   error
}

// MahimahiTrace is one of the pinned Mahimahi traces, such as
// "Verizon-LTE-driving.down", loaded once per process. It is read from
// $MOSEY_MAHIMAHI_DIR, or from mosey-netsim/mahimahi-<commit> in the user's
// cache directory, and fetched from the Mahimahi repository at the pinned
// commit if it is not there, unless $MOSEY_MAHIMAHI_FETCH is "0". Either
// way it must match its pinned SHA-256.
//
// A test that cannot have the trace gets an error and should skip.
//
// Call it outside a synctest bubble, as Profiles is usually called: inside
// one, the HTTP client's goroutines would belong to the bubble and its
// timeout would be in virtual time, which stands still while a fetch waits
// on the network.
func MahimahiTrace(name string) (*Trace, error) {
	mahimahi.Lock()
	defer mahimahi.Unlock()
	if r, ok := mahimahi.loaded[name]; ok {
		return r.trace, r.err
	}
	t, err := loadMahimahi(name)
	if mahimahi.loaded == nil {
		mahimahi.loaded = map[string]traceResult{}
	}
	mahimahi.loaded[name] = traceResult{t, err}
	return t, err
}

func loadMahimahi(name string) (*Trace, error) {
	sum, ok := mahimahiSHA256[name]
	if !ok {
		return nil, fmt.Errorf("netsim: no Mahimahi trace called %q is pinned", name)
	}
	dir, err := mahimahiDir()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, name)
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if os.Getenv(EnvMahimahiFetch) == "0" {
			return nil, fmt.Errorf("netsim: Mahimahi trace %s is not in %s, and %s=0: %w", name, dir, EnvMahimahiFetch, ErrTraceUnavailable)
		}
		if data, err = fetchMahimahi(name, sum); err != nil {
			return nil, err
		}
		// A cache that cannot be written to costs a fetch next time, and
		// nothing now.
		_ = writeFileAtomic(dir, name, data)
	case err != nil:
		return nil, fmt.Errorf("netsim: reading Mahimahi trace: %w", err)
	default:
		if err := checkSum(name, data, sum); err != nil {
			return nil, err
		}
	}
	t, err := LoadTrace(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("netsim: Mahimahi trace %s: %w", name, err)
	}
	return t, nil
}

func mahimahiDir() (string, error) {
	if d := os.Getenv(EnvMahimahiDir); d != "" {
		return d, nil
	}
	cache, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("netsim: finding a directory for Mahimahi traces (set %s): %w: %w", EnvMahimahiDir, ErrTraceUnavailable, err)
	}
	return filepath.Join(cache, "mosey-netsim", "mahimahi-"+mahimahiCommit[:12]), nil
}

func fetchMahimahi(name, sum string) ([]byte, error) {
	// No keep-alives, so no connection, and no goroutine serving one,
	// outlives the fetch.
	client := &http.Client{
		Timeout:   fetchTimeout,
		Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, DisableKeepAlives: true},
	}
	resp, err := client.Get(mahimahiURL + name)
	if err != nil {
		return nil, fmt.Errorf("netsim: fetching Mahimahi trace %s: %w: %w", name, ErrTraceUnavailable, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("netsim: fetching Mahimahi trace %s: %w: %s", name, ErrTraceUnavailable, resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxTraceFile+1))
	if err != nil {
		return nil, fmt.Errorf("netsim: fetching Mahimahi trace %s: %w: %w", name, ErrTraceUnavailable, err)
	}
	if len(data) > maxTraceFile {
		return nil, fmt.Errorf("netsim: fetching Mahimahi trace %s: more than %d bytes", name, maxTraceFile)
	}
	if err := checkSum(name, data, sum); err != nil {
		return nil, err
	}
	return data, nil
}

func checkSum(name string, data []byte, want string) error {
	got := sha256.Sum256(data)
	if hex.EncodeToString(got[:]) != want {
		return fmt.Errorf("netsim: Mahimahi trace %s has SHA-256 %x, not the pinned %s", name, got, want)
	}
	return nil
}

// writeFileAtomic puts data at dir/name by renaming a temporary file into
// place, so that test binaries fetching at once never see half a trace.
func writeFileAtomic(dir, name string, data []byte) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("netsim: making the Mahimahi trace directory: %w", err)
	}
	f, err := os.CreateTemp(dir, name+".*.tmp")
	if err != nil {
		return fmt.Errorf("netsim: saving Mahimahi trace %s: %w", name, err)
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("netsim: saving Mahimahi trace %s: %w", name, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("netsim: saving Mahimahi trace %s: %w", name, err)
	}
	if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		return fmt.Errorf("netsim: saving Mahimahi trace %s: %w", name, err)
	}
	return nil
}
