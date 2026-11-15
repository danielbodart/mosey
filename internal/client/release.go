package client

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/danielbodart/mosey/internal/bootstrap"
	"github.com/danielbodart/mosey/internal/provenance"
)

// releaseDeadline bounds the whole download of a release asset
// (bootstrap.md §4.7.4): 21 MB at 300 kbit/s is 9.3 minutes. A release
// doubled from about 10 MB when it took in sigstore-go (S1).
const releaseDeadline = 10 * time.Minute

// errNoRelease is a 404 for a release asset: no release of that version,
// or none for that platform.
var errNoRelease = errors.New("no such release")

// unprovenError is a release asset whose Sigstore bundle is missing or
// does not verify (bootstrap.md §4.7.4): the release is there, but it is
// not shown to be the release workflow's.
type unprovenError struct{ err error }

func (e *unprovenError) Error() string { return e.err.Error() }
func (e *unprovenError) Unwrap() error { return e.err }

// fetchRelease downloads mosey version v for goos/goarch from the release
// at base (bootstrap.ReleaseBase, or a test's server), checks its SHA-256
// against the release's SHA256SUMS and its Sigstore bundle with pv, which
// must attest this asset by name (so this version and platform) as well
// as by digest,
// before anyone uses a byte of it (bootstrap.md §4.7.4). HTTPS only,
// redirects included, every body bounded.
func fetchRelease(ctx context.Context, hc *http.Client, base, v, goos, goarch string, pv *provenance.Verifier) ([]byte, [32]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, releaseDeadline)
	defer cancel()
	dir := base + "/v" + v + "/"
	name := bootstrap.AssetName(v, goos, goarch)
	sums, err := get(ctx, hc, dir+bootstrap.SumsName, bootstrap.MaxSums)
	if err != nil {
		return nil, [32]byte{}, err
	}
	want, err := bootstrap.ParseSums(sums, name)
	if err != nil {
		return nil, [32]byte{}, err
	}
	bin, err := get(ctx, hc, dir+name, bootstrap.MaxBinary)
	if err != nil {
		return nil, [32]byte{}, err
	}
	if len(bin) == 0 {
		return nil, [32]byte{}, fmt.Errorf("%s is empty", name)
	}
	if got := sha256.Sum256(bin); got != want {
		return nil, [32]byte{}, fmt.Errorf("%s has SHA-256 %x, but %s says %x", name, got, bootstrap.SumsName, want)
	}
	// The bundle last, so a missing release or asset is still reported
	// as that. A 404 here is a release with no bundle for this asset,
	// which is refused (D7), not mistaken for no release at all.
	bundle, err := get(ctx, hc, dir+bootstrap.BundleName(name), provenance.MaxBundle)
	switch {
	case errors.Is(err, errNoRelease):
		return nil, [32]byte{}, &unprovenError{fmt.Errorf("%s: %w", bootstrap.BundleName(name), provenance.ErrMissing)}
	case err != nil:
		return nil, [32]byte{}, err
	}
	if err := pv.Verify(bundle, name, want); err != nil {
		return nil, [32]byte{}, &unprovenError{fmt.Errorf("%s: %w", bootstrap.BundleName(name), err)}
	}
	return bin, want, nil
}

// httpsOnly is an http.Client's CheckRedirect: GitHub sends release
// downloads to its object store, and every hop must be HTTPS too.
func httpsOnly(req *http.Request, via []*http.Request) error {
	if req.URL.Scheme != "https" {
		return fmt.Errorf("refusing a redirect to %s", req.URL.Redacted())
	}
	if len(via) >= 10 {
		return errors.New("too many redirects")
	}
	return nil
}

// releaseClient is the client the downloads use: HTTPS redirects only,
// and the system's proxy settings.
func releaseClient() *http.Client {
	return &http.Client{CheckRedirect: httpsOnly}
}

// get fetches url, at most max bytes of it.
func get(ctx context.Context, hc *http.Client, url string, max int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if req.URL.Scheme != "https" {
		return nil, fmt.Errorf("refusing %s: not https", url)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, fmt.Errorf("%s: %w", url, errNoRelease)
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("%s: %s", url, resp.Status)
	case resp.ContentLength > max:
		return nil, fmt.Errorf("%s is %d bytes, over %d", url, resp.ContentLength, max)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", url, err)
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%s is over %d bytes", url, max)
	}
	return b, nil
}

// readSelf is this client's own file, the very bytes it is running
// (bootstrap.md §4.7.4): on Linux through /proc/self/exe, which is the
// running image even if an upgrade has replaced the path since.
func readSelf() ([]byte, error) {
	path := "/proc/self/exe"
	if runtime.GOOS != "linux" {
		var err error
		if path, err = os.Executable(); err != nil {
			return nil, err
		}
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, bootstrap.MaxBinary+1))
	if err != nil {
		return nil, err
	}
	if len(b) > bootstrap.MaxBinary {
		return nil, fmt.Errorf("%s is over %d bytes", path, bootstrap.MaxBinary)
	}
	return b, nil
}
