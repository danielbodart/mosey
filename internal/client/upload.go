package client

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"runtime"

	"github.com/danielbodart/mosey/internal/bootstrap"
)

// copier is D7's answer to a probe that found no mosey the client can use
// (bootstrap.md §4.7): consent, the binary, the upload. On success the
// caller runs the bootstrap once more.
type copier struct {
	ssh     bootstrap.SSH
	version string // this client's: which release asset to fetch
	cfg     bootstrap.Config
	mode    UploadMode
	ask     func(question string) (string, error)
	stderr  io.Writer
	log     *slog.Logger
	getenv  func(string) string
	release string       // bootstrap.ReleaseBase, or a test's
	http    *http.Client // for the release
	self    func() ([]byte, error)
	// goos and goarch are this client's platform.
	goos, goarch string
}

func newCopier(o Options, s bootstrap.SSH, cfg bootstrap.Config) *copier {
	c := &copier{
		ssh: s, version: o.Version, cfg: cfg, mode: o.Upload, ask: o.Ask, stderr: o.Stderr, log: o.Log, getenv: o.Getenv,
		release: o.Releases, http: o.HTTP, self: o.Self,
		goos: runtime.GOOS, goarch: runtime.GOARCH,
	}
	if c.mode == "" {
		c.mode = UploadAsk
	}
	if c.release == "" {
		c.release = bootstrap.ReleaseBase
	}
	if c.http == nil {
		c.http = releaseClient()
	}
	if c.self == nil {
		c.self = func() ([]byte, error) { return readSelf(s.Self) }
	}
	return c
}

// copy answers the probe p: it ends with a build of the client's own
// installed at ~/.local/bin/mosey on the far host, or with an error for
// the user. It never touches a mosey elsewhere on the host's PATH: the
// probe ran that, whatever its version, and only reports a host with
// none it could use (Dan, 2026-11-15), which includes a
// ~/.local/bin/mosey of another protocol, on PATH or not (Dan,
// 2026-11-16).
func (c *copier) copy(ctx context.Context, p bootstrap.ProbeLine) error {
	dest, v := c.ssh.Destination, c.version
	goos, goarch, ok := bootstrap.Platform(p)
	if !ok {
		return fail(&bootstrap.NoServerError{Probe: p}, "%s is %s %s, which mosey has no build for", dest, p.System, p.Machine)
	}
	platform := goos + "/" + goarch
	if c.mode == UploadNo {
		return fail(&bootstrap.NoServerError{Probe: p}, "%s has no mosey: install it there, or run without -upload=no", dest)
	}
	ours := goos == c.goos && goarch == c.goarch
	if !ours && !bootstrap.IsRelease(v) {
		return fail(&bootstrap.NoServerError{Probe: p}, "this is a development build (%s) and %s is %s, which it cannot copy itself to: %s",
			v, dest, platform, c.byHand(platform))
	}

	// Our own file is read first, so the question can say how big it is;
	// a release is fetched only once the user has said yes. A
	// ~/.local/bin/mosey the probe could not use is replaced by the
	// install (§4.7.7).
	var bin []byte
	if ours {
		var err error
		if bin, err = c.self(); err != nil {
			return fail(err, "reading this mosey's own file to copy it to %s: %v", dest, err)
		}
	}
	if err := c.consent(question(dest, v, platform, bin, ours)); err != nil {
		return err
	}
	var sum [32]byte
	if ours {
		sum = sha256.Sum256(bin)
	} else {
		fmt.Fprintf(c.stderr, "mosey: fetching mosey %s for %s from GitHub\n", v, platform)
		var err error
		bin, sum, err = fetchRelease(ctx, c.http, c.release, v, goos, goarch)
		switch {
		case errors.Is(err, errNoRelease):
			return fail(err, "there is no release v%s on GitHub to fetch mosey for %s from: %s", v, platform, c.byHand(platform))
		case err != nil:
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fail(err, "fetching mosey %s for %s from GitHub: %v: %s", v, platform, err, c.byHand(platform))
		}
	}
	fmt.Fprintf(c.stderr, "mosey: copying mosey %s (%s, %s) to %s\n", v, platform, megabytes(len(bin)), dest)
	if err := c.upload(ctx, bin, sum); err != nil {
		return err
	}
	fmt.Fprintf(c.stderr, "mosey: copied mosey to %s\n", dest)
	return nil
}

// question is §4.7.5's: copy this client's own file, or download its
// version's release for another platform, to a host with no mosey this
// client can use, whether it has none or a ~/.local/bin/mosey the probe
// could not use. Every field is the client's own, never the far side's.
func question(dest, v, platform string, bin []byte, ours bool) string {
	if ours {
		return fmt.Sprintf("mosey: %s has no mosey this one can use. Copy this one (%s, %s) to ~/.local/bin/ there? [y/N] ",
			dest, platform, megabytes(len(bin)))
	}
	return fmt.Sprintf("mosey: %s has no mosey this one can use. Download mosey %s for %s from GitHub and copy it to ~/.local/bin/ there? [y/N] ",
		dest, v, platform)
}

// byHand is the advice when the client cannot supply a build itself.
func (c *copier) byHand(platform string) string {
	return fmt.Sprintf("build mosey for %s and put it at ~/.local/bin/mosey there, or pass -remote", platform)
}

// consent is bootstrap.md §4.7.5: remembered, asked, or given by -upload.
func (c *copier) consent(question string) error {
	dest := c.ssh.Destination
	if c.mode == UploadYes {
		return nil
	}
	path, err := HostsPath(c.getenv)
	if err != nil {
		c.log.Warn("no place to remember hosts", "err", err)
	}
	key, keyOK := hostKey(c.cfg, dest)
	if path != "" && keyOK {
		known, err := remembered(path, key)
		if err != nil {
			c.log.Warn("reading the remembered hosts", "err", err)
		}
		if known {
			c.log.Info("copying mosey: host remembered", "host", key)
			return nil
		}
	}
	if c.ask == nil {
		return fail(nil, "%s has no mosey this one can use, and there is no terminal to ask on: pass -upload=yes to copy it there", dest)
	}
	answer, err := c.ask(question)
	if err != nil {
		return fail(err, "asking whether to copy mosey to %s: %v", dest, err)
	}
	if !yes(answer) {
		return fail(nil, "not copying mosey to %s", dest)
	}
	if path != "" && keyOK {
		if err := remember(path, key); err != nil {
			c.log.Warn("remembering the host", "host", key, "err", err)
		}
	}
	return nil
}

// upload is bootstrap.md §4.7.6: the bootstrap's ssh, the binary on its
// stdin, the far side's complaints on the user's stderr, filtered.
func (c *copier) upload(ctx context.Context, bin []byte, sum [32]byte) error {
	dest := c.ssh.Destination
	cmd := c.ssh.UploadCommand(ctx, c.cfg, sum, int64(len(bin)))
	p, err := startPiped(cmd)
	if err != nil {
		return fail(err, "running %s: %v", cmd.Path, err)
	}
	c.log.Info("upload ssh started", "pid", cmd.Process.Pid, "destination", dest, "bytes", len(bin))
	copied := make(chan struct{})
	go func() {
		defer close(copied)
		w := bootstrap.Sanitize(c.stderr)
		io.Copy(w, p.stderr)
		w.Close()
		p.stderr.Close()
	}()
	go drain(p.stdout)
	wrote := make(chan error, 1)
	go func() {
		_, err := p.stdin.Write(bin)
		p.stdin.Close()
		wrote <- err
	}()
	werr := cmd.Wait()
	<-copied
	if err := <-wrote; err != nil {
		c.log.Warn("writing the binary to ssh", "err", err)
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	status := bootstrap.ExitStatus(werr)
	c.log.Info("upload ssh exited", "status", status)
	switch status {
	case 0:
		return nil
	case 126:
		return fail(werr, "the copy of mosey would not run on %s: is ~/.local/bin on a filesystem mounted noexec?", dest)
	case 255:
		return fail(werr, "ssh to %s failed", dest)
	}
	return fail(werr, "copying mosey to %s failed (exit %d; see above)", dest, status)
}

// megabytes is n bytes for a person: "9.8 MB".
func megabytes(n int) string {
	return fmt.Sprintf("%.1f MB", float64(n)/1e6)
}
