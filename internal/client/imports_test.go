package client_test

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// clientPath is every package the client runs (screen.md §9 item 1), the
// client's own included. mosey is one binary, so it does contain tuios, but
// only the server's emu role may reach it.
var clientPath = []string{
	"client", "render", "screen", "terminal", "userinput", "predict",
	"ssp", "transport", "handshake", "bootstrap", "nocore", "channel", "agent",
	"provenance",
}

// provenanceModules are sigstore-go and the modules it brings, which the
// client may reach only through internal/provenance (the test checks
// that no other client package imports them, directly or not), to verify a downloaded
// release's Sigstore bundle (D7, DEPENDENCIES.md). None of them parses an
// escape sequence. They are named one by one, as modules, so that a
// module sigstore-go starts to depend on in some later version fails
// here until someone has looked at it and added it.
var provenanceModules = []string{
	// The x/ modules, beyond the packages the rest of the path uses, that
	// sigstore-go's dependencies bring: semver and sumdb notes (Rekor
	// checkpoints), errgroup, and x/text's language and Unicode tables.
	"golang.org/x/mod",
	"golang.org/x/sync",
	"golang.org/x/text",
	"github.com/asaskevich/govalidator",
	"github.com/cenkalti/backoff/v5",
	"github.com/cespare/xxhash/v2",
	"github.com/cyberphone/json-canonicalization",
	"github.com/digitorus/pkcs7",
	"github.com/digitorus/timestamp",
	"github.com/go-logr/logr",
	"github.com/go-logr/stdr",
	"github.com/google/certificate-transparency-go",
	"github.com/google/go-containerregistry",
	"github.com/google/uuid",
	"github.com/go-openapi/analysis",
	"github.com/go-openapi/errors",
	"github.com/go-openapi/jsonpointer",
	"github.com/go-openapi/jsonreference",
	"github.com/go-openapi/loads",
	"github.com/go-openapi/runtime",
	"github.com/go-openapi/runtime/server-middleware",
	"github.com/go-openapi/spec",
	"github.com/go-openapi/strfmt",
	"github.com/go-openapi/swag/conv",
	"github.com/go-openapi/swag/fileutils",
	"github.com/go-openapi/swag/jsonutils",
	"github.com/go-openapi/swag/loading",
	"github.com/go-openapi/swag/mangling",
	"github.com/go-openapi/swag/pools",
	"github.com/go-openapi/swag/stringutils",
	"github.com/go-openapi/swag/typeutils",
	"github.com/go-openapi/swag/yamlutils",
	"github.com/go-openapi/validate",
	"github.com/go-viper/mapstructure/v2",
	"github.com/grpc-ecosystem/grpc-gateway/v2",
	"github.com/in-toto/attestation",
	"github.com/in-toto/in-toto-golang",
	"github.com/oklog/ulid/v2",
	"github.com/opencontainers/go-digest",
	"github.com/pkg/errors",
	"github.com/secure-systems-lab/go-securesystemslib",
	"github.com/shibumi/go-pathspec",
	"github.com/sigstore/protobuf-specs",
	"github.com/sigstore/rekor",
	"github.com/sigstore/rekor-tiles/v2",
	"github.com/sigstore/sigstore",
	"github.com/sigstore/sigstore-go",
	"github.com/sigstore/timestamp-authority/v2",
	"github.com/theupdateframework/go-tuf/v2",
	"github.com/transparency-dev/formats",
	"github.com/transparency-dev/merkle",
	"github.com/youmark/pkcs8",
	"google.golang.org/genproto/googleapis/api",
	"google.golang.org/genproto/googleapis/rpc",
	"google.golang.org/grpc",
	"google.golang.org/protobuf",
	"go.opentelemetry.io/auto/sdk",
	"go.opentelemetry.io/otel",
	"go.opentelemetry.io/otel/log",
	"go.opentelemetry.io/otel/metric",
	"go.opentelemetry.io/otel/trace",
	"go.yaml.in/yaml/v3",
	"k8s.io/klog/v2",
}

// The client never parses a remote escape sequence (D9), so nothing on its
// path may depend on a VT parser, directly or not (screen.md §9 item 1,
// §10). Checked two ways, for both operating systems the client ships for:
// no dependency on a known parser, and no dependency from outside the
// standard library, mosey's own client-path packages and the x/ modules,
// so a new escape parser cannot slip in under a name nobody listed.
func TestTheClientPathImportsNoEscapeParser(t *testing.T) {
	gobin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go command to list dependencies with")
	}
	const mosey = "github.com/danielbodart/mosey/internal/"
	var pkgs []string
	for _, p := range clientPath {
		pkgs = append(pkgs, mosey+p)
	}
	forbidden := []string{
		"tuios.dev/",
		mosey + "emu",
		mosey + "server",
		"github.com/charmbracelet/",
		"go.mitchellh.com/libghostty",
	}
	allowed := append([]string{
		mosey + "wire", mosey + "replay",
		"golang.org/x/crypto/", "golang.org/x/sys/", "golang.org/x/term", "golang.org/x/net/",
		"golang.org/x/text/width", "golang.org/x/text/transform",
		"vendor/golang.org/x/",
	}, pkgs...)
	for _, goos := range []string{"linux", "darwin"} {
		graph := importGraph(t, gobin, goos, pkgs)
		// What the client path reaches without going through
		// internal/provenance, and what it reaches through it: only the
		// second may use provenanceModules, so that no other client
		// package can start importing grpc or go-openapi unnoticed.
		var direct []string
		for _, p := range pkgs {
			if p != mosey+"provenance" {
				direct = append(direct, p)
			}
		}
		for _, c := range []struct {
			from    []string
			through bool
		}{{direct, false}, {[]string{mosey + "provenance"}, true}} {
			stop := ""
			if !c.through {
				stop = mosey + "provenance"
			}
		deps:
			for _, dep := range graph.reach(c.from, stop) {
				for _, f := range forbidden {
					if strings.HasPrefix(dep, f) {
						t.Errorf("%s: the client path depends on %s", goos, dep)
						continue deps
					}
				}
				if first, _, _ := strings.Cut(dep, "/"); !strings.Contains(first, ".") && first != "vendor" {
					continue // the standard library
				}
				for _, a := range allowed {
					if dep == a || strings.HasPrefix(dep, a) && strings.HasSuffix(a, "/") {
						continue deps
					}
				}
				if c.through {
					for _, m := range provenanceModules {
						if dep == m || strings.HasPrefix(dep, m+"/") {
							continue deps
						}
					}
					t.Errorf("%s: internal/provenance depends on %s, which is not on the allowed list", goos, dep)
					continue
				}
				t.Errorf("%s: the client path depends on %s other than through internal/provenance, and it is not on the allowed list", goos, dep)
			}
		}
	}
}

// imports is a package graph: each package's direct imports.
type imports map[string][]string

// importGraph is what go list says pkgs and everything they depend on
// import, for goos.
func importGraph(t *testing.T, gobin, goos string, pkgs []string) imports {
	t.Helper()
	cmd := exec.Command(gobin, append([]string{"list", "-deps", "-json=ImportPath,Imports"}, pkgs...)...)
	cmd.Env = append(os.Environ(), "GOOS="+goos)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list for %s: %v\n%s", goos, err, stderr.Bytes())
	}
	g := imports{}
	dec := json.NewDecoder(bytes.NewReader(out))
	for dec.More() {
		var p struct {
			ImportPath string
			Imports    []string
		}
		if err := dec.Decode(&p); err != nil {
			t.Fatalf("reading go list's output for %s: %v", goos, err)
		}
		g[p.ImportPath] = p.Imports
	}
	return g
}

// reach is every package reachable from roots, roots included, without
// going into stop (which is left out too, unless it is a root).
func (g imports) reach(roots []string, stop string) []string {
	seen := map[string]bool{}
	var out []string
	var walk func(string)
	walk = func(p string) {
		if seen[p] {
			return
		}
		seen[p] = true
		out = append(out, p)
		for _, q := range g[p] {
			if q != stop {
				walk(q)
			}
		}
	}
	for _, r := range roots {
		walk(r)
	}
	return out
}
