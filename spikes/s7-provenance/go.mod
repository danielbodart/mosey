module mosey.spike/s7-provenance

go 1.27

require (
	github.com/danielbodart/quoin v0.0.0
	golang.org/x/crypto v0.58.0
	golang.org/x/sys v0.49.0
)

// The spike's tests run against quoin's mosey/s7-provenance-envelope branch,
// in its worktree; the forwarder package itself imports only x/sys.
replace github.com/danielbodart/quoin => /home/dan/Projects/quoin-mosey-s7-provenance
