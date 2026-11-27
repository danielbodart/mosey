//go:build !darwin

package spawn

import (
	"errors"
	"testing"
)

// Off macOS nothing needs Start, and it says so rather than start a
// process without the limit it was asked for.
func TestStartIsUnsupportedOffMacOS(t *testing.T) {
	p, err := Start(Attr{Path: "/bin/true", Args: []string{"true"}, MemoryLimitMiB: 1})
	if !errors.Is(err, errors.ErrUnsupported) || p != nil {
		t.Errorf("Start gave %v, %v", p, err)
	}
}
