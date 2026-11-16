package install

import (
	"encoding/hex"
	"strconv"
	"strings"
	"testing"

	"github.com/danielbodart/mosey/internal/bootstrap"
)

// FuzzParse holds Parse to §4.7.7 step 1: whatever it accepts names an
// upload directly inside $HOME/.local/bin, so the installer is never
// pointed at another directory, and every field reads back as the
// argument it came from.
func FuzzParse(f *testing.F) {
	const hash = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	f.Add(hash, "5", "/home/me/.local/bin/.upload.Ab12Cd34", "/home/me")
	f.Add(hash, "5", "/home/me/.local/bin/.upload.a/b", "/home/me")
	f.Add(hash, "05", "/home/me/.local/bin/.upload.x", "/home/me")
	f.Add(hash, "5", "/home/me/.local/bin/../.upload.x", "/home/me")
	f.Add(hash, "5", "/home/me/.local/.upload.x", "/home/me")
	f.Fuzz(func(t *testing.T, h, size, temp, home string) {
		r, err := Parse([]string{h, size, temp}, home, 1000)
		if err != nil {
			return
		}
		if !strings.HasPrefix(home, "/") || r.Home != home {
			t.Fatalf("home %q accepted as %q", home, r.Home)
		}
		if temp != home+"/.local/bin/"+r.Temp || strings.Contains(r.Temp, "/") ||
			!strings.HasPrefix(r.Temp, tempPrefix) || r.Temp == tempPrefix ||
			r.Temp == "." || r.Temp == ".." {
			t.Fatalf("temp %q accepted as %q", temp, r.Temp)
		}
		if hex.EncodeToString(r.Hash[:]) != h {
			t.Fatalf("hash %q read as %x", h, r.Hash)
		}
		if r.Size < 1 || r.Size > bootstrap.MaxBinary || strconv.FormatInt(r.Size, 10) != size {
			t.Fatalf("size %q read as %d", size, r.Size)
		}
		if r.UID != 1000 {
			t.Fatalf("uid %d", r.UID)
		}
	})
}
