package hostname

import (
	"strings"
	"testing"
)

func TestValidIsRFC1123HostNames(t *testing.T) {
	for h, want := range map[string]bool{
		"desktop":                       true,
		"dan-desktop.lan":               true,
		"BLADE":                         true,
		"9front":                        true,
		strings.Repeat("a", 63):         true,
		strings.Repeat("a", 64):         false,
		"":                              false,
		"-x":                            false,
		"x-":                            false,
		"a..b":                          false,
		"a.":                            false,
		"under_score":                   false,
		"sp ace":                        false,
		"esc\x1b":                       false,
		"ü":                             false,
		strings.Repeat("a.", 126) + "a": true,
		strings.Repeat("a.", 127) + "a": false,
	} {
		if got := Valid(h); got != want {
			t.Errorf("Valid(%q) = %v, want %v", h, got, want)
		}
	}
}

func TestAClaimIsTheNameOrItsFirstLabelOrNothing(t *testing.T) {
	long := strings.Repeat("a", 40) + "." + strings.Repeat("b", 40)
	for name, want := range map[string]string{
		"desktop":                      "desktop",
		"dan-desktop.example.org":      "dan-desktop.example.org",
		long:                           strings.Repeat("a", 40),
		strings.Repeat("a", 64) + ".x": "",
		"bad_name.lan":                 "",
		"":                             "",
		"-x":                           "",
	} {
		got := Claim(name)
		if got != want {
			t.Errorf("Claim(%q) = %q, want %q", name, got, want)
		}
		if got != "" && !ValidClaim(got) {
			t.Errorf("Claim(%q) = %q, which is not a valid claim", name, got)
		}
	}
}

func TestOwnIsAValidClaimOrNothing(t *testing.T) {
	if h := Own(); h != "" && !ValidClaim(h) {
		t.Fatalf("Own() = %q", h)
	}
}

func TestALabelNeverShowsTheNameWithoutTheAddress(t *testing.T) {
	if got := Label("blade", "192.168.1.20"); got != "blade (192.168.1.20)" {
		t.Errorf("got %q", got)
	}
	if got := Label("", "127.0.0.1:60001"); got != "127.0.0.1:60001" {
		t.Errorf("got %q", got)
	}
}
