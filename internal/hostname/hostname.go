package hostname

import (
	"os"
	"strings"
)

// Max bounds a claimed host name, in bytes [D: one DNS label's bound
// (RFC 1035 §2.3.4), so a host's first label always fits, and a whole
// name of 63 bytes or less goes as it is].
const Max = 63

// maxName bounds any host name, in bytes (RFC 1123 §2.1).
const maxName = 253

// Valid says whether h is a host name (RFC 1123 §2.1): 1 to 253 bytes of
// dot-separated labels, each 1 to 63 letters, digits and '-', not starting
// or ending with '-'. Such a name holds nothing a terminal or a shell acts
// on, and never starts with '-', so it can never reach ssh as an option.
func Valid(h string) bool {
	if len(h) < 1 || len(h) > maxName {
		return false
	}
	for label := range strings.SplitSeq(h, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// ValidClaim says whether h may travel as a client's claimed name: a Valid
// host name of at most Max bytes.
func ValidClaim(h string) bool { return len(h) <= Max && Valid(h) }

// Claim is what a client whose host is called name claims: the name if it
// is a ValidClaim, else its first label if that is one, else "", which is
// no claim.
func Claim(name string) string {
	if ValidClaim(name) {
		return name
	}
	if first, _, _ := strings.Cut(name, "."); ValidClaim(first) {
		return first
	}
	return ""
}

// Own is this machine's Claim, "" when the system gives no usable name.
func Own() string {
	name, err := os.Hostname()
	if err != nil {
		return ""
	}
	return Claim(name)
}

// Label is how a client is shown: "NAME (ADDR)", or ADDR alone when it
// claimed no name. The name never goes without the address, since only
// the address was observed (bootstrap.md §9.1).
func Label(name, addr string) string {
	if name == "" {
		return addr
	}
	return name + " (" + addr + ")"
}
