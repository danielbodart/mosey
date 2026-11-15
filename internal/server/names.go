package server

import (
	"crypto/rand"
	hexenc "encoding/hex"
	"math/big"
)

// Generated session names (D8 R2, bootstrap.md §9.2): ADJECTIVE-NOUN from
// two lists of mosey's own, 64 words each, so 4096 names, every one an
// sname. The words are short, plain and calm, in keeping with the name.
var (
	adjectives = [64]string{
		"amber", "ambling", "bright", "brisk", "calm", "clear", "cosy", "crisp",
		"dappled", "dusky", "eager", "easy", "fair", "fleet", "gentle", "golden",
		"green", "hazy", "hidden", "idle", "jolly", "keen", "kind", "lazy",
		"light", "lively", "lucky", "mellow", "misty", "mossy", "nimble", "noble",
		"olive", "patient", "plain", "quick", "quiet", "rambling", "rosy", "rustic",
		"silver", "sleepy", "slow", "snug", "soft", "steady", "still", "sunny",
		"swift", "tame", "tidy", "tranquil", "upbeat", "velvet", "vivid", "warm",
		"wandering", "wary", "wild", "windy", "wise", "witty", "young", "zesty",
	}
	nouns = [64]string{
		"badger", "beaver", "bison", "bramble", "brook", "canyon", "cedar", "comet",
		"crane", "creek", "dune", "eagle", "egret", "falcon", "fern", "finch",
		"fjord", "fox", "glade", "glen", "grove", "harbour", "hare", "hazel",
		"heath", "heron", "hollow", "ibis", "island", "lark", "linnet", "lynx",
		"maple", "marsh", "meadow", "moor", "moth", "newt", "oak", "orchard",
		"osprey", "otter", "owl", "pebble", "pine", "plover", "pond", "puffin",
		"quail", "raven", "reed", "ridge", "river", "robin", "rowan", "sparrow",
		"spruce", "stoat", "swallow", "thrush", "valley", "willow", "wren", "yarrow",
	}
)

// maxNameDraws is how many names GenerateName draws before it gives up on
// a plain one and adds four hex digits [choice] (bootstrap.md §9.2).
const maxNameDraws = 32

// GenerateName is a name for a new session that no name in taken has:
// ADJECTIVE-NOUN, drawn again on a clash up to maxNameDraws times, and
// then the last draw with '-' and four random hex digits.
func GenerateName(taken map[string]bool) string {
	var name string
	for range maxNameDraws {
		name = adjectives[pick(len(adjectives))] + "-" + nouns[pick(len(nouns))]
		if !taken[name] {
			return name
		}
	}
	for {
		var b [2]byte
		rand.Read(b[:])
		if n := name + "-" + hexenc.EncodeToString(b[:]); !taken[n] {
			return n
		}
	}
}

// pick is a uniform index below n. crypto/rand never fails (Go 1.24): a
// name is not a secret, but this keeps one source of randomness.
func pick(n int) int {
	i, _ := rand.Int(rand.Reader, big.NewInt(int64(n)))
	return int(i.Int64())
}
