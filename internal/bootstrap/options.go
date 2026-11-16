package bootstrap

import (
	"fmt"
	"strings"
)

// SSHOptions are the user's ssh options (§2.1), normalised to one flag per
// argument and each option's value as an argument of its own, with -A and
// -a taken out.
type SSHOptions struct {
	Args []string
	// Agent is the last of -A ('A') and -a ('a') given, or 0 for neither:
	// ssh's own last-wins rule (D25).
	Agent byte
}

// Which of ssh's option letters pass through to both ssh runs, and which
// take a value (§2.1). Every other letter is refused: each either breaks
// the two-line protocol (-t, -n, -f, -N, -s, -W, -G, -O) or asks for
// something a session ssh leaves after a second cannot give (-L, -R, -D,
// -X, -M, -S, -w), and saying so is kinder than silently lacking it.
const (
	passFlags   = "46CKkqvx"
	passValues  = "BbcEFIiJlmoPp"
	agentLetter = "Aa"
)

// UsageError is a mistake on the command line (exit 2).
type UsageError struct{ Msg string }

func (e *UsageError) Error() string { return e.Msg }

// SplitSSHOptions splits what follows mosey's -- into the ssh options and
// the rest, which starts at DESTINATION (§2): the first word that is not
// an option or an option's separate value, as ssh's own getopt finds it.
// It judges nothing: ParseSSHOptions then reads the options, and refuses
// what it must.
func SplitSSHOptions(args []string) (opts, rest []string) {
	i := 0
	for i < len(args) {
		a := args[i]
		if len(a) < 2 || a[0] != '-' {
			break
		}
		i++
		for j := 1; j < len(a) && a != "--"; j++ {
			if strings.IndexByte(passValues, a[j]) >= 0 {
				if j == len(a)-1 {
					i++ // the value is the next word
				}
				break
			}
		}
	}
	i = min(i, len(args))
	return args[:i], args[i:]
}

// ParseSSHOptions reads the options given after --, with ssh's getopt
// rules: clusters (-4vC), values attached (-p2222, -oUser=x) or separate
// (-p 2222). A bare word, a second --, a refused letter or a missing value
// is a *UsageError.
func ParseSSHOptions(args []string) (SSHOptions, error) {
	var o SSHOptions
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			return SSHOptions{}, &UsageError{"mosey: -- may be given only once"}
		}
		if len(a) < 2 || a[0] != '-' {
			return SSHOptions{}, &UsageError{fmt.Sprintf("mosey: %q is not an ssh option", a)}
		}
		for j := 1; j < len(a); j++ {
			l := a[j]
			switch {
			case strings.IndexByte(passFlags, l) >= 0:
				o.Args = append(o.Args, "-"+string(l))
			case strings.IndexByte(agentLetter, l) >= 0:
				o.Agent = l
			case strings.IndexByte(passValues, l) >= 0:
				value := a[j+1:]
				if value == "" {
					if i+1 == len(args) {
						return SSHOptions{}, &UsageError{fmt.Sprintf("mosey: ssh option -%c needs a value", l)}
					}
					i++
					value = args[i]
				}
				o.Args = append(o.Args, "-"+string(l), value)
				j = len(a) // the value was the rest of the argument
			default:
				return SSHOptions{}, &UsageError{fmt.Sprintf("mosey: ssh option -%c can't be used for the bootstrap", l)}
			}
		}
	}
	return o, nil
}
