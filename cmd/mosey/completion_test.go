package main

import (
	"errors"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/danielbodart/mosey/internal/bootstrap"
)

func TestEveryShellsCompletionScriptCompletesEveryFlag(t *testing.T) {
	flags, _ := newFlags(&cli{})
	for _, shell := range completionShells {
		script := completionScript(shell)
		if strings.Contains(script, "@MOSEY_") {
			t.Errorf("%s: a placeholder is left unfilled", shell)
		}
		flags.VisitAll(func(f *flag.Flag) {
			// bash's list of flags, zsh's NAME:DESCRIPTION pairs and
			// fish's complete -o NAME lines.
			want := map[string]string{
				"bash": `_mosey_flags='([^']* )?-` + regexp.QuoteMeta(f.Name) + `[ ']`,
				"zsh":  `'-` + regexp.QuoteMeta(f.Name) + `:`,
				"fish": `\ncomplete -c mosey .* -o ` + regexp.QuoteMeta(f.Name) + ` `,
			}[shell]
			if !regexp.MustCompile(want).MatchString(script) {
				t.Errorf("%s: nothing matches %s for -%s", shell, want, f.Name)
			}
		})
	}
}

func TestCompletionNeedsAShellItKnows(t *testing.T) {
	for _, args := range [][]string{{"-completion"}, {"-completion", ""}, {"-completion", "tcsh"}, {"-completion=powershell"}} {
		_, err := parseArgs(args, origin{})
		var u *bootstrap.UsageError
		if !errors.As(err, &u) {
			t.Errorf("%q: %v", args, err)
		}
	}
	for _, shell := range completionShells {
		c, err := parseArgs([]string{"-completion", shell}, origin{})
		if err != nil || c.completion != shell {
			t.Errorf("-completion %s: %+v %v", shell, c, err)
		}
	}
}

// bashCompletion is a bash-completion to load, where one is installed in a
// usual place or MOSEY_BASH_COMPLETION names one (NixOS keeps it in the
// store), or "".
func bashCompletion() string {
	for _, p := range []string{
		os.Getenv("MOSEY_BASH_COMPLETION"),
		"/usr/share/bash-completion/bash_completion",
		"/usr/local/share/bash-completion/bash_completion",
		"/opt/homebrew/share/bash-completion/bash_completion",
	} {
		if p == "" {
			continue
		}
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// completer runs the bash completion script as bash would on TAB, in a
// home of its own with an ssh config, and with stand-ins for mosey and ssh
// on PATH that record being run.
type completer struct {
	t                      *testing.T
	bash, script, loadFile string
	dir, home, log         string
}

func newCompleter(t *testing.T, bash, bashCompletion string) *completer {
	dir := t.TempDir()
	c := &completer{t: t, bash: bash, loadFile: bashCompletion, dir: dir, home: filepath.Join(dir, "home"), log: filepath.Join(dir, "ran")}
	write := func(path, content string, mode os.FileMode) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(c.home, ".ssh", "config"), "Host dan-desktop\n  HostName 192.0.2.1\nHost dan-blade *.wild\nHost !negated\nInclude conf.d/*\n", 0o600)
	write(filepath.Join(c.home, ".ssh", "conf.d", "more"), "Host=dan-included\n", 0o600)
	c.script = filepath.Join(dir, "mosey.bash")
	write(c.script, completionScript("bash"), 0o600)
	// The table mosey -list localhost prints (client.List): a header, then
	// a session's name first on each line.
	write(filepath.Join(dir, "bin", "mosey"), `#!/bin/sh
echo "mosey $*" >>"$MOSEY_TEST_LOG"
if [ "$*" = "-list localhost" ]; then
	printf 'NAME  STATE     SINCE\nwork  detached  Mon 16 Nov 10:00\nplay  attached  Mon 16 Nov 11:00\n'
fi
`, 0o700)
	write(filepath.Join(dir, "bin", "ssh"), "#!/bin/sh\necho \"ssh $*\" >>\"$MOSEY_TEST_LOG\"\n", 0o700)
	return c
}

// complete is what bash offers for words, the last being the one under
// the cursor.
func (c *completer) complete(words ...string) []string {
	c.t.Helper()
	return c.completeAt(len(words)-1, words...)
}

// completeAt is what bash offers for words with the cursor on words[cword].
func (c *completer) completeAt(cword int, words ...string) []string {
	c.t.Helper()
	driver := `
load=$1 script=$2 cword=$3
shift 3
if [ -n "$load" ]; then . "$load"; fi
. "$script"
COMP_WORDS=("$@")
COMP_CWORD=$cword
COMP_LINE="$*"
COMP_POINT=${#COMP_LINE}
_mosey
printf '%s\n' "${COMPREPLY[@]}"
`
	args := append([]string{"--norc", "--noprofile", "-c", driver, "bash", c.loadFile, c.script, strconv.Itoa(cword)}, words...)
	cmd := exec.Command(c.bash, args...)
	cmd.Dir = c.dir
	cmd.Env = []string{
		"HOME=" + c.home,
		"PATH=" + filepath.Join(c.dir, "bin") + string(os.PathListSeparator) + os.Getenv("PATH"),
		"XDG_CONFIG_HOME=" + filepath.Join(c.home, ".config"),
		"XDG_DATA_HOME=" + filepath.Join(c.home, ".local", "share"),
		"XDG_STATE_HOME=" + filepath.Join(c.home, ".local", "state"),
		"XDG_CACHE_HOME=" + filepath.Join(c.home, ".cache"),
		"XDG_RUNTIME_DIR=" + filepath.Join(c.dir, "run"),
		"MOSEY_TEST_LOG=" + c.log,
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		c.t.Fatalf("%q: %v\n%s", words, err, stderr.String())
	}
	var got []string
	for line := range strings.Lines(string(out)) {
		if line = strings.TrimSuffix(line, "\n"); line != "" {
			got = append(got, line)
		}
	}
	return got
}

// ran is what the stand-ins for mosey and ssh were run with, and empties
// the record.
func (c *completer) ran() string {
	c.t.Helper()
	b, err := os.ReadFile(c.log)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		c.t.Fatal(err)
	}
	os.Remove(c.log)
	return string(b)
}

func TestBashCompletesHostsFlagsSessionsAndCommands(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash")
	}
	setups := map[string]string{"without bash-completion": ""}
	if bc := bashCompletion(); bc != "" {
		setups["with bash-completion"] = bc
	}
	for name, load := range setups {
		t.Run(name, func(t *testing.T) {
			c := newCompleter(t, bash, load)
			has := func(words []string, want ...string) {
				t.Helper()
				got := c.complete(words...)
				for _, w := range want {
					if !slices.Contains(got, w) {
						t.Errorf("%q: want %q among %q", words, w, got)
					}
				}
				for _, g := range got {
					if strings.ContainsAny(g, "*?!") {
						t.Errorf("%q: offered the pattern %q", words, g)
					}
				}
			}
			none := func(words []string) {
				t.Helper()
				if got := c.complete(words...); len(got) != 0 {
					t.Errorf("%q: want nothing, got %q", words, got)
				}
			}

			// DESTINATION: the ssh config's hosts, as ssh d<TAB> offers.
			has([]string{"mosey", "d"}, "dan-desktop", "dan-blade")
			has([]string{"mosey", "-A", "me@dan-b"}, "me@dan-blade")
			has([]string{"mosey", "-s", "work", "dan-d"}, "dan-desktop")
			has([]string{"mosey", "--", "-p", "2222", "dan-d"}, "dan-desktop")
			has([]string{"mosey", "loc"}, "localhost")
			if load == "" {
				// The fallback follows Include too.
				has([]string{"mosey", "dan-i"}, "dan-included")
			}

			// Flags, and their values.
			has([]string{"mosey", "-pre"}, "-predict")
			has([]string{"mosey", "-"}, "-s", "-kill", "-dir", "-list", "-completion")
			has([]string{"mosey", "-predict", "a"}, "adaptive", "always")
			has([]string{"mosey", "-predict", "=", "n"}, "never")
			has([]string{"mosey", "-upload", ""}, "ask", "yes", "no")
			has([]string{"mosey", "-completion", ""}, "bash", "zsh", "fish")
			if err := os.Mkdir(filepath.Join(c.dir, "src"), 0o700); err != nil {
				t.Fatal(err)
			}
			has([]string{"mosey", "-dir", "sr"}, "src")
			none([]string{"mosey", "-type", ""})

			// The command after DESTINATION completes as a command.
			has([]string{"mosey", "dan-desktop", "ech"}, "echo")
			if got := c.ran(); strings.Contains(got, "ssh") || strings.Contains(got, "mosey") {
				t.Errorf("completing ran %q", got)
			}

			// Sessions, from this machine only, and only for localhost or
			// before DESTINATION is typed.
			has([]string{"mosey", "-s", ""}, "work", "play")
			has([]string{"mosey", "-kill", "w"}, "work")
			if got := c.completeAt(2, "mosey", "-kill", "w", "localhost"); !slices.Equal(got, []string{"work"}) {
				t.Errorf("-kill w<TAB> localhost: %q", got)
			}
			if got := c.ran(); got != "mosey -list localhost\nmosey -list localhost\nmosey -list localhost\n" {
				t.Errorf("listing the sessions ran %q", got)
			}
			if got := c.completeAt(2, "mosey", "-s", "w", "far"); len(got) != 0 {
				t.Errorf("-s w<TAB> far: %q", got)
			}
			if got := c.ran(); got != "" {
				t.Errorf("completing a session on another host ran %q", got)
			}
		})
	}
}
