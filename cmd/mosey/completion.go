package main

import (
	"embed"
	"flag"
	"fmt"
	"strings"

	"github.com/danielbodart/mosey/internal/bootstrap"
	"github.com/danielbodart/mosey/internal/client"
	"github.com/danielbodart/mosey/internal/predict"
)

// The completion scripts are written by hand, one per shell, rather than
// with a completion library (Dan, 2026-11-16): each hands DESTINATION to
// the shell's own ssh host completion, so mosey d<TAB> offers what
// ssh d<TAB> does. What they must agree with mosey on, its flags and
// which take a value, is filled in here from the flag set parseArgs uses,
// so a flag added there is completed without anyone touching a script.
//
//go:embed completion
var completionFiles embed.FS

// completionShells are the shells -completion has a script for.
var completionShells = []string{"bash", "zsh", "fish"}

// completionScript is the completion script for shell, one of
// completionShells, with the client's flags filled in.
func completionScript(shell string) string {
	script, err := completionFiles.ReadFile("completion/mosey." + shell)
	if err != nil {
		panic(fmt.Sprintf("no embedded completion script for %s: %v", shell, err))
	}
	flags, _ := newFlags(&cli{})
	var all, values, zsh, fish []string
	flags.VisitAll(func(f *flag.Flag) {
		name, usage := flag.UnquoteUsage(f)
		takesValue := name != ""
		all = append(all, "-"+f.Name)
		if takesValue {
			values = append(values, "-"+f.Name)
		}
		// zsh's _describe takes NAME:DESCRIPTION, in a single-quoted
		// array element.
		zsh = append(zsh, shellQuote("-"+f.Name+":"+usage))
		line := fmt.Sprintf("complete -c mosey -n __mosey_before_destination -o %s -d %s", f.Name, fishQuote(usage))
		if takesValue {
			line += fmt.Sprintf(" -x -a '(__mosey_value %s)'", f.Name)
		}
		fish = append(fish, line)
	})
	var modes []string
	for _, m := range []predict.Mode{predict.Adaptive, predict.Always, predict.Never} {
		modes = append(modes, m.String())
	}
	return strings.NewReplacer(
		"@MOSEY_PREDICT_MODES@", strings.Join(modes, " "),
		"@MOSEY_UPLOAD_MODES@", strings.Join([]string{string(client.UploadAsk), string(client.UploadYes), string(client.UploadNo)}, " "),
		"@MOSEY_SHELLS@", strings.Join(completionShells, " "),
		"@MOSEY_FLAGS@", strings.Join(all, " "),
		"@MOSEY_VALUE_FLAGS@", strings.Join(values, " "),
		"@MOSEY_SSH_VALUE_LETTERS@", bootstrap.SSHValueLetters,
		"@MOSEY_ZSH_FLAGS@", strings.Join(zsh, " "),
		"@MOSEY_FISH_FLAGS@", strings.Join(fish, "\n"),
	).Replace(string(script))
}

// shellQuote is s in single quotes, for bash or zsh.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// fishQuote is s in single quotes, for fish, where a backslash escapes a
// quote or a backslash inside them.
func fishQuote(s string) string {
	return "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(s) + "'"
}
