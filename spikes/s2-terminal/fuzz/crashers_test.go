package fuzz

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"mosey.spike/s2-terminal/emu"
)

// TestCrashers re-runs every saved hang reproducer in fuzz/crashers/ in a
// child process with a 15 s limit and reports what really happens (hang,
// slow, panic, exit) — the fuzzer only says "hung or terminated
// unexpectedly". Opt-in: MOSEY_CRASHERS=1.
func TestCrashers(t *testing.T) {
	if os.Getenv("MOSEY_CRASHERS") == "" {
		t.Skip("set MOSEY_CRASHERS=1")
	}
	if one := os.Getenv("MOSEY_CRASHER_CHILD"); one != "" {
		name, file, _ := strings.Cut(one, "|")
		b, _ := os.ReadFile(file)
		lines := strings.Split(strings.TrimSpace(string(b)), "\n")
		lit := strings.TrimSuffix(strings.TrimPrefix(lines[len(lines)-1], "[]byte("), ")")
		data, err := strconv.Unquote(lit)
		if err != nil {
			t.Fatalf("unquote: %v", err)
		}
		fac, _ := emu.Get(name)
		start := time.Now()
		e := fac.New(80, 24)
		chunk := []byte(data)
		for len(chunk) > 0 { // same op encoding as run(), no invariant checks
			i := 0
			for i < len(chunk) && chunk[i] != 0xFF {
				i++
			}
			e.Write(chunk[:i])
			chunk = chunk[i:]
			if len(chunk) >= 3 {
				e.Resize(1+int(chunk[1])%200, 1+int(chunk[2])%100)
				chunk = chunk[3:]
			} else if len(chunk) > 0 {
				e.Write(chunk)
				chunk = nil
			}
		}
		os.Stderr.WriteString("DONE " + time.Since(start).String() + "\n")
		return
	}
	dirs, _ := filepath.Glob("crashers/Fuzz*")
	self, _ := os.Executable()
	for _, d := range dirs {
		name := strings.ToLower(strings.TrimPrefix(filepath.Base(d), "Fuzz"))
		files, _ := filepath.Glob(filepath.Join(d, "*"))
		for _, f := range files {
			cmd := exec.Command(self, "-test.run", "^TestCrashers$")
			cmd.Env = append(os.Environ(), "MOSEY_CRASHER_CHILD="+name+"|"+f)
			var out strings.Builder
			cmd.Stderr = &out
			cmd.Stdout = nil
			start := time.Now()
			_ = cmd.Start()
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			verdict := ""
			select {
			case err := <-done:
				s := out.String()
				switch {
				case strings.Contains(s, "DONE "):
					verdict = "completes in " + strings.TrimSpace(s[strings.Index(s, "DONE ")+5:])
				case strings.Contains(s, "panic"):
					verdict = "panic: " + firstLine(s[strings.Index(s, "panic"):])
				case strings.Contains(s, "deadlock"):
					verdict = "go-deadlock abort"
				default:
					verdict = "exit: " + firstLine(s) + " " + errString(err)
				}
			case <-time.After(15 * time.Second):
				_ = cmd.Process.Kill()
				<-done
				verdict = "HANG (killed after 15s)"
			}
			t.Logf("%s %s: %s (%.1fs)", name, filepath.Base(f), verdict, time.Since(start).Seconds())
		}
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
