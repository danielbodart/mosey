package emu

import (
	"bytes"
	"strings"

	"github.com/danielbodart/mosey/internal/screen"
)

// termpropOSC is the OSC number VTE reads its termprops from, the container
// mark among them (docs/spec/screen.md §4.6).
const termpropOSC = 666

// maxTermpropBody bounds the OSC 666 body emu reads: three values of
// MaxContainerValue bytes, each at most doubled by escaping, are 1.5 KiB,
// and the rest is room for termprops not carried [derived, §3]. A longer
// body is ignored whole.
const maxTermpropBody = 8 << 10

// The container termprops carried, and the prefix that names all of them.
const (
	containerPrefix  = "vte.container."
	containerName    = containerPrefix + "name"
	containerRuntime = containerPrefix + "runtime"
	containerUID     = containerPrefix + "uid"
)

// applyTermprops is the container mark after the OSC 666 body data, as
// tuios hands it over ("666;item;item..."), given the mark cur. It returns
// false, and the caller keeps cur, when the body is not OSC 666, is over
// maxTermpropBody, or carries a container value that is badly escaped or
// fails the allow-list: a rejected sequence changes nothing (§4.6). Every
// item that is not one of the three carried properties is skipped.
//
// This is not an escape-sequence parser: tuios has already found the
// sequence and its body (D9, D19). It only splits the item list, as VTE
// does, at ';'.
func applyTermprops(cur screen.Container, data []byte) (screen.Container, bool) {
	if len(data) > maxTermpropBody {
		return cur, false
	}
	rest, ok := bytes.CutPrefix(data, []byte("666"))
	if !ok || (len(rest) > 0 && rest[0] != ';') {
		return cur, false
	}
	if len(rest) == 0 {
		return cur, true
	}
	c := cur
	for _, item := range strings.Split(string(rest[1:]), ";") {
		if item == containerPrefix {
			c = screen.Container{}
			continue
		}
		key, value, set := strings.Cut(item, "=")
		var field *string
		switch key {
		case containerName:
			field = &c.Name
		case containerRuntime:
			field = &c.Runtime
		case containerUID:
			field = &c.UID
		default:
			continue
		}
		if !set {
			// A bare name unsets the one property, as the prefix unsets
			// all of them [derived, §4.6].
			*field = ""
			continue
		}
		v, ok := unescapeTermprop(value)
		valid := screen.ValidContainerValue
		if key == containerUID {
			valid = screen.ValidContainerUID
		}
		if !ok || !valid(v) {
			return cur, false
		}
		*field = v
	}
	return c, true
}

// unescapeTermprop reads VTE's escapes in a termprop value: \\ is a
// backslash, \s a semicolon and \n a newline; any other escape, or a
// backslash at the end, is refused (flong DESIGN.md "OSC 666"). A newline
// is a C0 control, so a value with one then fails the allow-list.
func unescapeTermprop(s string) (string, bool) {
	if !strings.Contains(s, `\`) {
		return s, true
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			b.WriteByte(s[i])
			continue
		}
		if i+1 >= len(s) {
			return "", false
		}
		i++
		switch s[i] {
		case '\\':
			b.WriteByte('\\')
		case 's':
			b.WriteByte(';')
		case 'n':
			b.WriteByte('\n')
		default:
			return "", false
		}
	}
	return b.String(), true
}
