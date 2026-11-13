package emu

import (
	"strings"
	"testing"
)

func TestSmoke(t *testing.T) {
	for _, f := range All() {
		t.Run(f.Name, func(t *testing.T) {
			e := f.New(20, 4)
			defer e.Close()
			e.Write([]byte("hi \x1b[1;31mred\x1b[0m\r\n\x1b]2;T\x07wide:漢é👍🏽\x1b[6n"))
			txt := Text(e)
			t.Logf("%s\n%s", f.Name, txt)
			if !strings.HasPrefix(txt, "hi red") {
				t.Errorf("text %q", txt)
			}
			c := e.CellAt(3, 0)
			if c.Attr&Bold == 0 || c.Fg != Indexed(1) {
				t.Errorf("cell(3,0) = %v", c)
			}
			x, y, _ := e.Cursor()
			t.Logf("cursor %d,%d title=%q resp=%q", x, y, e.Title(), e.Responses())
		})
	}
}
