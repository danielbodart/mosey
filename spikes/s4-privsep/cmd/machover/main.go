// machover prints a Mach-O binary's LC_BUILD_VERSION (min OS and the SDK
// version the linker claims). Apple's sandbox_init(3) man page says named
// profiles kill processes built against SDK >= 27; Go's linker writes this
// field itself, so this checks what a CGO_ENABLED=0 Go build declares.
package main

import (
	"debug/macho"
	"encoding/binary"
	"fmt"
	"os"
)

func main() {
	for _, p := range os.Args[1:] {
		f, err := macho.Open(p)
		if err != nil {
			panic(err)
		}
		for _, l := range f.Loads {
			raw := l.Raw()
			if binary.LittleEndian.Uint32(raw) == 0x32 { // LC_BUILD_VERSION
				minos := binary.LittleEndian.Uint32(raw[12:])
				sdk := binary.LittleEndian.Uint32(raw[16:])
				fmt.Printf("%s: LC_BUILD_VERSION platform=%d minos=%d.%d sdk=%d.%d\n", p,
					binary.LittleEndian.Uint32(raw[8:]), minos>>16, (minos>>8)&0xff, sdk>>16, (sdk>>8)&0xff)
			}
		}
	}
}
