// The trampoline into libSystem for program_darwin.go, in the style of
// golang.org/x/sys/unix's zsyscall_darwin_*.s. JMP is spelled the same on
// amd64 and arm64, so one file serves both.

#include "textflag.h"

TEXT libproc_pidinfo_trampoline<>(SB),NOSPLIT,$0-0
	JMP	libproc_pidinfo(SB)
GLOBL	·libproc_pidinfo_trampoline_addr(SB), RODATA, $8
DATA	·libproc_pidinfo_trampoline_addr(SB)/8, $libproc_pidinfo_trampoline<>(SB)
