// Trampolines into libSystem for sandbox_darwin.go, in the style of
// golang.org/x/sys/unix's zsyscall_darwin_*.s. JMP is spelled the same on
// amd64 and arm64, so one file serves both.

#include "textflag.h"

TEXT libsandbox_init_trampoline<>(SB),NOSPLIT,$0-0
	JMP	libsandbox_init(SB)
GLOBL	·libsandbox_init_trampoline_addr(SB), RODATA, $8
DATA	·libsandbox_init_trampoline_addr(SB)/8, $libsandbox_init_trampoline<>(SB)

TEXT libsandbox_free_error_trampoline<>(SB),NOSPLIT,$0-0
	JMP	libsandbox_free_error(SB)
GLOBL	·libsandbox_free_error_trampoline_addr(SB), RODATA, $8
DATA	·libsandbox_free_error_trampoline_addr(SB)/8, $libsandbox_free_error_trampoline<>(SB)

TEXT libsandbox_check_trampoline<>(SB),NOSPLIT,$0-0
	JMP	libsandbox_check(SB)
GLOBL	·libsandbox_check_trampoline_addr(SB), RODATA, $8
DATA	·libsandbox_check_trampoline_addr(SB)/8, $libsandbox_check_trampoline<>(SB)
