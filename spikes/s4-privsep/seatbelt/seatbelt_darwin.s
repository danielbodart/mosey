// Trampolines into libSystem, in the style of golang.org/x/sys/unix's
// zsyscall_darwin_*.s. Works for amd64 and arm64 (JMP is spelled the same).

#include "textflag.h"

TEXT libsb_sandbox_init_trampoline<>(SB),NOSPLIT,$0-0
	JMP	libsb_sandbox_init(SB)
GLOBL	·libsb_sandbox_init_trampoline_addr(SB), RODATA, $8
DATA	·libsb_sandbox_init_trampoline_addr(SB)/8, $libsb_sandbox_init_trampoline<>(SB)

TEXT libsb_sandbox_free_error_trampoline<>(SB),NOSPLIT,$0-0
	JMP	libsb_sandbox_free_error(SB)
GLOBL	·libsb_sandbox_free_error_trampoline_addr(SB), RODATA, $8
DATA	·libsb_sandbox_free_error_trampoline_addr(SB)/8, $libsb_sandbox_free_error_trampoline<>(SB)
