// Pre-runtime seccomp stage, approach (2b), arm64. See the amd64 file.
// Built and cross-compiled in the spike but NOT run with enforcement:
// qemu-user implements neither seccomp nor landlock (measured: ENOSYS).

#include "textflag.h"

TEXT ·prestart(SB),NOSPLIT|NOFRAME,$0
	MOVD	0(RSP), R0		// argc
	CMP	$2, R0
	BLT	done
	MOVD	16(RSP), R1		// argv[1]
	MOVWU	0(R1), R2
	MOVW	$0x0074656e, R3		// "net\0"
	CMPW	R3, R2
	BEQ	install
	MOVW	$0x00756d65, R3		// "emu\0"
	CMPW	R3, R2
	BEQ	install
	B	done

install:
	// prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
	MOVD	$38, R0
	MOVD	$1, R1
	MOVD	$0, R2
	MOVD	$0, R3
	MOVD	$0, R4
	MOVD	$167, R8
	SVC
	CMP	$0, R0
	BNE	fail
	// seccomp(SECCOMP_SET_MODE_FILTER, 0, &preFprog)
	MOVD	$1, R0
	MOVD	$0, R1
	MOVD	$·preFprog(SB), R2
	MOVD	$277, R8
	SVC
	CMP	$0, R0
	BNE	fail

done:
	B	_rt0_arm64_linux(SB)

fail:
	MOVD	$111, R0
	MOVD	$94, R8			// exit_group
	SVC
