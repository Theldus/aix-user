/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025
 */

#include <unistd.h>
#include "syscalls.h"

/**
 * @brief _exit syscall handler.
 *
 * Handles the AIX _exit syscall, which terminates the process immediately
 * without cleanup. This is the same as POSIX _exit(2).
 *
 * AIX calling convention:
 *   r3 = status (exit code)
 *
 * This function does not return.
 *
 * @return Never returns (calls _exit).
 */
int aix__exit(uc_engine *uc)
{
	((void)uc);

	u32 exit_code = read_gpr(3);
	_exit(exit_code);
	/* NOTREACHED */
}
