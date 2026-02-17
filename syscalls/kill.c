/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025-2026
 */

#include <sys/types.h>
#include <signal.h>
#include "syscalls.h"
#include "unix.h"
#include "aix_errno.h"

/**
 * @brief kill syscall handler.
 *
 * Handles the AIX kill syscall.
 * This should be aligned with the POSIX kill(2).
 *
 * AIX calling convention:
 *   r3 = pid
 *   r4 = signal
 *
 * Return value (in r3):
 *   If success returns 0, otherwise, -1 with errno set.
 */
int aix_kill(uc_engine *uc)
{
	int ret;
	u32 pid = read_1st_arg();
	u32 sig = read_2nd_arg();

	ret = kill(pid, sig);
	if (ret < 0)
		unix_set_conv_errno(errno);

	TRACE("kill", "%d, %d", pid, sig);
	return ret;
}
