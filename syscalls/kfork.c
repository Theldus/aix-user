/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025-2026
 */

#include <unistd.h>
#include "syscalls.h"
#include "unix.h"
#include "aix_errno.h"
#include "mm.h"

/**
 * @brief kfork syscall handler.
 *
 * Handles the AIX kfork syscall.
 * This should be aligned with the POSIX fork(2).
 *
 * AIX calling convention:
 *   no parameters
 *
 * Return value (in r3):
 *   If success returns 0, otherwise, -1 with errno set.
 */
int aix_kfork(uc_engine *uc)
{
	pid_t ret = fork();
	if (ret < 0)
		unix_set_conv_errno(errno);
	TRACE("kfork", " ");
	return ret;
}
