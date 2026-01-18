/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025-2026
 */

#include <unistd.h>
#include "syscalls.h"
#include "unix.h"
#include "aix_errno.h"

/**
 * @brief close syscall handler.
 *
 * Handles the AIX close syscall.
 * This should be aligned with the POSIX close(2).
 *
 * AIX calling convention:
 *   r3 = fd  (file descriptor)
 *
 * Return value (in r3):
 *   If success returns 0, otherwise, -1 with errno set.
 */
int aix_close(uc_engine *uc)
{
	int ret;
	u32 fd = read_1st_arg();

	ret = close(fd);
	if (ret < 0)
		unix_set_conv_errno(errno);

	TRACE("close", "%u", fd);
	return ret;
}
