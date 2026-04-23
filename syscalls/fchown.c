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
 * @brief fchown syscall handler.
 *
 * Handles the AIX fchown syscall.
 * This should be aligned with the POSIX fchown(2).
 *
 * AIX calling convention:
 *   r3 = file descriptor
 *   r4 = owner user id
 *   r5 = group id
 *
 * Return value (in r3):
 *   If success returns 0, otherwise, -1 with errno set.
 */
int aix_fchown(uc_engine *uc)
{
	int ret  = -1;
	u32 fd   = read_1st_arg();
	u32 uid  = read_2nd_arg();
	u32 gid  = read_3rd_arg();

	if (fd < 0) {
		unix_set_errno(AIX_EBADF);
		goto out;
	}

	ret = fchown(fd, uid, gid);
	if (ret < 0) {
		unix_set_conv_errno(errno);
		goto out;
	}

	ret = 0;
out:
	TRACE("fchown", "%d, %d, %d", fd, uid, gid);
	return ret;
}
