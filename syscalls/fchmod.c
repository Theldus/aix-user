/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025-2026
 */

#include <sys/stat.h>
#include "syscalls.h"
#include "unix.h"
#include "aix_errno.h"
#include "mm.h"

/**
 * @brief fchmod syscall handler.
 *
 * Handles the AIX fchmod syscall.
 * This should be aligned with the POSIX fchmod(2).
 *
 * AIX calling convention:
 *   r3 = file descriptor
 *   r4 = mode
 *
 * Return value (in r3):
 *   If success returns 0, otherwise, -1 with errno set.
 *
 * Note: AIX's modes are numerically equivalent to Linux modes,
 * so there's no need to convert them.
 */
int aix_fchmod(uc_engine *uc)
{
	int ret  = -1;
	u32 fd   = read_1st_arg();
	u32 mode = read_2nd_arg();

	if (fd < 0) {
		unix_set_errno(AIX_EBADF);
		goto out;
	}

	ret = fchmod(fd, mode);
	if (ret < 0) {
		unix_set_conv_errno(errno);
		goto out;
	}

	ret = 0;
out:
	TRACE("fchmod", "%d, %d", fd, mode);
	return ret;
}
