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
 * @brief rmdir syscall handler.
 *
 * Handles the AIX rmdir syscall.
 * This should be aligned with the POSIX rmdir(2).
 *
 * AIX calling convention:
 *   r3 = path
 *
 * Return value (in r3):
 *   If success returns 0, otherwise, -1 with errno set.
 */
int aix_rmdir(uc_engine *uc)
{
	int ret;
	char h_path[1024] = {0};
	u32 path = read_1st_arg();

	ret = -1;
	if (uc_mem_read(uc, path, &h_path, sizeof h_path)) {
		unix_set_errno(AIX_EFAULT);
		goto out;
	}

	ret = rmdir(h_path);
	if (ret < 0) {
		unix_set_conv_errno(errno);
		goto out;
	}

	ret = 0;
out:
	TRACE("rmdir", "%s", h_path);
	return ret;
}
