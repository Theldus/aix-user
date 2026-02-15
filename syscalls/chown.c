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
 * @brief chown syscall handler.
 *
 * Handles the AIX chown syscall.
 * This should be aligned with the POSIX chown(2).
 *
 * AIX calling convention:
 *   r3 = pathname 
 *   r4 = owner user id
 *   r5 = group id
 *
 * Return value (in r3):
 *   If success returns 0, otherwise, -1 with errno set.
 */
int aix_chown(uc_engine *uc)
{
	char h_path[1024] = {0};
	int ret  = -1;
	u32 path = read_1st_arg();
	u32 uid  = read_2nd_arg();
	u32 gid  = read_3rd_arg();

	if (!path) {
		unix_set_errno(AIX_EFAULT);
		goto out;
	}

	/* Read path from VM to host. */
	if (uc_mem_read(uc, path, h_path, sizeof h_path)) {
		warn("chown: failed to read path, at 0x%x\n", path);
		unix_set_errno(AIX_EFAULT);
		goto out;
	}

	ret = chown(h_path, uid, gid);
	if (ret < 0) {
		unix_set_conv_errno(errno);
		goto out;
	}

	ret = 0;
out:
	TRACE("chown", "\"%s\", %d, %d", h_path, uid, gid);
	return ret;
}
