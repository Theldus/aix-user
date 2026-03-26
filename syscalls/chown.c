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
	char *h_path = NULL;
	int ret  = -1;
	u32 path = read_1st_arg();
	u32 uid  = read_2nd_arg();
	u32 gid  = read_3rd_arg();

	if (!path) {
		unix_set_errno(AIX_EFAULT);
		goto out;
	}

	/* Convert host buffer from VM memory. */
	if (!(h_path = mm_vm2host(path))) {
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
