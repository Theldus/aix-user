/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025-2026
 */

#include <unistd.h>
#include <limits.h>
#include "syscalls.h"
#include "unix.h"
#include "aix_errno.h"
#include "mm.h"
#include "vfs.h"

/**
 * @brief readlink syscall handler.
 *
 * Handles the AIX readlink syscall.
 * This should be aligned with the POSIX readlink(2).
 *
 * AIX calling convention:
 *   r3 = path
 *   r4 = buffer
 *   r5 = buffer size
 *
 * Return value (in r3):
 *   If success returns 0, otherwise, -1 with errno set.
 */
int aix_readlink(uc_engine *uc)
{
	int ret;
	char *h_path = NULL;
	char *h_buff = NULL;
	char vfs_path[PATH_MAX+1];
	u32 path     = read_1st_arg();
	u32 buffer   = read_2nd_arg();
	u32 buffsiz  = read_3rd_arg();

	ret = -1;
	if (!(h_path = mm_vm2host(path))) {
		unix_set_errno(AIX_EFAULT);
		goto out;
	}
	if (vfs_resolve(h_path, VFS_NOFOLLOW, vfs_path) < 0)
		goto out;

	if (!(h_buff = mm_vm2host(buffer))) {
		unix_set_errno(AIX_EFAULT);
		goto out;
	}

	ret = readlink(vfs_path, h_buff, buffsiz);
	if (ret < 0) {
		unix_set_conv_errno(errno);
		goto out;
	}
out:
	TRACE("readlink", "%s, %x, %d", h_path, buffer, buffsiz);
	return ret;
}
