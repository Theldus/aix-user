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

/* chown/lchown syscall helper function. */
static int do_lchown_chown(uc_engine *uc, int deref)
{
	char vfs_path[PATH_MAX+1];
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

	if (vfs_resolve(h_path,
		(deref ? VFS_FOLLOW : VFS_NOFOLLOW), vfs_path) < 0) {
		goto out;
	}

	if (deref) ret =  chown(vfs_path, uid, gid);
	else       ret = lchown(vfs_path, uid, gid);

	if (ret < 0) {
		unix_set_conv_errno(errno);
		goto out;
	}
out:
	TRACE((deref ? "chown" : "lchown"),
		"\"%s\", %d, %d", h_path, uid, gid);
	return ret;
}

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
int aix_chown(uc_engine *uc) {
	return do_lchown_chown(uc, 1);
}

/**
 * @brief lchown syscall handler.
 * Same as chown, but does not dereference symlinks.
 */
int aix_lchown(uc_engine *uc) {
	return do_lchown_chown(uc, 0);
}
