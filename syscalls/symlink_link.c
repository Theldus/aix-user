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

/* sym/hard link impl. */
static int do_hard_symlink(uc_engine *uc, int hard)
{
	int ret       = -1;
	char *h_path1 = NULL;
	char *h_path2 = NULL;
	char vfs_path1[PATH_MAX+1];
	char vfs_path2[PATH_MAX+1];
	u32 path1  = read_1st_arg();
	u32 path2  = read_2nd_arg();

	/* path1. */
	if (!(h_path1 = mm_vm2host(path1))) {
		unix_set_errno(AIX_EFAULT);
		goto out;
	}
	if (vfs_resolve(h_path1, VFS_NOFOLLOW, vfs_path1) < 0)
		goto out;

	/* path2. */
	if (!(h_path2 = mm_vm2host(path2))) {
		unix_set_errno(AIX_EFAULT);
		goto out;
	}
	if (vfs_resolve(h_path2, VFS_NOFOLLOW, vfs_path2) < 0)
		goto out;

	/* create sym/hard link. */
	if (!hard) ret = symlink(vfs_path1, vfs_path2);
	else       ret =    link(vfs_path1, vfs_path2);

	if (ret < 0) {
		unix_set_conv_errno(errno);
		goto out;
	}
out:
	TRACE((hard ? "link" : "symlink"),
		"\"%s\", \"%s\"", h_path1, h_path2);
	return ret;
}

/**
 * @brief symlink syscall handler.
 *
 * Handles the AIX symlink syscall.
 * This should be aligned with the POSIX symlink(2).
 *
 * AIX calling convention:
 *   r3 = path1 (target file)
 *   r4 = path2 (link path)
 *
 * Return value (in r3):
 *   If success returns 0, otherwise, -1 with errno set.
 */
int aix_symlink(uc_engine *uc) {
	return do_hard_symlink(uc, 0);
}

/* @brief hardlink syscall handler.
 * Same behavior as symlink(2), just calls a different
 * function.
 */
int aix_link(uc_engine *uc) {
	return do_hard_symlink(uc, 1);
}
