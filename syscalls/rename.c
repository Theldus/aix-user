/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025-2026
 */

#include <stdio.h>
#include "syscalls.h"
#include "unix.h"
#include "aix_errno.h"
#include "mm.h"

/**
 * @brief rename syscall handler.
 *
 * Handles the AIX rename syscall.
 * This should be aligned with the POSIX rename(2).
 *
 * AIX calling convention:
 *   r3 = oldpath,
 *   r4 = newpath
 *
 * Return value (in r3):
 *   If success returns 0, otherwise, -1 with errno set.
 */
int aix_rename(uc_engine *uc)
{
	char *h_oldp = NULL;
	char *h_newp = NULL;
	int ret      = -1;
	u32 oldp     = read_1st_arg();
	u32 newp     = read_2nd_arg();

	if (!oldp || !newp) {
		unix_set_errno(AIX_EFAULT);
		goto out;
	}

	/* Convert host buffers from VM memory. */
	if (!(h_oldp = mm_vm2host(oldp))) {
		unix_set_errno(AIX_EFAULT);
		goto out;
	}
	if (!(h_newp = mm_vm2host(newp))) {
		unix_set_errno(AIX_EFAULT);
		goto out;
	}

	ret = rename(h_oldp, h_newp);
	if (ret < 0) {
		unix_set_conv_errno(errno);
		goto out;
	}

	ret = 0;
out:
	TRACE("rename", "\"%s\", \"%s\"", h_oldp, h_newp);
	return ret;
}

/**
 * @brief renameat syscall handler.
 *
 * Handles the AIX rename syscall.
 * This should be aligned with the POSIX rename(2).
 *
 * AIX calling convention:
 *   r3 = old file descriptor
 *   r4 = old file path
 *   r5 = new file descriptor
 *   r6 = new file path
 *
 * Return value (in r3):
 *   If success returns 0, otherwise, -1 with errno set.
 */
int aix_renameat(uc_engine *uc)
{
	char *h_oldp = NULL;
	char *h_newp = NULL;
	int ret      = -1;
	u32 oldfd    = read_1st_arg();
	u32 oldp     = read_2nd_arg();
	u32 newfd    = read_3rd_arg();
	u32 newp     = read_4th_arg();

	if (!oldp || !newp) {
		unix_set_errno(AIX_EFAULT);
		goto out;
	}

	/* Convert host buffers from VM memory. */
	if (!(h_oldp = mm_vm2host(oldp))) {
		unix_set_errno(AIX_EFAULT);
		goto out;
	}
	if (!(h_newp = mm_vm2host(newp))) {
		unix_set_errno(AIX_EFAULT);
		goto out;
	}

	ret = renameat(oldfd, h_oldp, newfd, h_newp);
	if (ret < 0) {
		unix_set_conv_errno(errno);
		goto out;
	}

	ret = 0;
out:
	TRACE("renameat", "%d, \"%s\", %d, \"%s\"", oldfd, h_oldp, newfd, h_newp);
	return ret;
}
