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
 * @brief mkdir syscall handler.
 *
 * Handles the AIX mkdir syscall.
 *
 * AIX calling convention:
 *   r3 = path  (file path)
 *   r4 = mode
 *
 * Return value (in r3):
 *   Returns 0 on success, otherwise, -1 with errno set.
 */
int aix_mkdir(uc_engine *uc)
{
	int ret;
	char *opath = NULL;
	u32 path = read_1st_arg();
	u32 mode = read_2nd_arg();

	ret = -1;
	if (!(opath = mm_vm2host(path))) {
		unix_set_errno(AIX_EFAULT);
		goto out;
	}

	ret = mkdir(opath, mode);
	if (ret < 0) {
		unix_set_conv_errno(errno);
		goto out;
	}

out:
	TRACE("mkdir", "\"%s\", 0x%x", opath, mode);
	return ret;
}

/**
 * @brief mkdirat syscall handler.
 *
 * Handles the AIX mkdirat syscall.
 *
 * AIX calling convention:
 *   r3 = dirfd
 *   r4 = path  (file path)
 *   r5 = mode
 *
 * Return value (in r3):
 *   Returns 0 on success, otherwise, -1 with errno set.
 */
int aix_mkdirat(uc_engine *uc)
{
	int ret;
	char *opath = NULL;
	u32 dirfd = read_1st_arg();
	u32 path  = read_2nd_arg();
	u32 mode  = read_3rd_arg();

	ret = -1;
	if (!(opath = mm_vm2host(path))) {
		unix_set_errno(AIX_EFAULT);
		goto out;
	}

	ret = mkdirat(dirfd, opath, mode);
	if (ret < 0) {
		unix_set_conv_errno(errno);
		goto out;
	}

out:
	TRACE("mkdirat", "%d, \"%s\", 0x%x", dirfd, opath, mode);
	return ret;
}
