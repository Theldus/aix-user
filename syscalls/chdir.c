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
 * @brief chdir syscall handler.
 *
 * Handles the AIX chdir syscall.
 * This should be aligned with the POSIX chdir(2).
 *
 * AIX calling convention:
 *   r3 = pathname 
 *
 * Return value (in r3):
 *   If success returns 0, otherwise, -1 with errno set.
 */
int aix_chdir(uc_engine *uc)
{
	char h_path[1024] = {0};
	int ret  = -1;
	u32 path = read_1st_arg();

	if (!path) {
		unix_set_errno(AIX_EFAULT);
		goto out;
	}

	/* Read path from VM to host. */
	if (uc_mem_read(uc, path, h_path, sizeof h_path)) {
		warn("chdir: failed to read path, at 0x%x\n", path);
		unix_set_errno(AIX_EFAULT);
		goto out;
	}

	ret = chdir(h_path);
	if (ret < 0) {
		unix_set_conv_errno(errno);
		goto out;
	}

	ret = 0;
out:
	TRACE("chdir", "\"%s\"", h_path);
	return ret;
}

/**
 * @brief fchdir syscall handler.
 *
 * Handles the AIX fchdir syscall.
 * This should be aligned with the POSIX fchdir(2).
 *
 * AIX calling convention:
 *   r3 = fd  
 *
 * Return value (in r3):
 *   If success returns 0, otherwise, -1 with errno set.
 */
int aix_fchdir(uc_engine *uc)
{
	int ret = -1;
	u32 fd  = read_1st_arg();

	ret = fchdir(fd);
	if (ret < 0) {
		unix_set_conv_errno(errno);
		goto out;
	}

	ret = 0;
out:
	TRACE("fchdir", "%d", fd);
	return ret;
}
