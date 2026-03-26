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
 * @brief unlink syscall handler.
 *
 * Handles the AIX unlink syscall.
 * This should be aligned with the POSIX unlink(2).
 *
 * AIX calling convention:
 *   r3 = path
 *
 * Return value (in r3):
 *   If success returns 0, otherwise, -1 with errno set.
 */
int aix_unlink(uc_engine *uc)
{
	int ret;
	char *h_path = NULL;
	u32 path     = read_1st_arg();

	ret = -1;
	if (!(h_path = mm_vm2host(path))) {
		unix_set_errno(AIX_EFAULT);
		goto out;
	}

	ret = unlink(h_path);
	if (ret < 0) {
		unix_set_conv_errno(errno);
		goto out;
	}

	ret = 0;
out:
	TRACE("unlink", "%s", h_path);
	return ret;
}
