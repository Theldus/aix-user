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
 * @brief access syscall handler.
 *
 * Handles the AIX accesss syscall.
 * This should be aligned with the POSIX access(2).
 *
 * AIX calling convention:
 *   r3 = file path
 *   r4 = mode
 *
 * Return value (in r3):
 *   If success (all perms granted), returns 0, otherwise, -1 with
 *   errno set.
 *
 * Note: [WRXF]_OK share the same values on Linux, and thus,
 * I am not translating them.
 */
int aix_access(uc_engine *uc)
{
	int ret;
	char h_path[1024] = {0};
	u32 path = read_1st_arg();
	u32 mode = read_2nd_arg();

	ret = -1;
	if (uc_mem_read(uc, path, &h_path, sizeof h_path)) {
		unix_set_errno(AIX_EFAULT);
		goto out;
	}

	ret = access(h_path, mode);
	if (ret < 0) {
		unix_set_conv_errno(errno);
		goto out;
	}

	ret = 0;
out:
	TRACE("access", "%s, 0%o", h_path, mode);
	return ret;
}
