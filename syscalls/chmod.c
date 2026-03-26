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
 * @brief chmod syscall handler.
 *
 * Handles the AIX chmod syscall.
 * This should be aligned with the POSIX chmod(2).
 *
 * AIX calling convention:
 *   r3 = pathname 
 *   r4 = file mode
 *
 * Return value (in r3):
 *   If success returns 0, otherwise, -1 with errno set.
 */
int aix_chmod(uc_engine *uc)
{
	char *h_path = NULL;
	int ret      = -1;
	u32 path     = read_1st_arg();
	u32 mode     = read_2nd_arg();

	if (!path) {
		unix_set_errno(AIX_EFAULT);
		goto out;
	}

	/* Convert host buffer from VM memory. */
	if (!(h_path = mm_vm2host(path))) {
		unix_set_errno(AIX_EFAULT);
		goto out;
	}

	ret = chmod(h_path, mode);
	if (ret < 0) {
		unix_set_conv_errno(errno);
		goto out;
	}

	ret = 0;
out:
	TRACE("chmod", "\"%s\", 0%o", h_path, mode);
	return ret;
}
