/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025-2026
 */

#include <sys/stat.h>
#include "syscalls.h"
#include "unix.h"
#include "aix_errno.h"

/**
 * @brief umask syscall handler.
 *
 * Handles the AIX umask syscall.
 * This should be aligned with the POSIX umaks(2).
 *
 * AIX calling convention:
 *   r3 = mode
 *
 * Return value (in r3): Returns the previous umask file.
 */
int aix_umask(uc_engine *uc)
{
	int ret;
	u32 mode = read_1st_arg();

	ret = umask(mode);
	TRACE("umask", "%o", mode);
	return ret;
}
