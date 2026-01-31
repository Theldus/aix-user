/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025-2026
 */

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include "syscalls.h"
#include "unix.h"
#include "aix_errno.h"

/**
 * @brief kfcntl syscall handler.
 *
 * Very initial implementation of kfcntl
 *
 * AIX calling convention:
 *   r3 = fd
 *   r4 = command
 *   r5 = argument
 *
 * Return value (in r3):
 *   If kfcntl subroutine fails, a value of -1 is returned. The errno
 *   global variable is set to indicate the error. Otherwise,
 *    - F_GETFL: Return the fd status and access modes.
 *    - F_GETFD: Get flags associated with FD (FD_CLOEXEC if set).
 *    - F_SETFD: Set flags to the FD (FD_CLOEXEC).
 *
 * !!Note:!! The flags handled here have the exact same values on Linux
 * and AIX so thats why I am not translating them. For *any* new flags,
 * please make sure they are compatible between systems.
 *
 * Compatible constants:
 *   F_GETFL, F_GETFD, F_SETFD, FD_CLOEXEC, O_WRONLY, O_RDWR
 */
int aix_kfcntl(uc_engine *uc)
{
	((void)uc);
	u32 fd   = read_1st_arg();
	u32 cmd  = read_2nd_arg();
	u32 arg  = read_3rd_arg();
	int lnx_ret = -1;
	int ret     =  0;

	if (cmd != F_GETFL && cmd != F_GETFD && cmd != F_SETFD) {
		ret = -1;
		warn("kfcntl: unknown command: %d\n", cmd);
		goto out;
	}

	/*
	 * Obs: the 'arg' is only evaluated if a cmd requires
	 * a third argument.
	 */
	lnx_ret = fcntl(fd, cmd, arg);
	if (lnx_ret < 0) {
		ret = -1;
		unix_set_conv_errno(errno);
		goto out;
	}

	if (cmd == F_GETFL) {
		if      (lnx_ret & O_WRONLY) ret = O_WRONLY;
		else if (lnx_ret & O_RDWR)   ret = O_RDWR;
	}

out:
	TRACE("kfcntl", "%d, %d, %x", fd, cmd, arg);
	return ret;
}
