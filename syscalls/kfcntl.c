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

#define AIX_F_DUP2FD 14 /* Equivalent to dup2(2), AIX-only. */

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
 *    - F_DUPFD: Dup the provided fd
 *
 * !!Note:!! The flags handled here have the exact same values on Linux
 * and AIX so thats why I am not translating them. For *any* new flags,
 * please make sure they are compatible between systems.
 *
 * Compatible constants:
 *   F_DUPFD, F_GETFL, F_GETFD, F_SETFD, FD_CLOEXEC, O_WRONLY, O_RDWR
 *   AIX_F_DUP2FD is AIX-only
 *
 * In meantime, there is no dup(2) and dup2(2) syscalls on AIX!,
 * these are only handled by fcntl.
 */
int aix_kfcntl(uc_engine *uc)
{
	((void)uc);
	u32 fd  = read_1st_arg();
	u32 cmd = read_2nd_arg();
	u32 arg = read_3rd_arg();
	int ret = -1;

	/* Call proper functions. */
	switch (cmd) {
	/*
	 * Obs: the 'arg' is only evaluated by fcntl() if a cmd
	 * requires a third argument.
	 */
	case F_DUPFD:
	case F_GETFL:
	case F_GETFD:
	case F_SETFD:      ret = fcntl(fd, cmd, arg); break;
	case AIX_F_DUP2FD: ret = dup2(fd, arg);       break;
	default:
		warn("kfcntl: unknown command: %d\n", cmd);
		goto out;
	}

	/* Check for errors/handle F_GETFL. */
	if (ret < 0)
		unix_set_conv_errno(errno);
	else if (cmd == F_GETFL) {
		if      (ret & O_WRONLY) ret = O_WRONLY;
		else if (ret & O_RDWR)   ret = O_RDWR;
	}

out:
	TRACE("kfcntl", "%d, %d, %x", fd, cmd, arg);
	return ret;
}
