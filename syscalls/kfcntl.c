/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025
 */

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include "syscalls.h"
#include "unix.h"
#include "aix_errno.h"

static u32 o_errno;

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
 *    - F_GETFL: Return the fd flags.
 */
int aix_kfcntl(uc_engine *uc)
{
	((void)uc);
	u32 fd   = read_1st_arg();
	u32 cmd  = read_2nd_arg();
	u32 arg  = read_3rd_arg();
	o_errno  = errno;
	int lnx_ret = -1;
	int ret     = -1;

	switch (cmd) {
		case F_GETFL:
			lnx_ret = fcntl(fd, cmd);
			break;
		default:
			warn("kfcntl: unknown command: %d\n", cmd);
			break;
	}

	if (lnx_ret < 0) {
		unix_set_conv_errno(errno);
		goto out;
	}

	/* These flags match AIX's flags, thats why I'm not translating them.
	 * For my future self:
	 *   When updating this, please make sure the flags
	 *   are equal in both systems, otherwise, convert them =).
	 */
	ret = 0;
	if (lnx_ret & O_WRONLY)
		ret |= O_WRONLY;
	else if (lnx_ret & O_RDWR)
		ret |= O_RDWR;

out:
	TRACE("kfcntl", "%d, %d, %x", fd, cmd, arg);
	return ret;
}
