/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025
 */

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include "syscalls.h"
#include "unix.h"

#define TXISATTY ('X'<<8)

static u32 o_errno;

/**
 * @brief kioctl syscall handler.
 *
 * For the moment, this is just a *very* small impl just in order
 * for 'isatty()' works...
 *
 * AIX calling convention:
 *   r3 = fd
 *   r4 = command
 *   r5 = argument
 *   r6 = extension parameter
 *
 * Return value (in r3):
 *   If the ioctl subroutine fails, a value of -1 is returned. The errno
 *   global variable is set to indicate the error.
 */
int aix_kioctl(uc_engine *uc)
{
	u32 fd  = read_1st_arg();
	u32 cmd = read_2nd_arg();
	u32 arg = read_3rd_arg();
	u32 ext = read_4th_arg();
	o_errno = errno;
	int ret = -1;

	if (cmd & TXISATTY) {
		if (isatty(fd))
			ret = 0;
	}

	if (o_errno != errno)
		unix_set_errno(errno);

	TRACE("kioctl", "%d, %d, %x, %x", fd, cmd, arg, ext);
	return ret;
}
