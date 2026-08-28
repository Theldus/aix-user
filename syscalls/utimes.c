/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025-2026
 */

#include <utime.h>
#include "syscalls.h"
#include "unix.h"
#include "aix_errno.h"
#include "mm.h"
#include "aix_time.h"

/**
 * @brief utimes syscall handler.
 *
 * Handles the AIX utimes syscall.
 * This should be aligned with the POSIX times(2).
 *
 * AIX calling convention:
 *   r3 = const char *path
 *   r4 = struct timeval times[2]
 *
 * Return value (in r3):
 *   Returns 0 if success, -1 otherwise (with errno set)
 */
int aix_utimes(uc_engine *uc)
{
	struct timeval      l_times[2];
	struct aix_timeval *a_times;
	const char *hpath;
	u32 atimes;
	u32 apath;
	int ret;

	ret    = -1;
	hpath  = NULL;
	apath  = read_1st_arg();
	atimes = read_2nd_arg();

	if (!apath) {
		unix_set_errno(AIX_EBADF);
		goto out;
	}
	if (!atimes) {
		unix_set_errno(AIX_EACCES);
		goto out;
	}

	/* Convert host buffer from VM memory. */
	if (!(hpath = mm_vm2host(apath))) {
		unix_set_errno(AIX_EFAULT);
		goto out;
	}
	if (!(a_times = mm_vm2host(atimes))) {
		unix_set_errno(AIX_EFAULT);
		goto out;
	}

	/* Actual utimes. */
	l_times[0].tv_sec  = (long)frombe32(a_times[0].tv_sec);
	l_times[0].tv_usec = (long)frombe32(a_times[0].tv_usec);
	l_times[1].tv_sec  = (long)frombe32(a_times[1].tv_sec);
	l_times[1].tv_usec = (long)frombe32(a_times[1].tv_usec);
	ret = utimes(hpath, l_times);
	if (ret < 0)
		unix_set_conv_errno(errno);

out:
	TRACE("utimes", "%s, %x", hpath, atimes);
	return ret;
}
