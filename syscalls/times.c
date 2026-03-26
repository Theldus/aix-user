/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025-2026
 */

#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/times.h>
#include "syscalls.h"
#include "unix.h"
#include "aix_errno.h"
#include "mm.h"

struct aix_tms {
	s32	tms_utime;   /* User time.             */
	s32	tms_stime;   /* System time.           */
	s32	tms_cutime;  /* User time, children.   */
	s32	tms_cstime;  /* System time, children. */
};

/**
 * @brief times syscall handler.
 *
 * Handles the AIX timess syscall.
 * This should be aligned with the POSIX times(2).
 *
 * AIX calling convention:
 *   r3 = struct tms buffer
 *
 * Return value (in r3):
 *   If success: elapse time in clock ticks since an arbitrary point
 *   in the past. Otherwise, -1 with errno set.
 */
int aix_times(uc_engine *uc)
{
	struct tms      l_tms;
	struct aix_tms *a_tms;
	clock_t l_ret;
	int ret;
	u32 tms;

	tms   = read_1st_arg();
	ret   = -1;
	l_ret = times(&l_tms);

	if (l_ret < 0) {
		unix_set_conv_errno(errno);
		goto out;
	}

	/* Convert host buffer from VM memory. */
	if (!tms || !(a_tms = mm_vm2host(tms))) {
		unix_set_errno(AIX_EFAULT);
		goto out;
	}

	/* Overflow is allowed. */
	a_tms->tms_utime  = htonl((s32)l_tms.tms_utime);
	a_tms->tms_stime  = htonl((s32)l_tms.tms_stime);
	a_tms->tms_cutime = htonl((s32)l_tms.tms_cutime);
	a_tms->tms_cstime = htonl((s32)l_tms.tms_cstime);

	ret = l_ret;
out:
	TRACE("times", "%x", tms);
	return ret;
}
