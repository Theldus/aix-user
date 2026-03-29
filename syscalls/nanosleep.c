/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025-2026
 */

#include <time.h>
#include <arpa/inet.h>

#include "unix.h"
#include "syscalls.h"
#include "aix_errno.h"
#include "aix_time.h"
#include "mm.h"

#define ONE_SEC_NS 1000000000

#define AIX_CLOCK_REALTIME  ((u64)9)
#define AIX_CLOCK_MONOTONIC ((u64)10)
#define AIX_TIMER_ABSTIME   999

/**
 * @brief Converts a Linux timespec structure to AIX's timespec.
 *
 * Both structures are identical, but AIX holds 32-bit values for both
 * seconds and nanoseconds, so this function increases the seconds
 * if the current nanoseconds are greater than 1NEC_NS.
 *
 * @param lin Linux source timespec structure.
 * @param aix AIX target timespec structure to be converted.
 */
static void
timespec_linux2aix(struct timespec *lin, struct aix_st_timespec *aix)
{
	aix->tv_sec = lin->tv_sec;
	while (lin->tv_nsec > ONE_SEC_NS) {
		aix->tv_sec++;
		lin->tv_nsec -= ONE_SEC_NS;
	}
	aix->tv_sec  = htonl(aix->tv_sec);
	aix->tv_nsec = htonl(lin->tv_nsec);
}

/**
 * @brief _nsleep syscall handler.
 *
 * Handles the AIX _nsleep syscall
 * This should be equivalent with the POSIX nanosleep(2).
 *
 * AIX calling convention:
 *   r3 = const struct aix_st_timespec buffer duration
 *   r4 =       struct aix_st_timespec buffer remaining time
 *
 * Return value (in r3):
 *   Returns 0 if success, -1 if the routine was interrupted due to
 *   a signal or event. In this case, r4 buffer will be updated
 *   with the unslept amount and errno set.
 */
int aix__nsleep(uc_engine *uc)
{
	struct aix_st_timespec *aix_dur, *aix_rem;
	struct timespec linux_dur, linux_rem;
	u32 dur, rem;
	int ret;

	dur = read_1st_arg();
	rem = read_2nd_arg();
	ret = -1;

	/* Convert host buffer from VM memory. */
	if (!dur || !(aix_dur = mm_vm2host(dur))) {
		unix_set_errno(AIX_EFAULT);
		goto out;
	}

	linux_dur.tv_sec  = ntohl(aix_dur->tv_sec);
	linux_dur.tv_nsec = ntohl(aix_dur->tv_nsec);

	if ((ret = nanosleep(&linux_dur, &linux_rem)) < 0) {
		unix_set_conv_errno(errno);
		if (!rem)
			goto out;
		/* We must set the remaining if nanosleep was interrupted. */
		if (!(aix_rem = mm_vm2host(rem))) {
			unix_set_errno(AIX_EFAULT);
			goto out;
		}
		timespec_linux2aix(&linux_rem, aix_rem);
	}

out:
	TRACE("_nsleep", "%x, %x", dur, rem);
	return ret;
}

/**
 * @brief _clock_nanosleep syscall handler.
 *
 * Handles the AIX _clock_nanosleep syscall
 * This should be equivalent with the POSIX nanosleep(2).
 *
 * AIX calling convention:
 *   r3 = clock_id high word
 *   r4 = clock_id low word
 *   r5 = flags
 *   r6 = const struct timespec *rqtp
 *   r7 = struct timespec *rmtp
 *
 * Return value (in r3):
 *   Returns 0 if success, 'errno' value otherwise.
 *   The errno variable is also set.
 */
int aix__clock_nanosleep(uc_engine *uc)
{
	struct aix_st_timespec *aix_dur, *aix_rem;
	struct timespec linux_dur, linux_rem;
	u32 vm_flags, li_flags;
	u32 vm_dur, vm_rem;
	u64 vm_cid, li_cid;
	int ret;

	vm_cid    = (((u64)read_1st_arg()) << 32) | read_2nd_arg();
	vm_flags  = read_3rd_arg();
	vm_dur    = read_4th_arg();
	vm_rem    = read_5th_arg();
	ret = -1;

	/* Convert host buffer from VM memory. */
	if (!vm_dur || !(aix_dur = mm_vm2host(vm_dur))) {
		unix_set_errno(AIX_EFAULT);
		goto out;
	}

	/* Convert flags. */
	li_flags = (vm_flags == AIX_TIMER_ABSTIME) ? TIMER_ABSTIME : 0;

	/* Convert clock id.
	 * Per man-page, this should work only for REALTIME and MONOTONIC:
	 *    'The subroutine fails if the clock_id argument refers to a
	 *     process or a thread CPU-time clock.'
	 */
	switch (vm_cid) {
		case AIX_CLOCK_REALTIME:  li_cid = CLOCK_REALTIME;  break;
		case AIX_CLOCK_MONOTONIC: li_cid = CLOCK_MONOTONIC; break;
		default:
			ret = AIX_EINVAL;
			unix_set_errno(AIX_EINVAL);
			goto out;
	}

	linux_dur.tv_sec  = ntohl(aix_dur->tv_sec);
	linux_dur.tv_nsec = ntohl(aix_dur->tv_nsec);

	if ((ret = clock_nanosleep(li_cid, li_flags, &linux_dur, &linux_rem))) {
		unix_set_conv_errno(errno);
		ret = errno_linux2aix(errno);
		if (!vm_rem)
			goto out;

		/* We must set the remaining if nanosleep was interrupted. */
		if (!(aix_rem = mm_vm2host(vm_rem))) {
			ret = AIX_EFAULT;
			unix_set_errno(AIX_EFAULT);
			goto out;
		}
		timespec_linux2aix(&linux_rem, aix_rem);
	}

out:
	TRACE("_clock_nanosleep", "%" PRId64 ", %d, %x, %x", vm_cid, vm_flags,
		vm_dur, vm_rem);
	return ret;
}
