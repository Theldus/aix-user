/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025-2026
 */

#include <string.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include "syscalls.h"
#include "aix_resource.h"
#include "unix.h"
#include "aix_errno.h"
#include "mm.h"

/* Not all these options are present on AIX's man page, but they
 * are on sys/wait.h, i guess it is.. outdated?
 */
#define AIX_WNOHANG    1 /* No hang the parent process.   */
#define AIX_WUNTRACED  2 /* Watches for stopped children. */
#define AIX_WEXITED    4 /* Normal termination.           */
#define AIX_WCONTINUED 0x1000000 /* Wait for delivery of SIGCONT.   */
#define AIX_WNOWAIT    0x10 /* Leave the child in a waitable state. */
#define	_W_STOPPED	   0x00000040 /* Bit set if stopped. */

/**
 * @brief Convert a linux rusage struct to AIX rusage 32-bit structure.
 * @param vaix_ru AIX's 32-bit rusage destination structure.
 * @param lin_ru  Linux rusage to be copied.
 */
static void
rusage_linux2aix(void *vaix_ru, const struct rusage *lin_ru)
{
	struct aix_rusage *aix_ru = vaix_ru;
	memset(aix_ru, 0, sizeof(*aix_ru));
	aix_ru->ru_utime.tv_sec  = tobe32((s32)lin_ru->ru_utime.tv_sec);
	aix_ru->ru_utime.tv_usec = tobe32((s32)lin_ru->ru_utime.tv_usec);
	aix_ru->ru_stime.tv_sec  = tobe32((s32)lin_ru->ru_stime.tv_sec);
	aix_ru->ru_stime.tv_usec = tobe32((s32)lin_ru->ru_stime.tv_usec);
	aix_ru->ru_maxrss   = tobe32((s32)lin_ru->ru_maxrss);
	aix_ru->ru_ixrss    = tobe32((s32)lin_ru->ru_ixrss);
	aix_ru->ru_idrss    = tobe32((s32)lin_ru->ru_idrss);
	aix_ru->ru_isrss    = tobe32((s32)lin_ru->ru_isrss);
	aix_ru->ru_minflt   = tobe32((s32)lin_ru->ru_minflt);
	aix_ru->ru_majflt   = tobe32((s32)lin_ru->ru_majflt);
	aix_ru->ru_nswap    = tobe32((s32)lin_ru->ru_nswap);
	aix_ru->ru_inblock  = tobe32((s32)lin_ru->ru_inblock);
	aix_ru->ru_oublock  = tobe32((s32)lin_ru->ru_oublock);
	aix_ru->ru_msgsnd   = tobe32((s32)lin_ru->ru_msgsnd);
	aix_ru->ru_msgrcv   = tobe32((s32)lin_ru->ru_msgrcv);
	aix_ru->ru_nsignals = tobe32((s32)lin_ru->ru_nsignals);
	aix_ru->ru_nvcsw    = tobe32((s32)lin_ru->ru_nvcsw);
	aix_ru->ru_nivcsw   = tobe32((s32)lin_ru->ru_nivcsw);
}

/**
 * @brief Convert a linux rusage struct to AIX rusage 64-bit structure.
 * @param vaix_ru AIX's 64-bit rusage destination structure.
 * @param lin_ru  Linux rusage to be copied.
 */
static void
rusage64_linux2aix(void *vaix_ru, const struct rusage *lin_ru)
{
	struct aix_rusage64 *aix_ru = vaix_ru;
	memset(aix_ru, 0, sizeof(*aix_ru));
	aix_ru->ru_utime.tv_sec  = tobe32((s32)lin_ru->ru_utime.tv_sec);
	aix_ru->ru_utime.tv_usec = tobe32((s32)lin_ru->ru_utime.tv_usec);
	aix_ru->ru_stime.tv_sec  = tobe32((s32)lin_ru->ru_stime.tv_sec);
	aix_ru->ru_stime.tv_usec = tobe32((s32)lin_ru->ru_stime.tv_usec);
	aix_ru->ru_maxrss   = tobe64((s64)lin_ru->ru_maxrss);
	aix_ru->ru_ixrss    = tobe64((s64)lin_ru->ru_ixrss);
	aix_ru->ru_idrss    = tobe64((s64)lin_ru->ru_idrss);
	aix_ru->ru_isrss    = tobe64((s64)lin_ru->ru_isrss);
	aix_ru->ru_minflt   = tobe64((s64)lin_ru->ru_minflt);
	aix_ru->ru_majflt   = tobe64((s64)lin_ru->ru_majflt);
	aix_ru->ru_nswap    = tobe64((s64)lin_ru->ru_nswap);
	aix_ru->ru_inblock  = tobe64((s64)lin_ru->ru_inblock);
	aix_ru->ru_oublock  = tobe64((s64)lin_ru->ru_oublock);
	aix_ru->ru_msgsnd   = tobe64((s64)lin_ru->ru_msgsnd);
	aix_ru->ru_msgrcv   = tobe64((s64)lin_ru->ru_msgrcv);
	aix_ru->ru_nsignals = tobe64((s64)lin_ru->ru_nsignals);
	aix_ru->ru_nvcsw    = tobe64((s64)lin_ru->ru_nvcsw);
	aix_ru->ru_nivcsw   = tobe64((s64)lin_ru->ru_nivcsw);
}

/**
 * @brief AIX actual kwaitpid implementation: kwaitpid is an 'all-in-one'
 * syscall and is called from multiples places, such as: wait, waitpid, wait3
 * and wait364.
 * @param wstatus Returned wait status.
 * @param pid     PID to wait for.
 * @param options How should wait.
 * @param rusage  Usage stats of the terminated child.
 * @param info    siginfo_t, unused.
 * @param is32    If 1, rusage is the 32-bit version, otherwise, is the 64-bit.
 * @return If success (and no WNOHANG), returns the PID of the terminated child,
 *         otherwise, -1.
 */
static int
aix_do_kwaitpid(u32 wstatus, s32 pid, u32 options, u32 rusage, u32 infop, int is32)
{
	((void)infop);
	struct rusage lin_rusage;
	int ret;
	int lin_opts    = 0;
	int lin_wstatus = 0;
	u32  *aix_wstatus = NULL;
	void *aix_rusage  = NULL;

	if (wstatus && !(aix_wstatus = mm_vm2host(wstatus))) {
		unix_set_errno(AIX_EFAULT);
		return -1;
	}
	if (rusage && !(aix_rusage = mm_vm2host(rusage))) {
		unix_set_errno(AIX_EFAULT);
		return -1;
	}
	/* Unsupported infop at the moment. */
	if (infop) {
		unix_set_errno(AIX_EINVAL);
		return -1;
	}

	/* Convert options. */
	if (options & AIX_WNOHANG)    lin_opts |= WNOHANG;
	if (options & AIX_WUNTRACED)  lin_opts |= WUNTRACED;
	if (options & AIX_WCONTINUED) lin_opts |= WCONTINUED;
	if (options & AIX_WNOWAIT)    lin_opts |= WNOWAIT;
	if (options & ~(AIX_WNOHANG|AIX_WUNTRACED|AIX_WCONTINUED|AIX_WNOWAIT|
		            AIX_WEXITED)) {
		unix_set_errno(AIX_EINVAL);
		return -1;
	}

	ret = wait4(pid, &lin_wstatus, lin_opts, &lin_rusage);
	if (ret < 0) {
		unix_set_conv_errno(errno);
		return -1;
	}

	/* Convert linux wstatus to AIX. */
	if (ret > 0 && aix_wstatus) {
		if (WIFEXITED(lin_wstatus))
			*aix_wstatus = (WEXITSTATUS(lin_wstatus) & 0xff) << 8;
		else if (WIFSIGNALED(lin_wstatus))
			*aix_wstatus = ((u32)WTERMSIG(lin_wstatus) << 16) |
			                    (WTERMSIG(lin_wstatus) & 0xff);
		else if (WIFSTOPPED(lin_wstatus))
			*aix_wstatus = ((u32)WSTOPSIG(lin_wstatus) <<  8) | _W_STOPPED;
		else if (WIFCONTINUED(lin_wstatus))
			*aix_wstatus = AIX_WCONTINUED;
		else
			warn("Unhandled wstatus %x\n", lin_wstatus);
		*aix_wstatus = tobe32(*aix_wstatus);
	}

	/* Conver rusage to AIX. */
	if (ret > 0 && aix_rusage) {
		if   (is32) rusage_linux2aix  (aix_rusage, &lin_rusage);
		else        rusage64_linux2aix(aix_rusage, &lin_rusage);
	}
	return ret;
}

/**
 * @brief kwaitpid syscall handler.
 *
 * Handles the AIX kwaitpid syscall.
 * This is not exactly aligned with POSIX, and have the following
 * signature:
 *   extern pid_t kwaitpid (int *wstatus, pid_t pid, int options,
 *       struct rusage *rusage, siginfo_t *infop);
 * (thanks to glibc v2.32, I wouldnt have guessed the signature
 * otherwise =))
 *
 * AIX calling convention:
 *   r3 = wstatus, status information about the child
 *   r4 = pid,     specifies the kind of children we should wait for.
 *   r5 = options, specifies how the function should behave
 *   r6 = rusage,  accounting information about the child
 *   r7 = infop,   siginfo_t structure.
 *
 * Return value (in r3):
 *   If success, returns the process ID of the child whose state
 *   was changed or 0 if there are no stopped/exit child processes and WNOHANG
 *   was specified. Otherwise, -1.
 */
int aix_kwaitpid(uc_engine *uc)
{
	int ret;
	u32 wstatus = read_1st_arg();
	s32 pid     = read_2nd_arg();
	u32 options = read_3rd_arg();
	u32 rusage  = read_4th_arg();
	u32 infop   = read_5th_arg();
	ret = aix_do_kwaitpid(wstatus, pid, options, rusage, infop, 1);
	TRACE("kwaitpid", "%x, %d, %d, %x, %x",
		wstatus, pid, options, rusage, infop);
	return ret;
}

/**
 * @brief Equivalent to 'aix_kwaitpid', but uses a 64-bit rusage structure.
 */
int aix_kwaitpid64(uc_engine *uc)
{
	int ret;
	u32 wstatus = read_1st_arg();
	s32 pid     = read_2nd_arg();
	u32 options = read_3rd_arg();
	u32 rusage  = read_4th_arg();
	u32 infop   = read_5th_arg();
	ret = aix_do_kwaitpid(wstatus, pid, options, rusage, infop, 0);
	TRACE("kwaitpid64", "%x, %d, %d, %x, %x",
		wstatus, pid, options, rusage, infop);
	return ret;
}
