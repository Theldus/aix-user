/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025-2026
 */

#include <string.h>
#include <sys/resource.h>
#include "syscalls.h"
#include "unix.h"
#include "aix_errno.h"
#include "mm.h"

/* Limits. */
#define AIX_RLIMIT_CPU     0 /* CPU time, in ms. */
#define AIX_RLIMIT_FSIZE   1 /* Max file size.   */
#define AIX_RLIMIT_DATA    2
#define AIX_RLIMIT_STACK   3
#define AIX_RLIMIT_CORE    4
#define AIX_RLIMIT_RSS     5
#define AIX_RLIMIT_AS      6
#define AIX_RLIMIT_NOFILE  7
#define AIX_RLIMIT_THREADS 8
#define AIX_RLIMIT_NPROC   9

struct aix_rlimit32 {
	u32 rlim_cur;
	u32 rlim_max;
};
struct aix_rlimit64 {
	u64 rlim_cur;
	u64 rlim_max;
};

/**
 * @brief Common getrlimit implementation for both 32-bit and 64-bit variants.
 *
 * @param uc       Unicorn engine instance.
 * @param is_64bit If non-zero, use 64-bit structures; otherwise use 32-bit.
 *
 * @return 0 on success, -1 on error with errno set.
 */
static int do_getrlimit(uc_engine *uc, int is_64bit)
{
	struct aix_rlimit32 ar32;
	struct aix_rlimit64 ar64;
	struct rlimit l_rlim;
	u32 resource = read_1st_arg();
	u32 d_rlimit = read_2nd_arg();
	char *h_drlimit;
	int l_res;
	int ret;

	ret = -1;

	/* Handle NULL pointer. */
	if (d_rlimit == 0) {
		unix_set_errno(AIX_EFAULT);
		goto out;
	}

	/* Convert host buffer from VM memory. */
	if (!(h_drlimit = mm_vm2host(d_rlimit))) {
		unix_set_errno(AIX_EFAULT);
		goto out;
	}

	/* Convert AIX resource to Linux resource. */
	switch (resource) {
		case AIX_RLIMIT_CPU:    l_res = RLIMIT_CPU;    break;
		case AIX_RLIMIT_FSIZE:  l_res = RLIMIT_FSIZE;  break;
		case AIX_RLIMIT_DATA:   l_res = RLIMIT_DATA;   break;
		case AIX_RLIMIT_STACK:  l_res = RLIMIT_STACK;  break;
		case AIX_RLIMIT_CORE:   l_res = RLIMIT_CORE;   break;
		case AIX_RLIMIT_RSS:    l_res = RLIMIT_RSS;    break;
		case AIX_RLIMIT_AS:     l_res = RLIMIT_AS;     break;
		case AIX_RLIMIT_NOFILE: l_res = RLIMIT_NOFILE; break;
		case AIX_RLIMIT_NPROC:  l_res = RLIMIT_NPROC;  break;
		default:
			unix_set_errno(AIX_EINVAL);
			goto out;
	}

	/* Get resource limits from host. */
	ret = getrlimit(l_res, &l_rlim);
	if (ret < 0) {
		unix_set_conv_errno(errno);
		goto out;
	}

	/* Convert and write to VM memory. */
	if (is_64bit) {
		ar64.rlim_cur = tobe64(l_rlim.rlim_cur);
		ar64.rlim_max = tobe64(l_rlim.rlim_max);
		memcpy(h_drlimit, &ar64, sizeof ar64);
	} else {
		ar32.rlim_cur = tobe32((u32)l_rlim.rlim_cur);
		ar32.rlim_max = tobe32((u32)l_rlim.rlim_max);
		memcpy(h_drlimit, &ar32, sizeof ar32);
	}

	ret = 0;
out:
	return ret;
}

/**
 * @brief aix_appgetrlimit syscall handler.
 *
 * This syscall should equivalent/similar to getrlimit, but a 32-bit
 * version.
 *
 * AIX calling convention:
 *   r3 = resource       (Which resource to get info)
 *   r4 = rlimit buffer  (Buffer that holds th returned info)
 *
 * Return value (in r3):
 *   Returns 0 if success, -1 otherwise with errno set.
 */
int aix_appgetrlimit(uc_engine *uc)
{
	int ret;
	u32 resource = read_1st_arg();
	u32 d_rlimit = read_2nd_arg();

	ret = do_getrlimit(uc, 0);
	TRACE("appgetrlimit", "%d, %x", resource, d_rlimit);
	return ret;
}

/**
 * @brief aix_getrlimit64 syscall handler.
 *
 * 64-bit version of getrlimit.
 *
 * AIX calling convention:
 *   r3 = resource       (Which resource to get info)
 *   r4 = rlimit buffer  (Buffer that holds th returned info)
 *
 * Return value (in r3):
 *   Returns 0 if success, -1 otherwise with errno set.
 */
int aix_getrlimit64(uc_engine *uc)
{
	int ret;
	u32 resource = read_1st_arg();
	u32 d_rlimit = read_2nd_arg();

	ret = do_getrlimit(uc, 1);
	TRACE("getrlimit64", "%d, %x", resource, d_rlimit);
	return ret;
}
