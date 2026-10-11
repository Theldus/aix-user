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
#include "aix_resource.h"
#include "mm.h"

/**
 * @brief Common setrlimit implementation for both 32-bit and 64-bit variants.
 *
 * @param uc       Unicorn engine instance.
 * @param is_64bit If non-zero, use 64-bit structures; otherwise use 32-bit.
 *
 * @return 0 on success, -1 on error with errno set.
 */
static int do_setrlimit(uc_engine *uc, int is_64bit)
{
	struct aix_rlimit32 ar32;
	struct aix_rlimit64 ar64;
	struct rlimit l_rlim;
	s32 resource = read_1st_arg();
	u32 s_rlimit = read_2nd_arg();
	char *h_srlimit;
	int l_res;
	int ret;

	ret = -1;

	/* Handle NULL pointer. */
	if (s_rlimit == 0) {
		unix_set_errno(AIX_EFAULT);
		goto out;
	}

	/* Convert host buffer from VM memory. */
	if (!(h_srlimit = mm_vm2host(s_rlimit))) {
		unix_set_errno(AIX_EFAULT);
		goto out;
	}

	/* Convert AIX resource to Linux resource. */
	if ((l_res = resource_aix2linux(resource)) < 0) {
		unix_set_errno(AIX_EINVAL);
		goto out;
	}

	/* Read aix_rlimit and save it into the Linux's rlimit struct. */
	if (is_64bit) {
		memcpy(&ar64, h_srlimit, sizeof ar64);
		l_rlim.rlim_cur = frombe64(ar64.rlim_cur);
		l_rlim.rlim_max = frombe64(ar64.rlim_max);
	} else {
		memcpy(&ar32, h_srlimit, sizeof ar32);
		l_rlim.rlim_cur = frombe32(ar32.rlim_cur);
		l_rlim.rlim_max = frombe32(ar32.rlim_max);
	}

	/* Set resource limits. */
	ret = setrlimit(l_res, &l_rlim);
	if (ret < 0) {
		unix_set_conv_errno(errno);
		goto out;
	}
out:
	return ret;
}

/**
 * @brief aix_appsetrlimit syscall handler.
 *
 * This syscall should equivalent/similar to setrlimit, but a 32-bit
 * version.
 *
 * AIX calling convention:
 *   r3 = resource            (Which resource to get info)
 *   r4 = const rlimit buffer (Buffer that holds th returned info)
 *
 * Return value (in r3):
 *   Returns 0 if success, -1 otherwise with errno set.
 */
int aix_appsetrlimit(uc_engine *uc)
{
	int ret;
	u32 resource = read_1st_arg();
	u32 s_rlimit = read_2nd_arg();

	ret = do_setrlimit(uc, 0);
	TRACE("appsetrlimit", "%d, %x", resource, s_rlimit);
	return ret;
}

/**
 * @brief aix_setrlimit64 syscall handler.
 *
 * 64-bit version of setrlimit.
 *
 * AIX calling convention:
 *   r3 = resource            (Which resource to get info)
 *   r4 = const rlimit buffer (Buffer that holds th returned info)
 *
 * Return value (in r3):
 *   Returns 0 if success, -1 otherwise with errno set.
 */
int aix_setrlimit64(uc_engine *uc)
{
	int ret;
	u32 resource = read_1st_arg();
	u32 s_rlimit = read_2nd_arg();

	ret = do_setrlimit(uc, 1);
	TRACE("setrlimit64", "%d, %x", resource, s_rlimit);
	return ret;
}
