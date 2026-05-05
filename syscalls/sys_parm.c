/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025-2026
 */

#include <string.h>
#include <unistd.h>
#include "syscalls.h"
#include "unix.h"
#include "aix_errno.h"
#include "mm.h"

/* Commands */
#define SYSP_GET 0
#define SYSP_SET 1

/* Flags. */
#define SYSP_NCARGS 14 /* Max amnt of env+argv (in pages of 4kiB). */

/**
 * @brief sys_parm syscall handler.
 *
 * Gets/sets kernel parameters.
 *
 * AIX calling convention:
 *   r3 = cmd  (command, whether SYSP_GET or SET)
 *   r4 = flag (which parameter to get/set to)
 *   r5 = ptr  (pointer in userspace to get/set the parameter)
 *
 * Return value (in r3):
 *   If success returns 0, otherwise, -1 with errno set.
 */
int aix_sys_parm(uc_engine *uc)
{
	int ret = -1;
	u32 cmd = read_1st_arg();
	u32 flg = read_2nd_arg();
	u32 ptr = read_3rd_arg();
	char *h_ptr;
	long l_val;
	u64 a_val;

	/* Convert host buffer from VM memory. */
	if (!(h_ptr = mm_vm2host(ptr))) {
		unix_set_errno(AIX_EFAULT);
		goto out;
	}

	if (cmd == SYSP_SET) {
		warn("sys_parm: SYSP_SET not implemented!\n");
		goto out;
	}

	switch (flg) {
		case SYSP_NCARGS:
			l_val = sysconf(_SC_ARG_MAX) / 4096;
			break;
		default:
			warn("sys_parm: parameter not supported!\n");
			goto out;
			break;
	}

	a_val = tobe64((u64)l_val);
	memcpy(h_ptr, &a_val, 8);
	ret = 0;
out:
	TRACE("sys_parm", "%d, %d, %x", cmd, flg, ptr);
	return ret;
}
