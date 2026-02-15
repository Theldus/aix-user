/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025-2026
 */

#include <unistd.h>
#include "syscalls.h"
#include "unix.h"
#include "aix_errno.h"

#define AIX_SYS_NMLN 32
static struct aix_utsname {
	char sysname[AIX_SYS_NMLN];
	char nodename[AIX_SYS_NMLN];
	char release[AIX_SYS_NMLN];
	char version[AIX_SYS_NMLN];
	char machine[AIX_SYS_NMLN];
} h_auts = {
	.sysname  = "AIX",
	.nodename = "aix-user", /* A bit of us here =). */
	.release  = "2",
	.version  = "7",
	.machine  = "000000000000",
};

static struct aix_xutsname {
	u32 nid;
	s32 reserved;
	u64 long_nid;
} h_autsx = {0};

/**
 * @brief uname syscall handler.
 *
 * Handles the AIX uname syscall.
 * This should be aligned with the POSIX uname(2).
 *
 * AIX calling convention:
 *   r3 = utsname structure 
 *
 * Return value (in r3):
 *   If success returns 0, otherwise, -1 with errno set.
 */
int aix_uname(uc_engine *uc)
{
	int ret     = -1;
	u32 utsname = read_1st_arg();

	if (!utsname) {
		unix_set_errno(AIX_EFAULT);
		goto out;
	}

	/* Read path from VM to host. */
	if (uc_mem_write(uc, utsname, &h_auts, sizeof h_auts)) {
		warn("uname: failed to write utsname, at 0x%x\n", utsname);
		unix_set_errno(AIX_EFAULT);
		goto out;
	}

	ret = 0;
out:
	TRACE("uname", "%x", utsname);
	return ret;
}

/**
 * @brief unamex syscall handler.
 *
 * Handles the AIX unamex syscall.
 * This should be aligned with the POSIX unamex(2).
 *
 * AIX calling convention:
 *   r3 = xutsname structure 
 *
 * Return value (in r3):
 *   If success returns 0, otherwise, -1 with errno set.
 */
int aix_unamex(uc_engine *uc)
{
	int ret      = -1;
	u32 xutsname = read_1st_arg();

	if (!xutsname) {
		unix_set_errno(AIX_EFAULT);
		goto out;
	}

	/* Read path from VM to host. */
	if (uc_mem_write(uc, xutsname, &h_autsx, sizeof h_autsx)) {
		warn("unamex: failed to write utsname, at 0x%x\n", xutsname);
		unix_set_errno(AIX_EFAULT);
		goto out;
	}

	ret = 0;
out:
	TRACE("unamex", "%x", xutsname);
	return ret;
}
