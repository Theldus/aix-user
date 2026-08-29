/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025-2026
 */

#include <unistd.h>
#include "syscalls.h"
#include "unix.h"
#include "aix_errno.h"
#include "mm.h"

/**
 * @brief __chxacl syscall handler.
 *
 * Handles the AIX __chxacl syscall.
 * This is AIX-specific syscall, which, accordingly to the 'acl.h' header,
 * follows this signature:
 *
 *     int __chxacl(
 *         char *path, uint64_t ctl_flags,
 *         acl_type_t acl_type,
 *         void *acl, size_t acl_sz, mode_t mode_info);
 *
 * AIX calling convention (inferred):
 *   r3  = path
 *   r4  = ctl_flags  (high-word)
 *   r5  = ctl_flags  (low-word)
 *   r6  = acl_type   (high-word)
 *   r7  = acl_type   (low-word)
 *   r8  = acl
 *   r9  = acl_sz
 *   r10 = mode_info
 *
 * (Note: this syscall seems to be called from the aclx_put(3) AIX libc
 *  function)
 *
 * Return value (in r3):
 *   Stub, always fails with -1, this forces the some programs (such
 *   as 'restbyname' to use chmod.
 */
int aix___chxacl(uc_engine *uc)
{
	char *h_path = NULL;
	u32 path      = read_1st_arg();
	u64 ctl_flags = (((u64)read_2nd_arg()) << 32) | read_3rd_arg();
	u64 acl_type  = (((u64)read_4th_arg()) << 32) | read_5th_arg();
	u32 acl       = read_6th_arg();
	u32 acl_sz    = read_7th_arg();
	u32 mode_info = read_8th_arg();
	int ret       = -1;

	if (!path) {
		unix_set_errno(AIX_EFAULT);
		goto out;
	}

	/* Convert host buffer from VM memory. */
	if (!(h_path = mm_vm2host(path))) {
		unix_set_errno(AIX_EFAULT);
		goto out;
	}

out:
	TRACE("__chxacl", "%s, %" PRId64 ", %" PRId64 ", %x, %d, %o",
		h_path, ctl_flags, acl_type, acl, acl_sz, mode_info);
	return ret;
}
