/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025-2026
 */

#include <stdlib.h>
#include <unistd.h>

#include "aix_errno.h"
#include "mm.h"
#include "unix.h"
#include "syscalls.h"

/**
 * @brief kpwrite syscall handler.
 *
 * Handles the AIX kpwrite syscall, which writes data to a file descriptor at
 * a given offset. This is essentially the same as POSIX pwrite(2).
 *
 * AIX calling convention:
 *   r3 = fd    (file descriptor)
 *   r4 = buf   (VM address of buffer)
 *   r5 = count (number of bytes to write)
 *   r6 = high offset (file offset high word)
 *   r7 = low  offset (file offset low word)
 *
 * Return value (in r3):
 *   Number of bytes written on success, -1 on error.
 *
 * @return Number of bytes written, or -1 on error.
 */
int aix_kpwrite(uc_engine *uc)
{
	int ret;
	char *h_buff;
	u32 vm_fd    = read_1st_arg();
	u32 vm_buff  = read_2nd_arg();
	u32 vm_count = read_3rd_arg();
	u64 vm_off   = (((u64)read_4th_arg()) << 32) | read_5th_arg();

	ret = -1;

	/* Handle zero-length writes. */
	if (!vm_count) {
		ret = 0;
		goto out;
	}

	/* Convert host buffer from VM memory. */
	if (!(h_buff = mm_vm2host(vm_buff))) {
		unix_set_errno(AIX_EFAULT);
		goto out;
	}

	/* Perform the actual write on the host. */
	ret = pwrite(vm_fd, h_buff, vm_count, vm_off);
	if (ret < 0)
		unix_set_conv_errno(errno);
out:
	TRACE("kpwrite", "%d, %x, %d, %" PRId64, vm_fd, vm_buff, vm_count, vm_off);
	return ret;
}
