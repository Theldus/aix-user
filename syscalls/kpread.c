/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025-2026
 */

#include <stdlib.h>
#include <unistd.h>

#include "syscalls.h"
#include "unix.h"
#include "aix_errno.h"
#include "mm.h"

/**
 * @brief kpread syscall handler.
 *
 * Handles the AIX kpread syscall, which reads data from a file descriptor for
 * a given offset. This is essentially the same as POSIX pread(2).
 *
 * AIX calling convention:
 *   r3 = fd        (file descriptor)
 *   r4 = dest buf  (destination VM buffer address)
 *   r5 = count     (number of bytes to read)
 *   r6 = high offset (file offset high word)
 *   r7 = low  offset (file offset low word)
 *
 * Return value (in r3):
 *   Number of bytes read on success, -1 on error and errno set.
 */
int aix_kpread(uc_engine *uc)
{
	int ret;
	char *h_buff;
	u32 vm_fd    = read_1st_arg();
	u32 vm_buff  = read_2nd_arg();
	u32 vm_count = read_3rd_arg();
	u64 vm_off   = (((u64)read_4th_arg()) << 32) | read_5th_arg();

	ret = -1;

	/* Handle zero-length reads. */
	if (!vm_count) {
		ret = 0;
		goto out;
	}

	/* Convert host buffer from VM memory. */
	if (!(h_buff = mm_vm2host(vm_buff))) {
		unix_set_errno(AIX_EFAULT);
		goto out;
	}

	/* Read FD on Linux with the already-mapped vm/host buffer. */
	ret = pread(vm_fd, h_buff, vm_count, vm_off);
	if (ret < 0)
		unix_set_conv_errno(errno);
out:
	TRACE("kpread", "%d, %x, %d, %" PRId64, vm_fd, vm_buff, vm_count, vm_off);
	return ret;
}
