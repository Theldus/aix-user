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
 * @brief kread syscall handler.
 *
 * Handles the AIX kread syscall, which reads data from a file descriptor.
 * This is essentially the same as POSIX read(2).
 *
 * AIX calling convention:
 *   r3 = fd        (file descriptor)
 *   r4 = dest buf  (destination VM buffer address)
 *   r5 = count     (number of bytes to read)
 *
 * Return value (in r3):
 *   Number of bytes read on success, -1 on error and errno set.
 */
int aix_kread(uc_engine *uc)
{
	int ret;
	char *h_buff;
	u32 vm_fd    = read_1st_arg();
	u32 vm_buff  = read_2nd_arg();
	u32 vm_count = read_3rd_arg();

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
	ret = read(vm_fd, h_buff, vm_count);
	if (ret < 0)
		unix_set_conv_errno(errno);
out:
	TRACE("kread", "%d, %x, %d", vm_fd, vm_buff, vm_count);
	return ret;
}
