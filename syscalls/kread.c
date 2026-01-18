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

	/* Handle zero-length reads. */
	if (vm_count == 0)
		return 0;

	/* Allocate host buffer to copy VM memory. */
	h_buff = malloc(vm_count);
	if (!h_buff)
		errx(1, "Host OOM: failed to allocate %u bytes\n", vm_count);

	/* Read FD on Linux and copy to our local buffer, before copying to the VM
	 * memory. */
	ret = read(vm_fd, h_buff, vm_count);
	if (ret < 0) {
		unix_set_conv_errno(errno);
		goto out;
	}

	/* Copy data from host to VM memory. */
	if (uc_mem_write(uc, vm_buff, h_buff, vm_count)) {
		unix_set_errno(AIX_EFAULT);
		warn("kread: failed to write to VM address 0x%x\n", vm_buff);
		free(h_buff);
		return -1;
	}

out:
	TRACE("kread", "%d, %x, %d", vm_fd, vm_buff, vm_count);
	free(h_buff);
	return ret;
}
