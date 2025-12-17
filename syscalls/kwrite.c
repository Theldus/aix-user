/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025
 */

#include <stdlib.h>
#include <unistd.h>
#include "syscalls.h"

/**
 * @brief kwrite syscall handler.
 *
 * Handles the AIX kwrite syscall, which writes data to a file descriptor.
 * This is essentially the same as POSIX write(2).
 *
 * AIX calling convention:
 *   r3 = fd    (file descriptor)
 *   r4 = buf   (VM address of buffer)
 *   r5 = count (number of bytes to write)
 *
 * Return value (in r3):
 *   Number of bytes written on success, -1 on error.
 *
 * @return Number of bytes written, or -1 on error.
 */
int aix_kwrite(uc_engine *uc)
{
	int ret;
	char *h_buff;
	u32 vm_fd    = read_1st_arg();
	u32 vm_buff  = read_2nd_arg();
	u32 vm_count = read_3rd_arg();

	/* Handle zero-length writes. */
	if (vm_count == 0)
		return 0;

	/* Allocate host buffer to copy VM memory. */
	h_buff = malloc(vm_count);
	if (!h_buff)
		errx(1, "Host OOM: failed to allocate %u bytes\n", vm_count);

	/* Copy data from VM memory to host buffer. */
	if (uc_mem_read(uc, vm_buff, h_buff, vm_count)) {
		warn("kwrite: failed to read from VM address 0x%x\n", vm_buff);
		free(h_buff);
		return -1;
	}

	/* Perform the actual write on the host. */
	ret = write(vm_fd, h_buff, vm_count);

	TRACE("kwrite", "%d, %.*s, %d", vm_fd, vm_count, h_buff, vm_count);
	free(h_buff);
	return ret;
}
