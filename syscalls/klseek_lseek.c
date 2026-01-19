/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025-2026
 */

#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include "syscalls.h"
#include "unix.h"
#include "aix_errno.h"

/**
 * @brief lseek syscall handler
 *
 * Contrary to the klseek below, this one is aligned to POSIX.
 *
 * AIX calling convention:
 *   r3 = fd
 *   r4 = offset
 *   r5 = whence/direction (SEEK_SET/CUR/END have the same values on Linux)
 *
 * Return value (in r3):
 *   If success, returns the byte offset from the beginning of the file,
 *   otherwise, -1 with errno set.
 */
int aix_lseek(uc_engine *uc)
{
	int ret;
	u32 vm_fd  = read_1st_arg();
	u32 vm_off = read_2nd_arg();
	u32 vm_whe = read_3rd_arg();

	ret = lseek(vm_fd, vm_off, vm_whe);
	if (ret < 0)
		unix_set_conv_errno(errno);

	TRACE("lseek", "%d, %d, %d", vm_fd, vm_off, vm_whe);
	return ret;
}

/**
 * @brief klseek syscall handler.
 *
 * This is the 8-byte offset vrsion of lseek and behaves a little
 * different from the POSIX syscall:
 *   1) The offset is passed in two words (r3 - high, r4 - low)
 *   2) The return value is only 0 and -1, the syscall do not return
 *      the resulting offset as lseek does.
 *   3) An additional argument is a pointer to where will be saved
 *      the returned result.
 *
 * This is the signature:
 *   extern int klseek (int fd, u64 offset, int sbase,
 *                      u64 *new_offp);
 *
 * AIX calling convention:
 *   r3 = fd
 *   r4 = offset high word
 *   r5 = offset low word
 *   r6 = whence/direction
 *   r7 = pointer to offp (32-bit pointer)
 *
 * Return value (in r3):
 *   Returns 0 if success, -1 otherwise with errno set.
 */
int aix_klseek(uc_engine *uc)
{
	int ret;
	u32 vm_fd   = read_1st_arg();
	u64 vm_off  = (((u64)read_2nd_arg()) << 32) | read_3rd_arg();
	u32 vm_whe  = read_4th_arg();
	u32 vm_offp = read_5th_arg();
	s64 off;

	ret = 0;
	off = lseek(vm_fd, vm_off, vm_whe);
	if (off < 0) {
		ret = -1;
		unix_set_conv_errno(errno);
	}

	/* Write resulting offset into offp. */
	if (off >= 0) {
		off = htonll(off);
		if (uc_mem_write(uc, vm_offp, &off, 8)) {
			ret = -1;
			unix_set_errno(AIX_EFAULT);
		}
	}

	TRACE("klseek", "%d, %" PRIx64", %d", vm_fd, vm_off, vm_whe);
	return ret;
}
