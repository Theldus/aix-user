/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025-2026
 */

#include <unistd.h>

#include "aix_errno.h"
#include "mm.h"
#include "unix.h"
#include "syscalls.h"

/**
 * @brief truncate syscall handler.
 *
 * Handles the AIX truncate syscall, which truncates a given path
 * for a given provided length.
 *
 * AIX calling convention:
 *   r3 = path
 *   r4 = length
 *
 * Return value (in r3):
 *   Returns 0 if success, -1 otherwise and errno is set.
 */
int aix_truncate(uc_engine *uc)
{
	int ret;
	const char *h_path;
	u32 vm_path   = read_1st_arg();
	u32 vm_length = read_2nd_arg();

	ret = -1;

	/* Convert host path from VM memory. */
	if (!(h_path = mm_vm2host(vm_path))) {
		unix_set_errno(AIX_EFAULT);
		goto out;
	}

	/* Actual truncate. */
	ret = truncate(h_path, vm_length);
	if (ret < 0)
		unix_set_conv_errno(errno);

out:
	TRACE("truncate", "%s, %d", h_path, vm_length);
	return ret;
}

/**
 * @brief ktruncate syscall handler.
 *
 * 64-bit version of truncate.
 *
 * AIX calling convention:
 *   r3 = path
 *   r4 = length (high word)
 *   r5 = length (low word)
 *
 * Return value (in r3):
 *   Returns 0 if success, -1 otherwise and errno is set.
 */
int aix_ktruncate(uc_engine *uc)
{
	int ret;
	const char *h_path;
	u32 vm_path   = read_1st_arg();
	u64 vm_length = (((u64)read_2nd_arg()) << 32) | read_3rd_arg();

	ret = -1;

	/* Convert host path from VM memory. */
	if (!(h_path = mm_vm2host(vm_path))) {
		unix_set_errno(AIX_EFAULT);
		goto out;
	}

	/* Actual truncate. */
	ret = truncate(h_path, vm_length);
	if (ret < 0)
		unix_set_conv_errno(errno);

out:
	TRACE("ktruncate", "%s, %ld", h_path, vm_length);
	return ret;
}

/**
 * @brief ftruncate syscall handler.
 *
 * Handles the AIX ftruncate syscall, which truncates a given fd
 * for a given provided length.
 *
 * AIX calling convention:
 *   r3 = file descriptor
 *   r4 = length
 *
 * Return value (in r3):
 *   Returns 0 if success, -1 otherwise and errno is set.
 */
int aix_ftruncate(uc_engine *uc)
{
	int ret       = -1;
	u32 vm_fd     = read_1st_arg();
	u32 vm_length = read_2nd_arg();

	/* Actual ftruncate. */
	ret = ftruncate(vm_fd, vm_length);
	if (ret < 0)
		unix_set_conv_errno(errno);

	TRACE("ftruncate", "%d, %d", vm_fd, vm_length);
	return ret;
}

/**
 * @brief ktruncate syscall handler.
 *
 * 64-bit version of ftruncate.
 *
 * AIX calling convention:
 *   r3 = fd
 *   r4 = length (high word)
 *   r5 = length (low word)
 *
 * Return value (in r3):
 *   Returns 0 if success, -1 otherwise and errno is set.
 */
int aix_kftruncate(uc_engine *uc)
{
	int ret       = -1;
	u32 vm_fd     = read_1st_arg();
	u64 vm_length = (((u64)read_2nd_arg()) << 32) | read_3rd_arg();

	/* Actual ftruncate. */
	ret = ftruncate(vm_fd, vm_length);
	if (ret < 0)
		unix_set_conv_errno(errno);

	TRACE("ftruncate", "%d, %ld", vm_fd, vm_length);
	return ret;
}
