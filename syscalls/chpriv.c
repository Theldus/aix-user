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
 * @brief chpriv syscall handler.
 *
 * Handles the AIX chpriv syscall.
 * This is AIX-specific syscall, which, accordingly to the 'sys/priv.h'
 * header, follows this signature:
 *
 *     int chpriv(char *path, struct pcl *, int);
 *
 * AIX calling convention (inferred):
 *   r3  = path
 *   r4  = pcl structure
 *   r5  = smth (something else)
 *
 * Really no idea what this does...
 *
 * Return value (in r3):
 *
 */
int aix_chpriv(uc_engine *uc)
{
	char *h_path = NULL;
	u32 path = read_1st_arg();
	u32 pcl  = read_2nd_arg();
	u32 smth = read_3rd_arg();
	int ret  = 0;

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
	TRACE("chpriv", "%s, %x, %d", h_path, pcl, smth);
	return ret;
}

/**
 * @brief fchpriv syscall handler.
 *
 * Handles the AIX fchpriv syscall.
 * This is AIX-specific syscall, which, accordingly to the 'sys/priv.h'
 * header, follows this signature:
 *
 *     int fchpriv(char *fd, struct pcl *, int);
 *
 * AIX calling convention (inferred):
 *   r3  = fd
 *   r4  = pcl structure
 *   r5  = smth (something else)
 *
 * Really no idea what this does... seems to be the 'file-descriptor'
 * equivalent to the chpriv...
 *
 * Return value (in r3):
 *
 */
int aix_fchpriv(uc_engine *uc)
{
	u32 fd   = read_1st_arg();
	u32 pcl  = read_2nd_arg();
	u32 smth = read_3rd_arg();
	int ret  = 0;

	if (fd < 0) {
		unix_set_errno(AIX_EBADF);
		goto out;
	}

out:
	TRACE("fchpriv", "%d, %x, %d", fd, pcl, smth);
	return ret;
}
