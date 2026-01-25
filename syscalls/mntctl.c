/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025-2026
 */

#include <stdio.h>
#include "syscalls.h"
#include "unix.h"
#include "aix_errno.h"

/**
 * @brief mntctl syscall handler.
 *
 * Sets/retrieves info about the mount points.
 * 
 * Some notes about 'MCTL_GET_MNTDOVER_INO':
 *
 * The common for 'pwd' is the MCTL_GET_MNTDOVER_INO (20) which for a given path,
 * it return the parent inode where that path resides:
 *    struct mctl_mntdover_ino {
 *	    ino64_t	mctl_mntdover_ino;	// O ino for mntdover vnode
 *	    char   *mctl_mntdover_path;	// I path for mntdover vnode
 *    }
 *
 * If it asks for the inode of /home, it is asking the inode of the dirent
 * 'home' on / (lets say, 4), which (on AIX) differs for the actual inode
 * of the mounted FS (lets say, 2).
 *
 * Since on Linux the reported inode is the same, there's no point on
 * implementing this cmd, so simply return an error seems to be the best
 * way to deal with this.
 *
 * See sys/vmount.h for more info.
 */
int aix_mntctl(uc_engine *uc)
{
	u32 cmd     = read_1st_arg();
	u32 size    = read_2nd_arg();
	u32 bufptr  = read_3rd_arg();
	int ret     = -1;

	TRACE("mntctl", "%d, %d, %x", cmd, size, bufptr);
	return ret;
}
