/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025-2026
 */

#define _LARGEFILE64_SOURCE
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include "syscalls.h"
#include "unix.h"
#include "aix_errno.h"

/*
 * Note:
 * The flags below do not exist a direct equivalent on Linux, and thus,
 * they will not be handled:
 *   O_CIO
 *   O_CIOR
 *   O_DEFER
 *   O_DELAY
 *   O_EFSOFF
 *   O_EFSON
 *   O_NSHARE
 *   O_RAW
 *   O_RSHARE
 *   O_SEARCH
 *   O_SNAPSHOT
 */

/* AIX file flags. */
#define AIX_O_APPEND     0x8
#define AIX_O_CREAT      0x100
#define AIX_O_DIRECT     0x8000000
#define AIX_O_DIRECTORY  0x80000
#define AIX_O_DSYNC      0x400000
#define AIX_O_EXCL       0x400
#define AIX_O_LARGEFILE  0x4000000
#define AIX_O_NDELAY     0x8000
#define AIX_O_NOCTTY     0x800
#define AIX_O_NONBLOCK   0x4
#define AIX_O_RDONLY     0x0
#define AIX_O_RDWR       0x2
#define AIX_O_RSYNC      0x200000
#define AIX_O_SYNC       0x10
#define AIX_O_TRUNC      0x200
#define AIX_O_WRONLY     0x1

/**
 * @brief kopen syscall handler.
 *
 * Handles the AIX kopen syscall, which opens and (maybe) creates a new file.
 * This shares the same essence as POSIX open(2), with AIX's extensions.
 *
 * AIX calling convention:
 *   r3 = path  (file path)
 *   r4 = flags (open flags
 *   r5 = mode  (if O_CREAT)
 *
 * Return value (in r3):
 *   If success: file descriptor of the opened file, otherwise,
     -1 with errno set.
 *
 * Note:
 *  There is no 'S_ENFMT'-equivalent on Linux, so this will be
 *  ignored. All other remaining flags are 1:1 and have the same
 *  values.
 */
int aix_kopen(uc_engine *uc)
{
	int ret;
	char opath[1024] = {0};
	u32 path   = read_1st_arg();
	u32 flags  = read_2nd_arg();
	u32 mode   = read_3rd_arg();
	s32 lflags = 0;

	ret = -1;
	if (uc_mem_read(uc, path, &opath, sizeof opath)) {
		unix_set_errno(AIX_EINVAL);
		goto out;
	}

	/*
	 * Create the Linux-equivalent flags from AIX flags.
	 *
	 * Access mode is in the low 2 bits (O_RDONLY=0, O_WRONLY=1, O_RDWR=2).
	 * These values match between AIX and Linux, so copy directly.
	 */
	lflags = flags & 0x3;

	/* Remaining flags. */
	if (flags & AIX_O_APPEND)    lflags |= O_APPEND;
	if (flags & AIX_O_CREAT)     lflags |= O_CREAT;
	if (flags & AIX_O_DIRECT)    lflags |= O_DIRECT;
	if (flags & AIX_O_DIRECTORY) lflags |= O_DIRECTORY;
	if (flags & AIX_O_DSYNC)     lflags |= O_DSYNC;
	if (flags & AIX_O_EXCL)      lflags |= O_EXCL;
	if (flags & AIX_O_LARGEFILE) lflags |= O_LARGEFILE;
	if (flags & AIX_O_NDELAY)    lflags |= O_NDELAY;
	if (flags & AIX_O_NOCTTY)    lflags |= O_NOCTTY;
	if (flags & AIX_O_NONBLOCK)  lflags |= O_NONBLOCK;
	if (flags & AIX_O_RSYNC)     lflags |= O_RSYNC;
	if (flags & AIX_O_SYNC)      lflags |= O_SYNC;
	if (flags & AIX_O_TRUNC)     lflags |= O_TRUNC;

	ret = open(opath, lflags, mode);
	if (ret < 0) {
		unix_set_conv_errno(errno);
		goto out;
	}

out:
	TRACE("kopen", "\"%s\", 0x%x, 0x%x", opath, flags, mode);
	return ret;
}
