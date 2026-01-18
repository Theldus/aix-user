/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025-2026
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <sys/sysmacros.h>
#include "syscalls.h"
#include "unix.h"
#include "aix_errno.h"

static u32 o_errno;
static struct stat linux_st;

struct aix_st_timespec {
	u32 tv_sec;
	u32 tv_nsec;
};
struct aix_timespec64 {
	u64 tv_sec;
	s32 tv_nsec;
	s32 tv_pad;
};

static struct aix_stat {
	u32 st_dev;
	u32 st_ino;
	u32 st_mode;
	u16 st_nlink;
	u16 st_flag;
	u32 st_uid;
	u32 st_gid;
	u32 st_rdev;
	s32 st_size;
	struct aix_st_timespec st_atim;
	struct aix_st_timespec st_mtim;
	struct aix_st_timespec st_ctim;
	u32 st_blksize;
	u32 st_blocks;
	s32 st_vfstype;
	u32 st_vfs;
	u32 st_type;
	u32 st_gen;
	u32 st_reserved[9];
} aix_st;
static struct aix_stat64 {
	u32 st_dev;
	u32 st_ino;
	u32 st_mode;
	u16 st_nlink;
	u16 st_flag;
	u32 st_uid;
	u32 st_gid;
	u32 st_rdev;
	u32 st_ssize;
	struct aix_st_timespec st_atim;
	struct aix_st_timespec st_mtim;
	struct aix_st_timespec st_ctim;
	u32 st_blksize;
	u32 st_blocks;
	s32 st_vfstype;
	u32 st_vfs;
	u32 st_type;
	u32 st_gen;
	u32 st_reserved[10];
	s64 st_size;
} aix_st64;
static struct aix_stat64x {
	u64 st_dev;
	u64 st_ino;
	u32 st_mode;
	u16 st_nlink;
	u16 st_flag;
	u32 st_uid;
	u32 st_gid;
	u64 st_rdev;
	s64 st_size;
	struct aix_timespec64 st_atim;
	struct aix_timespec64 st_mtim;
	struct aix_timespec64 st_ctim;
	u64 st_blksize;
	u64 st_blocks;
	s32 st_vfstype;
	u32 st_vfs;
	u32 st_type;
	u32 st_gen;
	u32 st_reserved[11];
} aix_st64x;

/* Cmd args. */
#define	STX_NORMAL  00  /* Normal stat. */
#define	STX_LINK    01  /* Returns info about symlinks too. */
#define	STX_MOUNT   02	/* Do not traverse final mount point */
#define	STX_HIDDEN  04	/* Returns info about hidden directory. */
#define	STX_64      010 /* Use stat64. */
#define STX_64X     020 /* Use stat64x. */

/* Make a device number: 32 and 64 bit */
#define	aix_makedev(__x,__y) (u32)(((__x)<<16) | (__y))
#define aix_makedev64(_major, _minor) \
	((u64)(((u64)(_major) << 32LL) | \
		((u64)(_minor) & 0x00000000FFFFFFFFLL) | 0x8000000000000000LL))

/**
 * @brief Converts a Linux's 'struct stat' structure into aix_stat
 * structure.
 * @param aix_st   Target AIX stat structure.
 * @param linux_st Source Linux stat structure.
 */
static void
stat_linux2aix(struct aix_stat *aix_st, const struct stat *linux_st)
{
	memset(aix_st, 0, sizeof (*aix_st));
	aix_st->st_dev   = htonl(
		                 aix_makedev(
		                 	major(linux_st->st_dev), minor(linux_st->st_dev)));
	
	aix_st->st_ino   = htonl(linux_st->st_ino);
	/*
	 * Obs: the AIX modes seems to match Linux's modes too, thats why no
     * conversion were made here!.
     */
	aix_st->st_mode  = htonl(linux_st->st_mode);
	aix_st->st_nlink = htons(linux_st->st_nlink);
	aix_st->st_uid   = htonl(linux_st->st_uid);
	aix_st->st_gid   = htonl(linux_st->st_gid);
	aix_st->st_rdev  = htonl(linux_st->st_rdev);
	aix_st->st_size  = htonl(linux_st->st_size);
	aix_st->st_atim.tv_sec  = htonl(linux_st->st_atim.tv_sec);
	aix_st->st_atim.tv_nsec = htonl(linux_st->st_atim.tv_nsec);
	aix_st->st_mtim.tv_sec  = htonl(linux_st->st_mtim.tv_sec);
	aix_st->st_mtim.tv_nsec = htonl(linux_st->st_mtim.tv_nsec);
	aix_st->st_ctim.tv_sec  = htonl(linux_st->st_ctim.tv_sec);
	aix_st->st_ctim.tv_nsec = htonl(linux_st->st_ctim.tv_nsec);
	aix_st->st_blksize = htonl(linux_st->st_blksize);
	aix_st->st_blocks  = htonl(linux_st->st_blocks);
	/* Below are fields that do not exist on Linux, so they'll be just ignored
     * at the moment. */
	aix_st->st_flag  = 0;
	aix_st->st_vfstype = 0;
	aix_st->st_vfs     = 0;
	aix_st->st_type    = 0;
	aix_st->st_gen     = 0;
}

/**
 * @brief Converts a Linux's 'struct stat' structure into aix_stat64
 * structure.
 * @param aix_st   Target AIX stat64 structure.
 * @param linux_st Source Linux stat structure.
 */
static void
stat64_linux2aix(struct aix_stat64 *aix_st, const struct stat *linux_st)
{
	memset(aix_st, 0, sizeof (*aix_st));
	aix_st->st_dev   = htonl(
		                 aix_makedev(
		                 	major(linux_st->st_dev), minor(linux_st->st_dev)));
	aix_st->st_ino   = htonl(linux_st->st_ino);
	aix_st->st_mode  = htonl(linux_st->st_mode);
	aix_st->st_nlink = htons(linux_st->st_nlink);
	aix_st->st_uid   = htonl(linux_st->st_uid);
	aix_st->st_gid   = htonl(linux_st->st_gid);
	aix_st->st_rdev  = htonl(linux_st->st_rdev);
	aix_st->st_ssize = htonl(linux_st->st_size);
	aix_st->st_size  = htonll(linux_st->st_size);
	aix_st->st_atim.tv_sec  = htonl(linux_st->st_atim.tv_sec);
	aix_st->st_atim.tv_nsec = htonl(linux_st->st_atim.tv_nsec);
	aix_st->st_mtim.tv_sec  = htonl(linux_st->st_mtim.tv_sec);
	aix_st->st_mtim.tv_nsec = htonl(linux_st->st_mtim.tv_nsec);
	aix_st->st_ctim.tv_sec  = htonl(linux_st->st_ctim.tv_sec);
	aix_st->st_ctim.tv_nsec = htonl(linux_st->st_ctim.tv_nsec);
	aix_st->st_blksize = htonl(linux_st->st_blksize);
	aix_st->st_blocks  = htonl(linux_st->st_blocks);
	/* No-equivalent fields. */
	aix_st->st_flag  = 0;
	aix_st->st_vfstype = 0;
	aix_st->st_vfs     = 0;
	aix_st->st_type    = 0;
	aix_st->st_gen     = 0;
}

/**
 * @brief Converts a Linux's 'struct stat' structure into aix_stat64x
 * structure.
 * @param aix_st   Target AIX stat64x structure.
 * @param linux_st Source Linux stat structure.
 */
static void
stat64x_linux2aix(struct aix_stat64x *aix_st, const struct stat *linux_st)
{
	memset(aix_st, 0, sizeof (*aix_st));
	aix_st->st_dev   = htonll(
		                 aix_makedev64(
		                 	major(linux_st->st_dev), minor(linux_st->st_dev)));
	aix_st->st_ino   = htonll(linux_st->st_ino);
	aix_st->st_mode  = htonl(linux_st->st_mode);
	aix_st->st_nlink = htons(linux_st->st_nlink);
	aix_st->st_uid   = htonl(linux_st->st_uid);
	aix_st->st_gid   = htonl(linux_st->st_gid);
	aix_st->st_rdev  = htonll(linux_st->st_rdev);
	aix_st->st_size  = htonll(linux_st->st_size);
	aix_st->st_atim.tv_sec  = htonll(linux_st->st_atim.tv_sec);
	aix_st->st_atim.tv_nsec = htonl(linux_st->st_atim.tv_nsec);
	aix_st->st_mtim.tv_sec  = htonll(linux_st->st_mtim.tv_sec);
	aix_st->st_mtim.tv_nsec = htonl(linux_st->st_mtim.tv_nsec);
	aix_st->st_ctim.tv_sec  = htonll(linux_st->st_ctim.tv_sec);
	aix_st->st_ctim.tv_nsec = htonl(linux_st->st_ctim.tv_nsec);
	aix_st->st_blksize = htonll(linux_st->st_blksize);
	aix_st->st_blocks  = htonll(linux_st->st_blocks);
	/* No-equivalent fields. */
	aix_st->st_flag  = 0;
	aix_st->st_vfstype = 0;
	aix_st->st_vfs     = 0;
	aix_st->st_type    = 0;
	aix_st->st_gen     = 0;
}

/**
 * @brief statx/fstatx syscall handler.
 *
 * Very initial implementation of statx
 *
 * Note: This is *NOT* the same as the Linux's statx syscall, but share
 * the same idea. Also, there is *no* 'stat(2)' syscall on AIX, so the
 * libc's stat, lstat and etc relies on this one.
 *
 * AIX calling convention:
 *   r3 = path
 *   r4 = buffer
 *   r5 = length
 *   r6 = command
 *
 * Return value (in r3):
 *   Returns 0 if success, -1 and errno otherwise.
 */
static int do_stat(uc_engine *uc, int have_fd)
{
	char spath[1024] = {0};
	u32 path_fd = read_1st_arg();
	u32 buff    = read_2nd_arg();
	u32 length  = read_3rd_arg();
	u32 cmd     = read_4th_arg();
	int ret     = -1;
	void *st;
	size_t exp_len;

	if (!have_fd) {
		if (uc_mem_read(uc, path_fd, &spath, sizeof spath)) {
			unix_set_errno(AIX_EINVAL);
			goto out;
		}
	}

	/* Determine which structure type based on command flags */
	if (cmd & STX_64X) {
		exp_len = sizeof(struct aix_stat64x);
		/* STX_64X requires exact size match */
		if (length != 0 && length != exp_len) {
			unix_set_errno(AIX_EINVAL);
			ret = -1;
			goto out;
		}
	} 
	else if (cmd & STX_64)
		exp_len = sizeof(struct aix_stat64);
	else
		exp_len = sizeof(struct aix_stat);

	/* Validate length parameter (0 means use full size) */
	if (length == 0)
		length = exp_len;
	else if (length > exp_len) {
		unix_set_errno(AIX_EINVAL);
		ret = -1;
		goto out;
	}

	/* Perform stat,lstat or fstat based on STX_LINK and have_fd flags. */
	if (!have_fd) {
		if (cmd & STX_LINK)
			ret = lstat(spath, &linux_st);
		else
			ret = stat(spath, &linux_st);
	}
	else
		ret = fstat(path_fd, &linux_st);

	if (ret < 0) {
		unix_set_conv_errno(errno);
		goto out;
	}

	/* Check for EOVERFLOW on normal stat with large files */
	if (!(cmd & (STX_64|STX_64X)) && linux_st.st_size > 0x7FFFFFFF) {
		unix_set_errno(AIX_EOVERFLOW);
		ret = -1;
		goto out;
	}

	/* Convert to appropriate AIX structure */
	if (cmd & STX_64X) {
		stat64x_linux2aix(&aix_st64x, &linux_st);
		st = &aix_st64x;
	} else if (cmd & STX_64) {
		stat64_linux2aix(&aix_st64, &linux_st);
		st = &aix_st64;
	} else {
		stat_linux2aix(&aix_st, &linux_st);
		st = &aix_st;
	}

	/* Write the converted structure to destination */
	if (uc_mem_write(uc, buff, st, length)) {
		unix_set_errno(AIX_EINVAL);
		ret = -1;
		goto out;
	}

	ret = 0;
out:
	if (!have_fd)
		TRACE("statx", "\"%s\", %x, %u, 0%o", spath, buff, length, cmd);
	else
		TRACE("fstatx", "%u, %x, %u, 0%o", path_fd, buff, length, cmd);
	return ret;
}

/**
 * AIX's statx entrypoint
 */
int aix_statx(uc_engine *uc) {
	return do_stat(uc, 0);
}

/**
 * AIX's fstatx entrypoint
 */
int aix_fstatx(uc_engine *uc) {
	return do_stat(uc, 1);
}
