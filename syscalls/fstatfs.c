/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025-2026
 */

#include <string.h>
#include <sys/vfs.h>
#include "syscalls.h"
#include "unix.h"
#include "aix_errno.h"
#include "mm.h"

static struct statfs linux_sfs;

/*
 * AIX's cp (32-bit) uses statfs (32-bit) and that's why I'm implementing
 * it. However, I dont known exactly *why* AIX makes use of it.
 *
 * As a comparison: GNU cp does *not* make use of statfs/fstatfs.
 */

struct aix_statfs {
	s32 f_version;    /* Version/type, 0.           */
	s32 f_type;       /* Type of info, 0.           */
	u32 f_bsize;      /* Optimal FS block size, 0   */
	u32 f_blocks;     /* Total data blocks in FS, 0 */
	u32 f_bfree;      /* Free blocks in FS, 0       */
	u32 f_bavail;     /* Free blocks available to non-SU, 0. */
	u32 f_files;      /* Total file nodes in filesystem.     */
	u32 f_ffree;      /* Free file nodes in FS, 0            */
	u32 f_fsid[2];    /* File System ID, 0          */
	s32 f_vfstype;    /* Type of VFS.               */
	u32 f_fsize;      /* Fundamental FS block.      */
	s32 f_vfsnumber;  /* VFS identifier number.     */
	s32 f_vfsoff;     /* VFS data offset, 0         */
	s32 f_vfslen;     /* VFS data len.              */
	s32 f_vfsvers;    /* VFS vers, 0.               */
	char f_fname[32]; /* File system name.          */
	char f_fpack[32]; /* 16x 0's + 4x 0xdeadbeef.   */
	s32 f_name_max;   /* 0xdeadbeef.                */
};

/*
 * Same structure as above, but with the values I could retrieve
 * from AIX 7.3.
 *
 * Interestingly, this structure seems to be way
 * 'well manered' than the 32-bit version, with many fields
 * properly filled and with sane values.
 */
struct aix_statfs64 {
	s32 f_version;       /* 0.    */
	s32 f_type;          /* 0.    */
	u64 f_bsize;         /* 4096. */
	u64 f_blocks;        /* != 0. */
	u64 f_bfree;         /* != 0. */
	u64 f_bavail;        /* != 0. */
	u64 f_files;         /* != 0. */
	u64 f_ffree;         /* != 0. */
	u64 f_fsid[2];       /* 0x8000000a00000008, 0x0. */
	s32 f_vfstype;       /* 0.      */
	u64 f_fsize;         /* 0x1000. */
	s32 f_vfsnumber;     /* 0x7.    */
	s32 f_vfsoff;        /* 0.      */
	s32 f_vfslen;        /* 0.      */
	s32 f_vfsvers;       /* 0.      */
	char f_fname[32];    /* /home.  */
	char f_fpack[32];    /* /home.  */
	s32 f_name_max;      /* 255.    */
};

/**
 * @brief Converts a Linux's 'struct statfs' structure into aix_statfs
 * structure.
 * @param aix_sfs   Target AIX statfs structure.
 * @param linux_sfs Source Linux statfs structure.
 */
static void
statfs_linux2aix(struct aix_statfs *aix_sfs, const struct statfs *linux_sfs)
{
	memset(aix_sfs, 0, sizeof (*aix_sfs));
	aix_sfs->f_bsize    = tobe32((u32)linux_sfs->f_bsize);
	aix_sfs->f_blocks   = tobe32((u32)linux_sfs->f_blocks);
	aix_sfs->f_bfree    = tobe32((u32)linux_sfs->f_bfree);
	aix_sfs->f_bavail   = tobe32((u32)linux_sfs->f_bavail);
	aix_sfs->f_files    = tobe32((u32)linux_sfs->f_files);
	aix_sfs->f_ffree    = tobe32((u32)linux_sfs->f_ffree);
	aix_sfs->f_fsid[0]  = tobe32((u32)linux_sfs->f_fsid.__val[0]);
	aix_sfs->f_fsid[1]  = tobe32((u32)linux_sfs->f_fsid.__val[1]);
	aix_sfs->f_fsize    = tobe32((u32)linux_sfs->f_frsize); /* Kinda similar?. */
	aix_sfs->f_name_max = tobe32((s32)linux_sfs->f_namelen);
	/* Remaining fields would be 0 and we pray that AIX does not complain ^.^ .*/
}

/**
 * @brief Converts a Linux's 'struct statfs' structure into aix_statfs64
 * structure.
 * @param aix_sfs   Target AIX statfs64 structure.
 * @param linux_sfs Source Linux statfs structure.
 */
static void
statfs64_linux2aix(struct aix_statfs64 *aix_sfs, const struct statfs *linux_sfs)
{
	memset(aix_sfs, 0, sizeof (*aix_sfs));
	aix_sfs->f_bsize    = tobe64(linux_sfs->f_bsize);
	aix_sfs->f_blocks   = tobe64(linux_sfs->f_blocks);
	aix_sfs->f_bfree    = tobe64(linux_sfs->f_bfree);
	aix_sfs->f_bavail   = tobe64(linux_sfs->f_bavail);
	aix_sfs->f_files    = tobe64(linux_sfs->f_files);
	aix_sfs->f_ffree    = tobe64(linux_sfs->f_ffree);
	aix_sfs->f_fsid[0]  = tobe64((u64)(u32)linux_sfs->f_fsid.__val[0]);
	aix_sfs->f_fsid[1]  = tobe64((u64)(u32)linux_sfs->f_fsid.__val[1]);
	aix_sfs->f_fsize    = tobe64(linux_sfs->f_frsize);
	aix_sfs->f_name_max = tobe32((s32)linux_sfs->f_namelen);
}

/**
 * @brief Generic fstatfs for both 32 and 64-bit.
 */
static int do_fstatfs(uc_engine *uc, int is_64bit)
{
	int ret;
	void *ptr;
	struct aix_statfs   *aix_sfs;
	struct aix_statfs64 *aix_sfs64;
	s32 fd  = read_1st_arg();
	u32 sfs = read_2nd_arg();
	ret     = -1;

	if (fd < 0 || !sfs) {
		unix_set_errno(AIX_EFAULT);
		goto out;
	}

	if (!(ptr = mm_vm2host(sfs))) {
		unix_set_errno(AIX_EFAULT);
		goto out;
	}

	ret = fstatfs(fd, &linux_sfs);
	if (ret < 0) {
		unix_set_conv_errno(errno);
		goto out;
	}

	if (!is_64bit) {
		aix_sfs = ptr;
		statfs_linux2aix(aix_sfs, &linux_sfs);
	} else {
		aix_sfs64 = ptr;
		statfs64_linux2aix(aix_sfs64, &linux_sfs);
	}
out:
	return ret;
}

/**
 * @brief fstatfs syscall handler.
 *
 * AIX calling convention:
 *   r3 = fd
 *   r4 = statfs buffer pointer
 *
 * Return value (in r3):
 *   Returns 0 if success, -1 and errno otherwise.
 */
int aix_fstatfs(uc_engine *uc)
{
	s32 fd  = read_1st_arg();
	u32 sfs = read_2nd_arg();
	int ret = do_fstatfs(uc, 0);
	TRACE("fstatfs", "%d, %x", fd, sfs);
	return ret;
}

/**
 * @brief fstatfs64 syscall handler.
 *
 * AIX calling convention:
 *   r3 = fd
 *   r4 = statfs64 buffer pointer
 *
 * Return value (in r3):
 *   Returns 0 if success, -1 and errno otherwise.
 */
int aix_fstatfs64(uc_engine *uc)
{
	s32 fd  = read_1st_arg();
	u32 sfs = read_2nd_arg();
	int ret = do_fstatfs(uc, 1);
	TRACE("fstatfs64", "%d, %x", fd, sfs);
	return ret;
}

/* ========================================================================= */

/**
 * @brief Generic statfs/statfs64 impl.
 * @param uc       Unicorn Context.
 * @param h_path   Host-converted path.
 * @param sfs      statfs/statfs64 VM pointer address.
 * @param is_64bit Indicates if it is 64-bit or not.
 * @return Returns 0 if success, -1 otherwise.
 */
static int do_statfs(uc_engine *uc, const char *h_path, u32 sfs, int is_64bit)
{
	int ret;
	void *ptr;
	struct aix_statfs   *aix_sfs;
	struct aix_statfs64 *aix_sfs64;
	ret = -1;

	if (!h_path || !sfs) {
		unix_set_errno(AIX_EFAULT);
		goto out;
	}

	if (!(ptr = mm_vm2host(sfs))) {
		unix_set_errno(AIX_EFAULT);
		goto out;
	}

	ret = statfs(h_path, &linux_sfs);
	if (ret < 0) {
		unix_set_conv_errno(errno);
		goto out;
	}

	if (!is_64bit) {
		aix_sfs = ptr;
		statfs_linux2aix(aix_sfs, &linux_sfs);
	} else {
		aix_sfs64 = ptr;
		statfs64_linux2aix(aix_sfs64, &linux_sfs);
	}
out:
	return ret;
}

/**
 * @brief statfs syscall handler.
 *
 * AIX calling convention:
 *   r3 = path
 *   r4 = statfs buffer pointer
 *
 * Return value (in r3):
 *   Returns 0 if success, -1 and errno otherwise.
 */
int aix_statfs(uc_engine *uc)
{
	const char *h_path;
	int ret;
	u32 sfs;
	h_path = mm_vm2host(read_1st_arg());
	sfs    = read_2nd_arg();
	ret    = do_statfs(uc, h_path, sfs, 0);
	TRACE("statfs", "%s, %x", h_path, sfs);
	return ret;
}

/**
 * @brief statfs64 syscall handler.
 *
 * AIX calling convention:
 *   r3 = path
 *   r4 = statfs buffer pointer
 *
 * Return value (in r3):
 *   Returns 0 if success, -1 and errno otherwise.
 */
int aix_statfs64(uc_engine *uc)
{
	const char *h_path;
	int ret;
	u32 sfs;
	h_path = mm_vm2host(read_1st_arg());
	sfs    = read_2nd_arg();
	ret    = do_statfs(uc, h_path, sfs, 1);
	TRACE("statfs", "%s, %x", h_path, sfs);
	return ret;
}
