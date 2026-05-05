/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025-2026
 */

#define _GNU_SOURCE
#include <dirent.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "syscalls.h"
#include "unix.h"
#include "aix_errno.h"
#include "mm.h"

#define NAME_MAX_LEN 255 /* Maximum name length on a dirent!!. */

/* dirent64 structure. */
struct aix_dirent64 {
	u64 off;     /* FD offset.          */
	u64 ino;     /* Inode number.       */
	u16 reclen;  /* This record length. */
	u16 namlen;  /* Name length.        */
	char name[NAME_MAX_LEN+1]; /* NULL-terminated, 4-byte padded. */
} __attribute__((packed));

/* linux_dirent64. */
struct linux_dirent64 {
	ino64_t        d_ino;    /* 64-bit inode number */
	off64_t        d_off;    /* 64-bit offset to next structure */
	unsigned short d_reclen; /* Size of this dirent */
	unsigned char  d_type;   /* File type */
	char           d_name[]; /* Filename (NULL-terminated) */
};

/**
 * @brief Converts a given linux_dirent64 structure into an appropriated
 * aix_dirent64 structure.
 *
 * @param ad aix_dirent64 target structure.
 * @param ld linux_dirent64 source structure.
 *
 * @return Returns the length of @p ad if success, -1 otherwise.
 */
static int
d64_linux2aix(struct aix_dirent64 *ad, const struct linux_dirent64 *ld)
{
	int i;
	int len;
	int reclen;

	if ((len = strlen(ld->d_name)) > NAME_MAX_LEN)
		return -1;

	ad->off    = tobe64(ld->d_off);
	ad->ino    = tobe64(ld->d_ino);
	ad->namlen = tobe16(len);
	memcpy(ad->name, ld->d_name, len);

	i = len;
	do {
		ad->name[i] = '\0';
	} while (++i & 3);

	reclen = i + 20; /* header (8+8+2+2) + padded name */
	ad->reclen = tobe16(reclen);
	return reclen;
}

/**
 * @brief getdirent64 syscall handler.
 *
 * Get directory entries.
 * This is very similar to the Linux getdents64, so this is mostly
 * a translation between these two syscalls.
 *
 * AIX calling convention:
 *   r3 = fd
 *   r4 = (struct dirent64 *) buffer ptr
 *   r5 = buffer size
 *
 * Return value (in r3):
 *   Number of bytes read on success, -1 on error and errno set.
 */
int aix_getdirent64(uc_engine *uc)
{
	u32 vm_fd     = read_1st_arg();
	u32 vm_d64ptr = read_2nd_arg();
	u32 vm_d64siz = read_3rd_arg();

	char *ptr;
	u32 rem_size;

	struct linux_dirent64 *ldir64;
	struct aix_dirent64    adir64;
	char    *l_buff;
	off64_t  last_off;
	u32      written;
	int      l_ret;
	int      ret;
	int      pos;

	l_buff = NULL;
	ret    = -1;

	/* Handle zero-length reads. */
	if (vm_d64siz == 0) {
		ret = 0;
		goto out;
	}

	/*
	 * Allocate a buffer just a hair bigger than the one provided by AIX, so
	 * we can guarantee that getdents64 will always returns enough entries to
	 * satisfy the AIX request with just a single call.
	 */
	if (!(l_buff = malloc(vm_d64siz + 256)))
		errx(1, "getdirent64: VM OOM!\n");

	l_ret  = getdents64(vm_fd, l_buff, vm_d64siz + 256);
	ldir64 = (struct linux_dirent64 *)l_buff;

	if (l_ret <= 0) {
		unix_set_conv_errno(errno);
		ret = l_ret;
		goto out;
	}

	/* Convert host ptr buffer from VM memory. */
	if (!(ptr = mm_vm2host(vm_d64ptr))) {
		unix_set_errno(AIX_EFAULT);
		goto out;
	}

	rem_size = vm_d64siz;
	written  = 0;
	last_off = 0;
	ret      = 0;
	pos      = 0;

	/* Iterate over all entries returned and save them into AIX. */
	while (l_ret > 0) {
		ret = d64_linux2aix(&adir64, ldir64);
		if (ret < 0)
			goto out;

		if (ret > rem_size) {
			/* Entry won't fit, Seek back so next call returns this entry. */
			lseek(vm_fd, last_off, SEEK_SET);

			/* If the provided buffer is small at the point to not have written
			 * anything: thats ok, AIX's getdirent64 (contrary to Linux's
			 * getdents64), only returns 0 and do no set errno. */
			break;
		}
		
		memcpy(ptr, &adir64, ret);
		last_off = ldir64->d_off;
		l_ret   -= ldir64->d_reclen;
		pos     += ldir64->d_reclen;
		ldir64   = (struct linux_dirent64 *)(l_buff + pos);

		rem_size -= ret;
		ptr      += ret;
		written  += ret;
	}

	ret = written;
out:
	free(l_buff);
	TRACE("getdirent64", "%d, %x, %d", vm_fd, vm_d64ptr, vm_d64siz);
	return ret;
}
