/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025-2026
 */

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "syscalls.h"
#include "unix.h"
#include "aix_errno.h"
#include "mm.h"
#include "aix_mmap.h"

#define AIX_SHM_MAP    0x800  /* Map a file instead of a memory segment.   */
#define AIX_SHM_RDONLY 0x1000 /* Attach a RO memory segment.               */
#define AIX_SHM_RND    0x2000 /* Round attached address to next lower seg. */
#define AIX_SHM_COPY   0x4000 /* Defered update (requires O_DEFER.)        */

#define SHMAT_UNUSED 0
#define SHMAT_AMNT_FILES 16
#define SHMAT_FILE_SIZE (64<<20) /* 64 MiB. */

struct shmat_file {
	int fd;
	u32 flags;    /* Mapping flags. */
	u32 addr;     /* VM address.                  */
	u32 size;     /* new truncated size.          */
	u32 osize;    /* old size, before any writes. */
	u32 cmaxpage; /* Current max page written.    */
	uc_hook hook; /* Unicorn memory hook.         */
} shmat_files[SHMAT_AMNT_FILES] = {0};

static bool page_write_hdlr(uc_engine *uc, uc_mem_type type, u64 address,
	int size, s64 value, void *user_data);

/**
 * @brief For a given @pcurr_pagenr and a @sh pointer structure, register
 * a new hook for the new calculated address and mapping pointed to by @p sh.
 *
 * @param uc          Unicorn context.
 * @param curr_pagenr Current page number.
 * @param sh          Pointer to 'shmat_file' structure.
 */
static void
register_hook(uc_engine *uc, u32 curr_pagenr, struct shmat_file *sh)
{
	uc_err err;
	u32 new_pagenr = curr_pagenr + 1;
	u32 new_addr   = sh->addr + (new_pagenr << PAGE_SHIFT);

	/* No need to add a new hook if already in last page. */
	if (new_pagenr >= (sh->size >> PAGE_SHIFT))
		return;

	err = uc_hook_add(uc, &sh->hook, UC_HOOK_MEM_WRITE, &page_write_hdlr, sh,
		new_addr, sh->addr + sh->size - 1);
	if (err != UC_ERR_OK)
		warn("Failed to add hook for new addr: %x\n", new_addr);
}

/**
 * @brief Page write handler: this handler is invoked whenever there is a write
 * to a new (non-tracked) max page, this allows us to precisely know what is
 * the highest written page during the shmat() lifecycle, and then, truncate
 * the file accordingly.
 *
 * @param uc        Unicorn context.
 * @param type      Memory type handler, must be UC_MEM_WRITE.
 * @param address   Triggered address.
 * @param size      Memory size what was written (unused).
 * @param value     Value that was attempted to be written.
 * @param user_data Pointer to 'shmat_file' structure.
 *
 * @return Always true.
 */
static bool page_write_hdlr(uc_engine *uc, uc_mem_type type, u64 address,
	int size, s64 value, void *user_data)
{
	struct shmat_file *sh = user_data;
	u32 pagenr;
	uc_err err;
	u32 newaddr;

	if (type != UC_MEM_WRITE)
		return true;

	/*
	 * This should'nt occur, but if the handler is triggered for an address
	 * below the max page, we ignore entirely.
	 */
	pagenr = (address - sh->addr) >> PAGE_SHIFT;
	if (pagenr <= sh->cmaxpage) {
		warn("Unexpected handler for pagenr: %d\n", pagenr);
		return true;
	}
	sh->cmaxpage = pagenr;

	if ((err = uc_hook_del(uc, sh->hook)) != UC_ERR_OK) {
		warn("Unable to delete hook for file mapped at: %x\n", sh->addr);
		return true;
	}

	/* Re-add hook again, but skipping into a new page. */
	register_hook(uc, pagenr, sh);
	return true;
}

/**
 * @brief Maps a RO file to the mapping pointed by @p sh.
 *
 * Read-only mappings are basically just an alias for mmap(), since the behavior
 * is exactly the same.
 *
 * @param uc  Unicorn context.
 * @param fd  File descriptor.
 * @param st  Stat structure for the given fd.
 * @param sh  Pointer to 'shmat_file' structure.
 *
 * @return If success, returns the mapped address, -1 otherwise (errno set).
 */
static s32
map_ro_file(uc_engine *uc, int fd, struct stat *st, struct shmat_file *sh)
{
	s32 addr;

	/* There's no point in mapping a 0-sized file as RO. */
	if (!st->st_size) {
		unix_set_errno(AIX_EBADF);
		return -1;
	}

	addr = aix_do_mmap(uc, 0, st->st_size, AIX_PROT_READ, AIX_MAP_SHARED, fd, 0);
	if (addr == -1)
		return -1;

	sh->osize    = st->st_size;
	sh->addr     = addr;
	sh->size     = st->st_size;
	sh->cmaxpage = 0;
	return addr;
}

/**
 * @brief Maps a RW file to the mapping pointed by @p sh.
 *
 * Read-write mappings differs from a standard mmap(): shmat() do *not* requires
 * a size to be know ahead-of-time and thus, the file grows dynamically,
 * PAGESIZE-aligned bytes. Even so, AIX imposes a limit of 256MiB for each
 * mapped file, which is called 'section', and thus, we're doing similar here:
 * defining a 'ceiling' on how much the file can grow (SHMAT_FILE_SIZE),
 * truncating to that size, tracking the highest page written, and finally,
 * truncating the file back to a more appropriated size, page-aligned too.
 *
 * @param uc  Unicorn context.
 * @param fd  File descriptor.
 * @param st  Stat structure for the given fd.
 * @param sh  Pointer to 'shmat_file' structure.
 *
 * @return If success, returns the mapped address, -1 otherwise (errno set).
 */
static s32
map_rw_file(uc_engine *uc, int fd, struct stat *st, struct shmat_file *sh)
{
	s32 addr;

	/* Max file size. */
	if (st->st_size >= SHMAT_FILE_SIZE) {
		unix_set_errno(AIX_ENOMEM);
		return -1;
	}

	/* (Attempt to) Truncate to max size first. */
	if (ftruncate(fd, SHMAT_FILE_SIZE) < 0) {
		unix_set_errno(AIX_ENOMEM);
		return -1;
	}

	addr = aix_do_mmap(uc, 0, SHMAT_FILE_SIZE, AIX_PROT_READ|AIX_PROT_WRITE,
		AIX_MAP_SHARED, fd, 0);
	if (addr == -1)
		return -1;

	sh->osize    = st->st_size;
	sh->addr     = addr;
	sh->size     = SHMAT_FILE_SIZE;
	sh->cmaxpage = 0;

	/* Register hook. */
	register_hook(uc, 0, sh);
	return addr;
}

/**
 * @brief shmat syscall handler.
 * Attaches a shared memory segment or a mapped file to the current
 * process.
 *
 * Note: This is *not*-POSIX aligned, the AIX version of shmat *do differs*
 * from the specs stated on POSIX. Moreover, the only feature being implemented
 * here is the file mapping, which borrows most of the functionality from the
 * mmap.
 *
 * AIX calling convention:
 *   r3 = shmid / fd (Shared memory ID or File descriptor)
 *   r4 = addr       (Shared memory address, might be NULL)
 *   r5 = flg        (Shared memory flags: SHM_COPY,SHM_MAP,SHM_RDONLY,SHM_RND
 *
 * Return value (in r3):
 *   If success, returns the starting address of the shared memory, otherwise,
 *   returns -1 with errno set.
 */
int aix_shmat(uc_engine *uc)
{
	struct stat st;
	int ret  = -1;
	u32 fd   = read_1st_arg();
	u32 addr = read_2nd_arg();
	u32 flg  = read_3rd_arg();
	int i;

	((void)addr); /* unused. */

	/* We only support SHM_MAP flag!. */
	if (!(flg & AIX_SHM_MAP)) {
		unix_set_errno(AIX_ENOTSUP);
		goto out;
	}

	/* Validate FD. */
	if (fstat(fd, &st) < 0) {
		unix_set_errno(AIX_EBADF);
		goto out;
	}

	/* Find an empty slot. */
	for (i = 0; i < SHMAT_AMNT_FILES; i++)
		if (shmat_files[i].addr == SHMAT_UNUSED)
			break;

	if (i == SHMAT_AMNT_FILES) {
		unix_set_errno(AIX_EMFILE);
		goto out;
	}

	shmat_files[i].fd    = fd;
	shmat_files[i].flags = flg;

	if (flg & AIX_SHM_RDONLY)
		ret = map_ro_file(uc, fd, &st, &shmat_files[i]);
	else
		ret = map_rw_file(uc, fd, &st, &shmat_files[i]);

out:
	TRACE("shmat", "%d, 0x%x, 0x%x", fd, addr, flg);
	return ret;
}

/**
 * @brief shmdt(2) AIX syscall handler.
 *
 * AIX calling convention:
 *   r3 = address
 *
 * Return value (in r3):
 *   On success, returns 0, -1 otherwise (with errno set).
 */
int aix_shmdt(uc_engine *uc)
{
	struct shmat_file *sh;
	int ret  = -1;
	u32 addr = read_1st_arg();
	u32 osize_aligned;
	u32 final_size;
	int i;

	for (i = 0, sh = &shmat_files[0]; i < SHMAT_AMNT_FILES; i++, sh++) {
		if (sh->addr == addr)
			break;
	}
	if (i == SHMAT_AMNT_FILES) {
		unix_set_errno(AIX_EINVAL);
		goto out;
	}

	/* If RW. */
	if (!(sh->flags & AIX_SHM_RDONLY)) {
		if (uc_hook_del(uc, sh->hook) != UC_ERR_OK) {
			unix_set_errno(AIX_EINVAL);
			goto out;
		}

		final_size    = (sh->cmaxpage + 1) << PAGE_SHIFT;
		osize_aligned = ALIGN_UP(sh->osize);

		/* If original size is greater than the highest written page,
		 * we truncate back to original size, page-aligned. */
		if (osize_aligned > final_size)
			final_size = osize_aligned;

		/* Truncate size to the biggest page touched during writes. */
		if (ftruncate(sh->fd, final_size) < 0) {
			unix_set_errno(AIX_EINVAL);
			goto out;
		}
	}

	/* RW or RO: RO only needs munmap. */
	ret = aix_do_munmap(sh->addr, sh->size);
	memset(sh, 0, sizeof(*sh));
out:
	TRACE("shmdt", "0x%x", addr);
	return ret;
}
