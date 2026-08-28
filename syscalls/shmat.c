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
#include <time.h>

#include "syscalls.h"
#include "unix.h"
#include "aix_errno.h"
#include "mm.h"
#include "aix_mmap.h"

/* Shared memory routines. */

#define AIX_SHM_MAP    0x800  /* Map a file instead of a memory segment.   */
#define AIX_SHM_RDONLY 0x1000 /* Attach a RO memory segment.               */
#define AIX_SHM_RND    0x2000 /* Round attached address to next lower seg. */
#define AIX_SHM_COPY   0x4000 /* Defered update (requires O_DEFER.)        */

#define SHM_MAX      16
#define SHMAT_UNUSED  0
#define SHMAT_FILE_SIZE (64<<20) /* 64 MiB. */

/* IPC flags & commands. */
#define AIX_IPC_CREAT  0020000
#define AIX_IPC_EXCL    0002000
#define AIX_IPC_PRIVATE ((s32)-1)
#define AIX_IPC_RMID    0

static struct shmat_internal {
	int id;       /* Used for aix_shmid_ds. */
	int fd;
	u32 flags;    /* Mapping flags. */
	u32 addr;     /* VM address.                  */
	u32 size;     /* new truncated size.          */
	u32 osize;    /* old size, before any writes. */
	u32 cmaxpage; /* Current max page written.    */
	uc_hook hook; /* Unicorn memory hook.         */
} shmat_priv[SHM_MAX] = {0};

/*
 * Yes, this is a *very* reduced and not binary-compatible yet
 * with AIX, since I dont plan to return a 'struct shmid_ds'
 * yet.
 */
struct aix_shmid_ds {
	struct aix_ipc_perm	{
		u32 mode;
		int key;
	} shm_perm;
	u32 shm_segsz;
	u32 shm_ctime;
} shms[SHM_MAX] = {0};

static bool page_write_hdlr(uc_engine *uc, uc_mem_type type, u64 address,
	int size, s64 value, void *user_data);

/**
 * @brief For a given @pcurr_pagenr and a @sh pointer structure, register
 * a new hook for the new calculated address and mapping pointed to by @p sh.
 *
 * @param uc          Unicorn context.
 * @param curr_pagenr Current page number.
 * @param sh          Pointer to 'shmat_internal' structure.
 */
static void
register_hook(uc_engine *uc, u32 curr_pagenr, struct shmat_internal *sh)
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
 * @param user_data Pointer to 'shmat_internal' structure.
 *
 * @return Always true.
 */
static bool page_write_hdlr(uc_engine *uc, uc_mem_type type, u64 address,
	int size, s64 value, void *user_data)
{
	struct shmat_internal *sh = user_data;
	u32 pagenr;
	uc_err err;

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
 * @param sh  Pointer to 'shmat_internal' structure.
 *
 * @return If success, returns the mapped address, -1 otherwise (errno set).
 */
static s32
map_ro_file(uc_engine *uc, int fd, struct stat *st, struct shmat_internal *sh)
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
 * @param sh  Pointer to 'shmat_internal' structure.
 *
 * @return If success, returns the mapped address, -1 otherwise (errno set).
 */
static s32
map_rw_file(uc_engine *uc, int fd, struct stat *st, struct shmat_internal *sh)
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
 * @brief Attaches the provided fd, into the current process.
 *
 * @param uc   Unicorn Context.
 * @param fd   File Descriptor to be attached.
 * @param flg  Shared memory flags, currenrly only 'SHM_RDONLY' flag.
 *
 * @return Returns the allocated shmem ad
 */
static int do_shmat_file(uc_engine *uc, u32 fd, u32 flg)
{
	struct stat st;
	int ret = -1;
	int i;

	/* Validate FD. */
	if (fstat(fd, &st) < 0) {
		unix_set_errno(AIX_EBADF);
		return ret;
	}

	/* Find an empty slot. */
	for (i = 0; i < SHM_MAX; i++)
		if (shmat_priv[i].addr == SHMAT_UNUSED)
			break;

	if (i == SHM_MAX) {
		unix_set_errno(AIX_EMFILE);
		return ret;
	}

	shmat_priv[i].fd    = fd;
	shmat_priv[i].flags = flg;

	if (flg & AIX_SHM_RDONLY)
		ret = map_ro_file(uc, fd, &st, &shmat_priv[i]);
	else
		ret = map_rw_file(uc, fd, &st, &shmat_priv[i]);

	return ret;
}

/**
 * @brief Attaches an already allocated shared memory id, into the
 * current process.
 *
 * @param uc   Unicorn Context.
 * @param id   Shared memory id.
 * @param addr Required address, if any.
 * @param flg  Shared memory flags, currenrly only 'SHM_RDONLY' flag.
 *
 * @return Returns the allocated shmem ad
 */
static int do_shmat_memory(uc_engine *uc, s32 id, u32 addr, u32 flg)
{
	int i;
	int ret;
	int mmap_flgs;
	int mmap_prot;
	struct aix_shmid_ds *shm;

	if (id < 1 || id > SHM_MAX) {
		unix_set_errno(AIX_EINVAL);
		return -1;
	}

	/* Find an empty slot. */
	for (i = 0; i < SHM_MAX; i++)
		if (shmat_priv[i].addr == SHMAT_UNUSED)
			break;
	if (i == SHM_MAX) {
		unix_set_errno(AIX_ENOSPC);
		return -1;
	}

	shm = &shms[id - 1];
	if (!shm->shm_ctime) { /* Not used. */
		unix_set_errno(AIX_EINVAL);
		return -1;
	}

	mmap_prot = AIX_PROT_READ;
	mmap_flgs = AIX_MAP_ANONYMOUS|AIX_MAP_SHARED;
	if (!(flg & AIX_SHM_RDONLY))
		mmap_prot |= AIX_PROT_WRITE;
	if (addr)
		mmap_flgs |= AIX_MAP_FIXED;

	ret = aix_do_mmap(uc, addr, shm->shm_segsz, mmap_prot, mmap_flgs, -1, 0);
	if (ret != -1) {
		shmat_priv[i].flags = flg;
		shmat_priv[i].id    = id;
		shmat_priv[i].addr  = ret;
		shmat_priv[i].size  = ALIGN_UP(shm->shm_segsz);
		shmat_priv[i].fd    = -1; /* Not a file. */
	}
	return ret;
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
	u32 fd_id = read_1st_arg();
	u32 addr  = read_2nd_arg();
	u32 flg   = read_3rd_arg();
	int ret   = -1;

	/* If file. */
	if (flg & AIX_SHM_MAP)
		ret = do_shmat_file(uc, fd_id, flg);

	/* If memory. */
	else
		ret = do_shmat_memory(uc, fd_id, addr, flg);

	TRACE("shmat", "%d, 0x%x, 0x%x", fd_id, addr, flg);
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
	struct shmat_internal *sh;
	int ret  = -1;
	u32 addr = read_1st_arg();
	u32 osize_aligned;
	u32 final_size;
	int i;

	for (i = 0, sh = &shmat_priv[0]; i < SHM_MAX; i++, sh++) {
		if (sh->addr == addr)
			break;
	}
	if (i == SHM_MAX) {
		unix_set_errno(AIX_EINVAL);
		goto out;
	}

	/* If file and RW. */
	if ((sh->flags & AIX_SHM_MAP) && !(sh->flags & AIX_SHM_RDONLY)) {
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

/**
 * @brief Reserve/allocate a new shared memory for a given @p key, with
 * @p size and @p flag.
 * @param key  Chosen key or -1 if IPC_PRIVATE.
 * @param size Size of the shared memory.
 * @param flag Shared memory flags (ignored here).
 * @return Returns the shared memory ID if success, -1 otherwise (errno set).
 */
static int new_shm(s32 key, s32 size, u32 flag)
{
	int id;

	/* Find empty slot. */
	for (id = 0; id < SHM_MAX; id++) {
		if (!shms[id].shm_ctime)
			break;
	}
	if (id == SHM_MAX) {
		unix_set_errno(AIX_ENOSPC);
		return -1;
	}

	shms[id].shm_segsz     = size;
	shms[id].shm_perm.mode = (flag & 0777);
	shms[id].shm_perm.key  = key;
	shms[id].shm_ctime     = time(NULL);
	return id + 1;
}

/**
 * @brief shmget(2) AIX syscall handler.
 *
 * AIX calling convention:
 *   r3 = key
 *   r4 = size
 *   r5 = shmflag
 *
 * @note This is a *very* lazy shmget implementation:
 * I'm just using my already-implemented mmap(2) with MAP_ANONYMOUS+MAP_SHARED
 * under the hood.
 *
 * The semantics are not identical but for the majority of the cases (i.e.,
 * where the VM forks a single another process), it should work the same
 * (multiple forks and/or execve would lose, though).
 *
 * If this proves to be insufficient (hope not), then I would consider
 * implementing a true shmem mechanism, using Linux's shmem routines + mapping
 * a 1:1 with the VM memory.
 *
 * Return value (in r3):
 *   On success, returns the shared memory identifier, -1 otherwise
 *   (with errno set).
 */
int aix_shmget(uc_engine *uc)
{
	int ret   = -1;
	int id    =  0;
	s32 key   = read_1st_arg();
	s32 size  = read_2nd_arg();
	u32 sflag = read_3rd_arg();

	if (size < 0) {
		unix_set_errno(AIX_EINVAL);
		goto out;
	}

	if (key == AIX_IPC_PRIVATE) {
		ret = new_shm(key, size, sflag);
		goto out;
	}

	/* Look if the provided key exists. */
	for (id = 0; id < SHM_MAX; id++) {
		if (!shms[id].shm_ctime)
			continue; /* Skip empty/not-used keys. */
		if (shms[id].shm_perm.key == key)
			break;
	}
	if (id == SHM_MAX) {
		/* Key not found, check if user asked to create. */
		if (!(sflag & AIX_IPC_CREAT)) {
			unix_set_errno(AIX_ENOENT);
			goto out;
		}
		ret = new_shm(key, size, sflag);
		goto out;
	}

	/* If explicitly asked to error if found an existing key,
	 * we do so now. */
	if ((sflag & AIX_IPC_CREAT) && (sflag & AIX_IPC_EXCL)) {
		unix_set_errno(AIX_EEXIST);
		goto out;
	}

	/*
	 * Errors out if the requested size is greater than
	 * the current segment.
	 */
	if ((u32)size > shms[id].shm_segsz) {
		unix_set_errno(AIX_EINVAL);
		goto out;
	}

	ret = id + 1;
out:
	TRACE("shmget", "%d, %d, %x", key, size, sflag);
	return ret;
}

/**
 * @brief shmctl(2) AIX syscall handler.
 *
 * Performs a given operation in a provided shared memory id.
 *
 * AIX calling convention:
 *   r3 = shmid
 *   r4 = operation
 *   r5 = shmid_ds structure pointer (ignored).
 *
 * (Currently only supports IPC_RMID)
 *
 * Return value (in r3):
 *   On success, returns 0, -1 otherwise (errno set).
 */
int aix_shmctl(uc_engine *uc)
{
	int ret   = -1;
	s32 shmid    = read_1st_arg();
	s32 op       = read_2nd_arg();
	u32 shmid_ds = read_3rd_arg();

	((void)shmid_ds);

	if (op < 0 || shmid < 1 || shmid > SHM_MAX) {
		unix_set_errno(AIX_EINVAL);
		goto out;
	}

	if (!shms[shmid - 1].shm_ctime) { /* If not used. */
		unix_set_errno(AIX_EIDRM);
		goto out;
	}

	if (op != AIX_IPC_RMID) { /* We only support RMID. */
		unix_set_errno(AIX_EINVAL);
		goto out;
	}

	ret = 0;
	memset(&shms[shmid - 1], 0, sizeof(struct aix_shmid_ds));
out:
	TRACE("shmctl", "%d, %d, %x", shmid, op, shmid_ds);
	return ret;
}
