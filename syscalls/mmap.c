/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025-2026
 */

#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

#include "aix_errno.h"
#include "mm.h"
#include "unix.h"
#include "syscalls.h"
#include "aix_mmap.h"

/**
 * aix-user mmap routines:
 * This is a 'quick-n'dirty' implementation of mmap: most of the functionality
 * is borrowed directly from the host's mmap(2).
 *
 * For anonymous pages: there is a single 1GiB memory region mapped on AIX, and
 * a single 1GiB 'PROT_NONE' mmap'ed memory region on host memory. This 1:1
 * mapping makes easier to 'allocate' new pages: simply set them as RO or RW
 * and keep track of the used pages.
 *
 * For file mapping pages: for files, there is a Unicorn mapping for each
 * file mapped, despite the files being RO or RW. This makes things easier
 * to handle: all the hard-work to read the files and mapping them to the pages
 * are done 'automatically' via Linux. Conversely, all the hard-work of track
 * which pages were written and flushing them to the files are also handled
 * by the Linux, thanks to the 1:1 mapping used here.
 *
 * ---
 * If (and only if) this approach proves to be insufficient, I do not want
 * to handle this at the 'page-level': handling page-faults and etc, as this
 * greatly complicates all the memory management we have until now.
 */

/**
 * Buffers:
 * char *mmap_base:
 *   Base address of the host-based mmap'ed address.
 *
 * u8   *mmap_page_map:
 *   'Byte-map' tracking all allocated pages at the moment.
 *   Although is a 'waste' of memory (256KiB vs 32KiB), if think it is
 *   still reasonable, so thats why I dont want to bother with bitmaps
 *   here =).
 */
#define AMNT_ANON_PAGES ((MMAP_ANON_SIZE/PAGE_SIZE))
static char *mmap_base;
static u8   *mmap_page_map;

#define PAGE_USED 1
#define PAGE_FREE 0

/* File mapping. */
#define AMNT_FILE_PAGES ((MMAP_FILE_SIZE/PAGE_SIZE))
#define MAX_MMAP_FILES 32
static struct mmap_file {
	int fd;
	int prot;
	u32 size;
	int status;
	u32 vm_base;
	char *host_base;
} mmap_files[MAX_MMAP_FILES];
static u8 *mmap_file_map;

/**
 * @brief Initializes the anonymous and file mapping data structures for mmap.
 */
void aix_mmap_init(void)
{
	/* --------------------------- ANONYMOUS -------------------------------- */
	/* mmap heap address space. */
	mmap_base =
		mmap(NULL, MMAP_ANON_SIZE, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if (mmap_base == MAP_FAILED)
		errx(1, "Unable to allocate mmap memory, aborting...\n");

	/*
	 * Register in region table but *map*into Unicorn: contrary to sbrk,
	 * we will have many sparse allocated data, instead of a big contiguous
	 * chunk, so we really need to allocate everything at once.
	 */
	mm_alloc_region(
		MMAP_ANON_ADDR, MMAP_ANON_SIZE, mmap_base, UC_PROT_READ|UC_PROT_WRITE,
		"mmap (heap)");

	mmap_page_map = calloc(1, AMNT_ANON_PAGES);
	if (!mmap_page_map)
		errx(1, "Unable to allocate pages 'byte-map', aborting...\n");

	/* ------------------------- FILE MAPPING ------------------------------- */
	mmap_file_map = calloc(1, AMNT_FILE_PAGES);
	if (!mmap_file_map)
		errx(1, "Unable to allocate pages for file mapping, aborting...\n");
}

/**
 * @brief Given a VM address pointed by @vm_addr of @p size, checks if the
 * provided address is within the provided region starting at @p base address
 * and size @p region_size.
 *
 * @param vm_addr   VM address to be validated.
 * @param size      VM size to be validated.
 * @param base      Region base address to be compared against.
 * @param region_sz Region size to be compared against.
 *
 * @retun Returns 1 if success, 0 otherwise.
 */
static int is_valid_mmap_addr(u32 vm_addr, u32 size, u32 base, u32 region_sz) {
	/* Range. */
	if (vm_addr < base || size > region_sz || vm_addr > base + region_sz - size)
		return 0;
	/* Invalid base address. (not page aligned.) */
	if ((vm_addr & PAGE_MASK) != vm_addr)
		return 0;
	return 1;
}

/**
 * @brief Finds an empty space on the memory @p pool and returns the starting
 * page number of the found space.
 *
 * @param vm_addr  VM address to be searched (MAP_FIXED-only).
 * @param npages   Amount of pages to be allocated/searched.
 * @param vm_base  VM base address of the searched @p pool.
 * @param vm_size  VM size of the searched @p pool.
 * @param pool     Memory pool to search, whether for anonymous of file mapping.
 * @param is_fixed Signals if the searched memory must be exact (MAP_FIXED) or
 *                 or not.
 * @return If success, returns the page number of the starting page, otherwise,
 * returns -1.
 */
static s32
find_memory(u32 vm_addr, u32 npages, u32 vm_base, u32 vm_size, u8 *pool,
	int is_fixed)
{
	s32 i;
	s32 spage = -1;
	u32 count = 0;
	s32 size  = (npages*PAGE_SIZE);
	u32 vm_max_pages;

	vm_max_pages = vm_size >> PAGE_SHIFT;

	/* Validate address if a fixed address was requested. */
	if (is_fixed) {
		if (!is_valid_mmap_addr(vm_addr, size, vm_base, vm_size)) {
			unix_set_errno(AIX_EINVAL);
			return -1;
		}
		i = (vm_addr - vm_base) >> PAGE_SHIFT;
	}
	else
		i = 0;

	/* Find free space if available. */
	for (; i < vm_max_pages && count < npages; i++) {
		if (pool[i] == PAGE_FREE) {
			count++;
			if (spage == -1)
				spage = i;
		}
		else {
			spage = -1;
			count =  0;
			/* Fixed regions should not find used pages. */
			if (is_fixed)
				break;
		}

	}
	return spage;
}

/**
 * @brief Allocates a new piece of memory (MAP_ANONYMOUS).
 *
 * @param vm_addr  If MAP_FIXED, contains the request address to be mapped.
 * @param lin_flgs Linux flags for the mapping.
 * @param npages   Amount of pages to be mapped.
 * @param prot     Protection flags of the new mapping.
 *
 * @return On success, returns a VM address (within [MMAP_ANON_ADDR,
 * MMAP_ANON_SIZE-1]) containing the allocated memory. On error, returns -1
 * with errno set.
 */
static s32 mmap_anon(u32 vm_addr, u32 lin_flgs, u32 npages, u32 prot)
{
	s32 spage    = -1; /* Starting page. */
	int is_fixed = ((lin_flgs & MAP_FIXED) == MAP_FIXED);

	if (npages > AMNT_ANON_PAGES)
		return -1;

	/* Find a free page. */
	spage = find_memory(vm_addr, npages, MMAP_ANON_ADDR, MMAP_ANON_SIZE,
		mmap_page_map, is_fixed);
	if (spage < 0) {
		unix_set_errno(AIX_ENOMEM);
		return -1;
	}

	/* If found, set them as used. */
	memset(mmap_page_map+spage, PAGE_USED, npages);

	/* Temporarily set to R/W so we can clean the page(s). */
	if (mprotect(mmap_base+(spage*PAGE_SIZE), npages*PAGE_SIZE,
		PROT_READ|PROT_WRITE) < 0) {
		errx(1, "Unable to set perms to page#%d via mmap!\n", spage);
	}

	/* Fill the memory to 0s, as it might be reused. */
	memset(mmap_base+(spage*PAGE_SIZE), 0, npages*PAGE_SIZE);
	if (prot != (PROT_READ|PROT_WRITE)) {
		if (mprotect(mmap_base+(spage*PAGE_SIZE), npages*PAGE_SIZE, prot) < 0)
			errx(1, "Unable to set perms to page#%d via mmap!\n", spage);
	}
	return MMAP_ANON_ADDR + (spage * PAGE_SIZE);
}

/**
 * @brief Maps an already opened file into memory.
 *
 * @param vm_addr  If MAP_FIXED, contains the request address to be mapped.
 * @param lin_flgs Linux flags for the mapping.
 * @param npages   Amount of pages to be mapped.
 * @param prot     Protection flags of the new mapping.
 * @param fd       File descriptor to be mapped.
 * @param off      File offset.
 *
 * @return On success, returns a VM address (within [MMAP_FILE_ADDR,
 * MMAP_FILE_SIZE-1]) containing the mapped memory. On error, returns -1
 * with errno set.
 */
static s32
mmap_file(u32 vm_addr, u32 lin_flgs, u32 npages, u32 prot, s32 fd, s64 off)
{
	s32 spage    = -1; /* Starting page. */
	int is_fixed = ((lin_flgs & MAP_FIXED) == MAP_FIXED);
	int slot;
	u32 size;
	u32 vm_base;

	if (npages > AMNT_FILE_PAGES)
		return -1;

	/* Find a free page. */
	spage = find_memory(vm_addr, npages, MMAP_FILE_ADDR, MMAP_FILE_SIZE,
		mmap_file_map, is_fixed);
	if (spage < 0) {
		unix_set_errno(AIX_ENOMEM);
		return -1;
	}

	size    = npages * PAGE_SIZE;
	vm_base = MMAP_FILE_ADDR + (spage * PAGE_SIZE);

	/* Find a vague slot to map a file. */
	for (slot = 0; slot < MAX_MMAP_FILES; slot++)
		if (mmap_files[slot].status == PAGE_FREE)
			break;

	if (slot == MAX_MMAP_FILES) {
		unix_set_errno(AIX_EMFILE); /* Too many files opened. */
		return -1;
	}

	mmap_files[slot].host_base = mmap(0, size, prot, lin_flgs, fd, off);
	if (mmap_files[slot].host_base == MAP_FAILED) {
		unix_set_errno(AIX_ENOMEM);
		return -1;
	}

	/* If found, set them as used. */
	memset(mmap_file_map+spage, PAGE_USED, npages);

	mm_alloc_region(
		vm_base,
		size,
		mmap_files[slot].host_base,
		UC_PROT_READ|UC_PROT_WRITE,
		"file/shmem");

	mmap_files[slot].fd      = fd;
	mmap_files[slot].prot    = prot;
	mmap_files[slot].status  = PAGE_USED;
	mmap_files[slot].vm_base = vm_base;
	mmap_files[slot].size    = size;
	return vm_base;
}

/**
 * @brief Main entry point for mmap.
 *
 * @param uc   Unicorn context.
 * @param addr Page-aligned address to be mapped, if any.
 * @param len  Mapping length (in bytes, not page-aligned).
 * @param prot Protection flags of the new mapping.
 * @param flgs Mapping flags.
 * @param fd   File descriptor, if applicable, -1 otherwise.
 * @param off  File offset, if applicable, 0 otherwise.
 *
 * @return Returns the address of the allocated memory on success, -1 otherwise.
 * (errno set).
 */
int aix_do_mmap(uc_engine *uc, u32 addr, u32 len, u32 prot, u32 flgs,
	s32 fd, s64 off)
{
	int ret;
	u32	pages;
	int lin_flgs;

	ret = -1;
	if (!len) {
		unix_set_errno(AIX_EINVAL);
		goto out;
	}

	/* Convert flags. */
	lin_flgs = 0;
	if (flgs & AIX_MAP_SHARED)    lin_flgs |= MAP_SHARED;
	if (flgs & AIX_MAP_PRIVATE)   lin_flgs |= MAP_PRIVATE;
	if (flgs & AIX_MAP_ANONYMOUS) lin_flgs |= MAP_ANONYMOUS;
	if (flgs & AIX_MAP_FIXED)     lin_flgs |= MAP_FIXED;

	pages = ALIGN_UP(len) >> PAGE_SHIFT;

	/* Non-file backed. */
	if (flgs & AIX_MAP_ANONYMOUS) {
		/* Shared anonymous mapping requires the *host* memory to be shared
		 * too, which we currently do not do, as we keep it as a single
		 * giant block. However, we can reuse the file-mapping, since
		 * the file mapping makes a new mmap(2) call (on host/Linux) for
		 * each new mmap(2) AIX call, and this allows us to make shared
		 * memory this way, hacky ?
		 */
		if (flgs & AIX_MAP_SHARED)
			ret = mmap_file(addr, lin_flgs, pages, prot, -1, 0);
		else
			ret = mmap_anon(addr, lin_flgs, pages, prot);
	}

	/* File mapping. */
	else if (fd >= 0)
		ret = mmap_file(addr, lin_flgs, pages, prot, fd, off);

	/* Anything else, error. */
	else {
		unix_set_errno(AIX_EINVAL);
		goto out;
	}
out:
	return ret;
}

/**
 * @brief 64-bit mmap(2) AIX syscall handler.
 *
 * AIX calling convention:
 *   r3 = address
 *   r4 = length
 *   r5 = protection/access permissions (PROT_READ/W/E/NONE)
 *   r6 = flags
 *   r7 = file descriptor (if any)
 *   r8 = offset (high word)
 *   r9 = offset (low word)
 *
 * Return value (in r3):
 *   Returns the mapped address, -1 otherwise (with errno set).
 */
int aix_kmmap(uc_engine *uc)
{
	int ret;
	u32 addr = read_1st_arg();
	u32 len  = read_2nd_arg();
	u32 prot = read_3rd_arg();
	u32 flgs = read_4th_arg();
	s32 fd   = read_5th_arg();
	s64 off  = (((s64)read_6th_arg()) << 32) | read_7th_arg();
	ret = aix_do_mmap(uc, addr, len, prot, flgs, fd, off);
	TRACE("kmmap", "0x%x, %d, 0x%x, 0x%x, %d, %ld", addr, len, prot, flgs, fd,
		off);
	return ret;
}

/**
 * @brief 32-bit mmap(2) AIX syscall handler.
 *
 * AIX calling convention:
 *   r3 = address
 *   r4 = length
 *   r5 = protection/access permissions (PROT_READ/W/E/NONE)
 *   r6 = flags
 *   r7 = file descriptor (if any)
 *   r8 = offset
 *
 * Return value (in r3):
 *   Returns the mapped address, -1 otherwise (with errno set).
 */
int aix_mmap(uc_engine *uc)
{
	int ret;
	u32 addr = read_1st_arg();
	u32 len  = read_2nd_arg();
	u32 prot = read_3rd_arg();
	u32 flgs = read_4th_arg();
	s32 fd   = read_5th_arg();
	s32 off  = read_6th_arg();
	ret = aix_do_mmap(uc, addr, len, prot, flgs, fd, off);
	TRACE("mmap", "0x%x, %d, 0x%x, 0x%x, %d, %d", addr, len, prot, flgs, fd,
		off);
	return ret;
}

/**
 * @brief Main entrypoint for munmap.
 *
 * @param addr Page-aligned address to be munmapped.
 * @param size Memory size to be munmapped.
 *
 * @return Returns 0 on success, -1 on error (errno set).
 */
int aix_do_munmap(u32 addr, u32 size)
{
	int ret  = -1;
	u32 spage; /* Initial page, 0-based. */
	u32 npage; /* Numebr of pages.       */
	int is_file;
	int is_anon;
	u32 vm_base;
	u32 i;

	/* Null addresses. */
	if (!addr || !size) {
		unix_set_errno(AIX_EINVAL);
		goto out;
	}

	is_file = is_valid_mmap_addr(addr, size, MMAP_FILE_ADDR, MMAP_FILE_SIZE);
	is_anon = is_valid_mmap_addr(addr, size, MMAP_ANON_ADDR, MMAP_ANON_SIZE);

	if (!is_file && !is_anon) {
		unix_set_errno(AIX_EINVAL);
		goto out;
	}

	vm_base = is_anon ? MMAP_ANON_ADDR : MMAP_FILE_ADDR;
	spage   = (addr - vm_base) >> PAGE_SHIFT;
	npage   = ALIGN_UP(size) >> PAGE_SHIFT;

	if (is_anon) {
		memset(mmap_page_map+spage, PAGE_FREE, npage);
		if (mprotect(mmap_base+(spage*PAGE_SIZE), npage*PAGE_SIZE, PROT_NONE) < 0)
			errx(1, "Unable to PROT_NONE to page#%d via munmap!\n", spage);
	}

	/* File. */
	else {
		for (i = 0; i < MAX_MMAP_FILES; i++) {
			if (mmap_files[i].vm_base == addr && mmap_files[i].size == size)
				break;
		}
		if (i == MAX_MMAP_FILES) {
			unix_set_errno(AIX_EINVAL);
			goto out;
		}
		if (mm_dealloc_region(addr, MM_DEALLOC_MUNMAP) < 0) {
			unix_set_errno(AIX_EINVAL);
			goto out;
		}
		memset(mmap_file_map+spage, PAGE_FREE, npage);
		mmap_files[i].fd        = 0;
		mmap_files[i].prot      = 0;
		mmap_files[i].status    = PAGE_FREE;
		mmap_files[i].host_base = NULL;
		mmap_files[i].vm_base   = 0;
		mmap_files[i].size      = 0;
	}
	ret = 0;
out:
	return ret;
}

/**
 * @brief munmap(2) AIX syscall handler.
 *
 * AIX calling convention:
 *   r3 = address
 *   r4 = size
 *
 * Return value (in r3):
 *   On success, returns 0, -1 otherwise (with errno set).
 *
 * @note Munmapping of file descriptors do not behave identical to POSIX:
 * contrary to the standards, its not possible to partially munmap a previous
 * allocated region, only the entire file.
 *
 * Since this (I expect) is a very edge case, I'm not implementing this.
 */
int aix_munmap(uc_engine *uc)
{
	int ret;
	u32 addr = read_1st_arg();
	u32 size = read_2nd_arg();
	ret = aix_do_munmap(addr, size);
	TRACE("munmap", "%x, %u", addr, size);
	return ret;
}
