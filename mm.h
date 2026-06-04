/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025
 */

#ifndef MM_H
#define MM_H

#include <unicorn/unicorn.h>
#include "util.h"

struct mm_region {
	const char *description;
	u8 *host_base;
	u32 vm_base;
	u32 prot;
	u32 size;
};

/* Memory Management. */
#define PAGE_SIZE 4096
#define PAGE_SHIFT  12
#define PAGE_MASK   (~(PAGE_SIZE - 1))
#define ALIGN_UP(x) (((x) + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1))

#define EXEC_TEXT_SIZE  0x1000000  /* 16 MiB. */
#define EXEC_DATA_SIZE  0x1000000  /* 16 MiB. */
#define TEXT_SIZE 0x10000000 /* 256 MiB. */
#define DATA_SIZE 0x10000000 /* 256 MiB. */

/* Miscellaneous export symbols (.data mapped).
 * Note: AIX 7.3 re-exports much more /unix symbols than 7.2.
 * This might happen later for newer versions too.
 */
#define UNIX_DATA_ADDR 0x100000 /* Starts at 1MiB. */
#define UNIX_DATA_SIZE 0x200000 /* 2MiB.           */

/* Special data structures on kernel. */
#define UNIX_SYSTEM_CONFIG    0x34e0
#define UNIX_SYSTEM_TB_CONFIG 0x3600

/* Milicode addresses. */
#define UNIX_MILI_ADDR 0xD000
#define UNIX_MILI_SIZE 0x5000 /* 5x 4KiB pages. */

/* XCOFF executable addresses range. */
#define TEXT_START 0x10000000
#define TEXT_END   (TEXT_START + TEXT_SIZE)
#define DATA_START 0x20000000
#define DATA_END   (DATA_START + DATA_SIZE)

/* Stack. */
#define STACK_ADDR 0x30000000
#define STACK_SIZE (32ULL*1024*1024)  /* bytes. */

/* Dynamic memory: (s)brk/mmap/... */
#define HEAP_ADDR 0x40000000 /* Starts at 1GiB. */ 
#define HEAP_SIZE 0x40000000 /* 1GiB.           */
#define MMAP_ANON_ADDR 0x80000000 /* Starts at 2GiB. */
#define MMAP_ANON_SIZE 0x40000000 /* 1GiB.           */
#define MMAP_FILE_ADDR 0xC0000000 /* Starts at 3GiB. */
#define MMAP_FILE_SIZE 0x40000000 /* 1GiB.           */

/* Unix function descriptors. */
#define UNIX_DESC_ADDR 0x0F000000  /* Descriptor heap */
#define UNIX_DESC_SIZE 0x00100000  /* 1MB for descriptors */

/* Forward declarations. */
struct loaded_coff;
extern char *heap_host;
extern char *curr_heap;

/* Initialize memory manager with Unicorn instance. */
void mm_init(uc_engine *uc);

/* Allocate memory for a COFF object (executable or library). */
void mm_alloc_coff_memory(
	u32 text_vaddr, u32 text_size,
	u32 data_vaddr, u32 data_size,
	u32 bss_vaddr,  u32 bss_size,
	struct loaded_coff *lcoff, int is_exe);

/* Read/write an u32 value for/to a given address. */
u32 mm_read_u32(u32 vaddr, int *err);
int mm_write_u32(u32 vaddr, u32 value);

/* Initialize stack with proper values for argc,argv and envp. */
void mm_init_stack(int argc, const char **argv, const char **envp);

/* Returns the host-equivalent address for a given Unicorn
 * memory address. */
void *mm_vm2host(u32 vaddr);

/* Gets the current mapped region ofr the VM address. */
struct mm_region *mm_find_region(u32 vaddr);

/* Allocates a new region for the VM. */
void mm_alloc_region(u32 vm_base, u32 size, void *host_base, u32 prot,
	const char *desc);

/* Deallocate an existing region. */
#define MM_DEALLOC_NONE   0
#define MM_DEALLOC_FREE   1
#define MM_DEALLOC_MUNMAP 2
int mm_dealloc_region(u32 vaddr, int dealloc_type);

#endif /* MM_H. */
