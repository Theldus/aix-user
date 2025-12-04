/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025
 */

#ifndef MM_H
#define MM_H

#include <unicorn/unicorn.h>
#include "util.h"

/* Memory Management. */
#define PAGE_SIZE 4096
#define PAGE_SHIFT  12
#define ALIGN_UP(x) (((x) + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1))

#define EXEC_TEXT_SIZE  0x1000000  /* 16 MiB. */
#define EXEC_DATA_SIZE  0x1000000  /* 16 MiB. */
#define TEXT_SIZE 0x10000000 /* 256 MiB. */
#define DATA_SIZE 0x10000000 /* 256 MiB. */

/* Miscellaneous export symbols (.data mapped). */
#define UNIX_DATA_ADDR 0x100000 /* Starts at 1MiB. */
#define UNIX_DATA_SIZE 0x100000 /* 1MiB.           */

/* Milicode addresses. */
#define UNIX_MILI_ADDR 0xD000
#define UNIX_MILI_SIZE 0x3000 /* 3x 4KiB pages. */

/* XCOFF executable addresses range. */
#define TEXT_START 0x10000000
#define TEXT_END   (TEXT_START + TEXT_SIZE)
#define DATA_START 0x20000000
#define DATA_END   (DATA_START + DATA_SIZE)

/* Stack. */
#define STACK_ADDR 0x30000000
#define STACK_SIZE (32ULL*1024*1024)  /* bytes. */

/* Unix function descriptors. */
#define UNIX_DESC_ADDR 0x0F000000  /* Descriptor heap */
#define UNIX_DESC_SIZE 0x00100000  /* 1MB for descriptors */

/* Forward declarations. */
struct loaded_coff;

/* Initialize memory manager with Unicorn instance. */
void mm_init(uc_engine *uc);

/* Allocate memory for main executable. */
void mm_alloc_main_exec_memory(
	u32 text_vaddr, u32 text_size,
	u32 data_vaddr, u32 data_size,
	u32 bss_vaddr,  u32 bss_size,
	struct loaded_coff *lcoff);

/* Allocate memory for library. */
int mm_alloc_library_memory(
	u32 text_vaddr, u32 text_size,
	u32 data_vaddr, u32 data_size,
	u32 bss_vaddr,  u32 bss_size,
	struct loaded_coff *lcoff);

/* Write .text section to allocated memory. */
void mm_write_text(struct loaded_coff *lcoff, int is_exe);

/* Write .data section to allocated memory. */
void mm_write_data(struct loaded_coff *lcoff, int is_exe);

/* Read/write an u32 value for/to a given address. */
u32 mm_read_u32(u32 vaddr, int *err);
int mm_write_u32(u32 vaddr, u32 value);

/* Initialize stack with proper values for argc,argv and envp. */
void mm_init_stack(int argc, const char **argv, const char **envp);


#endif /* MM_H. */
