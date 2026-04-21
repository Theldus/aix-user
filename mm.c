/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025-2026
 */

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "mm.h"
#include "util.h"
#include "loader.h"
#include "unix.h"

/**
 * Debug logging macro for the memory subsystem.
 */
#define MM(...) \
	do { \
		if (args.trace_memory) \
		  fprintf(stderr, "[mm] " __VA_ARGS__); \
	} while (0)

/* Memory Management. */
static uc_engine *g_uc = NULL;
static u32 next_text_base = TEXT_START + EXEC_TEXT_SIZE;
static u32 next_data_base = DATA_START + EXEC_DATA_SIZE;

/**
 * heap_host = Base address for the heap (on host)
 * curr_heap = Current address for the heap (on host)
 */
char *heap_host;
char *curr_heap;

/* Mmap external. */
extern void aix_mmap_init(void);

/* Region definition structure
 *
 * Each 'portion' of memory will be allocated as a 'region', this way,
 * aix-user can easily track all the memory layout and relationship
 * between the host/vm memory.
 */
#define MM_REGIONS 64
static struct mm_region regions [MM_REGIONS];

/**
 * @brief For a given VM address, returns the mapped region for that
 * address.
 *
 * @param vaddr Target address to search.
 *
 * @return If success, returns the region found, NULL otherwise.
 */
struct mm_region *mm_find_region(u32 vaddr) {
	struct mm_region *r;
	int i;
	for (i = 0; i < MM_REGIONS; i++) {
		r = &regions[i];
		if (vaddr >= r->vm_base && (vaddr - r->vm_base) < r->size)
			return r;
	}
	return NULL;
}

/**
 * @brief For a given Unicorn's address, returns the equivalent host address.
 * @param vaddr Unicorn memory address.
 * @return Host equivalent address.
 */
void *mm_vm2host(u32 vaddr) {
	const struct mm_region *r = mm_find_region(vaddr);
	if (!r)
		return NULL;
	return r->host_base + (vaddr - r->vm_base);
}

/**
 * @brief Given a Unicorn's memory permission, map into rwx.
 * @param prot Unicorn's permission.
 * @return Returns a string containing rwx, depending in the permission
 *         level provided.
 */
static const char *format_perms(u32 prot) {
	static char buff[4];
	memcpy(buff, "---", 3);
	if (prot & UC_PROT_READ)  buff[0] = 'r';
	if (prot & UC_PROT_WRITE) buff[1] = 'w';
	if (prot & UC_PROT_EXEC)  buff[2] = 'x';
	return buff;	
}

/**
 * @brief Formats a 4-byte unsigned size into KiB/MiB/GiB string.
 * @param size Size to be formatted.
 * @return Returns a string with the formatted size.
 */
static const char *format_size(u32 size) {
	static char str[16] = {0};
	if (size < 1024*1024)
		snprintf(str, sizeof str, "%3u KiB", size/1024);
	else if (size < 1024*1024*1024ULL)
		snprintf(str, sizeof str, "%3u MiB", size/(1024*1024));
	else
		snprintf(str, sizeof str, "%3llu GiB", size/(1024*1024*1024ULL));
	return str;
}

/**
 * @brief Allocates a memory region in the VM accordingly with the provided
 * parameters.
 * @param vm_base   Base address that will be mapped into the VM.
 * @param size      Region size to be mapped.
 * @param host_base Host backing memory to be mapped into the VM. If NULL, a
 *                  new memory will be allocated.
 * @param prot      Unicorn's permission level. If 0, the region wont be mapped
 *                  into Unicorn.
 * @param desc      String description of the to-be mapped memory region.
 */
void mm_alloc_region(u32 vm_base, u32 size, void *host_base, u32 prot,
	const char *desc)
{
	int region_idx;
	uc_err err;

	for (region_idx = 0; region_idx < MM_REGIONS; region_idx++)
		if (!regions[region_idx].size)
			break;

	if (region_idx >= MM_REGIONS)
		errx(1, "Unable to allocate region: %x/%d!\n", vm_base, size);
	if (!size)
		errx(1, "Invalid size for a region!\n");

	if (!host_base) {
		host_base = calloc(1, size);
		if (!host_base)
			errx(1, "Unable to allocate memory for region, size: %u\n", size);
	}

	regions[region_idx].vm_base     = vm_base;
	regions[region_idx].size        = size;
	regions[region_idx].prot        = prot;
	regions[region_idx].host_base   = host_base;
	regions[region_idx].description = desc;

	MM("Map: 0x%08x 0x%016" PRIxPTR" %s %s (%s)\n",
		vm_base, (uintptr_t)host_base, format_size(size), format_perms(prot),
		desc);

	/* If prot == UC_PROT_NONE (0): register in table only, don't map into
	 * Unicorn yet (used for heap: sbrk maps on first call). */
	if (prot) {
		err = uc_mem_map_ptr(g_uc, vm_base, size, prot, (void*)host_base);
		if (err)
			errx(1, "Unable to map_ptr region: reason: (%s)\n",
				uc_strerror(err));
	}
}

/**
 * @brief Deallocates a given region specified by the virtual address @p vaddr.
 *
 * @param vaddr        VM base address of the region to be deallocated.
 * @param dealloc_type Deallocation type: 0 for no-deallocation, 1 for free(),
 *                     2 for munmap.
 * @return Returns 0 if success, -1 otherwise.
 */
int mm_dealloc_region(u32 vaddr, int dealloc_type)
{
	struct mm_region *r = mm_find_region(vaddr);
	if (!r)
		return -1;

	uc_mem_unmap(g_uc, r->vm_base, r->size);
	if (dealloc_type) {
		if (dealloc_type == MM_DEALLOC_FREE)
			free(r->host_base);
		else if (dealloc_type == MM_DEALLOC_MUNMAP)
			munmap(r->host_base, r->size);
	}

	r->vm_base = 0;
	r->size    = 0;
	r->prot    = 0;
	r->host_base = NULL;
	r->description = NULL;
	return 0;
}

/**
 * @brief Allocates a section region (.text or .data/.bss).
 *
 * @param lcoff     Loaded COFF structure with parsed XCOFF data.
 * @param sec_num   Section number (1-based, from aux header).
 * @param vaddr     Runtime virtual address for this section.
 * @param end_vaddr End virtual address (e.g., vaddr+tsize or vbss+bsize).
 * @param copy_size Number of bytes to copy from the XCOFF file.
 * @param bump      Pointer to the bump allocator to update.
 * @param desc      Region description for debugging.
 */
static void mm_alloc_section_region(struct loaded_coff *lcoff,
	u16 sec_num, u32 vaddr, u32 end_vaddr, u32 copy_size,
	u32 *bump, u32 prot, const char *desc)
{
	struct xcoff_sec_hdr32 *sec;
	const void *sec_buff;
	void *new_buff;
	u32 aligned;
	u32 end;
	u32 size;

	if (sec_num == 0 || sec_num > lcoff->xcoff.hdr.f_nscns)
		errx(1, "Invalid %s section number!\n", desc);

	sec      = &lcoff->xcoff.secs[sec_num - 1];
	sec_buff = lcoff->xcoff.buff + sec->s_scnptr;

	aligned  = vaddr & ~(PAGE_SIZE - 1);
	end      = ALIGN_UP(end_vaddr);
	size     = end - aligned;
	new_buff = calloc(1, size);
	if (!new_buff)
		errx(1, "Unable to allocate memory for %s region!\n", desc);

	memcpy(new_buff + (vaddr - aligned), sec_buff, copy_size);
	mm_alloc_region(aligned, size, new_buff, prot, desc);
	*bump += size;
}

/**
 * @brief Copy file headers in the space between the text region base address
 * and the beginning of the .text section.
 *
 * AIX needs to inspect the XCOFF headers as part of the setup for
 * the ctors/dtors routines, and thus, we need to also copy to
 * memory the executable headers right before the .text region.
 *
 * @param lcoff Loaded COFF structure with parsed XCOFF data.
 *
 * @return Returns 0 if success, -1 otherwise.
 */
static int mm_copy_headers(const struct loaded_coff *lcoff)
{
	const struct mm_region *r;
	u32 gap;

	r = mm_find_region(lcoff->text_start);
	if (!r)
		errx(1, "Unable to find region for address: %x\n", lcoff->text_start);

	gap = lcoff->text_start - r->vm_base;
	if (!gap) {
		warn("Gap not found for address %x, execution might have issues...\n",
			lcoff->text_start);
		return -1;
	}
	memcpy(r->host_base, lcoff->xcoff.buff, gap);
	return 0;
}

/**
 * @brief AIX specs the presence of the .loader section right after the
 * .text section, so this function finds and copies this region into
 * the right place.
 *
 * @param lcoff Loaded COFF structure with parsed XCOFF data.
 *
 * @return Always 0.
 */
static int mm_copy_loader(const struct loaded_coff *lcoff)
{
	const struct xcoff_sec_hdr32 *sec_loader;
	const struct mm_region *r;

	r = mm_find_region(lcoff->text_start);
	if (!r)
		errx(1, "Unable to find region for address: %x\n", lcoff->text_start);

	sec_loader = &lcoff->xcoff.secs[lcoff->xcoff.aux.o_snloader-1];
	memcpy(
		r->host_base      + sec_loader->s_scnptr,
		lcoff->xcoff.buff + sec_loader->s_scnptr,
		sec_loader->s_size);
	return 0;
}

/**
 * @brief Initialize the VM's heap memory with the addresses
 * and size previously configured.
 *
 * @return Always 0.
 */
static int mm_init_heap(void)
{
	/* -------------- SBRK/BRK heap addresses. -------------- */
	heap_host = mmap(NULL, HEAP_SIZE, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if (heap_host == MAP_FAILED)
		errx(1, "Unable to allocate sbrk/brk memory, aborting...\n");
	curr_heap = heap_host;

	/*
	 * Register in region table but don't map into Unicorn yet:
	 * sbrk will map the used portion on first call.
	 */
	mm_alloc_region(HEAP_ADDR, HEAP_SIZE, heap_host, UC_PROT_NONE, "sbrk (heap)");

	/* -------------- MMAP heap addresses. -------------- */
	aix_mmap_init();
	return 0;
}

/**
 * @brief Initializes the VM memory region.
 */
static void mm_regions_init(void)
{
	/* Kernel regions (< 256MiB): 1:1 mapping with AIX 7.2 TL04 SP2.
	 * I could map all the interval between 0-256MiB, but doing so I'd
	 * skip all possible invalid read, since the memory is already mapped.
	 */
	mm_alloc_region(0,      4096, NULL,
		UC_PROT_READ, "page 0");
	mm_alloc_region(0x3000, 4096, NULL,
		UC_PROT_READ|UC_PROT_EXEC, "syscall");
	mm_alloc_region(UNIX_MILI_ADDR, UNIX_MILI_SIZE, NULL,
		UC_PROT_READ|UC_PROT_EXEC, "milicode");

	/* /unix data (not 1:1 with the kernel). */
	mm_alloc_region(UNIX_DESC_ADDR, UNIX_DESC_SIZE, NULL,
		UC_PROT_READ, "unix desc");
	mm_alloc_region(UNIX_DATA_ADDR, UNIX_DATA_SIZE, NULL,
		UC_PROT_READ, "unix data");

	/* User regions. */
	mm_alloc_region(STACK_ADDR-STACK_SIZE, STACK_SIZE, NULL,
		UC_PROT_READ|UC_PROT_WRITE, "stack");

	/* Heap region. */
	mm_init_heap();
}

/**
 * @brief Safe addition with overflow checking.
 *
 * @param a      First operand.
 * @param b      Second operand.
 * @param result Pointer to store result.
 * @return 0 on success, -1 on overflow.
 */
static int safe_add_u32(u32 a, u32 b, u32 *result)
{
	if (a > UINT32_MAX - b)
		return -1;
	*result = a + b;
	return 0;
}

/**
 * @brief Validate .data and .bss layout.
 *
 * @param data_vaddr .data virtual address.
 * @param data_size  .data size.
 * @param bss_vaddr  .bss virtual address.
 * @param bss_size   .bss size.
 */
static void validate_data_bss_layout(u32 data_vaddr, u32 data_size,
	u32 bss_vaddr, u32 bss_size)
{
	u32 data_end;
	if (bss_vaddr < data_vaddr)
		errx(1, ".bss starts before .data!\n");
	if (safe_add_u32(data_vaddr, data_size, &data_end))
		errx(1, ".data section causes address overflow!\n");
	if (bss_vaddr < data_end)
		errx(1, ".bss overlaps with .data!\n");
}

/**
 * @brief Generic memory allocation function.
 * Validates, maps, and finalizes memory regions.
 *
 * @param text_runtime  Runtime .text base address.
 * @param text_map_size Size to map for .text (page-aligned).
 * @param text_limit    Upper limit for .text region.
 * @param data_runtime  Runtime .data base address.
 * @param data_map_size Size to map for .data+.bss (page-aligned).
 * @param data_limit    Upper limit for .data region.
 * @param bss_runtime   Runtime .bss base address.
 * @param bss_size      Size of .bss section.
 * @param text_delta    .text relocation offset (0 for main exec).
 * @param data_delta    .data relocation offset (0 for main exec).
 * @param bss_delta     .bss relocation offset (0 for main exec).
 * @param lcoff         Loaded COFF structure to fill.
 */
static void mm_alloc_memory(
	u32 text_runtime, u32 text_map_size, u32 text_limit,
	u32 data_runtime, u32 data_map_size, u32 data_limit,
	u32 bss_runtime,  u32 bss_size,
	u32 text_delta,   u32 data_delta, u32 bss_delta,
	struct loaded_coff *lcoff, int is_exe)
{
	u32 end;
	struct xcoff_aux_hdr32 *aux = &lcoff->xcoff.aux;

	/* Validate .text region fits within limit. */
	if (safe_add_u32(text_runtime, text_map_size, &end))
		errx(1, "Text region causes overflow!\n");
	if (end > text_limit)
		errx(1, "Text region exceeds limit (0x%x > 0x%x)!\n",
			end, text_limit);

	/* Validate .data region fits within limit. */
	if (safe_add_u32(data_runtime, data_map_size, &end))
		errx(1, "Data region causes overflow!\n");
	if (end > data_limit)
		errx(1, "Data region exceeds limit (0x%x > 0x%x)!\n",
			end, data_limit);

	/* Fill loaded_coff structure. */
	lcoff->text_start = text_runtime;
	lcoff->data_start = data_runtime;
	lcoff->bss_start  = bss_runtime;

	lcoff->deltas[TEXT_DELTA] = text_delta;
	lcoff->deltas[DATA_DELTA] = data_delta;
	lcoff->deltas[BSS_DELTA]  = bss_delta;

	/* Alloc .text and .data/.bss regions. */
	mm_alloc_section_region(lcoff,
		aux->o_sntext,
		lcoff->text_start,
		(lcoff->text_start & ~(PAGE_SIZE - 1)) + text_map_size,
		aux->o_tsize,
		&next_text_base,
		UC_PROT_READ|UC_PROT_EXEC, ".text");

	mm_alloc_section_region(lcoff,
		aux->o_sndata,
		lcoff->data_start,
		lcoff->bss_start + aux->o_bsize,
		aux->o_dsize,
		&next_data_base,
		UC_PROT_READ|UC_PROT_WRITE, ".data/.bss");

	mm_copy_headers(lcoff);
	mm_copy_loader(lcoff);
}

/**
 * @brief Allocate memory for a XCOFF object (executable or library).
 *
 * For executables: uses XCOFF-suggested addresses directly (no relocation).
 * For libraries:   uses bump allocator and computes relocation deltas.
 *
 * @param text_vaddr .text virtual address from XCOFF.
 * @param text_size  .text size.
 * @param data_vaddr .data virtual address from XCOFF.
 * @param data_size  .data size.
 * @param bss_vaddr  .bss virtual address from XCOFF.
 * @param bss_size   .bss size.
 * @param lcoff      Loaded XCOFF structure to fill.
 * @param is_exe     1 for main executable, 0 for library.
 */
void mm_alloc_coff_memory(
	u32 text_vaddr, u32 text_size,
	u32 data_vaddr, u32 data_size,
	u32 bss_vaddr,  u32 bss_size,
	struct loaded_coff *lcoff, int is_exe)
{
	struct xcoff_sec_hdr32 *sec_loader, *sec_text;
	u32 text_runtime, data_runtime, bss_runtime;
	u32 text_delta, data_delta, bss_delta;
	u32 tsize, dsize;
	u32 data_end;
	int i;

	/* Validate .data and .bss layout. */
	validate_data_bss_layout(data_vaddr, data_size, bss_vaddr, bss_size);

	/*
	 * Validate .loader section: .loader must be always *after* the
	 * .text section, so we can blindly use the loader start+size
	 * in order to have the text region size.
	 */
	sec_loader = &lcoff->xcoff.secs[lcoff->xcoff.aux.o_snloader-1];
	sec_text   = &lcoff->xcoff.secs[lcoff->xcoff.aux.o_sntext-1];
	tsize      = sec_loader->s_scnptr + sec_loader->s_size;

	if (sec_loader->s_scnptr < sec_text->s_scnptr+sec_text->s_size)
		errx(1, ".loader *must not* start before .text!!\n");

	if (is_exe) {
		/* Validate .text is in expected range. */
		if (text_vaddr < TEXT_START)
			errx(1, ".text at 0x%x below TEXT_START!\n", text_vaddr);
		if (text_vaddr >= TEXT_START + EXEC_TEXT_SIZE)
			errx(1, ".text at 0x%x outside range!\n",    text_vaddr);

		/* Validate .data/.bss are in expected range. */
		if (data_vaddr < DATA_START)
			errx(1, ".data at 0x%x below DATA_START!\n", data_vaddr);
		if (data_vaddr >= DATA_START + EXEC_DATA_SIZE)
			errx(1, ".data at 0x%x outside range!\n",    data_vaddr);

		/* No relocation needed. */
		text_runtime = text_vaddr;
		data_runtime = data_vaddr;
		bss_runtime  = bss_vaddr;
		dsize        = data_size;
		text_delta   = data_delta = bss_delta = 0;

	} else {
		/* Calculate aligned sizes. */
		if (safe_add_u32(bss_vaddr, bss_size, &data_end))
			errx(1, ".bss causes address overflow!\n");

		dsize = data_end - data_vaddr;
		dsize = ALIGN_UP(dsize);
		if (dsize < (data_end - data_vaddr))
			errx(1, ".data+.bss size overflow!\n");

		/*
		 * Get runtime addresses from bump allocator.
		 * We're adding '+ s_scnptr' here so the start address points to
		 * the .text start, instead of the memory region, this give us
		 * a room to copy the binary header in that gap.
		 *
		 * The 'text_vaddr' provided by the exec alresdy have this gap, so
		 * thats why i'm only adding this here.
		 */
		text_runtime = next_text_base + sec_text->s_scnptr;
		data_runtime = next_data_base;

		/* Calculate separate deltas for each section. */
		text_delta = text_runtime - text_vaddr;
		data_delta = data_runtime - data_vaddr;

		/* Runtime .bss: preserve offset from .data. */
		bss_runtime = bss_vaddr   + data_delta;
		bss_delta   = bss_runtime - bss_vaddr;
	}

	mm_alloc_memory(
		text_runtime, tsize,  TEXT_END,
		data_runtime, dsize,  DATA_END,
		bss_runtime,  bss_size,
		text_delta, data_delta, bss_delta, lcoff, is_exe);
}

/**
 * @brief Read a 32-bit value from guest memory (big-endian).
 *
 * Reads a 32-bit value from the specified virtual address in guest memory
 * and converts it from big-endian (PowerPC) to host byte order.
 *
 * @param vaddr Virtual address to read from.
 * @param err   Pointer to error flag (set to -1 on failure).
 * @return The 32-bit value in host byte order, or 0 on error.
 */
u32 mm_read_u32(u32 vaddr, int *err)
{
	u32 *h_addr;
	if (!(h_addr = mm_vm2host(vaddr))) {
		*err = -1;
		warn("Unable to find a mapping from %x!\n", vaddr);
		return 0;
	}
	return htonl(*h_addr);
}

/**
 * @brief Write a 32-bit value to guest memory (big-endian).
 *
 * Converts a 32-bit value from host byte order to big-endian (PowerPC)
 * and writes it to the specified virtual address in guest memory.
 *
 * @param vaddr Virtual address to write to.
 * @param value Value to write (in host byte order).
 * @return 0 on success, -1 on error.
 */
int mm_write_u32(u32 vaddr, u32 value)
{
	u32 *h_addr;
	if (!(h_addr = mm_vm2host(vaddr))) {
		warn("Unable to find a mapping from %x!\n", vaddr);
		return -1;
	}
	*h_addr = htonl(value);
	return 0;
}

/**
 * @brief Handle invalid memory access: wheter protection and/or unmapped area.
 * @param uc    Unicorn context.
 * @param type  Failure type.
 * @param addr  Failed to access address.
 * @param size  Memory length.
 * @param value (For writes) value attempted to be written.
 * @param user_data User defined data.
 */
static void
hook_invalid_mem(uc_engine *uc, uc_mem_type type, uint64_t addr, int size,
	int64_t value, void *user_data)
{
	((void)user_data);

	switch (type) {
	case UC_MEM_WRITE_UNMAPPED:
		warn("\n\n>>> INVALID WRITE AT UNMAPPED ADDRESS <<<\n");
		warn("ADDR: 0x%" PRIx64"  VALUE: 0x%" PRIx64"  SIZE: %d\n",
		     addr, value, size);
		break;
	case UC_MEM_READ_UNMAPPED:
		warn("\n\n>>> INVALID READ AT UNMAPPED ADDRESS <<<\n");
		warn("ADDR: 0x%" PRIx64"  SIZE: %d\n",
		     addr, size);
		break;
	case UC_MEM_READ_PROT:
		warn("\n\n>>> INVALID READ AT ADDRESS (MAPPED) <<<\n");
		warn("ADDR: 0x%" PRIx64"  SIZE: %d\n",
		     addr, size);
		break;
	case UC_MEM_WRITE_PROT:
		warn("\n\n>>> INVALID WRITE AT ADDRESS (MAPPED) <<<\n");
		warn("ADDR: 0x%" PRIx64"  VALUE: 0x%" PRIx64"  SIZE: %d\n",
		     addr, value, size);
		break;
	default:
		break;
	}

	register_dump(uc);
}

/**
 * @brief Invalid instruction handler
 * @param uc   Unicorn context.
 * @param data User-defined data.
 *
 * @note Seems that this is not working at all, and I'm receiving
 * an unhandled exception instead, see insn_emu.c
 */
static void hook_invalid_insn(uc_engine *uc, void *data) {
	u32 pc;
	uc_reg_read(uc, UC_PPC_REG_PC, &pc);
	warn("\n\n>>> INVALID INSN <<<\n");
	warn("ADDR: 0x%x\n", pc);
	register_dump(uc);
}

/**
 * @brief Copies a NUL-terminated string from host to guest/VM.
 * @param dst
 * @param src
 * @return Returns a ptr to the end of the string.
 *
 * @note This is not the same signature as 'strcpy', as the returned
 * address is one byte past the dst buffer address.
 */
static u32 mm_strcpy(u32 dst, const char *src)
{
	char *h_dst;
	size_t len = strlen(src) + 1;
	if (!(h_dst = mm_vm2host(dst)))
		errx(1, "Unable to find mapping from %x address!\n", dst);
	memcpy(h_dst, src, len);
	return dst+len;
}

/**
 * @brief Initialize the stack with the proper expected layout for argc,
 * argv and envp variables.
 *
 * @param argc Argument count
 * @param argv Argument list, NULL-terminated
 * @param envp Environment variables list, NULL-terminated
 */
void mm_init_stack(int argc, const char **argv, const char **envp)
{
	const char **p;
	u32 stack_data;  /* Points to the strings itself. */
	u32 stack_ptr;   /* Points to the strings ptrs.   */
	int env_count;
	size_t bytes;
	u32 stack;
	u32 val;
	int i;

	bytes     = 0;
	env_count = 0;
	for (p = argv; *p; bytes += strlen(*p)+1, p++);
	for (p = envp; *p; bytes += strlen(*p)+1, p++, env_count++);
	/* NULL-pointers for argv and envp, + argc and env_count. */
	bytes += (2 + argc + env_count) * 4;

	/*
	 * Calculate starting stack address:
	 * Leave some room at the very top, and then calculate a starting
	 * address to put the first argv.
	 */
	vm_errno   = STACK_ADDR - 4;
	vm_environ = STACK_ADDR - 8;
	stack_ptr  = STACK_ADDR - 12 - 256;

	stack_ptr  -= bytes;
	stack_ptr  &= ~(u32)0xF;  /* Align to 16-byte boundary. */
	stack_data  = stack_ptr + ((argc + 1 + env_count + 1) * 4);
	stack       = stack_ptr;

	/* Copy argv. */
	for (p = argv; *p; p++, stack_ptr += 4) {
		mm_write_u32(stack_ptr, stack_data);
		stack_data = mm_strcpy(stack_data, *p);
	}
	mm_write_u32(stack_ptr, 0);
	stack_ptr += 4;

	/* Copy envp. */
	for (p = envp; *p; p++, stack_ptr += 4) {
		mm_write_u32(stack_ptr, stack_data);
		stack_data = mm_strcpy(stack_data, *p);
	}
	mm_write_u32(stack_ptr, 0);

	/* Registers. */
	uc_reg_write(g_uc, UC_PPC_REG_3, &argc);  /* argc. */
	uc_reg_write(g_uc, UC_PPC_REG_4, &stack); /* argv. */
	val = stack + ((argc + 1) * 4);

	/* envp: addr on r5 and on symbols environ/_environ. */
	uc_reg_write(g_uc, UC_PPC_REG_5, &val);
	mm_write_u32(vm_environ, val);

	/* errno symbol */
	unix_set_errno(0);

	/*
	 * Stack top should start with 16-NULL words (64-bytes) of distance
	 * of the first argv on stack.
	 */
	stack -= 16*4;
	uc_reg_write(g_uc, UC_PPC_REG_1, &stack);
}

/**
 * @brief Initialize memory manager with Unicorn instance.
 *
 * @param uc Unicorn engine instance.
 */
void mm_init(uc_engine *uc)
{
	uc_hook inv_read;
	uc_hook inv_insn;
	uc_err err;

	g_uc = uc;
	next_text_base = TEXT_START + EXEC_TEXT_SIZE;
	next_data_base = DATA_START + EXEC_DATA_SIZE;

	/* Initialize all static regions. */
	mm_regions_init();

	/* Troubleshooting hooks. */
	err = uc_hook_add(g_uc, &inv_read,
		UC_HOOK_MEM_READ_UNMAPPED|
		UC_HOOK_MEM_WRITE_UNMAPPED|
		UC_HOOK_MEM_READ_PROT|
		UC_HOOK_MEM_WRITE_PROT,
		hook_invalid_mem,
		NULL, 0, (1ULL<<32)-1);
	if (err)
		errx(1, "Unable to insert memory hooks hook!\n");

	err = uc_hook_add(g_uc, &inv_insn,
		UC_HOOK_INSN_INVALID, hook_invalid_insn, NULL, 1, 0);
	if (err)
		errx(1, "Unable to insert invalid insn hook!\n");
}
