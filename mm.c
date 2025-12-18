/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025
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

/* Memory Management. */
static uc_engine *g_uc = NULL;
static u32 next_text_base = TEXT_START + EXEC_TEXT_SIZE;
static u32 next_data_base = DATA_START + EXEC_DATA_SIZE;

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
 * @brief Zero-initialize .bss section.
 *
 * @param bss_addr .bss runtime address.
 * @param bss_size .bss size.
 */
static void write_zero_bss(u32 bss_addr, u32 bss_size)
{
	char *bss;
	if (!bss_size)
		return;
	bss = calloc(1, bss_size);
	if (!bss)
		errx(1, "Unable to allocate memory for .bss!\n");
	if (uc_mem_write(g_uc, bss_addr, bss, bss_size))
		errx(1, "Unable to write to .bss section at 0x%x!\n", bss_addr);
	free(bss);
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
	u32 bss_runtime, u32 bss_size,
	u32 text_delta, u32 data_delta, u32 bss_delta,
	struct loaded_coff *lcoff)
{
	u32 end;

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

	/* Map .text region. */
	if (uc_mem_map(g_uc, text_runtime, text_map_size, UC_PROT_ALL))
		errx(1, "Unable to map .text at 0x%x!\n", text_runtime);

	/* Map .data+.bss region. */
	if (uc_mem_map(g_uc, data_runtime, data_map_size, UC_PROT_ALL))
		errx(1, "Unable to map .data+.bss at 0x%x!\n", data_runtime);

	/* Zero-initialize .bss. */
	write_zero_bss(bss_runtime, bss_size);

	/* Fill loaded_coff structure. */
	lcoff->text_start = text_runtime;
	lcoff->data_start = data_runtime;
	lcoff->bss_start  = bss_runtime;

	lcoff->deltas[TEXT_DELTA] = text_delta;
	lcoff->deltas[DATA_DELTA] = data_delta;
	lcoff->deltas[BSS_DELTA]  = bss_delta;
}

/**
 * @brief Allocate memory for main executable.
 * Accepts XCOFF-suggested addresses (no relocation).
 *
 * @param text_vaddr .text virtual address from XCOFF.
 * @param text_size  .text size.
 * @param data_vaddr .data virtual address from XCOFF.
 * @param data_size  .data size.
 * @param bss_vaddr  .bss virtual address from XCOFF.
 * @param bss_size   .bss size.
 * @param lcoff      Loaded COFF structure to fill.
 */
void mm_alloc_main_exec_memory(
	u32 text_vaddr, u32 text_size,
	u32 data_vaddr, u32 data_size,
	u32 bss_vaddr,  u32 bss_size,
	struct loaded_coff *lcoff)
{
	/* Validate .text is in expected range (0x1000... range). */
	if (text_vaddr < TEXT_START)
		errx(1, "Main exec .text at 0x%x below TEXT_START!\n", text_vaddr);
	if (text_vaddr >= TEXT_START + EXEC_TEXT_SIZE)
		errx(1, "Main exec .text at 0x%x outside range!\n", text_vaddr);

	/* Validate .data and .bss layout. */
	validate_data_bss_layout(data_vaddr, data_size, bss_vaddr, bss_size);

	/* Validate .data/.bss are in expected range (0x2000... range). */
	if (data_vaddr < DATA_START)
		errx(1, "Main exec .data at 0x%x below DATA_START!\n", data_vaddr);
	if (data_vaddr >= DATA_START + EXEC_DATA_SIZE)
		errx(1, "Main exec .data at 0x%x outside range!\n", data_vaddr);

	/* Allocate using generic function (map full 16MiB regions). */
	mm_alloc_memory(
		TEXT_START, EXEC_TEXT_SIZE, TEXT_END,
		DATA_START, EXEC_DATA_SIZE, DATA_END,
		bss_vaddr, bss_size,
		0, 0, 0, lcoff);  /* All deltas are 0 for main executable */
}

/**
 * @brief Allocate memory for library.
 * Uses bump allocator and calculates base_delta for relocation.
 *
 * @param text_vaddr .text virtual address from XCOFF file.
 * @param text_size  .text size.
 * @param data_vaddr .data virtual address from XCOFF file.
 * @param data_size  .data size.
 * @param bss_vaddr  .bss virtual address from XCOFF file.
 * @param bss_size   .bss size.
 * @param lcoff      Loaded COFF structure to fill.
 * @return 0 on success, -1 on error.
 */
int mm_alloc_library_memory(
	u32 text_vaddr, u32 text_size,
	u32 data_vaddr, u32 data_size,
	u32 bss_vaddr,  u32 bss_size,
	struct loaded_coff *lcoff)
{
	u32 text_runtime, data_runtime, bss_runtime;
	u32 text_delta, data_delta, bss_delta;
	u32 tsize, dsize;
	u32 data_end;

	/* Validate .data and .bss layout. */
	validate_data_bss_layout(data_vaddr, data_size, bss_vaddr, bss_size);

	/* Calculate aligned sizes. */
	tsize = ALIGN_UP(text_size);
	if (tsize < text_size)
		errx(1, "Library .text size overflow after alignment!\n");

	if (safe_add_u32(bss_vaddr, bss_size, &data_end))
		errx(1, "Library .bss causes address overflow!\n");

	dsize = data_end - data_vaddr;
	dsize = ALIGN_UP(dsize);
	if (dsize < (data_end - data_vaddr))
		errx(1, "Library .data+.bss size overflow after alignment!\n");

	/* Get runtime addresses from bump allocator. */
	text_runtime = next_text_base;
	data_runtime = next_data_base;

	/* Calculate separate deltas for each section. */
	text_delta = text_runtime - text_vaddr;
	data_delta = data_runtime - data_vaddr;

	/* Calculate runtime .bss address (preserve offset from .data). */
	bss_runtime = bss_vaddr + data_delta;
	bss_delta = bss_runtime - bss_vaddr;

	/* Allocate using generic function. */
	mm_alloc_memory(
		text_runtime, tsize, TEXT_END,
		data_runtime, dsize, DATA_END,
		bss_runtime, bss_size,
		text_delta, data_delta, bss_delta, lcoff);

	/* Update bump allocators. */
	next_text_base += tsize;
	next_data_base += dsize;

	return 0;
}

/**
 * @brief Write .text section to allocated memory.
 * Uses runtime addresses from lcoff->text_start.
 *
 * @param lcoff  Loaded COFF structure with runtime addresses.
 * @param is_exe Signals if should use the section address or the allocated
 *               address.
 */
void mm_write_text(struct loaded_coff *lcoff, int is_exe)
{
	struct xcoff_sec_hdr32 *text_sec;
	struct xcoff_aux_hdr32 *aux;
	const void *text_buff;
	u32 vaddr;

	aux = &lcoff->xcoff.aux;
	if (aux->o_sntext == 0 || aux->o_sntext > lcoff->xcoff.hdr.f_nscns)
		errx(1, "Invalid .text section number!\n");

	text_sec  = &lcoff->xcoff.secs[aux->o_sntext - 1];
	text_buff = lcoff->xcoff.buff + text_sec->s_scnptr;
	vaddr     = (is_exe ? text_sec->s_vaddr : lcoff->text_start);

	if (uc_mem_write(g_uc, vaddr, text_buff, aux->o_tsize))
		errx(1, "Failed to write .text at 0x%x!\n", vaddr);
}

/**
 * @brief Write .data section to allocated memory.
 * Uses runtime addresses from lcoff->data_start.
 *
 * @param lcoff  Loaded COFF structure with runtime addresses.
 * @param is_exe Signals if should use the section address or the allocated
 *               address.
 */
void mm_write_data(struct loaded_coff *lcoff, int is_exe)
{
	struct xcoff_sec_hdr32 *data_sec;
	struct xcoff_aux_hdr32 *aux;
	const void *data_buff;
	u32 vaddr;

	aux = &lcoff->xcoff.aux;
	if (aux->o_sndata == 0 || aux->o_sndata > lcoff->xcoff.hdr.f_nscns)
		errx(1, "Invalid .data section number!\n");

	data_sec  = &lcoff->xcoff.secs[aux->o_sndata - 1];
	data_buff = lcoff->xcoff.buff + data_sec->s_scnptr;
	vaddr     = (is_exe ? data_sec->s_vaddr : lcoff->data_start);

	if (uc_mem_write(g_uc, vaddr, data_buff, aux->o_dsize))
		errx(1, "Failed to write .data at 0x%x!\n", vaddr);
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
	u32 v = 0;
	if (uc_mem_read(g_uc, vaddr, &v, sizeof v)) {
		warn("Unable to read a u32 from %x!\n", vaddr);
		*err = -1;
	}
	return htonl(v);
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
	value = htonl(value);
	if (uc_mem_write(g_uc, vaddr, &value, sizeof value)) {
		warn("Unable to write %x into %x!\n", value, vaddr);
		return -1;
	}
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
	size_t len = strlen(src) + 1;
	if (uc_mem_write(g_uc, dst, src, len))
		errx(1, "Unable to copy string (%s) into VM: %x!\n", src, dst);
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

	/* Stack. */
	if (uc_mem_map(g_uc, STACK_ADDR-STACK_SIZE, STACK_SIZE, UC_PROT_ALL))
		errx(1, "Unable to setup stack!\n");

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
