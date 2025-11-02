/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025
 */

#include <stdio.h>
#include <string.h>
#include <unicorn/unicorn.h>

#include "gdb.h"
#include "loader.h"
#include "mm.h"

/**
 * AIX seems to have a kernel memory-mapped are in user-space
 * to handle syscalls, we're basically doing the same, but instead
 * of doing useful...
 *
 *
 * Insns: blr + nop
 */
#define SYSCALL_ADDR 0x3700
#define SYSCALL_HANDLER \
	"\x4e\x80\x00\x20" \
	"\x60\x00\x00\x00"

/* AIX 7.2 TL04 SP02 syscall numbers.  */
#define SYS_write 10
#define SYS_exit  149



/* XCOFF file info. */
static struct loaded_coff lcoff;;

/* Unicorn vars. */
uc_engine *uc;

/**
 * @brief Init the VM memory layout for the executable pointed
 * at @p xcoff.
 *
 * @param xcoff XCOFF32 structure pointer.
 *
 * @return Returns 0 if succcess, -1 otherwise.
 */
static void vm_init_syscalls(void)
{
	/* Syscall/"kernel" entry point. */
	uc_mem_map(uc, 0x3000, 4096, UC_PROT_ALL);
	if (uc_mem_write(uc, SYSCALL_ADDR, SYSCALL_HANDLER, sizeof(SYSCALL_HANDLER)-1))
		errx(1, "Unable to write the syscall handler!\n");
}

/**
 * @brief Init our VM registers.
 *
 * @param xcoff XCOFF32 structure pointer.
 *
 * For the moment, only stack pointer and TOC.
 */
static int vm_init_registers(struct loaded_coff *lcoff)
{
	int r;

	/* Stack in r1. */
	r = STACK_ADDR;
	uc_reg_write(uc, UC_PPC_REG_1, &r);

	/* TOC Anchor in r2. */
	r = lcoff->xcoff.aux.o_toc;
	uc_reg_write(uc, UC_PPC_REG_2, &r);

	return 0;
}

/**
 * @brief Dump all registers for our VM pointed by @uc.
 *
 * @param uc Unicorn Engine pointer.
 */
static void dump_registers(uc_engine *uc)
{
	void *ptr_vals[32] = {0};
	int vals[32]       = {0};
	int regs[32];
	int i;

	for (i = 0; i < 32; i++) {
		regs[i] = i+2; /* UC_PPC_REG_0 starts at 2 on 'enum uc_ppc_reg'. */
		vals[i] = i+2;
		ptr_vals[i] = &vals[i];
	}

	if (uc_reg_read_batch(uc, regs, ptr_vals, 32) < 0) {
		warn("Unable to read GPRs...\n");
		return;
	}

	printf("  Register dump:\n");
	for (i = 0; i < 32; i += 4) {
		printf(
			"    r%02d: 0x%08x "
			"    r%02d: 0x%08x "
			"    r%02d: 0x%08x "
			"    r%02d: 0x%08x\n",
			i+0, vals[i+0],
			i+1, vals[i+1],
			i+2, vals[i+2],
			i+3, vals[i+3]
		);
	}
}

/**
 * @brief Write syscall handler (10).
 *
 * @param uc          Unicorn Engine pointer.
 * @param gpr_values  All GPRs values (0-31).
 *
 * Arguments in:
 *  r3 = fd, r4 = buffer, r5 = count
 *  Return value = r3
 *
 * @return Returns 0 if syscall could be handled (even if there
 * where errors), -1 if the syscall could not be called at all.
 */
int do_sys_write(uc_engine *uc, int *gpr_vals)
{
	char *buff;
	int ret;

	if (!gpr_vals[5]) {
		gpr_vals[3] = 0;
		warn("Invalid count size!\n");
		return -1;
	}

	buff = malloc(gpr_vals[5]);
	if (!buff) {
		warn("VM OOM!\n");
		return -1;
	}

	if (uc_mem_read(uc, gpr_vals[4], buff, gpr_vals[5])) {
		warn("Unable to read from VM memory: %x\n", gpr_vals[4]);
		free(buff);
		return -1;
	}

	gpr_vals[3] = write(gpr_vals[3], buff, gpr_vals[5]);
	free(buff);
	return 0;
}

/**
 * @brief _exit syscall handler (149).
 *
 * @param uc          Unicorn Engine pointer.
 * @param gpr_values  All GPRs values (0-31).
 *
 * Arguments in:
 *  r3 = exit code
 */
int do_sys_exit(uc_engine *uc, int *gpr_vals)
{
	((void)uc);
	_exit(gpr_vals[3]);
}

/**
 * @brief My attempt to make a generic syscall handler/dispatcher.
 *
 * @param uc   Unicorn Engine pointer.
 * @param addr Address which our handler was triggered.
 * @param size Instruction size.
 * @param user_data Optional user data.
 */ 
static void syscall_handler(uc_engine *uc, uint64_t addr, uint32_t size,
	void *user_data)
{
	void *ptr_vals[32] = {0};
	int vals[32]       = {0};
	int regs[32];
	int ret;
	int i;

	for (i = 0; i < 32; i++) {
		regs[i] = i+2;
		vals[i] = i+2;
		ptr_vals[i] = &vals[i];
	}
	if (uc_reg_read_batch(uc, regs, ptr_vals, 32) < 0) {
		warn("Unable to read GPRs...\n");
		return;
	}

	printf(">>> Syscall at 0x%" PRIx64", SYS_nr: %d\n", addr, vals[2]);

	switch (vals[2]) {
		/* Args: r3 = fd, r4 = buffer, r5 = count. */
		case SYS_write:
			ret = do_sys_write(uc, vals);
			break;
		case SYS_exit:
			ret = do_sys_exit(uc, vals);
			break;
		default:
			warn("Unknown syscall number: %d!, ignoring...\n", vals[2]);
	}

}




/* Main =). */
int main(int argc, char **argv)
{
	u32 entry_point;
	uc_hook trace;
	uc_err err;
	int ret;

	/* Initialize our AIX+PPC emulator =). */
	err = uc_open(UC_ARCH_PPC, UC_MODE_PPC32|UC_MODE_BIG_ENDIAN, &uc);
	if (err)
		errx(1, "Unable to create VM: %s\n", uc_strerror(err));

	mm_init(uc);
	vm_init_syscalls();
	vm_init_registers(&lcoff);

	/* Load executable. */
	lcoff = load_xcoff_file(uc, "clean", 1, &ret);
	if (ret < 0)
		return -1;

	/* Our 'syscall' handler. */
	uc_hook_add(uc, &trace, UC_HOOK_CODE, syscall_handler, NULL,
		SYSCALL_ADDR, SYSCALL_ADDR);

	/* Init GDB stub. */
	if (gdb_init(uc, 1234) < 0)
		errx(1, "Unable to start GDB server!\n");

	entry_point = xcoff_get_entrypoint(&lcoff.xcoff);
	err = uc_emu_start(uc, entry_point, entry_point+1024, 0, 0);
	if (err)
		errx(1, "Unable to start VM, error: %s\n", uc_strerror(err));
}
