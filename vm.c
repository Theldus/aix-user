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
#include "syscalls.h"

/* XCOFF file info. */
static struct loaded_coff *lcoff;;

/* Unicorn vars. */
uc_engine *uc;

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








/* Main =). */
int main(int argc, char **argv)
{
	u32 entry_point;
	uc_hook trace;
	uc_err err;

	/* Initialize our AIX+PPC emulator =). */
	err = uc_open(UC_ARCH_PPC, UC_MODE_PPC32|UC_MODE_BIG_ENDIAN, &uc);
	if (err)
		errx(1, "Unable to create VM: %s\n", uc_strerror(err));

	mm_init(uc);
	syscalls_init(uc);

	/* Load executable. */
	lcoff = load_xcoff_file(uc, "wr_ex", NULL, 1);
	if (!lcoff)
		return -1;

	vm_init_registers(lcoff);

	/* Init GDB stub. */
	if (gdb_init(uc, 1234) < 0)
		errx(1, "Unable to start GDB server!\n");

	entry_point = xcoff_get_entrypoint(&lcoff->xcoff);
	err = uc_emu_start(uc, entry_point, entry_point+1024, 0, 0);
	if (err)
		errx(1, "Unable to start VM, error: %s\n", uc_strerror(err));
}
