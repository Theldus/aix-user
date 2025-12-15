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
#include "unix.h"
#include "insn_emu.h"

/* XCOFF file info. */
static struct loaded_coff *lcoff;;

/* Unicorn vars. */
uc_engine *uc;

/* Main =). */
int main(int argc, const char **argv, const char **envp)
{
	u32 entry_point;
	uc_hook trace;
	uc_err err;

	/* Initialize our AIX+PPC emulator =). */
	err = uc_open(UC_ARCH_PPC, UC_MODE_PPC32|UC_MODE_BIG_ENDIAN, &uc);
	if (err)
		errx(1, "Unable to create VM: %s\n", uc_strerror(err));

	mm_init(uc);
	mm_init_stack(argc, argv, envp);
	unix_init(uc);
	insn_emu_init(uc);

	/* Load executable. */
	lcoff = load_xcoff_file(uc, "printf", NULL, 1);
	if (!lcoff)
		return -1;

	/* Init GDB stub. */
	if (gdb_init(uc, 1234) < 0)
		errx(1, "Unable to start GDB server!\n");

	entry_point = xcoff_get_entrypoint(&lcoff->xcoff);
	err = uc_emu_start(uc, entry_point, (1ULL<<48), 0, 0);
	if (err) {
		printf("FAILED with error: %s\n", uc_strerror(err));
		if (err == UC_ERR_EXCEPTION) {
			printf("  -> Exception occurred\n");
			register_dump(uc);
		}
		return 1;
	}
	return 0;
}
