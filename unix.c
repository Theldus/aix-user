/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025
 */

/*
 * AIX syscalls handlers and /unix handling.
 *
 * A note about /unix:
 *  Despite seemingly being just another library, /unix is actually the AIX
 *  kernel image itself (just like vmlinux on Linux) and this is pretty
 *  interesting in many ways:
 *
 *  - /unix is listed by 'ldd' and even on the XCOFF structures as a library,
 *    one that libc depends on.
 *
 *  - /unix is only directly used by libc
 *
 *  - Despite containing the kernel, some of its symbols are exported to libc,
 *    which includes the syscalls handlers itself. These syscalls are still
 *    issued by a 'sc' (Supervisor Call) (as one would expect for a Power CPU)
 *    but the caller resides inside /unix, instead of being issued directly via
 *    libc.
 *
 *  Since syscalls should be implemented/pollyfilled by me, there is no reason
 *  on loading /unix as this does not even make sense, but all handling of /unix
 *  should still happen somewhere, and this is the file where this will happen.
 */

#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "syscalls.h"
#include "milicode.h"
#include "mm.h"
#include "util.h"
#include "aix_errno.h"

/**
 * Debug logging macro for syscall subsystem.
 * Currently always enabled; will be disabled in release builds.
 */
#define UNIX(...) \
	do { \
		if (args.trace_loader) \
		  fprintf(stderr, "[unix] " __VA_ARGS__); \
	} while (0)

/**
 * Unix symbols data map
 * Each generic imported /unix data have an entry here.
 */
#define UNIX_MAX_DATA (UNIX_DATA_SIZE/4096)
static struct unix_data_entry {
	const char *sym_name;  /* /unix symbol name, e.g., _system_configuration. */
	u32 addr;              /* symbol address.                                 */
} unix_data[UNIX_MAX_DATA] = {0};
static u32 next_data_addr;
static u32 next_data_idx;

/* Unicorn engine instance (initialized in syscalls_init). */
static uc_engine *g_uc = NULL;

/* errno and _environ. */
u32 vm_errno;
u32 vm_environ;

/**
 * @brief Sets the VM's/guest errno.
 * Since many syscalls set the errno to signal the reason for something
 * that have failed, there is a need to update the VMs errno as well.
 *
 * @param err Errno value to be set.
 */
void unix_set_errno(u32 err) {
	mm_write_u32(vm_errno, err);
}

/**
 * @brief Sets a Linux2AIX converted errno to the VM's/guest errno.
 * @param err Errno value to be set.
 */
void unix_set_conv_errno(u32 err) {
	mm_write_u32(vm_errno, errno_linux2aix(err));
}

/**
 * @brief Nicely handle all unix imports.
 *
 * Not all /unix imports are functions, but might be data as well,
 * so there is a need to first ensure which kind of symbol we're
 * importing first.
 *
 * If it is some well-known symbol (such as environ, errno), handle them
 * accordingly.
 *
 * @param cur_sym Symbol to import.
 */
u32 handle_unix_imports(const struct xcoff_ldr_sym_tbl_hdr32 *cur_sym)
{
	u32 ret;
	int i, idx;
	const char *sym_name = cur_sym->u.l_strtblname;

	/*
	 * If normal function or 'syscall'*.
	 * Not all syscall handlers are marked as syscalls, but just a normal
	 * function descriptor.
	 */
	if (cur_sym->l_smclass & (XMC_DS|XMC_SV|XMC_SV3264))
		return syscall_register(sym_name);

	/* Normal data (Unclassified+RW), such as environ, errno... */
	if (cur_sym->l_smclass & (XMC_UA|XMC_RW)) {
		/* CHeck first for some known values. */
		if (!strcmp(sym_name, "errno")   || !strcmp(sym_name, "_errno"))
			return vm_errno;
		if (!strcmp(sym_name, "environ") || !strcmp(sym_name, "_environ"))
			return vm_environ;

		/* Generic symbol, find an spot if not already allocated. */
		for (i = 0; i < next_data_idx; i++) {
			if (strcmp(sym_name, unix_data[i].sym_name) == 0) {
				UNIX("Reusing /unix data '%s': data=0x%x, index=%d\n",
			    	sym_name, unix_data[i].addr, i);
				return unix_data[i].addr;
			}
		}

		/* Symbol doesn't exist yet, create a new mapping. */
		if (next_data_idx >= UNIX_MAX_DATA)
			errx(1, "Too many /unix data symbols! Increase UNIX_MAX_DATA!\n");

		unix_data[next_data_idx].sym_name = sym_name;
		unix_data[next_data_idx].addr     = next_data_addr;
		ret             = next_data_addr;
		next_data_addr += 4096;
		next_data_idx  += 1;

		UNIX("Creating /unix data for '%s', data=0x%x\n", sym_name, ret);
		return ret;
	}

	else {
		UNIX(">> WARNING <<: Class (%d) for symbol (%s) not supported yet!\n",
			cur_sym->l_smclass, sym_name);
		return 1; /* Return a generic value. */
	}
}

/**
 * @brief Initialize the Unicorn's CPU with common/default register values.
 * @param uc Unicorn context.
 */
static void registers_init(uc_engine *uc)
{
	static int regs_to_write[24];
	static void *vals[24];
	u32 reg1, reg2;
	uc_err err;
	int i;

	reg1 = 0xDEADBEEF;
	reg2 = 0x2000; /* Enable 'FP' on MSR. */
	
	/* Set other GPRs the default value: 0xDEADBEEF. */
	regs_to_write[0] = UC_PPC_REG_0;
	for (i = 6; i <= 25; i++)
		regs_to_write[i-5] = UC_PPC_REG_0 + i;
	regs_to_write[21] = UC_PPC_REG_LR;
	regs_to_write[22] = UC_PPC_REG_CTR;
	regs_to_write[23] = UC_PPC_REG_MSR;

	reg1 = 0xDEADBEEF;
	for (i = 0; i < 23; i++)
		vals[i] = &reg1;
	vals[23] = &reg2;

	if ((err = uc_reg_write_batch(uc, regs_to_write, vals, 24)))
		errx(1, "Unable to set default value regs: (%s)\n", uc_strerror(err));
}

/**
 * @brief Initialize the syscall subsystem.
 *
 * This function must be called once during VM initialization, before
 * any libraries are loaded. It:
 *   1. Sets up the global Unicorn engine reference
 *   2. Allocates memory for /unix function descriptors
 *   3. Maps the syscall entry point at 0x3700
 *   4. Installs a Unicorn hook to intercept syscalls
 *
 * @param uc Unicorn engine instance.
 */
void unix_init(uc_engine *uc)
{
	uc_err err;

	if (!uc)
		errx(1, "unix_init: NULL uc_engine pointer\n");

	/* Initialize global state. */
	g_uc = uc;
	next_data_idx  = 0;
	next_data_addr = UNIX_DATA_ADDR;

	/* Allocate memory region for /unix function descriptors. */
	err = uc_mem_map(g_uc, UNIX_DESC_ADDR, UNIX_DESC_SIZE,
	                 UC_PROT_READ | UC_PROT_WRITE);
	if (err)
		errx(1, "Failed to map /unix descriptor region: %s\n",
		     uc_strerror(err));

	/* Allocate memory region for /unix data. */
	err = uc_mem_map(g_uc, UNIX_DATA_ADDR, UNIX_DATA_SIZE,
		             UC_PROT_READ | UC_PROT_WRITE);
	if (err)
		errx(1, "Failed to map /unix data: %s\n", uc_strerror(err));

	/* Initial registers values. */
	registers_init(uc);
	/* Add milicode functions. */
	milicode_init(uc);
	/* Init syscalls. */
	syscalls_init(uc);
}
