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
#include "syscalls.h"
#include "mm.h"
#include "util.h"

static uc_hook syscall_trace;

#define SYSCALL_ADDR 0x3700
#define MAX_SYSCALLS 1024

/**
 * Our 'syscall handler' is just a stub, since the one that will actually
 * handles it is VM's handler.
 * Insns: blr + nop
 */
#define SYSCALL_HDLR \
	"\x4e\x80\x00\x20" \
	"\x60\x00\x00\x00"

#define SYS(...) \
 do { \
   fprintf(stderr, "[syscalls] " __VA_ARGS__); \
 } while (0)

static uc_engine *g_uc;
static u32 next_desc_addr;
static int next_syscall_idx;

static struct unix_syscalls {
	const char *sym_name;  /* Symbol/syscall name.         */
	u32 desc_addr;        /* Function descriptor address. */
} unix_syscalls[MAX_SYSCALLS];

/**
 *
 */
u32 create_unix_descriptor(const char *sym_name)
{
	int i;
	int idx;
	u32 desc[3];

	/*
	 * Check if symbol already added, in order to avoid duplicated function
	 * descriptors.
	 */
	for (i = 0; i < next_syscall_idx; i++) {
		if (strcmp(sym_name, unix_syscalls[i].sym_name))
			continue;

		SYS("Reusing /unix descriptor '%s': desc=0x%x, index=%d\n",
		    sym_name, unix_syscalls[i].desc_addr, i);
		return unix_syscalls[i].desc_addr;
	}

	/* Do not exist, create a new symbol. */
	if (next_syscall_idx >= MAX_SYSCALLS)
		errx(1, "Too many /unix syscalls! Increase MAX_UNIX_SYSCALLS\n");

	idx = next_syscall_idx++;
	desc[0] = SYSCALL_ADDR;
	desc[1] = idx;
	desc[2] = idx;

	/* Write descriptor into memory. */
	if (uc_mem_write(g_uc, next_desc_addr, desc, sizeof desc))
		errx(1, "Failed to write /unix descriptor for %s\n", sym_name);

	unix_syscalls[idx].sym_name  = sym_name;
	unix_syscalls[idx].desc_addr = next_desc_addr;
	next_desc_addr += 12;

	SYS("Created /unix descriptor for '%s': desc=0x%x, index=%d\n", sym_name,
		unix_syscalls[idx].desc_addr, idx);

	return unix_syscalls[idx].desc_addr;
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

/* AIX 7.2 TL04 SP02 syscall numbers.  */
#define SYS_write 10
#define SYS_exit  149

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

/**
 *
 */
void syscalls_init(uc_engine *uc)
{
	next_syscall_idx = 0;
	next_desc_addr   = UNIX_DESC_ADDR;

	if (!uc)
		errx(1, "Invalid uc_engine ptr!\n");
	g_uc = uc;

	/* Allocate/map room for the Unix function descriptors. */
	if (uc_mem_map(g_uc, UNIX_DESC_ADDR, UNIX_DESC_SIZE,
		           UC_PROT_READ|UC_PROT_WRITE)) {
		errx(1, "Unable to map memory to /unix function descriptors!\n");
	}

	/* Syscall/"kernel" entry point. */
	uc_mem_map(uc, 0x3000, 4096, UC_PROT_ALL);
	if (uc_mem_write(uc, SYSCALL_ADDR, SYSCALL_HDLR, sizeof(SYSCALL_HDLR)-1))
		errx(1, "Unable to write the syscall handler!\n");

	/* Our 'syscall' handler. */
	uc_hook_add(g_uc, &syscall_trace, UC_HOOK_CODE, syscall_handler, NULL,
		SYSCALL_ADDR, SYSCALL_ADDR);
}
