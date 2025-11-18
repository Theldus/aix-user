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
#include "mm.h"
#include "util.h"

static uc_hook syscall_trace;
typedef int (*syscall_fn)(void);


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
	int sys_table_idx;     /* Index on syscall table.      */
	u32 desc_addr;         /* Function descriptor address. */
} unix_syscalls[MAX_SYSCALLS];

/* Syscall table. */
int do_kwrite(void);
int do__exit(void);

static struct sys_table {
	const char *name;
	syscall_fn sys;
} sys_table[] = {
	{"kwrite", do_kwrite},
	{"_exit",  do__exit},
};

/**
 *
 */
static u32 read_gpr(u32 gpr) {
	uc_err err;
	u32 value;
	if (gpr > 31)
		errx(1, "read_gpr: invalid GPR, aborting...!\n");
	gpr += UC_PPC_REG_0;
	err  = uc_reg_read(g_uc, gpr, &value);
	if (err)
		errx(1, "Unable to read PPC GPR n=%d!\n",gpr);
	return value;
}

/**
 *
 */
static void write_gpr(u32 gpr, u32 val) {
	uc_err err;
	if (gpr > 31)
		errx(1, "write_gpr: invalid GPR, aborting...!\n");
	gpr += UC_PPC_REG_0;
	err  = uc_reg_write(g_uc, gpr, &val);
	if (err)
		errx(1, "Unable to write PPC GPR n=%d, val=%d!\n", gpr, val);
}

/**
 *
 */
static void write_ret_value(u32 val) {write_gpr(3, val);}

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
	desc[0] = htonl(SYSCALL_ADDR);
	desc[1] = htonl(idx);
	desc[2] = desc[1];

	/* Write descriptor into memory. */
	if (uc_mem_write(g_uc, next_desc_addr, desc, sizeof desc))
		errx(1, "Failed to write /unix descriptor for %s\n", sym_name);

	unix_syscalls[idx].sym_name      = sym_name;
	unix_syscalls[idx].desc_addr     = next_desc_addr;
	unix_syscalls[idx].sys_table_idx = -1;
	next_desc_addr += 12;

	SYS("Created /unix descriptor for '%s': desc=0x%x, index=%d\n", sym_name,
		unix_syscalls[idx].desc_addr, idx);

	/* Look at the sys_table and see if this symbol/syscall is implemented. */
	for (i = 0; i < sizeof(sys_table)/sizeof(sys_table[0]); i++) {
		if (strcmp(sym_name, sys_table[i].name))
			continue;
		unix_syscalls[idx].sys_table_idx = i;
		SYS("Symbol/syscall (%s) found on sys_table!\n", sym_name);
	}

	return unix_syscalls[idx].desc_addr;
}

/**
 * @brief Write syscall handler.
 *
 * Arguments in:
 *  r3 = fd, r4 = buffer, r5 = count
 *  Return value = r3
 *
 * @return Returns 0 if syscall could be handled (even if there
 * where errors), -1 if the syscall could not be called at all.
 */
int do_kwrite(void)
{
	int ret;
	char *h_buff;
	u32 vm_fd    = read_gpr(3);
	u32 vm_buff  = read_gpr(4);
	u32 vm_count = read_gpr(5);

	/* Invalid size. */
	if (!vm_count)
		return 0;

	if (!(h_buff = malloc(vm_count)))
		errx(1, "VM OOM\n");

	if (uc_mem_read(g_uc, vm_buff, h_buff, vm_count)) {
		warn("Unable to read from VM memory: 0x%x\n", vm_buff);
		return -1;
	}

	ret = write(vm_fd, h_buff, vm_count);
	free(h_buff);
	return ret;
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
int do__exit(void) {
	_exit(read_gpr(3));
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
	struct unix_syscalls *sys;
	u32 sys_nr = read_gpr(2);
	int ret;

	if (sys_nr >= next_syscall_idx) {
		warn(">>>> INVALID SYSCALL TRIGGERED, sysnr: %d <<<<\n", sys_nr);
		write_ret_value(-1);
		return;
	}

	sys = &unix_syscalls[sys_nr];
	SYS("Syscall at 0x%" PRIx64", SYS_nr: %d, func: (%s)\n",
		addr, sys_nr, sys->sym_name);

	if (sys->sys_table_idx < 0) {
		warn(">>> UNIMPLEMENTED SYSCALL !!! (%s) <<<\n", sys->sym_name);
		write_ret_value(-1);
		return;
	}

	ret = sys_table[sys->sys_table_idx].sys();
	write_ret_value(ret);
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
