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

/**
 * AIX syscall entry point address.
 * This is the well-known address where all syscalls are dispatched from.
 */
#define SYSCALL_ADDR 0x3700

/**
 * Maximum number of syscalls that can be registered.
 * Each /unix symbol import creates an entry in the syscall table.
 */
#define MAX_SYSCALLS 1024

/**
 * Syscall handler stub code.
 * This is a simple PowerPC code sequence that returns immediately:
 *   blr (Branch to Link Register) - returns to caller
 *   nop (No Operation)            - alignment padding
 *
 * The actual syscall handling is done by our Unicorn hook,
 * not by executing this code.
 */
#define SYSCALL_HDLR \
	"\x4e\x80\x00\x20" /* blr */ \
	"\x60\x00\x00\x00" /* nop */

/**
 * Debug logging macro for syscall subsystem.
 * Currently always enabled; will be disabled in release builds.
 */
#define SYS(...) \
	do { \
		fprintf(stderr, "[syscalls] " __VA_ARGS__); \
	} while (0)

/**
 * Syscall implementation function pointer type.
 * All syscall handlers must match this signature.
 *
 * @return Return value to be placed in r3 (or -1 on error).
 */
typedef int (*syscall_fn)(void);

/**
 * Unix syscall descriptor entry.
 * Each imported /unix symbol gets an entry here, mapping symbol names
 * to function descriptors and syscall implementations.
 */
struct unix_syscall_entry {
	const char *sym_name;  /* Symbol name (e.g., "kwrite", "_exit").     */
	int sys_table_idx;     /* Index in sys_table[] (-1 if unimplemented).*/
	u32 desc_addr;         /* VM address of function descriptor.         */
};

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

/**
 * Syscall implementation table entry.
 * Maps syscall names to their implementation functions.
 */
struct sys_table_entry {
	const char *name;   /* Syscall name.                    */
	syscall_fn handler; /* Implementation function pointer. */
};

/* Unicorn engine instance (initialized in syscalls_init). */
static uc_engine *g_uc = NULL;

/* Next available address for /unix function descriptors. */
static u32 next_desc_addr;

/* Number of registered syscalls. */
static int next_syscall_idx;

/* Unicorn hook handle for syscall interception. */
static uc_hook syscall_trace;

/* Array of all registered /unix syscalls. */
static struct unix_syscall_entry unix_syscalls[MAX_SYSCALLS];

/* errno and _environ. */
u32 vm_errno;
u32 vm_environ;

/* ========================================================================== */
/*           Syscall Handler Declarations + Implementation Table              */
/* ========================================================================== */

static int do_kwrite(void);
static int do__exit(void);

/**
 * Table mapping syscall names to their implementations.
 * When a /unix symbol is imported, we search this table to find
 * the corresponding implementation.
 */
static struct sys_table_entry sys_table[] = {
	{"kwrite", do_kwrite},
	{"_exit",  do__exit},
};

/* ========================================================================== */
/*                                   Helpers                                  */
/* ========================================================================== */

/**
 * @brief Read a PowerPC General Purpose Register.
 *
 * @param gpr Register number (0-31).
 * @return Value of the register.
 */
static u32 read_gpr(u32 gpr)
{
	uc_err err;
	u32 value;
	if (gpr > 31)
		errx(1, "read_gpr: invalid GPR %d (must be 0-31)\n", gpr);
	err = uc_reg_read(g_uc, UC_PPC_REG_0 + gpr, &value);
	if (err)
		errx(1, "Failed to read GPR %d: %s\n", gpr, uc_strerror(err));
	return value;
}

/**
 * @brief Write a PowerPC General Purpose Register.
 *
 * @param gpr Register number (0-31).
 * @param val Value to write.
 */
static void write_gpr(u32 gpr, u32 val)
{
	uc_err err;
	if (gpr > 31)
		errx(1, "write_gpr: invalid GPR %d (must be 0-31)\n", gpr);
	err = uc_reg_write(g_uc, UC_PPC_REG_0 + gpr, &val);
	if (err)
		errx(1, "Failed to write GPR %d: %s\n", gpr, uc_strerror(err));
}

/**
 * @brief Write syscall return value.
 *
 * By PowerPC ABI convention, syscall return values are placed in r3.
 *
 * @param val Return value to write.
 */
static void write_ret_value(u32 val) {
	write_gpr(3, val);
}

/**
 * @brief Create or reuse a /unix function descriptor for a symbol.
 *
 * This function creates synthetic function descriptors for /unix symbols
 * instead of loading the actual /unix kernel image. Each descriptor points
 * to our syscall dispatcher at 0x3700.
 *
 * Function descriptor format (3 words):
 *   [0] = Function address (always SYSCALL_ADDR = 0x3700)
 *   [1] = TOC anchor (we use this to store the syscall index)
 *   [2] = Environment pointer (same as [1])
 *
 * When libc calls through this descriptor, it will:
 *   1. Load 0x3700 into CTR
 *   2. Load the syscall index into r2
 *   3. Branch to 0x3700
 *   4. Our Unicorn hook intercepts execution at 0x3700
 *   5. We read r2 to determine which syscall was invoked
 *
 * @param sym_name Symbol name (e.g., "kwrite", "_exit").
 * @return VM address of the function descriptor.
 */
static u32 create_unix_descriptor(const char *sym_name)
{
	int i;
	int idx;
	u32 desc[3];
	size_t table_size;

	/*
	 * Check if this symbol already has a descriptor to avoid duplicates.
	 */
	for (i = 0; i < next_syscall_idx; i++) {
		if (strcmp(sym_name, unix_syscalls[i].sym_name) == 0) {
			SYS("Reusing /unix descriptor '%s': desc=0x%x, index=%d\n",
			    sym_name, unix_syscalls[i].desc_addr, i);
			return unix_syscalls[i].desc_addr;
		}
	}

	/* Symbol doesn't exist yet, create a new descriptor. */
	if (next_syscall_idx >= MAX_SYSCALLS)
		errx(1, "Too many /unix syscalls! Increase MAX_SYSCALLS\n");

	idx = next_syscall_idx++;

	/*
	 * Build the function descriptor.
	 * Note: Values are stored in big-endian (AIX PowerPC is big-endian).
	 */
	desc[0] = htonl(SYSCALL_ADDR);  /* Entry point: 0x3700            */
	desc[1] = htonl(idx);           /* TOC/syscall index              */
	desc[2] = desc[1];              /* Environment (same as TOC)      */

	/* Write descriptor to VM memory. */
	if (uc_mem_write(g_uc, next_desc_addr, desc, sizeof(desc)))
		errx(1, "Failed to write /unix descriptor for '%s'\n", sym_name);

	/* Register the new syscall. */
	unix_syscalls[idx].sym_name      = sym_name;
	unix_syscalls[idx].desc_addr     = next_desc_addr;
	unix_syscalls[idx].sys_table_idx = -1;
	next_desc_addr += 12; /* Each descriptor is 12 bytes (3 words) */

	SYS("Created /unix descriptor for '%s': desc=0x%x, index=%d\n",
	    sym_name, unix_syscalls[idx].desc_addr, idx);

	/* Check if we have an implementation for this syscall. */
	table_size = sizeof(sys_table) / sizeof(sys_table[0]);
	for (i = 0; i < (int)table_size; i++) {
		if (strcmp(sym_name, sys_table[i].name) == 0) {
			unix_syscalls[idx].sys_table_idx = i;
			SYS("Symbol/syscall '%s' found in sys_table!\n", sym_name);
			break;
		}
	}

	return unix_syscalls[idx].desc_addr;
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
		return create_unix_descriptor(sym_name);

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
				SYS("Reusing /unix data '%s': data=0x%x, index=%d\n",
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

		SYS("Creating /unix data for '%s', data=0x%x\n", sym_name, ret);
		return ret;
	}

	else {
		SYS(">> WARNING <<: Class (%d) for symbol (%s) not supported yet!\n",
			cur_sym->l_smclass, sym_name);
		return 1; /* Return a generic value. */
	}
}

/* ========================================================================== */
/*                         Syscall Implementations                            */
/* ========================================================================== */

/**
 * @brief kwrite syscall handler.
 *
 * Handles the AIX kwrite syscall, which writes data to a file descriptor.
 * This is essentially the same as POSIX write(2).
 *
 * AIX calling convention:
 *   r3 = fd    (file descriptor)
 *   r4 = buf   (VM address of buffer)
 *   r5 = count (number of bytes to write)
 *
 * Return value (in r3):
 *   Number of bytes written on success, -1 on error.
 *
 * @return Number of bytes written, or -1 on error.
 */
static int do_kwrite(void)
{
	int ret;
	char *h_buff;
	u32 vm_fd    = read_gpr(3);
	u32 vm_buff  = read_gpr(4);
	u32 vm_count = read_gpr(5);

	/* Handle zero-length writes. */
	if (vm_count == 0)
		return 0;

	/* Allocate host buffer to copy VM memory. */
	h_buff = malloc(vm_count);
	if (!h_buff)
		errx(1, "Host OOM: failed to allocate %u bytes\n", vm_count);

	/* Copy data from VM memory to host buffer. */
	if (uc_mem_read(g_uc, vm_buff, h_buff, vm_count)) {
		warn("kwrite: failed to read from VM address 0x%x\n", vm_buff);
		free(h_buff);
		return -1;
	}

	/* Perform the actual write on the host. */
	ret = write(vm_fd, h_buff, vm_count);
	free(h_buff);

	return ret;
}

/**
 * @brief _exit syscall handler.
 *
 * Handles the AIX _exit syscall, which terminates the process immediately
 * without cleanup. This is the same as POSIX _exit(2).
 *
 * AIX calling convention:
 *   r3 = status (exit code)
 *
 * This function does not return.
 *
 * @return Never returns (calls _exit).
 */
static int do__exit(void)
{
	u32 exit_code = read_gpr(3);
	_exit(exit_code);
	/* NOTREACHED */
}

/* ========================================================================== */
/*                           Syscall Dispatcher                               */
/* ========================================================================== */

/**
 * @brief Generic syscall handler/dispatcher.
 *
 * This function is called by Unicorn whenever execution reaches 0x3700
 * (SYSCALL_ADDR). It reads the syscall number from r2, looks up the
 * corresponding handler, and dispatches to it.
 *
 * The syscall number in r2 is actually an index into our unix_syscalls[]
 * array, which was set up when we created the function descriptor.
 *
 * @param uc        Unicorn engine instance.
 * @param addr      Address where the hook was triggered (always 0x3700).
 * @param size      Instruction size (unused).
 * @param user_data Optional user data (unused).
 */
static void syscall_handler(uc_engine *uc, uint64_t addr, uint32_t size,
	void *user_data)
{
	struct unix_syscall_entry *sys;
	u32 sys_nr;
	int ret;

	(void)uc;
	(void)size;
	(void)user_data;

	sys_nr = read_gpr(2);

	/* Validate syscall number. */
	if (sys_nr >= (u32)next_syscall_idx) {
		warn(">>>> INVALID SYSCALL NUMBER: %d <<<<\n", sys_nr);
		write_ret_value((u32)-1);
		return;
	}

	sys = &unix_syscalls[sys_nr];
	SYS("Syscall at 0x%" PRIx64 ", nr=%d, name='%s'\n",
	    addr, sys_nr, sys->sym_name);

	/* Check if we have an implementation for this syscall. */
	if (sys->sys_table_idx < 0) {
		warn(">>> UNIMPLEMENTED SYSCALL: '%s' <<<\n", sys->sym_name);
		write_ret_value((u32)-1);
		return;
	}

	/* Dispatch to the handler and write return value. */
	ret = sys_table[sys->sys_table_idx].handler();
	write_ret_value(ret);
}

/* ========================================================================== */
/*                            Initialization                                  */
/* ========================================================================== */

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
void syscalls_init(uc_engine *uc)
{
	uc_err err;

	if (!uc)
		errx(1, "syscalls_init: NULL uc_engine pointer\n");

	/* Initialize global state. */
	g_uc = uc;
	next_syscall_idx = 0;
	next_desc_addr   = UNIX_DESC_ADDR;
	next_data_idx    = 0;
	next_data_addr   = UNIX_DATA_ADDR;

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

	/* Map the syscall entry point page. */
	err = uc_mem_map(uc, 0x3000, 4096, UC_PROT_ALL);
	if (err)
		errx(1, "Failed to map syscall entry page: %s\n",
		     uc_strerror(err));

	/* Write the syscall stub code at 0x3700. */
	err = uc_mem_write(uc, SYSCALL_ADDR, SYSCALL_HDLR,
	                   sizeof(SYSCALL_HDLR) - 1);
	if (err)
		errx(1, "Failed to write syscall handler: %s\n",
		     uc_strerror(err));

	/* Install Unicorn hook to intercept syscalls. */
	err = uc_hook_add(g_uc, &syscall_trace, UC_HOOK_CODE,
	                  syscall_handler, NULL, SYSCALL_ADDR, SYSCALL_ADDR);
	if (err)
		errx(1, "Failed to install syscall hook: %s\n",
		     uc_strerror(err));
}
