/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <unicorn/unicorn.h>

#include "gdb.h"
#include "loader.h"
#include "mm.h"
#include "unix.h"
#include "insn_emu.h"

/* Command-line arguments. */
struct args args = {
	.lib_path      = ".",
	.trace_syscall = 0,
	.trace_loader  = 0,
	.gdb_port      = 1234,
	.enable_gdb    = 0,
};

/* XCOFF file info. */
static struct loaded_coff *lcoff;;

/* Unicorn vars. */
uc_engine *uc;

/**
 * @brief Show program usage.
 *
 * @param prgname Program name.
 */
static void usage(const char *prgname)
{
	fprintf(stderr, "Usage: %s [options] program [arguments...]\n", prgname);
	fprintf(stderr,
		"Options:\n"
		"  -L <path> Set library search path (default: current directory)\n"
		"  -s        Enable syscall trace\n"
		"  -l        Enable loader/binder/milicode/syscall trace\n"
		"  -d        Enable GDB server\n"
		"  -g <port> GDB server port (default: 1234)\n"
		"  -h        Show this help\n\n"
		"Example:\n"
		"  %s -L /usr/lib ./my_aix_program arg1 arg2\n"
		"  %s -s -l ./my_aix_program\n",
		prgname, prgname);
	exit(EXIT_FAILURE);
}

/**
 * @brief Parse command-line arguments.
 *
 * This function modifies argc/argv to point to the actual program
 * and its arguments after parsing aix-user options.
 *
 * @param argc Pointer to argument count.
 * @param argv Pointer to argument list.
 */
static void parse_args(int *argc, char ***argv)
{
	int c;
	int orig_argc = *argc;
	char **orig_argv = *argv;

	/* Parse options. */
	while ((c = getopt(*argc, *argv, "hL:slg:d")) != -1)
	{
		switch (c) {
		case 'h':
			usage((*argv)[0]);
			break;
		case 'L':
			args.lib_path = optarg;
			break;
		case 's':
			args.trace_syscall = 1;
			break;
		case 'l':
			args.trace_loader = 1;
			break;
		case 'g':
			args.gdb_port = atoi(optarg);
			if (args.gdb_port <= 0 || args.gdb_port > 65535) {
				fprintf(stderr, "Invalid GDB port: %s\n", optarg);
				usage((*argv)[0]);
			}
			break;
		case 'd':
			args.enable_gdb = 1;
			break;
		default:
			usage((*argv)[0]);
			break;
		}
	}

	/* Check if we have a program to execute. */
	if (optind >= *argc) {
		fprintf(stderr, "Error: no program specified\n\n");
		usage(orig_argv[0]);
	}

	/*
	 * Adjust argc/argv to point to the program and its arguments.
	 * optind now points to the first non-option argument (the program).
	 */
	*argc -= optind;
	*argv += optind;
}

/* Main =). */
int main(int argc, char **argv, char **envp)
{
	const char *program;
	u32 entry_point;
	uc_hook trace;
	uc_err err;

	/* Parse command-line arguments. */
	parse_args(&argc, &argv);
	program = argv[0];

	/* Initialize our AIX+PPC emulator =). */
	err = uc_open(UC_ARCH_PPC, UC_MODE_PPC32|UC_MODE_BIG_ENDIAN, &uc);
	if (err)
		errx(1, "Unable to create VM: %s\n", uc_strerror(err));

	mm_init(uc);
	mm_init_stack(argc, (const char **)argv, (const char **)envp);
	unix_init(uc);
	insn_emu_init(uc);

	/* Load executable. */
	lcoff = load_xcoff_file(uc, program, NULL, 1);
	if (!lcoff)
		return -1;

	/* Init GDB stub (if requested). */
	if (args.enable_gdb) {
		if (gdb_init(uc, args.gdb_port) < 0)
			errx(1, "Unable to start GDB server!\n");
	}

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
