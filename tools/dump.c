/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../xcoff.h"

/**
 * @brief Show usage information and exit.
 */
static void usage(void)
{
	fprintf(stderr,
		"XCOFF32 dump utility:\n"
		"Usage: dump <xcoff_file> [option]\n"
		"Options:\n"
		"  -h    Show file header only\n"
		"  -a    Show auxiliary header only\n"
		"  -s    Show section headers only\n"
		"  -A    Show all information (default)\n"
		"  -l    Show loader header\n");
	exit(1);
}

/**
 * @brief Main entry point for the XCOFF dump utility.
 *
 * @param argc Argument count.
 * @param argv Argument vector.
 *
 * @return Returns 0 on success, 1 on error.
 */
int main(int argc, char **argv)
{
	const char *xcoff_file;
	const char *option;
	struct xcoff xcoff = {0};
	int show_all       = 1;
	int show_filehdr   = 0;
	int show_auxhdr    = 0;
	int show_sechdrs   = 0;
	int show_loaderhdr = 0;
	int i;

	if (argc < 2)
		usage();

	xcoff_file = argv[1];

	/* Parse options. */
	if (argc >= 3) {
		option = argv[2];
		show_all = 0;

		if (!strcmp(option, "-h"))
			show_filehdr = 1;
		else if (!strcmp(option, "-a"))
			show_auxhdr = 1;
		else if (!strcmp(option, "-s"))
			show_sechdrs = 1;
		else if (!strcmp(option, "-A"))
			show_all = 1;
		else if (!strcmp(option, "-l"))
			show_loaderhdr = 1;
		else
			usage();
	}

	/* Open XCOFF file. */
	if (xcoff_open(xcoff_file, &xcoff) < 0)
		errx(1, "Unable to open XCOFF file '%s'\n", xcoff_file);

	/* Display requested information. */
	if (show_all || show_filehdr)
		xcoff_print_filehdr(&xcoff);

	if (show_all || show_auxhdr)
		xcoff_print_auxhdr(&xcoff);

	if (show_all || show_sechdrs) {
		for (i = 0; i < xcoff.hdr.f_nscns; i++) {
			printf("\n");
			xcoff_print_sechdr(&xcoff.secs[i], i + 1);
		}
	}

	if (show_all || show_loaderhdr)
		xcoff_print_ldr(&xcoff);

	xcoff_close(&xcoff);
	return 0;
}
