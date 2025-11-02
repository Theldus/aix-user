/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025
 */

#ifndef LOADER_H
#define LOADER_H

/* Tiny AIX dynamic loader. */

#include "xcoff.h"

struct loaded_coff {
	struct xcoff xcoff;
	u32 text_start;    /* Runtime .text base address. */
	u32 data_start;    /* Runtime .data base address. */
	u32 bss_start;     /* Runtime .bss base address. */
	u32 toc_anchor;    /* Runtime TOC anchor address. */
	/* Deltas. */
	u32 text_delta;    /* .text relocation offset (0 for main exe). */
	u32 data_delta;    /* .data relocation offset (0 for main exe). */
	u32 bss_delta;     /* .bss relocation offset  (0 for main exe). */
};

extern struct loaded_coff load_xcoff_file(uc_engine *uc, const char *bin_path,
	int is_exe, int *ret);

#endif /* LOADER_H. */
