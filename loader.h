/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025
 */

#ifndef LOADER_H
#define LOADER_H

/* Tiny AIX dynamic loader. */

#include "bigar.h"
#include "xcoff.h"

#define TEXT_DELTA 0
#define DATA_DELTA 1
#define BSS_DELTA  2

struct loaded_coff {
	/* Loaded bin info. */
	struct xcoff  xcoff;
	struct big_ar bar;
	const char *name;

	/* Relocations. */
	u32 text_start;    /* Runtime .text base address. */
	u32 data_start;    /* Runtime .data base address. */
	u32 bss_start;     /* Runtime .bss base address. */
	u32 toc_anchor;    /* Runtime TOC anchor address. */

	/* Deltas. */
	u32 deltas[3];     /* .text/.data/.bss relation offsets, o for exe. */

	/* List. */
	struct loaded_coff *next;
};

extern struct loaded_coff *load_xcoff_file(uc_engine *uc, const char *bin,
	const char *member, int is_exe);

#endif /* LOADER_H. */
