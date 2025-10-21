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
	u32 text_start;
	u32 data_start;
	u32 bss_start;
	u32 toc_anchor;
};

extern struct loaded_coff load_xcoff_file(uc_engine *uc, const char *bin_path,
	int is_exe, int *ret);

#endif /* LOADER_H. */
