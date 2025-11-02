/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025
 */

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <unicorn/unicorn.h>

#include "loader.h"
#include "mm.h"
#include "util.h"

/* Tiny AIX dynamic loader. */

/**
 *
 */
struct loaded_coff 
load_xcoff_file(uc_engine *uc, const char *bin_path, int is_exe, int *ret)
{
	struct loaded_coff lcoff = {0};
	struct xcoff_aux_hdr32 *aux;
	struct xcoff_sec_hdr32 *sec;

	if (!ret || !uc || !bin_path)
		return lcoff;

	*ret = -1;
	if (xcoff_open(bin_path, &lcoff.xcoff) < 0)
		return lcoff;
	
	aux = &lcoff.xcoff.aux;
	sec = &lcoff.xcoff.secs[aux->o_snbss - 1];
	lcoff.toc_anchor = aux->o_toc;
	
	/*
	 * Alloc the memory for .text, .data and .bss if the main exec
	 * or library. The distinction is due to...
	 */
	if (is_exe) {
		mm_alloc_main_exec_memory(
			aux->o_text_start, aux->o_tsize,
			aux->o_data_start, aux->o_dsize,
			sec->s_vaddr,      sec->s_size,
			&lcoff);
	} else {
		mm_alloc_library_memory(
			aux->o_text_start, aux->o_tsize,
			aux->o_data_start, aux->o_dsize,
			sec->s_vaddr,      sec->s_size,
			&lcoff);
	}

	mm_write_text(&lcoff);
	mm_write_data(&lcoff);

	*ret = 0;
	return lcoff;
}
