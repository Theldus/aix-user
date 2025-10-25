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
#include "util.h"

/* Tiny AIX dynamic loader. */

#define TEXT_START 0x10000000
#define TEXT_SIZE  0x1000000  /* 16 MiB. */
#define DATA_START 0x20000000
#define DATA_SIZE  0x1000000  /* 16 MiB. */

/**
 *
 */
static void
map_and_write_section(uc_engine *uc,
	u32 uc_start,
	u32 uc_size,
	u32 uc_perms,
	u32 off_start,
	u8 *buff,
	u32 bsize,
	const char *type,
	int map)
{
	if (map && uc_mem_map(uc, uc_start, uc_size, uc_perms))
		errx(1,"Unable to map memory for section %s: %x (%d)!\n", type, uc_start,
			uc_size);
	if (uc_mem_write(uc, uc_start+off_start, buff, bsize))
		errx(1, "Unable to write to section %s!\n", type);
}

/**
 *
 */
static void
map_and_write_text_section(uc_engine *uc, u32 start, u32 size, 
	const struct loaded_coff *lcoff)
{
	const struct xcoff_sec_hdr32 *sec;
	const struct xcoff_aux_hdr32 *aux;
	aux = &lcoff->xcoff.aux;
	sec = &lcoff->xcoff.secs[aux->o_sntext - 1];
	map_and_write_section(uc,
		start,
		size,
		UC_PROT_ALL, /* temporary. */
		lcoff->text_start - start,
		lcoff->xcoff.buff + sec->s_scnptr,
		sec->s_size,
		".text", 1
	);
}

/**
 *
 */
static void
map_and_write_data_section(uc_engine *uc, u32 start, u32 size,
	const struct loaded_coff *lcoff)
{
	const struct xcoff_sec_hdr32 *sec;
	const struct xcoff_aux_hdr32 *aux;
	aux = &lcoff->xcoff.aux;
	sec = &lcoff->xcoff.secs[aux->o_sndata - 1];
	map_and_write_section(uc,
		start,
		size,
		UC_PROT_ALL, /* temporary. */
		lcoff->data_start - start,
		lcoff->xcoff.buff + sec->s_scnptr,
		sec->s_size,
		".data", 1
	);
}

/**
 *
 */
static void write_bss_section(uc_engine *uc, const struct loaded_coff *lcoff)
{
	const struct xcoff_sec_hdr32 *sec;
	const struct xcoff_aux_hdr32 *aux;
	char *bss;
	aux = &lcoff->xcoff.aux;
	sec = &lcoff->xcoff.secs[aux->o_snbss - 1];
	bss = calloc(1, sec->s_size);
	if (!bss) {
		errx(1, "Error while allocating .bss!");
	}
	map_and_write_section(uc,
		lcoff->bss_start,
		0, /* not used. */
		0, /* not used. */
		0, /* not used. */
		bss,
		sec->s_size,
		".bss", 0
	);
	free(bss);
}

/**
 *
 */
int check_exe_sections(const struct xcoff_aux_hdr32 *aux, 
	const struct xcoff_sec_hdr32 *bss)
{
	u32 data_start;
	u32 data_end;

	/* .text fits into our range?. */
	if (!(aux->o_text_start >= TEXT_START && aux->o_tsize <= TEXT_SIZE)) {
		warn(".text is bigger than expected, start: %x, size: %u!\n",
			aux->o_text_start, aux->o_tsize);
		return -1;
	}

	/* .bss overlaps .data and/or stars before it?. */
	if (bss->s_vaddr < aux->o_data_start
		|| bss->s_vaddr+bss->s_size < aux->o_data_start+aux->o_dsize)
	{
		warn("Executable's .bss overlaps .data!");
		return -1;
	}

	data_start = min(aux->o_data_start, bss->s_vaddr);
	data_end   = max(aux->o_data_start+aux->o_dsize,
	                 bss->s_vaddr+bss->s_size);

	if (!(data_start >= DATA_START && data_end <= DATA_START+DATA_SIZE)) {
		warn(".data and .bss dot not conform as");
		return -1;
	}
	return 0;
}

/**
 *
 */
struct loaded_coff 
load_xcoff_file(uc_engine *uc, const char *bin_path, int is_exe, int *ret)
{
	struct loaded_coff lcoff = {0};
	struct xcoff_aux_hdr32 *aux;
	struct xcoff_sec_hdr32 *sec;
	u32 text_start;
	u32 data_start;
	u32 text_size;
	u32 data_size;

	if (!ret || !uc || !bin_path)
		return lcoff;

	*ret = -1;
	if (xcoff_open(bin_path, &lcoff.xcoff) < 0)
		return lcoff;
	
	aux = &lcoff.xcoff.aux;
	sec = &lcoff.xcoff.secs[aux->o_snbss - 1];
	
	/*
	 * If is the main executable, I assume a few things:
	 * - Im lazy, so lets just map 16MiB to text/data with hardcoded starts
	 * - .bss always comes after .data
	 * - .text stays at 0x100... range
	 * - .data/.bss stays at 0x200... range
	 */
	
	if (is_exe) {
		if (check_exe_sections(aux, sec) < 0)
			return lcoff;

		/* If everything passes, use our default values. */
		text_start = TEXT_START;
		text_size  = TEXT_SIZE;
		data_start = DATA_START;
		data_size  = DATA_SIZE;
		/* Configure our lcoff. */
		lcoff.text_start = aux->o_text_start;
		lcoff.data_start = aux->o_data_start;
		lcoff.bss_start  = sec->s_vaddr;
		lcoff.toc_anchor = aux->o_toc;
	}

	map_and_write_text_section(uc, text_start, text_size, &lcoff);
	map_and_write_data_section(uc, data_start, data_size, &lcoff);
	write_bss_section(uc, &lcoff);

	*ret = 0;
	return lcoff;
}
