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

#define LOADER(...) fprintf(stderr, "[loader] " __VA_ARGS__)


/* Tiny AIX dynamic loader. */
struct loaded_coff *loaded_modules;


/**
 *
 */
static void push_coff(struct loaded_coff *lc)
{
	struct loaded_coff **head = &loaded_modules;
	while (*head)
		head = &(*head)->next;
	*head = lc;
	lc->next = NULL;
}

/**
 *
 */
const char *get_bin_path(const char *bin, const char *member_name) {
	static char path[2048] = {0};
	if (member_name)
		snprintf(path, sizeof path - 1, "%s_%s", bin, member_name);
	else
		snprintf(path, sizeof path - 1, "%s", bin);
	return path;
}

/**
 *
 */
static const struct loaded_coff *
find_module(const struct xcoff_ldr_sym_tbl_hdr32 *imp_sym,
	const struct loaded_coff *lc)
{
	union xcoff_impid *impids;
	struct loaded_coff *head;
	const char *path;

	if (!imp_sym || !lc)
		return NULL;

	if (!imp_sym->l_ifile)
		errx(1, "Import ID for symbol (%s) should be greater than 0!\n",
			imp_sym->u.l_strtblname);

	head   = loaded_modules;
	impids = lc->xcoff.ldr.impids;
	path   = get_bin_path(impids[imp_sym->l_ifile].l_impidbase,
		                  impids[imp_sym->l_ifile].l_impidmem);
	
	/*
	 * If the current iterated XCOFF matches the name we're searching,
	 * we found the lib.
	 */
	while (head) {
		if (!strcmp(path, head->name))
			return head;
		head = head->next;
	}
	return head;
}

/**
 * @brief Resolves an imported symbol for an already (or not) loaded
 * library/module.
 *
 * @param imp_sym Symbol to be imported by another library.
 * @param lc      Current loaded xcoff where we want to import
 *                this symbol.
 *
 * This function does three things:
 * - a) Lookup if the desired lib is already loaded or not
 * -   b) If not loaded, load it
 * - c) Search for the symbol in that library, if not found, emmits an
 *   error!.
 *
 * @return Returns the imported symbol (already relocated) or abort if
 * not found!.
 */
static u32 
resolve_import(uc_engine *uc, const struct xcoff_ldr_sym_tbl_hdr32 *cur_sym,
	const struct loaded_coff *cur_lc)
{
	const struct xcoff_ldr_sym_tbl_hdr32 *imp_sym;
	const struct xcoff_ldr_hdr32 *imp_ldr;
	const struct loaded_coff *imp_lc;
	const union xcoff_impid *cur_id;
	int i;
	
	/* Look up for the right module and load if not already. */
	if (cur_sym->l_ifile >= cur_lc->xcoff.ldr.hdr.l_nimpid)
		errx(1, "Invalid import file ID %d for symbol %s!\n",
			cur_sym->l_ifile, cur_sym->u.l_strtblname);

	cur_id = &cur_lc->xcoff.ldr.impids[cur_sym->l_ifile];
	imp_lc = find_module(cur_sym, cur_lc);
	if (!imp_lc)
		imp_lc = load_xcoff_file(uc, cur_id->l_impidbase, cur_id->l_impidmem, 0);

	/* Look up for the symbol. */
	imp_ldr = &imp_lc->xcoff.ldr.hdr;
	imp_sym = imp_lc->xcoff.ldr.symtbl;

	for (i = 0; i < imp_ldr->l_nsyms; i++) {
		/* We're only interested on exported symbols, because we want
		 * to import an exported symbol =). */
		if (!(imp_sym[i].l_symtype & L_EXPORT))
			continue;

		if (!strcmp(cur_sym->u.l_strtblname, imp_sym[i].u.l_strtblname))
			return imp_sym[i].l_value;
	}

	errx(1, "Unresolved symbol (%s) from (%s)!\n", cur_sym->u.l_strtblname,
		cur_lc->name);
}

/**
 *
 *
 * @note See 984 on ToC doc
 */
static void process_relocations(uc_engine *uc, struct loaded_coff *lc)
{
	struct xcoff_ldr_sym_tbl_hdr32 *sym;
	struct xcoff_ldr_rel_tbl_hdr32 *rt;
	struct xcoff_ldr_hdr32 *ldr;
	u32 addr, value;
	int symidx;
	int ret;
	u32 i;

	ldr = &lc->xcoff.ldr.hdr;
	sym = lc->xcoff.ldr.symtbl;
	rt  = lc->xcoff.ldr.reltbl;

	/*
	 * Relocate export symbol address table too:
	 * These symbols *will* be relocated below, but the address on the table
	 * itself not. Since it would be great the have addresses fixed for later
	 * search*, I will do that too.
	 *
	 * *All of these relocated address might contains the function descriptor
	 * address, so this will become very handy during the import phase.
	 *
	 */
	for (i = 0; i < ldr->l_nsyms; i++) {
		if (!(sym[i].l_symtype & L_EXPORT))
			continue;

		sym[i].l_value += lc->deltas[ sym[i].l_secnum - 1 ];
	}

	/*
	 * Relocate sections addresses (.text/.data/.bss and IMPORTs)
	 */	
	LOADER("Relocating: (%s)\n", lc->name);
	for (i = 0; i < ldr->l_nreloc; i++)
	{
		/* Addr containing the addr to be relocated. */
		addr = rt[i].l_vaddr + lc->deltas[ rt[i].l_rsecnm - 1 ];

		/* Sections relocations. */
		if (rt[i].l_symndx < 3) {
			/* Read the value & relocate it. */
			value = mm_read_u32(addr, &ret);
			if (ret < 0)
				errx(1, "Unable to read address 0x%x to relocate!\n", addr);
			value += lc->deltas[rt[i].l_symndx];
		}
		/* Imports. */
		else {
			symidx = rt[i].l_symndx - 3;
			sym    = &lc->xcoff.ldr.symtbl[symidx];

			if (!(sym->l_symtype & L_IMPORT))
				continue;

			value = resolve_import(uc, sym, lc);
		}
		if (mm_write_u32(addr, value) < 0)
			errx(1, "Unable to write address relocated into 0x%x\n", addr);	
	}
}

/**
 *
 */
static void 
load_xcoff_or_bigar(const char *bin, const char *member, struct loaded_coff *lc)
{
	size_t size;
	const char *buff;

	/* Load an executable or an XCOFF32 library. */
	if (!member) {
		if (xcoff_open(bin, &lc->xcoff) < 0)
			errx(1, "Unable to load XCOFF (%s)!\n", bin);
	}

	/*
	 * Load the Big archive containing the XCOFF, and then, load the
	 * XCOFF32 library, thank you IBM for making our lives simpler /s
	 */
	else {
		if (ar_open(bin, &lc->bar) < 0) {
			errx(1, "Unable to open big archive: (%s)\n", bin);
		}
		buff = ar_extract_member(&lc->bar, member, &size);
		if (!buff) {
			errx(1, "Unable to extract member (%s) from (%s)!\n", member, bin);
		}
		if (xcoff_load(lc->bar.fd, buff, size, &lc->xcoff) < 0)
			errx(1, "Unable to load member (%s) from XCOFF file (%s)!\n",
				member, bin);
	}

	lc->name = strdup(get_bin_path(bin, member));
	if (!lc->name)
		errx(1, "Unable to associate name with the XCOFF!\n");
}

/**
 *
 *
 * TODO: Maybe split this into 'load_executable' and 'load_library'.
 */
struct loaded_coff *
load_xcoff_file(uc_engine *uc, const char *bin, const char *member, int is_exe)
{
	struct loaded_coff *lcoff = NULL;
	struct xcoff_aux_hdr32 *aux;
	struct xcoff_sec_hdr32 *sec;

	if (!uc || !bin)
		return lcoff;

	lcoff = calloc(1, sizeof(*lcoff));
	if (!lcoff)
		errx(1, "Unable to allocate buffer to load new XCOFF!\n");

	load_xcoff_or_bigar(bin, member, lcoff);	
	aux = &lcoff->xcoff.aux;
	sec = &lcoff->xcoff.secs[aux->o_snbss - 1];
	
	/*
	 * Alloc the memory for .text, .data and .bss if the main exec
	 * or library. The distinction is due to...
	 */
	if (is_exe) {
		mm_alloc_main_exec_memory(
			aux->o_text_start, aux->o_tsize,
			aux->o_data_start, aux->o_dsize,
			sec->s_vaddr,      sec->s_size,
			lcoff);
	} else {
		mm_alloc_library_memory(
			aux->o_text_start, aux->o_tsize,
			aux->o_data_start, aux->o_dsize,
			sec->s_vaddr,      sec->s_size,
			lcoff);
	}

	/* Relocate TOC anchor too. */
	lcoff->toc_anchor = aux->o_toc + lcoff->deltas[DATA_DELTA];

	push_coff(lcoff);

	mm_write_text(lcoff, is_exe);
	mm_write_data(lcoff, is_exe);

	/* Fix relocs. */
	process_relocations(uc, lcoff);
	return lcoff;
}
