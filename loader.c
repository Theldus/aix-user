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
#include "unix.h"

static int g_depth = -1;

#define INCREASE_DEPTH g_depth++
#define DECREASE_DEPTH g_depth--


#define LOADER(...) \
 do { \
   if (args.trace_loader) { \
     fprintf(stderr, "[loader] %*s", g_depth, ""); \
     fprintf(stderr, __VA_ARGS__); \
   } \
 } while (0)

/* Tiny AIX dynamic loader. */
struct loaded_coff *loaded_modules;

/**
 * @brief Add a loaded XCOFF module to the global module list.
 *
 * This function appends the given loaded XCOFF to the end of the
 * loaded_modules linked list, making it available for symbol resolution.
 *
 * @param lc Loaded COFF structure to register.
 */
static void push_coff(struct loaded_coff *lc)
{
	struct loaded_coff **head = &loaded_modules;
	while (*head)
		head = &(*head)->next;
	*head = lc;
	lc->next = NULL;
	LOADER("Registered in module list\n");
}

/**
 * @brief Construct a unique identifier path for a binary or archive member.
 *
 * For archive members, creates "binary_member" format.
 * For standalone binaries, uses the binary path as-is.
 *
 * @param buff        Output buffer to store the path.
 * @param size        Size of the output buffer.
 * @param bin         Binary/archive file path.
 * @param member_name Archive member name (NULL for standalone binaries).
 * @return Pointer to the output buffer.
 */
const char *
get_bin_path(char *buff, size_t size, const char *bin, const char *member_name) {
	if (member_name)
		snprintf(buff, size - 1, "%s_%s", bin, member_name);
	else
		snprintf(buff, size - 1, "%s", bin);
	return buff;
}

/**
 * @brief Search for a loaded module by import symbol reference.
 *
 * This function looks up the import ID from the symbol, constructs
 * the expected binary path, and searches the loaded_modules list
 * for a matching module.
 *
 * @param imp_sym Import symbol containing the import file ID.
 * @param lc      Current loaded XCOFF with import ID table.
 * @return Pointer to the loaded module if found, NULL otherwise.
 */
static const struct loaded_coff *
find_module(const struct xcoff_ldr_sym_tbl_hdr32 *imp_sym,
	const struct loaded_coff *lc)
{
	union xcoff_impid *impids;
	struct loaded_coff *head;
	char path[2048] = {0};

	if (!imp_sym || !lc)
		return NULL;

	if (!imp_sym->l_ifile)
		errx(1, "Import ID for symbol (%s) should be greater than 0!\n",
			imp_sym->u.l_strtblname);

	head   = loaded_modules;
	impids = lc->xcoff.ldr.impids;
	get_bin_path(path, sizeof path,
	             impids[imp_sym->l_ifile].l_impidbase,
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

	INCREASE_DEPTH;

	/*
	 * TODO; Imports with Import #ID0 is a special case where I still have to
	 * think about, so lets just emit a warning a return an invalid pointer,
	 * which should later trigger a hook for invalid memory access if there is
	 * any access on that address.
	 */
	if (cur_sym->l_ifile == 0) {
		LOADER(">> WARNING <<: Import ID#0 for symbol %s, ignoring!\n",
			   cur_sym->u.l_strtblname);
		DECREASE_DEPTH;
		return 0x1111;
	}
	
	/* Look up for the right module and load if not already. */
	if (cur_sym->l_ifile >= cur_lc->xcoff.ldr.hdr.l_nimpid)
		errx(1, "Invalid import file ID %d for symbol %s!\n",
			cur_sym->l_ifile, cur_sym->u.l_strtblname);

	cur_id = &cur_lc->xcoff.ldr.impids[cur_sym->l_ifile];

	/* Special handling for /unix */
	if (!strcmp(cur_id->l_impidbase, "unix")) {
		DECREASE_DEPTH;
		return handle_unix_imports(cur_sym);
	}

	LOADER("Resolving import: %s from %s (currently processing: %s)\n",
		cur_sym->u.l_strtblname,
		cur_id->l_impidbase,
		cur_lc->name);

	imp_lc = find_module(cur_sym, cur_lc);
	if (!imp_lc)
		imp_lc = load_xcoff_file(uc, cur_id->l_impidbase, cur_id->l_impidmem, 0);

	/* Look up for the symbol. */
	imp_ldr = &imp_lc->xcoff.ldr.hdr;
	imp_sym = imp_lc->xcoff.ldr.symtbl;

	for (i = 0; i < imp_ldr->l_nsyms; i++) {
		/* SKip symbols that do not match our search. */
		if (strcmp(cur_sym->u.l_strtblname, imp_sym[i].u.l_strtblname))
			continue;

		/* Check if this is a passthrough/re-exported symbol */
		if (imp_sym[i].l_symtype & L_IMPORT) {
			/*
			 * This symbol is re-exported (passthrough).
			 * Example: executable imports brk from libc, but libc also imports
			 * brk from /unix. Recursively resolve from the original source.
			 */
			LOADER("Passthrough symbol: %s, resolving from %s\n",
				imp_sym[i].u.l_strtblname,
				imp_lc->xcoff.ldr.impids[imp_sym[i].l_ifile].l_impidbase);

			return resolve_import(uc, &imp_sym[i], imp_lc);
		}

		/*
		 * Note: AIX libraries export function descriptors (in .data) for functions,
		 * not raw code addresses. So imp_sym[i].l_value points to the descriptor
		 * (already relocated on load module), containing [func_addr, toc_anchor,
		 * env]. Variables are exported as direct addresses. No distinction
		 * needed here.
		 */
		DECREASE_DEPTH;
		return imp_sym[i].l_value;
	}

	errx(1, "Unresolved symbol (%s) from (%s)!\n", cur_sym->u.l_strtblname,
		cur_lc->name);
}

/**
 * @brief Process all relocations for a loaded XCOFF module.
 *
 * This function performs two main tasks:
 * 1. Relocates export symbol addresses by applying section deltas
 * 2. Processes all relocation entries (section relocations and imports)
 *
 * For section relocations (.text/.data/.bss), adjusts pointers by
 * the appropriate delta. For imports, resolves symbols from other
 * modules (potentially loading them if not already loaded).
 *
 * @param uc Unicorn engine instance.
 * @param lc Loaded COFF structure with relocation information.
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

	INCREASE_DEPTH;

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
		LOADER("Fixing export, sym: %s, addr: 0x%08x\n", sym[i].u.l_strtblname,
			sym[i].l_value);
	}

	/*
	 * Relocate sections addresses (.text/.data/.bss and IMPORTs)
	 */	
	LOADER("Processing %d relocations (%s)...\n", ldr->l_nreloc, lc->name);
	for (i = 0; i < ldr->l_nreloc; i++)
	{
		/* Addr containing the addr to be relocated. */
		value = 0;
		addr  = rt[i].l_vaddr + lc->deltas[ rt[i].l_rsecnm - 1 ];

		/*
		 * Section relocations (symndx 0/1/2 = .text/.data/.bss).
		 * The value at this address points into that section and
		 * needs adjustment if the section moved (delta != 0).
		 */
		if (rt[i].l_symndx < 3) {
			/* Read the value & relocate it. */
			value = mm_read_u32(addr, &ret);
			if (ret < 0)
				errx(1, "Unable to read address 0x%x to relocate!\n", addr);
			
			/* Add section-specific delta to adjust the pointer */
			value += lc->deltas[rt[i].l_symndx];
		}

		/* Everything else (import/export) */
		else {
			symidx = rt[i].l_symndx - 3;
			sym    = &lc->xcoff.ldr.symtbl[symidx];

			if (sym->l_symtype & L_IMPORT) {
				value = resolve_import(uc, sym, lc);
				LOADER("Imported sym (%s), resolved, addr=0x%08x\n",
				       sym->u.l_strtblname, value);
			}

			/* Local symbol - already relocated in symbol table. */
			else if (sym->l_symtype & L_EXPORT) {
				value = sym->l_value;
				LOADER("Exported sym (%s), resolved, addr=0x%08x\n",
				       sym->u.l_strtblname, value);
			}
		}

		LOADER("Writing resolved symbol: v=0x%08x, addr=0x%08x\n",
			value, addr);
	
		if (mm_write_u32(addr, value) < 0)
			errx(1, "Unable to write address relocated into 0x%x\n", addr);	
	}

	DECREASE_DEPTH;
}

/**
 * @brief Load an XCOFF file or extract it from a Big-AR archive.
 *
 * If member is NULL, loads the file directly as an XCOFF executable.
 * If member is specified, opens the file as a Big-AR archive,
 * extracts the named member, and loads it as an XCOFF library.
 * Also assigns a unique name to the loaded module for tracking.
 *
 * @param bin    Path to the binary or archive file.
 * @param member Archive member name (NULL for standalone XCOFF).
 * @param lc     Loaded COFF structure to populate.
 */
static void
load_xcoff_or_bigar(const char *bin, const char *member, struct loaded_coff *lc)
{
	size_t size;
	char path[2048] = {0};
	const char *buff;

	LOADER("Loading: (%s)(%s)\n", bin, member);

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

	get_bin_path(path, sizeof path, bin, member);
	lc->name = strdup(path);
	if (!lc->name)
		errx(1, "Unable to associate name with the XCOFF!\n");
}

/**
 * @brief Load and initialize an XCOFF executable or library.
 *
 * This is the main entry point for loading XCOFF files. It:
 * 1. Loads the XCOFF from file or archive
 * 2. Allocates memory for .text/.data/.bss sections
 * 3. Writes section contents to VM memory
 * 4. Processes relocations and resolves imports
 * 5. Registers the module in the global list
 *
 * TODO: Maybe split this into 'load_executable' and 'load_library'.
 *
 * @param uc     Unicorn engine instance.
 * @param bin    Path to the binary or archive file.
 * @param member Archive member name (NULL for executables).
 * @param is_exe 1 for main executable, 0 for library.
 * @return Pointer to the loaded COFF structure, or NULL on error.
 */
struct loaded_coff *
load_xcoff_file(uc_engine *uc, const char *bin, const char *member, int is_exe)
{
	struct loaded_coff *lcoff = NULL;
	struct xcoff_aux_hdr32 *aux;
	struct xcoff_sec_hdr32 *sec;

	if (!uc || !bin)
		return lcoff;

	INCREASE_DEPTH;

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

	LOADER("Allocated: .text=0x%x .data=0x%x .bss=0x%x\n",
		lcoff->text_start, lcoff->data_start, lcoff->bss_start);

	/* Relocate TOC anchor and set it if we're handling the main exec. */
	lcoff->toc_anchor = aux->o_toc + lcoff->deltas[DATA_DELTA];
	if (is_exe)
		uc_reg_write(uc, UC_PPC_REG_2, &lcoff->toc_anchor);

	push_coff(lcoff);
	mm_write_text(lcoff, is_exe);
	mm_write_data(lcoff, is_exe);

	/* Fix relocs. */
	process_relocations(uc, lcoff);

	DECREASE_DEPTH;
	return lcoff;
}
