/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025-2026
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "syscalls.h"
#include "mm.h"
#include "loader.h"

#define AIX_DL_EXECQ      0x03000000
#define AIX_DL_EXITQ      0x04000000
#define AIX_DL_SRCHMODULE 0x00080000
#define AIX_DL_INFO_OK    0x00010000

#define AIX_DL_HAS_RTINIT 0x1  /* Module __rtinit symbols */
#define AIX_DL_IS_NEW     0x2  /* Module is newly loaded  */

union aix_dl_info {
	struct {
		u32 flags; /* General flags.   */
		u32 size;  /* Size per struct. */
		u32 len;   /* Module count.    */
		u32 padding;
	} h;
	struct {
		u32 text_start;
		u32 data_start;
		u32 data_size; /* This includes .bss */
		u16 index;     /* Entry index.       */
		u16 flags;     /* Entry flags.       */
	} e;
};

/**
 * @brief For a given loaded XCOFF, checks if the module has the
 * '__rtinit' symbol defined or not. The presence of this symbol
 * indicates that this module have constructors/destructors
 * to be called.
 *
 * @param xcoff XCOFF module to be queried.
 *
 * @return Returns 1 if has the symbol, 0 if not.
 */
static inline int module_has_rtinit(const struct xcoff *xcoff) {
	return strcmp(xcoff->ldr.symtbl[0].u.l_strtblname, "__rtinit") == 0;
}

/**
 * @brief __loadx syscall handler.
 *
 * AIX's __loadx is the spirit equivalent of dlopen() on Linux and manages
 * many dynamic-library operations, such as querying for symbols and
 * dyamically loading libraries at runtime.
 *
 * However, contrary to dlopen(), __loadx is a syscall and the kernel
 * is the one responsible for this, which in our case, is nice.
 *
 * For DL_EXEC/EXITQ: find modules with rtinit and returns a list of these
 *                    modules, with text_start/data_start and etc.
 *
 * AIX calling convention:
 *   r3 = flag
 *   r4 = symbol_name / buffer
 *   r5 = (output) pointer to symbol's module index
 *   r6 = (output) pointer to symbol's data origin
 *   r7 = (input)  extra parameter
 *
 * Return value (in r3):
 *   0 if success, something else(?) otherwise
 */
int aix___loadx(uc_engine *uc)
{
	union aix_dl_info *dl_info, *dlp;
	const struct mm_region *r;
	struct loaded_coff *lc;

	u32 flg     = read_1st_arg();
	u32 buffer  = read_2nd_arg();
	u32 sym_idx = read_3rd_arg();
	u32 sym_org = read_4th_arg();
	u32 ext     = read_5th_arg();
	int ret     = 0;
	int idx;

	if (flg & (AIX_DL_EXECQ|AIX_DL_EXITQ)) {
		if (!(dl_info = mm_vm2host(buffer))) {
			ret = -1;
			goto out;
		}

		/* Header. */
		dl_info->h.flags   = htonl(AIX_DL_INFO_OK);
		dl_info->h.size    = htonl(16);
		dl_info->h.len     = 0; /* to be incremented/converted later. */
		dl_info->h.padding = 0;
		dlp = dl_info+1;
		lc  = loaded_modules;
		idx = 0;

		for (; lc; lc = lc->next) {
			if (!module_has_rtinit(&lc->xcoff))
				continue;

			r = mm_find_region(lc->text_start);
			dlp->e.text_start = htonl(r->vm_base);
			dlp->e.data_start = htonl(lc->data_start);
			dlp->e.data_size  = htonl(lc->xcoff.aux.o_dsize +
			                          lc->xcoff.aux.o_bsize);
			dlp->e.index      = htons(idx);

			/* For EXECQ the IS_NEW flag is also returned on AIX, but not
			 * for the EXITQ, so we're omitting too, the remaining is
			 * exact the same.
			 */
			if (flg & AIX_DL_EXECQ)
				dlp->e.flags = htons(AIX_DL_HAS_RTINIT|AIX_DL_IS_NEW);
			else
				dlp->e.flags = htons(AIX_DL_HAS_RTINIT);

			dlp++;
			idx++;
		}
		dl_info->h.len = htonl(idx);
	}

out:
	TRACE("__loadx", "0x%x, 0x%x, 0x%x, 0x%x, 0x%x",
		flg,buffer,sym_idx,sym_org,ext);
	return ret;
}
