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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "xcoff.h"

/**
 * @brief Read the file header for a given XCOFF32.
 *
 * @param xcoff XCOFF32 data pointer.
 *
 * @return Returns 0 if success, a negative number otherwise.
 */
int xcoff_read_filehdr(struct xcoff *xcoff)
{
	struct xcoff_file_hdr32 *hdr;
	if (!xcoff)
		return -1;

	hdr = &xcoff->hdr;
	if (xcoff->file_size < sizeof (*hdr))
		return -1;

	memcpy(hdr, xcoff->buff, sizeof (*hdr));
	CONV16(hdr->f_magic);
	CONV16(hdr->f_nscns);
	CONV32(hdr->f_timdat);
	CONV32(hdr->f_symptr);
	CONV32(hdr->f_nsyms);
	CONV16(hdr->f_opthdr);
	CONV16(hdr->f_flags);
	return 0;
}

/**
 * @brief Prints file header for a given XCOFF32.
 *
 * @param xcoff XCOFF32 data pointer.
 */
void xcoff_print_filehdr(const struct xcoff *xcoff)
{
	const struct xcoff_file_hdr32 *hdr;
	if (!xcoff)
		return;

	hdr = &xcoff->hdr;
	printf("\nXCOFF32 File Header:\n"
	       "  f_magic:  %x\n"
	       "  f_nscns:  %d\n"
	       "  f_timdat: %d\n"
	       "  f_symptr: %d\n"
	       "  f_nsyms:  %d\n"
	       "  f_opthdr: %d\n",
	       hdr->f_magic,
	       hdr->f_nscns,
	       hdr->f_timdat,
	       hdr->f_symptr,
	       hdr->f_nscns,
	       hdr->f_opthdr
	);
}

/**
 * @brief Reads the Auxiliary Header for a given XCOFF32.
 *
 * @param xcoff XCOFF32 data pointer.
 *
 * @return Returns 0 if success, a negative number otherwise.
 */
int xcoff_read_auxhdr(struct xcoff *xcoff)
{
	struct xcoff_aux_hdr32 *aux;
	if (!xcoff)
		return -1;

	aux = &xcoff->aux;
	if (xcoff->file_size < XCOFF_FHDR_SIZE+XCOFF_AHDR_SIZE)
		return -1;

	memcpy(aux, xcoff->buff+XCOFF_FHDR_SIZE, XCOFF_AHDR_SIZE);
	CONV16(aux->o_mflag); 
	CONV16(aux->o_vstamp);
	CONV32(aux->o_tsize);
	CONV32(aux->o_dsize);
	CONV32(aux->o_bsize);
	CONV32(aux->o_entry);
	CONV32(aux->o_text_start);
	CONV32(aux->o_data_start);
	CONV32(aux->o_toc);
	CONV16(aux->o_snentry);
	CONV16(aux->o_sntext);
	CONV16(aux->o_sndata);
	CONV16(aux->o_sntoc);
	CONV16(aux->o_snloader);
	CONV16(aux->o_snbss);
	CONV16(aux->o_algntext);
	CONV16(aux->o_algndata);
	CONV32(aux->o_maxstack);
	CONV32(aux->o_maxdata);
	CONV32(aux->o_debugger);
	CONV16(aux->o_sntdata);
	CONV16(aux->o_sntbss);
	return 0;
}

/**
 * @brief Prints the Auxiliary Header for a given XCOFF32.
 *
 * @param xcoff XCOFF32 data pointer.
 */
void xcoff_print_auxhdr(const struct xcoff *xcoff)
{
	const struct xcoff_aux_hdr32 *aux;
	if (!xcoff)
		return;

	aux = &xcoff->aux;
	printf("\nXCOFF32 Auxiliary Header:\n"
		"  o_mflag:  %x\n" 
		"  o_vstamp: %d\n"
		"  o_tsize:  %d\n"
		"  o_dsize:  %d\n"
		"  o_bsize:  %d\n"
		"  o_entry:  0x%x\n"
		"  o_text_start: 0x%x\n"
		"  o_data_start: 0x%x\n"
		"  o_toc:        0x%x\n"
		"  o_snentry:    %d\n"
		"  o_sntext:     %d\n"
		"  o_sndata:     %d\n"
		"  o_sntoc:      %d\n"
		"  o_snloader:   %d\n"
		"  o_snbss:      %d\n"
		"  o_algntext:   %d\n"
		"  o_algndata:   %d\n"
		"  o_modtype:    %c%c\n"
		"  o_cpuflag:    %d\n"
		"  o_cputype:    %d\n"
		"  o_maxstack:   %d\n"
		"  o_maxdata:    %d\n"
		"  o_debugger:   %d\n"
		"  o_textpsize:  %d\n"
		"  o_datapsize:  %d\n"
		"  o_stackpsize: %d\n"
		"  o_flags:      %d\n"
		"  o_sntdata:    %d\n"
		"  o_sntbss:     %d\n",
		aux->o_mflag,    aux->o_vstamp,     aux->o_tsize,      aux->o_dsize,
		aux->o_bsize,    aux->o_entry,      aux->o_text_start, aux->o_data_start,
		aux->o_toc,      aux->o_snentry,    aux->o_sntext,     aux->o_sndata,
		aux->o_sntoc,    aux->o_snloader,   aux->o_snbss,      aux->o_algntext,
		aux->o_algndata, aux->o_modtype[0], aux->o_modtype[1], aux->o_cpuflag,
		aux->o_cputype,  aux->o_maxstack,   aux->o_maxdata,
		aux->o_debugger, aux->o_textpsize,  aux->o_datapsize,  aux->o_stackpsize,
		aux->o_flags,    aux->o_sntdata,    aux->o_sntbss
	);
}

/**
 * @brief Prints a section header for a given XCOFF32.
 *
 * @param xcoff XCOFF32 data pointer.
 * @param n     Section number.
 */
void xcoff_print_sechdr(const struct xcoff_sec_hdr32 *sec, int n)
{
	if (!sec)
		return;
	printf("XCOFF32 Section Header #%d:\n"
		"  s_name:    %s\n"
		"  s_paddr:   %x\n"
		"  s_vaddr:   %x\n"
		"  s_size:    %d\n"
		"  s_scnptr:  %d\n"
		"  s_relptr:  %d\n"
		"  s_lnnoptr: %d\n"
		"  s_nreloc:  %d\n"
		"  s_nlnno:   %d\n"
		"  s_flags:   0x%x\n",
		n,
		sec->s_name,   sec->s_paddr,   sec->s_vaddr, sec->s_size, sec->s_scnptr,
		sec->s_relptr, sec->s_lnnoptr, sec->s_nreloc, sec->s_nlnno, sec->s_flags
	);
}

/**
 * @brief Reads all section headers present on @p xcoff.
 *
 * @param xcoff XCOFF32 data pointer.
 *
 * @return Returns 0 if success, a negative number otherwise.
 */
static int xcoff_read_all_sechdrs(struct xcoff *xcoff)
{
	struct xcoff_sec_hdr32 *sec = {0};
	u32    cur_sec   = XCOFF_FHDR_SIZE+XCOFF_AHDR_SIZE;
	s32    rem_bytes = xcoff->file_size-cur_sec;
	size_t ntotsecs  = sizeof(xcoff->secs)/sizeof(xcoff->secs[0]);
	int i;

	if (xcoff->hdr.f_nscns > ntotsecs) {
		warn("Too many sections, I cant hold them: %zu/%d", ntotsecs,
			xcoff->hdr.f_nscns);
		return -1;
	}

	for (i = 0; i < xcoff->hdr.f_nscns; i++) {
		if (rem_bytes < (s32)XCOFF_SHDR_SIZE) {
			warn("Unable to read section #%d!\n", i+1);
			return -1;
		}
		sec = &xcoff->secs[i];
		memcpy(sec, xcoff->buff+cur_sec, XCOFF_SHDR_SIZE);
		CONV32(sec->s_paddr);
		CONV32(sec->s_vaddr);
		CONV32(sec->s_size);
		CONV32(sec->s_scnptr);
		CONV32(sec->s_relptr);
		CONV32(sec->s_lnnoptr);
		CONV16(sec->s_nreloc);
		CONV16(sec->s_nlnno);
		CONV32(sec->s_flags);

		rem_bytes -= XCOFF_SHDR_SIZE;
		cur_sec   += XCOFF_SHDR_SIZE;
	}
	return 0;
}

/**
 *
 */
static int
xcoff_read_reltbl(const struct xcoff_sec_hdr32 *sec, struct xcoff *xcoff)
{
	struct xcoff_ldr_rel_tbl_hdr32 *rt;
	struct xcoff_ldr_hdr32 *ldr;
	u32 start; /* STart of relocation table.       */
	u32 off;   /* File offset to end of rel table. */
	char *p;
	int i;

	if (!sec || !xcoff)
		return -1;

	ldr   = &xcoff->ldr.hdr;
	start = sec->s_scnptr + sizeof(*ldr) +
		    (ldr->l_nsyms * sizeof(struct xcoff_ldr_sym_tbl_hdr32));
	
	off   = start + (ldr->l_nreloc * sizeof(*rt));

	if (xcoff->file_size < off)
		errx(1, "Invalid relocation table!\n");

	xcoff->ldr.reltbl = calloc(ldr->l_nreloc, sizeof(*rt));
	if (!xcoff->ldr.reltbl)
		errx(1, "Unable to alloc for relocation table!\n");

	p = xcoff->buff + start;
	for (i = 0; i < ldr->l_nreloc; i++, p += sizeof(*rt)) {
		rt = &xcoff->ldr.reltbl[i];
		memcpy(rt, p, sizeof(*rt));
		CONV32(rt->l_vaddr);
		CONV32(rt->l_symndx);
		CONV16(rt->l_rsecnm);
	}
	return 0;
}

/**
 *
 */
static int
xcoff_read_symtbl(const struct xcoff_sec_hdr32 *sec, struct xcoff *xcoff)
{
	struct xcoff_ldr_sym_tbl_hdr32 *st;
	struct xcoff_ldr_hdr32 *ldr;
	u32 off;
	char *p;
	int i;

	if (!sec || !xcoff)
		return -1;

	ldr = &xcoff->ldr.hdr;
	off = sec->s_scnptr + sizeof(*ldr) + (ldr->l_nsyms*sizeof(*st));

	if (xcoff->file_size < off)
		errx(1, "Invalid symbol tbl!\n");

	xcoff->ldr.symtbl = calloc(ldr->l_nsyms, sizeof(*st));
	if (!xcoff->ldr.symtbl)
		errx(1, "Unable to alloc for import IDs!\n");

	p = xcoff->buff + sec->s_scnptr + sizeof(*ldr);
	for (i = 0; i < ldr->l_nsyms; i++, p += sizeof(*st)) {
		st = &xcoff->ldr.symtbl[i];
		memcpy(st, p, sizeof(*st));
		if (!st->u.s.zeroes)
			CONV32(st->u.s.offset);
		
		CONV32(st->l_value);
		CONV16(st->l_secnum);
		CONV32(st->l_ifile);
		CONV32(st->l_parm);
	}

	return 0;
}

/**
 *
 */
static int
xcoff_read_impids(const struct xcoff_sec_hdr32 *sec, struct xcoff *xcoff)
{
	struct xcoff_ldr_hdr32 *ldr;
	char *p, *end;
	int i, j;

	if (!sec || !xcoff)
		return -1;

	ldr = &xcoff->ldr.hdr;

	/* Load import IDs. */
	if (xcoff->file_size < sec->s_scnptr+ldr->l_impoff+ldr->l_istlen)
		errx(1, "Invalid Import IDs table!\n");

	xcoff->ldr.impids = calloc(ldr->l_nimpid, sizeof(union xcoff_impid));
	if (!xcoff->ldr.impids)
		errx(1, "Unable to alloc for import IDs!\n");

	p   = xcoff->buff+sec->s_scnptr+ldr->l_impoff;
	end = p + ldr->l_istlen;

	for (i = 0; i < ldr->l_nimpid; i++) {
		/* Read 3 null-delimited strings. */
		for (j = 0; j < 3; j++) {
			xcoff->ldr.impids[i].v[j] = p;
			if (xcoff->ldr.impids[i].v[j][0] == '\0')
				xcoff->ldr.impids[i].v[j] = NULL;

			while (p < end && *p) {p++;}
			if (p >= end)
				return -1;
			p++; /* Skip nul char. */
		}
	}
	return 0;
}

/**
 *
 */
static int
get_section(const struct xcoff *xcoff, const struct xcoff_sec_hdr32 **sec,
	u32 flags)
{
	int i;
	size_t ntotsecs;
	const struct xcoff_sec_hdr32 *s;

	if (!xcoff || !sec)
		return -1;

	for (i = 0; i < xcoff->hdr.f_nscns; i++) {
		s = &xcoff->secs[i];
		if (s->s_flags == flags)
			break;
	}
	if (i == xcoff->hdr.f_nscns)
		return -1;

	*sec = s;
	return 0;
}

/**
 *
 */
int xcoff_read_ldrhdr(struct xcoff *xcoff)
{
	const struct xcoff_sec_hdr32 *sec = NULL;
	struct xcoff_ldr_hdr32 *ldr;
	size_t i;

	if (!xcoff)
		return -1;

	ldr = &xcoff->ldr.hdr;
	if (get_section(xcoff, &sec, STYP_LOADER) < 0) {
		errx(1, "Unable to find loader section!\n");
		return -1;
	}

	/* Invalid data?. */
	if (xcoff->file_size < sec->s_scnptr+sec->s_size)
		return -1;

	memcpy(ldr, xcoff->buff+sec->s_scnptr, sizeof(*ldr));
	CONV32(ldr->l_version);
	CONV32(ldr->l_nsyms);
	CONV32(ldr->l_nreloc);
	CONV32(ldr->l_istlen);
	CONV32(ldr->l_nimpid);
	CONV32(ldr->l_impoff);
	CONV32(ldr->l_stlen);
	CONV32(ldr->l_stoff);

	if (xcoff_read_impids(sec, xcoff) < 0)
		return -1;
	if (xcoff_read_symtbl(sec, xcoff) < 0)
		return -1;
	if (xcoff_read_reltbl(sec, xcoff) < 0)
		return -1;

	return 0;
}

/**
 * @brief Prints a loader header for a given XCOFF32.
 *
 * @param xcoff XCOFF32 data pointer.
 */
void xcoff_print_ldr(const struct xcoff *xcoff)
{
	int i;
	const char *symname;
	const struct xcoff_sec_hdr32 *sec;
	const struct xcoff_ldr_hdr32 *ldr;
	const struct xcoff_ldr_sym_tbl_hdr32 *st;
	const struct xcoff_ldr_rel_tbl_hdr32 *rt;

	if (!xcoff)
		return;
	if (get_section(xcoff, &sec, STYP_LOADER) < 0)
		return;

	ldr = &xcoff->ldr.hdr;
	printf("\nXCOFF32 Loader Header:\n"
		"  l_version: %d\n"
		"  l_nsyms:   %d\n"
		"  l_nreloc:  %d\n"
		"  l_istlen:  %d\n"
		"  l_nimpid:  %d\n"
		"  l_impoff:  %d\n"
		"  l_stlen:   %d\n"
		"  l_stoff:   %d\n",
		ldr->l_version, ldr->l_nsyms,  ldr->l_nreloc, ldr->l_istlen,
		ldr->l_nimpid,  ldr->l_impoff, ldr->l_stlen,  ldr->l_stoff
	);

	printf("\nLIBPATH: (%s)\n", xcoff->ldr.impids[0].l_impidpath);
	for (i = 1; i < ldr->l_nimpid; i++) {
		printf(
			"Import ID#%d:\n"
			"  Path:   (%s)\n"
			"  Base:   (%s)\n"
			"  Member: (%s)\n",
			i,
			xcoff->ldr.impids[i].l_impidpath,
			xcoff->ldr.impids[i].l_impidbase,
			xcoff->ldr.impids[i].l_impidmem
		);
	}

	printf("\nXCOFF32 Symbol Table:\n");
	printf("IDX  Value      SecNum SymType SymClass IMPid   Name\n");
	for (i = 0; i < ldr->l_nsyms; i++) {
		st = &xcoff->ldr.symtbl[i];
		printf("%04d 0x%08x 0x%04x 0x%02x    0x%02x     0x%04x  ",
			i,
			st->l_value,
			st->l_secnum,
			st->l_symtype,
			st->l_smclass,
			st->l_ifile);

		if (st->u.s.zeroes != 0)
			printf("%.*s\n", 8, st->u.l_name);
		else {
			symname =  xcoff->buff + sec->s_scnptr + ldr->l_stoff;
			symname += st->u.s.offset;
			puts(symname);
		}
	}

	printf("\nXCOFF32 Relocation Table:\n");
	printf("Vaddr         Symndx      Type|Size    Relsect\n");
	for (i = 0; i < ldr->l_nreloc; i++) {
		rt = &xcoff->ldr.reltbl[i];
		printf("0x%08x    %08d    %02x   %02x      %04x\n",
			rt->l_vaddr,
			rt->l_symndx,
			rt->r_rtype,
			rt->r_rsize,
			rt->l_rsecnm);
	}
}

/**
 * @brief Provided the XCOFF32, read its entrypoint by reading
 * the aux header + function descriptor (stored on .data).
 *
 * The entrypoint for the .text section is located at the first
 * 4 bytes.
 *
 * @param xcoff XCOFF32 data pointer.
 *
 * @return Returns the executable's entrypoint.
 */
u32 xcoff_get_entrypoint(const struct xcoff *xcoff)
{
	struct xcoff_csec_func_desc ds = {0};
	struct xcoff_sec_hdr32 *sec;
	u32 off;

	off  = xcoff->aux.o_entry - xcoff->aux.o_data_start;
	off += xcoff->secs[xcoff->aux.o_sndata - 1].s_scnptr;
	memcpy(&ds, xcoff->buff+off, sizeof ds);
	CONV32(ds.address);
	CONV32(ds.toc_anchor);
	CONV32(ds.env_ptr);
	return ds.address;
}

/**
 *
 */
static int xcoff_read_hdrs(struct xcoff *xcoff)
{
	if (xcoff_read_auxhdr(xcoff) < 0)
		return -1;
	if (xcoff_read_all_sechdrs(xcoff) < 0)
		return -1;
	if (xcoff_read_ldrhdr(xcoff) < 0)
		return -1;

	return 0;
}

/**
 * @brief Open a given XCOFF32 executable file pointed by @p bin,
 * read its contents and to the initial validations.
 *
 * This is expected to be the first function called.
 *
 * @param bin    Path to the XCOFF32 binary file.
 * @param xcoff  Pointer to structure that will hold the all the
 *               needed data for further parsing.
 *
 * @return Returns 0 if success, a negative number otherwise.
 */
int xcoff_open(const char *bin, struct xcoff *xcoff)
{
	int ret;
	struct stat st = {0};

	ret = -1;

	if (!xcoff)
		return ret;

	xcoff->fd = open(bin, O_RDONLY);
	if (xcoff->fd < 0) {
		warn("Unable to open file!\n");
		return ret;
	}

	fstat(xcoff->fd, &st);
	xcoff->buff = mmap(0, st.st_size, PROT_READ, MAP_PRIVATE, xcoff->fd, 0);
	if (xcoff->buff == MAP_FAILED) {
		warn("Unable to mmap xcoff file!\n");
		return ret;
	}

	xcoff->file_size = st.st_size;
	if (xcoff_read_filehdr(xcoff) < 0) {
		warn("Unable to read file hdr!\n");
		return ret;
	}

	if (xcoff->hdr.f_magic != XCOFFF32_MAGIC)
		warn("Binary file (%s) is not an XCOFF32!!!\n", bin);

	if (xcoff_read_hdrs(xcoff) < 0)
		return ret;

	return 0;
}

/**
 * @brief Deallocate all data saved in @p xcoff
 */
void xcoff_close(const struct xcoff *xcoff)
{
	if (!xcoff)
		return;
	if (xcoff->buff) {
		munmap(xcoff->buff, xcoff->file_size);
		close(xcoff->fd);
	}
}
