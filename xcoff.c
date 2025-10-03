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
int xcoff_read_all_sechdrs(struct xcoff *xcoff)
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
int xcoff_read_hdrs(struct xcoff *xcoff)
{
	if (xcoff_read_auxhdr(xcoff) < 0)
		return 1;
	if (xcoff_read_all_sechdrs(xcoff) < 0)
		return 1;

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

	ret = 0;
	return ret;
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
