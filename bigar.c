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
#include <inttypes.h>
#include <unistd.h>

#include "bigar.h"

/**
 * @brief Parse an in-file member header @p hdr to an in-memory member
 * reader @p mem.
 *
 * @param hdr Source in-file member header to be parsed.
 * @param mem Target in-memory member header to be written to.
 *
 * @return Returns 0 if successfully parsed, -1 otherwise.
 */
static int
parse_member(const struct ar_memb_hdr *hdr, struct ar_memb_hdr_mem *mem)
{
	int err = 0;
	mem->size   = R64(hdr->ar_size,   &err);
	mem->nxtmem = R64(hdr->ar_nxtmem, &err);
	mem->prvmem = R64(hdr->ar_prvmem, &err);
	mem->date   = R64(hdr->ar_date,   &err);
	mem->uid    = R32(hdr->ar_uid,    &err);
	mem->gid    = R32(hdr->ar_gid,    &err);
	mem->mode   = R32(hdr->ar_mode,   &err);
	mem->namlen = R32(hdr->ar_namlen, &err);
	return err;
}

/**
 * @brief Show a single AR member.
 *
 * @param memb_name Buffer pointing to member name.
 * @param memb_data Buffer pointing to member data, with size mhdr->size.
 * @param mhdr      In-memory member header.
 * @param data      User defined pointer.
 *
 * @return Returns 0.
 */
static int member_info(
	const char *memb_name,
	const char *memb_data,
	const struct ar_memb_hdr_mem *mhdr, void *data)
{
	((void)data);
	printf(
		"Member: \n"
		"  ar_size:   %" PRId64"\n"
		"  ar_nxtmem: %" PRId64"\n"
		"  ar_prvmem: %" PRId64"\n"
		"  ar_date:   %" PRId64"\n"
		"  ar_uid:    %" PRId32"\n"
		"  ar_gid:    %" PRId32"\n"
		"  ar_mode:   %" PRId32"\n"
		"  ar_namlen: %" PRId8"\n"
		"  ar_name:   (%.*s)\n"
		"  data:      %02x %02x ...\n",
		mhdr->size,
		mhdr->nxtmem,
		mhdr->prvmem,
		mhdr->date,
		mhdr->uid,
		mhdr->gid,
		mhdr->mode,
		mhdr->namlen,
		mhdr->namlen, memb_name,
		(mhdr->size < 2) ? 0xFF : memb_data[0]&0xFF,
		(mhdr->size < 2) ? 0xFF : memb_data[1]&0xFF
	);
	return 0;
}

/**
 * @brief Iterate over all AR members from the referred @p ar. For each of them,
 * calls the callback routine @fn to handle the current member.
 *
 * @param ar   Opened AR file to be iterated.
 * @param fn   Callback function to be called over each member.
 * @param data User-defined data passed as argument to @p fn.
 *
 * @return Returns -1 if error, 0 otherwise.
 */
int ar_iterate_members(const struct big_ar *ar, const memb_hdlr_fn fn, void *data)
{
	struct ar_memb_hdr_mem mem;
	struct ar_memb_hdr hdr;
	const char *name_off;
	u64 curr_off;
	int ret;

	curr_off = ar->fl_hdr.fstmoff;

	while (curr_off != 0 && curr_off < ar->file_size) {
		memcpy(&hdr, ar->buff+curr_off, sizeof(hdr));
		if (parse_member(&hdr, &mem)) {
			warn("Unable to parse AR member!\n");
			return -1;
		}

		/* Validate name. */
		name_off  = ar->buff + curr_off + AR_MEMB_NAME;
		curr_off += AR_MEMB_NAME + mem.namlen;
		if (curr_off >= ar->file_size) {
			warn("Not enough space to read member name!\n");
			return -1;
		}

		/* Find offset to member data. */
		curr_off += (curr_off & 1);
		if (curr_off+2+mem.size > ar->file_size) {
			warn("Not enough space to read member data!\n");
			return -1;
		}

		/* Only consider non 0-length members. */
		if (mem.namlen) {
			if (fn(name_off, ar->buff+curr_off+2, &mem, data) < 0)
				break;
		}
		curr_off = mem.nxtmem;
	}
	return 0;
}

/**
 * @brief For an already opened AR file (@p ar), show its member infos.
 *
 * @param ar Opened archive.
 *
 * @return Returns 0 if success, -1 otherwise.
 */
int ar_show_info(struct big_ar *ar)
{
	if (!ar)
		return -1;

	return ar_iterate_members(ar, member_info, NULL);
}

struct member {
	const char *member_name;
	const char *buf;
	size_t size;
};

/**
 * @brief Extracts a single AR member.
 *
 * @param memb_name Buffer pointing to member name.
 * @param memb_data Buffer pointing to member data, with size mhdr->size.
 * @param mhdr      In-memory member header.
 * @param data      Member structure that holds parameters for the member
 *                  extraction.
 *
 * @return Returns 0.
 */
static int member_extract(
	const char *memb_name,
	const char *memb_data,
	const struct ar_memb_hdr_mem *mhdr, void *data)
{
	struct member *m = data;
	if (!m || !m->member_name)
		return -1; /* Abort search. */

	if (mhdr->namlen == strlen(m->member_name) &&
		!strncmp(memb_name, m->member_name, mhdr->namlen))
	{
		m->buf  = memb_data;
		m->size = mhdr->size;
		return -1; /* Found it. */
	}

	return 0; /* Keep searching. */
}

/**
 * @brief For an already opened AR file (@p ar), extract a single member,
 * referred by the name @p mname.
 *
 * @param ar    Opened archive.
 * @param mname Member name to be extracted, like 'shr.o'.
 * @param size  Pointer provided by the user, will save the member size (in
 *              bytes).
 *
 * @return Returns a constant buffer pointing to the beginning of the
 * member data.
 *
 * @note The returned pointer is a mmap'ed buffer or the archive file, and thus,
 * only valid during the life-time of @p ar. If the user wants to use the pointer
 * to have a greater life time, its their responsibility to allocate a new
 * buffer for that.
 */
const char *
ar_extract_member(const struct big_ar *ar, const char *mname, size_t *size)
{
	int ret;
	struct member m = {0};

	if (!ar || !mname || !size)
		return NULL;

	m.member_name = mname;
	ret = ar_iterate_members(ar, member_extract, &m);
	if (ret < 0 || !m.buf)
		return NULL;

	*size = m.size;
	return m.buf;
}

/**
 * @brief Read the file header for a given file @p bin, and save into the
 * the @ar structure.
 *
 * @param bin AR-file to be read.
 * @param ar  Target file to save th archive header.
 * 
 * @return Returns -1 if error, 0 otherwise.
 */
static int ar_read_filehdr(const char *bin, struct big_ar *ar)
{
	struct ar_fl_hdr      hdr;
	struct ar_fl_hdr_mem *mhdr;
	int err;
	if (!ar)
		return -1;

	err  = 0;
	mhdr = &ar->fl_hdr;
	if (ar->file_size < sizeof(hdr))
		return -1;

	memcpy(&hdr, ar->buff, sizeof(hdr));
	if (strncmp(hdr.fl_magic, AMAGICBIG, AMAGICLEN)) {
		warn("Binary file (%s) is not an AIX/big-ar file!!!\n", bin);
		return -1;
	}

	mhdr->memoff   = R64(hdr.fl_memoff, &err);
	mhdr->gstoff   = R64(hdr.fl_gstoff, &err);
	mhdr->gst64off = R64(hdr.fl_gst64off, &err);
	mhdr->fstmoff  = R64(hdr.fl_fstmoff, &err);
	mhdr->lstmoff  = R64(hdr.fl_lstmoff, &err);
	mhdr->freeoff  = R64(hdr.fl_freeoff, &err);

	if (err) {
		warn("Unable to parse all file header fields!\n");
		return -1;
	}

	return 0;
}

/**
 * @brief Open the archive file to read.
 * This must always be the very first operation while handling AR files.
 *
 * @param bin AR-file to be read.
 * @param ar  Target file to save th archive header.
 * 
 * @return Returns a negative number if error, 0 otherwise.
 */
int ar_open(const char *bin, struct big_ar *ar)
{
	int ret;
	struct stat st = {0};

	ret = -1;

	if (!ar)
		return ret;

	ar->fd = open(bin, O_RDONLY);
	if (ar->fd < 0) {
		warn("Unable to open file!\n");
		return ret;
	}

	fstat(ar->fd, &st);
	ar->buff = mmap(0, st.st_size, PROT_READ, MAP_PRIVATE, ar->fd, 0);
	if (ar->buff == MAP_FAILED) {
		warn("Unable to mmap xcoff file!\n");
		return ret;
	}

	ar->file_size = st.st_size;
	if (ar_read_filehdr(bin, ar) < 0) {
		warn("Unable to read file hdr!\n");
		return ret;
	}

	ret = 0;
	return ret;
}

/**
 * @brief Deallocate all data saved in @p ar
 */
void ar_close(const struct big_ar *ar)
{
	if (!ar)
		return;
	if (ar->buff) {
		munmap(ar->buff, ar->file_size);
		close(ar->fd);
	}
}
