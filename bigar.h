/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025
 */

#ifndef BIGAR_H
#define BIGAR_H

/* AIX/big-ar implementation. */

#include "util.h"

#define AMAGICBIG "<bigaf>\n"
#define AMAGICLEN 8

/* File header. */
struct ar_fl_hdr {
	char fl_magic[AMAGICLEN]; /* Magic.                            */
	char fl_memoff[20];       /* Offset to member table.           */
	char fl_gstoff[20];       /* Offset to global symbol table.    */
	char fl_gst64off[20];     /* Offset global symbol table for 64-bit
	                             objects. */
	char fl_fstmoff[20];      /* Offset to first archive member.   */
	char fl_lstmoff[20];      /* Offset to last archive member.    */
	char fl_freeoff[20];      /* Offset to first mem on free list. */
};

/* In-memory file header. */
struct ar_fl_hdr_mem {
	u64 memoff;       /* Offset to member table.           */
	u64 gstoff;       /* Offset to global symbol table.    */
	u64 gst64off;     /* Offset global symbol table for 64-bit
	                     objects. */
	u64 fstmoff;      /* Offset to first archive member.   */
	u64 lstmoff;      /* Offset to last archive member.    */
	u64 freeoff;      /* Offset to first mem on free list. */
};

#define AR_MEMB_NAME 112

/**
 * Member header.
 * All members have its value ASCII-encoded in decimal, except
 * file mode, which is octal, but also ASCII-encode.
 */
#define ATRLR "`\n"
struct ar_memb_hdr {
	char ar_size[20];    /* File member. */
	char ar_nxtmem[20];  /* Next member. */
	char ar_prvmem[20];  /* Prev member. */
	char ar_date[12];    /* File date (epoch). */
	char ar_uid[12];     /* File UID.    */
	char ar_gid[12];     /* File GID.    */
	char ar_mode[12];    /* File mode.   */
	char ar_namlen[4];   /* File name length.  */
	union {
		char ar_name[2]; /* File member name. */
		char ar_trlr[2]; /* Header trailer.   */
	} _ar_name;
};

/* In-memory member header. */
struct ar_memb_hdr_mem {
	u64 size;    /* File member. */
	u64 nxtmem;  /* Next member. */
	u64 prvmem;  /* Prev member. */
	u64 date;    /* File date (epoch). */
	u32 uid;     /* File UID.    */
	u32 gid;    /* File GID.    */
	u32 mode;   /* File mode.   */
	u8  namlen; /* File name length.  */
	union {
		char name[2]; /* File member name. */
		char trlr[2]; /* Header trailer.   */
	} _ar_name;
};

/**
 * Big AR data
 */ 
struct big_ar {
	int    fd;
	char   *buff;
	size_t file_size;
	struct ar_fl_hdr_mem fl_hdr;
};

/**
 * @brief Callback function called for each iteration on members list.
 *
 * @param memb_name Buffer pointing to member name (not null terminated,
 *                  see mhdr->namlen to get its size).
 * @param memb_data Buffer pointing to member data, with size mhdr->size.
 * @param mhdr      In-memory member header, useful to retrieve member infos
 *                  such as UID, GID, size, date and etc.
 * @param data      User defined pointer.
 *
 * @return Returns a negative number to abort the iteration, a number >= 0
 * to keep iterating until the end.
 *
 * @note All buffers provided are memory-mapped and exists for the lifecycle
 * of big_ar. You still want to keep these data after data, please
 * allocate a memory for that.
 */
typedef int (*memb_hdlr_fn)(
	const char *memb_name,
	const char *memb_data,
	const struct ar_memb_hdr_mem *mdhr, void *data);

/**
 * @brief For a given string @p str of length @p len, parses the number
 * it holds and returns it.
 *
 * This is different of strtol in a few ways:
 * - Only positive numbers allowed [0,1,2...]
 * - Allows non-null terminated strings: Big-AR strings are 0x20/' '
 *   terminated.
 *
 * Similar to strtol, this also check for possible overflow.
 *
 * @param str String to be parsed.
 * @param len String length.
 * @param err Error pointer if the parsing was not successful.
 *
 * @return Returns the number parsed, or 0 if error (@p err will be set too).
 */
#define R32(str, err) r32(str, sizeof((str)), err)
static inline u32 r32(const char *str, size_t len, int *err)
{
	const char *p = str;
	size_t i;

	u32 ret = 0;
	u8  dig = 0;

	if (!str || !len || !err || *err)
		return 0;

	*err = 1;
	for (i = 0; i < len; i++, p++) {
		if (*p == ' ')
			break;
		if (!(*p >= '0' && *p <= '9'))
			return 0;
		if (ret > UINT32_MAX / 10)
			return 0; 
		dig  = *p - '0';
		ret *= 10;
		if (ret > UINT32_MAX - dig)
			return 0;
		ret += dig;
	}
	*err = 0;
	return ret;
}

/**
 * @brief For a given string @p str of length @p len, parses the number
 * it holds and returns it.
 *
 * This is a 64-bit version of r32.
 *
 * @param str String to be parsed.
 * @param len String length.
 * @param err Error pointer if the parsing was not successful.
 *
 * @return Returns the number parsed, or 0 if error (@p err will be set too).
 */
#define R64(str, err) r64(str, sizeof((str)), err)
static inline u64 r64(const char *str, size_t len, int *err)
{
	const char *p = str;
	size_t i;

	u64 ret = 0;
	u8  dig = 0;

	if (!str || !len || !err || *err)
		return 0;

	*err = 1;
	for (i = 0; i < len; i++, p++) {
		if (*p == ' ')
			break;
		if (!(*p >= '0' && *p <= '9'))
			return 0;
		if (ret > UINT64_MAX / 10)
			return 0; 
		dig  = *p - '0';
		ret *= 10;
		if (ret > UINT64_MAX - dig)
			return 0;
		ret += dig;
	}
	*err = 0;
	return ret;
}

extern int ar_open(const char *bin, struct big_ar *ar);
extern void ar_close(const struct big_ar *ar);
extern const char *
ar_extract_member(const struct big_ar *ar, const char *mname, size_t *size);
extern int ar_show_info(struct big_ar *ar);
extern int ar_iterate_members(const struct big_ar *ar, const memb_hdlr_fn fn,
	void *data);

#endif /* BIGAR_H. */
