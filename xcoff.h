/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025
 */

#ifndef AIX_COFF_H
#define AIX_COFF_H

#include "util.h"

/*
 * Minimal COFF header for my tiny-AIX VM.
 * Based on:
 * https://www.ibm.com/docs/en/aix/7.2.0?topic=formats-xcoff-object-file-format
 */

#define XCOFFF32_MAGIC 0x01DF
#define XCOFFF64_MAGIC 0x01F7

/* Symbol types. */
#define	L_WEAK		0x08
#define	L_EXPORT	0x10
#define	L_ENTRY		0x20
#define	L_IMPORT	0x40

/**
 * 32-bit file header
 */
struct xcoff_file_hdr32 {
	u16 f_magic;    /* Magic number.                            */
	u16 f_nscns;    /* Number of sections.                      */
	u32 f_timdat;   /* Time and date of file creation... why??? */
	u32 f_symptr;   /* Byte offset to symbol table start. */
	u32 f_nsyms;    /* Number of entries in symbol table. */
	u16 f_opthdr;   /* Number of bytes in optional header. */
	u16 f_flags;    /* Flags... */
};

/**
 * 32-bit section header.
 */
struct xcoff_sec_hdr32 {
	u8 s_name[8];  /* 8-byte null-padded section name.                       */
	u32 s_paddr;   /* Physical address, not empty for .text, .data and .bss. */
	u32 s_vaddr;   /* Same as s_paddr. */
	u32 s_size;    /* Specifies the size (in bytes) of this section. */
	u32 s_scnptr;  /* Offset in file to raw data for section.        */
	u32 s_relptr;  /* Offset in file to relocation entries for section.  */
	u32 s_lnnoptr; /* Offset in file to line number entries for section. */
	u16 s_nreloc;  /* Number of relocation entries.     */
	u16 s_nlnno;   /* Number of line number entries.    */
	u32 s_flags;   /* Flags to define the section type. Contrary to what
	                  the docs says, it is 4-bytes, not 2!. */
};

/**
 * 32-bit Auxiliary Header.
 */
struct xcoff_aux_hdr32 {
	u16 o_mflag;       /* Flags.              */ 
	u16 o_vstamp;      /* Version.            */
	u32 o_tsize;       /* Text size in bytes. */
	u32 o_dsize;       /* Initialized data size in bytes. */
	u32 o_bsize;       /* BSS data size in bytes.         */
	u32 o_entry;       /* Entry point descriptor (virtual address) */
	u32 o_text_start;  /* Base address of text (virtual address).  */
	u32 o_data_start;  /* Base address of data (virtual address).  */
	u32 o_toc;         /* Address of TOC anchor.                   */
	u16 o_snentry;     /* Section number for entry point.          */
	u16 o_sntext;      /* Section number for .text.                */
	u16 o_sndata;      /* Section number for .data.                */
	u16 o_sntoc;       /* Section number for TOC.                  */
	u16 o_snloader;    /* Section number for loader data.          */
	u16 o_snbss;       /* Section number for .bss.                 */
	u16 o_algntext;    /* Maximum alignment for .text.             */
	u16 o_algndata;    /* Maximum alignment for .data.             */
	u8  o_modtype[2];  /* Module type field.                       */
	u8  o_cpuflag;     /* Bit flags - cpu types of objects.        */
	u8  o_cputype;     /* Reserved for CPU type.                   */
	u32 o_maxstack;    /* Maximum stack size allowed (bytes).      */
	u32 o_maxdata;     /* Maximum data size allowed (bytes).       */
	u32 o_debugger;    /* Reserved for debuggers.                  */
	u8  o_textpsize;   /* Requested text page size.                */
	u8  o_datapsize;   /* Requested data page size.                */
	u8  o_stackpsize;  /* Requested stack page size.               */
	u8  o_flags;       /* Flags and thread-local storage alignment */
	u16 o_sntdata;     /* Section number for .tdata.               */
	u16 o_sntbss;      /* Section number for .tbss.                */
};

/**
 * Control section (csec) function descriptor.
 */
struct xcoff_csec_func_desc {
	u32 address;    /* Address of executable function. */
	u32 toc_anchor; /* TOC anchor base address.        */
	u32 env_ptr;    /* Environment Pointer (??, no idea what is this). */
};

/**
 * Loader section
 */
struct xcoff_ldr_hdr32 {
	u32 l_version; /* Loader section version number.         */
	u32 l_nsyms;   /* Number of symbol table entries.        */
	u32 l_nreloc;  /* Number of relocation table entries.    */
	u32 l_istlen;  /* Length of import file ID string table. */
	u32 l_nimpid;  /* Number of import file IDs.             */
	u32 l_impoff;  /* Offset to start of import file IDs.    */
	u32 l_stlen;   /* Length of string table.         */
	u32 l_stoff;   /* Offset (from loader sec) to start of string table */
};

/**
 * Loader symbol table definition.
 */
struct xcoff_ldr_sym_tbl_hdr32 {
	union {              /* l_name or l_offset. */
		char l_name[8];
		struct {
			u32 zeroes;
			u32 offset;
		} s;
		/* EXTRA field I'm adding to hold the memory address from string
		   table, just because 'why not?', it is 8 bytes anyway. */
		const char *l_strtblname;                    
	} u;
	u32 l_value;         /* Address field.  */
	u16 l_secnum;        /* Section number. */
	u8  l_symtype;       /* Symbol type, export, import flags.          */
	u8  l_smclass;       /* Symbol storage class.                       */
	u32 l_ifile;         /* Import file ID; ordinal of import file IDs. */
	u32 l_parm;          /* Parameter type-check field.                 */
} __attribute__((packed));

/**
 * Relocation table
 * Note: The IBM's online docs are completely wrong about this structure:
 * - There is *no* l_value field
 * - l_rtype is 2 bytes, not 4!
 * - The structure have 12-bytes, not 16 as implied.
 */
struct xcoff_ldr_rel_tbl_hdr32 {
	u32 l_vaddr;  /* Virtual address field.                                 */
	u32 l_symndx; /* Loader section symbol table index of referenced item.
	               * values of 0,1,2 are ref to .text/.data/.bss. The first
	               * actual value starts at 3.                              */
	union {             /* Relocation type. */
		u16 l_rtype;
		struct {
			u8 r_rsize;
			u8 r_rtype;
		};
	};
	u16 l_rsecnm; /* Section number, 1-based.                               */
};

/**
 *
 */
union xcoff_impid {
	const char *v[3];
	struct {
		const char *l_impidpath; /* Path string, null-delimited, e.g., /usr/lib\0  */
		const char *l_impidbase; /* Base string, null-delimited. e.g., libc.a\0    */
		const char *l_impidmem;  /* Member string, null-delimited, e.g., shr.o\0   */
	} __attribute__((packed));
};

/* Section flags. */
#define STYP_TEXT    0x0020 /* Specifies an executable text (code) section.
                               A section of this type contains the executable
                               instructions of a program. */
#define STYP_DATA    0x0040 /* Specifies an initialized data section. A section
                               of this type contains the initialized data and
                               the TOC of a program. */
#define STYP_BSS     0x0080 /* Specifies an uninitialized data section.A section
                               header of this type defines the uninitialized
                               data of a program. */
#define STYP_EXCEPT  0x0100 /* Specifies an exception section. */
#define STYP_INFO    0x0200 /* Specifies a comment section.    */
#define STYP_TDATA   0x0400 /* Initialized thread-local data section.   */
#define STYP_TBSS    0x0800 /* Uninitialized thread-local data section. */
#define STYP_LOADER  0x1000 /* Loader section.                          */

/* Header sizes. */
#define XCOFF_FHDR_SIZE sizeof(struct xcoff_file_hdr32)
#define XCOFF_AHDR_SIZE sizeof(struct xcoff_aux_hdr32)
#define XCOFF_SHDR_SIZE sizeof(struct xcoff_sec_hdr32)


/**
 * XCOFF32 data
 */
struct xcoff {
	int    fd;
	const char *buff;
	size_t file_size;
	struct xcoff_file_hdr32 hdr; /* File header.      */
	struct xcoff_aux_hdr32  aux; /* Auxiliary header. */
	/* Section headers. */
	struct xcoff_sec_hdr32 secs[16]; /* All sections. */
	/* Loader. */
	struct {
		struct xcoff_ldr_hdr32 hdr;
		union xcoff_impid *impids;
		struct xcoff_ldr_sym_tbl_hdr32 *symtbl;
		struct xcoff_ldr_rel_tbl_hdr32 *reltbl;
	} ldr;
};

/* External functions. */
extern int  xcoff_read_filehdr(struct xcoff *xcoff);
extern void xcoff_print_filehdr(const struct xcoff *xcoff);
extern int  xcoff_read_auxhdr(struct xcoff *xcoff);
extern void xcoff_print_auxhdr(const struct xcoff *xcoff);
extern int  xcoff_read_auxhdr(struct xcoff *xcoff);
extern void xcoff_print_auxhdr(const struct xcoff *xcoff);
extern void xcoff_print_sechdr(const struct xcoff_sec_hdr32 *sec, int n);
extern void xcoff_print_sechdrs(const struct xcoff *xcoff);
extern int  xcoff_read_ldrhdr(struct xcoff *xcoff);
extern void xcoff_print_ldr(const struct xcoff *xcoff);
extern u32  xcoff_get_entrypoint(const struct xcoff *xcoff);
extern int xcoff_load(int fd, const char *buff, size_t size, struct xcoff *xcoff);
extern int  xcoff_open(const char *bin, struct xcoff *xcoff);
extern void xcoff_close(const struct xcoff *xcoff);

#endif /* AIX_COFF_H */
