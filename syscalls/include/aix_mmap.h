/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025-2026
 */

#ifndef AIX_MMAP_H
#define AIX_MMAP_H

/*
 * Perms.
 * These perms have the exact same values on Linux, so no need
 * to translate them.
 */
#define AIX_PROT_NONE  0x0
#define AIX_PROT_READ  0x1
#define AIX_PROT_WRITE 0x2
#define AIX_PROT_EXEC  0x4

/* Flags. */
#define AIX_MAP_FILE      0x0   /* Maps an fd into an address space.       */
#define AIX_MAP_VARIABLE  0x0   /* Selects an address if 'address' is NULL or
                                   if the chosen address cannot be mapped. */
#define AIX_MAP_SHARED    0x1   /* Shared memory.                          */
#define AIX_MAP_PRIVATE   0x2   /* Private into the process address space. */
#define AIX_MAP_ANONYMOUS 0x10  /* Standard allocation, 'malloc()'-like.   */
#define AIX_MAP_FIXED     0x100 /* Map into exact address. */

/* External declarations. */
extern int aix_do_mmap(uc_engine *uc, u32 addr, u32 len, u32 prot, u32 flgs,
	s32 fd, s64 off);
extern int aix_do_munmap(u32 addr, u32 size);
extern void aix_mmap_init(void);

#endif
