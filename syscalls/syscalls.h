/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025
 */

#ifndef SYSCALLS_H
#define SYSCALLS_H

#include "xcoff.h"
#include "util.h"
#include <unicorn/unicorn.h>

#define TRACE(sys,...) \
  do { \
    fprintf(stderr, "TRACE %s(", sys); \
    fprintf(stderr, __VA_ARGS__); \
    fprintf(stderr, ") = %d\n", ret); \
  } while(0)

extern void syscalls_init(uc_engine *uc);
extern u32 syscall_register(const char *sym_name);

/* GPRs. */
extern u32 read_gpr(u32 gpr);
extern void write_gpr(u32 gpr, u32 val);

/* Arguments. */
u32 read_1st_arg(void);
u32 read_2nd_arg(void);
u32 read_3rd_arg(void);
u32 read_4th_arg(void);
u32 read_5th_arg(void);
u32 read_6th_arg(void);
u32 read_7th_arg(void);
u32 read_8th_arg(void);

/* Syscalls signatures. */
extern int aix_kwrite(uc_engine *uc);
extern int aix__exit(uc_engine *uc);
extern int aix_kioctl(uc_engine *uc);
extern int aix_read_sysconfig(uc_engine *uc);
extern int aix___loadx(uc_engine *uc);

#endif /* SYSCALLS_H. */

