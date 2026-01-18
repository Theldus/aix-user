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
  	u32 trace_pc; \
  	if (args.trace_syscall) { \
  	  uc_reg_read(uc, UC_PPC_REG_LR, &trace_pc); \
      fprintf(stderr, "TRACE (%08x) %s(", trace_pc, sys); \
      fprintf(stderr, __VA_ARGS__); \
      fprintf(stderr, ") = 0x%x\n", ret); \
    } \
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
extern int aix_kfcntl(uc_engine *uc);
extern int aix_vmgetinfo(uc_engine *uc);
extern int aix_brk(uc_engine *uc);
extern int aix_sbrk(uc_engine *uc);
extern int aix___libc_sbrk(uc_engine *uc);
extern int aix_getuidx(uc_engine *uc);
extern int aix_getgidx(uc_engine *uc);
extern int aix_statx(uc_engine *uc);
extern int aix_kopen(uc_engine *uc);
extern int aix_close(uc_engine *uc);
extern int aix_kread(uc_engine *uc);
extern int aix_fstatx(uc_engine *uc);

#endif /* SYSCALLS_H. */

