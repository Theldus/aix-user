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
      fprintf(stderr, "TRACE (%08x) %s(", trace_pc - 4, sys); \
      fprintf(stderr, __VA_ARGS__); \
      fprintf(stderr, ") = 0x%x\n", ret); \
    } \
  } while(0)

extern void syscalls_init(uc_engine *uc);
extern u32 syscall_register(const char *sym_name);

/* GPRs. */
extern u32 read_gpr(u32 gpr);
extern void write_gpr(u32 gpr, u32 val);
extern void write_ret_value(u32 val);

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
extern int aix_klseek(uc_engine *uc);
extern int aix_lseek(uc_engine *uc);
extern int aix_getdirent64(uc_engine *uc);
extern int aix_mntctl(uc_engine *uc);
extern int aix_sys_parm(uc_engine *uc);
extern int aix__getpid(uc_engine *uc);
extern int aix__getppid(uc_engine *uc);
extern int aix__getpgrp(uc_engine *uc);
extern int aix_access(uc_engine *uc);
extern int aix_unlink(uc_engine *uc);
extern int aix_rmdir(uc_engine *uc);
extern int aix_accessx(uc_engine *uc);
extern int aix_times(uc_engine *uc);
extern int aix_appgetrlimit(uc_engine *uc);
extern int aix_getrlimit64(uc_engine *uc);
extern int aix_chmod(uc_engine *uc);
extern int aix_umask(uc_engine *uc);
extern int aix_chown(uc_engine *uc);
extern int aix_chdir(uc_engine *uc);
extern int aix_fchdir(uc_engine *uc);
extern int aix_uname(uc_engine *uc);
extern int aix_unamex(uc_engine *uc);
extern int aix_kill(uc_engine *uc);
extern int aix__nsleep(uc_engine *uc);
extern int aix__clock_nanosleep(uc_engine *uc);
extern int aix_truncate(uc_engine *uc);
extern int aix_ktruncate(uc_engine *uc);
extern int aix_ftruncate(uc_engine *uc);
extern int aix_kftruncate(uc_engine *uc);
extern int aix_mmap(uc_engine *uc);
extern int aix_kmmap(uc_engine *uc);
extern int aix_munmap(uc_engine *uc);
extern int aix_kpread(uc_engine *uc);
extern int aix_kpwrite(uc_engine *uc);
extern int aix_fchmod(uc_engine *uc);
extern int aix_fchown(uc_engine *uc);
extern int aix_shmat(uc_engine *uc);
extern int aix_shmdt(uc_engine *uc);
extern int aix_pipe(uc_engine *uc);
extern int aix_kfork(uc_engine *uc);
extern int aix_kwaitpid(uc_engine *uc);
extern int aix_kwaitpid64(uc_engine *uc);

#endif /* SYSCALLS_H. */
