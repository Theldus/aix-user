/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025-2026
 */

#ifndef UNIX_H
#define UNIX_H

#include "xcoff.h"
#include "util.h"
#include <unicorn/unicorn.h>

u32 handle_unix_imports(const struct xcoff_ldr_sym_tbl_hdr32 *cur_sym);
void unix_set_errno(u32 err);
void unix_set_conv_errno(u32 err);
void unix_init_system_config(uc_engine *uc);
void unix_init(uc_engine *uc);

/* errno and _environ. */
extern u32 vm_errno;
extern u32 vm_environ;

/**
 * System configuration structure located somewhere at UNIX_DATA
 */
struct system_config {
	s32 arch;                   /* Processor architecture.          */
	s32 impl;                   /* Processor implementation.        */
	s32 ver;                    /* Processor version.               */
	s32 bitwidth;               /* Width (32 or 64).                */
	s32 num_cpus;               /* Number of CPUs (1=UP, n=MP).     */
	s32 cache_attr;             /* L1 cache attrs (flags).          */
	s32 icache_sz;              /* L1 instruction cache size.       */
	s32 dcache_sz;              /* L1 data cache size.              */
	s32 icache_assoc;           /* L1 icache associativity.         */
	s32 dcache_assoc;           /* L1 dcache associativity.         */
	s32 icache_blk;             /* L1 icache block size.            */
	s32 dcache_blk;             /* L1 dcache block size.            */
	s32 icache_ln;              /* L1 icache line size.             */
	s32 dcache_ln;              /* L1 dcache line size.             */
	s32 l2_cache_sz;            /* L2 cache size (0=none).          */
	s32 l2_cache_assoc;         /* L2 cache associativity.          */
	s32 tlb_attr;               /* TLB attrs (flags).               */
	s32 itlb_sz;                /* Instruction TLB entries.         */
	s32 dtlb_sz;                /* Data TLB entries.                */
	s32 itlb_assoc;             /* Instruction TLB associativity.   */
	s32 dtlb_assoc;             /* Data TLB associativity.          */
	s32 reservation_sz;         /* Reservation size.                */
	s32 priv_lock_cnt;          /* Spinlock count (supervisor).     */
	s32 prob_lock_cnt;          /* Spinlock count (problem state).  */
	s32 rtc;                    /* RTC type.                        */
	s32 virt_alias_support;     /* Hardware aliasing supported.     */
	s32 cache_congruence;       /* Page bits for cache synonym.     */
	s32 model_arch_id;          /* Model determination (arch).      */
	s32 model_impl_id;          /* Model determination (impl).      */
	s32 xint;                   /* Timebase conversion (int part).  */
	s32 xfrac;                  /* Timebase conversion (frac part). */
	s32 kern_attr;              /* Kernel attrs (flags).            */
	s64 phys_mem;               /* OS available memory (bytes).     */
	s32 slb_attr;               /* SLB attrs (flags).               */
	s32 slb_sz;                 /* SLB size (0=none).               */
	s32 orig_num_cpus;          /* Original CPU count at boot.      */
	s32 max_num_cpus;           /* Max CPUs for this AIX image.     */
	s64 max_real_addr;          /* Max real memory address + 1.     */
	s64 orig_entitled_cap;      /* Boot entitled processor cap.     */
	s64 entitled_cap;           /* Current entitled processor cap.  */
	s64 dispatch_whl;           /* Dispatch wheel period (TB).      */
	s32 cap_increment;          /* Capacity delta for change.       */
	s32 var_cap_weight;         /* Priority for idle cap distrib.   */
	s32 splpar_state;           /* SPLPAR enablement state.         */
	s32 smt_state;              /* SMT enablement state.            */
	s32 smt_thr_cnt;            /* SMT threads per physical CPU.    */
	s32 vmx_ver;                /* VMX version (RPA defined).       */
	s64 sys_lmb_sz;             /* System LMB size.                 */
	s32 num_exclusive_cpus;     /* Exclusive CPUs online.           */
	s8 err_check_lvl;           /* Kernel error check level.        */
	u8 ame_state;               /* AME status.                      */
	s8 eco_state;               /* Extended cache options.          */
	s8 pad_byte;                /* Pad to word boundary.            */
	s32 dfp_ver;                /* DFP version (RPA defined).       */
	s32 vrm_state;              /* VRM capable/enabled.             */
	s16 phys_impl;              /* Physical processor impl.         */
	s16 phys_ver;               /* Physical processor version.      */
	s32 reserved[3];            /* Reserved for future use.         */
	s32 generation_cnt;         /* Generation counter.              */
};

/**
 * system_tb_config definition
 *
 * Since this structure is not defined anywhare on AIX, this
 * definition is product of RE and certainly do not match exactly
 * the original structure.
 *
 * However, it should be enough for aix-user purposes.
 */
struct system_tb_config {
	u64 tb_epoch_ticks;    /* 00: Epoch ticks since boot time.   */
	u64 tb_tod[2];         /* 08: Time of Day? maybe sec + nsec. */
	struct {
		u32 pad1;          /* 24: Padding, 0's. (maybe)          */
		u32 freq_hertz;    /* 28: Frequency in hertz.            */
	} ns_tics_per_sec;
	struct {
		u32 flag0;         /* 32: Flag?.                         */
		u32 dummy1;        /* 36. */
		u32 dummy2;        /* 40. */
		u32 dummy3;        /* 44. */
		u32 dummy4;        /* 48. */
		u32 dummy5;        /* 52. */
		u32 kernel_help;   /* 56: If set, use kernel help. to get
		                          the time value                 */
	} tb_ns_per_tic;
};

/* System config, rtc values. */
#define RTC_POWER    1 /* Power Arch.       */
#define RTC_POWER_PC 2 /* by Power PC Arch. */
#define RTC_IA64     3 /* IA64 Arch.        */

#endif /* UNIX_H */
