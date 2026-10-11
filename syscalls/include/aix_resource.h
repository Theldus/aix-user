/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025-2026
 */

#ifndef AIX_RESOURCE_H
#define AIX_RESOURCE_H

#include "aix_time.h"

/* Limits. */
#define AIX_RLIMIT_CPU     0 /* CPU time, in ms. */
#define AIX_RLIMIT_FSIZE   1 /* Max file size.   */
#define AIX_RLIMIT_DATA    2
#define AIX_RLIMIT_STACK   3
#define AIX_RLIMIT_CORE    4
#define AIX_RLIMIT_RSS     5
#define AIX_RLIMIT_AS      6
#define AIX_RLIMIT_NOFILE  7
#define AIX_RLIMIT_THREADS 8
#define AIX_RLIMIT_NPROC   9

struct aix_rusage {
	struct aix_timeval ru_utime; /* User time used.   */
	struct aix_timeval ru_stime; /* System time used. */
	s32 ru_maxrss;   /* Maximum Resident Set Size.    */
	s32 ru_ixrss;    /* Integral Shared Memory Size.  */
	s32 ru_idrss;    /* Integral Unshared Data Size.  */
	s32 ru_isrss;    /* Integral Unshared Stack Size. */
	s32 ru_minflt;   /* Page reclaims (sft pg fault). */
	s32 ru_majflt;   /* Page reclaims (hrd pg fault). */
	s32 ru_nswap;    /* Swaps.                        */
	s32 ru_inblock;  /* Block Input Operations.       */
	s32 ru_oublock;  /* Block Output Operations.      */
	s32 ru_msgsnd;   /* IPC messages sent.            */
	s32 ru_msgrcv;   /* IPC messages received.        */
	s32 ru_nsignals; /* Signals received.             */
	s32 ru_nvcsw;    /* Voluntary Context Switches.   */
	s32 ru_nivcsw;   /* Involuntary Context Switches. */
};

struct aix_rusage64 {
	struct aix_timeval ru_utime; /* User time used.   */
	struct aix_timeval ru_stime; /* System time used. */
	s64 ru_maxrss;   /* Maximum Resident Set Size.    */
	s64 ru_ixrss;    /* Integral Shared Memory Size.  */
	s64 ru_idrss;    /* Integral Unshared Data Size.  */
	s64 ru_isrss;    /* Integral Unshared Stack Size. */
	s64 ru_minflt;   /* Page reclaims (sft pg fault). */
	s64 ru_majflt;   /* Page reclaims (hrd pg fault). */
	s64 ru_nswap;    /* Swaps.                        */
	s64 ru_inblock;  /* Block Input Operations.       */
	s64 ru_oublock;  /* Block Output Operations.      */
	s64 ru_msgsnd;   /* IPC messages sent.            */
	s64 ru_msgrcv;   /* IPC messages received.        */
	s64 ru_nsignals; /* Signals received.             */
	s64 ru_nvcsw;    /* Voluntary Context Switches.   */
	s64 ru_nivcsw;   /* Involuntary Context Switches. */
};

struct aix_rlimit32 {
	u32 rlim_cur;
	u32 rlim_max;
};
struct aix_rlimit64 {
	u64 rlim_cur;
	u64 rlim_max;
};

static inline int resource_aix2linux(int resource) {
	int l_res;
	switch (resource) {
		case AIX_RLIMIT_CPU:    l_res = RLIMIT_CPU;    break;
		case AIX_RLIMIT_FSIZE:  l_res = RLIMIT_FSIZE;  break;
		case AIX_RLIMIT_DATA:   l_res = RLIMIT_DATA;   break;
		case AIX_RLIMIT_STACK:  l_res = RLIMIT_STACK;  break;
		case AIX_RLIMIT_CORE:   l_res = RLIMIT_CORE;   break;
		case AIX_RLIMIT_RSS:    l_res = RLIMIT_RSS;    break;
		case AIX_RLIMIT_AS:     l_res = RLIMIT_AS;     break;
		case AIX_RLIMIT_NOFILE: l_res = RLIMIT_NOFILE; break;
		case AIX_RLIMIT_NPROC:  l_res = RLIMIT_NPROC;  break;
		default:
			return -1;
	}
	return l_res;
}

#endif
