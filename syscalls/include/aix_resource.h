/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025-2026
 */

#ifndef AIX_RESOURCE_H
#define AIX_RESOURCE_H

#include "aix_time.h"

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

#endif
