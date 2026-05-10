/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025-2026
 */

#ifndef AIX_TIME_H
#define AIX_TIME_H

struct aix_st_timespec {
	s32 tv_sec;
	s32 tv_nsec;
};
struct aix_timespec64 {
	u64 tv_sec;
	s32 tv_nsec;
	s32 tv_pad;
};
struct aix_timeval {
	s32 tv_sec;
	s32 tv_usec;
};

#endif
