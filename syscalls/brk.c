/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025-2026
 */

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include "syscalls.h"
#include "unix.h"
#include "mm.h"

static int silence_trace;
static u32 curr_brk = HEAP_ADDR;

/**
 * @brief brk syscall handler.
 *
 * AIX calling convention:
 *   r3 = new brk address
 *
 * Return value (in r3):
 *   Returns 0 on success, -1 on error and errno is set with ENOMEM.
 */
int aix_brk(uc_engine *uc)
{
	((void)uc);
	u32 addr = read_1st_arg();
	int ret  = -1;

	/* Wrong address. */
	if (addr < HEAP_ADDR) {
		unix_set_errno(ENOMEM);
		ret = -1;
		goto out;
	}

	curr_brk = addr;
	ret = 0;
out:
	TRACE("brk", "0x%x", addr);
	return ret;
}

/**
 * @brief sbrk syscall handler.
 *
 * AIX calling convention:
 *   r3 = increment value
 *
 * Return value (in r3):
 *   On success, returns the previous break value (if increased).
 *   On error, -1 with errno set to ENOMEM
 */
int aix_sbrk(uc_engine *uc)
{
	((void)uc);
	s32 incr = read_1st_arg();
	u32 decr;
	int ret  = (int)curr_brk;

	if (incr >= 0) {
		if (curr_brk > UINT32_MAX - (u32)incr) {
			unix_set_errno(ENOMEM);
			ret = -1;
			goto out;
		}
		curr_brk += (u32)incr;
	}

	else {
		decr = (u32)(-incr);
		if (curr_brk < decr || (curr_brk-decr) < HEAP_ADDR) {
			unix_set_errno(ENOMEM);
			ret = -1;
			goto out;
		}
		curr_brk -= decr;
	}

out:
	if (!silence_trace)
		TRACE("sbrk", "%d", incr);
	return ret;
}

/**
 * @brief AIX's own sbrk helper syscall function.
 * This function receives an increment high and low (32-bit words)
 * and passes an appropriate value for sbrk.
 *
 * First of all: this *is* a syscall.
 * Second: this seems to 'aid' the calling of sbrk() in the following way:
 *   u16 flag = something...
 *   if (flag == 0)
 *     incr = (incr_high << 32) | incr_low
 *   else
 *     incr = incr_high
 *   sbrk(incr)
 *
 * My *guess* is that this flag means something like 'is_64bit_mode', because
 * if so, use the entire register (64-bit), otherwise, use the reg pair (r3/r4).
 *
 * For reference, this is the relevant part on kernel:
 *   00000000007fd0a0 <.__libc_sbrk>:
 *	  7fd0a0:   e8 a2 54 40     ld      r5,21568(r2)
 *	  7fd0a4:   78 60 07 c6     rldicr  r0,r3,32,31
 *	  7fd0a8:   88 a5 19 06     lbz     r5,6406(r5)
 *	  7fd0ac:   28 05 00 00     cmplwi  r5,0
 *	  7fd0b0:   40 82 00 0c     bne     7fd0bc <.__libc_sbrk+0x1c>
 *	  7fd0b4:   7c 03 23 78     or      r3,r0,r4
 *	  7fd0b8:   48 00 00 48     b       7fd100 <.__sbrk>
 *	  7fd0bc:   48 00 00 44     b       7fd100 <.__sbrk>
 *  
 * AIX calling convention:
 *   r3 = increment value (high-portion, usually 0)
 *   r4 = increment value (low-portion)
 *
 * Return value (in r3):
 *   Same as sbrk().
 */
int aix___libc_sbrk(uc_engine *uc)
{
	s32 incr_hi = read_1st_arg();
	s32 incr_lo = read_2nd_arg();
	int ret;

	/* Since we're emulating a 32-bit env, i'm ignoring the high
	   portion here. */
	write_gpr(3, incr_lo);
	silence_trace = 1;       /* Only works because.. single thread. */
		ret = aix_sbrk(uc);
	silence_trace = 0;
	TRACE("__libc_sbrk", "%d,%d", incr_hi, incr_lo);
	return ret;
}
