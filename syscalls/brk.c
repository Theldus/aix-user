/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025-2026
 */

#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>

#include "syscalls.h"
#include "unix.h"
#include "mm.h"
#include "aix_errno.h"

static int silence_trace;

/**
 * curr_brk = Current VMs virtual address break address.
  * Obs:
 * 'heap_host' holds the base address (host) for the heap region.
 * 'curr_heap' = Current host address break memory.
 */
static u32 vcurr_brk  = HEAP_ADDR;
static u32 vcurr_size = 0;  /* Nothing mapped in Unicorn until first sbrk. */

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
	s32 delta;
	int ret;

	ret = -1;
	if (addr < HEAP_ADDR) {
		unix_set_errno(AIX_ENOMEM);
		goto out;
	}

	delta = (s32)(addr - vcurr_brk);
	write_gpr(3, delta);
	silence_trace = 1;
		ret = aix_sbrk(uc);
	silence_trace = 0;

	/* brk returns 0 on success, not the old break. */
	if (ret != -1)
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
 *   The heap is reserved at init via mmap(PROT_NONE) but not mapped
 *   into Unicorn. On each sbrk call, host pages are enabled/disabled
 *   via mprotect, and the entire used portion is unmapped/remapped
 *   in Unicorn so that out-of-bounds accesses correctly fault.
 * 
 * Return value (in r3):
 *   On success, returns the previous break value.
 *   On error, -1 with errno set to ENOMEM.
 */
int aix_sbrk(uc_engine *uc)
{
	((void)uc);
	s32 incr = read_1st_arg();
	int ret  = (int)vcurr_brk;
	uc_err uerr;
	u32 new_size;

	if (incr > 0) {
		incr = ALIGN_UP(incr);

		if (vcurr_brk > UINT32_MAX - (u32)incr) {
			unix_set_errno(AIX_ENOMEM);
			ret = -1;
			goto out;
		}

		/* Enable pages on the host side. */
		if (mprotect(curr_heap, incr, PROT_READ|PROT_WRITE) < 0) {
			unix_set_errno(AIX_ENOMEM);
			ret = -1;
			goto out;
		}

		/* Unmap old heap region (skip on first call). */
		if (vcurr_size > 0) {
			if ((uerr = uc_mem_unmap(uc, HEAP_ADDR, vcurr_size)))
				errx(1, "Failed while unmapping heap region\n");
		}

		/* Map the entire used portion into Unicorn. */
		new_size = (vcurr_brk - HEAP_ADDR) + incr;
		uerr = uc_mem_map_ptr(uc, HEAP_ADDR, new_size,
			UC_PROT_READ|UC_PROT_WRITE, heap_host);
		if (uerr)
			errx(1, "Failed to remap heap into VM\n");

		curr_heap  += incr;
		vcurr_brk  += incr;
		vcurr_size  = new_size;

	}

	else if (incr < 0) {
		u32 decr = ALIGN_UP((u32)(-incr));

		/* Can't shrink below heap base. */
		if (vcurr_brk - HEAP_ADDR < decr) {
			unix_set_errno(AIX_ENOMEM);
			ret = -1;
			goto out;
		}

		/* Unmap old heap region in Unicorn. */
		if (vcurr_size > 0) {
			if ((uerr = uc_mem_unmap(uc, HEAP_ADDR, vcurr_size)))
				errx(1, "Failed while unmapping heap region\n");
		}

		curr_heap  -= decr;
		vcurr_brk  -= decr;
		new_size    = vcurr_brk - HEAP_ADDR;

		/* Release physical pages on host side. */
		mprotect(curr_heap, decr, PROT_NONE);

		/* Remap the remaining used portion (if any). */
		if (new_size > 0) {
			uerr = uc_mem_map_ptr(uc, HEAP_ADDR, new_size,
				UC_PROT_READ|UC_PROT_WRITE, heap_host);
			if (uerr)
				errx(1, "Failed to remap heap into VM\n");
		}

		vcurr_size = new_size;
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
