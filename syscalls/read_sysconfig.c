/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025
 */

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include "syscalls.h"

/**
 * @brief read_sysconfig
 *
 * I'm not entirely sure what this syscall does as it seems to be
 * AIX-only I'm unable to find proper docs regarding it.
 *
 * _Maybe_ it is related to the AIX's sysconfig() function [1], but
 * I still do not know the syscall return.
 *
 * So by the time being, this is just a stub.
 *
 * AIX calling convention:
 *   r3-r10: parameters
 *
 * Return value (in r3):
 *   Dont know
 *
 * [1]: https://www.ibm.com/docs/en/aix/7.2.0?topic=s-sysconfig-subroutine
 */
int aix_read_sysconfig(uc_engine *uc)
{
	((void)uc);
	u32 a01 = read_1st_arg();
	u32 a02 = read_2nd_arg();
	u32 a03 = read_3rd_arg();
	u32 a04 = read_4th_arg();
	u32 a05 = read_5th_arg();
	u32 a06 = read_6th_arg();
	u32 a07 = read_7th_arg();
	u32 a08 = read_8th_arg();
	int ret = 0;

	TRACE("read_sysconfig",
		"%x, %x, %x, %x, %x, %x, %x, %x",
		a01, a02, a03, a04, a05, a06, a07, a08);
	return ret;
}
