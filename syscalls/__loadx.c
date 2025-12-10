/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025
 */

#include <stdlib.h>
#include <unistd.h>
#include "syscalls.h"

/**
 * @brief __loadx syscall handler.
 *
 * AIX's __loadx is the spirit equivalent of dlopen() on Linux and manages
 * many dynamic-library operations, such as querying for symbols and
 * dyamically loading libraries at runtime.
 *
 * However, contrary to dlopen(), __loadx is a syscall and the kernel
 * is the one responsible for this, which in our case, is nice.
 *
 * But for the time being, I am not implementing this and I'll just
 * happily return a good '0' to signal success =).
 *
 * AIX calling convention:
 *   r3 = flag
 *   r4 = symbol_name
 *   r5 = (output) pointer to symbol's module index
 *   r6 = (output) pointer to symbol's data origin
 *   r7 = (input)  extra parameter
 *
 * Return value (in r3):
 *   0 if success, something else(?) otherwise
 */
int aix___loadx(uc_engine *uc)
{
	u32 flg     = read_1st_arg();
	u32 sname   = read_2nd_arg();
	u32 sym_idx = read_3rd_arg();
	u32 sym_org = read_4th_arg();
	u32 ext     = read_5th_arg();
	int ret     = 0;
	char s[32]  = {0};

	if (uc_mem_read(uc, sname, s, sizeof s - 1)) {
		warn("kwrite: failed to read from VM address 0x%x\n", sname);
		return -1;
	}

	TRACE("__loadx", "%x, %s, %x, %x, %x", flg,s,sym_idx,sym_org,ext);
	return ret;
}
