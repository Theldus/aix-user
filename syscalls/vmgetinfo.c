/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025-2026
 */

#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "unix.h"
#include "syscalls.h"
#include "aix_errno.h"

/* Command values. */
#define VM_PAGE_INFO 7

/* VM_PAGE_INFO structure. */
struct vm_page_info {
	u32 addr[2];     /* IN: address to be checked. */
	u32 pagesize[2]; /* OUT: page size of the address above. */
} pg_info;

/**
 * @brief vmgetinfo - Retrieves Virtual Memory Manager (VMM) information
 *
 * AIX function signature:
 *   #include <sys/vminfo.h>
 *   int vmgetinfo(void *out, int command, int arg)
 *
 * This syscall sets/gets *many* informations regarding the Virtual Memory
 * on AIX, so despite the good documentation (see [1] and 'man vmgetinfo'),
 * due to its complexity, I am *not* implementing everything on this syscall.
 *
 * New features will be added on demand.
 * Currently supports only:
 * - VM_PAGE_INFO
 *
 * AIX calling convention:
 *   r3: out buffer
 *   r4: command
 *   r5: additional parameter, depends on command
 *
 * Return value (in r3):
 *   -1 if error, <some positive value> otherwise.
 *
 * [1]: https://www.ibm.com/docs/en/aix/7.2.0?topic=v-vmgetinfo-subroutine
 */
int aix_vmgetinfo(uc_engine *uc)
{
	u32 out = read_1st_arg();
	u32 cmd = read_2nd_arg();
	u32 add = read_3rd_arg();
	int ret = 0;

	if (cmd != VM_PAGE_INFO) {
		ret = -1;
		unix_set_errno(AIX_EINVAL);
		goto out;
	}

	if (uc_mem_read(uc, out, &pg_info, sizeof pg_info)) {
		ret = -1;
		unix_set_errno(AIX_EINVAL);
		goto out;
	}

	pg_info.pagesize[1] = htonl(4096);
	uc_mem_write(uc, out, &pg_info, sizeof pg_info);
out:
	TRACE("vmgetinfo", "0x%x, %d, %d", out, cmd, add);
	return ret;
}
