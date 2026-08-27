/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025-2026
 */

#include <stdlib.h>
#include <unistd.h>

#include "syscalls.h"
#include "unix.h"
#include "aix_errno.h"
#include "mm.h"

/**
 * @brief pipe syscall handler.
 *
 * Handles the AIX pipe syscall, which creates a pair of fds, for
 * reading/writing.
 *
 * AIX calling convention:
 *   r3 = fds[2]  Output pipes pointer.
 *
 * Return value (in r3):
 *   Returns 0 if success, -1 otherwise (errno set).
 */
int aix_pipe(uc_engine *uc)
{
	int ret;
	int *h_pipe;
	u32  a_pipe = read_1st_arg();

	ret = -1;

	/* Fail if provided a NULL array. */
	if (!a_pipe) {
		unix_set_errno(AIX_EFAULT);
		goto out;
	}

	/* Convert host buffer from VM memory. */
	if (!(h_pipe = mm_vm2host(a_pipe))) {
		unix_set_errno(AIX_EFAULT);
		goto out;
	}

	/* Create the actual pipe. */
	ret = pipe(h_pipe);
	if (ret < 0)
		unix_set_conv_errno(errno);
	else {
		h_pipe[0] = tobe32(h_pipe[0]);
		h_pipe[1] = tobe32(h_pipe[1]);
	}
out:
	TRACE("pipe", "%x", a_pipe);
	return ret;
}
