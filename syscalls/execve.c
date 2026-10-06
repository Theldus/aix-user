/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025-2026
 */

#include <stdio.h>
#include <limits.h>
#include <unistd.h>

#include "xcoff.h"
#include "syscalls.h"
#include "unix.h"
#include "aix_errno.h"
#include "mm.h"
#include "vfs.h"

#include <string.h>

/**
 * @brief Converts an userspace AIX array provided by @p array, into a
 * readable host array. Mainly used to convert argv/envp.
 *
 * @param array Userspace/VM array, ended with NUL.
 * @param size  (Nullable) output pointer that is updated with the array
 *              size, excluding the NUL itself.
 *
 * @return On success, returns a readable char** array, NULL otherwise.
 */
static char **conv_vm_strarray(u32 array, int *size)
{
	char **tmp = NULL;
	char **arr = NULL;
	u32 dword, idx;
	int err;

	idx = 0;

	while (1) {
		dword = mm_read_u32(array + (idx * 4), &err);
		if (err)
			goto err;
		tmp   = realloc(arr, ((idx + 1) * sizeof(char*)));
		if (!tmp)
			goto err;
		arr = tmp;
		if (!dword) {
			arr[idx] = NULL; /* NUL found, we must stop. */
			break;
		}
		arr[idx] = mm_vm2host(dword);
		if (!arr[idx])
			goto err;
		idx++;
	}
	if (size)
		*size = idx;
	return arr;
err:
	free(arr);
	return NULL;
}

/**
 * @brief If a native call to Linux's execve(2) failed, we then check if it is
 * an XCOFF file, have a valid AIX/PPC magic number and headers, and only if
 * so, we call aix-user again passing the binary as parameter.
 *
 * @param path   Full path to be execve'd
 * @param h_argv Argument list pointer, will be relocated to acomodate the
 *               'aix-user' additional parameter.
 * @param envp   Environment pointer.
 *
 * Returns -1 if failure, do not return otherwise.
 */
static int
aix_user_execve(const char *path, const char ***h_argv, int argc, char **const envp)
{
	char aix_path[1024 + 1] = {0};
	struct xcoff xcoff = {0};
	const char **argv;
	ssize_t rl;
	int ret;

	/*
	 * The file exists, we just need to _attempt_ to open it: if success,
	 * we can (attempt) to emulate it.
	 */
	if (xcoff_open(path, &xcoff) < 0) {
		errno = ENOEXEC;
		xcoff_close(&xcoff);
		return -1;
	}
	xcoff_close(&xcoff);

	/* Get the full path for own VM. */
	if ((rl = readlink("/proc/self/exe", aix_path, sizeof aix_path)) < 0)
		return -1;
	if (rl == sizeof aix_path) /* not perfect, but meh. */
		return -1;

	/* Increase by 2 the argv, add 'aix-user' as the first entry.
	 * We increase by 2 because 'argc' do not consider the NUL entry, and
	 * we add the 'aix-user' and 'fullpath' as the first and second parameter,
	 * such as:
	 *   aix-user /full/path first_arg oldargs ... NUL
	 *                         ^-- prog name
	 *                                   ^-- argc refers to this
	 * The second arg, will be replaced: instead of the short name, we will
	 * put the full path name, so aix-user can find it.
	 */
	argv = realloc(*h_argv, (argc + 2) * sizeof(char*));
	if (!argv)
		return -1;
	*h_argv = argv;

	/* Call execve with changed args. */
	memmove(argv+1, argv, (argc + 1) * sizeof(char *));
	argv[0] = "aix-user";
	argv[1] = path;  /* replace short name with full path. */

	ret = execve(aix_path, (char *const*)argv, envp);
	return ret;
}

/**
 * @brief execve(2) syscall handler.
 *
 * Handles the AIX execve syscall.
 * This should be aligned with the POSIX execve(2).
 *
 * AIX calling convention:
 *   r3 = path
 *   r4 = argv
 *   r5 = envp
 *
 * Return value (in r3):
 *   If success returns 0, otherwise, -1 with errno set.
 */
int aix_execve(uc_engine *uc)
{
	char vfs_path[PATH_MAX+1];
	char *h_path  = NULL;
	char **h_argv = NULL;
	char **h_envp = NULL;
	int    h_argc = 0;
	int err;
	int ret   = -1;
	u32 path  = read_1st_arg();
	u32 argv  = read_2nd_arg();
	u32 envp  = read_3rd_arg();

	if (!path) {
		unix_set_errno(AIX_EFAULT);
		goto out;
	}

	/* Convert host buffers from VM memory. */
	if (!(h_path = mm_vm2host(path))) {
		unix_set_errno(AIX_EFAULT);
		goto out;
	}
	if (argv && !(h_argv = conv_vm_strarray(argv, &h_argc))) {
		unix_set_errno(AIX_EFAULT);
		goto out;
	}
	if (envp && !(h_envp = conv_vm_strarray(envp, NULL))) {
		unix_set_errno(AIX_EFAULT);
		goto out;
	}

	/* Convert from sysroot. */
	if (vfs_resolve(h_path, VFS_FOLLOW, vfs_path) < 0)
		goto out;

	ret = execve(vfs_path, h_argv, h_envp);
	if (ret < 0) {
		if (errno != ENOEXEC) {
			unix_set_conv_errno(errno);
			goto out;
		}
		/* A binary with ENOEXEC might mean the binary
		 * attempted to run was an AIX binary, and if so, we
		 * attempt to run this binary via aix-user.
		 */
		ret = aix_user_execve(vfs_path, (const char***)&h_argv, h_argc, h_envp);
		if (ret < 0)
			unix_set_conv_errno(errno);
	}

out:
	free(h_argv);
	free(h_envp);
	TRACE("execve", "\"%s\", %x, %x", h_path, argv, envp);
	return ret;
}
