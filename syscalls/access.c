/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025-2026
 */

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include "syscalls.h"
#include "unix.h"
#include "aix_errno.h"

/**
 * @brief access syscall handler.
 *
 * Handles the AIX accesss syscall.
 * This should be aligned with the POSIX access(2).
 *
 * AIX calling convention:
 *   r3 = file path
 *   r4 = mode
 *
 * Return value (in r3):
 *   If success (all perms granted), returns 0, otherwise, -1 with
 *   errno set.
 *
 * Note: [WRXF]_OK share the same values on Linux, and thus,
 * I am not translating them.
 */
int aix_access(uc_engine *uc)
{
	int ret;
	char h_path[1024] = {0};
	u32 path = read_1st_arg();
	u32 mode = read_2nd_arg();

	ret = -1;
	if (uc_mem_read(uc, path, &h_path, sizeof h_path)) {
		unix_set_errno(AIX_EFAULT);
		goto out;
	}

	ret = access(h_path, mode);
	if (ret < 0) {
		unix_set_conv_errno(errno);
		goto out;
	}

	ret = 0;
out:
	TRACE("access", "%s, 0%o", h_path, mode);
	return ret;
}

/* Who flags. */
#define ACC_SELF     0x00 /* Checks EUID + GID.      */
#define ACC_INVOKER  0x01 /* Checks RUID + GID.      */
#define ACC_OTHERS   0x08 /* Others...               */
#define ACC_ALL      0x20 /* Permited for all users. */

/* Any flags. */
#define ANY_R 0444
#define ANY_W 0222
#define ANY_X 0111

/**
 * @brief Given the requested mode at @r_mode, checks if
 * the current path permissions are valid.
 *
 * @param r_mode Requested mode to check.
 * @param who    'Who' to check perms (OTHERS/ALL)
 * @param path   Path to stat to.
 *
 * @return Returns 0 if success, have perms, -1 if not.
 *
 * @note This is as close as I can get to AIX's special
 * flags.
 */
static inline int acc_stat(u32 r_mode, u32 who, const char *path)
{
	struct stat st;
	mode_t others;
	mode_t all;

	if (stat(path, &st) < 0) {
		unix_set_conv_errno(errno);
		return -1;
	}

	if (who == ACC_OTHERS) {
		others = st.st_mode & 7;
		if ((r_mode & R_OK) && !(others & 4)) return -1;
		if ((r_mode & W_OK) && !(others & 2)) return -1;
		if ((r_mode & X_OK) && !(others & 1)) return -1;
	} else if (who == ACC_ALL) {
		all = (st.st_mode & 0x1FF);
		if ((r_mode & R_OK) && ((all & ANY_R) != ANY_R)) return -1;
		if ((r_mode & W_OK) && ((all & ANY_W) != ANY_W)) return -1;
		if ((r_mode & X_OK) && ((all & ANY_X) != ANY_X)) return -1;
	} else
		return -1;

	return 0;
}

/**
 * @brief accessx syscall handler.
 *
 * Handles the AIX accessx syscall.
 * This is an AIX-only syscall that extends the access with
 * and additional argument 'who', that refers on who
 * might have access or not to the given path.
 *
 * AIX calling convention:
 *   r3 = file path
 *   r4 = mode
 *   r5 = who
 *
 * Return value (in r3):
 *   If success (all perms granted), returns 0, otherwise, -1 with
 *   errno set.
 *
 * Note: [WRXF]_OK share the same values on Linux, and thus,
 * I am not translating them.
 */
int aix_accessx(uc_engine *uc)
{
	int ret;
	char h_path[1024] = {0};
	u32 path = read_1st_arg();
	u32 mode = read_2nd_arg();
	u32 who  = read_3rd_arg();

	ret = -1;
	if (uc_mem_read(uc, path, &h_path, sizeof h_path)) {
		unix_set_errno(AIX_EFAULT);
		goto out;
	}

	switch (who) {
		/* Trad access checks exactly this. */
		case ACC_INVOKER:
			ret = access(h_path, mode);
			if (ret < 0) {
				unix_set_conv_errno(errno);
				goto out;
			}
			break;

		/* EUID + GID. */
		case ACC_SELF:
			ret = faccessat(AT_FDCWD, h_path, mode, AT_EACCESS);
			if (ret < 0) {
				unix_set_conv_errno(errno);
				goto out;
			}
			break;

		/* Edge cases. */
		case ACC_OTHERS:
		case ACC_ALL:
			ret = acc_stat(mode, who, h_path);
			if (ret < 0) {
				unix_set_errno(AIX_EACCES);
				goto out;
			}
			break;
	}

	ret = 0;
out:
	TRACE("accessx", "%s, 0%o, %d", h_path, mode, who);
	return ret;
}
