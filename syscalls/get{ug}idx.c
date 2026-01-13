/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025-2026
 */

#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include "syscalls.h"
#include "unix.h"
#include "aix_errno.h"

#define	AIX_ID_EFFECTIVE 1
#define	AIX_ID_REAL      2
#define	AIX_ID_SAVED     4
#define	AIX_ID_LOGIN     8

/**
 * @brief getuidx syscall handler.
 *
 * Gets the real or effective user ID of the current process.
 *
 * AIX calling convention:
 *   r3 = type
 *
 * Return value (in r3):
 *   Returns the requested ID or -1 if an invalid ID type was requested.
 */
int aix_getuidx(uc_engine *uc)
{
	uid_t ruid, euid, suid;
	u32 type = read_1st_arg();
	int ret  = -1;

	getresuid(&ruid, &euid, &suid);
	switch (type) {
		case AIX_ID_EFFECTIVE:
			ret = euid;
			break;
		case AIX_ID_REAL:
			ret = ruid;
			break;
		case AIX_ID_SAVED:
			ret = suid;
			break;
		/*
		 * There's no 'Login User ID' on Linux, so I will just return EUID
		 * instead.
		 */
		case AIX_ID_LOGIN:
			ret = euid;
			break;
		
		default:
			unix_set_errno(AIX_EINVAL);
			break;
	}

	TRACE("getuidx", "%d", type);
	return ret;
}

/**
 * @brief getgidx syscall handler.
 *
 * Gets the real or effective group ID of the current process.
 *
 * AIX calling convention:
 *   r3 = type
 *
 * NOTE: Contrary to 'getuidx', there is *no* man-page for getgidx,
 * so I'm assuming the behavior is analogous.
 *
 * Return value (in r3):
 *   Returns the requested ID or -1 if an invalid ID type was requested.
 */
int aix_getgidx(uc_engine *uc)
{
	uid_t rgid, egid, sgid;
	u32 type = read_1st_arg();
	int ret  = -1;

	getresgid(&rgid, &egid, &sgid);
	switch (type) {
		case AIX_ID_EFFECTIVE:
			ret = egid;
			break;
		case AIX_ID_REAL:
			ret = rgid;
			break;
		case AIX_ID_SAVED:
			ret = sgid;
			break;
		case AIX_ID_LOGIN:
			ret = egid; /* Same behavior as getuidx. */
			break;
		
		default:
			unix_set_errno(AIX_EINVAL);
			break;
	}

	TRACE("getgidx", "%d", type);
	return ret;
}
