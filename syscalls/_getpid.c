/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025-2026
 */

#include <unistd.h>
#include "syscalls.h"
#include "unix.h"
#include "aix_errno.h"

/**
 * @brief _getpid syscall handler.
 *
 * POSIX getpid(2) syscall handler
 *
 * Return value (in r3): process pid
 */
int aix__getpid(uc_engine *uc)
{
	int ret = getpid();
	TRACE("_getpid", " ");
	return ret;
}

/**
 * @brief _getppid syscall handler.
 *
 * POSIX getppid(2) syscall handler
 *
 * Return value (in r3): parent process pid
 */
int aix__getppid(uc_engine *uc)
{
	int ret = getppid();
	TRACE("_getppid", " ");
	return ret;
}

/**
 * @brief _getppgrp syscall handler.
 *
 * POSIX getppgrp(2) syscall handler
 *
 * Return value (in r3): group process pid
 */
int aix__getpgrp(uc_engine *uc)
{
	int ret = getpgrp();
	TRACE("_getpgrp", " ");
	return ret;
}
