/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025-2026
 */

#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include "log.h"

static int fd_out = STDERR_FILENO;

/**
 * @brief Initializes the log to use the file pointed by
 * @p filename, or use stderr instead.
 *
 * @param filename File to be written to.
 * @return Always 0.
 */
int log_init(const char *filename) {
	if (!filename)
		return 0;
	fd_out = creat(filename, 0644);
	if (fd_out < 0) {
		fprintf(stderr, "Unable to open (%s) for log!\n", strerror(errno));
		exit(1);
	}
	atexit(log_close);
	return 0;
}

/**
 * @brief Flushes and closes the current opened log file.
 */
void log_close(void) {
	if (fd_out == STDERR_FILENO)
		return;
	fsync(fd_out);
	close(fd_out);
}

/**
 * @brief printf-style function that outputs the log at stderr or
 * the current opened file.
 *
 * @param fmt Format string.
 * @return If success, returns the number of bytes printed, NULL
 * otheriwise (errno set).
 */
int log_printf(const char *fmt, ...) {
	int ret;
	va_list ap;
	if (!fmt)
		return -1;
	va_start(ap, fmt);
	ret = vdprintf(fd_out, fmt, ap);
	va_end(ap);
	return ret;
}
