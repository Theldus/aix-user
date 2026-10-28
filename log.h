/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025-2026
 */

#ifndef LOG_H
#define LOG_H

extern int log_init(const char *filename);
extern void log_close(void);
extern int log_printf(const char *fmt, ...);

#endif /* LOG_H */
