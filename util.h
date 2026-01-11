/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025
 */

#ifndef UTIL_H
#define UTIL_H

#include <stdint.h>
#include <unicorn/unicorn.h>

struct args {
	const char *lib_path;     /* -L: library search path  */
	int trace_syscall;        /* -s: enable syscall trace */
	int trace_loader;         /* -l: enable loader/binder trace */
	int gdb_port;             /* -g: GDB server port      */
	int enable_gdb;           /* -d: enable GDB server    */
};
extern struct args args;

typedef uint8_t  u8;
typedef  int8_t  s8;
typedef uint16_t u16;
typedef  int16_t s16;
typedef uint32_t u32;
typedef  int32_t s32;
typedef uint64_t u64;
typedef  int64_t s64;

#define min(x,y) ((x)<(y)?(x):(y))
#define max(x,y) ((x)>(y)?(x):(y))

#define warn(...) fprintf(stderr, __VA_ARGS__)
#define errx(code,...) \
	do {\
		fprintf(stderr, __VA_ARGS__);\
		exit((code));\
	} while (0)

#define CONV16(field) \
    do {field = be16toh(field);} while (0)
#define CONV32(field) \
    do {field = be32toh(field);} while (0)

/**
 * From StackOverflow:
 *   https://stackoverflow.com/a/28592202
 * Credits goes to @deltamind106, thanks =)
 */
#if __BIG_ENDIAN__
#define htonll(x) (x)
#define ntohll(x) (x)
#else
#define htonll(x) (((uint64_t)htonl((x)&0xFFFFFFFF)<<32)|htonl((x) >> 32))
#define ntohll(x) (((uint64_t)ntohl((x)&0xFFFFFFFF)<<32)|ntohl((x) >> 32))
#endif

extern void register_dump(uc_engine *uc);

#endif /* UTIL_H */
