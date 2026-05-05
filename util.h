/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025
 */

#ifndef UTIL_H
#define UTIL_H

#include <stdint.h>
#include <arpa/inet.h>
#include <unicorn/unicorn.h>

struct args {
	const char *lib_path;     /* -L: library search path  */
	int trace_syscall;        /* -s: enable syscall trace */
	int trace_loader;         /* -l: enable loader/binder trace */
	int trace_memory;         /* -m: enable memory subsys trace */
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

/**
 * From StackOverflow:
 *   https://stackoverflow.com/a/28592202
 * Credits goes to @deltamind106, thanks =)
 */
#if __BIG_ENDIAN__
#define tobe64(x)   (x)
#define frombe64(x) (x)
#else
#define tobe64(x)   (((uint64_t)htonl((x)&0xFFFFFFFF)<<32)|htonl((x) >> 32))
#define frombe64(x) (((uint64_t)ntohl((x)&0xFFFFFFFF)<<32)|ntohl((x) >> 32))
#endif

#define tobe32(x)   htonl((x))
#define frombe32(x) ntohl((x))
#define tobe16(x)   htons((x))
#define frombe16(x) ntohs((x))

#define CONV16(field) \
    do {field = frombe16(field);} while (0)
#define CONV32(field) \
    do {field = frombe32(field);} while (0)

extern void register_dump(uc_engine *uc);

#endif /* UTIL_H */
