/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025
 */

#ifndef UTIL_H
#define UTIL_H

#include <stdint.h>
#include <unicorn/unicorn.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef  int32_t s32;
typedef uint64_t u64;

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

extern void register_dump(uc_engine *uc);

#endif /* UTIL_H */
