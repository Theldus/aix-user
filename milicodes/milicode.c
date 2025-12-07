/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025
 */

#include "mm.h"
#include "util.h"

#include "memcmp.h"
#include "strlen.h"
#include "memmove.h"
#include "strcmp.h"
#include "strcpy.h"

/**
 * Milicode:
 * Quoting 'AIX Version 7.2: Assembler Language Reference:
 *   The milicode routines contain machine-dependent and performance-critical
 *   functions.
 *   
 *   All of the fixed-point divide instructions, and some of the multiply
 *   instructions, are different for POWER ®family and PowerPC ®. To allow
 *   programs to run on systems based on either architecture, a set of special
 *   routines is provided by the operating system. These are called milicode
 *   routines and contain machine-dependent and performance-critical functions.
 *   Milicode routines are located at fixed addresses in the kernel segment.
 *   
 *   These routines can be reached by a bla instruction. All milicode routines
 *   use the link register.
 *
 * To me, this is kind of absurd, to have the *kernel* to provide these
 * functions, and more: there *is* some non-documented functions that 
 * also behaves as mili-code functions and are also provided by the kernel,
 * they are:
 *   memcmp_overlay,   memcmp64_overlay,  strstr_overlay,  strstr64_overlay,
 *   memccpy_overlay,  memccpy64_overlay, strcmp_overlay,  strcmp64_overlay,
 *   bzero_overlay,    memset_overlay,    strlen_overlay,  bzero64_overlay,
 *   memset64_overlay, strlen64_overlay,  memmove_overlay, memmove64_overlay,
 *   fill_overlay,     fill64_overlay,    strcpy_overlay,  strcpy64_overlay
 *
 * My functions might not be the fastest impl possible, as I'm more concerned
 * to correctness over speed atn, but as I make progress, I plan to replace
 * them with faster versions.
 */

/* Debug logging. */
#define DEBUG

#ifdef DEBUG
#define MC(...) \
	do { \
		fprintf(stderr, "[milicode] "); \
		fprintf(stderr, __VA_ARGS__); \
	} while (0)
#else
#define MC(...)
#endif

/* Milicodes. */
#define MILI(n) \
  .buff=milicodes_##n##_bin,.size=sizeof(milicodes_##n##_bin)

static struct milicodes {
	u32 addr;
	u8 *buff;
	int size;
} milicodes[] = {
	{.addr = 0xd000, MILI(memcmp)},
	{.addr = 0xdc00, MILI(strcmp)},
	{.addr = 0xe600, MILI(strlen)},
	{.addr = 0xf000, MILI(memmove)},
	{.addr = 0xfc00, MILI(strcpy)},
};

/**
 * Map and write all the milicode into their expected memory regions.
 * @param uc Unicorn Engine.
 */
void milicode_init(uc_engine *uc)
{
	uc_err err;
	int i;

	/* Map memory range for our AIX milicodes. */
	err = uc_mem_map(uc, UNIX_MILI_ADDR, UNIX_MILI_SIZE, UC_PROT_ALL);
	if (err)
		errx(1, "Unable to map milicode area!\n");

	for (i = 0; i < sizeof(milicodes)/sizeof(milicodes[0]); i++) {
		MC("Milicode #%d, addr=%x, len=%d\n", i, milicodes[i].addr,
			milicodes[i].size);
		
		err = uc_mem_write(uc, milicodes[i].addr, milicodes[i].buff,
			               milicodes[i].size);
		if (err)
			errx(1, "Unable to map current milicode, aborting...!\n");
	}
}
