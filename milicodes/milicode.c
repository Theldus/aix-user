/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025-2026
 */

#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include "mm.h"
#include "util.h"

#include "memcmp.h"
#include "strlen.h"
#include "memmove.h"
#include "strcmp.h"
#include "strcpy.h"
#include "strstr.h"
#include "memccpy.h"
#include "memset.h"
#include "bzero.h"
#include "fill.h"
#include "syscalls.h"

#define GENERIC_HOOK_MILI_HDLR \
	"\x4e\x80\x00\x20" /* blr */ \
	"\x60\x00\x00\x00" /* nop */

static void mili_read_tick(uc_engine *, u64, u32, void*);
static void mili_muldiv64(uc_engine *, u64, u32, void*);

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
 *
 * 32 bit:
 *   memcmp_overlay, strstr_overlay, memccpy_overlay, strcmp_overlay,
 *   bzero_overlay,  memset_overlay, strlen_overlay,  memmove_overlay,
 *   fill_overlay,   strcpy_overlay,  
 *
 * 64 bit (not implemented!):
 *   memcmp64_overlay, strstr64_overlay, memccpy64_overlay, strcmp64_overlay,
 *   bzero64_overlay,  memset64_overlay  strlen64_overlay,  fill64_overlay,
 *   strcpy64_overlay, memmove64_overlay
 *
 * My functions might not be the fastest impl possible, as I'm more concerned
 * to correctness over speed atn, but as I make progress, I plan to replace
 * them with faster versions.
 */

/* Debug logging. */
#define MC(...) \
	do { \
		if (args.trace_loader) { \
		  fprintf(stderr, "[milicode] "); \
		  fprintf(stderr, __VA_ARGS__); \
		} \
	} while (0)

/* Milicodes. */
#define MILI(n) \
  .buff=milicodes_##n##_bin,.size=sizeof(milicodes_##n##_bin)

static struct milicodes {
	u32 addr;
	u8 *buff;
	int size;
} milicodes[] = {
	{.addr = 0xd000, MILI(memcmp)},
	{.addr = 0xd400, MILI(strstr)},
	{.addr = 0xd800, MILI(memccpy)},
	{.addr = 0xdc00, MILI(strcmp)},
	{.addr = 0xe000, MILI(bzero)},
	{.addr = 0xe008, MILI(memset)},
	{.addr = 0xe600, MILI(strlen)},
	{.addr = 0xf000, MILI(memmove)},
	{.addr = 0xf800, MILI(fill)},
	{.addr = 0xfc00, MILI(strcpy)},
};

/*
 * Hook milicode
 * Sometimes there are kernel function calls that might be too big/expensive
 * do to with an 'already-baked' asm (like the milicodes above). When this
 * happen, a better stratety is to handle directly as a Unicorn hook.
 *
 * This happens for example at 0x11520, because I *need* to return a dynamic
 * value, so... I'm unable to do this without a hook.
 *
 * Other scenario happens at 0x11570, when a kernel muldiv64 is called:
 * this routine is pretty simple, but for 32-bit PPC this generates
 * roughly 5kiB of code due to GCC helpers being emitted for 64-bit
 * arithmetic.
 */
struct hook_milicode {
	u32 addr;
	void (*hndlr)(uc_engine *uc, u64 addr, u32 size, void *ud);
} hook_milicodes[] = {
	{.addr = 0x11520, mili_read_tick},
	{.addr = 0x11570, mili_muldiv64},
};

/**
 * @brief The original kernel function: "Read the current timer from HW
 * and adds an offset (boot time?)".
 *
 * Here I just ignore this offset and returns the current Epoch
 * at nanosecond scale. This works fine because previously I
 * set the Xfreq/Xfrac to 1/1, so the timer value is exactly the
 * time in nanoseconds, and when libc attempts to convert, it just
 * convert back to this same value, cool isn't it?
 */
static void mili_read_tick(uc_engine *uc, u64 addr, u32 size, void *user_data)
{
	struct timespec tp;
	u64 time_nano;

	clock_gettime(CLOCK_REALTIME, &tp);
	time_nano =  tp.tv_nsec;
	time_nano += (u64)tp.tv_sec * 1000000000ULL;

	write_gpr(5, (u32)(time_nano >> 32));
	write_gpr(6, (u32)(time_nano));
}

/**
 * @brief Multiply and divide with 64-bit intermediate result.
 *
 * Computes (value * multiplier) / divisor with 64-bit precision.
 * Avoids overflow by splitting into quotient and remainder parts.
 *
 * @param value 64-bit value to multiply and divide.
 * @param mult  32-bit multiplier.
 * @param div   32-bit divisor.
 *
 * @return Result of (value * multiplier) / divisor.
 */
static void mili_muldiv64(uc_engine *uc, u64 addr, u32 size, void *user_data)
{
	u64 value = ((u64)read_1st_arg() << 32) | read_2nd_arg();
	u32 mult  = read_3rd_arg();
	u32 div   = read_4th_arg();
	u64 quot  = value / div;
	u64 rem   = value % div;
	u64 ret   = quot * mult + (rem * mult) / div;
	write_gpr(3, (ret >> 32) & 0xFFFFFFFF);
	write_gpr(4, ret & 0xFFFFFFFF);
}

/**
 * @brief Initializes the milicode hooks part: a special-case of milicodes
 * for scenarios where a dynamic handler is better fit than an ASM.
 *
 * @param uc Unicorn context.
 */
static void milicode_hooks_init(uc_engine *uc)
{
	struct hook_milicode *hm;
	char *h_mili_base;
	uc_err  err;
	uc_hook mili;
	int i;

	if (!(h_mili_base = mm_vm2host(UNIX_MILI_ADDR)))
		errx(1, "Milicodes are not mapped?\n");

	for (i = 0; i < sizeof(hook_milicodes)/sizeof(hook_milicodes[0]); i++) {
		hm = &hook_milicodes[i];
		MC("Hook milicode #%d at: 0x%x\n", i, hook_milicodes[i].addr);

		/* Add dummy values at the expected location. */
		memcpy(
			h_mili_base + (hm->addr - UNIX_MILI_ADDR),
			GENERIC_HOOK_MILI_HDLR,
			sizeof(GENERIC_HOOK_MILI_HDLR) - 1);

		/* Add hook for the function. */
		err = uc_hook_add(uc, &mili, UC_HOOK_CODE, hm->hndlr, NULL, hm->addr,
			hm->addr);
		if (err)
			errx(1, "Failed to install HM %x, %s\n", hm->addr, uc_strerror(err));
	}
}

/**
 * Map and write all the milicode into their expected memory regions.
 * @param uc Unicorn Engine.
 */
void milicode_init(uc_engine *uc)
{
	char *h_mili_base;
	uc_err err;
	int i;

	if (!(h_mili_base = mm_vm2host(UNIX_MILI_ADDR)))
		errx(1, "Milicodes are not mapped?\n");

	for (i = 0; i < sizeof(milicodes)/sizeof(milicodes[0]); i++) {
		MC("Milicode #%d, addr=%x, len=%d\n", i, milicodes[i].addr,
			milicodes[i].size);

		memcpy(
			h_mili_base + (milicodes[i].addr - UNIX_MILI_ADDR),
			milicodes[i].buff,
			milicodes[i].size);
	}

	milicode_hooks_init(uc);
}
