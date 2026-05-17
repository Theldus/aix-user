/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025-2026
 */

#include <string.h>
#include <time.h>
#include "mm.h"
#include "util.h"
#include "syscalls.h"

#define GENERIC_HOOK_MILI_HDLR \
	"\x4e\x80\x00\x20" /* blr */ \
	"\x60\x00\x00\x00" /* nop */

#define MILI_HOOK(name) \
    static void name(uc_engine *uc, u64 addr, u32 size, void *ud)
#define MILI_UNUSED() ((void)uc, (void)addr, (void)size, (void)ud)

/**
 * @brief Read a given pointer argument at a provided position
 * and returns an already-converted host address.
 *
 * @param n   Argument number.
 * @param vm  Unsigned 32-bit VM address.
 *
 * @return Returns the host-equivalent address read.
 */
static inline void *arg_ptr(int n, u32 *vm) {
	*vm = read_gpr(2 + n);
	return mm_vm2host(*vm);
}

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

/* -------------------------------------------------------------------------- */
/* libc-equivalent milicodes                                                  */
/* -------------------------------------------------------------------------- */

/* memcmp milicode: int memcmp(const void *s1, const void *s2, size_t n); */
MILI_HOOK(mili_memcmp) {
	MILI_UNUSED();
	u32 s1, s2;
	void *hs1 = arg_ptr(1, &s1);
	void *hs2 = arg_ptr(2, &s2);
	u32 n     = read_3rd_arg();
	write_ret_value(memcmp(hs1, hs2, n));
}

/* strstr milicode: char *strstr(const char *haystack, const char *needle); */
MILI_HOOK(mili_strstr) {
	MILI_UNUSED();
	u32 s1, s2;
	char *ret;
	char *hs1 = arg_ptr(1, &s1);
	char *hs2 = arg_ptr(2, &s2);
	ret = strstr(hs1, hs2);
	write_ret_value(ret ? (u32)(ret-hs1)+s1 : 0);
}

/* memccpy milicode:
 * void *memccpy(void *restrict s1, const void *restrict s2, int c, size_t n)
 */
MILI_HOOK(mili_memccpy) {
	MILI_UNUSED();
	u32  s1, s2;
	char *ret;
	char *hs1 = arg_ptr(1, &s1);
	char *hs2 = arg_ptr(2, &s2);
	u32 c = read_3rd_arg();
	u32 n = read_4th_arg();
	ret = memccpy(hs1, hs2, c, n);
	write_ret_value(ret ? (u32)(ret-hs1)+s1 : 0);
}

/* strcmp milicode: int strcmp(const char *s1, const char *s2) */
MILI_HOOK(mili_strcmp) {
	MILI_UNUSED();
	char *hs1 = mm_vm2host(read_1st_arg());
	char *hs2 = mm_vm2host(read_2nd_arg());
	write_ret_value(strcmp(hs1,hs2));
}

/* bzero milicode: void bzero(void *s, size_t n) */
MILI_HOOK(mili_bzero) {
	MILI_UNUSED();
	void *hs1 = mm_vm2host(read_1st_arg());
	u32   n   = read_2nd_arg();
	memset(hs1, 0, n);
}

/* memset milicode: void *memset(void *s, int c, size_t n); */
MILI_HOOK(mili_memset) {
	MILI_UNUSED();
	u32 s1;
	void *hs1 = arg_ptr(1, &s1);
	s32    c  = read_2nd_arg();
	u32    n  = read_3rd_arg();
	memset(hs1, c, n);
	write_ret_value(s1);
}

/* strlen milicode: size_t strlen(const char *s); */
MILI_HOOK(mili_strlen) {
	MILI_UNUSED();
	char *hs1 = mm_vm2host(read_1st_arg());
	write_ret_value(strlen(hs1));
}

/* memmove milicode: void *memmove(void *dest, const void *src, size_t n); */
MILI_HOOK(mili_memmove) {
	MILI_UNUSED();
	u32 dst, src;
	void *hd = arg_ptr(1, &dst);
	void *hs = arg_ptr(2, &src);
	memmove(hd, hs, read_3rd_arg());
	write_ret_value(dst);
}

/* memmove fill: void *fill(void *dst, size_t len, uint32_t val); */
MILI_HOOK(mili_fill) {
	MILI_UNUSED();
	u32 dst, len, val, i;
	char *hdst = arg_ptr(1, &dst);
	len = read_2nd_arg();
	val = frombe32(read_3rd_arg());

	for (i = 0; i < (len & ~3); i += 4)
		memcpy(hdst+i, &val, 4);

	memcpy(hdst + (len & ~3), &val, len & 3);
	write_ret_value(dst);
}

/* memmove strcpy: char *strcpy(char *restrict s1, const char *restrict s2); */
MILI_HOOK(mili_strcpy) {
	MILI_UNUSED();
	u32 s1, s2;
	char *hs1 = arg_ptr(1, &s1);
	char *hs2 = arg_ptr(2, &s2);
	strcpy(hs1, hs2);
	write_ret_value(s1);
}

/* -------------------------------------------------------------------------- */
/* Misc milicodes                                                             */
/* -------------------------------------------------------------------------- */

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
	/* libc milicodes. */
	{.addr = 0xd000, mili_memcmp},
	{.addr = 0xd400, mili_strstr},
	{.addr = 0xd800, mili_memccpy},
	{.addr = 0xdc00, mili_strcmp},
	{.addr = 0xe000, mili_bzero},
	{.addr = 0xe008, mili_memset},
	{.addr = 0xe600, mili_strlen},
	{.addr = 0xf000, mili_memmove},
	{.addr = 0xf800, mili_fill},
	{.addr = 0xfc00, mili_strcpy},
	/* extra 'milicodes'. */
	{.addr = 0x11520, mili_read_tick},
	{.addr = 0x11570, mili_muldiv64},
};

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
void milicode_init(uc_engine *uc) {
	milicode_hooks_init(uc);
}
