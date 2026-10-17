/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025-2026
 */

/*
 * Power instruction emulation helper
 *
 * AIX binaries even when built for 32-bit, there is the possibility
 * of them using newer ISA versions, not supported on 32-bit processors,
 * such as cmpb, added in PowerISA v2.05 (Power6+).
 *
 * This forces me into two options:
 * a) Use a 64-bit processor: this is the logical choice, since 64-bit
 * processors also support running 32-bit binaries. However, support
 * for PPC64 on Unicorn is quite buggy to this date (13-Dec-2025 / v2.0.4)
 * and despite trying to use a Power7 CPU, I am still not able to run
 * ISA v2.05 instructions.
 *
 * b) Use a 32-bit processor + POWERPC_EXCP_HV_EMU: When a Power CPU
 * executes a non-supported instruction, this exception is triggered
 * and there is the possibility of the OS to 'polyfill'/emulate that
 * instruction.
 *
 * Since PPC64 is (ATM) unreliable, we sadly have to go this route.
 * I honestly hope that there isn't too much insns to emulate...
 */

#include <string.h>
#include <stdio.h>
#include "mm.h"
#include "util.h"
#include "insn_emu.h"

#define POWERPC_EXCP_HV_EMU 96

/* Instruction decoder helpers */
static inline u32 get_opcode(u32 insn) {
	return (insn >> 26) & 0x3F;
}
static inline u32 get_subop(u32 insn) {
	return (insn >> 1) & 0x3FF;
}

/**
 * @brief cmpb rD, rA, rB
 * Compare bytes: for each byte position, set result to 0xFF if equal,
 * 0x00 if not.
 *
 * Pseudo:
 * for i range(1,4)
 *   res[i] = if vA[i] == vB[i] ? 0xFF : 0x00
 *
 * @param uc   Unicorn context.
 * @param insn Instruction to emulate.
 */
static int emu_cmpb(uc_engine *uc, u32 insn, u32 pc)
{
	int i;
	int result;
	u32 vA, vB;
	u8 byteA, byteB, cmp;
	u32 rA = (insn >> 21) & 0x1F;
	u32 rD = (insn >> 16) & 0x1F;
	u32 rB = (insn >> 11) & 0x1F;

	result = 0;
	uc_reg_read(uc, UC_PPC_REG_0 + rA, &vA);
	uc_reg_read(uc, UC_PPC_REG_0 + rB, &vB);

	/* Compare each byte */
	for (i = 0; i < 4; i++) {
		byteA   = (vA >> (i * 8)) & 0xFF;
		byteB   = (vB >> (i * 8)) & 0xFF;
		cmp     = (byteA == byteB) ? 0xFF : 0x00;
		result |= (cmp << (i * 8));
	}

	uc_reg_write(uc, UC_PPC_REG_0 + rD, &result);
	INSN("(%08x) cmpb(r%d,r%d,r%d) = %08x\n", pc,rD,rA,rB,result);
	return 0;
}

/**
 * @brief fcfid FRT,FRB  // fcfids FRT,FRB
 * Floating Convert From Integer Doubleword: convert 64-bit signed
 * integer in FRB to double/single-precision float and store in FRT.
 *
 * @param uc   Unicorn context.
 * @param insn Instruction to emulate.
 * @param pc   Program counter.
 *
 * @note The PowerISA v2.04/v2.06 states that these registers are also
 * affected, i'm not touching any of them her:
 *   FPRF FR FI
 *   FX XX
 *   CR1
 *
 * fcfid:  Added at PowerISA v2.04
 * fcfids: Added at PowerISA v2.06
 */
static int do_fcfid_fcfids(uc_engine *uc, u32 insn, u32 pc, int single)
{
	u32 frt = (insn >> 21) & 0x1F;
	u32 frb = (insn >> 11) & 0x1F;
	u64 ival;
	double result;

	uc_reg_read(uc, UC_PPC_REG_FPR0 + frb, &ival);
	if (single) result = (double)(float)(int64_t)ival;
	else        result = (double)(int64_t)ival;
	uc_reg_write(uc, UC_PPC_REG_FPR0 + frt, &result);

	if (!single) INSN("(%08x) fcfid(f%d,f%d)  = %f\n", pc,frt,frb,result);
	else         INSN("(%08x) fcfids(f%d,f%d) = %f\n", pc,frt,frb,result);
	return 0;
}

/* Emulate fcfid. */
static int emu_fcfid(uc_engine *uc, u32 insn, u32 pc) {
	return do_fcfid_fcfids(uc, insn, pc, 0);
}

/* Emulate fcfids. */
static int emu_fcfids(uc_engine *uc, u32 insn, u32 pc) {
	return do_fcfid_fcfids(uc, insn, pc, 1);
}

/**
 * Load (zero/sign-extended) the contents of the memory of rB+rA
 * into the floating-point register FRT.
 *  0x7c004eee:
 *      26     21     16     11
 *  (31)    (FRT)  (RA)   (RB)
 *  011111  00000  00000  01001  1101110111 0
 *  lfiwzx  f0     0      9
 *
 * Or:
 *   EA  = (rA ? gpr[rA] : 0) + gpr[rB];
 *   FRTn = Zero/Sign-Extend ( MEM[EA, 4] )
 *
 * @note
 *   lfiwzx: Seems to be added at the PowerISA v2.06
 *   lfiwax: Seems to be added at v2.05.
 */
static int do_lfiwzx_lfiwax(uc_engine *uc, u32 insn, u32 pc, int sign)
{
	u32 frt = (insn >> 21) & 0x1F;
	u32 rA  = (insn >> 16) & 0x1F;
	u32 rB  = (insn >> 11) & 0x1F;
	u32 b, ea, rB_v, mem;
	u64 frt_v;

	/* b equals 0 if rA is 0, otherwise, b is the rA value, */
	b = 0;
	if (rA)
		uc_reg_read(uc, UC_PPC_REG_0 + rA, &b);
	uc_reg_read(uc, UC_PPC_REG_0 + rB, &rB_v);

	ea    = b + rB_v;
	uc_mem_read(uc, ea, &mem, 4);
	mem   = frombe32(mem);

	if (!sign) frt_v = (u64)mem;
	else       frt_v = (u64)(s64)(s32)mem; /* EXTS(MEM(EA, 4)). */

	uc_reg_write(uc, UC_PPC_REG_FPR0 + frt, &frt_v);
	if (!sign)
		INSN("(%08x) lfiwzx(f%d,%u,%u) = %" PRIx64"\n", pc,frt,rA,rB,frt_v);
	else
		INSN("(%08x) lfiwax(f%d,%u,%u) = %" PRIx64"\n", pc,frt,rA,rB,frt_v);
	return 0;
}

/* Emulate lfiwzx. */
static int emu_lfiwzx(uc_engine *uc, u32 insn, u32 pc) {
	return do_lfiwzx_lfiwax(uc, insn, pc, 0);
}
/* Emulate lfiwax. */
static int emu_lfiwax(uc_engine *uc, u32 insn, u32 pc) {
	return do_lfiwzx_lfiwax(uc, insn, pc, 1);
}

/**
 * Counts the amount of set bits in rS and saves into rA.
 *      26     21     16     11
 *  (31)     (RS)   (RA)   ////
 *  011111  00110  00110  00000  101111010 0
 *  popcntw  r6     r6
 *
 * Or: rA = popcnt(rS)
 *
 * @note popcntw seems to be added at PowerISA v2.06
 */
static int emu_popcntw(uc_engine *uc, u32 insn, u32 pc)
{
	u32 rA  = (insn >> 16) & 0x1F;
	u32 rS  = (insn >> 21) & 0x1F;
	u32 rS_v;

	uc_reg_read(uc, UC_PPC_REG_0 + rS, &rS_v);
	rS_v = __builtin_popcount(rS_v);
	uc_reg_write(uc, UC_PPC_REG_0 + rA, &rS_v);

	INSN("(%08x) popcntw(r%d,r%d) = %x\n", pc,rS,rA,rS_v);
	return 0;
}

/* Instruction handlers. */
typedef int (*insn_handler)(uc_engine *, u32, u32);
struct insns_handlers {
	u32 opcode;
	u32 subop;
	insn_handler fn;
} hndlers[] = {
	{.opcode = 31, .subop = 378, .fn = emu_popcntw},
	{.opcode = 31, .subop = 508, .fn = emu_cmpb},
	{.opcode = 31, .subop = 855, .fn = emu_lfiwax},
	{.opcode = 31, .subop = 887, .fn = emu_lfiwzx},
	{.opcode = 63, .subop = 846, .fn = emu_fcfid},
	{.opcode = 59, .subop = 846, .fn = emu_fcfids},
};

/**
 * @brief Main interrupt hook for instruction emulation
 * @param uc    Unicorn context.
 * @param intno Exception/interrup number.
 * @param user_data User defined data.
 */
static void hook_illegal_insn(uc_engine *uc, u32 intno, void *user_data)
{
	u32 pc, insn;
	size_t amnt;
	u32 opcode;
	u32 subop;
	((void)user_data);

	/* Only handle HV emulation assistance exceptions */
	if (intno != POWERPC_EXCP_HV_EMU) {
		errx(1, "Unknown exception: %d, aborting...\n", intno);
		return;
	}

	uc_reg_read(uc, UC_PPC_REG_PC, &pc);
	pc -= 4;
	uc_mem_read(uc, pc, &insn, 4);

	insn   = frombe32(insn);
	opcode = get_opcode(insn);
	subop  = get_subop(insn);

	/* Dispatch to appropriate emulator */
	amnt = sizeof(hndlers) / sizeof(hndlers[0]);
	for (size_t i = 0; i < amnt; i++) {
		if (hndlers[i].opcode == opcode && hndlers[i].subop == subop) {
			if (hndlers[i].fn(uc, insn, pc) >= 0)
				return;
			else
				break;
		}
	}

	/* If we get here, it's an unhandled instruction */
	errx(1, "Unhandled HV_EMU excep at 0x%x: 0x%08x (opcode=%d, subop=%d)\n",
		pc, insn, opcode, subop);
}

/**
 * @brief Initializes the instruction emulate code.
 * @param uc Unicorn context.
 */
void insn_emu_init(uc_engine *uc) {
	uc_hook hook;
	uc_err err;
	err = uc_hook_add(uc, &hook, UC_HOOK_INTR, hook_illegal_insn, NULL, 1, 0);
	if (err)
		errx(1, "Unable to add hook_illegal_insn!\n");
}
