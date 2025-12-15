/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025
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
#include <arpa/inet.h>
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
 * @brief Main interrupt hook for instruction emulation
 * @param uc    Unicorn context.
 * @param intno Exception/interrup number.
 * @param user_data User defined data.
 */
static void hook_illegal_insn(uc_engine *uc, u32 intno, void *user_data)
{
	u32 pc, insn;
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

	insn   = ntohl(insn);
	opcode = get_opcode(insn);
	subop  = get_subop(insn);

	/* Dispatch to appropriate emulator */
	if (opcode == 31 && subop == 508) {
		  /* cmpb - Compare Bytes */
		if (emu_cmpb(uc, insn, pc) == 0)
			return;
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
