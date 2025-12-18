/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025
 */

#include <stdio.h>
#include "util.h"

/**/
static const int regs_to_be_read[] = {
	UC_PPC_REG_0,  UC_PPC_REG_1,  UC_PPC_REG_2,   UC_PPC_REG_3,
	UC_PPC_REG_4,  UC_PPC_REG_5,  UC_PPC_REG_6,   UC_PPC_REG_7,
	UC_PPC_REG_8,  UC_PPC_REG_9,  UC_PPC_REG_10,  UC_PPC_REG_11,
	UC_PPC_REG_12, UC_PPC_REG_13, UC_PPC_REG_14,  UC_PPC_REG_15,
   	UC_PPC_REG_16, UC_PPC_REG_17, UC_PPC_REG_18,  UC_PPC_REG_19,
   	UC_PPC_REG_20, UC_PPC_REG_21, UC_PPC_REG_22,  UC_PPC_REG_23,
	UC_PPC_REG_24, UC_PPC_REG_25, UC_PPC_REG_26,  UC_PPC_REG_27,
	UC_PPC_REG_28, UC_PPC_REG_29, UC_PPC_REG_30,  UC_PPC_REG_31,
	UC_PPC_REG_PC,
	UC_PPC_REG_MSR,
	UC_PPC_REG_CR,
	UC_PPC_REG_LR,
	UC_PPC_REG_CTR,
	UC_PPC_REG_XER
};

#define PPC_REGS_AMNT (sizeof(regs_to_be_read)/sizeof(int))

/**
 * @brief Dump all PowerPC general-purpose and special registers.
 *
 * Reads and displays all 32 general-purpose registers (r0-r31) plus
 * special registers (PC, MSR, CR, LR, CTR, XER) in a formatted table.
 * Used for debugging and error reporting.
 *
 * @param uc Unicorn engine instance.
 */
void register_dump(uc_engine *uc)
{
	int i;
	int j;
	void *ptr_vals[PPC_REGS_AMNT] = {0};
	
	union ppc_regs {
		u32 u32_vals[PPC_REGS_AMNT];
		u8   u8_vals[PPC_REGS_AMNT*4];
	} ppcregs = {0};

	for (i = 0; i < PPC_REGS_AMNT; i++)
		ptr_vals[i] = &ppcregs.u32_vals[i];

	if (uc_reg_read_batch(uc, regs_to_be_read, ptr_vals, PPC_REGS_AMNT) < 0) {
		warn("Unable to read GPRs...\n");
		return;
	}

	fprintf(stderr, "Register dump:\n");
	for (i = 0; i < 32; i += 4) {
		fprintf(stderr,
			"r%02d: 0x%08x   r%02d: 0x%08x   r%02d: 0x%08x   r%02d: 0x%08x\n",
			i,   ppcregs.u32_vals[i],
			i+1, ppcregs.u32_vals[i+1],
			i+2, ppcregs.u32_vals[i+2],
			i+3, ppcregs.u32_vals[i+3]);
	}

	fprintf(stderr,
		"PC:  0x%08x   CTR: 0x%08x\n"
		"MSR: 0x%08x   CR:  0x%08x   LR:  0x%08x   XER: 0x%08x\n",
		ppcregs.u32_vals[32],
		ppcregs.u32_vals[33],
		ppcregs.u32_vals[34],
		ppcregs.u32_vals[35],
		ppcregs.u32_vals[36],
		ppcregs.u32_vals[37]
	);
}
