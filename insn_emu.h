#ifndef INSN_EMU_H
#define INSN_EMU_H

#define INSN_DEBUG

#ifdef INSN_DEBUG
#define INSN(...) \
 do { \
   fprintf(stderr, "[insn_emu] " __VA_ARGS__); \
 } while (0)
#else
#define INSN(...)
#endif

extern void insn_emu_init(uc_engine *uc);

#endif /* INSN_EMU_H. */
