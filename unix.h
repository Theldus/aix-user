/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025
 */

#ifndef UNIX_H
#define UNIX_H

#include "xcoff.h"
#include "util.h"
#include <unicorn/unicorn.h>

u32 handle_unix_imports(const struct xcoff_ldr_sym_tbl_hdr32 *cur_sym);
void unix_set_errno(u32 err);
void unix_set_conv_errno(u32 err);
void unix_init(uc_engine *uc);

/* errno and _environ. */
extern u32 vm_errno;
extern u32 vm_environ;

#endif /* UNIX_H */
