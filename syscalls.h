/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025
 */

#ifndef SYSCALLS_H
#define SYSCALLS_H

#include "util.h"
#include <unicorn/unicorn.h>

extern u32 create_unix_descriptor(const char *sym_name);
extern void syscalls_init(uc_engine *uc);

#endif /* SYSCALLS_H. */
