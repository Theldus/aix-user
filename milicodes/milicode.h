/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025
 */

#ifndef MILICODE_H
#define MILICODE_H

void milicode_init(uc_engine *uc);

#endif /* MILICODE_H */
