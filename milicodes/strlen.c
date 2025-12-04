/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025
 */

#include <stdio.h>

size_t strlen(const char *s) {
	const char *a = s;
	while (*s)
		s++;
	return s - a;
}
