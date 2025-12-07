/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025
 */

#include <stddef.h>

void *memset(void *s, int c, size_t n)
{
	unsigned char *p = (unsigned char *)s;
	while (n--)
		*p++ = (unsigned char)c;
	return s;
}
