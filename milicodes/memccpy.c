/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025
 */

#include <stddef.h>

void *memccpy(void *restrict s1, const void *restrict s2, int c, size_t n)
{
	unsigned char      *dest = (unsigned char *)s1;
	const unsigned char *src = (const unsigned char *)s2;
	unsigned char         uc = (unsigned char)c;

	for (size_t i = 0; i < n; i++) {
		dest[i] = src[i];
		if (src[i] == uc)
			return &dest[i + 1];
	}

	return NULL;
}
