/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025
 */

#include <stdio.h>

/**
 * @brief Compare two memory blocks byte by byte.
 *
 * Standard C library function compiled as AIX milicode overlay.
 *
 * @param s1 First memory block.
 * @param s2 Second memory block.
 * @param n Number of bytes to compare.
 * @return Negative if s1 < s2, zero if equal, positive if s1 > s2.
 */
int memcmp(const void *s1, const void *s2, size_t n)
{
	const unsigned char *p1 = (const unsigned char *) s1;
	const unsigned char *p2 = (const unsigned char *) s2;
	while (n--) {
		if (*p1 != *p2)
			return *p1 - *p2;
		p1++;
		p2++;
	}
	return 0;
}
