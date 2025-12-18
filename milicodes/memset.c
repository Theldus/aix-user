/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025
 */

#include <stddef.h>

/**
 * @brief Fill a memory block with a constant byte value.
 *
 * Standard C library function compiled as AIX milicode overlay.
 *
 * @param s Pointer to memory block.
 * @param c Byte value to fill (converted to unsigned char).
 * @param n Number of bytes to fill.
 * @return Pointer to the memory block.
 */
void *memset(void *s, int c, size_t n)
{
	unsigned char *p = (unsigned char *)s;
	while (n--)
		*p++ = (unsigned char)c;
	return s;
}
