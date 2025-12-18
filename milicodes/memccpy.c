/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025
 */

#include <stddef.h>

/**
 * @brief Copy memory until a specific byte is found.
 *
 * Standard C library function compiled as AIX milicode overlay.
 * Copies bytes from s2 to s1, stopping after the first occurrence of c.
 *
 * @param s1 Destination memory block.
 * @param s2 Source memory block.
 * @param c  Byte value to stop at (converted to unsigned char).
 * @param n  Maximum number of bytes to copy.
 * @return Pointer to byte after c in destination, or NULL if c not found.
 */
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
