/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025
 */

/**
 * @brief Copy memory block, handling overlapping regions correctly.
 *
 * Standard C library function compiled as AIX milicode overlay.
 * Based on PDCLib.
 *
 * @param s1 Destination memory block.
 * @param s2 Source memory block.
 * @param n Number of bytes to copy.
 * @return Pointer to destination memory block.
 */
void *memmove(void *s1, const void *s2, size_t n)
{
	char *dest      = (char *)s1;
	const char *src = (const char *)s2;

	if (dest <= src) {
		while (n--)
			*dest++ = *src++;
	} else {
		src  += n;
		dest += n;

		while (n--)
			*--dest = *--src;
	}
	return s1;
}
