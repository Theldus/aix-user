/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025
 */

#include <stdint.h>
#include <stddef.h>

/**
 * @brief Fill memory block with a 32-bit value, word at a time.
 *
 * AIX-specific milicode function. This is an optimized version of memset
 * that writes one word (4 bytes) at a time instead of a single byte.
 * Found in /unix as 'fill_overlay'.
 *
 * Note: Parameter order differs from memset - value is the third parameter!
 *
 * @param dst    Destination memory block.
 * @param nbytes Number of bytes to fill.
 * @param value  32-bit value to fill with.
 * @return Pointer to destination memory block.
 */
void *fill(void *dst, size_t nbytes, uint32_t value)
{
	uint8_t *p = dst;
	uint8_t b0 = (uint8_t)(value);
	uint8_t b1 = (uint8_t)(value >> 8);
	uint8_t b2 = (uint8_t)(value >> 16);
	uint8_t b3 = (uint8_t)(value >> 24);

	while (nbytes >= 4) {
		p[0] = b0;
		p[1] = b1;
		p[2] = b2;
		p[3] = b3;
		p += 4;
		nbytes -= 4;
	}

	/* Remainder */
	if (nbytes > 0) p[0] = b0;
	if (nbytes > 1) p[1] = b1;
	if (nbytes > 2) p[2] = b2;

	return dst;
}
