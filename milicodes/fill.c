/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025
 */

#include <stdint.h>
#include <stddef.h>

/**
 * In the kernel,/unix there is the definition of a function similar to this one
 * called 'fill_overlay'. Reading its assembly, this function appears to be an
 * optimized version of memset that writes one word (4 bytes) at a time,
 * instead of a single byte.
 *
 * I wasn’t able to find calls to this function in the libc, but for
 * completeness, here is an approximate implementation of what it does.
 *
 * Note: yes, the parameters are reversed: 'value' is the 3rd parameter,
 * not the second!
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
