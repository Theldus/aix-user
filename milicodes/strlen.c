/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025
 */

#include <stdio.h>

/**
 * @brief Calculate the length of a string.
 *
 * Standard C library function compiled as AIX milicode overlay.
 *
 * @param s Pointer to null-terminated string.
 * @return Length of the string (excluding null terminator).
 */
size_t strlen(const char *s) {
	const char *a = s;
	while (*s)
		s++;
	return s - a;
}
