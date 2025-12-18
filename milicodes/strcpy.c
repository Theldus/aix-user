/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025
 */

/**
 * @brief Copy a string from source to destination.
 *
 * Standard C library function compiled as AIX milicode overlay.
 *
 * @param s1 Destination buffer (must be large enough).
 * @param s2 Source null-terminated string.
 * @return Pointer to destination string.
 */
char *strcpy(char *restrict s1, const char *restrict s2) {
	for (; (*s1 = *s2); s1++, s2++);
	return s1;
}
