/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025
 */

/**
 * @brief Compare two strings lexicographically.
 *
 * Standard C library function compiled as AIX milicode overlay.
 *
 * @param s1 First null-terminated string.
 * @param s2 Second null-terminated string.
 * @return Negative if s1 < s2, zero if s1 == s2, positive if s1 > s2.
 */
int strcmp(const char *s1, const char *s2)
{
	while ((*s1) && (*s1 == *s2)) {
		s1++;
		s2++;
	}
	return (*(unsigned char*)s1 - *(unsigned char*)s2);
}
