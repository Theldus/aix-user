/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025
 */

#include <stddef.h>

/**
 * @brief Locate a substring within a string.
 *
 * Standard C library function compiled as AIX milicode overlay.
 *
 * @param s1 String to search in.
 * @param s2 Substring to search for.
 * @return Pointer to first occurrence of s2 in s1, or NULL if not found.
 */
char *strstr(const char *s1, const char *s2)
{
	const char *p1 = s1;
	const char *p2;

	while (*s1) {
		p2 = s2;

		while (*p2 && (*p1 == *p2)) {
			++p1;
			++p2;
		}

		if (!*p2)
			return (char *)s1;

		s1++;
		p1 = s1;
	}
	return NULL;
}
