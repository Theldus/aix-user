/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025
 */

/* Based on PDCLib. */
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
