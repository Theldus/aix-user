/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025
 */

char *strcpy(char *restrict s1, const char *restrict s2) {
	for (; (*s1 = *s2); s1++, s2++);
	return s1;
}
