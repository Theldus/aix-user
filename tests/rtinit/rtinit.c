/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025-2026
 */

#include <stdio.h>
void __attribute__ ((constructor)) my_constructor(void) {
	printf("-> Constructor called\n");
}
void __attribute__ ((destructor)) my_destructor(void) {
	printf("-> Destructor called\n");
}
int main(void) {
	printf("Main called!\n");
}
