/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025-2026
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#define TEST(name) printf("\n[TEST] %s\n", name)
#define PASS() printf("  [+] Result: PASS\n")
#define FAIL(msg) \
  do {\
	printf("  [-] Result: FAIL: %s\n", msg); \
	exit(1); \
  } while(0)

int main(void)
{
	void *old_brk, *new_brk, *tmp;
	char *ptr;
	int ret;

	/* Test 1: sbrk(0) returns current break without changing it */
	TEST("sbrk(0) - get current break");
	old_brk = sbrk(0);
	if (old_brk == (void*)-1)
		FAIL("sbrk(0) returned -1");
	new_brk = sbrk(0);
	if (old_brk != new_brk)
		FAIL("break value changed");
	printf("  Initial break: 0x%x\n", (unsigned)old_brk);
	PASS();

	/* Test 2: sbrk with positive increment */
	TEST("sbrk(4096) - increase heap");
	old_brk = sbrk(0);
	new_brk = sbrk(4096);
	if (new_brk == (void*)-1)
		FAIL("sbrk(4096) returned -1");
	if (new_brk != old_brk)
		FAIL("sbrk didn't return old break value");
	tmp = sbrk(0);
	if (tmp != (char*)old_brk + 4096)
		FAIL("break not advanced correctly");
	printf("  Old: 0x%x, New: 0x%x\n", (unsigned)old_brk, (unsigned)tmp);
	PASS();

	/* Test 3: Write to allocated memory */
	TEST("Write to sbrk-allocated memory");
	ptr = (char*)old_brk;
	memset(ptr, 0xAA, 4096);
	if (ptr[0] != 0xAA || ptr[4095] != 0xAA)
		FAIL("memory write/read failed");
	PASS();

	/* Test 4: sbrk with negative increment (shrink) */
	TEST("sbrk(-2048) - shrink heap");
	old_brk = sbrk(0);
	new_brk = sbrk(-2048);
	if (new_brk == (void*)-1)
		FAIL("sbrk(-2048) returned -1");
	if (new_brk != old_brk)
		FAIL("sbrk didn't return old break value");
	tmp = sbrk(0);
	if (tmp != (char*)old_brk - 2048)
		FAIL("break not decreased correctly");
	printf("  Old: 0x%x, New: 0x%x\n", (unsigned)old_brk, (unsigned)tmp);
	PASS();

	/* Test 5: brk() to set absolute address */
	TEST("brk() - set absolute break address");
	old_brk = sbrk(0);
	new_brk = (char*)old_brk + 8192;
	ret = brk(new_brk);
	if (ret != 0)
		FAIL("brk() returned non-zero");
	tmp = sbrk(0);
	if (tmp != new_brk)
		FAIL("brk didn't set correct address");
	printf("  Set break to: 0x%x\n", (unsigned)tmp);
	PASS();

	/* Test 6: Large allocation via sbrk */
	TEST("Large allocation (16MB)");
	old_brk = sbrk(0);
	new_brk = sbrk(16 << 20);  /* 16 MB */
	if (new_brk == (void*)-1)
		FAIL("large sbrk failed");
	ptr = (char*)old_brk;
	ptr[0] = 0x55;
	ptr[(16 << 20) - 1] = 0x55;
	if (ptr[0] != 0x55 || ptr[(16 << 20) - 1] != 0x55)
		FAIL("large memory access failed");
	printf("  Allocated 16MB at 0x%x\n", (unsigned)old_brk);
	PASS();

	/* Test 7: malloc uses sbrk underneath */
	TEST("malloc integration test");
	char *a = malloc(1 << 20);   /* 1 MB */
	char *b = malloc(2 << 20);   /* 2 MB */
	char *c = malloc(4 << 20);   /* 4 MB */
	char *d = malloc(8 << 20);   /* 8 MB */
	if (!a || !b || !c || !d)
		FAIL("malloc returned NULL");

	/* Verify we can write to all allocations */
	a[0] = a[(1 << 20) - 1] = 1;
	b[0] = b[(2 << 20) - 1] = 2;
	c[0] = c[(4 << 20) - 1] = 3;
	d[0] = d[(8 << 20) - 1] = 4;

	printf("  malloc'ed: 0x%x 0x%x 0x%x 0x%x\n",
		   (unsigned)a, (unsigned)b,
		   (unsigned)c, (unsigned)d);
	PASS();

	/* Test 8: Error case - brk below heap start (should fail) */
	TEST("brk(0x1000) - invalid address (should fail)");
	errno = 0;
	ret = brk((void*)0x1000);
	if (ret != -1)
		FAIL("brk should have failed but returned success");
	if (errno != ENOMEM)
		FAIL("errno should be ENOMEM");
	printf("  Correctly rejected with ENOMEM\n");
	PASS();

	printf("\n=================================\n");
	printf("All tests passed!\n");
	printf("=================================\n");

	return 0;
}
