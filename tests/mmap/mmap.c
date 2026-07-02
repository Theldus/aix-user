/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025-2026
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <sys/stat.h>

#define PAGE_SIZE 4096
#define ALIGN_UP(x) (((x) + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1))

#define FAIL(...) \
  do {\
	printf("  [-] Result: FAIL: "); \
	printf(__VA_ARGS__); \
	exit(1); \
  } while(0)

static int test_num;
#define SHOULD_PASS 0
#define SHOULD_FAIL 1

/**
 * Wrapper around mmap() that logs the result and optionally
 * verifies zero-fill + write-back on success.
 */
static void *
test_allocate(const char *description, int should_fail,
	void *addr, size_t length, int prot, int flags, int fd, off_t off)
{
	void *p;
	char *bytes;
	size_t real_len;
	size_t i;

	printf("\n[TEST #%d] %s\n", test_num++, description);
	printf("  addr=%p  len=%zu  prot=0x%x  flags=0x%x  fd=%d  off=%" PRId64 "\n",
		addr, length, prot, flags, fd, (int64_t)off);

	p = mmap(addr, length, prot, flags, fd, off);

	if (p == MAP_FAILED && !should_fail)
		FAIL("mmap returned MAP_FAILED: %s\n", strerror(errno));

	if (p == MAP_FAILED && should_fail) {
		printf("  -> Allocate result: [PASS] (expected failure, errno=%d: %s)\n",
			errno, strerror(errno));
		return MAP_FAILED;
	}

	if (p != MAP_FAILED && should_fail)
		FAIL("mmap succeeded but was expected to fail (ptr=%p)\n", p);

	printf("  -> Allocated at %p\n", p);

	real_len = ALIGN_UP(length);

	/* Verify zero-fill (anonymous readable mappings must be zeroed). */
	if ((flags & MAP_ANONYMOUS) && (prot & PROT_READ)) {
		bytes = p;
		for (i = 0; i < real_len; i++) {
			if (bytes[i] != 0)
				FAIL("byte at offset %zu is 0x%02x, expected 0x00\n",
					i, bytes[i]);
		}
		printf("  -> Zero-fill check: [PASS] (%zu bytes)\n", real_len);
	}

	/* If writable, verify we can write and read back a pattern. */
	if (prot & PROT_WRITE) {
		bytes = p;
		memset(bytes, 0xAB, real_len);
		for (i = 0; i < real_len; i++) {
			if ((bytes[i] & 0xFF) != 0xAB)
				FAIL("write-back check failed at offset %zu: got 0x%02x\n",
					i, bytes[i]);
		}
		printf("  -> Write-back check: [PASS] (%zu bytes)\n", real_len);
	}
	printf("  -> Allocate result: [PASS]\n");
	return p;
}

/**
 * Wrapper around munmap().
 */
static int
test_munmap(const char *description, int should_fail,
	void *addr, size_t length)
{
	int ret;

	printf("\n[TEST #%d] munmap (%s)\n", test_num++, description);
	printf("  addr=%p  len=%zu\n", addr, length);

	ret = munmap(addr, length);

	if (ret < 0 && !should_fail)
		FAIL("munmap failed: %s\n", strerror(errno));
	if (ret == 0 && should_fail)
		FAIL("munmap succeeded but was expected to fail\n");

	if (ret == 0)
		printf("  -> Munmap result: [PASS]\n");
	else
		printf("  -> Munmap result: [PASS] (expected failure, errno=%d: %s)\n",
			errno, strerror(errno));
	return ret;
}

/**
 * Create a temp file filled with a known pattern and return the fd.
 * The file is unlinked so it disappears after the test exits.
 */
static int
make_pattern_file(const char *path, size_t size, unsigned char byte)
{
	int fd;
	char *buf;

	fd = open(path, O_RDWR|O_CREAT|O_TRUNC, 0600);
	if (fd < 0)
		FAIL("open(%s): %s\n", path, strerror(errno));

	buf = malloc(size);
	if (!buf)
		FAIL("malloc(%zu): %s\n", size, strerror(errno));
	memset(buf, byte, size);

	if (write(fd, buf, size) != (ssize_t)size)
		FAIL("write(%s): %s\n", path, strerror(errno));

	free(buf);
	return fd;
}

int main(void)
{
	char *ptr1, *ptr2, *ptr3, *ptr4, *ptr5, *ptr6;
	const char *file_ro = "mmap_test_ro";
	const char *file_rw = "mmap_test_rw";
	uint64_t off64;
	int fd_ro;
	int fd_rw;
	ssize_t n;
	size_t i;
	int fd64;
	char *p64;
	char disk[4096];

	/* ================================================================
	 * Basic allocations.
	 * ================================================================ */
	ptr1 = test_allocate("First 4KiB anonymous (ptr1)", SHOULD_PASS,
		0, 4096, PROT_READ|PROT_WRITE,
		MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

	ptr2 = test_allocate("8KiB anonymous (ptr2)", SHOULD_PASS,
		0, 8192, PROT_READ|PROT_WRITE,
		MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

	ptr3 = test_allocate("Second 4KiB anonymous (ptr3)", SHOULD_PASS,
		0, 4096, PROT_READ|PROT_WRITE,
		MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

	/* ================================================================
	 * Address reuse: munmap ptr2, new alloc should land in its slot.
	 * ================================================================ */
	test_munmap("free 8KiB (ptr2)", SHOULD_PASS, ptr2, 8192);

	ptr4 = test_allocate(
		"Recycle ptr2 slot (ptr4 should land at ptr2)", SHOULD_PASS,
		0, 4096, PROT_READ|PROT_WRITE,
		MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

	if (ptr4 != ptr2)
		FAIL("expected ptr4 (%p) == ptr2 (%p)\n", ptr4, ptr2);
	printf("  -> Address reuse: [PASS]\n");

	/* ================================================================
	 * MAP_SHARED anonymous (should behave like MAP_PRIVATE here:
	 * there is no child process, so nothing to share with).
	 * ================================================================ */
	ptr5 = test_allocate("MAP_SHARED anonymous 4KiB", SHOULD_PASS,
		0, 4096, PROT_READ|PROT_WRITE,
		MAP_SHARED|MAP_ANONYMOUS, -1, 0);
	test_munmap("free MAP_SHARED anon", SHOULD_PASS, ptr5, 4096);

	/* ================================================================
	 * MAP_FIXED: ask for the exact address of ptr1, 40 pages away
	 * ================================================================ */
	ptr6 = test_allocate("MAP_FIXED at ptr5", SHOULD_PASS,
		ptr1+(40*PAGE_SIZE), 4096, PROT_READ|PROT_WRITE,
		MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0);

	if (ptr6 != ptr1+(40*PAGE_SIZE))
		FAIL("MAP_FIXED returned %p, expected %p\n", ptr6, ptr5);
	printf("  -> MAP_FIXED honored: [PASS]\n");
	test_munmap("free MAP_FIXED region", SHOULD_PASS, ptr6, 4096);

	/* MAP_FIXED on a page that's already in use (ptr1): must fail.
	 *
	 * AIX's man page says:
	 *   If the application has requested SPEC1170 complaint behavior and the mmap
	 *   request is successful, the mapping replaces any previous mappings for the
	 *   process' pages in the specified range. If the application has not
	 *   requested SPEC1170 compliant behavior and a previous mapping exists in
	 *   the range then the request fails.
	 *
	 * The SPEC1170 is enabled via 'export XPG_SUS_ENV=ON'. Since I'm not handling
	 * this yet, I'll use the default behavior: should fail.
	 */
	test_allocate("MAP_FIXED over allocated page (must fail)", SHOULD_FAIL,
		ptr1, 4096, PROT_READ|PROT_WRITE,
		MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0);

	/* ================================================================
	 * Invalid munmap cases.
	 * ================================================================ */
	test_munmap("munmap NULL address (must fail)", SHOULD_FAIL,
		(void *)0, 4096);

	test_munmap("munmap unaligned address (must fail)", SHOULD_FAIL,
		(char *)ptr1 + 17, 4096);

	test_munmap("munmap address below mmap region (must fail)", SHOULD_FAIL,
		(void *)0x1000, 4096);

	/* ================================================================
	 * File-backed mappings.
	 * ================================================================ */
	fd_ro = make_pattern_file(file_ro, 8192, 0x42);

	ptr5 = test_allocate("file-backed RO mapping (8KiB, pattern 0x42)",
		SHOULD_PASS, 0, 8192, PROT_READ, MAP_PRIVATE, fd_ro, 0);

	for (i = 0; i < 8192; i++) {
		if ((ptr5[i] & 0xFF) != 0x42)
			FAIL("file RO: byte %zu = 0x%02x, expected 0x42\n",
				i, ptr5[i]);
	}
	printf("  -> File-backed RO content: [PASS]\n");
	test_munmap("free file RO mapping", SHOULD_PASS, ptr5, 8192);
	close(fd_ro);
	unlink(file_ro);

	/* File-backed RW: write through the mapping, verify on disk. */
	fd_rw = make_pattern_file(file_rw, 4096, 0x00);

	ptr5 = test_allocate("file-backed RW mapping (4KiB)",
		SHOULD_PASS, 0, 4096, PROT_READ|PROT_WRITE,
		MAP_SHARED, fd_rw, 0);

	memset(ptr5, 0x5A, 4096);
	test_munmap("free file RW mapping", SHOULD_PASS, ptr5, 4096);

	/* Read back via lseek+read to confirm pages were flushed. */
	if (lseek(fd_rw, 0, SEEK_SET) < 0)
		FAIL("lseek: %s\n", strerror(errno));
	n = read(fd_rw, disk, sizeof disk);
	if (n != (ssize_t)sizeof disk)
		FAIL("read returned %zd\n", n);
	for (i = 0; i < sizeof disk; i++) {
		if ((disk[i] & 0xFF) != 0x5A)
			FAIL("file RW: disk byte %zu = 0x%02x, expected 0x5A\n",
				i, disk[i]);
	}
	printf("  -> File-backed RW write-back: [PASS]\n");
	close(fd_rw);
	unlink(file_rw);

	/* ================================================================
	 * mmap64: identical semantics, explicit 64-bit offset.
	 * Use a file >4KiB and map the second page.
	 * ================================================================ */
	off64 = 4096;
	fd64  = make_pattern_file("mmap_test_64", 8192, 0x77);
	p64   = mmap64(NULL, 4096, PROT_READ, MAP_PRIVATE, fd64, off64);
	if (p64 == MAP_FAILED)
		FAIL("mmap64 failed: %s\n", strerror(errno));

	for (i = 0; i < 4096; i++) {
		if ((p64[i] & 0xFF) != 0x77)
			FAIL("mmap64: byte %zu = 0x%02x, expected 0x77\n",
				i, p64[i]);
	}
	printf("\n[TEST #%d] mmap64 at offset 4096\n", test_num++);
	printf("  -> mmap64 content: [PASS]\n");
	test_munmap("free mmap64 region", SHOULD_PASS, p64, 4096);
	close(fd64);
	unlink("mmap_test_64");

	/* ================================================================
	 * Cleanup remaining anon regions.
	 * ================================================================ */
	test_munmap("free ptr1", SHOULD_PASS, ptr1, 4096);
	test_munmap("free ptr3", SHOULD_PASS, ptr3, 4096);
	test_munmap("free ptr4", SHOULD_PASS, ptr4, 4096);

	printf("\n===== All tests passed (%d total) =====\n", test_num);
	return 0;
}
