/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025-2026
 */

#include <inttypes.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/shm.h>
#include <sys/stat.h>

#define PAGE_SIZE 4096
#define ALIGN_UP(x) (((x) + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1))

#define errx(code,...) \
	do {\
		fprintf(stderr, "%s:%d ", __func__, __LINE__); \
		fprintf(stderr, __VA_ARGS__);\
		exit((code));\
	} while (0)

/**
 * @brief Check if a given character @p chr matches the one at position @p pos
 * for the opened file @p fd.
 *
 * @param fd  File descriptor to be read.
 * @param pos Position to be seeked.
 * @param chr Expected character.
 */
static inline void check_char_at_pos(int fd, int pos, int chr) {
	char ch;
	if (lseek(fd, pos, SEEK_SET) < 0)
		errx(1, "Unable to lseek to pos: %d\n", pos);
	if (read(fd, &ch, 1) != 1)
		errx(1, "Unable to read character!\n");
	if (ch != chr)
		errx(1, "Failed: read (%c), expected: (%c)!\n", ch, chr);
}

/**
 * @brief Creates a RO file for test, with intercalating pattern to be
 * checked later.
 */
void create_ro_file(void) {
	int fd;
	int i;
	fd = open("ro_test", O_RDWR|O_CREAT|O_TRUNC, 0644);
	if (fd < 0)
		errx(1, "Unable to create file!\n");
	for (i = 0; i < 2048; i++)
		if (write(fd, "ABCD", 4) != 4)
			errx(1, "Unable to write proper sequence!\n");
	close(fd);
}

int main(void)
{
	struct stat stat;
	char *buff, *ptr;
	int fd;
	int i;

	create_ro_file();

	/* ================================================================
	 * RO file test: since the mapping is exactly the same as mmap,
	 * a simple test is enough.
	 * ================================================================*/
	fd = open("ro_test", O_RDONLY);
	if (fd < 0)
		errx(1, "Unable to open ro_test file!\n");

	buff = shmat(fd, 0, SHM_MAP|SHM_RDONLY);
	if (buff == (char*)-1)
		errx(1, "Unable to shmat RO file: %d (%s)\n", errno, strerror(errno));

	for (i = 0, ptr = buff; i < 2048; i++, ptr += 4)
		if (strncmp(ptr, "ABCD", 4))
			errx(1, "Failed: Input file does not match written file!\n");

	shmdt(buff);
	close(fd);
	printf(" -> RO test: [PASS]\n");

	/* ================================================================
	 * RW file test: maps a new file as R/W, fill the file with some
	 * pattern, then read and check its size.
	 * ================================================================*/
	fd = open("rw_test", O_RDWR|O_CREAT|O_TRUNC, 0644);
	buff = shmat(fd, 0, SHM_MAP);
	if (buff == (char*)-1)
		errx(1, "Unable to shmat RW file: %d (%s)\n", errno, strerror(errno));

	buff[8]     = 'A';
	buff[4095]  = 'B';
	buff[4096]  = 'C';
	buff[5000]  = 'D';
	buff[8200]  = 'E';
	buff[9000]  = 'F';
	buff[90000] = 'G'; /* This defines the final file size. */
	buff[1000]  = 'H';
	buff[2048]  = 'I';
	shmdt(buff);

	/* Check each position. */
	check_char_at_pos(fd, 8,     'A');
	check_char_at_pos(fd, 4095,  'B');
	check_char_at_pos(fd, 4096,  'C');
	check_char_at_pos(fd, 5000,  'D');
	check_char_at_pos(fd, 8200,  'E');
	check_char_at_pos(fd, 9000,  'F');
	check_char_at_pos(fd, 90000, 'G');
	check_char_at_pos(fd, 1000,  'H');
	check_char_at_pos(fd, 2048,  'I');

	/* Check file size. */
	if (fstat(fd, &stat) < 0)
		errx(1, "Unable to fstat RW file: %d (%s)\n", errno, strerror(errno));

	if (stat.st_size != ALIGN_UP(90000)) /* 22 pages. */ {
		errx(1, "Failed: shmat(RW): sizes does not match!"
		        " expected: %d, read: %" PRId64 ")\n",
		        ALIGN_UP(90000), (uint64_t)stat.st_size);
	}
	close(fd);
	printf(" -> RW test: [PASS]\n");

	unlink("ro_test");
	unlink("rw_test");
	return 0;
}
