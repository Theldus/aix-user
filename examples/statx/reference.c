/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025-2026
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

/* Helper to print file type */
static void print_file_type(mode_t mode)
{
	printf("File type:                ");
	switch (mode & S_IFMT) {
		case S_IFBLK:  printf("block device\n");     break;
		case S_IFCHR:  printf("character device\n"); break;
		case S_IFDIR:  printf("directory\n");        break;
		case S_IFIFO:  printf("FIFO/pipe\n");        break;
		case S_IFLNK:  printf("symlink\n");          break;
		case S_IFREG:  printf("regular file\n");     break;
		case S_IFSOCK: printf("socket\n");           break;
		default:       printf("unknown?\n");         break;
	}
}

/* Generic print: use the largest type for uniform output */
#define PRINT_STAT(sb, dev_maj, dev_min) \
	do { \
		printf("ID of containing device:  [%lx,%lx]\n", \
			(unsigned long)(dev_maj), (unsigned long)(dev_min)); \
		print_file_type((sb).st_mode); \
		printf("I-node number:            %llu\n", \
			(unsigned long long)(sb).st_ino); \
		printf("Mode:                     %lo (octal)\n", \
			(unsigned long)(sb).st_mode); \
		printf("Link count:               %u\n", \
			(unsigned)(sb).st_nlink); \
		printf("Ownership:                UID=%lu   GID=%lu\n", \
			(unsigned long)(sb).st_uid, (unsigned long)(sb).st_gid); \
		printf("Preferred I/O block size: %llu bytes\n", \
			(unsigned long long)(sb).st_blksize); \
		printf("File size:                %lld bytes\n", \
			(long long)(sb).st_size); \
		printf("Blocks allocated:         %llu\n", \
			(unsigned long long)(sb).st_blocks); \
		printf("Last status change:       %llu\n", \
			(unsigned long long)(sb).st_ctime); \
		printf("Last file access:         %llu\n", \
			(unsigned long long)(sb).st_atime); \
		printf("Last file modification:   %llu\n", \
			(unsigned long long)(sb).st_mtime); \
	} while (0)

int main(int argc, char *argv[])
{
	struct stat sb;
	int ret;

	if (argc != 3) {
		fprintf(stderr, "Usage: %s <stat|lstat> <path>\n", argv[0]);
		exit(1);
	}

	int is_lstat = (strstr(argv[1], "lstat") != NULL);

	/* Call appropriate function */
	ret = is_lstat ? lstat(argv[2], &sb) : stat(argv[2], &sb);
	if (ret == -1) {
		perror(argv[1]);
		exit(1);
	}

	PRINT_STAT(sb, major(sb.st_dev), minor(sb.st_dev));

	return 0;
}
