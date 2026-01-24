/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025-2026
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <inttypes.h>

/* AIX dirent64 structure */
struct dirent64 {
	uint64_t   d_offset;
	uint64_t   d_ino;
	uint16_t   d_reclen;
	uint16_t   d_namlen;
	char       d_name[256];
};

static int len_entries[256];

/* getdirent64 syscall */
extern int getdirent64(int fd, char *buf, unsigned int bufsize);

static void print_dirent(const struct dirent64 *ent)
{
	printf("  d_offset = %llu (0x%llx)\n", 
		(unsigned long long)ent->d_offset,
		(unsigned long long)ent->d_offset);
	printf("  d_ino    = %llu\n", (unsigned long long)ent->d_ino);
	printf("  d_reclen = %u\n", ent->d_reclen);
	printf("  d_namlen = %u\n", ent->d_namlen);
	printf("  d_name   = \"%s\"\n\n", ent->d_name);
}

int main(int argc, char **argv)
{
	struct dirent64 *ent;
	int first_entry_len;
	char buf[4096];
	int offset;
	int ret;
	int fd;
	int i, j;
	const char *dir = argc > 1 ? argv[1] : "testdir";

	fd = open(dir, O_RDONLY|O_LARGEFILE);
	if (fd < 0) {
		perror("open");
		return 1;
	}

	printf("=== First read ===\n");
	ret = getdirent64(fd, buf, sizeof(buf));
	ent = (struct dirent64 *)buf;
	i   = 0;
	printf("getdirent64 returned: %d\n\n", ret);

	if (ret > 0) {
		offset = 0;
		first_entry_len = ent->d_reclen;

		while (offset < ret) {
			ent              = (struct dirent64 *)(buf + offset);
			len_entries[i++] = ent->d_reclen; 
			printf("Entry at buf+%d:\n", offset);
			print_dirent(ent);
			
			if (ent->d_reclen == 0) break;
			offset += ent->d_reclen;
		}
	}

	printf("=== Multiple sequential calls to getdirent64 ===\n");
	lseek(fd, 0, SEEK_SET);
	for (j = 0; j < i; j++) {
		ret = getdirent64(fd, buf, len_entries[j]);
		printf(
			"Entry #%d, >>> getdirent64(fd, buf, %d) = %d <<<\n",
			j,
			len_entries[j],
			ret);
		print_dirent((struct dirent64 *)buf);
	}

	/* Now test seeking with d_offset */
	printf("=== Testing lseek with d_offset ===\n");
	
	/* Rewind and read first entry */
	lseek(fd, 0, SEEK_SET);
	ret = getdirent64(fd, buf, first_entry_len);
	if (ret > 0) {
		ent = (struct dirent64 *)buf;
		printf("First entry: \"%s\", d_offset=%llu\n", 
		 ent->d_name, (unsigned long long)ent->d_offset);
		
		/* Seek to d_offset of first entry */
		printf("Seeking to d_offset=%llu...\n", (unsigned long long)ent->d_offset);
		llseek(fd, ent->d_offset, SEEK_SET);
		
		/* Read next entry */
		ret = getdirent64(fd, buf, sizeof(buf));
		if (ret > 0) {
			ent = (struct dirent64 *)buf;
			printf("After seek, first entry in buffer: \"%s\"\n", ent->d_name);
		}
	}

	/* Also check current position with lseek */
	printf("\n=== Checking file position ===\n");
	lseek(fd, 0, SEEK_SET);
	off64_t pos_before = llseek(fd, 0, SEEK_CUR);
	printf("Position before read: %lld\n", (long long)pos_before);
	
	ret = getdirent64(fd, buf, sizeof(buf));
	off64_t pos_after = llseek(fd, 0, SEEK_CUR);
	printf("Position after read:  %lld\n", (long long)pos_after);
	printf("Bytes returned: %d\n", ret);

	close(fd);
	return 0;
}
