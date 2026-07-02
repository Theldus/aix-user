/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025-2026
 */

#define _GNU_SOURCE
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

/*
 * This is a reference test file for getdirent64 that uses getdents64 and
 * and convert its output so it should look-like the same output to be
 * produced on getdirent64. That way, we can confirm if getdirent64
 * is working as expected or not.
 *
 * Thankfully, their behavior is pretty similar so there's not
 * much conversion to be done.
 */

#define ROUND_UP_4(x) (((x) + 3) & ~3)

/* linux_dirent64. */
struct linux_dirent64 {
	ino64_t        d_ino;       /* 64-bit inode number */
	off64_t        d_offset;    /* 64-bit offset to next structure */
	unsigned short d_reclen;    /* Size of this dirent */
	unsigned char  d_type;      /* File type */
	char           d_name[256]; /* Filename (NULL-terminated) */
};
static int fake_len_entries[256]; /* Simulated AIX entry size. */
static int true_len_entries[256]; /* Linux entry size.         */

/**
 * @brief For a given single Linux dirent @p ent, returns the calculated
 * size for an equivalent AIX dirent.
 *
 * @param ent Input linux dirent.
 * @return AIX dirent size.
 */
static inline int get_aix_dirent_size(const struct linux_dirent64 *ent) {
	return 20 + ROUND_UP_4(strlen(ent->d_name)+1);
}

/**
 * @brief For a given buffer filled with multiple Linux dir entries,
 * return the calculated size these entries will ocupy on AIX.
 *
 * @param buff Input Linux dirent buffer.
 * @param size Buffer size.
 * @return Returns the calculated size.
 */
static int get_aix_dirents_total_size(const char *buff, int size)
{
	struct linux_dirent64 *ent;
	int off;
	int ret;
	for (off = 0, ret = 0; off < size; off += ent->d_reclen) {
		ent = (struct linux_dirent64 *)(buff + off);
		ret += get_aix_dirent_size(ent);
	}
	return ret;
}

/**
 * @brief Linux getdents64 syscall.
 */
static ssize_t linux_getdents64(int fd, void *dirp, size_t count) {
	return syscall(SYS_getdents64, fd, dirp, count);
}

/**
 * @brief Print a given linux dirent
 * @param ent Linux dirent to be printed.
 */
static void print_dirent(const struct linux_dirent64 *ent)
{
	size_t namlen = strlen(ent->d_name);
	printf("  d_offset = %llu (0x%llx)\n", 
		(unsigned long long)ent->d_offset,
		(unsigned long long)ent->d_offset);
	printf("  d_ino    = %llu\n", (unsigned long long)ent->d_ino);
	printf("  d_reclen = %u\n", get_aix_dirent_size(ent));
	printf("  d_namlen = %zu\n", namlen);
	printf("  d_name   = \"%s\"\n\n", ent->d_name);
}

int main(int argc, char **argv)
{
	struct linux_dirent64 *ent;
	int first_entry_len;
	char buf[4096];
	int true_off;
	int fake_off;
	int ret;
	int fd;
	int i, j;
	const char *dir = argc > 1 ? argv[1] : "testdir";

	fd = open(dir, O_RDONLY);
	if (fd < 0) {
		perror("open");
		return 1;
	}

	printf("=== First read ===\n");
	ret = linux_getdents64(fd, buf, sizeof(buf));
	ent = (struct linux_dirent64 *)buf;
	i   = 0;
	printf("getdirent64 returned: %d\n\n",
		get_aix_dirents_total_size(buf, ret));

	if (ret > 0) {
		true_off = 0;
		fake_off = 0;
		first_entry_len = ent->d_reclen;

		while (true_off < ret) {
			ent = (struct linux_dirent64 *)(buf + true_off);
			true_len_entries[i  ] = ent->d_reclen; 
			fake_len_entries[i++] = get_aix_dirent_size(ent);
			printf("Entry at buf+%d:\n", fake_off);
			print_dirent(ent);
			
			if (ent->d_reclen == 0) break;
			true_off   += ent->d_reclen;
			fake_off += get_aix_dirent_size(ent);
		}
	}
	else {
		perror("getdirent64");
		return 1;
	}

	printf("=== Multiple sequential calls to getdirent64 ===\n");
	lseek(fd, 0, SEEK_SET);
	for (j = 0; j < i; j++) {
		ret = linux_getdents64(fd, buf, true_len_entries[j]);
		printf(
			"Entry #%d, >>> getdirent64(fd, buf, %d) = %d <<<\n",
			j,
			fake_len_entries[j],
			get_aix_dirent_size((struct linux_dirent64 *)buf));
		print_dirent((struct linux_dirent64 *)buf);
	}

	/* Now test seeking with d_offset */
	printf("=== Testing lseek with d_offset ===\n");
	
	/* Rewind and read first entry */
	lseek(fd, 0, SEEK_SET);
	ret = linux_getdents64(fd, buf, first_entry_len);
	if (ret > 0) {
		ent = (struct linux_dirent64 *)buf;
		printf("First entry: \"%s\", d_offset=%llu\n", 
		 ent->d_name, (unsigned long long)ent->d_offset);
		
		/* Seek to d_offset of first entry */
		printf("Seeking to d_offset=%llu...\n", (unsigned long long)ent->d_offset);
		lseek(fd, ent->d_offset, SEEK_SET);
		
		/* Read next entry */
		ret = linux_getdents64(fd, buf, sizeof(buf));
		if (ret > 0) {
			ent = (struct linux_dirent64 *)buf;
			printf("After seek, first entry in buffer: \"%s\"\n", ent->d_name);
		}
	}

	/* Also check current position with lseek */
	printf("\n=== Checking file position ===\n");
	lseek(fd, 0, SEEK_SET);
	off_t pos_before = lseek(fd, 0, SEEK_CUR);
	printf("Position before read: %lld\n", (long long)pos_before);
	
	ret = linux_getdents64(fd, buf, sizeof(buf));
	off_t pos_after = lseek(fd, 0, SEEK_CUR);
	printf("Position after read:  %lld\n", (long long)pos_after);
	printf("Bytes returned: %d\n", get_aix_dirents_total_size(buf, ret));

	close(fd);
	return 0;
}
