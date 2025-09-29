/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025
 */

#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include "../bigar.h"

struct extract_data {
	const char *output_dir;
};

/**
 * @brief Show usage information and exit.
 */
static void usage(void)
{
	fprintf(stderr,
		"Big AR for AIX utility:\n"
		"Usage: ar <archive_file> <option>\n"
		"Options:\n"
		"  -l              List all members\n"
		"  -x <output_dir> Extract all members to directory\n");
	exit(1);
}

/**
 * @brief Create directory if it doesn't exist.
 *
 * @param dir Directory path to create.
 *
 * @return Returns 0 if success, -1 otherwise.
 */
static int create_dir_if_needed(const char *dir)
{
	struct stat st;

	if (stat(dir, &st) == 0) {
		if (S_ISDIR(st.st_mode))
			return 0;
		warn("Path '%s' exists but is not a directory!\n", dir);
		return -1;
	}

	if (mkdir(dir, 0755) < 0) {
		warn("Unable to create directory '%s': %s\n", dir,
			strerror(errno));
		return -1;
	}

	return 0;
}

/**
 * @brief Extract a single AR member to the output directory.
 *
 * @param memb_name Buffer pointing to member name.
 * @param memb_data Buffer pointing to member data, with size mhdr->size.
 * @param mhdr      In-memory member header.
 * @param data      Extract data structure containing output directory.
 *
 * @return Returns 0 to continue extraction, -1 on error.
 */
static int extract_member(
	const char *memb_name,
	const char *memb_data,
	const struct ar_memb_hdr_mem *mhdr, void *data)
{
	struct extract_data *edata = data;
	char filepath[2048] = {0};
	size_t written;
	FILE *fp;

	if (!edata || !edata->output_dir)
		return -1;

	/* Build output file path. */
	if (snprintf(filepath, sizeof(filepath), "%s/%.*s",
		edata->output_dir, (int)mhdr->namlen, memb_name) >=
		(int)sizeof(filepath))
	{
		warn("Output path too long for member '%.*s'\n",
			(int)mhdr->namlen, memb_name);
		return 0; /* Continue with other members. */
	}

	fp = fopen(filepath, "wb");
	if (!fp) {
		warn("Unable to create file '%s': %s\n", filepath,
			strerror(errno));
		return 0; /* Continue with other members. */
	}

	written = fwrite(memb_data, 1, mhdr->size, fp);
	fclose(fp);

	if (written != mhdr->size) {
		warn("Warning: only wrote %zu of %zu bytes for '%s'\n",
			written, (size_t)mhdr->size, filepath);
	} else {
		printf("Extracted: %.*s (%zu bytes)\n",
			(int)mhdr->namlen, memb_name, (size_t)mhdr->size);
	}

	return 0;
}

/**
 * @brief Extract all members from the archive to the specified directory.
 *
 * @param ar         Opened archive.
 * @param output_dir Directory to extract files to.
 *
 * @return Returns 0 if success, -1 otherwise.
 */
static int extract_all_members(struct big_ar *ar, const char *output_dir)
{
	struct extract_data edata;

	if (create_dir_if_needed(output_dir) < 0)
		return -1;

	edata.output_dir = output_dir;
	return ar_iterate_members(ar, extract_member, &edata);
}

int main(int argc, char **argv)
{
	const char *archive_file;
	const char *output_dir;
	const char *option;
	struct big_ar ar;

	if (argc < 3)
		usage();

	archive_file = argv[1];
	option       = argv[2];

	if (ar_open(archive_file, &ar) < 0)
		errx(1, "Unable to open archive '%s'\n", archive_file);

	if (!strcmp(option, "-l")) {
		if (ar_show_info(&ar) < 0) {
			ar_close(&ar);
			errx(1, "Unable to list archive members\n");
		}
	} else if (!strcmp(option, "-x")) {
		if (argc < 4) {
			ar_close(&ar);
			usage();
		}
		output_dir = argv[3];
		if (extract_all_members(&ar, output_dir) < 0) {
			ar_close(&ar);
			errx(1, "Unable to extract archive members\n");
		}
	} else {
		ar_close(&ar);
		usage();
	}

	ar_close(&ar);
	return 0;
}
