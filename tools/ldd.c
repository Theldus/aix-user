/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025
 */

#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../xcoff.h"
#include "../bigar.h"

/* Linked list node for tracking seen dependencies. */
struct dep_node {
	char path[2048];
	struct dep_node *next;
};

/* Global library path override. */
static const char *g_lib_path = NULL;

/**
 * @brief Show usage information and exit.
 */
static void usage(void)
{
	fprintf(stderr,
		"AIX ldd-like utility for XCOFF binaries:\n"
		"Usage: ldd [options] <binary_file> [archive_member]\n"
		"Options:\n"
		"  -L <path>  Override library search path\n"
		"\n"
		"Examples:\n"
		"  ldd /path/to/binary\n"
		"  ldd /usr/lib/libc.a shr.o\n"
		"  ldd -L /custom/libs /path/to/binary\n");
	exit(1);
}

/**
 * @brief Check if a dependency has already been seen.
 *
 * @param path Dependency path to check.
 * @param seen Head of the seen dependencies linked list.
 *
 * @return Returns 1 if already seen, 0 if new.
 */
static int is_dep_seen(const char *path, struct dep_node *seen)
{
	struct dep_node *curr;

	if (!path)
		return 1;

	for (curr = seen; curr != NULL; curr = curr->next) {
		if (!strcmp(curr->path, path))
			return 1;
	}

	return 0;
}

/**
 * @brief Add a dependency to the seen list.
 *
 * @param path Dependency path to add.
 * @param seen Pointer to head of seen dependencies linked list.
 */
static void add_dep(const char *path, struct dep_node **seen)
{
	struct dep_node *node;
	struct dep_node **tail;

	if (!path || !seen)
		return;

	node = malloc(sizeof(struct dep_node));
	if (!node) {
		fprintf(stderr, "Unable to allocate memory for dependency\n");
		exit(1);
	}

	strncpy(node->path, path, sizeof(node->path) - 1);
	node->path[sizeof(node->path) - 1] = '\0';
	node->next = NULL;

	/* Append to end of list. */
	tail = seen;
	while (*tail)
		tail = &(*tail)->next;
	*tail = node;
}

/**
 * @brief Free the entire dependency list.
 *
 * @param head Head of the dependency list to free.
 */
static void free_dep_list(struct dep_node *head)
{
	struct dep_node *curr;
	struct dep_node *next;

	curr = head;
	while (curr) {
		next = curr->next;
		free(curr);
		curr = next;
	}
}

/**
 * @brief Build the full dependency path from an import ID.
 *
 * Constructs paths in the format:
 * - /path/base(member) for archive members
 * - /path/base for standalone binaries
 * - base for binaries without path
 *
 * @param impid    Import ID structure.
 * @param lib_path Custom library path (overrides impid path if set).
 * @param out      Output buffer for constructed path.
 * @param out_size Size of output buffer.
 */
static void build_dep_path(const union xcoff_impid *impid,
	const char *lib_path, char *out, size_t out_size)
{
	const char *path;
	const char *base;
	const char *memb;

	if (!impid || !out)
		return;

	path = impid->l_impidpath;
	base = impid->l_impidbase;
	memb = impid->l_impidmem;

	/* Override path if -L specified. */
	if (lib_path && lib_path[0] != '\0')
		path = lib_path;

	out[0] = '\0';

	/* Build path. */
	if (path && path[0] != '\0') {
		strncat(out, path, out_size - strlen(out) - 1);
		/* Only add separator if path doesn't end with /. */
		if (path[strlen(path) - 1] != '/')
			strncat(out, "/", out_size - strlen(out) - 1);
	}

	if (base && base[0] != '\0')
		strncat(out, base, out_size - strlen(out) - 1);

	if (memb && memb[0] != '\0') {
		strncat(out, "(", out_size - strlen(out) - 1);
		strncat(out, memb, out_size - strlen(out) - 1);
		strncat(out, ")", out_size - strlen(out) - 1);
	}
}

/**
 * @brief Verify that a file or archive exists on disk.
 *
 * For archive paths (containing parentheses), checks that the
 * archive file exists. For regular paths, checks the file directly.
 *
 * @param path Path to verify.
 *
 * @return Returns 0 if exists, -1 otherwise.
 */
static int verify_file_exists(const char *path)
{
	char archive_path[2048];
	const char *paren;
	struct stat st;
	size_t len;

	if (!path || path[0] == '\0')
		return -1;

	/* Check if this is an archive member path. */
	paren = strchr(path, '(');
	if (paren) {
		/* Extract archive path (before parenthesis). */
		len = paren - path;
		if (len >= sizeof(archive_path))
			return -1;
		strncpy(archive_path, path, len);
		archive_path[len] = '\0';
		return stat(archive_path, &st);
	}

	/* Regular file path. */
	return stat(path, &st);
}

/**
 * @brief Open an XCOFF file, either standalone or from an archive.
 *
 * @param bin    Binary or archive file path.
 * @param member Archive member name (NULL for standalone binaries).
 * @param xcoff  XCOFF structure to populate.
 * @param bar    Big-AR structure to populate (only if member != NULL).
 *
 * @return Returns 0 on success, -1 on error.
 */
static int open_xcoff_file(const char *bin, const char *member,
	struct xcoff *xcoff, struct big_ar *bar)
{
	const char *buff;
	size_t size;

	if (!bin || !xcoff)
		return -1;

	/* Standalone XCOFF binary. */
	if (!member) {
		if (xcoff_open(bin, xcoff) < 0) {
			fprintf(stderr, "Unable to open XCOFF '%s'\n", bin);
			return -1;
		}
		return 0;
	}

	/* Archive member. */
	if (!bar)
		return -1;

	if (ar_open(bin, bar) < 0) {
		fprintf(stderr, "Unable to open archive '%s'\n", bin);
		return -1;
	}

	buff = ar_extract_member(bar, member, &size);
	if (!buff) {
		fprintf(stderr, "Member '%s' not found in '%s'\n",
			member, bin);
		ar_close(bar);
		return -1;
	}

	if (xcoff_load(bar->fd, buff, size, xcoff) < 0) {
		fprintf(stderr, "Unable to load XCOFF from member '%s'\n",
			member);
		ar_close(bar);
		return -1;
	}

	return 0;
}

/**
 * @brief Recursively process XCOFF dependencies.
 *
 * Reads the loader section import IDs, constructs full paths for each
 * dependency, and recursively processes dependencies that haven't been
 * seen yet. Special handling for /unix (kernel).
 *
 * @param xcoff XCOFF structure with loader data.
 * @param seen  Pointer to head of seen dependencies list.
 */
static void process_xcoff_deps(const struct xcoff *xcoff,
	struct dep_node **seen)
{
	union xcoff_impid *impids;
	struct xcoff_ldr_hdr32 *ldr;
	struct big_ar bar = {0};
	struct xcoff dep_xcoff = {0};
	char dep_path[2048];
	const char *base;
	const char *memb;
	int is_unix;
	u32 i;

	if (!xcoff || !seen)
		return;

	ldr = (struct xcoff_ldr_hdr32 *)&xcoff->ldr.hdr;
	impids = xcoff->ldr.impids;

	if (!impids)
		return;

	/* Process each import ID (skip 0, which is LIBPATH). */
	for (i = 1; i < ldr->l_nimpid; i++) {
		/* Build full dependency path. */
		build_dep_path(&impids[i], g_lib_path, dep_path,
			sizeof(dep_path));

		/* Skip if already seen. */
		if (is_dep_seen(dep_path, *seen))
			continue;

		/* Add to seen list and print. */
		add_dep(dep_path, seen);
		printf("%s\n", dep_path);

		/* Check if this is /unix (kernel). */
		base = impids[i].l_impidbase;
		is_unix = (base && !strcmp(base, "unix"));

		/* Don't recurse into /unix. */
		if (is_unix)
			continue;

		/* Verify dependency exists. */
		if (verify_file_exists(dep_path) < 0) {
			fprintf(stderr, "Dependency not found: %s\n",
				dep_path);
			exit(1);
		}

		/* Open and recursively process dependency. */
		base = impids[i].l_impidbase;
		memb = impids[i].l_impidmem;

		if (open_xcoff_file(base, memb, &dep_xcoff, &bar) < 0)
			continue;

		/* Recurse. */
		process_xcoff_deps(&dep_xcoff, seen);

		/* Cleanup. */
		xcoff_close(&dep_xcoff);
		if (memb)
			ar_close(&bar);
	}
}

/**
 * @brief Main entry point. =)
 */
int main(int argc, char **argv)
{
	const char *binary_file = NULL;
	const char *archive_member = NULL;
	struct dep_node *seen_deps = NULL;
	struct big_ar bar = {0};
	struct xcoff xcoff = {0};
	int i;

	/* Parse command line arguments. */
	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-L")) {
			if (i + 1 >= argc)
				usage();
			g_lib_path = argv[++i];
		} else if (argv[i][0] == '-') {
			usage();
		} else if (!binary_file) {
			binary_file = argv[i];
		} else if (!archive_member) {
			archive_member = argv[i];
		} else {
			usage();
		}
	}

	if (!binary_file)
		usage();

	/* Open input binary. */
	if (open_xcoff_file(binary_file, archive_member, &xcoff, &bar) < 0) {
		free_dep_list(seen_deps);
		return 1;
	}

	/* Process dependencies recursively. */
	process_xcoff_deps(&xcoff, &seen_deps);

	/* Cleanup. */
	xcoff_close(&xcoff);
	if (archive_member)
		ar_close(&bar);
	free_dep_list(seen_deps);

	return 0;
}
