/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025-2026
 */

#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>

#include "unix.h"
#include "aix_errno.h"
#include "mm.h"
#include "vfs.h"

/**
 * aix-user 'VFS':
 * This is _not_ a proper VFS per-se, but since we're dealing with paths
 * and etc, this might be the beginning or something bigger, or not, we'll
 * see =).
 */

#define VFS_MAXLINKS 40

/* Append buffer. */
#define MAX_LINE 4096
struct str_ab {
	char buff[MAX_LINE + 1];
	size_t buff_len;
	size_t pos;
};

/**
 * @brief Initializes the append buffer context.
 * @param ab Append buffer structure.
 * @return Returns 0 if success, -1 otherwise.
 */
static int ab_init(struct str_ab *ab) {
	if (!ab)
		return (-1);
	memset(ab, 0, sizeof(*ab));
	ab->buff_len = MAX_LINE;
	ab->pos      = 0;
	return (0);
}

/**
 * @brief Returns the current string length/pos in bytes.
 * @param ab Input string to be checked.
 * @return Returns the length if success, -1 otherwise.
 */
static ssize_t ab_len(struct str_ab *ab) {
	if (!ab)
		return -1;
	return (ssize_t)ab->pos;
}

/**
 * @brief Trim the provided string pointed to by @p ab, for a provided
 * range @p s and @p e (both inclusive, 0-based).
 *
 * @param ab Input/output string to be trimmed.
 * @param s  Start index (inclusive, 0-based).
 * @param e  End index   (inclusive, 0-based).
 *
 * @return Returns 0 if success, -1 otherwise.
 */
static int ab_range(struct str_ab *ab, size_t s, size_t e) {
	size_t len;
	if (!ab)
		return -1;
	len = (size_t)ab_len(ab);
	if (s > e || e >= len) {
		unix_set_errno(AIX_EINVAL);
		return -1;
	}
	len = e - s + 1;
	memmove(ab->buff, ab->buff+s, len);
	ab->buff[len] = '\0';
	ab->pos = len;
	return 0;
}

/**
 * @brief Append a given char @p c into the buffer.
 * @param ab Aqua highlight context.
 * @param c Char to be appended.
 * @return Returns 0 if success, -1 otherwise.
 */
static int ab_append_chr(struct str_ab *ab, char c) {
	if (ab->pos + 2 >= MAX_LINE) {
		unix_set_errno(AIX_ENAMETOOLONG);
		return -1;
	}
	ab->buff[ab->pos + 0] = c;
	ab->buff[ab->pos + 1] = '\0';
	ab->pos++;
	return (0);
}

/**
 * @brief Appends a given string pointed by @p s of size @p len
 * into the current buffer.
 *
 * If @p len is 0, the string is assumed to be null-terminated
 * and its length is obtained.
 *
 * @param ab  Append buffer context.
 * @param s   String to be append into the buffer.
 * @param len String size, if 0, it's length is obtained.
 *
 * @return Returns 0 if success, -1 otherwise.
 *
 * @note When @p s is NULL, errno is left untouched: it belongs to
 * whoever failed to produce the string in the first place.
 */
static int ab_append_str(struct str_ab *ab, const char *s, size_t len) {
	if (!s)
		return -1;
	if (!len)
		len = strlen(s);
	if (ab->pos + len + 1 >= MAX_LINE) {
		unix_set_errno(AIX_ENAMETOOLONG);
		return (-1);
	}
	memcpy(ab->buff + ab->pos, s, len);
	ab->pos += len;
	ab->buff[ab->pos] = '\0';
	return (0);
}

/**
 * @brief Appends a given formatted string pointed by @p fmt.
 *
 * @param ab  Append buffer context.
 * @param fmt Formatted string to be appended.
 *
 * @return Returns 0 if success, -1 otherwise.
 */
static int ab_append_fmt(struct str_ab *ab, const char *fmt, ...) {
	int str_len, ab_len;
	char *buff_st;
	va_list ap;

	buff_st = ab->buff     + ab->pos;
	ab_len  = ab->buff_len - ab->pos;

	va_start(ap, fmt);
		str_len = vsnprintf(buff_st, ab_len, fmt, ap);
	va_end(ap);

	if (str_len < 0)
		return (-1);

	/* Our buffer is fixed: if it does not fit now, it never will, so
	 * drop whatever vsnprintf() has truncated into it. */
	if (str_len + 1 > ab_len) {
		ab->buff[ab->pos] = '\0';
		unix_set_errno(AIX_ENAMETOOLONG);
		return (-1);
	}

	ab->pos += str_len;
	return (0);
}

/*
 * These paths are 'special' and we must allow its access regardless
 * of the sysroot path configured.
 */
static const char *const special_paths[] = {
	"/dev", "/proc", "/sys", "/run"
};

/**
 * @brief Check if the provided path (complete path) belongs to a special
 * path or not.
 *
 * @param path (Complete) path to be checked.
 *
 * @return Returns 1 if it is a special path, 0 if not.
 */
static int is_special_path(struct str_ab *path) {
	size_t amnt = sizeof(special_paths)/sizeof(special_paths[0]);
	for (size_t i = 0; i < amnt; i++) {
		if (strlen(special_paths[i]) != strlen(path->buff))
			continue;
		if (!strcmp(path->buff, special_paths[i]))
			return 1;
	}
	return 0;
}

/**
 * @brief For a provided guest @p path, converts into the equivalent
 * host path, taking into account the current set sysroot.
 *
 * @param path Guest path.
 *
 * @return Returns the host-converted path if success, NULL otherwise.
 */
static const char *guest2host(struct str_ab *path) {
	static char buff[PATH_MAX] = {0};
	int ret;
	if (ab_len(path) + strlen(args.sysroot) + 1 >= sizeof buff) {
		unix_set_errno(AIX_ENAMETOOLONG);
		return NULL;
	}
	ret = snprintf(buff, sizeof buff, "%s%s", args.sysroot, path->buff);
	if (ret < 0 || ret >= PATH_MAX) {
		unix_set_errno(AIX_ENAMETOOLONG);
		return NULL;
	}
	return buff;
}

/**
 * @brief Returns the current guest CWD, using the configured sysroot
 * path as the basis.
 *
 * @param out_cwd Output buffer for CWD (at least PATH_MAX bytes)
 * @param size    Output buffer size.
 *
 * @return Returns the same 'out_cwd' buffer is success, NULL
 * otherwise.
 */
static const char *guest_cwd(char *out_cwd, size_t size) {
	char *p;
	size_t len_cwd, len_sys;
	if (!out_cwd || !size)
		return NULL;
	if (!getcwd(out_cwd, size))
		return NULL;
	if (vfs_pathcontains(args.sysroot, out_cwd) <= 0)
		return NULL;
	len_cwd = strlen(out_cwd);
	len_sys = strlen(args.sysroot);
	p = out_cwd + len_sys;
	memmove(out_cwd, p, len_cwd - len_sys + 1);
	return out_cwd;
}

/**
 * @brief Drops last component of a provided path.
 * The path is expected to always have a leading slash
 * and never a trailing slash, i.e., /foo, not /foo/
 *
 * @param resolved_path Current path until now.
 */
static void drop_last_component(struct str_ab *resolved_path) {
	char *last_slash;
	if (ab_len(resolved_path) == 0) /* Root path. */
		return;
	last_slash = strrchr(resolved_path->buff, '/');
	if (last_slash == resolved_path->buff)
		ab_init(resolved_path);
	else /* /foo/bar -> /foo */
		ab_range(resolved_path, 0, last_slash - resolved_path->buff - 1);
}

/**
 * @brief Trims leading and trailing slashes for a provided @p path.
 * @param path Path to be 'slash-trimmed'.
 * @return Returns 0 if success, -1 otherwise.
 */
static int trim_slashes(struct str_ab *path) {
	char *p;
	size_t idx, start;
	if (ab_len(path) <= 1)
		return 0;
	for (p = path->buff; p[0] == '/' && p[1] == '/'; p++);
	start = p - path->buff;
	for (idx = ab_len(path) - 1; idx > start && path->buff[idx] == '/'; idx--);
	return ab_range(path, start, idx);
}


/**
 * @brief Append the remaining path components into the output string.
 *
 * @param out     Output string.
 * @param next    Direct next component (or NULL if last component).
 * @param saveptr strtok_r saved pointer, used to keep state between
 *                each tokenization.
 * @return Returns 0 if success, -1 otherwise.
 */
static int append_remaining(struct str_ab *out, char *next, char *saveptr) {
	if (!out)  return -1;
	if (!next) return  0;
	do {
		if (*next != '\0') {
			if (ab_append_fmt(out, "/%s", next))
				return -1;
		}
	} while ((next = strtok_r(NULL, "/", &saveptr)) != NULL);
	return 0;
}

/**
 * @brief Does readlink(2) with some additional checks.
 *
 * @param link Path to be checked.
 *
 * @return Returns the path where the symlink points to, or
 * NULL if error (errno set).
 *
 * @note I'm assuming that its too much of a concidence to have the
 * returned link exactly our buffer size.
 */
static const char *host_readlink(const char *link) {
	static char buff[PATH_MAX] = {0};
	ssize_t ret;
	if (!link)
		return NULL;
	ret = readlink(link, buff, sizeof buff - 1);
	if (ret < 0)
		return NULL;
	if (ret == sizeof buff - 1) {
		unix_set_errno(AIX_ENAMETOOLONG);
		return NULL;
	}
	buff[ret] = '\0';
	return buff;
}

/**
 * @brief Checks if a @p needle path is inside the @p haystack path.
 * This is useful to ensure that a CWD really belongs to the provided
 * sysroot or not.
 *
 * @param haystack Path to be checked _against_ it (i..e, the sysroot)
 * @param needle   Path we hope is inside the @p haystack
 *
 * @return Returns 1 if the path is contained, 0 partially contained,
 * -1 if invalid input.
 */
int vfs_pathcontains(const char *haystack, const char *needle)
{
	size_t hl;
	if (!haystack || !needle)
		return -1;
	if (haystack[0] != '/' || needle[0] != '/')
		return -1;
	/* Skip trailing slashes. */
	for (hl = strlen(haystack); hl > 1 && haystack[hl - 1] == '/'; hl--);
	/* Partial equal. */
	if (strncmp(haystack, needle, hl) != 0)
		return 0;
	/* If:
	 * a) haystack points at '/'
	 * b) haystack and needle are identical
	 * c) needle is inside haystack & have more path components */
	return hl == 1 || needle[hl] == '\0' || needle[hl] == '/';
}

#define VFS_ERR(cond,label) \
	do { if ((cond)) goto label; } while (0)

/**
 * @brief Resolves a provided path, whether following until the last
 * component, or ignoring it.
 *
 * @param guest_path VM's AIX path to be converted to host path.
 * @param flags      Whether VFS_FOLLOW or VFS_NOFOLLOW
 * @param host_out   Output buffer, at least PATH_MAX bytes (required!).
 *
 * @return Returns 0 if success, -1 otherwise (invalid path).
 */
int vfs_resolve(const char *guest_path, int flags, char *host_out)
{
	struct str_ab host, resolved, remaining, symlink, gp;
	struct str_ab *cur, *nxt, *swp;
	char *c, *nc, *saveptr;
	char cwd[PATH_MAX];
	int trailing_slash;
	const char *hpath;
	int follow_last;
	struct stat st;
	int nlinks;
	int ret;

	ab_init(&gp);
	ab_init(&host);
	ab_init(&resolved);
	ab_init(&remaining);
	ab_init(&symlink);

	if (!guest_path || *guest_path == '\0') {
		unix_set_errno(AIX_ENOENT);
		return -1;
	}

	nlinks   =  0;
	ret      = -1;

	/*
	 * The path being tokenized ('cur') and the one we build the next
	 * round into ('nxt') must be two distinct buffers: strtok_r() keeps
	 * pointers into 'cur', so clearing it while a symlink is expanded
	 * would eat the components we still have to walk.
	 */
	cur = &gp;
	nxt = &symlink;

	/* Relative. */
	if (*guest_path != '/') {
		if (!guest_cwd(cwd, sizeof cwd))
			goto out;
		VFS_ERR(ab_append_str(&remaining, cwd, 0), out);
		VFS_ERR(ab_append_fmt(&remaining, "/%s", guest_path), out);
	}
	else {
		VFS_ERR(ab_append_str(&remaining, guest_path, 0), out);
	}

	/*
	 * Every path component must be followed.
	 * If the user provides a trailing slash, we also need to follow too,
	 * thats why we need to check if there's or not a slash at the end.
	 */
	trailing_slash = (ab_len(&remaining) > 1 &&
		remaining.buff[ab_len(&remaining) - 1] == '/');
	follow_last = !(flags & VFS_NOFOLLOW) || trailing_slash;

	VFS_ERR(trim_slashes(&remaining), out);
	VFS_ERR(ab_append_str(cur, remaining.buff, 0), out);

	/* Loop over each path component. */
	saveptr = NULL;
	c = strtok_r(cur->buff, "/", &saveptr);
	while (c) {
		nc = strtok_r(NULL, "/", &saveptr);

		/* Skip empty. */
		if (*c == '\0') goto loop;
		/* Skip same path. */
		if (strcmp(c, ".") == 0) goto loop;
		/* Drop component. */
		if (strcmp(c, "..") == 0) {
			drop_last_component(&resolved);
			goto loop;
		}
		/* Append component in current resolved path. */
		VFS_ERR(ab_append_fmt(&resolved, "/%s", c), out);

		/* If special path. */
		if (is_special_path(&resolved)) {
			VFS_ERR(ab_append_str(&host, resolved.buff, 0), out);
			VFS_ERR(append_remaining(&host, nc, saveptr), out);
			goto done_verbatim;
		}

		/* If last component and no-follow, we quit without checking it. */
		if (!nc && !follow_last)
			break;

		/*
		 * Check the entire path until now, if not found, dump as-is and
		 * let the Linux handle later.
		 */
		hpath = guest2host(&resolved);
		VFS_ERR(!hpath, out);

		if (lstat(hpath, &st) < 0) {
			VFS_ERR(ab_append_str(&host, hpath, 0), out);
			VFS_ERR(append_remaining(&host, nc, saveptr), out);
			goto done_verbatim;
		}

		/* Check if symlink: if so, we follow it and re-start
		 * our loop again. We only not follow a symlink if it is the last
		 * component.
		 */
		if (S_ISLNK(st.st_mode)) {
			if (++nlinks > VFS_MAXLINKS) {
				unix_set_errno(AIX_ELOOP);
				goto out;
			}

			/* Build the new path into the spare buffer: 'nc' and
			 * 'saveptr' still point into 'cur'. */
			ab_init(nxt);
			VFS_ERR(
				ab_append_str(
					nxt,
					host_readlink(hpath),
					0),
				out
			);

			if (!ab_len(nxt)) {
				unix_set_errno(AIX_ENOENT);
				goto out;
			}

			/* If absolute, we need to loop all the way again, otherwise,
			 * its relative and we just erase the symlink name component
			 * and append the remaining.
			 */
			drop_last_component(&resolved);
			if (*nxt->buff == '/')
				ab_init(&resolved); /* Restart at the guest root. */

			/* Prepare our buffer again to iterate over: the expanded
			 * path becomes the current one and the old one is recycled
			 * as the spare for the next symlink. */
			VFS_ERR(append_remaining(nxt, nc, saveptr), out);
			VFS_ERR(trim_slashes(nxt), out);

			swp = cur; cur = nxt; nxt = swp;

			saveptr = NULL;
			c = strtok_r(cur->buff, "/", &saveptr);
			continue;
		}

		/* Check middle component, it *should* be a dir. */
		if (nc && !S_ISDIR(st.st_mode)) {
			unix_set_errno(AIX_ENOTDIR);
			goto out;
		}
	loop:
		c = nc;
	}

	ab_init(&host);
	VFS_ERR(ab_append_str(&host, guest2host(&resolved), 0), out);

done_verbatim:
	/* Add the trailing slash again, it had one before */
	if (trailing_slash)
		VFS_ERR(ab_append_chr(&host, '/'), out);

	/* A double slash might ocurr when sysroot is '/' so we just
	 * advance the pointer to skip the extra slash. */
	c = host.buff;
	if (c[0] == '/' && c[1] == '/')
		c++;

	ret = snprintf(host_out, PATH_MAX, "%s", host.buff);
	if (ret < 0 || ret >= PATH_MAX) {
		unix_set_errno(AIX_ENAMETOOLONG);
		goto out;
	}
	ret = 0;
out:
	return ret;
}
