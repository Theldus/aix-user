/**
 * aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
 * on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
 * Made by Theldus, 2025-2026
 */

#ifndef VFS_H
#define VFS_H

#define VFS_FOLLOW    0
#define VFS_NOFOLLOW  1

extern int vfs_pathcontains(const char *haystack, const char *needle);
extern int vfs_resolve(const char *guest_path, int flags, char *host_out);

#endif
