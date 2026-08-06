#!/usr/bin/env bash

#
# aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
# on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
# Made by Theldus, 2025-2026
#

TEST_AIX72=y
TEST_AIX73=y

# chown test
#
# chown mutates inode metadata, so we verify the side effect via
# 'find -printf' (like chmod). Changing the *owner* needs root, but any
# user can change the *group* to one they belong to, so we set
# owner=self (a no-op, allowed unprivileged) and group=some other member
# group. AIX chown requires the Owner operand, hence "uid:gid", not
# ":gid".

function do_test() {
	touch test-file

	me=$(id -u)
	cur=$(find . -name test-file -printf "%G")

	# Pick a supplementary group different from the current one, so the
	# change is real.
	target=""
	for g in $(id -G); do
		if [[ "$g" != "$cur" ]]; then
			target="$g"
			break
		fi
	done

	if [[ -z "$target" ]]; then
		echo "no alternate group available, skipping chown test..."
		rm -f test-file
		return 0
	fi

	aix-user ${BIN} "${me}:${target}" test-file
	got=$(find . -name test-file -printf "%U:%G")
	rm -f test-file

	if [[ "${got}" != "${me}:${target}" ]]; then
		failed "owner/group for test-file differs! (got $got, want ${me}:${target})"
		return 1
	fi
}
