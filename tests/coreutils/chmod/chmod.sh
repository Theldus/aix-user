#!/usr/bin/env bash

#
# aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
# on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
# Made by Theldus, 2025-2026
#

TEST_AIX72=y
TEST_AIX73=y

# chmod test

function do_test() {
	touch test-file
	aix-user ${BIN} 456 test-file
	perms=$(find . -name test-file -printf "%m")
	rm -f test-file

	if [[ "${perms}" != "456" ]]; then
		failed "perms for test-file differs from expected! ($perms)"
		return 1
	fi
}
