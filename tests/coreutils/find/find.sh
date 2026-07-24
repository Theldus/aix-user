#!/usr/bin/env bash

#
# aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
# on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
# Made by Theldus, 2025-2026
#

TEST_AIX72=y
TEST_AIX73=y

# find tests
#
# 'find' commmand support is partial:
# There _is_ some syscalls still not implemented, such as:
# - _sigaction
# - fork       (this one being important for the '-exec' option)
#
# So this test is limited, and must be incremented
# further as the 'find' support increases.
#

function do_test() {
	au=$(aix-user ${BIN} .. -perm 0755  -print 2>&1 | grep -v "UNIMPLEMENTED")
	ln=$(find .. -perm 0755 -print)

	if [[ "${au}" != "${ln}" ]]; then
		failed "find test failed, outputs differ!"
		return 1
	fi
}
