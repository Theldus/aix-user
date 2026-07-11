#!/usr/bin/env bash

#
# aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
# on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
# Made by Theldus, 2025-2026
#

TEST_AIX72=y
TEST_AIX73=y

function do_test() {
	aix-user ${BIN} -n -o -r -c ../../syscalls/args_env/args_env > out
	if ! cmp -s out out_ref; then
		failed "output for dump differs from expected!"
		return 1
	fi
}
