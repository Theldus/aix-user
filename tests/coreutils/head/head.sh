#!/usr/bin/env bash

#
# aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
# on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
# Made by Theldus, 2025-2026
#

TEST_AIX72=y
TEST_AIX73=y

# head tests

function do_test() {
	au=$(aix-user ${BIN} -n 10 ../test_coreutils.sh)
	ln=$(head -n 10 ../test_coreutils.sh)

	if [[ "${au}" != "${ln}" ]]; then
		failed "head test failed, outputs differ!"
		return 1
	fi
}
