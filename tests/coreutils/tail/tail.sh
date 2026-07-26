#!/usr/bin/env bash

#
# aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
# on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
# Made by Theldus, 2025-2026
#

TEST_AIX72=y
TEST_AIX73=y

# tail tests

function do_test() {
	au=$(aix-user ${BIN} -20 ../test_coreutils.sh)
	ln=$(tail -20 ../test_coreutils.sh)

	if [[ "${au}" != "${ln}" ]]; then
		failed "tail test failed, outputs differ!"
		return 1
	fi
}
