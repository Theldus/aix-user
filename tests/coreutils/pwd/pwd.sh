#!/usr/bin/env bash

#
# aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
# on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
# Made by Theldus, 2025-2026
#

TEST_AIX72=y
TEST_AIX73=y

# pwd

function do_test() {
	au=$(aix-user ${BIN})
	ln=$(pwd)

	if [[ "${au}" != ${ln} ]]; then
		failed "PWD does not match! (${au}) / (${ln})"
		return 1
	fi
}
