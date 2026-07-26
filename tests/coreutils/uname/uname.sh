#!/usr/bin/env bash

#
# aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
# on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
# Made by Theldus, 2025-2026
#

TEST_AIX72=y
TEST_AIX73=y

# uname test

function do_test() {
	au=$(aix-user ${BIN} -a)
	if [[ "${au}" != "AIX aix-user 2 7 " ]]; then
		failed "output for uname differs from expected!"
		return 1
	fi
}
