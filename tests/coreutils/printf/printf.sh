#!/usr/bin/env bash

#
# aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
# on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
# Made by Theldus, 2025-2026
#

TEST_AIX72=y
TEST_AIX73=y

# printf tests

function do_test() {
	au=$(aix-user ${BIN} "%5d%4d\n" 1 21 321 4321 54321)
	ln=$(/usr/bin/printf "%5d%4d\n" 1 21 321 4321 54321)

	if [[ ${au} != ${ln} ]]; then
		failed "printf test failed, outputs differ!"
		return 1
	fi
}
