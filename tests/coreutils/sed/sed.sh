#!/usr/bin/env bash

#
# aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
# on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
# Made by Theldus, 2025-2026
#

TEST_AIX72=y
TEST_AIX73=y

# sed tests

function do_test() {
	au=$(printf "abcdefghijk" | aix-user ${BIN} 's/cde/1234/g')
	ln=$(printf "abcdefghijk" | sed 's/cde/1234/g')

	if [[ ${au} != ${ln} ]]; then
		failed "sed test failed, outputs differ!"
		return 1
	fi
}
