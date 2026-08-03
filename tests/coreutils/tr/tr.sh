#!/usr/bin/env bash

#
# aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
# on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
# Made by Theldus, 2025-2026
#

TEST_AIX72=y
TEST_AIX73=y

# tr tests

function do_test() {
	au=$(printf "123:456" | aix-user ${BIN} [:lower:] [:upper:])
	ln=$(printf "123:456" | tr [:lower:] [:upper:])

	if [[ ${au} != ${ln} ]]; then
		failed "tr test failed, outputs differ!"
		return 1
	fi
}
