#!/usr/bin/env bash

#
# aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
# on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
# Made by Theldus, 2025-2026
#

TEST_AIX72=y
TEST_AIX73=y

# 'uniq' tests

function do_test() {

	au=$(printf "bb\naa\naa\ncc" | aix-user ${BIN})
	ln=$(printf "bb\naa\naa\ncc" | uniq)

	if [[ "${au}" != "${ln}" ]]; then
		failed "uniq test failed: differ output!"
		return 1
	fi
}
