#!/usr/bin/env bash

#
# aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
# on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
# Made by Theldus, 2025-2026
#

TEST_AIX72=y
TEST_AIX73=y

function do_test() {
	printf "Hello,World!" | aix-user ${BIN} > out
	if ! cmp -s out out_ref; then
		rm out
		failed "od test failed: output differs from expected!"
		return 1
	fi
	rm out
}
