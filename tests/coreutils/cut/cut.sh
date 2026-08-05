#!/usr/bin/env bash

#
# aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
# on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
# Made by Theldus, 2025-2026
#

TEST_AIX72=y
TEST_AIX73=y

# 'cut' tests

function do_test() {

	au=$(printf "a:b:c:d:e:f\n1:2:3:4:5" | aix-user ${BIN} -f "1 4" -d ":")
	ln=$(printf "a:b:c:d:e:f\n1:2:3:4:5" | cut -f "1 4" -d ":")

	if [[ "${au}" != "${ln}" ]]; then
		failed "cut test failed: output differs!"
		return 1
	fi
}
