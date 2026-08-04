#!/usr/bin/env bash

#
# aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
# on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
# Made by Theldus, 2025-2026
#

TEST_AIX72=y
TEST_AIX73=y

# expr tests
input=(
	"length abcd"
	"4 < 3"
	"4 > 3"
	"substr use-aix-user 5 3"
)

function do_test() {
	for i in "${input[@]}"; do
		au=$(aix-user ${BIN} ${i})
		ln=$(expr ${i})
		if [[ ${au} != ${ln} ]]; then
			failed "expr tests failed: got: ${au}, expected! ${ln}"
			return 1
		fi
	done
}
