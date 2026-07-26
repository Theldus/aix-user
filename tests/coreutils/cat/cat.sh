#!/usr/bin/env bash

#
# aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
# on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
# Made by Theldus, 2025-2026
#

TEST_AIX72=y
TEST_AIX73=y

# cat tests
# -n: Displays output lines preceded by line numbers, numbered
#     sequentially from 1.
# -e: Displays a $ (dollar sign) at the end of each line, when specified
#     with the -v flag.
# -v: Displays nonprinting characters as visible characters
#

function do_test() {
	au=$(aix-user ${BIN} -nev ../test_coreutils.sh)
	ln=$(cat -nev ../test_coreutils.sh)

	if [[ "${au}" != "${ln}" ]]; then
		failed "cat test failed, outputs differ!"
		return 1
	fi
}
