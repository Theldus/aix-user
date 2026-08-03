#!/usr/bin/env bash

#
# aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
# on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
# Made by Theldus, 2025-2026
#

TEST_AIX72=y
TEST_AIX73=y

# wc tests
#
# Since AIX's wc uses a slightly different formatting/padding,
# so I am removing extra spaces in order to compare with Linux's wc.
#

function do_test() {
	au=$(aix-user ${BIN} ../test_coreutils.sh | sed -E 's/\s+/ /g')
	ln=$(wc ../test_coreutils.sh | sed -E 's/\s+/ /g')

	if [[ ${au} != ${ln} ]]; then
		failed "wc test failed, outputs differ!"
		return 1
	fi
}
