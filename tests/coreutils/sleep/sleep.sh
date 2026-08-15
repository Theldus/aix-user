#!/usr/bin/env bash

#
# aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
# on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
# Made by Theldus, 2025-2026
#

TEST_AIX72=y
TEST_AIX73=y

# sleep tests

function do_test() {
	# Get only the seconds (integer) part
	amnt=$(/usr/bin/time -f %e aix-user ${BIN} 1 |& cut -d'.' -f1)

	if [[ ${amnt} != 1 ]]; then
		failed "sleep test failed, slept for ${amnt} secs!"
		return 1
	fi
}
