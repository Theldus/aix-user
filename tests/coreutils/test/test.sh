#!/usr/bin/env bash

#
# aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
# on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
# Made by Theldus, 2025-2026
#

TEST_AIX72=y
TEST_AIX73=y

# 'test' tests
# Some random tests for the 'test' command

function do_test() {

	# Check for file existence
	if ! aix-user ${BIN} -f ../test_coreutils.sh; then
		failed "'test' test failed: unable to check regular files!"
		return 1
	fi

	# Check for directory existence
	if ! aix-user ${BIN} -d ../test; then
		failed "'test' test failed: unable to check dirs!"
		return 1
	fi

	# Check for char device
	if ! aix-user ${BIN} -c /dev/null; then
		failed "'test' test failed: unable to check file stats!"
		return 1
	fi
}
