#!/usr/bin/env bash

#
# aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
# on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
# Made by Theldus, 2025-2026
#

TEST_AIX72=y
TEST_AIX73=y

#
# Testing a hardcoded date since a dynamic/current date would require
# me to compare to something else, and since Linux's date slightly
# differs on output, would be.. a bit complicated to do so.
#
# An actual current-date test is done for the 'date' command.
#

function do_test() {
	aix-user ${BIN} 2026 > out
	if ! cmp -s out out_ref_${VER}; then
		failed "output for cal differs from expected!"
		return 1
	fi
}
