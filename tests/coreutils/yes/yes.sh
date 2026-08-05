#!/usr/bin/env bash

#
# aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
# on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
# Made by Theldus, 2025-2026
#

TEST_AIX72=y
TEST_AIX73=y

# 'yes' tests
# Meh, just for completeness, because... thats 'yes'...

function do_test() {

	au=$(aix-user ${BIN} use-aix-user | head -n 10)
	ln=$(yes use-aix-user | head -n 10)

	if [[ "${au}" != "${ln}" ]]; then
		failed "yes test failed: output differs!"
		return 1
	fi
}
