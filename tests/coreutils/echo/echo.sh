#!/usr/bin/env bash

#
# aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
# on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
# Made by Theldus, 2025-2026
#

TEST_AIX72=y
TEST_AIX73=y

# echo tests

function do_test() {
	au=$(aix-user ${BIN} "\n\n\nI'm at lunch.\nI'll be back at 1:00.")
	ln=$(/usr/bin/echo -e "\n\n\nI'm at lunch.\nI'll be back at 1:00.")

	if [[ ${au} != ${ln} ]]; then
		failed "echo test failed, outputs differ!"
		return 1
	fi
}
