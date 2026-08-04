#!/usr/bin/env bash

#
# aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
# on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
# Made by Theldus, 2025-2026
#

TEST_AIX72=y
TEST_AIX73=y

# tee tests

function do_test() {
	str="aix-user rocks \o/"
	out=$(echo "${str}" | aix-user ${BIN} foo)

	if [[ "${str}" != "${out}" ]]; then
		failed "tee test failed: stdout differ!"
		return 1
	fi

	if [[ ! -f foo ]]; then
		failed "tee test failed: file not created!"
		return 1
	fi

	out=$(cat foo)
	rm foo

	if [[ "${str}" != "${out}" ]]; then
		failed "tee test failed: output file content differs from expected!"
		return 1
	fi
}
