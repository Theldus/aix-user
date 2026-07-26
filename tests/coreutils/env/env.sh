#!/usr/bin/env bash

#
# aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
# on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
# Made by Theldus, 2025-2026
#

TEST_AIX72=y
TEST_AIX73=y

# env tests
# AIX's env can dump all environment vars by calling it without
# parameters, but *also* can print a single env var by passing
# it as first argument. I find this pretty neat and I'm using
# it here.
#

function do_test() {
	au=$(aix-user ${BIN} SHELL)
	ln=$(env | grep "SHELL=" | cut -d '=' -f2)

	if [[ "${au}" != ${ln} ]]; then
		failed "env var SHELL does not match! (${au}) / (${ln})"
		return 1
	fi
}
